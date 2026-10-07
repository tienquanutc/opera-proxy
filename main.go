package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	xproxy "golang.org/x/net/proxy"
)

const (
	API_DOMAIN   = "api.sec-tunnel.com"
	PROXY_SUFFIX = "sec-tunnel.com"
)

var (
	version = "undefined"
)

func perror(msg string) {
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, msg)
}

func arg_fail(msg string) {
	perror(msg)
	perror("Usage:")
	flag.PrintDefaults()
	os.Exit(2)
}

type CLIArgs struct {
	regions       []string
	listCountries bool
	listProxies   bool
	bindAddress   string
	verbosity     int
	timeout       time.Duration
	showVersion   bool
	proxy         string
	apiLogin      string
	apiPassword   string
	apiAddress    string

	refresh      time.Duration
	refreshRetry time.Duration

	certChainWorkaround bool
	caFile              string

	numOfProxies    int
	discoveryRounds int
	attempts        int
	stickyTTL       time.Duration
	cooldown        time.Duration
	maxCooldown     time.Duration
}

func parse_args() CLIArgs {
	var args CLIArgs
	var regions string
	flag.StringVar(&regions, "countries", "EU,AM", "comma separated regions to rotate egress over (EU, AM, AS)")
	flag.StringVar(&regions, "country", "EU,AM", "alias of -countries, kept for older command lines")
	flag.BoolVar(&args.listCountries, "list-countries", false, "list available regions and exit")
	flag.BoolVar(&args.listProxies, "list-proxies", false, "output the discovered endpoints and exit")
	flag.StringVar(&args.bindAddress, "bind-address", "0.0.0.0:18080", "HTTP proxy listen address")
	flag.IntVar(&args.verbosity, "verbosity", 30, "logging verbosity "+
		"(10 - debug, 20 - info, 30 - warning, 40 - error, 50 - critical)")
	flag.DurationVar(&args.timeout, "timeout", 10*time.Second, "timeout for SurfEasy API calls")
	flag.BoolVar(&args.showVersion, "version", false, "show program version and exit")
	flag.StringVar(&args.proxy, "proxy", "", "base proxy to use for all dial-outs. "+
		"Format: <http|https|socks5|socks5h>://[login:password@]host[:port]")
	flag.StringVar(&args.apiLogin, "api-login", "se0316", "SurfEasy API login")
	flag.StringVar(&args.apiPassword, "api-password", "SILrMEPBmJuhomxWkfm3JalqHX2Eheg1YhlEZiMh8II", "SurfEasy API password")
	flag.StringVar(&args.apiAddress, "api-address", "", fmt.Sprintf("override IP address of %s", API_DOMAIN))
	flag.DurationVar(&args.refresh, "refresh", 1*time.Hour, "endpoint refresh interval")
	flag.DurationVar(&args.refreshRetry, "refresh-retry", 1*time.Minute, "retry interval after a failed refresh")
	flag.BoolVar(&args.certChainWorkaround, "certchain-workaround", true,
		"add bundled cross-signed intermediate cert to certchain to make it check out on old systems")
	flag.StringVar(&args.caFile, "cafile", "", "use custom CA certificate bundle file")
	flag.IntVar(&args.numOfProxies, "numOfProxies", 20, "how many distinct egress endpoints to keep in rotation")
	flag.IntVar(&args.discoveryRounds, "discovery-rounds", 4,
		"upper bound on device registrations per refresh while reaching numOfProxies")
	flag.IntVar(&args.attempts, "attempts", 3, "how many endpoints a request may try before it fails")
	flag.DurationVar(&args.stickyTTL, "sticky-ttl", 10*time.Minute,
		"how long a destination host keeps the same egress (0 disables, i.e. a new endpoint per request)")
	flag.DurationVar(&args.cooldown, "cooldown", 30*time.Second,
		"how long an endpoint stays out of rotation after a failed connection")
	flag.DurationVar(&args.maxCooldown, "max-cooldown", 10*time.Minute,
		"ceiling for the cooldown of an endpoint that keeps failing")
	flag.Parse()

	for _, region := range strings.Split(regions, ",") {
		region = strings.TrimSpace(region)
		if region != "" {
			args.regions = append(args.regions, strings.ToUpper(region))
		}
	}
	if len(args.regions) == 0 {
		arg_fail("No region given: -countries can't be empty.")
	}
	if args.listCountries && args.listProxies {
		arg_fail("list-countries and list-proxies flags are mutually exclusive")
	}
	if args.numOfProxies < 1 {
		arg_fail("numOfProxies must be at least 1")
	}
	return args
}

func proxyFromURLWrapper(u *url.URL, next xproxy.Dialer) (xproxy.Dialer, error) {
	cdialer, ok := next.(ContextDialer)
	if !ok {
		return nil, errors.New("only context dialers are accepted")
	}
	return ProxyDialerFromURL(u, cdialer)
}

var logWriter = NewLogWriter(os.Stderr)

func run() int {
	args := parse_args()
	if args.showVersion {
		fmt.Println(version)
		return 0
	}

	mainLogger := NewCondLogger(log.New(logWriter, "MAIN    : ", log.LstdFlags|log.Lshortfile), args.verbosity)
	proxyLogger := NewCondLogger(log.New(logWriter, "PROXY   : ", log.LstdFlags|log.Lshortfile), args.verbosity)
	rotatorLogger := NewCondLogger(log.New(logWriter, "ROTATE  : ", log.LstdFlags|log.Lshortfile), args.verbosity)

	baseDialer, err := buildBaseDialer(args.proxy)
	if err != nil {
		mainLogger.Critical("Unable to build base dialer: %v", err)
		return 3
	}

	caPool, err := loadCAPool(args.caFile)
	if err != nil {
		mainLogger.Critical("Unable to load CA bundle: %v", err)
		return 3
	}

	provider := &Provider{
		regions:             args.regions,
		want:                args.numOfProxies,
		maxRounds:           args.discoveryRounds,
		timeout:             args.timeout,
		apiLogin:            args.apiLogin,
		apiPassword:         args.apiPassword,
		apiAddress:          args.apiAddress,
		certChainWorkaround: args.certChainWorkaround,
		caPool:              caPool,
		baseDialer:          baseDialer,
		logger:              mainLogger,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if args.listCountries {
		return listCountries(ctx, provider)
	}
	if args.listProxies {
		return listProxies(ctx, provider)
	}

	rotator := NewRotator(RotatorConfig{
		StickyTTL:   args.stickyTTL,
		Cooldown:    args.cooldown,
		MaxCooldown: args.maxCooldown,
	}, rotatorLogger)

	// The listener comes up immediately and answers 503 until the first discovery lands, instead of the process
	// exiting when SurfEasy is briefly unreachable at boot.
	go refreshLoop(ctx, provider, rotator, args, mainLogger)

	handler := NewProxyHandler(rotator, args.attempts, proxyLogger)
	server := &http.Server{
		Addr:              args.bindAddress,
		Handler:           handler,
		ReadHeaderTimeout: 30 * time.Second,
	}

	go func() {
		<-ctx.Done()
		mainLogger.Info("Shutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	mainLogger.Info("Listening on %s, rotating over %s, sticky %v, %d attempt(s) per request",
		args.bindAddress, strings.Join(args.regions, ","), args.stickyTTL, args.attempts)
	err = server.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		mainLogger.Critical("Server terminated with a reason: %v", err)
		return 3
	}
	return 0
}

// refreshLoop fills the rotation and keeps it fresh. A failed refresh leaves the previous endpoints in place and is
// retried sooner than the normal interval; it never installs an empty set.
func refreshLoop(ctx context.Context, provider *Provider, rotator *Rotator, args CLIArgs, logger *CondLogger) {
	for {
		endpoints, err := provider.Endpoints(ctx)
		wait := args.refresh
		if err != nil {
			total, _ := rotator.Stats(time.Now())
			logger.Error("Endpoint discovery failed (keeping %d endpoint(s)): %v", total, err)
			wait = args.refreshRetry
		} else if err := rotator.Replace(endpoints); err != nil {
			logger.Error("Endpoint refresh rejected: %v", err)
			wait = args.refreshRetry
		} else {
			total, available := rotator.Stats(time.Now())
			logger.Info("Endpoints refreshed: %d in rotation, %d available", total, available)
		}

		select {
		case <-ctx.Done():
			return
		case <-AfterWallClock(wait):
		}
	}
}

func listCountries(ctx context.Context, provider *Provider) int {
	geos, err := provider.Geos(ctx)
	if err != nil {
		perror(fmt.Sprintf("Unable to list countries: %v", err))
		return 3
	}
	fmt.Println("CODE\tNAME")
	for _, geo := range geos {
		fmt.Printf("%s\t%s\n", geo.CountryCode, geo.Country)
	}
	return 0
}

func listProxies(ctx context.Context, provider *Provider) int {
	endpoints, err := provider.Endpoints(ctx)
	if err != nil {
		perror(fmt.Sprintf("Unable to list proxies: %v", err))
		return 3
	}
	fmt.Println("REGION\tADDRESS")
	for _, endpoint := range endpoints {
		fmt.Printf("%s\t%s\n", endpoint.Region(), endpoint.Addr())
	}
	return 0
}

func buildBaseDialer(proxyURL string) (ContextDialer, error) {
	var dialer ContextDialer = &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	if proxyURL == "" {
		return dialer, nil
	}

	// -proxy was accepted but ignored before: dial-outs went straight out whatever it said.
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("parse proxy url: %w", err)
	}
	xproxy.RegisterDialerType("http", proxyFromURLWrapper)
	xproxy.RegisterDialerType("https", proxyFromURLWrapper)
	chained, err := xproxy.FromURL(parsed, dialer)
	if err != nil {
		return nil, fmt.Errorf("build proxy dialer: %w", err)
	}
	contextDialer, ok := chained.(ContextDialer)
	if !ok {
		return nil, errors.New("base proxy dialer does not support contexts")
	}
	return contextDialer, nil
}

func loadCAPool(caFile string) (*x509.CertPool, error) {
	if caFile == "" {
		return nil, nil
	}
	certs, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certs) {
		return nil, fmt.Errorf("no certificate found in %s", caFile)
	}
	return pool, nil
}

func main() {
	os.Exit(run())
}
