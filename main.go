package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	xproxy "golang.org/x/net/proxy"

	se "github.com/Snawoot/opera-proxy/seclient"
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
	countries           []string
	country             string
	listCountries       bool
	listProxies         bool
	bindAddress         string
	verbosity           int
	timeout             time.Duration
	showVersion         bool
	proxy               string
	apiLogin            string
	apiPassword         string
	apiAddress          string
	bootstrapDNS        string
	refresh             time.Duration
	refreshRetry        time.Duration
	certChainWorkaround bool
	caFile              string
	numOfProxies        int
}

func parse_args() CLIArgs {
	var args CLIArgs
	flag.Func("countries", "countries for rotate", func(s string) error {
		args.countries = strings.Split(s, ",")
		return nil
	})
	flag.StringVar(&args.country, "country", "EU", "desired proxy location")
	flag.BoolVar(&args.listCountries, "list-countries", false, "list available countries and exit")
	flag.BoolVar(&args.listProxies, "list-proxies", false, "output proxy list and exit")
	flag.StringVar(&args.bindAddress, "bind-address", "0.0.0.0:18080", "HTTP proxy listen address")
	flag.IntVar(&args.verbosity, "verbosity", 30, "logging verbosity "+
		"(10 - debug, 20 - info, 30 - warning, 40 - error, 50 - critical)")
	flag.DurationVar(&args.timeout, "timeout", 10*time.Second, "timeout for network operations")
	flag.BoolVar(&args.showVersion, "version", false, "show program version and exit")
	flag.StringVar(&args.proxy, "proxy", "", "sets base proxy to use for all dial-outs. "+
		"Format: <http|https|socks5|socks5h>://[login:password@]host[:port] "+
		"Examples: http://user:password@192.168.1.1:3128, socks5://10.0.0.1:1080")
	flag.StringVar(&args.apiLogin, "api-login", "se0316", "SurfEasy API login")
	flag.StringVar(&args.apiPassword, "api-password", "SILrMEPBmJuhomxWkfm3JalqHX2Eheg1YhlEZiMh8II", "SurfEasy API password")
	flag.StringVar(&args.apiAddress, "api-address", "", fmt.Sprintf("override IP address of %s", API_DOMAIN))
	flag.StringVar(&args.bootstrapDNS, "bootstrap-dns", "",
		"DNS/DoH/DoT/DoQ resolver for initial discovering of SurfEasy API address. "+
			"See https://github.com/ameshkov/dnslookup/ for upstream DNS URL format. "+
			"Examples: https://1.1.1.1/dns-query, quic://dns.adguard.com")
	flag.DurationVar(&args.refresh, "refresh", 1*time.Hour, "login refresh interval")
	flag.DurationVar(&args.refreshRetry, "refresh-retry", 5*time.Second, "login refresh retry interval")
	flag.BoolVar(&args.certChainWorkaround, "certchain-workaround", true,
		"add bundled cross-signed intermediate cert to certchain to make it check out on old systems")
	flag.StringVar(&args.caFile, "cafile", "", "use custom CA certificate bundle file")
	flag.IntVar(&args.numOfProxies, "numOfProxies", 20, "number of rotate proxies")
	flag.Parse()
	if args.country == "" {
		arg_fail("Country can't be empty string.")
	}
	if args.listCountries && args.listProxies {
		arg_fail("list-countries and list-proxies flags are mutually exclusive")
	}
	if args.apiAddress != "" && args.bootstrapDNS != "" {
		arg_fail("api-address and bootstrap-dns options are mutually exclusive")
	}
	if len(args.countries) == 0 {
		args.countries = []string{"EU", "AM"}
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

	rotateProxyHandler := RotateProxyHandler{proxyHandlers: buildProxyHandlersEx(args, args.numOfProxies)}

	runTicker(context.Background(), args.refresh, args.refreshRetry, func(ctx context.Context) error {
		proxyHandlers := buildProxyHandlersEx(args, args.numOfProxies)
		rotateProxyHandler.replaceHandlers(proxyHandlers)
		return nil
	})

	err := http.ListenAndServe(args.bindAddress, &rotateProxyHandler)
	mainLogger.Critical("Server terminated with a reason: %v", err)
	mainLogger.Info("Shutting down...")
	return 0
}

func buildProxyHandlersEx(args CLIArgs, numOfProxies int) []*ProxyHandler {
	var proxyHandlers []*ProxyHandler
	var failure = 0
	for len(proxyHandlers) < numOfProxies {
		for _, country := range args.countries {
			args.country = country
			handlers, err := buildProxyHandlers(args)
			if err != nil {
				//TODO: handle error
				failure += 1
				if failure > numOfProxies {
					return proxyHandlers
				}
				continue
			}
			proxyHandlers = append(proxyHandlers, handlers...)
		}
	}
	return proxyHandlers
}

func buildProxyHandlers(args CLIArgs) ([]*ProxyHandler, error) {
	mainLogger := NewCondLogger(log.New(logWriter, "MAIN    : ", log.LstdFlags|log.Lshortfile), args.verbosity)
	proxyLogger := NewCondLogger(log.New(logWriter, "PROXY   : ", log.LstdFlags|log.Lshortfile), args.verbosity)

	var seclientDialer ContextDialer = &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	// Dialing w/o SNI, receiving self-signed certificate, so skip verification.
	// Either way we'll validate certificate of actual proxy server.
	tlsConfig := &tls.Config{
		ServerName:         "",
		InsecureSkipVerify: true,
	}
	seclient, err := se.NewSEClient(args.apiLogin, args.apiPassword, &http.Transport{
		DialContext: seclientDialer.DialContext,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := seclientDialer.DialContext(ctx, network, addr)
			if err != nil {
				return conn, err
			}
			return tls.Client(conn, tlsConfig), nil
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	})
	if err != nil {
		mainLogger.Critical("Unable to construct SEClient: %v", err)
		return nil, err
	}

	ctx, cl := context.WithTimeout(context.Background(), args.timeout)
	defer cl()
	err = seclient.AnonRegister(ctx)
	if err != nil {
		mainLogger.Critical("Unable to perform anonymous registration: %v", err)
		return nil, err
	}

	ctx, cl = context.WithTimeout(context.Background(), args.timeout)
	defer cl()
	err = seclient.RegisterDevice(ctx)
	if err != nil {
		mainLogger.Critical("Unable to perform device registration: %v", err)
		return nil, err
	}

	ctx, cl = context.WithTimeout(context.Background(), args.timeout)
	defer cl()
	ips, err := seclient.Discover(ctx, fmt.Sprintf("\"%s\",,", args.country))

	if err != nil {
		mainLogger.Critical("Endpoint discovery failed: %v", err)
		return nil, err
	}

	if len(ips) == 0 {
		mainLogger.Critical("Empty endpoint list!")
		return nil, err
	}

	auth := func() string {
		return basic_auth_header(seclient.GetProxyCredentials())
	}

	var proxyHandlers []*ProxyHandler
	for _, ip := range ips {
		var dialer ContextDialer = &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		var caPool *x509.CertPool
		println(ip.IP)
		handlerDialer := NewProxyDialer(ip.NetAddr(), fmt.Sprintf("%s0.%s", args.country, PROXY_SUFFIX), auth, args.certChainWorkaround, caPool, dialer)
		proxyHandler := NewProxyHandler(handlerDialer, proxyLogger)

		proxyHandlers = append(proxyHandlers, proxyHandler)
	}
	return proxyHandlers, nil
}

func main() {
	os.Exit(run())
}
