package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	se "github.com/Snawoot/opera-proxy/seclient"
)

// Provider turns SurfEasy registrations into endpoints.
//
// One registration gives the credentials for a whole set of discovered endpoints, so the number of registrations is
// kept to what is needed: the previous version registered a new device for every round until it had counted enough
// handlers, which it did even when every round returned the same addresses - and since an endpoint's address is also
// its egress IP, duplicates bought nothing but API calls.
type Provider struct {
	regions []string
	want    int
	// an upper bound on registrations per refresh, so a failing API cannot be hammered
	maxRounds int
	timeout   time.Duration

	apiLogin    string
	apiPassword string
	apiAddress  string

	certChainWorkaround bool
	caPool              *x509.CertPool
	baseDialer          ContextDialer

	logger *CondLogger
}

func (p *Provider) Name() string {
	return "opera"
}

func (p *Provider) Endpoints(ctx context.Context) ([]*Endpoint, error) {
	seen := make(map[string]bool)
	var endpoints []*Endpoint
	var lastErr error

	for round := 0; round < p.maxRounds && len(endpoints) < p.want; round++ {
		added := 0
		for _, region := range p.regions {
			if len(endpoints) >= p.want {
				break
			}
			discovered, err := p.discover(ctx, region)
			if err != nil {
				lastErr = err
				p.logger.Error("discovery for region %q failed: %v", region, err)
				continue
			}
			for _, endpoint := range discovered {
				if seen[endpoint.Addr()] {
					continue
				}
				seen[endpoint.Addr()] = true
				endpoints = append(endpoints, endpoint)
				added++
			}
		}
		// another round would register another device to be told the same addresses
		if added == 0 {
			break
		}
	}

	if len(endpoints) == 0 {
		if lastErr == nil {
			lastErr = errors.New("every region returned an empty endpoint list")
		}
		return nil, lastErr
	}
	if len(endpoints) < p.want {
		p.logger.Warning("discovered %d of %d wanted endpoints", len(endpoints), p.want)
	}
	return endpoints, nil
}

// discover performs one anonymous registration and asks it for the endpoints of a region.
func (p *Provider) discover(ctx context.Context, region string) ([]*Endpoint, error) {
	client, err := p.newSEClient()
	if err != nil {
		return nil, fmt.Errorf("construct SEClient: %w", err)
	}

	steps := []struct {
		name string
		run  func(context.Context) error
	}{
		{"anonymous registration", client.AnonRegister},
		{"device registration", client.RegisterDevice},
	}
	for _, step := range steps {
		stepCtx, cancel := context.WithTimeout(ctx, p.timeout)
		err := step.run(stepCtx)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", step.name, err)
		}
	}

	discoverCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	ips, err := client.Discover(discoverCtx, fmt.Sprintf("%q,,", region))
	if err != nil {
		return nil, fmt.Errorf("discover: %w", err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("region %q returned no endpoints", region)
	}

	// the credentials belong to this registration, so every endpoint it produced shares them
	auth := func() string {
		return basic_auth_header(client.GetProxyCredentials())
	}
	tlsServerName := fmt.Sprintf("%s0.%s", region, PROXY_SUFFIX)

	endpoints := make([]*Endpoint, 0, len(ips))
	for _, ip := range ips {
		dialer := NewProxyDialer(ip.NetAddr(), tlsServerName, auth, p.certChainWorkaround, p.caPool, p.baseDialer)
		endpoints = append(endpoints, NewEndpoint(ip.NetAddr(), region, dialer))
	}
	p.logger.Info("region %s: %d endpoint(s)", region, len(endpoints))
	return endpoints, nil
}

// Geos lists the regions the API offers, for -list-countries.
func (p *Provider) Geos(ctx context.Context) ([]se.SEGeoEntry, error) {
	client, err := p.newSEClient()
	if err != nil {
		return nil, err
	}
	for _, step := range []func(context.Context) error{client.AnonRegister, client.RegisterDevice} {
		stepCtx, cancel := context.WithTimeout(ctx, p.timeout)
		err := step(stepCtx)
		cancel()
		if err != nil {
			return nil, err
		}
	}
	listCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	return client.GeoList(listCtx)
}

func (p *Provider) newSEClient() (*se.SEClient, error) {
	dialer := p.baseDialer
	if p.apiAddress != "" {
		dialer = NewFixedDialer(p.apiAddress, dialer)
	}

	// The API is reached without SNI and answers with a self-signed certificate, so its chain is not verified here.
	// What matters is the certificate of the proxy endpoint itself, which ProxyDialer verifies against the region's
	// server name.
	apiTLSConfig := &tls.Config{
		ServerName:         "",
		InsecureSkipVerify: true,
	}
	return se.NewSEClient(p.apiLogin, p.apiPassword, &http.Transport{
		DialContext: dialer.DialContext,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return conn, err
			}
			return tls.Client(conn, apiTLSConfig), nil
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	})
}
