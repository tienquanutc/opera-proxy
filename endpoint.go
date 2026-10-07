package main

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// Endpoint is one upstream Opera VPN proxy: its address is also the address the destination sees, so one endpoint is
// one egress IP. Everything a request needs to travel through it lives here, together with the health state that
// decides whether the rotation still offers it.
type Endpoint struct {
	addr   string
	region string

	dialer    *ProxyDialer
	transport *http.Transport

	// consecutive dial failures, and the time until which this endpoint is kept out of rotation
	failures     atomic.Int32
	cooldownTill atomic.Int64
}

func NewEndpoint(addr, region string, dialer *ProxyDialer) *Endpoint {
	endpoint := &Endpoint{
		addr:   addr,
		region: region,
		dialer: dialer,
	}
	endpoint.transport = &http.Transport{
		DialContext:           dialer.DialContext,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}
	return endpoint
}

func (e *Endpoint) Addr() string {
	return e.addr
}

func (e *Endpoint) Region() string {
	return e.region
}

func (e *Endpoint) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return e.dialer.DialContext(ctx, network, address)
}

func (e *Endpoint) RoundTripper() http.RoundTripper {
	return e.transport
}

// Available reports whether this endpoint may be handed out now. An endpoint that failed to dial is held out for a
// while instead of being dropped: Opera endpoints come back, and the discovery that would replace it costs a device
// registration.
func (e *Endpoint) Available(now time.Time) bool {
	return now.UnixMilli() >= e.cooldownTill.Load()
}

func (e *Endpoint) Failures() int {
	return int(e.failures.Load())
}

// MarkOK clears the failure count. Only a connection that was actually established says anything about an endpoint,
// so this is never called on the status a destination returned - see Pool.Pick.
func (e *Endpoint) MarkOK() {
	e.failures.Store(0)
	e.cooldownTill.Store(0)
}

// MarkFailed puts the endpoint on cooldown, doubling it per consecutive failure up to max.
func (e *Endpoint) MarkFailed(base, max time.Duration, now time.Time) time.Duration {
	failures := e.failures.Add(1)
	cooldown := base
	for i := int32(1); i < failures && cooldown < max; i++ {
		cooldown *= 2
	}
	if cooldown > max {
		cooldown = max
	}
	e.cooldownTill.Store(now.Add(cooldown).UnixMilli())
	return cooldown
}

func (e *Endpoint) CloseIdleConnections() {
	e.transport.CloseIdleConnections()
}
