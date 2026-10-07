package main

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

var ErrNoEndpoint = errors.New("no upstream endpoint available")

type RotatorConfig struct {
	// how long a destination host keeps the same egress; 0 disables stickiness
	StickyTTL time.Duration
	// how long an endpoint stays out of rotation after a failed dial, and the ceiling for repeated failures
	Cooldown    time.Duration
	MaxCooldown time.Duration
	// how many sticky entries to remember before the table is cleared
	MaxSticky int
}

func (c RotatorConfig) withDefaults() RotatorConfig {
	if c.Cooldown <= 0 {
		c.Cooldown = 30 * time.Second
	}
	if c.MaxCooldown < c.Cooldown {
		c.MaxCooldown = 10 * time.Minute
	}
	if c.MaxSticky <= 0 {
		c.MaxSticky = 4096
	}
	return c
}

type stickyEntry struct {
	endpoint *Endpoint
	expires  time.Time
}

// Rotator hands out endpoints and remembers which one each destination host was last sent through.
//
// Two things it deliberately does not do. It never rotates on a status code the destination returned: for an HTTPS
// request this proxy only sees a CONNECT tunnel, the status is inside TLS, and a proxy that retried on 403 would
// replay the request against another egress without knowing whether the first one had already been accepted. And it
// never drops an endpoint for one failure, because the replacement costs a device registration against the SurfEasy
// API - a failing endpoint is held out on a growing cooldown instead.
type Rotator struct {
	config    RotatorConfig
	logger    *CondLogger
	endpoints atomic.Pointer[[]*Endpoint]
	cursor    atomic.Uint64

	stickyMu sync.Mutex
	sticky   map[string]stickyEntry
}

func NewRotator(config RotatorConfig, logger *CondLogger) *Rotator {
	rotator := &Rotator{
		config: config.withDefaults(),
		logger: logger,
		sticky: make(map[string]stickyEntry),
	}
	empty := make([]*Endpoint, 0)
	rotator.endpoints.Store(&empty)
	return rotator
}

// Replace swaps in a new set of endpoints. An empty set is refused: a discovery that came back with nothing is a
// failed refresh, and serving no endpoints at all is worse than serving the previous ones for another interval.
func (p *Rotator) Replace(next []*Endpoint) error {
	if len(next) == 0 {
		return errors.New("refusing to install an empty endpoint set")
	}

	previous := p.List()
	kept := make(map[string]*Endpoint, len(next))
	for _, endpoint := range next {
		kept[endpoint.Addr()] = endpoint
	}

	p.endpoints.Store(&next)

	p.stickyMu.Lock()
	for host, entry := range p.sticky {
		if kept[entry.endpoint.Addr()] == nil {
			delete(p.sticky, host)
		}
	}
	p.stickyMu.Unlock()

	// an endpoint that is gone from the new set keeps its sockets open until its idle timeout otherwise
	for _, endpoint := range previous {
		if kept[endpoint.Addr()] == nil {
			endpoint.CloseIdleConnections()
		}
	}
	return nil
}

func (p *Rotator) List() []*Endpoint {
	return *p.endpoints.Load()
}

func (p *Rotator) Stats(now time.Time) (total, available int) {
	for _, endpoint := range p.List() {
		total++
		if endpoint.Available(now) {
			available++
		}
	}
	return total, available
}

// Pick returns an endpoint for this destination host.
//
// With stickiness on, a host keeps its egress for StickyTTL: a destination that sees one IP per session is far less
// likely to be challenged than one that sees a different IP per request, which is what rotating per request looks
// like from the other side. Rotation still happens across hosts, and across time as entries expire.
//
// tried holds the endpoints this request has already failed on, so a retry lands somewhere else.
func (p *Rotator) Pick(host string, tried map[string]bool) (*Endpoint, error) {
	endpoints := p.List()
	if len(endpoints) == 0 {
		return nil, ErrNoEndpoint
	}
	now := time.Now()

	if p.config.StickyTTL > 0 && host != "" && len(tried) == 0 {
		if endpoint := p.stickyPick(host, now); endpoint != nil {
			return endpoint, nil
		}
	}

	endpoint := p.rotate(endpoints, now, tried)
	if endpoint == nil {
		// everything is either on cooldown or already tried: prefer a cooled-down endpoint over failing the request
		endpoint = p.rotate(endpoints, time.Time{}, tried)
	}
	if endpoint == nil {
		return nil, ErrNoEndpoint
	}
	if p.config.StickyTTL > 0 && host != "" {
		p.remember(host, endpoint, now)
	}
	return endpoint, nil
}

// rotate walks the endpoints round-robin from a shared cursor, skipping the ones already tried and - unless now is
// the zero time - the ones on cooldown.
func (p *Rotator) rotate(endpoints []*Endpoint, now time.Time, tried map[string]bool) *Endpoint {
	start := p.cursor.Add(1)
	for i := 0; i < len(endpoints); i++ {
		endpoint := endpoints[(start+uint64(i))%uint64(len(endpoints))]
		if tried[endpoint.Addr()] {
			continue
		}
		if !now.IsZero() && !endpoint.Available(now) {
			continue
		}
		return endpoint
	}
	return nil
}

func (p *Rotator) stickyPick(host string, now time.Time) *Endpoint {
	p.stickyMu.Lock()
	defer p.stickyMu.Unlock()
	entry, found := p.sticky[host]
	if !found {
		return nil
	}
	if now.After(entry.expires) || !entry.endpoint.Available(now) {
		delete(p.sticky, host)
		return nil
	}
	return entry.endpoint
}

func (p *Rotator) remember(host string, endpoint *Endpoint, now time.Time) {
	p.stickyMu.Lock()
	defer p.stickyMu.Unlock()
	if len(p.sticky) >= p.config.MaxSticky {
		for key, entry := range p.sticky {
			if now.After(entry.expires) {
				delete(p.sticky, key)
			}
		}
		if len(p.sticky) >= p.config.MaxSticky {
			p.sticky = make(map[string]stickyEntry, p.config.MaxSticky)
		}
	}
	p.sticky[host] = stickyEntry{endpoint: endpoint, expires: now.Add(p.config.StickyTTL)}
}

// Forget drops the sticky entry for a host, so the next request for it goes out through a different endpoint. This is
// how a client asks for rotation: it knows what the destination answered, and this proxy does not.
func (p *Rotator) Forget(host string) {
	if host == "" {
		return
	}
	p.stickyMu.Lock()
	delete(p.sticky, host)
	p.stickyMu.Unlock()
}

func (p *Rotator) MarkFailed(endpoint *Endpoint) {
	cooldown := endpoint.MarkFailed(p.config.Cooldown, p.config.MaxCooldown, time.Now())
	p.logger.Warning("endpoint %s (%s) failed %d time(s) in a row, out of rotation for %v",
		endpoint.Addr(), endpoint.Region(), endpoint.Failures(), cooldown)
}
