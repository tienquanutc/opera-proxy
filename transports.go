package main

import (
	"github.com/patrickmn/go-cache"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

var (
	c = cache.New(30*time.Minute, 1*time.Hour)
	m sync.Mutex
)

func GetTransport(proxyUrl string) (*http.Transport, error) {
	if x, found := c.Get(proxyUrl); found {
		return x.(*http.Transport), nil
	}
	m.Lock()
	defer m.Unlock()

	if x, found := c.Get(proxyUrl); found {
		return x.(*http.Transport), nil
	}

	var dialer ContextDialer = &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	u, err := url.Parse(proxyUrl)
	if err != nil {
		return nil, err
	}

	httptransport := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext:           dialer.DialContext,
		Proxy:                 http.ProxyURL(u),
	}
	c.SetDefault(proxyUrl, httptransport)
	return httptransport, nil
}
