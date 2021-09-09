package main

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const BAD_REQ_MSG = "Bad Request\n"
const BAD_PROXY_URL_MSG = "Bad Proxy Url Request\n"
const BAD_REQUEST_URL_MSG = "Bad Request Url Request\n"

type AuthProvider func() string

type ProxyHandler struct {
	logger        *CondLogger
	dialer        ContextDialer
	httptransport http.RoundTripper
}

func NewProxyHandler(dialer ContextDialer, logger *CondLogger) *ProxyHandler {
	httptransport := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext:           dialer.DialContext,
	}
	return &ProxyHandler{
		logger:        logger,
		dialer:        dialer,
		httptransport: httptransport,
	}
}

func (s *ProxyHandler) HandleTunnel(wr http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	conn, err := s.dialer.DialContext(ctx, "tcp", req.RequestURI)
	if err != nil {
		s.logger.Error("Can't satisfy CONNECT request: %v", err)
		http.Error(wr, "Can't satisfy CONNECT request", http.StatusBadGateway)
		return
	}

	if req.ProtoMajor == 0 || req.ProtoMajor == 1 {
		// Upgrade client connection
		localconn, _, err := hijack(wr)
		if err != nil {
			s.logger.Error("Can't hijack client connection: %v", err)
			http.Error(wr, "Can't hijack client connection", http.StatusInternalServerError)
			return
		}
		defer localconn.Close()

		// Inform client connection is built
		fmt.Fprintf(localconn, "HTTP/%d.%d 200 OK\r\n\r\n", req.ProtoMajor, req.ProtoMinor)

		proxy(req.Context(), localconn, conn)
	} else if req.ProtoMajor == 2 {
		wr.Header()["Date"] = nil
		wr.WriteHeader(http.StatusOK)
		flush(wr)
		proxyh2(req.Context(), req.Body, wr, conn)
	} else {
		s.logger.Error("Unsupported protocol version: %s", req.Proto)
		http.Error(wr, "Unsupported protocol version.", http.StatusBadRequest)
		return
	}
}

func (s *ProxyHandler) HandleRequest(wr http.ResponseWriter, req *http.Request) {
	req.RequestURI = ""
	if req.ProtoMajor == 2 {
		req.URL.Scheme = "http" // We can't access :scheme pseudo-header, so assume http
		req.URL.Host = req.Host
	}
	resp, err := s.httptransport.RoundTrip(req)
	if err != nil {
		s.logger.Error("HTTP fetch error: %v", err)
		http.Error(wr, "Server Error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	s.logger.Info("%v %v %v %v", req.RemoteAddr, req.Method, req.URL, resp.Status)
	delHopHeaders(resp.Header)
	copyHeader(wr.Header(), resp.Header)
	wr.WriteHeader(resp.StatusCode)
	flush(wr)
	copyBody(wr, resp.Body)
}

func (s *ProxyHandler) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	s.logger.Info("Request: %v %v %v %v", req.RemoteAddr, req.Proto, req.Method, req.URL)

	proxyURLHeaders := req.Header["Proxy-Url"]
	proxyRequestURLHeaders := req.Header["Proxy-Request-Url"]
	if len(proxyURLHeaders) > 0 && len(proxyRequestURLHeaders) > 0 {
		proxyRequestUrl := proxyRequestURLHeaders[0]
		u, err := url.Parse(proxyRequestUrl)
		if err != nil {
			http.Error(wr, BAD_REQUEST_URL_MSG, http.StatusBadRequest)
			return
		}

		proxyUrl := proxyURLHeaders[0]
		transport, err := GetTransport(proxyUrl)
		if err != nil {
			http.Error(wr, BAD_PROXY_URL_MSG, http.StatusBadRequest)
			return
		}
		delHopHeaders(req.Header)
		req.URL = u
		req.Host = u.Host
		req.Header["Host"] = []string{u.Host}
		resp, err := transport.RoundTrip(req)
		defer resp.Body.Close()
		if err != nil {
			s.logger.Error("HTTP fetch error: %v", err)
			http.Error(wr, "Server Error", http.StatusInternalServerError)
			return
		}
		delHopHeaders(resp.Header)
		copyHeader(wr.Header(), resp.Header)
		wr.WriteHeader(resp.StatusCode)
		flush(wr)
		copyBody(wr, resp.Body)
		return
	}

	isConnect := strings.ToUpper(req.Method) == "CONNECT"
	if (req.URL.Host == "" || req.URL.Scheme == "" && !isConnect) && req.ProtoMajor < 2 || req.Host == "" && req.ProtoMajor == 2 {
		http.Error(wr, BAD_REQ_MSG, http.StatusBadRequest)
		return
	}
	delHopHeaders(req.Header)
	if isConnect {
		s.HandleTunnel(wr, req)
	} else {
		s.HandleRequest(wr, req)
	}
}

type RotateProxyHandler struct {
	proxyHandlers []*ProxyHandler
	lock          sync.Mutex
}

func (r *RotateProxyHandler) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	r.proxyHandler().ServeHTTP(wr, req)
}

func (r *RotateProxyHandler) replaceHandlers(proxyHandlers []*ProxyHandler) {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.proxyHandlers = proxyHandlers
}

func (r *RotateProxyHandler) proxyHandler() *ProxyHandler {
	r.lock.Lock()
	randomIndex := rand.Intn(len(r.proxyHandlers))
	r.lock.Unlock()
	return r.proxyHandlers[randomIndex]
}
