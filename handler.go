package main

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

const (
	BAD_REQ_MSG         = "Bad Request\n"
	BAD_PROXY_URL_MSG   = "Bad Proxy Url Request\n"
	BAD_REQUEST_URL_MSG = "Bad Request Url Request\n"

	// a client that knows the destination rejected it asks for a different egress with this header; the proxy cannot
	// make that decision itself because an HTTPS response travels inside the CONNECT tunnel
	ROTATE_HEADER = "Proxy-Rotate"
	// which endpoint served a plain-HTTP request, so a caller can tell one egress from another
	EGRESS_HEADER = "X-Proxy-Egress"
)

type AuthProvider func() string

// ProxyHandler serves the local proxy port, taking an endpoint from the rotation for each request and moving to another
// one when the connection to it fails.
type ProxyHandler struct {
	rotator  *Rotator
	attempts int
	logger   *CondLogger
}

func NewProxyHandler(rotator *Rotator, attempts int, logger *CondLogger) *ProxyHandler {
	if attempts < 1 {
		attempts = 1
	}
	return &ProxyHandler{
		rotator:  rotator,
		attempts: attempts,
		logger:   logger,
	}
}

func (s *ProxyHandler) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	s.logger.Info("Request: %v %v %v %v", req.RemoteAddr, req.Proto, req.Method, req.URL)

	if s.serveFixedProxy(wr, req) {
		return
	}

	isConnect := strings.ToUpper(req.Method) == "CONNECT"
	if (req.URL.Host == "" || req.URL.Scheme == "" && !isConnect) && req.ProtoMajor < 2 || req.Host == "" && req.ProtoMajor == 2 {
		http.Error(wr, BAD_REQ_MSG, http.StatusBadRequest)
		return
	}

	host := destinationHost(req, isConnect)
	if req.Header.Get(ROTATE_HEADER) != "" {
		s.rotator.Forget(host)
		s.logger.Info("client asked for a new egress for %s", host)
	}
	delHopHeaders(req.Header)

	if isConnect {
		s.handleTunnel(wr, req, host)
		return
	}
	s.handleRequest(wr, req, host)
}

// serveFixedProxy forwards through the proxy named by the Proxy-Url header instead of an Opera endpoint, for callers
// that bring their own upstream. It reports whether it handled the request.
func (s *ProxyHandler) serveFixedProxy(wr http.ResponseWriter, req *http.Request) bool {
	proxyURL := req.Header.Get("Proxy-Url")
	requestURL := req.Header.Get("Proxy-Request-Url")
	if proxyURL == "" || requestURL == "" {
		return false
	}

	target, err := url.Parse(requestURL)
	if err != nil {
		http.Error(wr, BAD_REQUEST_URL_MSG, http.StatusBadRequest)
		return true
	}
	transport, err := GetTransport(proxyURL)
	if err != nil {
		http.Error(wr, BAD_PROXY_URL_MSG, http.StatusBadRequest)
		return true
	}

	delHopHeaders(req.Header)
	req.RequestURI = ""
	req.URL = target
	req.Host = target.Host
	req.Header.Set("Host", target.Host)

	resp, err := transport.RoundTrip(req)
	if err != nil {
		// this used to defer resp.Body.Close() before testing err, which panicked on every upstream error
		s.logger.Error("HTTP fetch error via %s: %v", proxyURL, err)
		http.Error(wr, "Server Error", http.StatusBadGateway)
		return true
	}
	defer resp.Body.Close()

	delHopHeaders(resp.Header)
	copyHeader(wr.Header(), resp.Header)
	wr.WriteHeader(resp.StatusCode)
	flush(wr)
	copyBody(wr, resp.Body)
	return true
}

func (s *ProxyHandler) handleTunnel(wr http.ResponseWriter, req *http.Request, host string) {
	ctx := req.Context()
	tried := make(map[string]bool, s.attempts)

	for attempt := 1; attempt <= s.attempts; attempt++ {
		endpoint, err := s.rotator.Pick(host, tried)
		if err != nil {
			s.logger.Error("no endpoint for CONNECT %s: %v", req.RequestURI, err)
			http.Error(wr, "No upstream endpoint available", http.StatusServiceUnavailable)
			return
		}

		conn, err := endpoint.DialContext(ctx, "tcp", req.RequestURI)
		if err != nil {
			tried[endpoint.Addr()] = true
			s.rotator.MarkFailed(endpoint)
			s.rotator.Forget(host)
			if ctx.Err() != nil {
				return
			}
			s.logger.Warning("CONNECT %s via %s failed (attempt %d/%d): %v",
				req.RequestURI, endpoint.Addr(), attempt, s.attempts, err)
			continue
		}
		endpoint.MarkOK()
		s.logger.Info("CONNECT %s via %s", req.RequestURI, endpoint.Addr())
		s.pipe(wr, req, conn)
		return
	}

	s.logger.Error("CONNECT %s failed on all %d attempt(s)", req.RequestURI, s.attempts)
	http.Error(wr, "Can't satisfy CONNECT request", http.StatusBadGateway)
}

func (s *ProxyHandler) pipe(wr http.ResponseWriter, req *http.Request, conn net.Conn) {
	if req.ProtoMajor == 0 || req.ProtoMajor == 1 {
		localconn, _, err := hijack(wr)
		if err != nil {
			conn.Close()
			s.logger.Error("Can't hijack client connection: %v", err)
			http.Error(wr, "Can't hijack client connection", http.StatusInternalServerError)
			return
		}
		defer localconn.Close()

		fmt.Fprintf(localconn, "HTTP/%d.%d 200 OK\r\n\r\n", req.ProtoMajor, req.ProtoMinor)
		proxy(req.Context(), localconn, conn)
		return
	}
	if req.ProtoMajor == 2 {
		wr.Header()["Date"] = nil
		wr.WriteHeader(http.StatusOK)
		flush(wr)
		proxyh2(req.Context(), req.Body, wr, conn)
		return
	}
	conn.Close()
	s.logger.Error("Unsupported protocol version: %s", req.Proto)
	http.Error(wr, "Unsupported protocol version.", http.StatusBadRequest)
}

func (s *ProxyHandler) handleRequest(wr http.ResponseWriter, req *http.Request, host string) {
	req.RequestURI = ""
	if req.ProtoMajor == 2 {
		req.URL.Scheme = "http" // the :scheme pseudo-header is not exposed, so assume http
		req.URL.Host = req.Host
	}

	tried := make(map[string]bool, s.attempts)
	// a request whose body has been consumed cannot be sent to a second endpoint
	replayable := req.Body == nil || req.Body == http.NoBody || req.GetBody != nil

	for attempt := 1; attempt <= s.attempts; attempt++ {
		endpoint, err := s.rotator.Pick(host, tried)
		if err != nil {
			s.logger.Error("no endpoint for %s: %v", req.URL, err)
			http.Error(wr, "No upstream endpoint available", http.StatusServiceUnavailable)
			return
		}

		attemptReq := req
		if attempt > 1 && req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
				s.logger.Error("can't rewind request body for a retry: %v", err)
				http.Error(wr, "Server Error", http.StatusBadGateway)
				return
			}
			attemptReq = req.Clone(req.Context())
			attemptReq.Body = body
		}

		resp, err := endpoint.RoundTripper().RoundTrip(attemptReq)
		if err != nil {
			tried[endpoint.Addr()] = true
			s.rotator.MarkFailed(endpoint)
			s.rotator.Forget(host)
			if req.Context().Err() != nil {
				return
			}
			s.logger.Warning("%s via %s failed (attempt %d/%d): %v", req.URL, endpoint.Addr(), attempt, s.attempts, err)
			if !replayable {
				break
			}
			continue
		}
		defer resp.Body.Close()
		endpoint.MarkOK()

		// The status is the destination's answer, not a verdict on the endpoint: it is reported, never retried on.
		s.logger.Info("%v %v %v %v via %s", req.RemoteAddr, req.Method, req.URL, resp.Status, endpoint.Addr())
		delHopHeaders(resp.Header)
		copyHeader(wr.Header(), resp.Header)
		wr.Header().Set(EGRESS_HEADER, endpoint.Addr())
		wr.WriteHeader(resp.StatusCode)
		flush(wr)
		copyBody(wr, resp.Body)
		return
	}

	http.Error(wr, "Server Error", http.StatusBadGateway)
}

func destinationHost(req *http.Request, isConnect bool) string {
	raw := req.Host
	if isConnect && req.RequestURI != "" {
		raw = req.RequestURI
	} else if req.URL != nil && req.URL.Host != "" {
		raw = req.URL.Host
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		return host
	}
	return raw
}
