package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

const (
	PROXY_CONNECT_METHOD       = "CONNECT"
	PROXY_HOST_HEADER          = "Host"
	PROXY_AUTHORIZATION_HEADER = "Proxy-Authorization"
	MISSING_CHAIN_CERT         = `-----BEGIN CERTIFICATE-----
MIID0zCCArugAwIBAgIQVmcdBOpPmUxvEIFHWdJ1lDANBgkqhkiG9w0BAQwFADB7
MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYD
VQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UE
AwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTE5MDMxMjAwMDAwMFoXDTI4
MTIzMTIzNTk1OVowgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5
MRQwEgYDVQQHEwtKZXJzZXkgQ2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBO
ZXR3b3JrMS4wLAYDVQQDEyVVU0VSVHJ1c3QgRUNDIENlcnRpZmljYXRpb24gQXV0
aG9yaXR5MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEGqxUWqn5aCPnetUkb1PGWthL
q8bVttHmc3Gu3ZzWDGH926CJA7gFFOxXzu5dP+Ihs8731Ip54KODfi2X0GHE8Znc
JZFjq38wo7Rw4sehM5zzvy5cU7Ffs30yf4o043l5o4HyMIHvMB8GA1UdIwQYMBaA
FKARCiM+lvEH7OKvKe+CpX/QMKS0MB0GA1UdDgQWBBQ64QmG1M8ZwpZ2dEl23OA1
xmNjmjAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zARBgNVHSAECjAI
MAYGBFUdIAAwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5jb21vZG9jYS5j
b20vQUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNAYIKwYBBQUHAQEEKDAmMCQG
CCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wDQYJKoZIhvcNAQEM
BQADggEBABns652JLCALBIAdGN5CmXKZFjK9Dpx1WywV4ilAbe7/ctvbq5AfjJXy
ij0IckKJUAfiORVsAYfZFhr1wHUrxeZWEQff2Ji8fJ8ZOd+LygBkc7xGEJuTI42+
FsMuCIKchjN0djsoTI0DQoWz4rIjQtUfenVqGtF8qmchxDM6OW1TyaLtYiKou+JV
bJlsQ2uRl9EMC5MCHdK8aXdJ5htN978UeAOwproLtOGFfy/cQjutdAFI3tZs4RmY
CV4Ks2dH/hzg1cEo70qLRDEmBDeNiXQ2Lu+lIg+DdEmSx/cQwgwp+7e9un/jX9Wf
8qn0dNW44bOwgeThpWOjzOoEeJBuv/c=
-----END CERTIFICATE-----
`
)

var UpstreamBlockedError = errors.New("blocked by upstream")

var missingLinkDER, _ = pem.Decode([]byte(MISSING_CHAIN_CERT))
var missingLink, _ = x509.ParseCertificate(missingLinkDER.Bytes)

type Dialer interface {
	Dial(network, address string) (net.Conn, error)
}

type ContextDialer interface {
	Dialer
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type ProxyDialer struct {
	address                string
	tlsServerName          string
	auth                   AuthProvider
	next                   ContextDialer
	intermediateWorkaround bool
	caPool                 *x509.CertPool
}

func NewProxyDialer(address, tlsServerName string, auth AuthProvider, intermediateWorkaround bool, caPool *x509.CertPool, nextDialer ContextDialer) *ProxyDialer {
	return &ProxyDialer{
		address:                address,
		tlsServerName:          tlsServerName,
		auth:                   auth,
		next:                   nextDialer,
		intermediateWorkaround: intermediateWorkaround,
		caPool:                 caPool,
	}
}

func ProxyDialerFromURL(u *url.URL, next ContextDialer) (*ProxyDialer, error) {
	host := u.Hostname()
	port := u.Port()
	tlsServerName := ""
	var auth AuthProvider = nil

	switch strings.ToLower(u.Scheme) {
	case "http":
		if port == "" {
			port = "80"
		}
	case "https":
		if port == "" {
			port = "443"
		}
		tlsServerName = host
	default:
		return nil, errors.New("unsupported proxy type")
	}

	address := net.JoinHostPort(host, port)

	if u.User != nil {
		username := u.User.Username()
		password, _ := u.User.Password()
		authHeader := basic_auth_header(username, password)
		auth = func() string {
			return authHeader
		}
	}
	return NewProxyDialer(address, tlsServerName, auth, false, nil, next), nil
}

func (d *ProxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, errors.New("bad network specified for DialContext: only tcp is supported")
	}

	conn, err := d.next.DialContext(ctx, "tcp", d.address)
	if err != nil {
		return nil, err
	}

	// Set deadline for proxy handshake
	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline {
		conn.SetDeadline(deadline)
	} else {
		// Default 30 second timeout for proxy handshake
		conn.SetDeadline(time.Now().Add(30 * time.Second))
	}

	if d.tlsServerName != "" {
		// Custom cert verification logic:
		// DO NOT send SNI extension of TLS ClientHello
		// DO peer certificate verification against specified servername
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         "",
			InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error {
				opts := x509.VerifyOptions{
					DNSName:       d.tlsServerName,
					Intermediates: x509.NewCertPool(),
					Roots:         d.caPool,
				}
				waRequired := false
				for _, cert := range cs.PeerCertificates[1:] {
					opts.Intermediates.AddCert(cert)
					if d.intermediateWorkaround && !waRequired &&
						bytes.Compare(cert.AuthorityKeyId, missingLink.SubjectKeyId) == 0 {
						waRequired = true
					}
				}
				if waRequired {
					opts.Intermediates.AddCert(missingLink)
				}
				_, err := cs.PeerCertificates[0].Verify(opts)
				return err
			},
		})

		// Perform TLS handshake with timeout
		err = tlsConn.Handshake()
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake failed: %v", err)
		}
		conn = tlsConn
	}

	req := &http.Request{
		Method:     PROXY_CONNECT_METHOD,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		RequestURI: address,
		Host:       address,
		Header: http.Header{
			PROXY_HOST_HEADER: []string{address},
		},
	}

	if d.auth != nil {
		req.Header.Set(PROXY_AUTHORIZATION_HEADER, d.auth())
	}

	rawreq, err := httputil.DumpRequest(req, false)
	if err != nil {
		conn.Close()
		return nil, err
	}

	_, err = conn.Write(rawreq)
	if err != nil {
		conn.Close()
		return nil, err
	}

	proxyResp, err := readResponseWithTimeout(conn, req, ctx)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Clear deadline after successful proxy handshake
	var zeroTime time.Time
	conn.SetDeadline(zeroTime)

	if proxyResp.StatusCode != http.StatusOK {
		conn.Close()
		if proxyResp.StatusCode == http.StatusForbidden &&
			proxyResp.Header.Get("X-Hola-Error") == "Forbidden Host" {
			return nil, UpstreamBlockedError
		}
		return nil, fmt.Errorf("bad response from upstream proxy server: %s", proxyResp.Status)
	}

	return conn, nil
}

func (d *ProxyDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// readResponseWithTimeout reads HTTP response with proper timeout handling
func readResponseWithTimeout(r io.Reader, req *http.Request, ctx context.Context) (*http.Response, error) {
	type result struct {
		resp *http.Response
		err  error
	}

	resultCh := make(chan result, 1)

	go func() {
		resp, err := readResponse(r, req)
		resultCh <- result{resp: resp, err: err}
	}()

	select {
	case res := <-resultCh:
		return res.resp, res.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func readResponse(r io.Reader, req *http.Request) (*http.Response, error) {
	endOfResponse := []byte("\r\n\r\n")
	buf := &bytes.Buffer{}
	b := make([]byte, 1024) // Read in larger chunks for better performance

	for {
		n, err := r.Read(b)
		if n > 0 {
			buf.Write(b[:n])
			sl := buf.Bytes()
			if len(sl) >= len(endOfResponse) {
				if bytes.Contains(sl, endOfResponse) {
					break
				}
			}
		}

		if err != nil {
			if err == io.EOF && buf.Len() > 0 {
				// Try to parse what we have
				break
			}
			return nil, err
		}
	}

	return http.ReadResponse(bufio.NewReader(buf), req)
}
