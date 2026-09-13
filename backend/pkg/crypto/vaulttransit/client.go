package vaulttransit

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const requestTimeout = 5 * time.Second
const responseLimit = 1 << 20

var (
	ErrAuth      = errors.New("Vault authentication unavailable")
	ErrClosed    = errors.New("Vault client closed")
	ErrTransport = errors.New("Vault transport rejected or unavailable")
	ErrResponse  = errors.New("Vault response invalid")
	ErrDenied    = errors.New("Vault operation denied")
)

type wireError struct{ status int }

func (e *wireError) Error() string   { return "Vault request failed" }
func (e *wireError) retryable() bool { return e.status == 429 || e.status >= 500 }

type adapter struct {
	origin string
	http   *http.Client
}

// Production consumes only explicit deployment settings, never SDK credentials.
func rejectAmbientConfig() error {
	for _, key := range []string{"VAULT_ADDR", "VAULT_AGENT_ADDR", "VAULT_TOKEN", "VAULT_NAMESPACE", "VAULT_SKIP_VERIFY", "VAULT_TLS_SERVER_NAME", "VAULT_CACERT", "VAULT_CAPATH", "VAULT_CLIENT_CERT", "VAULT_CLIENT_KEY", "VAULT_PROXY_ADDR"} {
		if strings.TrimSpace(os.Getenv(key)) != "" {
			return ErrTransport
		}
	}
	return nil
}

func productionAdapter(address string) (*adapter, error) {
	if err := rejectAmbientConfig(); err != nil {
		return nil, err
	}
	origin, err := CanonicalOrigin(address)
	if err != nil {
		return nil, err
	}
	// A fresh transport does not inherit mutable default transports or env proxies.
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext:         (&net.Dialer{Timeout: requestTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: requestTimeout, ResponseHeaderTimeout: requestTimeout,
		IdleConnTimeout: 30 * time.Second,
	}
	return checkedAdapter(origin, transport, false)
}

// Test injection is private; production cannot enable HTTP through settings or env.
func checkedAdapter(origin string, transport *http.Transport, allowHTTP bool) (*adapter, error) {
	u, err := url.Parse(origin)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.Host == "" ||
		(u.Scheme != "https" && !(allowHTTP && u.Scheme == "http")) {
		return nil, ErrTransport
	}
	if transport == nil || transport.Proxy != nil || transport.DialTLSContext != nil || transport.DialTLS != nil {
		return nil, ErrTransport
	}
	if transport.TLSClientConfig != nil && (transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.ServerName != "") {
		return nil, ErrTransport
	}
	tr := transport.Clone()
	if tr.TLSClientConfig != nil {
		tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	}
	return &adapter{origin: origin, http: &http.Client{Transport: tr, Timeout: requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrTransport },
	}}, nil
}

func (a *adapter) call(ctx context.Context, method, path, token string, input, output any) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// Call sites supply fixed mount prefixes and validated ASCII key names.
	if !strings.HasPrefix(path, "/v1/") || strings.ContainsAny(path, "?#%\\") || strings.Contains(path, "..") {
		return ErrTransport
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return ErrResponse
	}
	defer clear(raw)
	bounded, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(bounded, method, a.origin+path, bytes.NewReader(raw))
	if err != nil {
		return ErrTransport
	}
	origin := req.URL.Scheme + "://" + req.URL.Host
	if origin != a.origin {
		return ErrTransport
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	resp, err := a.http.Do(req)
	if err != nil {
		if bounded.Err() != nil {
			return bounded.Err()
		}
		return ErrTransport
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, responseLimit+1))
	defer clear(body)
	if err != nil || len(body) > responseLimit {
		return ErrResponse
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &wireError{status: resp.StatusCode}
	}
	if err := json.Unmarshal(body, output); err != nil {
		return ErrResponse
	}
	return nil
}
