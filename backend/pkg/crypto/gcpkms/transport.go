package gcpkms

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"google.golang.org/api/option"
	"google.golang.org/api/option/internaloption"
	httptransport "google.golang.org/api/transport/http"
)

const defaultOrigin = "https://cloudkms.googleapis.com"
const operationTimeout = 10 * time.Second

var ErrEndpoint = errors.New("GCP KMS endpoint rejected")

// These are SDK inputs, not product configuration or credential sources.
var endpointEnvPolicy = map[string]string{
	"GOOGLE_API_USE_MTLS_ENDPOINT":      "never",
	"GOOGLE_API_USE_MTLS":               "false",
	"GOOGLE_API_USE_CLIENT_CERTIFICATE": "false",
	"EXPERIMENTAL_GOOGLE_API_USE_S2A":   "false",
	"GOOGLE_CLOUD_UNIVERSE_DOMAIN":      "googleapis.com",
}

func rejectEndpointEnv() error {
	for key, safe := range endpointEnvPolicy {
		if value := os.Getenv(key); value != "" && value != safe {
			return ErrEndpoint
		}
	}
	return nil
}

// A fresh transport avoids inheriting mutable global TLS or proxy settings.
func secureTransport() *http.Transport {
	return &http.Transport{
		DialContext:         (&net.Dialer{Timeout: operationTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: operationTimeout, ResponseHeaderTimeout: operationTimeout,
		IdleConnTimeout: 90 * time.Second, MaxIdleConns: 10, ForceAttemptHTTP2: true,
	}
}

// This guard is installed both before authentication and immediately before I/O.
// Token and metadata traffic uses the SDK's separate credential transport.
type destinationGuard struct{ next http.RoundTripper }

func (g destinationGuard) RoundTrip(r *http.Request) (*http.Response, error) {
	if r == nil || r.URL == nil || r.URL.Scheme != "https" || r.URL.Host != "cloudkms.googleapis.com" || r.URL.User != nil || r.URL.Opaque != "" || r.URL.Fragment != "" || (r.Host != "" && r.Host != r.URL.Host) {
		return nil, ErrEndpoint
	}
	if g.next == nil {
		return nil, ErrEndpoint
	}
	return g.next.RoundTrip(r)
}

func rejectRedirect(_ *http.Request, _ []*http.Request) error { return ErrEndpoint }
func quietLogger() *slog.Logger                               { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// resolveExplicit 以解封時提供的服務帳號金鑰檔內容顯式建構認證傳輸。
//
// **取代原本的環境自動發現**：原實作交由官方 SDK 自行發現認證來源（ADC），
// 註解並明載「無 caller-supplied option／token source／API key」。自本版起認證
// 材料是顯式輸入，故改以 option.WithCredentialsJSON 注入；token 更新仍由官方
// 程式庫負責，產品不自建 credential store、不持久化該材料。
//
// **缺憑證即拒絕，不回落**：materialJSON 為空時直接回 ErrAuthentication，
// 不呼叫任何會觸發環境自動發現的建構入口。
//
// 目的地閘（destinationGuard）與 TLS 閘（tlsTransport）仍在憑證**之後**——
// base 由呼叫端包好才傳入，換憑證來源不鬆動這兩道。
func resolveExplicit(material []byte) adcResolver {
	return func(ctx context.Context, base http.RoundTripper) (http.RoundTripper, error) {
		if len(material) == 0 {
			return nil, ErrAuthentication
		}
		return httptransport.NewTransport(ctx, base,
			internaloption.EnableNewAuthLibrary(),
			internaloption.WithDefaultEndpoint(defaultOrigin),
			internaloption.WithDefaultEndpointTemplate("https://cloudkms.UNIVERSE_DOMAIN"),
			internaloption.WithDefaultMTLSEndpoint("https://cloudkms.mtls.googleapis.com"),
			internaloption.WithDefaultUniverseDomain("googleapis.com"),
			internaloption.WithDefaultScopes(kms.DefaultAuthScopes()...),
			option.WithLogger(quietLogger()), option.WithTelemetryDisabled(),
			option.WithCredentialsJSON(material))
	}
}

// Validate the owned TLS policy at the final I/O boundary, not just at construction.
type tlsTransport struct{ base *http.Transport }

func (t tlsTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := validateTLS(t.base); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(r)
}
func validateTLS(t *http.Transport) error {
	if t == nil || t.TLSClientConfig == nil || t.TLSClientConfig.InsecureSkipVerify || t.TLSClientConfig.MinVersion < tls.VersionTLS12 || t.TLSClientConfig.ServerName != "" || t.DialTLS != nil || t.DialTLSContext != nil || t.Proxy != nil {
		return ErrEndpoint
	}
	return nil
}
