package gcpkms

import (
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"testing"
)

func TestGCPEndpoint(t *testing.T) {
	for key, safe := range endpointEnvPolicy {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, safe)
			if err := rejectEndpointEnv(); err != nil {
				t.Fatal("safe SDK input rejected")
			}
			t.Setenv(key, "malicious-secret-marker")
			called := false
			c, err := newClient(context.Background(), fixtureSettings(t), func(context.Context, http.RoundTripper) (http.RoundTripper, error) { called = true; return nil, nil }, nil, func() {})
			if c != nil || !errors.Is(err, ErrEndpoint) || called {
				t.Fatal("SDK override reached ADC")
			}
		})
	}
	t.Run("credential-env-is-not-endpoint", func(t *testing.T) {
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "deployment-credential-path")
		t.Setenv("GCE_METADATA_HOST", "metadata.google.internal")
		if rejectEndpointEnv() != nil {
			t.Fatal("ADC source incorrectly blocked")
		}
	})
	for _, target := range []string{"http://cloudkms.googleapis.com/v1/key", "https://evil.invalid/v1/key", "https://cloudkms.mtls.googleapis.com/v1/key", "https://cloudkms.googleapis.com:443/v1/key", "https://user@cloudkms.googleapis.com/v1/key", "https://cloudkms.googleapis.com/v1/key#fragment"} {
		t.Run(target, func(t *testing.T) {
			calls := 0
			g := destinationGuard{next: roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, nil })}
			r, _ := http.NewRequest("POST", target, nil)
			if _, err := g.RoundTrip(r); !errors.Is(err, ErrEndpoint) || calls != 0 {
				t.Fatal("nondefault destination reached transport")
			}
		})
	}
	t.Run("resolved-request-origin", func(t *testing.T) {
		calls := 0
		g := destinationGuard{next: roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, nil })}
		r, _ := http.NewRequest("POST", defaultOrigin+"/v1/key", nil)
		if _, err := g.RoundTrip(r); err != nil || calls != 1 {
			t.Fatal("official destination rejected")
		}
		r.Host = "evil.invalid"
		if _, err := g.RoundTrip(r); !errors.Is(err, ErrEndpoint) || calls != 1 {
			t.Fatal("Host override accepted")
		}
	})
}
func TestGCPTransport(t *testing.T) {
	t.Run("authenticated-transport-cannot-redirect", func(t *testing.T) {
		calls := 0
		resolve := func(_ context.Context, base http.RoundTripper) (http.RoundTripper, error) {
			return roundTripFunc(func(r *http.Request) (*http.Response, error) {
				copy := r.Clone(r.Context())
				copy.URL, _ = url.Parse("https://evil.invalid/v1/key")
				copy.Host = ""
				return base.RoundTrip(copy)
			}), nil
		}
		c := fixtureSDKClient(t, resolve, roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, nil }))
		if _, err := c.GetCryptoKey(context.Background(), fixtureMetadataRequest()); !errors.Is(err, ErrEndpoint) || calls != 0 {
			t.Fatal("final destination bypassed guard")
		}
	})
	t.Run("redirect-response", func(t *testing.T) {
		calls := 0
		c := fixtureSDKClient(t, noAuthFixture, roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			resp := responseJSON(r, 307, nil)
			resp.Header.Set("Location", defaultOrigin+"/v1/other")
			return resp, nil
		}))
		if _, err := c.GetCryptoKey(context.Background(), fixtureMetadataRequest()); !errors.Is(err, ErrEndpoint) || calls != 1 {
			t.Fatal("redirect was followed")
		}
	})
	t.Run("tls-policy", func(t *testing.T) {
		base := secureTransport()
		defer base.CloseIdleConnections()
		if validateTLS(base) != nil || base.TLSClientConfig.InsecureSkipVerify || base.TLSClientConfig.MinVersion < tls.VersionTLS12 {
			t.Fatal("default TLS policy invalid")
		}
		base.TLSClientConfig.InsecureSkipVerify = true
		r, _ := http.NewRequest("GET", defaultOrigin, nil)
		if _, err := (tlsTransport{base: base}).RoundTrip(r); !errors.Is(err, ErrEndpoint) {
			t.Fatal("TLS bypass accepted")
		}
		base.TLSClientConfig.InsecureSkipVerify = false
		base.Proxy = http.ProxyFromEnvironment
		if validateTLS(base) == nil {
			t.Fatal("unexpected proxy accepted")
		}
	})
	t.Run("adc-traffic-separated", func(t *testing.T) {
		authCalls := 0
		kmsCalls := 0
		resolve := func(_ context.Context, base http.RoundTripper) (http.RoundTripper, error) {
			return roundTripFunc(func(r *http.Request) (*http.Response, error) {
				auth := roundTripFunc(func(req *http.Request) (*http.Response, error) {
					if req.URL.Host != "oauth2.googleapis.com" {
						t.Fatal("wrong token host")
					}
					authCalls++
					return responseJSON(req, 200, nil), nil
				})
				tokenReq, _ := http.NewRequestWithContext(r.Context(), "POST", "https://oauth2.googleapis.com/token", nil)
				resp, err := auth.RoundTrip(tokenReq)
				if err != nil {
					return nil, err
				}
				resp.Body.Close()
				return base.RoundTrip(r)
			}), nil
		}
		c := fixtureSDKClient(t, resolve, fakeREST(t, newFakeClient(t), func(*http.Request, []byte) { kmsCalls++ }))
		if _, err := c.GetCryptoKey(context.Background(), fixtureMetadataRequest()); err != nil || authCalls != 1 || kmsCalls != 1 {
			t.Fatal("credential traffic blocked by KMS policy")
		}
	})
}

func fixtureMetadataRequest() *kmspb.GetCryptoKeyRequest {
	return &kmspb.GetCryptoKeyRequest{Name: fixtureKey}
}
