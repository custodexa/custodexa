package gcpkms

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/custodexa/backend/pkg/crypto"
	"golang.org/x/oauth2"
	"google.golang.org/api/option"
	"google.golang.org/api/option/internaloption"
	httptransport "google.golang.org/api/transport/http"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func noAuthFixture(_ context.Context, base http.RoundTripper) (http.RoundTripper, error) {
	return base, nil
}
func responseJSON(r *http.Request, code int, body []byte) *http.Response {
	return &http.Response{StatusCode: code, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(body)), Request: r}
}

// The real SDK serializes requests; this boundary never opens a network socket.
func fakeREST(t *testing.T, f *fakeClient, capture func(*http.Request, []byte)) http.RoundTripper {
	t.Helper()
	return roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var body []byte
		var err error
		if r.Body != nil {
			body, err = io.ReadAll(r.Body)
		}
		if err != nil {
			return nil, err
		}
		if capture != nil {
			capture(r, body)
		}
		name := strings.TrimPrefix(r.URL.Path, "/v1/")
		var out proto.Message
		switch {
		case strings.HasSuffix(name, ":encrypt"):
			req := &kmspb.EncryptRequest{}
			if err = protojson.Unmarshal(body, req); err == nil {
				req.Name = strings.TrimSuffix(name, ":encrypt")
				out, err = f.Encrypt(r.Context(), req)
			}
		case strings.HasSuffix(name, ":decrypt"):
			req := &kmspb.DecryptRequest{}
			if err = protojson.Unmarshal(body, req); err == nil {
				req.Name = strings.TrimSuffix(name, ":decrypt")
				out, err = f.Decrypt(r.Context(), req)
			}
		default:
			out, err = f.GetCryptoKey(r.Context(), &kmspb.GetCryptoKeyRequest{Name: name})
		}
		if err != nil {
			return responseJSON(r, 403, []byte(`{"error":{"code":403,"message":"redacted fixture failure"}}`)), nil
		}
		encoded, err := protojson.Marshal(out)
		if err != nil {
			return nil, err
		}
		return responseJSON(r, 200, encoded), nil
	})
}
func fixtureSDKClient(t *testing.T, resolve adcResolver, base http.RoundTripper) *Client {
	t.Helper()
	c, err := newClient(context.Background(), fixtureSettings(t), resolve, base, func() {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestGCPAADWire(t *testing.T) {
	f := newFakeClient(t)
	aad := crypto.DEKAAD("data", 3)
	seen := 0
	c := fixtureSDKClient(t, noAuthFixture, fakeREST(t, f, func(r *http.Request, body []byte) {
		if !strings.HasSuffix(r.URL.Path, ":encrypt") && !strings.HasSuffix(r.URL.Path, ":decrypt") {
			return
		}
		var wire map[string]json.RawMessage
		if err := json.Unmarshal(body, &wire); err != nil {
			t.Fatal(err)
		}
		var encoded string
		if err := json.Unmarshal(wire["additionalAuthenticatedData"], &encoded); err != nil {
			t.Fatal(err)
		}
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(raw, aad) {
			seen++
		}
		if _, ok := wire["additionalAuthenticatedDataCrc32c"]; !ok {
			t.Fatal("AAD checksum missing from REST")
		}
	}))
	p, err := c.Provider(context.Background(), fixtureKey)
	if err != nil {
		t.Fatal(err)
	}
	plain := bytes.Repeat([]byte{5}, 32)
	blob, err := p.Wrap(context.Background(), plain, aad)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Unwrap(context.Background(), blob, aad)
	if err != nil || !bytes.Equal(got, plain) || seen != 2 {
		t.Fatal("SDK wire did not encode raw AAD exactly once")
	}
	calls := f.snapshot()
	for _, call := range calls[len(calls)-2:] {
		switch r := call.request.(type) {
		case *kmspb.EncryptRequest:
			if !bytes.Equal(r.AdditionalAuthenticatedData, aad) || !fakeCRCValid(r.Plaintext, r.PlaintextCrc32C) {
				t.Fatal("encrypt wire changed")
			}
		case *kmspb.DecryptRequest:
			if !bytes.Equal(r.AdditionalAuthenticatedData, aad) || !fakeCRCValid(r.Ciphertext, r.CiphertextCrc32C) {
				t.Fatal("decrypt wire changed")
			}
		}
	}
}

type tokenFixture struct {
	calls atomic.Int32
	fail  atomic.Bool
}

func (s *tokenFixture) Token() (*oauth2.Token, error) {
	s.calls.Add(1)
	if s.fail.Load() {
		return nil, errors.New("token-secret-marker")
	}
	return &oauth2.Token{AccessToken: "test-token-marker", TokenType: "Bearer", Expiry: time.Now().Add(-time.Second)}, nil
}
func tokenResolver(source oauth2.TokenSource) adcResolver {
	return func(ctx context.Context, base http.RoundTripper) (http.RoundTripper, error) {
		return httptransport.NewTransport(ctx, base, internaloption.EnableNewAuthLibrary(), internaloption.WithDefaultUniverseDomain("googleapis.com"), option.WithTokenSource(source), option.WithLogger(quietLogger()), option.WithTelemetryDisabled())
	}
}
func TestGCPADC(t *testing.T) {
	for _, name := range []string{"missing", "invalid"} {
		t.Run(name, func(t *testing.T) {
			called := 0
			closed := 0
			c, err := newClient(context.Background(), fixtureSettings(t), func(context.Context, http.RoundTripper) (http.RoundTripper, error) {
				called++
				return nil, errors.New("credential-secret-marker")
			}, roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("unexpected service call"); return nil, nil }), func() { closed++ })
			if c != nil || !errors.Is(err, ErrAuthentication) || called != 1 || closed != 1 {
				t.Fatal("ADC failure fallback or resource leak")
			}
		})
	}
	t.Run("official-default-source", func(t *testing.T) {
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/nonexistent-gcp-credential-fixture")
		c, err := NewClient(context.Background(), fixtureSettings(t))
		if c != nil || !errors.Is(err, ErrAuthentication) {
			t.Fatal("default ADC did not reject absent file")
		}
	})
	t.Run("official-refresh", func(t *testing.T) {
		s := &tokenFixture{}
		f := newFakeClient(t)
		c := fixtureSDKClient(t, tokenResolver(s), fakeREST(t, f, func(r *http.Request, _ []byte) {
			if r.Header.Get("Authorization") != "Bearer test-token-marker" {
				t.Error("missing SDK bearer authentication")
			}
		}))
		for range 2 {
			if _, err := c.GetCryptoKey(context.Background(), &kmspb.GetCryptoKeyRequest{Name: fixtureKey}); err != nil {
				t.Fatal(err)
			}
		}
		if s.calls.Load() < 2 {
			t.Fatal("expired credentials were not refreshed by SDK")
		}
	})
	t.Run("refresh-failure", func(t *testing.T) {
		s := &tokenFixture{}
		s.fail.Store(true)
		calls := 0
		c := fixtureSDKClient(t, tokenResolver(s), roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, nil }))
		if out, err := c.GetCryptoKey(context.Background(), &kmspb.GetCryptoKeyRequest{Name: fixtureKey}); out != nil || err == nil || strings.Contains(err.Error(), "token-secret-marker") || calls != 0 {
			t.Fatal("refresh failure leaked or used anonymous fallback")
		}
	})
	t.Run("canceled-construction", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		calls := 0
		c, err := newClient(ctx, fixtureSettings(t), func(context.Context, http.RoundTripper) (http.RoundTripper, error) { calls++; return nil, nil }, nil, func() {})
		if c != nil || !errors.Is(err, context.Canceled) || calls != 0 {
			t.Fatal("canceled ADC construction continued")
		}
	})
}
func TestGCPAuthRedaction(t *testing.T) {
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(old)
	marker := "token role_id secret_id DEK credential-secret-marker"
	for _, code := range []int{401, 403, 500} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			c := fixtureSDKClient(t, noAuthFixture, roundTripFunc(func(r *http.Request) (*http.Response, error) {
				body, _ := json.Marshal(map[string]any{"error": map[string]any{"code": code, "message": marker}})
				return responseJSON(r, code, body), nil
			}))
			out, err := c.GetCryptoKey(context.Background(), &kmspb.GetCryptoKeyRequest{Name: fixtureKey})
			if out != nil || err == nil || strings.Contains(err.Error(), marker) || strings.Contains(logs.String(), marker) {
				t.Fatal("remote error leaked")
			}
			if code == 401 && !errors.Is(err, ErrAuthentication) {
				t.Fatal("authentication category lost")
			}
			if code == 403 && !errors.Is(err, ErrPermission) {
				t.Fatal("permission category lost")
			}
		})
	}
}
func TestGCPClientOwnership(t *testing.T) {
	t.Run("borrowed-providers", func(t *testing.T) {
		c := fixtureSDKClient(t, noAuthFixture, fakeREST(t, newFakeClient(t), nil))
		p, err := c.Provider(context.Background(), fixtureKey)
		if err != nil {
			t.Fatal(err)
		}
		q, err := c.Provider(context.Background(), fixtureOtherKey)
		if err != nil || p.api != c || q.api != c {
			t.Fatal("provider did not borrow shared client")
		}
		_ = c.Close()
		if out, err := p.Wrap(context.Background(), []byte("key"), []byte("aad")); out != nil || !errors.Is(err, ErrClosed) {
			t.Fatal("closed owner still usable")
		}
	})
	t.Run("concurrent-close-waits", func(t *testing.T) {
		started := make(chan struct{}, 8)
		ended := atomic.Int32{}
		closed := atomic.Int32{}
		c, err := newClient(context.Background(), fixtureSettings(t), noAuthFixture, roundTripFunc(func(r *http.Request) (*http.Response, error) {
			started <- struct{}{}
			<-r.Context().Done()
			ended.Add(1)
			return nil, r.Context().Err()
		}), func() { closed.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		var workers sync.WaitGroup
		for range 8 {
			workers.Add(1)
			go func() {
				defer workers.Done()
				if _, err := c.GetCryptoKey(context.Background(), &kmspb.GetCryptoKeyRequest{Name: fixtureKey}); err == nil {
					t.Error("canceled request succeeded")
				}
			}()
		}
		for range 8 {
			<-started
		}
		var closers sync.WaitGroup
		for range 4 {
			closers.Add(1)
			go func() { defer closers.Done(); _ = c.Close() }()
		}
		closers.Wait()
		workers.Wait()
		if ended.Load() != 8 || closed.Load() != 1 {
			t.Fatal("owner did not drain exactly once")
		}
	})
	t.Run("lifetime-cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		c, err := newClient(ctx, fixtureSettings(t), noAuthFixture, fakeREST(t, newFakeClient(t), nil), func() {})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		cancel()
		if _, err := c.GetCryptoKey(context.Background(), &kmspb.GetCryptoKeyRequest{Name: fixtureKey}); !errors.Is(err, context.Canceled) {
			t.Fatal("lifetime cancellation lost")
		}
	})
	t.Run("resolver-cancellation-cleanup", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		closed := 0
		c, err := newClient(ctx, fixtureSettings(t), func(_ context.Context, b http.RoundTripper) (http.RoundTripper, error) { cancel(); return b, nil }, roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, nil }), func() { closed++ })
		if c != nil || !errors.Is(err, context.Canceled) || closed != 1 {
			t.Fatal("construction cancellation leaked")
		}
	})
	t.Run("failed-preflight-cleanup", func(t *testing.T) {
		closed := 0
		c, err := newClient(context.Background(), fixtureSettings(t), noAuthFixture, roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return responseJSON(r, 403, []byte(`{"error":{"code":403}}`)), nil
		}), func() { closed++ })
		if err != nil {
			t.Fatal(err)
		}
		owner, p, err := preflightOwner(context.Background(), c, fixtureKey)
		if owner != nil || p != nil || !errors.Is(err, ErrPermission) {
			t.Fatal("preflight accepted forbidden key or lost permission category")
		}
		if closed != 1 {
			t.Fatal("failed preflight cleanup lost")
		}
	})
}
