package gcpkms

import (
	"context"
	"errors"
	"net/http"
	"sync"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var ErrAuthentication = errors.New("GCP KMS authentication rejected")
var ErrPermission = errors.New("GCP KMS permission denied")
var ErrUnavailable = errors.New("GCP KMS request failed")
var ErrClosed = errors.New("GCP KMS client closed")

// Client owns one SDK client; providers borrow it for the deployment lifetime.
// Close cancels in-flight requests and waits before closing SDK resources.
type Client struct {
	sdk       *kms.KeyManagementClient
	scope     ProjectScope
	lifetime  context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	closed    bool
	active    sync.WaitGroup
	closeOnce sync.Once
	closeBase func()
}

type adcResolver func(context.Context, http.RoundTripper) (http.RoundTripper, error)

// NewClient 以**顯式服務帳號金鑰檔內容**建構正式 client，不接觸任何 KMS 金鑰。
// 金鑰的中繼資料與加解密預檢由 Provider 於使用前完成。
//
// 憑證缺席即拒絕建構（ErrAuthentication），**不回落環境自動發現**：
// 「環境恰有可用 ADC」在本產品的部署形態下代表撿到不該用的憑證。
func NewClient(ctx context.Context, s Settings) (*Client, error) {
	if _, err := s.Scope.ResolveKey(s.KeyID); err != nil {
		return nil, err
	}
	if len(s.ServiceAccountJSON) == 0 {
		return nil, ErrAuthentication
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := rejectEndpointEnv(); err != nil {
		return nil, err
	}
	base := secureTransport()
	return newClient(ctx, s, resolveExplicit(s.ServiceAccountJSON), tlsTransport{base: base}, base.CloseIdleConnections)
}

// Only package tests replace the resolver and the network boundary.
func newClient(ctx context.Context, s Settings, resolve adcResolver, base http.RoundTripper, closeBase func()) (*Client, error) {
	if closeBase == nil {
		closeBase = func() {}
	}
	fail := func(err error) (*Client, error) { closeBase(); return nil, err }
	if _, err := s.Scope.ResolveKey(s.KeyID); err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if err := rejectEndpointEnv(); err != nil {
		return fail(err)
	}
	authenticated, err := resolve(ctx, destinationGuard{next: base})
	if err != nil || authenticated == nil {
		if ctx.Err() != nil {
			return fail(ctx.Err())
		}
		return fail(ErrAuthentication)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	hc := &http.Client{Transport: destinationGuard{next: authenticated}, CheckRedirect: rejectRedirect, Timeout: operationTimeout}
	sdk, err := kms.NewKeyManagementRESTClient(ctx, option.WithHTTPClient(hc), option.WithLogger(quietLogger()), option.WithTelemetryDisabled())
	if err != nil {
		return fail(safeError(err))
	}
	lifetime, cancel := context.WithCancel(ctx)
	return &Client{sdk: sdk, scope: s.Scope, lifetime: lifetime, cancel: cancel, closeBase: closeBase}, nil
}

func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.cancel()
		c.mu.Unlock()
		c.active.Wait()
		_ = c.sdk.Close()
		c.closeBase()
	})
	return nil
}

func (c *Client) begin(ctx context.Context) (context.Context, func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, nil, ErrClosed
	}
	if err := c.lifetime.Err(); err != nil {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	c.active.Add(1)
	call, cancel := context.WithTimeout(ctx, operationTimeout)
	stop := context.AfterFunc(c.lifetime, cancel)
	return call, func() { stop(); cancel(); c.active.Done() }, nil
}

func safeError(err error) error {
	if err == nil {
		return nil
	}
	for _, safe := range []error{context.Canceled, context.DeadlineExceeded, ErrEndpoint, ErrClosed, ErrAuthentication, ErrPermission, ErrUnavailable} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	var apiErr *googleapi.Error
	if errors.As(err, &apiErr) {
		if apiErr.Code == http.StatusUnauthorized {
			return ErrAuthentication
		}
		if apiErr.Code == http.StatusForbidden {
			return ErrPermission
		}
	}
	switch status.Code(err) {
	case codes.Unauthenticated:
		return ErrAuthentication
	case codes.PermissionDenied:
		return ErrPermission
	case codes.Canceled:
		return context.Canceled
	case codes.DeadlineExceeded:
		return context.DeadlineExceeded
	}
	return ErrUnavailable
}

// Retries are bounded by the operation deadline; automatic SDK retries are disabled.
// Integrity failures are rejected without returning any payload to the caller.
func noRetry() gax.CallOption { return gax.WithRetry(func() gax.Retryer { return nil }) }
func (c *Client) GetCryptoKey(ctx context.Context, r *kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	if r == nil {
		return nil, ErrKeyRef
	}
	if _, err := c.scope.ResolveKey(r.Name); err != nil {
		return nil, err
	}
	ctx, done, err := c.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	out, err := c.sdk.GetCryptoKey(ctx, r, noRetry())
	if err != nil {
		return nil, safeError(err)
	}
	return out, nil
}
func (c *Client) Encrypt(ctx context.Context, r *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
	if r == nil {
		return nil, ErrKeyRef
	}
	if _, err := c.scope.ResolveKey(r.Name); err != nil {
		return nil, err
	}
	ctx, done, err := c.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	out, err := c.sdk.Encrypt(ctx, r, noRetry())
	if err != nil {
		return nil, safeError(err)
	}
	return out, nil
}
func (c *Client) Decrypt(ctx context.Context, r *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
	if r == nil {
		return nil, ErrKeyRef
	}
	if _, err := c.scope.ResolveKey(r.Name); err != nil {
		return nil, err
	}
	ctx, done, err := c.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	out, err := c.sdk.Decrypt(ctx, r, noRetry())
	if err != nil {
		return nil, safeError(err)
	}
	return out, nil
}
