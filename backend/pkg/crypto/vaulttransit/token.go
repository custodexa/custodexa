package vaulttransit

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

type timer interface {
	channel() <-chan time.Time
	stop()
}
type clock interface {
	now() time.Time
	timer(time.Duration) timer
}
type wallClock struct{}
type wallTimer struct{ t *time.Timer }

func (wallClock) now() time.Time              { return time.Now() }
func (wallClock) timer(d time.Duration) timer { return wallTimer{time.NewTimer(d)} }
func (t wallTimer) channel() <-chan time.Time { return t.t.C }
func (t wallTimer) stop()                     { t.t.Stop() }

type authEnvelope struct {
	Auth *authData `json:"auth"`
}
type authData struct {
	Token     string `json:"client_token"`
	Duration  int64  `json:"lease_duration"`
	Renewable *bool  `json:"renewable"`
}

// Client owns exactly one renewal worker. Providers borrow it and never close it.
// The assembly owner must cancel the supplied lifetime or call Close and wait.
type Client struct {
	wire             *adapter
	scope            Scope
	roleID, secretID string
	// directToken 為真代表本 client 走直接權杖路徑：沒有可重試的登入，
	// 權杖失效即終局（見 Settings.Token）。
	directToken bool
	clock            clock
	life             context.Context
	cancel           context.CancelFunc
	done             chan struct{}
	wake             chan struct{}
	mu               sync.Mutex
	token            string
	expiry, next     time.Time
	renewable        bool
	retries          int
	terminal         bool
}

func NewClient(lifetime context.Context, s Settings) (*Client, error) {
	scope, _, err := ResolveScope(s.Address, s.KeyID)
	if err != nil || scope != s.Scope {
		return nil, ErrOutsideScope
	}
	wire, err := productionAdapter(scope.Origin())
	if err != nil {
		return nil, err
	}
	return startClient(lifetime, s, wire, wallClock{})
}

func startClient(lifetime context.Context, s Settings, wire *adapter, clk clock) (*Client, error) {
	// 兩條路徑**恰一**：同時提供或都不提供皆為組態矛盾，不做優先序猜測。
	byRole := s.RoleID != "" && s.SecretID != ""
	byToken := s.Token != ""
	if lifetime == nil || lifetime.Err() != nil || wire == nil || clk == nil || byRole == byToken {
		return nil, ErrAuth
	}
	life, cancel := context.WithCancel(lifetime)
	c := &Client{wire: wire, scope: s.Scope, roleID: s.RoleID, secretID: s.SecretID, clock: clk,
		life: life, cancel: cancel, done: make(chan struct{}), wake: make(chan struct{}, 1)}
	var err error
	if byToken {
		c.directToken = true
		err = c.adoptTokenLocked(s.Token)
	} else {
		err = c.loginLocked()
	}
	if err != nil {
		cancel()
		wire.http.CloseIdleConnections()
		return nil, err
	}
	go c.run()
	return c, nil
}

// tokenLookupEnvelope 是 /v1/auth/token/lookup-self 的回應形狀。
type tokenLookupEnvelope struct {
	Data *tokenLookupData `json:"data"`
}
type tokenLookupData struct {
	TTL       int64 `json:"ttl"`
	Renewable *bool `json:"renewable"`
}

// maxDirectTokenLease 直接權杖在回報 TTL 為 0（不過期）時採用的租期上限。
//
// **不把「不過期」表示為無限**：續期迴圈以 expiry 為終止條件，無限值會讓它
// 永遠不再檢查權杖是否仍被接受。取一年為上界使 client 至少每年重新確認一次；
// 真正的失效偵測仍由每次呼叫的 401／403 承擔（見 call 的 ErrDenied 分支）。
const maxDirectTokenLease = 86400 * 366

// adoptTokenLocked 接手直接提供的權杖：以 lookup-self 取得其租期與可續期性。
//
// **不接受「看起來像權杖就用」**：沒有 lookup-self 的確認就無從得知租期，
// 續期排程會落空而權杖在毫無訊號的情況下過期。查詢失敗即終局。
func (c *Client) adoptTokenLocked(token string) error {
	if strings.TrimSpace(token) == "" || strings.ContainsAny(token, "\r\n") {
		c.terminal = true
		return ErrAuth
	}
	var result tokenLookupEnvelope
	start := c.clock.now()
	err := c.wire.call(c.life, "GET", "/v1/auth/token/lookup-self", token, struct{}{}, &result)
	if err != nil || result.Data == nil || result.Data.Renewable == nil {
		c.token = ""
		c.terminal = true
		return ErrAuth
	}
	ttl, renewable := result.Data.TTL, *result.Data.Renewable
	if ttl <= 0 {
		ttl, renewable = maxDirectTokenLease, false
	}
	auth := &authData{Token: token, Duration: ttl, Renewable: &renewable}
	if c.installLocked(auth, start) != nil {
		c.token = ""
		c.terminal = true
		return ErrAuth
	}
	return nil
}

func (c *Client) installLocked(auth *authData, start time.Time) error {
	if auth == nil || strings.TrimSpace(auth.Token) == "" || strings.ContainsAny(auth.Token, "\r\n") || auth.Duration <= 0 || auth.Duration > 86400*366 || auth.Renewable == nil {
		return ErrAuth
	}
	expiry := start.Add(time.Duration(auth.Duration) * time.Second)
	if !c.clock.now().Before(expiry) || c.life.Err() != nil {
		return ErrAuth
	}
	c.token, c.expiry, c.renewable = auth.Token, expiry, *auth.Renewable
	c.next = start.Add(time.Duration(auth.Duration) * time.Second / 2)
	if !c.renewable {
		c.next = expiry
	}
	c.retries = 0
	return nil
}

func (c *Client) loginLocked() error {
	var result authEnvelope
	start := c.clock.now()
	err := c.wire.call(c.life, "POST", "/v1/auth/approle/login", "", map[string]string{"role_id": c.roleID, "secret_id": c.secretID}, &result)
	if err != nil || c.installLocked(result.Auth, start) != nil {
		c.token = ""
		c.terminal = true
		return ErrAuth
	}
	return nil
}

func (c *Client) run() {
	defer close(c.done)
	defer c.wire.http.CloseIdleConnections()
	defer func() {
		c.mu.Lock()
		c.token = ""
		c.roleID = ""
		c.secretID = ""
		c.terminal = true
		c.mu.Unlock()
	}()
	for {
		c.mu.Lock()
		if c.terminal || c.life.Err() != nil {
			c.mu.Unlock()
			return
		}
		now := c.clock.now()
		if !now.Before(c.expiry) || c.token == "" {
			// 直接權杖路徑沒有可重試的登入：失效即終局，**不以角色識別補位**。
			if c.directToken {
				c.token = ""
				c.terminal = true
				c.mu.Unlock()
				return
			}
			// A failed re-login is terminal, rather than a credential retry loop.
			if c.loginLocked() != nil {
				c.mu.Unlock()
				return
			}
		} else if !now.Before(c.next) && c.renewable {
			var result authEnvelope
			start := now
			err := c.wire.call(c.life, "POST", "/v1/auth/token/renew-self", c.token, struct{}{}, &result)
			if err == nil {
				err = c.installLocked(result.Auth, start)
			}
			if err != nil {
				var remote *wireError
				retryable := errors.Is(err, ErrTransport) || errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &remote) && remote.retryable())
				if !retryable {
					c.token = ""
					c.expiry = c.clock.now()
					c.next = c.expiry
				} else {
					c.retries++
					c.next = c.expiry
					if c.retries <= 2 {
						remaining := c.expiry.Sub(c.clock.now())
						delay := time.Second
						if remaining/2 < delay {
							delay = remaining / 2
						}
						c.next = c.clock.now().Add(delay)
					}
				}
			}
		}
		delay := c.next.Sub(c.clock.now())
		if delay < 0 {
			delay = 0
		}
		tick := c.clock.timer(delay)
		c.mu.Unlock()
		select {
		case <-c.life.Done():
			tick.stop()
			return
		case <-c.wake:
			tick.stop()
		case <-tick.channel():
			tick.stop()
		}
	}
}

func (c *Client) Close() { c.cancel(); <-c.done }

func (c *Client) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *Client) call(ctx context.Context, method, path string, input, output any) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	c.mu.Lock()
	if c.life.Err() != nil {
		c.mu.Unlock()
		return ErrClosed
	}
	if c.terminal || c.token == "" || !c.clock.now().Before(c.expiry) {
		c.mu.Unlock()
		c.signal()
		return ErrAuth
	}
	token := c.token
	c.mu.Unlock()
	linked, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.life, cancel)
	defer func() { stop(); cancel() }()
	err := c.wire.call(linked, method, path, token, input, output)
	c.mu.Lock()
	defer c.mu.Unlock()
	var remote *wireError
	if errors.As(err, &remote) && (remote.status == 401 || remote.status == 403) {
		if c.token == token {
			c.token = ""
			c.expiry = c.clock.now()
			c.signal()
		}
		return ErrDenied
	}
	if c.life.Err() != nil {
		return ErrClosed
	}
	if c.terminal || c.token != token || !c.clock.now().Before(c.expiry) {
		return ErrAuth
	}
	return err
}

// MatchesDeployment avoids copying credential ownership into assembly closures.
func (c *Client) MatchesDeployment(s Settings) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.life.Err() != nil || c.terminal || s.Scope != c.scope || s.Address != c.scope.Origin() {
		return false
	}
	// 權杖路徑與角色路徑不可互認：兩者的失效語義不同，把一方的 settings 餵給
	// 另一方建構出的 client 會讓「失效後能不能重新登入」這件事變成偶然。
	if c.directToken {
		return s.UsesToken()
	}
	return !s.UsesToken() && s.RoleID == c.roleID && s.SecretID == c.secretID
}
