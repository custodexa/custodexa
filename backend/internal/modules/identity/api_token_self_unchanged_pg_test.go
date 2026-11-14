package identity

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// token 對所屬帳號本人送出「值與現況相同」的受保護欄位時放行，但這次請求不寫該欄位：
// 讀到現值、判定為未變更之後，其他請求可能已提交新值，寫回讀到的值會把新值蓋回去。
// 兩個交錯以停點固定，token 與管理者各由一個獨立連線池驅動（＝兩個後端副本），在 PostgreSQL 上跑。
//
//	TEST_PG_DSN="..." REQUIRE_INTEGRATION=1 go test ./internal/modules/identity -run 'APIToken.*PG'

// pointGate 在指定停點擋住第一個走到的呼叫；之後再走到同一停點的呼叫直接通過。
type pointGate struct {
	mu      sync.Mutex
	points  map[string]*pointHold
	cleanup func()
}

type pointHold struct {
	once    sync.Once
	reached chan struct{}
	release chan struct{}
	freed   sync.Once
}

func newPointGate(t *testing.T, names ...string) *pointGate {
	t.Helper()
	g := &pointGate{points: map[string]*pointHold{}}
	for _, n := range names {
		g.points[n] = &pointHold{reached: make(chan struct{}), release: make(chan struct{})}
	}
	restore := SetLockOrderHookForTest(func(point string, _ *gorm.DB, _ ...uint) {
		g.mu.Lock()
		h := g.points[point]
		g.mu.Unlock()
		if h == nil {
			return
		}
		first := false
		h.once.Do(func() { first = true; close(h.reached) })
		if first {
			<-h.release
		}
	})
	// 斷言失敗時也放行被擋住的交易，否則 schema 清理會等鎖而掛住整包測試
	t.Cleanup(func() {
		for _, h := range g.points {
			h.freed.Do(func() { close(h.release) })
		}
		restore()
	})
	return g
}

func (g *pointGate) await(t *testing.T, name string) {
	t.Helper()
	select {
	case <-g.points[name].reached:
	case <-time.After(5 * time.Second):
		t.Fatalf("token 的請求未走到停點 %s", name)
	}
}

func (g *pointGate) release(name string) {
	h := g.points[name]
	h.freed.Do(func() { close(h.release) })
}

func (e *apiTokenPGEnv) tokenSelfOp(t *testing.T) Operator {
	t.Helper()
	return Operator{UserID: e.owner, Username: "owner", ClientIP: "127.0.0.1",
		Principal: filteredPrincipalOf(t, e.dbA, e.owner, e.roles["identity_admin"])}
}

func (e *apiTokenPGEnv) usersOn(db *gorm.DB) *UserService {
	u := NewUserService(db, nil)
	u.SetAssignmentGuard(NewAssignmentGuard(FullCatalog()))
	u.SetProtectedAccountOps(NewProtectedAccountOps(audit.NewTxSink(), audit.NewSystemAlertSink(nil)))
	u.authzRevoker = noopRevoker{}
	return u
}

func (e *apiTokenPGEnv) ownerRow(t *testing.T) model.User {
	t.Helper()
	var u model.User
	require.NoError(t, e.dbA.First(&u, e.owner).Error)
	return u
}

// TestAPITokenSelfCIDRsUnchangedDoesNotOverwriteConcurrentChangePG token 以本人送來與現值相同的允許來源網段：
// token 的請求讀到 A、送出 B；管理者先把 A 改成 B 並提交，token 在交易內讀到 B（未變更、放行）；
// 管理者接著把 B 收緊為 C 並提交，token 才寫入。最後落地的是管理者的 C，token 的其他欄位照常寫入，
// 回傳的變更差異不含來源網段（稽核不會記成 token 改了來源網段）。
func TestAPITokenSelfCIDRsUnchangedDoesNotOverwriteConcurrentChangePG(t *testing.T) {
	e := newAPITokenPGEnv(t)
	tokenUsers := e.usersOn(e.dbA)
	admin := e.op(e.root)
	cidrs := func(v ...string) *UpdateUserRequest { return &UpdateUserRequest{AllowedCIDRs: &v} }

	_, _, err := e.usersB.Update(admin, e.owner, cidrs("10.0.0.0/8"))
	require.NoError(t, err)
	a := e.ownerRow(t).AllowedCIDRs
	_, _, err = e.usersB.Update(admin, e.owner, cidrs("10.0.0.0/8", "198.51.100.0/24"))
	require.NoError(t, err)
	b := e.ownerRow(t).AllowedCIDRs
	_, _, err = e.usersB.Update(admin, e.owner, cidrs("10.0.0.0/8"))
	require.NoError(t, err)
	require.Equal(t, a, e.ownerRow(t).AllowedCIDRs)

	gate := newPointGate(t, "user_update_before_tx", "user_update_token_self_cidrs_checked")
	type result struct {
		diff map[string]string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		bv := []string{"10.0.0.0/8", "198.51.100.0/24"}
		_, diff, err := tokenUsers.Update(e.tokenSelfOp(t), e.owner, &UpdateUserRequest{FullName: "renamed-by-token", AllowedCIDRs: &bv})
		done <- result{diff, err}
	}()

	gate.await(t, "user_update_before_tx") // token 已讀到 A、決定送出 B，尚未進交易
	_, _, err = e.usersB.Update(admin, e.owner, cidrs("10.0.0.0/8", "198.51.100.0/24"))
	require.NoError(t, err)
	require.Equal(t, b, e.ownerRow(t).AllowedCIDRs)
	gate.release("user_update_before_tx")

	gate.await(t, "user_update_token_self_cidrs_checked") // token 在交易內讀到 B，判定未變更
	_, _, err = e.usersB.Update(admin, e.owner, cidrs("172.16.0.0/12"))
	require.NoError(t, err, "token 的判定不持有帳號列鎖，管理者的收緊應可提交")
	c := e.ownerRow(t).AllowedCIDRs
	require.NotEqual(t, b, c)
	gate.release("user_update_token_self_cidrs_checked")

	var r result
	select {
	case r = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("token 的請求沒有完成")
	}
	require.NoError(t, r.err, "值與交易內現值相同，token 的請求應放行")
	final := e.ownerRow(t)
	assert.Equal(t, c, final.AllowedCIDRs, "最後落地的應是管理者收緊後的值，不得被 token 寫回")
	assert.Equal(t, "renamed-by-token", final.FullName, "同一請求的其他欄位照常寫入")
	assert.NotContains(t, r.diff, "allowed_cidrs.before", "變更差異不含來源網段")
	assert.NotContains(t, r.diff, "allowed_cidrs.after")
	assert.Equal(t, "renamed-by-token", r.diff["full_name.after"])
}

// TestAPITokenSelfMFADisableNotEnrolledDoesNotClearConcurrentEnrollmentPG token 對未啟用兩步驟驗證的本人送出停用：
// token 在交易內讀到未啟用（不是實際變更、放行）之後，本人完成註冊並提交；token 不寫入，註冊保留。
func TestAPITokenSelfMFADisableNotEnrolledDoesNotClearConcurrentEnrollmentPG(t *testing.T) {
	e := newAPITokenPGEnv(t)
	auth := &AuthService{}
	auth.SetEpochGateDB(e.dbA)
	auth.SetProtectedAccountOps(NewProtectedAccountOps(audit.NewTxSink(), audit.NewSystemAlertSink(nil)))

	gate := newPointGate(t, "mfa_disable_token_self_checked")
	done := make(chan error, 1)
	go func() { done <- auth.AdminDisableMFABy(e.tokenSelfOp(t), e.owner) }()

	gate.await(t, "mfa_disable_token_self_checked")
	require.NoError(t, e.dbB.Model(&model.User{}).Where("id = ?", e.owner).
		Updates(map[string]any{"totp_enabled": true, "totp_secret_enc": "enrolled-during-check"}).Error,
		"token 的判定不持有帳號列鎖，本人的註冊應可提交")
	gate.release("mfa_disable_token_self_checked")

	select {
	case err := <-done:
		require.NoError(t, err, "讀到未啟用：不是實際變更，應放行")
	case <-time.After(10 * time.Second):
		t.Fatal("token 的請求沒有完成")
	}
	u := e.ownerRow(t)
	assert.True(t, u.TOTPEnabled, "讀取之後完成的註冊不得被清除")
	assert.Equal(t, "enrolled-during-check", u.TOTPSecretEnc)
}
