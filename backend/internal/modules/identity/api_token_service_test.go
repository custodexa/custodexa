package identity

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// API token 的建立、撤銷、清單投影（服務層）。

// recordingTokenEvents 測試用留痕落地面：記下事件；fail 為真時回錯以驗證整筆回滾。
type recordingTokenEvents struct {
	mu      sync.Mutex
	created []APITokenCreatedEvent
	revoked []APITokenRevokedEvent
	fail    bool
}

func (r *recordingTokenEvents) APITokenCreated(_ *gorm.DB, ev APITokenCreatedEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail {
		return errors.New("recorder down")
	}
	r.created = append(r.created, ev)
	return nil
}

func (r *recordingTokenEvents) APITokenRevoked(_ *gorm.DB, ev APITokenRevokedEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail {
		return errors.New("recorder down")
	}
	r.revoked = append(r.revoked, ev)
	return nil
}

func (r *recordingTokenEvents) revokedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.revoked)
}

type tokenEnv struct {
	*acctEnv
	tokens *APITokenService
	events *recordingTokenEvents
	gen    *string
	clock  time.Time
}

func newTokenEnv(t *testing.T) *tokenEnv {
	t.Helper()
	a := newAcctEnv(t, nil)
	require.NoError(t, a.db.AutoMigrate(&model.APIToken{}, &model.APITokenRole{}, &model.UserRoleMapping{},
		&model.UserGroupMember{}, &model.UserGroupRole{}, &model.SecurityPolicy{}))
	a.users.authzRevoker = noopRevoker{}
	ev := &recordingTokenEvents{}
	gen := "gen-1"
	e := &tokenEnv{acctEnv: a, events: ev, gen: &gen, clock: time.Date(2026, 11, 14, 8, 0, 0, 0, time.UTC)}
	e.tokens = NewAPITokenService(a.db, ev)
	e.tokens.now = func() time.Time { return e.clock }
	e.tokens.SetRestoreGenerationSource(func(*gorm.DB) (string, error) { return *e.gen, nil })
	return e
}

func (e *tokenEnv) future(d time.Duration) *time.Time {
	at := e.clock.Add(d)
	return &at
}

func (e *tokenEnv) mustCreate(t *testing.T, owner uint, name string, roles ...uint) *CreatedAPIToken {
	t.Helper()
	got, err := e.tokens.Create(e.op(owner), CreateAPITokenInput{Name: name, RoleIDs: roles, NeverExpires: true})
	require.NoError(t, err)
	return got
}

func (e *tokenEnv) tokenRows(t *testing.T, owner uint) []model.APIToken {
	t.Helper()
	var rows []model.APIToken
	require.NoError(t, e.db.Where("user_id = ?", owner).Order("id").Find(&rows).Error)
	return rows
}

func (e *tokenEnv) viewOf(t *testing.T, owner, tokenID uint) APITokenView {
	t.Helper()
	views, err := e.tokens.ListForUser(owner)
	require.NoError(t, err)
	for _, v := range views {
		if v.ID == tokenID {
			return v
		}
	}
	t.Fatalf("token %d 不在清單中", tokenID)
	return APITokenView{}
}

func assertTokenErr(t *testing.T, err error, want *APITokenError) {
	t.Helper()
	var te *APITokenError
	require.True(t, errors.As(err, &te), "want %s, got %v", want.Code, err)
	assert.Equal(t, want.Code, te.Code)
	assert.Equal(t, want.Status, te.Status)
}

// ── 4.1 建立 ─────────────────────────────────────────────

func TestAPITokenCreateStoresDigestOnlyAndReturnsPlaintextOnce(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	got, err := e.tokens.Create(e.op(owner), CreateAPITokenInput{Name: "terraform", RoleIDs: []uint{e.roles["identity_admin"]}, ExpiresAt: e.future(30 * 24 * time.Hour)})
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(got.Token, APITokenPrefix))
	assert.Greater(t, len(got.Token), len(APITokenPrefix)+40, "明文帶 256 位元亂數")
	rows := e.tokenRows(t, owner)
	require.Len(t, rows, 1)
	assert.Equal(t, apiTokenDigest(got.Token), rows[0].TokenHash)
	assert.NotContains(t, rows[0].TokenHash, APITokenPrefix, "資料庫不存明文")
	assert.Equal(t, "gen-1", rows[0].RestoreGeneration, "記建立當下的還原世代")
	assert.Equal(t, APITokenStatusActive, got.View.Status)
	require.Len(t, got.View.GrantedRoles, 1)
	assert.True(t, got.View.GrantedRoles[0].Effective)
	// 同一把再建一次得到不同明文
	other, err := e.tokens.Create(e.op(owner), CreateAPITokenInput{Name: "other", RoleIDs: []uint{e.roles["identity_admin"]}, NeverExpires: true})
	require.NoError(t, err)
	assert.NotEqual(t, got.Token, other.Token)
	// 留痕事件不含明文或雜湊
	require.Len(t, e.events.created, 2)
	ev := e.events.created[0]
	assert.Equal(t, owner, ev.OwnerID)
	assert.Equal(t, "terraform", ev.Name)
	for _, s := range []string{ev.Name, ev.OwnerUsername} {
		assert.NotContains(t, s, got.Token)
		assert.NotContains(t, s, rows[0].TokenHash)
	}
}

func TestAPITokenCreateExpiryInPastRejected(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	_, err := e.tokens.Create(e.op(owner), CreateAPITokenInput{Name: "n", RoleIDs: []uint{e.roles["identity_admin"]}, ExpiresAt: e.future(-time.Second)})
	assertTokenErr(t, err, ErrAPITokenExpiryInvalid)
	assert.Empty(t, e.tokenRows(t, owner))
}

func TestAPITokenCreateExpiryEqualToNowRejected(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	_, err := e.tokens.Create(e.op(owner), CreateAPITokenInput{Name: "n", RoleIDs: []uint{e.roles["identity_admin"]}, ExpiresAt: e.future(0)})
	assertTokenErr(t, err, ErrAPITokenExpiryInvalid)
	assert.Empty(t, e.tokenRows(t, owner))
}

func TestAPITokenCreateExpiryAndNeverExpiresTogetherRejected(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	_, err := e.tokens.Create(e.op(owner), CreateAPITokenInput{Name: "n", RoleIDs: []uint{e.roles["identity_admin"]}, ExpiresAt: e.future(time.Hour), NeverExpires: true})
	assertTokenErr(t, err, ErrAPITokenExpiryInvalid)
	_, err = e.tokens.Create(e.op(owner), CreateAPITokenInput{Name: "n", RoleIDs: []uint{e.roles["identity_admin"]}})
	assertTokenErr(t, err, ErrAPITokenExpiryRequired)
	assert.Empty(t, e.tokenRows(t, owner))
	// 永不到期：expires_at 為空
	got := e.mustCreate(t, owner, "never", e.roles["identity_admin"])
	assert.Nil(t, got.View.ExpiresAt)
}

func TestAPITokenCreateNameLengthCountsCharactersNotBytes(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	name100 := strings.Repeat("名", 100)
	require.Greater(t, len(name100), 100, "多位元組字元的位元組數超過 100")
	got := e.mustCreate(t, owner, name100, e.roles["identity_admin"])
	assert.Equal(t, name100, got.View.Name)
	_, err := e.tokens.Create(e.op(owner), CreateAPITokenInput{Name: strings.Repeat("名", 101), RoleIDs: []uint{e.roles["identity_admin"]}, NeverExpires: true})
	assertTokenErr(t, err, ErrAPITokenNameInvalid)
	for _, bad := range []string{"", "   ", "a\tb", "a\x00b"} {
		_, err := e.tokens.Create(e.op(owner), CreateAPITokenInput{Name: bad, RoleIDs: []uint{e.roles["identity_admin"]}, NeverExpires: true})
		assertTokenErr(t, err, ErrAPITokenNameInvalid)
	}
	assert.Len(t, e.tokenRows(t, owner), 1)
}

func TestAPITokenCreateRoleRules(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin", "user")
	_, err := e.tokens.Create(e.op(owner), CreateAPITokenInput{Name: "n", NeverExpires: true})
	assertTokenErr(t, err, ErrAPITokenRoleRequired)
	// 本人未持有的角色
	_, err = e.tokens.Create(e.op(owner), CreateAPITokenInput{Name: "n", RoleIDs: []uint{e.roles["identity_admin"], e.roles["security_admin"]}, NeverExpires: true})
	assertTokenErr(t, err, ErrAPITokenRoleNotGrantable)
	// 本人持有但不屬管理類的角色
	_, err = e.tokens.Create(e.op(owner), CreateAPITokenInput{Name: "n", RoleIDs: []uint{e.roles["user"]}, NeverExpires: true})
	assertTokenErr(t, err, ErrAPITokenRoleNotGrantable)
	assert.Empty(t, e.tokenRows(t, owner), "整筆拒絕，不留任何列")
	// 只選部分角色
	both := e.mkUser(t, "both", "identity_admin", "security_admin")
	got := e.mustCreate(t, both, "partial", e.roles["security_admin"])
	require.Len(t, got.View.GrantedRoles, 1)
	assert.Equal(t, e.roles["security_admin"], got.View.GrantedRoles[0].RoleID)
	assert.True(t, got.View.Privileged, "授權含系統安全管理員")
	assert.Equal(t, []string{model.BuiltinSecurityAdmin}, e.events.created[0].PrivilegedKeys)
}

func TestAPITokenCreateRequiresManagementRole(t *testing.T) {
	e := newTokenEnv(t)
	plain := e.mkUser(t, "plain", "user")
	elig, err := e.tokens.Eligibility(plain)
	require.NoError(t, err)
	assert.False(t, elig.CanCreate)
	assert.Equal(t, APITokenIneligibleNoManagementRole, elig.Reason)
	require.Len(t, elig.NonGrantableRoles, 1)
	_, err = e.tokens.Create(e.op(plain), CreateAPITokenInput{Name: "n", RoleIDs: []uint{e.roles["user"]}, NeverExpires: true})
	assertTokenErr(t, err, ErrAPITokenNotEligible)
	assert.Empty(t, e.tokenRows(t, plain))

	agent := e.agent(t, "bot")
	require.NoError(t, e.db.Create(&model.UserRole{UserID: agent, RoleID: e.roles["identity_admin"], Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
	elig, err = e.tokens.Eligibility(agent)
	require.NoError(t, err)
	assert.Equal(t, APITokenIneligibleNotHuman, elig.Reason)
	_, err = e.tokens.Create(e.op(agent), CreateAPITokenInput{Name: "n", RoleIDs: []uint{e.roles["identity_admin"]}, NeverExpires: true})
	assertTokenErr(t, err, ErrAPITokenNotEligible)
}

// TestAPITokenCreateEligibilityRecheckedInTransaction 資格與授權角色以交易內現值判定，不沿用請求開始時解析的主體。
func TestAPITokenCreateEligibilityRecheckedInTransaction(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin", "security_admin")
	stale := e.op(owner)
	stale.Principal = principalOf(t, e.db, owner) // 請求開始時解析：仍持兩個角色
	require.NoError(t, e.db.Where("user_id = ? AND role_id = ?", owner, e.roles["security_admin"]).Delete(&model.UserRole{}).Error)
	_, err := e.tokens.Create(stale, CreateAPITokenInput{Name: "n", RoleIDs: []uint{e.roles["security_admin"]}, NeverExpires: true})
	assertTokenErr(t, err, ErrAPITokenRoleNotGrantable)
	require.NoError(t, e.db.Where("user_id = ?", owner).Delete(&model.UserRole{}).Error)
	_, err = e.tokens.Create(stale, CreateAPITokenInput{Name: "n", RoleIDs: []uint{e.roles["identity_admin"]}, NeverExpires: true})
	assertTokenErr(t, err, ErrAPITokenNotEligible)
	assert.Empty(t, e.tokenRows(t, owner))
}

func TestAPITokenCreateRejectsTokenAndNonRequestOperators(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	in := CreateAPITokenInput{Name: "n", RoleIDs: []uint{e.roles["identity_admin"]}, NeverExpires: true}
	_, err := e.tokens.Create(e.tokenOp(t, owner, e.roles["identity_admin"]), in)
	assertTokenErr(t, err, ErrAPITokenCredentialForbidden)
	_, err = e.tokens.Create(Operator{UserID: owner, Username: "owner"}, in)
	assertTokenErr(t, err, ErrAPITokenOperatorRequired)
	_, err = e.tokens.Create(systemOperator(), in)
	assertTokenErr(t, err, ErrAPITokenOperatorRequired)
	assert.Empty(t, e.tokenRows(t, owner))
	// 未注入留痕落地面即拒絕寫入
	bare := NewAPITokenService(e.db, nil)
	_, err = bare.Create(e.op(owner), in)
	require.ErrorIs(t, err, errAPITokenRecorderMissing)
	assert.Empty(t, e.tokenRows(t, owner))
}

func TestAPITokenCreateSuspendedSameNameRejected(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin", "security_admin")
	first := e.mustCreate(t, owner, "terraform-apply", e.roles["security_admin"])
	// 授權角色被收回：暫停中，仍占用名稱
	require.NoError(t, e.db.Where("user_id = ? AND role_id = ?", owner, e.roles["security_admin"]).Delete(&model.UserRole{}).Error)
	assert.Equal(t, APITokenStatusSuspendedRolesRevoked, e.viewOf(t, owner, first.View.ID).Status)
	_, err := e.tokens.Create(e.op(owner), CreateAPITokenInput{Name: "terraform-apply", RoleIDs: []uint{e.roles["identity_admin"]}, NeverExpires: true})
	assertTokenErr(t, err, ErrAPITokenNameConflict)
	// 可用的同名同樣被拒；不同帳號的同名不受影響
	_, err = e.tokens.Create(e.op(owner), CreateAPITokenInput{Name: "terraform-apply", RoleIDs: []uint{e.roles["identity_admin"]}, ExpiresAt: e.future(time.Hour)})
	assertTokenErr(t, err, ErrAPITokenNameConflict)
	other := e.mkUser(t, "other", "identity_admin")
	e.mustCreate(t, other, "terraform-apply", e.roles["identity_admin"])
	assert.Len(t, e.tokenRows(t, owner), 1)
}

func TestAPITokenCreateRevokedExpiredOrRestoreInvalidatedNameReusable(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	ida := e.roles["identity_admin"]
	revoked := e.mustCreate(t, owner, "revoked-name", ida)
	require.NoError(t, e.tokens.RevokeOwn(e.op(owner), revoked.View.ID, ""))
	e.mustCreate(t, owner, "revoked-name", ida)

	_, err := e.tokens.Create(e.op(owner), CreateAPITokenInput{Name: "expired-name", RoleIDs: []uint{ida}, ExpiresAt: e.future(time.Hour)})
	require.NoError(t, err)
	e.clock = e.clock.Add(2 * time.Hour)
	e.mustCreate(t, owner, "expired-name", ida)

	e.mustCreate(t, owner, "restored-name", ida)
	*e.gen = "gen-2" // 以管理腳本還原備份：世代改變
	e.mustCreate(t, owner, "restored-name", ida)
	assert.Len(t, e.tokenRows(t, owner), 6)
}

// TestAPITokenCreateFailureRollsBackAllRows 留痕失敗時整筆回滾：token 列與授權角色列都不留。
func TestAPITokenCreateFailureRollsBackAllRows(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	e.events.fail = true
	_, err := e.tokens.Create(e.op(owner), CreateAPITokenInput{Name: "n", RoleIDs: []uint{e.roles["identity_admin"]}, NeverExpires: true})
	require.Error(t, err)
	var n int64
	require.NoError(t, e.db.Model(&model.APIToken{}).Count(&n).Error)
	assert.Zero(t, n)
	require.NoError(t, e.db.Model(&model.APITokenRole{}).Count(&n).Error)
	assert.Zero(t, n)
	e.events.fail = false
	e.mustCreate(t, owner, "n", e.roles["identity_admin"])
}

// ── 4.3 撤銷 ─────────────────────────────────────────────

func TestAPITokenRevokeOwnRecordsRevokerAndNote(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	got := e.mustCreate(t, owner, "n", e.roles["identity_admin"])
	require.NoError(t, e.tokens.RevokeOwn(e.op(owner), got.View.ID, "  rotated  "))
	v := e.viewOf(t, owner, got.View.ID)
	assert.Equal(t, APITokenStatusRevoked, v.Status)
	require.NotNil(t, v.RevokedBy)
	assert.Equal(t, owner, v.RevokedBy.UserID)
	assert.Equal(t, "owner", v.RevokedBy.Username)
	assert.Equal(t, "rotated", v.RevokeNote)
	assert.Equal(t, 1, e.events.revokedCount())
	// 他人的 token 與不存在的 token 同形
	other := e.mkUser(t, "other", "identity_admin")
	foreign := e.mustCreate(t, other, "x", e.roles["identity_admin"])
	assert.ErrorIs(t, e.tokens.RevokeOwn(e.op(owner), foreign.View.ID, ""), ErrAPITokenNotFound)
	assert.ErrorIs(t, e.tokens.RevokeOwn(e.op(owner), 99999, ""), ErrAPITokenNotFound)
	assert.Equal(t, APITokenStatusActive, e.viewOf(t, other, foreign.View.ID).Status)
	// 原因上限
	assertTokenErr(t, e.tokens.RevokeOwn(e.op(other), foreign.View.ID, strings.Repeat("字", APITokenNoteMaxRunes+1)), ErrAPITokenNoteTooLong)
	require.NoError(t, e.tokens.RevokeOwn(e.op(other), foreign.View.ID, strings.Repeat("字", APITokenNoteMaxRunes)))
}

// TestAPITokenRevokeRepeatedKeepsRecordAndSkipsAudit 重複撤銷不覆寫紀錄、不另寫留痕。
func TestAPITokenRevokeRepeatedKeepsRecordAndSkipsAudit(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	admin := e.admin
	got := e.mustCreate(t, owner, "n", e.roles["identity_admin"])
	require.NoError(t, e.tokens.RevokeOwn(e.op(owner), got.View.ID, "first"))
	before := e.tokenRows(t, owner)[0]
	e.clock = e.clock.Add(time.Hour)
	require.NoError(t, e.tokens.RevokeOwn(e.op(owner), got.View.ID, "second"))
	require.NoError(t, e.tokens.RevokeForUser(e.op(admin), owner, got.View.ID, "third"))
	after := e.tokenRows(t, owner)[0]
	assert.Equal(t, before.RevokedAt.UTC(), after.RevokedAt.UTC())
	assert.Equal(t, *before.RevokedBy, *after.RevokedBy)
	assert.Equal(t, "first", after.RevokeNote)
	assert.Equal(t, 1, e.events.revokedCount(), "重複撤銷不另寫留痕")
	n, err := e.tokens.RevokeAllForUser(e.op(admin), owner, "")
	require.NoError(t, err)
	assert.Zero(t, n)
	assert.Equal(t, 1, e.events.revokedCount())
}

// TestAPITokenRevokeProtectedAccountRequiresSuperAdmin 對象持超級管理者或系統安全管理員身分時，他人撤銷只限超級管理者。
func TestAPITokenRevokeProtectedAccountRequiresSuperAdmin(t *testing.T) {
	e := newTokenEnv(t)
	ida := e.mkUser(t, "ida", "identity_admin")
	superOwner := e.mkUser(t, "sa-owner", "admin", "identity_admin")
	secOwner := e.mkUser(t, "sec-owner", "security_admin")
	plainOwner := e.mkUser(t, "plain-owner", "identity_admin")
	superTok := e.mustCreate(t, superOwner, "s", e.roles["identity_admin"])
	secTok := e.mustCreate(t, secOwner, "s", e.roles["security_admin"])
	plainTok := e.mustCreate(t, plainOwner, "p", e.roles["identity_admin"])

	assertCode(t, e.tokens.RevokeForUser(e.op(ida), superOwner, superTok.View.ID, ""), apierror.CodeAuthProtectedAccountOperation)
	assertCode(t, e.tokens.RevokeForUser(e.op(ida), secOwner, secTok.View.ID, ""), apierror.CodeAuthProtectedAccountOperation)
	_, err := e.tokens.RevokeAllForUser(e.op(ida), superOwner, "")
	assertCode(t, err, apierror.CodeAuthProtectedAccountOperation)
	assert.Equal(t, APITokenStatusActive, e.viewOf(t, superOwner, superTok.View.ID).Status, "被拒時 token 仍可使用")
	assert.Equal(t, APITokenStatusActive, e.viewOf(t, secOwner, secTok.View.ID).Status)
	// 帶限定的超管操作者（token 未授權超級管理者角色）同樣不是超管
	assertTokenErr(t, e.tokens.RevokeForUser(Operator{UserID: e.admin, Username: "root", Principal: filteredPrincipalOf(t, e.db, e.admin)}, superOwner, superTok.View.ID, ""), ErrAPITokenCredentialForbidden)

	require.NoError(t, e.tokens.RevokeForUser(e.op(ida), plainOwner, plainTok.View.ID, "by admin"))
	require.NoError(t, e.tokens.RevokeForUser(e.op(e.admin), superOwner, superTok.View.ID, ""))
	require.NoError(t, e.tokens.RevokeForUser(e.op(e.admin), secOwner, secTok.View.ID, ""))
	v := e.viewOf(t, plainOwner, plainTok.View.ID)
	require.NotNil(t, v.RevokedBy)
	assert.Equal(t, ida, v.RevokedBy.UserID, "本人的清單顯示是誰撤銷的")
	assert.Equal(t, "by admin", v.RevokeNote)
}

func TestAPITokenRevokeAllForUserCountsUsableOnly(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin", "security_admin")
	ida, sec := e.roles["identity_admin"], e.roles["security_admin"]
	e.mustCreate(t, owner, "a", ida)
	suspended := e.mustCreate(t, owner, "suspended", sec)
	old := e.mustCreate(t, owner, "restore", ida)
	_, err := e.tokens.Create(e.op(owner), CreateAPITokenInput{Name: "short", RoleIDs: []uint{ida}, ExpiresAt: e.future(time.Minute)})
	require.NoError(t, err)
	done := e.mustCreate(t, owner, "done", ida)
	require.NoError(t, e.tokens.RevokeOwn(e.op(owner), done.View.ID, ""))
	require.NoError(t, e.db.Model(&model.APIToken{}).Where("id = ?", old.View.ID).Update("restore_generation", "gen-0").Error)
	require.NoError(t, e.db.Where("user_id = ? AND role_id = ?", owner, sec).Delete(&model.UserRole{}).Error)
	e.clock = e.clock.Add(time.Hour)

	n, err := e.tokens.RevokeAllForUser(e.op(e.admin), owner, "offboarding")
	require.NoError(t, err)
	assert.Equal(t, 2, n, "可用的一把與暫停中的一把；已到期、已因還原失效、已撤銷的不算")
	assert.Equal(t, APITokenStatusRevoked, e.viewOf(t, owner, suspended.View.ID).Status)
	assert.Equal(t, APITokenStatusInvalidatedByRestore, e.viewOf(t, owner, old.View.ID).Status)
}

func TestAPITokenRevokeRejectsTokenOperator(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	got := e.mustCreate(t, owner, "n", e.roles["identity_admin"])
	assertTokenErr(t, e.tokens.RevokeOwn(e.tokenOp(t, owner, e.roles["identity_admin"]), got.View.ID, ""), ErrAPITokenCredentialForbidden)
	_, err := e.tokens.RevokeAllForUser(e.tokenOp(t, e.admin, e.roles["admin"]), owner, "")
	assertTokenErr(t, err, ErrAPITokenCredentialForbidden)
	assert.Equal(t, APITokenStatusActive, e.viewOf(t, owner, got.View.ID).Status)
}

// TestAPITokenAccountDeleteMarksTokensRevoked 刪除帳號時同交易標記其 token；撤銷者為刪除的操作者。
func TestAPITokenAccountDeleteMarksTokensRevoked(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	a := e.mustCreate(t, owner, "a", e.roles["identity_admin"])
	b := e.mustCreate(t, owner, "b", e.roles["identity_admin"])
	require.NoError(t, e.tokens.RevokeOwn(e.op(owner), b.View.ID, "kept"))
	bystander := e.mkUser(t, "bystander", "identity_admin")
	c := e.mustCreate(t, bystander, "c", e.roles["identity_admin"])

	_, err := e.users.DeleteWithSummaryBy(e.op(e.admin), owner)
	require.NoError(t, err)
	rows := e.tokenRows(t, owner)
	require.Len(t, rows, 2)
	for _, r := range rows {
		require.NotNil(t, r.RevokedAt, "token %d 未標記", r.ID)
	}
	assert.Equal(t, e.admin, *rows[0].RevokedBy)
	assert.Equal(t, owner, *rows[1].RevokedBy, "已撤銷的不覆寫")
	assert.Equal(t, "kept", rows[1].RevokeNote)
	_ = a
	assert.Nil(t, e.tokenRows(t, bystander)[0].RevokedAt, "其他帳號不受影響")
	assert.Equal(t, APITokenStatusActive, e.viewOf(t, bystander, c.View.ID).Status)
}

// ── 4.4 清單投影 ─────────────────────────────────────────

func TestAPITokenStatusActive(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	got, err := e.tokens.Create(e.op(owner), CreateAPITokenInput{Name: "n", RoleIDs: []uint{e.roles["identity_admin"]}, ExpiresAt: e.future(8 * 24 * time.Hour)})
	require.NoError(t, err)
	assert.Equal(t, APITokenStatusActive, e.viewOf(t, owner, got.View.ID).Status)
}

func TestAPITokenStatusExpiringSoon(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	got, err := e.tokens.Create(e.op(owner), CreateAPITokenInput{Name: "n", RoleIDs: []uint{e.roles["identity_admin"]}, ExpiresAt: e.future(7 * 24 * time.Hour)})
	require.NoError(t, err)
	assert.Equal(t, APITokenStatusExpiringSoon, e.viewOf(t, owner, got.View.ID).Status, "7 天內到期")
}

func TestAPITokenStatusExpired(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	got, err := e.tokens.Create(e.op(owner), CreateAPITokenInput{Name: "n", RoleIDs: []uint{e.roles["identity_admin"]}, ExpiresAt: e.future(time.Hour)})
	require.NoError(t, err)
	e.clock = e.clock.Add(time.Hour)
	assert.Equal(t, APITokenStatusExpired, e.viewOf(t, owner, got.View.ID).Status)
}

func TestAPITokenStatusRevoked(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	got := e.mustCreate(t, owner, "n", e.roles["identity_admin"])
	require.NoError(t, e.tokens.RevokeOwn(e.op(owner), got.View.ID, ""))
	assert.Equal(t, APITokenStatusRevoked, e.viewOf(t, owner, got.View.ID).Status)
}

func TestAPITokenStatusInvalidatedByRestore(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	got := e.mustCreate(t, owner, "n", e.roles["identity_admin"])
	*e.gen = "gen-2"
	assert.Equal(t, APITokenStatusInvalidatedByRestore, e.viewOf(t, owner, got.View.ID).Status)
}

func TestAPITokenStatusSuspendedAccountDisabled(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	got := e.mustCreate(t, owner, "n", e.roles["identity_admin"])
	require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", owner).Update("active", false).Error)
	assert.Equal(t, APITokenStatusSuspendedAccountDisabled, e.viewOf(t, owner, got.View.ID).Status)
	require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", owner).Update("active", true).Error)
	assert.Equal(t, APITokenStatusActive, e.viewOf(t, owner, got.View.ID).Status, "重新啟用後恢復")
}

func TestAPITokenStatusSuspendedRolesRevoked(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	got := e.mustCreate(t, owner, "n", e.roles["identity_admin"])
	require.NoError(t, e.db.Where("user_id = ?", owner).Delete(&model.UserRole{}).Error)
	v := e.viewOf(t, owner, got.View.ID)
	assert.Equal(t, APITokenStatusSuspendedRolesRevoked, v.Status)
	assert.False(t, v.GrantedRoles[0].Effective)
	assert.Nil(t, v.GrantedRoles[0].Scope)
	require.NoError(t, e.db.Create(&model.UserRole{UserID: owner, RoleID: e.roles["identity_admin"], Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
	assert.Equal(t, APITokenStatusActive, e.viewOf(t, owner, got.View.ID).Status, "指派回來即恢復")
}

// TestAPITokenStatusPriorityWhenMultipleApply 同時符合多種狀態時依優先序取最前者。
func TestAPITokenStatusPriorityWhenMultipleApply(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	got, err := e.tokens.Create(e.op(owner), CreateAPITokenInput{Name: "n", RoleIDs: []uint{e.roles["identity_admin"]}, ExpiresAt: e.future(time.Hour)})
	require.NoError(t, err)
	// 已到期且帳號停用：已到期
	e.clock = e.clock.Add(2 * time.Hour)
	require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", owner).Update("active", false).Error)
	assert.Equal(t, APITokenStatusExpired, e.viewOf(t, owner, got.View.ID).Status)

	now := e.clock
	past, soon := now.Add(-time.Minute), now.Add(time.Hour)
	revokedAt := now
	cases := []struct {
		name          string
		tok           model.APIToken
		active, roles bool
		want          APITokenStatus
	}{
		{"撤銷優先於還原失效", model.APIToken{RevokedAt: &revokedAt, RestoreGeneration: "old", ExpiresAt: &past}, false, false, APITokenStatusRevoked},
		{"還原失效優先於到期", model.APIToken{RestoreGeneration: "old", ExpiresAt: &past}, false, false, APITokenStatusInvalidatedByRestore},
		{"到期優先於帳號停用", model.APIToken{RestoreGeneration: "cur", ExpiresAt: &past}, false, false, APITokenStatusExpired},
		{"帳號停用優先於角色收回", model.APIToken{RestoreGeneration: "cur", ExpiresAt: &soon}, false, false, APITokenStatusSuspendedAccountDisabled},
		{"角色收回優先於即將到期", model.APIToken{RestoreGeneration: "cur", ExpiresAt: &soon}, true, false, APITokenStatusSuspendedRolesRevoked},
		{"即將到期優先於有效", model.APIToken{RestoreGeneration: "cur", ExpiresAt: &soon}, true, true, APITokenStatusExpiringSoon},
		{"永不到期", model.APIToken{RestoreGeneration: "cur"}, true, true, APITokenStatusActive},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, apiTokenStatusOf(c.tok, c.active, c.roles, "cur", now), c.name)
	}
}

// TestAPITokenEffectiveRoleDualSource 同一角色同時經直接與群組取得時，收回其中一個不影響有效判定。
func TestAPITokenEffectiveRoleDualSource(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	g := model.UserGroup{Name: "ops"}
	require.NoError(t, e.db.Create(&g).Error)
	require.NoError(t, e.db.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: owner, Manual: true}).Error)
	require.NoError(t, e.db.Create(&model.UserGroupRole{UserGroupID: g.ID, RoleID: e.roles["identity_admin"], ScopeKind: model.ScopeKindGlobal, CreatedAt: time.Now()}).Error)
	got := e.mustCreate(t, owner, "n", e.roles["identity_admin"])

	require.NoError(t, e.db.Where("user_id = ?", owner).Delete(&model.UserRole{}).Error)
	v := e.viewOf(t, owner, got.View.ID)
	assert.True(t, v.GrantedRoles[0].Effective, "群組來源仍在")
	assert.Equal(t, APITokenStatusActive, v.Status)
	require.NoError(t, e.db.Where("user_group_id = ?", g.ID).Delete(&model.UserGroupRole{}).Error)
	v = e.viewOf(t, owner, got.View.ID)
	assert.False(t, v.GrantedRoles[0].Effective, "兩個來源都收回")
	assert.Equal(t, APITokenStatusSuspendedRolesRevoked, v.Status)
}

// TestAPITokenEffectiveRoleNodeScopeAndDeletedRole 節點範圍跟隨本人；範圍內節點全數消失即不生效；
// 被刪除的角色仍列出並保留名稱。
func TestAPITokenEffectiveRoleNodeScopeAndDeletedRole(t *testing.T) {
	e := newTokenEnv(t)
	assetMgr := e.create(t, "asset-mgr", "asset:view", "asset:update")
	owner := e.mkUser(t, "owner", "identity_admin")
	n1, n2 := model.AssetGroup{Name: "n1"}, model.AssetGroup{Name: "n2"}
	require.NoError(t, e.db.Create(&n1).Error)
	require.NoError(t, e.db.Create(&n2).Error)
	require.NoError(t, e.db.Create(&model.UserRole{UserID: owner, RoleID: assetMgr.ID, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindNodes}).Error)
	for _, n := range []uint{n2.ID, n1.ID} {
		require.NoError(t, e.db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser, SubjectID: owner, RoleID: assetMgr.ID, NodeID: n}).Error)
	}
	got := e.mustCreate(t, owner, "n", assetMgr.ID, e.roles["identity_admin"])
	v := e.viewOf(t, owner, got.View.ID)
	byID := map[uint]APITokenRoleView{}
	for _, r := range v.GrantedRoles {
		byID[r.RoleID] = r
	}
	require.True(t, byID[assetMgr.ID].Effective)
	assert.Equal(t, model.ScopeKindNodes, byID[assetMgr.ID].Scope.Kind)
	assert.Equal(t, []uint{n1.ID, n2.ID}, byID[assetMgr.ID].Scope.NodeIDs)
	assert.Equal(t, model.ScopeKindGlobal, byID[e.roles["identity_admin"]].Scope.Kind)

	require.NoError(t, e.db.Delete(&n1).Error)
	v = e.viewOf(t, owner, got.View.ID)
	for _, r := range v.GrantedRoles {
		if r.RoleID == assetMgr.ID {
			assert.Equal(t, []uint{n2.ID}, r.Scope.NodeIDs, "範圍跟隨本人")
		}
	}
	require.NoError(t, e.db.Delete(&n2).Error)
	v = e.viewOf(t, owner, got.View.ID)
	for _, r := range v.GrantedRoles {
		if r.RoleID == assetMgr.ID {
			assert.False(t, r.Effective, "範圍內節點全數消失即不生效")
			assert.Nil(t, r.Scope)
		}
	}
	assert.Equal(t, APITokenStatusActive, v.Status, "另一個授權角色仍有效")

	// 角色刪除（與角色定義服務的刪除同形：名稱接上刪除字尾以釋出名稱，再軟刪）：
	// 清單與稽核詳情仍列出並保留刪除前的名稱，不顯示刪除字尾
	require.NoError(t, e.db.Where("user_id = ? AND role_id = ?", owner, assetMgr.ID).Delete(&model.UserRole{}).Error)
	require.NoError(t, e.db.Model(&model.Role{}).Where("id = ?", assetMgr.ID).Update("name", "asset-mgr"+deletedRoleNameSuffix(assetMgr.ID)).Error)
	require.NoError(t, e.db.Delete(&model.Role{}, assetMgr.ID).Error)
	ref, err := e.tokens.AuditRef(got.View.ID)
	require.NoError(t, err)
	for _, r := range ref.GrantedRoles {
		if r.RoleID == assetMgr.ID {
			assert.Equal(t, "asset-mgr", r.Name, "稽核詳情的授權角色名稱不含刪除字尾")
		}
	}
	v = e.viewOf(t, owner, got.View.ID)
	found := false
	for _, r := range v.GrantedRoles {
		if r.RoleID == assetMgr.ID {
			found = true
			assert.Equal(t, "asset-mgr", r.Name)
			assert.False(t, r.Effective)
		}
	}
	assert.True(t, found)
}

func TestAPITokenListNeverExposesSecret(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	got := e.mustCreate(t, owner, "n", e.roles["identity_admin"])
	views, err := e.tokens.ListForUser(owner)
	require.NoError(t, err)
	require.Len(t, views, 1)
	digest := e.tokenRows(t, owner)[0].TokenHash
	for _, s := range []string{views[0].Name, views[0].LastUsedIP, views[0].RevokeNote} {
		assert.NotContains(t, s, got.Token)
		assert.NotContains(t, s, digest)
	}
}
