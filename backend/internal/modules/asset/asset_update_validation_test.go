package asset

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
)

// 資產更新套用建立時的欄位規則：規則的任一依賴欄位有效值改變、且更新後違規才拒絕；同值重送不算改變；
// 檢核以交易內重讀（必要時重套）後的結果判定，並在任何寫入之前完成。

func setupUpdateValidationDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&model.Asset{}, &model.AuditLog{}, &model.AssetGroup{}, &model.AssetNode{},
		&model.AssetAuthorization{}, &model.AssetAccount{}, &model.Credential{}, &model.CredentialSecretVersion{}))
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })
	return db
}

type uvFixture struct {
	t   *testing.T
	db  *gorm.DB
	svc *AssetService
}

func newUpdateValidationFixture(t *testing.T) *uvFixture {
	db := setupUpdateValidationDB(t)
	svc := newLifecycleService(t)
	svc.SetAssetWriteScopePort(allowAllAssetWriteScope{})
	return &uvFixture{t: t, db: db, svc: svc}
}

func (f *uvFixture) asset(a model.Asset) model.Asset {
	f.t.Helper()
	a.Host = "198.51.100.40"
	require.NoError(f.t, f.db.Create(&a).Error)
	return a
}

// account 直接寫表建一筆掛載與其專用憑證。
func (f *uvFixture) account(assetID uint, username, purpose string, isDefault bool) {
	f.t.Helper()
	cred := model.Credential{Scope: model.CredentialScopeDedicated, Username: username}
	require.NoError(f.t, f.db.Create(&cred).Error)
	require.NoError(f.t, f.db.Create(&model.AssetAccount{AssetID: assetID, CredentialID: cred.ID, Username: username,
		IsDefault: isDefault, Purpose: purpose}).Error)
}

func (f *uvFixture) counts() map[string]int64 {
	f.t.Helper()
	out := map[string]int64{}
	for _, tbl := range []string{"assets", "asset_accounts", "credentials", "credential_secret_versions", "audit_logs"} {
		var n int64
		require.NoError(f.t, f.db.Table(tbl).Count(&n).Error)
		out[tbl] = n
	}
	return out
}

func (f *uvFixture) load(id uint) model.Asset {
	f.t.Helper()
	var a model.Asset
	require.NoError(f.t, f.db.First(&a, id).Error)
	return a
}

func intp(i int) *int { return &i }

// uvCtx 操作者持有全部欄位能力（相容並列能力，不另做憑證語義的目標判定）。
func uvCtx() context.Context {
	return WithFieldCapability(context.Background(), func(string) FieldCapGrant { return FieldCapViaCompat })
}
func protop(p model.ProtocolType) *model.ProtocolType {
	return &p
}

// expectRejected 被拒：回指定錯誤，資產列、帳號、憑證、密文版本與稽核列皆無寫入。
func (f *uvFixture) expectRejected(id uint, req *UpdateAssetRequest, want error) {
	f.t.Helper()
	before, counts := f.load(id), f.counts()
	_, err := f.svc.Update(uvCtx(), id, req)
	require.True(f.t, errors.Is(err, want), "應回 %v，得 %v", want, err)
	after := f.load(id)
	assert.Equal(f.t, counts, f.counts(), "被拒的更新不得寫入任何列")
	assert.True(f.t, before.UpdatedAt.Equal(after.UpdatedAt), "資產列不得改動")
	assert.Equal(f.t, before.Port, after.Port)
	assert.Equal(f.t, before.Protocol, after.Protocol)
	assert.Equal(f.t, before.Username, after.Username)
	assert.Equal(f.t, before.HasPassword, after.HasPassword)
}

func (f *uvFixture) expectAccepted(id uint, req *UpdateAssetRequest) model.Asset {
	f.t.Helper()
	_, err := f.svc.Update(uvCtx(), id, req)
	require.NoError(f.t, err)
	return f.load(id)
}

// TestUpdateValidation_DesignCases design 案例表的八種情形（埠號拒絕另含 0 與 70000 兩個值）。
func TestUpdateValidation_DesignCases(t *testing.T) {
	t.Run("1_valid_port_changed_to_zero_or_70000", func(t *testing.T) {
		for _, p := range []int{0, 70000} {
			f := newUpdateValidationFixture(t)
			a := f.asset(model.Asset{Name: "p", Protocol: model.ProtocolSSH, Port: 22})
			f.expectRejected(a.ID, &UpdateAssetRequest{Port: intp(p)}, ErrAssetPortOutOfRange)
		}
	})
	t.Run("2_legacy_bad_port_description_edit_resending_protocol_and_port", func(t *testing.T) {
		f := newUpdateValidationFixture(t)
		a := f.asset(model.Asset{Name: "legacy", Protocol: model.ProtocolSSH, Port: 70000})
		got := f.expectAccepted(a.ID, &UpdateAssetRequest{Description: strp("edited"), Protocol: protop(model.ProtocolSSH), Port: intp(70000)})
		assert.Equal(t, "edited", got.Description)
		assert.Equal(t, 70000, got.Port, "既有壞值原樣保留")
	})
	t.Run("3_legacy_bad_port_changed_to_another_bad_port", func(t *testing.T) {
		f := newUpdateValidationFixture(t)
		a := f.asset(model.Asset{Name: "legacy", Protocol: model.ProtocolSSH, Port: 70000})
		f.expectRejected(a.ID, &UpdateAssetRequest{Port: intp(0)}, ErrAssetPortOutOfRange)
	})
	t.Run("4_ssh_with_password_clears_username", func(t *testing.T) {
		f := newUpdateValidationFixture(t)
		a := f.asset(model.Asset{Name: "ssh", Protocol: model.ProtocolSSH, Port: 22, Username: "root", HasPassword: true})
		f.account(a.ID, "root", model.AccountPurposeLogin, true)
		f.expectRejected(a.ID, &UpdateAssetRequest{Username: strp("")}, ErrUsernameRequired)
	})
	t.Run("5_vnc_password_only_switches_to_ssh", func(t *testing.T) {
		f := newUpdateValidationFixture(t)
		a := f.asset(model.Asset{Name: "vnc", Protocol: model.ProtocolVNC, Port: 5900, HasPassword: true})
		f.account(a.ID, "", model.AccountPurposeLogin, true)
		f.expectRejected(a.ID, &UpdateAssetRequest{Protocol: protop(model.ProtocolSSH)}, ErrUsernameRequired)
	})
	t.Run("6_ssh_without_credentials_gets_password_only", func(t *testing.T) {
		f := newUpdateValidationFixture(t)
		a := f.asset(model.Asset{Name: "bare", Protocol: model.ProtocolSSH, Port: 22})
		f.expectRejected(a.ID, &UpdateAssetRequest{Password: strp("fixture-only-secret")}, ErrUsernameRequired)
	})
	t.Run("7_vnc_password_only_keeps_empty_username", func(t *testing.T) {
		f := newUpdateValidationFixture(t)
		a := f.asset(model.Asset{Name: "vnc", Protocol: model.ProtocolVNC, Port: 5900, HasPassword: true})
		f.account(a.ID, "", model.AccountPurposeLogin, true)
		got := f.expectAccepted(a.ID, &UpdateAssetRequest{Username: strp(""), Description: strp("vnc edit")})
		assert.Equal(t, "vnc edit", got.Description)
	})
	t.Run("8_zero_login_accounts_or_executor_only_description_edit", func(t *testing.T) {
		f := newUpdateValidationFixture(t)
		zero := f.asset(model.Asset{Name: "zero", Protocol: model.ProtocolSSH, Port: 22})
		exec := f.asset(model.Asset{Name: "exec", Protocol: model.ProtocolSSH, Port: 22})
		f.account(exec.ID, "svc-exec", model.AccountPurposeExecutor, false)
		for _, id := range []uint{zero.ID, exec.ID} {
			got := f.expectAccepted(id, &UpdateAssetRequest{Description: strp("pending is legal")})
			assert.Equal(t, "pending is legal", got.Description)
		}
	})
}

// TestUpdateValidation_EdgeCases 依賴集合的邊界：同值重送、已有秘密時換一組新秘密、合法的埠號變更、
// 預設帳號引用共用憑證時帳號名稱規則不適用。
func TestUpdateValidation_EdgeCases(t *testing.T) {
	t.Run("same_value_port_resend_with_valid_port", func(t *testing.T) {
		f := newUpdateValidationFixture(t)
		a := f.asset(model.Asset{Name: "p", Protocol: model.ProtocolSSH, Port: 22})
		f.expectAccepted(a.ID, &UpdateAssetRequest{Port: intp(22)})
		got := f.expectAccepted(a.ID, &UpdateAssetRequest{Port: intp(2222)})
		assert.Equal(t, 2222, got.Port)
	})
	t.Run("legacy_bad_port_fixed_to_valid", func(t *testing.T) {
		f := newUpdateValidationFixture(t)
		a := f.asset(model.Asset{Name: "legacy", Protocol: model.ProtocolSSH, Port: 70000})
		got := f.expectAccepted(a.ID, &UpdateAssetRequest{Port: intp(22)})
		assert.Equal(t, 22, got.Port)
	})
	t.Run("legacy_empty_username_with_password_unrelated_edit", func(t *testing.T) {
		// 既有的「SSH、有密碼、沒有帳號名稱」：只改描述、原樣重送協定，依賴欄位沒變，不擋
		f := newUpdateValidationFixture(t)
		a := f.asset(model.Asset{Name: "legacy-user", Protocol: model.ProtocolSSH, Port: 22, HasPassword: true})
		f.account(a.ID, "", model.AccountPurposeLogin, true)
		f.expectAccepted(a.ID, &UpdateAssetRequest{Description: strp("x"), Protocol: protop(model.ProtocolSSH), Username: strp("")})
	})
	t.Run("shared_credential_default_account_is_exempt", func(t *testing.T) {
		f := newUpdateValidationFixture(t)
		a := f.asset(model.Asset{Name: "vnc-shared", Protocol: model.ProtocolVNC, Port: 5900, HasPassword: true})
		cred := model.Credential{Scope: model.CredentialScopeShared, Name: strp("shared-login"), Username: ""}
		require.NoError(t, f.db.Create(&cred).Error)
		require.NoError(t, f.db.Create(&model.AssetAccount{AssetID: a.ID, CredentialID: cred.ID, IsDefault: true,
			Purpose: model.AccountPurposeLogin}).Error)
		got := f.expectAccepted(a.ID, &UpdateAssetRequest{Protocol: protop(model.ProtocolSSH)})
		assert.Equal(t, model.ProtocolSSH, got.Protocol)
	})
}

// TestUpdateValidation_RebasedResult 交易外讀取之後列被他人改過時，更新以交易內重讀的列重套請求；
// 檢核以重套後的結果判定。以同交易內、鎖定重讀之前的寫入模擬另一個已提交的修改。
func TestUpdateValidation_RebasedResult(t *testing.T) {
	f := newUpdateValidationFixture(t)
	a := f.asset(model.Asset{Name: "rebase", Protocol: model.ProtocolSSH, Port: 22, Username: "root"})
	fired := false
	require.NoError(t, f.db.Callback().Query().Before("gorm:query").Register("test:concurrent_clear_username", func(db *gorm.DB) {
		if fired || db.Statement.Table != "assets" {
			return
		}
		if _, locking := db.Statement.Clauses["FOR"]; !locking {
			return
		}
		fired = true
		// 另一位操作者清空帳號名稱（交易外讀取之後、本交易鎖定重讀之前）
		require.NoError(t, db.Session(&gorm.Session{NewDB: true}).Exec(
			`UPDATE assets SET username = '', updated_at = ? WHERE id = ?`, time.Now().Add(time.Second), a.ID).Error)
	}))
	t.Cleanup(func() { _ = f.db.Callback().Query().Remove("test:concurrent_clear_username") })

	counts := f.counts()
	// 交易外的基底帳號名稱為 root，帶入密碼看似合法；重套到已清空帳號名稱的列後違規
	_, err := f.svc.Update(uvCtx(), a.ID, &UpdateAssetRequest{Password: strp("fixture-only-secret")})
	require.True(t, fired, "前提：鎖定重讀之前確實插入了另一個修改")
	require.True(t, errors.Is(err, ErrUsernameRequired), "應以重套後的結果判定並拒絕，得 %v", err)
	assert.Equal(t, counts, f.counts(), "被拒的更新不得寫入任何列")
	got := f.load(a.ID)
	assert.False(t, got.HasPassword)
	// 模擬的修改在被拒的交易內，一併回滾：資產維持原狀
	assert.Equal(t, "root", got.Username)
}
