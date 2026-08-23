package identity

import (
	"github.com/custodexa/backend/internal/modules/policy"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// 登入時密碼 gate 測試：沿用 setupLockoutEnv 的
// sqlite in-memory 環境（單 goroutine 循序讀寫，無 :memory: 連線池風險）。
// 出廠政策：min_length=12、require_alnum=true、max_age=0（關閉）

func seedGateUser(t *testing.T, db *gorm.DB, password string, mutate func(*model.User)) *model.User {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	user := &model.User{Username: "gate-user", Email: strPtr("g@x"), Password: string(hash), Active: true}
	if mutate != nil {
		mutate(user)
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user
}

func loginGate(t *testing.T, auth *AuthService, password string) *LoginResponse {
	t.Helper()
	resp, err := auth.Login(&LoginRequest{Username: "gate-user", Password: password})
	if err != nil {
		t.Fatalf("Login err = %v", err)
	}
	return resp
}

func TestLoginGateTooShortIntercepted(t *testing.T) {
	auth, _, db := setupLockoutEnv(t)
	seedGateUser(t, db, "admin123", nil) // 8 碼 < 政策 12，正是出廠預設密碼情境

	resp := loginGate(t, auth, "admin123")
	if !resp.PasswordChangeRequired || resp.Token != "" {
		t.Fatalf("應進強制改密且不發正式 token，got %+v", resp)
	}
	if resp.PasswordChangeReason != PasswordChangeReasonNoncompliant {
		t.Errorf("reason = %q, want policy_noncompliant", resp.PasswordChangeReason)
	}
	if resp.ReasonCode != apierror.CodePasswordTooShort {
		t.Errorf("reason_code = %q, want CodePasswordTooShort", resp.ReasonCode)
	}
	if resp.ReasonParams["min"] != 12 {
		t.Errorf("reason_params.min = %v, want 12", resp.ReasonParams["min"])
	}
	if resp.PolicyNoncompliantCategory == "" {
		t.Error("偵測類別應非空（供 handler 落審計）")
	}
	if resp.ChangeToken == "" || resp.PolicyHint == "" {
		t.Error("應附 change_token 與 policy_hint")
	}

	var reloaded model.User
	db.First(&reloaded, "username = ?", "gate-user")
	if !reloaded.MustChangePassword {
		t.Error("合規命中應持久化 must_change_password = true")
	}
}

func TestLoginGateComplexityIntercepted(t *testing.T) {
	auth, _, db := setupLockoutEnv(t)
	seedGateUser(t, db, "abcdefghijkl", nil) // 12 碼純字母，缺數字

	resp := loginGate(t, auth, "abcdefghijkl")
	if resp.PasswordChangeReason != PasswordChangeReasonNoncompliant {
		t.Fatalf("reason = %q, want policy_noncompliant", resp.PasswordChangeReason)
	}
	if resp.ReasonCode != apierror.CodePasswordComplexity {
		t.Errorf("reason_code = %q, want CodePasswordComplexity", resp.ReasonCode)
	}
}

func TestLoginGateCompliantUnaffected(t *testing.T) {
	auth, _, db := setupLockoutEnv(t)
	now := time.Now()
	seedGateUser(t, db, "compliant-pw-99", func(u *model.User) { u.PasswordChangedAt = &now })

	resp := loginGate(t, auth, "compliant-pw-99")
	if resp.PasswordChangeRequired || resp.PasswordChangeReason != "" {
		t.Fatalf("合規者不應觸發 gate，got %+v", resp)
	}
	if resp.Token == "" {
		t.Error("應正常發放 token")
	}
	var reloaded model.User
	db.First(&reloaded, "username = ?", "gate-user")
	if reloaded.MustChangePassword {
		t.Error("合規者不應被標記改密")
	}
}

func TestLoginGateExpiredIntercepted(t *testing.T) {
	auth, policies, db := setupLockoutEnv(t)
	policies.Update(policy.PolicyPasswordMaxAgeDays, "90", "admin")
	old := time.Now().AddDate(0, 0, -91)
	seedGateUser(t, db, "compliant-pw-99", func(u *model.User) { u.PasswordChangedAt = &old })

	resp := loginGate(t, auth, "compliant-pw-99")
	if resp.PasswordChangeReason != PasswordChangeReasonExpired {
		t.Fatalf("reason = %q, want password_expired", resp.PasswordChangeReason)
	}
	// 過期是時間戳的純函數，不寫旗標（雙重事實源禁止，改密即自然解除）
	var reloaded model.User
	db.First(&reloaded, "username = ?", "gate-user")
	if reloaded.MustChangePassword {
		t.Error("過期觸發不應寫 must_change_password")
	}
}

func TestLoginGateMaxAgeDisabledSkipsExpiry(t *testing.T) {
	auth, _, db := setupLockoutEnv(t)
	// 出廠 max_age=0：NULL 時間戳也不評估
	seedGateUser(t, db, "compliant-pw-99", nil)

	resp := loginGate(t, auth, "compliant-pw-99")
	if resp.PasswordChangeRequired {
		t.Fatalf("政策關閉時不應觸發過期 gate，got %+v", resp)
	}
}

func TestLoginGateNullTimestampTreatedExpired(t *testing.T) {
	auth, policies, db := setupLockoutEnv(t)
	policies.Update(policy.PolicyPasswordMaxAgeDays, "90", "admin")
	seedGateUser(t, db, "compliant-pw-99", nil) // PasswordChangedAt 為 NULL（legacy 列）

	resp := loginGate(t, auth, "compliant-pw-99")
	if resp.PasswordChangeReason != PasswordChangeReasonExpired {
		t.Fatalf("NULL 時間戳應視為已過期（fail-secure），reason = %q", resp.PasswordChangeReason)
	}
}

func TestLoginGateLDAPSkipped(t *testing.T) {
	auth, policies, db := setupLockoutEnv(t)
	policies.Update(policy.PolicyPasswordMaxAgeDays, "90", "admin")
	// LDAP 用戶：旗標 true＋NULL 時間戳＋佔位 hash 全部命中條件，仍不得觸發。
	// Login 的 LDAP 路徑需目錄連線，此處直測 finishLogin（gate 所在地）
	user := seedGateUser(t, db, "x1", func(u *model.User) {
		u.IsLDAP = true
		u.MustChangePassword = true
	})

	resp, err := auth.finishLogin(user, nil, crypto.AuthContext{})
	if err != nil {
		t.Fatalf("finishLogin err = %v", err)
	}
	if resp.PasswordChangeRequired {
		t.Fatalf("LDAP 用戶不應觸發任何密碼 gate，got %+v", resp)
	}
	if resp.Token == "" {
		t.Error("LDAP 用戶應正常發放 token")
	}
}

func TestLoginGatePersistIdempotentAndFlagPriority(t *testing.T) {
	auth, _, db := setupLockoutEnv(t)
	seedGateUser(t, db, "admin123", nil)

	// 第一次：偵測＋持久化，reason 帶具體違規
	first := loginGate(t, auth, "admin123")
	if first.PasswordChangeReason != PasswordChangeReasonNoncompliant {
		t.Fatalf("first reason = %q", first.PasswordChangeReason)
	}

	// 第二次：旗標已 true，偵測跳過（不重複寫入），依優先序回 must_change
	second := loginGate(t, auth, "admin123")
	if second.PasswordChangeReason != PasswordChangeReasonMustChange {
		t.Errorf("second reason = %q, want must_change（旗標優先）", second.PasswordChangeReason)
	}
	if second.PolicyNoncompliantCategory != "" {
		t.Error("旗標已 true 不應重複偵測（不重複落審計）")
	}
}

func TestLoginGateHistoryNotEvaluated(t *testing.T) {
	auth, policies, db := setupLockoutEnv(t)
	policies.Update(policy.PolicyPasswordHistoryCount, "4", "admin")
	user := seedGateUser(t, db, "compliant-pw-99", func(u *model.User) {
		now := time.Now()
		u.PasswordChangedAt = &now
	})
	// 現行密碼寫入歷史（慣例：每次設密都入歷史）
	if err := db.Create(&model.PasswordHistory{UserID: user.ID, PasswordHash: user.Password}).Error; err != nil {
		t.Fatalf("seed history: %v", err)
	}

	resp := loginGate(t, auth, "compliant-pw-99")
	if resp.PasswordChangeRequired {
		t.Fatalf("歷史政策不得於登入評估（現行密碼必在歷史內），got %+v", resp)
	}
}

func TestLoginGateNoncompliantBeatsExpired(t *testing.T) {
	auth, policies, db := setupLockoutEnv(t)
	policies.Update(policy.PolicyPasswordMaxAgeDays, "90", "admin")
	seedGateUser(t, db, "admin123", nil) // 同時：不合規＋NULL 時間戳過期

	resp := loginGate(t, auth, "admin123")
	if resp.PasswordChangeReason != PasswordChangeReasonNoncompliant {
		t.Fatalf("多源命中應回合規原因（帶具體指引），got %q", resp.PasswordChangeReason)
	}
}

func TestLoginGateMFAPersistFailureFailsClose(t *testing.T) {
	// MFA 用戶的 gate 依賴持久化旗標（第二階段明文不可得）：偵測命中但寫入失敗
	// 必須拒發 pending token（否則違規判定遺失、過完 MFA 取得正式會話）
	auth, _, db := setupLockoutEnv(t)
	seedGateUser(t, db, "admin123", func(u *model.User) { u.TOTPEnabled = true })
	// sqlite trigger 強制 must_change_password 寫入失敗（模擬暫時性 DB 故障）
	if err := db.Exec(`CREATE TRIGGER fail_mcp BEFORE UPDATE OF must_change_password ON users
		BEGIN SELECT RAISE(ABORT, 'forced write failure'); END`).Error; err != nil {
		t.Fatalf("create trigger: %v", err)
	}

	_, err := auth.Login(&LoginRequest{Username: "gate-user", Password: "admin123"})
	if err == nil {
		t.Fatal("MFA 用戶偵測命中且持久化失敗應 fail-close 拒絕登入")
	}

	// 對照：同故障下純密碼用戶仍被 in-memory 旗標攔下（不 fail-close、不放行）
	if err := db.Exec(`UPDATE users SET totp_enabled = false WHERE username = 'gate-user'`).Error; err != nil {
		t.Fatalf("reset totp: %v", err)
	}
	resp := loginGate(t, auth, "admin123")
	if !resp.PasswordChangeRequired || resp.PasswordChangeReason != PasswordChangeReasonNoncompliant {
		t.Fatalf("純密碼路徑寫入失敗仍應本次攔截，got %+v", resp)
	}
}

func TestPersistMustChangeWriteFailureStillGates(t *testing.T) {
	// 寫入失敗不影響 gate 判定：in-memory 旗標照設，本次登入仍被攔
	_, mock, _ := setupAuthMockDB(t)
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE "users"`).WillReturnError(gorm.ErrInvalidDB)
	mock.ExpectRollback()

	auth := NewAuthService("test-secret", 15*time.Minute)
	user := &model.User{Username: "gate-user", Active: true}
	user.ID = 7
	auth.persistMustChange(user)
	if !user.MustChangePassword {
		t.Fatal("寫入失敗仍應設 in-memory 旗標（本次 gate 照攔，下次登入重判自癒）")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock 預期未滿足: %v", err)
	}
}
