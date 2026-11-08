package identity

import (
	"errors"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// 已啟用 MFA 的帳號重新產生驗證器密鑰須附現行驗證碼；
// 覆寫只在寫入時狀態仍是檢查時的狀態才生效。
// 全部走真 sqlite 與真服務，斷言直接讀資料庫列。

// mfaEnrolledEnv 含 MFA 加密能力的服務＋一個已啟用 MFA 的帳號（密鑰為 testTOTPSecret）。
type mfaEnrolledEnv struct {
	svc    *AuthService
	db     *gorm.DB
	userID uint
	encOld string
}

func setupMFAEnrolledEnv(t *testing.T, enrolled bool) *mfaEnrolledEnv {
	t.Helper()
	_, policies, db := setupLockoutEnv(t)
	svc := newMFAAuthService(t)
	svc.SetSecurityPolicies(policies)

	hash, _ := bcrypt.GenerateFromPassword([]byte("right-pass-1"), bcrypt.MinCost)
	u := &model.User{Username: "bob", Email: strPtr("b@x"), Password: string(hash), Active: true}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	env := &mfaEnrolledEnv{svc: svc, db: db, userID: u.ID}
	if enrolled {
		env.encOld = encryptTestSecret(t, svc)
		if err := db.Model(&model.User{}).Where("id = ?", u.ID).
			Updates(map[string]any{"totp_secret_enc": env.encOld, "totp_enabled": true}).Error; err != nil {
			t.Fatalf("enroll: %v", err)
		}
	}
	return env
}

func (e *mfaEnrolledEnv) row(t *testing.T) model.User {
	t.Helper()
	var u model.User
	if err := e.db.First(&u, e.userID).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	return u
}

// assertUnchanged 密文與啟用狀態仍是登錄時的值。
func (e *mfaEnrolledEnv) assertUnchanged(t *testing.T) {
	t.Helper()
	u := e.row(t)
	if !u.TOTPEnabled {
		t.Fatalf("totp_enabled 被改為 false")
	}
	if u.TOTPSecretEnc != e.encOld {
		t.Fatalf("totp_secret_enc 被改寫")
	}
}

func fixedClock(at time.Time) func() time.Time { return func() time.Time { return at } }

func codeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	c, err := totp.GenerateCode(secret, at)
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	return c
}

func TestMFASetupRequiresCurrentCode_MissingCode(t *testing.T) {
	e := setupMFAEnrolledEnv(t, true)
	_, err := e.svc.GenerateMFASetup(e.userID, "")
	e.assertUnchanged(t)
	if !errors.Is(err, ErrMFACurrentCodeRequired) {
		t.Fatalf("err = %v, want ErrMFACurrentCodeRequired", err)
	}
}

func TestMFASetupRequiresCurrentCode_WrongCode(t *testing.T) {
	e := setupMFAEnrolledEnv(t, true)
	at := time.Unix(1_700_000_010, 0)
	e.svc.mfaNow = fixedClock(at)
	good := codeAt(t, testTOTPSecret, at)
	wrong := "000000"
	if good == wrong {
		wrong = "111111"
	}
	_, err := e.svc.GenerateMFASetup(e.userID, wrong)
	e.assertUnchanged(t)
	if !errors.Is(err, ErrMFAInvalidCode) {
		t.Fatalf("err = %v, want ErrMFAInvalidCode", err)
	}
}

func TestMFASetupRequiresCurrentCode_ReplayedCode(t *testing.T) {
	e := setupMFAEnrolledEnv(t, true)
	at := time.Unix(1_700_000_010, 0)
	e.svc.mfaNow = fixedClock(at)
	code := codeAt(t, testTOTPSecret, at)
	// 同一 time-step 的碼先被登入第二階段消耗
	if err := e.svc.VerifyMFACode(e.userID, code); err != nil {
		t.Fatalf("VerifyMFACode: %v", err)
	}
	_, err := e.svc.GenerateMFASetup(e.userID, code)
	e.assertUnchanged(t)
	if !errors.Is(err, ErrMFAReplay) {
		t.Fatalf("err = %v, want ErrMFAReplay", err)
	}
}

// 回歸：未啟用者免碼；目錄帳號（無本地密碼）帶現行碼可重設。
func TestMFASetupRequiresCurrentCode_NotEnrolledNeedsNoCode(t *testing.T) {
	e := setupMFAEnrolledEnv(t, false)
	resp, err := e.svc.GenerateMFASetup(e.userID, "")
	if err != nil || resp == nil || resp.Secret == "" {
		t.Fatalf("resp=%+v err=%v", resp, err)
	}
	u := e.row(t)
	if u.TOTPEnabled || u.TOTPSecretEnc == "" {
		t.Fatalf("未啟用者的 setup 應寫入未啟用的新密文: enabled=%v enc=%q", u.TOTPEnabled, u.TOTPSecretEnc)
	}
}

func TestMFASetupRequiresCurrentCode_DirectoryAccountResetsWithCode(t *testing.T) {
	e := setupMFAEnrolledEnv(t, true)
	if err := e.db.Model(&model.User{}).Where("id = ?", e.userID).
		Updates(map[string]any{"is_ldap": true, "external_credential": true, "password": "x"}).Error; err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1_700_000_010, 0)
	e.svc.mfaNow = fixedClock(at)
	resp, err := e.svc.GenerateMFASetup(e.userID, codeAt(t, testTOTPSecret, at))
	if err != nil || resp == nil {
		t.Fatalf("resp=%+v err=%v", resp, err)
	}
	u := e.row(t)
	if u.TOTPEnabled || u.TOTPSecretEnc == e.encOld {
		t.Fatalf("重設後應為未啟用的新密文")
	}
}

// 重設後的完整流程：同 step 的新碼為重放、下一 step 才能啟用，之後登入第二階段只認新驗證器。
func TestMFASetupRequiresCurrentCode_ResetFlow(t *testing.T) {
	e := setupMFAEnrolledEnv(t, true)
	stepN := time.Unix(1_700_000_010, 0)
	e.svc.mfaNow = fixedClock(stepN)

	resp, err := e.svc.GenerateMFASetup(e.userID, codeAt(t, testTOTPSecret, stepN))
	if err != nil {
		t.Fatalf("以現行碼重設: %v", err)
	}
	newSecret := resp.Secret

	// 同 step 的新碼：重放，仍未啟用
	if err := e.svc.EnableMFA(e.userID, codeAt(t, newSecret, stepN)); !errors.Is(err, ErrMFAReplay) {
		t.Fatalf("同 step 啟用 err = %v, want ErrMFAReplay", err)
	}
	if e.row(t).TOTPEnabled {
		t.Fatalf("重放後不應啟用")
	}

	// 下一 step 啟用成功
	stepN1 := stepN.Add(30 * time.Second)
	e.svc.mfaNow = fixedClock(stepN1)
	if err := e.svc.EnableMFA(e.userID, codeAt(t, newSecret, stepN1)); err != nil {
		t.Fatalf("下一 step 啟用: %v", err)
	}
	if !e.row(t).TOTPEnabled {
		t.Fatalf("啟用後 totp_enabled 應為 true")
	}

	// 登入第二階段：舊驗證器的碼被拒，新驗證器的碼通過
	stepN2 := stepN.Add(60 * time.Second)
	e.svc.mfaNow = fixedClock(stepN2)
	login, err := e.svc.Login(&LoginRequest{Username: "bob", Password: "right-pass-1"})
	if err != nil || login == nil || !login.MFARequired {
		t.Fatalf("Login = %+v err=%v, want MFARequired", login, err)
	}
	if _, err := e.svc.VerifyMFALogin(&MFAVerifyRequest{PendingToken: login.PendingToken,
		Code: codeAt(t, testTOTPSecret, stepN2)}); !errors.Is(err, ErrMFAInvalidCode) {
		t.Fatalf("舊驗證器的碼 err = %v, want ErrMFAInvalidCode", err)
	}
	// 失敗計數以外的狀態不變，新驗證器的碼應通過
	done, err := e.svc.VerifyMFALogin(&MFAVerifyRequest{PendingToken: login.PendingToken,
		Code: codeAt(t, newSecret, stepN2)})
	if err != nil || done == nil || done.Token == "" {
		t.Fatalf("新驗證器的碼: resp=%+v err=%v", done, err)
	}
}

// 讀到未啟用後暫停，另一請求完成啟用：前者不得覆寫。
func TestMFASetupRequiresCurrentCode_RaceEnableBetweenReadAndWrite(t *testing.T) {
	e := setupMFAEnrolledEnv(t, false)
	// 先以一次 setup 準備好密鑰 A（未啟用）
	first, err := e.svc.GenerateMFASetup(e.userID, "")
	if err != nil {
		t.Fatal(err)
	}
	encA := e.row(t).TOTPSecretEnc

	at := time.Unix(1_700_000_010, 0)
	e.svc.mfaNow = fixedClock(at)
	hookHit := 0
	e.svc.mfaStageHook = func(stage string) {
		if stage != "setup-before-write" {
			return
		}
		hookHit++
		e.svc.mfaStageHook = nil
		// 另一請求在此時完成啟用
		if err := e.svc.EnableMFA(e.userID, codeAt(t, first.Secret, at)); err != nil {
			t.Errorf("交錯的 enable: %v", err)
		}
	}
	_, err = e.svc.GenerateMFASetup(e.userID, "")
	if hookHit != 1 {
		t.Fatalf("掛勾觸發 %d 次，未走到交錯分支", hookHit)
	}
	if !errors.Is(err, ErrMFACurrentCodeRequired) {
		t.Fatalf("err = %v, want ErrMFACurrentCodeRequired", err)
	}
	u := e.row(t)
	if !u.TOTPEnabled || u.TOTPSecretEnc != encA {
		t.Fatalf("交錯後應維持已啟用且密文為已啟用者: enabled=%v sameEnc=%v", u.TOTPEnabled, u.TOTPSecretEnc == encA)
	}
}

// 讀到未啟用（密文 A）後暫停，另一個 setup 換成密文 B 且仍未啟用：前者不得覆寫。
func TestMFASetupRequiresCurrentCode_RaceSecretReplacedWhileNotEnabled(t *testing.T) {
	e := setupMFAEnrolledEnv(t, false)
	if _, err := e.svc.GenerateMFASetup(e.userID, ""); err != nil {
		t.Fatal(err)
	}
	hookHit := 0
	var encB string
	e.svc.mfaStageHook = func(stage string) {
		if stage != "setup-before-write" {
			return
		}
		hookHit++
		e.svc.mfaStageHook = nil
		if _, err := e.svc.GenerateMFASetup(e.userID, ""); err != nil {
			t.Errorf("交錯的 setup: %v", err)
		}
		encB = e.row(t).TOTPSecretEnc
	}
	_, err := e.svc.GenerateMFASetup(e.userID, "")
	if hookHit != 1 {
		t.Fatalf("掛勾觸發 %d 次，未走到交錯分支", hookHit)
	}
	if !errors.Is(err, ErrMFACurrentCodeRequired) {
		t.Fatalf("err = %v, want ErrMFACurrentCodeRequired", err)
	}
	u := e.row(t)
	if u.TOTPEnabled || u.TOTPSecretEnc != encB {
		t.Fatalf("密文應仍為後到者 B 且未啟用: enabled=%v sameEnc=%v", u.TOTPEnabled, u.TOTPSecretEnc == encB)
	}
}

// enable 驗碼後暫停，另一請求換掉密鑰：enable 不生效。
func TestMFASetupRequiresCurrentCode_RaceEnableAfterSecretReplaced(t *testing.T) {
	e := setupMFAEnrolledEnv(t, false)
	first, err := e.svc.GenerateMFASetup(e.userID, "")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1_700_000_010, 0)
	e.svc.mfaNow = fixedClock(at)
	hookHit := 0
	var encB string
	e.svc.mfaStageHook = func(stage string) {
		if stage != "enable-before-write" {
			return
		}
		hookHit++
		e.svc.mfaStageHook = nil
		if _, err := e.svc.GenerateMFASetup(e.userID, ""); err != nil {
			t.Errorf("交錯的 setup: %v", err)
		}
		encB = e.row(t).TOTPSecretEnc
	}
	err = e.svc.EnableMFA(e.userID, codeAt(t, first.Secret, at))
	if hookHit != 1 {
		t.Fatalf("掛勾觸發 %d 次，未走到交錯分支", hookHit)
	}
	if !errors.Is(err, ErrMFASetupRequired) {
		t.Fatalf("err = %v, want ErrMFASetupRequired", err)
	}
	u := e.row(t)
	if u.TOTPEnabled || u.TOTPSecretEnc != encB {
		t.Fatalf("enable 不應生效: enabled=%v sameEnc=%v", u.TOTPEnabled, u.TOTPSecretEnc == encB)
	}
}

// 重設入口的錯碼與登入第二階段共用鎖定計數：達門檻回鎖定，且鎖定期間正確碼也不放行。
func TestMFASetupRequiresCurrentCode_WrongCodesCountToLockout(t *testing.T) {
	e := setupMFAEnrolledEnv(t, true)
	e.svc.policies.Update(policy.PolicyLockoutMaxAttempts, "3", "admin")
	at := time.Unix(1_700_000_010, 0)
	e.svc.mfaNow = fixedClock(at)
	good := codeAt(t, testTOTPSecret, at)
	wrong := "000000"
	if good == wrong {
		wrong = "111111"
	}
	var lastErr error
	for i := 0; i < 3; i++ {
		_, lastErr = e.svc.GenerateMFASetup(e.userID, wrong)
	}
	if !errors.Is(lastErr, ErrAccountLocked) {
		t.Fatalf("第 3 次錯碼 = %v, want ErrAccountLocked", lastErr)
	}
	if _, err := e.svc.GenerateMFASetup(e.userID, good); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("鎖定期間正確碼 = %v, want ErrAccountLocked", err)
	}
	e.assertUnchanged(t)
}
