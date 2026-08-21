package identity

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/policy"
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// gate chain 與 OIDC 的交互（idp-oidc-integration tasks 4.6）。
//
// 三條性質：
//
//	密碼類 gate 依**本次登入方式**判定，不依帳號屬性——否則混合帳號無論怎麼登入
//	  都會被同一種判定綁死。
//	OIDC＋MFA 疊加時，第二階段完成點回的仍是正式會話而非改密 token。
//	MFA 兩個完成點（VerifyMFALogin／CompleteEnrollment）都要複查憑證世代，
//	  且複查必須排在「驗碼」與「寫入 TOTP 因子」之前。

// Scenario: OIDC＋MFA 完成後不觸發密碼 gate（tasks 4.6）
func TestOIDCLoginWithMFADoesNotTriggerPasswordGate(t *testing.T) {
	e := setupOIDCLifecycleEnv(t)
	// 三個密碼 gate 觸發源同時成立：強制改密旗標、密碼有效期已過（時間戳為 NULL
	// 視為已過期）。任一漏判都會讓 OIDC 登入者被導去改一個他根本沒有的密碼
	e.policies.Update(policy.PolicyPasswordMaxAgeDays, "90", "admin")
	user := e.seedMFAIdentityUser(t, "sso-mfa", "sub-sso-mfa")
	if err := e.db.Model(&model.User{}).Where("id = ?", user.ID).
		Updates(map[string]any{"must_change_password": true, "password_changed_at": nil}).Error; err != nil {
		t.Fatalf("設定改密旗標: %v", err)
	}
	var reloaded model.User
	if err := e.db.Preload("Roles").First(&reloaded, user.ID).Error; err != nil {
		t.Fatalf("重載使用者: %v", err)
	}

	first, err := e.auth.LoginWithExternalIdentity(&reloaded, e.oidcCtxFor(&reloaded))
	if err != nil {
		t.Fatalf("OIDC 登入: %v", err)
	}
	if !first.MFARequired || first.PendingToken == "" {
		t.Fatalf("已註冊 TOTP 者應進入第二階段，實得 %+v", first)
	}
	// 第一階段就不該回改密（gate 統一留在 finishLogin，且 MFA 之後）
	if first.PasswordChangeRequired {
		t.Error("OIDC 第一階段不應回改密要求")
	}

	final, err := e.auth.VerifyMFALogin(&MFAVerifyRequest{
		PendingToken: first.PendingToken, Code: validTestCode(t)})
	if err != nil {
		t.Fatalf("MFA 第二階段: %v", err)
	}
	if final.PasswordChangeRequired || final.ChangeToken != "" {
		t.Fatalf("OIDC 登入者不得被密碼 gate 攔下（must_change／過期皆屬本地密碼語義），實得 %+v", final)
	}
	if final.Token == "" || final.RefreshToken == "" {
		t.Fatal("應直接發出正式會話")
	}
	// 旗標仍在（不是被靜默清掉才過關）——同一帳號若哪天改走本地密碼路徑仍須被攔
	var after model.User
	e.db.First(&after, user.ID)
	if !after.MustChangePassword {
		t.Error("OIDC 登入不應清除 must_change_password 旗標（gate 是不適用，不是已滿足）")
	}
}

// Scenario: 混合帳號雙路徑各依登入方式判定（tasks 4.6）
func TestHybridAccountPasswordGateFollowsLoginMethod(t *testing.T) {
	e := setupOIDCLifecycleEnv(t)
	const password = "Str0ng-Passw0rd!x"

	// 混合帳號：本地來源、保有可用的本地密碼，同時綁定外部身分
	user := e.seedLocalUser(t, "mixed-gate", password, func(u *model.User) {
		u.MustChangePassword = true
	})
	if err := e.db.Create(&model.UserExternalIdentity{
		UserID: user.ID, ProviderID: e.provider.ID,
		Issuer: e.provider.Issuer, ClientID: e.provider.ClientID, Subject: "sub-mixed-gate",
	}).Error; err != nil {
		t.Fatalf("建立外部身分: %v", err)
	}

	// (a) 本地密碼路徑：照常被密碼 gate 攔下
	local, err := e.auth.Login(&LoginRequest{Username: "mixed-gate", Password: password})
	if err != nil {
		t.Fatalf("本地登入: %v", err)
	}
	if !local.PasswordChangeRequired || local.ChangeToken == "" {
		t.Fatalf("本地密碼路徑須觸發密碼 gate，實得 %+v", local)
	}
	if local.PasswordChangeReason != PasswordChangeReasonMustChange {
		t.Errorf("gate 成因 = %q, want %q", local.PasswordChangeReason, PasswordChangeReasonMustChange)
	}
	if local.Token != "" {
		t.Error("被 gate 攔下時不得同時發出正式 token")
	}

	// (b) OIDC 路徑：同一個帳號、同一個旗標，不適用密碼類 gate
	ticket := issueTestTicket(t, e.login, user, e.provider, capabilityBrowserSecret)
	oidc, _, err := e.login.Exchange(ticket, capabilityBrowserSecret)
	if err != nil {
		t.Fatalf("OIDC 兌換: %v", err)
	}
	if oidc.PasswordChangeRequired {
		t.Fatalf("OIDC 路徑不應觸發密碼 gate（判定須依本次登入方式），實得 %+v", oidc)
	}
	if oidc.Token == "" {
		t.Fatal("OIDC 路徑應發出正式會話")
	}

	// (c) 判定沒有被 OIDC 那次登入改寫：本地路徑再登一次仍被攔
	again, err := e.auth.Login(&LoginRequest{Username: "mixed-gate", Password: password})
	if err != nil {
		t.Fatalf("再次本地登入: %v", err)
	}
	if !again.PasswordChangeRequired {
		t.Error("OIDC 登入不得使本地路徑的密碼 gate 失效")
	}
}

// Scenario: pending 期間 provider 被停用，MFA 完成被拒（tasks 4.6）
func TestMFACompletionRejectedWhenProviderDisabledDuringPending(t *testing.T) {
	e := setupOIDCLifecycleEnv(t)
	user := e.seedMFAIdentityUser(t, "sso-pending", "sub-sso-pending")

	first, err := e.auth.LoginWithExternalIdentity(user, e.oidcCtxFor(user))
	if err != nil {
		t.Fatalf("OIDC 登入: %v", err)
	}
	if first.PendingToken == "" {
		t.Fatalf("應簽出 pending token，實得 %+v", first)
	}

	// pending 窗（5 分鐘）內停用：該 token 尚未兌換，任何連線掃描都涵蓋不到它
	e.setProviderEnabled(t, false)

	_, err = e.auth.VerifyMFALogin(&MFAVerifyRequest{
		PendingToken: first.PendingToken, Code: validTestCode(t)})
	if !errors.Is(err, ErrMFAPendingTokenInvalid) {
		t.Fatalf("停用後完成 MFA = %v, want ErrMFAPendingTokenInvalid（與過期／偽造同一回應）", err)
	}

	// 世代閘須排在驗碼之前：否則一次被拒的嘗試會白白消耗掉該 time-step，
	// 使用者於停用復原後的下一次嘗試會被防重放判定誤殺
	var after model.User
	if err := e.db.First(&after, user.ID).Error; err != nil {
		t.Fatalf("重載使用者: %v", err)
	}
	if after.TOTPLastStep != nil {
		t.Errorf("拒絕須發生於驗碼之前，實得已消耗 step=%d", *after.TOTPLastStep)
	}
}

// Scenario: enrollment 期間 provider 被停用，綁定完成被拒且不得寫入因子（tasks 4.6）
func TestMFAEnrollmentCompletionRejectedWhenProviderDisabled(t *testing.T) {
	e := setupOIDCLifecycleEnv(t)
	e.policies.Update(policy.PolicyMFARequired, policy.MFARequiredAll, "admin")

	// 受強制但未註冊：OIDC 登入後改發 enrollment token
	user := e.seedIdentityUser(t, "sso-enroll", "sub-sso-enroll", nil)
	first, err := e.auth.LoginWithExternalIdentity(user, e.oidcCtxFor(user))
	if err != nil {
		t.Fatalf("OIDC 登入: %v", err)
	}
	if !first.MFAEnrollmentRequired || first.EnrollmentToken == "" {
		t.Fatalf("應進入強制註冊流程，實得 %+v", first)
	}
	if _, err := e.auth.EnrollmentSetup(first.EnrollmentToken); err != nil {
		t.Fatalf("EnrollmentSetup: %v", err)
	}
	// 以測試 secret 覆蓋，使「若閘被拿掉就會綁定成功」成立
	if err := e.db.Model(&model.User{}).Where("id = ?", user.ID).
		Update("totp_secret_enc", encryptTestSecret(t, e.auth)).Error; err != nil {
		t.Fatalf("覆寫 TOTP secret: %v", err)
	}

	e.setProviderEnabled(t, false)

	_, err = e.auth.CompleteEnrollment(first.EnrollmentToken, validTestCode(t))
	if !errors.Is(err, ErrMFAPendingTokenInvalid) {
		t.Fatalf("停用後完成綁定 = %v, want ErrMFAPendingTokenInvalid", err)
	}
	// 閘必須排在 EnableMFA 之前：排在其後等於讓已失效的憑證仍能改變帳號狀態
	var after model.User
	if err := e.db.First(&after, user.ID).Error; err != nil {
		t.Fatalf("重載使用者: %v", err)
	}
	if after.TOTPEnabled {
		t.Error("已失效的 enrollment token 不得寫入第二因子")
	}
	if after.TOTPLastStep != nil {
		t.Errorf("拒絕須發生於驗碼之前，實得已消耗 step=%d", *after.TOTPLastStep)
	}
}
