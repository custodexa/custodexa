package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
)

// 已啟用 MFA 的帳號重新產生驗證器密鑰須附現行驗證碼：
// 缺碼、錯碼、重放碼都回對應機器碼、密文與啟用狀態不變、並留 denied 審計；
// 附有效碼則成功並在審計細節標示重設。

func (e *authSrcEnv) mfaSetupCall(t *testing.T, payload any) (int, string) {
	t.Helper()
	w := e.post(t, "/auth/mfa/setup", func(c *gin.Context) {
		c.Set("userID", e.uid)
		c.Set("username", "source-subject")
		e.h.MFASetup(c)
	}, payload, false)
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	code, _ := resp["code"].(string)
	return w.Code, code
}

func (e *authSrcEnv) mfaRow(t *testing.T) model.User {
	t.Helper()
	var u model.User
	if err := e.db.First(&u, e.uid).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	return u
}

func TestMFASetupRequiresCurrentCode_Handler(t *testing.T) {
	type tc struct {
		name     string
		payload  func(e *authSrcEnv) any
		wantCode string
	}
	cases := []tc{
		{"missing_code", func(e *authSrcEnv) any { return map[string]string{} }, "RULE_MFA_CURRENT_CODE_REQUIRED"},
		{"wrong_code", func(e *authSrcEnv) any {
			good, _ := totp.GenerateCode(e.totpSecret, time.Now())
			wrong := "000000"
			if good == wrong {
				wrong = "111111"
			}
			return map[string]string{"code": wrong}
		}, "RULE_MFA_INVALID_CODE"},
		{"replayed_code", func(e *authSrcEnv) any {
			code, _ := totp.GenerateCode(e.totpSecret, time.Now())
			if err := e.auth.VerifyMFACode(e.uid, code); err != nil {
				t.Fatalf("先消耗該碼: %v", err)
			}
			e.clearAudit(t)
			return map[string]string{"code": code}
		}, "RULE_MFA_REPLAY"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			e := setupAuthSourceEnv(t)
			e.enableTOTP(t)
			before := e.mfaRow(t)
			payload := c.payload(e)

			status, code := e.mfaSetupCall(t, payload)

			after := e.mfaRow(t)
			if !after.TOTPEnabled || after.TOTPSecretEnc != before.TOTPSecretEnc {
				t.Fatalf("拒絕後密文或啟用狀態被改動: enabled=%v sameEnc=%v",
					after.TOTPEnabled, after.TOTPSecretEnc == before.TOTPSecretEnc)
			}
			if status != http.StatusBadRequest || code != c.wantCode {
				t.Fatalf("回應 = %d %q, want 400 %q", status, code, c.wantCode)
			}
			rows := e.rows(t)
			if len(rows) != 1 || rows[0].Status != model.StatusDenied || rows[0].Action != model.ActionUpdate {
				t.Fatalf("應恰有一筆 denied 審計，實得 %+v", rows)
			}
		})
	}
}

func TestMFASetupRequiresCurrentCode_HandlerSuccessMarksReset(t *testing.T) {
	e := setupAuthSourceEnv(t)
	e.enableTOTP(t)
	code, _ := totp.GenerateCode(e.totpSecret, time.Now())

	status, _ := e.mfaSetupCall(t, map[string]string{"code": code})

	if status != http.StatusOK {
		t.Fatalf("附有效碼應回 200，實得 %d", status)
	}
	rows := e.rows(t)
	if len(rows) != 1 || rows[0].Status != model.StatusSuccess ||
		!strings.Contains(rows[0].Details, `"mfa_reset":true`) {
		t.Fatalf("成功列應標示 mfa_reset: %+v", rows)
	}
}

// 回歸：未啟用 MFA 的註冊免碼，成功列不標重設。
func TestMFASetupRequiresCurrentCode_HandlerFirstEnrollmentNeedsNoCode(t *testing.T) {
	e := setupAuthSourceEnv(t)

	status, _ := e.mfaSetupCall(t, map[string]string{})

	if status != http.StatusOK {
		t.Fatalf("未啟用者免碼應回 200，實得 %d", status)
	}
	rows := e.rows(t)
	if len(rows) != 1 || strings.Contains(rows[0].Details, "mfa_reset") {
		t.Fatalf("首次註冊的審計列不應標示重設: %+v", rows)
	}
}
