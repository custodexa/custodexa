package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
)

// changePasswordRaw 同 pwCtxEnv.changePassword，但回傳未解析的 ResponseRecorder：
// 「body 是不是單一 JSON」這件事只有在拿到原始位元組時才驗得到
func (e *pwCtxEnv) changePasswordRaw(t *testing.T, bearer, oldPw, newPw string) *httptest.ResponseRecorder {
	t.Helper()
	router := setupTestRouter()
	router.POST("/auth/change-password", e.h.ChangePassword)

	body, _ := json.Marshal(map[string]string{"old_password": oldPw, "new_password": newPw})
	req := httptest.NewRequest("POST", "/auth/change-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// 改密錯誤回應的信封完整性（批 14 對抗審查 M3）。
//
// respondChangePasswordError 是一個 switch：每個分支只設定 code／status，統一由
// 函式尾端寫出一次回應。若某個分支自行呼叫 apierror.Respond 卻忘了 return，
// 該路徑會**寫兩次**回應——第二次以零值 ErrCode 進 apierror.Write，落入
// 「unregistered code」分支再串接一段泛化 500 訊息。HTTP 狀態碼由第一次寫入
// 決定（看起來正常），但 body 是兩段 JSON 串接，前端 JSON.parse 直接失敗、
// i18n 也查不到碼。
//
// 斷言刻意寫在「body 必須是單一 JSON 物件且帶得到碼」上，而非某一分支的實作
// 細節：任何分支漏 return 都會被同一句斷言擋下。
func TestChangePasswordErrorRespondsExactlyOnce(t *testing.T) {
	env := setupPasswordContextEnv(t)

	// 轉為僅外部登入（external_credential=true）→ SelfChangePassword 回
	// ErrExternalUserPassword，走 respondChangePasswordError 的外部帳號分支
	if err := env.db.Model(&model.User{}).Where("id = ?", env.uid).
		Update("external_credential", true).Error; err != nil {
		t.Fatalf("轉為僅外部登入: %v", err)
	}

	login, err := env.auth.IssueSessionResponse(env.uid, crypto.AuthMethodOIDC, env.pid)
	if err != nil {
		t.Fatalf("OIDC 登入: %v", err)
	}

	w := env.changePasswordRaw(t, login.Token, pwCtxOldPassword, pwCtxNewPassword)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("外部帳號改密應回 400，實得 %d（body=%s）", w.Code, w.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("回應不是單一 JSON 物件（回應被寫了兩次）: %v\nbody=%s",
			err, w.Body.String())
	}
	code, _ := body["code"].(string)
	if code == "" {
		t.Fatalf("錯誤回應缺少機器可讀錯誤碼，body=%s", w.Body.String())
	}
	if code != string(apierror.CodeExternalUserPassword) {
		t.Errorf("錯誤碼 = %q, want %q", code, apierror.CodeExternalUserPassword)
	}
}
