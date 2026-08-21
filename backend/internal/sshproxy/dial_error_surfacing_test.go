package sshproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/k8sproxy"
	"github.com/custodexa/backend/internal/modules/asset"
)

// TestK8sDialCode k8sproxy 分類（K8sError.Kind）→ apierror code 映射
// （backend-i18n-unification A8）：六類各配一碼、彼此相異且都已註冊；
// Kind 值變動或漏配時本測試紅（散文降級為 Data fallback 後，碼是唯一分辨依據）。
func TestK8sDialCode(t *testing.T) {
	kinds := []string{
		k8sproxy.KindUnauthorized, k8sproxy.KindForbidden, k8sproxy.KindNotFound,
		k8sproxy.KindTLS, k8sproxy.KindUnreachable, k8sproxy.KindUnknown,
	}
	seen := map[apierror.ErrCode]string{}
	for _, kind := range kinds {
		code := k8sDialCode(&k8sproxy.K8sError{Kind: kind, Message: "x"})
		if code == apierror.CodeK8sPodUnavailable {
			t.Errorf("kind %q 落回泛碼（未配專屬碼）", kind)
		}
		if !apierror.IsRegistered(code) {
			t.Errorf("kind %q 映到未註冊的碼 %q", kind, code)
		}
		if prev, dup := seen[code]; dup {
			t.Errorf("kind %q 與 %q 共用碼 %q（六類必須可分辨）", kind, prev, code)
		}
		seen[code] = kind
	}
	// 非 K8sError 與未知 Kind 退回泛碼（不 panic、不誤用他類碼）
	if got := k8sDialCode(errors.New("boom")); got != apierror.CodeK8sPodUnavailable {
		t.Errorf("非 K8sError 應退回泛碼，got %q", got)
	}
	if got := k8sDialCode(&k8sproxy.K8sError{Kind: "brand-new"}); got != apierror.CodeK8sPodUnavailable {
		t.Errorf("未知 Kind 應退回泛碼，got %q", got)
	}
}

// TestDialErrorCode sentinel → apierror code 映射（ssh-connect-error-surfacing D3）
func TestDialErrorCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want apierror.ErrCode
	}{
		{name: "host key 變更", err: asset.ErrHostKeyChanged, want: apierror.CodeSSHHostKeyChanged},
		{name: "包裹後的 host key 變更仍命中", err: fmt.Errorf("wrap: %w", asset.ErrHostKeyChanged), want: apierror.CodeSSHHostKeyChanged},
		{name: "認證失敗", err: ErrAuthFailed, want: apierror.CodeSSHAuthFailed},
		{name: "逾時", err: ErrDialTimeout, want: apierror.CodeSSHDialTimeout},
		{name: "不可達", err: ErrUnreachable, want: apierror.CodeSSHUnreachable},
		{name: "未分類錯誤落不可達", err: errors.New("boom"), want: apierror.CodeSSHUnreachable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dialErrorCode(tt.err); got != tt.want {
				t.Errorf("dialErrorCode(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

// TestWriteDialErrorWS 瀏覽器 WS 客戶端收到升級後的 MsgError（code＋zh fallback）
// 後連線正常關閉（ssh-connect-error-surfacing D1）
func TestWriteDialErrorWS(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/ssh", func(c *gin.Context) {
		writeDialError(c, apierror.CodeSSHHostKeyChanged, "主機金鑰已變更，連線已拒絕")
	})
	srv := httptest.NewServer(r)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ssh"
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("WS 升級應成功: err=%v resp=%v", err, resp)
	}
	defer conn.Close()

	_, raw, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("讀取 error 訊息失敗: %v", err)
	}
	var msg Message
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatalf("error 訊息非合法 JSON: %v (%s)", err, raw)
	}
	if msg.Type != MsgError {
		t.Errorf("Type = %q, want %q", msg.Type, MsgError)
	}
	if msg.Code != "RULE_SSH_HOST_KEY_CHANGED" {
		t.Errorf("Code = %q, want RULE_SSH_HOST_KEY_CHANGED", msg.Code)
	}
	if !strings.Contains(msg.Data, "主機金鑰已變更") {
		t.Errorf("Data = %q, want 含「主機金鑰已變更」", msg.Data)
	}

	// error 訊息後應收到正常關閉
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("error 訊息後應關閉連線")
	} else if !websocket.IsCloseError(err, websocket.CloseNormalClosure) {
		t.Errorf("關閉語義非 NormalClosure: %v", err)
	}
}

// TestWriteDialErrorHTTP 非 WS 升級請求維持既有 HTTP 502 JSON 語義
func TestWriteDialErrorHTTP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/ssh", func(c *gin.Context) {
		writeDialError(c, apierror.CodeSSHAuthFailed, "SSH 認證失敗，請確認資產憑證")
	})
	req := httptest.NewRequest("GET", "/ssh", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("狀態碼 = %d, want 502", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("回應非 JSON: %v (%s)", err, w.Body.String())
	}
	if resp["error"] != "SSH 認證失敗，請確認資產憑證" {
		t.Errorf("error = %v, want SSH 認證失敗文案", resp["error"])
	}
}
