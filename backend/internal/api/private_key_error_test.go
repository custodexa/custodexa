package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/gin-gonic/gin"
)

// TestPrivateKeyInvalidMapsTo400 資產、資產帳號、憑證庫三個錯誤出口：私鑰無法解析一律
// 回 400 與同一個碼，回應不帶解析函式的原始錯誤。錯誤取自共用解析函式的真實輸出
// （含 ssh 庫原文），不是手造的 sentinel。回應頂層帶 field=private_key。
func TestPrivateKeyInvalidMapsTo400(t *testing.T) {
	_, parseErr := asset.ParsePrivateKey([]byte("not a private key"))
	if parseErr == nil {
		t.Fatal("前提：壞私鑰須解析失敗")
	}
	if !strings.Contains(parseErr.Error(), "ssh:") {
		t.Fatalf("前提：錯誤應帶庫原文以驗證不外洩，實得 %q", parseErr.Error())
	}

	exits := map[string]func(c *gin.Context){
		"資產":   func(c *gin.Context) { respondAssetError(c, apierror.CodeInternalAssetCreate, parseErr) },
		"資產帳號": func(c *gin.Context) { respondAccountError(c, apierror.CodeInternalAssetCreate, parseErr) },
		"憑證庫":  func(c *gin.Context) { respondCredentialError(c, apierror.CodeInternalCredentialCreate, parseErr) },
	}
	for name, respond := range exits {
		t.Run(name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("POST", "/x", nil)

			respond(c)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("狀態碼 = %d，預期 400", w.Code)
			}
			var resp map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("回應非 JSON: %v", err)
			}
			if resp["code"] != string(apierror.CodeCredentialPrivateKeyInvalid) {
				t.Fatalf("code = %v，預期 %s", resp["code"], apierror.CodeCredentialPrivateKeyInvalid)
			}
			// 表單據 field 把錯誤掛在私鑰欄下方
			if resp["field"] != "private_key" {
				t.Fatalf("field = %v，預期 private_key", resp["field"])
			}
			if body := w.Body.String(); strings.Contains(body, "ssh:") {
				t.Fatalf("回應洩漏解析原文: %s", body)
			}
		})
	}
}
