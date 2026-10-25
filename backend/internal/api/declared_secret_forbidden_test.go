package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/gin-gonic/gin"
)

// TestDeclaredSecretForbiddenMapsTo403 資產表單與帳號表單內嵌密碼／私鑰時，持
// credential:manage 而缺 credential:set-secret 者由服務層回 ErrCredentialBindForbidden。
// 兩個出口都須回 403 權限不足，不得落入 500 內部錯誤；回應不帶缺哪一項能力。
// 服務層錯誤可能原樣或包一層傳出，兩種形態都驗。
func TestDeclaredSecretForbiddenMapsTo403(t *testing.T) {
	errs := map[string]error{
		"原樣": asset.ErrCredentialBindForbidden,
		"包裝": fmt.Errorf("更新資產失敗: %w", asset.ErrCredentialBindForbidden),
	}
	exits := map[string]func(c *gin.Context, err error){
		"資產": func(c *gin.Context, err error) { respondAssetError(c, apierror.CodeInternalAssetUpdate, err) },
		"資產帳號": func(c *gin.Context, err error) {
			respondAccountError(c, apierror.CodeInternalAssetUpdate, err)
		},
	}
	for exitName, respond := range exits {
		for errName, err := range errs {
			t.Run(exitName+"/"+errName, func(t *testing.T) {
				gin.SetMode(gin.TestMode)
				w := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(w)
				c.Request = httptest.NewRequest("PUT", "/x", nil)

				respond(c, err)

				if w.Code != http.StatusForbidden {
					t.Fatalf("狀態碼 = %d，預期 403（缺映射會落 500）", w.Code)
				}
				var resp map[string]any
				if jerr := json.Unmarshal(w.Body.Bytes(), &resp); jerr != nil {
					t.Fatalf("回應非 JSON: %v", jerr)
				}
				if resp["code"] != string(apierror.CodePermissionDenied) {
					t.Fatalf("code = %v，預期 %s", resp["code"], apierror.CodePermissionDenied)
				}
				if params, ok := resp["params"]; ok && params != nil {
					t.Fatalf("回應不應帶參數（缺哪一項能力不外露），實得 %v", params)
				}
			})
		}
	}
}
