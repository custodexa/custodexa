package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
)

// 依設定鍵篩選安全政策的變更列。
//
// 稽核人員由某個設定名追到它的變更記錄時，落到一份未篩選的日誌上等於把最後一步
// 變成一場搜尋。變更列把鍵記在訊息欄（`policy=<鍵> …`），端點因此要能以鍵收斂。
//
// **本檔刻意用寫入端的同一支函式產生訊息欄**（policyChangeAuditFields）：篩選條件
// 與寫入格式是同一件事的兩端，各寫一份字面量的話，寫入端改格式時篩選會安靜地失準。
//
// 突變自證：拿掉 List 的鍵條件 → 第一個斷言紅（回全部列）；把 LIKE 的萬用字元
// 轉義拿掉 → 「底線不得當成萬用字元」那格紅。

// seedPolicyChangeRow 以寫入端的真實格式寫一列安全政策變更。
func seedPolicyChangeRow(t *testing.T, db *gorm.DB, key, oldValue, newValue string, at time.Time) {
	t.Helper()
	details, errorMsg := policyChangeAuditFields(key, oldValue, newValue)
	seedAuditRowWithMessage(t, db, errorMsg, details, at)
}

// seedAuditRowWithMessage 寫一列訊息欄由呼叫端指定的審計列（用於誘餌列）。
func seedAuditRowWithMessage(t *testing.T, db *gorm.DB, errorMsg, details string, at time.Time) {
	t.Helper()
	row := &model.AuditLog{
		Action:    model.ActionUpdate,
		Resource:  model.ResourceSecurityPolicy,
		Status:    model.StatusSuccess,
		UserID:    1,
		Username:  "policy-admin",
		Method:    http.MethodPut,
		Path:      "/api/v1/security-policies",
		ErrorMsg:  errorMsg,
		Details:   details,
		CreatedAt: at,
	}
	if err := db.Create(row).Error; err != nil {
		t.Fatalf("seed 審計列 %q: %v", errorMsg, err)
	}
}

type auditListResponse struct {
	Data []struct {
		ErrorMsg string `json:"error_msg"`
		Details  string `json:"details"`
	} `json:"data"`
	Total int64 `json:"total"`
}

func callAuditLogList(t *testing.T, query string) (int, auditListResponse) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	h := NewAuditLogHandler(audit.NewAuditLogService(&config.FeatureFlags{}))
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs"+query, nil)
	h.List(c)

	var body auditListResponse
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode %q: %v", rec.Body.String(), err)
		}
	}
	return rec.Code, body
}

func TestAuditLogListFiltersByPolicyKey(t *testing.T) {
	db := installAuditHubDB(t)
	base := time.Date(2026, 9, 8, 1, 0, 0, 0, time.UTC)

	// 目標鍵的兩次變更（整數型：舊值與新值同在訊息欄）
	seedPolicyChangeRow(t, db, policy.PolicyPasswordMinLength, "8", "12", base)
	seedPolicyChangeRow(t, db, policy.PolicyPasswordMinLength, "12", "14", base.Add(time.Hour))
	// 別的鍵的變更
	seedPolicyChangeRow(t, db, policy.PolicyPasswordMaxAgeDays, "0", "90", base.Add(2*time.Hour))
	// 誘餌一：底線位置換成別的字元。未轉義的 LIKE 會把 `_` 當成萬用字元而收進來
	seedAuditRowWithMessage(t, db, "policy=passwordXminXlength old=1 new=2", "", base.Add(3*time.Hour))
	// 誘餌二：目標鍵出現在別的鍵的值裡。前綴錨定才不會收進來
	seedAuditRowWithMessage(t, db,
		"policy=login_banner_title old="+policy.PolicyPasswordMinLength+" new=x", "",
		base.Add(4*time.Hour))
	// 誘餌三：鍵名是目標鍵的延伸（前綴相同，後面沒有分隔的空白）
	seedAuditRowWithMessage(t, db,
		"policy="+policy.PolicyPasswordMinLength+"_extra old=1 new=2", "", base.Add(5*time.Hour))

	code, body := callAuditLogList(t, "?key="+policy.PolicyPasswordMinLength)
	if code != http.StatusOK {
		t.Fatalf("狀態 = %d，want 200", code)
	}
	if body.Total != 2 {
		t.Fatalf("以鍵篩選的總數 = %d，want 2（回了 %d 列）", body.Total, len(body.Data))
	}
	for _, row := range body.Data {
		if want := "policy=" + policy.PolicyPasswordMinLength + " "; len(row.ErrorMsg) < len(want) ||
			row.ErrorMsg[:len(want)] != want {
			t.Errorf("篩選結果混入別的鍵：%q", row.ErrorMsg)
		}
	}

	// 篩選條件與其他條件同時成立（AND，不是把別的條件蓋掉）
	code, body = callAuditLogList(t,
		"?key="+policy.PolicyPasswordMinLength+"&resource=security_policy")
	if code != http.StatusOK || body.Total != 2 {
		t.Errorf("鍵＋分類 = 狀態 %d／總數 %d，want 200／2", code, body.Total)
	}
	code, body = callAuditLogList(t, "?key="+policy.PolicyPasswordMinLength+"&resource=user")
	if code != http.StatusOK || body.Total != 0 {
		t.Errorf("鍵＋不相干分類 = 狀態 %d／總數 %d，want 200／0", code, body.Total)
	}

	// 不帶鍵時維持原行為：全部列都在
	code, body = callAuditLogList(t, "")
	if code != http.StatusOK || body.Total != 6 {
		t.Errorf("不帶鍵 = 狀態 %d／總數 %d，want 200／6", code, body.Total)
	}
}

// TestAuditLogListFiltersTextPolicyKey 文字型設定的變更把舊值與新值放在變更詳情欄，
// 訊息欄只剩鍵名——篩選對這一型同樣要成立，否則長文字的設定追不到記錄。
func TestAuditLogListFiltersTextPolicyKey(t *testing.T) {
	db := installAuditHubDB(t)
	base := time.Date(2026, 9, 8, 1, 0, 0, 0, time.UTC)

	seedPolicyChangeRow(t, db, policy.PolicyLoginBannerBody, "舊公告", "新公告", base)
	seedPolicyChangeRow(t, db, policy.PolicyPasswordMinLength, "12", "14", base.Add(time.Hour))

	code, body := callAuditLogList(t, "?key="+policy.PolicyLoginBannerBody)
	if code != http.StatusOK {
		t.Fatalf("狀態 = %d，want 200", code)
	}
	if body.Total != 1 {
		t.Fatalf("文字型設定的篩選總數 = %d，want 1", body.Total)
	}
	if body.Data[0].Details == "" {
		t.Errorf("文字型的變更詳情應帶舊值與新值，got 空字串")
	}
}
