package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// TestAuditLogListAndGetCarryReason 擋：操作日誌加了原因欄卻弄丟原有欄位
// （列表回應改成包裝型別，嵌入失效時 id、details、path 會整批消失）
func TestAuditLogListAndGetCarryReason(t *testing.T) {
	db := installAuditHubDB(t)
	base := time.Date(2026, 10, 10, 2, 0, 0, 0, time.UTC)
	retention := &model.AuditLog{CreatedAt: base, Username: "system", Action: model.ActionDelete,
		Resource: model.ResourceRetention, Status: model.StatusSuccess,
		Details: `{"target":"audit_logs","days":365,"deleted":12,"partial":false}`}
	withPath := &model.AuditLog{CreatedAt: base.Add(time.Minute), UserID: 1, Username: "admin", Action: model.ActionDelete,
		Resource: model.ResourceAsset, Status: model.StatusSuccess, Method: http.MethodDelete, Path: "/api/v1/assets/7"}
	for _, r := range []*model.AuditLog{retention, withPath} {
		if err := db.Create(r).Error; err != nil {
			t.Fatal(err)
		}
	}

	gin.SetMode(gin.TestMode)
	h := NewAuditLogHandler(audit.NewAuditLogService(&config.FeatureFlags{}))
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs?sort_by=created_at&sort_order=asc", nil)
	h.List(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("列表 %d: %s", rec.Code, rec.Body.String())
	}
	var list struct {
		Data  []map[string]any `json:"data"`
		Total int64            `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if list.Total != 2 || len(list.Data) != 2 {
		t.Fatalf("列表 total=%d rows=%d, want 2", list.Total, len(list.Data))
	}
	byID := map[float64]map[string]any{}
	for _, row := range list.Data {
		for _, k := range []string{"id", "created_at", "action", "resource", "status", "username"} {
			if _, ok := row[k]; !ok {
				t.Errorf("列表列缺原有欄位 %q：%v", k, row)
			}
		}
		id, _ := row["id"].(float64)
		byID[id] = row
	}
	r := byID[float64(retention.ID)]
	if r["details"] == nil || r["reason_code"] != "retention_purge" {
		t.Errorf("保留清除列 details=%v reason_code=%v", r["details"], r["reason_code"])
	}
	if p, _ := r["reason_params"].(map[string]any); p["target"] != "audit_logs" || p["deleted"] != "12" || p["days"] != "365" {
		t.Errorf("保留清除列 reason_params = %v", r["reason_params"])
	}
	w := byID[float64(withPath.ID)]
	if w["path"] != "/api/v1/assets/7" {
		t.Errorf("帶路徑列 path = %v", w["path"])
	}
	if _, ok := w["reason_code"]; ok {
		t.Errorf("帶路徑列不應有 reason_code：%v", w["reason_code"])
	}

	// 單筆
	rec = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(rec)
	id := strconv.FormatUint(uint64(retention.ID), 10)
	c.Params = gin.Params{{Key: "id", Value: id}}
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs/"+id, nil)
	h.Get(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("單筆 %d: %s", rec.Code, rec.Body.String())
	}
	var one map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &one); err != nil {
		t.Fatal(err)
	}
	if one["id"] != float64(retention.ID) || one["details"] == nil || one["reason_code"] != "retention_purge" {
		t.Errorf("單筆 id=%v details=%v reason_code=%v", one["id"], one["details"], one["reason_code"])
	}
}
