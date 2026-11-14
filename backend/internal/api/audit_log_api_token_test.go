package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// 稽核查詢回應帶出 token 欄位：列表與詳情的每一列帶 api_token_id／api_token_name（非 token 列不出現），
// 詳情另附 token 物件，列表可依 token 篩選，調查工作台的操作日誌事件同樣帶值。

type fakeAuditRefs map[uint]identity.APITokenAuditRef

func (f fakeAuditRefs) AuditRef(id uint) (identity.APITokenAuditRef, error) { return f[id], nil }

func seedTokenAuditRows(t *testing.T, db *gorm.DB) (viaToken, human, other uint) {
	t.Helper()
	at := time.Date(2026, 8, 10, 9, 0, 0, 0, time.UTC)
	mk := func(tokenID *uint, name string, offset time.Duration) uint {
		row := &model.AuditLog{Action: model.ActionUpdate, Resource: model.ResourceUser, Status: model.StatusSuccess,
			UserID: 9, Username: "owner", Method: http.MethodPut, Path: "/api/v1/users/4", CreatedAt: at.Add(offset)}
		if tokenID != nil {
			row.APITokenID, row.APITokenName = tokenID, &name
		}
		if err := db.Create(row).Error; err != nil {
			t.Fatal(err)
		}
		return row.ID
	}
	t1, t2 := uint(12), uint(13)
	return mk(&t1, "terraform-prod", 0), mk(nil, "", time.Minute), mk(&t2, "other-tool", 2*time.Minute)
}

func auditGet(t *testing.T, h *AuditLogHandler, id uint) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Params = gin.Params{{Key: "id", Value: jsonNumber(id)}}
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs/"+jsonNumber(id), nil)
	h.Get(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("detail %d: %d %s", id, rec.Code, rec.Body)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func jsonNumber(v uint) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// TestAuditLogListDetailAndTimelineCarryAPIToken 三個查詢回應在 token 操作的列上帶值（非空），人類工作階段的列不出現這些鍵。
func TestAuditLogListDetailAndTimelineCarryAPIToken(t *testing.T) {
	db := setupIPTimelineDB(t)
	viaToken, human, other := seedTokenAuditRows(t, db)
	exp := time.Date(2027, 1, 1, 15, 59, 59, 0, time.UTC)
	h := NewAuditLogHandler(audit.NewAuditLogService(&config.FeatureFlags{}), nil).WithAPITokenRefs(fakeAuditRefs{
		12: {Found: true, GrantedRoles: []identity.APITokenAuditRole{{RoleID: 5, Name: "身分管理員"}}, ExpiresAt: &exp},
	})

	// 列表：依 token 篩選只回該 token 的列，且列上帶識別與名稱
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs?api_token_id=12", nil)
	h.List(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	var list struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Data) != 1 || list.Data[0]["id"] != float64(viaToken) {
		t.Fatalf("依 token 篩選應只回列 %d：%v", viaToken, list.Data)
	}
	if list.Data[0]["api_token_id"] != float64(12) || list.Data[0]["api_token_name"] != "terraform-prod" {
		t.Fatalf("列表列應帶 token 欄位：%v", list.Data[0])
	}
	// 未篩選：人類工作階段的列不出現這兩個鍵
	rec = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs", nil)
	h.List(c)
	list.Data = nil
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Data) != 3 {
		t.Fatalf("未篩選應回 3 列：%d", len(list.Data))
	}
	for _, row := range list.Data {
		if row["id"] == float64(human) {
			if _, ok := row["api_token_id"]; ok {
				t.Fatal("人類工作階段的列不出現 api_token_id")
			}
			if _, ok := row["api_token_name"]; ok {
				t.Fatal("人類工作階段的列不出現 api_token_name")
			}
		}
	}
	// 篩選值不合法回參數錯誤
	rec = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs?api_token_id=abc", nil)
	h.List(c)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("不合法的篩選值應回 400：%d", rec.Code)
	}

	// 詳情：token 物件（名稱取列的快照，授權角色與到期取 token 列）
	detail := auditGet(t, h, viaToken)
	tok, ok := detail["api_token"].(map[string]any)
	if !ok {
		t.Fatalf("詳情應附 token 物件：%v", detail)
	}
	if tok["id"] != float64(12) || tok["name"] != "terraform-prod" || tok["owner_deleted"] != false || tok["expires_at"] != "2027-01-01T15:59:59Z" {
		t.Fatalf("token 物件：%v", tok)
	}
	roles, _ := tok["granted_roles"].([]any)
	if len(roles) != 1 || roles[0].(map[string]any)["role_id"] != float64(5) || roles[0].(map[string]any)["name"] != "身分管理員" {
		t.Fatalf("授權角色：%v", tok["granted_roles"])
	}
	if detail["api_token_id"] != float64(12) || detail["api_token_name"] != "terraform-prod" {
		t.Fatalf("詳情列應帶 token 欄位：%v", detail)
	}
	// token 列已不存在：仍附物件（名稱取快照），授權角色為空、所屬帳號視同已刪除
	gone := auditGet(t, h, other)["api_token"].(map[string]any)
	if gone["name"] != "other-tool" || gone["owner_deleted"] != true || len(gone["granted_roles"].([]any)) != 0 {
		t.Fatalf("token 列不存在時：%v", gone)
	}
	if _, ok := auditGet(t, h, human)["api_token"]; ok {
		t.Fatal("人類工作階段的列不附 token 物件")
	}

	// 調查工作台：操作日誌事件帶 token 欄位
	r := ipTimelineRouter(t, db)
	w := ipTimelineGet(t, r, "/api/v1/audit/timeline?subject=user&subject_id=9&types=audit_log&"+timelineWindow)
	if w.Code != http.StatusOK {
		t.Fatalf("timeline: %d %s", w.Code, w.Body)
	}
	var tl struct {
		Events []map[string]any `json:"events"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &tl); err != nil {
		t.Fatal(err)
	}
	var seenToken, seenHuman bool
	for _, ev := range tl.Events {
		switch ev["id"] {
		case "audit_log:" + jsonNumber(viaToken):
			seenToken = true
			if ev["api_token_id"] != float64(12) || ev["api_token_name"] != "terraform-prod" {
				t.Fatalf("工作台事件應帶 token 欄位：%v", ev)
			}
		case "audit_log:" + jsonNumber(human):
			seenHuman = true
			if _, ok := ev["api_token_id"]; ok {
				t.Fatal("人類工作階段的事件不出現 api_token_id")
			}
		}
	}
	if !seenToken || !seenHuman {
		t.Fatalf("工作台應含兩列：%v", tl.Events)
	}
}
