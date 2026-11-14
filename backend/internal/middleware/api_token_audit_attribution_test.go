package middleware

import (
	"net/http/httptest"
	"testing"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/gin-gonic/gin"
)

// 請求層級的稽核歸因：經 API token 認證的請求，HTTP 稽核中介層的列與 handler 自組的條目、請求欄位
// 都帶 token 的識別與名稱快照；人類工作階段的列兩欄為空。

func (f *apiTokenGateFixture) attributionRouter(t *testing.T, handler gin.HandlerFunc) *gin.Engine {
	t.Helper()
	if err := f.db.AutoMigrate(&model.AuditLog{}); err != nil {
		t.Fatal(err)
	}
	old := database.DB
	database.DB = f.db
	t.Cleanup(func() { database.DB = old })
	r := gin.New()
	r.Use(AuditLogMiddleware(newAnonAuditService()), AgentRouteAllowlist(f.auth), (&apiTokenGate{auth: f.auth, decide: allowAllAPITokenRoutes}).Handle)
	r.PUT("/api/v1/users/:id/roles", AuthMiddleware(f.auth), handler)
	return r
}

func (f *apiTokenGateFixture) auditRowsSince(t *testing.T, after uint) []model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	if err := f.db.Where("id > ?", after).Order("id").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}

func (f *apiTokenGateFixture) maxAuditID(t *testing.T) uint {
	t.Helper()
	var id uint
	if err := f.db.Raw("SELECT COALESCE(MAX(id), 0) FROM audit_logs").Scan(&id).Error; err != nil {
		t.Fatal(err)
	}
	return id
}

// TestAPITokenRoleAssignmentRequestRowAttributed 以 token 呼叫角色指派端點：中介層的請求列帶 token 識別與名稱；
// 人類工作階段呼叫同一端點，請求列兩欄為空。
func TestAPITokenRoleAssignmentRequestRowAttributed(t *testing.T) {
	f := newAPITokenGateFixture(t)
	r := f.attributionRouter(t, func(c *gin.Context) { c.Status(200) })

	before := f.maxAuditID(t)
	if w := bearerRequest(r, "PUT", "/api/v1/users/5/roles", f.plain); w.Code != 200 {
		t.Fatalf("token: %d %s", w.Code, w.Body)
	}
	rows := f.auditRowsSince(t, before)
	if len(rows) == 0 {
		t.Fatal("中介層應落地請求列")
	}
	for _, row := range rows {
		if row.APITokenID == nil || *row.APITokenID != f.tokenID || row.APITokenName == nil || *row.APITokenName != "terraform" {
			t.Fatalf("請求列應帶 token 標示：id=%v name=%v", row.APITokenID, row.APITokenName)
		}
	}

	before = f.maxAuditID(t)
	if w := bearerRequest(r, "PUT", "/api/v1/users/5/roles", f.humanToken(t)); w.Code != 200 {
		t.Fatalf("human: %d %s", w.Code, w.Body)
	}
	rows = f.auditRowsSince(t, before)
	if len(rows) == 0 {
		t.Fatal("人類工作階段同樣落地請求列")
	}
	for _, row := range rows {
		if row.APITokenID != nil || row.APITokenName != nil {
			t.Fatalf("親自操作的列不帶 token 標示：id=%v name=%v", row.APITokenID, row.APITokenName)
		}
	}
}

// TestAPITokenHandlerEntryAndMetaAttributed handler 自組的稽核條目與寫入面請求欄位，經歸因函式補上 token 標示；
// 人類工作階段原樣不動。
func TestAPITokenHandlerEntryAndMetaAttributed(t *testing.T) {
	f := newAPITokenGateFixture(t)
	var entry *audit.AuditLogEntry
	var meta gatewayapi.RequestMeta
	r := f.attributionRouter(t, func(c *gin.Context) {
		entry = AttributeAuditEntry(c, &audit.AuditLogEntry{Action: model.ActionUpdate, Resource: model.ResourceUser})
		meta = AttributeAuditMeta(c, gatewayapi.RequestMeta{ClientIP: "192.0.2.8"})
		c.Status(200)
	})
	if w := bearerRequest(r, "PUT", "/api/v1/users/5/roles", f.plain); w.Code != 200 {
		t.Fatalf("token: %d", w.Code)
	}
	if entry.APITokenID == nil || *entry.APITokenID != f.tokenID || entry.APITokenName != "terraform" {
		t.Fatalf("條目應帶 token 標示：%v %q", entry.APITokenID, entry.APITokenName)
	}
	if meta.APITokenID == nil || *meta.APITokenID != f.tokenID || meta.APITokenName != "terraform" {
		t.Fatalf("請求欄位應帶 token 標示：%v %q", meta.APITokenID, meta.APITokenName)
	}
	if w := bearerRequest(r, "PUT", "/api/v1/users/5/roles", f.humanToken(t)); w.Code != 200 {
		t.Fatalf("human: %d", w.Code)
	}
	if entry.APITokenID != nil || entry.APITokenName != "" || meta.APITokenID != nil || meta.APITokenName != "" {
		t.Fatal("人類工作階段的條目與請求欄位不帶 token 標示")
	}
	// 沒有 gin 脈絡的 token 標示（未經閘門）不會憑空出現
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	if got := AttributeAuditEntry(c, &audit.AuditLogEntry{}); got.APITokenID != nil {
		t.Fatal("未經閘門的脈絡不帶標示")
	}
}
