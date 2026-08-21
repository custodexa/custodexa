package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 連線樞紐涵蓋子資源（clipboard-read-provenance）。
//
// 缺口：剪貼簿取證讀取自 ResourceClipboardEvent 起獨立分類後，
// `GET /audit-logs/resource/session/:id` 的白名單只認 session，稽核查一場連線
// 再也看不到「誰在這場連線裡取走了剪貼簿內容」——取證動作是連線調查中最該
// 出現的一項，卻因分類變細而從樞紐消失。
//
// **突變自證**：把 model.AuditHubSubResources 的 ResourceSession 條目清空
//（或移除 ResourceClipboardEvent），本檔第一個案例即紅（total 3→2、缺該列）。
// 把 handler 的排序拿掉則第一個案例的時序斷言紅。
// 還原一律用事前 cp 快照，禁用 git checkout。

// installAuditHubDB 裝一個只含 audit_logs 的最小 database.DB。
// `:memory:` 必須把連線池釘成 1——多連線各自拿到獨立的空記憶體庫，
// 寫入與讀取會落在不同庫而製造假紅（見 clipboard tap flaky 的真因）。
func installAuditHubDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.AuditLog{}); err != nil {
		t.Fatalf("migrate audit_logs: %v", err)
	}
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })
	return db
}

func seedAuditRow(t *testing.T, db *gorm.DB, resource model.AuditResource, resourceID uint, at time.Time) {
	t.Helper()
	row := &model.AuditLog{
		Action:     model.ActionRead,
		Resource:   resource,
		ResourceID: &resourceID,
		Status:     model.StatusSuccess,
		UserID:     1,
		Username:   "auditor",
		Method:     http.MethodGet,
		Path:       "/api/v1/seed",
		CreatedAt:  at,
	}
	if err := db.Create(row).Error; err != nil {
		t.Fatalf("seed %s/%d: %v", resource, resourceID, err)
	}
}

type hubResponse struct {
	Resource   string `json:"resource"`
	ResourceID uint   `json:"resource_id"`
	Total      int    `json:"total"`
	Logs       []struct {
		Resource   string    `json:"resource"`
		ResourceID uint      `json:"resource_id"`
		CreatedAt  time.Time `json:"created_at"`
	} `json:"logs"`
}

func callHub(t *testing.T, resource, id string) (int, hubResponse) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	h := NewAuditLogHandler(audit.NewAuditLogService(&config.FeatureFlags{}))
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs/resource/"+resource+"/"+id, nil)
	c.Params = gin.Params{{Key: "resource", Value: resource}, {Key: "id", Value: id}}
	h.GetByResourceID(c)

	var body hubResponse
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("解析回應失敗: %v (body=%s)", err, rec.Body.String())
		}
	}
	return rec.Code, body
}

func TestSessionHubIncludesClipboardEvidenceReads(t *testing.T) {
	db := installAuditHubDB(t)
	base := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)

	seedAuditRow(t, db, model.ResourceSession, 7, base)                    // 看了一眼連線詳情
	seedAuditRow(t, db, model.ResourceClipboardEvent, 7, base.Add(2*time.Minute)) // 取走剪貼簿證物
	seedAuditRow(t, db, model.ResourceSession, 7, base.Add(4*time.Minute))
	// 干擾組：同分類但別場連線，樞紐不得撈到
	seedAuditRow(t, db, model.ResourceClipboardEvent, 8, base.Add(time.Minute))
	seedAuditRow(t, db, model.ResourceSession, 8, base.Add(time.Minute))

	code, body := callHub(t, "session", "7")
	if code != http.StatusOK {
		t.Fatalf("狀態碼 = %d，預期 200", code)
	}
	if body.Resource != "session" || body.ResourceID != 7 {
		t.Fatalf("樞紐識別回應漂移: resource=%q resource_id=%d", body.Resource, body.ResourceID)
	}
	if body.Total != 3 || len(body.Logs) != 3 {
		t.Fatalf("total=%d len(logs)=%d，預期 3（兩筆連線讀取＋一筆剪貼簿取證）", body.Total, len(body.Logs))
	}

	clipboard := 0
	for _, l := range body.Logs {
		if l.ResourceID != 7 {
			t.Fatalf("撈到別場連線的列: resource=%s resource_id=%d", l.Resource, l.ResourceID)
		}
		if l.Resource == string(model.ResourceClipboardEvent) {
			clipboard++
		}
	}
	if clipboard != 1 {
		t.Fatalf("剪貼簿取證列數 = %d，預期 1——連線樞紐須答得出「誰取走了這場連線的剪貼簿內容」", clipboard)
	}

	// 合併後仍是單一時間軸（倒序）
	for i := 1; i < len(body.Logs); i++ {
		if body.Logs[i-1].CreatedAt.Before(body.Logs[i].CreatedAt) {
			t.Fatalf("合併後時序錯亂: [%d]=%s 早於 [%d]=%s",
				i-1, body.Logs[i-1].CreatedAt, i, body.Logs[i].CreatedAt)
		}
	}
}

func TestNonSessionHubUnaffectedBySubResourceExpansion(t *testing.T) {
	db := installAuditHubDB(t)
	base := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)

	seedAuditRow(t, db, model.ResourceAsset, 7, base)
	seedAuditRow(t, db, model.ResourceClipboardEvent, 7, base.Add(time.Minute))
	seedAuditRow(t, db, model.ResourceSession, 7, base.Add(2*time.Minute))

	code, body := callHub(t, "asset", "7")
	if code != http.StatusOK {
		t.Fatalf("狀態碼 = %d，預期 200", code)
	}
	if body.Total != 1 || len(body.Logs) != 1 || body.Logs[0].Resource != string(model.ResourceAsset) {
		t.Fatalf("資產樞紐被污染: total=%d logs=%+v——展開只適用於 id 空間相同的子資源", body.Total, body.Logs)
	}
}

// id 空間不同的分類不得入列：change_secret_plan／authorization 的 resource_id
// 是計畫 id／授權列 id，展開會把別的實體的事件掛到連線上（產生假事件）。
// 本斷言是「同型缺陷換條路徑」的擋板——D1.3(a) 訂正過的缺陷不得由樞紐展開重生。
func TestHubSubResourcesExcludeForeignIDSpaces(t *testing.T) {
	forbidden := map[model.AuditResource]bool{
		model.ResourceChangeSecretPlan: true,
		model.ResourceAuthorization:    true,
		model.ResourceAuditTimeline:    true,
		model.ResourceUser:             true,
		model.ResourceAsset:            true,
	}
	for hub, subs := range model.AuditHubSubResources {
		for _, sub := range subs {
			if forbidden[sub] {
				t.Fatalf("樞紐 %s 展開了 id 空間不同的 %s——會產生假事件", hub, sub)
			}
			if sub == hub {
				t.Fatalf("樞紐 %s 把自身列為子資源，會重複計數", hub)
			}
		}
	}
	if len(model.AuditHubSubResources[model.ResourceSession]) == 0 {
		t.Fatal("連線樞紐無任何子資源涵蓋——剪貼簿取證讀取將從連線調查中消失")
	}
}

// TestSessionHubIncludesRecordingAndCommandRetrieval 連線樞紐須帶出錄影調閱與
// 指令查詢（audit-resource-classification-closure 批 1）。
//
// 缺口：兩族自 session 拆出獨立分類後，若不同批加進 AuditHubSubResources，
// 稽核查一場連線就再也看不到「誰取走了這場連線的錄影／指令原文」——那是**真事件
// 消失**，比分不出兩者更糟（A 類訂正撈不到的全是假事件，此處不是）。
//
// **突變自證**：把 model.AuditHubSubResources[ResourceSession] 的
// ResourceRecording／ResourceCommand 移除，本案例即紅（total 4→2、缺該兩列）。
func TestSessionHubIncludesRecordingAndCommandRetrieval(t *testing.T) {
	db := installAuditHubDB(t)
	base := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)

	seedAuditRow(t, db, model.ResourceSession, 7, base)                           // 看了一眼連線詳情
	seedAuditRow(t, db, model.ResourceRecording, 7, base.Add(time.Minute))        // 取走錄影本體
	seedAuditRow(t, db, model.ResourceCommand, 7, base.Add(2*time.Minute))        // 取走指令原文
	seedAuditRow(t, db, model.ResourceClipboardEvent, 7, base.Add(3*time.Minute)) // 取走剪貼簿明文
	// 干擾組：同分類但別場連線，樞紐不得撈到
	seedAuditRow(t, db, model.ResourceRecording, 8, base.Add(time.Minute))
	seedAuditRow(t, db, model.ResourceCommand, 8, base.Add(time.Minute))

	code, body := callHub(t, "session", "7")
	if code != http.StatusOK {
		t.Fatalf("狀態碼 = %d，預期 200", code)
	}
	if body.Total != 4 || len(body.Logs) != 4 {
		t.Fatalf("total=%d len(logs)=%d，預期 4（連線讀取＋錄影／指令／剪貼簿三種取證）",
			body.Total, len(body.Logs))
	}

	seen := map[string]int{}
	for _, l := range body.Logs {
		if l.ResourceID != 7 {
			t.Fatalf("撈到別場連線的列: resource=%s resource_id=%d", l.Resource, l.ResourceID)
		}
		seen[l.Resource]++
	}
	for _, want := range []model.AuditResource{
		model.ResourceRecording, model.ResourceCommand, model.ResourceClipboardEvent,
	} {
		if seen[string(want)] != 1 {
			t.Errorf("%s 取證列數 = %d，預期 1——連線樞紐須答得出「誰取走了這場連線的%s」",
				want, seen[string(want)], want)
		}
	}
}

// TestRecordingHubTypeRemoved `recording` 已非樞紐型別（批 1，design D4 面 3）。
//
// 其 resource_id 自批 1 起是**連線 id**（`/sessions/:id/recording*`）或 nil，
// 沒有一種是「錄影列 id」，留在白名單即違反「各型的 :id 指向該型自身實體 id」。
// 移除代價為零——訂正前 `/recordings/*` 的 resource_id 恆 nil，該入口永遠空集。
func TestRecordingHubTypeRemoved(t *testing.T) {
	db := installAuditHubDB(t)
	seedAuditRow(t, db, model.ResourceRecording, 7, time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC))

	code, _ := callHub(t, "recording", "7")
	if code != http.StatusBadRequest {
		t.Fatalf("狀態碼 = %d，預期 400——recording 若仍是樞紐型，`:id` 語義就是"+
			"「錄影列 id」而實際塞的是連線 id，回的會是語義虛假的結果集", code)
	}

	// 反向：連線樞紐才是錄影調閱的正確入口，同一筆列須在此撈得到
	code, body := callHub(t, "session", "7")
	if code != http.StatusOK {
		t.Fatalf("連線樞紐狀態碼 = %d，預期 200", code)
	}
	if body.Total != 1 || len(body.Logs) != 1 || body.Logs[0].Resource != string(model.ResourceRecording) {
		t.Fatalf("錄影調閱未由連線樞紐承接: total=%d logs=%+v", body.Total, body.Logs)
	}
}
