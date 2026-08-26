package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/seal"
	"github.com/custodexa/backend/pkg/crypto"
)

// 單實例守衛的組裝根測試：
//   - 鎖鍵撞號守衛（四把 64 位元鍵以匯出常數兩兩比對）。
//   - 狀態出口：GET /seal/status 含 instance_guard 粗狀態且不含識別資訊；
//     GET /instance-guard 非 admin 403、admin 200 含 holder.code，且審計留一列讀取。
//   - 事件 sink 的 details 對應（actor=operator via env、status 對應、欄位齊備、不含連線細節）。
//   - B 模式（sealwire）的 seal status 亦帶 instance_guard 欄。

// TestInstanceGuardLockKeyDistinct advisory lock 鍵撞號守衛（沿 TestLDAPDirectoryLockKeyDistinct 的先例）。
//
// 置於組裝根：internal/database 是 infra，不得反向 import keyvault／identity；組裝根已同時
// import 三者，故四把 64 位元鍵直接以匯出常數兩兩比對（identity 的兩把為此改為匯出常數，
// 只為跨包可見、不改語義）。任一鍵改名即編譯錯誤，不會靜默縮水。
func TestInstanceGuardLockKeyDistinct(t *testing.T) {
	keys := []struct {
		name string
		key  int64
	}{
		{"keyvault.KEKDataKeysLockKey", keyvault.KEKDataKeysLockKey},
		{"identity.LocalAdminLockKey", identity.LocalAdminLockKey},
		{"identity.LDAPDirectoryLockKey", identity.LDAPDirectoryLockKey},
		{"database.InstanceGuardLockKey", database.InstanceGuardLockKey},
	}
	if database.InstanceGuardLockKey != 0x6F74_6B65_6B00_0004 {
		t.Fatalf("InstanceGuardLockKey=%#x，登記值為 0x6F74_6B65_6B00_0004（keyspace 的 0x0004）", database.InstanceGuardLockKey)
	}
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[i].key == keys[j].key {
				t.Fatalf("advisory lock key 撞號：%s 與 %s 同為 %#x", keys[i].name, keys[j].name, keys[i].key)
			}
		}
	}
	// keyspace 登記處必須有 0x0004 一行
	reg, err := os.ReadFile(filepath.Join(guardModuleRoot(t), "internal", "modules", "keyvault", "key_manager_lock.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(reg), "0x0004") || !strings.Contains(string(reg), "InstanceGuardLockKey") {
		t.Fatal("key_manager_lock.go 的 keyspace 登記清單缺 0x0004（InstanceGuardLockKey）一行")
	}
}

// ── 狀態出口 ──────────────────────────────────────────────────────────────

const guardTestJWTSecret = "instance-guard-status-export-test-secret-only"

func sampleGuardView() api.InstanceGuardView {
	return api.InstanceGuardView{
		State:        "overridden",
		Since:        "2026-08-25T07:12:03Z",
		Reason:       "ack_startup",
		Instance:     api.InstanceGuardInstance{Hostname: "node-a", PID: 4242, StartedAt: "2026-08-25T07:12:00Z"},
		DBSessionPID: 555,
		Holder: &api.InstanceGuardHolder{
			ApplicationName: "custodexa-instance-guard", PID: 777,
			BackendStart: "2026-08-25T07:00:00Z", Code: "ab12cd34ef56", FingerprintSource: "pg_stat_activity",
		},
		Ack:       "ab12cd34ef56",
		LostTotal: 1,
		Peers:     1,
	}
}

// installGuardStatusDB 裝一個帶 users／audit_logs 的 sqlite（連線池 1，見 installCoverageAuditDB）。
func installGuardStatusDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("開 sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.AuditLog{}, &model.User{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for _, name := range []string{"guard-admin", "guard-user"} {
		email := name + "@example.invalid"
		u := model.User{Username: name, Email: &email, Password: "x"}
		if err := db.Create(&u).Error; err != nil {
			t.Fatalf("建使用者 %s: %v", name, err)
		}
	}
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })
	return db
}

// newGuardStatusRouter 以真 authService／同步 auditService 建 router，注入固定的守衛視圖。
func newGuardStatusRouter(t *testing.T, view api.InstanceGuardView) (*gin.Engine, *gorm.DB, map[string]string) {
	t.Helper()
	prev := gin.Mode()
	gin.SetMode(gin.TestMode)
	t.Cleanup(func() { gin.SetMode(prev) })

	db := installGuardStatusDB(t)
	d := testDeps(false, true)
	d.authService = identity.NewAuthService(guardTestJWTSecret, time.Hour)
	d.auditService = newCoverageAuditService()
	sealHandler := api.NewSealHandler(seal.NewUnsealed(nil), nil)
	sealHandler.SetInstanceGuardProbe(func() api.InstanceGuardStatus { return view.Coarse() })
	d.seal = sealHandler
	d.instanceGuard = api.NewInstanceGuardHandler(func() api.InstanceGuardView { return view })

	r := gin.New()
	registerRoutes(r, d)

	jwt := crypto.NewJWTManager(guardTestJWTSecret, time.Hour)
	admin, err := jwt.GenerateToken(1, "guard-admin", "guard-admin@example.invalid", "admin", crypto.AuthContext{})
	if err != nil {
		t.Fatal(err)
	}
	user, err := jwt.GenerateToken(2, "guard-user", "guard-user@example.invalid", "user", crypto.AuthContext{})
	if err != nil {
		t.Fatal(err)
	}
	return r, db, map[string]string{"admin": admin, "user": user}
}

func guardGet(r *gin.Engine, path, bearer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// TestInstanceGuardSealStatusExposesCoarseStateOnly /seal/status 含粗狀態、不含識別資訊。
func TestInstanceGuardSealStatusExposesCoarseStateOnly(t *testing.T) {
	r, db, _ := newGuardStatusRouter(t, sampleGuardView())

	w := guardGet(r, "/api/v1/seal/status", "")
	if w.Code != http.StatusOK {
		t.Fatalf("/seal/status 回 %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		InstanceGuard *api.InstanceGuardStatus `json:"instance_guard"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.InstanceGuard == nil {
		t.Fatalf("/seal/status 缺 instance_guard 欄：%s", w.Body.String())
	}
	if body.InstanceGuard.State != "overridden" || body.InstanceGuard.Reason != "ack_startup" ||
		body.InstanceGuard.Peers != 1 || body.InstanceGuard.Since != "2026-08-25T07:12:03Z" {
		t.Fatalf("粗狀態欄位不符：%+v", body.InstanceGuard)
	}
	// 識別資訊以 JSON 鍵與值比對（`"ack":` 而非裸 `ack`——reason 的 `ack_startup` 是合法值）
	raw := w.Body.String()
	for _, banned := range []string{`"holder"`, `"ack":`, `"hostname"`, `"instance"`, `"db_session_pid"`, "ab12cd34ef56", "node-a", "4242"} {
		if strings.Contains(raw, banned) {
			t.Errorf("/seal/status 不得含識別資訊 %q：%s", banned, raw)
		}
	}
	// 粗狀態出口不寫審計列（鏈中無認證中介層，供介面輪詢）
	if n := countAuditRows(t, db); n != 0 {
		t.Fatalf("/seal/status 的輪詢不得產生審計列，實得 %d", n)
	}
}

// TestInstanceGuardEndpointAdminOnly /instance-guard 非 admin 403、無憑證 401、admin 200 含全貌並留讀取列。
func TestInstanceGuardEndpointAdminOnly(t *testing.T) {
	r, db, tokens := newGuardStatusRouter(t, sampleGuardView())

	if w := guardGet(r, "/api/v1/instance-guard", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("無憑證回 %d，want 401", w.Code)
	}
	if w := guardGet(r, "/api/v1/instance-guard", tokens["user"]); w.Code != http.StatusForbidden {
		t.Fatalf("非 admin 回 %d，want 403：%s", w.Code, w.Body.String())
	}
	before := countAuditRows(t, db)

	w := guardGet(r, "/api/v1/instance-guard", tokens["admin"])
	if w.Code != http.StatusOK {
		t.Fatalf("admin 回 %d，want 200：%s", w.Code, w.Body.String())
	}
	var view api.InstanceGuardView
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.Holder == nil || view.Holder.Code != "ab12cd34ef56" || view.Ack != "ab12cd34ef56" ||
		view.Instance.Hostname != "node-a" || view.Instance.PID != 4242 || view.LostTotal != 1 || view.Peers != 1 ||
		view.DBSessionPID != 555 || view.Holder.FingerprintSource != "pg_stat_activity" {
		t.Fatalf("全貌欄位不齊：%s", w.Body.String())
	}

	// 每次呼叫一列讀取留痕，resource=instance_guard：admin 成功一列；
	// 非 admin 的 403 另有一列 denied（既有的拒絕留痕），同資源分類
	var rows []model.AuditLog
	if err := db.Unscoped().Where("resource = ?", model.ResourceInstanceGuard).Order("id ASC").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	var success, denied int
	for _, row := range rows {
		if row.Action != model.ActionRead {
			t.Errorf("守衛端點的審計列 action=%s，want read：%+v", row.Action, row)
		}
		switch {
		case row.Status == model.StatusSuccess && row.UserID == 1:
			success++
		case row.Status == model.StatusDenied && row.UserID == 2:
			denied++
		default:
			t.Errorf("非預期的審計列：%+v", row)
		}
	}
	if success != 1 || denied != 1 {
		t.Fatalf("admin 讀取應留恰一列 success（user 1）、非 admin 應留恰一列 denied（user 2），實得 success=%d denied=%d（總列數 %d→%d）",
			success, denied, before, countAuditRows(t, db))
	}
}

// TestInstanceGuardBModeSealStatusCarriesGuardField B 模式（sealwire 接線）的 /seal/status 亦帶 instance_guard 欄。
//
// A／C 模式的接線在 main.go（不可測），由部署後的人工驗證承接；此格證明 sealwire 那一側沒漏接。
func TestInstanceGuardBModeSealStatusCarriesGuardField(t *testing.T) {
	env := newSealIntegrationEnv(t)
	w := env.do(http.MethodGet, "/api/v1/seal/status", "")
	if w.Code != http.StatusOK {
		t.Fatalf("/seal/status 回 %d: %s", w.Code, w.Body.String())
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, ok := body["instance_guard"]; !ok {
		t.Fatalf("B 模式 /seal/status 缺 instance_guard 欄（sealwire 未接探針）：%s", w.Body.String())
	}
}

// ── 事件 sink 的 details 對應 ─────────────────────────────────────────

func TestInstanceGuardEventDetails(t *testing.T) {
	at := time.Date(2026, 8, 25, 7, 12, 3, 0, time.UTC)
	holder := &database.HolderFingerprint{ApplicationName: "custodexa-instance-guard", PID: 777,
		BackendStart: "2026-08-25T07:00:00Z", Code: "ab12cd34ef56", Source: "pg_stat_activity"}
	base := database.GuardEvent{
		At:           at,
		Instance:     database.GuardInstance{Hostname: "node-a", PID: 4242, StartedAt: at.Add(-time.Minute)},
		DBSessionPID: 555,
		LostTotal:    1,
	}

	t.Run("overridden 含 ack、持鎖者指紋與 actor", func(t *testing.T) {
		ev := base
		ev.Event, ev.Reason, ev.Ack, ev.Holder = database.GuardEventOverridden, database.GuardReasonAckStartup, "ab12cd34ef56", holder
		d := instanceGuardEventDetails(ev)
		if d["actor"] != "operator via env" || d["ack"] != "ab12cd34ef56" || d["reason"] != "ack_startup" {
			t.Fatalf("overridden details 不齊：%v", d)
		}
		h := d["holder"].(map[string]any)
		if h["code"] != "ab12cd34ef56" || h["fingerprint_source"] != "pg_stat_activity" || h["pid"] != int64(777) {
			t.Fatalf("holder 欄位不齊：%v", h)
		}
		inst := d["instance"].(map[string]any)
		if inst["hostname"] != "node-a" || inst["pid"] != 4242 || inst["started_at"] != "2026-08-25T07:11:03Z" {
			t.Fatalf("instance 欄位不齊：%v", inst)
		}
		if d["db_session_pid"] != 555 || d["at"] != "2026-08-25T07:12:03Z" {
			t.Fatalf("db_session_pid／at 不齊：%v", d)
		}
		body, _ := json.Marshal(d)
		for _, banned := range []string{"password", "host=", "dbname", "client_addr", "user="} {
			if strings.Contains(string(body), banned) {
				t.Errorf("details 不得含 %q：%s", banned, body)
			}
		}
	})

	t.Run("lost 含 reason；contention 才帶持鎖者", func(t *testing.T) {
		ev := base
		ev.Event, ev.Reason = database.GuardEventLost, database.GuardReasonDBUnreachable
		d := instanceGuardEventDetails(ev)
		if d["reason"] != "db_unreachable" || d["holder"] != nil || d["actor"] != nil || d["ack"] != nil {
			t.Fatalf("lost{db_unreachable} details 不符：%v", d)
		}
		ev.Reason, ev.Holder = database.GuardReasonContention, holder
		d = instanceGuardEventDetails(ev)
		if d["reason"] != "contention" || d["holder"] == nil {
			t.Fatalf("lost{contention} 應含持鎖者：%v", d)
		}
	})

	t.Run("regained 含 unheld_for_ms", func(t *testing.T) {
		ev := base
		ev.Event, ev.Reason, ev.UnheldForMS = database.GuardEventRegained, database.GuardReasonAckStartup, 1234
		d := instanceGuardEventDetails(ev)
		if d["unheld_for_ms"] != int64(1234) || d["lost_total"] != uint64(1) {
			t.Fatalf("regained details 不符：%v", d)
		}
	})
}

// TestInstanceGuardAuditSinkWritesSystemRows sink 以系統主體寫列：status 對應與時間戳為事件當下。
func TestInstanceGuardAuditSinkWritesSystemRows(t *testing.T) {
	db := installGuardStatusDB(t)
	svc := newCoverageAuditService()
	sink := instanceGuardAuditSink(svc)

	at := time.Date(2026, 8, 25, 7, 12, 3, 0, time.UTC)
	for _, ev := range []database.GuardEvent{
		{Event: database.GuardEventOverridden, Reason: database.GuardReasonAckStartup, At: at, Ack: "ab12cd34ef56"},
		{Event: database.GuardEventLost, Reason: database.GuardReasonContention, At: at.Add(time.Minute)},
		{Event: database.GuardEventRegained, Reason: database.GuardReasonContention, At: at.Add(2 * time.Minute), UnheldForMS: 60000},
	} {
		sink(ev)
	}

	var rows []model.AuditLog
	if err := db.Unscoped().Where("resource = ?", model.ResourceInstanceGuard).Order("id ASC").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("三事件應各寫一列，實得 %d", len(rows))
	}
	wantStatus := []model.AuditStatus{model.StatusFailure, model.StatusFailure, model.StatusSuccess}
	for i, row := range rows {
		if row.UserID != 0 || row.Username != "system" || row.Action != model.ActionExecute {
			t.Errorf("第 %d 列主體／動作不符：%+v", i, row)
		}
		if row.Status != wantStatus[i] {
			t.Errorf("第 %d 列 status=%s，want %s（regained→success、lost／overridden→failure）", i, row.Status, wantStatus[i])
		}
		if !row.CreatedAt.Equal(at.Add(time.Duration(i) * time.Minute)) {
			t.Errorf("第 %d 列 created_at=%v，want 事件當下 %v（緩衝補寫不得以入列時刻頂替）", i, row.CreatedAt, at.Add(time.Duration(i)*time.Minute))
		}
		var d map[string]any
		if err := json.Unmarshal([]byte(row.Details), &d); err != nil {
			t.Fatalf("第 %d 列 details 非 JSON: %v", i, err)
		}
		if d["event"] == nil || d["reason"] == nil || d["instance"] == nil {
			t.Errorf("第 %d 列 details 缺基本欄位：%s", i, row.Details)
		}
	}
	if !strings.Contains(rows[0].Details, `"actor":"operator via env"`) {
		t.Errorf("overridden 列應含 actor=operator via env：%s", rows[0].Details)
	}
}
