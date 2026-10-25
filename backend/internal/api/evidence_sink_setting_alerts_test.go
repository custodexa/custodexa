package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/offsite"
	"github.com/custodexa/backend/internal/testgate"
)

// ── 共用替身與讀取 ───────────────────────────────────────────────────────────

// switchableTxSink 交易內審計落地面；fail 時回錯（驗整筆回滾）。
type switchableTxSink struct {
	inner port.TxSink
	mu    sync.Mutex
	fail  bool
}

func (s *switchableTxSink) set(fail bool) { s.mu.Lock(); s.fail = fail; s.mu.Unlock() }
func (s *switchableTxSink) WriteInTx(tx *gorm.DB, ev port.AuditEvent) error {
	s.mu.Lock()
	fail := s.fail
	s.mu.Unlock()
	if fail {
		return errors.New("注入審計失敗")
	}
	return s.inner.WriteInTx(tx, ev)
}

// switchableAlertSink 系統告警落地面；fail 時回錯。
type switchableAlertSink struct {
	inner port.SystemAlertSink
	mu    sync.Mutex
	fail  bool
}

func (s *switchableAlertSink) set(fail bool) { s.mu.Lock(); s.fail = fail; s.mu.Unlock() }
func (s *switchableAlertSink) RaiseInTx(tx *gorm.DB, ev port.SystemAlertEvent) (port.SystemAlertReceipt, error) {
	s.mu.Lock()
	fail := s.fail
	s.mu.Unlock()
	if fail {
		return port.SystemAlertReceipt{}, errors.New("注入告警失敗")
	}
	return s.inner.RaiseInTx(tx, ev)
}

func alertDetails(t *testing.T, db *gorm.DB, typ port.SystemAlertType) []model.SystemAlertDetail {
	t.Helper()
	var rows []model.SystemAlertDetail
	if err := db.Where("alert_type = ?", string(typ)).Order("alert_id").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}

func alertParams(t *testing.T, d model.SystemAlertDetail) map[string]string {
	t.Helper()
	out := map[string]string{}
	if err := json.Unmarshal([]byte(d.Params), &out); err != nil {
		t.Fatalf("告警參數無法解析: %v", err)
	}
	return out
}

func auditRowsOf(t *testing.T, db *gorm.DB, resource model.AuditResource) []model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	if err := db.Where("resource = ?", string(resource)).Order("id").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}

func detailsMap(t *testing.T, s string) map[string]any {
	t.Helper()
	out := map[string]any{}
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		t.Fatalf("審計 details 無法解析: %v（%s）", err, s)
	}
	return out
}

// openEvidencePG 以 TEST_PG_DSN 開一個獨立 schema（不得回退 SQLite）。
func openEvidencePG(t *testing.T, prefix string) *gorm.DB {
	t.Helper()
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	schema := fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE")
		if s, err := admin.DB(); err == nil {
			_ = s.Close()
		}
	})
	db, err := gorm.Open(postgres.Open(dsn+" search_path="+schema), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if s, err := db.DB(); err == nil {
			_ = s.Close()
		}
	})
	if db.Dialector.Name() != "postgres" {
		t.Fatalf("PG 子案例的 dialector = %s", db.Dialector.Name())
	}
	fmt.Println("EVIDENCE dialect=postgres")
	return db
}

// advisoryHolder 回傳目前持有指定交易級諮詢鎖（bigint 鍵：pg_locks 的 classid／objid 為
// 高低 32 位元、objsubid=1）的後端 PID，並限定當前資料庫；必須恰有一個持有者，否則失敗。
// 同時回傳呼叫當下已在等這把鎖的 PID，供之後排除既有等待者。
func advisoryHolder(t *testing.T, db *gorm.DB, key int64) (int64, map[int64]bool) {
	t.Helper()
	hi, lo := uint32(key>>32), uint32(key)
	var holders []int64
	if err := db.Raw(`SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND database = (SELECT oid FROM pg_database WHERE datname = current_database()) AND classid = ? AND objid = ? AND objsubid = 1 AND granted`, hi, lo).Scan(&holders).Error; err != nil {
		t.Fatalf("查 pg_locks: %v", err)
	}
	if len(holders) != 1 {
		t.Fatalf("應恰有一個後端持有這把鎖，得 %v", holders)
	}
	var waiting []int64
	if err := db.Raw(`SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND database = (SELECT oid FROM pg_database WHERE datname = current_database()) AND classid = ? AND objid = ? AND objsubid = 1 AND NOT granted`, hi, lo).Scan(&waiting).Error; err != nil {
		t.Fatalf("查 pg_locks: %v", err)
	}
	pre := map[int64]bool{}
	for _, p := range waiting {
		pre[p] = true
	}
	return holders[0], pre
}

// waitAdvisoryWaiter 等到有一個新的後端（不是持有者、也不是呼叫 advisoryHolder 時就已在等的）
// 在當前資料庫內等指定的交易級諮詢鎖（NOT granted），且 pg_blocking_pids 指向持有者；逾時即失敗。
func waitAdvisoryWaiter(t *testing.T, db *gorm.DB, key int64, holder int64, pre map[int64]bool) {
	t.Helper()
	hi, lo := uint32(key>>32), uint32(key)
	deadline := time.Now().Add(10 * time.Second)
	for {
		var pids []int64
		if err := db.Raw(`SELECT l.pid FROM pg_locks l WHERE l.locktype = 'advisory' AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database()) AND l.classid = ? AND l.objid = ? AND l.objsubid = 1 AND NOT l.granted AND l.pid <> ? AND ? = ANY(pg_blocking_pids(l.pid))`, hi, lo, holder, holder).Scan(&pids).Error; err != nil {
			t.Fatalf("查 pg_locks: %v", err)
		}
		for _, p := range pids {
			if !pre[p] {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("10 秒內沒有看到請求 2 的後端在等這把交易級鎖（且被請求 1 擋住）：讀改寫沒有被序列化")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// ── syslog ──────────────────────────────────────────────────────────────────

type countingForwarder struct {
	mu      sync.Mutex
	reloads int
	onLoad  func()
}

func (f *countingForwarder) Reload() {
	f.mu.Lock()
	f.reloads++
	cb := f.onLoad
	f.mu.Unlock()
	if cb != nil {
		cb()
	}
}
func (f *countingForwarder) Dropped() uint64                    { return 0 }
func (f *countingForwarder) SendTest(model.SyslogSetting) error { return nil }
func (f *countingForwarder) count() int                         { f.mu.Lock(); defer f.mu.Unlock(); return f.reloads }

type syslogAlertEnv struct {
	db       *gorm.DB
	r        *gin.Engine
	policies *policy.SecurityPolicyService
	fw       *countingForwarder
	tx       *switchableTxSink
	alerts   *switchableAlertSink
}

func newSyslogAlertEnv(t *testing.T, db *gorm.DB) *syslogAlertEnv {
	t.Helper()
	if err := db.AutoMigrate(&model.SyslogSetting{}, &model.SecurityPolicy{}); err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(evidenceSinkModels()...); err != nil {
		t.Fatal(err)
	}
	policies := policy.NewSecurityPolicyService(db)
	fw := &countingForwarder{}
	h := NewSyslogSettingHandler(db, nil, nil)
	h.forwarder = fw
	h.SetTransmissionPolicy(policy.NewTransmissionPolicyService(policies, nil))
	txs := &switchableTxSink{inner: audit.NewTxSink()}
	als := &switchableAlertSink{inner: audit.NewSystemAlertSink(nil)}
	h.SetEvidenceSinks(txs, als)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(42))
		c.Set("username", "sec-admin")
	})
	r.PUT("/syslog-settings", h.Update)
	return &syslogAlertEnv{db: db, r: r, policies: policies, fw: fw, tx: txs, alerts: als}
}

func (e *syslogAlertEnv) put(t *testing.T, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	payload, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/syslog-settings", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.r.ServeHTTP(w, req)
	return w
}

func syslogBody(enabled bool, host string, port int, protocol string) map[string]any {
	return map[string]any{"enabled": enabled, "host": host, "port": port, "protocol": protocol}
}

func newSQLiteFile(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+filepath.Join(t.TempDir(), "ev.db")+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)"),
		&gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if s, err := db.DB(); err == nil {
			_ = s.Close()
		}
	})
	return db
}

// ── 金鑰拓撲 ──────────────────────────────────────────────────────────────

type topologyAlertEnv struct {
	h      *KeyManagementHandler
	db     *gorm.DB
	tx     *switchableTxSink
	alerts *switchableAlertSink
}

func newTopologyAlertEnv(t *testing.T, db *gorm.DB, provider string) *topologyAlertEnv {
	t.Helper()
	if err := db.AutoMigrate(&model.KEKTopology{}, &model.DataKey{}); err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(evidenceSinkModels()...); err != nil {
		t.Fatal(err)
	}
	h := NewKeyManagementHandler(db, nil, nil, "test-fp", nil)
	h.SetDeploymentKMSProvider(func() string { return provider })
	// 失敗留痕走正式審計服務（同步寫入 database.DB），斷言讀真實的審計列
	prev := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = prev })
	h.SetAuditService(audit.NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true}))
	env := &topologyAlertEnv{h: h, db: db,
		tx: &switchableTxSink{inner: audit.NewTxSink()}, alerts: &switchableAlertSink{inner: audit.NewSystemAlertSink(nil)}}
	h.SetEvidenceSinks(env.tx, env.alerts)
	return env
}

func (e *topologyAlertEnv) put(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(42))
		c.Set("username", "sec-admin")
	})
	r.PUT("/api/v1/keys/topology", e.h.UpdateKEKTopology)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/api/v1/keys/topology", strings.NewReader(body)))
	return w
}

func (e *topologyAlertEnv) rewrap(t *testing.T, region string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/keys/rewrap", nil)
	c.Set("userID", uint(42))
	c.Set("username", "sec-admin")
	e.h.persistRewrapTopology(c, &rewrapPayload{Mode: rewrapModeKMS, Region: region, KeyRef: "arn:aws:kms:x:1:key/k"})
	if w.Code != http.StatusOK && w.Code != 0 {
		t.Fatalf("重包流程寫拓撲不得改寫回應，得 %d", w.Code)
	}
}

// failedTopologyAudits 拓撲失敗留痕的真實審計列（status=failure、resource=key_management）。
func failedTopologyAudits(t *testing.T, db *gorm.DB) []model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	if err := db.Where("resource = ? AND status = ?", string(model.ResourceKeyManagement), string(model.StatusFailure)).
		Order("id").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}

func topologyRow(t *testing.T, db *gorm.DB) *model.KEKTopology {
	t.Helper()
	var rows []model.KEKTopology
	if err := db.Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		return nil
	}
	return &rows[0]
}

// TestEvidenceSinkSettingAlerts 擋：syslog、離機副本與金鑰拓撲的停用或改目的地沒有同交易審計與
// 系統告警、告警與審計的關聯識別對不上、審計或告警失敗卻半套生效（或已重載轉發器）、
// 並行讀改寫讀到同一舊值而漏報，以及拓撲兩條成功路徑的失敗回應錯置。
func TestEvidenceSinkSettingAlerts(t *testing.T) {
	// ── syslog ──
	t.Run("syslog/啟用改停用得 disabled 一筆", func(t *testing.T) {
		e := newSyslogAlertEnv(t, newSQLiteFile(t))
		if w := e.put(t, syslogBody(true, "log-a.internal", 6514, "tcp+tls")); w.Code != 200 {
			t.Fatalf("啟用失敗: %d %s", w.Code, w.Body.String())
		}
		before := len(alertDetails(t, e.db, port.SystemAlertOffsiteOrSyslogChanged))
		if w := e.put(t, syslogBody(false, "log-a.internal", 6514, "tcp+tls")); w.Code != 200 {
			t.Fatalf("停用失敗: %d %s", w.Code, w.Body.String())
		}
		al := alertDetails(t, e.db, port.SystemAlertOffsiteOrSyslogChanged)
		if len(al) != before+1 {
			t.Fatalf("停用應多一筆告警，得 %d→%d", before, len(al))
		}
		if p := alertParams(t, al[len(al)-1]); p["subject"] != "syslog" || p["change"] != "disabled" {
			t.Fatalf("參數不符: %v", p)
		}
		rows := auditRowsOf(t, e.db, model.ResourceSyslogSetting)
		last := detailsMap(t, rows[len(rows)-1].Details)
		if last["correlation_id"] != al[len(al)-1].CorrelationID {
			t.Fatalf("告警與審計的關聯識別不同: %v vs %s", last["correlation_id"], al[len(al)-1].CorrelationID)
		}
	})

	t.Run("syslog/啟用中改 host 得 destination_changed，before.host 為原 host", func(t *testing.T) {
		e := newSyslogAlertEnv(t, newSQLiteFile(t))
		e.put(t, syslogBody(true, "log-a.internal", 6514, "tcp+tls"))
		if w := e.put(t, syslogBody(true, "log-b.internal", 6514, "tcp+tls")); w.Code != 200 {
			t.Fatalf("改 host 失敗: %d %s", w.Code, w.Body.String())
		}
		al := alertDetails(t, e.db, port.SystemAlertOffsiteOrSyslogChanged)
		if p := alertParams(t, al[len(al)-1]); p["change"] != "destination_changed" {
			t.Fatalf("參數不符: %v", p)
		}
		rows := auditRowsOf(t, e.db, model.ResourceSyslogSetting)
		d := detailsMap(t, rows[len(rows)-1].Details)
		b, _ := d["before"].(map[string]any)
		if b["host"] != "log-a.internal" {
			t.Fatalf("before.host = %v, want log-a.internal", b["host"])
		}
		if d["correlation_id"] != al[len(al)-1].CorrelationID {
			t.Fatal("告警與審計的關聯識別不同")
		}
		if rows[len(rows)-1].UserID != 42 {
			t.Fatalf("審計操作者 = %d", rows[len(rows)-1].UserID)
		}
	})

	t.Run("syslog/停用改啟用到不同 port 得 destination_changed", func(t *testing.T) {
		e := newSyslogAlertEnv(t, newSQLiteFile(t))
		e.put(t, syslogBody(true, "log-a.internal", 6514, "tcp+tls"))
		e.put(t, syslogBody(false, "log-a.internal", 6514, "tcp+tls"))
		n := len(alertDetails(t, e.db, port.SystemAlertOffsiteOrSyslogChanged))
		e.put(t, syslogBody(true, "log-a.internal", 7514, "tcp+tls"))
		al := alertDetails(t, e.db, port.SystemAlertOffsiteOrSyslogChanged)
		if len(al) != n+1 || alertParams(t, al[len(al)-1])["change"] != "destination_changed" {
			t.Fatalf("停用改啟用到不同 port 應一筆 destination_changed，得 %d→%d", n, len(al))
		}
	})

	t.Run("syslog/只改 TLS CA 不告警、有審計", func(t *testing.T) {
		e := newSyslogAlertEnv(t, newSQLiteFile(t))
		e.put(t, syslogBody(true, "log-a.internal", 6514, "tcp+tls"))
		n := len(alertDetails(t, e.db, port.SystemAlertOffsiteOrSyslogChanged))
		audits := len(auditRowsOf(t, e.db, model.ResourceSyslogSetting))
		body := syslogBody(true, "log-a.internal", 6514, "tcp+tls")
		body["tls_ca"] = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
		if w := e.put(t, body); w.Code != 200 {
			t.Fatalf("改 CA 失敗: %d %s", w.Code, w.Body.String())
		}
		if len(alertDetails(t, e.db, port.SystemAlertOffsiteOrSyslogChanged)) != n {
			t.Fatal("只改 TLS CA 不得告警")
		}
		if len(auditRowsOf(t, e.db, model.ResourceSyslogSetting)) != audits+1 {
			t.Fatal("只改 TLS CA 仍須審計")
		}
	})

	t.Run("syslog/warn 傳輸風險確認留兩列審計，兩列與告警的關聯識別相同", func(t *testing.T) {
		e := newSyslogAlertEnv(t, newSQLiteFile(t))
		if _, err := e.policies.UpdateBatchAudited(map[string]string{policy.PolicyTransportSyslogLevel: policy.TransportLevelWarn},
			policy.PolicyActor{ID: 1, Name: "admin"}, func(*gorm.DB, policy.PolicyChange) error { return nil }); err != nil {
			t.Fatal(err)
		}
		body := syslogBody(true, "log-a.internal", 514, "tcp")
		body["risk_acknowledged"] = true
		if w := e.put(t, body); w.Code != 200 {
			t.Fatalf("warn＋確認失敗: %d %s", w.Code, w.Body.String())
		}
		ack := auditRowsOf(t, e.db, model.ResourceTransmission)
		upd := auditRowsOf(t, e.db, model.ResourceSyslogSetting)
		if len(ack) != 1 || len(upd) != 1 {
			t.Fatalf("應有風險確認與設定更新各一列，得 %d／%d", len(ack), len(upd))
		}
		ad, ud := detailsMap(t, ack[0].Details), detailsMap(t, upd[0].Details)
		if ad["event"] != "setting_ack" {
			t.Fatalf("風險確認列 event = %v", ad["event"])
		}
		al := alertDetails(t, e.db, port.SystemAlertOffsiteOrSyslogChanged)
		if len(al) != 1 || ad["correlation_id"] != al[0].CorrelationID || ud["correlation_id"] != al[0].CorrelationID {
			t.Fatalf("兩列審計與告警的關聯識別應相同: ack=%v upd=%v alert=%v", ad["correlation_id"], ud["correlation_id"], al)
		}
	})

	t.Run("syslog/審計或告警失敗設定不變、不重載；成功恰重載一次且在提交後", func(t *testing.T) {
		for _, inject := range []string{"audit", "alert"} {
			e := newSyslogAlertEnv(t, newSQLiteFile(t))
			e.put(t, syslogBody(true, "log-a.internal", 6514, "tcp+tls"))
			reloads := e.fw.count()
			e.tx.set(inject == "audit")
			e.alerts.set(inject == "alert")
			w := e.put(t, syslogBody(true, "log-b.internal", 6514, "tcp+tls"))
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("注入 %s 失敗應 500，得 %d", inject, w.Code)
			}
			if inject == "alert" && !strings.Contains(w.Body.String(), "INTERNAL_SYSTEM_ALERT_RAISE") {
				t.Fatalf("告警失敗應回告警寫入碼: %s", w.Body.String())
			}
			var row model.SyslogSetting
			e.db.First(&row, 1)
			if row.Host != "log-a.internal" {
				t.Fatalf("注入 %s 失敗後設定被改為 %s", inject, row.Host)
			}
			if e.fw.count() != reloads {
				t.Fatalf("注入 %s 失敗時不得重載轉發器", inject)
			}
		}
		e := newSyslogAlertEnv(t, newSQLiteFile(t))
		var seenHost string
		e.fw.onLoad = func() {
			var row model.SyslogSetting
			e.db.First(&row, 1)
			seenHost = row.Host
		}
		if w := e.put(t, syslogBody(true, "log-c.internal", 6514, "tcp+tls")); w.Code != 200 {
			t.Fatalf("成功路徑失敗: %d", w.Code)
		}
		if e.fw.count() != 1 {
			t.Fatalf("成功應恰重載一次，得 %d", e.fw.count())
		}
		if seenHost != "log-c.internal" {
			t.Fatalf("重載時另一連線讀到 %q：重載早於提交", seenHost)
		}
	})

	t.Run("postgres_concurrent_syslog", func(t *testing.T) {
		db := openEvidencePG(t, "p2g_syslog")
		e := newSyslogAlertEnv(t, db)
		if w := e.put(t, syslogBody(true, "log-a.internal", 6514, "tcp+tls")); w.Code != 200 {
			t.Fatalf("前置失敗: %d %s", w.Code, w.Body.String())
		}
		firstLocked, releaseFirst := make(chan struct{}), make(chan struct{})
		secondLocked := make(chan struct{}, 1)
		syslogSettingHooks.afterLock = func(host string) {
			switch host {
			case "log-b.internal":
				close(firstLocked)
				<-releaseFirst
			case "log-a.internal":
				secondLocked <- struct{}{}
			}
		}
		t.Cleanup(func() { syslogSettingHooks.afterLock = nil })
		release := sync.OnceFunc(func() { close(releaseFirst) })
		t.Cleanup(release)
		done := make(chan int, 2)
		go func() { done <- e.put(t, syslogBody(true, "log-b.internal", 6514, "tcp+tls")).Code }()
		<-firstLocked
		holderPID, preWaiters := advisoryHolder(t, db, syslogSettingLockKey)
		go func() { done <- e.put(t, syslogBody(true, "log-a.internal", 6514, "tcp+tls")).Code }()
		// 以 pg_locks 確認請求 2 確實在等同一把交易級鎖，才放行請求 1
		waitAdvisoryWaiter(t, db, syslogSettingLockKey, holderPID, preWaiters)
		select {
		case <-secondLocked:
			t.Fatal("請求 2 在請求 1 提交前取得了鎖")
		default:
		}
		release()
		for i := 0; i < 2; i++ {
			if c := <-done; c != 200 {
				t.Fatalf("並行請求回 %d", c)
			}
		}
		al := alertDetails(t, db, port.SystemAlertOffsiteOrSyslogChanged)
		var changed []model.SystemAlertDetail
		for _, d := range al {
			if alertParams(t, d)["change"] == "destination_changed" {
				changed = append(changed, d)
			}
		}
		// 前置啟用一筆＋並行兩筆
		if len(changed) != 3 {
			t.Fatalf("destination_changed 應 3 筆（前置 1＋並行 2），得 %d", len(changed))
		}
		rows := auditRowsOf(t, db, model.ResourceSyslogSetting)
		lastBefore, _ := detailsMap(t, rows[len(rows)-1].Details)["before"].(map[string]any)
		if lastBefore["host"] != "log-b.internal" {
			t.Fatalf("第二筆的 before.host = %v, want log-b.internal", lastBefore["host"])
		}
	})

	// ── 離機副本 ──
	t.Run("offsite/停用：保管鏈事件帶操作者與關聯識別，告警 disabled 一筆", func(t *testing.T) {
		env := newOffsiteAPIEnv(t)
		token := env.adminToken(t, 301)
		if w := env.do(t, http.MethodPut, "/api/v1/offsite-storage/settings", token, env.s3Payload("bucket-one")); w.Code != 200 {
			t.Fatalf("建立失敗: %d %s", w.Code, w.Body.String())
		}
		if n := len(env.alerts.all()); n != 0 {
			t.Fatalf("初次建立不得告警，得 %d", n)
		}
		before := len(env.journal.all())
		if w := env.do(t, http.MethodPost, "/api/v1/offsite-storage/settings/disable", token, map[string]any{}); w.Code != 200 {
			t.Fatalf("停用失敗: %d %s", w.Code, w.Body.String())
		}
		evs := env.journal.all()[before:]
		if len(evs) != 1 {
			t.Fatalf("停用應恰 1 筆保管鏈事件，得 %d", len(evs))
		}
		ev := evs[0]
		if ev.Actor == nil || ev.Actor.ID != 301 || ev.CorrelationID == "" {
			t.Fatalf("事件應帶操作者與關聯識別: %+v", ev)
		}
		for _, k := range []string{"old_generation_id", "result", "actor_id"} {
			if _, ok := ev.Details[k]; !ok {
				t.Fatalf("事件 details 缺 %s: %v", k, ev.Details)
			}
		}
		al := env.alerts.all()
		if len(al) != 1 || al[0].Change != offsite.OffsiteChangeDisabled || al[0].CorrelationID != ev.CorrelationID {
			t.Fatalf("告警不符: %+v", al)
		}
	})

	t.Run("offsite/確認切換：兩筆事件帶同一關聯識別，告警 destination_changed", func(t *testing.T) {
		env := newOffsiteAPIEnv(t)
		token := env.adminToken(t, 301)
		w := env.do(t, http.MethodPut, "/api/v1/offsite-storage/settings", token, env.s3Payload("bucket-one"))
		gen1 := uint(offsiteBody(t, w)["generation_id"].(float64))
		env.seedObject(t, gen1, 9001, offsite.StateUploaded)
		hint := offsiteBody(t, env.do(t, http.MethodPut, "/api/v1/offsite-storage/settings", token, env.s3Payload("bucket-two")))
		req := env.s3Payload("bucket-two")
		req["expected_current_generation_id"] = gen1
		req["settings_digest"] = hint["settings_digest"]
		before := len(env.journal.all())
		if w := env.do(t, http.MethodPost, "/api/v1/offsite-storage/settings/confirm", token, req); w.Code != 200 {
			t.Fatalf("確認失敗: %d %s", w.Code, w.Body.String())
		}
		evs := env.journal.all()[before:]
		if len(evs) != 2 || evs[0].CorrelationID == "" || evs[0].CorrelationID != evs[1].CorrelationID ||
			evs[0].Actor == nil || evs[1].Actor == nil || evs[0].Actor.ID != 301 {
			t.Fatalf("確認切換應兩筆帶同一關聯識別與操作者的事件: %+v", evs)
		}
		al := env.alerts.all()
		if len(al) != 1 || al[0].Change != offsite.OffsiteChangeDestinationChanged || al[0].CorrelationID != evs[0].CorrelationID {
			t.Fatalf("告警不符: %+v", al)
		}
	})

	t.Run("offsite/物件數為 0 時 Save 直接切換：不需確認、兩筆事件、告警一筆", func(t *testing.T) {
		env := newOffsiteAPIEnv(t)
		token := env.adminToken(t, 301)
		env.do(t, http.MethodPut, "/api/v1/offsite-storage/settings", token, env.s3Payload("bucket-one"))
		before := len(env.journal.all())
		w := env.do(t, http.MethodPut, "/api/v1/offsite-storage/settings", token, env.s3Payload("bucket-two"))
		if w.Code != 200 || offsiteBody(t, w)["needs_confirmation"] != false {
			t.Fatalf("物件數 0 應直接切換: %d %s", w.Code, w.Body.String())
		}
		evs := env.journal.all()[before:]
		if len(evs) != 2 || evs[0].CorrelationID == "" || evs[0].CorrelationID != evs[1].CorrelationID {
			t.Fatalf("直接切換應兩筆帶同一關聯識別的事件: %+v", evs)
		}
		al := env.alerts.all()
		if len(al) != 1 || al[0].Change != offsite.OffsiteChangeDestinationChanged {
			t.Fatalf("直接切換應告警一筆: %+v", al)
		}
	})

	t.Run("offsite/直接切換注入告警失敗：新世代不存在、舊世代未退役", func(t *testing.T) {
		env := newOffsiteAPIEnv(t)
		token := env.adminToken(t, 301)
		env.do(t, http.MethodPut, "/api/v1/offsite-storage/settings", token, env.s3Payload("bucket-one"))
		var beforeRows []model.OffsiteProfile
		env.db.Order("generation_id").Find(&beforeRows)
		env.alerts.mu.Lock()
		env.alerts.fail = true
		env.alerts.mu.Unlock()
		w := env.do(t, http.MethodPut, "/api/v1/offsite-storage/settings", token, env.s3Payload("bucket-two"))
		if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "INTERNAL_SYSTEM_ALERT_RAISE") {
			t.Fatalf("告警失敗應 500＋告警寫入碼: %d %s", w.Code, w.Body.String())
		}
		var afterRows []model.OffsiteProfile
		env.db.Order("generation_id").Find(&afterRows)
		if len(afterRows) != len(beforeRows) || afterRows[0].RetiredAt != nil || afterRows[0].Bucket != "bucket-one" {
			t.Fatalf("告警失敗後世代表被改動: before=%d after=%d", len(beforeRows), len(afterRows))
		}
		var objects int64
		env.db.Model(&model.OffsiteObject{}).Where("state = ?", offsite.StateForeign).Count(&objects)
		if objects != 0 {
			t.Fatal("告警失敗後帳冊列被轉 foreign")
		}
	})

	t.Run("offsite/同世代就地更新不告警；注入告警失敗時停用狀態不變", func(t *testing.T) {
		env := newOffsiteAPIEnv(t)
		token := env.adminToken(t, 301)
		env.do(t, http.MethodPut, "/api/v1/offsite-storage/settings", token, env.s3Payload("bucket-one"))
		same := env.s3Payload("bucket-one")
		delete(same, "access_key_id")
		delete(same, "secret_access_key")
		if w := env.do(t, http.MethodPut, "/api/v1/offsite-storage/settings", token, same); w.Code != 200 {
			t.Fatalf("就地更新失敗: %d %s", w.Code, w.Body.String())
		}
		if n := len(env.alerts.all()); n != 0 {
			t.Fatalf("同世代就地更新不得告警，得 %d", n)
		}
		env.alerts.mu.Lock()
		env.alerts.fail = true
		env.alerts.mu.Unlock()
		if w := env.do(t, http.MethodPost, "/api/v1/offsite-storage/settings/disable", token, map[string]any{}); w.Code != http.StatusInternalServerError {
			t.Fatalf("停用時告警失敗應 500，得 %d", w.Code)
		}
		var cur int64
		env.db.Model(&model.OffsiteProfile{}).Where("retired_at IS NULL").Count(&cur)
		if cur != 1 {
			t.Fatalf("告警失敗後現行世代應仍在，得 %d", cur)
		}
	})

	// ── 金鑰拓撲 ──
	const vaultA = `{"address":"https://vault-a.example:8200","transit_key_name":"kek","role_id":"r1"}`
	const vaultB = `{"address":"https://vault-b.example:8200","transit_key_name":"kek","role_id":"r1"}`

	t.Run("topology/端點改位址得一筆告警，change_kind 含 address、不含位址字串", func(t *testing.T) {
		e := newTopologyAlertEnv(t, newSQLiteFile(t), keyvault.TopologyProviderVault)
		e.put(t, vaultA)
		if w := e.put(t, vaultB); w.Code != 200 {
			t.Fatalf("改位址失敗: %d %s", w.Code, w.Body.String())
		}
		al := alertDetails(t, e.db, port.SystemAlertKeyTopologyChanged)
		if len(al) != 2 {
			t.Fatalf("兩次寫入應各一筆告警，得 %d", len(al))
		}
		p := alertParams(t, al[1])
		if p["change_kind"] != "address" || strings.Contains(al[1].Params, "vault-") {
			t.Fatalf("參數不符: %s", al[1].Params)
		}
		rows := auditRowsOf(t, e.db, model.ResourceKeyManagement)
		d := detailsMap(t, rows[len(rows)-1].Details)
		if d["correlation_id"] != al[1].CorrelationID || d["source"] != "topology_endpoint" {
			t.Fatalf("審計 details 不符: %v", d)
		}
	})

	t.Run("topology/重包流程寫入不同拓撲得一筆審計與告警，source 為 rewrap", func(t *testing.T) {
		e := newTopologyAlertEnv(t, newSQLiteFile(t), keyvault.TopologyProviderAWS)
		e.rewrap(t, "us-east-1")
		e.rewrap(t, "ap-northeast-1")
		al := alertDetails(t, e.db, port.SystemAlertKeyTopologyChanged)
		if len(al) != 2 || alertParams(t, al[1])["change_kind"] != "region" {
			t.Fatalf("重包寫拓撲應各一筆告警: %d", len(al))
		}
		rows := auditRowsOf(t, e.db, model.ResourceKeyManagement)
		if d := detailsMap(t, rows[len(rows)-1].Details); d["source"] != "rewrap" || d["correlation_id"] != al[1].CorrelationID {
			t.Fatalf("重包審計 details 不符: %v", d)
		}
	})

	t.Run("topology/前後相同不告警", func(t *testing.T) {
		e := newTopologyAlertEnv(t, newSQLiteFile(t), keyvault.TopologyProviderVault)
		e.put(t, vaultA)
		e.put(t, vaultA)
		if n := len(alertDetails(t, e.db, port.SystemAlertKeyTopologyChanged)); n != 1 {
			t.Fatalf("前後相同不得告警，得 %d 筆（含首次設定 1 筆）", n)
		}
	})

	t.Run("topology/端點注入審計或告警失敗：500、拓撲不變、成功告警 0、失敗審計 1", func(t *testing.T) {
		for _, inject := range []string{"audit", "alert"} {
			e := newTopologyAlertEnv(t, newSQLiteFile(t), keyvault.TopologyProviderVault)
			e.put(t, vaultA)
			alerts := len(alertDetails(t, e.db, port.SystemAlertKeyTopologyChanged))
			e.tx.set(inject == "audit")
			e.alerts.set(inject == "alert")
			w := e.put(t, vaultB)
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("注入 %s 失敗應 500，得 %d", inject, w.Code)
			}
			if inject == "alert" && !strings.Contains(w.Body.String(), "INTERNAL_SYSTEM_ALERT_RAISE") {
				t.Fatalf("告警失敗應回告警寫入碼: %s", w.Body.String())
			}
			if row := topologyRow(t, e.db); row == nil || row.Address != "https://vault-a.example:8200" {
				t.Fatalf("注入 %s 失敗後拓撲被改", inject)
			}
			if n := len(alertDetails(t, e.db, port.SystemAlertKeyTopologyChanged)); n != alerts {
				t.Fatalf("注入 %s 失敗後多了告警", inject)
			}
			rows := failedTopologyAudits(t, e.db)
			if len(rows) != 1 || rows[0].UserID != 42 || !strings.Contains(rows[0].RequestBody, "vault-b.example") ||
				!strings.Contains(rows[0].RequestBody, "rejected_code") {
				t.Fatalf("注入 %s 失敗應留 1 筆帶企圖值與原因的失敗審計列，得 %d 列 %+v", inject, len(rows), rows)
			}
		}
	})

	t.Run("topology/重包流程注入告警失敗：回應不變、拓撲不變、失敗審計記拓撲未同步", func(t *testing.T) {
		e := newTopologyAlertEnv(t, newSQLiteFile(t), keyvault.TopologyProviderAWS)
		e.rewrap(t, "us-east-1")
		alerts := len(alertDetails(t, e.db, port.SystemAlertKeyTopologyChanged))
		e.alerts.set(true)
		e.rewrap(t, "ap-northeast-1")
		if row := topologyRow(t, e.db); row == nil || row.Region != "us-east-1" {
			t.Fatal("告警失敗後拓撲被改")
		}
		if n := len(alertDetails(t, e.db, port.SystemAlertKeyTopologyChanged)); n != alerts {
			t.Fatal("告警失敗後多了告警")
		}
		rows := failedTopologyAudits(t, e.db)
		if len(rows) != 1 || !strings.Contains(rows[0].RequestBody, "ap-northeast-1") ||
			!strings.Contains(rows[0].RequestBody, "rewrap_topology_not_synced") || rows[0].UserID != 42 {
			t.Fatalf("應留 1 筆記下企圖值與「拓撲未同步」的失敗審計列，得 %d 列 %+v", len(rows), rows)
		}
	})

	t.Run("topology/不可編輯與驗證被拒的路徑只留失敗審計", func(t *testing.T) {
		e := newTopologyAlertEnv(t, newSQLiteFile(t), keyvault.TopologyProviderGCP)
		if w := e.put(t, `{}`); w.Code != http.StatusBadRequest {
			t.Fatalf("GCP 應 400，得 %d", w.Code)
		}
		v := newTopologyAlertEnv(t, newSQLiteFile(t), keyvault.TopologyProviderVault)
		if w := v.put(t, `{"address":"http://plain.example","transit_key_name":"kek","role_id":"r1"}`); w.Code != http.StatusBadRequest {
			t.Fatalf("明文位址應 400，得 %d", w.Code)
		}
		if len(failedTopologyAudits(t, e.db)) != 1 || len(failedTopologyAudits(t, v.db)) != 1 {
			t.Fatalf("被拒路徑應各 1 筆失敗審計列，得 %d／%d", len(failedTopologyAudits(t, e.db)), len(failedTopologyAudits(t, v.db)))
		}
		var okRows int64
		v.db.Model(&model.AuditLog{}).Where("resource = ? AND status = ?", string(model.ResourceKeyManagement), string(model.StatusSuccess)).Count(&okRows)
		if okRows != 0 {
			t.Fatalf("被拒路徑不得寫交易內成功審計，得 %d", okRows)
		}
	})

	t.Run("postgres_concurrent_topology", func(t *testing.T) {
		db := openEvidencePG(t, "p2g_topology")
		e := newTopologyAlertEnv(t, db, keyvault.TopologyProviderVault)
		if w := e.put(t, vaultA); w.Code != 200 {
			t.Fatalf("前置失敗: %d %s", w.Code, w.Body.String())
		}
		firstLocked, releaseFirst := make(chan struct{}), make(chan struct{})
		secondLocked := make(chan struct{}, 1)
		kekTopologyHooks.afterLock = func(address string) {
			switch address {
			case "https://vault-b.example:8200":
				close(firstLocked)
				<-releaseFirst
			case "https://vault-a.example:8200":
				secondLocked <- struct{}{}
			}
		}
		t.Cleanup(func() { kekTopologyHooks.afterLock = nil })
		release := sync.OnceFunc(func() { close(releaseFirst) })
		t.Cleanup(release)
		done := make(chan int, 2)
		go func() { done <- e.put(t, vaultB).Code }()
		<-firstLocked
		holderPID, preWaiters := advisoryHolder(t, db, keyvault.KEKTopologyLockKey)
		go func() { done <- e.put(t, vaultA).Code }()
		// 以 pg_locks 確認請求 2 確實在等同一把交易級鎖，才放行請求 1
		waitAdvisoryWaiter(t, db, keyvault.KEKTopologyLockKey, holderPID, preWaiters)
		select {
		case <-secondLocked:
			t.Fatal("請求 2 在請求 1 提交前取得了鎖")
		default:
		}
		release()
		for i := 0; i < 2; i++ {
			if c := <-done; c != 200 {
				t.Fatalf("並行請求回 %d", c)
			}
		}
		if n := len(alertDetails(t, db, port.SystemAlertKeyTopologyChanged)); n != 3 {
			t.Fatalf("告警應 3 筆（前置 1＋並行 2），得 %d", n)
		}
		rows := auditRowsOf(t, db, model.ResourceKeyManagement)
		if d := detailsMap(t, rows[len(rows)-1].Details); !strings.Contains(fmt.Sprint(d["before"]), "vault-b.example") {
			t.Fatalf("第二筆的 before = %v, want vault-b", d["before"])
		}
	})
}
