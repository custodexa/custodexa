package audit

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/testgate"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// audit-checkpoint-chain 第 1 組「前置基準實測」的量測腳本。
//
// **為何非測不可**：retention 對 audit_logs 的清除是刻意繞過 BeforeDelete 守衛的
// 原生 SQL 熱路徑（retention_service.go:130-134）。第 6 組要把它從「逐列刪」改成
// 「整區間刪」——不先記下現況的批次行為、partial 判定與耗時，改完就沒有對照組，
// 部署後首輪 retention 的差異將無從歸因。第 4 組的「封章不進熱路徑」
// 同樣需要一組改造前的寫入吞吐基準，故 1.4 的腳本在此一併定形供後續重跑。
//
// 一律在**獨立 schema** 內建表量測，不觸碰 dev 資料庫的 public schema 現況資料。
//
// 跑法（compose 內）：
//
//	docker compose exec -T backend sh -c \
//	  'TEST_PG_DSN="host=postgres user=postgres password=postgres dbname=custodexa port=5432 sslmode=disable" \
//	   go test ./internal/modules/audit -run "TestRetentionBaselinePostgres|TestAuditWriteThroughputPostgres" -v -count=1'
//
// 未設 TEST_PG_DSN 時 skip（沿 internal/testgate 的既有 gating 語義），
// 故本檔不影響 `go test ./...` 的常規全綠。

// baselineSchemaDB 於獨立 schema 建立量測用的最小 schema。
func baselineSchemaDB(t *testing.T, schema string) *gorm.DB {
	t.Helper()
	dsn := testgate.Value(t, testgate.EnvPGDSN)

	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("postgres 連線失敗: %v", err)
	}
	drop := "DROP SCHEMA IF EXISTS " + schema + " CASCADE"
	if err := admin.Exec(drop).Error; err != nil {
		t.Fatalf("清理舊 schema 失敗: %v", err)
	}
	if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		t.Fatalf("建立 schema 失敗: %v", err)
	}
	t.Cleanup(func() {
		_ = admin.Exec(drop)
		if s, err := admin.DB(); err == nil {
			_ = s.Close()
		}
	})

	db, err := gorm.Open(postgres.Open(dsn+" search_path="+schema),
		&gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("scoped 連線失敗: %v", err)
	}
	t.Cleanup(func() {
		if s, err := db.DB(); err == nil {
			_ = s.Close()
		}
	})

	if err := db.AutoMigrate(&model.AuditLog{}, &model.SecurityPolicy{}); err != nil {
		t.Fatalf("AutoMigrate: %v", err)
	}
	// PurgeAll 逐一走三個目標表：另兩張以最小結構建起來（本測不 seed，刪 0 筆）
	for _, stmt := range []string{
		"CREATE TABLE session_commands (id BIGSERIAL PRIMARY KEY, executed_at TIMESTAMPTZ NOT NULL)",
		"CREATE TABLE command_alerts (id BIGSERIAL PRIMARY KEY, triggered_at TIMESTAMPTZ NOT NULL)",
	} {
		if err := db.Exec(stmt).Error; err != nil {
			t.Fatalf("建表: %v", err)
		}
	}
	return db
}

// seedExpiredAuditLogs 以單句 generate_series 灌入 n 筆過期列（避免 seed 時間污染量測）。
func seedExpiredAuditLogs(t *testing.T, db *gorm.DB, n int, age time.Duration) {
	t.Helper()
	stmt := `INSERT INTO audit_logs (created_at, updated_at, action, resource, status, user_id, username, integrity_hmac, key_version)
	         SELECT ?, ?, 'read', 'audit_log', 'success', 0, 'baseline', 'x', 1 FROM generate_series(1, ?)`
	ts := time.Now().Add(-age)
	if err := db.Exec(stmt, ts, ts, n).Error; err != nil {
		t.Fatalf("seed %d 筆: %v", n, err)
	}
}

func countAuditLogs(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	if err := db.Raw("SELECT count(*) FROM audit_logs").Scan(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// TestRetentionBaselinePostgres：現行逐列清除的實際行為與耗時。
func TestRetentionBaselinePostgres(t *testing.T) {
	db := baselineSchemaDB(t, "cpchain_retention_baseline")

	pol := policy.NewSecurityPolicyService(db)
	if err := db.Create(&model.SecurityPolicy{
		Key: policy.PolicyRetentionAuditLogDays, Value: "365", UpdatedAt: time.Now(),
	}).Error; err != nil {
		t.Fatalf("設定保留政策: %v", err)
	}

	// --- 1.3 的生效參數（單一事實源即 service 常數與安全政策頁） ---
	t.Logf("[1.3] retentionBatchSize 常數 = %d（無 env 覆寫入口，RETENTION_BATCH_SIZE 未被程式讀取）", retentionBatchSize)
	t.Logf("[1.3] retentionBatchPause = %v（每批之間固定停頓，計入下方耗時）", retentionBatchPause)

	// --- 1.2 逐列清除的基準：20000 筆過期列（4 個滿批） ---
	const seedN = 20000
	seedExpiredAuditLogs(t, db, seedN, 400*24*time.Hour)
	seedExpiredAuditLogs(t, db, 500, 24*time.Hour) // 未過期對照列
	before := countAuditLogs(t, db)

	auditSink := &fakeAuditLogger{}
	svc := NewRetentionService(db, pol, nil, auditSink)
	t.Logf("[1.3] maxPerRunNow() 生效值 = %d（預設 %d、下界 %d；"+
		"生效值由安全政策鍵 retention_max_per_run 供給，env 僅為初值）",
		svc.maxPerRunNow(), retentionMaxPerRunDefault, retentionMinPerRun)

	start := time.Now()
	results := svc.PurgeAll()
	elapsed := time.Since(start)
	after := countAuditLogs(t, db)

	var auditResult *PurgeResult
	for i := range results {
		if results[i].Target == "audit_logs" {
			auditResult = &results[i]
		}
	}
	if auditResult == nil {
		t.Fatal("PurgeAll 未回報 audit_logs 結果")
	}
	if auditResult.Deleted != seedN {
		t.Fatalf("[1.2] 刪除筆數 = %d, want %d", auditResult.Deleted, seedN)
	}
	if auditResult.Partial {
		t.Fatalf("[1.2] 過期筆數(%d) 低於單次上限(%d) 卻標記 partial", seedN, svc.maxPerRun)
	}
	if before-after != seedN {
		t.Fatalf("[1.2] 實際列差 = %d, want %d", before-after, seedN)
	}
	var trail string
	if len(auditSink.entries) > 0 {
		for _, e := range auditSink.entries {
			if e.Resource == model.ResourceRetention {
				var pr PurgeResult
				_ = json.Unmarshal([]byte(e.Details), &pr)
				if pr.Target == "audit_logs" {
					trail = e.Details
				}
			}
		}
	}
	batches := (seedN + retentionBatchSize - 1) / retentionBatchSize
	pause := time.Duration(batches-1) * retentionBatchPause
	t.Logf("[1.2] 前 %d 列 / 後 %d 列；刪除 %d 筆、partial=%v",
		before, after, auditResult.Deleted, auditResult.Partial)
	t.Logf("[1.2] PurgeAll 全程耗時 %v（含 %d 批次間停頓共 %v，另含兩張空表的探測）；"+
		"扣除停頓的純刪除約 %v，即約 %.0f 列/秒",
		elapsed.Round(time.Millisecond), batches-1, pause,
		(elapsed - pause).Round(time.Millisecond),
		float64(seedN)/(elapsed-pause).Seconds())
	t.Logf("[1.2] 留痕 JSON 全文：%s", trail)

	// --- 1.3 partial 探測：過期筆數恰等於單次上限時不得誤報 partial ---
	svc.maxPerRun = 2000
	svc.batchSize = 1000
	seedExpiredAuditLogs(t, db, svc.maxPerRun, 400*24*time.Hour)
	exact := svc.PurgeAll()
	var exactResult PurgeResult
	for _, r := range exact {
		if r.Target == "audit_logs" {
			exactResult = r
		}
	}
	if exactResult.Deleted != int64(svc.maxPerRun) || exactResult.Partial {
		t.Fatalf("[1.3] 過期筆數=上限(%d) 時 deleted=%d partial=%v，want deleted=%d partial=false",
			svc.maxPerRun, exactResult.Deleted, exactResult.Partial, svc.maxPerRun)
	}
	t.Logf("[1.3] 過期筆數=上限(%d)：deleted=%d partial=%v（探測正確，不誤報）",
		svc.maxPerRun, exactResult.Deleted, exactResult.Partial)

	// 上限+1：partial 必為 true，殘量留待次輪
	seedExpiredAuditLogs(t, db, svc.maxPerRun+1, 400*24*time.Hour)
	over := svc.PurgeAll()
	var overResult PurgeResult
	for _, r := range over {
		if r.Target == "audit_logs" {
			overResult = r
		}
	}
	if overResult.Deleted != int64(svc.maxPerRun) || !overResult.Partial {
		t.Fatalf("[1.3] 過期筆數=上限+1 時 deleted=%d partial=%v，want deleted=%d partial=true",
			overResult.Deleted, overResult.Partial, svc.maxPerRun)
	}
	t.Logf("[1.3] 過期筆數=上限+1(%d)：deleted=%d partial=%v（殘 1 筆留待次輪）",
		svc.maxPerRun+1, overResult.Deleted, overResult.Partial)
	if n := countAuditLogs(t, db); n != 501 {
		t.Fatalf("[1.3] 殘留列數 = %d, want 501（500 未過期 + 1 殘量）", n)
	}
}

// TestAuditWriteThroughputPostgres：audit_logs 入庫吞吐與 p95 基準。
//
// 量測的是**入庫路徑本身**（model.AuditLog 的 BeforeCreate 蓋章 hook ＋ INSERT），
// 不含 HTTP 中介層——第 4 組要對照的「封章是否拖慢寫入」正是這一段。
// 兩種形狀各測一輪：逐列 Create（同步直寫路徑）與 10 列一批 CreateInBatches
// （AuditLogService 非同步 worker 的 batchSize 形狀）。
func TestAuditWriteThroughputPostgres(t *testing.T) {
	db := baselineSchemaDB(t, "cpchain_throughput_baseline")

	// 蓋章 hook：以固定鑰模擬生產的 StampOne，使量測涵蓋 HMAC 計算成本
	svc := &AuditIntegrityService{
		activeFn: func() (int, []byte) { return 1, []byte("baseline-stamp-key-32-bytes-long") },
		keyFn:    func(int) []byte { return []byte("baseline-stamp-key-32-bytes-long") },
	}
	model.SetAuditCreateHooks(svc.StampOne, nil)
	t.Cleanup(func() { model.SetAuditCreateHooks(nil, nil) })

	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("取 sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(32)

	newRow := func(i int) *model.AuditLog {
		return &model.AuditLog{
			Action: model.ActionRead, Resource: model.ResourceAuditLog,
			Status: model.StatusSuccess, UserID: 1, Username: "bench",
			Method: "GET", Path: fmt.Sprintf("/api/v1/bench/%d", i),
			ClientIP: "127.0.0.1", StatusCode: 200, Duration: 3,
		}
	}

	run := func(name string, concurrency, perWorker, batch int) {
		var mu sync.Mutex
		lat := make([]time.Duration, 0, concurrency*perWorker)
		var wg sync.WaitGroup
		start := time.Now()
		for w := 0; w < concurrency; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				local := make([]time.Duration, 0, perWorker)
				for i := 0; i < perWorker; i += batch {
					rows := make([]*model.AuditLog, 0, batch)
					for b := 0; b < batch; b++ {
						rows = append(rows, newRow(w*perWorker+i+b))
					}
					t0 := time.Now()
					var err error
					if batch == 1 {
						err = db.Create(rows[0]).Error
					} else {
						err = db.CreateInBatches(rows, batch).Error
					}
					if err != nil {
						t.Errorf("寫入失敗: %v", err)
						return
					}
					local = append(local, time.Since(t0))
				}
				mu.Lock()
				lat = append(lat, local...)
				mu.Unlock()
			}(w)
		}
		wg.Wait()
		elapsed := time.Since(start)
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		p95 := lat[int(float64(len(lat))*0.95)]
		rows := concurrency * perWorker
		t.Logf("[1.4] %s：並發 %d、共 %d 列、批次 %d → 耗時 %v、吞吐 %.0f 列/秒、"+
			"每次操作 p50 %v／p95 %v",
			name, concurrency, rows, batch, elapsed.Round(time.Millisecond),
			float64(rows)/elapsed.Seconds(), lat[len(lat)/2].Round(time.Microsecond),
			p95.Round(time.Microsecond))
	}

	run("逐列 Create", 8, 1000, 1)
	run("逐列 Create", 32, 1000, 1)
	run("批次 CreateInBatches(10)", 8, 1000, 10)

	if n := countAuditLogs(t, db); n == 0 {
		t.Fatal("量測後無任何列，寫入路徑未實際執行")
	}
}
