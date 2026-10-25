package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/testgate"
)

// 啟動時偵測其他實例並發系統告警：真守衛、真交易內審計與系統告警落地面。
// 對等數查詢與告警落地的失敗以注入的函式與落地面替身製造；PG 子案例用私有隔離資料庫。

var startupGuardCodePattern = regexp.MustCompile(`code=([0-9a-f]{12})`)

func startupGuardOpts(ack string) database.InstanceGuardOptions {
	return database.InstanceGuardOptions{Ack: ack, RetryInterval: time.Millisecond, RetryAttempts: 2}
}

func startupAlertDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(append(baselineExtraModels(), &model.AuditLog{})...); err != nil {
		t.Fatal(err)
	}
	return db
}

// failingAlertSink 告警落地面替身：一律回錯。
type failingAlertSink struct{}

func (failingAlertSink) RaiseInTx(*gorm.DB, port.SystemAlertEvent) (port.SystemAlertReceipt, error) {
	return port.SystemAlertReceipt{}, errors.New("injected alert failure")
}

// captureLog 攔截標準 logger 輸出，測試結束還原。
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

// startupHeldGuard 取得單實例鎖並回傳守衛（held）。
func startupHeldGuard(t *testing.T) (*database.InstanceGuard, *gorm.DB) {
	t.Helper()
	lockDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	a := database.NewInstanceGuard(lockDB, startupGuardOpts(""))
	if err := a.Acquire(context.Background()); err != nil {
		t.Fatalf("持鎖者取鎖失敗: %v", err)
	}
	t.Cleanup(a.Stop)
	return a, lockDB
}

// startupOverriddenGuard 先有持鎖者，再以相符確認碼取鎖得 overridden（環境變數路徑）。
func startupOverriddenGuard(t *testing.T) *database.InstanceGuard {
	t.Helper()
	_, lockDB := startupHeldGuard(t)
	probe := database.NewInstanceGuard(lockDB, startupGuardOpts(""))
	err := probe.Acquire(context.Background())
	if !errors.Is(err, database.ErrInstanceGuardBlocked) {
		t.Fatalf("前置條件：無確認碼的第二次取鎖應被攔下，實得 %v", err)
	}
	m := startupGuardCodePattern.FindStringSubmatch(err.Error())
	if m == nil {
		t.Fatalf("攔下訊息沒有確認碼: %v", err)
	}
	b := database.NewInstanceGuard(lockDB, startupGuardOpts(m[1]))
	if err := b.Acquire(context.Background()); err != nil {
		t.Fatalf("相符確認碼取鎖失敗: %v", err)
	}
	t.Cleanup(b.Stop)
	if b.State() != database.GuardStateOverridden {
		t.Fatalf("前置條件：狀態應為 overridden，實得 %s", b.State())
	}
	return b
}

func newStartupCheckFor(db *gorm.DB, g *database.InstanceGuard, alerts port.SystemAlertSink) *instanceGuardStartupCheck {
	c := newInstanceGuardStartupCheck(db, audit.NewTxSink(), alerts)
	c.snapshot = g.Snapshot
	c.probe = g.ProbePeers
	return c
}

// startupAlertHead 告警列的比對欄位（不整列載入：sqlite 的時間欄位無法掃進 time.Time）。
type startupAlertHead struct {
	ID       uint
	UserID   uint
	Severity string
	Kind     string
}

type startupAlertRow struct {
	Alert  startupAlertHead
	Detail model.SystemAlertDetail
	Params map[string]string
}

func startupAlerts(t *testing.T, db *gorm.DB) []startupAlertRow {
	t.Helper()
	var alerts []startupAlertHead
	if err := db.Table("command_alerts").Select("id, user_id, severity, kind").
		Where("reason_code = ?", string(port.SystemAlertConcurrentInstanceDetected)).Order("id").Scan(&alerts).Error; err != nil {
		t.Fatal(err)
	}
	out := make([]startupAlertRow, 0, len(alerts))
	for _, a := range alerts {
		var d model.SystemAlertDetail
		if err := db.Where("alert_id = ?", a.ID).First(&d).Error; err != nil {
			t.Fatalf("告警 %d 沒有明細: %v", a.ID, err)
		}
		params := map[string]string{}
		if err := json.Unmarshal([]byte(d.Params), &params); err != nil {
			t.Fatal(err)
		}
		out = append(out, startupAlertRow{Alert: a, Detail: d, Params: params})
	}
	return out
}

func startupAuditRows(t *testing.T, db *gorm.DB) []model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	if err := db.Where("resource = ? AND details LIKE ?", string(model.ResourceInstanceGuard), "%"+startupPeerEvent+"%").
		Order("id").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}

func requireStartupCounts(t *testing.T, db *gorm.DB, wantAlerts, wantAudits int) {
	t.Helper()
	if n := len(startupAlerts(t, db)); n != wantAlerts {
		t.Fatalf("concurrent_instance_detected 告警應 %d 則，實有 %d", wantAlerts, n)
	}
	if n := len(startupAuditRows(t, db)); n != wantAudits {
		t.Fatalf("%s 審計應 %d 列，實有 %d", startupPeerEvent, wantAudits, n)
	}
}

func TestInstanceGuardStartupPeerAlert(t *testing.T) {
	t.Run("no_peers_when_held", func(t *testing.T) {
		db := startupAlertDB(t)
		a, _ := startupHeldGuard(t)
		if err := newStartupCheckFor(db, a, audit.NewSystemAlertSink(nil)).Run(context.Background()); err != nil {
			t.Fatalf("檢查應回 nil: %v", err)
		}
		requireStartupCounts(t, db, 0, 0)
	})

	t.Run("overridden_env", func(t *testing.T) {
		db := startupAlertDB(t)
		b := startupOverriddenGuard(t)
		check := newStartupCheckFor(db, b, audit.NewSystemAlertSink(nil))
		if err := check.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		requireStartupCounts(t, db, 1, 1)
		row := startupAlerts(t, db)[0]
		want := map[string]string{
			"signal": "overridden", "peers_query": "ok", "peers": "0",
			"confirm_source": "env", "confirmed_by": "operator via env", "actor": "system",
		}
		for k, v := range want {
			if row.Params[k] != v {
				t.Errorf("參數 %s = %q，應為 %q（全部 %v）", k, row.Params[k], v, row.Params)
			}
		}
		if row.Alert.UserID != 0 || row.Alert.Severity != model.AlertSeverityHigh || row.Alert.Kind != model.AlertKindSystemSecurity {
			t.Errorf("告警列操作者／分級／種類不符: %+v", row.Alert)
		}
		if row.Detail.TargetKind != string(port.SystemAlertTargetSystemSetting) || row.Detail.TargetID != "instance_guard" {
			t.Errorf("目標應為 system_setting／instance_guard，實得 %s／%s", row.Detail.TargetKind, row.Detail.TargetID)
		}
		au := startupAuditRows(t, db)[0]
		if au.UserID != 0 || au.Username != "system" || au.Action != model.ActionExecute {
			t.Errorf("審計列操作者或動作不符: %+v", au)
		}
		var details map[string]any
		if err := json.Unmarshal([]byte(au.Details), &details); err != nil {
			t.Fatal(err)
		}
		if details["event"] != startupPeerEvent || details["signal"] != "overridden" || details["actor_source"] != "env" {
			t.Errorf("審計 details 不符: %v", details)
		}
		if corr, _ := details["correlation_id"].(string); corr == "" || corr != row.Detail.CorrelationID {
			t.Errorf("告警 CorrelationID %q 應等於同交易審計列的 correlation_id %q", row.Detail.CorrelationID, corr)
		}
		// 同一次啟動再呼叫：不產生第二則
		if err := check.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		requireStartupCounts(t, db, 1, 1)
	})

	t.Run("held_probe_failed", func(t *testing.T) {
		db := startupAlertDB(t)
		a, _ := startupHeldGuard(t)
		buf := captureLog(t)
		check := newStartupCheckFor(db, a, audit.NewSystemAlertSink(nil))
		check.probe = func(context.Context) (int, error) { return 0, errors.New("injected probe failure") }
		if err := check.Run(context.Background()); err != nil {
			t.Fatalf("查詢失敗時檢查仍應回 nil（不中止啟動）: %v", err)
		}
		requireStartupCounts(t, db, 0, 0)
		if !strings.Contains(buf.String(), "CRITICAL") {
			t.Errorf("沒有已成立的信號而查詢失敗，日誌應有 CRITICAL 行: %q", buf.String())
		}
	})

	t.Run("overridden_probe_failed", func(t *testing.T) {
		db := startupAlertDB(t)
		b := startupOverriddenGuard(t)
		buf := captureLog(t)
		check := newStartupCheckFor(db, b, audit.NewSystemAlertSink(nil))
		check.probe = func(context.Context) (int, error) { return 0, errors.New("injected probe failure") }
		if err := check.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		requireStartupCounts(t, db, 1, 1)
		row := startupAlerts(t, db)[0]
		if row.Params["signal"] != "overridden" || row.Params["peers_query"] != "failed" {
			t.Errorf("參數不符: %v", row.Params)
		}
		if _, has := row.Params["peers"]; has {
			t.Errorf("查詢失敗時參數不得帶 peers（不以 0 假稱無對等）: %v", row.Params)
		}
		if !strings.Contains(buf.String(), "CRITICAL") {
			t.Errorf("查詢失敗時日誌應有 CRITICAL 行: %q", buf.String())
		}
	})

	t.Run("alert_failure_rolls_back_audit", func(t *testing.T) {
		db := startupAlertDB(t)
		b := startupOverriddenGuard(t)
		buf := captureLog(t)
		if err := newStartupCheckFor(db, b, failingAlertSink{}).Run(context.Background()); err != nil {
			t.Fatalf("告警落地失敗時檢查仍應回 nil: %v", err)
		}
		requireStartupCounts(t, db, 0, 0)
		if !strings.Contains(buf.String(), "CRITICAL") {
			t.Errorf("告警落地失敗時日誌應有 CRITICAL 行: %q", buf.String())
		}
	})

	t.Run("stage2_order", func(t *testing.T) {
		pos := func(name string) int {
			for i, n := range stage2ServiceInventory {
				if n == name {
					return i
				}
			}
			t.Fatalf("stage2ServiceInventory 沒有 %q", name)
			return -1
		}
		if !(pos("systemAlertSink") < pos("instanceGuardStartupCheck") && pos("instanceGuardStartupCheck") < pos("changeSecretScheduler")) {
			t.Errorf("mark 序列應為 systemAlertSink < instanceGuardStartupCheck < changeSecretScheduler: %v", stage2ServiceInventory)
		}
		src, err := os.ReadFile("stage2.go")
		if err != nil {
			t.Fatal(err)
		}
		text := string(src)
		sink := strings.Index(text, `mark("systemAlertSink")`)
		call := strings.Index(text, "newInstanceGuardStartupCheck(")
		start := strings.Index(text, "changeSecretScheduler.Start()")
		if sink < 0 || call < 0 || start < 0 || !(sink < call && call < start) {
			t.Errorf("stage2.go 的實際呼叫位置應在 systemAlertSink 之後、changeSecretScheduler.Start 之前（%d < %d < %d）", sink, call, start)
		}
	})

	t.Run("other_types_reject_system_actor", func(t *testing.T) {
		db := startupAlertDB(t)
		sink := audit.NewSystemAlertSink(nil)
		cat := audit.SystemAlertCatalog()
		if len(cat) != 19 {
			t.Fatalf("目錄應 19 型，實有 %d", len(cat))
		}
		rejected := 0
		for _, def := range cat {
			params := map[string]string{}
			for _, p := range def.Params {
				switch p.Kind {
				case audit.SystemAlertParamEnum:
					params[p.Name] = p.Enum[0]
				case audit.SystemAlertParamInt:
					params[p.Name] = "3"
				case audit.SystemAlertParamTokens:
					params[p.Name] = "host"
				default:
					params[p.Name] = "x"
				}
			}
			ev := port.SystemAlertEvent{
				Type:   def.Type,
				Actor:  port.SystemAlertActor{UserID: 0, Username: port.SystemAlertSystemActorName},
				Target: port.SystemAlertTarget{Kind: def.Targets[0], ID: "1"}, Params: params,
			}
			err := db.Transaction(func(tx *gorm.DB) error {
				_, e := port.RaiseInTx(sink, tx, ev)
				return e
			})
			if def.Type == port.SystemAlertConcurrentInstanceDetected {
				if err != nil {
					t.Errorf("帶 SystemActor 旗標的型別應接受系統主體: %v", err)
				}
				continue
			}
			rejected++
			if err == nil {
				t.Errorf("%s 不帶旗標，以系統主體產生應回錯", def.Type)
			}
		}
		if rejected != 18 {
			t.Errorf("應有 18 型拒絕系統主體，實有 %d", rejected)
		}
		var n int64
		db.Model(&model.CommandAlert{}).Count(&n)
		if n != 1 {
			t.Errorf("只有帶旗標的型別寫入一列，其餘 18 型不寫任何列；告警列實有 %d", n)
		}
		db.Model(&model.SystemAlertDetail{}).Count(&n)
		if n != 1 {
			t.Errorf("明細列應 1，實有 %d", n)
		}
	})

	t.Run("postgres", func(t *testing.T) {
		runStartupPeerAlertPostgres(t)
	})
}

// runStartupPeerAlertPostgres 真 PG：另一條釘選連線（application_name 同守衛）模擬另一個守衛版實例。
//
// DSN 必須指向隔離的資料庫（私有靶機），不得是執行中後端的資料庫：對等計數以 current_database() 與
// application_name 過濾，advisory lock 命名空間也是每 database。開跑前先確認沒有既存的守衛鎖與守衛工作階段。
func runStartupPeerAlertPostgres(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	ctx := context.Background()

	open := func(extra string) *gorm.DB {
		db, err := gorm.Open(postgres.Open(dsn+extra), &gorm.Config{Logger: logger.Discard, DisableForeignKeyConstraintWhenMigrating: true})
		if err != nil {
			t.Fatalf("postgres 連線失敗: %v", err)
		}
		return db
	}
	closePool := func(db *gorm.DB) {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	}
	admin := open("")
	t.Cleanup(func() { closePool(admin) })

	guardLocks := func() int64 {
		var n int64
		if err := admin.Raw(`SELECT count(*) FROM pg_locks
			WHERE locktype = 'advisory' AND objsubid = 1 AND granted
			  AND ((classid::bigint << 32) | objid::bigint) = ?
			  AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`,
			database.InstanceGuardLockKey).Scan(&n).Error; err != nil {
			t.Fatalf("查 pg_locks 失敗: %v", err)
		}
		return n
	}
	guardSessions := func() int64 {
		var n int64
		if err := admin.Raw(`SELECT count(*) FROM pg_stat_activity
			WHERE datname = current_database() AND application_name = ?`,
			database.InstanceGuardApplicationName).Scan(&n).Error; err != nil {
			t.Fatalf("查 pg_stat_activity 失敗: %v", err)
		}
		return n
	}
	if n := guardLocks(); n != 0 {
		t.Fatalf("前置條件：本資料庫已有 %d 把守衛鎖（DSN 是否指向執行中後端的資料庫？）", n)
	}
	if n := guardSessions(); n != 0 {
		t.Fatalf("前置條件：本資料庫已有 %d 條守衛工作階段（DSN 是否指向執行中後端的資料庫？）", n)
	}

	// 記錄用的 schema（審計與告警列）；與守衛連線池分開
	schema := fmt.Sprintf("startup_peer_%d", time.Now().UnixNano())
	if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Exec("DROP SCHEMA " + schema + " CASCADE").Error })
	recDB := open(" search_path=" + schema)
	t.Cleanup(func() { closePool(recDB) })
	if err := recDB.AutoMigrate(append(baselineExtraModels(), &model.AuditLog{})...); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// 本實例：包級單例守衛（持鎖、釘選連線帶守衛 application_name）
	ownDB := open("")
	previousDB := database.DB
	database.DB = ownDB
	t.Cleanup(func() {
		_ = database.Close() // 先釋放守衛的釘選連線與鎖，再關連線池
		database.DB = previousDB
	})
	if err := database.AcquireInstanceLock(ctx, ownDB, ""); err != nil {
		t.Fatalf("本實例取鎖失敗: %v", err)
	}
	if st := database.InstanceGuardSnapshot().State; st != database.GuardStateHeld {
		t.Fatalf("本實例應持鎖，實得 %s", st)
	}
	if n := guardSessions(); n != 1 {
		t.Fatalf("取鎖後應恰有本實例一條守衛工作階段，實有 %d", n)
	}

	sink := audit.NewSystemAlertSink(nil)
	newCheck := func() *instanceGuardStartupCheck {
		return newInstanceGuardStartupCheck(recDB, audit.NewTxSink(), sink) // 生產接線：單例快照與 InstanceGuardProbePeers
	}

	// 只有本實例的守衛連線：對等數 0，不算自己
	if n, err := database.InstanceGuardProbePeers(ctx); err != nil || n != 0 {
		t.Fatalf("只有本實例守衛連線時 InstanceGuardProbePeers 應回 0，實得 %d／%v", n, err)
	}
	if err := newCheck().Run(ctx); err != nil {
		t.Fatal(err)
	}
	requireStartupCounts(t, recDB, 0, 0)

	// 另一個連線池開一條守衛 application_name 的釘選連線＝另一個守衛版實例
	peerDB := open("")
	peerSQL, _ := peerDB.DB()
	peerConn, err := peerSQL.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peerConn.ExecContext(ctx, "SELECT set_config('application_name', $1, false)", database.InstanceGuardApplicationName); err != nil {
		t.Fatal(err)
	}
	peerClosed := false
	closePeer := func() {
		if peerClosed {
			return
		}
		peerClosed = true
		_ = peerConn.Close()
		_ = peerSQL.Close() // 關掉專用連線池：實體 session 結束，而不是歸池
	}
	t.Cleanup(closePeer)
	if n := guardSessions(); n != 2 {
		t.Fatalf("模擬對等後應有 2 條守衛工作階段，實有 %d", n)
	}

	if err := newCheck().Run(ctx); err != nil {
		t.Fatal(err)
	}
	requireStartupCounts(t, recDB, 1, 1)
	row := startupAlerts(t, recDB)[0]
	peers := 0
	fmt.Sscanf(row.Params["peers"], "%d", &peers)
	if row.Params["signal"] != "peers" || row.Params["peers_query"] != "ok" || peers < 1 {
		t.Fatalf("對等存在時應為 signal=peers、peers>=1，實得 %v", row.Params)
	}

	// 關閉該連線池，確認實體 session 已消失，再以新實例執行檢查 → 不再多出告警
	closePeer()
	deadline := time.Now().Add(10 * time.Second)
	for guardSessions() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("模擬對等的實體工作階段未在期限內結束，仍有 %d 條守衛工作階段", guardSessions())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if n, err := database.InstanceGuardProbePeers(ctx); err != nil || n != 0 {
		t.Fatalf("關閉對等後 InstanceGuardProbePeers 應回 0，實得 %d／%v", n, err)
	}
	if err := newCheck().Run(ctx); err != nil {
		t.Fatal(err)
	}
	requireStartupCounts(t, recDB, 1, 1)

	fmt.Println("EVIDENCE dialect=postgres")
	t.Log("EVIDENCE dialect=postgres")
}
