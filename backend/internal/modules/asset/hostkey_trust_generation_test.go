package asset

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/testgate"
	"golang.org/x/crypto/ssh"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// hostKeySQLRecorder 記錄對 asset_host_keys 的 UPDATE／INSERT 語句與其是否在交易內執行。
type hostKeySQLRecorder struct {
	mu    sync.Mutex
	stmts []hostKeyRecordedStmt
	all   []hostKeyRecordedStmt // 全程紀錄，reset() 不清
}

type hostKeyRecordedStmt struct {
	kind string // update／create
	sql  string // 去掉引號與空白的正規化文字
	inTx bool
}

func (r *hostKeySQLRecorder) install(t *testing.T, db *gorm.DB) {
	t.Helper()
	record := func(kind string) func(*gorm.DB) {
		return func(tx *gorm.DB) {
			if tx.Statement == nil || tx.Statement.Table != "asset_host_keys" {
				return
			}
			_, inTx := tx.Statement.ConnPool.(*sql.Tx)
			norm := strings.NewReplacer("`", "", "\"", "", " ", "").Replace(tx.Statement.SQL.String())
			r.mu.Lock()
			st := hostKeyRecordedStmt{kind: kind, sql: norm, inTx: inTx}
			r.stmts = append(r.stmts, st)
			r.all = append(r.all, st)
			r.mu.Unlock()
		}
	}
	name := fmt.Sprintf("test:hostkey_rec_%p", r)
	if err := db.Callback().Update().After("gorm:update").Register(name+"_u", record("update")); err != nil {
		t.Fatal(err)
	}
	if err := db.Callback().Create().After("gorm:create").Register(name+"_c", record("create")); err != nil {
		t.Fatal(err)
	}
}

func (r *hostKeySQLRecorder) reset() {
	r.mu.Lock()
	r.stmts = nil
	r.mu.Unlock()
}

// snapshotAll 回傳安裝以來的全部語句，不受 reset() 影響。
func (r *hostKeySQLRecorder) snapshotAll() []hostKeyRecordedStmt {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]hostKeyRecordedStmt(nil), r.all...)
}

func (r *hostKeySQLRecorder) snapshot() []hostKeyRecordedStmt {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]hostKeyRecordedStmt(nil), r.stmts...)
}

const hostKeyGenExpr = "trust_generation=trust_generation+1"

// updatesOf 取出 UPDATE 語句
func updatesOf(stmts []hostKeyRecordedStmt) []hostKeyRecordedStmt {
	var out []hostKeyRecordedStmt
	for _, s := range stmts {
		if s.kind == "update" {
			out = append(out, s)
		}
	}
	return out
}

// requireOneGenUpdate 斷言恰一條交易內的 UPDATE 含世代欄位運算，且與金鑰欄（或重置旗標）在同一條語句。
func requireOneGenUpdate(t *testing.T, what string, stmts []hostKeyRecordedStmt, sameStmtHas string) {
	t.Helper()
	n := 0
	for _, s := range updatesOf(stmts) {
		if !strings.Contains(s.sql, hostKeyGenExpr) {
			continue
		}
		n++
		if !s.inTx {
			t.Errorf("%s：世代更新必須在交易內執行: %s", what, s.sql)
		}
		if !strings.Contains(s.sql, sameStmtHas) {
			t.Errorf("%s：世代更新應與 %s 在同一條語句: %s", what, sameStmtHas, s.sql)
		}
	}
	if n != 1 {
		t.Errorf("%s：應恰一條含世代運算的 UPDATE，實有 %d：%v", what, n, stmts)
	}
}

// requireNoGenWrite 斷言沒有任何語句寫 trust_generation。
func requireNoGenWrite(t *testing.T, what string, stmts []hostKeyRecordedStmt) {
	t.Helper()
	for _, s := range stmts {
		if s.kind == "update" && strings.Contains(s.sql, "trust_generation") {
			t.Errorf("%s：不得寫 trust_generation: %s", what, s.sql)
		}
	}
}

func hostKeyRowFor(t *testing.T, db *gorm.DB, assetID uint) model.AssetHostKey {
	t.Helper()
	var rec model.AssetHostKey
	if err := db.Where("asset_id = ?", assetID).First(&rec).Error; err != nil {
		t.Fatalf("讀取資產 %d 的主機金鑰記錄: %v", assetID, err)
	}
	return rec
}

func lastAdoptDetails(t *testing.T, db *gorm.DB) map[string]any {
	t.Helper()
	var al model.AuditLog
	if err := db.Where("action = ?", string(model.ActionHostKeyAdopt)).Order("id DESC").First(&al).Error; err != nil {
		t.Fatalf("讀取採用審計: %v", err)
	}
	var d map[string]any
	if err := json.Unmarshal([]byte(al.Details), &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func requireGenDetails(t *testing.T, d map[string]any, before, after int64) {
	t.Helper()
	b, okB := d["trust_generation_before"].(float64)
	a, okA := d["trust_generation_after"].(float64)
	if !okB || !okA || int64(b) != before || int64(a) != after {
		t.Fatalf("採用審計世代應為 %d／%d，實得 %v", before, after, d)
	}
}

func requireAlertParamKeys(t *testing.T, ev port.SystemAlertEvent) {
	t.Helper()
	if len(ev.Params) != 3 {
		t.Fatalf("告警參數應維持三鍵，實得 %v", ev.Params)
	}
	for _, k := range []string{"change", "previous_fingerprint", "adopted_fingerprint"} {
		if _, ok := ev.Params[k]; !ok {
			t.Fatalf("告警參數缺 %s: %v", k, ev.Params)
		}
	}
}

// runTrustGenerationCore 資產表以外的世代規則（SQLite 與 PostgreSQL 共用）。
func runTrustGenerationCore(t *testing.T, db *gorm.DB) {
	const assetID = uint(31)
	const addr = "10.1.1.1:22"
	svc, alerts := newHostKeyTestService(db)
	rec := &hostKeySQLRecorder{}
	rec.install(t, db)
	actor := hostKeyActorForTest()
	ka, kb, kc, kd := genHostKey(t), genHostKey(t), genHostKey(t), genHostKey(t)
	dial := func(k ssh.PublicKey, a string) *HostKeyDialResult {
		err, res := hostKeyDial(svc, assetID, HostKeyPathTerminal, a, k)
		if err != nil {
			t.Fatalf("撥號: %v", err)
		}
		return res
	}
	allStmts := rec.snapshotAll

	// 首次信任建列為 1
	dial(ka, addr)
	if got := hostKeyRowFor(t, db, assetID); got.TrustGeneration != 1 {
		t.Fatalf("首次信任世代應為 1，實為 %d", got.TrustGeneration)
	}

	// 位址補記不推進、不寫世代
	rec.reset()
	dial(ka, "10.9.9.9:22")
	if got := hostKeyRowFor(t, db, assetID); got.TrustGeneration != 1 || got.Host != "10.9.9.9" {
		t.Fatalf("位址補記後世代應維持 1 且位址更新: %+v", got)
	}
	requireNoGenWrite(t, "位址補記", rec.snapshot())
	if len(updatesOf(rec.snapshot())) != 1 {
		t.Fatalf("位址補記應只有一條 UPDATE: %v", rec.snapshot())
	}

	// 採用 B：+1、審計 1／2；再採用 A：3
	dial(kb, "10.9.9.9:22")
	alerts.events = nil
	rec.reset()
	if _, err := svc.Adopt(assetID, ssh.FingerprintSHA256(kb), actor); err != nil {
		t.Fatalf("採用 B: %v", err)
	}
	requireOneGenUpdate(t, "採用 B", rec.snapshot(), "fingerprint")
	if got := hostKeyRowFor(t, db, assetID); got.TrustGeneration != 2 || got.Fingerprint != ssh.FingerprintSHA256(kb) {
		t.Fatalf("採用 B 後應為 B／世代 2: %+v", got)
	}
	requireGenDetails(t, lastAdoptDetails(t, db), 1, 2)
	requireAlertParamKeys(t, alerts.events[0])
	dial(ka, "10.9.9.9:22")
	if _, err := svc.Adopt(assetID, ssh.FingerprintSHA256(ka), actor); err != nil {
		t.Fatalf("採用 A: %v", err)
	}
	if got := hostKeyRowFor(t, db, assetID); got.TrustGeneration != 3 {
		t.Fatalf("再採用 A 世代應為 3，實為 %d", got.TrustGeneration)
	}
	requireGenDetails(t, lastAdoptDetails(t, db), 2, 3)

	// 重置：+1、reset_pending、結果前後 3／4；沒有新增審計列、告警三鍵不變
	auditBefore := func() int64 {
		var n int64
		db.Model(&model.AuditLog{}).Count(&n)
		return n
	}()
	alerts.events = nil
	rec.reset()
	res, err := svc.MarkResetWithGeneration(assetID, actor)
	if err != nil || res != (HostKeyResetResult{Reset: true, GenerationBefore: 3, GenerationAfter: 4}) {
		t.Fatalf("重置結果應為 3→4: %+v %v", res, err)
	}
	requireOneGenUpdate(t, "重置", rec.snapshot(), "reset_pending")
	if got := hostKeyRowFor(t, db, assetID); got.TrustGeneration != 4 || !got.ResetPending {
		t.Fatalf("重置後應為世代 4 且待記錄: %+v", got)
	}
	var auditAfter int64
	db.Model(&model.AuditLog{}).Count(&auditAfter)
	if auditAfter != auditBefore {
		t.Fatalf("服務層重置不得新增審計列（前 %d 後 %d）", auditBefore, auditAfter)
	}
	if len(alerts.events) != 1 {
		t.Fatalf("重置應一則告警，實有 %d", len(alerts.events))
	}
	requireAlertParamKeys(t, alerts.events[0])

	// 重複重置：回 false、世代不變、沒有任何寫入、沒有新告警
	rec.reset()
	res, err = svc.MarkResetWithGeneration(assetID, actor)
	if err != nil || res != (HostKeyResetResult{}) {
		t.Fatalf("重複重置應回空結果: %+v %v", res, err)
	}
	if len(rec.snapshot()) != 0 || len(alerts.events) != 1 {
		t.Fatalf("重複重置不得寫入或發告警: %v 告警 %d", rec.snapshot(), len(alerts.events))
	}

	// 重置後重錄同一把 A：世代不變、旗標清除，且 UPDATE 不帶世代
	rec.reset()
	dial(ka, "10.9.9.9:22")
	if got := hostKeyRowFor(t, db, assetID); got.TrustGeneration != 4 || got.ResetPending {
		t.Fatalf("同鑰重錄應世代不變且清旗標: %+v", got)
	}
	requireNoGenWrite(t, "同鑰重錄", rec.snapshot())

	// 重置後首連出示 B：再 +1
	if r, err := svc.MarkResetWithGeneration(assetID, actor); err != nil || r.GenerationAfter != 5 {
		t.Fatalf("第二次重置應到 5: %+v %v", r, err)
	}
	rec.reset()
	dial(kb, "10.9.9.9:22")
	if got := hostKeyRowFor(t, db, assetID); got.TrustGeneration != 6 || got.ResetPending || got.Fingerprint != ssh.FingerprintSHA256(kb) {
		t.Fatalf("重置後換鑰首連世代應為 6: %+v", got)
	}
	requireOneGenUpdate(t, "重置後換鑰重錄", rec.snapshot(), "reset_pending")

	// 採用交易注入審計失敗：金鑰與世代同時回滾，觀察紀錄仍在
	dial(kc, "10.9.9.9:22")
	before := hostKeyRowFor(t, db, assetID)
	svc.SetAuditTxSink(failingTxSink{err: errors.New("injected audit failure")})
	if _, err := svc.Adopt(assetID, ssh.FingerprintSHA256(kc), actor); err == nil {
		t.Fatal("審計失敗時採用應失敗")
	}
	svc.SetAuditTxSink(audit.NewTxSink())
	after := hostKeyRowFor(t, db, assetID)
	if after.TrustGeneration != before.TrustGeneration || after.Fingerprint != before.Fingerprint || after.ResetPending != before.ResetPending {
		t.Fatalf("採用交易失敗應整筆回滾: 前 %+v 後 %+v", before, after)
	}
	if n := countObservations(t, db, assetID); n != 1 {
		t.Fatalf("回滾後觀察紀錄應保留 1 筆，實有 %d", n)
	}

	// 重置後首連的鎖後重讀：觀察 C 仍在 → 重置（6→7）→ 首連 D 在鎖前讀完之後、鎖內寫入之前，採用 C 提交
	if r, err := svc.MarkResetWithGeneration(assetID, actor); err != nil || r.GenerationAfter != 7 {
		t.Fatalf("重置應到 7: %+v %v", r, err)
	}
	rec.reset()
	fired := false
	svc.evalWriteBarrier = func() {
		if fired {
			return
		}
		fired = true
		svc.evalWriteBarrier = nil
		if _, err := svc.Adopt(assetID, ssh.FingerprintSHA256(kc), actor); err != nil {
			t.Fatalf("交錯中的採用 C: %v", err)
		}
	}
	res2 := dial(kd, "10.9.9.9:22")
	if !fired {
		t.Fatal("交錯掛點未觸發")
	}
	got := hostKeyRowFor(t, db, assetID)
	if got.Fingerprint != ssh.FingerprintSHA256(kc) || got.TrustGeneration != 8 || got.ResetPending {
		t.Fatalf("最終列應為採用的 C 且世代 8，不得被鎖前讀到的 D 覆寫: %+v", got)
	}
	if !res2.Mismatch() {
		t.Fatal("鎖後應重新分類：D 與已採用的 C 不符，應判不符而非重錄")
	}

	// 全程沒有對 asset_host_keys 的整列 Save：全程紀錄中任何 UPDATE 的 SET 不含 asset_id／created_at
	if len(updatesOf(allStmts())) < 8 {
		t.Fatalf("全程紀錄應涵蓋各段 UPDATE，實有 %d 條", len(updatesOf(allStmts())))
	}
	for _, s := range updatesOf(allStmts()) {
		set := s.sql
		if i := strings.Index(set, "WHERE"); i >= 0 {
			set = set[:i]
		}
		if strings.Contains(set, "asset_id=") || strings.Contains(set, "created_at=") {
			t.Errorf("不得整列 Save: %s", s.sql)
		}
	}
}

func TestHostKeyTrustGeneration(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		runTrustGenerationCore(t, setupHostKeyDB(t))
	})

	t.Run("sqlite_assets", func(t *testing.T) {
		db := setupAccountDB(t)
		if err := db.AutoMigrate(&model.AssetHostKey{}, &model.AssetHostKeyMismatch{}, &model.User{}); err != nil {
			t.Fatal(err)
		}
		assets, _ := newAccountServices(t)
		assets.SetAuthorizationRevoker(noopRevoker{})
		svc, _ := newHostKeyTestService(db)
		mk := func(name string) *model.Asset {
			a, err := assets.Create(WithSystemCaller(context.Background()), &CreateAssetRequest{
				Name: name, Protocol: model.ProtocolSSH, Host: "10.5.0.1", Port: 22,
				Username: "root", Password: "s3cret", CreatedBy: 1,
			})
			if err != nil {
				t.Fatalf("建立資產 %s: %v", name, err)
			}
			return a
		}
		key := genHostKey(t)
		dialAs := func(a *model.Asset) *HostKeyDialResult {
			err, res := hostKeyDial(svc, a.ID, HostKeyPathTerminal, "10.5.0.1:22", key)
			if err != nil {
				t.Fatalf("撥號: %v", err)
			}
			return res
		}
		rows := func(a *model.Asset) int64 {
			var n int64
			db.Model(&model.AssetHostKey{}).Where("asset_id = ?", a.ID).Count(&n)
			return n
		}
		a1 := mk("src")
		dialAs(a1)
		src := hostKeyRowFor(t, db, a1.ID)
		if src.TrustGeneration != 1 {
			t.Fatalf("來源列世代應為 1: %+v", src)
		}

		// 同位址沿用建自身列為 1；來源列世代不變
		a2 := mk("inherit")
		dialAs(a2)
		if got := hostKeyRowFor(t, db, a2.ID); got.TrustGeneration != 1 || got.ResetPending {
			t.Fatalf("沿用建列世代應為 1: %+v", got)
		}

		// 無自身列、只有沿用來源時重置：新建待記錄列、世代 1、結果 0→1、來源列不變
		a3 := mk("reset-no-own")
		r, err := svc.MarkResetWithGeneration(a3.ID, hostKeyActorForTest())
		if err != nil || r != (HostKeyResetResult{Reset: true, GenerationBefore: 0, GenerationAfter: 1}) {
			t.Fatalf("無自身列重置結果應為 0→1: %+v %v", r, err)
		}
		if got := hostKeyRowFor(t, db, a3.ID); got.TrustGeneration != 1 || !got.ResetPending {
			t.Fatalf("新建列應為世代 1 且待記錄: %+v", got)
		}
		if again := hostKeyRowFor(t, db, a1.ID); again.TrustGeneration != src.TrustGeneration || again.ResetPending ||
			again.Fingerprint != src.Fingerprint {
			t.Fatalf("來源列不得被動到: %+v", again)
		}

		// 重置讀完前置資料、進鎖之前，同資產的「沿用建列」先提交：最終恰一列，重置改走已存在的列（不丟 reset_pending）
		a4 := mk("race-reset-after-inherit")
		fired := false
		svc.resetTxBarrier = func() {
			if fired {
				return
			}
			fired = true
			svc.resetTxBarrier = nil
			dialAs(a4)
		}
		r, err = svc.MarkResetWithGeneration(a4.ID, hostKeyActorForTest())
		if err != nil || !fired || r != (HostKeyResetResult{Reset: true, GenerationBefore: 1, GenerationAfter: 2}) {
			t.Fatalf("交錯後重置應走已存在列 1→2: %+v %v 觸發=%v", r, err, fired)
		}
		if got := hostKeyRowFor(t, db, a4.ID); rows(a4) != 1 || got.TrustGeneration != 2 || !got.ResetPending {
			t.Fatalf("最終應恰一列、世代 2、待記錄: %+v", got)
		}

		// 反向：沿用建列讀完來源、進鎖之前，重置先提交新建待記錄列：沿用放棄建列，依當下狀態重新分類為重置後首連
		a5 := mk("race-inherit-after-reset")
		fired = false
		svc.evalWriteBarrier = func() {
			if fired {
				return
			}
			fired = true
			svc.evalWriteBarrier = nil
			if rr, err := svc.MarkResetWithGeneration(a5.ID, hostKeyActorForTest()); err != nil || !rr.Reset {
				t.Fatalf("交錯中的重置: %+v %v", rr, err)
			}
		}
		dialAs(a5)
		if !fired {
			t.Fatal("交錯掛點未觸發")
		}
		if got := hostKeyRowFor(t, db, a5.ID); rows(a5) != 1 || got.TrustGeneration != 1 || got.ResetPending {
			t.Fatalf("應恰一列；同鑰重錄消耗重置旗標且世代維持 1: %+v", got)
		}
	})

	t.Run("postgres", func(t *testing.T) {
		dsn := testgate.Value(t, testgate.EnvPGDSN)
		admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
		if err != nil {
			t.Fatalf("postgres 連線失敗: %v", err)
		}
		schema := fmt.Sprintf("hk_gen_%d", time.Now().UnixNano())
		if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = admin.Exec("DROP SCHEMA " + schema + " CASCADE").Error
			if sqlDB, err := admin.DB(); err == nil {
				_ = sqlDB.Close()
			}
		})
		db, err := gorm.Open(postgres.Open(dsn+" search_path="+schema), &gorm.Config{
			Logger: logger.Discard, DisableForeignKeyConstraintWhenMigrating: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if sqlDB, err := db.DB(); err == nil {
				_ = sqlDB.Close()
			}
		})
		if err := db.AutoMigrate(&model.AssetHostKey{}, &model.AssetHostKeyMismatch{}, &model.AuditLog{}, &model.User{}); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		runTrustGenerationCore(t, db)
		fmt.Println("EVIDENCE dialect=postgres")
		t.Log("EVIDENCE dialect=postgres")
	})
}
