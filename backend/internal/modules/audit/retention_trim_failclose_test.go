package audit

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 鏈修剪的前置驗證：點簽章、清除簽章、鏈頭錨定任一不成立，整輪不修剪、不簽修剪記錄、
// 經結構層失效路徑上報。每個案例同時跑 sqlite 與 postgres（postgres 版由 testgate 守門）。

const (
	trimDay      = 24 * time.Hour
	trimAgeOld   = 4000 * trimDay
	trimAgeMid   = 3000 * trimDay
	trimAgeNear  = 2999 * trimDay
	trimAgeLate  = 1000 * trimDay
	trimAgeGen   = 4001 * trimDay
	trimRowsAged = 400 * trimDay
)

type trimChainSpec struct {
	rows      int
	sealedAge time.Duration // sealed_at 距今
	createdAt time.Time     // 區間內列的 created_at
	purge     bool
}

// buildTrimChain 在 genesis 之後依序封章（可清除），最後再封一個新的尾點，並把 genesis 催老（重簽整鏈，不引入竄改）。
func buildTrimChain(t *testing.T, f *purgeFixture, specs []trimChainSpec) []model.AuditCheckpoint {
	t.Helper()
	cutoff := time.Now().Add(-365 * trimDay)
	for _, sp := range specs {
		cp := f.sealAt(t, sp.rows, sp.createdAt, time.Now().Add(-sp.sealedAge))
		if sp.purge {
			if _, err := f.purger.PurgeInterval(cp, 365, cutoff); err != nil {
				t.Fatalf("purge seq=%d: %v", cp.Seq, err)
			}
		}
	}
	f.sealInterval(t, 1, time.Now())
	f.ageGenesis(t, time.Now().Add(-trimAgeGen))
	return loadChain(t, f.db)
}

func loadChain(t *testing.T, db *gorm.DB) []model.AuditCheckpoint {
	t.Helper()
	var chain []model.AuditCheckpoint
	if err := db.Order("seq ASC").Find(&chain).Error; err != nil {
		t.Fatalf("load chain: %v", err)
	}
	return chain
}

func trimTableCount(t *testing.T, db *gorm.DB, table string) int64 {
	t.Helper()
	var n int64
	if err := db.Table(table).Count(&n).Error; err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// trimCandidatePrecondition 斷言指定 seq 的檢查點「點簽章與清除簽章本身都驗得過」，
// 證明之後的暫停不是候選點檢查擋下的。
func trimCandidatePrecondition(t *testing.T, f *purgeFixture, seqs ...uint) {
	t.Helper()
	for _, seq := range seqs {
		cp := f.reload(t, seq)
		if _, ok := checkpointPointSignature(&cp, f.signer); !ok {
			t.Fatalf("前置不成立：seq=%d 點簽章驗不過", seq)
		}
		if cp.RowCount > 0 && cp.PurgedAt != nil {
			ok, err := f.purger.VerifyPurgeTombstone(&cp, 365)
			if err != nil || !ok {
				t.Fatalf("前置不成立：seq=%d 清除簽章驗不過（ok=%v err=%v）", seq, ok, err)
			}
		}
	}
}

// assertTrimPaused 修剪暫停的四項後置條件：回傳 0、無新修剪記錄、檢查點列數不變、告警已上報。
func assertTrimPaused(t *testing.T, f *purgeFixture, alerts *fakeChainAlerter, days int, wantTrims int64) {
	t.Helper()
	cpBefore := trimTableCount(t, f.db, "audit_checkpoints")
	n, trim, err := f.purger.TrimChain(days)
	if err != nil {
		t.Fatalf("TrimChain: %v", err)
	}
	cpAfter := trimTableCount(t, f.db, "audit_checkpoints")
	trimsAfter := trimTableCount(t, f.db, "audit_checkpoint_trims")
	t.Logf("TrimChain 回傳 trimmed=%d trim=%v；檢查點 %d -> %d；修剪記錄 %d（預期 %d）；告警 %d 筆",
		n, trim != nil, cpBefore, cpAfter, trimsAfter, wantTrims, len(alerts.calls))
	if n != 0 || trim != nil {
		t.Errorf("不得修剪：trimmed=%d trim=%v", n, trim != nil)
	}
	if cpAfter != cpBefore {
		t.Errorf("檢查點列數不得變動：%d -> %d", cpBefore, cpAfter)
	}
	if trimsAfter != wantTrims {
		t.Errorf("不得簽出新修剪記錄：%d 筆（預期 %d）", trimsAfter, wantTrims)
	}
	if !alerts.has("report", model.MechanismAuditChainStructure) {
		t.Errorf("應經結構層失效路徑上報，實得 %+v", alerts.calls)
	}
}

func withTrimDBs(t *testing.T, name string, fn func(t *testing.T, f *purgeFixture)) {
	t.Run("sqlite", func(t *testing.T) { fn(t, setupPurgeFixture(t)) })
	t.Run("postgres", func(t *testing.T) {
		db, _ := purgeSchemaDB(t, "trim_failclose_"+name)
		fn(t, pgFixture(t, db))
	})
}

// TestTrimChainForged 未到期的檢查點被改成「已到期且已清除」：整輪不修剪。
func TestTrimChainForged(t *testing.T) {
	t.Run("封章時間與清除時間一併被改", func(t *testing.T) {
		withTrimDBs(t, "sealed_purged", func(t *testing.T, f *purgeFixture) {
			old := time.Now().Add(-trimRowsAged)
			chain := buildTrimChain(t, f, []trimChainSpec{
				{rows: 2, sealedAge: trimAgeOld, createdAt: old, purge: true},
				{rows: 2, sealedAge: 0, createdAt: old}, // 仍覆蓋現存列、未到期
			})
			if len(chain) < 2 {
				t.Fatalf("前置不成立：鏈長 %d", len(chain))
			}
			trimCandidatePrecondition(t, f, 2, 3)
			f.mustExecSQL(t, "UPDATE audit_checkpoints SET sealed_at = ?, purged_at = ? WHERE seq = 3",
				time.Now().Add(-trimAgeOld+time.Minute).UTC(), time.Now().Add(-trimAgeOld+time.Minute).UTC())
			forged := f.reload(t, 3)
			if _, ok := checkpointPointSignature(&forged, f.signer); ok {
				t.Fatal("前置不成立：被改封章時間後的點簽章應驗不過")
			}
			alerts := &fakeChainAlerter{}
			f.purger.SetFailureAlerter(alerts)
			assertTrimPaused(t, f, alerts, 3650, 0)
		})
	})
	t.Run("只有清除時間被偽造", func(t *testing.T) {
		withTrimDBs(t, "purged_only", func(t *testing.T, f *purgeFixture) {
			old := time.Now().Add(-trimRowsAged)
			chain := buildTrimChain(t, f, []trimChainSpec{
				{rows: 2, sealedAge: trimAgeOld, createdAt: old, purge: true},
				{rows: 2, sealedAge: trimAgeOld - trimDay, createdAt: old}, // 已到期但仍覆蓋現存列
			})
			if len(chain) < 2 {
				t.Fatalf("前置不成立：鏈長 %d", len(chain))
			}
			trimCandidatePrecondition(t, f, 2)
			f.mustExecSQL(t, "UPDATE audit_checkpoints SET purged_at = ? WHERE seq = 3", time.Now().UTC())
			forged := f.reload(t, 3)
			if _, ok := checkpointPointSignature(&forged, f.signer); !ok {
				t.Fatal("前置不成立：只改清除時間時點簽章本身應仍有效")
			}
			if forged.PurgedAt == nil || forged.RowCount == 0 {
				t.Fatal("前置不成立：被改的點應有清除標記且覆蓋列數大於零")
			}
			if ok, _ := f.purger.VerifyPurgeTombstone(&forged, 365); ok {
				t.Fatal("前置不成立：偽造的清除標記不應通過清除簽章")
			}
			alerts := &fakeChainAlerter{}
			f.purger.SetFailureAlerter(alerts)
			assertTrimPaused(t, f, alerts, 3650, 0)
		})
	})
}

// headAnchorChain 造出已修剪過一次、其後仍有三個到期且已清除候選點的鏈（候選點的點簽章與清除簽章全部合法）。
func headAnchorChain(t *testing.T, f *purgeFixture) {
	t.Helper()
	old := time.Now().Add(-trimRowsAged)
	buildTrimChain(t, f, []trimChainSpec{
		{rows: 2, sealedAge: trimAgeOld, createdAt: old, purge: true},
		{rows: 2, sealedAge: trimAgeMid, createdAt: old, purge: true},
		{rows: 2, sealedAge: trimAgeNear, createdAt: old, purge: true},
		{rows: 2, sealedAge: trimAgeLate, createdAt: old, purge: true},
	})
	n, trim, err := f.purger.TrimChain(3650)
	if err != nil || n == 0 || trim == nil {
		t.Fatalf("前置不成立：第一次修剪應成功（n=%d trim=%v err=%v）", n, trim != nil, err)
	}
	if trim.LastTrimmedSeq != 2 {
		t.Fatalf("前置不成立：第一次應修剪到 seq=2，實得 %d", trim.LastTrimmedSeq)
	}
}

// TestTrimChainHeadAnchor 鏈頭錨定不成立（前一修剪記錄被刪、被改、被換成不接鏈頭的舊記錄）時不修剪。
func TestTrimChainHeadAnchor(t *testing.T) {
	type anchorCase struct {
		name   string
		schema string
		tamper func(t *testing.T, f *purgeFixture)
	}
	cases := []anchorCase{
		{"前一修剪記錄被刪", "head_deleted", func(t *testing.T, f *purgeFixture) {
			f.mustExecSQL(t, "DELETE FROM audit_checkpoint_trims")
		}},
		{"前一修剪記錄欄位被改", "head_edited", func(t *testing.T, f *purgeFixture) {
			f.mustExecSQL(t, "UPDATE audit_checkpoint_trims SET policy_days = 1")
		}},
		{"前一修剪記錄換成不接現存鏈頭的較舊有效記錄", "head_older", func(t *testing.T, f *purgeFixture) {
			n, trim, err := f.purger.TrimChain(2000)
			if err != nil || n == 0 || trim == nil {
				t.Fatalf("前置不成立：第二次修剪應成功（n=%d err=%v）", n, err)
			}
			f.mustExecSQL(t, "DELETE FROM audit_checkpoint_trims WHERE id = ?", trim.ID)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withTrimDBs(t, tc.schema, func(t *testing.T, f *purgeFixture) {
				headAnchorChain(t, f)
				tc.tamper(t, f)
				chain := loadChain(t, f.db)
				if len(chain) < 2 {
					t.Fatalf("前置不成立：鏈長 %d", len(chain))
				}
				// 候選點（鏈頭起第一個到最後一個之前）的點簽章與清除簽章本身都合法
				for _, cp := range chain[:len(chain)-1] {
					trimCandidatePrecondition(t, f, cp.Seq)
				}
				alerts := &fakeChainAlerter{}
				f.purger.SetFailureAlerter(alerts)
				trimsBefore := trimTableCount(t, f.db, "audit_checkpoint_trims")
				assertTrimPaused(t, f, alerts, 500, trimsBefore)
				// 結構層驗證仍回報鏈頭異常
				prev, err := latestTrimTx(f.db)
				if err != nil {
					t.Fatalf("latestTrim: %v", err)
				}
				baseline, err := readIntegrityBaseline(f.db)
				if err != nil {
					t.Fatalf("baseline: %v", err)
				}
				st := checkpointChainStructure(loadChain(t, f.db), prev, baseline, f.signer)
				if st.Points[0].Status == IntervalStatusPassed {
					t.Errorf("結構驗證應回報鏈頭異常，實得 %s", st.Points[0].Status)
				}
			})
		})
	}
}

// TestTrimChainEmptyIntervalNoTombstone 到期的空區間沒有清除標記與清除簽章，仍正常修剪且不告警。
func TestTrimChainEmptyIntervalNoTombstone(t *testing.T) {
	f := setupPurgeFixture(t)
	old := time.Now().Add(-trimRowsAged)
	chain := buildTrimChain(t, f, []trimChainSpec{
		{rows: 0, sealedAge: trimAgeOld, createdAt: old},
		{rows: 2, sealedAge: trimAgeOld - trimDay, createdAt: old, purge: true},
	})
	empty := -1
	for i, cp := range chain[:len(chain)-1] {
		if cp.RowCount == 0 && cp.PurgedAt == nil && cp.PurgeSignature == nil && cp.Seq != 1 {
			empty = i
		}
	}
	if empty < 0 {
		t.Fatalf("前置不成立：候選範圍內應含 row_count=0、無清除標記的非 genesis 點：%+v", chain)
	}
	if _, ok := checkpointPointSignature(&chain[empty], f.signer); !ok {
		t.Fatal("前置不成立：空區間的點簽章應有效")
	}
	alerts := &fakeChainAlerter{}
	f.purger.SetFailureAlerter(alerts)
	n, trim, err := f.purger.TrimChain(3650)
	if err != nil || trim == nil || n == 0 {
		t.Fatalf("空區間不得阻擋修剪：n=%d trim=%v err=%v", n, trim != nil, err)
	}
	if trim.LastTrimmedSeq < chain[empty].Seq {
		t.Fatalf("修剪應涵蓋空區間 seq=%d，實得到 seq=%d", chain[empty].Seq, trim.LastTrimmedSeq)
	}
	if len(alerts.calls) != 0 {
		t.Fatalf("不得發出結構層告警，實得 %+v", alerts.calls)
	}
	if trim.UnverifiedCount == nil || *trim.UnverifiedCount != 0 {
		t.Fatalf("正常修剪的未驗證段數應為 0：%v", trim.UnverifiedCount)
	}
}

// TestTrimCutIndexRejectsInvalidPointSignature 候選點的點簽章無效，其封章時間與清除簽章本身合法且到期，
// 仍判為不可修剪。
func TestTrimCutIndexRejectsInvalidPointSignature(t *testing.T) {
	f := setupPurgeFixture(t)
	old := time.Now().Add(-trimRowsAged)
	buildTrimChain(t, f, []trimChainSpec{
		{rows: 2, sealedAge: trimAgeOld, createdAt: old, purge: true},
		{rows: 2, sealedAge: trimAgeOld - trimDay, createdAt: old, purge: true},
	})
	trimCandidatePrecondition(t, f, 2, 3)
	chain := loadChain(t, f.db)
	cutoff := time.Now().Add(-3650 * trimDay)
	if cut, pause := trimCutIndex(chain, cutoff, 365, f.purger); cut < 2 || pause != "" {
		t.Fatalf("前置不成立：合法鏈應可修剪到 seq=3 以上（cut=%d pause=%q）", cut, pause)
	}
	// 只破壞第三個點（seq=3）的簽章欄位本身；其封章時間與清除簽章不動
	bad := append([]model.AuditCheckpoint(nil), chain...)
	sig := []byte(bad[2].Signature)
	if sig[0] == 'A' {
		sig[0] = 'B'
	} else {
		sig[0] = 'A'
	}
	bad[2].Signature = string(sig)
	cut, pause := trimCutIndex(bad, cutoff, 365, f.purger)
	if pause == "" || cut != -1 {
		t.Fatalf("點簽章無效的候選點必須使判定暫停（fail-close）：cut=%d pause=%q", cut, pause)
	}
}

// TestTrimAnchorLinkIgnoresNewHead 被修剪最後一點簽章無效時回 false，且不回傳新鏈頭的 prev_checkpoint_hash。
func TestTrimAnchorLinkIgnoresNewHead(t *testing.T) {
	f := setupPurgeFixture(t)
	f.sealInterval(t, 1, time.Now())
	f.sealInterval(t, 1, time.Now())
	chain := loadChain(t, f.db)
	last, newHead := chain[0], chain[1]
	if _, ok := checkpointPointSignature(&newHead, f.signer); !ok || newHead.PrevCheckpointHash == "" {
		t.Fatal("前置不成立：新鏈頭簽章應有效且帶 prev_checkpoint_hash")
	}
	if link, ok := trimAnchorLink(&last, &newHead, f.signer); !ok || link == "" {
		t.Fatalf("前置不成立：末點有效時應回其重算的鏈接（ok=%v）", ok)
	}
	last.Signature = "AAAA" + last.Signature[4:]
	link, ok := trimAnchorLink(&last, &newHead, f.signer)
	if ok {
		t.Fatal("被修剪最後一點簽章無效時必須回 ok=false")
	}
	if link != "" || link == newHead.PrevCheckpointHash {
		t.Fatalf("不得回傳新鏈頭的 prev_checkpoint_hash：%q", link)
	}
}

// replaceLatestTrimUnverified 以測試私鑰把最新一筆修剪記錄換成「同內容、指定未驗證段數、重新簽章」的記錄。
func replaceLatestTrimUnverified(t *testing.T, f *purgeFixture, n int64) {
	t.Helper()
	prev, err := latestTrimTx(f.db)
	if err != nil || prev == nil {
		t.Fatalf("latest trim: %v %v", prev, err)
	}
	rec := *prev
	rec.ID = 0
	rec.UnverifiedCount = &n
	payload, err := CheckpointTrimSignBytes(&rec)
	if err != nil {
		t.Fatalf("trim sign bytes: %v", err)
	}
	rec.SigningKeyVersion, rec.Signature = f.signer.Sign(payload)
	f.mustExecSQL(t, "DELETE FROM audit_checkpoint_trims WHERE id = ?", prev.ID)
	if err := f.db.Create(&rec).Error; err != nil {
		t.Fatalf("create trim: %v", err)
	}
}

func trimReportJSON(t *testing.T, v *CheckpointVerifier) (*ChainReport, map[string]any) {
	t.Helper()
	rep, err := v.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return rep, m
}

// TestTrimAnchorUnverifiedSurfaced 既存修剪記錄載有未驗證段數時：驗證回應揭露段數，總狀態仍為 passed，排程驗證不開事件。
func TestTrimAnchorUnverifiedSurfaced(t *testing.T) {
	f := setupPurgeFixture(t)
	old := time.Now().Add(-trimRowsAged)
	buildTrimChain(t, f, []trimChainSpec{
		{rows: 2, sealedAge: trimAgeOld, createdAt: old, purge: true},
	})
	if n, trim, err := f.purger.TrimChain(3650); err != nil || n == 0 || trim == nil {
		t.Fatalf("前置不成立：修剪應成功（n=%d err=%v）", n, err)
	}
	replaceLatestTrimUnverified(t, f, 3)
	v := NewCheckpointVerifier(f.db, f.seal, f.purger, nil, nil)
	rep, m := trimReportJSON(t, v)
	t.Logf("驗證回應 trim_disclosure=%v trim_unverified_segments=%v status=%v",
		m["trim_disclosure"], m["trim_unverified_segments"], m["status"])
	if m["trim_disclosure"] != "trim_unverified" {
		t.Errorf("回應應含 trim_unverified，實得 %v", m["trim_disclosure"])
	}
	if got, _ := m["trim_unverified_segments"].(float64); got != 3 {
		t.Errorf("揭露段數應為 3，實得 %v", m["trim_unverified_segments"])
	}
	if rep.Status != IntervalStatusPassed {
		t.Errorf("總狀態仍應為 passed，實得 %s", rep.Status)
	}
	alerts := &fakeChainAlerter{}
	if err := runScheduledVerify(t, f, alerts); err != nil {
		t.Fatalf("排程驗證: %v", err)
	}
	for _, c := range alerts.calls {
		if c.kind == "report" {
			t.Errorf("排程驗證不得因揭露而開立事件：%+v", c)
		}
	}
}

func runScheduledVerify(t *testing.T, f *purgeFixture, alerts *fakeChainAlerter) error {
	t.Helper()
	if err := f.db.AutoMigrate(&model.AuditChainVerifyState{}); err != nil {
		return err
	}
	verifier := NewCheckpointVerifier(f.db, f.seal, f.purger, nil, nil)
	svc := NewChainVerifyService(f.db, verifier, f.seal, &stubChainSigner{ready: true},
		&stubChainPolicy{vals: map[string]int{}},
		&stubChainTuning{days: 7, interval: time.Hour, rows: 1000000}, alerts)
	return svc.RunFullNow(context.Background())
}

// TestTrimUnverifiedPersistsAfterNormalTrim 升級前已有「3 → 0」兩筆修剪記錄：之後再做一次正常修剪，揭露仍為 3。
func TestTrimUnverifiedPersistsAfterNormalTrim(t *testing.T) {
	f := setupPurgeFixture(t)
	old := time.Now().Add(-trimRowsAged)
	buildTrimChain(t, f, []trimChainSpec{
		{rows: 2, sealedAge: trimAgeOld, createdAt: old, purge: true},
		{rows: 2, sealedAge: 3500 * trimDay, createdAt: old, purge: true},
		{rows: 2, sealedAge: trimAgeMid, createdAt: old, purge: true},
		{rows: 2, sealedAge: trimAgeNear, createdAt: old, purge: true},
	})
	// 前置：依序簽出兩筆修剪記錄，未驗證段數依序為 3、0
	if n, trim, err := f.purger.TrimChain(3650); err != nil || n == 0 || trim == nil {
		t.Fatalf("前置不成立：第一次修剪應成功（n=%d err=%v）", n, err)
	}
	replaceLatestTrimUnverified(t, f, 3) // 第一筆：3
	if n, trim, err := f.purger.TrimChain(3200); err != nil || n == 0 || trim == nil {
		t.Fatalf("前置不成立：第二次修剪應成功（n=%d err=%v）", n, err)
	}
	if got := trimTableCount(t, f.db, "audit_checkpoint_trims"); got != 2 {
		t.Fatalf("前置不成立：應有兩筆修剪記錄，實得 %d", got)
	}
	pre, err := latestTrimTx(f.db)
	if err != nil || pre == nil || pre.UnverifiedCount == nil || *pre.UnverifiedCount != 0 {
		t.Fatalf("前置不成立：最新一筆修剪記錄的未驗證段數應為 0：%v %v", pre, err)
	}
	// 正常修剪之前：揭露已是 3（來自第一筆），最新一筆為 0
	_, mPre := trimReportJSON(t, NewCheckpointVerifier(f.db, f.seal, f.purger, nil, nil))
	if got, _ := mPre["trim_unverified_segments"].(float64); got != 3 {
		t.Fatalf("前置不成立：正常修剪前揭露段數應為 3，實得 %v", mPre["trim_unverified_segments"])
	}

	// 第三次：正常修剪，新記錄只計本輪、恆為 0
	before := trimTableCount(t, f.db, "audit_checkpoint_trims")
	n, third, err := f.purger.TrimChain(2000)
	if err != nil || n == 0 || third == nil {
		t.Fatalf("第三次修剪應成功（n=%d trim=%v err=%v）", n, third != nil, err)
	}
	if trimTableCount(t, f.db, "audit_checkpoint_trims") != before+1 {
		t.Fatal("應新增一筆修剪記錄")
	}
	latest, err := latestTrimTx(f.db)
	if err != nil || latest == nil || latest.UnverifiedCount == nil || *latest.UnverifiedCount != 0 {
		t.Fatalf("最新一筆修剪記錄的未驗證段數應為 0：%v %v", latest, err)
	}
	if latest.ID == pre.ID {
		t.Fatal("最新一筆應為本次新增，而非前置的第二筆")
	}
	v := NewCheckpointVerifier(f.db, f.seal, f.purger, nil, nil)
	rep, m := trimReportJSON(t, v)
	if m["trim_disclosure"] != "trim_unverified" {
		t.Errorf("回應應含 trim_unverified，實得 %v", m["trim_disclosure"])
	}
	if got, _ := m["trim_unverified_segments"].(float64); got != 3 {
		t.Errorf("揭露段數應仍為 3（全部記錄加總），實得 %v", m["trim_unverified_segments"])
	}
	if rep.Status != IntervalStatusPassed {
		t.Errorf("總狀態仍應為 passed，實得 %s", rep.Status)
	}
}
