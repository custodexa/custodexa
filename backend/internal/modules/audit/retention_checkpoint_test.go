package audit

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"gorm.io/gorm"
)

// audit-checkpoint-chain 第 6 組（retention 改造）的測試。
//
// 本組是全案最高風險處：它動的是刻意繞過 BeforeDelete 守衛的原生 SQL 熱路徑，
// 且錯法的代價是**系統自己觸發竄改警報**（列沒了但無有效 tombstone）。
// 故本檔的斷言重心不在「有沒有刪對」，而在「任何失敗組合下都不留下半清狀態」。

// ── 夾具 ────────────────────────────────────────────────────────────────

// purgeFixture 一組互相接線的封章器＋清除器＋retention（共用同一把簽章鑰）
type purgeFixture struct {
	db      *gorm.DB
	seal    *CheckpointService
	purger  *CheckpointPurger
	svc     *RetentionService
	audit   *fakeAuditLogger
	signer  *testSigner
	nowFunc func() time.Time
}

// setupPurgeFixture 建立可完整跑一輪 retention 的 sqlite 夾具。
//
// 封章器與清除器共用同一把 testSigner：tombstone 與檢查點簽章本來就同一把鑰，
// 分兩把會讓「輪替後 tombstone 仍可驗」的欄位語義失去測試意義
func setupPurgeFixture(t *testing.T) *purgeFixture {
	t.Helper()
	db := setupCheckpointDB(t)
	if err := db.AutoMigrate(&model.SecurityPolicy{}, &model.AuditCheckpointTrim{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for _, stmt := range []string{
		"CREATE TABLE session_commands (id INTEGER PRIMARY KEY AUTOINCREMENT, executed_at DATETIME NOT NULL)",
		"CREATE TABLE command_alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, triggered_at DATETIME NOT NULL)",
	} {
		if err := db.Exec(stmt).Error; err != nil {
			t.Fatalf("建表: %v", err)
		}
	}
	seal, signer := newCheckpointService(t, db, nil, nil)
	if err := seal.EnsureGenesis(); err != nil {
		t.Fatalf("genesis: %v", err)
	}
	purger := NewCheckpointPurger(db, signer)
	auditLog := &fakeAuditLogger{}
	svc := NewRetentionService(db, policy.NewSecurityPolicyService(db), nil, auditLog)
	svc.checkpoints = purger
	svc.auditLogMode = auditLogPurgeInterval
	return &purgeFixture{db: db, seal: seal, purger: purger, svc: svc, audit: auditLog, signer: signer}
}

// setPolicyDays 經政策服務設值（與生產同一入口；本組只關心執行期行為）
func setPolicyDays(t *testing.T, svc *RetentionService, key string, days int) {
	t.Helper()
	if _, err := svc.policy.Update(key, strconv.Itoa(days), "test"); err != nil {
		t.Fatalf("set policy %s: %v", key, err)
	}
}

// countRange [from, to] 內的現存列數
func countRange(t *testing.T, db *gorm.DB, from, to uint) int64 {
	t.Helper()
	var n int64
	if err := db.Raw("SELECT COUNT(*) FROM audit_logs WHERE id >= ? AND id <= ?", from, to).
		Scan(&n).Error; err != nil {
		t.Fatalf("count range: %v", err)
	}
	return n
}

// sealInterval 灌 n 列（指定 created_at）後封章，回傳新檢查點
func (f *purgeFixture) sealInterval(t *testing.T, n int, createdAt time.Time) *model.AuditCheckpoint {
	t.Helper()
	seedAuditRows(t, f.db, n, createdAt)
	cp, err := f.seal.SealNow()
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return cp
}

// sealAt 以指定的 sealed_at 封章。
//
// **不可改用 SQL 直改 sealed_at 來「催老」檢查點**：sealed_at 在簽章涵蓋範圍內，
// 直改會使該檢查點簽章失效、鏈接雜湊改變——測試就會在驗證自己製造的竄改，
// 而不是在驗證修剪邏輯（本測第一版即踩此坑）
func (f *purgeFixture) sealAt(t *testing.T, n int, createdAt, sealedAt time.Time) *model.AuditCheckpoint {
	t.Helper()
	orig := f.seal.now
	f.seal.now = func() time.Time { return sealedAt }
	defer func() { f.seal.now = orig }()
	seedAuditRows(t, f.db, n, createdAt)
	cp, err := f.seal.SealNow()
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return cp
}

// mustExecSQL 原生 SQL（模擬 DB 直寫；ORM 守衛不適用於此路徑）
func (f *purgeFixture) mustExecSQL(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := f.db.Exec(sql, args...).Error; err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

// reload 自 DB 重讀檢查點（斷言 tombstone 是否真的落庫，而非只看記憶體物件）
func (f *purgeFixture) reload(t *testing.T, seq uint) model.AuditCheckpoint {
	t.Helper()
	var cp model.AuditCheckpoint
	if err := f.db.Where("seq = ?", seq).First(&cp).Error; err != nil {
		t.Fatalf("reload seq=%d: %v", seq, err)
	}
	return cp
}

// resignWithRowCount 把指定檢查點的 row_count 改成 want 並**重新簽章**，
// 使該列仍能通過簽章閘（用於單獨測試 row_count 條件本身的偵測力）
func (f *purgeFixture) resignWithRowCount(t *testing.T, seq uint, want int64) {
	t.Helper()
	cp := f.reload(t, seq)
	cp.RowCount = want
	payload, err := CheckpointSignBytes(&cp)
	if err != nil {
		t.Fatalf("sign bytes: %v", err)
	}
	_, sig := f.signer.Sign(payload)
	if err := f.db.Exec("UPDATE audit_checkpoints SET row_count = ?, signature = ? WHERE seq = ?",
		want, sig, seq).Error; err != nil {
		t.Fatalf("resign: %v", err)
	}
}

// ── 6.2 可清區間查詢（唯讀）──────────────────────────────────────────────

// TestPurgeableIntervalsConditions 四個可清條件各自不成立時皆不得回傳。
//
// 每個條件獨立造反例，而非只測「全部成立時回傳」——後者對「條件被拿掉」
// 毫無偵測力（守衛假綠的既有形態）
func TestPurgeableIntervalsConditions(t *testing.T) {
	f := setupPurgeFixture(t)
	old := time.Now().Add(-400 * 24 * time.Hour)
	fresh := time.Now().Add(-1 * time.Hour)
	cutoff := time.Now().Add(-365 * 24 * time.Hour)

	expired := f.sealInterval(t, 3, old)         // seq=2：全部過期 → 可清
	notExpired := f.sealInterval(t, 2, fresh)    // seq=3：未過期 → 不可清
	alreadyPurged := f.sealInterval(t, 2, old)   // seq=4：已有 tombstone → 不可清
	tampered := f.sealInterval(t, 2, old)        // seq=5：簽章被改 → 不可清
	emptyWithTime := f.sealInterval(t, 2, old)   // seq=6：改造成 row_count=0 → 不可清

	// seq=4：直接標記已清（走白名單 map 形式，與生產路徑同一入口）
	if err := f.db.Model(&model.AuditCheckpoint{}).Where("seq = ?", alreadyPurged.Seq).
		Updates(map[string]any{"purged_at": time.Now()}).Error; err != nil {
		t.Fatalf("mark purged: %v", err)
	}
	// seq=5：以原生 SQL 竄改被簽章欄（模擬 DB 直寫；ORM 路徑被守衛擋住）
	if err := f.db.Exec("UPDATE audit_checkpoints SET agg_hash = ? WHERE seq = ?",
		"00000000000000000000000000000000000000000000000000000000000000ff", tampered.Seq).Error; err != nil {
		t.Fatalf("tamper: %v", err)
	}
	// seq=6：造出「row_count=0 但 max_created_at 有值」的畸形列，**且簽章有效**。
	//
	// 為何要重新簽而不是 SQL 直改 row_count：row_count 在簽章涵蓋範圍內，
	// 直改會使該列先被簽章閘擋掉，`row_count > 0` 這道條件就永遠沒被執行到
	//（本測第一版即如此，突變存活）。重簽之後這道條件才是唯一擋下它的東西。
	//
	// 此形狀今日的自然路徑產不出來（空區間的 max_created_at 必為 NULL），
	// 本條防的是「未來的聚合實作漂移或持鑰者構造」——若它進了清除路徑，
	// 系統會對一個「零列的區間」簽下 tombstone，等於在鏈上簽一個從未發生的清除
	f.resignWithRowCount(t, emptyWithTime.Seq, 0)

	got, err := f.purger.PurgeableIntervals(cutoff)
	if err != nil {
		t.Fatalf("PurgeableIntervals: %v", err)
	}
	if len(got) != 1 || got[0].Seq != expired.Seq {
		var seqs []uint
		for _, cp := range got {
			seqs = append(seqs, cp.Seq)
		}
		t.Fatalf("僅 seq=%d 應可清，實得 %v（未過期=%d 已清=%d 竄改=%d 空區間=%d）",
			expired.Seq, seqs, notExpired.Seq, alreadyPurged.Seq, tampered.Seq, emptyWithTime.Seq)
	}
}

// TestPurgeableIntervalsExcludesNaturalEmpty genesis 與自然空區間（max_created_at NULL）
// 不得進入清除路徑——它們的 id_from > id_to，閉區間刪除雖為空集合，
// 但寫下 tombstone 等於在鏈上簽一個從未發生的清除
func TestPurgeableIntervalsExcludesNaturalEmpty(t *testing.T) {
	f := setupPurgeFixture(t)
	// genesis（seq=1）已存在且為空區間；再封一個空區間
	if _, err := f.seal.SealNow(); err != nil {
		t.Fatalf("seal empty: %v", err)
	}
	got, err := f.purger.PurgeableIntervals(time.Now())
	if err != nil {
		t.Fatalf("PurgeableIntervals: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("空區間不得可清，實得 %d 個", len(got))
	}
}

// ── 6.3 pre-genesis 逐列路徑的 id 上界 ───────────────────────────────────

// setupStraddleFixture 造出橫跨 genesis 邊界的過期資料：
// genesis 之前 n 列（逐列路徑的地盤）、之後 m 列並封章（區間路徑的地盤），
// 兩段的 created_at 同樣過期——時間上無從區分，只有 id 上界能分開它們
func setupStraddleFixture(t *testing.T, pre, post int, freshTail bool) (*purgeFixture, uint, *model.AuditCheckpoint) {
	t.Helper()
	old := time.Now().Add(-400 * 24 * time.Hour)
	db := setupCheckpointDB(t)
	if err := db.AutoMigrate(&model.SecurityPolicy{}, &model.AuditCheckpointTrim{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for _, stmt := range []string{
		"CREATE TABLE session_commands (id INTEGER PRIMARY KEY AUTOINCREMENT, executed_at DATETIME NOT NULL)",
		"CREATE TABLE command_alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, triggered_at DATETIME NOT NULL)",
	} {
		if err := db.Exec(stmt).Error; err != nil {
			t.Fatalf("建表: %v", err)
		}
	}
	// genesis 之前的列必須先於 genesis 存在——這正是真實部署的形狀
	seedAuditRows(t, db, pre, old)
	seal, signer := newCheckpointService(t, db, nil, nil)
	if err := seal.EnsureGenesis(); err != nil {
		t.Fatalf("genesis: %v", err)
	}
	genesis, err := seal.Latest()
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	auditLog := &fakeAuditLogger{}
	svc := NewRetentionService(db, policy.NewSecurityPolicyService(db), nil, auditLog)
	purger := NewCheckpointPurger(db, signer)
	svc.checkpoints = purger
	svc.auditLogMode = auditLogPurgeInterval
	f := &purgeFixture{db: db, seal: seal, purger: purger, svc: svc, audit: auditLog, signer: signer}
	seedAuditRows(t, db, post, old)
	if freshTail {
		// 區間內夾一列未過期 → 該區間整段不可清；此時逐列路徑若少了 id 上界，
		// 就會把區間內那 post 列過期列刪光而不留任何 tombstone
		seedAuditRows(t, db, 1, time.Now())
	}
	cp, err := seal.SealNow()
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	setPolicyDays(t, svc, policy.PolicyRetentionAuditLogDays, 365)
	return f, genesis.IDFrom, cp
}

// TestPreGenesisPurgeDoesNotCrossBoundary 逐列路徑只碰 id < genesis id_from。
//
// 這是本組最容易出人命的一條：兩段的 created_at 完全一樣過期，
// 少了 id 上界，逐列路徑會把已被檢查點覆蓋的列一併刪光而不留任何 tombstone
// ——那正是「列沒了但無有效 tombstone」的自傷告警
func TestPreGenesisPurgeDoesNotCrossBoundary(t *testing.T) {
	f, genesisIDFrom, cp := setupStraddleFixture(t, 6, 4, true)
	if genesisIDFrom != 7 {
		t.Fatalf("genesis id_from 應為 7（pre 6 列＋1），實得 %d", genesisIDFrom)
	}
	before := countRange(t, f.db, 1, genesisIDFrom-1)
	if before != 6 {
		t.Fatalf("pre-genesis 應有 6 列，實得 %d", before)
	}

	results := f.svc.PurgeAll()
	var audits *PurgeResult
	for i := range results {
		if results[i].Target == auditLogsTable {
			audits = &results[i]
		}
	}
	if audits == nil {
		t.Fatal("audit_logs 無清除結果")
	}
	// pre-genesis 6 列應清空
	if n := countRange(t, f.db, 1, genesisIDFrom-1); n != 0 {
		t.Fatalf("pre-genesis 應清空，殘 %d 列", n)
	}
	// genesis 之後的 5 列（4 過期 + 1 未過期）一筆未少：該區間不可清，
	// 而逐列路徑碰不到它們
	if n := countRange(t, f.db, cp.IDFrom, cp.IDTo); n != 5 {
		t.Fatalf("已被檢查點覆蓋的列不得由逐列路徑刪除，應餘 5 列實得 %d", n)
	}
	// 該區間未被標記清除——沒有 tombstone 就代表沒有任何列被合法清走
	if got := f.reload(t, cp.Seq); got.PurgedAt != nil {
		t.Fatalf("逐列路徑不得寫 tombstone，seq=%d purged_at=%v", cp.Seq, got.PurgedAt)
	}
	if audits.PreGenesis != 6 {
		t.Fatalf("pre_genesis 留痕應為 6，實得 %d", audits.PreGenesis)
	}
}

// ── 6.4 區間清除交易 ────────────────────────────────────────────────────

// TestPurgeIntervalSuccess 正常清除：列全刪、tombstone 落庫且可驗
func TestPurgeIntervalSuccess(t *testing.T) {
	f := setupPurgeFixture(t)
	old := time.Now().Add(-400 * 24 * time.Hour)
	cutoff := time.Now().Add(-365 * 24 * time.Hour)
	cp := f.sealInterval(t, 5, old)

	deleted, err := f.purger.PurgeInterval(cp, 365, cutoff)
	if err != nil {
		t.Fatalf("PurgeInterval: %v", err)
	}
	if deleted != 5 {
		t.Fatalf("刪除筆數 = %d, want 5", deleted)
	}
	if n := countRange(t, f.db, cp.IDFrom, cp.IDTo); n != 0 {
		t.Fatalf("區間應清空，殘 %d 列", n)
	}
	got := f.reload(t, cp.Seq)
	if got.PurgedAt == nil || got.PurgeSignature == nil || got.PurgeSigningKeyVersion == nil {
		t.Fatalf("tombstone 三欄必須齊備: %+v", got)
	}
	ok, err := f.purger.VerifyPurgeTombstone(&got, 365)
	if err != nil || !ok {
		t.Fatalf("tombstone 應可驗，ok=%v err=%v", ok, err)
	}
	// policy_days 隨簽章保存（增列 purge_policy_days 欄）：
	// **驗證以記錄值為準，不受呼叫端傳入值影響**——否則 admin 調整保留天數
	// 就會讓全部歷史 tombstone 一起驗不過（大規模自傷告警）
	if got.PurgePolicyDays == nil || *got.PurgePolicyDays != 365 {
		t.Fatalf("purge_policy_days 應記錄 365，實得 %v", got.PurgePolicyDays)
	}
	if ok, err := f.purger.VerifyPurgeTombstone(&got, 366); err != nil || !ok {
		t.Fatal("政策值改變後 tombstone 仍須可驗（記錄值才是簽章的輸入）")
	}
	// 但**竄改記錄值**必驗不過——綁定沒有因此變鬆（跨區間重放仍不可能）
	f.mustExecSQL(t, "UPDATE audit_checkpoints SET purge_policy_days = 366 WHERE seq = ?", cp.Seq)
	tampered := f.reload(t, cp.Seq)
	if ok, _ := f.purger.VerifyPurgeTombstone(&tampered, 365); ok {
		t.Fatal("竄改 purge_policy_days 後 tombstone 不得仍驗過")
	}
}

// TestPurgeIntervalRowsMissingAborts 區間已被抽列時必須中止並保全證據。
//
// 若照清不誤，驗證端會回報 purged_legal——系統親手把一起竊取洗成合法清除
func TestPurgeIntervalRowsMissingAborts(t *testing.T) {
	f := setupPurgeFixture(t)
	old := time.Now().Add(-400 * 24 * time.Hour)
	cutoff := time.Now().Add(-365 * 24 * time.Hour)
	cp := f.sealInterval(t, 5, old)
	// 攻擊者以 DB 直寫抽走中段一列
	if err := f.db.Exec("DELETE FROM audit_logs WHERE id = ?", cp.IDFrom+2).Error; err != nil {
		t.Fatalf("抽列: %v", err)
	}

	if _, err := f.purger.PurgeInterval(cp, 365, cutoff); err == nil {
		t.Fatal("區間短少列時必須中止，實得 nil")
	}
	if n := countRange(t, f.db, cp.IDFrom, cp.IDTo); n != 4 {
		t.Fatalf("中止必回滾：殘餘 4 列，實得 %d", n)
	}
	if got := f.reload(t, cp.Seq); got.PurgedAt != nil {
		t.Fatalf("中止不得留下 tombstone: %+v", got)
	}
}

// TestPurgeIntervalNotFullyExpiredSkips 封章後落地的 straggler 使區間本輪不清。
//
// max_created_at 是封章當下的快照；少了本檢查，未過期的 straggler 會因
// 「所屬區間已過期」被提早刪除（spec：反向偏差 SHALL NOT 發生）
func TestPurgeIntervalNotFullyExpiredSkips(t *testing.T) {
	f := setupPurgeFixture(t)
	old := time.Now().Add(-400 * 24 * time.Hour)
	cutoff := time.Now().Add(-365 * 24 * time.Hour)
	cp := f.sealInterval(t, 4, old)
	// straggler：id 落在已封區間內，但 created_at 是新的
	if err := f.db.Exec("UPDATE audit_logs SET created_at = ? WHERE id = ?",
		time.Now(), cp.IDTo).Error; err != nil {
		t.Fatalf("straggler: %v", err)
	}

	_, err := f.purger.PurgeInterval(cp, 365, cutoff)
	if err == nil {
		t.Fatal("含未過期列的區間不得清除，實得 nil")
	}
	if n := countRange(t, f.db, cp.IDFrom, cp.IDTo); n != 4 {
		t.Fatalf("不得刪除任何列，殘 %d（want 4）", n)
	}
	if got := f.reload(t, cp.Seq); got.PurgedAt != nil {
		t.Fatal("未清除不得寫 tombstone")
	}
}

// ── 6.5 tombstone 時序 ──────────────────────────────────────────────────

// assertNoHalfPurged 交叉查詢：帶 tombstone 的檢查點其區間殘列必為 0。
//
// 這是「列沒了但無有效 tombstone」與「有 tombstone 卻還有列」兩種半清狀態的
// 統一探針，spec 的驗收 SQL 逐字對應
func assertNoHalfPurged(t *testing.T, f *purgeFixture, policyDays int) {
	t.Helper()
	type row struct {
		Seq    uint
		Remain int64
	}
	var rows []row
	if err := f.db.Raw(`SELECT c.seq AS seq,
		(SELECT COUNT(*) FROM audit_logs l WHERE l.id >= c.id_from AND l.id <= c.id_to) AS remain
		FROM audit_checkpoints c WHERE c.purged_at IS NOT NULL`).Scan(&rows).Error; err != nil {
		t.Fatalf("交叉查詢: %v", err)
	}
	for _, r := range rows {
		if r.Remain != 0 {
			t.Fatalf("seq=%d 有 tombstone 卻殘 %d 列（半清狀態）", r.Seq, r.Remain)
		}
	}
	// 反向：未帶 tombstone 的非空區間，其列必須完整存在（不得少列）
	var cps []model.AuditCheckpoint
	if err := f.db.Where("purged_at IS NULL AND row_count > 0").Find(&cps).Error; err != nil {
		t.Fatalf("讀未清區間: %v", err)
	}
	for i := range cps {
		cp := cps[i]
		if n := countRange(t, f.db, cp.IDFrom, cp.IDTo); n < cp.RowCount {
			t.Fatalf("seq=%d 無 tombstone 卻只剩 %d/%d 列——這正是自傷告警的形態",
				cp.Seq, n, cp.RowCount)
		}
	}
}

// TestPurgeTombstoneTimingInvariant 清除前後、成功與失敗路徑，交叉查詢恆成立
func TestPurgeTombstoneTimingInvariant(t *testing.T) {
	f := setupPurgeFixture(t)
	old := time.Now().Add(-400 * 24 * time.Hour)
	cutoff := time.Now().Add(-365 * 24 * time.Hour)
	a := f.sealInterval(t, 3, old)
	b := f.sealInterval(t, 3, old)

	assertNoHalfPurged(t, f, 365)
	if _, err := f.purger.PurgeInterval(a, 365, cutoff); err != nil {
		t.Fatalf("purge a: %v", err)
	}
	assertNoHalfPurged(t, f, 365)

	// 注入 tombstone 寫入前失敗，b 必須整段回滾
	f.purger.faults.beforeTombstoneWrite = func() error { return errTestInjected }
	if _, err := f.purger.PurgeInterval(b, 365, cutoff); err == nil {
		t.Fatal("注入失敗後 PurgeInterval 應回錯")
	}
	f.purger.faults.beforeTombstoneWrite = nil
	if f.purger.faults.fired == 0 {
		t.Fatal("注入器從未被觸發：本測退化為零觸發假綠")
	}
	assertNoHalfPurged(t, f, 365)
	if n := countRange(t, f.db, b.IDFrom, b.IDTo); n != 3 {
		t.Fatalf("b 區間應完整回滾，殘 %d（want 3）", n)
	}
}

// TestGenesisIDFromFailsClosedOnEmptyChain 鏈為空時必須停手而非退回「無上界」
func TestGenesisIDFromFailsClosedOnEmptyChain(t *testing.T) {
	f := setupPurgeFixture(t)
	if err := f.db.Exec("DELETE FROM audit_checkpoints").Error; err != nil {
		t.Fatalf("wipe chain: %v", err)
	}
	if _, err := f.purger.GenesisIDFrom(); err == nil {
		t.Fatal("鏈為空時 GenesisIDFrom 必須回錯（fail-close），實得 nil")
	}
}

// errTestInjected 測試注入的故障（與真實錯誤可區分）
var errTestInjected = errors.New("測試注入的故障")

// ── 6.6 上限在區間邊界停 ────────────────────────────────────────────────

// TestPurgeStopsAtIntervalBoundary 剩餘額度吃不下整個區間時整段留待次輪。
//
// 半個區間＋無 tombstone＝自傷告警，故此處寧可少刪也不可切開區間
func TestPurgeStopsAtIntervalBoundary(t *testing.T) {
	f := setupPurgeFixture(t)
	old := time.Now().Add(-400 * 24 * time.Hour)
	a := f.sealInterval(t, 3, old)
	b := f.sealInterval(t, 3, old)
	setPolicyDays(t, f.svc, policy.PolicyRetentionAuditLogDays, 365)
	f.svc.maxPerRun = 4 // 吃得下 a（3 列），吃不下 b（剩 1 列額度）

	results := f.svc.PurgeAll()
	res := auditLogResult(t, results)
	if res.Deleted != 3 || !res.Partial {
		t.Fatalf("應刪 3 筆且標 partial，實得 deleted=%d partial=%v", res.Deleted, res.Partial)
	}
	if n := countRange(t, f.db, a.IDFrom, a.IDTo); n != 0 {
		t.Fatalf("a 區間應清空，殘 %d", n)
	}
	if n := countRange(t, f.db, b.IDFrom, b.IDTo); n != 3 {
		t.Fatalf("b 區間必須完全未被觸碰，殘 %d（want 3）", n)
	}
	if got := f.reload(t, b.Seq); got.PurgedAt != nil {
		t.Fatal("未處理的區間不得有 tombstone")
	}
	assertNoHalfPurged(t, f, 365)

	// 次輪：額度回滿，b 才被整段清除
	f.svc.maxPerRun = 100
	res2 := auditLogResult(t, f.svc.PurgeAll())
	if res2.Deleted != 3 || res2.Partial {
		t.Fatalf("次輪應刪 3 筆且非 partial，實得 deleted=%d partial=%v", res2.Deleted, res2.Partial)
	}
	assertNoHalfPurged(t, f, 365)
}

// auditLogResult 自 PurgeAll 結果取出 audit_logs 那一筆
func auditLogResult(t *testing.T, results []PurgeResult) PurgeResult {
	t.Helper()
	for _, r := range results {
		if r.Target == auditLogsTable {
			return r
		}
	}
	t.Fatalf("結果中無 audit_logs：%+v", results)
	return PurgeResult{}
}

// ── 6.7 切換至區間策略：與 legacy 的行為差異 ────────────────────────────

// seedMixedIntervals 造出「整段過期的 a」與「過期列＋未過期列混合的 b」
func seedMixedIntervals(t *testing.T, f *purgeFixture) (a, b *model.AuditCheckpoint) {
	t.Helper()
	old := time.Now().Add(-400 * 24 * time.Hour)
	fresh := time.Now().Add(-time.Hour)
	a = f.sealInterval(t, 3, old)
	seedAuditRows(t, f.db, 2, old)   // 已過期
	seedAuditRows(t, f.db, 1, fresh) // 未過期 → 整個 b 區間暫不清
	cp, err := f.seal.SealNow()
	if err != nil {
		t.Fatalf("seal b: %v", err)
	}
	setPolicyDays(t, f.svc, policy.PolicyRetentionAuditLogDays, 365)
	return a, cp
}

// TestIntervalModeVsLegacyDelta 切換前後的差異必須完全可由區間語義解釋。
//
// 同一份資料跑兩次（legacy／interval），差額必須恰好等於「所屬區間尚有
// 未過期列」的那些過期列——這就是 spec 明載的「有界過度保留」，
// 也是部署後首輪 retention 唯一應出現的行為差異
func TestIntervalModeVsLegacyDelta(t *testing.T) {
	legacy := setupPurgeFixture(t)
	legacy.svc.auditLogMode = auditLogPurgeLegacy
	aL, bL := seedMixedIntervals(t, legacy)
	resLegacy := auditLogResult(t, legacy.svc.PurgeAll())

	interval := setupPurgeFixture(t)
	aI, bI := seedMixedIntervals(t, interval)
	resInterval := auditLogResult(t, interval.svc.PurgeAll())

	// legacy：逐列刪，a 的 3 列＋b 的 2 列過期列全刪（b 被切成半個區間！）
	if resLegacy.Deleted != 5 {
		t.Fatalf("legacy 應刪 5 筆（3+2），實得 %d", resLegacy.Deleted)
	}
	if n := countRange(t, legacy.db, bL.IDFrom, bL.IDTo); n != 1 {
		t.Fatalf("legacy 下 b 區間應只剩 1 列未過期，實得 %d", n)
	}
	if got := legacy.reload(t, bL.Seq); got.PurgedAt != nil {
		t.Fatal("legacy 不寫 tombstone")
	}
	_ = aL

	// interval：只清整段過期的 a，b 整段暫留（含其 2 列已過期列）
	if resInterval.Deleted != 3 {
		t.Fatalf("interval 應刪 3 筆，實得 %d", resInterval.Deleted)
	}
	if n := countRange(t, interval.db, bI.IDFrom, bI.IDTo); n != 3 {
		t.Fatalf("interval 下 b 區間應完整保留 3 列，實得 %d", n)
	}
	if got := interval.reload(t, aI.Seq); got.PurgedAt == nil {
		t.Fatal("a 應有 tombstone")
	}
	// 差額 = 2 = b 區間內已過期但因區間未全過期而暫留的列數
	if delta := resLegacy.Deleted - resInterval.Deleted; delta != 2 {
		t.Fatalf("兩模式差額應為 2（b 區間的過期列），實得 %d", delta)
	}
	assertNoHalfPurged(t, interval, 365)
}

// ── 6.8 pre-genesis 與區間路徑的邊界不重疊、不漏刪 ──────────────────────

// TestBoundaryThreeRoundsNoOverlap 連跑三輪：邊界穩定、無重複計數、無漏刪
func TestBoundaryThreeRoundsNoOverlap(t *testing.T) {
	f, genesisIDFrom, cpOld := setupStraddleFixture(t, 6, 3, false)
	// 再加一個「含未過期列」的區間，確保區間路徑不是全清
	seedAuditRows(t, f.db, 1, time.Now())
	cpFresh, err := f.seal.SealNow()
	if err != nil {
		t.Fatalf("seal fresh: %v", err)
	}

	var rounds []int64
	for i := 0; i < 3; i++ {
		res := auditLogResult(t, f.svc.PurgeAll())
		rounds = append(rounds, res.Deleted)
		assertNoHalfPurged(t, f, 365)
		t.Logf("第 %d 輪：deleted=%d pre_genesis=%d intervals=%+v partial=%v",
			i+1, res.Deleted, res.PreGenesis, res.Intervals, res.Partial)
	}
	// 首輪清 pre-genesis 6 列＋整段過期區間 3 列＝9；二三輪皆 0（無重複計數）
	if rounds[0] != 9 || rounds[1] != 0 || rounds[2] != 0 {
		t.Fatalf("三輪刪除筆數 = %v, want [9 0 0]", rounds)
	}
	if n := countRange(t, f.db, 1, genesisIDFrom-1); n != 0 {
		t.Fatalf("pre-genesis 應清空，殘 %d", n)
	}
	if got := f.reload(t, cpOld.Seq); got.PurgedAt == nil {
		t.Fatal("整段過期區間應有 tombstone")
	}
	if n := countRange(t, f.db, cpFresh.IDFrom, cpFresh.IDTo); n != 1 {
		t.Fatalf("未過期區間應原封不動，殘 %d（want 1）", n)
	}
	if got := f.reload(t, cpFresh.Seq); got.PurgedAt != nil {
		t.Fatal("未過期區間不得有 tombstone")
	}
}

// ── 6.9 清除留痕含 seq 清單 ─────────────────────────────────────────────

// dbAuditLogger 把留痕真的寫進 audit_logs（驗證「留痕列本身落入後續檢查點」）
type dbAuditLogger struct{ db *gorm.DB }

func (d *dbAuditLogger) Log(e *AuditLogEntry) {
	row := model.AuditLog{
		Username: e.Username, Action: e.Action, Resource: e.Resource,
		Status: e.Status, Details: e.Details, ErrorMsg: e.ErrorMsg,
		CreatedAt: time.Now(), KeyVersion: 1, IntegrityHMAC: "deadbeef",
	}
	_ = d.db.Create(&row).Error
}

// TestPurgeAuditTrailCarriesSeqList 留痕載明 seq 與區間，且該列落入後續檢查點
func TestPurgeAuditTrailCarriesSeqList(t *testing.T) {
	f := setupPurgeFixture(t)
	f.svc.audit = &dbAuditLogger{db: f.db}
	old := time.Now().Add(-400 * 24 * time.Hour)
	a := f.sealInterval(t, 3, old)
	b := f.sealInterval(t, 2, old)
	setPolicyDays(t, f.svc, policy.PolicyRetentionAuditLogDays, 365)

	res := auditLogResult(t, f.svc.PurgeAll())
	if len(res.Intervals) != 2 {
		t.Fatalf("留痕應含 2 個區間，實得 %+v", res.Intervals)
	}
	if res.Intervals[0].Seq != a.Seq || res.Intervals[1].Seq != b.Seq {
		t.Fatalf("seq 清單 = %+v, want [%d %d]", res.Intervals, a.Seq, b.Seq)
	}
	if res.Intervals[0].IDFrom != a.IDFrom || res.Intervals[0].IDTo != a.IDTo {
		t.Fatalf("留痕須載明 id 區間，實得 %+v", res.Intervals[0])
	}
	blob, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(blob), `"intervals"`) {
		t.Fatalf("留痕 JSON 未含 intervals: %s", blob)
	}
	t.Logf("留痕 JSON 全文：%s", blob)

	// 留痕列本身寫入 audit_logs，下一次封章必須把它納入新區間
	var trail model.AuditLog
	if err := f.db.Where("resource = ?", model.ResourceRetention).
		Order("id DESC").First(&trail).Error; err != nil {
		t.Fatalf("讀留痕列: %v", err)
	}
	next, err := f.seal.SealNow()
	if err != nil {
		t.Fatalf("seal next: %v", err)
	}
	if trail.ID < next.IDFrom || trail.ID > next.IDTo {
		t.Fatalf("留痕列 id=%d 未落入新檢查點區間 [%d,%d]", trail.ID, next.IDFrom, next.IDTo)
	}
	if next.RowCount < 1 {
		t.Fatalf("新檢查點應覆蓋留痕列，row_count=%d", next.RowCount)
	}
}

// ── 6.10 檢查點鏈到期修剪 ──────────────────────────────────────────────

// TestCheckpointTrimFromHeadOnly 自鏈頭連續修剪、產生可驗修剪記錄、殘鏈可錨定
func TestCheckpointTrimFromHeadOnly(t *testing.T) {
	f := setupPurgeFixture(t)
	old := time.Now().Add(-400 * 24 * time.Hour)
	// 造 4 個已清除（有 tombstone）的舊區間 + 1 個新區間
	aged := time.Now().Add(-4000 * 24 * time.Hour)
	var cps []*model.AuditCheckpoint
	for i := 0; i < 4; i++ {
		cps = append(cps, f.sealAt(t, 2, old, aged.Add(time.Duration(i)*time.Minute)))
	}
	cutoff := time.Now().Add(-365 * 24 * time.Hour)
	for _, cp := range cps {
		if _, err := f.purger.PurgeInterval(cp, 365, cutoff); err != nil {
			t.Fatalf("purge seq=%d: %v", cp.Seq, err)
		}
	}
	newest := f.sealInterval(t, 1, time.Now())
	// genesis（seq=1）也必須是舊的才會被修剪：它由 EnsureGenesis 以真實時鐘封章，
	// 故以 sealed_at 早於 cutoff 的四個區間夾在其後，genesis 自身另行催老
	if err := f.db.Exec("UPDATE audit_checkpoints SET sealed_at = ? WHERE seq = 1",
		aged.Add(-time.Hour)).Error; err != nil {
		t.Fatalf("age genesis: %v", err)
	}
	genesisBefore, err := f.purger.GenesisIDFrom()
	if err != nil {
		t.Fatalf("genesis before: %v", err)
	}

	trimmed, trim, err := f.purger.TrimChain(3650)
	if err != nil {
		t.Fatalf("TrimChain: %v", err)
	}
	if trimmed != 5 || trim == nil { // genesis(seq=1) + 四個已清區間
		t.Fatalf("應修剪 5 個檢查點，實得 %d（trim=%v）", trimmed, trim)
	}
	if trim.LastTrimmedSeq != cps[3].Seq {
		t.Fatalf("last_trimmed_seq = %d, want %d", trim.LastTrimmedSeq, cps[3].Seq)
	}
	// 修剪記錄可驗
	ok, err := f.purger.VerifyTrim(trim)
	if err != nil || !ok {
		t.Fatalf("修剪記錄應可驗，ok=%v err=%v", ok, err)
	}
	// 殘鏈鏈頭的 prev hash 必須等於修剪記錄的錨——否則「合法修剪」與「鏈頭被挖」無從區分
	head := f.reload(t, newest.Seq)
	if head.PrevCheckpointHash != trim.LastTrimmedLinkHash {
		t.Fatalf("殘鏈鏈頭 prev hash %s 與修剪錨 %s 不符",
			head.PrevCheckpointHash, trim.LastTrimmedLinkHash)
	}
	// pre-genesis 邊界不得因修剪而放寬
	genesisAfter, err := f.purger.GenesisIDFrom()
	if err != nil {
		t.Fatalf("genesis after: %v", err)
	}
	if genesisAfter != genesisBefore {
		t.Fatalf("修剪後 pre-genesis 邊界由 %d 漂移到 %d——逐列路徑會吃掉曾被覆蓋的 id 段",
			genesisBefore, genesisAfter)
	}
}

// TestCheckpointTrimStopsAtLiveCoverage 仍覆蓋現存列的檢查點絕不修剪。
//
// 修剪它會讓那些列成為「無檢查點覆蓋也非 pre-genesis」的孤兒段，
// 其日後的缺失既不可證為合法清除也不可證為竄改
func TestCheckpointTrimStopsAtLiveCoverage(t *testing.T) {
	f := setupPurgeFixture(t)
	old := time.Now().Add(-400 * 24 * time.Hour)
	aged := time.Now().Add(-4000 * 24 * time.Hour)
	live := f.sealAt(t, 2, old, aged) // 未清除，仍有列
	f.sealInterval(t, 1, time.Now())
	if err := f.db.Exec("UPDATE audit_checkpoints SET sealed_at = ? WHERE seq = 1",
		aged.Add(-time.Hour)).Error; err != nil {
		t.Fatalf("age genesis: %v", err)
	}

	trimmed, trim, err := f.purger.TrimChain(3650)
	if err != nil {
		t.Fatalf("TrimChain: %v", err)
	}
	// 只有 genesis（空區間）可修剪，到 live 就停
	if trimmed != 1 || trim.LastTrimmedSeq != 1 {
		t.Fatalf("應只修剪 genesis，實得 trimmed=%d last=%v", trimmed, trim)
	}
	if _, err := f.purger.LatestTrim(); err != nil {
		t.Fatalf("LatestTrim: %v", err)
	}
	var still int64
	f.db.Model(&model.AuditCheckpoint{}).Where("seq = ?", live.Seq).Count(&still)
	if still != 1 {
		t.Fatal("仍覆蓋現存列的檢查點不得被修剪")
	}
}

// TestCheckpointTrimNeverEmptiesChain 永不修剪到鏈為空（會使 audit_logs 清除整個停擺）
func TestCheckpointTrimNeverEmptiesChain(t *testing.T) {
	f := setupPurgeFixture(t)
	f.sealAt(t, 0, time.Now(), time.Now().Add(-4000*24*time.Hour))
	if err := f.db.Exec("UPDATE audit_checkpoints SET sealed_at = ? WHERE seq = 1",
		time.Now().Add(-4001*24*time.Hour)).Error; err != nil {
		t.Fatalf("age genesis: %v", err)
	}
	if _, _, err := f.purger.TrimChain(3650); err != nil {
		t.Fatalf("TrimChain: %v", err)
	}
	var n int64
	f.db.Model(&model.AuditCheckpoint{}).Count(&n)
	if n < 1 {
		t.Fatal("鏈不得被修剪成空")
	}
	if _, err := f.purger.GenesisIDFrom(); err != nil {
		t.Fatalf("修剪後 GenesisIDFrom 仍須可用: %v", err)
	}
}

// TestCheckpointTrimRecordIsImmutable 修剪記錄不得經 ORM 改刪（它是殘鏈的唯一錨）
func TestCheckpointTrimRecordIsImmutable(t *testing.T) {
	f := setupPurgeFixture(t)
	f.sealInterval(t, 1, time.Now())
	if err := f.db.Exec("UPDATE audit_checkpoints SET sealed_at = ? WHERE seq = 1",
		time.Now().Add(-4000*24*time.Hour)).Error; err != nil {
		t.Fatalf("age genesis: %v", err)
	}
	_, trim, err := f.purger.TrimChain(3650)
	if err != nil || trim == nil {
		t.Fatalf("TrimChain: %v", err)
	}
	if err := f.db.Delete(trim).Error; err == nil {
		t.Fatal("修剪記錄必須拒絕 ORM 刪除")
	}
	if err := f.db.Model(trim).Updates(map[string]any{"policy_days": 1}).Error; err == nil {
		t.Fatal("修剪記錄必須拒絕 ORM 更新")
	}
}

// ── 6.11-6.13 故障注入與自傷告警回歸守衛 ────────────────────────────────

// verifyInterval 以封章器的 Aggregate 做內容層驗證（與生產同一聚合實作）
func (f *purgeFixture) verifyInterval(t *testing.T, seq uint, policyDays int) string {
	t.Helper()
	cp := f.reload(t, seq)
	res, err := f.purger.VerifyIntervalContent(&cp, policyDays, f.verifyDeps())
	if err != nil {
		t.Fatalf("驗證 seq=%d: %v", seq, err)
	}
	return res.Status
}

// verifyDeps 內容層驗證的兩個依賴（聚合走生產實作；列級 HMAC 由本組的
// 測試夾具提供——本組的 audit_logs 測試列不經蓋章 hook，故以「HMAC 非空
// 即有效」的等價判定代替，多列情境的真偽判定由第 8 組的整合測試涵蓋）
func (f *purgeFixture) verifyDeps() IntervalVerifyDeps {
	return IntervalVerifyDeps{
		Aggregate: func(idFrom, idTo uint) (string, int64, error) {
			h, n, _, _, err := f.seal.Aggregate(idFrom, idTo)
			return h, n, err
		},
		RowHMAC: func(idFrom, idTo uint) (bool, []uint, error) {
			var bad []uint
			if err := f.db.Raw(
				"SELECT id FROM audit_logs WHERE id >= ? AND id <= ? AND (integrity_hmac IS NULL OR integrity_hmac = '')",
				idFrom, idTo).Scan(&bad).Error; err != nil {
				return false, nil, err
			}
			return len(bad) == 0, bad, nil
		},
	}
}

// failingSigner 簽章鑰暫時不可用（回傳 (0, "")）
type failingSigner struct {
	inner *testSigner
	fail  bool
	calls int
}

func (s *failingSigner) ActiveVersion() int { return s.inner.ActiveVersion() }
func (s *failingSigner) Sign(data []byte) (int, string) {
	s.calls++
	if s.fail {
		return 0, ""
	}
	return s.inner.Sign(data)
}
func (s *failingSigner) Verify(v int, data []byte, sig string) (bool, error) {
	return s.inner.Verify(v, data, sig)
}

// TestPurgeIntervalTombstoneFailure 故障注入 A：簽章失敗與 tombstone 寫入失敗。
//
// 兩者都必須使整個區間的刪除回滾，且後續驗證回報 passed 而非 purged_invalid
// ——系統 MUST NOT 因自身清除流程而製造假的竄改告警
func TestPurgeIntervalTombstoneFailure(t *testing.T) {
	cases := []struct {
		name  string
		setup func(f *purgeFixture) func() int // 回傳「注入器觸發次數」的取值器
	}{
		{
			name: "簽章失敗",
			setup: func(f *purgeFixture) func() int {
				fs := &failingSigner{inner: f.signer, fail: true}
				f.purger.signer = fs
				return func() int { return fs.calls }
			},
		},
		{
			name: "tombstone 寫入失敗",
			setup: func(f *purgeFixture) func() int {
				f.purger.faults.beforeTombstoneWrite = func() error { return errTestInjected }
				return func() int { return f.purger.faults.fired }
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := setupPurgeFixture(t)
			old := time.Now().Add(-400 * 24 * time.Hour)
			cp := f.sealInterval(t, 4, old)
			setPolicyDays(t, f.svc, policy.PolicyRetentionAuditLogDays, 365)
			fired := tc.setup(f)

			res := auditLogResult(t, f.svc.PurgeAll())
			if res.Deleted != 0 {
				t.Fatalf("注入故障下不得刪除任何列，實刪 %d", res.Deleted)
			}
			if res.Error == "" {
				t.Fatal("清除失敗必須進留痕（不得靜默）")
			}
			if fired() == 0 {
				t.Fatal("注入器觸發計數為 0：本測退化為零觸發假綠")
			}
			// 列仍在、無 tombstone
			if n := countRange(t, f.db, cp.IDFrom, cp.IDTo); n != 4 {
				t.Fatalf("交易必須整段回滾，殘 %d（want 4）", n)
			}
			if got := f.reload(t, cp.Seq); got.PurgedAt != nil {
				t.Fatalf("回滾後不得有 tombstone: %+v", got)
			}
			// 關鍵：驗證回報 passed，而非 purged_invalid
			if st := f.verifyInterval(t, cp.Seq, 365); st != IntervalStatusPassed {
				t.Fatalf("失敗的清除不得製造竄改告警，狀態 = %s（want %s）",
					st, IntervalStatusPassed)
			}
			assertNoHalfPurged(t, f, 365)
		})
	}
}

// TestPurgeIntervalInterrupted 故障注入 B：清除進行中行程中斷（panic）。
//
// 以交易內 panic 重現真實的行程中止：GORM 的 Transaction 會 rollback 後
// 重新 panic，故本測捕捉之並斷言 DB 側維持「列完整存在且無 tombstone」
func TestPurgeIntervalInterrupted(t *testing.T) {
	f := setupPurgeFixture(t)
	old := time.Now().Add(-400 * 24 * time.Hour)
	cutoff := time.Now().Add(-365 * 24 * time.Hour)
	cp := f.sealInterval(t, 5, old)

	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		f.purger.faults.afterDelete = func() error { panic("模擬清除窗口內的行程中止") }
		_, _ = f.purger.PurgeInterval(cp, 365, cutoff)
	}()
	f.purger.faults.afterDelete = nil
	if !panicked {
		t.Fatal("注入的中斷未實際發生：本測退化為零觸發假綠")
	}
	if f.purger.faults.fired == 0 {
		t.Fatal("注入器觸發計數為 0")
	}

	// 重啟後的狀態：列完整存在且無 tombstone（二選一的其中一態）
	if n := countRange(t, f.db, cp.IDFrom, cp.IDTo); n != 5 {
		t.Fatalf("中斷必回滾：應殘 5 列，實得 %d", n)
	}
	if got := f.reload(t, cp.Seq); got.PurgedAt != nil {
		t.Fatal("中斷不得留下 tombstone")
	}
	if st := f.verifyInterval(t, cp.Seq, 365); st != IntervalStatusPassed {
		t.Fatalf("中斷後狀態 = %s，want %s（不得產生假告警）", st, IntervalStatusPassed)
	}
	assertNoHalfPurged(t, f, 365)

	// 重啟後重試必須成功並取得合法 tombstone
	if _, err := f.purger.PurgeInterval(cp, 365, cutoff); err != nil {
		t.Fatalf("中斷後重試應成功: %v", err)
	}
	if st := f.verifyInterval(t, cp.Seq, 365); st != IntervalStatusPurgedLegal {
		t.Fatalf("重試後狀態 = %s，want %s", st, IntervalStatusPurgedLegal)
	}
}

// TestPurgeNeverSelfAlarms 自傷告警回歸守衛。
//
// 五種情形逐一造出，斷言**沒有任何一種**產生 purged_invalid。
// 這是常駐守衛：日後任何人把 tombstone 移出交易、或讓刪除先於簽章提交，
// 本測就會轉紅
func TestPurgeNeverSelfAlarms(t *testing.T) {
	cases := []struct {
		name   string
		want   string
		mutate func(t *testing.T, f *purgeFixture)
	}{
		{name: "成功清除", want: IntervalStatusPurgedLegal},
		{
			name: "簽章失敗", want: IntervalStatusPassed,
			mutate: func(t *testing.T, f *purgeFixture) {
				f.purger.signer = &failingSigner{inner: f.signer, fail: true}
			},
		},
		{
			name: "tombstone 寫入失敗", want: IntervalStatusPassed,
			mutate: func(t *testing.T, f *purgeFixture) {
				f.purger.faults.beforeTombstoneWrite = func() error { return errTestInjected }
			},
		},
		{
			name: "刪除後中途中斷", want: IntervalStatusPassed,
			mutate: func(t *testing.T, f *purgeFixture) {
				f.purger.faults.afterDelete = func() error { return errTestInjected }
			},
		},
		{name: "重複執行", want: IntervalStatusPurgedLegal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := setupPurgeFixture(t)
			old := time.Now().Add(-400 * 24 * time.Hour)
			cp := f.sealInterval(t, 3, old)
			setPolicyDays(t, f.svc, policy.PolicyRetentionAuditLogDays, 365)
			if tc.mutate != nil {
				tc.mutate(t, f)
			}
			f.svc.PurgeAll()
			if tc.name == "重複執行" {
				f.svc.PurgeAll()
				f.svc.PurgeAll()
			}
			st := f.verifyInterval(t, cp.Seq, 365)
			if st == IntervalStatusPurgedInvalid {
				t.Fatalf("合法清除流程在「%s」下產生了自傷竄改告警", tc.name)
			}
			if st != tc.want {
				t.Fatalf("「%s」狀態 = %s, want %s", tc.name, st, tc.want)
			}
			assertNoHalfPurged(t, f, 365)
		})
	}
}

// TestVerifyDetectsRealTampering 對照組：真正的竄改必須被判為告警。
//
// 沒有這組，上面五個「不得告警」的斷言可能只是因為驗證器根本什麼都驗不出來
func TestVerifyDetectsRealTampering(t *testing.T) {
	old := time.Now().Add(-400 * 24 * time.Hour)
	t.Run("抽走全部列而無 tombstone", func(t *testing.T) {
		f := setupPurgeFixture(t)
		cp := f.sealInterval(t, 3, old)
		if err := f.db.Exec("DELETE FROM audit_logs WHERE id >= ? AND id <= ?",
			cp.IDFrom, cp.IDTo).Error; err != nil {
			t.Fatalf("抽列: %v", err)
		}
		if st := f.verifyInterval(t, cp.Seq, 365); st != IntervalStatusPurgedInvalid {
			t.Fatalf("狀態 = %s, want %s", st, IntervalStatusPurgedInvalid)
		}
	})
	t.Run("抽走中段列", func(t *testing.T) {
		f := setupPurgeFixture(t)
		cp := f.sealInterval(t, 3, old)
		if err := f.db.Exec("DELETE FROM audit_logs WHERE id = ?", cp.IDFrom+1).Error; err != nil {
			t.Fatalf("抽列: %v", err)
		}
		if st := f.verifyInterval(t, cp.Seq, 365); st != IntervalStatusCountMismatch {
			t.Fatalf("狀態 = %s, want %s", st, IntervalStatusCountMismatch)
		}
	})
	t.Run("偽造 tombstone", func(t *testing.T) {
		f := setupPurgeFixture(t)
		cp := f.sealInterval(t, 3, old)
		if err := f.db.Exec("DELETE FROM audit_logs WHERE id >= ? AND id <= ?",
			cp.IDFrom, cp.IDTo).Error; err != nil {
			t.Fatalf("抽列: %v", err)
		}
		if err := f.db.Exec(`UPDATE audit_checkpoints SET purged_at = ?,
			purge_signature = ?, purge_signing_key_version = 1 WHERE seq = ?`,
			time.Now(), "ZmFrZQ==", cp.Seq).Error; err != nil {
			t.Fatalf("偽造: %v", err)
		}
		if st := f.verifyInterval(t, cp.Seq, 365); st != IntervalStatusPurgedInvalid {
			t.Fatalf("狀態 = %s, want %s", st, IntervalStatusPurgedInvalid)
		}
	})
	t.Run("改列內容", func(t *testing.T) {
		f := setupPurgeFixture(t)
		cp := f.sealInterval(t, 3, old)
		if err := f.db.Exec("UPDATE audit_logs SET integrity_hmac = ? WHERE id = ?",
			"beefbeef", cp.IDFrom).Error; err != nil {
			t.Fatalf("改列: %v", err)
		}
		if st := f.verifyInterval(t, cp.Seq, 365); st != IntervalStatusHashMismatch {
			t.Fatalf("狀態 = %s, want %s", st, IntervalStatusHashMismatch)
		}
	})
}
