package audit

import (
	"context"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/notifycat"
)

// 兩層自動驗證的行為釘子。
//
// 本組最重要的一項是 TestChainVerifyFalseResolveGuard：沒有那條修法，本機制會
// **自動把真實的竄改事件結案**——比不做告警更糟，不做告警只是沒人知道，
// 錯誤結案是系統主動宣告「已恢復」。

// ── 測試替身 ──────────────────────────────────────────────────────────────

// stubChainTuning 三顆旋鈕的可控來源（政策鍵的實作由後續批次落地）
type stubChainTuning struct {
	days     int
	interval time.Duration
	rows     int64
}

func (s *stubChainTuning) RecentWindowDays() int       { return s.days }
func (s *stubChainTuning) FullInterval() time.Duration { return s.interval }
func (s *stubChainTuning) RowsPerHour() int64          { return s.rows }

// stubChainPolicy 政策讀取（只用到審計保留天數的 clamp）
type stubChainPolicy struct{ vals map[string]int }

func (s *stubChainPolicy) GetInt(key string) int { return s.vals[key] }

// stubChainSigner 簽章服務自檢探針；ready=false 模擬 keyvault 整體不可用
type stubChainSigner struct{ ready bool }

func (s *stubChainSigner) ActiveVersion() int {
	if s.ready {
		return 1
	}
	return 0
}

func (s *stubChainSigner) ActivePublicKeyBase64() string {
	if s.ready {
		return "cHVibGljLWtleQ=="
	}
	return ""
}

// chainAlertCall 一次告警動作的觀測記錄
type chainAlertCall struct {
	kind      string // report／resolve／ongoing
	mechanism string
	cause     string
	counts    map[string]int
	params    map[string]string
}

type fakeChainAlerter struct{ calls []chainAlertCall }

func (f *fakeChainAlerter) ReportWithCounts(mechanism, causeCode string,
	params map[string]string, counts map[string]int) {
	f.calls = append(f.calls, chainAlertCall{kind: "report", mechanism: mechanism,
		cause: causeCode, counts: counts, params: params})
}

func (f *fakeChainAlerter) Resolve(mechanism string) {
	f.calls = append(f.calls, chainAlertCall{kind: "resolve", mechanism: mechanism})
}

func (f *fakeChainAlerter) NotifyOngoing(event notifycat.Event, params map[string]string) {
	f.calls = append(f.calls, chainAlertCall{kind: "ongoing",
		mechanism: params["mechanism"], cause: params["cause_code"], params: params})
}

func (f *fakeChainAlerter) reset() { f.calls = nil }

func (f *fakeChainAlerter) has(kind, mechanism string) bool {
	for _, c := range f.calls {
		if c.kind == kind && c.mechanism == mechanism {
			return true
		}
	}
	return false
}

// ── 夾具 ──────────────────────────────────────────────────────────────────

type chainVerifyFixture struct {
	*verifyFixture
	svc    *ChainVerifyService
	alerts *fakeChainAlerter
	tuning *stubChainTuning
	pol    *stubChainPolicy
	now    time.Time
}

func setupChainVerifyFixture(t *testing.T) *chainVerifyFixture {
	t.Helper()
	base := setupVerifyFixture(t)
	if err := base.db.AutoMigrate(&model.AuditChainVerifyState{}); err != nil {
		t.Fatalf("migrate state: %v", err)
	}
	alerts := &fakeChainAlerter{}
	// 出廠形態：窗口 7 天、間隔 1 小時、速率 100 萬列/小時
	tuning := &stubChainTuning{days: 7, interval: time.Hour, rows: 1000000}
	pol := &stubChainPolicy{vals: map[string]int{}}
	f := &chainVerifyFixture{verifyFixture: base, alerts: alerts, tuning: tuning, pol: pol,
		now: time.Now()}
	f.svc = NewChainVerifyService(base.db, base.verifier, base.seal,
		&stubChainSigner{ready: true}, pol, tuning, alerts)
	f.svc.SetClock(func() time.Time { return f.now })
	return f
}

// sealIntervals 依序封出 n 個各含 rows 列的區間，回傳其 seq
func (f *chainVerifyFixture) sealIntervals(t *testing.T, n, rows int) []uint {
	t.Helper()
	out := make([]uint, 0, n)
	for i := 0; i < n; i++ {
		f.stampedRows(t, rows, f.now)
		cp, err := f.seal.SealNow()
		if err != nil {
			t.Fatalf("seal #%d: %v", i, err)
		}
		out = append(out, cp.Seq)
	}
	return out
}

// state 現況狀態列
func (f *chainVerifyFixture) state(t *testing.T) *model.AuditChainVerifyState {
	t.Helper()
	st, err := f.svc.LoadState()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	return st
}

// rowIn 取指定區間內的第 offset 列（供可逆的抽列／還原）
func (f *chainVerifyFixture) rowIn(t *testing.T, seq uint, offset int) model.AuditLog {
	t.Helper()
	var cp model.AuditCheckpoint
	if err := f.db.Where("seq = ?", seq).First(&cp).Error; err != nil {
		t.Fatalf("checkpoint seq=%d: %v", seq, err)
	}
	var rows []model.AuditLog
	if err := f.db.Unscoped().Where("id >= ? AND id <= ?", cp.IDFrom, cp.IDTo).
		Order("id ASC").Find(&rows).Error; err != nil {
		t.Fatalf("rows of seq=%d: %v", seq, err)
	}
	if offset >= len(rows) {
		t.Fatalf("seq=%d 只有 %d 列，取不到 offset=%d", seq, len(rows), offset)
	}
	return rows[offset]
}

// ── 假恢復（驗收必查項）────────────────────────────────────────────────────

// TestChainVerifyFalseResolveGuard 假恢復守衛。
//
// **造的情境**：第 N 輪令區間 X 驗出 count_mismatch 並開立事件；第 N+1 輪的
// 滾動窗驗的是**別的區間且全數通過**。斷言事件未被結案、未發出恢復通知、
// 且 X 於該輪**確實有被重驗**（必驗集合生效）。
//
// **為什麼這條非有不可**：滾動窗每輪驗的是不同窗口。若以「本輪驗過的區間全數
// 通過」為結案條件，被刪列的區間 X 會在下一輪被誤判為已恢復——而 X 的列早已
// 被刪、根本沒被重驗。被刪的列不會自己回來，該事件本應保持開啟。錯誤結案的
// 後果不只是漏報：恢復通知會使收件人認為問題已解決，且該異常要到下一個完整
// 繞行週期才會被重新開立，屆時記錄的開始時間已非首次發現時間。
//
// **第 3 輪是「X 真的有被重驗」的證據**：X 只在必驗集合裡（滾動窗此時已在別處），
// 它的狀態能由紅轉綠，只可能是因為它每輪都被重驗。
func TestChainVerifyFalseResolveGuard(t *testing.T) {
	f := setupChainVerifyFixture(t)
	seqs := f.sealIntervals(t, 4, 3) // genesis 之後的四個區間
	x := seqs[0]                     // 受害區間：滾動窗第一輪會驗到它

	// 每輪預算 8 列（速率 10000 列/小時 × 3 秒）：扣掉必驗集合後只剩個位數，
	// 滾動窗每輪只推得動一兩個區間——這正是「本輪驗的是別的窗口」的前提
	f.tuning.rows = 10000
	f.tuning.interval = 3 * time.Second
	if budget := f.svc.rowBudget(); budget != 8 {
		t.Fatalf("測試前提失效：每輪預算 = %d, want 8", budget)
	}

	// 游標對準 X
	st := f.state(t)
	st.ContentCursorSeq = x
	if err := f.svc.saveState(st); err != nil {
		t.Fatalf("save cursor: %v", err)
	}

	// ── 第 N 輪：抽掉 X 的中段列 ──
	victim := f.rowIn(t, x, 1)
	f.mustExec(t, "DELETE FROM audit_logs WHERE id = ?", victim.ID)
	f.alerts.reset()
	if err := f.svc.RunFullNow(context.Background()); err != nil {
		t.Fatalf("第 N 輪: %v", err)
	}
	if !f.alerts.has("report", model.MechanismAuditChainContent) {
		t.Fatalf("第 N 輪應以內容層機制開立失效事件，實得 %+v", f.alerts.calls)
	}
	st = f.state(t)
	open := decodeSeqSet(st.OpenFailedSeqs)
	if _, ok := open[x]; !ok {
		t.Fatalf("第 N 輪後失敗區間集合應含 seq=%d，實得 %v", x, open)
	}
	if st.ContentCursorSeq == x {
		t.Fatalf("游標應已推離 X（現為 %d）——否則第 N+1 輪的滾動窗仍會驗到 X，測不出假恢復",
			st.ContentCursorSeq)
	}

	// ── 第 N+1 輪：滾動窗驗別的區間且全數通過 ──
	f.alerts.reset()
	if err := f.svc.RunFullNow(context.Background()); err != nil {
		t.Fatalf("第 N+1 輪: %v", err)
	}
	if f.alerts.has("resolve", model.MechanismAuditChainContent) {
		t.Fatalf("假恢復：X 尚未重驗轉綠，內容層事件不得結案、不得發恢復通知。實得 %+v",
			f.alerts.calls)
	}
	st = f.state(t)
	open = decodeSeqSet(st.OpenFailedSeqs)
	if _, ok := open[x]; !ok {
		t.Fatalf("第 N+1 輪後 seq=%d 仍未轉綠，應留在失敗區間集合，實得 %v", x, open)
	}
	// X（必驗集合）＋鏈尾（必驗）＋滾動窗一個區間＝三個區間被驗過。
	// 少於 3 即代表必驗集合沒生效
	if st.ContentVerifiedIntervals < 3 {
		t.Fatalf("第 N+1 輪只驗了 %d 個區間：必驗集合（鏈尾＋失敗區間）未生效",
			st.ContentVerifiedIntervals)
	}

	// ── 第 N+2 輪：把 X 的列原樣放回，X 應被重驗為通過並結案 ──
	restore := victim
	if err := f.db.Create(&restore).Error; err != nil {
		t.Fatalf("還原被抽的列: %v", err)
	}
	f.alerts.reset()
	if err := f.svc.RunFullNow(context.Background()); err != nil {
		t.Fatalf("第 N+2 輪: %v", err)
	}
	st = f.state(t)
	if open := decodeSeqSet(st.OpenFailedSeqs); len(open) != 0 {
		t.Fatalf("X 已轉綠，失敗區間集合應清空，實得 %v", open)
	}
	if !f.alerts.has("resolve", model.MechanismAuditChainContent) {
		t.Fatalf("失敗區間集合清空後應結案並發恢復通知，實得 %+v", f.alerts.calls)
	}
}

// TestChainVerifyNoResolveWhileUnverifiedMemberRemains 假恢復守衛之二：
// 失敗區間**整段被移除**（本輪無從重驗）時，即使本輪驗過的區間全數通過，
// 事件仍不得結案。
//
// **這條與上一條分工明確**：上一條釘的是「必驗集合要真的每輪重驗」，本條釘的是
// 「結案條件是集合清空、不是本輪全過」。兩者缺一，假恢復就會從另一邊漏出去——
// 若以「本輪全數通過」結案，刪掉整個區間反而成了讓告警消失的最快路徑
func TestChainVerifyNoResolveWhileUnverifiedMemberRemains(t *testing.T) {
	f := setupChainVerifyFixture(t)
	f.sealIntervals(t, 3, 3)

	// 集合中留一個現存鏈上已不存在的區間（整段被移除的痕跡）
	ghost := uint(9999)
	st := f.state(t)
	st.OpenFailedSeqs = encodeSeqSet(map[uint]string{ghost: IntervalStatusCountMismatch})
	if err := f.svc.saveState(st); err != nil {
		t.Fatalf("save: %v", err)
	}

	f.alerts.reset()
	if err := f.svc.RunFullNow(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	// 本輪驗過的區間全數通過——但集合未清空
	if f.alerts.has("resolve", model.MechanismAuditChainContent) {
		t.Fatalf("假恢復：本輪全數通過不構成結案條件，未重驗轉綠的失敗區間仍在集合中。實得 %+v",
			f.alerts.calls)
	}
	if !f.alerts.has("report", model.MechanismAuditChainContent) {
		t.Fatalf("集合非空即為異常狀態，應持續以內容層機制上報，實得 %+v", f.alerts.calls)
	}
	if open := decodeSeqSet(f.state(t).OpenFailedSeqs); len(open) != 1 {
		t.Fatalf("整段被移除的失敗區間不得因「已不存在」而被移出集合，實得 %v", open)
	}
}

// TestChainVerifyOpenSetKeepsUnverifiedMembers 未被驗到的成員一律留在集合。
//
// 涵蓋「整個區間其後被移除」的情形：SHALL NOT 以「區間已不存在」為由逕行移出
// ——否則即開出「刪除整個區間即可使告警消失」的路徑
func TestChainVerifyOpenSetKeepsUnverifiedMembers(t *testing.T) {
	f := setupChainVerifyFixture(t)
	st := &model.AuditChainVerifyState{
		OpenFailedSeqs: encodeSeqSet(map[uint]string{
			7: IntervalStatusCountMismatch, // 本輪未驗到（區間已不存在）
			8: IntervalStatusHashMismatch,  // 本輪重驗仍失敗
			9: IntervalStatusCountMismatch, // 本輪重驗轉綠
		}),
	}
	open := f.svc.mergeOpenFailed(st, map[uint]string{
		8: IntervalStatusHashMismatch,
		9: IntervalStatusPassed,
		// 結構層狀態不新增為內容層成員，但也不使既有成員被移出
		10: IntervalStatusSignatureInvalid,
	})
	if _, ok := open[7]; !ok {
		t.Error("未被重驗的成員被移出集合＝「刪掉整個區間即可讓告警消失」的路徑")
	}
	if _, ok := open[8]; !ok {
		t.Error("重驗仍失敗的成員應留在集合")
	}
	if _, ok := open[9]; ok {
		t.Error("重驗轉綠的成員應移出集合")
	}
	if _, ok := open[10]; ok {
		t.Error("結構層狀態不得計入內容層失敗區間集合（機制碼按攻擊面分）")
	}
}

// TestChainVerifyPurgedLegalLeavesSet 合法清除且清除簽章驗過者移出集合；
// 驗不過者留下
func TestChainVerifyPurgedLegalLeavesSet(t *testing.T) {
	f := setupChainVerifyFixture(t)
	st := &model.AuditChainVerifyState{
		OpenFailedSeqs: encodeSeqSet(map[uint]string{
			3: IntervalStatusCountMismatch,
			4: IntervalStatusCountMismatch,
		}),
	}
	open := f.svc.mergeOpenFailed(st, map[uint]string{
		3: IntervalStatusPurgedLegal,
		4: IntervalStatusPurgedInvalid,
	})
	if _, ok := open[3]; ok {
		t.Error("purged_legal＝依政策合法清除且清除簽章驗過，非異常，應移出")
	}
	if _, ok := open[4]; !ok {
		t.Error("purged_invalid＝清除簽章驗不過，應留在集合")
	}
}

// ── 只跑結構層是不夠的 ───────────────────────────────────────────────────

// TestChainVerifyContentCatchesRowDeletionWhileStructurePasses 反向對照：
// 已封區間被抽列時，**結構層全鏈仍回 passed**（檢查點一個字都沒動），
// 只有內容層看得見。這是「兩層都必須跑內容層」的實證
func TestChainVerifyContentCatchesRowDeletionWhileStructurePasses(t *testing.T) {
	f := setupChainVerifyFixture(t)
	seqs := f.sealIntervals(t, 2, 3)
	victim := f.rowIn(t, seqs[1], 1)
	f.mustExec(t, "DELETE FROM audit_logs WHERE id = ?", victim.ID)

	report, err := f.verifier.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if report.Status != IntervalStatusPassed {
		t.Fatalf("結構層應仍通過（檢查點未被動），實得 %s", report.Status)
	}

	f.alerts.reset()
	if err := f.svc.RunRecentNow(context.Background()); err != nil {
		t.Fatalf("近期層: %v", err)
	}
	if f.alerts.has("report", model.MechanismAuditChainStructure) {
		t.Error("結構層無異常時不得以結構層機制上報")
	}
	if !f.alerts.has("report", model.MechanismAuditChainContent) {
		t.Fatalf("內容層應驗出抽列並告警，實得 %+v", f.alerts.calls)
	}
	st := f.state(t)
	if st.RecentLastStatus != ChainVerifyStatusFailed {
		t.Errorf("近期層狀態 = %s, want %s", st.RecentLastStatus, ChainVerifyStatusFailed)
	}
	if st.RecentLastRunAt == nil {
		t.Error("近期層須記錄最近執行時點——它是唯一能看出「機制沒在跑」的訊號")
	}
}

// ── 依賴自檢 ──────────────────────────────────────────────────────────────

// TestChainVerifySelfCheckSkipsBothLayers 簽章服務不可用時：上報「驗證本身
// 失敗」，且**不產出任何竄改結論**。
//
// 沒有這一步，keyvault 降級會讓全鏈每一點都判 signature_invalid，
// 排程就會發出「整條鏈被竄改」的最高嚴重度告警而真因是環境問題
func TestChainVerifySelfCheckSkipsBothLayers(t *testing.T) {
	f := setupChainVerifyFixture(t)
	f.sealIntervals(t, 2, 3)
	f.svc.signing = &stubChainSigner{ready: false}

	f.alerts.reset()
	if err := f.svc.Tick(context.Background()); err == nil {
		t.Fatal("自檢不過時 Tick 應回錯（本輪兩層皆跳過）")
	}
	if !f.alerts.has("report", model.MechanismAuditChainVerify) {
		t.Fatalf("應以「驗證本身失敗」機制上報，實得 %+v", f.alerts.calls)
	}
	for _, m := range []string{model.MechanismAuditChainStructure, model.MechanismAuditChainContent} {
		if f.alerts.has("report", m) {
			t.Errorf("自檢不過時不得產出竄改結論（機制 %s）", m)
		}
	}
	st := f.state(t)
	if st.RecentLastRunAt != nil || st.FullLastRunAt != nil {
		t.Error("自檢不過時兩層皆不執行，最近執行時點不得被更新（否則畫面上看起來像驗過了）")
	}
}

// TestChainVerifyStateLoadFailureReportsVerifyMechanism 狀態載入失敗（資料庫
// 不可讀）時：以「驗證本身失敗」機制上報，且**不**以任何竄改機制上報。
//
// **為什麼這條非有不可**：規格把「資料庫不可讀」明列為 audit_chain_verify_failed
// 的成因，但 Tick 的第一件事就是載入狀態列——該早退若不上報，這個成因在真實
// 裝配上永遠不會出聲（不開事件、不發通知，只剩一行本地 log），偵測控制就在
// 最需要出聲的時候是啞的。這不是走不到的邊界：資料庫不可讀是維運故障，
// 每一個排程 tick 都會踩到。
//
// **機制碼必須是 audit_chain_verify**：驗證跑不完＝機制狀態未知（維運事件），
// 與「鏈被竄改」（安全事件）處置完全不同。報成 structure／content 等於對稽核
// 發出「整條鏈被竄改」的假警報。
func TestChainVerifyStateLoadFailureReportsVerifyMechanism(t *testing.T) {
	assert := func(t *testing.T, f *chainVerifyFixture) {
		t.Helper()
		if err := f.svc.Tick(context.Background()); err == nil {
			t.Fatal("狀態載入失敗時 Tick 應回錯")
		}
		reports := 0
		for _, c := range f.alerts.calls {
			if c.kind != "report" {
				continue
			}
			reports++
			if c.mechanism != model.MechanismAuditChainVerify {
				t.Errorf("驗證本身失敗不得報成竄改機制：實得 %s", c.mechanism)
			}
			if c.cause != model.CauseAuditChainVerifyFailed {
				t.Errorf("cause = %s, want %s", c.cause, model.CauseAuditChainVerifyFailed)
			}
		}
		if reports != 1 {
			// 恰好一次：既不得靜默（0），也不得在同一輪內重試上報（>1）——
			// 持續故障期間的去重由 AuditFailureService 的 in-memory 旗標承擔
			t.Fatalf("應恰好上報一次「驗證本身失敗」，實得 %d 次：%+v", reports, f.alerts.calls)
		}
	}

	// (a) 狀態表不可讀（表級破損）
	t.Run("狀態表不可讀", func(t *testing.T) {
		f := setupChainVerifyFixture(t)
		f.sealIntervals(t, 2, 3)
		f.mustExec(t, "DROP TABLE audit_chain_verify_states")
		f.alerts.reset()
		assert(t, f)
	})

	// (b) 資料庫整體不可讀——規格字面上的那個成因
	t.Run("資料庫整體不可讀", func(t *testing.T) {
		f := setupChainVerifyFixture(t)
		f.sealIntervals(t, 2, 3)
		sqlDB, err := f.db.DB()
		if err != nil {
			t.Fatalf("db handle: %v", err)
		}
		if err := sqlDB.Close(); err != nil {
			t.Fatalf("close db: %v", err)
		}
		f.alerts.reset()
		assert(t, f)
	})
}

// ── 滾動窗與列預算 ───────────────────────────────────────────────────────

// TestChainVerifyBudgetScalesWithInterval 每輪列預算＝速率 × 間隔。
//
// **釘住「延長間隔不延長繞行週期」**：若預算改成每輪固定列數，把間隔調到上界
// 7 天就會把繞行週期拉長 168 倍，而管理員從介面上只看見「驗得稀疏一點」
func TestChainVerifyBudgetScalesWithInterval(t *testing.T) {
	f := setupChainVerifyFixture(t)
	f.tuning.rows = 1000000

	f.tuning.interval = time.Hour
	base := f.svc.rowBudget()
	if base != 1000000 {
		t.Fatalf("出廠速率、間隔 1 小時的每輪預算 = %d, want 1000000", base)
	}
	f.tuning.interval = 2 * time.Hour
	if got := f.svc.rowBudget(); got != 2*base {
		t.Fatalf("間隔加倍時每輪預算應等比加倍：%d, want %d", got, 2*base)
	}
	f.tuning.interval = 7 * 24 * time.Hour
	if got, want := f.svc.rowBudget(), int64(1000000*7*24); got != want {
		t.Fatalf("間隔調到上界時每輪預算 = %d, want %d（繞行週期因此不變）", got, want)
	}

	// 下界 clamp：速率設到形同關閉時以下界執行（介面上仍開著、實際只推進數列
	// 的靜默關閉路徑）
	f.tuning.interval = time.Hour
	f.tuning.rows = 1
	if got := f.svc.rowBudget(); got != chainVerifyRowsPerHourMin {
		t.Fatalf("速率低於下界時應以下界執行：%d, want %d", got, chainVerifyRowsPerHourMin)
	}
}

// TestChainVerifyRollingCursorAdvancesAndWraps 游標推進、回捲並記一次繞行完成；
// 單一超預算區間仍整段驗完
func TestChainVerifyRollingCursorAdvancesAndWraps(t *testing.T) {
	f := setupChainVerifyFixture(t)
	seqs := f.sealIntervals(t, 3, 3)
	// 每輪預算 5 列：扣掉必驗的鏈尾（3 列）只剩 2 列，**小於單一區間的 3 列**
	// ——區間不可分，故仍整段驗完後才停
	f.tuning.rows = 10000
	f.tuning.interval = 2 * time.Second
	if budget := f.svc.rowBudget(); budget != 5 {
		t.Fatalf("測試前提失效：每輪預算 = %d, want 5", budget)
	}

	st := f.state(t)
	st.ContentCursorSeq = seqs[0]
	if err := f.svc.saveState(st); err != nil {
		t.Fatalf("save cursor: %v", err)
	}

	var cycles int
	for i := 0; i < 6; i++ {
		if err := f.svc.RunFullNow(context.Background()); err != nil {
			t.Fatalf("第 %d 輪: %v", i, err)
		}
		if f.state(t).LastFullCycleAt != nil {
			cycles++
			break
		}
	}
	if cycles == 0 {
		t.Fatal("滾動窗未在有限輪次內推到鏈尾並回捲——全歷史將永遠繞不完")
	}
	st = f.state(t)
	if st.ContentCursorSeq == 0 {
		t.Error("回捲後游標應落在鏈頭而非 0")
	}
}

// TestChainVerifyOpenSetOverBudgetHoldsCursor 失敗區間集合的預估列數超出本輪
// 預算時：只驗集合、不推進游標。SHALL NOT 為控制成本而丟棄集合成員
func TestChainVerifyOpenSetOverBudgetHoldsCursor(t *testing.T) {
	f := setupChainVerifyFixture(t)
	seqs := f.sealIntervals(t, 4, 3)
	f.tuning.rows = 10000
	f.tuning.interval = time.Second // 每輪預算 2 列，遠小於必驗集合

	st := f.state(t)
	st.ContentCursorSeq = seqs[1]
	st.OpenFailedSeqs = encodeSeqSet(map[uint]string{
		seqs[0]: IntervalStatusCountMismatch,
	})
	if err := f.svc.saveState(st); err != nil {
		t.Fatalf("save: %v", err)
	}
	before := st.ContentCursorSeq

	if err := f.svc.RunFullNow(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	st = f.state(t)
	if st.ContentCursorSeq != before {
		t.Errorf("必驗集合已吃滿預算時不得推進游標：%d → %d", before, st.ContentCursorSeq)
	}
	if st.ContentVerifiedIntervals == 0 {
		t.Error("必驗集合不受列預算限制，本輪仍須驗完集合與鏈尾")
	}
}

// ── 近期層 ────────────────────────────────────────────────────────────────

// TestChainVerifyRecentWindowClampedByRetention 近期窗口被審計保留天數 clamp，
// 且**生效值**寫入狀態（承諾驗保留期以外的範圍是空頭支票）
func TestChainVerifyRecentWindowClampedByRetention(t *testing.T) {
	f := setupChainVerifyFixture(t)
	f.sealIntervals(t, 1, 3)
	f.tuning.days = 30
	f.pol.vals[policy.PolicyRetentionAuditLogDays] = 7

	if err := f.svc.RunRecentNow(context.Background()); err != nil {
		t.Fatalf("近期層: %v", err)
	}
	if got := f.state(t).RecentWindowDaysEffective; got != 7 {
		t.Fatalf("生效窗口 = %d 天, want 7（設定值 30 應被保留天數 clamp）", got)
	}

	// 保留天數 0＝永久：不 clamp
	f.pol.vals[policy.PolicyRetentionAuditLogDays] = 0
	if err := f.svc.RunRecentNow(context.Background()); err != nil {
		t.Fatalf("近期層（永久保留）: %v", err)
	}
	if got := f.state(t).RecentWindowDaysEffective; got != 30 {
		t.Fatalf("保留天數 0＝永久時不應 clamp，生效窗口 = %d, want 30", got)
	}
}

// TestChainVerifyRecentThrottledToOneSealInterval 近期層節流為至多每封存週期
// 一次。未節流時負載對寫入量呈二次成長（10 倍寫入量＝10 倍觸發頻率 ×
// 10 倍窗內列數＝100 倍成本）
func TestChainVerifyRecentThrottledToOneSealInterval(t *testing.T) {
	f := setupChainVerifyFixture(t)
	f.sealIntervals(t, 1, 3)

	st := f.state(t)
	if recent, _, _ := f.svc.due(st, f.now); !recent {
		t.Fatal("有新封章且從未跑過近期層時應到期")
	}

	// 剛跑過近期層，且又有新封章
	ran := f.now
	st.RecentLastRunAt = &ran
	st.RecentLastSeq = 0
	if recent, _, _ := f.svc.due(st, f.now.Add(time.Minute)); recent {
		t.Error("距上次近期層未滿一個封存週期即再次執行＝節流失效")
	}
	if recent, _, _ := f.svc.due(st, f.now.Add(f.seal.Interval())); !recent {
		t.Error("滿一個封存週期且有新封章時應再次執行")
	}

	// 沒有新封章就不跑（觀測式觸發）
	st.RecentLastSeq = 999
	if recent, _, _ := f.svc.due(st, f.now.Add(24*time.Hour)); recent {
		t.Error("最新已封 seq 未前進時近期層不應觸發")
	}
}

// ── 唯讀不變式與邊界 ──────────────────────────────────────────────────────

// TestChainVerifyNeverWritesAuditLogs 驗證不製造待封列。
//
// 若驗證寫審計，每次驗證都會產生新的未封列並成為下一次驗證的對象，
// 形成自我餵養——鏈的內容會被「鏈在驗證自己」的紀錄逐漸稀釋
func TestChainVerifyNeverWritesAuditLogs(t *testing.T) {
	f := setupChainVerifyFixture(t)
	f.sealIntervals(t, 2, 3)
	var before int64
	if err := f.db.Unscoped().Model(&model.AuditLog{}).Count(&before).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := f.svc.RunRecentNow(context.Background()); err != nil {
			t.Fatalf("近期層 #%d: %v", i, err)
		}
		if err := f.svc.RunFullNow(context.Background()); err != nil {
			t.Fatalf("全鏈層 #%d: %v", i, err)
		}
	}
	var after int64
	if err := f.db.Unscoped().Model(&model.AuditLog{}).Count(&after).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if after != before {
		t.Fatalf("驗證不得寫入 audit_logs：%d → %d", before, after)
	}
	// 檢查點欄位亦不得被驗證改動（唯讀）
	var cp model.AuditCheckpoint
	if err := f.db.Order("seq DESC").First(&cp).Error; err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if cp.PurgedAt != nil {
		t.Error("驗證不得修補任何檢查點欄位")
	}
}

// TestChainVerifyEmptyChainDoesNotPanic 鏈為空是驗證要回報的結論，不是啟動失敗，
// 更不該讓編排崩掉
func TestChainVerifyEmptyChainDoesNotPanic(t *testing.T) {
	f := setupChainVerifyFixture(t)
	// 繞過不可變守衛清空鏈（模擬整鏈被抹除）
	f.mustExec(t, "DELETE FROM audit_checkpoints")

	f.alerts.reset()
	if err := f.svc.RunFullNow(context.Background()); err != nil {
		t.Fatalf("空鏈不應回錯: %v", err)
	}
	if !f.alerts.has("report", model.MechanismAuditChainStructure) {
		t.Fatalf("空鏈＝機制未啟用或整鏈被抹除，應以結構層機制上報，實得 %+v", f.alerts.calls)
	}
}

// TestChainVerifyFingerprintFromOpenSetOnly 指紋只由跨輪累積的失敗集合計算。
//
// 若改由「本輪驗過的區間結果」計算，兩層交替執行時指紋會逐輪抖動 →
// 每輪觸發重發 → 收件端靜音整個通道
func TestChainVerifyFingerprintFromOpenSetOnly(t *testing.T) {
	a := chainVerifyFingerprint(0, map[uint]string{3: IntervalStatusCountMismatch})
	b := chainVerifyFingerprint(0, map[uint]string{3: IntervalStatusCountMismatch})
	if a != b {
		t.Fatal("同一組失敗集合的指紋必須穩定，否則每輪都會觸發重發通知")
	}
	c := chainVerifyFingerprint(0, map[uint]string{
		3: IntervalStatusCountMismatch, 5: IntervalStatusHashMismatch})
	if a == c {
		t.Fatal("失敗集合擴大時指紋必須改變，否則範圍變化不會再次出聲")
	}
	if chainVerifyFingerprint(0, nil) != "" {
		t.Fatal("無異常時指紋應為空——空指紋是「上一輪無異常」的判準")
	}
	if chainVerifyFingerprint(2, nil) == "" {
		t.Fatal("結構層失敗點數不為 0 時仍屬異常，指紋不得為空")
	}
}
