package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/notifycat"
	"gorm.io/gorm"
)

// 檢查點鏈的兩層自動驗證編排（audit-chain-scheduled-verification D2／D9）。
//
// **為什麼要有這一支**：鏈的驗證原本只有人拉的入口（驗證頁的按鈕）。有人以
// 資料庫直寫刪掉某已封區間的中段列時，鏈**確實留下了證據**（該區間 agg_hash
// 重算不符），但系統不會通知任何人——證據存在卻無人被告知，等同把偵測控制
// 降級成事後鑑識工具。本服務讓驗證變成有節奏、會出聲的常設控制。
//
// **兩層，缺一不可**：
//   - 近期層（layer=recent）：觀測到新封章即驗「封章時間落在最近 N 天」的已封
//     區間。買的是**低延遲**——發現時延壓到一個封存週期（上界 24 小時）。
//     其不可關閉性繼承自封存本身（封存門檻不開 ZeroDisables 且有上界）。
//   - 全鏈層（layer=full）：依政策週期跑結構層全鏈＋內容層滾動窗。買的是
//     **無盲區**——全歷史終將被重驗。
//
// **兩層都必須跑內容層**：結構層不讀 audit_logs，故「已封區間內的列被資料庫
// 直寫刪除」對它完全不可見（檢查點一個字都沒動，全鏈驗證 100% 通過），
// 而那正是本機制的招牌威脅。只跑結構層等於對招牌威脅無感而仍對外宣稱在驗證。
//
// **唯讀**：本服務不寫入、不修補、不重算任何檢查點欄位，亦不因驗證而寫入任何
// audit_logs 列——若寫入，每次驗證都會製造新的未封列並成為下一次驗證的對象，
// 形成自我餵養。唯一的寫入面是單列狀態表 audit_chain_verify_states。

// 驗證層別（只落 cause_params 與狀態表，不出站）
const (
	// ChainVerifyLayerRecent 近期層：封存完成觸發，範圍為最近 N 天的已封區間
	ChainVerifyLayerRecent = "recent"
	// ChainVerifyLayerFull 全鏈層：排程週期觸發，結構層全鏈＋內容層滾動窗
	ChainVerifyLayerFull = "full"
)

// 單層執行結果（寫入狀態表的 *_last_status）
const (
	// ChainVerifyStatusPassed 本層本輪驗過的範圍全數通過
	ChainVerifyStatusPassed = "passed"
	// ChainVerifyStatusFailed 本層本輪驗出異常（結構層或內容層）
	ChainVerifyStatusFailed = "failed"
	// ChainVerifyStatusError 本層本輪無法完成（讀取失敗）——狀態為未知，非「無異常」
	ChainVerifyStatusError = "error"
)

// 消費端的防禦性邊界（政策層另有 Min／Max 驗證；此處防「資料層直改」把值
// 打到失效區）。**下界的意義是「低於此值該機制即失去意義」**：
// 掃描速率若可為極小值，即開出「介面上仍開著、實際上每輪只推進數列」的
// 靜默關閉路徑。
const (
	chainVerifyRecentDaysDefault = 7
	chainVerifyRecentDaysMax     = 30
	chainVerifyIntervalDefault   = time.Hour
	chainVerifyIntervalMax       = 7 * 24 * time.Hour

	chainVerifyRowsPerHourDefault int64 = 1000000
	chainVerifyRowsPerHourMin     int64 = 10000
	chainVerifyRowsPerHourMax     int64 = 5000000
)

// ErrChainVerifyDependency 依賴自檢不通過：本輪**兩層**都跳過，不產出任何竄改結論。
//
// 理由：spec 明文「版本對應之鑰不存在 SHALL 計為 signature_invalid」。簽章服務
// 整體不可用時全鏈每一點都會回 signature_invalid，未經自檢即會發出「整條鏈被
// 竄改」的最高嚴重度告警而真因是環境問題，使真實竄改淹沒於環境噪音
var ErrChainVerifyDependency = errors.New("鏈驗證依賴自檢不通過：本輪跳過，狀態為未知")

// ChainVerifyTuning 兩層的執行期旋鈕（實作為安全政策頁的三個鍵）。
//
// 以介面而非直接讀政策鍵：本服務只關心「間隔多長、窗口幾天、掃多快」，
// 鍵名與其驗證屬於政策層。**每次呼叫都須現讀**，不得快取——政策一改，
// 下一分鐘就要生效，不能等重啟
type ChainVerifyTuning interface {
	// RecentWindowDays 近期層窗口天數（設定值；保留天數 clamp 由本服務施加）
	RecentWindowDays() int
	// FullInterval 全鏈層驗證間隔
	FullInterval() time.Duration
	// RowsPerHour 內容層掃描**速率**（列/小時）。
	//
	// **是速率不是每輪列數**：每輪列預算＝速率 × 間隔，使繞行週期與資料庫
	// 佔空比對間隔選擇不變。若定成每輪固定列數，把間隔從 1 小時調到上界
	// 7 天就會把繞行週期拉長 168 倍，而管理員從介面上只看見「驗得稀疏一點」
	RowsPerHour() int64
}

// ChainVerifyAlerter 告警出口（實作為 *AuditFailureService）
type ChainVerifyAlerter interface {
	// ReportWithCounts 上報失效；counts 為受控整數計數（出站只帶碼與計數）
	ReportWithCounts(mechanism, causeCode string, params map[string]string, counts map[string]int)
	// Resolve 結案並發恢復通知
	Resolve(mechanism string)
	// NotifyOngoing 對進行中的失效直接投遞提醒（不動事件列、不偽造恢復）
	NotifyOngoing(event notifycat.Event, params map[string]string)
}

// chainVerifySigningProbe 依賴自檢用的簽章服務窄介面
// （實作為 keyvault.CheckpointSigningService）
type chainVerifySigningProbe interface {
	ActiveVersion() int
	ActivePublicKeyBase64() string
}

// ChainVerifyService 兩層自動驗證的編排者
type ChainVerifyService struct {
	db       *gorm.DB
	verifier *CheckpointVerifier
	seal     *CheckpointService
	signing  chainVerifySigningProbe
	policies checkpointPolicyReader
	tuning   ChainVerifyTuning
	alerts   ChainVerifyAlerter

	// now 時鐘（測試注入；nil 走 time.Now）
	now func() time.Time
}

// NewChainVerifyService 建立編排者。
//
// **不改任何既有驗證邏輯**：VerifyChain／VerifyContentBySeq／九個區間狀態碼
// 全部沿用，本服務是它們的第二個呼叫端而非替代品
func NewChainVerifyService(db *gorm.DB, verifier *CheckpointVerifier, seal *CheckpointService,
	signing chainVerifySigningProbe, policies checkpointPolicyReader,
	tuning ChainVerifyTuning, alerts ChainVerifyAlerter) *ChainVerifyService {
	return &ChainVerifyService{db: db, verifier: verifier, seal: seal, signing: signing,
		policies: policies, tuning: tuning, alerts: alerts}
}

// SetClock 注入時鐘（測試用；生產不呼叫）
func (s *ChainVerifyService) SetClock(now func() time.Time) { s.now = now }

func (s *ChainVerifyService) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// ── 執行期旋鈕（現讀，帶消費端防禦邊界）────────────────────────────────────

// recentWindowDays 近期層本次生效的窗口天數。
//
// **有效值＝min(設定值, 審計紀錄保留天數)**（保留天數為 0＝永久時不 clamp）：
// 承諾驗證保留期以外的範圍是空頭支票——該範圍的列早已依保留政策清除，
// 驗出來的只會是一片合法清除或誤報。此為消費端約束，刻意不做成跨鍵儲存驗證
// （把窗口設得比保留期長只是無效，不危險，不需擋下存檔）
func (s *ChainVerifyService) recentWindowDays() int {
	n := chainVerifyRecentDaysDefault
	if s.tuning != nil {
		if v := s.tuning.RecentWindowDays(); v >= 1 && v <= chainVerifyRecentDaysMax {
			n = v
		}
	}
	if s.policies != nil {
		if keep := s.policies.GetInt(policy.PolicyRetentionAuditLogDays); keep > 0 && keep < n {
			n = keep
		}
	}
	return n
}

func (s *ChainVerifyService) fullInterval() time.Duration {
	if s.tuning == nil {
		return chainVerifyIntervalDefault
	}
	d := s.tuning.FullInterval()
	if d < time.Second || d > chainVerifyIntervalMax {
		return chainVerifyIntervalDefault
	}
	return d
}

// effectiveRowsPerHour 掃描速率的生效值（政策現值經消費端上下界收束）。
//
// **低於下界即等同實質關閉**（介面上仍開著、實際上每輪只推進數列），
// 高於上界即超出實測可承受的 DB 佔空比。驗證頁揭露的是這個生效值而非
// 政策設定值——顯示值 ≠ 生效值是本專案在別處已拒絕的不誠實
func (s *ChainVerifyService) effectiveRowsPerHour() int64 {
	rate := chainVerifyRowsPerHourDefault
	if s.tuning != nil {
		rate = s.tuning.RowsPerHour()
	}
	if rate < chainVerifyRowsPerHourMin {
		rate = chainVerifyRowsPerHourMin
	}
	if rate > chainVerifyRowsPerHourMax {
		rate = chainVerifyRowsPerHourMax
	}
	return rate
}

// rowBudget 本輪內容層列預算＝掃描速率 × 本次間隔（D10）。
//
// **不是每輪固定列數**：繞行一輪全歷史所需時間正比於「間隔 ÷ 每輪預算」，
// 若預算為每輪固定值，延長驗證間隔即等比延長繞行週期，而管理員從介面上
// 只看見「驗得稀疏一點」。以速率表達使繞行週期與 DB 負載佔比對間隔選擇不變
func (s *ChainVerifyService) rowBudget() int64 {
	budget := s.effectiveRowsPerHour() * int64(s.fullInterval()/time.Second) / int64(time.Hour/time.Second)
	if budget < 1 {
		budget = 1
	}
	return budget
}

// ── 狀態表 ────────────────────────────────────────────────────────────────

// LoadState 讀單列狀態（不存在即建立空列）。供驗證頁與排程器共用
func (s *ChainVerifyService) LoadState() (*model.AuditChainVerifyState, error) {
	var st model.AuditChainVerifyState
	err := s.db.First(&st, model.AuditChainVerifyStateID).Error
	switch {
	case err == nil:
		return &st, nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		st = model.AuditChainVerifyState{ID: model.AuditChainVerifyStateID}
		if err := s.db.Create(&st).Error; err != nil {
			return nil, fmt.Errorf("建立鏈驗證狀態列失敗: %w", err)
		}
		return &st, nil
	default:
		return nil, fmt.Errorf("讀取鏈驗證狀態失敗: %w", err)
	}
}

// loadStateOrReport 載入狀態列；失敗即以「驗證本身失敗」機制上報後才回錯。
//
// **為什麼載入失敗必須出聲**：狀態列讀不到＝資料庫不可讀，而那正是 D5 明列為
// audit_chain_verify_failed 的成因之一。若此處只 return，這個成因在真實裝配上
// 永遠不會上報、不會發通知，只留一行本地 log——偵測控制在最需要出聲的時候是啞的
// （對抗驗收 6.5 的缺陷 A）。且它必須走**這個**機制碼而非竄改機制：
// 資料庫不可讀是維運故障（機制狀態為未知），把它報成 audit_chain_structure／
// audit_chain_content 等於對稽核謊稱「整條鏈被竄改」，兩者的處置完全不同。
//
// **不會變成每分鐘重發，也不會遞迴或無限重試**：
//   - 上報的第一層去重是 in-memory 的，且旗標在寫 DB **之前**就置起
//     （audit_failure_service.go:200-206），故資料庫全掛期間仍然有效——
//     每分鐘一次的 tick 只會在「進入失效」那一次出聲；
//   - 上報端的 DB 建列是 best-effort，失敗只 log 而通知照發
//     （同檔 :227-229「DB 全掛正是最需要告警的時刻」），故上報本身寫不進去時
//     不重試、不回錯、不 panic；
//   - 本函式回錯後 tick 立刻結束，排程器只記一行 log 等下一分鐘重判
//     （scheduler/chain_verify.go:86-94），不在本輪內迴圈重試。
//
// 資料庫恢復後由 Tick 的自檢成功路徑 Resolve（此機制與竄改機制各自結案）
func (s *ChainVerifyService) loadStateOrReport() (*model.AuditChainVerifyState, error) {
	st, err := s.LoadState()
	if err != nil {
		s.reportVerifyFailure(fmt.Errorf("%w: %v", ErrChainVerifyDependency, err))
		return nil, err
	}
	return st, nil
}

func (s *ChainVerifyService) saveState(st *model.AuditChainVerifyState) error {
	st.ID = model.AuditChainVerifyStateID
	if err := s.db.Save(st).Error; err != nil {
		return fmt.Errorf("寫入鏈驗證狀態失敗: %w", err)
	}
	return nil
}

// ── 依賴自檢 ──────────────────────────────────────────────────────────────

// SelfCheck 驗證前的依賴自檢：資料庫可讀、簽章服務可取得現行公鑰。
// 不通過回 ErrChainVerifyDependency 包裝的錯誤，呼叫端據此跳過**兩層**
func (s *ChainVerifyService) SelfCheck() error {
	var n int64
	if err := s.db.Model(&model.AuditCheckpoint{}).Count(&n).Error; err != nil {
		return fmt.Errorf("%w: 資料庫不可讀: %v", ErrChainVerifyDependency, err)
	}
	if s.signing == nil {
		return fmt.Errorf("%w: 簽章服務未注入", ErrChainVerifyDependency)
	}
	if s.signing.ActiveVersion() <= 0 || s.signing.ActivePublicKeyBase64() == "" {
		return fmt.Errorf("%w: 簽章服務無法取得現行公鑰", ErrChainVerifyDependency)
	}
	return nil
}

// ── tick 與兩層編排 ───────────────────────────────────────────────────────

// Tick 每分鐘一次的 due 判定與執行（排程器唯一入口）。
//
// 兩層由同一支排程器承載並**串行執行**（不並行推進同一份狀態）；同一 tick 內
// 兩者都到期時**先跑近期層**（低延遲告警優先）
func (s *ChainVerifyService) Tick(ctx context.Context) error {
	st, err := s.loadStateOrReport()
	if err != nil {
		return err
	}
	now := s.clock()
	recentDue, fullDue, tailSeq := s.due(st, now)
	if !recentDue && !fullDue {
		return nil
	}

	// 自檢是兩層唯一的共同前置：不過即兩層都跳過並報「驗證本身失敗」
	if err := s.SelfCheck(); err != nil {
		s.reportVerifyFailure(err)
		return err
	}
	// 自檢通過＝「驗證本身」這個機制已恢復（與竄改機制無關，各自結案）
	s.alerts.Resolve(model.MechanismAuditChainVerify)

	var errs []error
	if recentDue {
		// 觀測式觸發的狀態推進：不論本輪成敗都記下已觀測到的鏈尾，
		// 否則同一次封章會在每一分鐘重複觸發近期層
		st.RecentLastSeq = tailSeq
		if err := s.runLayer(ctx, ChainVerifyLayerRecent, st); err != nil {
			errs = append(errs, err)
		}
	}
	// **一層失敗不阻斷另一層**（依賴自檢除外）：兩者的失敗成因不同，任一層
	// 失效時另一層仍是有效的觀測管道；相互阻斷會把單層故障放大為全盲
	if fullDue {
		if err := s.runLayer(ctx, ChainVerifyLayerFull, st); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// due 判定兩層是否到期，並回傳當下觀測到的鏈尾 seq。
//
// 近期層＝「最新已封 seq 前進」且「距上次近期層已滿一個封存週期」——
// 節流不是可選項：封存為「週期或筆數門檻先到先觸發」，高寫入量部署的封存
// 頻率隨寫入量上升，而近期層每次的成本亦隨寫入量上升；未節流時負載對寫入量
// 呈二次成長（10 倍寫入量＝10 倍觸發頻率 × 10 倍窗內列數＝100 倍成本）
func (s *ChainVerifyService) due(st *model.AuditChainVerifyState, now time.Time) (recent, full bool, tailSeq uint) {
	if latest, err := s.seal.Latest(); err == nil && latest != nil {
		tailSeq = latest.Seq
	}
	if tailSeq > st.RecentLastSeq {
		throttle := s.seal.Interval()
		if st.RecentLastRunAt == nil || now.Sub(*st.RecentLastRunAt) >= throttle {
			recent = true
		}
	}
	if st.FullLastRunAt == nil || now.Sub(*st.FullLastRunAt) >= s.fullInterval() {
		full = true
	}
	return recent, full, tailSeq
}

// RunRecentNow／RunFullNow 略過 due 判定直接跑一層（測試與人工驗證用；
// 仍走完整的自檢、必驗集合與告警路徑）
func (s *ChainVerifyService) RunRecentNow(ctx context.Context) error {
	return s.runNow(ctx, ChainVerifyLayerRecent)
}

func (s *ChainVerifyService) RunFullNow(ctx context.Context) error {
	return s.runNow(ctx, ChainVerifyLayerFull)
}

func (s *ChainVerifyService) runNow(ctx context.Context, layer string) error {
	st, err := s.loadStateOrReport()
	if err != nil {
		return err
	}
	if err := s.SelfCheck(); err != nil {
		s.reportVerifyFailure(err)
		return err
	}
	s.alerts.Resolve(model.MechanismAuditChainVerify)
	if layer == ChainVerifyLayerRecent {
		if latest, err := s.seal.Latest(); err == nil && latest != nil {
			st.RecentLastSeq = latest.Seq
		}
	}
	return s.runLayer(ctx, layer, st)
}

// runLayer 跑完一層：結構層全鏈 → 內容層（必驗集合＋本層範圍）→ 更新集合 → 告警。
func (s *ChainVerifyService) runLayer(ctx context.Context, layer string, st *model.AuditChainVerifyState) error {
	start := s.clock()

	// 結構層：兩層共用同一支既有全鏈驗證，不改其行為、不新增 verifier API
	report, err := s.verifier.VerifyChain()
	if err != nil {
		s.finishLayer(st, layer, start, ChainVerifyStatusError)
		s.reportVerifyFailure(fmt.Errorf("結構層全鏈驗證失敗: %w", err))
		_ = s.saveState(st)
		return err
	}
	st.StructureFailedCount = int(report.Failed)
	structurePassed := report.Status == IntervalStatusPassed

	verified, advanceTo, wrapped, err := s.verifyContent(ctx, layer, st, report)
	if err != nil {
		s.finishLayer(st, layer, start, ChainVerifyStatusError)
		s.reportVerifyFailure(fmt.Errorf("內容層驗證失敗: %w", err))
		_ = s.saveState(st)
		return err
	}

	open := s.mergeOpenFailed(st, verified)
	st.ContentVerifiedIntervals = len(verified)
	if layer == ChainVerifyLayerFull && advanceTo > 0 {
		st.ContentCursorSeq = advanceTo
		if wrapped {
			at := s.clock()
			st.LastFullCycleAt = &at
		}
	}

	status := ChainVerifyStatusPassed
	if !structurePassed || len(open) > 0 {
		status = ChainVerifyStatusFailed
	}
	s.finishLayer(st, layer, start, status)

	prev := st.LastFingerprint
	fp := chainVerifyFingerprint(st.StructureFailedCount, open)
	st.LastFingerprint = fp
	if err := s.saveState(st); err != nil {
		// 狀態寫不進去不該吞掉告警：異常仍要出聲（DB 全掛正是最需要告警的時刻）
		log.Printf("[ChainVerify] 狀態寫入失敗（告警照發）: %v", err)
	}
	s.syncAlerts(layer, structurePassed, st.StructureFailedCount, open, prev, fp)
	return nil
}

func (s *ChainVerifyService) finishLayer(st *model.AuditChainVerifyState, layer string,
	start time.Time, status string) {
	end := s.clock()
	ms := end.Sub(start).Milliseconds()
	if layer == ChainVerifyLayerRecent {
		st.RecentLastRunAt = &end
		st.RecentLastStatus = status
		st.RecentLastDurationMs = ms
		return
	}
	st.FullLastRunAt = &end
	st.FullLastStatus = status
	st.FullLastDurationMs = ms
}

// ── 內容層 ────────────────────────────────────────────────────────────────

// seqRange 內容層一次驗證呼叫的 seq 閉區間
type seqRange struct{ from, to uint }

// verifyContent 依層別規劃並執行內容層驗證。
//
// 回傳 verified（seq → 區間狀態）、advanceTo（全鏈層的新游標；0＝不推進）、
// wrapped（本輪推到鏈尾並回捲＝繞完一輪）
func (s *ChainVerifyService) verifyContent(ctx context.Context, layer string,
	st *model.AuditChainVerifyState, report *ChainReport) (map[uint]string, uint, bool, error) {
	verified := map[uint]string{}
	if report.Total == 0 {
		// 鏈為空：沒有任何區間可驗。這不是「通過」——空鏈本身由結構層以
		// seq_gap 回報（機制未啟用或整鏈被抹除），此處只是無內容層工作
		return verified, 0, false, nil
	}

	head := chainVerifyHeadSeq(report)
	tail := report.LatestSeq

	// 必驗集合（不受列預算限制，兩層皆適用）：
	//   1. 鏈尾最新的已封區間——近期層已涵蓋它，全鏈層**刻意保留冗餘**，
	//      使兩層各自自足、不因對方失效而失去鏈尾覆蓋；
	//   2. 尚未重驗轉綠的失敗區間集合（D9 假恢復修法的核心）。
	mandatory := map[uint]bool{tail: true}
	for seq := range decodeSeqSet(st.OpenFailedSeqs) {
		if seq >= head && seq <= tail {
			mandatory[seq] = true
		}
		// 落在現有鏈之外的成員（整段被移除）刻意不驗、也不移出集合——
		// 否則即開出「刪除整個區間即可使告警消失」的路徑
	}

	ranges := mergeSeqRanges(mandatory)
	advanceTo, wrapped := uint(0), false

	switch layer {
	case ChainVerifyLayerRecent:
		days := s.recentWindowDays()
		st.RecentWindowDaysEffective = days
		now := s.clock()
		from, to, err := s.verifier.SeqRangeByTime(now.AddDate(0, 0, -days), now)
		if err != nil {
			return nil, 0, false, err
		}
		if from != 0 && to != 0 {
			ranges = append(ranges, seqRange{from: from, to: to})
		}
	case ChainVerifyLayerFull:
		budget := s.rowBudget()
		spent, err := s.estimateRows(mandatory)
		if err != nil {
			return nil, 0, false, err
		}
		// **集合預估列數超出本輪預算時只驗集合、不推進游標**：已知異常的
		// 追蹤優先於未驗歷史的推進。不丟棄集合成員——丟棄等同重新製造假恢復
		if spent < budget {
			r, next, w, err := s.planRolling(st, head, tail, budget-spent)
			if err != nil {
				return nil, 0, false, err
			}
			if r != nil {
				ranges = append(ranges, *r)
			}
			advanceTo, wrapped = next, w
		}
	}

	for _, r := range ranges {
		if err := ctx.Err(); err != nil {
			return nil, 0, false, err
		}
		content, err := s.verifier.VerifyContentBySeq(r.from, r.to)
		if err != nil {
			return nil, 0, false, err
		}
		for _, iv := range content.Intervals {
			verified[iv.Seq] = iv.Status
		}
	}
	return verified, advanceTo, wrapped, nil
}

// planRolling 規劃滾動窗：自游標往後累加 row_count 至列預算用盡。
//
// **單一區間是不可分的驗證單位**（即使其列數超出預算亦整段驗完），
// 預算以檢查點記錄的 row_count 累加預估而非先掃列
func (s *ChainVerifyService) planRolling(st *model.AuditChainVerifyState,
	head, tail uint, budget int64) (*seqRange, uint, bool, error) {
	cursor := st.ContentCursorSeq
	if cursor < head || cursor > tail {
		cursor = head
	}
	var rows []struct {
		Seq      uint
		RowCount int64
	}
	if err := s.db.Model(&model.AuditCheckpoint{}).
		Select("seq, row_count").Where("seq >= ?", cursor).
		Order("seq ASC").Scan(&rows).Error; err != nil {
		return nil, 0, false, fmt.Errorf("讀取滾動窗檢查點失敗: %w", err)
	}
	if len(rows) == 0 {
		return nil, head, true, nil
	}
	spent := int64(0)
	last := rows[0].Seq
	for i, r := range rows {
		if i > 0 && spent >= budget {
			break
		}
		spent += r.RowCount
		last = r.Seq
	}
	if last >= tail {
		// 推至鏈尾即回捲至鏈頭（或最新修剪點之後），並記一次繞行完成
		return &seqRange{from: cursor, to: tail}, head, true, nil
	}
	return &seqRange{from: cursor, to: last}, last + 1, false, nil
}

// estimateRows 以檢查點記錄的 row_count 估算一組 seq 的掃描成本（不先掃列）
func (s *ChainVerifyService) estimateRows(seqs map[uint]bool) (int64, error) {
	if len(seqs) == 0 {
		return 0, nil
	}
	list := make([]uint, 0, len(seqs))
	for seq := range seqs {
		list = append(list, seq)
	}
	var total int64
	row := struct{ Total *int64 }{}
	if err := s.db.Model(&model.AuditCheckpoint{}).
		Select("SUM(row_count) AS total").Where("seq IN ?", list).Scan(&row).Error; err != nil {
		return 0, fmt.Errorf("估算掃描列數失敗: %w", err)
	}
	if row.Total != nil {
		total = *row.Total
	}
	return total, nil
}

// chainVerifyHeadSeq 鏈頭：最新修剪點之後，或現存最舊的檢查點
func chainVerifyHeadSeq(report *ChainReport) uint {
	head := report.OldestSeq
	if report.TrimmedThroughSeq != nil && *report.TrimmedThroughSeq+1 > head {
		head = *report.TrimmedThroughSeq + 1
	}
	return head
}

// mergeSeqRanges 把離散 seq 併成連續閉區間，減少 VerifyContentBySeq 呼叫次數
func mergeSeqRanges(seqs map[uint]bool) []seqRange {
	if len(seqs) == 0 {
		return nil
	}
	list := make([]uint, 0, len(seqs))
	for seq := range seqs {
		list = append(list, seq)
	}
	sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
	out := []seqRange{{from: list[0], to: list[0]}}
	for _, seq := range list[1:] {
		tail := &out[len(out)-1]
		if seq == tail.to+1 {
			tail.to = seq
			continue
		}
		out = append(out, seqRange{from: seq, to: seq})
	}
	return out
}

// ── 失敗區間集合（D9）─────────────────────────────────────────────────────

// mergeOpenFailed 以本輪結果更新未結案的失敗區間集合，並寫回狀態。
//
// **規則只有三條，且刻意如此**：
//   - 本輪驗為 passed／purged_legal → 移出（依政策合法清除且清除簽章驗過者非異常）；
//   - 本輪驗為內容層異常 → 加入／留下；
//   - 本輪**未被驗到**（含整段已被移除、與結構層狀態）→ **留下**。
//
// 第三條是假恢復修法的要害：只有「真的被重驗且轉綠」才准移出。若以
// 「區間已不存在」為由逕行移出，就開出了「刪除整個區間即可使告警消失」的路徑
func (s *ChainVerifyService) mergeOpenFailed(st *model.AuditChainVerifyState,
	verified map[uint]string) map[uint]string {
	open := decodeSeqSet(st.OpenFailedSeqs)
	for seq, status := range verified {
		switch {
		case status == IntervalStatusPassed || status == IntervalStatusPurgedLegal:
			delete(open, seq)
		case chainVerifyContentFailed(status):
			open[seq] = status
		default:
			// 結構層狀態（signature_invalid／chain_broken／seq_gap）：由結構層
			// 機制承擔，不新增為內容層成員；但既有成員亦**不移出**（未轉綠）
		}
	}
	st.OpenFailedSeqs = encodeSeqSet(open)
	return open
}

// chainVerifyContentFailed 內容層異常判準（passed／purged_legal 之外的內容層狀態）
func chainVerifyContentFailed(status string) bool {
	switch status {
	case IntervalStatusCountMismatch, IntervalStatusHashMismatch,
		IntervalStatusPurgedInvalid, IntervalStatusExtraRowsValidHMAC:
		return true
	}
	return false
}

// chainVerifyContentCause 一輪內出現多種狀態時取較嚴重者（mismatch > extra_rows）
func chainVerifyContentCause(open map[uint]string) string {
	cause := model.CauseAuditChainContentExtraRows
	for _, status := range open {
		if status != IntervalStatusExtraRowsValidHMAC {
			return model.CauseAuditChainContentMismatch
		}
	}
	return cause
}

// decodeSeqSet／encodeSeqSet 集合的 JSON 表述（seq → 該 seq 最近一次的失敗狀態）
func decodeSeqSet(raw string) map[uint]string {
	out := map[uint]string{}
	if strings.TrimSpace(raw) == "" {
		return out
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		// 解不開的集合不得靜默視為空集合——那等同一次假恢復。
		// 保守起見回一個 sentinel 成員（seq 0 不存在於鏈上，故永不被重驗轉綠），
		// 使事件保持開啟並由人介入
		log.Printf("[ChainVerify] 失敗區間集合解析失敗，保守視為仍有未結案異常: %v", err)
		return map[uint]string{0: IntervalStatusCountMismatch}
	}
	return out
}

func encodeSeqSet(set map[uint]string) string {
	if len(set) == 0 {
		return ""
	}
	raw, err := json.Marshal(set)
	if err != nil {
		log.Printf("[ChainVerify] 失敗區間集合序列化失敗: %v", err)
		return ""
	}
	return string(raw)
}

// chainVerifyFingerprint 重發判準的指紋＝「最嚴重狀態＋結構層失敗點數＋
// 未結案失敗區間集合」的 SHA-256 前 16 hex。
//
// **由跨輪累積的集合計算，不由本輪驗過的區間結果計算**：兩層與滾動窗每輪驗到
// 的區間本就不同，以本輪結果計算會使指紋逐輪抖動而每輪觸發重發通知——
// 其實際效果就是「每輪重複發送」，收件端會靜音整個通道
func chainVerifyFingerprint(structureFailed int, open map[uint]string) string {
	if structureFailed == 0 && len(open) == 0 {
		return ""
	}
	seqs := make([]string, 0, len(open))
	for seq := range open {
		seqs = append(seqs, fmt.Sprintf("%d", seq))
	}
	sort.Strings(seqs)
	severity := ""
	if len(open) > 0 {
		severity = chainVerifyContentCause(open)
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%s", severity, structureFailed, strings.Join(seqs, ","))))
	return hex.EncodeToString(sum[:])[:16]
}

// ── 告警 ──────────────────────────────────────────────────────────────────

// syncAlerts 依**合併後的狀態**（非單層單輪結果）決定開立、重發與結案。
//
// 三條同時成立：
//   - 進入異常狀態時發告警（失效事件的開始時間即首次發現時間，永久留存）；
//   - 未結案集合改變時再次發出通知，且**不先結案再重開**——偽造一次不存在的
//     恢復會破壞失效區間的起訖證據；
//   - **結案以集合清空為條件**，不以「本輪驗過的區間全數通過」為條件（D9）。
func (s *ChainVerifyService) syncAlerts(layer string, structurePassed bool, structureFailed int,
	open map[uint]string, prevFingerprint, fingerprint string) {
	params := map[string]string{model.FailureParamChainVerifyLayer: layer}
	changed := prevFingerprint != "" && fingerprint != prevFingerprint

	if structurePassed {
		s.alerts.Resolve(model.MechanismAuditChainStructure)
	} else {
		s.alerts.ReportWithCounts(model.MechanismAuditChainStructure,
			model.CauseAuditChainStructureInvalid, params,
			map[string]int{model.FailureParamFailedPoints: structureFailed})
		if changed {
			s.alerts.NotifyOngoing(notifycat.EventAuditFailureOngoing, map[string]string{
				"mechanism":                    model.MechanismAuditChainStructure,
				"cause_code":                   model.CauseAuditChainStructureInvalid,
				"reported_at":                  s.clock().Format(time.RFC3339),
				model.FailureParamFailedPoints: fmt.Sprintf("%d", structureFailed),
			})
		}
	}

	// **結案僅在集合清空時**：「本輪驗過的區間全數通過」不構成結案條件——
	// 滾動窗每輪驗的是不同窗口，以本輪結果結案會把被刪列的區間錯誤宣告為已恢復
	if len(open) == 0 {
		s.alerts.Resolve(model.MechanismAuditChainContent)
		return
	}
	cause := chainVerifyContentCause(open)
	s.alerts.ReportWithCounts(model.MechanismAuditChainContent, cause, params,
		map[string]int{model.FailureParamFailedIntervals: len(open)})
	if changed {
		s.alerts.NotifyOngoing(notifycat.EventAuditFailureOngoing, map[string]string{
			"mechanism":                       model.MechanismAuditChainContent,
			"cause_code":                      cause,
			"reported_at":                     s.clock().Format(time.RFC3339),
			model.FailureParamFailedIntervals: fmt.Sprintf("%d", len(open)),
		})
	}
}

// reportVerifyFailure 上報「驗證本身失敗」：運維事件，機制狀態為**未知**而非
// 「無異常」。此路徑 SHALL NOT 產出任何竄改結論
func (s *ChainVerifyService) reportVerifyFailure(err error) {
	s.alerts.ReportWithCounts(model.MechanismAuditChainVerify, model.CauseAuditChainVerifyFailed,
		map[string]string{model.CauseParamDetail: err.Error()}, nil)
}
