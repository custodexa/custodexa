package audit

import (
	"errors"
	"fmt"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"gorm.io/gorm"
)

// 檢查點驗證的兩層實作（audit-checkpoint-chain D10／tasks 8.1-8.3）。
//
// **結構層與內容層的成本差三個數量級**，故切開：
//   - 結構層只讀 audit_checkpoints（萬級列），預設涵蓋全鏈、常開。
//   - 內容層要重掃 audit_logs（十億級），必須帶範圍（8.2 拒絕無範圍請求）。
//
// 驗證一律唯讀：不得因驗證而寫入、修補或重算任何檢查點欄位（spec 明文）。

const (
	// ChainStatusChainBroken 鏈接斷裂：prev hash 對不上、或區間不鄰接
	ChainStatusChainBroken = "chain_broken"
	// ChainStatusSeqGap seq 不連續（中段檢查點被刪、或鏈頭缺修剪記錄）
	ChainStatusSeqGap = "seq_gap"
)

// ErrCheckpointRangeRequired 內容層未帶範圍（8.2：不得啟動全歷史掃描）
var ErrCheckpointRangeRequired = errors.New("內容層驗證必須指定範圍（seq 區間或日期區間）")

// checkpointPolicyReader 取政策天數的窄介面（tombstone 驗證需要 policy_days）
type checkpointPolicyReader interface {
	GetInt(key string) int
}

// CheckpointVerifier 檢查點驗證服務（結構層＋內容層的唯一入口）。
//
// 組合而非繼承：聚合來自封章器（與封章同一份實作，避免驗證用另一套聚合而
// 永遠自洽）、tombstone 與簽章來自清除器、列級 HMAC 來自完整性服務。
// 三者任一為 nil 時對應能力誠實停用而非靜默降級（見各方法）
type CheckpointVerifier struct {
	db     *gorm.DB
	seal   *CheckpointService
	purger *CheckpointPurger
	// integrity 列級 HMAC 驗證來源；nil＝無法判定多出列的真偽
	integrity *AuditIntegrityService
	policy    checkpointPolicyReader
}

// NewCheckpointVerifier 建立驗證服務
func NewCheckpointVerifier(db *gorm.DB, seal *CheckpointService, purger *CheckpointPurger,
	integrity *AuditIntegrityService, pol checkpointPolicyReader) *CheckpointVerifier {
	return &CheckpointVerifier{db: db, seal: seal, purger: purger, integrity: integrity, policy: pol}
}

// ChainPointResult 結構層逐檢查點結果
type ChainPointResult struct {
	Seq          uint       `json:"seq"`
	IDFrom       uint       `json:"id_from"`
	IDTo         uint       `json:"id_to"`
	RowCount     int64      `json:"row_count"`
	SealedAt     time.Time  `json:"sealed_at"`
	AnchorStatus string     `json:"anchor_status"`
	PurgedAt     *time.Time `json:"purged_at,omitempty"`
	// Status passed／signature_invalid／chain_broken／seq_gap
	Status string `json:"status"`
	// Detail 失敗原因（人讀輔助；狀態才是機器可判定的部分）
	Detail string `json:"detail,omitempty"`
}

// ChainReport 結構層報告
type ChainReport struct {
	Total     int64  `json:"total"`
	LatestSeq uint   `json:"latest_seq"`
	OldestSeq uint   `json:"oldest_seq"`
	Passed    int64  `json:"passed"`
	Failed    int64  `json:"failed"`
	Status    string `json:"status"`
	// Failures 失敗點清單（全部，鏈長萬級故不截斷）
	Failures []ChainPointResult `json:"failures"`
	// UnsealedRows 最新檢查點之後尚未封章的列數（誠實邊界 R5 的窗口大小）
	UnsealedRows int64 `json:"unsealed_rows"`
	// UnsealedFromID 未封尾段的起始 id（＝最新 id_to + 1）
	UnsealedFromID uint `json:"unsealed_from_id"`
	// AnchorDisabled 最新檢查點是否無離機錨定（R3 降級橫幅的判據；
	// 取鏈尾而非全鏈聚合，理由見 VerifyChain）
	AnchorDisabled bool `json:"anchor_disabled"`
	// SealIntervalSeconds／SealRowThreshold 現行封章觸發門檻。
	//
	// **回傳現值而非讓前端寫死**：R5 的窗口上界就是這兩個值，而它們自
	// audit-checkpoint-chain 起可由管理員在安全政策頁調整（上限 24 小時／
	// 百萬筆）。文案若硬寫「最長一小時或一萬筆」，管理員一調就成了對稽核
	// 的假陳述——邊界聲明錯得比沒有更糟
	SealIntervalSeconds int64 `json:"seal_interval_seconds"`
	SealRowThreshold    int64 `json:"seal_row_threshold"`
	// TrimmedThroughSeq 鏈頭曾被修剪至此 seq（含）；nil＝未修剪過
	TrimmedThroughSeq *uint `json:"trimmed_through_seq,omitempty"`
	// AutoVerify 兩層自動驗證的營運狀態（audit-chain-scheduled-verification D8）。
	//
	// **掛在本報告上而非另開端點**：狀態的讀者與結構層報告完全相同（驗證頁），
	// 且新增路由要動兩份機器產物（端點索引與路由 golden）。nil＝本次未附帶
	// （驗證器本身不讀狀態表——填值由 handler 以獨立的狀態讀取端注入，
	// 使既有驗證路徑不因一張營運狀態表而多一個失敗成因）
	AutoVerify *ChainAutoVerifyStatus `json:"auto_verify,omitempty"`
}

// VerifyChain 結構層全鏈驗證：逐點驗簽章、驗 prev hash 鏈接、驗 seq 連續與區間鄰接。
//
// **不讀 audit_logs**（spec 明文）——除了尾段未封列數那一個 COUNT，
// 它回答的是「鏈保護到哪裡為止」而非任何列的內容真偽
func (v *CheckpointVerifier) VerifyChain() (*ChainReport, error) {
	var chain []model.AuditCheckpoint
	if err := v.db.Order("seq ASC").Find(&chain).Error; err != nil {
		return nil, fmt.Errorf("讀取檢查點鏈失敗: %w", err)
	}
	report := &ChainReport{Total: int64(len(chain)), Failures: []ChainPointResult{}}
	// 門檻在早退之前填：邊界聲明是常駐文案，鏈為空時同樣要說得出窗口上界
	if v.seal != nil {
		report.SealIntervalSeconds = int64(v.seal.Interval() / time.Second)
		report.SealRowThreshold = v.seal.RowThreshold()
	}
	if len(chain) == 0 {
		// 鏈為空本身就是一個結論（機制未啟用或整鏈被抹除），不是「通過」
		report.Status = ChainStatusSeqGap
		return report, nil
	}
	report.OldestSeq, report.LatestSeq = chain[0].Seq, chain[len(chain)-1].Seq

	trim, err := v.purger.LatestTrim()
	if err != nil {
		return nil, err
	}
	if trim != nil {
		seq := trim.LastTrimmedSeq
		report.TrimmedThroughSeq = &seq
	}

	for i := range chain {
		res := v.verifyChainPoint(chain, i, trim)
		if res.Status == IntervalStatusPassed {
			report.Passed++
		} else {
			report.Failed++
			report.Failures = append(report.Failures, res)
		}
	}
	// **以鏈尾（最新）檢查點的錨定狀態判定降級**，不是「全鏈是否曾有過錨定」。
	//
	// R3 的降級橫幅要回答的是「現在有沒有離機見證」：曾經啟用過 syslog、
	// 後來關掉的部署，若以「任一檢查點非 disabled」判定就會不顯示橫幅，
	// 而那正是最需要提醒的狀態（有幾個舊檢查點有外部證跡，新的全都沒有）。
	// 鏈尾狀態於封章當下取自轉發器的 Enabled()，是最新的可信快照
	report.AnchorDisabled = chain[len(chain)-1].AnchorStatus == model.AnchorStatusDisabled
	report.Status = IntervalStatusPassed
	if report.Failed > 0 {
		report.Status = report.Failures[0].Status
	}

	// 未封尾段（R5）：最新 id_to 之後的列尚無鏈保護
	last := chain[len(chain)-1]
	report.UnsealedFromID = last.IDTo + 1
	var unsealed int64
	if err := v.db.Unscoped().Model(&model.AuditLog{}).
		Where("id > ?", last.IDTo).Count(&unsealed).Error; err != nil {
		return nil, fmt.Errorf("計數未封尾段失敗: %w", err)
	}
	report.UnsealedRows = unsealed
	return report, nil
}

// verifyChainPoint 單點的結構層判定。
//
// 判定順序：簽章 → seq 連續 → 鏈接（prev hash 與區間鄰接）。簽章不過時
// 後兩者不必再判——一個驗不過的檢查點，它的 seq 與 id_from 都是攻擊者寫的
func (v *CheckpointVerifier) verifyChainPoint(chain []model.AuditCheckpoint, i int,
	trim *model.AuditCheckpointTrim) ChainPointResult {
	cp := chain[i]
	res := ChainPointResult{
		Seq: cp.Seq, IDFrom: cp.IDFrom, IDTo: cp.IDTo, RowCount: cp.RowCount,
		SealedAt: cp.SealedAt, AnchorStatus: cp.AnchorStatus, PurgedAt: cp.PurgedAt,
		Status: IntervalStatusPassed,
	}
	payload, err := CheckpointSignBytes(&cp)
	if err != nil {
		res.Status = IntervalStatusSignatureInvalid
		res.Detail = err.Error()
		return res
	}
	ok, err := v.purger.signer.Verify(cp.SigningKeyVersion, payload, cp.Signature)
	if err != nil || !ok {
		res.Status = IntervalStatusSignatureInvalid
		res.Detail = fmt.Sprintf("簽章驗證失敗（鑰版本 v%d）", cp.SigningKeyVersion)
		if err != nil {
			res.Detail = fmt.Sprintf("%s: %v", res.Detail, err)
		}
		return res
	}

	if i == 0 {
		return v.verifyChainHead(cp, trim, res)
	}

	prev := chain[i-1]
	if cp.Seq != prev.Seq+1 {
		res.Status = ChainStatusSeqGap
		res.Detail = fmt.Sprintf("seq 不連續：前一點 seq=%d", prev.Seq)
		return res
	}
	linkHash, err := CheckpointLinkHash(&prev)
	if err != nil {
		res.Status = ChainStatusChainBroken
		res.Detail = err.Error()
		return res
	}
	if cp.PrevCheckpointHash != linkHash {
		res.Status = ChainStatusChainBroken
		res.Detail = "prev_checkpoint_hash 與前一點重算值不符"
		return res
	}
	if cp.IDFrom != prev.IDTo+1 {
		// 區間鄰接是 spec 明文要求：不鄰接代表中間有一段 id 不受任何檢查點覆蓋
		res.Status = ChainStatusChainBroken
		res.Detail = fmt.Sprintf("區間不鄰接：前一點 id_to=%d、本點 id_from=%d", prev.IDTo, cp.IDFrom)
	}
	return res
}

// verifyChainHead 鏈頭的錨定判定：genesis 錨 integrity_baselines、
// 修剪後的鏈頭錨修剪記錄。
//
// **鏈頭是攻擊者最想動的地方**（刪掉最舊幾個檢查點就沒有人能證明那段資料
// 曾存在）。故鏈頭必須指得出它接在什麼東西後面：不是 seq=1 又沒有修剪記錄
// 就是 seq_gap，不接受「鏈本來就從這裡開始」的說法
func (v *CheckpointVerifier) verifyChainHead(cp model.AuditCheckpoint,
	trim *model.AuditCheckpointTrim, res ChainPointResult) ChainPointResult {
	if trim != nil && trim.LastTrimmedSeq+1 == cp.Seq {
		ok, err := v.purger.VerifyTrim(trim)
		if err != nil || !ok {
			res.Status = ChainStatusSeqGap
			res.Detail = "鏈頭修剪記錄簽章驗不過"
			return res
		}
		if cp.PrevCheckpointHash != trim.LastTrimmedLinkHash {
			res.Status = ChainStatusChainBroken
			res.Detail = "鏈頭 prev_checkpoint_hash 與修剪記錄的錨不符"
		}
		return res
	}
	if cp.Seq != 1 {
		res.Status = ChainStatusSeqGap
		res.Detail = fmt.Sprintf("鏈頭 seq=%d 既非 genesis 亦無對應的修剪記錄", cp.Seq)
		return res
	}
	var baseline model.IntegrityBaseline
	if err := v.db.First(&baseline, 1).Error; err != nil {
		res.Status = ChainStatusChainBroken
		res.Detail = "完整性基準不可讀，genesis 無錨可驗"
		return res
	}
	want, err := CheckpointGenesisPrevHash(baseline.MaxLogID, baseline.BaselineAt)
	if err != nil {
		res.Status = ChainStatusChainBroken
		res.Detail = err.Error()
		return res
	}
	if cp.PrevCheckpointHash != want {
		res.Status = ChainStatusChainBroken
		res.Detail = "genesis 的 prev_checkpoint_hash 與完整性基準重算值不符"
	}
	return res
}

// IntervalReport 內容層逐區間結果（結構層欄位一併帶出，供 UI 單表呈現）
type IntervalReport struct {
	ChainPointResult
	RemainRows     int64  `json:"remain_rows"`
	InvalidHMACIDs []uint `json:"invalid_hmac_ids,omitempty"`
}

// ContentReport 內容層報告
type ContentReport struct {
	SeqFrom   uint             `json:"seq_from"`
	SeqTo     uint             `json:"seq_to"`
	Intervals []IntervalReport `json:"intervals"`
	// StatusCounts 各狀態的區間數（UI 總覽）
	StatusCounts map[string]int64 `json:"status_counts"`
}

// VerifyContentBySeq 內容層驗證（必須帶 seq 範圍）。
//
// 每個區間先跑結構層判定：一個 chain_broken／seq_gap 的檢查點，其 id 區間
// 主張本身就不可信，再去重掃它宣稱的範圍只會產生誤導性的內容層結論
func (v *CheckpointVerifier) VerifyContentBySeq(seqFrom, seqTo uint) (*ContentReport, error) {
	if seqFrom == 0 || seqTo == 0 || seqFrom > seqTo {
		return nil, ErrCheckpointRangeRequired
	}
	var chain []model.AuditCheckpoint
	if err := v.db.Order("seq ASC").Find(&chain).Error; err != nil {
		return nil, fmt.Errorf("讀取檢查點鏈失敗: %w", err)
	}
	trim, err := v.purger.LatestTrim()
	if err != nil {
		return nil, err
	}
	policyDays := 0
	if v.policy != nil {
		policyDays = v.policy.GetInt(policy.PolicyRetentionAuditLogDays)
	}

	report := &ContentReport{SeqFrom: seqFrom, SeqTo: seqTo,
		Intervals: []IntervalReport{}, StatusCounts: map[string]int64{}}
	for i := range chain {
		cp := chain[i]
		if cp.Seq < seqFrom || cp.Seq > seqTo {
			continue
		}
		item := IntervalReport{ChainPointResult: v.verifyChainPoint(chain, i, trim)}
		if item.Status == IntervalStatusPassed {
			content, err := v.purger.VerifyIntervalContent(&cp, policyDays, v.intervalDeps())
			if err != nil {
				return nil, err
			}
			item.Status = content.Status
			item.RemainRows = content.RemainRows
			item.InvalidHMACIDs = content.InvalidHMACIDs
		}
		report.StatusCounts[item.Status]++
		report.Intervals = append(report.Intervals, item)
	}
	return report, nil
}

// intervalDeps 內容層的兩個依賴（聚合與列級 HMAC）。
//
// integrity 為 nil 時 RowHMAC 回錯而非「一律有效」——後者會讓
// extra_rows_valid_hmac 在無驗證能力的部署上變成無根據的背書
func (v *CheckpointVerifier) intervalDeps() IntervalVerifyDeps {
	return IntervalVerifyDeps{
		Aggregate: func(idFrom, idTo uint) (string, int64, error) {
			h, n, _, _, err := v.seal.Aggregate(idFrom, idTo)
			return h, n, err
		},
		RowHMAC: func(idFrom, idTo uint) (bool, []uint, error) {
			if v.integrity == nil {
				return false, nil, errors.New("列級完整性服務未注入：無法判定多出列的真偽")
			}
			rep, err := v.integrity.VerifyIDRange(v.db, idFrom, idTo)
			if err != nil {
				return false, nil, err
			}
			return rep.Mismatched == 0, rep.MismatchedIDs, nil
		},
	}
}

// SeqRangeByTime 日期區間 → seq 區間的近似映射（D1：時間映射為近似，
// 精確定位以 id 為準）。
//
// 選取規則＝spec 明文：`sealed_at` 或 `[min_created_at, max_created_at]`
// 與查詢範圍相交的全部檢查點。查無相交回 (0,0,nil)，呼叫端據此回空結果
// 而非把它當成「全鏈」——把空範圍放大成全歷史正是 8.2 要擋的事
func (v *CheckpointVerifier) SeqRangeByTime(from, to time.Time) (uint, uint, error) {
	var row struct {
		MinSeq *uint
		MaxSeq *uint
	}
	err := v.db.Model(&model.AuditCheckpoint{}).
		Select("MIN(seq) AS min_seq, MAX(seq) AS max_seq").
		Where("(sealed_at >= ? AND sealed_at < ?) OR "+
			"(min_created_at IS NOT NULL AND min_created_at < ? AND max_created_at >= ?)",
			from, to, to, from).
		Scan(&row).Error
	if err != nil {
		return 0, 0, fmt.Errorf("時間映射檢查點失敗: %w", err)
	}
	if row.MinSeq == nil || row.MaxSeq == nil {
		return 0, 0, nil
	}
	return *row.MinSeq, *row.MaxSeq, nil
}

// List 檢查點列表（seq 倒序、分頁）
func (v *CheckpointVerifier) List(offset, limit int) ([]model.AuditCheckpoint, int64, error) {
	var total int64
	if err := v.db.Model(&model.AuditCheckpoint{}).Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("計數檢查點失敗: %w", err)
	}
	var rows []model.AuditCheckpoint
	if err := v.db.Order("seq DESC").Offset(offset).Limit(limit).Find(&rows).Error; err != nil {
		return nil, 0, fmt.Errorf("查詢檢查點失敗: %w", err)
	}
	return rows, total, nil
}
