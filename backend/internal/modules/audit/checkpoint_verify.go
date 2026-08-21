package audit

import (
	"fmt"

	"github.com/custodexa/backend/internal/model"
)

// 內容層逐區間驗證狀態（audit-checkpoint-chain D10）。
//
// **本檔只做「單一區間的內容層」判定**——結構層（chain_broken／seq_gap，需要
// 整條鏈）在 checkpoint_chain_verify.go。分開的理由是第 6 組必須能自證
// 「合法清除流程在任何失敗組合下都不產生竄改告警」（tasks 6.13），
// 而那個自證不能等到 API 層才有。
const (
	// IntervalStatusPassed 區間列完整且聚合相符
	IntervalStatusPassed = "passed"
	// IntervalStatusPurgedLegal 列已不存在，且 tombstone 驗過（合法清除）
	IntervalStatusPurgedLegal = "purged_legal"
	// IntervalStatusPurgedInvalid 列已不存在（或已標記清除）但無有效 tombstone。
	// **這就是本組最怕的自傷形態**：系統自己的清除流程若在任何時點留下
	// 半清狀態，驗證端就會對合法清除發出竄改告警
	IntervalStatusPurgedInvalid = "purged_invalid"
	// IntervalStatusCountMismatch 列數短少但非全空，且無 tombstone
	IntervalStatusCountMismatch = "count_mismatch"
	// IntervalStatusHashMismatch 列數相符但聚合雜湊不符（內容或順序被動）；
	// 亦涵蓋「列數多出且其中有列級 HMAC 驗不過者」——多出的列若是偽造的，
	// 那是竄改而非 straggler
	IntervalStatusHashMismatch = "hash_mismatch"
	// IntervalStatusExtraRowsValidHMAC 列數多於封章主張，且**區間內全部列的
	// 列級 HMAC 皆有效**（tasks 8.3 補齊：在此之前本狀態只判「多列」，
	// 名字宣稱的「HMAC 有效」從未被驗過）。
	//
	// 語義＝「多出來的列看起來是合法寫入的」：可能是超過 grace 才 commit 的
	// 長交易（誠實邊界 R1），也可能是持蓋章鑰者插入的列——兩者在本機制內
	// 不可區分，故獨立狀態供人工研判，不判通過也不判竄改
	IntervalStatusExtraRowsValidHMAC = "extra_rows_valid_hmac"
	// IntervalStatusSignatureInvalid 檢查點自身簽章驗不過（其一切主張不可信）
	IntervalStatusSignatureInvalid = "signature_invalid"
)

// IntervalVerifyDeps 內容層驗證的兩個外部能力。
//
// **兩者都是必填**：Aggregate 缺席就無從比對雜湊；RowHMAC 缺席時
// `extra_rows_valid_hmac` 這個狀態的名字會撒謊（它宣稱多出的列 HMAC 有效）。
// 以結構體帶入而非可選參數，是為了讓「少給一個」在編譯期就顯眼
type IntervalVerifyDeps struct {
	// Aggregate 重算區間聚合（雜湊, 列數）
	Aggregate func(idFrom, idTo uint) (string, int64, error)
	// RowHMAC 驗區間內全部列的列級 HMAC；回 (全部有效, 無效列 id 樣本, err)
	RowHMAC func(idFrom, idTo uint) (bool, []uint, error)
}

// IntervalContentResult 單一區間的內容層結果
type IntervalContentResult struct {
	// Status 九態之一（結構層兩態由鏈驗證產生）
	Status string `json:"status"`
	// RemainRows 區間內現存列數
	RemainRows int64 `json:"remain_rows"`
	// InvalidHMACIDs 列級 HMAC 驗不過的列 id 樣本（研判用；上限見整合服務）
	InvalidHMACIDs []uint `json:"invalid_hmac_ids,omitempty"`
}

// VerifyIntervalContent 單一檢查點區間的內容層驗證。
//
// 判定順序刻意如此：先驗檢查點自身簽章（它不可信時 row_count／agg_hash
// 全部不可用），再看 tombstone（已清區間無列可重算），最後才重掃聚合。
func (p *CheckpointPurger) VerifyIntervalContent(cp *model.AuditCheckpoint,
	policyDays int, deps IntervalVerifyDeps) (IntervalContentResult, error) {
	res := IntervalContentResult{}
	if deps.Aggregate == nil || deps.RowHMAC == nil {
		return res, fmt.Errorf("內容層驗證缺依賴（Aggregate=%v RowHMAC=%v）",
			deps.Aggregate != nil, deps.RowHMAC != nil)
	}
	payload, err := CheckpointSignBytes(cp)
	if err != nil {
		return res, err
	}
	ok, err := p.signer.Verify(cp.SigningKeyVersion, payload, cp.Signature)
	if err != nil || !ok {
		res.Status = IntervalStatusSignatureInvalid
		return res, nil
	}

	var remain int64
	if err := p.db.Raw("SELECT COUNT(*) FROM audit_logs WHERE id >= ? AND id <= ?",
		cp.IDFrom, cp.IDTo).Scan(&remain).Error; err != nil {
		return res, fmt.Errorf("計數區間 [%d,%d] 失敗: %w", cp.IDFrom, cp.IDTo, err)
	}
	res.RemainRows = remain

	if cp.PurgedAt != nil {
		valid, err := p.VerifyPurgeTombstone(cp, policyDays)
		if err != nil {
			return res, err
		}
		if !valid {
			res.Status = IntervalStatusPurgedInvalid
			return res, nil
		}
		if remain != 0 {
			// 有 tombstone 卻還有列＝半清（本實作以同一交易排除，
			// 但驗證端不得假設清除端沒有 bug）
			res.Status = IntervalStatusCountMismatch
			return res, nil
		}
		res.Status = IntervalStatusPurgedLegal
		return res, nil
	}

	switch {
	case cp.RowCount > 0 && remain == 0:
		// 列全沒了卻無任何合法性主張——竄改告警
		res.Status = IntervalStatusPurgedInvalid
		return res, nil
	case remain < cp.RowCount:
		res.Status = IntervalStatusCountMismatch
		return res, nil
	case remain > cp.RowCount:
		// **多列必須真的驗列級 HMAC**：狀態名宣稱「HMAC 有效」，
		// 只數列數就掛這個名字等於系統替攻擊者背書
		allValid, badIDs, err := deps.RowHMAC(cp.IDFrom, cp.IDTo)
		if err != nil {
			return res, err
		}
		res.InvalidHMACIDs = badIDs
		if allValid {
			res.Status = IntervalStatusExtraRowsValidHMAC
		} else {
			res.Status = IntervalStatusHashMismatch
		}
		return res, nil
	}

	hash, count, err := deps.Aggregate(cp.IDFrom, cp.IDTo)
	if err != nil {
		return res, err
	}
	if count != cp.RowCount || hash != cp.AggHash {
		res.Status = IntervalStatusHashMismatch
		return res, nil
	}
	res.Status = IntervalStatusPassed
	return res, nil
}
