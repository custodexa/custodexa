package audit

import (
	"errors"
	"fmt"

	"github.com/custodexa/backend/internal/model"
)

// 結構層逐點驗證的共用純函式。
//
// 驗證頁（VerifyChain）、權限起點判定（permissionLineage）與鏈修剪（TrimChain 的前錨承接）
// 都呼叫同一個函式，保證「起點計算所信的結構」與「驗證頁顯示的結構」是同一個答案。
// 函式內不碰任何資料庫：鏈、最新修剪錨與完整性基準由呼叫端在同一個交易內讀入後傳進來，
// 讀取失敗由呼叫端先回錯（不把讀不到當成沒有）。

// chainStructure 整條鏈的結構層結果。Points 與輸入鏈逐一對齊。
type chainStructure struct {
	Points []ChainPointResult
	// HeadHistory 鏈頭之前的累計權限事實（none／attested／unverified），依修剪錨承接規則判定：
	// 鏈頭是 genesis 且無修剪錨→none；接在驗過章、接得上鏈頭的修剪錨之後→該錨的值（舊格式視同 none）；
	// 其餘（錨被刪、被改、被換成不接鏈頭的舊錨、未知格式、鏈頭自身驗不過）→unverified。
	HeadHistory string
}

// allPassed 每一點都通過（空鏈視為成立）。
func (s chainStructure) allPassed() bool {
	for _, p := range s.Points {
		if p.Status != IntervalStatusPassed {
			return false
		}
	}
	return true
}

// checkpointChainStructure 逐點判定：載荷重建 → 簽章（以該點載荷內的版本重建）→ 鏈頭錨定／
// 版本序不遞減 → seq 連續 → 鏈接（prev hash 與區間鄰接、帳本鄰接）→ 附證形狀。
// 簽章不過時後者不必再判——一個驗不過的檢查點，它的 seq 與 id_from 都是攻擊者寫的。
func checkpointChainStructure(chain []model.AuditCheckpoint, trim *model.AuditCheckpointTrim,
	baseline *model.IntegrityBaseline, signer permissionSigner) chainStructure {
	out := chainStructure{Points: make([]ChainPointResult, len(chain)), HeadHistory: model.TrimPermHistoryNone}
	if len(chain) == 0 {
		if trim != nil {
			out.HeadHistory = model.TrimPermHistoryUnverified
		}
		return out
	}
	sawAttestation := false
	for i := range chain {
		cp := &chain[i]
		res, sigOK := checkpointPointSignature(cp, signer)
		if i == 0 {
			status, detail, history := anchorChainHead(cp, sigOK, trim, baseline, signer)
			out.HeadHistory = history
			if sigOK && status != IntervalStatusPassed {
				res.Status, res.Detail = status, detail
			}
		} else if sigOK {
			res = checkpointPointLink(&chain[i-1], cp, res)
		}
		if res.Status == IntervalStatusPassed {
			res = checkpointPointAttestationShape(cp, res, sawAttestation, out.HeadHistory)
		}
		if checkpointHasAnyPermColumn(cp) {
			sawAttestation = true
		}
		out.Points[i] = res
	}
	return out
}

func newChainPointResult(cp *model.AuditCheckpoint) ChainPointResult {
	return ChainPointResult{
		Seq: cp.Seq, IDFrom: cp.IDFrom, IDTo: cp.IDTo, RowCount: cp.RowCount,
		SealedAt: cp.SealedAt, AnchorStatus: cp.AnchorStatus, PurgedAt: cp.PurgedAt,
		Status: IntervalStatusPassed,
	}
}

// checkpointPointSignature 載荷重建與驗章。回傳的布林＝簽章驗過。
//
// 載荷建不出來與簽章驗不過是兩件事（見 IntervalStatusPayloadInvalid）：結構層與內容層
// 對同一個檢查點必須給同一個答案，否則兩份報表互相矛盾
func checkpointPointSignature(cp *model.AuditCheckpoint, signer permissionSigner) (ChainPointResult, bool) {
	res := newChainPointResult(cp)
	payload, err := CheckpointSignBytes(cp)
	if err != nil {
		res.Status = IntervalStatusSignatureInvalid
		if errors.Is(err, ErrCheckpointPayloadInvalid) {
			res.Status = IntervalStatusPayloadInvalid
		}
		res.Detail = err.Error()
		return res, false
	}
	if signer == nil {
		res.Status, res.Detail = IntervalStatusSignatureInvalid, "未注入檢查點驗章能力"
		return res, false
	}
	ok, err := signer.Verify(cp.SigningKeyVersion, payload, cp.Signature)
	if err != nil || !ok {
		res.Status = IntervalStatusSignatureInvalid
		res.Detail = fmt.Sprintf("簽章驗證失敗（鑰版本 v%d）", cp.SigningKeyVersion)
		if err != nil {
			res.Detail = fmt.Sprintf("%s: %v", res.Detail, err)
		}
		return res, false
	}
	return res, true
}

// checkpointPointLink 非鏈頭點與前一點的關係：版本序、seq、鏈接、區間與帳本鄰接。
func checkpointPointLink(prev, cp *model.AuditCheckpoint, res ChainPointResult) ChainPointResult {
	if checkpointSchemeRank(cp.AggScheme) < checkpointSchemeRank(prev.AggScheme) {
		res.Status = IntervalStatusPayloadInvalid
		res.Detail = fmt.Sprintf("checkpoint scheme downgrade: %s after %s", cp.AggScheme, prev.AggScheme)
		return res
	}
	if cp.Seq != prev.Seq+1 {
		res.Status = ChainStatusSeqGap
		res.Detail = fmt.Sprintf("seq 不連續：前一點 seq=%d", prev.Seq)
		return res
	}
	linkHash, err := CheckpointLinkHash(prev)
	if err != nil {
		res.Status, res.Detail = ChainStatusChainBroken, err.Error()
		return res
	}
	if cp.PrevCheckpointHash != linkHash {
		res.Status, res.Detail = ChainStatusChainBroken, "prev_checkpoint_hash 與前一點重算值不符"
		return res
	}
	if cp.IDFrom != prev.IDTo+1 {
		// 區間鄰接是 spec 明文要求：不鄰接代表中間有一段 id 不受任何檢查點覆蓋
		res.Status = ChainStatusChainBroken
		res.Detail = fmt.Sprintf("區間不鄰接：前一點 id_to=%d、本點 id_from=%d", prev.IDTo, cp.IDFrom)
	}
	if checkpointHasLedger(cp.AggScheme) {
		want := uint(1)
		if checkpointHasLedger(prev.AggScheme) && prev.ToolCallIDTo != nil {
			want = *prev.ToolCallIDTo + 1
		}
		if *cp.ToolCallIDFrom != want {
			res.Status = ChainStatusChainBroken
			res.Detail = fmt.Sprintf("ledger interval not adjacent: want from=%d got=%d", want, *cp.ToolCallIDFrom)
		}
	}
	return res
}

// checkpointPointAttestationShape 驗得過的點在附證形狀上的產品缺陷訊號（attestation_invalid）：
// 第四版之前的點帶附證欄（那些欄不在其簽章內）；或啟用後（鏈上已有更早的附證點、或修剪錨記載
// 曾有附證／曾有驗不過的點）又出現不帶附證的第四版點。
func checkpointPointAttestationShape(cp *model.AuditCheckpoint, res ChainPointResult, sawAttestation bool, headHistory string) ChainPointResult {
	if cp.AggScheme != model.AggSchemeV4 {
		if checkpointHasAnyPermColumn(cp) {
			res.Status, res.Detail = IntervalStatusAttestationInvalid, "第四版之前的檢查點帶權限附證欄（不在其簽章內）"
		}
		return res
	}
	if !checkpointHasAnyPermColumn(cp) && (sawAttestation || headHistory != model.TrimPermHistoryNone) {
		res.Status, res.Detail = IntervalStatusAttestationInvalid, "啟用後的第四版檢查點不帶權限附證"
	}
	return res
}

// anchorChainHead 鏈頭的錨定判定與修剪錨承接：genesis 錨 integrity_baselines、修剪後的鏈頭錨修剪記錄。
// 回傳結構層狀態、說明與鏈頭之前的累計權限事實。
//
// **鏈頭是攻擊者最想動的地方**（刪掉最舊幾個檢查點就沒有人能證明那段資料曾存在）。故鏈頭必須
// 指得出它接在什麼東西後面：不是 seq=1 又沒有修剪記錄就是 seq_gap，不接受「鏈本來就從這裡開始」
// 的說法；證明不了之前的歷史時，累計事實一律帶成 unverified。
func anchorChainHead(head *model.AuditCheckpoint, headSigOK bool, trim *model.AuditCheckpointTrim,
	baseline *model.IntegrityBaseline, signer permissionSigner) (string, string, string) {
	history := func(h string) string {
		if !headSigOK {
			return model.TrimPermHistoryUnverified
		}
		return h
	}
	unverified := model.TrimPermHistoryUnverified
	if trim != nil && trim.LastTrimmedSeq+1 == head.Seq {
		if !checkpointTrimSignatureValid(trim, signer) {
			return ChainStatusSeqGap, "鏈頭修剪記錄簽章驗不過", unverified
		}
		if head.PrevCheckpointHash != trim.LastTrimmedLinkHash {
			return ChainStatusChainBroken, "鏈頭 prev_checkpoint_hash 與修剪記錄的錨不符", unverified
		}
		return IntervalStatusPassed, "", history(checkpointTrimHistory(trim))
	}
	if head.Seq != 1 {
		return ChainStatusSeqGap, fmt.Sprintf("鏈頭 seq=%d 既非 genesis 亦無對應的修剪記錄", head.Seq), unverified
	}
	if baseline == nil {
		return ChainStatusChainBroken, "完整性基準不可讀，genesis 無錨可驗", unverified
	}
	want, err := CheckpointGenesisPrevHash(baseline.MaxLogID, baseline.BaselineAt)
	if err != nil {
		return ChainStatusChainBroken, err.Error(), unverified
	}
	if head.PrevCheckpointHash != want {
		return ChainStatusChainBroken, "genesis 的 prev_checkpoint_hash 與完整性基準重算值不符", unverified
	}
	if trim != nil {
		// 鏈頭是 genesis 卻有修剪錨：錨記載的被剪段接不上現存鏈，證明不了之前的歷史
		return IntervalStatusPassed, "", unverified
	}
	return IntervalStatusPassed, "", history(model.TrimPermHistoryNone)
}

// checkpointTrimSignatureValid 修剪錨簽章可驗（未知格式、載荷建不出、驗章能力未注入或回錯皆為 false）。
func checkpointTrimSignatureValid(trim *model.AuditCheckpointTrim, signer permissionSigner) bool {
	if signer == nil {
		return false
	}
	payload, err := CheckpointTrimSignBytes(trim)
	if err != nil {
		return false
	}
	ok, err := signer.Verify(trim.SigningKeyVersion, payload, trim.Signature)
	return err == nil && ok
}

// checkpointTrimHistory 已驗過章的修剪錨所記載的累計事實：舊格式視同 none；
// 第二版取其枚舉值，值域外（理論上已被簽章擋下）一律 unverified。
func checkpointTrimHistory(trim *model.AuditCheckpointTrim) string {
	if trim.Format == model.CheckpointTrimFormatV1 {
		return model.TrimPermHistoryNone
	}
	if trim.PermHistory != nil && trimPermHistoryRank(*trim.PermHistory) > 0 {
		return *trim.PermHistory
	}
	return model.TrimPermHistoryUnverified
}

// trimPermHistoryRank none < attested < unverified；值域外為 0。
func trimPermHistoryRank(h string) int {
	switch h {
	case model.TrimPermHistoryNone:
		return 1
	case model.TrimPermHistoryAttested:
		return 2
	case model.TrimPermHistoryUnverified:
		return 3
	}
	return 0
}

// maxTrimPermHistory 累計單調：取兩者較高者。
func maxTrimPermHistory(a, b string) string {
	if trimPermHistoryRank(b) > trimPermHistoryRank(a) {
		return b
	}
	return a
}
