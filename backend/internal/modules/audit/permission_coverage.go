package audit

import (
	"errors"
	"fmt"
	"strings"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 權限附證的起點判定（lineage）。
//
// 威脅模型：持資料庫帳密者可任意讀寫刪任何表，但沒有審計完整性密鑰與檢查點簽章私鑰。
// 因此任何把狀態推向「尚未涵蓋」或「可信基準」的事實，都只能來自**驗章通過的載荷**：
// 現存每一點的載荷（第四版起附證在其中，含起點旗標）與修剪錨的載荷（被剪段的累計事實）。
// 事件表、附證欄是否為空、資料庫欄位的版本標示，都不是往「可信」方向的判定輸入。
//
//   - 尚未涵蓋（clean）：沒有任何附證痕跡、整條現存鏈逐點驗章通過、修剪歷史為 none、事件表為空。
//     只有這時封章才會把起點旗標寫成 true。
//   - 候選基準：第四版、附證欄齊、重建成功、簽章驗過，且（封章當下對帳相符或為起點）的點。
//     起點的形狀只有一種：origin=true、reconciled=null，所以候選判定保留對帳結果的三態。
//   - 其餘找不到可信基準的情況一律「無法判定」並開單。

// permAttestAnyColumn 任一權限附證欄非空（部分清空也算痕跡）；與部分索引的述詞逐字相同。
const permAttestAnyColumn = model.CheckpointPermTracePredicate

// permissionCandidate 驗章通過的第四版附證點。
type permissionCandidate struct {
	cp   model.AuditCheckpoint
	perm *checkpointPermEntry
}

// permissionLineage 起點判定所需的事實（一次讀齊）。
type permissionLineage struct {
	anyPermColumn bool
	chainEmpty    bool
	// cleanChain 整條現存鏈逐點驗章通過（只在沒有任何附證痕跡時計算；有痕跡時 clean 已不成立）
	cleanChain bool
	chainFail  string // 第一個結構失敗點（原因字串用）
	// trimHistory 鏈頭之前的累計權限事實（none／attested／unverified）
	trimHistory string
	// candidates 第四版、重建成功、簽章驗過的附證點（seq 降冪；對帳結果三態保留）
	candidates       []permissionCandidate
	payloadInvalid   int // 第四版但附證欄部分為 NULL 或出值域
	signatureInvalid int // 第四版重建成功但簽章驗不過
	traces           int // 第四版之前卻帶附證欄
	eventsExist      bool
	latestCpSeq      uint
}

// readPermissionLineage 讀齊起點判定的事實。任何讀取失敗都回錯（呼叫端判無法判定），
// 不以「讀不到」當作「沒有」：附證欄與事件表由同一次遷移建立，事件表不存在即為異常。
func readPermissionLineage(tx *gorm.DB, signer permissionSigner) (*permissionLineage, error) {
	if signer == nil {
		return nil, errors.New("未注入檢查點驗章能力：無法驗證任何附證")
	}
	l := &permissionLineage{}
	if err := tx.Raw(`SELECT EXISTS (SELECT 1 FROM audit_checkpoints WHERE ` + permAttestAnyColumn + `)`).Scan(&l.anyPermColumn).Error; err != nil {
		return nil, fmt.Errorf("讀取權限附證失敗: %w", err)
	}
	trim, err := latestTrimTx(tx)
	if err != nil {
		return nil, err
	}
	baseline, err := readIntegrityBaseline(tx)
	if err != nil {
		return nil, err
	}
	if l.anyPermColumn {
		if err := l.classifyTraces(tx, signer); err != nil {
			return nil, err
		}
		var head []model.AuditCheckpoint
		if err := tx.Order("seq ASC").Limit(1).Find(&head).Error; err != nil {
			return nil, fmt.Errorf("讀取檢查點鏈頭失敗: %w", err)
		}
		l.trimHistory = checkpointChainStructure(head, trim, baseline, signer).HeadHistory
	} else {
		var chain []model.AuditCheckpoint
		if err := tx.Order("seq ASC").Find(&chain).Error; err != nil {
			return nil, fmt.Errorf("讀取檢查點鏈失敗: %w", err)
		}
		l.chainEmpty = len(chain) == 0
		st := checkpointChainStructure(chain, trim, baseline, signer)
		l.cleanChain, l.trimHistory = st.allPassed(), st.HeadHistory
		for _, p := range st.Points {
			if p.Status != IntervalStatusPassed {
				l.chainFail = fmt.Sprintf("seq=%d %s", p.Seq, p.Status)
				break
			}
		}
	}
	if !permissionEventsTableExists(tx) {
		return nil, fmt.Errorf("%w: 權限狀態事件表不存在", ErrPermissionEventChain)
	}
	var first []model.PermissionStateEvent
	if err := tx.Order("seq ASC").Limit(1).Find(&first).Error; err != nil {
		return nil, fmt.Errorf("讀取權限狀態事件失敗: %w", err)
	}
	l.eventsExist = len(first) > 0
	var tail []model.AuditCheckpoint
	if err := tx.Order("seq DESC").Limit(1).Find(&tail).Error; err != nil {
		return nil, fmt.Errorf("讀取檢查點鏈尾失敗: %w", err)
	}
	if len(tail) > 0 {
		l.latestCpSeq = tail[0].Seq
	}
	return l, nil
}

// classifyTraces 讀所有帶痕跡的列（六欄任一非 NULL，不分版本、不要求欄位齊、不預先篩對帳結果），
// 逐列交唯一重建器分四桶。不得用「六欄非 NULL」當讀取條件：唯一合法起點的對帳結果為 null。
func (l *permissionLineage) classifyTraces(tx *gorm.DB, signer permissionSigner) error {
	var rows []model.AuditCheckpoint
	if err := tx.Where(permAttestAnyColumn).Order("seq DESC").Find(&rows).Error; err != nil {
		return fmt.Errorf("讀取權限附證失敗: %w", err)
	}
	for i := range rows {
		cp := rows[i]
		if cp.AggScheme != model.AggSchemeV4 {
			// 第四版之前的點不簽附證欄：帶任一欄即為痕跡（預發行資料或外人插入），永不成為候選
			l.traces++
			continue
		}
		perm, err := checkpointPermFromColumns(&cp)
		if err != nil {
			l.payloadInvalid++
			continue
		}
		res, ok := checkpointPointSignature(&cp, signer)
		if !ok {
			if res.Status == IntervalStatusPayloadInvalid {
				l.payloadInvalid++
			} else {
				l.signatureInvalid++
			}
			continue
		}
		l.candidates = append(l.candidates, permissionCandidate{cp: cp, perm: perm})
	}
	return nil
}

// latestTrimTx 最新修剪錨（同一交易內讀）；沒有回 nil。表不存在（只建部分表的測試夾具）視同沒有。
func latestTrimTx(tx *gorm.DB) (*model.AuditCheckpointTrim, error) {
	if !tx.Migrator().HasTable(&model.AuditCheckpointTrim{}) {
		return nil, nil
	}
	var rows []model.AuditCheckpointTrim
	if err := tx.Order("last_trimmed_seq DESC").Limit(1).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("讀取鏈修剪記錄失敗: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}

// clean 能以驗過章的事實證明「此前從未有附證」：無附證痕跡、整條現存鏈逐點驗章通過、
// 修剪歷史為 none、事件表為空。鏈為空時即「無修剪錨、無事件」。
func (l *permissionLineage) clean() bool {
	return !l.anyPermColumn && l.cleanChain && l.trimHistory == model.TrimPermHistoryNone && !l.eventsExist
}

// base 候選基準：驗章通過且（封章當下相符或為起點）的點中 seq 最大者；沒有回 nil。
func (l *permissionLineage) base() *permissionCandidate {
	for i := range l.candidates {
		c := &l.candidates[i]
		if c.perm.Origin || (c.perm.Reconciled != nil && *c.perm.Reconciled) {
			return c
		}
	}
	return nil
}

// noBaseReason 找不到可信基準時寫進錯誤的原因（不帶個資，供告警與重設審計摘要）。
func (l *permissionLineage) noBaseReason() string {
	var parts []string
	if l.anyPermColumn {
		parts = append(parts, "有附證痕跡但無可信基準")
	}
	if l.payloadInvalid > 0 {
		parts = append(parts, fmt.Sprintf("第四版檢查點載荷無法重建 %d 點", l.payloadInvalid))
	}
	if l.signatureInvalid > 0 {
		parts = append(parts, fmt.Sprintf("第四版檢查點簽章驗不過 %d 點", l.signatureInvalid))
	}
	if l.traces > 0 {
		parts = append(parts, fmt.Sprintf("第四版之前的檢查點帶附證欄 %d 點", l.traces))
	}
	if !l.anyPermColumn && !l.cleanChain {
		parts = append(parts, "現存鏈結構驗證失敗（"+l.chainFail+"）")
	}
	switch l.trimHistory {
	case model.TrimPermHistoryAttested:
		parts = append(parts, "修剪錨記載曾有附證")
	case model.TrimPermHistoryUnverified:
		parts = append(parts, "修剪錨記載曾有驗不過的點")
	}
	if l.eventsExist && !l.anyPermColumn {
		parts = append(parts, "事件紀錄非空但鏈上無附證")
	}
	if len(parts) == 0 {
		parts = append(parts, "找不到可信基準")
	}
	return strings.Join(parts, "；")
}
