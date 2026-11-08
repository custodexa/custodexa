package audit

import (
	"fmt"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// LegacyTrimForTest 造出載有未驗證段數的修剪記錄，供權限起點判定的相容測試使用；
// 現行 TrimChain 不會產生這種記錄。
func LegacyTrimForTest(p *CheckpointPurger, days int) (int64, *model.AuditCheckpointTrim, error) {
	cutoff := p.now().UTC().AddDate(0, 0, -days)
	var trim *model.AuditCheckpointTrim
	err := p.db.Transaction(func(tx *gorm.DB) error {
		var chain []model.AuditCheckpoint
		if err := tx.Order("seq ASC").Find(&chain).Error; err != nil {
			return err
		}
		if len(chain) <= 1 {
			return nil
		}
		prev, err := latestTrimTx(tx)
		if err != nil {
			return err
		}
		cut := -1
		for i := 0; i < len(chain)-1; i++ {
			cp := chain[i]
			if i > 0 && cp.Seq != chain[i-1].Seq+1 {
				break
			}
			if !cp.SealedAt.UTC().Before(cutoff) {
				break
			}
			if cp.RowCount > 0 && cp.PurgedAt == nil {
				break
			}
			cut = i
		}
		if cut < 0 {
			return nil
		}
		baseline, err := readIntegrityBaseline(tx)
		if err != nil {
			return err
		}
		inherited := checkpointChainStructure(chain, prev, baseline, p.signer).HeadHistory
		segment, unverified := model.TrimPermHistoryNone, int64(0)
		for i := 0; i <= cut; i++ {
			cp := &chain[i]
			if _, ok := checkpointPointSignature(cp, p.signer); !ok {
				unverified++
			}
			if checkpointHasAnyPermColumn(cp) {
				segment = maxTrimPermHistory(segment, model.TrimPermHistoryAttested)
			}
		}
		if unverified > 0 {
			segment = model.TrimPermHistoryUnverified
		}
		link := ""
		if _, ok := checkpointPointSignature(&chain[cut], p.signer); ok {
			l, err := CheckpointLinkHash(&chain[cut])
			if err != nil {
				return err
			}
			link = l
		} else if _, ok := checkpointPointSignature(&chain[cut+1], p.signer); ok {
			link = chain[cut+1].PrevCheckpointHash
		} else {
			return nil
		}
		genesisIDFrom := chain[0].IDFrom
		for i := range chain {
			if chain[i].IDFrom < genesisIDFrom {
				genesisIDFrom = chain[i].IDFrom
			}
		}
		if prev != nil {
			genesisIDFrom = prev.GenesisIDFrom
		}
		history := maxTrimPermHistory(inherited, segment)
		trim = &model.AuditCheckpointTrim{
			FromSeq: chain[0].Seq, LastTrimmedSeq: chain[cut].Seq, TrimmedCount: int64(cut + 1),
			LastTrimmedLinkHash: link, GenesisIDFrom: genesisIDFrom, PolicyDays: days,
			TrimmedAt: p.now().UTC().Truncate(time.Microsecond), Format: model.CheckpointTrimFormatV2,
			PermHistory: &history, UnverifiedCount: &unverified,
		}
		payload, err := CheckpointTrimSignBytes(trim)
		if err != nil {
			return err
		}
		version, sig := p.signer.Sign(payload)
		if version <= 0 || sig == "" {
			return fmt.Errorf("legacy trim sign failed")
		}
		trim.SigningKeyVersion, trim.Signature = version, sig
		res := tx.Exec("DELETE FROM audit_checkpoints WHERE seq >= ? AND seq <= ?", trim.FromSeq, trim.LastTrimmedSeq)
		if res.Error != nil {
			return res.Error
		}
		return tx.Create(trim).Error
	})
	if err != nil || trim == nil {
		return 0, nil, err
	}
	return trim.TrimmedCount, trim, nil
}
