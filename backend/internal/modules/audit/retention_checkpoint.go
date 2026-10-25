package audit

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// audit_logs 的檢查點區間清除（log-retention spec）。
//
// **為何非改不可**：改造前 retention 是「逐列刪過期列」，驗證端因此無法區分
// 「retention 刪的」與「攻擊者挑過期時段抽列」——攻擊者只要抽夠舊的列就洗白。
// 改為「已封檢查點區間整段清除＋簽章 tombstone」後，列的缺席必須伴隨一個
// 以檢查點私鑰簽的合法性主張，偽造它需要私鑰（誠實邊界 R0）。
//
// **本檔最容易出錯的地方是自傷**：若「列已刪」與「tombstone 已寫」之間存在
// 任何可持久化的窗口，系統就會對自己的合法清除發出竄改告警。故刪除與
// tombstone 一律同一交易，中斷必回滾（spec：SHALL NOT 產生「列已被刪除但無
// 有效 tombstone 已提交」的持久狀態）。

// ErrCheckpointChainAbsent 鏈為空：無 genesis 可界定 pre-genesis 邊界。
//
// **fail-close**：此時既不能走區間路徑（無區間），也不能走無上界的逐列路徑
//（那會刪到本應由區間路徑處理的列，且不留 tombstone＝自製竄改告警）。
// 鏈被整套抹除正是本機制要偵測的攻擊形態，遇到它必須停手並留痕
var ErrCheckpointChainAbsent = errors.New("檢查點鏈為空：audit_logs 清除停手（無 genesis 可界定 pre-genesis 邊界）")

// CheckpointPurger audit_logs 的區間清除引擎。
//
// 與 CheckpointService 分型：封章是「產生證據」，清除是「消滅資料並簽下
// 合法性主張」，兩者的失敗語義相反（封章失敗只是少一個檢查點，清除失敗
// 若留下半清狀態就是永久的證據破口）
type CheckpointPurger struct {
	db     *gorm.DB
	signer checkpointSigner

	// now 時間注入點（tombstone 的 purged_at 進簽章 payload，測試需可控）
	now func() time.Time

	// faults 故障注入點：**僅單元測試設定，生產路徑恆為零值**。
	// 之所以做進生產型別而非以介面包裝：要注入的是「同一交易內部的
	// 特定時點」，包裝層無法在交易中途插入
	faults purgeFaults
}

// purgeFaults 區間清除的交易內故障注入點（測試專用）。
//
// fired 計數是「注入器真的被觸發過」的自證——前置條件早退會造成注入器
// 零觸發卻仍讓測試通過，故須以此計數避免測試靜默失去防護意義
type purgeFaults struct {
	// afterDelete 於區間列刪除之後、tombstone 簽章之前呼叫
	afterDelete func() error
	// beforeTombstoneWrite 於簽章之後、tombstone 落庫之前呼叫
	beforeTombstoneWrite func() error
	// fired 注入器觸發次數
	fired int
}

// NewCheckpointPurger 建立區間清除引擎
func NewCheckpointPurger(db *gorm.DB, signer checkpointSigner) *CheckpointPurger {
	return &CheckpointPurger{db: db, signer: signer, now: time.Now}
}

// GenesisIDFrom pre-genesis 逐列路徑的 id 上界（回傳值 g 代表 `id < g` 為 pre-genesis）。
//
// 取鏈上最小的 id_from；**鏈被修剪過時改取修剪記錄保存的原始值**——
// 修剪會使 MIN(id_from) 上移，若跟著上移，逐列路徑的地盤就會隨每次修剪
// 自動擴張到「曾被檢查點覆蓋、清除語義應由區間路徑決定」的那段 id 上。
//
// 鏈為空時回 ErrCheckpointChainAbsent 而非退回「無上界」——退回無上界
// 會讓逐列路徑刪掉本該由區間路徑處理的列且不留 tombstone
func (p *CheckpointPurger) GenesisIDFrom() (uint, error) {
	var count int64
	if err := p.db.Model(&model.AuditCheckpoint{}).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("計數檢查點失敗: %w", err)
	}
	if count == 0 {
		return 0, ErrCheckpointChainAbsent
	}
	trim, err := p.LatestTrim()
	if err != nil {
		return 0, err
	}
	if trim != nil {
		return trim.GenesisIDFrom, nil
	}
	var idFrom uint
	if err := p.db.Model(&model.AuditCheckpoint{}).
		Select("COALESCE(MIN(id_from), 0)").Scan(&idFrom).Error; err != nil {
		return 0, fmt.Errorf("讀取 genesis id_from 失敗: %w", err)
	}
	return idFrom, nil
}

// LatestTrim 最近一筆鏈修剪記錄（無修剪回 nil, nil）
func (p *CheckpointPurger) LatestTrim() (*model.AuditCheckpointTrim, error) {
	var trim model.AuditCheckpointTrim
	err := p.db.Order("last_trimmed_seq DESC").First(&trim).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("讀取鏈修剪記錄失敗: %w", err)
	}
	return &trim, nil
}

// 區間清除的兩種「不清但也不算執行失敗」的判定（呼叫端跳過該區間續處理下一個）
var (
	// ErrPurgeIntervalRowsMissing 區間內現存列數少於檢查點所簽的 row_count。
	//
	// **必須中止**：少列代表有人已經抽走了列。此時若照清不誤並寫下 tombstone，
	// 驗證端會回報 purged_legal——系統親手把一起竊取洗成合法清除。
	// 中止則列維持現況，驗證回報 count_mismatch，竊取現形
	ErrPurgeIntervalRowsMissing = errors.New("區間現存列數少於檢查點簽章所主張：疑遭抽列，中止清除以保全證據")
	// ErrPurgeIntervalNotFullyExpired 區間內存在 created_at 晚於 cutoff 的列。
	//
	// max_created_at 是封章當下的快照，涵蓋不到封章後才 commit 的 straggler
	//（誠實邊界 R1）。少了本檢查，那些列會因「所屬區間已過期」被提早刪除，
	// 違反 spec「反向偏差（早於保留期刪除）SHALL NOT 發生」
	ErrPurgeIntervalNotFullyExpired = errors.New("區間內仍有未過期列（封章後落地的 straggler）：本輪不清")
)

// PurgeInterval 清除單一檢查點區間：刪除 [id_from, id_to] 全部列並寫下 tombstone。
//
// **刪除與 tombstone 同一交易，中斷必回滾**（log-retention spec）。順序刻意是
// 「先刪光、再簽、再寫 tombstone」：tombstone 主張的是「這些列已不存在」，
// 先簽再刪會讓簽章早於它所主張的事實。任一步失敗都使整個交易回滾，
// 區間留待下輪重試——**絕不留下「列沒了但無有效 tombstone」的持久狀態**，
// 那正是系統對自己發出竄改告警的形態。
func (p *CheckpointPurger) PurgeInterval(cp *model.AuditCheckpoint, policyDays int, cutoff time.Time) (int64, error) {
	if p.signer == nil {
		return 0, errors.New("檢查點簽章鑰未注入：無法簽 tombstone，拒絕清除")
	}
	if cp.IDFrom > cp.IDTo || cp.RowCount <= 0 {
		return 0, fmt.Errorf("拒絕清除空區間 seq=%d [%d,%d] row_count=%d",
			cp.Seq, cp.IDFrom, cp.IDTo, cp.RowCount)
	}
	purgedAt := p.now().UTC().Truncate(time.Microsecond)

	var deleted int64
	err := p.db.Transaction(func(tx *gorm.DB) error {
		// 交易內先驗「無未過期列」——放在交易外會與寫入端競態
		var fresh int64
		if err := tx.Raw(
			"SELECT COUNT(*) FROM audit_logs WHERE id >= ? AND id <= ? AND created_at >= ?",
			cp.IDFrom, cp.IDTo, cutoff).Scan(&fresh).Error; err != nil {
			return fmt.Errorf("檢查 seq=%d 區間未過期列失敗: %w", cp.Seq, err)
		}
		if fresh > 0 {
			return fmt.Errorf("%w: seq=%d 尚有 %d 列未過期", ErrPurgeIntervalNotFullyExpired, cp.Seq, fresh)
		}

		// 原生 SQL 硬刪（與 pre-genesis 逐列路徑同一收口家族，刻意繞
		// BeforeDelete 守衛；此為 audit_logs 僅有的兩條刪除語句之一）
		res := tx.Exec("DELETE FROM audit_logs WHERE id >= ? AND id <= ?", cp.IDFrom, cp.IDTo)
		if res.Error != nil {
			return fmt.Errorf("刪除 seq=%d 區間 [%d,%d] 失敗: %w", cp.Seq, cp.IDFrom, cp.IDTo, res.Error)
		}
		deleted = res.RowsAffected
		if deleted < cp.RowCount {
			return fmt.Errorf("%w: seq=%d 實刪 %d 列、檢查點主張 %d 列",
				ErrPurgeIntervalRowsMissing, cp.Seq, deleted, cp.RowCount)
		}
		if hook := p.faults.afterDelete; hook != nil {
			p.faults.fired++
			if err := hook(); err != nil {
				return err
			}
		}

		payload, err := CheckpointPurgeSignBytes(cp.Seq, purgedAt, cp.RowCount, policyDays)
		if err != nil {
			return err
		}
		version, sig := p.signer.Sign(payload)
		if version <= 0 || sig == "" {
			// 簽章鑰暫時不可用：spec 明列此情形必須整段回滾
			return fmt.Errorf("seq=%d 的 tombstone 簽章失敗（version=%d）：整段回滾", cp.Seq, version)
		}
		if hook := p.faults.beforeTombstoneWrite; hook != nil {
			p.faults.fired++
			if err := hook(); err != nil {
				return err
			}
		}

		// 只認 map 形式（model 白名單守衛拒絕結構體路徑）
		upd := tx.Model(&model.AuditCheckpoint{}).Where("id = ?", cp.ID).
			Updates(map[string]any{
				"purged_at":                 purgedAt,
				"purge_signature":           sig,
				"purge_signing_key_version": version,
				// 簽章的輸入隨簽章一起保存（理由見 VerifyPurgeTombstone）
				"purge_policy_days": policyDays,
			})
		if upd.Error != nil {
			return fmt.Errorf("寫入 seq=%d 的 tombstone 失敗: %w", cp.Seq, upd.Error)
		}
		if upd.RowsAffected != 1 {
			return fmt.Errorf("寫入 seq=%d 的 tombstone 影響 %d 列（應為 1）", cp.Seq, upd.RowsAffected)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

// VerifyPurgeTombstone tombstone 是否為本系統以檢查點私鑰簽出的合法清除主張。
//
// 驗證端據此區分 purged_legal 與 purged_invalid；清除路徑亦用它做重複執行的
// 冪等判定（已有有效 tombstone 者不再處理）
func (p *CheckpointPurger) VerifyPurgeTombstone(cp *model.AuditCheckpoint, policyDays int) (bool, error) {
	if cp.PurgedAt == nil || cp.PurgeSignature == nil || cp.PurgeSigningKeyVersion == nil {
		return false, nil
	}
	// **以清除當下記錄的政策天數重算**，不是現行政策值：
	// policy_days 是簽章的輸入，拿別的值重算等於在驗一個不同的主張——
	// admin 把保留期由 365 改成 730 的那一刻，全部歷史 tombstone 會一起
	// 驗不過而回報 purged_invalid（系統對自己的合法清除發大規模竄改告警）。
	// 缺欄位時退回呼叫端傳入值（升級期相容）
	days := policyDays
	if cp.PurgePolicyDays != nil {
		days = *cp.PurgePolicyDays
	}
	payload, err := CheckpointPurgeSignBytes(cp.Seq, cp.PurgedAt.UTC(), cp.RowCount, days)
	if err != nil {
		return false, err
	}
	return p.signer.Verify(*cp.PurgeSigningKeyVersion, payload, *cp.PurgeSignature)
}

// PurgeableIntervals 可清區間（唯讀；seq 升冪＝最舊優先）。
//
// 四個條件全部成立才可清（log-retention spec「audit_logs 以檢查點區間為清除單位」）：
//
//	row_count > 0        空區間無列可刪；對它寫 tombstone 等於在鏈上簽下一個
//	                     從未發生的清除。自然產生的空區間 max_created_at 為 NULL
//	                     已被下一條擋掉，本條是對「直寫 DB 或未來 scheme 漂移」
//	                     造出的畸形列的第二道閘（兩道獨立，不是同一條件的重寫）
//	purged_at IS NULL    已清區間不重複處理（重複刪除會覆寫 tombstone 時戳）
//	max_created_at <     整區間過期才清。NULL（空區間）不滿足此比較，
//	  cutoff             故自然空區間在此即被排除
//	簽章有效             簽章驗不過的檢查點可能已被竄改，其 id 區間主張不可信；
//	                     依它刪列等於照著攻擊者給的範圍銷毀證據
func (p *CheckpointPurger) PurgeableIntervals(cutoff time.Time) ([]model.AuditCheckpoint, error) {
	if p.signer == nil {
		return nil, errors.New("檢查點簽章鑰未注入：無法判定區間可清性，拒絕清除")
	}
	var candidates []model.AuditCheckpoint
	err := p.db.
		Where("row_count > 0").
		Where("purged_at IS NULL").
		Where("max_created_at IS NOT NULL AND max_created_at < ?", cutoff).
		Order("seq ASC").Find(&candidates).Error
	if err != nil {
		return nil, fmt.Errorf("查詢可清區間失敗: %w", err)
	}

	out := make([]model.AuditCheckpoint, 0, len(candidates))
	for i := range candidates {
		cp := candidates[i]
		if cp.IDFrom > cp.IDTo {
			// row_count>0 卻是空區間＝記錄自相矛盾，不碰
			log.Printf("[Retention] 檢查點 seq=%d 區間矛盾（id_from=%d > id_to=%d），跳過清除",
				cp.Seq, cp.IDFrom, cp.IDTo)
			continue
		}
		payload, err := CheckpointSignBytes(&cp)
		if err != nil {
			return nil, err
		}
		ok, err := p.signer.Verify(cp.SigningKeyVersion, payload, cp.Signature)
		if err != nil || !ok {
			log.Printf("[Retention] 檢查點 seq=%d 簽章不可驗（err=%v），跳過清除（其區間主張不可信）",
				cp.Seq, err)
			continue
		}
		out = append(out, cp)
	}
	return out, nil
}

// TrimChain 依 retention_checkpoint_days 自鏈頭（最舊 seq）起連續修剪檢查點。
//
// 回傳被修剪的檢查點數與修剪記錄（未修剪時 (0, nil, nil)）。
//
// 三條不可退讓的約束（log-retention spec「檢查點自身的保留與鏈修剪」）：
//
//  1. **只自鏈頭連續修剪**。自中段挖除必造成無法解釋的 seq 斷洞——那正是
//     攻擊者刪檢查點時留下的形狀，系統自己不得製造同形狀的東西。
//  2. **仍覆蓋現存列的檢查點絕不修剪**。修剪它會讓那些列變成「無檢查點覆蓋
//     也非 pre-genesis」的孤兒段，其缺失日後既不可證為合法清除也不可證為竄改。
//     此約束不依賴跨鍵政策驗證（第 7 組），即使政策被 SQL 直改成違規值也成立。
//  3. **至少留一個檢查點**。全數修剪＝鏈為空＝GenesisIDFrom fail-close，
//     audit_logs 清除會整個停擺。
//
// 修剪錨（第二版）以簽章帶走被剪段的累計權限事實：被剪段曾有附證→至少 attested；曾有驗不過的點
// →unverified；並承接前一錨（只承接驗過章且接得上現存鏈頭者，證明不了就帶 unverified）。累計單調，
// 修剪因此不會讓原本沒有可信起點的狀態自行獲得起點。錨值取自簽章可驗的邊界：被剪最後一點驗得過就
// 以它重算，否則取殘鏈新鏈頭簽章內的 prev_checkpoint_hash（新鏈頭須驗得過）；兩者皆驗不過本輪不剪。
//
// 讀前錨、讀鏈、逐點驗章、簽章、刪除、寫入錨在同一交易內以同一份輸入完成；PG 上交易開頭對修剪錨表
// 取 SHARE ROW EXCLUSIVE 表鎖，兩個並行修剪因此序列化（後者看得到前者寫出的錨）。
func (p *CheckpointPurger) TrimChain(days int) (int64, *model.AuditCheckpointTrim, error) {
	if days <= 0 || p.signer == nil {
		return 0, nil, nil // 0＝永久保留
	}
	cutoff := p.now().UTC().AddDate(0, 0, -days)
	var trim *model.AuditCheckpointTrim
	err := p.db.Transaction(func(tx *gorm.DB) error {
		if tx.Dialector.Name() == "postgres" {
			if err := tx.Exec("LOCK TABLE audit_checkpoint_trims IN SHARE ROW EXCLUSIVE MODE").Error; err != nil {
				return err
			}
		}
		var chain []model.AuditCheckpoint
		if err := tx.Order("seq ASC").Find(&chain).Error; err != nil {
			return fmt.Errorf("讀取檢查點鏈失敗: %w", err)
		}
		if len(chain) <= 1 {
			return nil
		}
		prev, err := latestTrimTx(tx)
		if err != nil {
			return err // 讀取錯誤不當成「沒有前錨」：本輪不剪
		}
		cut := trimCutIndex(chain, cutoff)
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
		link, ok := trimAnchorLink(&chain[cut], &chain[cut+1], p.signer)
		if !ok {
			log.Printf("[Retention] 被剪段最後一點 seq=%d 與殘鏈新鏈頭 seq=%d 的簽章皆驗不過，本輪不修剪",
				chain[cut].Seq, chain[cut+1].Seq)
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
			FromSeq:             chain[0].Seq,
			LastTrimmedSeq:      chain[cut].Seq,
			TrimmedCount:        int64(cut + 1),
			LastTrimmedLinkHash: link,
			GenesisIDFrom:       genesisIDFrom,
			PolicyDays:          days,
			TrimmedAt:           p.now().UTC().Truncate(time.Microsecond),
			Format:              model.CheckpointTrimFormatV2,
			PermHistory:         &history,
			UnverifiedCount:     &unverified,
		}
		payload, err := CheckpointTrimSignBytes(trim)
		if err != nil {
			return err
		}
		version, sig := p.signer.Sign(payload)
		if version <= 0 || sig == "" {
			return fmt.Errorf("鏈修剪記錄簽章失敗（version=%d）：不修剪", version)
		}
		trim.SigningKeyVersion, trim.Signature = version, sig
		// 原生 SQL：audit_checkpoints 的 BeforeDelete 全拒，鏈修剪是
		// spec 定義的唯一清除路徑，與 audit_logs 的收口路徑同一家族。
		// 刪除與錨定記錄同一交易：不得存在「檢查點沒了但無有效修剪記錄」的持久狀態
		res := tx.Exec("DELETE FROM audit_checkpoints WHERE seq >= ? AND seq <= ?",
			trim.FromSeq, trim.LastTrimmedSeq)
		if res.Error != nil {
			return fmt.Errorf("修剪檢查點 seq [%d,%d] 失敗: %w", trim.FromSeq, trim.LastTrimmedSeq, res.Error)
		}
		if res.RowsAffected != trim.TrimmedCount {
			return fmt.Errorf("修剪影響 %d 列，與預期 %d 不符：整段回滾",
				res.RowsAffected, trim.TrimmedCount)
		}
		if err := tx.Create(trim).Error; err != nil {
			return fmt.Errorf("寫入鏈修剪記錄失敗: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	if trim == nil {
		return 0, nil, nil
	}
	log.Printf("[Retention] 鏈修剪：seq [%d,%d] 共 %d 個檢查點（保留 %d 天），"+
		"殘鏈以修剪記錄錨定（累計權限事實 %s、本段驗不過 %d 點）", trim.FromSeq, trim.LastTrimmedSeq,
		trim.TrimmedCount, days, *trim.PermHistory, *trim.UnverifiedCount)
	return trim.TrimmedCount, trim, nil
}

// trimCutIndex 自鏈頭起逐個判定，遇到第一個不可修剪的就停（連續性由此保證）；回傳最後可剪的索引（-1＝不剪）。
func trimCutIndex(chain []model.AuditCheckpoint, cutoff time.Time) int {
	cut := -1
	for i := 0; i < len(chain)-1; i++ { // len-1：至少留一個
		cp := chain[i]
		if i > 0 && cp.Seq != chain[i-1].Seq+1 {
			// 鏈已有斷洞：不在斷洞之上再疊修剪（那會讓斷洞永遠無法歸因）
			log.Printf("[Retention] 檢查點鏈於 seq=%d 前已有斷洞，停止修剪", cp.Seq)
			break
		}
		if !cp.SealedAt.UTC().Before(cutoff) {
			break // 尚未到期
		}
		if cp.RowCount > 0 && cp.PurgedAt == nil {
			log.Printf("[Retention] 檢查點 seq=%d 仍覆蓋 %d 列現存資料，停止修剪"+
				"（修剪它會讓那些列成為無法歸因的孤兒段）", cp.Seq, cp.RowCount)
			break
		}
		cut = i
	}
	return cut
}

// trimAnchorLink 修剪錨的錨值：被剪最後一點驗得過就以它重算鏈接；否則取殘鏈新鏈頭簽章內的
// prev_checkpoint_hash（新鏈頭須驗得過）；兩者皆驗不過回 false（本輪不剪）。
func trimAnchorLink(last, newHead *model.AuditCheckpoint, signer permissionSigner) (string, bool) {
	if _, ok := checkpointPointSignature(last, signer); ok {
		if link, err := CheckpointLinkHash(last); err == nil {
			return link, true
		}
	}
	if _, ok := checkpointPointSignature(newHead, signer); ok {
		return newHead.PrevCheckpointHash, true
	}
	return "", false
}

// VerifyTrim 修剪記錄的簽章是否有效（驗證端據此把殘鏈鏈頭錨回被修剪段）
func (p *CheckpointPurger) VerifyTrim(trim *model.AuditCheckpointTrim) (bool, error) {
	payload, err := CheckpointTrimSignBytes(trim)
	if err != nil {
		return false, err
	}
	return p.signer.Verify(trim.SigningKeyVersion, payload, trim.Signature)
}
