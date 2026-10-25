package policy

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// RetentionFloorDays 四個資料保留鍵（操作日誌、指令流、告警記錄、錄影）的下界（天）。
// 合法值域為 {0} ∪ [7, 3650]，0＝永久保留不受下界影響。檢查點保留鍵不設下界，
// 只受跨鍵約束（cross_key_retention.go）。
const RetentionFloorDays = 7

// PolicyFloorRaisedBy 升級對帳寫入政策列時的 updated_by（系統抬升身分）。
const PolicyFloorRaisedBy = "system:retention-floor"

// 保留下限的升級對帳。
//
// 每次啟動在保留讀者與保留排程之前執行一次，冪等：
//
//  1. 前狀態：直接讀四個資料鍵與檢查點鍵的原始列（不經 GetInt——1–6 會被讀取路徑
//     退回其他值）；沒有列取出廠預設，無法解析或超出上界者依既有讀取規則取有效值。
//  2. 值在 1–6 的資料鍵改為 7（below_floor）。
//  3. 檢查點鍵非 0 且小於 7，而且有任一資料鍵「前狀態被檢查點涵蓋、在第 2 步被抬升」
//     時，檢查點鍵改為 7（cross_key_follow）。這保證前狀態成立的每一組涵蓋關係抬升後
//     仍成立：被涵蓋又被抬升的資料鍵原值 d 滿足 1 ≤ d ≤ cp ≤ 6，抬到 7 後檢查點也到 7；
//     其餘鍵不變，檢查點只增不減。
//  4. 不以修補前狀態原本就違反的關係為目標（例如資料鍵 0 而檢查點 10）：修補方向屬保留
//     政策的選擇，不由對帳代管理者決定。第 3 步必要的跟隨抬升可能順帶使某組原本違反的
//     關係成立，照實記 log；對帳後未被涵蓋的關係集合恆為前狀態未涵蓋集合的子集，
//     未消除者記 log 並由 RetentionFloorReport 即時列出，不讓啟動失敗。
//
// 對帳不經政策批次寫入，是跨鍵約束的第二個豁免入口（第一個是環境變數播種）；跨鍵驗證
// 本身不改，之後經安全政策頁的儲存仍受全域驗證。抬升是收緊，不產生系統告警。

// FloorRaise 一個被抬升的保留鍵。
type FloorRaise struct {
	Key      string
	OldValue int
	NewValue int
	Floor    int
	Reason   string // model.PolicyFloorRaiseReason*
}

// FloorRaiseAuditor 在對帳交易內為一個被抬升的鍵寫審計；回錯即整筆回滾。
// 實作在組裝根（交易內審計落地面），政策模組不直接依賴審計模組。
type FloorRaiseAuditor func(tx *gorm.DB, raise FloorRaise) error

// UncoveredRetention 一組未被檢查點保留涵蓋的資料保留關係（0＝永久）。
type UncoveredRetention struct {
	Key            string `json:"key"`
	DataDays       int    `json:"data_days"`
	CheckpointDays int    `json:"checkpoint_days"`
}

// FloorReconcileResult 一次對帳的結果。
type FloorReconcileResult struct {
	Raised []FloorRaise
	// UncoveredBefore／UncoveredAfter 對帳前後未被涵蓋的關係（後者恆為前者的子集）
	UncoveredBefore []UncoveredRetention
	UncoveredAfter  []UncoveredRetention
	// IncidentallyCovered 因檢查點跟隨抬升而順帶變為成立的關係（以對帳前的值記）
	IncidentallyCovered []UncoveredRetention
}

// ErrFloorRaiseAuditMissing 對帳缺審計寫入者。
var ErrFloorRaiseAuditMissing = errors.New("保留下限對帳缺審計寫入者")

// floorReconcileLog 對帳的 log 出口（測試替換成紀錄器替身）。
var floorReconcileLog = log.Printf

// ReconcileRetentionFloor 執行保留下限的升級對帳（見本檔說明）。auditor 不得為 nil；
// productVersion 記入抬升紀錄。任一步失敗整筆回滾並回錯。
func (s *SecurityPolicyService) ReconcileRetentionFloor(auditor FloorRaiseAuditor, productVersion string) (FloorReconcileResult, error) {
	var res FloorReconcileResult
	if auditor == nil {
		return res, ErrFloorRaiseAuditMissing
	}
	now := time.Now()
	err := s.db.Transaction(func(tx *gorm.DB) error {
		res = FloorReconcileResult{}
		if err := lockPolicyHistory(tx); err != nil {
			return err
		}
		before := map[string]int{}
		for _, key := range append(append([]string{}, dataRetentionKeys...), PolicyRetentionCheckpointDays) {
			v, err := s.rawRetentionValue(tx, key)
			if err != nil {
				return err
			}
			before[key] = v
		}
		cpBefore := before[PolicyRetentionCheckpointDays]
		after := map[string]int{}
		for k, v := range before {
			after[k] = v
		}
		follow := false
		for _, key := range dataRetentionKeys {
			d := before[key]
			if d >= 1 && d < RetentionFloorDays {
				after[key] = RetentionFloorDays
				res.Raised = append(res.Raised, FloorRaise{Key: key, OldValue: d, NewValue: RetentionFloorDays,
					Floor: RetentionFloorDays, Reason: model.PolicyFloorRaiseReasonBelowFloor})
				if RetentionCovers(cpBefore, d) {
					follow = true
				}
			}
		}
		if follow && cpBefore != 0 && cpBefore < RetentionFloorDays {
			after[PolicyRetentionCheckpointDays] = RetentionFloorDays
			res.Raised = append(res.Raised, FloorRaise{Key: PolicyRetentionCheckpointDays, OldValue: cpBefore,
				NewValue: RetentionFloorDays, Floor: RetentionFloorDays, Reason: model.PolicyFloorRaiseReasonCrossKeyFollow})
		}
		res.UncoveredBefore = uncoveredRetention(before)
		res.UncoveredAfter = uncoveredRetention(after)
		for _, u := range res.UncoveredBefore {
			if RetentionCovers(after[PolicyRetentionCheckpointDays], after[u.Key]) {
				res.IncidentallyCovered = append(res.IncidentallyCovered, u)
			}
		}

		for _, r := range res.Raised {
			row := model.SecurityPolicy{Key: r.Key, Value: strconv.Itoa(r.NewValue), UpdatedBy: PolicyFloorRaisedBy, UpdatedAt: now}
			if err := tx.Save(&row).Error; err != nil {
				return fmt.Errorf("寫入保留政策 %s 失敗: %w", r.Key, err)
			}
			if err := auditor(tx, r); err != nil {
				return fmt.Errorf("寫入保留下限抬升審計（%s）失敗: %w", r.Key, err)
			}
			rec := model.SecurityPolicyFloorRaise{
				PolicyKey: r.Key, OldValue: strconv.Itoa(r.OldValue), NewValue: strconv.Itoa(r.NewValue),
				Reason: r.Reason, RaisedAt: now, ProductVersion: productVersion,
			}
			if err := tx.Create(&rec).Error; err != nil {
				return fmt.Errorf("寫入保留下限抬升紀錄（%s）失敗: %w", r.Key, err)
			}
		}
		return nil
	})
	if err != nil {
		return FloorReconcileResult{}, err
	}
	if len(res.Raised) > 0 {
		s.generation.Add(1)
		s.mu.Lock()
		for _, r := range res.Raised {
			delete(s.cache, r.Key)
		}
		s.mu.Unlock()
	}
	for _, r := range res.Raised {
		floorReconcileLog("[SecurityPolicy] 保留下限對帳：%s 由 %d 抬升為 %d（%s）", r.Key, r.OldValue, r.NewValue, r.Reason)
	}
	for _, u := range res.IncidentallyCovered {
		floorReconcileLog("[SecurityPolicy] 保留下限對帳：%s=%d 因檢查點保留跟隨抬升（%d → %d）而改為受涵蓋",
			u.Key, u.DataDays, u.CheckpointDays, RetentionFloorDays)
	}
	for _, u := range res.UncoveredAfter {
		floorReconcileLog("[SecurityPolicy] 保留政策跨鍵約束未成立：%s=%d、%s=%d（升級前即存在，請到安全政策頁調整）",
			u.Key, u.DataDays, PolicyRetentionCheckpointDays, u.CheckpointDays)
	}
	return res, nil
}

// rawRetentionValue 對帳用的原始值：有列且可解析、不超上界時取原始整數（含 1–6），
// 沒有列取出廠預設，其餘依既有讀取規則取有效值。
func (s *SecurityPolicyService) rawRetentionValue(tx *gorm.DB, key string) (int, error) {
	def := findDef(key)
	var row model.SecurityPolicy
	switch err := tx.Where("key = ?", key).First(&row).Error; {
	case errors.Is(err, gorm.ErrRecordNotFound):
		n, _ := strconv.Atoi(def.Default)
		return n, nil
	case err != nil:
		return 0, fmt.Errorf("讀取保留政策 %s 失敗: %w", key, err)
	}
	n, err := strconv.Atoi(row.Value)
	max := def.Max
	if max == 0 {
		max = defaultPolicyIntMax
	}
	if err != nil || n < 0 || n > max {
		fallback, _ := strconv.Atoi(s.lastGoodOrDefault(key, def))
		return fallback, nil
	}
	return n, nil
}

// retentionValuesConsistent 以單一查詢讀五個保留鍵的已提交現值（呈現用）：
// 讀取失敗回錯，不退回快取、最後已知值或出廠預設——呈現若在讀不到實況時回空清單，
// 仍違規的部署會被顯示成沒有待調整事項。無列取出廠預設；存量列不合法時沿讀取路徑規則。
// 一次查詢取五鍵，不會拼出跨批次的狀態。
func (s *SecurityPolicyService) retentionValuesConsistent() (map[string]int, error) {
	keys := append(append([]string{}, dataRetentionKeys...), PolicyRetentionCheckpointDays)
	var rows []model.SecurityPolicy
	if err := s.db.Where("key IN ?", keys).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("讀取保留政策現值失敗: %w", err)
	}
	raw := map[string]string{}
	for _, r := range rows {
		raw[r.Key] = r.Value
	}
	out := map[string]int{}
	for _, key := range keys {
		def := findDef(key)
		value := def.Default
		if v, ok := raw[key]; ok {
			if normalized, err := normalizePolicyValue(def, v); err == nil {
				value = normalized
			} else {
				value = s.lastGoodOrDefault(key, def)
			}
		}
		n, err := strconv.Atoi(value)
		if err != nil {
			return nil, fmt.Errorf("保留政策 %s 現值無法解析: %w", key, err)
		}
		out[key] = n
	}
	return out, nil
}

// uncoveredRetention 依給定值計算未被檢查點涵蓋的資料保留關係（依 dataRetentionKeys 順序）。
func uncoveredRetention(values map[string]int) []UncoveredRetention {
	cp := values[PolicyRetentionCheckpointDays]
	var out []UncoveredRetention
	for _, key := range dataRetentionKeys {
		if !RetentionCovers(cp, values[key]) {
			out = append(out, UncoveredRetention{Key: key, DataDays: values[key], CheckpointDays: cp})
		}
	}
	return out
}

// FloorRaiseRecord 抬升紀錄的唯讀形狀。
type FloorRaiseRecord struct {
	Key            string    `json:"key"`
	OldValue       string    `json:"old_value"`
	NewValue       string    `json:"new_value"`
	Reason         string    `json:"reason"`
	RaisedAt       time.Time `json:"raised_at"`
	ProductVersion string    `json:"product_version"`
}

// FloorReport 保留下限的告知內容：抬升紀錄與以目前有效值即時計算的未涵蓋關係。
type FloorReport struct {
	Raises    []FloorRaiseRecord   `json:"raises"`
	Uncovered []UncoveredRetention `json:"uncovered"`
}

// RetentionFloorReport 唯讀：回傳抬升紀錄（依時間與寫入序）與目前未被涵蓋的跨鍵關係。
// 升級說明卡經此取得要列出的項目；紀錄表不受審計保留清除。
func (s *SecurityPolicyService) RetentionFloorReport() (FloorReport, error) {
	var rows []model.SecurityPolicyFloorRaise
	if err := s.db.Order("raised_at, id").Find(&rows).Error; err != nil {
		return FloorReport{}, fmt.Errorf("讀取保留下限抬升紀錄失敗: %w", err)
	}
	rep := FloorReport{Raises: make([]FloorRaiseRecord, 0, len(rows))}
	for _, r := range rows {
		rep.Raises = append(rep.Raises, FloorRaiseRecord{Key: r.PolicyKey, OldValue: r.OldValue, NewValue: r.NewValue,
			Reason: r.Reason, RaisedAt: r.RaisedAt, ProductVersion: r.ProductVersion})
	}
	values, err := s.retentionValuesConsistent()
	if err != nil {
		return FloorReport{}, err
	}
	rep.Uncovered = uncoveredRetention(values)
	if rep.Uncovered == nil {
		rep.Uncovered = []UncoveredRetention{}
	}
	return rep, nil
}
