package policy

import (
	"errors"
	"fmt"
	"strconv"
)

// 保留政策的跨鍵約束（audit-checkpoint-chain／security-policy spec
//「保留政策的跨鍵約束」）——本檔是政策服務的**第一個跨鍵驗證面**。
//
// 約束：`retention_checkpoint_days` 不得低於四個資料保留鍵的有效值，
// **0 視為無限大**（任一資料鍵為 0＝永久時，檢查點鍵僅允許 0）。
// 理由：檢查點是「這段資料沒被動過」的證明，證明活得比它所證明的資料短，
// 等於在資料還在的期間把證明先丟掉。
//
// 落點刻意在**批次層**而非 validatePolicyValue：單鍵驗證看不到其他鍵的終值，
// 而同一批次可能同時調兩側（spec 要求以終值判定，不得因鍵在請求中的先後
// 順序而異）。單鍵驗證行為完全不變。

// dataRetentionKeys 受本約束涵蓋的四個資料保留鍵。
//
// **不是「所有帶天數的鍵」**：只有「被檢查點鏈證明的審計資料」才在此列。
// 新增資料類別時須同步本清單，否則新類別的保留期可以超過檢查點保留期而無人擋
var dataRetentionKeys = []string{
	PolicyRetentionAuditLogDays,
	PolicyRetentionSessionCommandDays,
	PolicyRetentionAlertDays,
	PolicyRetentionRecordingDays,
}

// ErrPolicyRetentionCrossKey 跨鍵保留約束違反
var ErrPolicyRetentionCrossKey = errors.New("檢查點保留期不得短於資料保留期")

// PolicyRetentionCrossKeyError 跨鍵約束違反，附觸發的資料保留鍵與兩側終值。
//
// Key 保證出自 dataRetentionKeys（皆在 apierror 的 policyKey 允許清單內），
// 故可安全作為 ParamEnum 出 wire——admin 需要知道是哪一個鍵擋住了整批
type PolicyRetentionCrossKeyError struct {
	// Key 觸發違反的資料保留鍵
	Key string
	// DataDays 該資料鍵的批次終值（0=永久）
	DataDays int
	// CheckpointDays 檢查點鍵的批次終值（0=永久）
	CheckpointDays int
}

func (e *PolicyRetentionCrossKeyError) Error() string {
	return fmt.Sprintf("%s: %s=%d、%s=%d",
		ErrPolicyRetentionCrossKey.Error(),
		e.Key, e.DataDays, PolicyRetentionCheckpointDays, e.CheckpointDays)
}

// Unwrap 讓 errors.Is 可比對 sentinel
func (e *PolicyRetentionCrossKeyError) Unwrap() error { return ErrPolicyRetentionCrossKey }

// RetentionCovers 檢查點保留天數是否涵蓋資料保留天數（0 = 無限大）。
//
// 導出供 retention 執行期的保守判定複用——設定期與執行期
// 用同一個比較器，才不會出現「設定時說合法、執行時說違規」的兩把尺
func RetentionCovers(checkpointDays, dataDays int) bool {
	switch {
	case checkpointDays == 0:
		return true // 檢查點永久保留涵蓋一切
	case dataDays == 0:
		return false // 資料永久、檢查點有期＝證明先於資料消失
	default:
		return checkpointDays >= dataDays
	}
}

// validateCrossKeyRetention 批次層跨鍵驗證。updates 為本批次的待寫值。
//
// **觸及即全驗**：批次只要碰到五個保留鍵（四個資料鍵＋
// 檢查點鍵）中的任一個，就對**全部四組關係**以批次終值驗一遍；批次完全
// 不含保留鍵時不驗（不相干的政策編輯不受本約束干擾）。
//
// 為何不是「只驗本批次觸及的關係」（本檔前一版的做法）：那個退讓源自
// 「出廠檢查點鍵 3650 而資料鍵 0」的自相矛盾，出廠值改為 0 之後，
// 五鍵出廠即自洽（`RetentionCovers(0, 任意)` 恆真），退讓的理由消失。
//
// 退讓留下的實際缺口是**批次外造成的違規可以無限期靜默續存**：跨鍵約束
// 有一個明文豁免入口（`SeedFromEnv`，見其註解）與 SQL 直改面，任一資料鍵
// 經那些路徑變成違規值之後，只驗觸及關係的版本在「編輯另一個資料鍵」時
// 不會發現它，違規要拖到 retention 執行期才由 7.5 的保守跳過引爆
//（引爆形態是「修剪被靜默跳過」，admin 不會知道原因在政策）。
// 全域驗使**任何一次保留鍵編輯都是一次全域自檢**，違規在設定期即現形。
//
// 誤擋風險已由出廠值消除，並由 `TestCrossKeyRetentionDoesNotBlockFactoryState`
// 雙向釘住（出廠狀態下四個資料鍵逐一設任意合法值皆須通過）。
func (s *SecurityPolicyService) validateCrossKeyRetention(updates map[string]string) error {
	if !touchesRetentionKeys(updates) {
		return nil
	}

	cpDays, err := s.terminalIntValue(updates, PolicyRetentionCheckpointDays)
	if err != nil {
		return err
	}
	for _, key := range dataRetentionKeys {
		days, err := s.terminalIntValue(updates, key)
		if err != nil {
			return err
		}
		if !RetentionCovers(cpDays, days) {
			return &PolicyRetentionCrossKeyError{Key: key, DataDays: days, CheckpointDays: cpDays}
		}
	}
	return nil
}

// touchesRetentionKeys 本批次是否觸及五個保留鍵中的任一個。
//
// 「完全不含保留鍵就不驗」是刻意保留的邊界：政策頁其他分域的編輯
// （密碼長度、連線政策……）不該因為一個與它無關的既存違規而失敗
func touchesRetentionKeys(updates map[string]string) bool {
	if _, ok := updates[PolicyRetentionCheckpointDays]; ok {
		return true
	}
	for _, key := range dataRetentionKeys {
		if _, ok := updates[key]; ok {
			return true
		}
	}
	return false
}

// terminalIntValue 該鍵在本批次套用後的終值：批次帶了就取批次值，否則取現值。
//
// 批次值此時已通過單鍵驗證（UpdateBatch 的呼叫順序），故解析失敗只可能是
// 呼叫順序被改動——回錯而非默默當 0（當 0 會被讀成「永久」，方向完全相反）
func (s *SecurityPolicyService) terminalIntValue(updates map[string]string, key string) (int, error) {
	if raw, ok := updates[key]; ok {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return 0, &PolicyInvalidValueError{Key: key, Reason: "須為非負整數"}
		}
		return n, nil
	}
	return s.GetInt(key), nil
}
