// Package dberr 資料庫錯誤的方言無關判定。
//
// `isUniqueViolation` 原寄居於改密域
// （`internal/modules/asset/change_secret_plan_service.go`），卻被 authz／identity／asset
// 三個模組共 6 處呼叫。它零領域語義、零外部相依，留在任一
// 業務模組都會製造無謂的跨模組出向邊，故先於任何模組搬檔提取為 kernel 包
// （這是模組搬檔的順序約束）。
//
// 本包 SHALL NOT 依賴 `internal/model`、`internal/service` 或任何業務模組——
// 它是被消費方，方向恆為單向。
package dberr

import "strings"

// IsUniqueViolation 寬鬆比對唯一鍵衝突（postgres 23505 / sqlite UNIQUE）。
//
// 比對字串而非驅動錯誤型別：專案同時支援 postgres 與 sqlite（測試），
// 兩者的唯一鍵衝突訊息形態不同，且 GORM 的 `ErrDuplicatedKey` 轉譯不涵蓋
// 全部驅動組合——呼叫端因此普遍寫成 `errors.Is(err, gorm.ErrDuplicatedKey) ||
// dberr.IsUniqueViolation(err)` 的雙判定。
func IsUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "23505") ||
		strings.Contains(msg, "UNIQUE constraint failed") ||
		strings.Contains(msg, "duplicate key")
}
