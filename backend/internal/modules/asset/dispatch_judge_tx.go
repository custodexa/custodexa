package asset

import (
	"log"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 背景派送的判定短交易。
//
// 判定（發起者、重排者與目標範圍）與遠端 I/O 之間若沒有序列化點，移出範圍或改歸的拓撲寫入可能在
// 判定通過之後、送出之前提交，送出的那一步就是以舊範圍放行的。這裡把判定放進一個短交易：
// 交易的第一個動作取拓撲序列化鎖（與拓撲寫入交易同一把），鎖後以交易內視圖判定；輪替成員另把派送
// 領取寫在同一交易，與判定一起提交。遠端 I/O 一律在提交之後。
//
// 兩種提交順序的結果：拓撲寫入先提交＝判定看到新範圍、不放行；判定先提交＝該步依判定當下的範圍
// 送出，拓撲寫入在其後完成，同一工作的下一步重驗看到新範圍。
//
// 交易內的判定與寫入只能用傳入的 tx：同一連線池上另開語句在單連線的測試庫會互相等待，
// 在正式庫則讀不到鎖後的一致視圖。

// judgeInTopologyTx 開短交易、取拓撲序列化鎖後執行 judge；回 judge 的原因碼（空字串＝放行）。
// 取鎖失敗、judge 回錯誤或提交失敗一律回 ChangeSecretReasonAuthzUnavailable（無從證明放行依據，fail closed）。
func judgeInTopologyTx(db *gorm.DB, lock func(*gorm.DB) error, judge func(tx *gorm.DB) (string, error)) string {
	reason, _ := judgeInTopologyTxCommitted(db, lock, judge)
	return reason
}

// judgeInTopologyTxCommitted 同 judgeInTopologyTx，另回判定交易是否完整提交。
// 未提交時回的原因碼一律是 ChangeSecretReasonAuthzUnavailable，不是 judge 在交易內給出的原因：
// 呼叫端依 judge 的原因分流（例如只略過一台）前，必須先確認交易已提交。
func judgeInTopologyTxCommitted(db *gorm.DB, lock func(*gorm.DB) error, judge func(tx *gorm.DB) (string, error)) (string, bool) {
	if db == nil || lock == nil {
		return model.ChangeSecretReasonAuthzUnavailable, false
	}
	reason := ""
	err := db.Transaction(func(tx *gorm.DB) error {
		if err := lock(tx); err != nil {
			return err
		}
		r, err := judge(tx)
		reason = r
		return err
	})
	if err != nil {
		log.Printf("[ChangeSecret] 派送判定短交易未完成，停止派送: %v", err)
		return model.ChangeSecretReasonAuthzUnavailable, false
	}
	return reason, true
}
