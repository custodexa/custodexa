package asset

import (
	"fmt"
	"log"

	"github.com/custodexa/backend/internal/model"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// 憑證群組：系統已知哪些資產帳號共用同一組憑證。
//
// # 為什麼需要它
//
// 「從其他帳號複製」建號會把密文原樣搬過去，於是兩台機器上的帳號自此共用同一組
// 憑證，而帳號表對此毫無記錄——輪替證據報告若不知道這件事，會把「改了一個帳號」
// 呈現成「這一個帳號合規」，而實際上另外幾台仍在用同一組還沒換掉的憑證。
//
// # 語義邊界（誠實標示）
//
// 群組只反映**系統知道的事**：複製建號時歸組，系統改密成功提交時脫組。
// 管理者手動編輯憑證不動群組——手動輸入的密碼可能仍是共用的，系統無從判定，
// 動它等於宣稱一件不知道的事。本能力引入前已存在的複製關係也不回溯補登：
// 舊資料裡沒有任何可據以判定的痕跡。兩項邊界皆於對外文件明載。
//
// # 為什麼不出 API
//
// 群組識別本身是一張「哪些帳號共用憑證」的拓撲圖，對外只投影成一個布林。

// joinCredentialGroup 使來源帳號與新帳號歸於同一群組。
//
// 來源尚無群組時先為其產生一個——群組是**成對關係的產物**，在有第二個成員之前
// 沒有意義，故不在建號時就給每個帳號一個群組值。
//
// 呼叫端須在建號的同一交易內呼叫，且在新帳號已寫入之後：來源的群組值與新帳號的
// 群組值必須一起成立或一起不成立，否則會留下一個「來源有群組、成員只有它自己」
// 的孤兒狀態，而那在報告上會顯示成一個不存在的共用關係。
//
// 回傳歸入的群組值，供呼叫端同步手上的 model 實例——建號回應要據此投影出
// 「共用憑證」，而 UPDATE 不會回寫呼叫端持有的結構。
func joinCredentialGroup(tx *gorm.DB, sourceAccountID, newAccountID uint) (string, error) {
	var source model.AssetAccount
	if err := tx.First(&source, sourceAccountID).Error; err != nil {
		return "", fmt.Errorf("讀取複製來源帳號的憑證群組失敗: %w", err)
	}

	group := source.CredentialGroup
	if group == "" {
		group = uuid.New().String()
		if err := tx.Model(&model.AssetAccount{}).
			Where("id = ?", sourceAccountID).
			Update("credential_group", group).Error; err != nil {
			return "", fmt.Errorf("設定來源帳號的憑證群組失敗: %w", err)
		}
	}
	if err := tx.Model(&model.AssetAccount{}).
		Where("id = ?", newAccountID).
		Update("credential_group", group).Error; err != nil {
		return "", fmt.Errorf("設定新帳號的憑證群組失敗: %w", err)
	}
	return group, nil
}

// leaveCredentialGroup 使帳號脫離憑證群組（系統改密成功並提交新憑證後）。
//
// 脫離後群組只剩一個成員時，該成員一併脫離：一個人的「共用」不是共用，留著它會
// 讓報告持續標示一個已經不存在的共用關係。
//
// 傳入的 `db` 可以是交易也可以是根連線；內部另起一層交易，使「清本列」與
// 「解散只剩一員的群組」不會被其他並行的脫組看到中間態——兩個成員同時改密成功時，
// 中間態會讓兩邊都讀到「還有兩個成員」而誰都不解散。
//
// 帳號不屬於任何群組時為 no-op。
func leaveCredentialGroup(db *gorm.DB, accountID uint) error {
	return db.Transaction(func(tx *gorm.DB) error {
		var account model.AssetAccount
		if err := tx.First(&account, accountID).Error; err != nil {
			return fmt.Errorf("讀取帳號的憑證群組失敗: %w", err)
		}
		group := account.CredentialGroup
		if group == "" {
			return nil
		}
		if err := tx.Model(&model.AssetAccount{}).
			Where("id = ?", accountID).
			Update("credential_group", nil).Error; err != nil {
			return fmt.Errorf("清除帳號的憑證群組失敗: %w", err)
		}

		var remaining int64
		if err := tx.Model(&model.AssetAccount{}).
			Where("credential_group = ?", group).
			Count(&remaining).Error; err != nil {
			return fmt.Errorf("計算憑證群組剩餘成員失敗: %w", err)
		}
		if remaining != 1 {
			return nil
		}
		if err := tx.Model(&model.AssetAccount{}).
			Where("credential_group = ?", group).
			Update("credential_group", nil).Error; err != nil {
			return fmt.Errorf("解散只剩一員的憑證群組失敗: %w", err)
		}
		return nil
	})
}

// noteCredentialGroupLeft 在改密成功提交後脫組，失敗只留 log。
//
// **不讓脫組失敗把一次成功的改密翻成失敗**：憑證此刻已經換掉且提交完成，回報失敗
// 會讓操作者以為要重跑，而重跑會對一台已經改好的機器再改一次。群組只是報告用的
// 標示，它的代價是報告上多標一個共用憑證，遠低於錯誤地重跑改密。
func noteCredentialGroupLeft(db *gorm.DB, accountID uint) {
	if err := leaveCredentialGroup(db, accountID); err != nil {
		log.Printf("[ChangeSecret] 憑證群組脫組失敗（改密已成功提交）account=%d err=%v", accountID, err)
	}
}

// noteCredentialGroupCommitted 改密成功提交後的群組處置：兩條提交路徑（改密執行器與
// 重試轉正）的唯一入口。
//
// 新憑證是各自隨機的（sharedGroup 為空）即脫組；是批次整批同一組的（sharedGroup 非空）
// 即先脫離原群組、再歸入該批次的群組——同一組密碼此刻在多台生效，報告必須看得見。
// 兩種情形的失敗都只留 log，理由同 noteCredentialGroupLeft。
func noteCredentialGroupCommitted(db *gorm.DB, accountID uint, sharedGroup string) {
	if sharedGroup == "" {
		noteCredentialGroupLeft(db, accountID)
		return
	}
	if err := joinSharedCredentialGroup(db, accountID, sharedGroup); err != nil {
		log.Printf("[ChangeSecret] 歸入共用憑證群組失敗（改密已成功提交）account=%d err=%v", accountID, err)
	}
}

// joinSharedCredentialGroup 使帳號歸入指定群組。
//
// 先沿既有規則脫離原群組（含「只剩一員即解散」），再寫入新值：帳號從此持有的是
// 批次的那組密碼，與原群組的其他成員不再共用。
func joinSharedCredentialGroup(db *gorm.DB, accountID uint, group string) error {
	return db.Transaction(func(tx *gorm.DB) error {
		if err := leaveCredentialGroup(tx, accountID); err != nil {
			return err
		}
		if err := tx.Model(&model.AssetAccount{}).
			Where("id = ?", accountID).
			Update("credential_group", group).Error; err != nil {
			return fmt.Errorf("歸入共用憑證群組失敗: %w", err)
		}
		return nil
	})
}

// settleSharedGroup 批次群組的解散判定：成員少於 2 且該批次已無待驗證候選時解散。
//
// 「已無待驗證候選」是必要條件——三台裡一台成功、兩台暫時連不上時，若在批次結束就
// 解散，稍後兩台轉正各自歸入一個已空的群組、各自又被解散，三台實際共用同一組密碼
// 卻沒有一台被標示。候選被清除而非轉正時群組可能只剩一員而不再有解散的觸發點，
// 此時報告會多標一個共用憑證：偏向多警告的一側，不是漏警告。
func settleSharedGroup(db *gorm.DB, batchID uint, group string) error {
	if group == "" {
		return nil
	}
	return db.Transaction(func(tx *gorm.DB) error {
		var members int64
		if err := tx.Model(&model.AssetAccount{}).
			Where("credential_group = ?", group).Count(&members).Error; err != nil {
			return fmt.Errorf("計算批次群組成員失敗: %w", err)
		}
		if members == 0 || members >= 2 {
			return nil
		}
		var pending int64
		if err := tx.Model(&model.ChangeSecretCandidate{}).
			Where("batch_id = ?", batchID).Count(&pending).Error; err != nil {
			return fmt.Errorf("計算批次待驗證候選失敗: %w", err)
		}
		if pending > 0 {
			return nil
		}
		return tx.Model(&model.AssetAccount{}).
			Where("credential_group = ?", group).
			Update("credential_group", nil).Error
	})
}

// noteSharedGroupSettled 解散判定的失敗只留 log（理由同 noteCredentialGroupLeft）
func noteSharedGroupSettled(db *gorm.DB, batchID uint, group string) {
	if err := settleSharedGroup(db, batchID, group); err != nil {
		log.Printf("[ChangeSecret] 批次群組解散判定失敗 batch=%d err=%v", batchID, err)
	}
}
