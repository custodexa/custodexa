package asset

import (
	"fmt"
	"strconv"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
)

// 自訂秘密使用的系統安全事件（生產端）。
//
// 告警留痕是這條路徑的重點，不是阻擋：操作者宣告或指定了一組由人決定的秘密，
// 系統照常執行，同時留下一筆不可刪停的系統告警與同交易的服務審計。
//
// # 契約
//
//   - 類型固定為 custom_secret_used（單一類型），以入口參數 entry 區分三種情形：
//     change_password＝自訂值遠端寫入；detach_shared＝脫離（隨機或自訂，一次一份）；
//     declare_new_secret＝直接宣告新秘密（含資產與帳號表單內嵌的同義宣告）。
//   - 與本地變更及服務審計同一交易，經 port.RaiseInTx；落地面缺席或寫入失敗一律讓錯誤逸出
//     交易閉包整筆回滾，不退回直接通知、不接受空成功實作。
//   - 事件與審計 details 共用同一個 correlation_id；秘密來源（custom｜random）只進審計 details，
//     不是告警宣告參數。
//   - 事件不帶任何秘密：不帶明文、密文、秘密雜湊與遠端回吐的原文，也不帶憑證名與資產名。

// customSecretEntry 對應告警目錄中 entry 參數的值域。
const (
	secretEntryChangePassword = "change_password"
	secretEntryDetachShared   = "detach_shared"
	secretEntryDeclareNew     = "declare_new_secret"
)

// 秘密來源（只進審計 details）。
const (
	secretSourceCustom = "custom"
	secretSourceRandom = "random"
)

// customSecretEntryFor 自訂秘密使用事件的入口分類器。一次操作只選一種：
// 脫離（隨機或自訂）＝detach_shared；直接宣告新秘密＝declare_new_secret；
// 其餘由人指定值的遠端寫入（目前沒有對應的產品輸入模式，未來同義入口必走這裡）＝change_password。
// 隨機整組輪替與拆分不在此列：它們沒有人決定的秘密值，不產生事件。
func customSecretEntryFor(op CredentialOperation) string {
	switch op {
	case CredOpDetach:
		return secretEntryDetachShared
	case CredOpSetSecret:
		return secretEntryDeclareNew
	default:
		return secretEntryChangePassword
	}
}

// customSecretEvent 一次自訂秘密使用事件的非秘密描述。
type customSecretEvent struct {
	Entry         string
	CredentialID  uint
	AssetID       uint // 0＝與單一資產無關
	CorrelationID string
	UserID        uint
	Username      string
}

// raiseCustomSecretUsed 在呼叫端的業務交易內產生 custom_secret_used。
// sink 缺席回 port.ErrSystemAlertSinkMissing（呼叫端讓它逸出交易）。
func raiseCustomSecretUsed(sink port.SystemAlertSink, tx *gorm.DB, ev customSecretEvent) error {
	target := port.SystemAlertTarget{Kind: port.SystemAlertTargetCredential,
		ID: strconv.FormatUint(uint64(ev.CredentialID), 10)}
	if ev.CredentialID == 0 {
		target = port.SystemAlertTarget{Kind: port.SystemAlertTargetAsset,
			ID: strconv.FormatUint(uint64(ev.AssetID), 10)}
	}
	alert := port.SystemAlertEvent{
		Type:          port.SystemAlertCustomSecretUsed,
		Actor:         port.SystemAlertActor{UserID: ev.UserID, Username: ev.Username},
		Target:        target,
		CorrelationID: ev.CorrelationID,
		Params:        map[string]string{"entry": ev.Entry},
	}
	if ev.AssetID != 0 {
		id := ev.AssetID
		alert.AssetID = &id
	}
	if _, err := port.RaiseInTx(sink, tx, alert); err != nil {
		return fmt.Errorf("產生自訂秘密使用系統告警失敗: %w", err)
	}
	return nil
}

// stampDeclaredSecretAudit 內嵌宣告帶秘密時，為服務審計補上關聯識別與秘密來源（不含任何秘密）。
func stampDeclaredSecretAudit(a *model.AssetAccountAudit, declared bool) error {
	if !declared {
		return nil
	}
	corr, err := newAssetCorrelationID()
	if err != nil {
		return err
	}
	a.CorrelationID, a.SecretSource = corr, secretSourceCustom
	return nil
}

// raiseDeclaredSecret 內嵌宣告在服務審計之後、同交易產生自訂秘密使用告警。
func raiseDeclaredSecret(sink port.SystemAlertSink, tx *gorm.DB, a model.AssetAccountAudit,
	declared bool, userID uint, operator string) error {
	if !declared {
		return nil
	}
	return raiseCustomSecretUsed(sink, tx, customSecretEvent{
		Entry: customSecretEntryFor(CredOpSetSecret), CredentialID: a.CredentialID, AssetID: a.AssetID,
		CorrelationID: a.CorrelationID, UserID: userID, Username: operator,
	})
}
