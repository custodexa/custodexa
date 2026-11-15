package asset

import (
	"context"
	"fmt"
	"strconv"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
)

// 以 API token 掛載既有憑證的系統告警。
//
// 產生點只在四個入口的外層：建立單筆資產、匯入（整批一次）、建立資產帳號、掛載與更換憑證。
// 低層的寫入函式（createPreparedTx、bindNewDedicatedCredential）只回報事實，不決定發不發——
// 內嵌秘密新建的專用憑證落地後憑證識別同樣非零，但它不是引用既有憑證。
//
// 只對以 API token 認證的請求產生；登入工作階段的掛載不產生。告警與業務寫入同一交易：
// 落地失敗即回錯使整筆回滾，回滾也就不留告警。同交易稽核列的明細帶同一個關聯識別，
// 由告警可回查逐台的資產與憑證。告警參數只含名稱與計數，不含秘密、密文、token 明文或雜湊，
// 也不含連線位址。

// 入口值域（與類型目錄宣告的值域一致）
const (
	attachEntryAssetCreate   = audit.CredentialAttachEntryAssetCreate
	attachEntryAccountCreate = audit.CredentialAttachEntryAccountCreate
	attachEntryBind          = audit.CredentialAttachEntryBind
	attachEntryRebind        = audit.CredentialAttachEntryRebind
	attachEntryImport        = audit.CredentialAttachEntryImport
)

// credentialAttachRequest 一次可能產生告警的請求：只有以 API token 認證時 active 為真。
type credentialAttachRequest struct {
	active        bool
	tokenName     string
	correlationID string
}

// newCredentialAttachRequest 依請求脈絡判定是否為 API token 請求；是則先產生關聯識別，
// 供同交易稽核列與告警共用。非 API token 請求回零值（不產生告警、不改稽核明細）。
func newCredentialAttachRequest(ctx context.Context) (credentialAttachRequest, error) {
	ref, ok := model.APITokenRefFrom(ctx)
	if !ok {
		return credentialAttachRequest{}, nil
	}
	corr, err := newAssetCorrelationID()
	if err != nil {
		return credentialAttachRequest{}, err
	}
	return credentialAttachRequest{active: true, tokenName: ref.Name, correlationID: corr}, nil
}

// auditCorrelation 同交易稽核列要帶的關聯識別（非 API token 請求為空，稽核明細不變）。
func (r credentialAttachRequest) auditCorrelation() string {
	if !r.active {
		return ""
	}
	return r.correlationID
}

// credentialDisplayName 共用憑證的名稱（共用憑證必有名稱；缺漏時以識別代替，不留空）。
func credentialDisplayName(cred *model.Credential) string {
	if cred.Name != nil && *cred.Name != "" {
		return *cred.Name
	}
	return "#" + strconv.FormatUint(uint64(cred.ID), 10)
}

// raiseSingle 單筆入口（建立資產、建立資產帳號、掛載、更換憑證）：目標為該資產。
func (r credentialAttachRequest) raiseSingle(sink port.SystemAlertSink, tx *gorm.DB, entry string,
	userID uint, username string, assetID uint, assetName string, cred *model.Credential) error {

	if !r.active {
		return nil
	}
	id := assetID
	_, err := port.RaiseInTx(sink, tx, port.SystemAlertEvent{
		Type:          port.SystemAlertAPITokenCredentialAttached,
		Actor:         port.SystemAlertActor{UserID: userID, Username: username},
		Target:        port.SystemAlertTarget{Kind: port.SystemAlertTargetAsset, ID: strconv.FormatUint(uint64(assetID), 10)},
		AssetID:       &id,
		CorrelationID: r.correlationID,
		Params: map[string]string{
			"token_name":      r.tokenName,
			"entry":           entry,
			"credential_name": credentialDisplayName(cred),
			"asset_name":      assetName,
		},
	})
	if err != nil {
		return fmt.Errorf("產生 API token 掛載既有憑證告警失敗: %w", err)
	}
	return nil
}

// raiseImport 匯入：一次一則，目標為操作者。assetCount 只計實際引用既有憑證的列；
// 一列都沒有時不產生。
func (r credentialAttachRequest) raiseImport(sink port.SystemAlertSink, tx *gorm.DB,
	userID uint, username string, assetCount, credentialCount int) error {

	if !r.active || assetCount == 0 {
		return nil
	}
	_, err := port.RaiseInTx(sink, tx, port.SystemAlertEvent{
		Type:          port.SystemAlertAPITokenCredentialAttached,
		Actor:         port.SystemAlertActor{UserID: userID, Username: username},
		Target:        port.SystemAlertTarget{Kind: port.SystemAlertTargetUser, ID: strconv.FormatUint(uint64(userID), 10)},
		CorrelationID: r.correlationID,
		Params: map[string]string{
			"token_name":       r.tokenName,
			"entry":            attachEntryImport,
			"asset_count":      strconv.Itoa(assetCount),
			"credential_count": strconv.Itoa(credentialCount),
		},
	})
	if err != nil {
		return fmt.Errorf("產生 API token 匯入引用既有憑證告警失敗: %w", err)
	}
	return nil
}
