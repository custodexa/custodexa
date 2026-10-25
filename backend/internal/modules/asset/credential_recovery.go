package asset

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 失權後的有限驗證（recovery verify）。
//
// 遠端變更已經送出、結果未知的候選（或輪替成員），在發起者失權後仍可能是「遠端已是新秘密、
// 本地還沒記錄」。完全停手會讓帳號永久鎖死，照常繼續又等於替失權者辦事，所以只開一條窄路：
//   - 只做 Verify（以候選秘密登入原目標）與本地提交；不 Rotate、不產生秘密、不增加目標、
//     不刪舊鑰、不還原、不以舊值探試；
//   - 只在候選確實已下達（Applied）、建立未滿 24 小時、目標指紋仍與建立當下相符、
//     且目標主機的金鑰記錄仍在時進行；其餘一律停止並保留候選；
//   - 不接受呼叫端提供的 actor 或目標，全部事實取自 DB；
//   - 退避與期限沿用候選既有的 5 分鐘起、1 小時封頂、24 小時截止，期限看候選建立時刻，
//     重啟與人工重試都不重設。

// recoveryWindow 有限驗證的截止時間（自候選或輪替建立起算）。
const recoveryWindow = candidateRetryDeadline

// targetFingerprintOf 目標指紋：位址、通道、掛載、帳號、憑證引用的雜湊。
// 不含任何秘密，也不含主機金鑰（金鑰身分由撥號時的主機金鑰驗證與記錄存在檢查負責）。
func targetFingerprintOf(asset *model.Asset, binding *model.AssetAccount) string {
	channel := asset.EffectiveRotationChannel()
	sum := sha256.Sum256([]byte(fmt.Sprintf("tf1|%d|%d|%s|%d|%s|%s|%s",
		binding.ID, binding.AssetID, binding.Username, binding.CredentialID,
		channel, rotationAddr(asset, channel), string(asset.Protocol))))
	return hex.EncodeToString(sum[:])
}

// loadTargetFingerprint 以當下的資料庫事實計算掛載的目標指紋。
func loadTargetFingerprint(db *gorm.DB, accountID uint) (string, error) {
	var binding model.AssetAccount
	if err := db.Where("id = ?", accountID).First(&binding).Error; err != nil {
		return "", err
	}
	var asset model.Asset
	if err := db.Where("id = ?", binding.AssetID).First(&asset).Error; err != nil {
		return "", err
	}
	return targetFingerprintOf(&asset, &binding), nil
}

// recoveryVerdict 判定失權後能否做有限驗證。回空字串＝可以；否則回應記錄的原因碼。
// 任何缺證據的情形都不放行。主機身分以撥號前查庫（hostIdentityVerdict）判定：
// 工作綁定的身分必須仍是資產當下的記錄，否則歸主機身分變更。
func recoveryVerdict(db *gorm.DB, hostKeys *HostKeyService, applied bool, createdAt time.Time,
	storedFingerprint string, accountID uint, job hostIdentityJob) string {

	if !applied {
		// 尚未確認下達（prepared 或下達中被中斷）：沒有「遠端可能已變更」的證據，不給例外
		return model.ChangeSecretReasonAuthzRevoked
	}
	if time.Since(createdAt) >= recoveryWindow {
		return model.ChangeSecretReasonAuthzConvergenceExpired
	}
	if storedFingerprint == "" || hostKeys == nil {
		return model.ChangeSecretReasonAuthzTargetChanged
	}
	var binding model.AssetAccount
	if err := db.Where("id = ?", accountID).First(&binding).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return model.ChangeSecretReasonAuthzTargetChanged
		}
		return model.ChangeSecretReasonAuthzUnavailable
	}
	var asset model.Asset
	if err := db.Where("id = ?", binding.AssetID).First(&asset).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return model.ChangeSecretReasonAuthzTargetChanged
		}
		return model.ChangeSecretReasonAuthzUnavailable
	}
	if targetFingerprintOf(&asset, &binding) != storedFingerprint {
		return model.ChangeSecretReasonAuthzTargetChanged
	}
	// 綁定的身分與資產當下的記錄不同（含記錄缺失、重置待重新記錄、世代或指紋改變）：停止
	if reason := hostIdentityRecoveryReason(hostIdentityVerdict(db, job, &asset)); reason != "" {
		return reason
	}
	// 撥號前查庫對未綁定或不適用記錄比對的工作列放行；失權分支仍要求記錄存在，
	// 不讓有限驗證在首連時採信新身分
	if _, err := hostKeys.Get(binding.AssetID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return model.ChangeSecretReasonAuthzTargetChanged
		}
		return model.ChangeSecretReasonAuthzUnavailable
	}
	return ""
}

// recoveryAuditInput 有限驗證的審計內容（不含任何秘密）。
type recoveryAuditInput struct {
	resource        model.AuditResource
	resourceID      uint
	assetID         uint
	accountID       uint
	authorizationID *uint
	initiatorID     uint
	initiatorName   string
	cleanupPending  bool
	source          string
	// result verified｜verify_failed；failure 時 status 為 failed
	result string
	// fingerprint 建立當下固定的目標指紋（雜湊，非秘密）
	fingerprint string
}

// 有限驗證放行的理由（寫進審計，讓事後看得出為何在失權狀態下仍動作）。
const recoveryAllowedBecause = "revoked_initiator;dispatched_confirmed;within_24h;fingerprint_match;host_identity_match"

// claimRecoveryAlert 搶下「進入有限驗證」告警的發送權：把這一列（候選或輪替成員）的
// recovery_alerted_at 由空設為現在。回 true＝應發告警。
//
// 去重靠本模組自己的列，以條件式更新一次完成，並行的手動重試與排程不會各發一則。
// 失敗方向是重複而非遺漏：更新失敗、或更新落空後無法證實列上已記過，一律照發——
// 告警要留痕，寧可多一則，也不因去重狀態讀寫失敗而漏掉。
func claimRecoveryAlert(db *gorm.DB, row any, id uint) bool {
	res := db.Model(row).Where("id = ? AND recovery_alerted_at IS NULL", id).
		UpdateColumn("recovery_alerted_at", time.Now())
	if res.Error != nil {
		log.Printf("[ChangeSecret] 有限驗證告警去重狀態寫入失敗，照發告警 id=%d: %v", id, res.Error)
		return true
	}
	if res.RowsAffected > 0 {
		return true
	}
	var n int64
	if err := db.Model(row).Where("id = ? AND recovery_alerted_at IS NOT NULL", id).Count(&n).Error; err != nil {
		log.Printf("[ChangeSecret] 有限驗證告警去重狀態讀取失敗，照發告警 id=%d: %v", id, err)
		return true
	}
	return n == 0
}

// writeRecoveryVerifyAudit 有限驗證的留痕。落地面缺席或寫入失敗回錯誤，呼叫端據此不提交本地、
// 保留候選：在發起者已失權的狀態下代為完成動作，沒有留痕就不能做。
func writeRecoveryVerifyAudit(sink port.TxSink, db *gorm.DB, in recoveryAuditInput) error {
	if sink == nil {
		return port.ErrTxSinkMissing
	}
	details, _ := json.Marshal(map[string]any{
		"resource": string(in.resource), "operation": "recovery_verify", "source": in.source,
		"account_id": in.accountID, "authorization_id": in.authorizationID,
		"initiator_id": in.initiatorID, "cleanup_pending": in.cleanupPending,
		"result": in.result, "reason": model.ChangeSecretReasonAuthzRevoked,
		"target_fingerprint": in.fingerprint, "allowed_because": recoveryAllowedBecause,
	})
	status := model.StatusSuccess
	if in.result != "verified" {
		status = model.StatusFailure
	}
	resID, assetID := in.resourceID, in.assetID
	err := db.Transaction(func(tx *gorm.DB) error {
		return port.WriteInTx(sink, tx, port.AuditEvent{
			OccurredAt: time.Now(),
			Actor:      gatewayapi.Actor{UserID: in.initiatorID, Username: in.initiatorName},
			Action:     string(model.ActionUpdate),
			Resource:   string(in.resource),
			ResourceID: &resID,
			AssetID:    &assetID,
			Status:     string(status),
			Details:    string(details),
		})
	})
	if err != nil {
		log.Printf("[ChangeSecret] 有限驗證審計寫入失敗 source=%s account=%d: %v", in.source, in.accountID, err)
	}
	return err
}
