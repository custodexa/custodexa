package asset

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 服務重啟時停在「改密中」的輪替成員。
//
// # 為什麼要在啟動時處理
//
// 「改密中」只在一次成員推進的執行期間存在：推進者先轉入改密中、再對遠端下達，
// 結束時一定轉出（已送出未驗證、等待重試或終局失敗）。行程在這個窗口內結束，成員就
// 永遠停在改密中——背景排程只掃等待重試與已送出未驗證，逐台補跑對改密中也是無操作，
// 而遠端可能已經收下新秘密。
//
// # 為什麼轉成「已送出未驗證」
//
// 那是既有狀態機裡「遠端結果未知」的那一格：候選保留、就位版本不動、之後只做以新秘密
// 驗證（不下達新變更）——背景依候選列的退避登入驗證，人也可以逐台補跑確認；驗證不過
// 且逾期才轉終局失敗，之後背景不再碰它，只由人逐台補跑重新下達。它是比改密中更保守的
// 描述，而不是一個新的推論。
//
// 背景驗證只是登入、不改遠端，節奏與期限同遠端結果未知的既有處置（5 分鐘起倍增、上限
// 每小時一次、24 小時為止），不另開一套會增加鎖帳風險的排程。
//
// # 為什麼這樣做是安全的
//
//   - 同一行程內仍在推進的成員（解封模式重建服務圖時，前一份圖的推進可能還沒結束）
//     持有該掛載的行程內互斥鎖；取不到鎖即跳過，不碰正在動的成員。
//   - 離開改密中的每一筆寫入都帶「狀態仍是改密中」的條件（transitionMember）。若另一個
//     實例（操作者確認繼續的雙實例）其實還在推進，它之後的轉移會因狀態已變而不生效，
//     成員停在已送出未驗證，仍是保守的那一側；不會有任何路徑因此下達新變更或就位。
//   - 不動授權脈絡、還原世代與候選；之後的驗證照常先過授權重驗與還原世代比對。
//
// 轉換與它的審計同一交易：審計寫不進去即不轉換（成員維持原狀，下次啟動再處理）。

// interruptedRecoveryBatch 一次啟動最多處理的成員數（有界；殘留量遠小於此）。
const interruptedRecoveryBatch = 500

// RecoverInterruptedMembers 把停在「改密中」的輪替成員轉為「已送出未驗證」，留審計並告警一次。
//
// 只在啟動時、背景排程與路由開始之前呼叫。回傳已轉換的成員數；查詢失敗回錯誤，
// 單一成員的失敗只記日誌並告警，不中斷其餘成員。
func (s *CredentialRotationService) RecoverInterruptedMembers() (int, error) {
	// 人工承接的未消耗紀錄與改密中的成員同屬「行程中途結束」的殘留，收束在同一步。
	// 失敗只記日誌：不拖累成員收束，殘留紀錄留到下次啟動
	if n, err := recoverInterruptedConfirmations(s.db); err != nil {
		log.Printf("[HostIdentityTakeover] 啟動時收束未消耗的承接紀錄失敗（不阻擋啟動）: %v", err)
	} else if n > 0 {
		log.Printf("[HostIdentityTakeover] 啟動時把 %d 筆未消耗的承接紀錄收束為 unknown", n)
	}
	var members []model.CredentialRotationMember
	err := s.db.Model(&model.CredentialRotationMember{}).
		Joins("JOIN credential_rotations ON credential_rotations.id = credential_rotation_members.rotation_id").
		Where("credential_rotation_members.state = ?", model.CredentialMemberChanging).
		Where("credential_rotations.status IN ?", rotationOpenStatuses).
		Order("credential_rotation_members.id ASC").
		Limit(interruptedRecoveryBatch).
		Find(&members).Error
	if err != nil {
		return 0, fmt.Errorf("查詢改密中的輪替成員失敗: %w", err)
	}
	converted := 0
	for i := range members {
		if s.recoverInterruptedMember(&members[i]) {
			converted++
		}
	}
	return converted, nil
}

// recoverInterruptedMember 單一成員的轉換；true＝已轉換。
func (s *CredentialRotationService) recoverInterruptedMember(member *model.CredentialRotationMember) bool {
	release, ok := tryLockRotationAccount(member.AccountID)
	if !ok {
		// 本行程內仍有推進者持有這個掛載：它還在動，不是殘留
		log.Printf("[CredentialRotation] 改密中成員仍在推進，略過 rotation=%d member=%d", member.RotationID, member.ID)
		return false
	}
	defer release()

	err := s.db.Transaction(func(tx *gorm.DB) error {
		m, lerr := loadRotationMember(tx, member.RotationID, member.ID)
		if lerr != nil {
			return lerr
		}
		if m.State != model.CredentialMemberChanging {
			return errInterruptedMemberMoved
		}
		if err := transitionMember(tx, m, model.CredentialMemberChangedUnverified,
			memberTransition{LastError: model.ChangeSecretReasonInterrupted}); err != nil {
			return err
		}
		return s.writeInterruptedAudit(tx, m)
	})
	if errors.Is(err, errInterruptedMemberMoved) {
		return false
	}
	if err != nil {
		log.Printf("[CredentialRotation] 改密中成員未能轉為已送出未驗證（審計或狀態寫入失敗，維持原狀，下次啟動再處理）rotation=%d member=%d: %v",
			member.RotationID, member.ID, err)
		s.notifyInterrupted(member, false)
		return false
	}
	s.notifyInterrupted(member, true)
	return true
}

// errInterruptedMemberMoved 取鎖後重讀時成員已不在改密中（別的路徑已推進過）。
var errInterruptedMemberMoved = errors.New("輪替成員已離開改密中")

// writeInterruptedAudit 轉換的審計（系統身分），寫在轉換的交易內：寫不進去即整筆回滾。
func (s *CredentialRotationService) writeInterruptedAudit(tx *gorm.DB, member *model.CredentialRotationMember) error {
	details, _ := json.Marshal(map[string]any{
		"resource": string(model.ResourceCredential), "credential_id": member.CredentialID,
		"operation": "rotation_interrupted", "rotation_id": member.RotationID, "member_id": member.ID,
		"account_id": member.AccountID, "reason": model.ChangeSecretReasonInterrupted,
		"from_state": model.CredentialMemberChanging, "to_state": model.CredentialMemberChangedUnverified,
	})
	credID, assetID := member.CredentialID, member.AssetID
	return port.WriteInTx(s.auditTx, tx, port.AuditEvent{
		OccurredAt: time.Now(),
		Actor:      gatewayapi.Actor{Username: "system"},
		Action:     string(model.ActionUpdate),
		Resource:   string(model.ResourceCredential),
		ResourceID: &credID,
		AssetID:    &assetID,
		Status:     string(model.StatusSuccess),
		Details:    string(details),
	})
}

// notifyInterrupted 每個被中斷的成員告警一次（成員離開改密中之後不會再被處理，故不需去重）。
func (s *CredentialRotationService) notifyInterrupted(member *model.CredentialRotationMember, converted bool) {
	if s.stopNotify == nil {
		return
	}
	if converted {
		s.stopNotify("改密工作因服務重啟中斷",
			fmt.Sprintf("rotation=%d asset_id=%d account=%s 服務重啟時本台正在改密，遠端是否已收下新秘密未知；已轉為已送出未驗證並保留候選，背景會以新秘密登入驗證（不再下達），也可在憑證詳情逐台補跑確認",
				member.RotationID, member.AssetID, member.Username))
		return
	}
	s.stopNotify("改密工作因服務重啟中斷",
		fmt.Sprintf("rotation=%d asset_id=%d account=%s 服務重啟時本台正在改密，但轉為已送出未驗證未完成（審計或狀態寫入失敗），本台維持改密中，下次啟動再處理",
			member.RotationID, member.AssetID, member.Username))
}

// tryLockRotationAccount 不等待地取某掛載的行程內互斥鎖；取不到回 false。
func tryLockRotationAccount(accountID uint) (func(), bool) {
	lockAny, _ := rotationAccountLocks.LoadOrStore(accountID, &sync.Mutex{})
	lock := lockAny.(*sync.Mutex)
	if !lock.TryLock() {
		return nil, false
	}
	return lock.Unlock, true
}

// takeoverOutcomeUnknown 啟動收束寫入的結果：行程在紀錄建立之後、結果寫下之前結束，
// 遠端是否已被驗證過、本地是否已提交都無從證明，所以不假設任何一邊。
const takeoverOutcomeUnknown = "unknown"

// recoverInterruptedConfirmations 把所有尚未消耗的承接紀錄寫為 outcome=unknown、consumed_at=now。
//
// 紀錄存在即代表確認已宣告開始（建立紀錄與審計同一交易）。啟動時仍未消耗的紀錄，
// 其驗證或提交所在的行程已經結束：這裡不重放任何對目標主機的動作、不增加認證嘗試，
// 也不猜測結果；具權者之後重新明示確認，才會建立下一個 revision。
//
// 條件式更新只碰尚未消耗的列：已寫下結果的紀錄（verified、verify_failed、identity_moved、
// commit_failed）原封不動。同一行程內若有仍在進行的承接（解封模式重建服務圖），它之後的
// 條件式消耗會因列已被收束而失敗並整筆回滾，停在較保守的一側。
func recoverInterruptedConfirmations(db *gorm.DB) (int64, error) {
	res := db.Model(&model.CredentialHostIdentityConfirmation{}).
		Where("consumed_at IS NULL").
		Updates(map[string]any{"consumed_at": time.Now(), "outcome": takeoverOutcomeUnknown})
	if res.Error != nil {
		return 0, fmt.Errorf("收束未消耗的承接紀錄失敗: %w", res.Error)
	}
	return res.RowsAffected, nil
}
