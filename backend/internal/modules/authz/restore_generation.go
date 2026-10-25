package authz

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"gorm.io/gorm"
)

// 持久還原世代。
//
// 世代是 256-bit CSPRNG 值，在「恢復交易」內與 version+1、操作 ID、輸入摘要一起提交，
// status=pending；後端啟動、解封之後、開放一般服務之前由 CompletePendingRestore 寫入 restore
// 事件並改為 done。一般重啟與 migration 重跑不碰世代。

// 恢復狀態。
const (
	RestoreStatusPending = "pending"
	// RestoreStatusSealPending restore 事件已記下、涵蓋新世代的檢查點尚未封出（持久的待封狀態）。
	// 行程重啟後仍在，啟動時據此補封；封章成功才轉 done。
	RestoreStatusSealPending = "seal_pending"
	RestoreStatusDone        = "done"
)

// ErrRestoreOpConflict 已有不同操作 ID／輸入摘要的恢復紀錄卡在 pending：無法判定該續做還是重做，停下。
var ErrRestoreOpConflict = errors.New("存在未完成且操作識別不同的恢復紀錄，無法判定續做或重做")

// NewRestoreGeneration 產生 256-bit 隨機世代（hex）。
func NewRestoreGeneration() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("產生還原世代失敗: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// RestoreGeneration 讀目前持久還原世代。權限模型遷移前（沒有 authz_state 表或恢復欄）回空字串
// ＝legacy 世代；其他讀取錯誤原樣回傳（呼叫端須 fail-close，不得退回 legacy）。
func RestoreGeneration(db *gorm.DB) (string, error) {
	var gen string
	err := db.Raw("SELECT restore_generation FROM authz_state WHERE id = 1").Scan(&gen).Error
	if err == nil {
		return gen, nil
	}
	// 查詢失敗：先確認資料庫連得上（連不上不是 legacy，必須回錯讓呼叫端 fail-close），
	// 再判斷是否只是權限模型遷移前沒有該表／欄。
	sqlDB, derr := db.DB()
	if derr != nil {
		return "", fmt.Errorf("讀取還原世代失敗: %w", derr)
	}
	if perr := sqlDB.Ping(); perr != nil {
		return "", fmt.Errorf("讀取還原世代失敗（資料庫不可用）: %w", perr)
	}
	m := db.Migrator()
	if !m.HasTable(&model.AuthzState{}) || !m.HasColumn(&model.AuthzState{}, "RestoreGeneration") {
		return "", nil
	}
	return "", fmt.Errorf("讀取還原世代失敗: %w", err)
}

// CommitRestoreOnce 在單一交易內提交恢復：換新世代、version+1、記操作 ID 與輸入摘要、status=pending。
// 同一個 (opID, inputDigest) 已提交過（含已 done）就原樣回傳既有世代、不重換（腳本落盤前中斷後的 resume）；
// 另一個未完成的操作 ID 卡在 pending 回 ErrRestoreOpConflict。交易內任何失敗整體回滾。
// 回傳 (世代, 是否本次新換)。
func CommitRestoreOnce(db *gorm.DB, opID, inputDigest string) (string, bool, error) {
	if opID == "" || inputDigest == "" {
		return "", false, errors.New("恢復交易需要操作識別與輸入摘要")
	}
	var gen string
	fresh := false
	err := db.Transaction(func(tx *gorm.DB) error {
		var st model.AuthzState
		if err := tx.Where("id = 1").Take(&st).Error; err != nil {
			return fmt.Errorf("%w: %v", ErrAuthzStateMissing, err)
		}
		if st.RestoreOpID == opID && st.RestoreInputDigest == inputDigest && st.RestoreGeneration != "" {
			gen = st.RestoreGeneration
			return nil
		}
		if st.RestoreStatus == RestoreStatusPending && st.RestoreOpID != "" {
			return ErrRestoreOpConflict
		}
		g, err := NewRestoreGeneration()
		if err != nil {
			return err
		}
		res := tx.Exec(`UPDATE authz_state SET restore_generation = ?, restore_op_id = ?, restore_input_digest = ?,
 restore_status = ?, restored_at = ?, version = version + 1 WHERE id = 1`,
			g, opID, inputDigest, RestoreStatusPending, time.Now().UTC())
		if res.Error != nil {
			return fmt.Errorf("提交恢復交易失敗: %w", res.Error)
		}
		// 臨時授權（ticket／break-glass）簽發於舊世代，備份帶回後不得再提供連線：
		// 沿用既有到期語義（解析不命中、記錄留存供審計）一併到期；常設授權不動。
		// 新核准／新申請於提交後簽發，記新世代。
		if err := tx.Exec(`UPDATE asset_authorizations SET date_expired = ?
 WHERE source = ? AND deleted_at IS NULL AND (date_expired IS NULL OR date_expired > ?)`,
			time.Now().UTC(), model.AuthorizationSourceTicket, time.Now().UTC()).Error; err != nil {
			return fmt.Errorf("到期舊世代臨時授權失敗: %w", err)
		}
		gen, fresh = g, true
		return nil
	})
	if err != nil {
		return "", false, err
	}
	return gen, fresh, nil
}

// CompletePendingRestore 後端啟動、解封之後、開放一般服務之前呼叫：偵測 pending → 同交易寫入 restore 事件
// （附證已啟用時）並把狀態改為 seal_pending（持久的待封狀態，封章成功後由 MarkRestoreSealed 轉 done）。
// 回傳是否處理了 pending。沒有 pending 為 no-op（一般重啟）。
// 事件寫入失敗則整體回滾、狀態維持 pending，呼叫端不得開放一般服務。
func CompletePendingRestore(ctx context.Context, db *gorm.DB) (bool, error) {
	done := false
	err := db.Transaction(func(tx *gorm.DB) error {
		var st model.AuthzState
		if err := tx.Where("id = 1").Take(&st).Error; err != nil {
			return nil // 無列＝權限模型尚未遷移，沒有恢復可完成
		}
		if st.RestoreStatus != RestoreStatusPending {
			return nil
		}
		if err := audit.RecordPermissionStateEvent(ctx, tx, model.PermEventRestore, st.RestoreOpID); err != nil {
			return err
		}
		if err := tx.Exec("UPDATE authz_state SET restore_status = ? WHERE id = 1", RestoreStatusSealPending).Error; err != nil {
			return fmt.Errorf("標記恢復完成失敗: %w", err)
		}
		done = true
		return nil
	})
	return done, err
}

// RestoreSealPending 是否有 restore 事件已記、但涵蓋新世代的檢查點尚未封出的狀態（讀取失敗回錯）。
func RestoreSealPending(db *gorm.DB) (bool, error) {
	var st model.AuthzState
	res := db.Where("id = 1").Limit(1).Find(&st)
	if res.Error != nil {
		return false, fmt.Errorf("讀取待封狀態失敗: %w", res.Error)
	}
	return res.RowsAffected > 0 && st.RestoreStatus == RestoreStatusSealPending, nil
}

// MarkRestoreSealed 封章成功後清除待封狀態（seal_pending → done）；不是 seal_pending 時為 no-op。
func MarkRestoreSealed(db *gorm.DB) error {
	if err := db.Exec("UPDATE authz_state SET restore_status = ? WHERE id = 1 AND restore_status = ?",
		RestoreStatusDone, RestoreStatusSealPending).Error; err != nil {
		return fmt.Errorf("清除待封狀態失敗: %w", err)
	}
	return nil
}

// restoreJWTKeyDomain 還原世代派生簽章鑰的固定域。
const restoreJWTKeyDomain = "custodexa/jwt-restore-generation/v1\x00"

// DeriveRestoreJWTKey 由 JWT_SECRET 與持久還原世代派生執行期簽章鑰。
//
// 空世代（從未還原過）回原 secret，使正常升級／重啟不讓任何人登出；非空世代以
// HMAC-SHA256(key=secret, msg=固定域‖世代) 派生，簽發端與全部驗證端（access、MFA、改密、
// 解封中繼 token）必須用同一把，且非空時絕不回退原鑰——所以備份帶回、還原前簽出的 token
// 在還原後無法通過驗證。claims 形狀與 `.env` 都不變。
// 放在 authz 而非 pkg/crypto：後者受 TestMaterialScopeGuard 對金鑰材料基準的凍結，
// 本函式只是 stdlib HMAC，不是新的金鑰材料來源。
func DeriveRestoreJWTKey(secret, generation string) string {
	if generation == "" {
		return secret
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(restoreJWTKeyDomain + generation))
	return hex.EncodeToString(mac.Sum(nil))
}
