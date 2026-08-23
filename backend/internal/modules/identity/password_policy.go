package identity

import (
	"errors"
	"fmt"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// 密碼政策的**歷史狀態半邊**（identity 側；判定半邊已遷入 `internal/modules/policy`
// 的 `password_compliance.go`）。
//
// 留在本檔的四個方法都讀寫 identity 自有表 `password_histories`（或建構在其上），
// 且掛在 `*UserService` 上：`ValidateNewPassword`／`CheckPasswordCompliance`／
// `isPasswordReused`／`recordPasswordHistory`。無狀態判定
// （`policy.CheckCompliance`）、違規型別與 4 個哨兵已改由 policy 提供。

// passwordMaxInputBytes 密碼雜湊實作回報的輸入上限。
//
// **不再寫死 72**：那是 bcrypt 特有的限制，
// 換演算法後該數字就錯了。改由 `Hasher.MaxInputBytes()` 回報，
// 無上限的實作（Argon2id／PBKDF2）回 `MaxInputUnlimited`（負值），
// 故 `len(pw) > limit` 對它們天然恆為 false，不需要特判。
func passwordMaxInputBytes() int {
	return crypto.DefaultPasswordHasher().MaxInputBytes()
}

// historyRetentionFloor 歷史裁剪保底筆數：政策調低（含 0=關閉）時仍保留
// PCI 建議的 4 筆，避免日後調回時歷史已被清空
const historyRetentionFloor = 4

// ValidateNewPassword service 層單一密碼 validator（政策驅動）：
// Create/自助改密/admin 重設全走此函式。userID=0 表示新帳號（跳過歷史比對）。
// 政策服務未注入（僅測試建構路徑）時不啟用政策驗證
func (s *UserService) ValidateNewPassword(userID uint, newPassword string) error {
	if s.policies == nil {
		return nil
	}

	// 輸入上限先擋：超過會讓雜湊實作回錯而落到 500，改回人話 400。
	// 上限由實作回報；無上限者回負值，本比較天然不成立。
	if limit := passwordMaxInputBytes(); limit >= 0 && len(newPassword) > limit {
		return &policy.PasswordPolicyViolation{
			Reason: policy.ErrPasswordTooLong,
			// **訊息不寫死「約 72 個英數字元」**：那是 bcrypt 特有的換算，
			// 換演算法後會變成錯的。只講位元組上限——那是這條限制的真實語義。
			Message: fmt.Sprintf("密碼過長（上限 %d 位元組）", limit),
			Code:    apierror.CodePasswordTooLong,
			Params:  map[string]any{"limit": limit},
		}
	}

	if err := s.CheckPasswordCompliance(newPassword); err != nil {
		return err
	}

	historyCount := s.policies.GetInt(policy.PolicyPasswordHistoryCount)
	if userID != 0 && historyCount > 0 {
		reused, err := s.isPasswordReused(userID, newPassword, historyCount)
		if err != nil {
			return err
		}
		if reused {
			return &policy.PasswordPolicyViolation{
				Reason:  policy.ErrPasswordReused,
				Message: fmt.Sprintf("新密碼不可與最近 %d 次使用過的密碼相同", historyCount),
				Code:    apierror.CodePasswordReused,
				Params:  map[string]any{"count": historyCount},
			}
		}
	}

	return nil
}

// CheckPasswordCompliance 無狀態政策合規子集。
// 設密路徑經 ValidateNewPassword 呼叫；登入 gate 走 policy.CheckCompliance
// （AuthService 無 UserService 引用）
func (s *UserService) CheckPasswordCompliance(password string) error {
	return policy.CheckCompliance(s.policies, password)
}

// isPasswordReused bcrypt 逐筆比對近 N 筆歷史。
// 每次設定密碼都會寫入歷史（含初始密碼），故近 N 筆已涵蓋現行密碼
func (s *UserService) isPasswordReused(userID uint, newPassword string, historyCount int) (bool, error) {
	var histories []model.PasswordHistory
	err := s.db.Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(historyCount).
		Find(&histories).Error
	if err != nil {
		return false, fmt.Errorf("查詢密碼歷史失敗: %w", err)
	}

	// 逐筆以**該筆當初的演算法**驗證（Verifier 依雜湊前綴分派）。
	//
	// **密碼歷史 SHALL NOT 被重新雜湊**：
	// 歷史列是 write-once，且我方沒有舊明文——重雜湊在密碼學上做不到。
	// 也不可「偷偷把比中的那筆升級」：那會使「撞到第幾筆歷史」變成可觀察的側信道。
	// 這正是「不做向下相容也躲不掉舊演算法驗證器」的原因：
	// 就算全體重設密碼，歷史列裡的舊雜湊仍需要能被驗證。
	for _, h := range histories {
		if crypto.DefaultPasswordVerifier().Verify(h.PasswordHash, []byte(newPassword)) == nil {
			return true, nil
		}
	}
	return false, nil
}

// recordPasswordHistory 寫入密碼歷史並裁剪超額舊紀錄（在呼叫端事務內執行）
func (s *UserService) recordPasswordHistory(tx *gorm.DB, userID uint, passwordHash string) error {
	if err := tx.Create(&model.PasswordHistory{
		UserID:       userID,
		PasswordHash: passwordHash,
	}).Error; err != nil {
		return fmt.Errorf("寫入密碼歷史失敗: %w", err)
	}

	keep := historyRetentionFloor
	if s.policies != nil {
		if n := s.policies.GetInt(policy.PolicyPasswordHistoryCount); n > keep {
			keep = n
		}
	}

	// 保留最近 keep 筆，刪其餘。以單調遞增主鍵 id 排序與刪除：
	// created_at 在同秒/粗精度下可能碰撞，會過刪（連該留的也刪，低於 floor）
	var cutoff model.PasswordHistory
	err := tx.Where("user_id = ?", userID).
		Order("id DESC").
		Offset(keep).
		First(&cutoff).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("查詢密碼歷史裁剪點失敗: %w", err)
	}

	if err := tx.Where("user_id = ? AND id <= ?", userID, cutoff.ID).
		Delete(&model.PasswordHistory{}).Error; err != nil {
		return fmt.Errorf("裁剪密碼歷史失敗: %w", err)
	}
	return nil
}
