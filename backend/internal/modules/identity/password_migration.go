package identity

import (
	"fmt"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
)

// === 密碼雜湊的漸進遷移：可見性與觸發===
//
// **批次重新雜湊在密碼學上不可實作，這不是實作限制。** 把一筆舊演算法的雜湊轉成
// 新演算法需要**明文密碼**，而系統沒有明文——那正是雜湊存在的意義。
// 任何「一鍵把所有帳號遷移過去」的功能都做不出來，除非要求全體重設密碼。
// 此處明文記載，免得日後重複提出同一個想法。
//
// 漸進遷移剩下兩個真實缺口，本檔提供的是第二個的出口：
//   缺口一：長期不登入的帳號永遠不會遷移
//           → 既有的**密碼有效期政策**（`password_max_age_days`）已足以覆蓋，
//             密碼過期即強制改密，改密時自然採用新演算法。
//   缺口二：管理員想立刻收斂，不想等有效期到
//           → 本檔：**遷移狀態的可見性 ＋ 強制改密的觸發**，而非重雜湊。

// PasswordMigrationStatus 密碼雜湊的遷移概況。
type PasswordMigrationStatus struct {
	// CurrentAlgorithm 目前的寫入演算法
	CurrentAlgorithm string `json:"current_algorithm"`
	// Migrated 已是當前演算法與參數的本地帳號數
	Migrated int64 `json:"migrated"`
	// Pending 仍待遷移的本地帳號數（登入或改密時會自動升級）
	Pending int64 `json:"pending"`
	// External 外部化帳號數（LDAP／OIDC）：無本地密碼，不在遷移射程內
	External int64 `json:"external"`
}

// PasswordMigrationStatus 統計遷移概況。
//
// **逐列判定而非 SQL 條件**：是否需要升級由 `Verifier.NeedsRehash` 決定
// （它看的是雜湊字串的演算法 token 與參數），那個邏輯不該在 SQL 裡複製一份
// ——複製出來的那份會在換演算法時悄悄過時。
func (s *UserService) PasswordMigrationStatus() (*PasswordMigrationStatus, error) {
	var users []model.User
	if err := s.db.Select("id", "password", "is_ldap", "external_credential",
		"provisioning_origin").Find(&users).Error; err != nil {
		return nil, fmt.Errorf("查詢使用者失敗: %w", err)
	}

	verifier := crypto.DefaultPasswordVerifier()
	out := &PasswordMigrationStatus{
		CurrentAlgorithm: crypto.DefaultPasswordHasher().ID(),
	}
	for i := range users {
		u := &users[i]
		if u.IsExternal() || u.Password == "" {
			out.External++
			continue
		}
		if verifier.NeedsRehash(u.Password) {
			out.Pending++
			continue
		}
		out.Migrated++
	}
	return out, nil
}

// MarkPendingForPasswordChange 把待遷移的帳號標記為「下次登入須改密」。
//
// **沿用既有的 `must_change_password` 機制，不新造流程**：
// 首次登入強制改密即是用它，被標記者下次登入被要求改密，改完即為新演算法。
//
// **這不是批次重雜湊**——它不碰任何密碼欄位，只設一個旗標。
// 真正的轉換仍發生在使用者送上明文的那一刻。
//
// 回傳實際被標記的帳號數。外部化帳號與已是當前演算法者一律跳過：
// 前者沒有本地密碼可改，後者改了也不會變得更新。
func (s *UserService) MarkPendingForPasswordChange() (int, error) {
	var users []model.User
	if err := s.db.Select("id", "password", "is_ldap", "external_credential",
		"provisioning_origin", "must_change_password").Find(&users).Error; err != nil {
		return 0, fmt.Errorf("查詢使用者失敗: %w", err)
	}

	verifier := crypto.DefaultPasswordVerifier()
	var targets []uint
	for i := range users {
		u := &users[i]
		if u.IsExternal() || u.Password == "" || u.MustChangePassword {
			continue
		}
		if verifier.NeedsRehash(u.Password) {
			targets = append(targets, u.ID)
		}
	}
	if len(targets) == 0 {
		return 0, nil
	}

	if err := s.db.Model(&model.User{}).
		Where("id IN ?", targets).
		Update("must_change_password", true).Error; err != nil {
		return 0, fmt.Errorf("標記強制改密失敗: %w", err)
	}
	return len(targets), nil
}
