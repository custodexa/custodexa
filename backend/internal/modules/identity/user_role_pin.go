package identity

import (
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 釘住：把外部群組賦予的角色固定為管理者指派。
//
// # 為什麼是獨立端點而不是替換端點的副作用
//
// 釘住是一個顯式動作。做成「把讀出來的兩份集合併起來回寫」的副作用，
// 等於讓一次例行的表單送出靜默把映射角色升格為管理者指派——升格之後那個角色
// 不再隨外部群組異動消失，而審計上它與管理者主動指派完全同形。
//
// # 為什麼要求目標角色目前有映射成分
//
// 釘住的語義是「把外部給的這一半固定下來」。目標角色沒有映射成分時該動作沒有
// 意義，靜默當成一般追加會讓「釘住」與「指派」在同一支端點上得到兩種語義。

// ErrRoleNotMapped 目標角色目前不是由外部群組映射賦予
var ErrRoleNotMapped = errors.New("此角色目前並非由群組映射賦予")

// PinMappedRole 把目標角色的來源自 mapped 升為 both（已是 both 即為 no-op）。
//
// 不新建有效角色（該角色本來就在有效集裡），故**不推進憑證世代、不留痕**
// ——來源欄是投影，投影變動不改變有效集。
func (s *UserService) PinMappedRole(userID uint, roleName string) (*RoleSets, error) {
	var user model.User
	if err := s.db.First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("查詢使用者失敗: %w", err)
	}
	var role model.Role
	if err := s.db.Where("name = ?", roleName).First(&role).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRoleNotFound
		}
		return nil, fmt.Errorf("查詢角色失敗: %w", err)
	}

	var sets RoleSets
	// 判定與升格同交易、同鎖：鎖外預讀會讓一次併發的登入重算把來源改掉，
	// 而本次仍以舊來源決定放行與否
	if err := WithUserCredentialLock(s.db, userID, func(tx *gorm.DB) error {
		source, exists, err := model.UserRoleSourceOf(tx, userID, role.ID)
		if err != nil {
			return err
		}
		if !exists || source == model.RoleSourceManual {
			return ErrRoleNotMapped
		}
		if source == model.RoleSourceMapped {
			if _, err := AddManualRole(tx, userID, role.ID); err != nil {
				return err
			}
		}
		sets, err = roleSetsOf(tx, userID)
		return err
	}); err != nil {
		if errors.Is(err, ErrRoleNotMapped) {
			return nil, err
		}
		return nil, fmt.Errorf("釘住角色失敗: %w", err)
	}
	return &sets, nil
}
