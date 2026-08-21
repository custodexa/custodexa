package keyvault

import (
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
)

// B 模式解封的材料驗證原語（kek-provider-modularization D6.3／D6.6）。
//
// 三個函式都在**臨界區之內**被呼叫（CAS 取得持有權在任何驗證之前，D6.2.1），
// 且全部回傳不可區分的錯誤——呼叫端 SHALL 把它們一律映射為單一材料失敗碼。

// ErrSealNoRepresentativeRow 金鑰表非空但查不到本 KEK 的現行代表列。
var ErrSealNoRepresentativeRow = errors.New("無法以此材料取得現行代表列")

// **W6 6.0d**：`VerifyInitialAdminCredential` 與 `ErrSealInitialAdminInvalid`
// 已移交 identity（`internal/service/initial_admin_verifier.go`）——查 users、
// 展開 Roles 判 admin、bcrypt 比對三件事全屬 identity 語義，留在此處會使 keyvault
// 在資料層直接讀 identity 的三張表（backlog B-13）。

// CountDataKeys 回傳金鑰表筆數。
//
// **沿用 InitKeyManager 既有的 count == 0 判定**（D6.3），不另造判準：
// 兩處若各自定義「空庫」，初始化解封與 bootstrap 的分流就可能不一致，
// 而該不一致的後果是「材料被固化為主 KEK 卻沒有對應的 bootstrap」。
func CountDataKeys(db *gorm.DB) (int64, error) {
	var count int64
	if err := db.Model(&model.DataKey{}).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("讀取金鑰表筆數失敗: %w", err)
	}
	return count, nil
}

// ProbeKEKUnwrap 以候選 KEK 嘗試解包**全部**現行代表列。
//
// 這是一般解封的唯一判準（D6.3／D9）：金鑰引用一致**且**現行代表列全數實際
// 解包成功。只比對指紋不足——本地 KeyID 是 64-bit 截斷摘要，相等不能證明同材料。
//
// 純讀取、零副作用：驗證不得順手完成任何屬於段 2 的工作，否則「驗證失敗回
// 來源態」就不再是無痕的。
func ProbeKEKUnwrap(db *gorm.DB, kek crypto.KEKProvider) error {
	var rows []model.DataKey
	if err := db.Where("kek_id = ? AND kek_retired_at IS NULL AND wrapped_key <> ''", kek.KeyRef().KeyID).
		Order("purpose, version").Find(&rows).Error; err != nil {
		return fmt.Errorf("讀取現行代表列失敗: %w", err)
	}
	if len(rows) == 0 {
		return ErrSealNoRepresentativeRow
	}
	for _, r := range rows {
		if _, err := unwrapMaterial(kek, r.Purpose, r.Version, r.WrappedKey); err != nil {
			return fmt.Errorf("代表列 %s v%d 解包失敗: %w", r.Purpose, r.Version, err)
		}
	}
	return nil
}
