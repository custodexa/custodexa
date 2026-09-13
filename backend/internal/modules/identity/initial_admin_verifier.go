package identity

import (
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
)

// 初始管理員憑證驗證（初始化解封專用）。
//
// **為何住在 identity 而不是 keyvault**：本函式做的三件事——
// 查 `users`、展開 `Roles`
// 判 admin、bcrypt 比對——**全部是 identity 的語義**。它原先住在
// `internal/modules/keyvault/seal_verify.go`，使 keyvault 在「import 層零出向」
// 的宣稱下，於**資料層**直接讀 identity 的 `users`／`roles`／`user_roles`
// 並在包內執行 identity 的認證判定。搬到 identity 側後，
// 這三張表對 keyvault 而言不再是跨模組讀取。
//
// **不引入介面**：唯一呼叫端是組裝根（`cmd/server/sealwire.go` 的
// `verifyInitializeUnseal`），keyvault 自己不呼叫它——故正解是「把宣告搬到
// 擁有者那邊、由組裝根直呼」，而不是為了搬家而在 keyvault 造一個它其實不需要
// 的窄介面（export budget 紀律：搬包所需不等於新增跨包 API）。

// ErrSealInitialAdminInvalid 初始管理員憑證不符。
//
// **刻意保留原名**（含 Seal 前綴）：這是搬檔，符號只跨包不改名；
// 改名會讓「純移動」與「介面變更」在 diff 上混在一起。
var ErrSealInitialAdminInvalid = errors.New("初始管理員憑證不符")

// VerifyInitialAdminCredential 驗證初始管理員憑證（初始化解封專用）。
//
// **段 1 簡化路徑，刻意不套用既有帳號鎖定政策**：SecurityPolicyService 於段 2
// 才建構，此處取用不到；其防爆破由解封退避／冷卻承擔。
// 此界線必須明說，免得被誤解為已享有既有帳號鎖定保護。
//
// **SHALL NOT 觸碰 MustChangePassword**：驗證通過即受理解封，該帳號的
// 「首次登入強制改密」狀態維持不變、SHALL NOT 因通過解封而被清除或視為已完成。
// 解封是一次性的部署動作，不是登入，二者不得互相代償。
//
// **不觸及任何受 KEK 保護的欄位**：密碼是 bcrypt 雜湊、不受 KEK 保護，
// 全新安裝亦必然尚未啟用 MFA（totp_secret_enc 為空），故此驗證不觸發
// MFA 死鎖——該死鎖論證只對既有部署的一般解封成立。
// **password 為 []byte 而非 string**：解封路徑的秘密一律以可覆寫的 buffer
// 傳遞，字串化會產生不可覆寫的副本（見 api.SealUnsealPayload.Zeroize 的誠實
// 邊界）。bcrypt 直接吃 []byte，故此處零轉換。
func VerifyInitialAdminCredential(db *gorm.DB, username string, password []byte) error {
	if username == "" || len(password) == 0 {
		return ErrSealInitialAdminInvalid
	}
	var user model.User
	if err := db.Preload("Roles").Where("username = ?", username).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrSealInitialAdminInvalid
		}
		return fmt.Errorf("查詢初始管理員失敗: %w", err)
	}
	// 外部身分帳號（LDAP／OIDC）的 password 欄位是隨機填充值，不可作為本地憑證來源；
	// 且外部認證需要段 2 才建構的 authenticator/provider，封印期一律不可用。
	//
	// 判定用 IsExternal() 而非 IsLDAP：OIDC 影子帳號的
	// is_ldap 為 false，只認該欄會讓它落到 bcrypt 比對——雖然隨機密碼必不匹配，
	// 但那是靠巧合擋住，語義不明確；欄位語義一旦調整即可能真的放行
	if user.IsExternal() || !user.Active || user.Password == "" {
		return ErrSealInitialAdminInvalid
	}
	hasAdmin := false
	for _, r := range user.Roles {
		if r.Name == model.RoleAdmin {
			hasAdmin = true
			break
		}
	}
	if !hasAdmin {
		return ErrSealInitialAdminInvalid
	}
	if crypto.DefaultPasswordVerifier().Verify(user.Password, password) != nil {
		return ErrSealInitialAdminInvalid
	}
	return nil
}

// VerifySealAdminCredential 驗證解封流程的管理員帳密（封存期專用）。
//
// # 與一般登入的差別，以及為什麼是這些差別
//
//   - **不驗動態驗證碼**：TOTP 種子是受資料金鑰保護的欄位，封存時解不出來。
//     要求它會構成「先解封才能驗證、先驗證才能解封」的循環。正常登入的動態
//     驗證碼要求**不因此弱化**——本函式不是登入，不簽發工作階段、不改任何
//     帳號狀態（含 MustChangePassword 與失敗計數）。
//   - **不套用 SecurityPolicyService 的帳號鎖定政策**：該服務於段 2 才建構，
//     此處取用不到。本函式仍尊重已寫入帳號的鎖定期限（LockedUntil），
//     其餘防爆破由解封端點的退避與冷卻承擔。
//
// # 回應不可區分
//
// 帳號不存在、密碼錯、非管理角色、帳號停用、外部身分帳號、鎖定中一律回同一個
// ErrSealInitialAdminInvalid。呼叫端 SHALL NOT 讓它們產生不同的回應內容——
// 本階段面對的是匿名探測，可區分的錯誤等於帳號枚舉。
//
// 回傳通過驗證的使用者識別，供授權脈絡與審計記錄「是誰要求解封」。
func VerifySealAdminCredential(db *gorm.DB, username string, password []byte) (uint, error) {
	if err := VerifyInitialAdminCredential(db, username, password); err != nil {
		return 0, ErrSealInitialAdminInvalid
	}
	var user model.User
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		return 0, ErrSealInitialAdminInvalid
	}
	// 鎖定期內一律拒絕：鎖定是既有的爆破防護，不因為走的是解封頁而豁免。
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		return 0, ErrSealInitialAdminInvalid
	}
	return user.ID, nil
}

// VerifySealAdminStillAuthorized 重新確認該使用者仍具解封資格。
//
// 供解封授權脈絡於**每次使用**時重新判定：脈絡的效期以分鐘計，而在那段窗口內
// 帳號可能被停用、被降權、被鎖定，或其憑證世代被推進。規格要求「權限變動 SHALL
// 使該脈絡失效並要求重驗」，那句話只有在取用時重新判定才成立。
//
// **不驗密碼**：密碼已在簽發時驗過，這裡問的是「這個人現在還有沒有資格」。
// 回錯即失效；錯誤內容不對外（呼叫端一律收斂為同一個機器碼）。
func VerifySealAdminStillAuthorized(db *gorm.DB, userID uint) error {
	if db == nil || userID == 0 {
		return ErrSealInitialAdminInvalid
	}
	var user model.User
	if err := db.Preload("Roles").First(&user, userID).Error; err != nil {
		return ErrSealInitialAdminInvalid
	}
	if user.IsExternal() || !user.Active {
		return ErrSealInitialAdminInvalid
	}
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		return ErrSealInitialAdminInvalid
	}
	for _, r := range user.Roles {
		if r.Name == model.RoleAdmin {
			return nil
		}
	}
	return ErrSealInitialAdminInvalid
}
