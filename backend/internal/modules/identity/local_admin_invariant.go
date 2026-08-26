package identity

import (
	"fmt"
	"log"
	"sync"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 「本地 admin 數量不得自一以上降為零」不變式（2.7）。
//
// **本地 admin** ＝ 啟用中（active）、具 admin 角色、且憑證未由外部身分提供者託管
//（model.User.IsExternal() 為 false，即 external_credential=false 且 is_ldap=false
// 且 provisioning_origin 為 local/空）。定義與封印解封的驗證條件同源
//（seal_verify.go VerifyInitialAdminCredential）：解封只認本地 admin 憑證，
// 失去最後一個此類帳號＝遇 KEK 重啟時無人能解封＝持久的管理面鎖死。
//
// **語義是「不得自一以上降為零」，不是「操作後必須 ≥1」**：
// 後者會讓已處於零個狀態的既有部署（全員已切 SSO）連正常的帳號管理都做不了。
// 故判定為「目標當下計為本地 admin，且系統本地 admin 總數為 1」時才拒絕；
// 目標本就不是本地 admin（含總數已為零的部署）一律放行，僅由管理端持續警示。
//
// **必須跨操作序列化**：單次操作內檢查擋不住 write-skew——
// 僅有兩個本地 admin A、B 時，兩個並發請求各自看見「對方還在」即可同時提交，結果歸零。
// 故四條路徑（停用、刪除、移除 admin 角色、改為僅外部登入）SHALL 共用同一把
// 系統級鎖，且判定 SHALL 於鎖內重讀。

// LocalAdminLockKey 系統級「本地 admin 不變式」互斥的 advisory lock key。
//
// keyspace 沿用 key_manager_lock.go 登記的專案保留段（高位元 "otkek" 專案識別、
// 低位元為子系統內編號）；該檔的 0x...0001 為 data_keys 寫入互斥，本鍵取 0x...0002。
// 兩者不得相同，由 TestLocalAdminLockKeyDistinct 守衛。
//
// **設計順序**：本鎖為「system → provider → user」取鎖順序中的
// system 級鎖；2.8 的連線兌換／Join 若需同持多鎖，一律先取本鎖再取 provider/user 鎖。
const LocalAdminLockKey int64 = 0x6F74_6B65_6B00_0002

// localAdminProcessMu 無 advisory lock 能力環境（sqlite）的等價序列化。
// package 層級共用（跨 UserService 實例），與 postgres 路徑同語義。
var localAdminProcessMu sync.Mutex

// localAdminPreWriteHook 測試用同步點：於「不變式判定通過之後、實際寫入之前」呼叫。
//
// **可覆寫的唯一理由是測試**（同 key_manager_lock.go 的 pgSessionLockAcquireSQL 慣例）：
// 「兩個並發操作各自看見對方仍在」的 write-skew 只在特定交錯下成立，靠時間競賽觸發
// 不穩定；本 hook 讓測試能在該精確位置製造交錯，使「把鎖內重讀改成鎖外預讀」的
// 突變被**確定性**地抓到，而非碰運氣。生產路徑此值恆為 nil，改寫者僅限 _test.go。
var localAdminPreWriteHook func()

// LastLocalAdminError 不變式拒絕。
//
// **刻意讓 errors.Is(err, ErrLastAdmin) 成立**（見 Is 方法）：Delete／UpdateStatus
// 的既有 handler 只認 ErrLastAdmin 並回 400＋既有機器碼，若本錯誤與其無關，
// 這條合法的規則拒絕會落到 RespondInternal 變成 500。在 handler 尚未接上本碼
// 之前（2.8 一併處理外部身分管理端點時接），此相容性保證「拒絕」以 4xx 呈現。
// 需要精確碼的呼叫端以 errors.As 取 Code。
//
// 連帶效果為所欲：inactivity_service.go 對 ErrLastAdmin 的「跳過自動停用、記警告」
// 同樣適用於本不變式——閒置掃描不該把最後一個本地 admin 掃掉。
type LastLocalAdminError struct {
	// Code 精確出口碼（RULE_USER_LAST_LOCAL_ADMIN）
	Code apierror.ErrCode
}

func (e *LastLocalAdminError) Error() string {
	return "此操作將使系統失去最後一個本地管理員帳號（啟用中且憑證未由外部身分提供者託管）"
}

// Is 使本錯誤同時滿足 errors.Is(err, ErrLastAdmin)。
// 單向：ErrLastAdmin 本身不會被判為 LastLocalAdminError。
func (e *LastLocalAdminError) Is(target error) bool { return target == ErrLastAdmin }

// ErrLastLocalAdmin 不變式拒絕的哨兵值（errors.Is 比對用）。
var ErrLastLocalAdmin error = &LastLocalAdminError{Code: apierror.CodeLastLocalAdmin}

// localAdminScope 「啟用中且未外部化的 admin」查詢範圍（單一事實源）。
//
// IsExternal() 的三訊號在 SQL 端逐一展開：任一指出外部即不計入，與 Go 端
// fail-secure 的聯集語義一致。provisioning_origin 的 NULL／空字串視同 local
// （欄位帶 default 'local'，但既有列於 migration 前可能為空）。
//
// **密碼非空是第四個必要條件**：計數的用途是判斷「還有
// 沒有人能以本地憑證登入／解封」，而空密碼列**無法以本地密碼登入**——旗標與
// 密碼不一致的漂移列（external_credential=false 但密碼為空字串，任一建號路徑
// 漏設旗標即成立，見 oidc_invariant_matrix_test.go 的橫向守衛）若計入，會墊高
// 計數而把「2→1」誤判成安全的變動，實際上是「1→0」：最後一個能登入的 admin
// 被移除後無人可登入，遇 KEK 重啟即永久鎖死。判準與 hasLoginPathAfterUnbind
// 的 TrimSpace 同寬嚴度（僅含空白同樣不可用）
func localAdminScope(tx *gorm.DB) *gorm.DB {
	return tx.Model(&model.User{}).
		Joins("JOIN user_roles ON user_roles.user_id = users.id").
		Joins("JOIN roles ON roles.id = user_roles.role_id").
		Where("roles.name = ?", model.RoleAdmin).
		Where("users.active = ?", true).
		Where("users.deleted_at IS NULL").
		Where("users.external_credential = ?", false).
		Where("users.is_ldap = ?", false).
		Where("users.password IS NOT NULL AND TRIM(users.password) <> ''").
		Where("users.provisioning_origin IS NULL OR users.provisioning_origin = '' OR users.provisioning_origin = ?",
			model.AuthSourceLocal)
}

// CountLocalAdmins 現存本地 admin 數。
// 管理端的「已無本地 admin」警示（不阻擋操作，僅提示解封能力已失）亦用此函式，
// 確保警示與不變式判定同一定義、不會出現「擋你的條件」與「告訴你的條件」不一致。
func CountLocalAdmins(tx *gorm.DB) (int64, error) {
	var n int64
	if err := localAdminScope(tx).Distinct("users.id").Count(&n).Error; err != nil {
		return 0, fmt.Errorf("統計本地管理員數量失敗: %w", err)
	}
	return n, nil
}

// isLocalAdmin 指定使用者當下是否計為本地 admin。
func isLocalAdmin(tx *gorm.DB, userID uint) (bool, error) {
	var n int64
	if err := localAdminScope(tx).Where("users.id = ?", userID).
		Distinct("users.id").Count(&n).Error; err != nil {
		return false, fmt.Errorf("查詢使用者本地管理員資格失敗: %w", err)
	}
	return n > 0, nil
}

// assertLocalAdminInvariant 鎖內判定：本操作若會使本地 admin 數自一降為零，回 ErrLastLocalAdmin。
//
// 前提：呼叫端保證本操作**會移除 targetUserID 的本地 admin 資格**（停用、刪除、
// 移除 admin 角色、改為僅外部登入）。不移除資格的操作（例如仍保留 admin 的角色
// 重設）不該經此判定——那會把「沒有減少」誤判為「減少」。
//
// 判定邏輯刻意分兩步而非「操作後數量必須 ≥1」：
//   - 目標當下不是本地 admin → 本操作不改變計數（含總數已為零的部署）→ 放行
//   - 目標是本地 admin 且總數 ≤1 → 一降為零 → 拒絕
func assertLocalAdminInvariant(tx *gorm.DB, targetUserID uint) error {
	isTarget, err := isLocalAdmin(tx, targetUserID)
	if err != nil {
		return err
	}
	if !isTarget {
		return nil
	}
	total, err := CountLocalAdmins(tx)
	if err != nil {
		return err
	}
	if total <= 1 {
		log.Printf("[LocalAdminInvariant] 拒絕：操作將使本地管理員自 %d 降為 0 (targetUserID=%d)",
			total, targetUserID)
		return ErrLastLocalAdmin
	}
	return nil
}

// WithLocalAdminInvariant 於系統級鎖內開交易、重讀判定不變式，通過後在**同一交易**內執行 fn。
//
// 四條路徑（停用、刪除、移除 admin 角色、2.8 的「改為僅外部登入」）一律經此進入；
// fn 內的寫入與判定同交易同鎖，故不存在「判定通過後、寫入前被他人插隊」的窗。
//
// **阻塞而非 try 語義**（與 withDataKeysLock 的取捨相反，刻意）：金鑰操作是低頻長任務，
// 回「另一操作進行中」讓管理者重試是合理的；帳號停用／刪除是高頻管理動作，try 失敗
// 會變成隨機的偽錯誤。持鎖時長界定為單次 DB 往返級（判定 ＋ fn 的資料寫入），
// 實際的收線／終斷連線一律由呼叫端於**鎖外**執行（關閉連線於鎖外）。
//
// 未知 dialect fail-close（沿用 withDataKeysLock 的白名單語義）：靜默退化為行程內鎖
// 會讓多實例部署失去保護，而本不變式失效的後果是不可逆的管理面鎖死。
func WithLocalAdminInvariant(db *gorm.DB, targetUserID uint, fn func(tx *gorm.DB) error) error {
	run := func(tx *gorm.DB) error {
		if err := assertLocalAdminInvariant(tx, targetUserID); err != nil {
			return err
		}
		if localAdminPreWriteHook != nil {
			localAdminPreWriteHook()
		}
		return fn(tx)
	}

	switch db.Dialector.Name() {
	case "postgres":
		return db.Transaction(func(tx *gorm.DB) error {
			// xact lock：隨交易結束自動釋放，無持有者崩潰殘留問題。
			// 阻塞版（非 try）——見上方取捨說明。
			if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", LocalAdminLockKey).Error; err != nil {
				return fmt.Errorf("取得本地管理員不變式互斥鎖失敗: %w", err)
			}
			return run(tx)
		})
	case "sqlite":
		localAdminProcessMu.Lock()
		defer localAdminProcessMu.Unlock()
		return db.Transaction(run)
	default:
		return fmt.Errorf("不支援的資料庫 dialect %q：無跨實例本地管理員互斥實作",
			db.Dialector.Name())
	}
}
