package identity

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"gorm.io/gorm"
)

// LDAP 目錄設定寫入路徑的並發線性化（ldap-settings-migration D1）。
//
// **獨立成檔**沿本專案的既有歸檔慣例：跨實例鎖一律有自己的檔
// （key_manager_lock.go、user_credential_lock.go、oidc_provider_lock.go），
// 使「這個子系統怎麼互斥的」不必到服務本體裡撈。
//
// # 為什麼 DB 約束不夠
//
// `CHECK (singleton = 1)` ＋ partial unique index 保的是**資料正確**，不保
// **upsert 語義**：兩個並發 PUT（或 PUT 與 env seed）同時讀到空表，兩者都會
// 走「無列 → 建立」，其一撞 unique violation 而對 admin 回 500。更隱蔽的是
// seed 的軟刪競態——seed 在事務外看到空表，並行的「建立後軟刪」使 partial
// unique index 不佔位，seed 於是插入一列**啟用的外部認證來源**。
//
// 兩者的共同解是同一把交易範圍互斥：`WithLDAPDirectoryLock` 為 CRUD 與 seed
// 的唯一寫入入口，**一切判定於鎖內以 tx 重讀**（鎖外預讀只能當提示）。

// ── 跨實例互斥（D1）──────────────────────────────────────────────────────

// ldapDirectoryLockKey LDAP 目錄設定寫入的 advisory lock key。
//
// **自有 key、不複用 KEKDataKeysLockKey**（D1／R3-opus MED）：`withDataKeysLock`
// 綁在 KeyManagerService 上且硬寫 KEK 的 key，共用會使目錄設定的存檔與 KEK
// 輪替無謂互斥（admin 存個 base DN 卻被「另一金鑰操作進行中」擋下）。
//
// 取號沿 key_manager_lock.go 的保留段（"otkek" ASCII ＋ 子系統序號），並已於
// 該檔的 keyspace 清單登記——比照 user_credential_lock.go 的先例，所有跨實例
// 鎖都要能在該檔追溯。撞號守衛見 TestLDAPDirectoryLockKeyDistinct。
const ldapDirectoryLockKey int64 = 0x6F74_6B65_6B00_0003

// ldapDirectoryProcessMu 無 advisory lock 能力環境（sqlite 測試）的等價序列化。
// package 層級共用（跨 service 實例）、TryLock 非阻塞——與 postgres 路徑同語義
var ldapDirectoryProcessMu sync.Mutex

// ldapDirectoryPreWriteHook 測試用同步點：於「判定通過之後、實際寫入之前」呼叫。
//
// 同 userCredentialPreWriteHook 的理由：並發語義只在特定交錯下可辨識，靠時間
// 競賽觸發不穩定；本 hook 讓測試在鎖內製造確定性的交錯，使「把互斥拿掉」或
// 「把判定移到鎖外」的突變被穩定抓到。生產路徑恆為 nil，改寫者僅限 _test.go
var ldapDirectoryPreWriteHook func()

// ErrLDAPDirectoryBusy 取鎖失敗：另一項目錄設定操作進行中。
// try 語義不阻塞，呼叫端可重試——**不是 500**，admin 重按一次即可
var ErrLDAPDirectoryBusy = errors.New("另一項 LDAP 目錄設定操作進行中，請稍後重試")

// ErrLDAPDirectoryConflict 單列約束衝突（unique violation）。
//
// 鎖已使正常路徑不可能撞上，本錯誤是**最後防線**：跨版本混跑、鎖被繞過或
// 手工 SQL 都可能製造第二列。與 Busy 同樣是可重試語義，不外洩為 500
var ErrLDAPDirectoryConflict = errors.New("LDAP 目錄設定併發衝突，請重新讀取後再試")

// WithLDAPDirectoryLock 取得 LDAP 目錄設定互斥後，於**單一交易**內執行 fn。
//
// 供本檔的 CRUD 與 seed（ldap_seed_migration.go 的「表非空」判定與插列）共用：
// 兩者對同一張表做「先判定、後寫入」，不共用互斥即存在軟刪競態——seed 在事務外
// 看到空表，並行的「建立後軟刪」使 partial unique index 不佔位，seed 仍插入一列
// 啟用設定。**呼叫端的一切判定必須在 fn 內以 tx 重讀**，鎖外預讀不算數。
//
// try 語義：取不到鎖回 ErrLDAPDirectoryBusy（不阻塞）。postgres 的 advisory
// xact lock 隨交易結束自動釋放，無持有者崩潰殘留問題。
//
// dialect 白名單 fail-close（沿 withDataKeysLock 語義）：未知 dialect 無跨實例
// 互斥能力，靜默退化為行程內鎖會讓多實例部署失去保護——直接拒絕。
func WithLDAPDirectoryLock(db *gorm.DB, fn func(tx *gorm.DB) error) error {
	switch db.Dialector.Name() {
	case "postgres":
		return db.Transaction(func(tx *gorm.DB) error {
			var got bool
			if err := tx.Raw("SELECT pg_try_advisory_xact_lock(?)", ldapDirectoryLockKey).
				Scan(&got).Error; err != nil {
				return fmt.Errorf("取得 LDAP 目錄設定互斥鎖失敗: %w", err)
			}
			if !got {
				return ErrLDAPDirectoryBusy
			}
			return fn(tx)
		})
	case "sqlite":
		if !ldapDirectoryProcessMu.TryLock() {
			return ErrLDAPDirectoryBusy
		}
		defer ldapDirectoryProcessMu.Unlock()
		return db.Transaction(fn)
	default:
		return fmt.Errorf("不支援的資料庫 dialect %q：無跨實例 LDAP 目錄設定互斥實作",
			db.Dialector.Name())
	}
}

// ldapDirectoryWriteError 把寫入路徑的底層錯誤轉為哨兵錯誤。
//
// unique violation 是單列約束的最後防線；轉哨兵而非原樣上拋，使 3.1 能回可
// 重試的機器碼而非 500
func ldapDirectoryWriteError(err error) error {
	if err == nil {
		return nil
	}
	if isLDAPDirectoryUniqueViolation(err) {
		return ErrLDAPDirectoryConflict
	}
	return err
}

// isLDAPDirectoryUniqueViolation 判定是否為唯一約束衝突。
//
// 以訊息比對而非 driver 型別：本專案未啟用 GORM 的 TranslateError，且同一份
// 程式碼同時跑在 postgres（生產）與 sqlite（單元測試）上
func isLDAPDirectoryUniqueViolation(err error) bool {
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint") ||
		strings.Contains(msg, "duplicate key value") ||
		strings.Contains(msg, "sqlstate 23505")
}
