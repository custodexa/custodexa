package offsite

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"gorm.io/gorm"
)

// 離機儲存設定世代表（`offsite_profiles`）寫入路徑的並發線性化。
//
// **獨立成檔**沿本專案的既有歸檔慣例：跨實例鎖一律有自己的檔
// （key_manager_lock.go、user_credential_lock.go、oidc_provider_lock.go、
// ldap_directory_lock.go），使「這個子系統怎麼互斥的」不必到服務本體裡撈。
//
// # 為什麼 DB 約束不夠
//
// `CHECK (singleton = 1)` ＋ partial unique index 保的是**資料正確**，不保
// **upsert 語義**：兩個並發儲存（或儲存與 env seed）同時在鎖外讀到空表，
// 兩者都會走「無現行世代 → 建立」，其一撞 unique violation 而對 admin 回 500。
// 世代切換的確認流程更嚴重——CAS 的「重讀現行世代」若不在鎖內，
// 兩名管理員的確認可能交錯成兩列現行世代。
//
// 共同解是同一把交易範圍互斥：`WithOffsiteProfileLock` 是**五個寫入者的唯一入口**
// （Save／ConfirmGenerationSwitch／RevokeCredentials／Disable／env seed），
// **一切判定於鎖內以 tx 重讀**——鎖外預讀只能當提示，不得作為寫入依據。

// OffsiteProfileLockKey 離機儲存設定寫入的 advisory lock key。
//
// **自有 key、不複用既有四把**：與 KEK 輪替、LDAP 目錄設定、單實例開機守衛
// 各自無關，共用會製造無謂互斥（admin 存個 bucket 名卻被「另一金鑰操作進行中」擋下）。
//
// 取號沿 key_manager_lock.go 的保留段（"otkek" ASCII ＋ 子系統序號 0x0005），
// 並已於該檔的 keyspace 清單登記——該檔明文要求「新增 advisory lock 一律在此檔登記」。
// 撞號守衛見 TestOffsiteProfileLockKeyDistinct。
const OffsiteProfileLockKey int64 = 0x6F74_6B65_6B00_0005

// offsiteProfileProcessMu 無 advisory lock 能力環境（sqlite 測試）的等價序列化。
// package 層級共用（跨 service 實例）、TryLock 非阻塞——與 postgres 路徑同語義
var offsiteProfileProcessMu sync.Mutex

// offsiteProfilePreWriteHook 測試用同步點：於「判定通過之後、實際寫入之前」呼叫。
//
// 同 ldapDirectoryPreWriteHook 的理由：並發語義只在特定交錯下可辨識，靠時間競賽
// 觸發不穩定；本 hook 讓測試在鎖內製造**確定性**的交錯，使「把互斥拿掉」或
// 「把 CAS 移到鎖外」的突變被穩定抓到。生產路徑恆為 nil，改寫者僅限 _test.go
var offsiteProfilePreWriteHook func()

// ErrOffsiteProfileBusy 取鎖失敗：另一項離機儲存設定操作進行中。
// try 語義不阻塞，呼叫端可重試——**不是 500**，admin 重按一次即可
var ErrOffsiteProfileBusy = errors.New("另一項離機儲存設定操作進行中，請稍後重試")

// ErrOffsiteProfileConflict 單列約束衝突（unique violation）。
//
// 鎖已使正常路徑不可能撞上，本錯誤是**最後防線**：跨版本混跑、鎖被繞過或手工 SQL
// 都可能製造第二列現行世代。與 Busy 同樣是可重試語義，不外洩為 500
var ErrOffsiteProfileConflict = errors.New("離機儲存設定併發衝突，請重新讀取後再試")

// WithOffsiteProfileLock 取得離機儲存設定互斥後，於**單一交易**內執行 fn。
//
// try 語義：取不到鎖回 ErrOffsiteProfileBusy（不阻塞）。postgres 的 advisory
// xact lock 隨交易結束自動釋放，無持有者崩潰殘留問題。
//
// dialect 白名單 fail-close（沿 withDataKeysLock／WithLDAPDirectoryLock 語義）：
// 未知 dialect 無跨實例互斥能力，靜默退化為行程內鎖會讓多實例部署失去保護
// ——直接拒絕。
func WithOffsiteProfileLock(db *gorm.DB, fn func(tx *gorm.DB) error) error {
	switch db.Dialector.Name() {
	case "postgres":
		return db.Transaction(func(tx *gorm.DB) error {
			var got bool
			if err := tx.Raw("SELECT pg_try_advisory_xact_lock(?)", OffsiteProfileLockKey).
				Scan(&got).Error; err != nil {
				return fmt.Errorf("取得離機儲存設定互斥鎖失敗: %w", err)
			}
			if !got {
				return ErrOffsiteProfileBusy
			}
			return fn(tx)
		})
	case "sqlite":
		if !offsiteProfileProcessMu.TryLock() {
			return ErrOffsiteProfileBusy
		}
		defer offsiteProfileProcessMu.Unlock()
		return db.Transaction(fn)
	default:
		return fmt.Errorf("不支援的資料庫 dialect %q：無跨實例離機儲存設定互斥實作",
			db.Dialector.Name())
	}
}

// offsiteProfileWriteError 把寫入路徑的底層錯誤轉為哨兵錯誤。
//
// unique violation 是單列約束的最後防線；轉哨兵而非原樣上拋，使 handler 能回
// 可重試的機器碼而非 500
func offsiteProfileWriteError(err error) error {
	if err == nil {
		return nil
	}
	if isOffsiteProfileUniqueViolation(err) {
		return ErrOffsiteProfileConflict
	}
	return err
}

// isOffsiteProfileUniqueViolation 判定是否為唯一約束衝突。
//
// 以訊息比對而非 driver 型別：本專案未啟用 GORM 的 TranslateError，且同一份
// 程式碼同時跑在 postgres（生產）與 sqlite（單元測試）上
func isOffsiteProfileUniqueViolation(err error) bool {
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint") ||
		strings.Contains(msg, "duplicate key value") ||
		strings.Contains(msg, "sqlstate 23505")
}
