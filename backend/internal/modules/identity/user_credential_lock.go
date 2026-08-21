package identity

import (
	"fmt"
	"sync"

	"gorm.io/gorm"
)

// user-scoped 憑證鎖（idp-oidc-integration 2.8 / design D13）。
//
// 用途：凡「以該使用者的登入途徑或憑證世代為前提做出判定、再據以寫入」的操作
// SHALL 於本鎖內完成「重讀前提 → 判定 → 寫入」三步。單次操作內的檢查擋不住
// write-skew——帳號有兩筆外部身分時，兩個並發解綁各自看見「還有另一筆」即可
// 同時提交，結果登入途徑歸零（design 行 341，codex MEDIUM）。
//
// **與 localAdminLockKey 的分工**：後者是系統級（全體本地 admin 的總數不變式），
// 本鎖是使用者級（單一帳號的登入途徑與憑證世代）。同時需要兩者的操作
//（解綁＋停用、改為僅外部登入）一律**先系統後使用者**，即 design D13 所定的
// system → provider → user 固定順序，避免與其他持鎖路徑互鎖。
//
// **鎖內只做 DB 判定與寫入**：實際的收線（終斷協議會話、收線監看訂閱、撤銷
// 錄影 token）一律由呼叫端於鎖外執行，持鎖時長維持在單次 DB 往返級
//（同 WithLocalAdminInvariant 的取捨）。

// userCredentialLockClass postgres 兩參數 advisory lock 的 classid。
//
// 取**兩參數形式**（classid, objid）而非 64 位元單鍵：objid 直接放 userID，
// 使不同使用者的操作天然並行，不會像單一全域鍵那樣把所有帳號的解綁序列化。
// postgres 的「一個 64 位元鍵」與「兩個 32 位元鍵」屬**不同的鎖空間**，
// 故本 classid 與 key_manager_lock.go 登記的 KEKDataKeysLockKey／localAdminLockKey
// 天然不會相撞；classid 值仍取自同一保留段（"otk" ASCII ＋ 子系統序號 0x03）
// 以維持「所有 advisory lock 都能在該檔追溯」的慣例。
const userCredentialLockClass int32 = 0x6F74_6B03

// userCredentialMu 無 advisory lock 能力環境（sqlite）的等價序列化：per-user 互斥。
// package 層級共用（跨 UserService 實例），與 postgres 路徑同語義。
var userCredentialMu sync.Map // uint -> *sync.Mutex

func userCredentialLockFor(userID uint) *sync.Mutex {
	mu, _ := userCredentialMu.LoadOrStore(userID, &sync.Mutex{})
	return mu.(*sync.Mutex)
}

// userCredentialPreWriteHook 測試用同步點：於「判定通過之後、實際寫入之前」呼叫。
//
// 同 localAdminPreWriteHook 的理由（key_manager_lock.go 的 pgSessionLockAcquireSQL 慣例）：
// write-skew 只在特定交錯下成立，靠時間競賽觸發不穩定；本 hook 讓並發測試在該精確
// 位置製造交錯，使「把鎖內重讀改成鎖外預讀」的突變被**確定性**地抓到。
// 生產路徑此值恆為 nil，改寫者僅限 _test.go。
//
// **變數維持未匯出**（modular-architecture W8 9.9）：跨包後以
// `SetUserCredentialPreWriteHookForTest`（`export_test.go`）這個窄出口暴露，
// 理由同 `oidcProviderPreWriteHook`——匯出可寫的包級 hook 等於讓任何包覆寫
// 別人掛的同步點。
var userCredentialPreWriteHook func()

// WithUserCredentialLock 取得使用者級鎖後開交易執行 fn（判定與寫入同鎖同交易）。
//
// 阻塞而非 try 語義：解綁／轉換皆為管理者的互動操作，try 失敗會變成隨機的偽錯誤。
// 未知 dialect fail-close——靜默退化為行程內鎖會使多副本部署失去保護。
//
// **兩種 dialect 一律先開交易、再於交易內取鎖**（批 14 對抗審查 M2）：sqlite 分支
// 原本先取 mutex 再開交易，與 withUserCredentialLockTx（呼叫端已持交易）相反，
// 兩條路徑對同一 userID 並發即循環等待。詳見 WithCapabilityLocks 的同段說明。
func WithUserCredentialLock(db *gorm.DB, userID uint, fn func(tx *gorm.DB) error) error {
	switch db.Dialector.Name() {
	case "postgres", "sqlite":
		return db.Transaction(func(tx *gorm.DB) error {
			return withUserCredentialLockTx(tx, userID, fn)
		})
	default:
		return fmt.Errorf("不支援的資料庫 dialect %q：無跨實例使用者憑證互斥實作",
			db.Dialector.Name())
	}
}

// withUserCredentialLockTx 於**既有交易**內取得使用者級鎖。
//
// 供「已持系統級鎖（WithLocalAdminInvariant 已開交易）」的操作使用——解綁＋停用、
// 改為僅外部登入兩者同時受兩個不變式約束，須在同一交易內依 system → user 的
// 固定順序疊加，不得各開一個交易（那會使兩段寫入不再原子）。
func withUserCredentialLockTx(tx *gorm.DB, userID uint, fn func(tx *gorm.DB) error) error {
	switch tx.Dialector.Name() {
	case "postgres":
		// xact lock：隨交易結束自動釋放，無持有者崩潰殘留問題
		// userID 經 ParseUint(bitSize 32) 而來，uint32→int32 在該值域內是雙射，
		// advisory lock key（pg 的 int4 objid）唯一性不受影響
		if err := tx.Exec("SELECT pg_advisory_xact_lock(?, ?)",
			userCredentialLockClass, int32(uint32(userID))).Error; err != nil {
			return fmt.Errorf("取得使用者憑證互斥鎖失敗: %w", err)
		}
		return fn(tx)
	case "sqlite":
		mu := userCredentialLockFor(userID)
		mu.Lock()
		defer mu.Unlock()
		return fn(tx)
	default:
		return fmt.Errorf("不支援的資料庫 dialect %q：無跨實例使用者憑證互斥實作",
			tx.Dialector.Name())
	}
}
