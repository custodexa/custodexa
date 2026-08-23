package identity

import (
	"fmt"
	"sync"

	"gorm.io/gorm"
)

// provider-scoped 認證世代鎖（3.8a）。
//
// 用途：凡「以某 provider 的 auth_epoch 為前提做出判定、再據以建立長效能力」的
// 位置，SHALL 於本鎖內完成「重查前提 → 讀世代 → 建立」三步；provider 的停用／
// 刪除／密鑰輪替亦於同一把鎖內完成「推進 epoch → 掃描標記」。
//
// **單純先查後插擋不住這個序列**（design 行 266）：
//
//	兌換讀到 epoch=7 → 停用推進至 8 並完成 session 掃描終斷 → 兌換才插入 epoch=7
//	的 session → 該連線不在掃描集合內，而協議連線建立後沒有持續的 token 檢查，
//	於是永久存活。
//
// **取列鎖而非 advisory lock**（design 行 268）：pg 以 `SELECT ... FOR UPDATE`
// 鎖該 provider 列，不同 provider 天然互不阻塞，且無須在 key_manager_lock.go
// 佔用新的 advisory key（該檔的登記段落已註明本鎖採列鎖路徑）。
// sqlite 無列鎖語義，改以 per-provider key mutex 等價序列化。
//
// **阻塞而非 try 語義**（design 行 268 明令）：連線 token 是一次性的，取不到鎖
// 就回錯會讓使用者的連線嘗試直接失敗且**不可重試**（token 已焚）。
//
// **鎖內只做 DB 判定與標記**：實際關閉 WS、收線監看訂閱、撤銷錄影 token 一律
// 由呼叫端於鎖外執行，持鎖時長因此界定為單次 DB 往返級——`internal/proxy` 的
// 計時敏感測試已有 flaky 前科，長時間持鎖會把它變成常態。
//
// **取鎖順序固定 system → provider → user**（design 行 264）：system 級即
// local_admin_invariant.go 的 localAdminLockKey；同時需要 provider 與 user 兩把者
// 一律經 WithCapabilityLocks 進入，不得自行分開取。

// oidcProviderRowLockSQL pg 的 provider 列鎖。
//
// **刻意不帶 `deleted_at IS NULL`**：軟刪的 provider 列仍實體存在，且刪除路徑
// 本身就要在鎖內推進世代與掃描；若查詢條件排除軟刪列，刪除完成後任何殘留的
// 兌換請求都會鎖到「零列」而完全失去序列化。
//
// var 而非 const：測試以此驗證取鎖語句確實被送出。
var oidcProviderRowLockSQL = "SELECT id FROM oidc_providers WHERE id = ? FOR UPDATE"

// oidcProviderMu 無列鎖語義環境（sqlite）的等價序列化：per-provider 互斥。
// package 層級共用（跨 service 實例），與 postgres 路徑同語義。
var oidcProviderMu sync.Map // uint -> *sync.Mutex

func oidcProviderLockFor(providerID uint) *sync.Mutex {
	mu, _ := oidcProviderMu.LoadOrStore(providerID, &sync.Mutex{})
	return mu.(*sync.Mutex)
}

// 序列化同步點的位置標籤。每個「以既有身分或憑證產生新長效能力」的位置各有一個，
// 使並發測試能只掛住其中一邊——兩邊都掛會在鎖生效時直接互相等死，測不出東西。
//
// **匯出面只留有生產跨包消費者的兩個**（export budget 收斂）：
// `OIDCSiteSessionCreate`／`OIDCSiteMonitorJoin` 由 `internal/service` 的
// `session_provider_termination.go` 傳給 `FirePreWriteHook`，故必須是公開常數；
// 其餘三個只有 identity 自己觸發，測試側經 `export_test.go` 的同名別名取得。
const (
	OIDCSiteSessionCreate = "session_create" // connect token 兌換建 session（生產跨包消費）
	OIDCSiteMonitorJoin   = "monitor_join"   // 監看／分享訂閱 Join（生產跨包消費）

	oidcSiteProviderInvalidate = "provider_invalidate" // 停用／刪除／輪替的鎖內失效
	oidcSiteTicketIssue        = "ticket_issue"        // callback 簽 ticket
	oidcSiteTicketExchange     = "ticket_exchange"     // ticket 兌換正式會話
)

// oidcProviderPreWriteHook 測試用同步點：於「鎖內前提重讀通過之後、實際寫入之前」呼叫。
//
// 同 localAdminPreWriteHook／userCredentialPreWriteHook 的理由：TOCTOU 只在特定
// 交錯下成立，靠時間競賽觸發不穩定；本 hook 讓並發測試在該精確位置製造交錯，
// 使「把鎖內重讀改成鎖外預讀」或「拿掉鎖本身」的突變被**確定性**地抓到。
// 生產路徑此值恆為 nil，改寫者僅限 _test.go。
//
// **變數本身維持未匯出**：跨包後改以
// `FirePreWriteHook`（觸發，生產面）與 `SetPreWriteHookForTest`（設定，
// `export_test.go`）兩個窄出口暴露，而不是把 var 匯出——匯出可寫的包級 hook
// 等於讓任何包都能覆寫別人掛的同步點。
var oidcProviderPreWriteHook func(site string)

// FirePreWriteHook 於序列化同步點觸發測試 hook（生產路徑恆為 no-op）。
//
// **存在理由是跨包**：session 模組的 `CreateWithGenerationGuard`／
// `JoinWithGenerationGuard` 在 identity 的能力鎖交易內，且同步點必須落在
// 「鎖內重讀通過之後、實際寫入之前」——那一點在 session 的程式碼裡，
// 但 hook 與位置標籤屬於 identity 的序列化契約。
func FirePreWriteHook(site string) {
	if oidcProviderPreWriteHook != nil {
		oidcProviderPreWriteHook(site)
	}
}

// WithOIDCProviderLock 取得 provider 級鎖後開交易執行 fn（判定與寫入同鎖同交易）。
//
// providerID 為 0 時**不取鎖直接開交易**：0 是「本地／LDAP 登入」的語義，
// 不對應任何 provider 列，取鎖無意義（且 sqlite 路徑會把所有本地登入序列化）。
func WithOIDCProviderLock(db *gorm.DB, providerID uint, fn func(tx *gorm.DB) error) error {
	return WithCapabilityLocks(db, providerID, 0, fn)
}

// WithCapabilityLocks 以固定順序取 provider 鎖與 user 鎖後執行 fn。
//
// 「以既有身分或憑證產生新長效能力」的位置（連線兌換建 session、監看／分享訂閱
// Join、callback 簽 ticket、ticket exchange、refresh 輪替）一律經此進入：
// 兩種世代各有其對應鎖（auth_epoch → provider、credential_epoch → user），
// 兩者皆須時**順序固定為 provider → user**（system 級鎖若需要，由更外層先取）。
//
// 任一 ID 為 0 即跳過該把鎖（0 為「不適用」的既有零值語義，非萬用字元）。
// **兩種 dialect 一律先開交易、再於交易內取鎖**：
// sqlite 分支原本把 key mutex 取在 db.Transaction 之外，與已持交易才取鎖的
// withCapabilityLocksTx／withUserCredentialLockTx（WithLocalAdminInvariant 走這條）
// 形成相反的取鎖順序——一邊持連線等 mutex、另一邊持 mutex 等連線，對同一 userID
// 並發即循環等待（SetMaxOpenConns(1) 下永久掛住）。順序統一後兩條路徑同形。
func WithCapabilityLocks(db *gorm.DB, providerID, userID uint, fn func(tx *gorm.DB) error) error {
	switch db.Dialector.Name() {
	case "postgres", "sqlite":
		return db.Transaction(func(tx *gorm.DB) error {
			return withCapabilityLocksTx(tx, providerID, userID, fn)
		})
	default:
		return fmt.Errorf("不支援的資料庫 dialect %q：無跨實例認證世代互斥實作",
			db.Dialector.Name())
	}
}

// withCapabilityLocksTx 於**既有交易**內依序取 provider 與 user 鎖。
//
// 供已由更外層開啟交易（例如已持 system 級鎖）的操作使用——多個不變式同時適用時
// 須在同一交易內疊加，不得各開一個交易（那會使各段寫入不再原子）。
func withCapabilityLocksTx(tx *gorm.DB, providerID, userID uint, fn func(tx *gorm.DB) error) error {
	switch tx.Dialector.Name() {
	case "postgres":
		if providerID != 0 {
			// 阻塞式列鎖：取不到就等，不回 busy（一次性 token 不可重試）
			var locked []uint
			if err := tx.Raw(oidcProviderRowLockSQL, providerID).Scan(&locked).Error; err != nil {
				return fmt.Errorf("取得 provider 世代互斥鎖失敗: %w", err)
			}
		}
		if userID != 0 {
			return withUserCredentialLockTx(tx, userID, fn)
		}
		return fn(tx)
	case "sqlite":
		unlock := lockCapabilityKeys(providerID, userID)
		defer unlock()
		return fn(tx)
	default:
		return fmt.Errorf("不支援的資料庫 dialect %q：無跨實例認證世代互斥實作",
			tx.Dialector.Name())
	}
}

// lockCapabilityKeys sqlite 路徑的兩把 key mutex，順序 provider → user。
// 回傳的 unlock 以相反順序釋放。
func lockCapabilityKeys(providerID, userID uint) func() {
	var pMu, uMu *sync.Mutex
	if providerID != 0 {
		pMu = oidcProviderLockFor(providerID)
		pMu.Lock()
	}
	if userID != 0 {
		uMu = userCredentialLockFor(userID)
		uMu.Lock()
	}
	return func() {
		if uMu != nil {
			uMu.Unlock()
		}
		if pMu != nil {
			pMu.Unlock()
		}
	}
}
