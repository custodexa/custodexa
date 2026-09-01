package keyvault

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"gorm.io/gorm"
)

// data_keys 跨實例互斥。
//
// 五個寫入路徑（RewrapKEK／AbandonRewrap／finalizeSwitch／RotateDataDEK／
// RotateAuditKey）一律經 withDataKeysLock 進入：postgres 以 advisory
// transaction lock 跨實例序列化；一切狀態判定（pending／backlog／campaign
// 歸屬）必須在鎖內交易重讀——鎖外預讀只可作 fast-fail 提示，不得作為寫入依據。
//
// advisory lock key 保留段：0x6F74_6B65_6B00_0000 起之高位元為 "otkek" ASCII
// 專案識別；低位元為子系統內編號。目前已用：
//
//	0x0001 data_keys 寫入互斥（本檔）
//	0x0002 最後本地 admin 不變式（LocalAdminLockKey，local_admin_invariant.go；
//	       撞號守衛見 TestLocalAdminLockKeyDistinct）
//	0x0003 LDAP 目錄設定寫入互斥（LDAPDirectoryLockKey，ldap_directory_service.go；
//	       CRUD 與 env seed 共用，撞號守衛見 TestLDAPDirectoryLockKeyDistinct。
//	       **刻意不複用 0x0001**：withDataKeysLock 綁在 KeyManagerService 上且
//	       硬寫本檔的 key，共用會使目錄設定存檔與 KEK 輪替無謂互斥）
//	0x0004 單實例開機守衛（database.InstanceGuardLockKey，internal/database/instance_guard.go；
//	       **session 級**、由一條終生不歸池的釘選連線持有、持鎖期＝行程生命期。
//	       撞號守衛見 cmd/server 的 TestInstanceGuardLockKeyDistinct——infra 不得反向
//	       import keyvault，故守衛置於組裝根，直接以四把匯出常數兩兩比對）
//	0x0005 離機儲存設定世代寫入互斥（offsite.OffsiteProfileLockKey，
//	       internal/offsite/profile_lock.go；**五個寫入者共用**——Save／
//	       ConfirmGenerationSwitch／RevokeCredentials／Disable／env seed。
//	       撞號守衛見 TestOffsiteProfileLockKeyDistinct）
//
// 新增 advisory lock 一律在此檔登記，防跨子系統撞號。
//
// **兩參數形式（classid, objid）另有其鎖空間**，與上述 64 位元鍵天然不相撞；
// 已用 classid：
//
//	0x6F74_6B03 使用者憑證世代 user-scoped 鎖（userCredentialLockClass，
//	            user_credential_lock.go；objid 為 userID）
//
// **非 advisory 的跨實例互斥亦在此登記**（否則「所有跨實例鎖都能在本檔追溯」的
// 慣例會有漏）：
//
//	provider 認證世代鎖（oidc_provider_lock.go）採 `SELECT ... FOR UPDATE` 的
//	**資料列鎖**，不佔用任何 advisory key。取列鎖而非 advisory 的理由是不同
//	provider 天然互不阻塞，且鎖的生命週期與該列的交易完全一致。
//	取鎖順序：system（LocalAdminLockKey）→ provider（列鎖）→
//	user（userCredentialLockClass）。
const KEKDataKeysLockKey int64 = 0x6F74_6B65_6B00_0001

// ErrKeyOpBusy 取鎖失敗：另一金鑰操作進行中（或鎖被其他連線佔用——
// 兩者對本端不可區分，訊息不假稱能區分）。try 語義不阻塞，管理操作可重試。
var ErrKeyOpBusy = errors.New("另一金鑰操作進行中或互斥鎖被佔用，請稍後重試")

// kekProcessMu 無 advisory lock 能力環境（sqlite 測試）的等價序列化：
// package 層級共用（跨 service 實例）、TryLock 非阻塞——與 postgres 路徑同語義。
// 注意這不是 per-instance rotMu：單行程多 service 實例的互斥測試依賴此鎖。
var kekProcessMu sync.Mutex

// withDataKeysLock 以 try 語義取得 data_keys 互斥，並在單一交易內執行 fn。
// 取不到鎖回 ErrKeyOpBusy（不阻塞）。postgres 的 advisory xact lock 隨交易
// 結束自動釋放，無持有者崩潰殘留問題。
func (s *KeyManagerService) withDataKeysLock(fn func(tx *gorm.DB) error) error {
	switch s.db.Dialector.Name() {
	case "postgres":
		return s.db.Transaction(func(tx *gorm.DB) error {
			var got bool
			if err := tx.Raw("SELECT pg_try_advisory_xact_lock(?)", KEKDataKeysLockKey).
				Scan(&got).Error; err != nil {
				return fmt.Errorf("取得金鑰互斥鎖失敗: %w", err)
			}
			if !got {
				return ErrKeyOpBusy
			}
			return fn(tx)
		})
	case "sqlite":
		if !kekProcessMu.TryLock() {
			return ErrKeyOpBusy
		}
		defer kekProcessMu.Unlock()
		return s.db.Transaction(fn)
	default:
		// 白名單 fail-close：未知 dialect 無跨實例互斥能力，
		// 靜默退化為行程內鎖會讓多實例部署失去保護——直接拒絕
		return fmt.Errorf("不支援的資料庫 dialect %q：無跨實例金鑰互斥實作", s.db.Dialector.Name())
	}
}

// sessionLockUnlockTimeout 解鎖收尾的 bounded context 上限（不繼承請求 context）
const sessionLockUnlockTimeout = 5 * time.Second

// pgSessionLockAcquireSQL session 級取鎖查詢。
//
// **可覆寫的唯一理由是測試**（使該分支可驗證）：「DB 端已取得鎖、
// 但取鎖回應在客戶端失敗」這條路徑是本檔最危險的分支（歸池即永久鎖洩漏），
// 而它在真 postgres 上無法用一般手段觸發。測試以「多回一欄使 Scan 失敗」的變體
// 覆寫本變數，即可在鎖確實已被 DB 端授予的前提下走進錯誤路徑。
// 生產路徑不改寫本變數；改寫者僅限 _test.go。
var pgSessionLockAcquireSQL = "SELECT pg_try_advisory_lock($1)"

// withKeyOpSessionLock 以 **session 級** advisory lock 執行長任務（鎖分級）。
//
// **為何不用 withDataKeysLock 的 xact lock**：AAD 正向遷移與退版回寫是可中斷續跑、
// 逐值失敗續行的長任務，包成單一大交易＝失敗回滾全部進度＋長持鎖阻塞其他金鑰操作，
// 與該語義直接牴觸。故本鎖與交易解耦：鎖由**一條釘選的連線**持有，任務本體在一般
// 連線池上以逐值小交易推進。
//
// **同一把 key `KEKDataKeysLockKey`**（與 xact lock 共 keyspace 故天然互斥）：
// 長任務持鎖期間 enable／rotate／rewrap／cleanup 一律 ErrKeyOpBusy，反之亦然——
// 此為設計行為，非缺陷。
//
// postgres：`sqlDB.Conn(ctx)` 釘選單一連線取 `pg_try_advisory_lock`，解鎖必須落在
// **同一條連線**（經連線池取鎖則解鎖可能落到另一條＝永久鎖洩漏）。解鎖收尾使用獨立
// 的 bounded cleanup context（不繼承可能已取消的請求 context）、核對回傳值為 true，
// 失敗即丟棄該實體連線——連線關閉時 postgres 自動釋放其 session lock。
//
// **ctx 為操作 context**：取池連線與取鎖都受呼叫端的取消／逾時
// 支配，否則請求早已中止而本函式仍在池上乾等。解鎖 cleanup 另用獨立的 bounded
// context，不繼承可能已取消的 ctx。
//
// **取鎖回應失敗一律丟棄實體連線**：`pg_try_advisory_lock`
// 可能已在 DB 端授予、僅回應在客戶端失敗（連線中斷、context 取消、回應解析失敗）。
// 此時把連線歸池＝一條持鎖的連線回到池中＝**永久鎖洩漏**。故該路徑以
// driver.ErrBadConn 語義丟棄連線，由 postgres 隨連線結束釋放其 session lock。
// 「取不到鎖」（got=false）則不同：DB 端明確未授予，連線乾淨，正常歸池。
//
// sqlite：`kekProcessMu.TryLock` 全程持有，**不開外層交易**——照抄 withDataKeysLock
// 的 `db.Transaction(fn)` 會使測試環境變成單一大交易，驗的是與生產相反的語義。
//
// 未知 dialect fail-close（同 withDataKeysLock 的白名單語義）。
func withKeyOpSessionLock(ctx context.Context, db *gorm.DB, fn func() error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	switch db.Dialector.Name() {
	case "postgres":
		sqlDB, err := db.DB()
		if err != nil {
			return fmt.Errorf("取得底層連線池失敗: %w", err)
		}
		conn, err := sqlDB.Conn(ctx)
		if err != nil {
			return fmt.Errorf("釘選連線失敗（session 級金鑰互斥鎖）: %w", err)
		}
		var got bool
		if err := conn.QueryRowContext(ctx,
			pgSessionLockAcquireSQL, KEKDataKeysLockKey).Scan(&got); err != nil {
			// 鎖可能已在 DB 端授予：SHALL NOT 歸池
			discardPGConn(conn)
			return fmt.Errorf("取得金鑰互斥鎖（session 級）失敗（已丟棄該連線以確保不殘留鎖）: %w", err)
		}
		if !got {
			_ = conn.Close()
			return ErrKeyOpBusy
		}
		// defer 保證 panic 亦解鎖（否則一次 panic 就是永久鎖洩漏）
		defer releasePGSessionLock(conn)
		return fn()
	case "sqlite":
		if !kekProcessMu.TryLock() {
			return ErrKeyOpBusy
		}
		defer kekProcessMu.Unlock()
		return fn()
	default:
		return fmt.Errorf("不支援的資料庫 dialect %q：無跨實例金鑰互斥實作", db.Dialector.Name())
	}
}

// releasePGSessionLock 於釘選連線上解鎖並歸還；核對失敗即丟棄該實體連線。
func releasePGSessionLock(conn *sql.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), sessionLockUnlockTimeout)
	defer cancel()
	var released bool
	err := conn.QueryRowContext(ctx,
		"SELECT pg_advisory_unlock($1)", KEKDataKeysLockKey).Scan(&released)
	if err != nil || !released {
		log.Printf("[KeyManager] session 級互斥鎖解鎖未確認（err=%v, released=%v）：丟棄該連線以強制釋放", err, released)
		discardPGConn(conn)
		return
	}
	_ = conn.Close()
}

// discardPGConn 丟棄實體連線（**不歸池**）：以 driver.ErrBadConn 語義標記後關閉，
// database/sql 於此情形實體關閉連線而非歸還池；postgres 隨連線結束自動釋放其
// session 級 advisory lock。凡「鎖狀態不可知」的路徑一律走此函式。
func discardPGConn(conn *sql.Conn) {
	_ = conn.Raw(func(any) error { return driver.ErrBadConn })
	_ = conn.Close()
}
