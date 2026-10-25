package identity

import (
	"fmt"
	"github.com/custodexa/backend/internal/modules/authz"
	"math"
	"sort"
	"sync"

	"gorm.io/gorm"
)

// user-scoped 憑證鎖（2.8）。
//
// 用途：凡「以該使用者的登入途徑或憑證世代為前提做出判定、再據以寫入」的操作
// SHALL 於本鎖內完成「重讀前提 → 判定 → 寫入」三步。單次操作內的檢查擋不住
// write-skew——帳號有兩筆外部身分時，兩個並發解綁各自看見「還有另一筆」即可
// 同時提交，結果登入途徑歸零。
//
// **與 LocalAdminLockKey 的分工**：後者是系統級（全體本地 admin 的總數不變式），
// 本鎖是使用者級（單一帳號的登入途徑與憑證世代）。同時需要兩者的操作
//（解綁＋停用、改為僅外部登入）一律**先系統後使用者**，即
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
// 故本 classid 與 key_manager_lock.go 登記的 KEKDataKeysLockKey／LocalAdminLockKey
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
// **變數維持未匯出**：跨包後以
// `SetUserCredentialPreWriteHookForTest`（`export_test.go`）這個窄出口暴露，
// 理由同 `oidcProviderPreWriteHook`——匯出可寫的包級 hook 等於讓任何包覆寫
// 別人掛的同步點。
var userCredentialPreWriteHook func()

// WithUserCredentialLock 取得使用者級鎖後開交易執行 fn（判定與寫入同鎖同交易）。
//
// 阻塞而非 try 語義：解綁／轉換皆為管理者的互動操作，try 失敗會變成隨機的偽錯誤。
// 未知 dialect fail-close——靜默退化為行程內鎖會使多副本部署失去保護。
//
// **兩種 dialect 一律先開交易、再於交易內取鎖**：sqlite 分支
// 原本先取 mutex 再開交易，與 withUserCredentialLockTx（呼叫端已持交易）相反，
// 兩條路徑對同一 userID 並發即循環等待。詳見 WithCapabilityLocks 的同段說明。
func WithUserCredentialLock(db *gorm.DB, userID uint, fn func(tx *gorm.DB) error) error {
	switch db.Dialector.Name() {
	case "postgres", "sqlite":
		err := db.Transaction(func(tx *gorm.DB) error {
			return withUserCredentialLockTx(tx, userID, fn)
		})
		// 本鎖交易內的權限寫入（推進權限版本）於提交後通知行程內持有者重新驗證
		authz.NotifyVersionCommittedAfter(db, err)
		return err
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
	// postgres 分支把 userID 折成 int32 當 advisory lock 的 objid；折疊只在 32 位元值域內是雙射。
	// 呼叫端的 userID 來自 ParseUint(bitSize 32) 或 users.id（32 位元內），但這個不變式不在型別上，
	// 在此以入口檢查把它落成程式碼（兩種 dialect 一致，測試才打得到）
	if userID > math.MaxUint32 {
		return fmt.Errorf("使用者 ID %d 超出互斥鎖鍵值域（上限 %d）", userID, uint(math.MaxUint32))
	}
	switch tx.Dialector.Name() {
	case "postgres":
		// xact lock：隨交易結束自動釋放，無持有者崩潰殘留問題
		// userID 經 ParseUint(bitSize 32) 而來，uint32→int32 在該值域內是雙射，
		// advisory lock key（pg 的 int4 objid）唯一性不受影響
		if err := lockUserPairTx(tx, userID, true); err != nil {
			return err
		}
		if h := loadLockOrderHook(); h != nil {
			h("user_credential_lock_acquired", tx, userID)
		}
		return fn(tx)
	case "sqlite":
		// 鎖序守衛探針（測試期；生產恆為 nil）：取行程內互斥鎖之前
		if probe := authz.LockOrderProbeHook(); probe != nil {
			probe(tx, authz.LockLayerUserCredential, userID)
		}
		mu := userCredentialLockFor(userID)
		if h := loadUserMutexAcquireHook(); h != nil {
			h(userID)
		}
		mu.Lock()
		defer mu.Unlock()
		return fn(tx)
	default:
		return fmt.Errorf("不支援的資料庫 dialect %q：無跨實例使用者憑證互斥實作",
			tx.Dialector.Name())
	}
}

// 使用者層鎖有兩層：憑證互斥鎖（advisory，序列化帳號的登入途徑與憑證世代判定）與
// users 實體列鎖（FOR NO KEY UPDATE，序列化會寫該帳號列或以它為外鍵父列的路徑）。
// 同一交易內，使用者層資源依「使用者編號升冪、同一位先 advisory 後列鎖」的全序取得，
// 一位的兩把鎖緊接著取、中間不插入其他使用者的鎖，所以不同入口只要各自按此序就不會互等成環。
//
// 列鎖取 NO KEY UPDATE 而非 UPDATE：兩者都與其他寫入者互斥，但 NO KEY UPDATE 不擋
// 外鍵檢查對父列取的 KEY SHARE，指向 users 的外鍵寫入（建立者、擁有者、成員等）不會因為
// 有人持列鎖而與持有其他鎖的交易互等。

// lockUserRowTx 於既有交易內對單一 users 列取 FOR NO KEY UPDATE（僅 postgres）。
// 不帶 deleted_at 過濾：已軟刪的列照鎖；列不存在時不回錯，是否合法由呼叫端自行裁決。
func lockUserRowTx(tx *gorm.DB, userID uint) error {
	// 鎖序守衛探針（測試期；生產恆為 nil）：取帳號列鎖之前
	if probe := authz.LockOrderProbeHook(); probe != nil {
		probe(tx, authz.LockLayerUserRow, userID)
	}
	var ids []uint
	if err := tx.Raw(`SELECT "id" FROM "users" WHERE "id" = ? FOR NO KEY UPDATE`, userID).Scan(&ids).Error; err != nil {
		return fmt.Errorf("鎖定使用者列失敗: %w", err)
	}
	return nil
}

// lockUserPairTx 取得一位使用者的鎖：withAdvisory 為真時先 advisory 再列鎖，否則只取列鎖。
func lockUserPairTx(tx *gorm.DB, userID uint, withAdvisory bool) error {
	if withAdvisory {
		// 鎖序守衛探針（測試期；生產恆為 nil）：取憑證互斥鎖之前
		if probe := authz.LockOrderProbeHook(); probe != nil {
			probe(tx, authz.LockLayerUserCredential, userID)
		}
		// xact lock：隨交易結束自動釋放。userID 已驗在 32 位元值域內，折成 int32 為雙射
		if err := tx.Exec("SELECT pg_advisory_xact_lock(?, ?)",
			userCredentialLockClass, int32(uint32(userID))).Error; err != nil {
			return fmt.Errorf("取得使用者憑證互斥鎖失敗: %w", err)
		}
	}
	return lockUserRowTx(tx, userID)
}

func checkUserLockRange(userID uint) error {
	if userID > math.MaxUint32 {
		return fmt.Errorf("使用者 ID %d 超出互斥鎖鍵值域（上限 %d）", userID, uint(math.MaxUint32))
	}
	return nil
}

// lockUserPlanTx 依使用者編號升冪取得一組使用者層鎖（僅 postgres，其他 dialect 為 no-op）：
// withAdvisory 內的使用者取（advisory、列鎖）配對，rowOnly 內的使用者只取列鎖；
// 同時出現在兩者的使用者視為需要配對。先驗完整個輸入的值域，再取任何一把鎖。
// onLocked 非 nil 時，每取完一位使用者的鎖就以該編號呼叫一次（測試停點用，生產路徑不依賴它）。
func lockUserPlanTx(tx *gorm.DB, withAdvisory, rowOnly []uint, onLocked func(id uint)) error {
	if tx.Dialector.Name() != "postgres" {
		// 鎖序守衛探針（測試期；生產恆為 nil）：非 postgres 不取鎖，仍登記邏輯持有（只有憑證互斥鎖一層）
		if probe := authz.LockOrderProbeHook(); probe != nil {
			probe(tx, authz.LockLayerUserCredential, withAdvisory...)
		}
		return nil
	}
	need := make(map[uint]bool, len(withAdvisory)+len(rowOnly))
	for _, id := range rowOnly {
		if err := checkUserLockRange(id); err != nil {
			return err
		}
		if _, ok := need[id]; !ok {
			need[id] = false
		}
	}
	for _, id := range withAdvisory {
		if err := checkUserLockRange(id); err != nil {
			return err
		}
		need[id] = true
	}
	ids := make([]uint, 0, len(need))
	for id := range need {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		if err := lockUserPairTx(tx, id, need[id]); err != nil {
			return err
		}
		if onLocked != nil {
			onLocked(id)
		}
	}
	return nil
}

// withUserLockPlanTx 為「擁有者取（憑證鎖、列鎖）、被擁有的 agent 只取列鎖」的簽發類操作取鎖：
// postgres 依兩者編號升冪取得（agent 編號較小時順序為 agent 列、擁有者憑證鎖、擁有者列），
// 不先呼叫擁有者的單人 helper 再補取較小的 agent。sqlite 沿用擁有者的 per-user mutex，
// 取鎖點與次數與單人 helper 相同；未知 dialect 照舊拒絕。取鎖後才呼叫 fn，
// 呼叫端須在 fn 內重讀判定所依據的欄位。
func withUserLockPlanTx(tx *gorm.DB, ownerID, agentID uint, fn func(tx *gorm.DB) error) error {
	if tx.Dialector.Name() != "postgres" {
		return withUserCredentialLockTx(tx, ownerID, fn)
	}
	if err := lockUserPlanTx(tx, []uint{ownerID}, []uint{agentID}, func(id uint) {
		h := loadLockOrderHook()
		if h == nil {
			return
		}
		if id == ownerID {
			h("user_credential_lock_acquired", tx, ownerID)
			h("agent_token_after_owner_lock", tx, ownerID)
		} else {
			h("agent_token_after_agent_lock", tx, agentID)
		}
	}); err != nil {
		return err
	}
	return fn(tx)
}

// lockUsersCredentialUpfrontTx 於既有交易內一次取得多位使用者的憑證互斥鎖與列鎖，
// 之後同一交易內逐一呼叫 withUserCredentialLockTx 對 postgres 是重入（同一 session
// 已持有的鎖不會阻塞）。輸入不需事先排序：內部複製、去重、升冪，並先驗完整個輸入的
// 值域再取任何一把鎖；每位使用者取（advisory、列鎖）配對。
//
// 用途是鎖序：權限版本推進（authz_state 的列鎖）會持有到交易結束，
// 群組角色替換、群組刪除與成員替換對全體成員亦經此預取，使帳號生命週期的鎖內判定
// 與群組授出保護角色互斥。多使用者迴圈若邊走邊取使用者鎖，會在持有 authz_state 後去等
// 下一位使用者的鎖，與「先取使用者鎖、再推進」的單一使用者路徑形成反向等待。先把全部
// 使用者鎖取齊，推進就必然發生在最後一把使用者鎖之後。sqlite 的行程內 mutex 不可重入且
// 單寫者，不需要也不能預取，直接略過。
func lockUsersCredentialUpfrontTx(tx *gorm.DB, userIDs []uint) error {
	if tx.Dialector.Name() != "postgres" {
		// 鎖序守衛探針（測試期；生產恆為 nil）：非 postgres 不預取，仍登記邏輯持有，
		// 之後逐人取行程內互斥鎖時算重入（postgres 由逐位的取鎖點各自登記）
		if probe := authz.LockOrderProbeHook(); probe != nil {
			probe(tx, authz.LockLayerUserCredential, userIDs...)
		}
		return nil
	}
	for _, userID := range userIDs {
		if err := checkUserLockRange(userID); err != nil {
			return err
		}
	}
	sorted := append([]uint(nil), userIDs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	for i, userID := range sorted {
		if i > 0 && sorted[i-1] == userID {
			continue
		}
		if h := loadLockOrderHook(); h != nil {
			h("upfront_before_user", tx, userID)
		}
		if err := lockUserPairTx(tx, userID, true); err != nil {
			return err
		}
		if h := loadLockOrderHook(); h != nil {
			h("upfront_after_user", tx, userID)
		}
	}
	return nil
}
