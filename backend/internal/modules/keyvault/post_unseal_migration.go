package keyvault

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// 解封後遷移佇列與重加密入口（交叉相容契約 3）。
//
// **為何需要佇列**：需要 codec 的資料 migration 不能留在
// 啟動段 1——B（ui）模式的段 1 既無 KEK 也無 DEK（兩者都要等解封後的段 2），
// 「migration 期自建 codec」在 B 模式下不可能成立。故：
//
//	任何需要 codec 的資料 migration SHALL 登記進本佇列、由段 2 於
//	InitKeyManager 成功後執行，SHALL NOT 執行於段 1。
//
// A／C 模式下段 1 與段 2 連續執行，佇列在啟動內即跑完（**行為與現況無異**）；
// B 模式下自然延後至解封後——**一套機制涵蓋三模式，不需模式分支**。
// 純 schema migration（無密文讀寫）不受此限，維持段 1 執行。

// PostUnsealMigration 佇列項：冪等、可重試、失敗不阻塞服務（沿既有 legacy 遷移語義）
type PostUnsealMigration struct {
	// Name 供 log 與重試辨識
	Name string
	// Run 執行體；codec 由佇列注入（呼叫端不自全域取得）
	Run func(db *gorm.DB, codec crypto.ColumnCodec) error
}

// postUnsealBuiltin 內建遷移的「登記器」：由組裝根（與測試 setup）顯式提供。
type postUnsealBuiltin struct {
	// Name 登記器身分（去重鍵）；與其登記的佇列項同名，便於診斷
	Name string
	// Register 執行實際的 RegisterPostUnsealMigration 呼叫
	Register func()
}

var (
	postUnsealMu    sync.Mutex
	postUnsealQueue []PostUnsealMigration
	// postUnsealBuiltins 已登記的內建登記器（依登記序保存＝佇列順序）。
	//
	// **存在理由是 4.9 環拆解**：原本
	// RegisterBuiltinPostUnsealMigrations 直接呼叫 identity 的
	// registerLDAPSeedMigration，使 keyvault→identity 成為真出向邊
	// （即 4.9 環）。改由各模組把自己的登記器交給組裝根、組裝根注入本清單後，
	// keyvault 只擁有佇列機制，不再認識任何業務模組。
	//
	// 清單與佇列分開保存，是為了讓 ResetPostUnsealQueueForTest 仍能
	// 「清空後重新登記 builtin」（該決定不因拆環而失效）——
	// 佇列被清空，登記器不被清空，重播即回到生產狀態。
	postUnsealBuiltins []postUnsealBuiltin
	// postUnsealRuns 逐項執行次數。
	//
	// 存在理由是 B 模式的時序驗收：「envelope_legacy 於 sealed 期
	// 不執行、解封後恰執行一次」無法由佇列成員清單觀察——那只說明它被登記了，
	// 不說明它被跑了幾次。沒有計數器時，該驗收只能靠日誌字串比對。
	postUnsealRuns = map[string]int{}
)

// PostUnsealMigrationRunCounts 回傳各佇列項的累計執行次數（快照）。
func PostUnsealMigrationRunCounts() map[string]int {
	postUnsealMu.Lock()
	defer postUnsealMu.Unlock()
	out := make(map[string]int, len(postUnsealRuns))
	for k, v := range postUnsealRuns {
		out[k] = v
	}
	return out
}

// ResetPostUnsealRunCountsForTest 歸零執行次數（測試用）。
func ResetPostUnsealRunCountsForTest() {
	postUnsealMu.Lock()
	postUnsealRuns = map[string]int{}
	postUnsealMu.Unlock()
}

// RegisterPostUnsealMigration 登記一項解封後遷移（組裝期呼叫）。
// **同名去重**：重複登記為 no-op——RegisterBuiltinPostUnsealMigrations 的冪等性
// 由此保證（main 與各測試 setup 皆可安全重複呼叫）。
func RegisterPostUnsealMigration(m PostUnsealMigration) {
	postUnsealMu.Lock()
	defer postUnsealMu.Unlock()
	for _, existing := range postUnsealQueue {
		if existing.Name == m.Name {
			return
		}
	}
	postUnsealQueue = append(postUnsealQueue, m)
}

// RegisterPostUnsealBuiltin 登記一個內建遷移的登記器，並立即執行它一次。
//
// **呼叫者是組裝根**（`cmd/server/stage2.go`）**與測試 setup**，不是 keyvault 自己：
// 佇列機制屬 keyvault，遷移內容屬各業務模組，兩者由組裝層縫合（4.9 環的拆法）。
//
// **為何仍不是 init()**：Go 的 init 依檔名字典序執行，
// 順序不可控；改為組裝根顯式登記後，佇列順序＝組裝根的登記順序，是可讀、可測、
// 可重置的單一事實。
//
// 冪等：同名登記器只保存一次；`register` 本身亦冪等（RegisterPostUnsealMigration 同名去重）。
func RegisterPostUnsealBuiltin(name string, register func()) {
	if register == nil {
		return
	}
	postUnsealMu.Lock()
	exists := false
	for _, b := range postUnsealBuiltins {
		if b.Name == name {
			exists = true
			break
		}
	}
	if !exists {
		postUnsealBuiltins = append(postUnsealBuiltins, postUnsealBuiltin{Name: name, Register: register})
	}
	postUnsealMu.Unlock()
	// 在鎖外執行：register 會回頭呼叫 RegisterPostUnsealMigration（同一把鎖）
	register()
}

// RegisterBuiltinPostUnsealMigrations 重播全部已登記的內建登記器（冪等）。
//
// **佇列不含任何過渡格式遷移**：legacy 密文信封化
// （`envelope_legacy`）與 AAD 正向遷移已整組拆除——終態下寫入端只產 `enc:a1`，
// 無存量可遷。佇列機制本身是三模式共用的正式架構，保留。
// 生產佇列現有一項：LDAP 設定 env seed（`ldap_seed`
// ——需 codec 加密 bind 密碼，故必登記於本佇列而非段 1 migration），
// 其登記器由 `cmd/server/stage2.go` 注入。
func RegisterBuiltinPostUnsealMigrations() {
	postUnsealMu.Lock()
	builtins := make([]postUnsealBuiltin, len(postUnsealBuiltins))
	copy(builtins, postUnsealBuiltins)
	postUnsealMu.Unlock()
	for _, b := range builtins {
		b.Register()
	}
}

// PostUnsealMigrationNames 已登記項名稱（供測試與診斷）
func PostUnsealMigrationNames() []string {
	postUnsealMu.Lock()
	defer postUnsealMu.Unlock()
	names := make([]string, 0, len(postUnsealQueue))
	for _, m := range postUnsealQueue {
		names = append(names, m.Name)
	}
	return names
}

// ResetPostUnsealQueueForTest 測試用重置：**清空後重新登記 builtin**。
// 單純清空會讓「用了 Reset 的測試」看到一個沒有內建項的
// 佇列，與生產狀態不符——那正是登記改為顯式函式後必須配套的一半。
func ResetPostUnsealQueueForTest() {
	postUnsealMu.Lock()
	postUnsealQueue = nil
	postUnsealMu.Unlock()
	RegisterBuiltinPostUnsealMigrations()
}

// RunPostUnsealMigrations 依序執行佇列；單項失敗僅記錄、不阻塞（下次啟動／下次解封重試）。
// 回傳失敗項數。
func RunPostUnsealMigrations(db *gorm.DB, codec crypto.ColumnCodec) int {
	postUnsealMu.Lock()
	queue := make([]PostUnsealMigration, len(postUnsealQueue))
	copy(queue, postUnsealQueue)
	postUnsealMu.Unlock()

	failed := 0
	for _, m := range queue {
		postUnsealMu.Lock()
		postUnsealRuns[m.Name]++
		postUnsealMu.Unlock()
		if err := m.Run(db, codec); err != nil {
			failed++
			log.Printf("[PostUnsealMigration] %s 失敗（不阻塞服務，下次重試）: %v", m.Name, err)
			continue
		}
		log.Printf("[PostUnsealMigration] %s 完成", m.Name)
	}
	return failed
}

// RecryptForNewRef 重加密入口（交叉相容契約 3(a)）：將綁定 oldRef 的密文改綁 newRef。
//
// AAD 綁 table|column（不綁 pk），故**同表同欄的列間複製不需經本入口**
// （密文原樣複製即可，資產多帳號的複製契約因此完好）；本入口用於
// **跨表或跨欄**的搬遷（如 assets.password_enc → asset_accounts.password_enc）。
//
// **codec 由呼叫端傳入**，不自全域或 KeyManager 取得——「複製一列密文到另一列」
// 這種操作必然發生在明確知道兩端身分的地方，讓呼叫端顯式提供 codec 才能在
// B 模式（段 1 無 codec）下被正確排程進解封後佇列。
//
// 冪等：已綁 newRef 的值重跑會先解成功再重加密，結果等價。
func RecryptForNewRef(ctx context.Context, codec crypto.ColumnCodec,
	oldRef, newRef crypto.CipherRef, ciphertext string) (string, error) {
	if codec == nil {
		return "", fmt.Errorf("重加密入口需要呼叫端傳入 codec（不得自全域取得）")
	}
	if ciphertext == "" {
		return "", nil
	}
	plain, err := codec.DecryptFor(ctx, oldRef, ciphertext)
	if err != nil {
		return "", fmt.Errorf("以來源欄位身分解密失敗（%s）: %w", oldRef, err)
	}
	out, err := codec.EncryptFor(ctx, newRef, plain)
	if err != nil {
		return "", fmt.Errorf("以目標欄位身分重加密失敗（%s）: %w", newRef, err)
	}
	return out, nil
}
