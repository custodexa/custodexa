package identity

import (
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"
)

// sqlite 路徑的取鎖順序。
//
// postgres 路徑一律「先開交易、再於交易內取鎖」（advisory xact lock 與列鎖本來
// 就只存在於交易內）。sqlite 的等價序列化是 key mutex，而它原本取在 db.Transaction
// **之外**——於是同一支程式出現兩種相反的取鎖順序：
//
//	A（WithLocalAdminInvariant → withUserCredentialLockTx）：先交易、後 mutex
//	B（WithUserCredentialLock／WithCapabilityLocks）：先 mutex、後交易
//
// 兩者對同一 userID 並發即循環等待：A 持著唯一的 sqlite 連線等 mutex，B 持著
// mutex 等連線。`SetMaxOpenConns(1)`（本 change 多數 sqlite fixture 的必要設定）
// 下這是**永久掛住**，在有 busy_timeout 的環境下則是幾秒後的 SQLITE_BUSY 假錯誤。
//
// 影響面不只「測試環境的偶發卡住」：sqlite 分支是 dialect 白名單的一支，
// 序列化語義若與 postgres 相反，測試驗到的就不是生產跑的那套；而所有並發不變式
// 測試（write-skew、TOCTOU）都跑在 sqlite 上。
//
// 斷言方式為結構性且確定性：讓測試自己佔住唯一的連線，觀察被阻塞的取鎖路徑
// **有沒有在等連線的同時持有 key mutex**。持有即順序反轉。
func TestSqliteCapabilityLocksTakeTransactionBeforeKeyMutex(t *testing.T) {
	cases := map[string]func(db *gorm.DB, userID uint, fn func(tx *gorm.DB) error) error{
		"WithCapabilityLocks": func(db *gorm.DB, userID uint, fn func(tx *gorm.DB) error) error {
			return WithCapabilityLocks(db, 0, userID, fn)
		},
		"WithUserCredentialLock": WithUserCredentialLock,
	}
	for name, enter := range cases {
		t.Run(name, func(t *testing.T) {
			db := localAdminDB(t) // SetMaxOpenConns(1)
			sqlDB, err := db.DB()
			if err != nil {
				t.Fatalf("sql db: %v", err)
			}
			const userID uint = 4242

			// 測試自己佔住唯一的連線，模擬「另一條路徑已持有交易」
			holder := db.Begin()
			if holder.Error != nil {
				t.Fatalf("begin: %v", holder.Error)
			}
			var released sync.Once
			release := func() { released.Do(func() { holder.Rollback() }) }
			defer release()

			done := make(chan struct{})
			go func() {
				defer close(done)
				_ = enter(db, userID, func(*gorm.DB) error { return nil })
			}()

			// 等到該 goroutine 確實卡在「等連線」上（連線池的 WaitCount 是唯一
			// 可觀測的證據，避免用 sleep 猜時序而產生假綠）
			deadline := time.Now().Add(5 * time.Second)
			for sqlDB.Stats().WaitCount == 0 {
				if time.Now().After(deadline) {
					release()
					<-done
					t.Fatal("等待連線的 goroutine 未出現：本測試的前提不成立")
				}
				time.Sleep(time.Millisecond)
			}

			// 此刻它正在等連線。若 key mutex 已被它取走，代表順序是
			// 「先 mutex、後交易」——與 postgres 路徑相反，且與持交易後才取
			// mutex 的 withUserCredentialLockTx 形成循環等待
			mu := userCredentialLockFor(userID)
			holdsMutex := !mu.TryLock()
			if !holdsMutex {
				mu.Unlock()
			}

			release()
			<-done

			if holdsMutex {
				t.Fatalf("%s 在等待 sqlite 連線時已持有 user key mutex——"+
					"取鎖順序與 postgres 路徑（先交易後鎖）相反，"+
					"與 withUserCredentialLockTx 並發即循環等待", name)
			}
		})
	}
}

// TestSqliteUserCredentialLockStillSerializes 順序調整不得換掉序列化本身：
// 同一 userID 的兩個進入者仍須互斥（否則順序調整就把 write-skew 防護拆了）
func TestSqliteUserCredentialLockStillSerializes(t *testing.T) {
	db := localAdminDB(t)
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql db: %v", err)
	}
	// 連線放寬到 2，讓「兩者能同時開交易」不再是序列化的原因——
	// 仍互斥才證明是 key mutex 在起作用
	sqlDB.SetMaxOpenConns(2)

	const userID uint = 99
	var mu sync.Mutex
	inside, maxInside := 0, 0
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = WithUserCredentialLock(db, userID, func(*gorm.DB) error {
				mu.Lock()
				inside++
				if inside > maxInside {
					maxInside = inside
				}
				mu.Unlock()
				time.Sleep(time.Millisecond)
				mu.Lock()
				inside--
				mu.Unlock()
				return nil
			})
		}()
	}
	wg.Wait()
	if maxInside != 1 {
		t.Fatalf("同一 userID 的鎖內同時進入者最多 %d 個, want 1（序列化已失效）", maxInside)
	}
}

// TestCapabilityLocksAcquireProviderBeforeUser 取鎖順序不變式：
// **provider 鎖 SHALL 早於 user 鎖取得**（system → provider → user）。
//
// # 為何既有兩支測試不足以承接這條不變式
//
//   - `TestSqliteCapabilityLocksTakeTransactionBeforeKeyMutex` 守的是另一條軸
//     （交易 vs key mutex 的先後），對 provider／user 之間的先後完全不表態。
//   - `TestCapabilityLockOrderingHasNoDeadlock` 靠「兩把鎖交叉配對後是否互鎖」
//     偵測，抓得到的是**兩條路徑不一致**（只把 `lockCapabilityKeys` 寫反，pg 分支
//     不動）。若有人**兩處一起**改成 user → provider，全庫仍然自洽、不會互鎖，
//     那支 watchdog 測試照樣綠——順序本身無人看守。
//
// 本測試直接觀察順序而不觀察後果：測試先佔住 user 鎖，再讓取鎖路徑進場。
//   - 順序正確（provider → user）⇒ 它會**先取得 provider 鎖**、再卡在 user 鎖上，
//     故此刻 provider 鎖必為已持有。
//   - 順序寫反（user → provider）⇒ 它一進場就卡在 user 鎖，provider 鎖永遠不會被取得。
//
// 判別式是「provider 鎖有沒有被取走」這個狀態，不是計時：正確實作下它在數十微秒內
// 成立，逾時才代表順序反了。
func TestCapabilityLocksAcquireProviderBeforeUser(t *testing.T) {
	db := localAdminDB(t)
	const providerID, userID uint = 8101, 8102

	// 測試佔住 user 鎖，迫使取鎖路徑在第二把鎖上停下來
	uMu := userCredentialLockFor(userID)
	uMu.Lock()
	var released sync.Once
	release := func() { released.Do(uMu.Unlock) }
	defer release()

	entered := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(entered)
		done <- WithCapabilityLocks(db, providerID, userID, func(*gorm.DB) error { return nil })
	}()
	<-entered

	pMu := oidcProviderLockFor(providerID)
	deadline := time.Now().Add(5 * time.Second)
	held := false
	for {
		if !pMu.TryLock() {
			held = true
			break
		}
		pMu.Unlock()
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}

	release()
	if err := <-done; err != nil {
		t.Fatalf("取鎖路徑本身失敗（本測試的前提不成立）: %v", err)
	}
	if !held {
		t.Fatal("卡在 user 鎖上時 provider 鎖並未被持有——取鎖順序不是 provider → user。" +
			"固定的取鎖順序是跨路徑不互鎖的唯一依據（`WithOIDCProviderLock` 只取 provider、" +
			"`WithLocalAdminInvariant` 走 user 側），顛倒即與它們形成循環等待")
	}
}
