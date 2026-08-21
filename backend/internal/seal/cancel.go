package seal

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// CheckCancel 是段 2 的合作式取消檢查點（D6.2.4）。
//
// 契約（段 2 的實作方 SHALL 遵守）：
//   - 段 2 SHALL 於每個具外部副作用的步驟「之前」呼叫本函式，回傳非 nil 即
//     SHALL 立刻中止並回傳該 error，不得繼續。
//   - 取消後 SHALL NOT 啟動排程器（cron / ticker / 背景 worker goroutine）。
//   - 取消後 SHALL NOT 開始通知投遞（webhook、syslog forwarder、告警佇列）。
//   - 取消後 SHALL NOT 建立新的外部連線（LDAP、K8s、guacd、SSH、HTTP 用戶端）。
//   - 已發生的 DB 寫入無須回溯：bootstrap／finalizeSwitch 本就冪等且受跨實例
//     互斥鎖保護，重試安全。
//
// 逾時只取消 context；epoch（generation）只擋發佈。兩者都擋不住「已經啟動的
// 副作用」——擋住它們的唯一手段就是段 2 自己在每一步之前檢查。
func CheckCancel(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("seal: 段 2 已取消，中止後續副作用: %w", err)
	}
	return nil
}

// CheckCancelStep 與 CheckCancel 同語義，另把步驟名帶進錯誤訊息，
// 使逾時／取消可被定位到具體的段 2 步驟。
func CheckCancelStep(ctx context.Context, step string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("seal: 段 2 已取消，中止步驟 %q: %w", step, err)
	}
	return nil
}

// Releaser 是可釋放資源的最小介面。
//
// 段 2 建構的每一個持有資源的物件（連線池、檔案控制代碼、外部用戶端、背景
// goroutine、cron 排程器、套件級單例與全域 hook）SHALL 以本介面登記於
// ResourceBag，使逾時或初始化失敗時的收束是遍歷而非人工記憶。
// 現況盤點與各項的釋放狀態見同目錄 RESOURCES.md。
type Releaser interface {
	Release(ctx context.Context) error
}

// ReleaserFunc 讓既有的 Stop()／Shutdown()／Close() 以閉包接入 Releaser。
type ReleaserFunc func(ctx context.Context) error

func (f ReleaserFunc) Release(ctx context.Context) error { return f(ctx) }

// ResourceBag 依建構順序收集 Releaser，並以反序（LIFO）釋放。
//
// 反序的理由：後建者通常依賴先建者（排程器依賴服務、服務依賴 codec），
// 先關依賴者才不會讓仍在跑的 worker 打到已釋放的物件。
// Release 為冪等：重複呼叫不重複釋放（現況多個 Stop() 非冪等，
// 二次呼叫會 close 已關閉的 channel 而 panic，見 RESOURCES.md）。
type ResourceBag struct {
	mu       sync.Mutex
	items    []bagItem
	released bool
}

type bagItem struct {
	name string
	r    Releaser
}

// Add 登記一項資源。name 僅供錯誤訊息定位，不影響釋放順序。
// r 為 nil 時忽略，使呼叫端可寫 bag.Add("x", maybeNil) 而不需前置判斷。
func (b *ResourceBag) Add(name string, r Releaser) {
	if r == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.items = append(b.items, bagItem{name: name, r: r})
}

// AddFunc 以閉包登記一項資源。
func (b *ResourceBag) AddFunc(name string, fn func(ctx context.Context) error) {
	if fn == nil {
		return
	}
	b.Add(name, ReleaserFunc(fn))
}

// Len 回傳已登記項數。
func (b *ResourceBag) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.items)
}

// Names 回傳已登記項目的名稱，**依登記序**。
//
// 存在理由是啟停整合測試（modular-architecture Phase B W1 1.15）：釋放為 LIFO，
// 故登記序的反序即實際釋放序，而「誰在誰之後釋放」是本專案數條安全契約的載體
// （金鑰歸零必須最後、推送器必須晚於排程器停）。沒有這個出口，整合測試只能
// 觀察釋放的**結果**而無法觀察釋放的**順序**，而順序正是那些契約的內容。
//
// 已釋放後回傳 nil（items 於 Release 內清空）：呼叫端 SHALL 於 Release 之前讀取。
func (b *ResourceBag) Names() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, len(b.items))
	for i, it := range b.items {
		out[i] = it.name
	}
	return out
}

// Released 回傳是否已釋放過。
func (b *ResourceBag) Released() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.released
}

// Release 以反序釋放全部資源。
//
// 單項失敗或 panic 不中斷後續釋放——收束的目的是把資源交還，
// 中途放棄會讓剩下的項目永久洩漏而使 cleanup 永不完成。
// 全部錯誤以 errors.Join 聚合回傳。
func (b *ResourceBag) Release(ctx context.Context) error {
	b.mu.Lock()
	if b.released {
		b.mu.Unlock()
		return nil
	}
	b.released = true
	items := b.items
	b.items = nil
	b.mu.Unlock()

	var errs []error
	for i := len(items) - 1; i >= 0; i-- {
		it := items[i]
		if err := releaseOne(ctx, it); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func releaseOne(ctx context.Context, it bagItem) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("seal: 釋放 %q 時 panic: %v", it.name, r)
		}
	}()
	if e := it.r.Release(ctx); e != nil {
		return fmt.Errorf("seal: 釋放 %q 失敗: %w", it.name, e)
	}
	return nil
}
