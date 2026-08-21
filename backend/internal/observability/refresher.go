package observability

import (
	"context"
	"fmt"
	"log"
	"runtime/debug"
	"sync"
	"time"
)

// DefaultRefreshInterval 背景刷新週期。
//
// 指標值因此最多落後一個週期，此邊界須記載於部署文件（spec「營運指標最小集合」）。
const DefaultRefreshInterval = 30 * time.Second

// StopWaitBudget 停止函式等待「進行中的那一輪刷新」結束的內建上限。
//
// 兩個方向的風險各需要一個界：
//   - 不等待 → 停止函式回傳後刷新仍在跑，它會與關機序後段（`database.Close()`、
//     全域句柄復原）賽跑，資料源在刷新途中失去其事實源。這正是本常數存在的起因。
//   - 無限等待 → 一次卡住的 DB 查詢或磁碟遍歷就能吊死整個關機序。
//
// 取 2 秒是因為行程關機總預算為 5 秒（`main.go` 的 shutdown ctx），而指標刷新是
// 旁路功能，不該吃掉主監聽與審計 flush 的份額。等不到就放手回錯——殘餘暴露面由
// 資料源自身的可用性檢查（回 error 而非裸解參考）與本檔的 panic 攔截兜住。
// 呼叫端傳入的 ctx 若更早到期，以較早者為準。
const StopWaitBudget = 2 * time.Second

// RefreshSources 背景刷新所需的資料源。任一為 nil 時該項跳過，不影響其餘。
//
// **契約**：資料源回 error 時只記 log、不中止任務。故資料源 SHALL 在其事實源
// （DB 句柄、檔案系統路徑）不可用時回 error，而非讓下游裸解參考——後者在背景
// goroutine 內等同終止行程。
type RefreshSources struct {
	// ActiveSessions 回傳依協議分的活躍會話數（DB 查詢）。
	ActiveSessions func() (map[string]float64, error)
	// RecordingStorage 回傳錄影已用位元組（檔案系統遍歷）。
	RecordingStorage func() (used float64, err error)
	// PendingAlerts 回傳依嚴重度分的未審閱告警數（DB 聚合查詢）。
	PendingAlerts func() (map[string]float64, error)
}

// StopRefresherFunc 停止背景刷新並等待進行中的刷新結束。
//
// 冪等：可重複呼叫、可並行呼叫。回 error 表示「已發出停止信號但未等到刷新結束」
// ——呼叫端據此得知關機序後段（關 DB、還原全域）將與殘餘刷新重疊。
type StopRefresherFunc func(ctx context.Context) error

// StartRefresher 啟動背景刷新任務，回傳停止函式。
//
// **為何不在採集當下同步查詢**：採集間隔可低至 15 秒，而活躍會話走 DB 查詢、
// 錄影儲存量走檔案系統遍歷——採集頻率會直接放大成資料庫與磁碟負載，且該負載
// 由外部採集端的設定決定，不受本系統控制。改為固定週期刷新後，成本與採集頻率脫鉤。
//
// **停止函式冪等**（`sync.Once` 封住 channel 關閉）：比照既有背景任務的形態，
// B 模式下每次解封都會建立一個新的任務，重複關閉同一個 channel 會 panic。
//
// **停止函式等待進行中的刷新**：只送信號不等待，等於讓刷新的存活期超出組裝根的
// 生命週期——關機序把 refresher 排在最前（R-13）正是為了「它先停，其依賴才拆」，
// 不等待則該順序名存實亡。等待上限見 `StopWaitBudget`。
//
// **背景 panic 不得終止行程**：指標刷新是旁路功能，它不該有能力殺掉一個正在服務
// 連線的堡壘機。攔截分兩層——資料源逐一以 `callSource` 包覆（轉成 error 走既有
// 失敗路徑，該輪跳過、任務續行），任務本體另有一層兜底（記錄後結束任務，指標停在
// 最後一次成功值）。兩層都記錄 panic 值與完整堆疊，不做無聲吞噬。
func StartRefresher(m *Metrics, src RefreshSources, interval time.Duration) StopRefresherFunc {
	if interval <= 0 {
		interval = DefaultRefreshInterval
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	var once sync.Once

	stopping := func() bool {
		select {
		case <-stop:
			return true
		default:
			return false
		}
	}

	refresh := func() {
		if src.ActiveSessions != nil {
			var byProtocol map[string]float64
			if err := callSource("活躍會話", func() (err error) {
				byProtocol, err = src.ActiveSessions()
				return err
			}); err != nil {
				// 刷新失敗只記 log 不中止任務：一次查詢失敗不該讓後續刷新全部停擺，
				// 而指標值停在前一輪比整條指標消失更能反映「系統還在，只是這次沒讀到」
				log.Printf("[Metrics] 活躍會話刷新失敗：%v", err)
			} else {
				m.SetActiveSessions(byProtocol)
			}
		}
		// 收到停止信號後不再起新的資料源查詢：關機期預算有限（見 StopWaitBudget），
		// 一輪刷新剩下的部分不值得讓關機多等一次 DB 往返
		if stopping() {
			return
		}

		if src.RecordingStorage != nil {
			var used float64
			if err := callSource("錄影儲存量", func() (err error) {
				used, err = src.RecordingStorage()
				return err
			}); err != nil {
				log.Printf("[Metrics] 錄影儲存量刷新失敗：%v", err)
			} else {
				m.SetRecordingStorage(used)
			}
		}
		if stopping() {
			return
		}

		if src.PendingAlerts != nil {
			var bySeverity map[string]float64
			if err := callSource("未審閱告警數", func() (err error) {
				bySeverity, err = src.PendingAlerts()
				return err
			}); err != nil {
				log.Printf("[Metrics] 未審閱告警數刷新失敗：%v", err)
			} else {
				m.SetPendingAlerts(bySeverity)
			}
		}
	}

	go func() {
		// close(done) 必須是最外層 defer：無論正常返回、被 panic 展開、或被兜底
		// recover 收掉，停止函式的等待都必須解除，否則關機固定吃滿 StopWaitBudget
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[Metrics] 背景刷新任務因 panic 終止（指標將停在最後一次成功值）：%v\n%s",
					r, debug.Stack())
			}
		}()

		// 先刷一次再進入週期，否則首個週期內的採集全部讀到零值——
		// 那與「服務不存在」在採集端無法區分
		refresh()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			// 先驗停止信號再進 select：兩個 channel 同時就緒時 select 是隨機挑的，
			// 停止後仍可能再跑一輪刷新，而那一輪正落在「依賴已開始拆除」的窗口內
			if stopping() {
				return
			}
			select {
			case <-stop:
				return
			case <-ticker.C:
				refresh()
			}
		}
	}()

	return func(ctx context.Context) error {
		once.Do(func() { close(stop) })

		if ctx == nil {
			ctx = context.Background()
		}
		budget := time.NewTimer(StopWaitBudget)
		defer budget.Stop()

		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return fmt.Errorf("指標刷新未在關機期限內結束（%w）；關機序後段將與殘餘刷新重疊", ctx.Err())
		case <-budget.C:
			return fmt.Errorf("指標刷新未在 %s 內結束；關機序後段將與殘餘刷新重疊", StopWaitBudget)
		}
	}
}

// callSource 以 recover 包住一次資料源呼叫，把 panic 轉成 error 交回既有失敗路徑。
//
// **為何要攔**：刷新跑在背景 goroutine，Go 的 goroutine panic 不經呼叫端、直接終止
// 整個行程。指標是旁路功能，一次 nil 句柄的解參考不該讓正在服務連線的堡壘機下線。
//
// **為何不算掩蓋根因**：掩蓋的定義是資訊消失。這裡轉出的 error 帶資料源名稱、panic
// 值與完整堆疊，並照既有契約寫進 log；相較之下 panic 讓行程死亡，除了容器最後一段
// stderr 之外什麼也查不到。攔截後任務續行，故同一缺陷會每個週期重複記錄一次，
// 不會只留一根孤證。
func callSource(name string, fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("資料源 %s panic（旁路功能已攔下，行程續行）：%v\n%s", name, r, debug.Stack())
		}
	}()
	return fn()
}
