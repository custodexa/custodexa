package observability

import (
	"bytes"
	"context"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

// 背景刷新任務的韌性與停止語義（observability-lite，2026-08-16 競態 FAIL 的回歸）。
//
// 被回歸的缺陷：資料源在執行當下解參考一個已消失的 DB 句柄 → panic → 因為刷新跑在
// 背景 goroutine，panic 直接終止整個行程；而停止函式只送信號不等待，關機序把
// refresher 排在最前（R-13）的用意（它先停、其依賴才拆）因此形同虛設。
//
// 本檔的每個斷言前都先證明「注入確實發生」——注入器沒觸發而測試全綠是本專案踩過的坑。

// syncBuffer log 輸出的併發安全接收端。
//
// 刷新在背景 goroutine 內寫 log，測試主 goroutine 讀；裸 bytes.Buffer 在此處是資料競態，
// 且會讓「讀到空字串」看起來像「沒記錄」——那正是本檔要斷言的事，不能由競態決定。
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureLog 把標準 logger 導向測試緩衝區，並於結束時還原。
func captureLog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	prevOut := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(buf)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})
	return buf
}

// waitFor 輪詢直到條件成立；逾時即 fatal（訊息由呼叫端說明「沒等到什麼」）。
func waitFor(t *testing.T, timeout time.Duration, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("等待逾時（%s）：%s", timeout, msg)
}

// TestPanickingSourceDoesNotKillProcessAndIsLogged
// 「刷新進行中、資料源不可用（panic）」→ 行程存活、該輪跳過、任務續行、事件留下可定位紀錄。
//
// 若攔截失效，這個測試不會是紅的——它會讓整個 test binary 當場死掉（就像缺陷發生時
// `cmd/server` 那樣）。這是本測試唯一可能的失敗形態之一，故意保留：它與生產的失敗形態同構。
func TestPanickingSourceDoesNotKillProcessAndIsLogged(t *testing.T) {
	logs := captureLog(t)
	m := New()

	var mu sync.Mutex
	panicCalls, okCalls := 0, 0

	stop := StartRefresher(m, RefreshSources{
		ActiveSessions: func() (map[string]float64, error) {
			mu.Lock()
			panicCalls++
			mu.Unlock()
			// 以真的 nil 解參考注入，而非 panic("boom")：要回歸的是 gorm 對 nil
			// 句柄的 `invalid memory address` 形態，人造字串 panic 走不到同一條路徑
			var nilDB *struct{ n int }
			return map[string]float64{"ssh": float64(nilDB.n)}, nil
		},
		// 排在 panic 源之後：它有沒有被刷到，決定了「該輪跳過」與「整條任務死掉」的分別
		PendingAlerts: func() (map[string]float64, error) {
			mu.Lock()
			okCalls++
			mu.Unlock()
			return map[string]float64{"high": 7}, nil
		},
	}, 5*time.Millisecond)
	t.Cleanup(func() { _ = stop(context.Background()) })

	counts := func() (int, int) {
		mu.Lock()
		defer mu.Unlock()
		return panicCalls, okCalls
	}

	// —— 前置條件：注入確實觸發，且觸發了不只一次 ——
	// 只跑一次不足以區分「攔下了」與「任務被第一次 panic 帶走」
	waitFor(t, 3*time.Second, "panic 資料源未被呼叫 ≥2 次（注入未觸發，或任務已被第一次 panic 終止）",
		func() bool { p, _ := counts(); return p >= 2 })

	// —— 該輪跳過而非整條停擺：panic 源之後的資料源仍持續被刷新 ——
	waitFor(t, 3*time.Second, "panic 源之後的資料源未被刷新 ≥2 次（panic 已使整輪或整條任務停擺）",
		func() bool { _, o := counts(); return o >= 2 })
	require.Equal(t, 7.0, testutil.ToFloat64(m.commandAlertsPending.WithLabelValues("high")),
		"panic 之後的資料源雖被呼叫，其值卻未寫入指標")

	require.NoError(t, stop(context.Background()))

	// —— 事件被記錄，且記錄足以定位根因 ——
	out := logs.String()
	require.Contains(t, out, "活躍會話", "log 未指出是哪一個資料源出事")
	require.Contains(t, out, "panic", "log 未表明這是被攔下的 panic，讀者會誤判為普通查詢失敗")
	require.Contains(t, out, "invalid memory address",
		"log 未帶出 panic 值本身——沒有它就分不出是 nil 句柄還是別的失敗")
	require.Contains(t, out, "refresher_test.go",
		"log 未帶出堆疊：攔截若不留現場，就是把根因藏起來而非處理掉")
}

// TestStopWaitsForInflightRefresh 停止函式必須等到「進行中的那一輪」真正結束才返回。
//
// 這是缺陷的第二個層次：不等待，停止函式返回後刷新仍在跑，關機序後段（關 DB、
// 還原全域句柄）就會與它重疊——R-13 把 refresher 排在最前的用意被抵銷。
func TestStopWaitsForInflightRefresh(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once

	stop := StartRefresher(New(), RefreshSources{
		ActiveSessions: func() (map[string]float64, error) {
			once.Do(func() { close(entered) })
			<-release
			return map[string]float64{"ssh": 1}, nil
		},
	}, time.Hour) // 只靠啟動時的首刷，不讓 ticker 攪進時序

	// —— 前置條件：刷新確實正在進行中 ——
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("資料源未進入：本測試的「等待進行中刷新」斷言將由假前提成立")
	}

	stopped := make(chan error, 1)
	go func() { stopped <- stop(context.Background()) }()

	// 刷新還卡著時，停止函式不得返回
	select {
	case err := <-stopped:
		close(release)
		t.Fatalf("刷新仍進行中，停止函式卻已返回（err=%v）：關機序將與殘餘刷新重疊", err)
	case <-time.After(150 * time.Millisecond):
	}

	close(release)
	select {
	case err := <-stopped:
		require.NoError(t, err, "刷新已結束，停止函式卻回報未等到")
	case <-time.After(3 * time.Second):
		t.Fatal("刷新已結束，停止函式仍未返回")
	}
}

// TestStopDoesNotHangOnStuckSource 卡死的資料源不得吊住關機序。
//
// 與上一個測試互為反向：等待是必要的，但不能是無限的——一次卡住的 DB 查詢
// 不該讓一台正在關機的堡壘機停在那裡。呼叫端的 ctx 與內建預算，先到者為準。
func TestStopDoesNotHangOnStuckSource(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { close(release) })

	stop := StartRefresher(New(), RefreshSources{
		ActiveSessions: func() (map[string]float64, error) {
			once.Do(func() { close(entered) })
			<-release
			return nil, nil
		},
	}, time.Hour)

	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("資料源未進入：本測試的「不得吊住」斷言將由假前提成立")
	}

	// 呼叫端 ctx 先到期（生產路徑：收束 ctx 由關機總預算派生）
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := stop(ctx)
	require.Error(t, err, "資料源卡死，停止函式卻宣稱刷新已結束")
	require.Less(t, time.Since(start), StopWaitBudget,
		"停止函式未依呼叫端 ctx 提前放手")

	// 無期限 ctx 時由內建預算收尾，不得無限等待
	start = time.Now()
	err = stop(context.Background())
	require.Error(t, err)
	elapsed := time.Since(start)
	require.GreaterOrEqual(t, elapsed, StopWaitBudget, "內建預算未生效（等待被略過）")
	require.Less(t, elapsed, StopWaitBudget+2*time.Second, "內建預算未收尾，關機將被吊住")
}

// TestStopIsIdempotent 重複與並行停止不得 panic（B 模式每次解封都會建立新任務）。
func TestStopIsIdempotent(t *testing.T) {
	stop := StartRefresher(New(), RefreshSources{
		ActiveSessions: func() (map[string]float64, error) {
			return map[string]float64{"ssh": 1}, nil
		},
	}, 5*time.Millisecond)

	require.NoError(t, stop(context.Background()))
	require.NoError(t, stop(context.Background()))

	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = stop(context.Background())
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		require.NoError(t, err, "並行停止第 %d 個呼叫回錯", i)
	}
}

// TestStopAfterTaskPanicReturnsPromptly 任務本體被 panic 帶走後，停止函式仍須即刻返回。
//
// 兜底 recover 若沒有讓等待解除（例如 done 沒關），關機會固定吃滿 StopWaitBudget——
// 一個只該影響指標的缺陷，變成每次關機都慢兩秒。
func TestStopAfterTaskPanicReturnsPromptly(t *testing.T) {
	logs := captureLog(t)

	// 指標為 nil：資料源成功回值後、寫入指標時 panic——這一段在 callSource 之外，
	// 由任務本體的兜底層攔截
	called := make(chan struct{})
	var once sync.Once
	stop := StartRefresher(nil, RefreshSources{
		ActiveSessions: func() (map[string]float64, error) {
			once.Do(func() { close(called) })
			return map[string]float64{"ssh": 1}, nil
		},
	}, time.Hour)

	select {
	case <-called:
	case <-time.After(3 * time.Second):
		t.Fatal("資料源未被呼叫：本測試的兜底斷言將由假前提成立")
	}

	start := time.Now()
	require.NoError(t, stop(context.Background()), "任務已因 panic 結束，停止函式卻回報未等到")
	require.Less(t, time.Since(start), StopWaitBudget, "停止函式等滿了預算：done 未於 panic 展開時關閉")

	require.True(t, strings.Contains(logs.String(), "背景刷新任務因 panic 終止"),
		"任務本體的 panic 未留下紀錄：\n%s", logs.String())
}
