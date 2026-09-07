package api

import (
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// 攔下確認端點的退避在**併發**下的射程。
//
// 逐次送出時的上限已由既有兩檔釘住；本檔補的是併發這一半：一波同時抵達的錯密
// 請求，走到憑證驗證的次數不得超過上限。這是先前形態真正失效的地方——准入判定
// 與失敗計數之間沒有互斥，同時抵達的請求全部讀到同一個未達上限的計數而一起放行，
// 於是「五次就鎖」只對單執行緒的送法成立。
//
// **判準用可注入的確認函式計數，不看回應碼分佈**：回應碼只說明「這一次被擋了」，
// 說明不了「憑證驗證被觸及幾次」，而後者才是上限要保護的東西。

// TestInstanceGuardAckConcurrentAttemptsRespectLimit 20 個併發錯密請求：
// 走到憑證驗證的次數 MUST <= haltAckMaxFailures，其餘 MUST 得到 429。
func TestInstanceGuardAckConcurrentAttemptsRespectLimit(t *testing.T) {
	prev := gin.Mode()
	gin.SetMode(gin.TestMode)
	t.Cleanup(func() { gin.SetMode(prev) })

	const concurrent = 20

	var verified int64
	// 起跑閘：全部 goroutine 備妥後才一起放行，讓准入判定真的重疊。
	var start sync.WaitGroup
	start.Add(1)
	// 驗證閘：進入「憑證驗證」的請求全部停在此，直到最後一個請求也送出為止。
	// 沒有它，先到的請求會在後到者判定准入之前就結束、把名額退還／確認完畢，
	// 併發窗口被自己的速度抹平，測試會退化成逐次送出。
	var hold sync.WaitGroup
	hold.Add(1)

	h := NewInstanceGuardHaltHandler(
		func() InstanceGuardHaltView { return haltedView() },
		func(InstanceGuardAckRequest) InstanceGuardAckResult {
			atomic.AddInt64(&verified, 1)
			hold.Wait()
			return InstanceGuardAckResult{Outcome: AckOutcomeInvalidCredential}
		})
	r := gin.New()
	h.RegisterRoutes(r.Group("/api/v1"))

	codes := make([]int, concurrent)
	var settled int64 // 已回應完畢者（驗證閘放行前，只有被退避擋下的請求會走到這裡）
	var done sync.WaitGroup
	for i := 0; i < concurrent; i++ {
		done.Add(1)
		go func(i int) {
			defer done.Done()
			start.Wait()
			codes[i] = postAck(t, r, fullAckRequest()).Code
			atomic.AddInt64(&settled, 1)
		}(i)
	}
	start.Done()

	// 等到「已被擋下者」與「已進入驗證者」合計等於全部請求，才放行驗證閘。
	// 以計數收斂而非睡固定時間：後者在慢機器上會提早放行而讓測試失去射程。
	waitAllDispatched(t, &verified, &settled, concurrent)
	hold.Done()
	done.Wait()

	got := atomic.LoadInt64(&verified)
	if got > haltAckMaxFailures {
		t.Fatalf("併發 %d 個錯密請求中有 %d 個走到憑證驗證，上限為 %d——"+
			"准入預留失效：判定與計數之間若不互斥，同時抵達的請求會一起通過",
			concurrent, got, haltAckMaxFailures)
	}
	if got == 0 {
		t.Fatalf("一個請求都沒走到憑證驗證，測試沒有射程")
	}

	var unauthorized, locked int
	for _, c := range codes {
		switch c {
		case http.StatusUnauthorized:
			unauthorized++
		case http.StatusTooManyRequests:
			locked++
		default:
			t.Fatalf("非預期狀態碼 %d（只應有 401 與 429）", c)
		}
	}
	if unauthorized != int(got) {
		t.Fatalf("401 有 %d 個，但只有 %d 個請求走到憑證驗證", unauthorized, got)
	}
	if locked != concurrent-unauthorized {
		t.Fatalf("其餘 %d 個請求應全部得到 429，實得 %d", concurrent-unauthorized, locked)
	}
}

// waitAllDispatched 等所有請求都已完成准入判定：已進入驗證者（卡在驗證閘）
// 加上已回應完畢者（＝被退避擋下者）等於總數。以計數收斂而非睡眠判定——
// 睡固定時間在慢機器上會提早放行，讓測試失去射程卻照樣綠。
func waitAllDispatched(t *testing.T, verified, settled *int64, total int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if int(atomic.LoadInt64(verified)+atomic.LoadInt64(settled)) >= total {
			return
		}
		runtime.Gosched()
	}
	t.Fatalf("准入判定未於預算內全部完成（已驗證 %d、已回應 %d、總數 %d）",
		atomic.LoadInt64(verified), atomic.LoadInt64(settled), total)
}
