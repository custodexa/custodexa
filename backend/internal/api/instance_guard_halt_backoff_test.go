package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// 攔下確認端點的行程內退避「時窗」守衛。
//
// 上限（達 haltAckMaxFailures 次即 429）已由
// TestInstanceGuardAckLocksOutAfterRepeatedCredentialFailures 釘住；
// 本檔補的是**時窗**這一半：暫拒的期限、期滿受理、以及期滿後計數歸零
//（`reserveAttempt()` 的到期分支——它自己的註解點名「否則下一次失敗立刻再鎖」的死循環，
// 卻是零覆蓋）。時鐘由 handler 的 now 欄位注入，測試不必真的等 5 分鐘。
//
// **推進時鐘一律用字面時距，不得用 haltAckLockWindow 推導**：用常數推導的話，
// 把常數改成 0 或 5 小時時測試會跟著位移而照樣綠——那就是拿被測對象當基準。

// haltBackoffStub 可變的確認結果與可推進的假時鐘。
type haltBackoffStub struct {
	outcome InstanceGuardAckOutcome
	calls   int
	now     time.Time
}

func (s *haltBackoffStub) advance(d time.Duration) { s.now = s.now.Add(d) }

func newHaltBackoffRouter(t *testing.T) (*gin.Engine, *haltBackoffStub) {
	t.Helper()
	prev := gin.Mode()
	gin.SetMode(gin.TestMode)
	t.Cleanup(func() { gin.SetMode(prev) })

	s := &haltBackoffStub{
		outcome: AckOutcomeInvalidCredential,
		now:     time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC),
	}
	h := NewInstanceGuardHaltHandler(
		func() InstanceGuardHaltView { return haltedView() },
		func(InstanceGuardAckRequest) InstanceGuardAckResult {
			s.calls++
			return InstanceGuardAckResult{Outcome: s.outcome}
		})
	h.now = func() time.Time { return s.now }
	r := gin.New()
	h.RegisterRoutes(r.Group("/api/v1"))
	return r, s
}

// failUntilLocked 跑滿上限次憑證失敗（各須回 401），使該來源進入退避。
func failUntilLocked(t *testing.T, r *gin.Engine) {
	t.Helper()
	for i := 0; i < haltAckMaxFailures; i++ {
		if w := postAck(t, r, fullAckRequest()); w.Code != http.StatusUnauthorized {
			t.Fatalf("第 %d 次憑證失敗應回 401，實得 %d（body=%s）", i+1, w.Code, w.Body.String())
		}
	}
}

// TestInstanceGuardAckBackoffWindowRejectsThenExpires 退避時窗的三件事：
// 期內即使帳密正確亦暫拒（且不觸及確認函式）、期內再嘗試不延長時窗、期滿受理。
func TestInstanceGuardAckBackoffWindowRejectsThenExpires(t *testing.T) {
	r, s := newHaltBackoffRouter(t)
	failUntilLocked(t, r)
	confirmsAtLock := s.calls

	// 帳密改成正確：退避期內仍 MUST 暫拒，且 MUST NOT 觸及確認函式。
	s.outcome = AckOutcomeAccepted
	w := postAck(t, r, fullAckRequest())
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("退避期內即使帳密正確亦應暫拒（429），實得 %d（body=%s）", w.Code, w.Body.String())
	}
	if body := decodeBody(t, w); body["code"] != "INSTANCE_GUARD_ACK_LOCKED" {
		t.Fatalf("機器碼 = %v，want INSTANCE_GUARD_ACK_LOCKED", body["code"])
	}

	// 時窗尚未過半即再送一次：MUST 仍暫拒，且此次嘗試 MUST NOT 延長時窗
	//（下一步在 6 分鐘處受理即為證明——若被延長，那裡會是 429）。
	s.advance(4 * time.Minute)
	if w := postAck(t, r, fullAckRequest()); w.Code != http.StatusTooManyRequests {
		t.Fatalf("退避期內（第 4 分鐘）應仍暫拒，實得 %d", w.Code)
	}
	if s.calls != confirmsAtLock {
		t.Fatalf("退避期內 MUST NOT 觸及確認函式（＝不比對憑證），鎖定後又呼叫 %d 次",
			s.calls-confirmsAtLock)
	}

	// 時窗過後（第 6 分鐘，字面時距）：MUST 受理。
	s.advance(2 * time.Minute)
	w = postAck(t, r, fullAckRequest())
	if w.Code != http.StatusOK {
		t.Fatalf("退避期滿後應受理，實得 %d（body=%s）", w.Code, w.Body.String())
	}
	if s.calls != confirmsAtLock+1 {
		t.Fatalf("期滿後的請求 MUST 走到確認函式，呼叫次數 %d → %d", confirmsAtLock, s.calls)
	}
}

// TestInstanceGuardAckBackoffCounterResetsAfterWindow 期滿後失敗計數歸零。
//
// 若不歸零，期滿後的**第一次**失敗就會立刻重新達到上限而再鎖（handler 註解點名的
// 死循環）；本測試要求期滿後必須再跑滿一整輪上限才會回到 429。
func TestInstanceGuardAckBackoffCounterResetsAfterWindow(t *testing.T) {
	r, s := newHaltBackoffRouter(t)
	failUntilLocked(t, r)
	if w := postAck(t, r, fullAckRequest()); w.Code != http.StatusTooManyRequests {
		t.Fatalf("前提不成立：達上限後應為 429，實得 %d", w.Code)
	}

	s.advance(6 * time.Minute) // 字面時距，理由見檔頭
	// 期滿後的每一次失敗都應回 401（計數已歸零），跑滿一整輪才再鎖。
	failUntilLocked(t, r)
	if w := postAck(t, r, fullAckRequest()); w.Code != http.StatusTooManyRequests {
		t.Fatalf("期滿後再跑滿上限應重新暫拒，實得 %d", w.Code)
	}
}
