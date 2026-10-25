package asset

import (
	"context"
	"errors"
	"sync/atomic"
)

// remoteCallCounter 只計數、一律回錯的遠端替身：外部測試用它證明某條路徑沒有任何遠端呼叫。
type remoteCallCounter struct{ n *atomic.Int64 }

func (e remoteCallCounter) Rotate(context.Context, rotationTarget, []byte, []byte) error {
	e.n.Add(1)
	return errors.New("counting executor")
}

func (e remoteCallCounter) Verify(context.Context, rotationTarget, []byte) error {
	e.n.Add(1)
	return errors.New("counting executor")
}

// CountRemoteCallsForTest 把執行器換成計數替身，回傳讀取累計遠端呼叫次數的函式。
func CountRemoteCallsForTest(r *ChangeSecretRunner) func() int64 {
	n := &atomic.Int64{}
	r.executors = func(string) rotationExecutor { return remoteCallCounter{n: n} }
	return n.Load
}

// SetPlanPreTxHookForTest 計畫修改與一鍵重新授權在鎖前讀取之後、交易開始之前呼叫 fn。
func SetPlanPreTxHookForTest(s *ChangeSecretPlanService, fn func()) { s.preTxHook = fn }
