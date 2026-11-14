package audit

// 即時寫出（FlushQueued）守衛。
//
// # 釘的是什麼
//
// 審計列在寫入時才蓋完整性章；組裝根在收回蓋章所需的材料之前呼叫 FlushQueued，
// 要的是「呼叫當下已入列的列，返回時都已寫出」。本檔釘這個保證的三個來源與兩個邊界：
//
//  1. worker 已取走、還沒湊滿一批的列（留在 worker 手上，定時 flush 還沒到）。
//  2. 還在佇列內、沒有 worker 取走的列。
//  3. 寫出之後 worker 仍在運作（本方法不是關閉）。
//  4. sink 停滯時於期限內返回錯誤，不無限等待。
//  5. 服務已關閉後呼叫直接返回。

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// flushSink 測試注入的批次 sink：記下寫出的列，可選擇停滯。
type flushSink struct {
	mu    sync.Mutex
	paths []string
	stall chan struct{}
}

func (k *flushSink) write(logs []*model.AuditLog) error {
	if k.stall != nil {
		<-k.stall
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, l := range logs {
		k.paths = append(k.paths, l.Path)
	}
	return nil
}

func (k *flushSink) count() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.paths)
}

// newFlushTestService 啟動 workers 條 worker 的非同步審計服務；定時 flush 設為
// 一小時，使「列留在 worker 手上」的狀態在測試期間穩定存在。
func newFlushTestService(t *testing.T, workers int, sink *flushSink) *AuditLogService {
	t.Helper()
	s := newDrainTestService(t, false)
	s.workerCount = workers
	s.writeBatch = sink.write
	s.flushReqs = make([]chan chan struct{}, workers)
	for i := range s.flushReqs {
		s.flushReqs[i] = make(chan chan struct{})
	}
	for i := 0; i < workers; i++ {
		s.wg.Add(1)
		go s.worker(i)
	}
	return s
}

func logRows(s *AuditLogService, n int) {
	for i := 0; i < n; i++ {
		s.Log(&AuditLogEntry{
			Username: "flush", Action: model.ActionLogin, Resource: model.ResourceAuth,
			Status: model.StatusSuccess, Method: "POST", Path: "/api/v1/flush",
			ClientIP: "203.0.113.9", StatusCode: 200,
		})
	}
}

func stopFlushTestService(t *testing.T, s *AuditLogService) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, s.Shutdown(ctx))
}

// TestFlushQueuedWritesRowsHeldByWorkers worker 手上未滿一批的列在返回前寫出，
// 之後 worker 仍在運作。
func TestFlushQueuedWritesRowsHeldByWorkers(t *testing.T) {
	sink := &flushSink{}
	s := newFlushTestService(t, 3, sink)
	defer stopFlushTestService(t, s)

	const n = 7 // 小於批量：沒有任何一條 worker 會自行 flush
	logRows(s, n)
	require.Eventually(t, func() bool { return s.QueueDepth() == 0 && s.inFlight.Load() == n },
		5*time.Second, 5*time.Millisecond, "前置條件：全部列已被 worker 取走、留在手上")
	require.Zero(t, sink.count(), "前置條件：定時 flush 未到、未滿一批，尚無任何列寫出")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, s.FlushQueued(ctx))
	require.Equal(t, n, sink.count(), "返回時 worker 手上的列必須已全數寫出")
	require.Zero(t, s.inFlight.Load())

	// 不是關閉：之後入列的列仍由 worker 處理，再呼叫一次同樣寫出
	logRows(s, 3)
	require.NoError(t, s.FlushQueued(ctx))
	require.Equal(t, n+3, sink.count())
}

// TestFlushQueuedWritesRowsStillInQueue 沒有 worker 取走的佇列殘留由呼叫端直接寫出。
func TestFlushQueuedWritesRowsStillInQueue(t *testing.T) {
	sink := &flushSink{}
	s := newDrainTestService(t, false) // 不啟動 worker
	s.writeBatch = sink.write
	const n = 25
	enqueueRows(t, s, n)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, s.FlushQueued(ctx))
	require.Equal(t, n, sink.count())
	require.Zero(t, s.QueueDepth())
	require.Zero(t, s.inFlight.Load())
}

// TestFlushQueuedReturnsWhenSinkStalls sink 停滯時於期限內返回錯誤。
func TestFlushQueuedReturnsWhenSinkStalls(t *testing.T) {
	sink := &flushSink{stall: make(chan struct{})}
	s := newFlushTestService(t, 1, sink)
	logRows(s, s.batchSize) // 湊滿一批：worker 自行 flush 並卡在 sink 內
	require.Eventually(t, func() bool { return s.QueueDepth() == 0 && s.inFlight.Load() == int64(s.batchSize) },
		5*time.Second, 5*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := s.FlushQueued(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), 2*time.Second, "不得等待停滯的 sink 超過期限")

	close(sink.stall)
	stopFlushTestService(t, s)
}

// TestFlushQueuedAfterShutdownReturns 服務關閉後呼叫直接返回，不等待已結束的 worker。
func TestFlushQueuedAfterShutdownReturns(t *testing.T) {
	sink := &flushSink{}
	s := newFlushTestService(t, 2, sink)
	stopFlushTestService(t, s)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, s.FlushQueued(ctx))
}
