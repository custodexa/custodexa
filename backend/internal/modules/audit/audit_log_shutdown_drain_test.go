package audit

// 關機排空守衛。
//
// # 釘的是什麼
//
// 非同步審計的 worker 收到關閉訊號時，原本只 flush 自己手上的批次就返回；
// 佇列（容量 1000）內尚未被取走的列隨行程一起消失，而那些列對應的請求早已
// 回應完成——呼叫端以為已留痕。本檔釘兩件事：
//
//  1. 佇列殘留在關機返回前全數落地（sink 正常時）。
//  2. sink 停滯時關機仍於期限內返回，且未落地的筆數以計數器與日誌明確報出，不靜默。
//
// # 測試的構造方式
//
// 兩個測試都**先讓 Shutdown 發出關閉訊號、再啟動 worker**：worker 從第一輪 select
// 起就看得到 stopChan，走的必然是關機路徑。反過來先起 worker，正常消費路徑有機會
// 把佇列吃光，對「關機不排空」的舊行為就驗不出紅。

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/model"
)

// newDrainTestService 建一個非同步審計服務，**不啟動 worker**——由測試決定
// worker 何時進場。計時器設為一小時：本檔只驗關機路徑，不讓定時 flush 介入。
func newDrainTestService(t *testing.T, fallbackToFile bool) *AuditLogService {
	t.Helper()
	return &AuditLogService{
		cfg: &config.FeatureFlags{
			AuditLogEnabled:     true,
			AsyncAuditEnabled:   true,
			AuditFallbackToFile: fallbackToFile,
		},
		logChan:     make(chan *model.AuditLog, 1000),
		workerCount: 1,
		batchSize:   10,
		flushTicker: time.NewTicker(time.Hour),
		stopChan:    make(chan struct{}),
		drainAbort:  make(chan struct{}),
		fallbackDir: t.TempDir(),
	}
}

func enqueueRows(t *testing.T, s *AuditLogService, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		s.Log(&AuditLogEntry{
			Username: "drain", Action: model.ActionLogin, Resource: model.ResourceAuth,
			Status: model.StatusFailure, Method: "GET", Path: fmt.Sprintf("/api/v1/drain/%d", i),
			ClientIP: "203.0.113.9", StatusCode: 401,
		})
	}
	require.Equal(t, n, s.QueueDepth(), "前置條件：worker 尚未啟動，全部列都還在佇列內")
}

// shutdownThenStartWorker 先發關閉訊號、等它真的發出，再讓 worker 進場。
// 回傳 Shutdown 的結果通道。
func shutdownThenStartWorker(s *AuditLogService, timeout time.Duration) <-chan error {
	errCh := make(chan error, 1)
	s.wg.Add(1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		errCh <- s.Shutdown(ctx)
	}()
	<-s.stopChan
	go s.worker(0)
	return errCh
}

// syncBuffer log 輸出的執行緒安全緩衝：worker 與測試主體分屬不同 goroutine。
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

func captureLog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	prev := log.Writer()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return buf
}

// TestShutdownDrainsQueuedRowsBeforeReturn 佇列殘留在關機返回前全數落地。
func TestShutdownDrainsQueuedRowsBeforeReturn(t *testing.T) {
	db := installBatchIsolationDB(t)
	s := newDrainTestService(t, false)
	const n = 25 // 不是批量的整數倍：最後一批必須靠排空結束時的 flush 才落地
	enqueueRows(t, s, n)

	errCh := shutdownThenStartWorker(s, 5*time.Second)
	select {
	case err := <-errCh:
		require.NoError(t, err, "sink 正常時排空應在期限內完成")
	case <-time.After(10 * time.Second):
		t.Fatal("Shutdown 未返回")
	}

	var count int64
	require.NoError(t, db.Model(&model.AuditLog{}).Count(&count).Error)
	require.EqualValues(t, n, count, "關閉訊號到達時仍在佇列內的列必須全數入庫")
	require.Equal(t, 0, s.QueueDepth())
	require.Zero(t, s.inFlight.Load(), "排空完成後不得有未回報的列")
}

// TestShutdownReportsUnflushedRowsWhenSinkStalls sink 停滯時：關機於期限內返回，
// 且未落地筆數以錯誤、觀測掛勾（計數器資料源）與日誌三處明確報出。
func TestShutdownReportsUnflushedRowsWhenSinkStalls(t *testing.T) {
	for _, tc := range []struct {
		name           string
		fallbackToFile bool
	}{
		{"檔案降級開啟：佇列殘留寫檔可回收", true},
		{"檔案降級關閉：佇列殘留確定遺失", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newDrainTestService(t, tc.fallbackToFile)

			// 停滯的 sink：第一批進來就卡住，直到測試結束才放行（避免 goroutine 洩漏到其他測試）
			release := make(chan struct{})
			var sinkCalls atomic.Int32
			s.writeBatch = func([]*model.AuditLog) error {
				sinkCalls.Add(1)
				<-release
				return nil
			}
			rec := &dropRecorder{}
			s.SetDropObserver(rec.observe)
			logs := captureLog(t)
			t.Cleanup(func() { close(release) })

			const n = 25
			enqueueRows(t, s, n)

			const budget = 300 * time.Millisecond
			start := time.Now()
			errCh := shutdownThenStartWorker(s, budget)
			var err error
			select {
			case err = <-errCh:
			case <-time.After(5 * time.Second):
				t.Fatal("sink 停滯時 Shutdown 未在期限內返回——關機被 sink 卡住")
			}
			// 上界＝期限＋中止窗口＋處置殘留；取寬鬆值容忍容器負載，但遠小於「等 sink」的無限期
			require.Less(t, time.Since(start), 3*time.Second)
			require.EqualValues(t, 1, sinkCalls.Load(), "前置條件：sink 恰被呼叫一次且停滯中")

			var drainErr *ShutdownDrainError
			require.ErrorAs(t, err, &drainErr, "期限到必須以結構化錯誤報出，不得回 nil 或裸 ctx.Err()")
			require.Equal(t, n, drainErr.Unflushed, "未確認落地的總數＝佇列殘留＋worker 持有中")
			require.Equal(t, s.batchSize, drainErr.InFlight, "卡在 sink 內的那一批")

			residual := n - s.batchSize
			if tc.fallbackToFile {
				require.Equal(t, residual, drainErr.FallbackFiled)
				require.Zero(t, drainErr.Lost())
				require.Equal(t, residual, countFallbackLines(t, s.fallbackDir), "殘留列須逐列寫進降級檔")
			} else {
				require.Zero(t, drainErr.FallbackFiled)
				require.Equal(t, residual, drainErr.Lost())
			}

			calls := rec.snapshot()
			require.Len(t, calls, residual, "佇列殘留須逐列通知觀測掛勾（計數器資料源）")
			for _, fellBack := range calls {
				require.Equal(t, tc.fallbackToFile, fellBack)
			}

			require.Contains(t, logs.String(), fmt.Sprintf("%d 列未確認落地", n), "日誌須帶筆數，不得只說逾時")
			require.Equal(t, 0, s.QueueDepth(), "殘留已被取走處置，不留在佇列內")
		})
	}
}

func countFallbackLines(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	total := 0
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		require.NoError(t, err)
		total += len(strings.Split(strings.TrimSpace(string(data)), "\n"))
	}
	return total
}
