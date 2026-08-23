package recorder

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// TestProbeWritable 簽發點前置探測
func TestProbeWritable(t *testing.T) {
	t.Run("可寫目錄通過", func(t *testing.T) {
		if err := ProbeWritable(t.TempDir()); err != nil {
			t.Fatalf("可寫目錄應通過: %v", err)
		}
	})

	t.Run("基礎路徑為檔案時失敗", func(t *testing.T) {
		// 以「路徑是檔案」誘發——root 也擋得住（權限類誘發對 root 無效）
		f := filepath.Join(t.TempDir(), "not-a-dir")
		if err := os.WriteFile(f, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := ProbeWritable(f); err == nil {
			t.Fatal("basePath 為檔案應失敗")
		}
	})

	t.Run("日期子目錄被檔案佔用時失敗", func(t *testing.T) {
		// 文字路徑實際寫 {base}/{YYYY-MM-DD}/，只驗 base
		// 會放行「base 可寫但日期層被佔用」→ probe 必須探到日期層
		dir := t.TempDir()
		today := time.Now().Format("2006-01-02")
		if err := os.WriteFile(filepath.Join(dir, today), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := ProbeWritable(dir); err == nil {
			t.Fatal("日期層被佔用應失敗")
		}
	})

	t.Run("探測檔不殘留", func(t *testing.T) {
		dir := t.TempDir()
		if err := ProbeWritable(dir); err != nil {
			t.Fatalf("probe: %v", err)
		}
		dateDir := filepath.Join(dir, time.Now().Format("2006-01-02"))
		entries, _ := os.ReadDir(dateDir)
		if len(entries) != 0 {
			t.Fatalf("探測檔應清除: %v", entries)
		}
	})
}

// TestAutoFlushIdleErrorNotify 閒置路徑：錯誤只發生在定時 flush（無後續寫入）
// 時仍須通知——這是核心保證
func TestAutoFlushIdleErrorNotify(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RECORDING_PATH", dir)
	r := NewAsciicastRecorder(dir)
	if err := r.Start(RecordingMetadata{SessionID: 2, Width: 80, Height: 24, StartTime: time.Now()}); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer r.Stop()

	var notified atomic.Int32
	r.SetOnError(func(error) { notified.Add(1) })

	// 先抽走檔案，再小量寫入（入 bufio 緩衝、不觸發底層寫）——其後零寫入，
	// 錯誤唯一的發現點是 autoFlush 定時 Flush
	r.mu.Lock()
	r.file.Close()
	r.mu.Unlock()
	if err := r.WriteOutput(time.Millisecond, []byte("tiny")); err != nil {
		t.Fatalf("小量寫入應入緩衝不報錯: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for notified.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if notified.Load() == 0 {
		t.Fatal("閒置會話的定時 flush 錯誤應經 SetOnError 通知")
	}
}

// TestSetOnErrorAfterLatch 註冊窗口：Start 與 SetOnError
// 之間已 latch 的錯誤，註冊當下立即補通知
func TestSetOnErrorAfterLatch(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RECORDING_PATH", dir)
	r := NewAsciicastRecorder(dir)
	if err := r.Start(RecordingMetadata{SessionID: 3, Width: 80, Height: 24, StartTime: time.Now()}); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer r.Stop()

	// 尚未註冊回呼時先製造 latch
	r.mu.Lock()
	r.file.Close()
	r.mu.Unlock()
	_ = r.WriteOutput(time.Millisecond, []byte("tiny"))
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		latched := r.flushErr != nil
		r.mu.Unlock()
		if latched {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	var notified atomic.Int32
	r.SetOnError(func(error) { notified.Add(1) })
	if notified.Load() != 1 {
		t.Fatal("已 latch 錯誤時註冊回呼應立即補通知")
	}
}

// TestAutoFlushErrorLatch autoFlush 錯誤 latch：磁碟層失敗須通知一次、
// 後續寫入浮出錯誤，閒置不沉默
func TestAutoFlushErrorLatch(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RECORDING_PATH", dir)
	r := NewAsciicastRecorder(dir)
	if err := r.Start(RecordingMetadata{SessionID: 1, Width: 80, Height: 24, StartTime: time.Now()}); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer r.Stop()

	var notified atomic.Int32
	r.SetOnError(func(error) { notified.Add(1) })

	// 從 recorder 腳下關閉檔案模擬磁碟層失敗；超過 bufio 緩衝的寫入
	// 觸發底層寫錯誤，其後 autoFlush 應 latch 並通知
	r.mu.Lock()
	r.file.Close()
	r.mu.Unlock()
	_ = r.WriteOutput(time.Millisecond, make([]byte, 8192))

	deadline := time.Now().Add(2 * time.Second)
	for notified.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if notified.Load() == 0 {
		t.Fatal("autoFlush 錯誤應觸發一次通知")
	}

	if err := r.WriteOutput(2*time.Millisecond, []byte("x")); err == nil {
		t.Fatal("latch 後寫入應回錯誤（閒置不沉默的浮出保證）")
	}

	// 再等數個 flush 週期：通知恰一次
	time.Sleep(300 * time.Millisecond)
	if got := notified.Load(); got != 1 {
		t.Fatalf("通知應恰一次, got %d", got)
	}
}
