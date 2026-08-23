package recorder

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AsciicastHeader asciinema v2 格式的 Header
// 參考: https://github.com/asciinema/asciinema/blob/develop/doc/asciicast-v2.md
type AsciicastHeader struct {
	Version   int               `json:"version"`
	Width     int               `json:"width"`
	Height    int               `json:"height"`
	Timestamp int64             `json:"timestamp"` // Unix timestamp
	Env       map[string]string `json:"env,omitempty"`
}

// AsciicastRecorder 實作 asciinema v2 格式的錄製器
type AsciicastRecorder struct {
	basePath   string // 錄影根目錄，建構時已由 ResolveBasePath 正規化
	file       *os.File
	writer     *bufio.Writer
	metadata   RecordingMetadata
	startTime  time.Time
	eventCount int
	mu         sync.Mutex
	closed     bool

	// 定時 Flush 機制
	flushTicker *time.Ticker
	stopFlush   chan struct{}

	// 錯誤 latch：autoFlush 的磁碟錯誤不得
	// 因閒置（無後續輸出）而永久沉默——latch 首個錯誤、通知一次
	flushErr error
	onError  func(error)
}

// NewAsciicastRecorder 創建新的 asciinema 錄製器
// basePath: 錄製檔案基礎路徑（例如: /var/lib/custodexa/recordings）；空字串則於
// Start 時退回 RECORDING_PATH／出廠預設。此處即正規化，Start 不再自己讀環境變數。
//
// 註：注入值原本被建構子**整個丟棄**（Start 一律重讀 env），呼叫端傳什麼都沒有作用。
// 生產路徑上兩者同值故行為未變，但那讓「注入」形同裝飾、也讓落檔位置無法在測試中
// 獨立於環境變數驗證。改為存起來並交由 ResolveBasePath 收口。
func NewAsciicastRecorder(basePath string) *AsciicastRecorder {
	return &AsciicastRecorder{
		basePath:  ResolveBasePath(basePath),
		closed:    false,
		stopFlush: make(chan struct{}),
	}
}

// Start 開始錄製
func (r *AsciicastRecorder) Start(metadata RecordingMetadata) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.file != nil {
		return fmt.Errorf("錄製已經開始")
	}

	r.metadata = metadata
	r.startTime = metadata.StartTime
	if r.startTime.IsZero() {
		r.startTime = time.Now()
	}

	// 創建錄製檔案路徑: {basePath}/{YYYY-MM-DD}/session-{session_id}.cast
	dateDir := r.startTime.Format("2006-01-02")
	dirPath := filepath.Join(ResolveBasePath(r.basePath), dateDir)
	// 0700／0600：錄影是會話全文，可能含使用者在目標機上鍵入的密碼。後端本體以
	// root 讀寫不受影響，容器內的其他身分（資料庫 CLI 的降權執行身分）則讀不到
	if err := os.MkdirAll(dirPath, 0700); err != nil {
		return fmt.Errorf("創建錄製目錄失敗: %w", err)
	}
	// MkdirAll 只對**新建**的目錄套 perm，既存目錄原樣不動（實測：本版上線當天的
	// 日期目錄由舊版以 0755 建立，改成 0700 後仍是 0755）。故每次開檔顯式收斂一次，
	// 讓既有部署自我修復——否則「錄影目錄 0700」在跨日之前都只是紙上規定
	if err := os.Chmod(dirPath, 0700); err != nil {
		return fmt.Errorf("收斂錄製目錄權限失敗: %w", err)
	}

	// 檔案名稱: session-{session_id}.cast
	fileName := fmt.Sprintf("session-%d.cast", metadata.SessionID)
	filePath := filepath.Join(dirPath, fileName)

	// 創建檔案（0600，理由同上；os.Create 的 0666&umask 會落在 0644）
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("創建錄製檔案失敗: %w", err)
	}

	r.file = file
	r.writer = bufio.NewWriter(file)

	// 寫入 Header（asciinema v2 第一行）
	if err := r.writeHeader(); err != nil {
		r.file.Close()
		return fmt.Errorf("寫入 Header 失敗: %w", err)
	}

	// 啟動定時 Flush（每 100ms）
	r.flushTicker = time.NewTicker(100 * time.Millisecond)
	go r.autoFlush()

	return nil
}

// writeHeader 寫入 asciinema v2 Header（第一行）
func (r *AsciicastRecorder) writeHeader() error {
	header := AsciicastHeader{
		Version:   2,
		Width:     r.metadata.Width,
		Height:    r.metadata.Height,
		Timestamp: r.startTime.Unix(),
		Env:       r.metadata.Env,
	}

	// 如果沒有提供尺寸，使用默認值
	if header.Width == 0 {
		header.Width = 80
	}
	if header.Height == 0 {
		header.Height = 24
	}

	// 序列化為 JSON（不換行）
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return fmt.Errorf("序列化 Header 失敗: %w", err)
	}

	// 寫入第一行
	if _, err := r.writer.Write(headerJSON); err != nil {
		return err
	}
	if _, err := r.writer.WriteString("\n"); err != nil {
		return err
	}

	return nil
}

// WriteInput 寫入輸入事件
func (r *AsciicastRecorder) WriteInput(elapsed time.Duration, data []byte) error {
	return r.writeEvent(elapsed, "i", data)
}

// WriteOutput 寫入輸出事件
func (r *AsciicastRecorder) WriteOutput(elapsed time.Duration, data []byte) error {
	return r.writeEvent(elapsed, "o", data)
}

// WriteResize 寫入終端尺寸變更事件（asciicast v2 的 "r" 事件，格式 "{cols}x{rows}"）
func (r *AsciicastRecorder) WriteResize(elapsed time.Duration, cols, rows int) error {
	return r.writeEvent(elapsed, "r", []byte(fmt.Sprintf("%dx%d", cols, rows)))
}

// writeEvent 寫入事件
// asciinema v2 事件格式: [timestamp, event_type, data]
// timestamp: 浮點數，單位為秒
// event_type: "o" (output) 或 "i" (input)
// data: 字串
func (r *AsciicastRecorder) writeEvent(elapsed time.Duration, eventType string, data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return fmt.Errorf("錄製已停止")
	}

	if r.writer == nil {
		return fmt.Errorf("錄製尚未開始")
	}

	// 先前 flush 已失敗：直接浮出（bufio sticky error 同向，此處保證即使
	// 錯誤發生於 autoFlush 也會在下一次寫入被呼叫端看到）
	if r.flushErr != nil {
		return fmt.Errorf("錄製寫入先前已失敗: %w", r.flushErr)
	}

	// 跳過空資料
	if len(data) == 0 {
		return nil
	}

	// 計算時間戳（秒，保留 3 位小數）
	timestamp := elapsed.Seconds()

	// 構建事件: [timestamp, event_type, data]
	event := []interface{}{
		timestamp,
		eventType,
		string(data),
	}

	// 序列化為 JSON
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("序列化事件失敗: %w", err)
	}

	// 寫入事件行
	if _, err := r.writer.Write(eventJSON); err != nil {
		return fmt.Errorf("寫入事件失敗: %w", err)
	}
	if _, err := r.writer.WriteString("\n"); err != nil {
		return fmt.Errorf("寫入換行失敗: %w", err)
	}

	r.eventCount++

	return nil
}

// SetOnError 註冊首次寫入/flush 錯誤的通知回呼。
// 回呼於鎖外執行，可安全做 DB/告警等慢速工作。若註冊前 autoFlush 已 latch
// 錯誤（Start 與註冊之間的窗口），立即補通知——閒置會話不得因時序沉默；
// 重複通知由呼叫端 once 語義去重
func (r *AsciicastRecorder) SetOnError(cb func(error)) {
	r.mu.Lock()
	latched := r.flushErr
	r.onError = cb
	r.mu.Unlock()
	if latched != nil && cb != nil {
		cb(latched)
	}
}

// autoFlush 自動定時 Flush 緩衝區
func (r *AsciicastRecorder) autoFlush() {
	for {
		select {
		case <-r.flushTicker.C:
			var notify func(error)
			var ferr error
			r.mu.Lock()
			if r.writer != nil && !r.closed {
				if err := r.writer.Flush(); err != nil && r.flushErr == nil {
					r.flushErr = err
					notify, ferr = r.onError, err
				}
			}
			r.mu.Unlock()
			if notify != nil {
				notify(ferr)
			}
		case <-r.stopFlush:
			return
		}
	}
}

// Flush 立即 Flush 緩衝區
func (r *AsciicastRecorder) Flush() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.writer == nil {
		return fmt.Errorf("錄製尚未開始")
	}

	return r.writer.Flush()
}

// Stop 停止錄製
func (r *AsciicastRecorder) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil // 已經關閉
	}

	r.closed = true

	// 停止定時 Flush
	if r.flushTicker != nil {
		r.flushTicker.Stop()
		close(r.stopFlush)
	}

	// Flush 剩餘資料
	if r.writer != nil {
		if err := r.writer.Flush(); err != nil {
			return fmt.Errorf("Flush 失敗: %w", err)
		}
	}

	// 關閉檔案
	if r.file != nil {
		if err := r.file.Close(); err != nil {
			return fmt.Errorf("關閉檔案失敗: %w", err)
		}
	}

	return nil
}

// GetFilePath 取得錄製檔案路徑
func (r *AsciicastRecorder) GetFilePath() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.file == nil {
		return ""
	}

	return r.file.Name()
}

// GetMetadata 取得錄製元數據（測試用）
func (r *AsciicastRecorder) GetMetadata() RecordingMetadata {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.metadata
}

// GetEventCount 取得事件數量（測試用）
func (r *AsciicastRecorder) GetEventCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.eventCount
}
