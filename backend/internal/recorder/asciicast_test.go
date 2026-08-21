package recorder

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestAsciicastRecorder_HeaderGeneration 測試 Header 生成
func TestAsciicastRecorder_HeaderGeneration(t *testing.T) {
	// 準備測試環境
	tmpDir := t.TempDir()
	os.Setenv("RECORDING_PATH", tmpDir)
	defer os.Unsetenv("RECORDING_PATH")

	recorder := NewAsciicastRecorder(tmpDir)

	metadata := RecordingMetadata{
		SessionID: 123,
		Protocol:  "ssh",
		Width:     120,
		Height:    40,
		Env: map[string]string{
			"TERM": "xterm-256color",
			"LANG": "en_US.UTF-8",
		},
		StartTime: time.Date(2025, 10, 20, 12, 0, 0, 0, time.UTC),
	}

	err := recorder.Start(metadata)
	if err != nil {
		t.Fatalf("Start() 失敗: %v", err)
	}
	defer recorder.Stop()

	// 驗證檔案是否創建
	filePath := recorder.GetFilePath()
	if filePath == "" {
		t.Fatal("GetFilePath() 返回空路徑")
	}

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Fatalf("錄製檔案不存在: %s", filePath)
	}

	// 讀取並驗證 Header
	recorder.Stop() // 確保資料已寫入

	file, err := os.Open(filePath)
	if err != nil {
		t.Fatalf("打開檔案失敗: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		t.Fatal("無法讀取第一行（Header）")
	}

	headerLine := scanner.Text()
	var header AsciicastHeader
	if err := json.Unmarshal([]byte(headerLine), &header); err != nil {
		t.Fatalf("解析 Header 失敗: %v, Header: %s", err, headerLine)
	}

	// 驗證 Header 內容
	if header.Version != 2 {
		t.Errorf("Version = %d, 期望 2", header.Version)
	}
	if header.Width != 120 {
		t.Errorf("Width = %d, 期望 120", header.Width)
	}
	if header.Height != 40 {
		t.Errorf("Height = %d, 期望 40", header.Height)
	}
	expectedTimestamp := metadata.StartTime.Unix()
	if header.Timestamp != expectedTimestamp {
		t.Errorf("Timestamp = %d, 期望 %d", header.Timestamp, expectedTimestamp)
	}
	if header.Env["TERM"] != "xterm-256color" {
		t.Errorf("Env[TERM] = %s, 期望 xterm-256color", header.Env["TERM"])
	}
}

// TestAsciicastRecorder_EventWriting 測試事件寫入
func TestAsciicastRecorder_EventWriting(t *testing.T) {
	tmpDir := t.TempDir()
	os.Setenv("RECORDING_PATH", tmpDir)
	defer os.Unsetenv("RECORDING_PATH")

	recorder := NewAsciicastRecorder(tmpDir)

	metadata := RecordingMetadata{
		SessionID: 456,
		Protocol:  "ssh",
		Width:     80,
		Height:    24,
		StartTime: time.Now(),
	}

	if err := recorder.Start(metadata); err != nil {
		t.Fatalf("Start() 失敗: %v", err)
	}

	// 寫入多個事件
	events := []struct {
		elapsed   time.Duration
		eventType string // "i" or "o"
		data      string
	}{
		{100 * time.Millisecond, "o", "$ "},
		{200 * time.Millisecond, "i", "ls\r"},
		{250 * time.Millisecond, "o", "file1.txt\nfile2.txt\n"},
		{300 * time.Millisecond, "o", "$ "},
	}

	for _, e := range events {
		var err error
		if e.eventType == "i" {
			err = recorder.WriteInput(e.elapsed, []byte(e.data))
		} else {
			err = recorder.WriteOutput(e.elapsed, []byte(e.data))
		}
		if err != nil {
			t.Fatalf("寫入事件失敗: %v", err)
		}
	}

	// 驗證事件數量
	if recorder.GetEventCount() != len(events) {
		t.Errorf("GetEventCount() = %d, 期望 %d", recorder.GetEventCount(), len(events))
	}

	recorder.Stop()

	// 讀取並驗證事件
	file, err := os.Open(recorder.GetFilePath())
	if err != nil {
		t.Fatalf("打開檔案失敗: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	// 跳過 Header
	if !scanner.Scan() {
		t.Fatal("無法讀取 Header")
	}

	// 驗證事件
	eventIndex := 0
	for scanner.Scan() {
		line := scanner.Text()
		var event []interface{}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("解析事件失敗: %v, 行: %s", err, line)
		}

		if len(event) != 3 {
			t.Fatalf("事件格式錯誤: %v", event)
		}

		// 驗證時間戳
		timestamp, ok := event[0].(float64)
		if !ok {
			t.Fatalf("時間戳類型錯誤: %T", event[0])
		}

		expectedTimestamp := events[eventIndex].elapsed.Seconds()
		if timestamp != expectedTimestamp {
			t.Errorf("事件 %d 時間戳 = %f, 期望 %f", eventIndex, timestamp, expectedTimestamp)
		}

		// 驗證事件類型
		eventType, ok := event[1].(string)
		if !ok {
			t.Fatalf("事件類型錯誤: %T", event[1])
		}
		if eventType != events[eventIndex].eventType {
			t.Errorf("事件 %d 類型 = %s, 期望 %s", eventIndex, eventType, events[eventIndex].eventType)
		}

		// 驗證資料
		data, ok := event[2].(string)
		if !ok {
			t.Fatalf("資料類型錯誤: %T", event[2])
		}
		if data != events[eventIndex].data {
			t.Errorf("事件 %d 資料 = %q, 期望 %q", eventIndex, data, events[eventIndex].data)
		}

		eventIndex++
	}

	if eventIndex != len(events) {
		t.Errorf("讀取到 %d 個事件, 期望 %d", eventIndex, len(events))
	}
}

// TestAsciicastRecorder_ConcurrentWrites 測試並發寫入安全性
func TestAsciicastRecorder_ConcurrentWrites(t *testing.T) {
	tmpDir := t.TempDir()
	os.Setenv("RECORDING_PATH", tmpDir)
	defer os.Unsetenv("RECORDING_PATH")

	recorder := NewAsciicastRecorder(tmpDir)

	metadata := RecordingMetadata{
		SessionID: 789,
		Protocol:  "ssh",
		Width:     80,
		Height:    24,
		StartTime: time.Now(),
	}

	if err := recorder.Start(metadata); err != nil {
		t.Fatalf("Start() 失敗: %v", err)
	}
	defer recorder.Stop()

	// 並發寫入測試
	var wg sync.WaitGroup
	numWriters := 10
	writesPerWriter := 50

	for i := 0; i < numWriters; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < writesPerWriter; j++ {
				elapsed := time.Duration(id*100+j) * time.Millisecond
				data := []byte("test")
				if id%2 == 0 {
					recorder.WriteOutput(elapsed, data)
				} else {
					recorder.WriteInput(elapsed, data)
				}
			}
		}(i)
	}

	wg.Wait()

	// 驗證事件數量
	expectedCount := numWriters * writesPerWriter
	actualCount := recorder.GetEventCount()
	if actualCount != expectedCount {
		t.Errorf("並發寫入後事件數量 = %d, 期望 %d", actualCount, expectedCount)
	}
}

// TestAsciicastRecorder_EmptyData 測試空資料處理
func TestAsciicastRecorder_EmptyData(t *testing.T) {
	tmpDir := t.TempDir()
	os.Setenv("RECORDING_PATH", tmpDir)
	defer os.Unsetenv("RECORDING_PATH")

	recorder := NewAsciicastRecorder(tmpDir)

	metadata := RecordingMetadata{
		SessionID: 999,
		Protocol:  "ssh",
		Width:     80,
		Height:    24,
		StartTime: time.Now(),
	}

	if err := recorder.Start(metadata); err != nil {
		t.Fatalf("Start() 失敗: %v", err)
	}
	defer recorder.Stop()

	// 寫入空資料（應該被忽略）
	err := recorder.WriteOutput(100*time.Millisecond, []byte{})
	if err != nil {
		t.Fatalf("寫入空資料失敗: %v", err)
	}

	// 驗證沒有事件被記錄
	if recorder.GetEventCount() != 0 {
		t.Errorf("空資料應該被忽略, 但 GetEventCount() = %d", recorder.GetEventCount())
	}
}

// TestAsciicastRecorder_StopTwice 測試重複 Stop
func TestAsciicastRecorder_StopTwice(t *testing.T) {
	tmpDir := t.TempDir()
	os.Setenv("RECORDING_PATH", tmpDir)
	defer os.Unsetenv("RECORDING_PATH")

	recorder := NewAsciicastRecorder(tmpDir)

	metadata := RecordingMetadata{
		SessionID: 1001,
		Protocol:  "ssh",
		Width:     80,
		Height:    24,
		StartTime: time.Now(),
	}

	if err := recorder.Start(metadata); err != nil {
		t.Fatalf("Start() 失敗: %v", err)
	}

	// 第一次 Stop
	if err := recorder.Stop(); err != nil {
		t.Fatalf("第一次 Stop() 失敗: %v", err)
	}

	// 第二次 Stop（應該不報錯）
	if err := recorder.Stop(); err != nil {
		t.Errorf("第二次 Stop() 不應報錯: %v", err)
	}
}

// TestAsciicastRecorder_FilePathStructure 測試檔案路徑結構
func TestAsciicastRecorder_FilePathStructure(t *testing.T) {
	tmpDir := t.TempDir()
	os.Setenv("RECORDING_PATH", tmpDir)
	defer os.Unsetenv("RECORDING_PATH")

	recorder := NewAsciicastRecorder(tmpDir)

	startTime := time.Date(2025, 10, 20, 15, 30, 0, 0, time.UTC)
	metadata := RecordingMetadata{
		SessionID: 42,
		Protocol:  "ssh",
		Width:     80,
		Height:    24,
		StartTime: startTime,
	}

	if err := recorder.Start(metadata); err != nil {
		t.Fatalf("Start() 失敗: %v", err)
	}
	defer recorder.Stop()

	filePath := recorder.GetFilePath()

	// 驗證路徑包含日期目錄
	expectedDateDir := "2025-10-20"
	if !strings.Contains(filePath, expectedDateDir) {
		t.Errorf("檔案路徑應包含日期目錄 %s, 實際: %s", expectedDateDir, filePath)
	}

	// 驗證檔案名稱
	fileName := filepath.Base(filePath)
	expectedFileName := "session-42.cast"
	if fileName != expectedFileName {
		t.Errorf("檔案名稱 = %s, 期望 %s", fileName, expectedFileName)
	}
}

// TestAsciicastRecorder_DefaultDimensions 測試默認終端尺寸
func TestAsciicastRecorder_DefaultDimensions(t *testing.T) {
	tmpDir := t.TempDir()
	os.Setenv("RECORDING_PATH", tmpDir)
	defer os.Unsetenv("RECORDING_PATH")

	recorder := NewAsciicastRecorder(tmpDir)

	metadata := RecordingMetadata{
		SessionID: 100,
		Protocol:  "ssh",
		// Width 和 Height 未設定
		StartTime: time.Now(),
	}

	if err := recorder.Start(metadata); err != nil {
		t.Fatalf("Start() 失敗: %v", err)
	}
	recorder.Stop()

	// 讀取 Header 驗證默認值
	file, err := os.Open(recorder.GetFilePath())
	if err != nil {
		t.Fatalf("打開檔案失敗: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		t.Fatal("無法讀取 Header")
	}

	var header AsciicastHeader
	if err := json.Unmarshal([]byte(scanner.Text()), &header); err != nil {
		t.Fatalf("解析 Header 失敗: %v", err)
	}

	// 驗證默認尺寸
	if header.Width != 80 {
		t.Errorf("默認 Width = %d, 期望 80", header.Width)
	}
	if header.Height != 24 {
		t.Errorf("默認 Height = %d, 期望 24", header.Height)
	}
}

// TestAsciicastRecorder_Flush 測試 Flush 功能
func TestAsciicastRecorder_Flush(t *testing.T) {
	tmpDir := t.TempDir()
	os.Setenv("RECORDING_PATH", tmpDir)
	defer os.Unsetenv("RECORDING_PATH")

	recorder := NewAsciicastRecorder(tmpDir)

	metadata := RecordingMetadata{
		SessionID: 200,
		Protocol:  "ssh",
		Width:     80,
		Height:    24,
		StartTime: time.Now(),
	}

	if err := recorder.Start(metadata); err != nil {
		t.Fatalf("Start() 失敗: %v", err)
	}
	defer recorder.Stop()

	// 寫入事件
	recorder.WriteOutput(100*time.Millisecond, []byte("test data"))

	// 手動 Flush
	if err := recorder.Flush(); err != nil {
		t.Fatalf("Flush() 失敗: %v", err)
	}

	// 驗證資料已寫入（檔案大小 > Header 大小）
	fileInfo, err := os.Stat(recorder.GetFilePath())
	if err != nil {
		t.Fatalf("Stat 失敗: %v", err)
	}

	// Header + Event 應該 > 50 bytes (調整期望值)
	if fileInfo.Size() < 50 {
		t.Errorf("檔案大小 = %d bytes, 期望 > 50", fileInfo.Size())
	}
}

// TestAsciicastRecorder_DirAndFilePermissions 錄影檔 0600、日期目錄 0700。
//
// 錄影是會話全文，可能含使用者在目標機上鍵入的密碼；容器內的其他身分
// （資料庫 CLI 的降權身分）連目錄都不得進入。此性質原本只寫在 spec 與註解裡、
// 無任何機械斷言。
//
// 特別涵蓋「日期目錄已存在且為 0755」的情境：os.MkdirAll 對既存目錄不套權限，
// 只靠它會讓升級當天的目錄一直停在 0755。
func TestAsciicastRecorder_DirAndFilePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("RECORDING_PATH", tmpDir)

	start := time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)
	// 先以 0755 建好日期目錄，模擬舊版留下的既存目錄
	dateDir := filepath.Join(tmpDir, start.Format("2006-01-02"))
	if err := os.MkdirAll(dateDir, 0755); err != nil {
		t.Fatalf("預建日期目錄失敗: %v", err)
	}
	if err := os.Chmod(dateDir, 0755); err != nil {
		t.Fatalf("預設日期目錄權限失敗: %v", err)
	}

	rec := NewAsciicastRecorder(tmpDir)
	if err := rec.Start(RecordingMetadata{
		SessionID: 4242, Protocol: "postgres", Width: 80, Height: 24, StartTime: start,
	}); err != nil {
		t.Fatalf("Start() 失敗: %v", err)
	}
	defer rec.Stop()

	dirInfo, err := os.Stat(dateDir)
	if err != nil {
		t.Fatalf("讀取日期目錄失敗: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0700 {
		t.Errorf("日期目錄權限 = %04o，期望 0700（既存目錄也必須被收斂）", perm)
	}

	fileInfo, err := os.Stat(rec.GetFilePath())
	if err != nil {
		t.Fatalf("讀取錄影檔失敗: %v", err)
	}
	if perm := fileInfo.Mode().Perm(); perm != 0600 {
		t.Errorf("錄影檔權限 = %04o，期望 0600", perm)
	}
}
