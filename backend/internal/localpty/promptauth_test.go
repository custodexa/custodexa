//go:build linux

package localpty

import (
	"bytes"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/creack/pty"
)

// 這組測試以真 PTY 對打：slave 端模擬 CLI 輸出、master 端跑提示注入器，
// 並直接操作行紀律旗標重現「client 正在讀密碼」與「client 在 readline」兩種狀態。

const testPrompt = "Password for user u: "

func newInjector(t *testing.T, cfg PasswordAuth) (*promptAuth, *os.File) {
	t.Helper()
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatalf("開 PTY 失敗: %v", err)
	}
	t.Cleanup(func() { master.Close(); slave.Close() })
	c := &Conn{ptmx: master}
	a := newPromptAuth(cfg, master, c.Write)
	return a, slave
}

// setLineState 直接設定 PTY 的 ICANON/ECHO（模擬 client 讀密碼 vs readline 互動）
func setLineState(t *testing.T, f *os.File, canonical, echo bool) {
	t.Helper()
	rc, err := f.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	if err := rc.Control(func(fd uintptr) {
		var tio syscall.Termios
		if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd,
			uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&tio))); e != 0 {
			t.Fatalf("TCGETS: %v", e)
		}
		if canonical {
			tio.Lflag |= syscall.ICANON
		} else {
			tio.Lflag &^= syscall.ICANON
		}
		if echo {
			tio.Lflag |= syscall.ECHO
		} else {
			tio.Lflag &^= syscall.ECHO
		}
		if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd,
			uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&tio))); e != 0 {
			t.Fatalf("TCSETS: %v", e)
		}
	}); err != nil {
		t.Fatalf("Control: %v", err)
	}
}

// collector 常駐消費注入器的過濾後輸出（單一 reader，避免多個 Read 互搶資料）
type collector struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func startCollector(a *promptAuth) *collector {
	c := &collector{}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := a.Read(buf)
			if n > 0 {
				c.mu.Lock()
				c.buf.Write(buf[:n])
				c.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	return c
}

func (c *collector) snapshot() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// waitFor 輪詢等待輸出出現 want；逾時即失敗
func (c *collector) waitFor(t *testing.T, want string, d time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if s := c.snapshot(); strings.Contains(s, want) {
			return s
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("逾時未等到 %q，實際輸出 = %q", want, c.snapshot())
	return ""
}

// quiet 確認一段時間內輸出流保持空白（提示未外流）
func (c *collector) quiet(t *testing.T, d time.Duration) {
	t.Helper()
	time.Sleep(d)
	if s := c.snapshot(); s != "" {
		t.Fatalf("輸出流不應有內容，實際 = %q", s)
	}
}

func readRaw(t *testing.T, f *os.File, d time.Duration) []byte {
	t.Helper()
	_ = f.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	_ = f.SetReadDeadline(time.Time{})
	return buf[:n]
}

// TestPromptAuthInjectsAndHidesPrompt 主線：提示不外流、密碼注入到 client、
// 注入後的回顯（到第一個換行為止）也不外流
func TestPromptAuthInjectsAndHidesPrompt(t *testing.T) {
	a, slave := newInjector(t, PasswordAuth{
		Password: "pw-sentinel", Prompt: testPrompt, RequireCanonical: true,
	})
	setLineState(t, slave, true, false) // client 正在讀密碼
	col := startCollector(a)

	if _, err := slave.Write([]byte(testPrompt)); err != nil {
		t.Fatal(err)
	}
	// client 端應收到密碼＋換行
	if got := string(readRaw(t, slave, time.Second)); got != "pw-sentinel\n" {
		t.Fatalf("client 收到的輸入 = %q", got)
	}
	// 提示被吃掉 → 呼叫端拿不到任何位元組
	col.quiet(t, 200*time.Millisecond)

	// 注入後 client 的換行被吞、後續輸出正常通過
	if _, err := slave.Write([]byte("\r\npsql (16.14)\r\n")); err != nil {
		t.Fatal(err)
	}
	got := col.waitFor(t, "psql (16.14)", time.Second)
	if strings.Contains(got, "pw-sentinel") {
		t.Fatal("密碼出現在輸出流")
	}
	if strings.Contains(got, "Password for user") {
		t.Fatalf("提示外流到輸出流: %q", got)
	}
}

// TestPromptAuthSplitPrompt 提示跨兩次 read 被切斷時仍須完整辨識，
// 且前半段不得先漏到錄影
func TestPromptAuthSplitPrompt(t *testing.T) {
	a, slave := newInjector(t, PasswordAuth{
		Password: "pw", Prompt: testPrompt, RequireCanonical: true,
	})
	setLineState(t, slave, true, false)
	col := startCollector(a)

	if _, err := slave.Write([]byte("Password for ")); err != nil {
		t.Fatal(err)
	}
	col.quiet(t, 200*time.Millisecond) // 前半段被扣住，不得先漏進錄影
	if _, err := slave.Write([]byte("user u: ")); err != nil {
		t.Fatal(err)
	}
	if got := string(readRaw(t, slave, time.Second)); got != "pw\n" {
		t.Fatalf("切斷的提示未被辨識，client 輸入 = %q", got)
	}
}

// TestPromptAuthOnlyAtEndOfChunk 提示字串出現在輸出中段（不是 client 在等輸入）
// 時不得注入——否則使用者可用查詢結果誘出密碼
func TestPromptAuthOnlyAtEndOfChunk(t *testing.T) {
	a, slave := newInjector(t, PasswordAuth{
		Password: "pw", Prompt: testPrompt, RequireCanonical: true,
	})
	setLineState(t, slave, true, false)
	col := startCollector(a)

	payload := testPrompt + "trailing"
	if _, err := slave.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if got := col.waitFor(t, payload, time.Second); got != payload {
		t.Fatalf("中段提示不應被吃掉: %q", got)
	}
	if b := readRaw(t, slave, 300*time.Millisecond); len(b) != 0 {
		t.Fatalf("不該注入卻注入了: %q", b)
	}
}

// TestPromptAuthRequiresPasswordLineState readline 互動態（ICANON 關）下即使輸出
// 剛好以提示字串結尾也不得注入
func TestPromptAuthRequiresPasswordLineState(t *testing.T) {
	a, slave := newInjector(t, PasswordAuth{
		Password: "pw", Prompt: testPrompt, RequireCanonical: true,
	})
	setLineState(t, slave, false, false) // readline 互動中
	col := startCollector(a)

	if _, err := slave.Write([]byte(testPrompt)); err != nil {
		t.Fatal(err)
	}
	if got := col.waitFor(t, testPrompt, time.Second); got != testPrompt {
		t.Fatalf("非密碼態的文字應原樣通過: %q", got)
	}
	if b := readRaw(t, slave, 300*time.Millisecond); len(b) != 0 {
		t.Fatalf("非密碼態卻注入了: %q", b)
	}
}

// TestPromptAuthInjectsOnlyOnce 一次性注入：實測同 user/host/port 的 psql
// \connect 會重用快取密碼而不再提示，故第一次之後的同名提示必然是換了目標
// （例如 `\c db u otherhost`），此時把密碼送出去就是外洩
func TestPromptAuthInjectsOnlyOnce(t *testing.T) {
	a, slave := newInjector(t, PasswordAuth{
		Password: "pw", Prompt: testPrompt, RequireCanonical: true,
	})
	setLineState(t, slave, true, false)
	col := startCollector(a)

	if _, err := slave.Write([]byte(testPrompt)); err != nil {
		t.Fatal(err)
	}
	if got := string(readRaw(t, slave, time.Second)); got != "pw\n" {
		t.Fatalf("第一次注入失敗: %q", got)
	}
	// 結束吞噬期
	if _, err := slave.Write([]byte("\r\nready\r\n")); err != nil {
		t.Fatal(err)
	}
	col.waitFor(t, "ready", time.Second)

	// 第二次提示：不得注入，且提示原樣呈現給使用者（他們才知道 client 在等什麼）
	if _, err := slave.Write([]byte(testPrompt)); err != nil {
		t.Fatal(err)
	}
	col.waitFor(t, testPrompt, time.Second)
	if b := readRaw(t, slave, 300*time.Millisecond); len(b) != 0 {
		t.Fatalf("第二次提示不得注入，卻寫出了 %q", b)
	}
}

// TestPromptAuthNoAuthIsPassthrough 未設提示注入時 Read 全透明（k8s exec 等共用路徑）
func TestPromptAuthNoAuthIsPassthrough(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()
	c := &Conn{ptmx: master}
	if _, err := slave.Write([]byte(testPrompt)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	_ = master.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := c.Read(buf)
	if string(buf[:n]) != testPrompt {
		t.Fatalf("無注入設定時應原樣通過: %q", buf[:n])
	}
}

// TestPromptPrefixLen 尾端部分命中的長度計算（跨 read 切斷的辨識基礎）
func TestPromptPrefixLen(t *testing.T) {
	p := []byte("Password: ")
	cases := []struct {
		data string
		want int
	}{
		{"xxPassword", 8},
		{"xxPass", 4},
		{"xx", 0},
		{"Password: ", 0}, // 完整命中由 HasSuffix 處理，不算前綴
		{"P", 1},
	}
	for _, c := range cases {
		if got := promptPrefixLen([]byte(c.data), p); got != c.want {
			t.Errorf("promptPrefixLen(%q) = %d, want %d", c.data, got, c.want)
		}
	}
}
