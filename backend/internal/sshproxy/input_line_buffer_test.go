package sshproxy

import "testing"

func feedAll(b *InputLineBuffer, s string) (string, bool, bool) {
	return b.Feed([]byte(s))
}

func TestInputLineBufferBasic(t *testing.T) {
	b := NewInputLineBuffer()
	line, submitted, trusted := feedAll(b, "rm -rf /\r")
	if !submitted || !trusted || line != "rm -rf /" {
		t.Errorf("got %q %v %v", line, submitted, trusted)
	}
}

func TestInputLineBufferBackspace(t *testing.T) {
	b := NewInputLineBuffer()
	b.Feed([]byte("rm -rgg"))
	b.Feed([]byte{0x7f, 0x7f})
	line, submitted, trusted := feedAll(b, "f /tmp\r")
	if !submitted || !trusted || line != "rm -rf /tmp" {
		t.Errorf("got %q %v %v", line, submitted, trusted)
	}
}

func TestInputLineBufferUTF8Backspace(t *testing.T) {
	b := NewInputLineBuffer()
	b.Feed([]byte("echo 測試"))
	b.Feed([]byte{0x7f}) // 退一個中文字
	line, _, _ := feedAll(b, "\r")
	if line != "echo 測" {
		t.Errorf("got %q", line)
	}
}

func TestInputLineBufferEscapeFailOpen(t *testing.T) {
	b := NewInputLineBuffer()
	b.Feed([]byte{0x1b, '[', 'A'}) // 上方向鍵（歷史指令）
	line, submitted, trusted := feedAll(b, "\r")
	if !submitted || trusted {
		t.Errorf("ESC must mark untrusted: %q %v %v", line, submitted, trusted)
	}
	// Enter 後重置回可信
	line, submitted, trusted = feedAll(b, "ls\r")
	if !trusted || line != "ls" {
		t.Errorf("after reset: %q %v %v", line, submitted, trusted)
	}
}

func TestInputLineBufferCtrlCClears(t *testing.T) {
	b := NewInputLineBuffer()
	b.Feed([]byte("rm -rf /"))
	b.Feed([]byte{0x03}) // Ctrl+C
	line, _, trusted := feedAll(b, "ls\r")
	if line != "ls" || !trusted {
		t.Errorf("got %q trusted=%v", line, trusted)
	}
}
