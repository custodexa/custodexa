package sshproxy

import "testing"

// feedAll 餵入一段輸入，回傳最後一個已提交的行（無提交則回零值）
func feedAll(b *InputLineBuffer, s string) (string, bool, bool) {
	lines := b.Feed([]byte(s))
	if len(lines) == 0 {
		return "", false, false
	}
	last := lines[len(lines)-1]
	return last.Text, true, last.Trusted
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

// 一個輸入幀內的所有已提交行依序回傳，殘段留在緩衝供下一幀接續
func TestInputLineBufferFeedReturnsEveryLine(t *testing.T) {
	b := NewInputLineBuffer()
	lines := b.Feed([]byte("one\ntwo\r\nthree"))
	if len(lines) != 3 || lines[0].Text != "one" || lines[1].Text != "two" || lines[2].Text != "" {
		t.Fatalf("lines = %+v", lines)
	}
	for _, l := range lines {
		if !l.Trusted {
			t.Errorf("行 %q 應可信", l.Text)
		}
	}
	rest := b.Feed([]byte("-tail\n"))
	if len(rest) != 1 || rest[0].Text != "three-tail" || !rest[0].Trusted {
		t.Fatalf("殘段接續失敗: %+v", rest)
	}
}

// 括號貼上標記透明，不使行失準（含標記被拆在兩幀之間）
func TestInputLineBufferBracketedPasteTransparent(t *testing.T) {
	b := NewInputLineBuffer()
	lines := b.Feed([]byte("\x1b[200~cat a\nls\n\x1b[201~"))
	if len(lines) != 2 || lines[0].Text != "cat a" || lines[1].Text != "ls" {
		t.Fatalf("lines = %+v", lines)
	}
	for _, l := range lines {
		if !l.Trusted {
			t.Errorf("括號貼上的行 %q 不應失準", l.Text)
		}
	}
	b.Feed([]byte("\x1b[2"))
	b.Feed([]byte("00~"))
	got := b.Feed([]byte("pwd\n"))
	if len(got) != 1 || got[0].Text != "pwd" || !got[0].Trusted {
		t.Fatalf("拆幀標記後的行: %+v", got)
	}
}

// 其他跳脫序列與未追蹤的控制字元使所在行失準，且只影響該行
func TestInputLineBufferUntrackedControlUnsynced(t *testing.T) {
	cases := map[string]string{
		"arrow":       "ls\x1b[D\n",
		"ctrl_a":      "ls\x01\n",
		"ctrl_w":      "ls -l\x17\n",
		"tab":         "ls\t\n",
		"escape_pair": "ls\x1b\n",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			b := NewInputLineBuffer()
			lines := b.Feed([]byte(in + "pwd\n"))
			if len(lines) != 2 {
				t.Fatalf("lines = %+v", lines)
			}
			if lines[0].Trusted {
				t.Errorf("行 %q 應失準", lines[0].Text)
			}
			if !lines[1].Trusted || lines[1].Text != "pwd" {
				t.Errorf("下一行應恢復可信: %+v", lines[1])
			}
		})
	}
}

// Reset 清掉殘段、失準狀態與辨識中的跳脫前綴
func TestInputLineBufferResetClearsEverything(t *testing.T) {
	b := NewInputLineBuffer()
	b.Feed([]byte("abc\x01\x1b[2"))
	b.Reset()
	lines := b.Feed([]byte("pwd\n"))
	if len(lines) != 1 || lines[0].Text != "pwd" || !lines[0].Trusted {
		t.Fatalf("Reset 後應乾淨: %+v", lines)
	}
}
