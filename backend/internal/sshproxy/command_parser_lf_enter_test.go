package sshproxy

import (
	"fmt"
	"testing"
)

// Enter 判定同源化的釘子：`\r` 與 `\n` 都是 Enter，且所有以 Enter 為界的判定走同一個函式。
// 只認其中一種時，另一種送出的指令在對端執行、錄影留存，指令審計卻無任何紀錄與降級訊號。

func TestIndexEnter(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"uptime\r", 6},
		{"uptime\n", 6},
		{"uptime\r\n", 6},
		{"a\nb\r", 1},
		{"a\rb\n", 1},
		{"no enter", -1},
		{"", -1},
	}
	for _, c := range cases {
		if got := indexEnter([]byte(c.in)); got != c.want {
			t.Errorf("indexEnter(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestCountEnters(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"a\r", 1},
		{"a\n", 1},
		{"a\r\n", 2},
		{"a\rb\nc\r", 3},
		{"abc", 0},
	}
	for _, c := range cases {
		if got := countEnters([]byte(c.in)); got != c.want {
			t.Errorf("countEnters(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// typeCommandWith 同 typeCommand，但 Enter 位元組由呼叫端指定（`\r`／`\n`／`\r\n` 對照用）。
func typeCommandWith(p *CommandParser, typedEcho, enter string) {
	p.WriteInput([]byte("x"))
	p.WriteOutput([]byte(typedEcho))
	p.WriteInput([]byte(enter))
	p.WriteOutput([]byte("\r\n"))
}

// TestCommandParserLFEnterMatchesCR 三種 Enter 位元組的結算結果必須相同。
func TestCommandParserLFEnterMatchesCR(t *testing.T) {
	for _, enter := range []string{"\r", "\n", "\r\n"} {
		t.Run(fmt.Sprintf("%q", enter), func(t *testing.T) {
			parser, commands, records := newRecordingParser("ssh")
			parser.WriteOutput([]byte("testuser@host:~$ "))
			typeCommandWith(parser, "uptime", enter)
			parser.WriteOutput([]byte("testuser@host:~$ "))
			parser.Flush()
			if len(*commands) != 1 || (*commands)[0] != "uptime" {
				t.Errorf("enter=%q: commands = %v, want [\"uptime\"]（恰一筆）", enter, *commands)
			}
			if len(*records) != 0 {
				t.Errorf("enter=%q: 多出降級／限定列 %+v：CRLF 的第二個 Enter 是空輪，不得產生任何紀錄", enter, *records)
			}
		})
	}
}

// TestCommandParserLFEnterSameFrameMulti 同幀多條以 `\n` 分隔的指令各自記錄，
// 與既有 `\r` 分隔的同幀多指令路徑（重放佇列）行為一致。
func TestCommandParserLFEnterSameFrameMulti(t *testing.T) {
	for _, enter := range []string{"\r", "\n"} {
		t.Run(fmt.Sprintf("%q", enter), func(t *testing.T) {
			parser, commands := newTestParser()
			parser.WriteOutput([]byte("$ "))
			parser.WriteInput([]byte("echo a" + enter + "echo b" + enter))
			parser.WriteOutput([]byte("echo a\r\na\r\n$ "))
			parser.WriteOutput([]byte("echo b\r\nb\r\n$ "))
			parser.Flush()
			want := []string{"echo a", "echo b"}
			if len(*commands) != 2 || (*commands)[0] != want[0] || (*commands)[1] != want[1] {
				t.Errorf("enter=%q: commands = %v, want %v", enter, *commands, want)
			}
		})
	}
}

// TestCommandParserLFEnterDuringPendingQueued pending 期間抵達的 `\n` 結尾輸入排入佇列，
// 前一輪結算後重放並正確記錄（既有 `\r` 路徑的對照）。
func TestCommandParserLFEnterDuringPendingQueued(t *testing.T) {
	for _, enter := range []string{"\r", "\n"} {
		t.Run(fmt.Sprintf("%q", enter), func(t *testing.T) {
			parser, commands := newTestParser()
			parser.WriteOutput([]byte("$ "))
			parser.WriteInput([]byte("x"))
			parser.WriteOutput([]byte("uptime"))
			parser.WriteInput([]byte(enter))
			// 回顯尚未返回即送下一條
			parser.WriteInput([]byte("id" + enter))
			parser.WriteOutput([]byte("\r\n 12:00 up\r\n$ "))
			parser.WriteOutput([]byte("id\r\nuid=1\r\n$ "))
			parser.Flush()
			want := []string{"uptime", "id"}
			if len(*commands) != 2 || (*commands)[0] != want[0] || (*commands)[1] != want[1] {
				t.Errorf("enter=%q: commands = %v, want %v", enter, *commands, want)
			}
		})
	}
}
