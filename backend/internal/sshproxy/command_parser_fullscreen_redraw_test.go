package sshproxy

// 全螢幕重繪輪不得吞掉其後的真實指令（charter backlog #13）。
//
// 語料為**實錄**：session-222（`vim --cmd 'set t_ti= t_te='`，即真 vim 但完全不送
// alternate-screen 標記）的 asciicast `"o"` 事件與該會話的 WS 送出紀錄依時間戳交錯。
// 一個 asciicast `"o"` 事件 == 一次 `bridge.go:391` 的 `sink.WriteOutput(res.data)`，
// 故這裡的 out 邊界就是解析器當時真正看到的幀邊界，不是人工湊的。
//
// **這支測試守的是修法自己引入的漏記**：D 方向讓解析路徑遇全螢幕重繪不再捏造，
// 代價是 vim 那一輪之後送出的 `echo done-VIMNOALT` 與 `exit` 一併被丟掉
// （原型狀態實測：只入庫 2 筆）。捏造與漏記都是 DoD，不得以其一換其一。
//
// 兩個方向的斷言都要有：
//   (a) vim 內打進檔案的文字、狀態列、檔案訊息列一筆都不得入庫（防捏造回歸）；
//   (b) vim 離開之後送出的真實指令必須入庫（防本項漏記）。

import (
	"strings"
	"testing"
	"time"
)

type fullScreenOp struct {
	dir  string // "in" 使用者按鍵／"out" 伺服器回顯
	data string
}

// vimNoAltScreenOps 為 session-222 的實錄事件序。
var vimNoAltScreenOps = []fullScreenOp{
	{dir: "out", data: "Welcome to OpenSSH Server\r\n\u001b[?2004hssh-test-server:~$ "},
	{dir: "in", data: "echo sync-42\r"},
	{dir: "out", data: "echo sync-42\r\n\u001b[?2004l\r"},
	{dir: "out", data: "sync-42\r\n\u001b[?2004hssh-test-server:~$ "},
	{dir: "in", data: "vim --cmd 'set t_ti= t_te=' /tmp/proto_D9.txt\r"},
	{dir: "out", data: "vim --cmd 'set t_ti= t_te=' /tmp/proto_D9.txt\r\n\u001b[?2004l\r"},
	{dir: "out", data: "\u001b[?1006;1000h\u001b[?1002h\u001b[>4;2m\u001b[?1h\u001b=\u001b[?2004h\u001b[?1004h\u001b[1;30r\u001b[?12h\u001b[?12l\u001b[22;2t\u001b[22;1t"},
	{dir: "out", data: "\u001b[27m\u001b[23m\u001b[29m\u001b[m\u001b[H\u001b[2J\u001b[?25l\u001b[30;1H\"/tmp/proto_D9.txt\" [New]"},
	{dir: "out", data: "\u001b[2;1H\u25bd\u001b[6n\u001b[2;1H  \u001b[3;1H\u001bPzz\u001b\\\u001b[0%m\u001b[6n\u001b[3;1H           \u001b[1;1H"},
	{dir: "out", data: "\u001b[>c\u001b]10;?\u0007\u001b]11;?\u0007"},
	{dir: "out", data: "\u001b[2;1H\u001b[94m~                                                                                                                       \u001b[3;1H~                                                                                                                       \u001b[4;1H~                                                                                                                       \u001b[5;1H~                                                                                                                       \u001b[6;1H~                                                                                                                       \u001b[7;1H~                                                                                                                       \u001b[8;1H~                                                                                                                       \u001b[9;1H~                                                                                                                       \u001b[10;1H~                                                                                                                       \u001b[11;1H~                                                                                                                       \u001b[12;1H~                                                                                                                       \u001b[13;1H~                                                                                                                       \u001b[14;1H~                                                                                                                       \u001b[15;1H~                                                                                                                       \u001b[16;1H~                                                                                                                       \u001b[17;1H~                                                                                                                       \u001b[18;1H~                                                                                                                       \u001b[19;1H~                                                                                                                       \u001b[20;1H~                                                                                                                       \u001b[21;1H~                                                                                                                       \u001b[22;1H~                                                                                                                       \u001b[23;1H~                                                                                                                       \u001b[24;1H~                                                                                                                       \u001b[25;1H~                                                                                                                       \u001b[26;1H~                                                                                                                       \u001b[27;1H~                                                                                                                       \u001b[28;1H~                                                                                                                       \u001b[29;1H~                                                                                                                       \u001b[m\u001b[30;103H0,0-1\u001b[9CAll\u001b[?25h\u001b[1;1H\u001b[?4m"},
	{dir: "in", data: "i"},
	{dir: "out", data: "\u001b[?25l\u001b[30;93Hi\u001b[1;1H\u001b[30;93H \u001b[1;1H\u001b[30;1H\u001b[1m-- INSERT --\u001b[m\u001b[30;13H\u001b[K\u001b[30;103H0,1\u001b[11CAll\u001b[1;1H\u001b[?25h"},
	{dir: "in", data: "LINE_A_D9\r"},
	{dir: "out", data: "\u001b[?25lLINE_A_D9\u001b[2;1H\u001b[K\u001b[?25h\u001b[?25l\u001b[30;103H2\u001b[2;1H\u001b[?25h"},
	{dir: "in", data: "LINE_B_D9\r"},
	{dir: "out", data: "\u001b[?25lLINE_B_D9\u001b[3;1H\u001b[K\u001b[?25h\u001b[?25l\u001b[30;103H3\u001b[3;1H\u001b[?25h"},
	{dir: "in", data: "LINE_C_D9\r"},
	{dir: "out", data: "\u001b[?25lLINE_C_D9\u001b[4;1H\u001b[K\u001b[?25h\u001b[?25l\u001b[30;103H4\u001b[4;1H\u001b[?25h"},
	{dir: "in", data: "LINE_D_D9\r"},
	{dir: "out", data: "\u001b[?25lLINE_D_D9\u001b[5;1H\u001b[K\u001b[?25h\u001b[?25l\u001b[30;103H5\u001b[5;1H\u001b[?25h"},
	{dir: "in", data: "LINE_E_D9\r"},
	{dir: "out", data: "\u001b[?25lLINE_E_D9\u001b[6;1H\u001b[K\u001b[?25h\u001b[?25l\u001b[30;103H6\u001b[6;1H\u001b[?25h"},
	{dir: "in", data: "\u001b"},
	{dir: "out", data: "\u001b[30;1H\u001b[K\u001b[6;1H\u001b[?25l\u001b[30;93H^[\u001b[6;1H"},
	{dir: "out", data: "\u001b[30;93H  \u001b[6;1H"},
	{dir: "out", data: "\u001b[30;103H6,0-1\u001b[9CAll\u001b[6;1H\u001b[?25h"},
	{dir: "in", data: ":wq\r"},
	{dir: "out", data: "\u001b[?25l\u001b[30;103H\u001b[K\u001b[30;1H:wq\r\u001b[?1006;1000l\u001b[?1002l\u001b[?2004l\u001b[>4;m"},
	{dir: "out", data: "\"/tmp/proto_D9.txt\""},
	{dir: "out", data: " [New] 6L, 51B written"},
	{dir: "out", data: "\r\u001b[23;2t\u001b[23;1t\u001b[?1004l\u001b[?2004l\u001b[?1l\u001b>\u001b[?25h\u001b[>4;m\r\r\n"},
	{dir: "out", data: "\u001b[?2004hssh-test-server:~$ "},
	{dir: "in", data: "echo done-VIMNOALT\r"},
	{dir: "out", data: "echo done-VIMNOALT\r\n\u001b[?2004l\r"},
	{dir: "out", data: "done-VIMNOALT\r\n"},
	{dir: "out", data: "\u001b[?2004hssh-test-server:~$ "},
	{dir: "in", data: "exit\r"},
	{dir: "out", data: "exit\r\n\u001b[?2004l\rlogout\r\n"},
}

func replayFullScreenOps(ops []fullScreenOp) []string {
	var got []string
	p := NewCommandParser(func(cmd string, _ time.Time) {
		got = append(got, cmd)
	}, "ssh")
	for _, op := range ops {
		if op.dir == "in" {
			p.WriteInput([]byte(op.data))
			continue
		}
		p.WriteOutput([]byte(op.data))
	}
	p.Flush()
	return got
}

func TestCommandParserFullScreenRoundDoesNotSwallowLaterCommands(t *testing.T) {
	got := replayFullScreenOps(vimNoAltScreenOps)

	// (a) 防捏造：vim 內的按鍵與螢幕殘留一律不得成為指令。
	//     `LINE_x_D9` 是打進檔案內容的文字（使用者確實按了，但從未當成指令執行）；
	//     `-- INSERT --` 與 `[New]` 是 vim 的狀態列／檔案訊息列。
	forbidden := []string{"LINE_A_D9", "LINE_B_D9", "LINE_C_D9", "LINE_D_D9", "LINE_E_D9",
		"-- INSERT --", "[New]", "proto_D9.txt\" ", "wq"}
	for _, cmd := range got {
		for _, bad := range forbidden {
			if strings.Contains(cmd, bad) {
				t.Errorf("入庫了使用者從未執行的字串（捏造）：%q 命中 %q\n全部結算：%q", cmd, bad, got)
			}
		}
	}

	// (b) 防漏記：離開 vim 之後送出的兩條指令必須各自入庫。
	//     它們是在全螢幕程式結束、shell 提示符回來之後才送出的，
	//     與 vim 的按鍵完全不同一件事。
	for _, want := range []string{"echo done-VIMNOALT", "exit"} {
		if !containsExact(got, want) {
			t.Errorf("離開全螢幕程式後送出的指令漏記：%q 不在結算結果中\n全部結算：%q", want, got)
		}
	}

	// 會話最前面兩條（進 vim 之前）本來就該在，順帶釘住重放保真度。
	for _, want := range []string{"echo sync-42", "vim --cmd 'set t_ti= t_te=' /tmp/proto_D9.txt"} {
		if !containsExact(got, want) {
			t.Errorf("進入全螢幕程式之前的指令漏記：%q\n全部結算：%q", want, got)
		}
	}
}

func containsExact(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
