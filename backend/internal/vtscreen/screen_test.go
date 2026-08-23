package vtscreen

import (
	"strconv"
	"strings"
	"testing"
)

func equalLines(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

type screenCase struct {
	name  string
	input string
	want  []string
}

func runScreenCases(t *testing.T, cases []screenCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Lines([]byte(c.input))
			if !equalLines(got, c.want) {
				t.Fatalf("input=%q\n got=%q\nwant=%q", c.input, got, c.want)
			}
		})
	}
}

// TestScreenCSIMatrix 對每個有實作語義的 CSI 功能各驗「有參數／無參數／參數 0」三例。
// 參數 0 一律等同預設值，是 ECMA-48 的參數預設規則。
func TestScreenCSIMatrix(t *testing.T) {
	runScreenCases(t, []screenCase{
		// ICH（@）：於游標處插入空白，其後右移
		{"ICH-有參數", "abcdef\x1b[3D\x1b[3@", []string{"abc   def"}},
		{"ICH-無參數", "abcdef\x1b[3D\x1b[@", []string{"abc def"}},
		{"ICH-參數0", "abcdef\x1b[3D\x1b[0@", []string{"abc def"}},

		// CUU（A）：上移
		{"CUU-有參數", "l1\r\nl2\r\nl3\x1b[2Ax", []string{"l1x", "l2", "l3"}},
		{"CUU-無參數", "l1\r\nl2\r\nl3\x1b[Ax", []string{"l1", "l2x", "l3"}},
		{"CUU-參數0", "l1\r\nl2\r\nl3\x1b[0Ax", []string{"l1", "l2x", "l3"}},

		// CUD（B）：下移
		{"CUD-有參數", "l1\x1b[2Bx", []string{"l1", "", "  x"}},
		{"CUD-無參數", "l1\x1b[Bx", []string{"l1", "  x"}},
		{"CUD-參數0", "l1\x1b[0Bx", []string{"l1", "  x"}},

		// CUF（C）：右移
		{"CUF-有參數", "abcdef\x1b[3D\x1b[2CZ", []string{"abcdeZ"}},
		{"CUF-無參數", "abcdef\x1b[3D\x1b[CZ", []string{"abcdZf"}},
		{"CUF-參數0", "abcdef\x1b[3D\x1b[0CZ", []string{"abcdZf"}},

		// CUB（D）：左移
		{"CUB-有參數", "abcdef\x1b[2DZ", []string{"abcdZf"}},
		{"CUB-無參數", "abcdef\x1b[DZ", []string{"abcdeZ"}},
		{"CUB-參數0", "abcdef\x1b[0DZ", []string{"abcdeZ"}},

		// CNL（E）：下移並回到行首
		{"CNL-有參數", "l1\x1b[2Ex", []string{"l1", "", "x"}},
		{"CNL-無參數", "l1\x1b[Ex", []string{"l1", "x"}},
		{"CNL-參數0", "l1\x1b[0Ex", []string{"l1", "x"}},

		// CPL（F）：上移並回到行首
		{"CPL-有參數", "l1\r\nl2\r\nl3\x1b[2Fx", []string{"x1", "l2", "l3"}},
		{"CPL-無參數", "l1\r\nl2\r\nl3\x1b[Fx", []string{"l1", "x2", "l3"}},
		{"CPL-參數0", "l1\r\nl2\r\nl3\x1b[0Fx", []string{"l1", "x2", "l3"}},

		// CHA（G）：參數 1-based，游標 0-based——CSI 1G 必須落在第 0 欄
		{"CHA-有參數", "55> \x1b[1Gab", []string{"ab> "}},
		{"CHA-無參數", "abcdef\x1b[GX", []string{"Xbcdef"}},
		{"CHA-參數0", "abcdef\x1b[0GX", []string{"Xbcdef"}},

		// CUP（H）：列與欄皆 1-based
		{"CUP-有參數", "abcdefgh\x1b[10;20HX",
			[]string{"abcdefgh", "", "", "", "", "", "", "", "", "                   X"}},
		{"CUP-無參數", "abcdefgh\x1b[HX", []string{"Xbcdefgh"}},
		{"CUP-參數0", "abcdefgh\x1b[0;0HX", []string{"Xbcdefgh"}},

		// HVP（f）：等同 CUP
		{"HVP-有參數", "abcdefgh\x1b[2;5fX", []string{"abcdefgh", "    X"}},
		{"HVP-無參數", "abcdefgh\x1b[fX", []string{"Xbcdefgh"}},
		{"HVP-參數0", "abcdefgh\x1b[0;0fX", []string{"Xbcdefgh"}},

		// ED（J）：清畫面，列數與游標皆不動
		{"ED-有參數", "garbage\r\n\x1b[2J\x1b[Hprompt$ ls", []string{"prompt$ ls"}},
		{"ED-無參數", "l1\r\nl2\r\nl3\x1b[2;2H\x1b[J", []string{"l1", "l"}},
		{"ED-參數0", "l1\r\nl2\r\nl3\x1b[2;2H\x1b[0J", []string{"l1", "l"}},

		// EL（K）：清行，游標不動
		{"EL-有參數", "first line\r\nabcdef\x1b[2K\rxyz", []string{"first line", "xyz"}},
		{"EL-無參數", "abcdef\x1b[3D\x1b[K", []string{"abc"}},
		{"EL-參數0", "abcdef\x1b[3D\x1b[0K", []string{"abc"}},

		// DCH（P）：刪除字元、其後左移
		{"DCH-有參數", "abcdef\x1b[4D\x1b[2P", []string{"abef"}},
		{"DCH-無參數", "abcdef\x1b[4D\x1b[P", []string{"abdef"}},
		{"DCH-參數0", "abcdef\x1b[4D\x1b[0P", []string{"abdef"}},

		// ECH（X）：原地清成空白，不左移
		{"ECH-有參數", "abcdef\x1b[4D\x1b[2X", []string{"ab  ef"}},
		{"ECH-無參數", "abcdef\x1b[4D\x1b[X", []string{"ab def"}},
		{"ECH-參數0", "abcdef\x1b[4D\x1b[0X", []string{"ab def"}},

		// VPA（d）：列 1-based，欄不變
		{"VPA-有參數", "abcdefgh\x1b[3dX", []string{"abcdefgh", "", "        X"}},
		{"VPA-無參數", "abcdefgh\x1b[dX", []string{"abcdefghX"}},
		{"VPA-參數0", "abcdefgh\x1b[0dX", []string{"abcdefghX"}},

		// SGR（m）：吃掉不解讀，不得對任何屬性做特殊處理
		{"SGR-有參數", "\x1b[1;31mred\x1b[0m done", []string{"red done"}},
		{"SGR-無參數", "cmd \x1b[mtail", []string{"cmd tail"}},
		{"SGR-參數0", "\x1b[0;32mgreen\x1b[0m plain", []string{"green plain"}},

		// SM／RM（h／l）：吃掉不解讀
		{"SM-RM-有參數", "\x1b[4habc\x1b[4ldef", []string{"abcdef"}},
		{"SM-RM-無參數", "\x1b[habc\x1b[ldef", []string{"abcdef"}},
		{"SM-RM-參數0", "\x1b[0habc\x1b[0ldef", []string{"abcdef"}},
	})
}

// TestScreenEraseBranches 覆蓋 ED／EL 的其餘分支。
func TestScreenEraseBranches(t *testing.T) {
	runScreenCases(t, []screenCase{
		// EL Ps=1：自行首清至游標欄（含該欄），其右原樣保留
		{"EL-1-游標在行中", "abcdef\x1b[3D\x1b[1K", []string{"    ef"}},
		{"EL-1-游標在行尾之後", "abcdef\x1b[1K", nil},
		// ED Ps=1：上方內容清空，列數與游標皆不動
		{"ED-1", "l1\r\nl2\r\nl3\x1b[1Jtail", []string{"", "", "  tail"}},
		// ED Ps=3：本實作無捲動歷史，等同無事發生
		{"ED-3", "l1\r\nl2\x1b[3Jx", []string{"l1", "l2x"}},
	})

	// EL Ps=2 只清當前列：游標不動，其他列不受影響
	s := New()
	s.Write([]byte("first line\r\nabcdef\x1b[2K"))
	if got := s.CursorX(); got != 6 {
		t.Fatalf("CSI 2K 不得移動游標：CursorX=%d want=6", got)
	}
	if got := s.Lines(); !equalLines(got, []string{"first line"}) {
		t.Fatalf("CSI 2K 只該清當前列：got=%q", got)
	}
}

// TestScreenC0 覆蓋 CR／LF／BS／BEL／HT。
func TestScreenC0(t *testing.T) {
	runScreenCases(t, []screenCase{
		{"CR-回行首覆寫", "hello world\rbye", []string{"byelo world"}},
		{"BS-左移不抹除", "lss\x08x", []string{"lsx"}},
		{"BS-左移後清行尾", "lss\x08\x1b[K", []string{"ls"}},
		{"BEL-不進文字", "ls \x07", []string{"ls "}},
		// LF 只下移一列、欄位不變（ECMA-48／xterm 於 LNM 重置下的語義），
		// 寫入時再以空白補齊到游標欄
		{"LF-欄位不歸零", "abc\ndef", []string{"abc", "   def"}},
		{"CRLF-兩列", "line one\r\nline two", []string{"line one", "line two"}},
		// HT 推進到下一個 8 欄 tab stop；游標恰在 tab stop 上時推進到「下一個」
		{"HT-自第8欄推進到第16欄", "printf a\tb", []string{"printf a        b"}},
		{"HT-自第0欄推進到第8欄", "\tx", []string{"        x"}},
	})

	// HT 只移動游標，不覆寫既有內容
	got := Lines([]byte("abcdefghijklmnop\r\tX"))
	if !equalLines(got, []string{"abcdefghXjklmnop"}) {
		t.Fatalf("HT 不得覆寫既有內容：got=%q", got)
	}
}

// TestScreenCHAIsZeroBasedOrigin 是指令原點偽證缺陷的專項證明：
// CSI 1G 必須把游標設到第 0 欄。設成第 1 欄會使重繪前的第一個位元組存活，
// 讓審計得到一條使用者從未輸入過的指令。
func TestScreenCHAIsZeroBasedOrigin(t *testing.T) {
	got := Lines([]byte("55> \x1b[1Gab"))
	want := []string{"ab> "}
	if !equalLines(got, want) {
		t.Fatalf("CSI 1G 未落在第 0 欄：got=%q want=%q", got, want)
	}

	// 同型：提示符殘骸不再存活（sqlcmd 重繪形態）
	got = Lines([]byte("> \x1b[1G55> SELECT name\x1b[0K\x1b[16G"))
	want = []string{"55> SELECT name"}
	if !equalLines(got, want) {
		t.Fatalf("重繪殘骸仍存活：got=%q want=%q", got, want)
	}
}

// TestScreenRedrawOverwriteMatrix 掃描真實 readline 的主力重繪形態：
// CR ＋ CUF×N ＋ EL ＋ 新內容。N 對應提示符顯示寬度，錯一欄入庫的就是另一條指令。
func TestScreenRedrawOverwriteMatrix(t *testing.T) {
	const base = "0123456789abcdefghij" // 20 欄
	for n := 0; n <= 20; n++ {
		var b strings.Builder
		b.WriteString(base)
		b.WriteString("\r")
		if n > 0 { // CSI 0C 等同 CSI 1C，N=0 時不得送出 CUF
			b.WriteString("\x1b[")
			b.WriteString(strconv.Itoa(n))
			b.WriteString("C")
		}
		b.WriteString("\x1b[K")
		b.WriteString("XY")

		want := base[:n] + "XY"
		got := Lines([]byte(b.String()))
		if !equalLines(got, []string{want}) {
			t.Fatalf("N=%d：got=%q want=%q", n, got, []string{want})
		}
	}
}

// TestScreenWritePadsToCursor 斷言游標右移超出行尾時，寫入前以空白補齊。
func TestScreenWritePadsToCursor(t *testing.T) {
	got := Lines([]byte("abc\x1b[40GX"))
	want := []string{"abc" + strings.Repeat(" ", 36) + "X"}
	if !equalLines(got, want) {
		t.Fatalf("越界右移未補空白：got=%q want=%q", got, want)
	}
	if len(got[0]) != 40 {
		t.Fatalf("X 應落在第 39 欄（0-based）：長度=%d", len(got[0]))
	}
}

// TestScreenSeedRestoresOrigin 斷言 Seed 種入的原點使重繪落在正確欄位。
// 這是指令原點修正的核心：提示符不在回顯緩衝內，但欄位算術以含提示符的整行為原點。
func TestScreenSeedRestoresOrigin(t *testing.T) {
	const prompt = "ssh-test-server:~$ " // 19 欄，尾端空白是內容的一部分

	s := New()
	s.Seed(prompt, len(prompt))
	if got := s.CursorX(); got != 19 {
		t.Fatalf("Seed 後 CursorX=%d want=19", got)
	}
	if got := s.CurrentLine(); got != prompt {
		t.Fatalf("Seed 後 CurrentLine=%q want=%q", got, prompt)
	}

	// 使用者打了一段指令後按 Ctrl-U：readline 以 CR ＋ CUF19 ＋ EL 重繪整行
	s.Write([]byte("rm -rf /tmp/should-not-be-audited"))
	s.Write([]byte("\r\x1b[19C\x1b[K"))
	s.Write([]byte("echo safe"))

	want := prompt + "echo safe"
	if got := s.CurrentLine(); got != want {
		t.Fatalf("重繪後的螢幕不正確：got=%q want=%q", got, want)
	}
	if got := s.Lines(); !equalLines(got, []string{want}) {
		t.Fatalf("Lines=%q want=%q", got, []string{want})
	}
}

// TestScreenSeedResetsState 斷言 Seed 會重置螢幕，且不吃控制字元。
func TestScreenSeedResetsState(t *testing.T) {
	s := New()
	s.Write([]byte("garbage\r\nmore"))
	s.Seed("ab\x07c", 1)
	if got := s.CurrentLine(); got != "abc" {
		t.Fatalf("Seed 應略過控制字元並重置螢幕：got=%q", got)
	}
	if got := s.CursorX(); got != 1 {
		t.Fatalf("CursorX=%d want=1", got)
	}
	if got := s.Lines(); !equalLines(got, []string{"abc"}) {
		t.Fatalf("Seed 未重置既有列：got=%q", got)
	}
}

// TestScreenCurrentLineEmptyAfterNewline 斷言尾端為 CRLF 時，游標已在新的一列、原點為空。
// 這是 beginTyping 取原點時的關鍵形態。
func TestScreenCurrentLineEmptyAfterNewline(t *testing.T) {
	s := New()
	s.Write([]byte("testuser@host:~$ ls -la\r\n"))
	if got := s.CurrentLine(); got != "" {
		t.Fatalf("CRLF 之後的原點應為空：got=%q", got)
	}
	if got := s.CursorX(); got != 0 {
		t.Fatalf("CursorX=%d want=0", got)
	}
	if got := s.Lines(); !equalLines(got, []string{"testuser@host:~$ ls -la"}) {
		t.Fatalf("尾端空白列應被去除：got=%q", got)
	}
}

// TestScreenWideRunes 覆蓋雙寬字元的欄位算術與覆寫時的殘半處理。
func TestScreenWideRunes(t *testing.T) {
	runScreenCases(t, []screenCase{
		// 覆寫寬字元左半：右半在真實終端上成為空白格
		{"覆寫寬字元左半", "中文測試\rX", []string{"X 文測試"}},
		// 寬字元覆蓋兩個窄字元
		{"寬字元覆寫兩窄欄", "abcd\x1b[1G中", []string{"中cd"}},
		{"emoji", "echo 🎉 ok", []string{"echo 🎉 ok"}},
	})

	s := New()
	s.Write([]byte("中文"))
	if got := s.CursorX(); got != 4 {
		t.Fatalf("兩個雙寬字元後 CursorX=%d want=4", got)
	}

	// 零寬字元附著於左側主位，不佔顯示欄
	s = New()
	s.Write([]byte("écho"))
	if got := s.CursorX(); got != 4 {
		t.Fatalf("含組合附加符號時 CursorX=%d want=4", got)
	}
	if got := s.CurrentLine(); got != "écho" {
		t.Fatalf("組合附加符號不得消失：got=%q", got)
	}
}

// TestScreenNoWrapOnLongLine 斷言超寬指令不被折成多行。
func TestScreenNoWrapOnLongLine(t *testing.T) {
	long := "echo " + strings.Repeat("x", 300)
	got := Lines([]byte(long))
	if len(got) != 1 || got[0] != long {
		t.Fatalf("超寬指令被折行或截斷：行數=%d", len(got))
	}
}
