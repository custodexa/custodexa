package vtscreen

import (
	"strings"
	"testing"
)

// implementedFinals 是 screen.csiDispatch 有實作語義的 final byte。
// 其餘 0x40-0x7E 一律走 catch-all：完整消耗、不留殘骸。
var implementedFinals = map[byte]bool{
	'@': true, 'A': true, 'B': true, 'C': true, 'D': true, 'E': true,
	'F': true, 'G': true, 'H': true, 'J': true, 'K': true, 'P': true,
	'X': true, 'd': true, 'f': true, 'm': true, 'h': true, 'l': true,
}

// assertNoResidue 斷言還原結果不含任何控制位元組，也不含 CSI 引導字元的殘骸。
func assertNoResidue(t *testing.T, label string, lines []string) {
	t.Helper()
	for _, line := range lines {
		for _, r := range line {
			if r < 0x20 || r == 0x7F {
				t.Fatalf("%s：輸出含控制位元組 %#U，行=%q", label, r, line)
			}
		}
		if strings.ContainsRune(line, '[') {
			t.Fatalf("%s：輸出含 CSI 殘骸 '['，行=%q", label, line)
		}
	}
}

// TestParserCatchAllFinalBytes 對 0x40-0x7E 全部 final byte 各跑一次，
// 斷言序列被完整消耗、輸出零 ESC/CSI 殘骸。
func TestParserCatchAllFinalBytes(t *testing.T) {
	for _, params := range []string{"", "1", "1;2", "0"} {
		for b := byte(0x40); b <= 0x7E; b++ {
			input := "A\x1b[" + params + string(b) + "B"
			lines := Lines([]byte(input))
			label := "final=" + string(b) + " params=" + params
			assertNoResidue(t, label, lines)
			if !implementedFinals[b] {
				got := strings.Join(lines, "\n")
				if got != "AB" {
					t.Fatalf("%s：未實作語義的 final byte 應被完整吃掉，got=%q want=%q", label, got, "AB")
				}
			}
		}
	}
}

// TestParserTruncatedSequenceKeepsState 斷言輸入結束在序列中途時，
// 狀態保留於狀態機內、不 panic、不吐出殘留位元組（design.md D5 B5）。
func TestParserTruncatedSequenceKeepsState(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"csi-引導後即結束", "ls -la\x1b[", "ls -la"},
		{"csi-參數中途結束", "ls\x1b[12;", "ls"},
		{"esc-後即結束", "ls -la\x1b", "ls -la"},
		{"osc-未終止", "ls\x1b]0;titl", "ls"},
		{"csi-中間位元組後結束", "ls\x1b[!", "ls"},
		{"esc-中間位元組後結束", "ls\x1b(", "ls"},
		{"dcs-未終止", "ls\x1bPq;;", "ls"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lines := Lines([]byte(c.input))
			assertNoResidue(t, c.name, lines)
			if got := strings.Join(lines, "\n"); got != c.want {
				t.Fatalf("got=%q want=%q", got, c.want)
			}
		})
	}
}

// TestParserTruncatedSequenceResumesOnNextWrite 斷言被切開的序列於下次 Write 續接。
func TestParserTruncatedSequenceResumesOnNextWrite(t *testing.T) {
	s := New()
	s.Write([]byte("55> \x1b["))
	s.Write([]byte("1G"))
	s.Write([]byte("ab"))
	if got := strings.Join(s.Lines(), "\n"); got != "ab> " {
		t.Fatalf("跨 Write 續接的序列未生效：got=%q want=%q", got, "ab> ")
	}
}

// TestParserChunkSplitInvariance 斷言逐位元組餵入與整段餵入結果一致。
func TestParserChunkSplitInvariance(t *testing.T) {
	inputs := []string{
		"\x1b]0;user@host: ~\x07prompt$ ls",
		"abcdef\x1b[4D\x1b[2X",
		"中文測試\rX",
		"l1\r\nl2\r\nl3\x1b[1Jtail",
		"\x1b[1G55> SELECT name\x1b[0K\x1b[16G",
	}
	for _, in := range inputs {
		whole := strings.Join(Lines([]byte(in)), "\n")
		s := New()
		for i := 0; i < len(in); i++ {
			s.Write([]byte{in[i]})
		}
		if got := strings.Join(s.Lines(), "\n"); got != whole {
			t.Fatalf("分塊餵入結果不同：input=%q byte-wise=%q whole=%q", in, got, whole)
		}
	}
}

// TestParserOSCTerminators 斷言 OSC 同時接受 BEL 與 7-bit ST（design.md D5 B6）。
func TestParserOSCTerminators(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"bel-終止", "\x1b]0;user@host: ~\x07prompt$ ls"},
		{"st-終止", "\x1b]0;title\x1b\\prompt$ ls"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lines := Lines([]byte(c.input))
			assertNoResidue(t, c.name, lines)
			if got := strings.Join(lines, "\n"); got != "prompt$ ls" {
				t.Fatalf("視窗標題流進文字：got=%q", got)
			}
		})
	}
}

// TestParserStringControlsSwallowed 斷言 DCS／SOS／PM／APC 的內容不流進文字。
func TestParserStringControlsSwallowed(t *testing.T) {
	for _, intro := range []string{"P", "X", "^", "_"} {
		input := "a\x1b" + intro + "secret-payload\x1b\\b"
		lines := Lines([]byte(input))
		assertNoResidue(t, "string-"+intro, lines)
		got := strings.Join(lines, "\n")
		if got != "ab" {
			t.Fatalf("ESC %s 的字串內容未被吃掉：got=%q", intro, got)
		}
	}
}

// TestParserC0InsideSequence 斷言序列途中的 C0 控制字元即時生效（ECMA-48）。
func TestParserC0InsideSequence(t *testing.T) {
	// CSI 之後先來 CR：游標歸零後序列以 "1G" 續完，最終仍定位到第 0 欄
	if got := strings.Join(Lines([]byte("abc\x1b[\r1Gx")), "\n"); got != "xbc" {
		t.Fatalf("序列途中的 CR 未即時生效：got=%q want=%q", got, "xbc")
	}
}

// TestParserCANSUBAbortSequence 斷言 CAN／SUB 中止進行中的序列。
func TestParserCANSUBAbortSequence(t *testing.T) {
	for _, abort := range []string{"\x18", "\x1a"} {
		got := strings.Join(Lines([]byte("ab\x1b[1"+abort+"Gc")), "\n")
		if got != "abGc" {
			t.Fatalf("中止字元 %q 未中止序列：got=%q want=%q", abort, got, "abGc")
		}
	}
}

// TestParserPrivateAndIntermediateIgnored 斷言帶私有前綴或中間位元組的序列整段忽略。
func TestParserPrivateAndIntermediateIgnored(t *testing.T) {
	cases := []struct{ name, input, want string }{
		{"私有前綴-EL", "abc\x1b[?0K", "abc"},
		{"私有前綴-模式設定", "\x1b[?1049hvim\x1b[?1049l$ ", "vim$ "},
		{"中間位元組-DECSTR", "abc\x1b[!p", "abc"},
		{"中間位元組-游標形狀", "abc\x1b[ q", "abc"},
		{"子參數-SGR", "\x1b[38:2::255:0:0mred", "red"},
		{"參數位元組溢位", "abc\x1b[" + strings.Repeat("1;", 60) + "K", "abc"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lines := Lines([]byte(c.input))
			assertNoResidue(t, c.name, lines)
			if got := strings.Join(lines, "\n"); got != c.want {
				t.Fatalf("got=%q want=%q", got, c.want)
			}
		})
	}
}

// TestParserEscNonCSISequencesConsumed 斷言字集指示與 ESC 7/8、D/E/M、c 被正確消耗。
func TestParserEscNonCSISequencesConsumed(t *testing.T) {
	cases := []struct{ name, input, want string }{
		{"字集指示-G0", "\x1b(Bplain", "plain"},
		{"字集指示-G1", "\x1b)0plain", "plain"},
		{"儲存與回復游標", "a\x1b7b\x1b8c", "abc"},
		{"index", "a\x1bDb", "ab"},
		{"reverse-index", "a\x1bMb", "ab"},
		{"next-line", "a\x1bEb", "ab"},
		{"重置", "a\x1bcb", "ab"},
		{"孤立-ST", "a\x1b\\b", "ab"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lines := Lines([]byte(c.input))
			assertNoResidue(t, c.name, lines)
			if got := strings.Join(lines, "\n"); got != c.want {
				t.Fatalf("got=%q want=%q", got, c.want)
			}
		})
	}
}

// TestParserUTF8AcrossWrites 斷言被分塊切開的多位元組字元不吐殘骸、下次寫入時續接。
func TestParserUTF8AcrossWrites(t *testing.T) {
	s := New()
	s.Write([]byte{0xE4, 0xB8}) // "中" 的前兩個位元組
	if got := s.Lines(); len(got) != 0 {
		t.Fatalf("未收齊的多位元組字元不應輸出：got=%q", got)
	}
	s.Write([]byte{0xAD})
	if got := strings.Join(s.Lines(), "\n"); got != "中" {
		t.Fatalf("續接後應還原為「中」：got=%q", got)
	}
}

// TestParserInvalidUTF8NotPanics 斷言非法 UTF-8 位元組不 panic 也不流出控制位元組。
func TestParserInvalidUTF8NotPanics(t *testing.T) {
	inputs := [][]byte{
		{'a', 0x80, 'b'},
		{'a', 0xC3},
		{'a', 0xC3, 'b'},
		{0xFF, 0xFE, 0xFD},
		{'a', 0xE4, 0xB8, 0xE4, 0xB8, 0xAD},
	}
	for _, in := range inputs {
		assertNoResidue(t, "invalid-utf8", Lines(in))
	}
}
