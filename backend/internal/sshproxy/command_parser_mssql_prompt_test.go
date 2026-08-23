package sshproxy

import (
	"strings"
	"testing"
)

// === 提示符污染===
//
// sqlcmd 的提示符逐行遞增（1>／2>／…／55>），且實測「Enter 回顯的換行」與「下一行提示符」
// 是兩次獨立的 write。使用者按上鍵召回歷史時，重繪會重印提示符；若按鍵落在那兩次 write 之間，
// beginTyping 取到的 promptText 就是空字串或半截提示符，提示符因而留在審計文字裡。
// 產品資料庫實查命中：`SELECT name\n55> SELECT name\n…`（session 521）。
// 危害：稽核查「有沒有人下過某危險語句」做的是子字串比對，污染使比對與去重雙雙失準。

// mssqlRedraw 是 dev 靶機實測捕獲的上鍵重繪序列（\x1b[1G + 提示符 + 指令 + 清除到行尾 + 定位）
const mssqlRedraw = "\x1b[1G55> SELECT name\x1b[0K\x1b[16G"

// mssqlRedrawSingleDigit 為單位數提示符（`5>`）的同型重繪序列
const mssqlRedrawSingleDigit = "\x1b[1G5> SELECT name\x1b[0K\x1b[15G"

func TestCommandParserMSSQLPromptNotLeakedOnRedraw(t *testing.T) {
	cases := []struct {
		name string
		// tail 為按鍵抵達前已進入閒置緩衝的輸出（決定 promptText 快照）
		tail string
		// echo 為輸入狀態下收到的回顯（提示符是否落進此處視 chunk 切法而定）
		echo string
	}{
		// 形態 C：換行先到、提示符尚未到，使用者按上鍵 → 快照為空
		{"快照為空、提示符未落入回顯", "", mssqlRedraw},
		// 形態 A：快照為空，提示符與重繪雙雙落進回顯（實走重現即此形態）
		{"快照為空、提示符落入回顯", "", "55> " + mssqlRedraw},
		// 半截提示符：chunk 切在提示符中間
		{"快照到半截提示符", "5", "5> " + mssqlRedraw},
		// 上一批次的結果文字殿後、提示符尚未到
		{"快照到結果文字", "(5 rows affected)\r\n", mssqlRedraw},
		// chunk 切在提示符數字**之後**：快照吃掉數字段，重繪重疊後行首只剩孤立的 `>`
		// （螢幕為 `>55> SELECT name`）——既有前綴剝除與數字掃描雙雙不啟動的形態
		{"快照切在數字之後（兩位數）", "55", "> " + mssqlRedraw},
		{"快照切在數字之後（單位數）", "5", "> " + mssqlRedrawSingleDigit},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			parser, commands := newTestParserMSSQL()
			parser.WriteOutput([]byte(c.tail))

			parser.WriteInput([]byte("\x1b[A")) // 上鍵
			parser.WriteOutput([]byte(c.echo))
			parser.WriteInput([]byte("\r"))
			parser.WriteOutput([]byte("\r\n"))
			parser.Flush()

			if len(*commands) != 1 {
				t.Fatalf("commands = %#v, want 1 筆", *commands)
			}
			got := (*commands)[0]
			if strings.Contains(got, ">") {
				t.Errorf("入庫文字仍含提示符殘留: %q", got)
			}
			if got != "SELECT name" {
				t.Errorf("入庫文字 = %q, want %q", got, "SELECT name")
			}
		})
	}
}

// 誤剝反面：提示符正常抵達時（快照本身即提示符形態），使用者輸入的
// `<數字>> ` 起頭內容必須原樣入庫。行內出現的同型字串本就不在射程內。
func TestCommandParserMSSQLDoesNotStripUserTypedPromptLikeText(t *testing.T) {
	cases := []struct {
		name   string
		prompt string
		typed  string
		want   string
	}{
		{"使用者輸入以提示符樣式起頭", "12> ", "55> SELECT 1;", "55> SELECT 1;"},
		{"行內的提示符樣式", "12> ", "SELECT '55> x';", "SELECT '55> x';"},
		{"大於號比較運算不受影響", "12> ", "SELECT 1 WHERE 5 > 3;", "SELECT 1 WHERE 5 > 3;"},
		// 剝完會變空的行：寧可原樣入庫也不吞掉一筆審計記錄
		{"整行只有提示符樣式時不吞記錄", "", "55>", "55>"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			parser, commands := newTestParserMSSQL()
			parser.WriteOutput([]byte(c.prompt))
			typeCommand(parser, c.typed)
			parser.Flush()

			if len(*commands) != 1 || (*commands)[0] != c.want {
				t.Errorf("commands = %#v, want [%q]", *commands, c.want)
			}
		})
	}
}

// 孤立 `>` 形態的誤剝防線：**快照非提示符形態（剝除閘門開啟）**時，行首的 `>`
// 只有在其後緊跟另一個 `<數字>>` 提示符時才算殘骸。使用者自打的引用符號、比較運算
// 後面接的是內容而非提示符，必須原樣入庫。
func TestCommandParserMSSQLDoesNotStripLoneGreaterThan(t *testing.T) {
	cases := []struct {
		name  string
		typed string
		want  string
	}{
		{"引用符號起頭", "> SELECT 1;", "> SELECT 1;"},
		{"連續兩個大於號", ">>", ">>"},
		{"大於號後為比較運算", "> 5 > 6", "> 5 > 6"},
		{"大於號與提示符間有空白（非殘骸）", "> 55> SELECT 1;", "> 55> SELECT 1;"},
		{"大於號後接非數字", ">x> SELECT 1;", ">x> SELECT 1;"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			parser, commands := newTestParserMSSQL()
			// 不餵 tail → 快照為空（非提示符形態）＝剝除閘門開啟，正面壓測誤剝
			typeCommand(parser, c.typed)
			parser.Flush()

			if len(*commands) != 1 || (*commands)[0] != c.want {
				t.Errorf("commands = %#v, want [%q]", *commands, c.want)
			}
		})
	}
}

// 只剝一層：競態下洩漏的提示符與「使用者自己打的提示符樣式文字」會相鄰出現，
// 迴圈剝除會把使用者實際輸入的內容也吃掉——審計文字必須忠於使用者送出的內容。
func TestCommandParserMSSQLStripsOnlyOnePromptLayer(t *testing.T) {
	parser, commands := newTestParserMSSQL()
	// tailBuf 空（換行先到、提示符未到）→ 快照為空；洩漏的 `12> ` 後面是使用者自打的 `55> `
	parser.WriteInput([]byte("x"))
	parser.WriteOutput([]byte("12> 55> SELECT 1;"))
	parser.WriteInput([]byte("\r"))
	parser.WriteOutput([]byte("\r\n"))
	parser.Flush()

	want := "55> SELECT 1;"
	if len(*commands) != 1 || (*commands)[0] != want {
		t.Errorf("commands = %#v, want [%q]", *commands, want)
	}
}

// **零回歸釘死**：提示符剝除補強只對 mssql 生效。既有三協議（與 ssh／redis／k8s）
// 餵入同型的「提示符落入打字緩衝」位元組序列時，結算文字必須與補強前完全相同——
// 也就是提示符**照舊留著**。此測試若在拿掉 tsqlMode 閘門後仍通過，即為假綠。
func TestCommandParserPromptStripIsMSSQLOnly(t *testing.T) {
	// 期望值即「補強前」的行為：快照為空 → 提示符原樣留在文字裡
	cases := []struct {
		protocol string
		want     string
	}{
		{"ssh", "55> SELECT name"},
		{"mysql", "55> SELECT name"},
		{"postgres", "55> SELECT name"},
		{"redis", "55> SELECT name"},
		{"k8s", "55> SELECT name"},
	}
	for _, c := range cases {
		t.Run(c.protocol, func(t *testing.T) {
			parser, commands := newTestParserMode(c.protocol)
			// tailBuf 空 → 快照為空，重繪帶進提示符
			parser.WriteInput([]byte("\x1b[A"))
			parser.WriteOutput([]byte(mssqlRedraw))
			parser.WriteInput([]byte("\r"))
			parser.WriteOutput([]byte("\r\n"))
			parser.Flush()

			if len(*commands) != 1 || (*commands)[0] != c.want {
				t.Errorf("%s: commands = %#v, want [%q]（補強前行為）", c.protocol, *commands, c.want)
			}
		})
	}

	// 孤立 `>` 殘骸形態同樣只對 mssql 生效
	//
	// 期望值由 `>55> SELECT name` 改為 `> SELECT name`：
	// 成因是自有解析器修好了 CHA（`CSI 1G` 自第 0 欄覆寫），重繪前已寫出的
	// 半截提示符不再有位元組存活，螢幕成為 `55> SELECT name` 而非 `>55> SELECT name`；
	// 非 mssql 協議走前綴剝除規則切除種入的原點 `55` 後即為 `> SELECT name`。
	// **守衛目的不變**：驗的仍是「提示符剝除只對 mssql 生效」——
	// 拿掉 tsqlMode 閘門後 mssql 的剝除會對這些協議生效、得到 `SELECT name`，此測試照樣轉紅。
	for _, c := range cases {
		t.Run(c.protocol+"/孤立大於號殘骸", func(t *testing.T) {
			parser, commands := newTestParserMode(c.protocol)
			parser.WriteOutput([]byte("55")) // 快照切在提示符數字之後
			parser.WriteInput([]byte("\x1b[A"))
			parser.WriteOutput([]byte("> " + mssqlRedraw))
			parser.WriteInput([]byte("\r"))
			parser.WriteOutput([]byte("\r\n"))
			parser.Flush()

			want := "> SELECT name"
			if len(*commands) != 1 || (*commands)[0] != want {
				t.Errorf("%s: commands = %#v, want [%q]（提示符剝除未對非 mssql 生效）", c.protocol, *commands, want)
			}
		})
	}
}

// 剝除輔助函式的邊界矩陣
func TestTrimSqlcmdPromptPrefix(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"55> SELECT 1", "SELECT 1", true},
		{"555> SELECT 1", "SELECT 1", true},
		{"1>SELECT 1", "SELECT 1", true},
		{"  7> SELECT 1", "SELECT 1", true},
		{"SELECT 1", "SELECT 1", false},
		{"GO", "GO", false},
		{"GO 3", "GO 3", false},
		{"5 > 3", "5 > 3", false},
		{"> SELECT 1", "> SELECT 1", false},
		{"55", "55", false},
		{"", "", false},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, ok := trimSqlcmdPromptPrefix(c.in)
			if got != c.want || ok != c.wantOK {
				t.Errorf("trimSqlcmdPromptPrefix(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.wantOK)
			}
		})
	}
}

// TestTrimOrphanPromptRemnantPrefix（14 例矩陣）隨 trimOrphanPromptRemnantPrefix
// 一併移除：該函式處理的
// 「行首孤立 `>` ＋ 緊跟完整提示符」形態是 CHA 缺陷的產物，
// 自有解析器修好 `CSI 1G` 之後在原理上不再出現，留著就是不可達的防線。
//
// **斷言搬家、不是刪除**（原 14 例的新去處）：
//   - 4 例正面命中（`>55> SELECT name`／`>5> x`／`>555>SELECT 1`／`  >55> SELECT name`）
//     轉為「殘骸不再產生」的證明：vtscreen 的 TestScreenCHAIsZeroBasedOrigin
//     （`CSI 1G` 自第 0 欄覆寫，含 sqlcmd 重繪形態）＋ 本檔的
//     TestCommandParserScreenHasNoOrphanPromptRemnant（chunk 切在提示符數字之後的端到端）。
//   - 10 例誤剝反面（`> SELECT 1`／`>>`／`> 5 > 6`／`> 55> SELECT 1`／`>x> SELECT 1`／
//     `>55`／`>`／`55> SELECT 1`／`SELECT 1 WHERE 5 > 3`／空字串）逐例搬到
//     command_parser_origin_test.go 的 TestTrimSqlcmdPromptPrefixOrphanRemnantCases，
//     其中 5 例另有 TestCommandParserMSSQLDoesNotStripLoneGreaterThan 的端到端覆蓋。
//
// 逐例對照表見該檔的註解，未刪除任何一條斷言的意圖。
