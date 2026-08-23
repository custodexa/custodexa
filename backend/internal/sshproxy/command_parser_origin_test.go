package sshproxy

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

// === 指令原點修正 ===
//
// 結算時解析的緩衝區不含提示符，但 shell／readline 的欄位算術以「含提示符的整行」為原點。
// 清行序列（`\r` ＋ CUF×N ＋ EL，N 等於提示符顯示寬度）因而從錯誤的欄位切開，
// 前半段殘留 ＋ 後半段新指令 ＝ 一條使用者從未打過的指令。
// 捏造比漏記更糟，這是稽核產品最嚴重的失效形態。

// captureLog 把標準 logger 導向 buf，回傳還原函式。
func captureLog(buf *bytes.Buffer) func() {
	flags := log.Flags()
	log.SetOutput(buf)
	return func() {
		log.SetOutput(os.Stderr)
		log.SetFlags(flags)
	}
}

// TestBeginTypingSnapshotsUntrimmedOrigin 釘死原點快照的兩個關鍵語義。
//
// 為什麼不能拿 promptText 當原點：它經過 TrimSpace。
// `ssh-test-server:~$ ` 是 19 欄，trim 後只剩 18 欄，種進去就又差一欄；
// 而 tail 尾端是換行時（游標已在新的一列、原點應為空），promptText 取到的是上一列的結果文字。
func TestBeginTypingSnapshotsUntrimmedOrigin(t *testing.T) {
	cases := []struct {
		name       string
		tail       string
		wantPrompt string
		wantOrigin string
		wantX      int
	}{
		{
			name:       "提示符尾端那一格空白是原點的一部分",
			tail:       "ssh-test-server:~$ ",
			wantPrompt: "ssh-test-server:~$",  // TrimSpace 後 18 欄
			wantOrigin: "ssh-test-server:~$ ", // 未 trim，19 欄
			wantX:      19,
		},
		{
			name:       "tail 尾端為換行時原點為空、游標欄為 0",
			tail:       "ssh-test-server:~$ ls -la\r\n",
			wantPrompt: "ssh-test-server:~$ ls -la", // promptText 取到的是上一列的文字
			wantOrigin: "",
			wantX:      0,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			parser, _ := newTestParser()
			parser.WriteOutput([]byte(c.tail))
			parser.WriteInput([]byte("x")) // 首鍵觸發 beginTyping

			if parser.promptText != c.wantPrompt {
				t.Errorf("promptText = %q, want %q", parser.promptText, c.wantPrompt)
			}
			if parser.originText != c.wantOrigin {
				t.Errorf("originText = %q, want %q（原點必須是未 trim 的原文）", parser.originText, c.wantOrigin)
			}
			if parser.originX != c.wantX {
				t.Errorf("originX = %d, want %d（TrimSpace 後的欄數不得用作原點）", parser.originX, c.wantX)
			}
		})
	}
}

// TestCommandParserCtrlUKillDoesNotFabricateCommand 是本 change 的核心回歸釘死：
// 使用者 Ctrl-U 清掉整行後改打別的指令，入庫的必須是新指令，
// 不得是「前半段殘留 ＋ 後半段新指令」拼出來的偽證。
//
// 序列取自 dev 靶機實錄（ssh-capture 的 ctrl-u-kill／psql-capture 的 psql-tab），
// 差別只在此處把「輸入起始前已在螢幕上的提示符」一併餵入——
// 產線上提示符必然在 tailBuf 內（shell 在每條指令前印提示符）。
func TestCommandParserCtrlUKillDoesNotFabricateCommand(t *testing.T) {
	cases := []struct {
		name      string
		protocol  string
		prompt    string
		typed     string
		retyped   string
		forbidden string
		want      string
	}{
		{
			name:      "ssh：rm -rf 被 Ctrl-U 清掉後改打 echo safe",
			protocol:  "ssh",
			prompt:    "ssh-test-server:~$ ", // 19 欄
			typed:     "rm -rf /tmp/should-not-be-audited",
			retyped:   "echo safe",
			forbidden: "rm -rf",
			want:      "echo safe",
		},
		{
			name:      "psql：SELECT * FROM sess 被 Ctrl-U 清掉後改打 SELECT 2;",
			protocol:  "postgres",
			prompt:    "custodexa=# ", // 12 欄
			typed:     "SELECT * FROM sess",
			retyped:   "SELECT 2;",
			forbidden: "FRO",
			want:      "SELECT 2;",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			parser, commands := newTestParserMode(c.protocol)
			parser.WriteOutput([]byte(c.prompt))

			parser.WriteInput([]byte(c.typed))
			parser.WriteOutput([]byte(c.typed)) // 逐字回顯

			// Ctrl-U 的回顯：回到行首、右移到提示符之後、清到行尾
			parser.WriteInput([]byte("\x15"))
			parser.WriteOutput([]byte("\r" + strings.Repeat("\x1b[C", len(c.prompt)) + "\x1b[K"))

			parser.WriteInput([]byte(c.retyped + "\r"))
			parser.WriteOutput([]byte(c.retyped + "\r\n"))
			parser.Flush()

			if len(*commands) != 1 || (*commands)[0] != c.want {
				t.Fatalf("commands = %#v, want [%q]", *commands, c.want)
			}
			for _, cmd := range *commands {
				if strings.Contains(cmd, c.forbidden) {
					t.Errorf("入庫了使用者已清除的片段 %q：%q", c.forbidden, cmd)
				}
			}
		})
	}
}

// TestCommandParserOriginPrefixIsVerifiedNotAssumed 釘死原點切除的前綴比對。
//
// 伺服器可能用 `\r` ＋ 新內容直接蓋掉提示符（進度條即此形態），
// 此時螢幕最後一行不再以原點起頭。若不比對前綴就盲目切掉開頭 N 個字元，
// 切掉的會是使用者的指令文字（原點比指令長時甚至是負索引切片）。
func TestCommandParserOriginPrefixIsVerifiedNotAssumed(t *testing.T) {
	parser, commands := newTestParser()
	parser.WriteOutput([]byte("prompt$ ")) // 原點 8 欄

	parser.WriteInput([]byte("x"))
	parser.WriteOutput([]byte("\rXY")) // 回行首後只蓋掉兩欄，其餘提示符字元存活
	parser.WriteInput([]byte("\r"))
	parser.WriteOutput([]byte("\r\n"))
	parser.Flush()

	want := "XYompt$" // 真實終端在那一刻的螢幕內容（尾端空白 trim 後）
	if len(*commands) != 1 || (*commands)[0] != want {
		t.Errorf("commands = %#v, want [%q]", *commands, want)
	}
}

// TestCommandParserScreenHasNoOrphanPromptRemnant 是移除 trimOrphanPromptRemnantPrefix 的
// 前置閘門與斷言搬家的去處。
//
// chunk 切在 sqlcmd 提示符數字**之後**時（快照 `55`、回顯 `> …`），舊虛擬螢幕對 `\x1b[1G`
// 從第 2 欄起覆寫，行首會殘留一個孤立的 `>`（螢幕 `>55> SELECT name`）。
// 自有解析器修好 CHA（`CSI 1G` 落在第 0 欄）之後，該形態在原理上不再產生。
func TestCommandParserScreenHasNoOrphanPromptRemnant(t *testing.T) {
	cases := []struct {
		name string
		tail string
		echo string
		want string
	}{
		{"兩位數提示符", "55", "> " + mssqlRedraw, "55> SELECT name"},
		{"單位數提示符", "5", "> " + mssqlRedrawSingleDigit, "5> SELECT name"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			parser, _ := newTestParserMSSQL()
			parser.WriteOutput([]byte(c.tail))
			parser.WriteInput([]byte("\x1b[A")) // 上鍵：觸發重繪

			screen := parser.renderScreen(parser.originText, parser.originX, []byte(c.echo))
			got := lastNonEmptyRawLine(screen.lines)
			t.Logf("tail=%q origin=%q originX=%d → 螢幕最後一行=%q",
				c.tail, parser.originText, parser.originX, got)

			if got != c.want {
				t.Errorf("螢幕最後一行 = %q, want %q", got, c.want)
			}
			if strings.HasPrefix(got, ">") {
				t.Errorf("孤立的 `>` 殘骸又出現了：%q——該移除裁決須作廢", got)
			}
		})
	}
}

// TestTrimSqlcmdPromptPrefixOrphanRemnantCases 承接 TestTrimOrphanPromptRemnantPrefix
// 14 例矩陣中的 10 例誤剝反面（該測試隨函式移除，見 command_parser_mssql_prompt_test.go 的對照表）。
//
// 這些輸入一律不得被剝除：行首孤立的 `>` 是使用者打的引用符號或比較運算，
// 不是提示符殘骸——殘骸形態自 CHA 修好後已不再產生。
func TestTrimSqlcmdPromptPrefixOrphanRemnantCases(t *testing.T) {
	cases := []string{
		"> SELECT 1",
		">>",
		"> 5 > 6",
		"> 55> SELECT 1",
		">x> SELECT 1",
		">55",
		">",
		"SELECT 1 WHERE 5 > 3",
		"",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			got, ok := trimSqlcmdPromptPrefix(in)
			if ok || got != in {
				t.Errorf("trimSqlcmdPromptPrefix(%q) = (%q, %v), want (%q, false)", in, got, ok, in)
			}
		})
	}

	// 第 10 例 `55> SELECT 1`：它是正常提示符形態，單獨剝除確實命中，
	// 但端到端不得剝（快照本身即提示符時閘門關閉）——由
	// TestCommandParserMSSQLDoesNotStripUserTypedPromptLikeText 覆蓋，此處只釘死判準本身。
	if got, ok := trimSqlcmdPromptPrefix("55> SELECT 1"); !ok || got != "SELECT 1" {
		t.Errorf(`trimSqlcmdPromptPrefix("55> SELECT 1") = (%q, %v), want ("SELECT 1", true)`, got, ok)
	}
}

// TestCommandParserDegradeLogsOnceWithoutCommandBytes 驗證解析 panic 的降級可觀測性：
// 每個實例最多一行，且日誌不含任何指令位元組。
func TestCommandParserDegradeLogsOnceWithoutCommandBytes(t *testing.T) {
	// 指令文字可能是使用者在終端打錯位置的密碼，一個位元組都不得進日誌
	const secret = "mysql -u root -pSuperSecret123"

	var buf bytes.Buffer
	defer captureLog(&buf)()

	parser, commands := newTestParser()
	parser.render = func(string, int, []byte) screenRender {
		panic("測試注入：虛擬螢幕解析失敗")
	}

	parser.WriteOutput([]byte("$ "))
	typeCommand(parser, secret)      // 第一次降級
	parser.WriteOutput([]byte("$ ")) // 第二次降級
	typeCommand(parser, secret)

	if len(*commands) != 2 {
		t.Fatalf("降級後仍須結算出指令：commands = %#v", *commands)
	}
	for _, cmd := range *commands {
		if strings.ContainsRune(cmd, 0x1B) {
			t.Errorf("降級輸出含原始 ESC 位元組：%q", cmd)
		}
	}

	logged := buf.String()
	if n := strings.Count(logged, "\n"); n != 1 {
		t.Errorf("降級日誌行數 = %d, want 1\n%s", n, logged)
	}
	if !strings.Contains(logged, "降級") {
		t.Errorf("降級日誌缺少可辨識的原因：%q", logged)
	}
	assertLogHasNoCommandBytes(t, logged, secret)
}

// TestCommandParserDropLogsOnceWithoutCommandBytes 驗證「虛擬螢幕觸及記憶體上限而丟棄內容」
// 的可觀測性。上限本身保留，但不得靜默。
func TestCommandParserDropLogsOnceWithoutCommandBytes(t *testing.T) {
	const secret = "psql -h db -U admin -W Hunter2Hunter2"
	// 超限定位：CHA 到最大欄後再右移，寫入時必然越過 maxCols
	const overflow = "\x1b[65535G\x1b[10CX"

	var buf bytes.Buffer
	defer captureLog(&buf)()

	parser, commands := newTestParser()
	parser.WriteOutput([]byte("$ "))
	typeCommand(parser, secret+overflow)        // 第一次丟棄
	parser.WriteOutput([]byte("$ " + overflow)) // 第二次丟棄（beginTyping 路徑）
	typeCommand(parser, secret+overflow)

	if len(*commands) == 0 {
		t.Fatal("丟棄不得吞掉整條指令")
	}

	logged := buf.String()
	if n := strings.Count(logged, "\n"); n != 1 {
		t.Errorf("丟棄日誌行數 = %d, want 1\n%s", n, logged)
	}
	if !strings.Contains(logged, "上限") {
		t.Errorf("丟棄日誌缺少可辨識的原因：%q", logged)
	}
	assertLogHasNoCommandBytes(t, logged, secret)
}

// assertLogHasNoCommandBytes 斷言日誌不含指令文字：整串比對之外，
// 連指令的任一「長度 8 以上的片段」都不得出現——只驗整串等於沒驗。
func assertLogHasNoCommandBytes(t *testing.T, logged, command string) {
	t.Helper()
	if strings.Contains(logged, command) {
		t.Fatalf("日誌含指令文字：%q", logged)
	}
	const window = 8
	for i := 0; i+window <= len(command); i++ {
		if frag := command[i : i+window]; strings.Contains(logged, frag) {
			t.Errorf("日誌含指令片段 %q：%q", frag, logged)
		}
	}
}
