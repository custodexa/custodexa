package sshproxy

import (
	"testing"
	"time"
)

// newTestParser 建立測試用解析器與收集結算指令的 slice（逐行模式，非 SQL）
func newTestParser() (*CommandParser, *[]string) {
	return newTestParserMode("ssh")
}

// newTestParserSQL 建立 DB CLI 多行語句累積模式的測試解析器（postgres 為代表）
func newTestParserSQL() (*CommandParser, *[]string) {
	return newTestParserMode("postgres")
}

// newTestParserMSSQL 建立 mssql 模式（SQL 累積 ＋ GO 批次終止符）的測試解析器
func newTestParserMSSQL() (*CommandParser, *[]string) {
	return newTestParserMode("mssql")
}

func newTestParserMode(protocol string) (*CommandParser, *[]string) {
	commands := &[]string{}
	parser := NewCommandParser(func(cmd string, _ time.Time) {
		*commands = append(*commands, cmd)
	}, protocol)
	return parser, commands
}

// typeCommand 模擬一條指令的完整互動：逐字輸入 + echo、Enter、回顯換行
func typeCommand(p *CommandParser, typedEcho string) {
	p.WriteInput([]byte("x"))        // 任意首鍵觸發輸入狀態（內容取自 echo，輸入值不影響）
	p.WriteOutput([]byte(typedEcho)) // shell 回顯
	p.WriteInput([]byte("\r"))       // Enter
	p.WriteOutput([]byte("\r\n"))    // Enter 的回顯換行 → 觸發結算
}

func TestCommandParserSimpleCommand(t *testing.T) {
	// Arrange
	parser, commands := newTestParser()
	parser.WriteOutput([]byte("testuser@host:~$ ")) // prompt 進 tailBuf

	// Act
	typeCommand(parser, "ls -la")

	// Assert
	if len(*commands) != 1 || (*commands)[0] != "ls -la" {
		t.Errorf("commands = %v, want [\"ls -la\"]", *commands)
	}
}

func TestCommandParserBackspaceCorrection(t *testing.T) {
	// Arrange
	parser, commands := newTestParser()
	parser.WriteOutput([]byte("$ "))

	// Act：輸入 lss 後退格一次（echo 為 退格+清尾），最終螢幕為 "ls"
	typeCommand(parser, "lss\b\x1b[K")

	// Assert
	if len(*commands) != 1 || (*commands)[0] != "ls" {
		t.Errorf("commands = %v, want [\"ls\"]", *commands)
	}
}

func TestCommandParserTabCompletion(t *testing.T) {
	// Arrange
	parser, commands := newTestParser()
	parser.WriteOutput([]byte("$ "))

	// Act：輸入部分路徑後 Tab，shell 回顯補全的尾段
	typeCommand(parser, "cat /etc/hos"+"ts")

	// Assert
	if len(*commands) != 1 || (*commands)[0] != "cat /etc/hosts" {
		t.Errorf("commands = %v, want [\"cat /etc/hosts\"]", *commands)
	}
}

func TestCommandParserHistoryRecall(t *testing.T) {
	// Arrange
	parser, commands := newTestParser()
	parser.WriteOutput([]byte("testuser@host:~$ "))

	// Act：上鍵叫出歷史，shell 整行重繪（\r + 清行 + prompt + 指令）
	parser.WriteInput([]byte("\x1b[A"))
	parser.WriteOutput([]byte("\r\x1b[K" + "testuser@host:~$ ls -la"))
	parser.WriteInput([]byte("\r"))
	parser.WriteOutput([]byte("\r\n"))

	// Assert：prompt 前綴被剝除
	if len(*commands) != 1 || (*commands)[0] != "ls -la" {
		t.Errorf("commands = %v, want [\"ls -la\"]", *commands)
	}
}

func TestCommandParserAltScreenSuppressed(t *testing.T) {
	// Arrange
	parser, commands := newTestParser()
	parser.WriteOutput([]byte("$ "))

	// Act：開 vim 進入 alternate screen，期間連按 Enter 不得記錄
	typeCommand(parser, "vim notes.txt")
	parser.WriteOutput([]byte("\x1b[?1049h vim screen content"))
	parser.WriteInput([]byte("ihello\r"))
	parser.WriteOutput([]byte("hello\r\n"))
	parser.WriteInput([]byte("\r"))
	parser.WriteOutput([]byte("\r\n"))

	// 離開 vim 後恢復解析
	parser.WriteOutput([]byte("\x1b[?1049l"))
	parser.WriteOutput([]byte("$ "))
	typeCommand(parser, "pwd")

	// Assert：只有 vim 啟動指令與離開後的 pwd
	want := []string{"vim notes.txt", "pwd"}
	if len(*commands) != len(want) {
		t.Fatalf("commands = %v, want %v", *commands, want)
	}
	for i := range want {
		if (*commands)[i] != want[i] {
			t.Errorf("commands[%d] = %q, want %q", i, (*commands)[i], want[i])
		}
	}
}

func TestCommandParserEchoRace(t *testing.T) {
	// Arrange：Enter 比 echo 先到（輸入快於回顯的競態）
	parser, commands := newTestParser()
	parser.WriteOutput([]byte("$ "))

	// Act：輸入與 Enter 連發，echo 之後才到
	parser.WriteInput([]byte("whoami\r"))
	parser.WriteOutput([]byte("whoami\r\n"))

	// Assert
	if len(*commands) != 1 || (*commands)[0] != "whoami" {
		t.Errorf("commands = %v, want [\"whoami\"]", *commands)
	}
}

func TestCommandParserEmptyEnterIgnored(t *testing.T) {
	// Arrange
	parser, commands := newTestParser()
	parser.WriteOutput([]byte("$ "))

	// Act：直接按 Enter（無指令內容）
	parser.WriteInput([]byte("\r"))
	parser.WriteOutput([]byte("\r\n"))

	// Assert
	if len(*commands) != 0 {
		t.Errorf("commands = %v, want 空", *commands)
	}
}

func TestCommandParserConsecutiveCommands(t *testing.T) {
	// Arrange
	parser, commands := newTestParser()
	parser.WriteOutput([]byte("$ "))

	// Act：連續兩條指令，中間夾指令輸出與新 prompt
	typeCommand(parser, "echo one")
	parser.WriteOutput([]byte("one\r\n$ "))
	typeCommand(parser, "echo two")

	// Assert
	want := []string{"echo one", "echo two"}
	if len(*commands) != 2 || (*commands)[0] != want[0] || (*commands)[1] != want[1] {
		t.Errorf("commands = %v, want %v", *commands, want)
	}
}

func TestCommandParserSQLMultiLineAccumulated(t *testing.T) {
	// Arrange：DB CLI 模式，一條 SQL 跨三次 Enter（續行 prompt）
	parser, commands := newTestParserSQL()
	parser.WriteOutput([]byte("custodexa=# ")) // 主 prompt

	// Act
	typeCommand(parser, "SELECT") // 未見 ; → 累積
	parser.WriteOutput([]byte("custodexa-# "))
	typeCommand(parser, "1 AS") // 累積
	parser.WriteOutput([]byte("custodexa-# "))
	typeCommand(parser, "x;") // 見 ; → 結算為單一語句

	// Assert：合併為一條，含完整語句
	if len(*commands) != 1 || (*commands)[0] != "SELECT\n1 AS\nx;" {
		t.Errorf("commands = %#v, want [\"SELECT\\n1 AS\\nx;\"]", *commands)
	}
}

func TestCommandParserSQLSplitKeywordNotEvaded(t *testing.T) {
	// Arrange：把 DROP 與 TABLE 拆兩行送（規避企圖）
	parser, commands := newTestParserSQL()
	parser.WriteOutput([]byte("testdb> "))

	// Act
	typeCommand(parser, "DROP")
	parser.WriteOutput([]byte("    -> "))
	typeCommand(parser, "TABLE users;")

	// Assert：合併後單一指令含相鄰可被告警正則命中的完整關鍵字
	if len(*commands) != 1 || (*commands)[0] != "DROP\nTABLE users;" {
		t.Fatalf("commands = %#v, want [\"DROP\\nTABLE users;\"]", *commands)
	}
	// \s 吃換行：drop\s+table 對合併字串應命中（與告警器同款語意）
	if !sqlStatementComplete("TABLE users;") {
		t.Error("尾端 ; 應判為語句結束")
	}
}

func TestCommandParserSQLBackslashMetaCommand(t *testing.T) {
	// Arrange：psql 元命令 \dt 單行即完成（不以 ; 結尾）
	parser, commands := newTestParserSQL()
	parser.WriteOutput([]byte("custodexa=# "))

	// Act
	typeCommand(parser, `\dt`)
	parser.WriteOutput([]byte("custodexa=# "))
	typeCommand(parser, "SELECT 1;")

	// Assert：兩條獨立指令（元命令未被併入下一語句）
	want := []string{`\dt`, "SELECT 1;"}
	if len(*commands) != 2 || (*commands)[0] != want[0] || (*commands)[1] != want[1] {
		t.Errorf("commands = %#v, want %#v", *commands, want)
	}
}

func TestCommandParserSQLFlushIncomplete(t *testing.T) {
	// Arrange：未以 ; 結尾的語句在會話結束時應被 flush 出來
	parser, commands := newTestParserSQL()
	parser.WriteOutput([]byte("custodexa=# "))
	typeCommand(parser, "SELECT 1") // 無 ; → 仍累積

	// Act
	parser.Flush()

	// Assert
	if len(*commands) != 1 || (*commands)[0] != "SELECT 1" {
		t.Errorf("commands = %#v, want [\"SELECT 1\"]", *commands)
	}
}

func TestCommandParserFlushPending(t *testing.T) {
	// Arrange：會話在 Enter 後立即斷線，echo 換行未到
	parser, commands := newTestParser()
	parser.WriteOutput([]byte("$ "))
	parser.WriteInput([]byte("x"))
	parser.WriteOutput([]byte("exit"))
	parser.WriteInput([]byte("\r"))

	// Act
	parser.Flush()

	// Assert
	if len(*commands) != 1 || (*commands)[0] != "exit" {
		t.Errorf("commands = %v, want [\"exit\"]", *commands)
	}
}
