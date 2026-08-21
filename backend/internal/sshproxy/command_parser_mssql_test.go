package sshproxy

import "testing"

// T-SQL 的執行單位是批次，以獨立一行的 GO 送出；`;` 不觸發執行。
// 不認 GO 的話，整條會話的 SQL 會累積成單一巨大「指令」，
// 審計切分與實際執行批次永久錯位，SQL 危險規則比對的是錯的對象。
func TestCommandParserMSSQLGoTerminatesBatch(t *testing.T) {
	// Arrange
	parser, commands := newTestParserMSSQL()
	parser.WriteOutput([]byte("1> "))

	// Act：兩行 SELECT 後以 GO 送出批次
	typeCommand(parser, "SELECT 1")
	parser.WriteOutput([]byte("2> "))
	typeCommand(parser, "SELECT 2")
	parser.WriteOutput([]byte("3> "))
	typeCommand(parser, "GO")

	// Assert：結算為一筆含三行的批次
	want := "SELECT 1\nSELECT 2\nGO"
	if len(*commands) != 1 || (*commands)[0] != want {
		t.Errorf("commands = %#v, want [%q]", *commands, want)
	}
}

// GO 的辨識形態：大小寫不拘、前後空白不拘、可帶重複次數。
// 反面同等重要——行內出現的 GO（如 SELECT 'GO'）不得誤判為終止符，
// 誤判會把一條語句劈成兩半，等於自己製造出拆行規避的效果。
func TestCommandParserMSSQLGoRecognitionMatrix(t *testing.T) {
	cases := []struct {
		name string
		line string
		want bool
	}{
		{"標準 GO", "GO", true},
		{"小寫 go", "go", true},
		{"混合大小寫", "Go", true},
		{"前後空白", "   GO  ", true},
		{"帶重複次數", "GO 3", true},
		{"帶多位數重複次數", "GO 10", true},
		{"重複次數為 0", "GO 0", false},
		{"行內字串中的 GO", "SELECT 'GO'", false},
		{"以 GO 開頭的識別字", "GOTO", false},
		{"GO 後接非數字", "GO abc", false},
		{"空行", "", false},
		{"只有 G", "G", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tsqlBatchTerminator(c.line); got != c.want {
				t.Errorf("tsqlBatchTerminator(%q) = %v, want %v", c.line, got, c.want)
			}
		})
	}
}

// mssql 保留 `;` 為終止符（取聯集）：使用者習慣上會打 `;`，
// 且「拆行規避 SQL 危險規則」的防線不能因為新增 GO 而變弱。
func TestCommandParserMSSQLSemicolonStillTerminates(t *testing.T) {
	parser, commands := newTestParserMSSQL()
	parser.WriteOutput([]byte("1> "))

	typeCommand(parser, "SELECT 1;")

	if len(*commands) != 1 || (*commands)[0] != "SELECT 1;" {
		t.Errorf("commands = %#v, want [\"SELECT 1;\"]", *commands)
	}
}

// 行內 GO 的端到端反面：SELECT 'GO' 不得被當成批次結束，
// 應繼續累積直到真正的 GO 行。
func TestCommandParserMSSQLInlineGoDoesNotTerminate(t *testing.T) {
	parser, commands := newTestParserMSSQL()
	parser.WriteOutput([]byte("1> "))

	typeCommand(parser, "SELECT 'GO'")
	parser.WriteOutput([]byte("2> "))
	if len(*commands) != 0 {
		t.Fatalf("行內 GO 不應結算，commands = %#v", *commands)
	}
	typeCommand(parser, "GO")

	want := "SELECT 'GO'\nGO"
	if len(*commands) != 1 || (*commands)[0] != want {
		t.Errorf("commands = %#v, want [%q]", *commands, want)
	}
}

// **回歸釘死**：GO 終止符只對 mssql 啟用。既有三協議（與 ssh）送出獨立一行 GO 時，
// 切分行為必須與本功能加入前完全相同——postgres/mysql 繼續累積（未見 `;`），
// ssh/redis 繼續逐行結算。
func TestCommandParserGoIsMSSQLOnly(t *testing.T) {
	t.Run("sqlMode 協議不因 GO 而結算", func(t *testing.T) {
		parser, commands := newTestParserSQL() // postgres
		parser.WriteOutput([]byte("custodexa=# "))

		typeCommand(parser, "SELECT 1")
		parser.WriteOutput([]byte("custodexa-# "))
		typeCommand(parser, "GO")

		// 未見 `;`：兩行仍在累積中，尚未結算
		if len(*commands) != 0 {
			t.Fatalf("postgres 不應把 GO 當終止符，commands = %#v", *commands)
		}
		parser.Flush()
		want := "SELECT 1\nGO"
		if len(*commands) != 1 || (*commands)[0] != want {
			t.Errorf("commands = %#v, want [%q]", *commands, want)
		}
	})

	t.Run("逐行協議行為不變", func(t *testing.T) {
		parser, commands := newTestParser() // ssh
		parser.WriteOutput([]byte("$ "))

		typeCommand(parser, "SELECT 1")
		typeCommand(parser, "GO")

		want := []string{"SELECT 1", "GO"}
		if len(*commands) != 2 || (*commands)[0] != want[0] || (*commands)[1] != want[1] {
			t.Errorf("commands = %#v, want %#v", *commands, want)
		}
	})
}

// 模式推導的單一事實源守衛：協議 → (sqlMode, tsqlMode) 的對照必須雙向正確。
// 漏掉 mssql 的 sqlMode 會使多行 SQL 逐行結算（拆行規避告警重新開門）；
// 誤把 tsqlMode 開給其他協議則會改動既有切分。
func TestNewCommandParserModeByProtocol(t *testing.T) {
	cases := []struct {
		protocol     string
		wantSQLMode  bool
		wantTSQLMode bool
	}{
		{"mysql", true, false},
		{"postgres", true, false},
		{"mssql", true, true},
		{"redis", false, false},
		{"ssh", false, false},
		{"k8s", false, false},
	}
	for _, c := range cases {
		t.Run(c.protocol, func(t *testing.T) {
			p := NewCommandParser(nil, c.protocol)
			if p.sqlMode != c.wantSQLMode {
				t.Errorf("sqlMode = %v, want %v", p.sqlMode, c.wantSQLMode)
			}
			if p.tsqlMode != c.wantTSQLMode {
				t.Errorf("tsqlMode = %v, want %v", p.tsqlMode, c.wantTSQLMode)
			}
		})
	}
}
