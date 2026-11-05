package sshproxy

import (
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 會話結束時回顯未完成的一輪。
//
// 一輪正常結算的條件是 Enter 的回顯換行抵達；會話在那之前結束時，
// 已收到的回顯可能只是前綴，而遠端讀到的是完整一行。
// 本檔釘：該輪 SHALL 記為降級且無指令文字；回顯完整後才結束的會話照常入庫。

// typeCharByChar 模擬逐字元輸入：每個字元一幀輸入，回顯只回到 echoed 為止。
func typeCharByChar(p *CommandParser, line, echoed string) {
	for i := 0; i < len(line); i++ {
		p.WriteInput([]byte{line[i]})
		if i < len(echoed) {
			p.WriteOutput([]byte{echoed[i]})
		}
	}
	p.WriteInput([]byte("\r"))
}

func TestTruncatedEchoAtCloseIsDegraded(t *testing.T) {
	parser, commands, records := newRecordingParser("ssh")
	parser.WriteOutput([]byte("$ "))

	typeCharByChar(parser, "touch /tmp/marker-file", "touch /tm")
	parser.Flush()

	if len(*commands) != 0 {
		t.Fatalf("截斷回顯不得以乾淨指令入庫：commands=%q", *commands)
	}
	if len(*records) != 1 {
		t.Fatalf("紀錄數 = %d, want 1：%+v", len(*records), *records)
	}
	r := (*records)[0]
	if !r.degraded || r.reason != model.DegradeEchoIncompleteAtClose {
		t.Errorf("record = %+v, want degraded reason=%q", r, model.DegradeEchoIncompleteAtClose)
	}
	assertNoTextInDegraded(t, *records)
	if !parser.echoIncompleteAtClose {
		t.Error("echoIncompleteAtClose 旗標未設")
	}
}

// 整行一幀送出、回顯只回來前段：與逐字元同一結算路徑。
func TestTruncatedEchoWholeFrameAtCloseIsDegraded(t *testing.T) {
	parser, commands, records := newRecordingParser("ssh")
	parser.WriteOutput([]byte("$ "))

	parser.WriteInput([]byte("touch /tmp/marker-file\r"))
	parser.WriteOutput([]byte("touch /tmp/mar"))
	parser.Flush()

	if len(*commands) != 0 {
		t.Fatalf("commands=%q, want none", *commands)
	}
	if len(*records) != 1 || (*records)[0].reason != model.DegradeEchoIncompleteAtClose {
		t.Fatalf("records=%+v, want one %q", *records, model.DegradeEchoIncompleteAtClose)
	}
	assertNoTextInDegraded(t, *records)
}

// 字元回顯全部到齊、但 Enter 的回顯換行未到：仍不得記為乾淨指令——
// 沒有換行就沒有證據說回顯已完整（解析器不留存輸入內容，無從比對）。
func TestFullTextButMissingNewlineEchoAtCloseIsDegraded(t *testing.T) {
	parser, commands, records := newRecordingParser("ssh")
	parser.WriteOutput([]byte("$ "))

	typeCharByChar(parser, "id", "id")
	parser.Flush()

	if len(*commands) != 0 {
		t.Fatalf("commands=%q, want none", *commands)
	}
	if len(*records) != 1 || (*records)[0].reason != model.DegradeEchoIncompleteAtClose {
		t.Fatalf("records=%+v, want one %q", *records, model.DegradeEchoIncompleteAtClose)
	}
}

// 正常情況：回顯（含換行）完整後才結束，照常以乾淨指令入庫、不補任何降級列。
func TestCompleteEchoBeforeCloseIsClean(t *testing.T) {
	for _, tc := range []struct {
		name  string
		after string // Enter 之後的輸出
	}{
		{"newline-only", "\r\n"},
		{"newline-and-prompt", "\r\n$ "},
		{"newline-output-prompt", "\r\nok\r\n$ "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parser, commands, records := newRecordingParser("ssh")
			parser.WriteOutput([]byte("$ "))
			typeCharByChar(parser, "touch /tmp/marker-file", "touch /tmp/marker-file")
			parser.WriteOutput([]byte(tc.after))
			parser.Flush()

			if len(*commands) != 1 || (*commands)[0] != "touch /tmp/marker-file" {
				t.Fatalf("commands=%q, want [touch /tmp/marker-file]", *commands)
			}
			if len(*records) != 0 {
				t.Fatalf("回顯完整後結束不得產生降級／限定紀錄：%+v", *records)
			}
		})
	}
}

// 零回顯即結束：維持既有的 input_without_echo，不改碼。
func TestNoEchoAtCloseKeepsNoEchoReason(t *testing.T) {
	parser, commands, records := newRecordingParser("ssh")
	parser.WriteOutput([]byte("$ "))

	parser.WriteInput([]byte("touch /tmp/marker-file\r"))
	parser.Flush()

	if len(*commands) != 0 {
		t.Fatalf("commands=%q", *commands)
	}
	if len(*records) != 1 || (*records)[0].reason != model.DegradeNoEcho {
		t.Fatalf("records=%+v, want one %q", *records, model.DegradeNoEcho)
	}
}

// 只按 Enter 即結束：不記（與既有空輪規則一致）。
func TestBareEnterPendingAtCloseNotRecorded(t *testing.T) {
	parser, commands, records := newRecordingParser("ssh")
	parser.WriteOutput([]byte("$ "))

	parser.WriteInput([]byte("\r"))
	parser.Flush()

	if len(*commands) != 0 || len(*records) != 0 {
		t.Fatalf("只按 Enter 不得產生紀錄：commands=%q records=%+v", *commands, *records)
	}
}

// 前面已入庫的乾淨指令不受影響；最後一輪截斷只影響它自己。
func TestTruncatedLastRoundDoesNotAffectEarlierCommands(t *testing.T) {
	parser, commands, records := newRecordingParser("ssh")
	parser.WriteOutput([]byte("$ "))

	typeCharByChar(parser, "echo first", "echo first")
	parser.WriteOutput([]byte("\r\nfirst\r\n$ "))
	typeCharByChar(parser, "touch /tmp/marker-file", "touch /t")
	parser.Flush()

	if len(*commands) != 1 || (*commands)[0] != "echo first" {
		t.Fatalf("commands=%q, want [echo first]", *commands)
	}
	if len(*records) != 1 || (*records)[0].reason != model.DegradeEchoIncompleteAtClose {
		t.Fatalf("records=%+v, want one %q（且不再另補 input_without_command）", *records, model.DegradeEchoIncompleteAtClose)
	}
}

// 未掛紀錄槽時：截斷前綴也不得退回 onCommand 以乾淨指令發出。
func TestTruncatedEchoAtCloseWithoutSinkEmitsNothing(t *testing.T) {
	var commands []string
	parser := NewCommandParser(func(cmd string, _ time.Time) { commands = append(commands, cmd) }, "ssh")
	parser.WriteOutput([]byte("$ "))
	typeCharByChar(parser, "touch /tmp/marker-file", "touch /tm")
	parser.Flush()
	if len(commands) != 0 {
		t.Fatalf("commands=%q, want none", commands)
	}
}

// sqlMode：累積中的語句最後一段回顯未完成時，整條語句不得以乾淨紀錄在 Flush 尾段發出。
func TestTruncatedEchoAtCloseDiscardsAccumulatedSQL(t *testing.T) {
	parser, commands, records := newRecordingParser("postgres")
	parser.WriteOutput([]byte("db=> "))

	typeCharByChar(parser, "SELECT 1", "SELECT 1")
	parser.WriteOutput([]byte("\r\ndb-> "))
	typeCharByChar(parser, "FROM pg_tables;", "FROM pg_")
	parser.Flush()

	if len(*commands) != 0 {
		t.Fatalf("半條語句不得以乾淨紀錄發出：commands=%q", *commands)
	}
	if len(*records) != 1 || (*records)[0].reason != model.DegradeEchoIncompleteAtClose {
		t.Fatalf("records=%+v, want one %q", *records, model.DegradeEchoIncompleteAtClose)
	}
}

// sqlMode：累積中的語句，最後一段零回顯就結束時，前面累積的前綴同樣不得以乾淨紀錄發出。
// 零回顯終態自己不發文字，但若不丟棄 stmtBuf，Flush 尾段會替它發出前綴（degraded=false）。
func TestNoEchoAtCloseDiscardsAccumulatedSQL(t *testing.T) {
	for _, mode := range []string{"postgres", "mysql", "mssql"} {
		t.Run(mode, func(t *testing.T) {
			parser, commands, records := newRecordingParser(mode)
			parser.WriteOutput([]byte("db=> "))

			typeCharByChar(parser, "DELETE FROM t", "DELETE FROM t")
			parser.WriteOutput([]byte("\r\ndb-> "))
			parser.WriteInput([]byte("WHERE id=1;\r"))
			parser.Flush()

			if len(*commands) != 0 {
				t.Fatalf("半條語句不得以乾淨紀錄發出：commands=%q", *commands)
			}
			if len(*records) != 1 || (*records)[0].reason != model.DegradeNoEcho {
				t.Fatalf("records=%+v, want one %q", *records, model.DegradeNoEcho)
			}
		})
	}
}

// 非會話結束的零回顯輪不得丟棄累積語句：只有 atClose 才改變行為。
func TestNoEchoRoundMidSessionKeepsAccumulatedSQL(t *testing.T) {
	parser, commands, _ := newRecordingParser("postgres")
	parser.WriteOutput([]byte("db=> "))

	typeCharByChar(parser, "SELECT 1", "SELECT 1")
	parser.WriteOutput([]byte("\r\ndb-> "))
	typeCharByChar(parser, "FROM t;", "FROM t;")
	parser.WriteOutput([]byte("\r\n x \r\n db=> "))
	parser.Flush()

	if len(*commands) != 1 {
		t.Fatalf("commands=%q, want one joined statement", *commands)
	}
}
