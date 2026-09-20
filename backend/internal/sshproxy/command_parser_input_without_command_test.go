package sshproxy

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// 會話結束時的安全網：有實質輸入卻零紀錄 → 恰一筆 input_without_command 降級列。
// 目的：任何尚未被發現的判定缺口，對稽核者呈現為「審計失效」而非「沒有操作」。

// TestCommandParserInputWithoutCommandEmitsDegradedAtClose 有輸入、解析器什麼都沒結算。
// 模擬手法：輸入從未以 Enter 送出（對端也無回顯），使既有所有路徑都不產出。
func TestCommandParserInputWithoutCommandEmitsDegradedAtClose(t *testing.T) {
	parser, commands, records := newRecordingParser("ssh")
	parser.WriteOutput([]byte("$ "))
	parser.WriteInput([]byte("uptime")) // 沒有 Enter、沒有回顯：既有路徑一筆都不會記
	parser.Flush()

	if len(*commands) != 0 {
		t.Fatalf("不該有指令列：%v", *commands)
	}
	if len(*records) != 1 {
		t.Fatalf("降級列數 = %d, want 1：%+v", len(*records), *records)
	}
	r := (*records)[0]
	if !r.degraded || r.reason != model.DegradeInputNoCommand {
		t.Errorf("record = %+v, want degraded=true reason=%q", r, model.DegradeInputNoCommand)
	}
	assertNoTextInDegraded(t, *records)
}

// TestCommandParserInputWithoutCommandNotOnNormalSession 有指令列的會話不補任何東西。
func TestCommandParserInputWithoutCommandNotOnNormalSession(t *testing.T) {
	parser, commands, records := newRecordingParser("ssh")
	parser.WriteOutput([]byte("$ "))
	typeCommand(parser, "uptime")
	parser.WriteOutput([]byte("$ "))
	parser.Flush()

	if len(*commands) != 1 {
		t.Fatalf("commands = %v, want [uptime]", *commands)
	}
	if len(*records) != 0 {
		t.Errorf("正常會話不該有降級列：%+v", *records)
	}
}

// TestCommandParserInputWithoutCommandNotOnEnterOnly 只按 Enter（含 `\n`）不算實質輸入。
func TestCommandParserInputWithoutCommandNotOnEnterOnly(t *testing.T) {
	parser, _, records := newRecordingParser("ssh")
	parser.WriteOutput([]byte("$ "))
	parser.WriteInput([]byte("\r"))
	parser.WriteOutput([]byte("\r\n$ "))
	parser.WriteInput([]byte("\n"))
	parser.WriteOutput([]byte("\r\n$ "))
	parser.Flush()

	if len(*records) != 0 {
		t.Errorf("只按 Enter 不該有降級列：%+v", *records)
	}
}

// TestCommandParserInputWithoutCommandNotDuplicatingNoEcho 既有 input_without_echo 已記一筆，
// 安全網不得再補第二筆（recordCount 含降級列）。
func TestCommandParserInputWithoutCommandNotDuplicatingNoEcho(t *testing.T) {
	parser, _, records := newRecordingParser("ssh")
	parser.WriteOutput([]byte("$ "))
	parser.WriteInput([]byte("id\r"))
	parser.WriteOutput([]byte("\r\n"))
	parser.Flush()

	if len(*records) != 1 {
		t.Fatalf("records = %+v, want 恰一筆 input_without_echo", *records)
	}
	if (*records)[0].reason != model.DegradeNoEcho {
		t.Errorf("reason = %q, want %q", (*records)[0].reason, model.DegradeNoEcho)
	}
}

// TestCommandParserInputWithoutCommandCountsInterruptedAndQueuedBytes 中斷鍵前的位元組與
// pending 期間排入佇列的位元組同樣是「打過的字」：整條會話零紀錄時安全網仍要補一筆。
func TestCommandParserInputWithoutCommandCountsInterruptedAndQueuedBytes(t *testing.T) {
	t.Run("interrupted", func(t *testing.T) {
		parser, _, records := newRecordingParser("ssh")
		parser.WriteOutput([]byte("$ "))
		parser.WriteInput([]byte("ls\x03"))
		parser.Flush()
		if len(*records) != 1 || (*records)[0].reason != model.DegradeInputNoCommand {
			t.Errorf("records = %+v, want 恰一筆 %s", *records, model.DegradeInputNoCommand)
		}
	})
	t.Run("queued_during_pending", func(t *testing.T) {
		parser, _, records := newRecordingParser("ssh")
		parser.WriteOutput([]byte("$ "))
		parser.WriteInput([]byte("\r")) // 空 Enter 進 pending
		parser.WriteInput([]byte("ls")) // pending 期間排入佇列，從未按 Enter
		parser.Flush()
		if len(*records) != 1 || (*records)[0].reason != model.DegradeInputNoCommand {
			t.Errorf("records = %+v, want 恰一筆 %s", *records, model.DegradeInputNoCommand)
		}
	})
	t.Run("interrupt_only_not_counted", func(t *testing.T) {
		parser, _, records := newRecordingParser("ssh")
		parser.WriteOutput([]byte("$ "))
		parser.WriteInput([]byte("\x03"))
		parser.Flush()
		if len(*records) != 0 {
			t.Errorf("只按 Ctrl-C 不該有降級列：%+v", *records)
		}
	})
}
