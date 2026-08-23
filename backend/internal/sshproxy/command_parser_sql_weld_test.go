package sshproxy

import (
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// 多行 SQL 的降級輪不得把半條語句焊接到後續乾淨輪。
//
// 形狀：DB CLI（sqlMode）的多行語句靠 accumulateSQL 跨續行累積到 stmtBuf，遇語句
// 結束符才 emit。若一條語句的**組成輪**中有一輪降級（該輪的回顯無法可信重組），
// finalize 走降級分支並在該輪留下降級紀錄——但若不清 stmtBuf，前面已累積的半條
// 語句會留在緩衝裡，被後續**乾淨**輪的 accumulateSQL 接上去，emit 成一條使用者
// 從未送出的語句、且 degraded=false（看起來可信）。SSH 無此路徑：逐行協議每輪各自
// emit，不跨輪累積。
//
// 正確處置：降級輪把累積中的半條語句一併丟棄。丟棄不是漏記——留在 stmtBuf 的是
// 續行提示符下**尚未終止、尚未作為一條指令執行**的前綴；而該輪的降級紀錄已在那個
// 位置留下可搜尋、可歸因的訊號，整條語句因此呈現為「一筆降級」而非「一條假語句」，
// 也非靜默少一列。
//
// 兩個子案各觸發 finalize 的一條降級分支（兩條落地路徑）：
//   - roundAltScreen：對端在該輪處於 alternate-screen 標記區間內。
//   - anchorNone && (roundTainted||spanned)：該輪的回顯是全螢幕重繪且錨全部落空。
func TestCommandParserSQLDegradedRoundDoesNotWeldFakeStatement(t *testing.T) {
	// assertNoWeld 語句一的完成行降級後，只應留下語句二一條乾淨紀錄；
	// 且該會話 SHALL NOT 出現跨語句焊接的假語句。
	assertNoWeld := func(t *testing.T, commands []string, records []degradeRecord) {
		t.Helper()

		// 焊接的假語句是把語句一的殘留前綴接到語句二上：commands 中不得出現任何
		// 同時含兩條語句碎片的字串（此處以語句一的可辨識前綴 "'a'" 為記號）。
		for _, cmd := range commands {
			if strings.Contains(cmd, "'a'") {
				t.Errorf("入庫指令含語句一的殘留前綴（跨語句焊接的假語句）：%q", cmd)
			}
		}

		// 修法後語句二仍須乾淨入庫成單一語句，一字不差。
		if len(commands) != 1 || commands[0] != "SELECT 'c';" {
			t.Errorf("commands = %#v, want [\"SELECT 'c';\"]（半條語句丟棄、語句二乾淨入庫）", commands)
		}

		// 降級輪必須留下可歸因、無文字的降級紀錄——語句一不是靜默少一列。
		degraded := 0
		for _, r := range records {
			if r.degraded {
				degraded++
			}
		}
		if degraded < 1 {
			t.Errorf("降級紀錄數 = %d, want >=1（語句一的降級輪必須留痕，不得靜默漏記）：%+v",
				degraded, records)
		}
		assertNoTextInDegraded(t, records)
	}

	t.Run("altscreen_round", func(t *testing.T) {
		parser, commands, records := newRecordingParser("postgres")
		parser.WriteOutput([]byte("custodexa=# "))

		// 語句一第一行：續行，累積進 stmtBuf（未見 ; ）。
		typeCommand(parser, "SELECT 'a' AS a,")
		parser.WriteOutput([]byte("custodexa-# ")) // 續行提示符

		// 語句一的完成行落在一輪 alternate-screen 標記區間內 → 該輪降級。
		parser.WriteOutput([]byte("\x1b[?1049h"))
		parser.WriteInput([]byte("x"))
		parser.WriteOutput([]byte("'b' AS b;"))
		parser.WriteInput([]byte("\r"))
		parser.WriteOutput([]byte("\r\n"))
		parser.WriteOutput([]byte("\x1b[?1049l"))
		parser.WriteOutput([]byte("custodexa=# "))

		// 語句二：乾淨的一輪。
		typeCommand(parser, "SELECT 'c';")

		assertNoWeld(t, *commands, *records)
	})

	// replay_tainted_drop 覆蓋重放路徑的同型缺陷：半條語句已累積，之後一個重放輪
	// 因全螢幕重繪而 tainted-drop（finalizeReplayFallback 的拒發分支）。不清 stmtBuf
	// 則同樣被後續乾淨輪焊接。這是 same-type-different-path：修 finalize 兩分支不夠，
	// 重放路徑的降級終端也要清。
	t.Run("replay_tainted_drop", func(t *testing.T) {
		parser, commands, records := newRecordingParser("postgres")
		parser.WriteOutput([]byte("custodexa=# "))

		// 半條語句累積進 stmtBuf。
		typeCommand(parser, "SELECT 'a' AS a,")
		parser.WriteOutput([]byte("custodexa-# "))

		// 一輪送出後、結算期間另一輪抵達 → 排隊成重放輪；重放輪等到的是一次
		// 絕對定位重繪，定位不到自身回顯 ⇒ tainted-drop（不以輸入位元組結算）。
		parser.WriteInput([]byte("cont\r"))
		parser.WriteInput([]byte("more\r"))
		parser.WriteOutput([]byte("cont\r\n"))
		parser.WriteOutput([]byte("\x1b[3;1Hfull screen redraw line\r\n"))
		parser.Flush()

		// 半條語句（含中途 tainted-drop）必須被丟棄，不得焊接。
		for _, cmd := range *commands {
			if strings.Contains(cmd, "'a'") {
				t.Errorf("重放路徑降級後仍焊接半條語句：%q", cmd)
			}
		}
		if got := countReason(*records, model.DegradeFullScreenInput); got < 1 {
			t.Errorf("reason=%q 的降級紀錄 = %d, want >=1：%+v",
				model.DegradeFullScreenInput, got, *records)
		}
		assertNoTextInDegraded(t, *records)
	})

	t.Run("redraw_unanchored", func(t *testing.T) {
		parser, commands, records := newRecordingParser("postgres")
		parser.WriteOutput([]byte("custodexa=# "))

		typeCommand(parser, "SELECT 'a' AS a,")
		parser.WriteOutput([]byte("custodexa-# "))

		// 語句一的完成行落在一輪全螢幕重繪上：回顯以絕對定位改寫整螢幕、
		// 最後一個非空白行不是提示符 ⇒ roundTainted 且錨全部落空 ⇒ 該輪降級。
		parser.WriteInput([]byte("x"))
		parser.WriteOutput([]byte("\x1b[5;1H\x1b[Kredrawn status content"))
		parser.WriteInput([]byte("\r"))
		parser.WriteOutput([]byte("\r\n"))
		parser.WriteOutput([]byte("custodexa=# "))

		typeCommand(parser, "SELECT 'c';")

		assertNoWeld(t, *commands, *records)

		// 該輪的降級碼應為「重繪且無錨」。
		if got := countReason(*records, model.DegradeRedrawUnanchored); got < 1 {
			t.Errorf("reason=%q 的降級紀錄 = %d, want >=1：%+v",
				model.DegradeRedrawUnanchored, got, *records)
		}
	})
}
