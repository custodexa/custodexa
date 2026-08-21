package sshproxy

import (
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 降級紀錄的守衛（command-audit-altscreen-bypass tasks 2.x）。
//
// 本檔釘的是「零紀錄不再存在」與「降級紀錄不含指令文字」這兩件事，
// 以及 command_store 佇列滿載時**斷號即證據**的既有行為。

type degradeRecord struct {
	command  string
	degraded bool
	reason   string
}

// newRecordingParser 建立掛上紀錄槽的解析器：指令與降級／限定紀錄分開收集。
func newRecordingParser(protocol string) (*CommandParser, *[]string, *[]degradeRecord) {
	commands := &[]string{}
	records := &[]degradeRecord{}
	p := NewCommandParser(func(cmd string, _ time.Time) {
		*commands = append(*commands, cmd)
	}, protocol)
	p.SetRecordSink(func(cmd string, degraded bool, reason string, _ time.Time) {
		*records = append(*records, degradeRecord{command: cmd, degraded: degraded, reason: reason})
	})
	return p, commands, records
}

// assertNoTextInDegraded 降級紀錄 SHALL NOT 含任何指令文字——捏造比漏記更嚴重。
func assertNoTextInDegraded(t *testing.T, records []degradeRecord) {
	t.Helper()
	for i, r := range records {
		if r.degraded && r.command != "" {
			t.Errorf("第 %d 筆降級紀錄含指令文字 %q：降級紀錄必須無文字", i, r.command)
		}
		if r.degraded && r.reason == "" {
			t.Errorf("第 %d 筆降級紀錄沒有 reason：不可歸因的降級列無法告警", i)
		}
	}
}

// TestAltScreenRoundsProduceDegradedRecordsNotSilence 釘 ADDED Scenario
// 「全螢幕程式的會話產生降級紀錄而非零紀錄」：alternate screen 期間的每一輪
// 都必須留下可歸因的降級列，且不得含任何指令文字。
//
// **修法前這裡是零紀錄**：scanAltScreen 命中進入標記即整段早退，
// 那些輪次在狀態機裡根本不存在。
func TestAltScreenRoundsProduceDegradedRecordsNotSilence(t *testing.T) {
	parser, commands, records := newRecordingParser("ssh")
	parser.WriteOutput([]byte("$ "))
	typeCommand(parser, "vim notes.txt")

	// 進入 alternate screen 後在 vim 內按三次 Enter
	parser.WriteOutput([]byte("\x1b[?1049h vim screen content"))
	for _, line := range []string{"hello", "world", "third"} {
		parser.WriteInput([]byte("i" + line + "\r"))
		parser.WriteOutput([]byte(line + "\r\n"))
	}
	parser.WriteOutput([]byte("\x1b[?1049l"))
	parser.WriteOutput([]byte("$ "))
	typeCommand(parser, "pwd")

	if got := len(*records); got != 3 {
		t.Errorf("降級紀錄數 = %d, want 3（vim 內的每一輪各一筆）：%+v", got, *records)
	}
	for i, r := range *records {
		if r.reason != model.DegradeAltScreen {
			t.Errorf("第 %d 筆的 reason = %q, want %q", i, r.reason, model.DegradeAltScreen)
		}
	}
	assertNoTextInDegraded(t, *records)

	// 使用者打進檔案的內文不得成為指令（原點錨會命中，故不能只靠 anchorNone）
	for _, cmd := range *commands {
		if strings.Contains(cmd, "hello") || strings.Contains(cmd, "world") || strings.Contains(cmd, "third") {
			t.Errorf("vim 內的檔案內文被記成指令：%q", cmd)
		}
	}
}

// TestFakeAltScreenMarkDoesNotSilenceSession 釘 MODIFIED Scenario
// 「偽造的 alternate-screen 標記不使會話靜音」：使用者自己印出進入標記後，
// 其後每一輪仍各自產生審計記錄（此處為降級紀錄），SHALL NOT 零紀錄。
func TestFakeAltScreenMarkDoesNotSilenceSession(t *testing.T) {
	parser, _, records := newRecordingParser("ssh")
	parser.WriteOutput([]byte("$ "))

	// 一條會把進入標記印到終端的指令（PoC 形態）
	typeCommand(parser, `printf '\033[?1049h'`)
	parser.WriteOutput([]byte("\x1b[?1049h"))

	// 其後兩條帶副作用的指令
	for _, cmd := range []string{"touch /tmp/poc-a", "touch /tmp/poc-b"} {
		parser.WriteInput([]byte("x"))
		parser.WriteOutput([]byte(cmd))
		parser.WriteInput([]byte("\r"))
		parser.WriteOutput([]byte("\r\n$ "))
	}

	if len(*records) != 2 {
		t.Errorf("偽標記之後的審計記錄數 = %d, want 2（每輪一筆）：%+v", len(*records), *records)
	}
	assertNoTextInDegraded(t, *records)
}

// TestRoundWithInputButNoEchoIsRecorded 釘「有輸入但無回顯」這一終態。
//
// 這一類**連錄影都救不回**（asciicast 只有輸出方向的事件），
// 舊行為在此靜默 return，於是關掉回顯後做的事在審計與回放兩側同時無跡可循。
func TestRoundWithInputButNoEchoIsRecorded(t *testing.T) {
	parser, commands, records := newRecordingParser("ssh")
	parser.WriteOutput([]byte("$ "))

	// 打了一整條指令、按 Enter，對端一個位元組都沒回顯（stty -echo 形態）
	parser.WriteInput([]byte("id\r"))
	parser.WriteOutput([]byte("\r\n"))

	if len(*records) != 1 {
		t.Fatalf("無回顯輪的紀錄數 = %d, want 1：%+v", len(*records), *records)
	}
	if (*records)[0].reason != model.DegradeNoEcho {
		t.Errorf("reason = %q, want %q", (*records)[0].reason, model.DegradeNoEcho)
	}
	assertNoTextInDegraded(t, *records)
	// 輸入位元組不得回填：記錄按鍵內容是獨立能力，不在本 change 的射程內
	if (*records)[0].command != "" {
		t.Errorf("降級紀錄回填了輸入位元組：%q", (*records)[0].command)
	}
	if len(*commands) != 0 {
		t.Errorf("無回顯輪不得產生指令列：%v", *commands)
	}
}

// TestBareEnterDoesNotProduceDegradedRecord 純空 Enter 是正常的空輸入，
// **不得**產生降級紀錄——否則每個空 Enter 都是一筆噪音，
// 而告警門檻會被這類噪音推爆。
func TestBareEnterDoesNotProduceDegradedRecord(t *testing.T) {
	parser, commands, records := newRecordingParser("ssh")
	parser.WriteOutput([]byte("$ "))

	parser.WriteInput([]byte("\r"))
	parser.WriteOutput([]byte("\r\n$ "))
	parser.WriteInput([]byte("\r"))
	parser.WriteOutput([]byte("\r\n$ "))

	if len(*records) != 0 {
		t.Errorf("空 Enter 產生了 %d 筆降級紀錄：%+v", len(*records), *records)
	}
	if len(*commands) != 0 {
		t.Errorf("空 Enter 產生了指令列：%v", *commands)
	}
}

// TestDiscardedQueueEmitsOneRecordPerRound 佇列丟棄類降級**逐輪發**：
// 以佇列中的 Enter 數計數（那是計數不是猜測），維持「一輪一筆」。
func TestDiscardedQueueEmitsOneRecordPerRound(t *testing.T) {
	parser, _, records := newRecordingParser("ssh")
	parser.WriteOutput([]byte("$ "))
	typeCommand(parser, "vim notes.txt")
	parser.WriteOutput([]byte("\x1b[?1049h vim screen"))

	// 一輪送出，回顯未到之前又送了三輪（全部排進佇列）
	parser.WriteInput([]byte("iA\r"))
	parser.WriteInput([]byte("iB\rC\rD\r"))
	parser.WriteOutput([]byte("A\r\n"))

	if len(*records) != 4 {
		t.Errorf("降級紀錄數 = %d, want 4（結算輪 1 ＋ 佇列中的 3 個 Enter）：%+v",
			len(*records), *records)
	}
	var queued int
	for _, r := range *records {
		if r.reason == model.DegradeQueueDiscarded {
			queued++
		}
	}
	if queued != 3 {
		t.Errorf("佇列丟棄類降級列 = %d, want 3", queued)
	}
	assertNoTextInDegraded(t, *records)
}

// countReason 數某個 reason 的降級紀錄筆數。
func countReason(records []degradeRecord, reason string) int {
	var n int
	for _, r := range records {
		if r.degraded && r.reason == reason {
			n++
		}
	}
	return n
}

// 以下四支補齊 tasks 2.3 列舉的降級終態守衛（tasks 3.1）。
// **沒有這些斷言，「降級可告警」就是宣稱而不是事實**——一個終態若根本不發紀錄，
// 告警面再完備也收不到它，而該終態的每一輪就是靜默零紀錄。
// 第五個終態（discardFullScreenQueue）由上方
// TestDiscardedQueueEmitsOneRecordPerRound 覆蓋。

// TestUnanchoredRoundProducesDegradedRecord 釘 finalize 的拒發分支
// （錨全部落空 **且** 當輪被重繪汙染或跨列）。
//
// 這是原型 D 把捏造換成漏記的那個交換點：不發指令文字是對的，但**該輪確實存在**
// ——使用者按了 Enter、遠端執行了某件事。沒有降級紀錄則它在審計上等於沒發生過，
// 正是 spec「SHALL NOT 為零紀錄」所禁止的形態。
//
// 語料形狀取自 command_parser_relative_redraw_test.go 的
// TestCommandParserRelativeRedrawWithoutAnchorIsNotEmitted（同一條終態，
// 該支釘的是「不得發出指令」這一半，本支釘的是「必須留下紀錄」那一半）。
func TestUnanchoredRoundProducesDegradedRecord(t *testing.T) {
	parser, commands, records := newRecordingParser("ssh")

	// 全螢幕程式停在螢幕上：原點與提示符都被它的狀態列佔走
	parser.WriteOutput([]byte("\x1b[7m/etc/services\x1b[27m\x1b[K"))

	parser.WriteInput([]byte(" "))
	parser.WriteOutput([]byte("\r\x1b[Ktacacs 49/tcp\r\ndomain 53/tcp\r\nbootps 67/udp\r\n:\x1b[K"))
	parser.WriteInput([]byte("q\r"))
	parser.WriteOutput([]byte("\r\x1b[Kbye-from-pager\r\n"))
	parser.Flush()

	if len(*commands) != 0 {
		t.Fatalf("跨列且無錨時仍發出指令（即捏造）：%q", *commands)
	}
	if got := countReason(*records, model.DegradeRedrawUnanchored); got != 1 {
		t.Errorf("reason=%q 的降級紀錄 = %d, want 1（該輪存在卻無紀錄＝靜默零紀錄）：%+v",
			model.DegradeRedrawUnanchored, got, *records)
	}
	assertNoTextInDegraded(t, *records)
}

// TestTaintedReplayRoundProducesDegradedRecord 釘 finalizeReplayFallback 的拒發分支：
// 重放輪未能在輸出中定位自身回顯，且當輪的回顯是全螢幕重繪 ⇒ 不以輸入位元組結算。
//
// 不以輸入位元組結算是對的（那些按鍵是餵給全螢幕程式的，不是 shell 指令），
// 但該輪同樣確實存在，必須留下可歸因的降級列。
func TestTaintedReplayRoundProducesDegradedRecord(t *testing.T) {
	parser, _, records := newRecordingParser("ssh")
	parser.WriteOutput([]byte("$ "))

	parser.WriteInput([]byte("first\r"))  // 第一輪送出，等回顯
	parser.WriteInput([]byte("second\r")) // 結算期間抵達 → 排隊，稍後重放

	// 第一輪結算，drainReplay 開出 second 的重放輪
	parser.WriteOutput([]byte("first\r\n"))
	// 重放輪等不到自己的回顯，等到的是一次絕對定位重繪（當輪即被汙染）
	parser.WriteOutput([]byte("\x1b[3;1Hfull screen redraw line\r\n"))
	parser.Flush()

	if got := countReason(*records, model.DegradeFullScreenInput); got != 1 {
		t.Errorf("reason=%q 的降級紀錄 = %d, want 1：%+v",
			model.DegradeFullScreenInput, got, *records)
	}
	assertNoTextInDegraded(t, *records)
}

// TestQueueRemainderAtCloseProducesDegradedRecords 釘 flushReplayQueue 的丟棄分支：
// 會話在「全螢幕程式仍在吃按鍵」的狀態下結束，佇列殘留逐輪各留一筆。
func TestQueueRemainderAtCloseProducesDegradedRecords(t *testing.T) {
	parser, _, records := newRecordingParser("ssh")
	parser.WriteOutput([]byte("$ "))

	parser.WriteInput([]byte("first\r"))
	parser.WriteInput([]byte("second\r")) // 重放輪
	parser.WriteInput([]byte("third\r"))  // 仍排在佇列裡
	parser.WriteInput([]byte("fourth\r")) // 仍排在佇列裡

	parser.WriteOutput([]byte("first\r\n"))
	parser.WriteOutput([]byte("\x1b[3;1Hfull screen redraw line\r\n"))
	parser.Flush()

	if got := countReason(*records, model.DegradeQueueDiscardedAtClose); got != 2 {
		t.Errorf("reason=%q 的降級紀錄 = %d, want 2（佇列殘留的兩個 Enter）：%+v",
			model.DegradeQueueDiscardedAtClose, got, *records)
	}
	assertNoTextInDegraded(t, *records)
}

// TestReplayQueueOverflowProducesDegradedRecord 釘 noteReplayOverflow：
// 佇列達上限之後抵達的輸入根本沒進佇列，**其後的輪數不可知**。
//
// 一次溢出一筆（不是每個被丟棄的位元組一筆）：溢出的語義是
// 「自此刻起輸入不再排隊」，那是一個事實不是 N 個。
func TestReplayQueueOverflowProducesDegradedRecord(t *testing.T) {
	parser, _, records := newRecordingParser("ssh")
	parser.WriteOutput([]byte("$ "))
	parser.WriteInput([]byte("first\r")) // 進入 pending，其後輸入全部排隊

	// 灌入量固定不由常數推導（同 TestReplayQueueCapacityIsBoundedAndObservable 的理由）
	if replayQueueMax != 64*1024 {
		t.Fatalf("replayQueueMax = %d，與本測試的灌入量（96 KiB）不再匹配", replayQueueMax)
	}
	chunk := strings.Repeat("x", 4096)
	for i := 0; i < 24; i++ {
		parser.WriteInput([]byte(chunk))
	}

	if got := countReason(*records, model.DegradeQueueOverflow); got != 1 {
		t.Errorf("reason=%q 的降級紀錄 = %d, want 1：%+v",
			model.DegradeQueueOverflow, got, *records)
	}
	assertNoTextInDegraded(t, *records)
}

// TestCommandStoreQueueFullDropLeavesSeqGap 釘 command_store 佇列滿載時的
// **斷號即證據**（design §6.4）：s.seq++ 在 select 之前，故丟棄留下一個
// 用不掉的序號。稽核看到 1,2,4 就知道第 3 筆存在過且沒進來，
// 遠好過一段看起來完整無缺的 1,2,3。
//
// 今天行為即正確，但在本 change 之前沒有任何測試釘住它——把 seq++ 移到
// select 成功之後會讓丟棄變成靜默，而那個改動不會打紅任何東西。
func TestCommandStoreQueueFullDropLeavesSeqGap(t *testing.T) {
	// 不啟動 writeLoop：本測試量的是入隊路徑的編號行為，不碰資料庫
	s := &CommandStore{sessionID: 7, ch: make(chan model.SessionCommand, 2)}
	now := time.Now()

	s.Enqueue("first", now)  // seq=1，入隊
	s.Enqueue("second", now) // seq=2，入隊
	s.Enqueue("third", now)  // seq=3，佇列已滿 → 丟棄
	if n := s.dropped.Load(); n != 1 {
		t.Fatalf("丟棄計數 = %d, want 1", n)
	}

	<-s.ch // 騰出一格
	s.EnqueueDegraded(model.DegradeAltScreen, now)

	var seqs []int
	got := []model.SessionCommand{<-s.ch, <-s.ch}
	for _, c := range got {
		seqs = append(seqs, c.Seq)
	}
	if len(seqs) != 2 || seqs[0] != 2 || seqs[1] != 4 {
		t.Errorf("入隊的序號 = %v, want [2 4]：第 3 號的缺口就是丟棄的證據", seqs)
	}

	// 降級紀錄與指令共用同一個計數器（時序正確性因此免費）
	last := got[1]
	if !last.Degraded {
		t.Error("EnqueueDegraded 入隊的列 degraded 不為真")
	}
	if last.Command != "" {
		t.Errorf("降級列的 command = %q, want 空字串", last.Command)
	}
	if last.DegradeReason != model.DegradeAltScreen {
		t.Errorf("降級列的 reason = %q, want %q", last.DegradeReason, model.DegradeAltScreen)
	}
}
