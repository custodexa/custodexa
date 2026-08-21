package sshproxy

import (
	"bytes"
	"strings"
	"testing"
)

// === 結算期間抵達的輸入不得遺失（command-audit-pending-queue）===
//
// 缺陷：Enter 送出後那一輪要等回顯換行才結算，期間抵達的輸入被整段丟棄——
// 指令在遠端正常執行、審計零紀錄。送出時機與封包切分由使用者端控制，
// 故可主動觸發：被繞過的是留痕，不是執行權（goal-charter §6，B 類必修）。
//
// 本檔的輸出分幀**全部取自 ssh-test 靶機實跑**（2026-08-18，linuxserver/openssh-server，
// bash + readline + bracketed paste）。不是手工編造的理想序列——
// 真實序列的關鍵性質是：**第二條指令的 echo 與前一條的執行結果、新提示符黏在同一幀**。
// 任何「結算後立刻開下一輪、見第一個換行就結算」的修法都會在此處把執行結果
// 記成一條使用者從未輸入的指令，那是比漏記更嚴重的捏造。

const (
	// promptFrame 開場提示符（實測：bracketed paste 開啟序列 + 提示符）
	promptFrame = "\x1b[?2004hssh-test-server:~$ "
	// sameFrameEcho1 形態 (a) 的第一個輸出幀：只有第一條的 echo 與 Enter 換行
	sameFrameEcho1 = "echo A\r\n\x1b[?2004l\r"
	// sameFrameEcho2 形態 (a) 的第二個輸出幀：**第一條的執行結果 A、新提示符、
	// 第二條的 echo、第二條的執行結果 B、再一個提示符，全部在同一幀**
	sameFrameEcho2 = "A\r\n\x1b[?2004hssh-test-server:~$ echo B\r\n\x1b[?2004l\rB\r\n\x1b[?2004hssh-test-server:~$ "
	// crossFrameEcho1 形態 (b) 的第一個輸出幀：echo、Enter 換行、執行結果同幀
	crossFrameEcho1 = "echo A\r\n\x1b[?2004l\rA\r\n"
	// crossFrameEcho2 形態 (b) 的第二個輸出幀
	crossFrameEcho2 = "\x1b[?2004hssh-test-server:~$ echo B\r\n\x1b[?2004l\rB\r\n\x1b[?2004hssh-test-server:~$ "
)

// TestPendingQueueSameFrameMultipleCommands 形態 (a)：同一封包內多條指令。
// 使用者在終端貼上一段多行指令即命中，不需要任何特殊操作。
func TestPendingQueueSameFrameMultipleCommands(t *testing.T) {
	parser, commands := newTestParser()
	parser.WriteOutput([]byte(promptFrame))

	parser.WriteInput([]byte("echo A\recho B\r"))
	parser.WriteOutput([]byte(sameFrameEcho1))
	parser.WriteOutput([]byte(sameFrameEcho2))

	want := []string{"echo A", "echo B"}
	assertCommands(t, *commands, want)
}

// TestPendingQueueCrossFrameRapidSend 形態 (b)：前一條的回顯尚未返回就送出下一條。
func TestPendingQueueCrossFrameRapidSend(t *testing.T) {
	parser, commands := newTestParser()
	parser.WriteOutput([]byte(promptFrame))

	parser.WriteInput([]byte("echo A\r"))
	parser.WriteInput([]byte("echo B\r")) // 回顯尚未返回即送出
	parser.WriteOutput([]byte(crossFrameEcho1))
	parser.WriteOutput([]byte(crossFrameEcho2))

	want := []string{"echo A", "echo B"}
	assertCommands(t, *commands, want)
}

// TestPendingQueueNeverFabricatesResultOutput 捏造防線：執行結果不得被記成指令。
//
// 這條與上面兩條是**同一個修法的兩面**：補漏記若以「結算後立刻開輪、
// 見第一個換行就結算」實作，這條必紅——第一個換行屬於前一條的執行結果 A。
func TestPendingQueueNeverFabricatesResultOutput(t *testing.T) {
	parser, commands := newTestParser()
	parser.WriteOutput([]byte(promptFrame))

	parser.WriteInput([]byte("echo A\recho B\r"))
	parser.WriteOutput([]byte(sameFrameEcho1))
	parser.WriteOutput([]byte(sameFrameEcho2))

	for _, got := range *commands {
		if got == "A" || got == "B" {
			t.Errorf("執行結果被記成指令：commands = %v，%q 是輸出不是輸入", *commands, got)
		}
	}
}

// TestPendingQueueOrderPreserved 順序斷言：三條連送，記錄順序須與送出順序一致。
func TestPendingQueueOrderPreserved(t *testing.T) {
	parser, commands := newTestParser()
	parser.WriteOutput([]byte(promptFrame))

	parser.WriteInput([]byte("echo 1\recho 2\recho 3\r"))
	parser.WriteOutput([]byte("echo 1\r\n\x1b[?2004l\r"))
	parser.WriteOutput([]byte("1\r\n\x1b[?2004hssh-test-server:~$ echo 2\r\n\x1b[?2004l\r"))
	parser.WriteOutput([]byte("2\r\n\x1b[?2004hssh-test-server:~$ echo 3\r\n\x1b[?2004l\r"))
	parser.WriteOutput([]byte("3\r\n\x1b[?2004hssh-test-server:~$ "))

	want := []string{"echo 1", "echo 2", "echo 3"}
	assertCommands(t, *commands, want)
}

// assertCommands 逐條比對結算結果，失敗時印出完整實得序列。
func assertCommands(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("結算筆數 = %d，want %d\n實得：%q\n期望：%q",
			len(got), len(want), got, want)
	}
	for i := range want {
		if strings.TrimSpace(got[i]) != want[i] {
			t.Errorf("第 %d 筆 = %q，want %q\n實得：%q", i+1, got[i], want[i], got)
		}
	}
}

// === 實測分幀（續）：歷史鍵與長時執行 ===

const (
	// histEcho1／histEcho2 pending 期間按上鍵（實測 scenario hist）：
	// 遠端**確實重繪並執行了**前一條指令。輸入位元組是 "\x1b[A\r"，
	// 可見文字只存在於 echo 裡——輸入錨在此不可用，改由提示符定位。
	histEcho1 = "echo A\r\n\x1b[?2004l\rA\r\n"
	histEcho2 = "\x1b[?2004hssh-test-server:~$ echo A\r\n\x1b[?2004l\rA\r\n\x1b[?2004hssh-test-server:~$ "
	// sleepEcho1／sleepEcho2 前一條長時間執行中送出下一條（實測 scenario sleep，
	// 兩幀相隔 2074ms）。時間差不影響解析，但證明這不是只在同一毫秒內成立的競態。
	sleepEcho1 = "sleep 2\r\n\x1b[?2004l\r"
	sleepEcho2 = "\x1b[?2004hssh-test-server:~$ echo B\r\n\x1b[?2004l\rB\r\n\x1b[?2004hssh-test-server:~$ "
)

// TestPendingQueueHistoryKeyStillAudited 結算期間按上鍵送出的指令仍須留痕。
//
// 這條是**錨定路徑補不到的那一半**：輸入位元組 "\x1b[A" 沒有可見文字，
// 錨為空。若因此跳過該輪，就等於保留了一條「按上鍵重複執行不留痕」的規避路徑。
func TestPendingQueueHistoryKeyStillAudited(t *testing.T) {
	parser, commands := newTestParser()
	parser.WriteOutput([]byte(promptFrame))

	parser.WriteInput([]byte("echo A\r"))
	parser.WriteInput([]byte("\x1b[A\r")) // 上鍵 + Enter，回顯尚未返回
	parser.WriteOutput([]byte(histEcho1))
	parser.WriteOutput([]byte(histEcho2))

	assertCommands(t, *commands, []string{"echo A", "echo A"})
}

// TestPendingQueueLongRunningPrevious 前一條長時間執行中送出下一條。
func TestPendingQueueLongRunningPrevious(t *testing.T) {
	parser, commands := newTestParser()
	parser.WriteOutput([]byte(promptFrame))

	parser.WriteInput([]byte("sleep 2\r"))
	parser.WriteInput([]byte("echo B\r"))
	parser.WriteOutput([]byte(sleepEcho1))
	parser.WriteOutput([]byte(sleepEcho2))

	assertCommands(t, *commands, []string{"sleep 2", "echo B"})
}

// === 新失敗面：佇列上界（tasks 3，spec「重放佇列的容量上界機器可見」）===

// TestReplayQueueCapacityIsBoundedAndObservable 佇列不得無限增長，
// 且達到上界是**可觀測的終態**而非靜默丟棄。
//
// 為什麼這條不能以「實務上不會發生」略過：對端正是不受信的納管主機，
// 它永不回顯就能讓結算永不完成。
func TestReplayQueueCapacityIsBoundedAndObservable(t *testing.T) {
	var logBuf bytes.Buffer
	defer captureLog(&logBuf)()

	// **灌入量固定、不由 replayQueueMax 推導。**
	// 獨立驗收實測：迴圈次數若跟著常數走，把上界放寬 4096 倍（1<<28）整包照樣綠
	// ——那種斷言只抓得到「上界完全沒生效」，抓不到「上界被悄悄調鬆」
	// （`docs/dev/testing.md` §5 形態 8：只驗刪除、不驗放寬）。
	// 固定灌 96 KiB 之後，上界一旦被調到 96 KiB 以上，溢位旗標就不會設，本測試即紅。
	if replayQueueMax != 64*1024 {
		t.Fatalf("replayQueueMax = %d，與本測試的灌入量（96 KiB）不再匹配。"+
			"調整上界是安全參數變更，請一併檢視此處的灌入量與理由，勿只改常數", replayQueueMax)
	}
	const (
		feedChunk  = 4096
		feedRounds = 24 // 96 KiB > 64 KiB 上界
	)

	parser, _ := newTestParser()
	parser.WriteOutput([]byte(promptFrame))
	parser.WriteInput([]byte("echo A\r")) // 進入 pending，其後輸入全部排隊

	// 對端永不回顯：持續灌入輸入（不含 Enter，避免測到指令數而非容量）
	chunk := bytes.Repeat([]byte("x"), feedChunk)
	for i := 0; i < feedRounds; i++ {
		parser.WriteInput(chunk)
	}

	if got := parser.replayQueue.Len(); got > replayQueueMax {
		t.Errorf("佇列長度 = %d，超過上界 %d——上界沒有生效", got, replayQueueMax)
	}
	if !parser.replayOverflowed {
		t.Error("達到上界卻未設可觀測旗標：這是靜默丟棄")
	}
	if !strings.Contains(logBuf.String(), "重放佇列達上限") {
		t.Errorf("達到上界未留下日誌，log = %q", logBuf.String())
	}
	if n := strings.Count(logBuf.String(), "重放佇列達上限"); n != 1 {
		t.Errorf("上界日誌記了 %d 次，應每連線僅一次（避免灌爆日誌）", n)
	}
}

// TestReplayQueueSurvivesNeverEchoingPeer 對端永不回顯時，已排隊的輪次仍須留痕。
//
// 誠實邊界：**第一輪**（走既有 echo 重建路徑的那一輪）在沒有任何回顯時取不到文字，
// 這是「指令文字取自 echo」的原理性邊界，不在本 change 射程內
// （proposal Non-Goals 已列）。本測試釘的是排隊的那些輪次不因對端沉默而消失。
func TestReplayQueueSurvivesNeverEchoingPeer(t *testing.T) {
	parser, commands := newTestParser()
	parser.WriteOutput([]byte(promptFrame))

	parser.WriteInput([]byte("echo A\recho B\recho C\r"))
	// 對端一個位元組都不回

	parser.Flush()

	assertCommands(t, *commands, []string{"echo B", "echo C"})
	if !parser.replayFellBack {
		t.Error("以輸入錨結算卻未設可觀測旗標：降級必須留下訊號")
	}
}

// TestReplayQueueNeverEmitsUnsentBytes 捏造防線：尾端沒有 Enter 的殘段從未送出，
// 不得進審計。與 abortTyping 同一條紀律。
func TestReplayQueueNeverEmitsUnsentBytes(t *testing.T) {
	parser, commands := newTestParser()
	parser.WriteOutput([]byte(promptFrame))

	parser.WriteInput([]byte("echo A\rsecret-not-sent"))
	parser.Flush()

	for _, got := range *commands {
		if strings.Contains(got, "secret-not-sent") {
			t.Errorf("未送出的位元組進了審計：commands = %v", *commands)
		}
	}
}

// === 重放段內的既有語義（獨立驗收指出原為靜態推論，此處補實跑）===

const (
	// **中斷鍵在重放段內的行為：實測過，但刻意不寫成測試。**
	// 靶機實跑（scenario ctrlc）送 `sleep 3\r` ＋ `\x03echo X\r`，結果有兩點出乎預期：
	//   1. 遠端執行的是 `cho X` 不是 `echo X`——Ctrl-C 中斷時 readline 吃掉了下一個字元。
	//   2. `sleep 3` **在遠端根本沒執行**（4ms 就回應，無 3 秒延遲），整行被 Ctrl-C 取消。
	// 於是該場景只會產生一筆紀錄，而**把修法改回「整段丟棄」時它同樣產生那一筆**
	// （中斷鍵後的 echo 落在前一輪尚未結算的 typingBuf 裡，誤打誤撞被結算）。
	// 一條在正確與錯誤實作下都綠的測試沒有守衛價值，只是噪音——故不寫。
	// 實跑輸出存於 `openspec/changes/command-audit-pending-queue/evidence.md`。

	// multiEnter1..4 同幀多個 Enter（空輪）夾在兩條指令之間（實測 scenario multienter）。
	// 注意第三幀是**被切斷的提示符**（`sh-test-server:~$`）——真實封包不照語義邊界切。
	multiEnter1 = "echo A\r\n\x1b[?2004l\r"
	multiEnter2 = "A\r\n\x1b[?2004hssh-test-server:~$ \r\n\x1b[?2004l\r\x1b[?2004hs"
	multiEnter3 = "sh-test-server:~$ \r\n\x1b[?2004l\r"
	// 第 4 幀更極端：**整幀只有一個控制序列、一個可見字元都沒有**。
	// 早期版本的測試把它併進第 5 幀省略掉了，與 evidence.md 不一致——
	// 那正是「用理想化序列取代實測序列」的失真，故補回逐字餵入。
	multiEnter4 = "\x1b[?2004h"
	multiEnter5 = "ssh-test-server:~$ echo B\r\n\x1b[?2004l\rB\r\n\x1b[?2004hssh-test-server:~$ "
)

// TestPendingQueueEmptyEnterRoundsSkipped 夾在指令之間的空 Enter 不得產生假紀錄，
// 也不得把其後的真指令吃掉。
func TestPendingQueueEmptyEnterRoundsSkipped(t *testing.T) {
	parser, commands := newTestParser()
	parser.WriteOutput([]byte(promptFrame))

	parser.WriteInput([]byte("echo A\r\r\recho B\r"))
	parser.WriteOutput([]byte(multiEnter1))
	parser.WriteOutput([]byte(multiEnter2))
	parser.WriteOutput([]byte(multiEnter3))
	parser.WriteOutput([]byte(multiEnter4))
	parser.WriteOutput([]byte(multiEnter5))

	assertCommands(t, *commands, []string{"echo A", "echo B"})
}

// === 情境 4 的真因:同幀內召回 echo 被當成 tail 丟棄（對抗輪實跑撈出）===
//
// 對抗輪真 WS 實跑：pending 期間上鍵召回帶副作用的指令，20 輪約 15% 漏記。
// 靶機（echocap s4）撈出真因——當 f1 的 echo、執行結果、召回輪的 echo **落在同一個
// 輸出幀**時，`appendPending` 正常輪 finalize 後把同幀剩餘（含召回 echo）appendTail
// 丟進閒置緩衝，才 drainReplay 開召回輪的 pending，於是召回輪永遠等不到自己的回顯。
// 分幀落點決定漏不漏，故間歇。
//
// 下列常數為 echocap s4 的**單幀實測**（2026-08-19，ssh-test 靶機）。

const (
	// s4Prompt 前置提示符
	s4Prompt = "\x1b[?2004hssh-test-server:~$ "
	// s4SingleFrame f1 的 echo ＋ 執行結果 ＋ 召回輪的 echo ＋ 召回執行結果，全在一幀
	s4SingleFrame = "echo s4x$((20+22)); echo m >> /tmp/echocap_s4\r\n" +
		"\x1b[?2004l\rs4x42\r\n" +
		"\x1b[?2004hssh-test-server:~$ echo s4x$((20+22)); echo m >> /tmp/echocap_s4\r\n" +
		"\x1b[?2004l\rs4x42\r\n" +
		"\x1b[?2004hssh-test-server:~$ "
)

// TestPendingQueueRecallEchoInSameFrame 召回輪的 echo 與前一輪同幀時仍須留痕。
//
// 遠端執行了兩次（f1 直接一次、上鍵召回一次），審計必須有兩筆——否則就是
// 「執行兩次只留一條可查」，稽核據殘缺紀錄追查會漏掉真正發生過的操作。
func TestPendingQueueRecallEchoInSameFrame(t *testing.T) {
	parser, commands := newTestParser()
	parser.WriteOutput([]byte(s4Prompt))

	parser.WriteInput([]byte("echo s4x$((20+22)); echo m >> /tmp/echocap_s4\r"))
	parser.WriteInput([]byte("\x1b[A\r")) // 上鍵召回，回顯尚未返回
	parser.WriteOutput([]byte(s4SingleFrame))

	want := "echo s4x$((20+22)); echo m >> /tmp/echocap_s4"
	if len(*commands) != 2 {
		t.Fatalf("結算筆數 = %d，want 2（召回輪漏記＝執行兩次只留一條）\n實得：%q", len(*commands), *commands)
	}
	for i, got := range *commands {
		if strings.TrimSpace(got) != want {
			t.Errorf("第 %d 筆 = %q, want %q", i+1, got, want)
		}
	}
}
