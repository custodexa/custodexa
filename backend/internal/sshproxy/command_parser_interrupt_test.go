package sshproxy

import (
	"strings"
	"testing"
)

// === 中斷鍵中止當輪輸入 ===
//
// Ctrl-C 不含 `\r`，在中止鍵加入前它開啟的那一輪 typing 永遠不會結算：
// shell 隨後印的 `^C`、換行與**重印的提示符**全落進同一個 typingBuf，
// 下一次按鍵不會重取原點，三條剝除規則同時落空，
// 入庫的就是「提示符＋下一條指令」這種使用者從未輸入過的字串
// （實錄 ctrl-c 情境曾入庫 `ssh-test-server:~$ exit`）。
//
// 這一組測試守三個面向：
//   - 正面：中斷之後下一條指令必須乾淨結算（無提示符污染）
//   - 反面：被中斷的那一輪打字內容**不得以任何形式**進審計
//     （否則只是把「提示符污染」換成另一種偽證）
//   - 對抗：中斷鍵之後、**同一幀內**的指令仍須進審計（本檔後半的同幀規避段）。
//     封包切分由使用者控制，任何「這樣切就不留痕」的形態都是規避路徑，不是精度問題。

const interruptTestPrompt = "ssh-test-server:~$ " // 19 欄，與實錄語料同形

// interruptEcho 模擬 Ctrl-C 的伺服器回顯：`^C`、換行、重印提示符。
// 拆成三次 WriteOutput 是照著 ssh-capture ctrl-c 情境的原始 chunk 邊界。
func interruptEcho(p *CommandParser) {
	p.WriteOutput([]byte("^C"))
	p.WriteOutput([]byte("\r\n"))
	p.WriteOutput([]byte(interruptTestPrompt))
}

// assertNoFabrication 斷言所有結算值都不含指定片段。
// 只驗「最後一條等於期望值」是不夠的——偽證可能落在任何一條上。
func assertNoFabrication(t *testing.T, commands []string, forbidden ...string) {
	t.Helper()
	for _, cmd := range commands {
		for _, frag := range forbidden {
			if strings.Contains(cmd, frag) {
				t.Errorf("入庫了不該出現的片段 %q：指令=%q\n  全部結算值=%#v", frag, cmd, commands)
			}
		}
	}
}

// TestCommandParserCtrlCAbortedInputNeverReachesAudit 是任務 A 的核心釘死：
// 使用者打了一半的危險指令按 Ctrl-C 中止、改打別的指令，
// 入庫的必須只有真正送出的那一條，且**全庫查不到**被中止的片段。
//
// `rm -rf /tmp/x` 這一輪從未按過 Enter，它沒有被執行；
// 若它出現在審計裡，稽核會看到一條根本沒發生過的破壞性操作。
func TestCommandParserCtrlCAbortedInputNeverReachesAudit(t *testing.T) {
	const aborted = "rm -rf /tmp/x"

	parser, commands := newTestParser()
	parser.WriteOutput([]byte(interruptTestPrompt))

	// 打一半的危險指令（逐字回顯），不按 Enter
	parser.WriteInput([]byte(aborted))
	parser.WriteOutput([]byte(aborted))

	// Ctrl-C 中止
	parser.WriteInput([]byte("\x03"))
	interruptEcho(parser)

	// 改打 ls 並送出
	parser.WriteInput([]byte("ls"))
	parser.WriteOutput([]byte("ls"))
	parser.WriteInput([]byte("\r"))
	parser.WriteOutput([]byte("\r\n"))
	parser.Flush()

	if len(*commands) != 1 || (*commands)[0] != "ls" {
		t.Fatalf("commands = %#v, want [\"ls\"]", *commands)
	}
	assertNoFabrication(t, *commands, "rm -rf", "rm", "/tmp/x", "^C", interruptTestPrompt)
}

// TestCommandParserCtrlCAtIdlePromptDoesNotPolluteNextCommand 重現實錄 ctrl-c 情境的形態：
// 指令**已送出並開始執行**，使用者按 Ctrl-C 中斷的是行程（此時解析器處於閒置、
// 游標確實在行首，快照到的原點正確地是空字串），接著打收尾指令。
//
// 這一筆與上一筆的差別在於中斷發生的時點（閒置 vs 打字中），
// 兩條路徑都會經過 beginTyping → 中止，缺一不可。
func TestCommandParserCtrlCAtIdlePromptDoesNotPolluteNextCommand(t *testing.T) {
	parser, commands := newTestParser()
	parser.WriteOutput([]byte(interruptTestPrompt))

	// sleep 100 + Enter：指令完整送出，必須入庫
	parser.WriteInput([]byte("sleep 100"))
	parser.WriteOutput([]byte("sleep 100"))
	parser.WriteInput([]byte("\r"))
	parser.WriteOutput([]byte("\r\n\x1b[?2004l\r"))

	// Ctrl-C 中斷執行中的 sleep：此刻解析器已回到閒置
	parser.WriteInput([]byte("\x03"))
	interruptEcho(parser)

	// 收尾指令
	parser.WriteInput([]byte("exit\r"))
	parser.WriteOutput([]byte("exit\r\n\x1b[?2004l\r"))
	parser.Flush()

	want := []string{"sleep 100", "exit"}
	if len(*commands) != len(want) {
		t.Fatalf("commands = %#v, want %#v", *commands, want)
	}
	for i := range want {
		if (*commands)[i] != want[i] {
			t.Errorf("commands[%d] = %q, want %q（全部：%#v）", i, (*commands)[i], want[i], *commands)
		}
	}
	assertNoFabrication(t, *commands, interruptTestPrompt, "ssh-test-server", "^C")
}

// TestCommandParserEnterBeforeInterruptStillSettles 釘死優先序：
// 同一次 read 內先有 `\r` 後有 Ctrl-C 時，那一行**已經送出並執行**，
// 中斷鍵中止的是執行中的行程而非輸入行——不得因此漏記。
//
// 這一條是修法的反向護欄：若把「含中斷鍵就中止」寫成不看位置，
// 使用者按 Enter 後迅速 Ctrl-C（兩者落進同一次 read）就會讓已執行的指令消失於審計。
func TestCommandParserEnterBeforeInterruptStillSettles(t *testing.T) {
	parser, commands := newTestParser()
	parser.WriteOutput([]byte(interruptTestPrompt))

	parser.WriteInput([]byte("sleep 100"))
	parser.WriteOutput([]byte("sleep 100"))
	parser.WriteInput([]byte("\r\x03")) // Enter 與 Ctrl-C 擠在同一次 read
	parser.WriteOutput([]byte("\r\n"))
	parser.Flush()

	if len(*commands) != 1 || (*commands)[0] != "sleep 100" {
		t.Fatalf("commands = %#v, want [\"sleep 100\"]（Enter 先到就必須結算）", *commands)
	}
}

// === 同幀規避（不得存在「藏在中斷鍵後面就不留痕」的輸入切分）===
//
// WriteInput 收到的是使用者端送來的原始一幀，切分完全由使用者控制。
// 若中斷鍵之後的位元組被整批丟棄，只要把指令與 Ctrl-C 放進同一幀就能執行而不進審計。
//
// 這不是紙上推演：2026-08-16 對 ssh-test 靶機（bash+readline）實測，
// `sleep` 執行中單幀送出 "\x03echo X\r"，遠端確實印出 X——指令真的執行了。
// 本產品的存在意義是讓有權者留痕，繞過留痕即為必修（goal-charter §6）。
//
// 下面兩支測試用的回顯序列取自該次實測，不是想像的形態。

// interruptRedrawEcho 重現實測的 bash+readline 中斷回顯（shell 閒置或正在收打字時）：
// tty 先把 `^C` 回顯在游標處，readline 接著關閉 bracketed paste、`\r` 回到行首，
// 再以 cursorCol 個 \x1b[C 把游標移回原處，然後才回顯同幀其後的按鍵。
// 中斷與提示符重印之間**沒有換行**，這正是實測與「憑印象假設」差最多的一點。
func interruptRedrawEcho(cursorCol int, echoed string) string {
	return "^C\x1b[?2004l\r\x1b[?2004h" + strings.Repeat("\x1b[C", cursorCol) + echoed + "\r\n"
}

// TestCommandParserSameFrameInterruptCannotEvadeAudit 是本組的核心釘死：
// **不得存在能規避審計的輸入切分**。
//
// 使用者把 Ctrl-C 與整條指令塞進同一幀（貼上或自製客戶端即可辦到），
// 指令照常執行；審計若因此一筆都不留，等於提供了一條官方繞過路徑。
// 這裡斷言結算值「含該指令」且「不為空」——不要求乾淨，只要求查得到。
func TestCommandParserSameFrameInterruptCannotEvadeAudit(t *testing.T) {
	const injected = "rm -rf /important"

	t.Run("shell閒置", func(t *testing.T) {
		parser, commands := newTestParser()
		parser.WriteOutput([]byte(interruptTestPrompt))

		// 單幀：中斷鍵 + 指令 + Enter
		parser.WriteInput([]byte("\x03" + injected + "\r"))
		// 實測回顯：^C 之後 readline 把游標移回提示符之後（19 欄）才回顯指令
		parser.WriteOutput([]byte(interruptRedrawEcho(len(interruptTestPrompt), injected)))
		parser.WriteOutput([]byte("\x1b[?2004l\r\r\n" + interruptTestPrompt))
		parser.Flush()

		assertAudited(t, *commands, injected)
		t.Logf("shell 閒置時的結算值：%#v", *commands)
	})

	t.Run("shell忙碌", func(t *testing.T) {
		parser, commands := newTestParser()
		parser.WriteOutput([]byte(interruptTestPrompt))

		// 先送出 sleep：解析器回到閒置，tailBuf 內沒有提示符
		parser.WriteInput([]byte("sleep 100\r"))
		parser.WriteOutput([]byte("sleep 100\r\n\x1b[?2004l\r"))

		// 單幀：中斷鍵 + 指令 + Enter（實測 sleep 被殺、指令照常執行）
		parser.WriteInput([]byte("\x03" + injected + "\r"))
		// 實測回顯：tty 直接把 ^C 與後續按鍵接在同一列，bash 之後才印換行＋提示符＋自己的回顯
		parser.WriteOutput([]byte("^C" + injected + "\r\n"))
		parser.WriteOutput([]byte("\r\n" + interruptTestPrompt))
		parser.WriteOutput([]byte(injected + "\r\n\x1b[?2004l\r"))
		parser.Flush()

		assertAudited(t, *commands, injected)
		// 忙碌時原點取不到提示符，結算值會夾帶 ^C——已知且可接受的降級，
		// 使用者實際打的指令仍在字串裡，稽核做子字串比對找得到。
		t.Logf("shell 忙碌時的結算值（已知會夾帶 ^C）：%#v", *commands)
	})
}

// assertAudited 斷言至少有一條結算值含指定片段，且該條不為空。
func assertAudited(t *testing.T, commands []string, want string) {
	t.Helper()
	for _, cmd := range commands {
		if cmd != "" && strings.Contains(cmd, want) {
			return
		}
	}
	t.Errorf("執行過的指令 %q 完全沒進審計：全部結算值=%#v\n"+
		"  這是可被使用者主動觸發的規避路徑，不是精度問題", want, commands)
}

// TestCommandParserInterruptBeforeEnterStillAuditsFollowingCommand 釘死中斷鍵先到時的**兩面**：
//   - 被中止的那一輪內容不得進審計（原有保護，不可放寬）
//   - 同幀中斷鍵之後的指令仍須進審計（本次修掉的規避路徑）
//
// 這支測試的期望值在 2026-08-16 被改過一次：原本它把「同幀漏記」當成期望行為釘住，
// 理由是「漏記可查、捏造不可查」。那個取捨套錯了地方——兩個選項不是「漏記 vs 捏造」，
// 而是「完全沒紀錄 vs 帶 ^C 前綴的紀錄」，後者裡使用者實際打的指令仍在。
func TestCommandParserInterruptBeforeEnterStillAuditsFollowingCommand(t *testing.T) {
	const (
		aborted  = "rm -rf /tmp/x"
		injected = "ls -la /etc"
	)

	parser, commands := newTestParser()
	parser.WriteOutput([]byte(interruptTestPrompt))

	// 打一半（不送出）
	parser.WriteInput([]byte(aborted))
	parser.WriteOutput([]byte(aborted))

	// 中斷鍵先到，其後的指令與 Enter 擠在同一幀
	parser.WriteInput([]byte("\x03" + injected + "\r"))
	// 實測回顯：游標被移回「提示符＋已打字內容」之後才回顯新按鍵
	parser.WriteOutput([]byte(interruptRedrawEcho(len(interruptTestPrompt)+len(aborted), injected)))
	parser.WriteOutput([]byte("\x1b[?2004l\r\r\n" + interruptTestPrompt))
	parser.Flush()

	assertAudited(t, *commands, injected)
	// 被中止那一輪的字從未送出執行，任何形式的入庫都是偽證——這部分不放寬
	assertNoFabrication(t, *commands, "rm -rf", "/tmp/x", interruptTestPrompt)
	t.Logf("中斷鍵先到時的結算值（已知會夾帶 ^C 與重繪空白）：%#v", *commands)
}

// TestCommandParserAbortedRoundNeverReachesAuditAcrossFrames 是上一支的對照：
// 中斷鍵**獨立成幀**（產線實錄的形態）時，被中止的內容一樣不得入審計，
// 且下一幀的指令必須乾淨結算。
//
// 它與 TestCommandParserCtrlCAbortedInputNeverReachesAudit 的差別在於
// 下一條指令連同 Enter 一次送出（`ls\r` 同幀）——那條路徑走的是
// WriteInput 逐段迴圈的「無中斷鍵」分支，需要獨立覆蓋。
func TestCommandParserAbortedRoundNeverReachesAuditAcrossFrames(t *testing.T) {
	parser, commands := newTestParser()
	parser.WriteOutput([]byte(interruptTestPrompt))

	parser.WriteInput([]byte("abc"))
	parser.WriteOutput([]byte("abc"))

	parser.WriteInput([]byte("\x03")) // 中斷鍵獨立成幀
	interruptEcho(parser)

	parser.WriteInput([]byte("ls\r")) // 指令與 Enter 同幀
	parser.WriteOutput([]byte("ls\r\n"))
	parser.Flush()

	if len(*commands) != 1 || (*commands)[0] != "ls" {
		t.Fatalf("commands = %#v, want [\"ls\"]", *commands)
	}
	assertNoFabrication(t, *commands, "abc", "^C", interruptTestPrompt)
}

// TestCommandParserCtrlUIsNotAnInterruptKey 把中斷鍵集合的**下界**釘死。
//
// Ctrl-U（0x15）清的是行內容、輸入行本身仍在繼續，該輪原點快照依然有效。
// 若有人「順手」把它加進 interruptKeys，使用者 Ctrl-U 後重打的指令就會整條漏記——
// 這條測試會立刻轉紅。上界（不得憑猜加入 Ctrl-D／Ctrl-Z）沒有測試守得住，
// 由 interruptKeys 的註解與回報中的 backlog 承接。
func TestCommandParserCtrlUIsNotAnInterruptKey(t *testing.T) {
	if strings.ContainsRune(interruptKeys, 0x15) {
		t.Fatal("Ctrl-U(0x15) 不得列為中斷鍵：它清行但不中止輸入行")
	}

	parser, commands := newTestParser()
	parser.WriteOutput([]byte(interruptTestPrompt))

	parser.WriteInput([]byte("rm -rf /tmp/x"))
	parser.WriteOutput([]byte("rm -rf /tmp/x"))
	// Ctrl-U 的回顯：回到行首、右移到提示符之後、清到行尾
	parser.WriteInput([]byte("\x15"))
	parser.WriteOutput([]byte("\r" + strings.Repeat("\x1b[C", len(interruptTestPrompt)) + "\x1b[K"))
	parser.WriteInput([]byte("echo safe\r"))
	parser.WriteOutput([]byte("echo safe\r\n"))
	parser.Flush()

	if len(*commands) != 1 || (*commands)[0] != "echo safe" {
		t.Fatalf("commands = %#v, want [\"echo safe\"]（Ctrl-U 後重打的指令不得漏記）", *commands)
	}
	assertNoFabrication(t, *commands, "rm -rf")
}

// TestCommandParserAbortTypingResetsRoundState 釘死中止後的狀態：
// 回到閒置，且不留下任何可被下一輪誤用的殘值。
//
// 原點與 promptText 若殘留，下一輪雖會覆寫，但殘留期間任何新增的
// 早退路徑都可能拿到過期的原點去切字——那是切在錯的欄位、切出偽證的老路。
func TestCommandParserAbortTypingResetsRoundState(t *testing.T) {
	parser, commands := newTestParser()
	parser.WriteOutput([]byte(interruptTestPrompt))

	parser.WriteInput([]byte("rm -rf /tmp/x"))
	parser.WriteOutput([]byte("rm -rf /tmp/x"))
	parser.WriteInput([]byte("\x03"))

	switch {
	case parser.typing:
		t.Error("中斷後 typing 仍為 true：typing 黏住正是本次要修掉的成因")
	case parser.pending:
		t.Error("中斷後 pending 為 true：中斷鍵不得把當輪推進到待結算")
	}
	if parser.typingBuf.Len() != 0 {
		t.Errorf("中斷後 typingBuf 未清空（殘留 %d bytes）：被中止的打字內容不得留在緩衝裡",
			parser.typingBuf.Len())
	}
	if parser.originText != "" || parser.originX != 0 || parser.promptText != "" {
		t.Errorf("中斷後原點未清：originText=%q originX=%d promptText=%q",
			parser.originText, parser.originX, parser.promptText)
	}

	// Flush 不得把中止的那一輪補結算出來
	parser.Flush()
	if len(*commands) != 0 {
		t.Errorf("中止的那一輪被結算出來了：%#v", *commands)
	}
}
