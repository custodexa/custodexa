package sshproxy

import (
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/apierror"
)

// 改連守衛對 ESC 序列與括號貼上標記的處理：只轉送游標與編輯類標準序列，
// 其餘 ESC 序列與括號貼上標記不轉送；守衛的行內容與子程序端的當前輸入行保持一致。

var guardedProtocols = []string{"mysql", "redis", "mssql"}

// filterFrames 依序把各幀交給守衛，回傳轉送內容的串接；任一幀被攔下即回傳該次攔截。
func filterFrames(g *reconnectGuard, frames ...string) (string, *reconnectBlock) {
	var out []byte
	for _, f := range frames {
		fwd, blk := g.Filter([]byte(f))
		out = append(out, fwd...)
		if blk != nil {
			return string(out), blk
		}
	}
	return string(out), nil
}

// simpleLineEditor 以最小的行編輯語義（可印字元累積、Backspace 退一字元）還原轉送內容
// 在子程序端的當前輸入行；轉送內容不得含 ESC。
func simpleLineEditor(t *testing.T, fwd string) string {
	t.Helper()
	var cur []byte
	for i := 0; i < len(fwd); i++ {
		switch c := fwd[i]; {
		case c == 0x1b:
			t.Fatalf("轉送內容不應含 ESC：%q", fwd)
		case c == 0x7f || c == 0x08:
			if len(cur) > 0 {
				cur = cur[:len(cur)-1]
			}
		case c >= 0x20:
			cur = append(cur, c)
		}
	}
	return string(cur)
}

// rawInput 子程序 stdin 收到的全部位元組。
func (c *fakeCLI) rawInput() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var all []byte
	for _, w := range c.raw {
		all = append(all, w...)
	}
	return string(all)
}

// ── 非游標類 ESC 序列不轉送 ─────────────────────────────────────────────

func TestReconnectGuardEscapeSequencesNotForwarded(t *testing.T) {
	var inputs []string
	for c := byte(0x20); c <= 0x7e; c++ {
		switch c {
		case '[', 'O', ']', 'P', '_', '^', 'X':
			continue
		}
		inputs = append(inputs, "ab\x1b"+string(c)+"cd")
	}
	inputs = append(inputs,
		"ab\x1b1\x1b#cd",
		"ab\x1b\x1b#cd",
		"ab\x1b[2~cd",     // 不在轉送清單內的 CSI
		"ab\x1b[200~cd",   // 括號貼上開始標記
		"ab\x1b[201~cd",   // 括號貼上結束標記
		"ab\x1b[?2004hcd", // 私有參數
		"ab\x1b[1;5Zcd",   // 未知結尾
		"ab\x1b[1;2;3Acd", // 多餘參數
		"ab\x1b[5Acd",     // 方向鍵帶非標準參數
		"ab\x1bOxcd",      // 未知 SS3
		"ab\x1b]0;title\x07cd",
		"ab\x1b]0;title\x1b\\cd",
		"ab\x1bPq#0\x1b\\cd",
		"ab\x1b_x\x1b\\cd",
	)
	for _, p := range guardedProtocols {
		for _, in := range inputs {
			g := newReconnectGuard(p, nil, 0, 0, 0)
			fwd, blk := filterFrames(g, in)
			if blk != nil {
				t.Fatalf("%s %q：不應攔截", p, in)
			}
			if fwd != "abcd" {
				t.Fatalf("%s %q：轉送內容 = %q, want %q", p, in, fwd, "abcd")
			}
			if string(g.line) != "abcd" || g.unsynced {
				t.Fatalf("%s %q：守衛行 = %q unsynced=%v", p, in, g.line, g.unsynced)
			}
			if d, want := string(g.takeDiscarded()), in[2:len(in)-2]; d != want {
				t.Fatalf("%s %q：不轉送序列 = %q, want %q", p, in, d, want)
			}
		}
	}
}

func TestReconnectGuardEscapeSequenceAcrossFrames(t *testing.T) {
	g := newReconnectGuard("mysql", nil, 0, 0, 0)
	fwd, blk := filterFrames(g, "#select 1", "\x1b", "1", "\x1b", "#")
	if blk != nil || fwd != "#select 1" {
		t.Fatalf("轉送內容 = %q（攔截 %v），want %q", fwd, blk, "#select 1")
	}
	// ESC 後接控制字元：只捨棄 ESC，控制字元照常處理
	g = newReconnectGuard("mysql", nil, 0, 0, 0)
	fwd, blk = filterFrames(g, "SELECT 1;\x1b", "\r")
	if blk != nil || fwd != "SELECT 1;\r" {
		t.Fatalf("轉送內容 = %q（攔截 %v），want %q", fwd, blk, "SELECT 1;\r")
	}
	// 字串型序列跨幀
	g = newReconnectGuard("redis", nil, 0, 0, 0)
	fwd, _ = filterFrames(g, "a\x1b]0;x", "y\x1b", "\\b")
	if fwd != "ab" {
		t.Fatalf("轉送內容 = %q, want %q", fwd, "ab")
	}
}

func TestReconnectGuardNoEscapeReachesCLI(t *testing.T) {
	for _, p := range guardedProtocols {
		t.Run(p, func(t *testing.T) {
			r := newReconnectRig(t, p, "human", rigOpts{})
			r.send("#select 1")
			r.send("\x1b1\x1b#")
			r.send("\x1bb\x1b.\x1b\x7f")
			r.send("\x03")
			r.settle(t)
			if raw := r.cli.rawInput(); strings.ContainsRune(raw, 0x1b) {
				t.Fatalf("子程序 stdin 收到 ESC 序列：%q", raw)
			}
			// 不轉送的序列仍進鍵盤紀錄的 blocked 旁路
			if _, blocked, _ := r.ks.snapshot(); !strings.Contains(blocked, "\x1b1\x1b#") || !strings.Contains(blocked, "\x1bb\x1b.\x1b") {
				t.Fatalf("鍵盤紀錄 blocked 旁路缺不轉送的序列：%q", blocked)
			}
		})
	}
}

// ── 括號貼上標記不轉送；守衛行與子程序端一致 ──────────────────────────────

func TestReconnectGuardPasteMarkersStripped(t *testing.T) {
	cases := [][]string{
		{"connecXY\x1b[200~\x7f\x7f\x7f\x7ft 203.0.113.5"},
		{"connecXY", "\x1b[200~", "\x7f\x7f\x7f\x7f", "t 203.0.113.5"},
		{"conn\x1b[200~", "ecX\x7f\x1b[201~", "\x7f\x1b[201~t h"},
		{"\x1b[200~select 1\x1b[201~\x7f\x7f"},
		{"ab\x1b[20", "0~\x7fc\x1b[2", "01~d"},
	}
	for _, p := range guardedProtocols {
		for _, frames := range cases {
			g := newReconnectGuard(p, nil, 0, 0, 0)
			fwd, blk := filterFrames(g, frames...)
			if blk != nil {
				t.Fatalf("%s %q：Enter 前不應攔截", p, frames)
			}
			if got, want := string(g.line), simpleLineEditor(t, fwd); got != want || g.unsynced {
				t.Fatalf("%s %q：守衛行 %q 與子程序端 %q 不一致（unsynced=%v）", p, frames, got, want, g.unsynced)
			}
		}
	}
}

func TestReconnectGuardPasteMarkersWithBackspace(t *testing.T) {
	for _, entry := range []string{"human", "agent"} {
		t.Run(entry+"/含改連的行被攔", func(t *testing.T) {
			r := newReconnectRig(t, "mysql", entry, rigOpts{})
			r.send("connecXY")
			r.send("\x1b[200~")
			r.send("\x7f\x7f")
			r.send("\x1b[201~")
			r.send("t testdb 203.0.113.5\r")
			r.settle(t)
			assertNoConnectExecuted(t, r)
			rcWaitFor(t, "終端收到警告幀", func() bool { return len(r.log.noticeCodes()) > 0 })
			if codes := r.log.noticeCodes(); codes[0] != string(apierror.CodeDBReconnectBlocked) {
				t.Fatalf("警告碼 = %v, want %s", codes, apierror.CodeDBReconnectBlocked)
			}
		})
	}
	t.Run("子程序端執行的行與守衛判定的行相同", func(t *testing.T) {
		r := newReconnectRig(t, "mysql", "human", rigOpts{})
		r.send("connecXY\x1b[200~\x7f\x7f\x7f\x7ft testdb 203.0.113.5\r")
		r.settle(t)
		got := r.executedExcludingSettle()
		if len(got) != 1 || got[0] != "connt testdb 203.0.113.5" {
			t.Fatalf("執行過的行 = %q, want [connt testdb 203.0.113.5]", got)
		}
		if raw := r.cli.rawInput(); strings.ContainsRune(raw, 0x1b) {
			t.Fatalf("子程序 stdin 收到 ESC 序列：%q", raw)
		}
	})
}

// ── 游標與編輯類標準序列照常轉送 ────────────────────────────────────────

func TestReconnectGuardCursorKeysForwarded(t *testing.T) {
	seqs := []string{
		"\x1b[A", "\x1b[B", "\x1b[C", "\x1b[D", "\x1b[H", "\x1b[F",
		"\x1bOA", "\x1bOB", "\x1bOC", "\x1bOD", "\x1bOH", "\x1bOF",
		"\x1b[1~", "\x1b[3~", "\x1b[4~", "\x1b[5~", "\x1b[6~", "\x1b[7~", "\x1b[8~",
		"\x1b[1;5C", "\x1b[1;5D", "\x1b[1;3A", "\x1b[3;5~",
	}
	for _, p := range guardedProtocols {
		for _, seq := range seqs {
			g := newReconnectGuard(p, nil, 0, 0, 0)
			fwd, blk := filterFrames(g, "SELECT 1"+seq)
			if blk != nil || fwd != "SELECT 1"+seq {
				t.Fatalf("%s %q：轉送內容 = %q（攔截 %v）", p, seq, fwd, blk)
			}
			if !g.unsynced {
				t.Fatalf("%s %q：轉送游標序列後該行應為無法確定", p, seq)
			}
			// 跨幀拆開的序列同樣轉送
			g = newReconnectGuard(p, nil, 0, 0, 0)
			fwd, _ = filterFrames(g, seq[:2], seq[2:])
			if fwd != seq {
				t.Fatalf("%s %q：跨幀轉送內容 = %q", p, seq, fwd)
			}
		}
	}
	for _, p := range guardedProtocols {
		t.Run(p+"/方向鍵送達子程序", func(t *testing.T) {
			r := newReconnectRig(t, p, "human", rigOpts{})
			r.send("\x1b[A\x1b[D\x1bOH\x1b[F\x03")
			r.settle(t)
			if raw := r.cli.rawInput(); !strings.Contains(raw, "\x1b[A\x1b[D\x1bOH\x1b[F") {
				t.Fatalf("方向鍵與 Home／End 應原樣送達子程序，實得 %q", raw)
			}
		})
	}
}
