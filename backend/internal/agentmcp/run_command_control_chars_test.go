package agentmcp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// 單行命令之外的內容不得進入會話：內嵌換行、回車、跳脫字元、tab 與其他控制字元都在去除尾端換行後被拒。
func TestRunCommandControlCharsRejected(t *testing.T) {
	cases := map[string]string{
		"embedded_lf":     "echo one\necho two",
		"embedded_cr":     "echo one\recho two",
		"embedded_crlf":   "echo one\r\necho two",
		"escape":          "echo one\x1b[D",
		"tab":             "echo\tone",
		"other_control":   "echo one\x01",
		"leading_newline": "\necho one",
	}
	for name, command := range cases {
		t.Run(name, func(t *testing.T) {
			e, bytes, _ := terminalFixture(t, func(string, int) string { return "user$ " })
			r := op(t, e, "run_command", map[string]any{"command": command, "timeout_seconds": 1})
			v := object(t, r)
			require.True(t, r.IsError, resultText(r))
			require.Equal(t, "VALIDATION_BAD_REQUEST", v["code"], resultText(r))
			time.Sleep(50 * time.Millisecond)
			require.EqualValues(t, 0, bytes.Load(), "被拒的命令不得寫入會話")
		})
	}
}

// 單行命令（可帶尾端換行）照常送入。
func TestRunCommandControlCharsSingleLineAccepted(t *testing.T) {
	for _, command := range []string{"echo one", "echo one\n", "echo one\r\n"} {
		t.Run(command, func(t *testing.T) {
			e, _, _ := terminalFixture(t, func(data string, _ int) string {
				require.Equal(t, "echo one\r", data)
				return "one\r\nuser$ "
			})
			r := op(t, e, "run_command", map[string]any{"command": command, "timeout_seconds": 1})
			v := object(t, r)
			require.Equal(t, "completed", v["status"], resultText(r))
		})
	}
}
