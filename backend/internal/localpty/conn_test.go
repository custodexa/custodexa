package localpty

import (
	"os"
	"strings"
	"testing"
	"time"
)

// readUntil 從 conn 讀到包含 want 或逾時，回傳累積輸出
func readUntil(t *testing.T, c *Conn, want string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var sb strings.Builder
	buf := make([]byte, 4096)
	for time.Now().Before(deadline) {
		n, err := c.ptmx.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
			if strings.Contains(sb.String(), want) {
				return sb.String()
			}
		}
		if err != nil {
			break
		}
	}
	return sb.String()
}

func TestStartEchoRoundtrip(t *testing.T) {
	// Arrange & Act：以 sh 驗證 PTY 雙向流（與資料庫/kubectl CLI 同一路徑）
	conn, err := Start("/bin/sh", []string{"-c", "echo pty-ready; cat"}, nil, 80, 24)
	if err != nil {
		t.Fatalf("Start 失敗: %v", err)
	}
	defer conn.Close()

	// Assert：讀到啟動輸出
	out := readUntil(t, conn, "pty-ready", 3*time.Second)
	if !strings.Contains(out, "pty-ready") {
		t.Fatalf("未讀到啟動輸出, got: %q", out)
	}

	// Act：寫入經 cat 回顯
	if _, err := conn.Write([]byte("marker-123\n")); err != nil {
		t.Fatalf("Write 失敗: %v", err)
	}
	out = readUntil(t, conn, "marker-123", 3*time.Second)
	if !strings.Contains(out, "marker-123") {
		t.Fatalf("未讀到回顯, got: %q", out)
	}
}

func TestStartEnvMinimal(t *testing.T) {
	// Arrange：後端程序環境放一個機密哨兵，子程序不得繼承
	const sentinel = "LOCALPTY_TEST_SECRET"
	os.Setenv(sentinel, "leak-me")
	defer os.Unsetenv(sentinel)

	conn, err := Start("/bin/sh", []string{"-c", "env; echo env-done"}, []string{"CRED_VAR=ok"}, 80, 24)
	if err != nil {
		t.Fatalf("Start 失敗: %v", err)
	}
	defer conn.Close()

	out := readUntil(t, conn, "env-done", 3*time.Second)

	// Assert：哨兵不得洩入，注入的憑證變數必須在
	if strings.Contains(out, sentinel) {
		t.Errorf("後端環境變數洩入子程序: %q", out)
	}
	if !strings.Contains(out, "CRED_VAR=ok") {
		t.Errorf("注入的憑證變數未生效, got: %q", out)
	}
}

func TestWindowChangeAndClose(t *testing.T) {
	conn, err := Start("/bin/sh", []string{"-c", "cat"}, nil, 80, 24)
	if err != nil {
		t.Fatalf("Start 失敗: %v", err)
	}

	// Act & Assert：resize 不出錯
	if err := conn.WindowChange(40, 120); err != nil {
		t.Errorf("WindowChange 失敗: %v", err)
	}

	// Close 後子程序應被回收（不留殭屍）；重複 Close 不 panic
	conn.Close()
	conn.Close()
}

// TestParseSystemID uid/gid 解析的值域邊界（CodeQL #29/#30 的 32 位元平台假設）。
//
// **邊界必須以純函式測**：LookupUser 走真實 `user.Lookup`，超界的 uid 無法從
// 系統帳號注入，邊界那兩格在整合層根本走不到；把解析抽出來，2^31-1／2^31
// 就成為可逐格斷言的兩行。
func TestParseSystemID(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  int
		ok    bool
	}{
		{"一般系統帳號", "65123", 65123, true},
		{"root", "0", 0, true},
		{"上界內最大值 2^31-1", "2147483647", 2147483647, true},
		{"超界 2^31 落入 fail-close", "2147483648", 0, false},
		{"某些系統的 nobody（4294967294）超界", "4294967294", 0, false},
		{"負值不受理", "-1", 0, false},
		{"非數值不受理", "dbcli", 0, false},
		{"空字串不受理", "", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSystemID(tc.input)
			if tc.ok {
				if err != nil {
					t.Fatalf("parseSystemID(%q) 回錯 %v, want %d", tc.input, err, tc.want)
				}
				if got != tc.want {
					t.Errorf("parseSystemID(%q) = %d, want %d", tc.input, got, tc.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("parseSystemID(%q) = %d, want 錯誤（fail-close）", tc.input, got)
			}
		})
	}
}
