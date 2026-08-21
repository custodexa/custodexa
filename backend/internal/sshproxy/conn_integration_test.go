package sshproxy

import (
	"errors"
	"golang.org/x/crypto/ssh"
	"os"
	"strings"
	"testing"
	"time"
)

// 整合測試對 docker-compose 內的 ssh-test 容器執行。
// 在 backend 容器內跑時 host 為 ssh-test、port 2222；
// 設定 SSH_TEST_HOST/SSH_TEST_PORT 可覆寫。未設定且容器不可達時跳過。
func sshTestTarget(t *testing.T) (string, int) {
	t.Helper()

	host := os.Getenv("SSH_TEST_HOST")
	if host == "" {
		host = "ssh-test"
	}
	port := 2222
	return host, port
}

func dialTestServer(t *testing.T, cols, rows int) *SSHConn {
	t.Helper()

	host, port := sshTestTarget(t)
	conn, err := Dial(ConnConfig{
		HostKey:  ssh.InsecureIgnoreHostKey(),
		Host:     host,
		Port:     port,
		Username: "testuser",
		Password: "testpass123",
		Cols:     cols,
		Rows:     rows,
	})
	if err != nil {
		if errors.Is(err, ErrUnreachable) || errors.Is(err, ErrDialTimeout) {
			t.Skipf("ssh-test 容器不可達，跳過整合測試: %v", err)
		}
		t.Fatalf("Dial 失敗: %v", err)
	}

	t.Cleanup(conn.Close)
	return conn
}

// readUntil 持續讀取輸出直到出現關鍵字或逾時
func readUntil(t *testing.T, conn *SSHConn, keyword string, timeout time.Duration) string {
	t.Helper()

	var sb strings.Builder
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 4096)

	for time.Now().Before(deadline) {
		n, err := conn.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
			if strings.Contains(sb.String(), keyword) {
				return sb.String()
			}
		}
		if err != nil {
			break
		}
	}
	return sb.String()
}

func TestIntegrationDialAndEcho(t *testing.T) {
	// Arrange
	conn := dialTestServer(t, 80, 24)

	// Act：等 shell prompt 就緒後執行指令
	readUntil(t, conn, "$", 10*time.Second)
	if _, err := conn.Write([]byte("echo integration-ok\r")); err != nil {
		t.Fatalf("Write 失敗: %v", err)
	}
	output := readUntil(t, conn, "integration-ok", 10*time.Second)

	// Assert
	if !strings.Contains(output, "integration-ok") {
		t.Errorf("輸出未包含指令結果, got: %q", output)
	}
}

func TestIntegrationWindowChange(t *testing.T) {
	// Arrange
	conn := dialTestServer(t, 80, 24)
	readUntil(t, conn, "$", 10*time.Second)

	// Act：改變視窗尺寸後以 stty size 驗證 PTY 已更新
	if err := conn.WindowChange(50, 200); err != nil {
		t.Fatalf("WindowChange 失敗: %v", err)
	}
	if _, err := conn.Write([]byte("stty size\r")); err != nil {
		t.Fatalf("Write 失敗: %v", err)
	}
	output := readUntil(t, conn, "50 200", 10*time.Second)

	// Assert
	if !strings.Contains(output, "50 200") {
		t.Errorf("stty size 未回報新尺寸, got: %q", output)
	}
}

func TestIntegrationAuthFailed(t *testing.T) {
	// Arrange
	host, port := sshTestTarget(t)

	// Act
	_, err := Dial(ConnConfig{
		HostKey:  ssh.InsecureIgnoreHostKey(),
		Host:     host,
		Port:     port,
		Username: "testuser",
		Password: "wrong-password",
		Cols:     80,
		Rows:     24,
	})

	// Assert
	if errors.Is(err, ErrUnreachable) || errors.Is(err, ErrDialTimeout) {
		t.Skipf("ssh-test 容器不可達，跳過整合測試: %v", err)
	}
	if !errors.Is(err, ErrAuthFailed) {
		t.Errorf("錯誤分類 = %v, want ErrAuthFailed", err)
	}
}

func TestIntegrationUnreachable(t *testing.T) {
	// Act：RFC 5737 測試位址不可路由，驗證逾時/不可達分類
	_, err := Dial(ConnConfig{
		HostKey:  ssh.InsecureIgnoreHostKey(),
		Host:     "192.0.2.1",
		Port:     22,
		Username: "testuser",
		Password: "testpass123",
		Cols:     80,
		Rows:     24,
	})

	// Assert
	if !errors.Is(err, ErrDialTimeout) && !errors.Is(err, ErrUnreachable) {
		t.Errorf("錯誤分類 = %v, want ErrDialTimeout 或 ErrUnreachable", err)
	}
}

func TestDialNoCredentials(t *testing.T) {
	// Act：未提供任何憑證應在 Dial 前即拒絕
	_, err := Dial(ConnConfig{Host: "ssh-test", Port: 2222, Username: "testuser", Cols: 80, Rows: 24, HostKey: ssh.InsecureIgnoreHostKey()})

	// Assert
	if err == nil || !strings.Contains(err.Error(), "未設定可用憑證") {
		t.Errorf("錯誤 = %v, want 含「未設定可用憑證」", err)
	}
}

func TestDialRejectsMissingHostKeyCallback(t *testing.T) {
	_, err := Dial(ConnConfig{Host: "ssh-test", Port: 2222, Username: "testuser", Password: "x", Cols: 80, Rows: 24})
	if err == nil || !strings.Contains(err.Error(), "host key") {
		t.Errorf("nil HostKey must fail closed, got %v", err)
	}
}
