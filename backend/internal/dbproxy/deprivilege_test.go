//go:build linux

package dbproxy

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/localpty"
)

// TestStartRunsCLIAsDeprivilegedUser 資料庫會話的 CLI 子程序必須以降權身分執行。
//
// 這是把「安全保證」接上「執行環境」的那一針：localpty 的降權能力若沒有在
// dbproxy.Start 被實際使用，環境不變式測得再漂亮也與 DB 會話無關。
func TestStartRunsCLIAsDeprivilegedUser(t *testing.T) {
	uid, gid, _, err := localpty.LookupUser(localpty.CLIUser)
	if err != nil {
		t.Fatalf("查不到 CLI 降權身分（backend image 需重建）: %v", err)
	}

	// 接受連線但不回應：psql 停在等待伺服端訊息，子程序穩定存活可供查驗
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("建立探針監聽失敗: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()

	conn, err := Start(Target{
		Protocol: "postgres",
		Host:     "127.0.0.1",
		Port:     ln.Addr().(*net.TCPAddr).Port,
		Username: "probe",
		Password: "probe",
	}, 80, 24)
	if err != nil {
		t.Fatalf("啟動資料庫 CLI 失敗: %v", err)
	}
	defer conn.Close()

	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", conn.Pid()))
	if err != nil {
		t.Fatalf("讀 CLI 子程序狀態失敗: %v", err)
	}
	wantUID := fmt.Sprintf("Uid:\t%d\t%d\t%d\t%d", uid, uid, uid, uid)
	wantGID := fmt.Sprintf("Gid:\t%d\t%d\t%d\t%d", gid, gid, gid, gid)
	status := string(raw)
	if !strings.Contains(status, wantUID) {
		t.Errorf("CLI 子程序未以降權身分執行，期望 %q\n%s", wantUID, uidLines(status))
	}
	if !strings.Contains(status, wantGID) {
		t.Errorf("CLI 子程序群組未降權，期望 %q\n%s", wantGID, uidLines(status))
	}
}

// TestStartWiresPasswordPromptInjection 憑證面的同型一針：憑證已不進子程序環境，
// 若 Start 沒把提示注入器接上，password 認證的資料庫會話會停在使用者答不出來的
// 密碼提示（且該提示會被濾除，症狀是「開籤後畫面空白」）。
// 與 TestStartRunsCLIAsDeprivilegedUser 同理——能力存在於 localpty 但沒被用上，等同沒有。
func TestStartWiresPasswordPromptInjection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("建立探針監聽失敗: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	withPassword, err := Start(Target{
		Protocol: "postgres", Host: "127.0.0.1", Port: port,
		Username: "probe", Password: "probe",
	}, 80, 24)
	if err != nil {
		t.Fatalf("啟動資料庫 CLI 失敗: %v", err)
	}
	defer withPassword.Close()
	if !withPassword.HasPasswordPrompt() {
		t.Error("有密碼的資料庫會話未接上 PTY 提示注入器（憑證已不在環境，會話將停在密碼提示）")
	}

	noPassword, err := Start(Target{
		Protocol: "postgres", Host: "127.0.0.1", Port: port, Username: "probe",
	}, 80, 24)
	if err != nil {
		t.Fatalf("啟動無密碼資料庫 CLI 失敗: %v", err)
	}
	defer noPassword.Close()
	if noPassword.HasPasswordPrompt() {
		t.Error("無密碼時不應武裝提示注入（無密碼可注入，武裝只會多出誤判面）")
	}
}

func uidLines(status string) string {
	var out []string
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, "Uid:") || strings.HasPrefix(line, "Gid:") ||
			strings.HasPrefix(line, "Groups:") {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}
