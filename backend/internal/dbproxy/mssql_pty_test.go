package dbproxy

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/localpty"
)

// 本檔為**對真實 sqlcmd 二進位**的實測，不是對我方程式碼的單元測試。
// 目的是把兩件只能實測的事釘死：
//
//  1. 提示字串真的是 `Password:`（無尾隨空白）——它是 PTY 注入器唯一的觸發條件，
//     錯一個字元就是注入永不觸發、會話無聲斷線。
//  2. 真憑證確實沒有進入子程序——直接讀該子程序的 /proc/<pid>/cmdline 與 environ
//     核對，而不是只檢查我方組出的 argv／env（後者只證明我們沒傳，不證明子程序沒有）。
//
// sqlcmd 在**連線之前**就會索取密碼，故本測試不需要 MSSQL 靶機。
// 缺二進位或非 Linux 一律 skip（開發者本機直跑 go test 時）。
func TestMSSQLRealBinaryPromptAndCredentialIsolation(t *testing.T) {
	if _, err := exec.LookPath("sqlcmd"); err != nil {
		t.Skip("映像內無 sqlcmd 二進位，跳過實測")
	}
	if _, err := os.Stat("/proc/self/cmdline"); err != nil {
		t.Skip("非 Linux（無 procfs），跳過實測")
	}

	const secret = "Str0ng-P@ssw0rd-For-Leak-Check"
	target := Target{
		Protocol: "mssql",
		// 不可路由的位址：即使密碼階段之後才連線，也不會真的打到任何東西
		Host: "192.0.2.1", Port: 1433,
		Username: "sa", Password: secret,
	}

	prog, args, env, err := BuildCommand(target, "")
	if err != nil {
		t.Fatalf("BuildCommand: %v", err)
	}
	// **刻意不帶 Options.User（不降權）**：正式路徑會降權為 dbcli，但行程一改變
	// uid 後核心即清掉 dumpable 旗標，此後讀它的 /proc/<pid>/environ 需要
	// CAP_SYS_PTRACE——而容器預設不給該 capability，連容器內的 root 都讀不到
	//（實測為 EACCES，且 cmdline 讀出空字串）。那個現象本身是降權的加分項，
	// 卻使本測試要驗的東西無法觀測。故此處以相同的 prog/args/env 起未降權的
	// 子程序來讀 /proc：**憑證是否進入子程序取決於 argv 與 env 的內容，
	// 與執行身分無關**，兩條路徑用的是同一組 BuildCommand 產物。
	conn, err := localpty.StartWithOptions(prog, args, env, 80, 24,
		localpty.Options{Auth: PasswordPrompt(target)})
	if err != nil {
		t.Fatalf("啟動 sqlcmd 失敗: %v", err)
	}
	defer conn.Close()

	pid := conn.Pid()
	if pid <= 0 {
		t.Fatal("取不到子程序 pid")
	}

	// --- 憑證隔離：直接讀子程序的 argv 與環境 ---
	for _, f := range []string{"cmdline", "environ"} {
		raw, err := readProcAfterExec(pid, f, 5*time.Second)
		if err != nil {
			t.Fatalf("讀 /proc/%d/%s 失敗: %v", pid, f, err)
		}
		// procfs 以 NUL 分隔，轉成可讀形式再比對
		text := strings.ReplaceAll(string(raw), "\x00", " ")
		if strings.Contains(text, secret) {
			t.Errorf("**憑證紅線破口**：密碼出現在子程序的 %s", f)
		}
		if strings.Contains(text, "SQLCMDPASSWORD") {
			t.Errorf("子程序 %s 含 SQLCMDPASSWORD", f)
		}
		if strings.Contains(text, "SQLCMD_LANG") {
			t.Errorf("子程序 %s 含 SQLCMD_LANG（提示字串會被在地化）", f)
		}
		t.Logf("/proc/%d/%s = %q", pid, f, text)
	}

	// 注入器會把提示與回顯一併從輸出流濾除（不進錄影／監看／審計），
	// 故**掛著 Auth 時讀不到 `Password:`**——那正是預期行為，不是缺陷。
	// 此處逾時（讀不到 marker）正是預期路徑，故不檢查回傳的 found。
	withAuth, _ := readUntil(t, conn, 10*time.Second, "Password:")
	if strings.Contains(withAuth, "Password:") {
		t.Errorf("掛注入器時提示不應出現在輸出流（會落進錄影／審計）：%q", withAuth)
	}
	if strings.Contains(withAuth, secret) {
		t.Errorf("**憑證紅線破口**：密碼出現在輸出流（會落進錄影／審計）：%q", withAuth)
	}
	t.Logf("掛注入器時的輸出=%q", withAuth)
}

// 提示字串本身的實測：不掛注入器（否則會被濾掉），直接看 sqlcmd 印了什麼。
// 這是 PasswordPrompt 的 matcher 唯一的事實來源——上游改字串時本測試須先紅。
func TestMSSQLRealBinaryPromptLiteral(t *testing.T) {
	if _, err := exec.LookPath("sqlcmd"); err != nil {
		t.Skip("映像內無 sqlcmd 二進位，跳過實測")
	}

	target := Target{Protocol: "mssql", Host: "192.0.2.1", Port: 1433, Username: "sa"}
	prog, args, env, err := BuildCommand(target, "")
	if err != nil {
		t.Fatalf("BuildCommand: %v", err)
	}
	// Auth 為 nil：提示原樣流出，可逐位元組比對
	conn, err := localpty.StartWithOptions(prog, args, env, 80, 24, localpty.Options{})
	if err != nil {
		t.Fatalf("啟動 sqlcmd 失敗: %v", err)
	}
	defer conn.Close()

	const marker = "Password:"
	got, found := readUntil(t, conn, 15*time.Second, marker)
	if !found {
		t.Fatalf("等待 sqlcmd 的 %q 提示逾時（上限 15s）——提示字串可能已被上游改掉，"+
			"或 sqlcmd 根本沒索取密碼；期間累積輸出=%q", marker, got)
	}
	// 尾隨空白會使 matcher 不命中（psql 的提示有、sqlcmd 沒有）
	after := got[strings.Index(got, "Password:")+len("Password:"):]
	if strings.HasPrefix(after, " ") {
		t.Errorf("提示帶尾隨空白，PasswordPrompt 的 Prompt 須同步修正：%q", got)
	}
	// 與 PasswordPrompt 宣告的字串對齊
	want := PasswordPrompt(Target{Protocol: "mssql", Password: "x"}).Prompt
	if !strings.Contains(got, want) {
		t.Errorf("實測提示 %q 不含 PasswordPrompt 宣告的 %q", got, want)
	}
	t.Logf("實測提示輸出=%q", got)
}

// readProcAfterExec 讀 /proc/<pid>/<name>，並容忍 fork 與 execve 之間的空窗。
//
// 子程序在 execve 完成前，`/proc/<pid>/cmdline` 讀出**空字串**（`-count=3` 實測會中
// 一次）。空內容不足以宣稱「不含憑證」，故舊版直接 Fatal——但那是與真回歸長得
// 一模一樣的假紅（訊息還帶「憑證紅線」語氣），一樣會訓練人忽略本測試。
// 此處輪詢至非空為止；只有逾時仍為空才是真失敗，且訊息說明等的是什麼。
func readProcAfterExec(pid int, name string, timeout time.Duration) ([]byte, error) {
	path := "/proc/" + itoa(pid) + "/" + name
	deadline := time.Now().Add(timeout)
	for {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if len(raw) > 0 {
			return raw, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("等待子程序 execve 完成逾時（%s）：%s 持續為空，"+
				"無法據此宣稱「不含憑證」（子程序可能已結束）", timeout, path)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// readUntil 讀到出現 marker 或逾時為止，回傳累積輸出與「是否讀到 marker」。
//
// **逾時必須是牆鐘上限，不能靠迴圈頂端的 deadline 檢查**：`Conn` 沒有
// SetReadDeadline，子程序不吐位元組時 `conn.Read` 會永久阻塞，迴圈條件根本沒機會
// 再被求值。舊版即如此——提示 matcher 一旦回歸，本檔會掛死到整包 `go test` 逾時
// panic（實測 90 秒），而真正該紅的守衛 `TestMSSQLRealBinaryPromptLiteral`
// 0.07 秒就紅、紅訊息卻被那個 panic 蓋掉，讀的人會把真回歸誤判成環境問題。
// 故讀取移到獨立 goroutine，主線只等 deadline：回歸時的失敗訊號是明確斷言，
// 不是 timeout panic。goroutine 於 `conn.Close()`（各測試的 defer）後 Read 回錯而退出。
func readUntil(t *testing.T, conn *Conn, timeout time.Duration, marker string) (string, bool) {
	t.Helper()
	chunks := make(chan []byte, 256)
	go func() {
		defer close(chunks)
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				b := make([]byte, n)
				copy(b, buf[:n])
				select {
				case chunks <- b:
				default: // 主線已離開；丟棄即可，不讓本 goroutine 卡在送出上
				}
			}
			if err != nil {
				return
			}
		}
	}()

	var out strings.Builder
	deadline := time.After(timeout)
	for {
		select {
		case b, ok := <-chunks:
			if !ok { // 子程序結束／PTY 關閉
				return out.String(), strings.Contains(out.String(), marker)
			}
			out.Write(b)
			if strings.Contains(out.String(), marker) {
				return out.String(), true
			}
		case <-deadline:
			return out.String(), false
		}
	}
}

// itoa 避免為單一轉換引入 strconv 之外的相依
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
