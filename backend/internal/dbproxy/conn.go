package dbproxy

import (
	"fmt"
	"os"

	"github.com/custodexa/backend/internal/localpty"
)

// Conn 資料庫 CLI PTY 連線（實體在 localpty，此處保留型別別名供呼叫端語意清晰）
type Conn = localpty.Conn

// Start 依目標啟動資料庫 CLI 子程序並掛上 PTY（database-protocol 階段 2）。
// 憑證既不落 argv 也不進環境：CLI 子程序全程不持有真憑證，密碼在 client 開口索取的
// 那一刻由 PTY 層注入（PasswordPrompt），提示與回顯不進錄影／監看／審計。
// 子程序環境最小化由 localpty 保證。
// verify-ca/verify-full 模式：把自訂 CA 寫成暫存檔供 client 驗證，連線結束時清掉（CA 為公開憑證非機密）。
//
// CLI 子程序以專用非 root 身分執行（環境降權）：
// client 的本機能力面（`\copy … FROM`、`\i` 等讀檔類命令）維持開放，安全保證改由
// 「該身分在容器內讀不到、寫不了任何有價值的東西」承擔，不依賴輸入解析。
func Start(t Target, cols, rows int) (*Conn, error) {
	cols, rows = clampWinsize(t.Protocol, cols, rows)

	uid, gid, _, err := localpty.LookupUser(localpty.CLIUser)
	if err != nil {
		return nil, err
	}

	var caFile string
	var cleanup func()
	if (t.TLSMode == "verify-ca" || t.TLSMode == "verify-full") && t.CACert != "" {
		f, err := os.CreateTemp("", "dbproxy-ca-*.pem")
		if err != nil {
			return nil, fmt.Errorf("建立 CA 暫存檔失敗: %w", err)
		}
		if _, err := f.WriteString(t.CACert); err != nil {
			f.Close()
			os.Remove(f.Name())
			return nil, fmt.Errorf("寫入 CA 暫存檔失敗: %w", err)
		}
		f.Close()
		// CA 為公開憑證非機密，但檔案由 root 以 0600 建立，降權後的 client 讀不到：
		// 改 owner 而非放寬 mode，避免同一容器內其他身分也讀得到
		if err := os.Chown(f.Name(), uid, gid); err != nil {
			os.Remove(f.Name())
			return nil, fmt.Errorf("移交 CA 暫存檔給 CLI 執行身分失敗: %w", err)
		}
		caFile = f.Name()
		cleanup = func() { os.Remove(caFile) }
	}

	prog, args, env, err := BuildCommand(t, caFile)
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, err
	}
	conn, err := localpty.StartWithOptions(prog, args, env, cols, rows,
		localpty.Options{User: localpty.CLIUser, Auth: PasswordPrompt(t)})
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, err
	}
	if cleanup != nil {
		conn.SetOnClose(cleanup)
	}
	return conn, nil
}

// 終端尺寸的保底值（mssql 專用，見 clampWinsize）
const (
	defaultCols = 80
	defaultRows = 24
)

// clampWinsize mssql 專屬的終端尺寸保底（liner 的 winsize 前提）。
//
// sqlcmd 經 peterh/liner 讀密碼，liner 在**終端寬度為 0 時直接回錯誤且不印提示**
// （peterh/liner v1.2.2 line.go 的 getColumns 檢查）。cols／rows 來自前端查詢參數，
// 為 0 時 pty.StartWithSize 會設出 0 欄的 winsize，sqlcmd 將不印 "Password:"，
// 提示注入器永不觸發，使用者只看到一個沒有原因的斷線——是本協議最容易漏的一步。
//
// **只夾 mssql**：其餘三協議的既有行為（0 值原樣傳給 pty）不得因此改變。
func clampWinsize(protocol string, cols, rows int) (int, int) {
	if protocol != "mssql" {
		return cols, rows
	}
	if cols <= 0 {
		cols = defaultCols
	}
	if rows <= 0 {
		rows = defaultRows
	}
	return cols, rows
}
