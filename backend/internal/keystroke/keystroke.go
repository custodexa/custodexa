// Package keystroke 保存終端型會話中「平台已轉送出去」的使用者輸入。
//
// 檔案格式、分段加密與讀取判定見子套件：
//   - format：標頭與事件編碼
//   - sealer：分段 AEAD 封裝
//   - reader：開檔限制、標頭核對與完整性判定
//   - writer：有界佇列、背壓與單一寫入 goroutine
//
// 本套件本身只放與子套件共用的小型常數與純函式（路徑、涵蓋判定）。
// 明文按鍵內容不得進入任何 log、錯誤訊息或審計欄位。
package keystroke

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// FileExt 為紀錄檔副檔名。
const FileExt = ".cxkr"

// RootDirName 為審計資料根下的子目錄名稱。
const RootDirName = "keystrokes"

// 目錄與檔案權限：同其他審計落地檔的慣例。
const (
	DirPerm  os.FileMode = 0o700
	FilePerm os.FileMode = 0o600
)

// RootFromAuditDir 由審計資料根推得鍵盤紀錄根目錄。
func RootFromAuditDir(auditDir string) string {
	return filepath.Join(auditDir, RootDirName)
}

// RelPath 回傳相對於根目錄的檔案路徑：YYYY-MM-DD/<record_uuid>.cxkr，
// 日期取起點 UTC。以紀錄 UUID 命名，會話 id 重用時不會接到舊檔。
func RelPath(recordUUID string, start time.Time) string {
	return filepath.Join(start.UTC().Format("2006-01-02"), recordUUID+FileExt)
}

// EnsureDir 建立目錄（含上層）並確保其權限為 0700。
func EnsureDir(dir string) error {
	if err := os.MkdirAll(dir, DirPerm); err != nil {
		return err
	}
	return os.Chmod(dir, DirPerm)
}

// Probe 檢查根目錄可建立並寫入檔案（簽發點探測用）。不留殘檔。
func Probe(root string) error {
	if err := EnsureDir(root); err != nil {
		return err
	}
	f, err := os.CreateTemp(root, ".probe-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_, werr := f.Write([]byte{0})
	cerr := f.Close()
	rerr := os.Remove(name)
	switch {
	case werr != nil:
		return werr
	case cerr != nil:
		return cerr
	case rerr != nil:
		return rerr
	}
	return nil
}

// SessionKind 為涵蓋判定的會話類型。
type SessionKind string

const (
	KindSSHTerminal    SessionKind = "ssh_terminal"
	KindDBCLI          SessionKind = "db_cli"
	KindK8sExec        SessionKind = "k8s_exec"
	KindAgentTerminal  SessionKind = "agent_terminal"
	KindK8sLogs        SessionKind = "k8s_logs"
	KindDBConsole      SessionKind = "db_console"
	KindAgentDBConsole SessionKind = "agent_db_console"
	KindGraphics       SessionKind = "graphics"
	KindFileTransfer   SessionKind = "file_transfer"
)

// 不涵蓋原因碼（紀錄列 coverage_reason）。
const (
	ReasonK8sLogsReadonly = "k8s_logs_readonly"
	ReasonDBConsole       = "db_console"
	// ReasonGraphicsPending 圖形會話擷取上線前的歷史原因碼；現行判定不再產生，保留供歷史列。
	ReasonGraphicsPending = "graphics_pending"
	ReasonFileTransfer    = "file_transfer"
)

// Coverage 判定會話類型是否產生鍵盤紀錄。涵蓋者回 (true, "")，
// 不涵蓋者回 (false, 原因碼)。未知類型視為不涵蓋並回空原因，由呼叫端處理。
func Coverage(kind SessionKind) (covered bool, reason string) {
	switch kind {
	case KindSSHTerminal, KindDBCLI, KindK8sExec, KindAgentTerminal, KindGraphics:
		return true, ""
	case KindK8sLogs:
		return false, ReasonK8sLogsReadonly
	case KindDBConsole, KindAgentDBConsole:
		return false, ReasonDBConsole
	case KindFileTransfer:
		return false, ReasonFileTransfer
	}
	return false, ""
}

// ErrUnknownKind 供呼叫端對未知類型包裝錯誤。
func ErrUnknownKind(kind SessionKind) error {
	return fmt.Errorf("keystroke: unknown session kind %q", string(kind))
}
