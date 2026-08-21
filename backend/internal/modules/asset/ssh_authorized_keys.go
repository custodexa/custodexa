package asset

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// authorizedKeysPath 目標帳號的 authorized_keys 相對路徑（相對於登入後的 home）
const (
	sshDirName          = ".ssh"
	authorizedKeysName  = ".ssh/authorized_keys"
	authorizedKeysMode  = 0o600
	sshDirMode          = 0o700
	authorizedKeysLimit = 1 << 20 // 1 MiB：正常 authorized_keys 遠小於此，超過即異常
)

// ErrSFTPUnavailable 目標機未提供 SFTP 子系統。
//
// **不提供 shell fallback**：以 shell 命令拼接檔案內容會把引號與變數展開的注入面
// 加回來，正是本設計刻意消掉的東西（design「憑證投遞方式」第 3 點）。
var ErrSFTPUnavailable = errors.New("目標機未提供 SFTP 子系統，無法安全改寫 authorized_keys")

// GenerateSSHKeyPair 產生新的 Ed25519 金鑰對。
// 回傳 OpenSSH 格式私鑰 PEM 與 authorized_keys 行格式公鑰（含 comment）。
//
// 私鑰**只存在於後端記憶體與信封加密欄位**，SHALL NOT 被寫入目標機任何位置。
func GenerateSSHKeyPair(comment string) (privatePEM string, authorizedLine string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("產生金鑰對失敗: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return "", "", fmt.Errorf("序列化私鑰失敗: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", "", fmt.Errorf("序列化公鑰失敗: %w", err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " " + comment
	return string(pem.EncodeToMemory(block)), line, nil
}

// PublicLineFromPrivateKey 由私鑰推導其 authorized_keys 公鑰行（不含 comment）。
// 用於在輪替時精確定位「本系統先前推送的那一行」
func PublicLineFromPrivateKey(privatePEM string) (string, error) {
	signer, err := ssh.ParsePrivateKey([]byte(privatePEM))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), nil
}

// AuthorizedKeysFile 目標帳號 authorized_keys 的內容快照
type AuthorizedKeysFile struct {
	// Original 原始內容（供還原）。檔案不存在時為空字串
	Original string
	// Existed 檔案原本是否存在
	Existed bool
}

// openSFTP 以既有 SSH 連線開 SFTP 子系統
func openSFTP(client *ssh.Client) (*sftp.Client, error) {
	sc, err := sftp.NewClient(client)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSFTPUnavailable, err)
	}
	return sc, nil
}

// ReadAuthorizedKeys 讀取 authorized_keys 現況（檔案不存在視為空，非錯誤）
func ReadAuthorizedKeys(sc *sftp.Client) (AuthorizedKeysFile, error) {
	f, err := sc.Open(authorizedKeysName)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return AuthorizedKeysFile{Existed: false}, nil
		}
		return AuthorizedKeysFile{}, fmt.Errorf("讀取 authorized_keys 失敗: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, authorizedKeysLimit))
	if err != nil {
		return AuthorizedKeysFile{}, fmt.Errorf("讀取 authorized_keys 失敗: %w", err)
	}
	return AuthorizedKeysFile{Original: string(data), Existed: true}, nil
}

// WriteAuthorizedKeys 原子寫回：先寫暫存檔再 rename 覆蓋。
//
// 中途失敗時原檔仍完整——直接截斷原檔改寫的話，寫到一半斷線就會留下一個
// 半截的 authorized_keys，帳號當場失去全部金鑰入口。
func WriteAuthorizedKeys(sc *sftp.Client, content string) error {
	if err := ensureSSHDir(sc); err != nil {
		return err
	}
	tmp := authorizedKeysName + ".ot-tmp"
	f, err := sc.Create(tmp)
	if err != nil {
		return fmt.Errorf("建立暫存檔失敗: %w", err)
	}
	if _, err := f.Write([]byte(content)); err != nil {
		f.Close()
		_ = sc.Remove(tmp)
		return fmt.Errorf("寫入暫存檔失敗: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = sc.Remove(tmp)
		return fmt.Errorf("關閉暫存檔失敗: %w", err)
	}
	if err := sc.Chmod(tmp, authorizedKeysMode); err != nil {
		_ = sc.Remove(tmp)
		return fmt.Errorf("設定暫存檔權限失敗: %w", err)
	}
	// PosixRename 覆蓋既有檔（一般 rename 在部分伺服端遇既存檔會失敗）
	if err := sc.PosixRename(tmp, authorizedKeysName); err != nil {
		_ = sc.Remove(tmp)
		return fmt.Errorf("覆寫 authorized_keys 失敗: %w", err)
	}
	return nil
}

// ensureSSHDir 確保 ~/.ssh 存在且權限為 0700（sshd 對過寬的權限會拒絕採用金鑰）
func ensureSSHDir(sc *sftp.Client) error {
	if _, err := sc.Stat(sshDirName); err == nil {
		return nil
	}
	if err := sc.Mkdir(sshDirName); err != nil {
		return fmt.Errorf("建立 .ssh 目錄失敗: %w", err)
	}
	if err := sc.Chmod(sshDirName, sshDirMode); err != nil {
		return fmt.Errorf("設定 .ssh 目錄權限失敗: %w", err)
	}
	return nil
}

// AppendKeyLine 在內容尾端加一行公鑰（重複則原樣回傳）
func AppendKeyLine(content, line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return content
	}
	if containsKeyLine(content, line) {
		return content
	}
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content + line + "\n"
}

// RemoveKeyLine 移除與 target 同金鑰材料的行。
//
// 比對以「金鑰型別 ＋ base64 材料」兩欄為準，忽略 comment 與 options 前綴的差異——
// comment 由本系統寫入，但目標機管理員可能手動編修過；以完整行字串比對會漏刪。
func RemoveKeyLine(content, target string) string {
	targetKey := keyMaterial(target)
	if targetKey == "" {
		return content
	}
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if keyMaterial(l) == targetKey {
			continue
		}
		out = append(out, l)
	}
	joined := strings.Join(out, "\n")
	// 去除因刪行產生的尾端連續空行，但保留單一結尾換行
	joined = strings.TrimRight(joined, "\n")
	if joined == "" {
		return ""
	}
	return joined + "\n"
}

func containsKeyLine(content, line string) bool {
	target := keyMaterial(line)
	if target == "" {
		return false
	}
	for _, l := range strings.Split(content, "\n") {
		if keyMaterial(l) == target {
			return true
		}
	}
	return false
}

// keyMaterial 自 authorized_keys 行取出「型別 材料」正規化字串；非金鑰行回空字串
func keyMaterial(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return ""
	}
	fields := strings.Fields(line)
	for i := 0; i+1 < len(fields); i++ {
		// 金鑰型別欄一律以 ssh- 或 ecdsa-／sk- 開頭；其前可能有 options 欄
		if strings.HasPrefix(fields[i], "ssh-") ||
			strings.HasPrefix(fields[i], "ecdsa-") ||
			strings.HasPrefix(fields[i], "sk-") {
			return fields[i] + " " + fields[i+1]
		}
	}
	return ""
}
