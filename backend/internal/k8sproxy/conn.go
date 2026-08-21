// Package k8sproxy K8s 容器 exec 的本地 CLI 代理（k8s-exec）：
// kubectl exec 子程序掛 PTY 直連指定容器，Bearer Token 經 0600 臨時
// kubeconfig 傳遞（不落 argv、會話結束即刪），文字流走 sshproxy bridge
// 的 TerminalConn 介面，審計鏈全沿用。取捨：不另建沙箱 shell、也不繞道圖形代理
// 管線——直接複用文字終端鏈路，錄製／指令審計／阻斷／監看零改動。
package k8sproxy

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/custodexa/backend/internal/branding"
	"net/url"
	"os"
	"path/filepath"

	"github.com/custodexa/backend/internal/localpty"
)

// Target K8s exec 連線目標（Token 由後端記憶體解密，不出端）
type Target struct {
	Server    string // https://host:port
	Token     string
	Namespace string
	Pod       string
	Container string // 空＝pod 預設容器
	// control plane TLS（對抗審查 mustFix #3）
	CACert   string // API server CA（PEM，選填）
	Insecure bool   // 顯式略過 TLS 驗證（預設 false）
	// 連線模態（D6）：空＝interactive-exec
	Mode    Mode
	Command string // one-shot 模態的單一指令
}

// Mode K8s 連線模態（D6）
type Mode string

const (
	ModeInteractive Mode = ""        // 互動 shell
	ModeLogs        Mode = "logs"    // kubectl logs -f 唯讀
	ModeOneShot     Mode = "oneshot" // 單指令 exec
)

// clusterTLS 依 CA/insecure 產生 kubeconfig 的 cluster TLS 區塊；
// 預設（無 CA、非 insecure）＝以系統根憑證驗證 API server。
func clusterTLS(caCert string, insecure bool) string {
	if insecure {
		return "    insecure-skip-tls-verify: true\n"
	}
	if caCert != "" {
		b64 := base64.StdEncoding.EncodeToString([]byte(caCert))
		return "    certificate-authority-data: " + b64 + "\n"
	}
	return ""
}

// kubeconfigYAML 記憶體組裝 kubeconfig；TLS 依 CA/insecure（對抗審查 mustFix #3：
// 預設驗證 TLS，insecure 須資產顯式開啟）
func kubeconfigYAML(server, token, caCert string, insecure bool) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: target
  cluster:
    server: %s
%scontexts:
- name: target
  context:
    cluster: target
    user: operator
current-context: target
users:
- name: operator
  user:
    token: %s
`, server, clusterTLS(caCert, insecure), token)
}

// writeTempKubeconfig 將 kubeconfig 落 0600 私有臨時目錄；
// 回傳路徑與清理函式（冪等）
func writeTempKubeconfig(t Target) (string, func(), error) {
	dir, err := os.MkdirTemp("", "k8sproxy-*")
	if err != nil {
		return "", nil, fmt.Errorf("建立臨時目錄失敗: %w", err)
	}
	path := filepath.Join(dir, "kubeconfig")
	cfg := kubeconfigYAML(t.Server, t.Token, t.CACert, t.Insecure)
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return "", nil, fmt.Errorf("寫入臨時 kubeconfig 失敗: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	return path, cleanup, nil
}

// buildArgs 依模態組裝 kubectl 參數（token 不在其中——經 KUBECONFIG 環境傳遞）。
// interactive：進容器優先 bash、退 sh；logs：唯讀串流；one-shot：跑單一指令。
func buildArgs(t Target) []string {
	switch t.Mode {
	case ModeLogs:
		args := []string{"logs", "-f", "-n", t.Namespace, t.Pod}
		if t.Container != "" {
			args = append(args, "-c", t.Container)
		}
		return args
	case ModeOneShot:
		args := []string{"exec", "-i", "-t", "-n", t.Namespace, t.Pod}
		if t.Container != "" {
			args = append(args, "-c", t.Container)
		}
		return append(args, "--", "sh", "-c", t.Command)
	default: // ModeInteractive
		args := []string{"exec", "-i", "-t", "-n", t.Namespace, t.Pod}
		if t.Container != "" {
			args = append(args, "-c", t.Container)
		}
		return append(args, "--", "sh", "-c", "command -v bash >/dev/null && exec bash || exec sh")
	}
}

// Conn K8s exec PTY 連線：包裝 localpty 並負責 kubeconfig 生命週期
type Conn struct {
	*localpty.Conn
	cleanup func()
	mode    Mode
	hinted  bool // distroless 提示是否已附（只附一次）
}

// distrolessHint 偵測到的 kubectl「無 shell」提示（繁中，黃字）
var distrolessHint = []byte("\r\n\x1b[33m[" + branding.Name + "] 此容器似乎沒有可用的 shell（distroless/scratch 映像）。" +
	"可改用「日誌」模式檢視輸出，或改連同一 pod 中有 shell 的容器。\x1b[0m\r\n")

// Read 覆寫：interactive/one-shot 模態下偵測 kubectl 無 shell 錯誤，
// 於輸出後附繁中提示（D7），避免使用者只看到裸英文錯誤後被踢出。
func (c *Conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && !c.hinted && c.mode != ModeLogs {
		if bytes.Contains(p[:n], []byte("executable file not found")) ||
			bytes.Contains(p[:n], []byte("OCI runtime exec failed")) {
			c.hinted = true
			if n+len(distrolessHint) <= len(p) {
				copy(p[n:], distrolessHint)
				n += len(distrolessHint)
			}
		}
	}
	return n, err
}

// Close 收線並即焚臨時 kubeconfig
func (c *Conn) Close() {
	c.Conn.Close()
	if c.cleanup != nil {
		c.cleanup()
	}
}

// validateTarget 驗證連線目標：防 kubeconfig YAML 注入（server/token 禁換行）、
// 防 kubectl flag 注入（ns/pod/container 不以 - 開頭、禁控制字元）、server 須為合法 https URL
func validateTarget(t Target) error {
	if t.Server == "" || t.Namespace == "" || t.Pod == "" {
		return fmt.Errorf("K8s 連線目標不完整（server/namespace/pod 必填）")
	}
	// server 進 kubeconfig YAML：須為合法 URL 且 scheme=https，杜絕換行注入與惡意 scheme
	u, err := url.Parse(t.Server)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("K8s API server 必須為合法 https URL")
	}
	if err := localpty.SafeSecret("Token", t.Token); err != nil {
		return err
	}
	for field, val := range map[string]string{
		"Namespace": t.Namespace, "Pod": t.Pod, "Container": t.Container,
	} {
		if err := localpty.SafeArg(field, val); err != nil {
			return err
		}
	}
	return nil
}

// Start 啟動 kubectl exec PTY。kubectl 認證/連線失敗會印在 PTY 輸出後退出，
// 使用者在終端直接看到原因；此處僅在參數缺失/不合法、寫檔或 PTY 失敗時回錯。
func Start(t Target, cols, rows int) (*Conn, error) {
	if err := validateTarget(t); err != nil {
		return nil, err
	}

	cfgPath, cleanup, err := writeTempKubeconfig(t)
	if err != nil {
		return nil, err
	}

	inner, err := localpty.Start("kubectl", buildArgs(t),
		[]string{"KUBECONFIG=" + cfgPath}, cols, rows)
	if err != nil {
		cleanup()
		return nil, err
	}
	return &Conn{Conn: inner, cleanup: cleanup, mode: t.Mode}, nil
}
