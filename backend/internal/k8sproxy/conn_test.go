package k8sproxy

import (
	"os"
	"strings"
	"testing"
)

func TestBuildExecArgsTokenNeverInArgv(t *testing.T) {
	// Arrange
	target := Target{
		Server: "https://10.0.0.1:6443", Token: "secret-token-abc",
		Namespace: "prod", Pod: "web-0", Container: "app",
	}

	// Act
	args := buildArgs(target)

	// Assert：token 與 server 都不得出現在 argv（經 KUBECONFIG 傳遞）
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "secret-token-abc") || strings.Contains(joined, "10.0.0.1") {
		t.Fatalf("憑證洩入 argv: %q", joined)
	}
	for _, want := range []string{"exec", "-n", "prod", "web-0", "-c", "app"} {
		if !strings.Contains(joined, want) {
			t.Errorf("argv 缺 %q: %q", want, joined)
		}
	}
}

func TestBuildExecArgsDefaultContainer(t *testing.T) {
	args := buildArgs(Target{Namespace: "ns", Pod: "p"})
	// 僅檢查 "--" 之前的 kubectl 參數段（其後的 sh -c 本就含 -c）
	for _, a := range args {
		if a == "--" {
			break
		}
		if a == "-c" {
			t.Fatal("container 空時 kubectl 參數不應帶 -c")
		}
	}
}

func TestWriteTempKubeconfigPermsAndCleanup(t *testing.T) {
	// Act
	path, cleanup, err := writeTempKubeconfig(Target{Server: "https://k8s.local:6443", Token: "tkn-123"})
	if err != nil {
		t.Fatalf("writeTempKubeconfig 失敗: %v", err)
	}

	// Assert：0600 權限、內容含 server 與 token
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("kubeconfig 不存在: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("kubeconfig 權限應為 0600, got %v", info.Mode().Perm())
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "https://k8s.local:6443") || !strings.Contains(string(raw), "tkn-123") {
		t.Errorf("kubeconfig 內容不完整: %s", raw)
	}

	// Assert：cleanup 即焚（冪等）
	cleanup()
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("cleanup 後 kubeconfig 應已刪除")
	}
}

func TestStartIncompleteTarget(t *testing.T) {
	if _, err := Start(Target{Server: "https://x"}, 80, 24); err == nil {
		t.Fatal("缺 namespace/pod 應回錯")
	}
}

// TestKubeconfigTLSDefaults：預設驗證 TLS（不含 skip-verify），
// insecure 須顯式，CA 走 certificate-authority-data。
func TestKubeconfigTLSDefaults(t *testing.T) {
	def := kubeconfigYAML("https://s:6443", "tok", "", false)
	if strings.Contains(def, "insecure-skip-tls-verify") {
		t.Error("預設不應略過 TLS 驗證（mustFix #3）")
	}
	if strings.Contains(def, "certificate-authority-data") {
		t.Error("未設 CA 時不應出現 certificate-authority-data")
	}

	ins := kubeconfigYAML("https://s:6443", "tok", "", true)
	if !strings.Contains(ins, "insecure-skip-tls-verify: true") {
		t.Error("insecure=true 應顯式 skip-verify")
	}

	ca := kubeconfigYAML("https://s:6443", "tok", "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----", false)
	if !strings.Contains(ca, "certificate-authority-data:") {
		t.Error("設 CA 時應寫 certificate-authority-data")
	}
	if strings.Contains(ca, "insecure-skip-tls-verify") {
		t.Error("設 CA 時不應 skip-verify")
	}
}

// TestBuildArgsModes：模態分支（logs/one-shot/interactive）
func TestBuildArgsModes(t *testing.T) {
	base := Target{Namespace: "ns", Pod: "p", Container: "c"}
	logs := strings.Join(buildArgs(Target{Namespace: "ns", Pod: "p", Container: "c", Mode: ModeLogs}), " ")
	if !strings.HasPrefix(logs, "logs -f") {
		t.Errorf("logs 模態應為 kubectl logs -f: %q", logs)
	}
	one := strings.Join(buildArgs(Target{Namespace: "ns", Pod: "p", Mode: ModeOneShot, Command: "id"}), " ")
	if !strings.Contains(one, "exec") || !strings.HasSuffix(one, "id") {
		t.Errorf("one-shot 應 exec 跑指令: %q", one)
	}
	inter := strings.Join(buildArgs(base), " ")
	if !strings.Contains(inter, "exec bash || exec sh") {
		t.Errorf("interactive 應 bash/sh 退路: %q", inter)
	}
}

func TestValidateTargetRejectsInjection(t *testing.T) {
	base := Target{Server: "https://10.0.0.1:6443", Token: "tok", Namespace: "default", Pod: "web-0"}
	cases := []struct {
		name   string
		mutate func(Target) Target
		ok     bool
	}{
		{"合法目標", func(x Target) Target { return x }, true},
		{"server 非 https", func(x Target) Target { x.Server = "http://10.0.0.1:6443"; return x }, false},
		{"server 換行注入", func(x Target) Target { x.Server = "https://x\n    server: https://evil"; return x }, false},
		{"token 換行注入 YAML", func(x Target) Target { x.Token = "t\n    token: evil"; return x }, false},
		{"pod flag 注入", func(x Target) Target { x.Pod = "--kubeconfig=/evil"; return x }, false},
		{"namespace flag 注入", func(x Target) Target { x.Namespace = "-n"; return x }, false},
		{"container flag 注入", func(x Target) Target { x.Container = "--as=admin"; return x }, false},
		{"缺 pod", func(x Target) Target { x.Pod = ""; return x }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateTarget(c.mutate(base))
			if (err == nil) != c.ok {
				t.Errorf("validateTarget err=%v, 期望 ok=%v", err, c.ok)
			}
		})
	}
}
