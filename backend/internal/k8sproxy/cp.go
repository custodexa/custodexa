// cp.go：kubectl cp 容器檔案進出（k8s-exec）。
// 後端以選定 pod/container 跑 kubectl cp；檔名/大小/方向的審計由 API 層落 audit_log
// （exec-tar 串流為不透明二進位，既有 PTY 指令審計解不出，故獨立記錄）。
package k8sproxy

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/custodexa/backend/internal/localpty"
)

// CopyToPod 上傳本地檔到容器（kubectl cp local pod:dest）
func CopyToPod(ctx context.Context, t Target, localPath, destPath string) error {
	if err := validateCpTarget(t, destPath); err != nil {
		return err
	}
	cfgPath, cleanup, err := writeTempKubeconfig(t)
	if err != nil {
		return err
	}
	defer cleanup()
	args := []string{"cp", localPath, fmt.Sprintf("%s/%s:%s", t.Namespace, t.Pod, destPath)}
	if t.Container != "" {
		args = append(args, "-c", t.Container)
	}
	return runKubectlCp(ctx, cfgPath, args)
}

// CopyFromPod 從容器下載檔到本地（kubectl cp pod:src local）
func CopyFromPod(ctx context.Context, t Target, srcPath, localPath string) error {
	if err := validateCpTarget(t, srcPath); err != nil {
		return err
	}
	cfgPath, cleanup, err := writeTempKubeconfig(t)
	if err != nil {
		return err
	}
	defer cleanup()
	args := []string{"cp", fmt.Sprintf("%s/%s:%s", t.Namespace, t.Pod, srcPath), localPath}
	if t.Container != "" {
		args = append(args, "-c", t.Container)
	}
	return runKubectlCp(ctx, cfgPath, args)
}

func runKubectlCp(ctx context.Context, cfgPath string, args []string) error {
	cmd := exec.CommandContext(ctx, "kubectl", args...)
	// 最小環境（沿 dbproxy/exec 慣例，不繼承後端機密），僅 KUBECONFIG 與 PATH
	cmd.Env = []string{"KUBECONFIG=" + cfgPath, "PATH=/usr/local/bin:/usr/bin:/bin"}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("kubectl cp 失敗: %s", string(out))
	}
	return nil
}

// validateCpTarget 防注入：namespace/pod/container/path 禁 flag 與控制字元
func validateCpTarget(t Target, path string) error {
	if t.Namespace == "" || t.Pod == "" {
		return fmt.Errorf("缺 namespace/pod")
	}
	if path == "" {
		return fmt.Errorf("缺檔案路徑")
	}
	for field, val := range map[string]string{
		"Namespace": t.Namespace, "Pod": t.Pod, "Container": t.Container, "Path": path,
	} {
		if err := localpty.SafeArg(field, val); err != nil {
			return err
		}
	}
	return nil
}
