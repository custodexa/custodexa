// client.go：list pods / SSAR 預檢 / get pod 快照（k8s-exec 連線時選 pod）。
// 走 client-go in-memory REST config（D3：免第二個落檔的 kubeconfig，縮短 token 暴露窗口）。
package k8sproxy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/custodexa/backend/internal/modules/policy"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const defaultContainerAnnotation = "kubernetes.io/default-container"
const defaultListTimeout = 10 * time.Second

// ContainerInfo 選擇器用容器摘要
type ContainerInfo struct {
	Name  string `json:"name"`
	Image string `json:"image"`
	Ready bool   `json:"ready"`
}

// PodInfo 選擇器用 pod 摘要（k9s 最小可用集：狀態/Ready/重啟/容器）
type PodInfo struct {
	Name             string          `json:"name"`
	Phase            string          `json:"phase"`
	Ready            string          `json:"ready"` // "2/3"
	Restarts         int32           `json:"restarts"`
	StartedAt        *time.Time      `json:"started_at,omitempty"`
	Node             string          `json:"node"`
	Containers       []ContainerInfo `json:"containers"`
	DefaultContainer string          `json:"default_container,omitempty"`
}

// PodSnapshot 會話不可變快照來源（mustFix #2）
type PodSnapshot struct {
	Namespace string
	Pod       string
	UID       string
	Container string
	Image     string
	Node      string
}

// K8sError 分類後的連線錯誤（供前端呈現五類人話）
type K8sError struct {
	Kind    string // unreachable/tls/unauthorized/forbidden/notfound/unknown
	Message string
}

// K8sError.Kind 的枚舉常數（backend-i18n-unification A8）。
//
// 值即機器識別字：sshproxy 依此映 apierror 碼、internal/api 的 pod 列表回應以
// `kind` 欄直傳前端——**值一字不可改**（改了等於改 API 契約）。
const (
	KindUnauthorized = "unauthorized"
	KindForbidden    = "forbidden"
	KindNotFound     = "notfound"
	KindTLS          = "tls"
	KindUnreachable  = "unreachable"
	KindUnknown      = "unknown"
)

func (e *K8sError) Error() string { return e.Message }

// minListTimeout 列表逾時的下界（policy-numeric-lower-bounds）：一次列表要走完
// TLS 握手＋API server 查詢＋回傳，健康但有負載的叢集本來就可能花上一兩秒。
// 低於此值時正常叢集的正常回應也會被判逾時——K8s 功能實質不可用而資產列表
// 上仍顯示著這些叢集。與 PolicyK8sListTimeoutSeconds 的 Min 同值
const minListTimeout = 3 * time.Second

// policySource 列表逾時的執行期來源（安全政策頁）。
// 套件級而非服務級：listTimeout() 本身即套件級函式，三個呼叫點都不持有服務實例
type policySource interface {
	GetInt(key string) int
}

var (
	policyMu  sync.RWMutex
	policySrc policySource
)

// SetPolicySource 接上安全政策頁作為列表逾時的執行期事實源。
// 每次列表都重讀——管理員為慢叢集調高逾時的當下就要生效，不該等重啟
func SetPolicySource(p policySource) {
	policyMu.Lock()
	defer policyMu.Unlock()
	policySrc = p
}

func listTimeout() time.Duration {
	policyMu.RLock()
	src := policySrc
	policyMu.RUnlock()
	if src != nil {
		d := time.Duration(src.GetInt(policy.PolicyK8sListTimeoutSeconds)) * time.Second
		// 邊界複查：政策若因資料層直改而落到下界之下，每次列表都會逾時
		if d < minListTimeout {
			return minListTimeout
		}
		return d
	}
	// 未接政策時的退路（單元測試與未接政策的組裝路徑）
	if v := os.Getenv("K8S_LIST_TIMEOUT_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return defaultListTimeout
}

// restConfig 由 Target 組 in-memory REST config（CA/insecure 與 exec 路徑同語義）
func restConfig(t Target) *rest.Config {
	cfg := &rest.Config{Host: t.Server, BearerToken: t.Token}
	if t.Insecure {
		cfg.TLSClientConfig = rest.TLSClientConfig{Insecure: true}
	} else if t.CACert != "" {
		cfg.TLSClientConfig = rest.TLSClientConfig{CAData: []byte(t.CACert)}
	}
	return cfg
}

func clientset(t Target) (*kubernetes.Clientset, error) {
	return kubernetes.NewForConfig(restConfig(t))
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// classifyErr 將 client-go / 網路 / TLS 錯誤映成五類人話（D7）
func classifyErr(ns string, err error) *K8sError {
	if err == nil {
		return nil
	}
	switch {
	case apierrors.IsUnauthorized(err):
		return &K8sError{KindUnauthorized, "Token 認證失敗（401）：請確認 Bearer Token 有效"}
	case apierrors.IsForbidden(err):
		return &K8sError{KindForbidden, fmt.Sprintf("無權限（403）：Token 需要 namespace %q 的 list pods 權限", ns)}
	case apierrors.IsNotFound(err):
		return &K8sError{KindNotFound, fmt.Sprintf("namespace %q 不存在（404）", ns)}
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "x509") || strings.Contains(msg, "certificate"):
		return &K8sError{KindTLS, "TLS 憑證驗證失敗：請設定正確的 CA 憑證，或（不建議）開啟略過驗證"}
	case isTimeout(err) || strings.Contains(msg, "connection refused") || strings.Contains(msg, "no such host"):
		return &K8sError{KindUnreachable, "無法連到 API server：請確認位址/連接埠與網路可達性"}
	}
	log.Printf("[k8sproxy] unclassified error (ns=%s): %v", ns, err)
	return &K8sError{KindUnknown, "連線 K8s 失敗，請確認叢集位址、認證與網路"}
}

// ListPods 列 namespace 內活 pod（隱藏 Succeeded 完成 pod）；錯誤映五類
func ListPods(ctx context.Context, t Target) ([]PodInfo, error) {
	cs, err := clientset(t)
	if err != nil {
		return nil, classifyErr(t.Namespace, err)
	}
	ctx, cancel := context.WithTimeout(ctx, listTimeout())
	defer cancel()
	list, err := cs.CoreV1().Pods(t.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, classifyErr(t.Namespace, err)
	}
	out := make([]PodInfo, 0, len(list.Items))
	for i := range list.Items {
		p := &list.Items[i]
		if p.Status.Phase == corev1.PodSucceeded {
			continue // 隱藏 Completed job pod
		}
		out = append(out, toPodInfo(p))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func toPodInfo(p *corev1.Pod) PodInfo {
	info := PodInfo{
		Name:             p.Name,
		Phase:            string(p.Status.Phase),
		Node:             p.Spec.NodeName,
		DefaultContainer: p.Annotations[defaultContainerAnnotation],
	}
	if p.DeletionTimestamp != nil {
		info.Phase = "Terminating"
	}
	statusByName := make(map[string]corev1.ContainerStatus, len(p.Status.ContainerStatuses))
	readyCount := 0
	var restarts int32
	for _, cs := range p.Status.ContainerStatuses {
		statusByName[cs.Name] = cs
		if cs.Ready {
			readyCount++
		}
		restarts += cs.RestartCount
		if cs.State.Waiting != nil && cs.State.Waiting.Reason == "CrashLoopBackOff" {
			info.Phase = "CrashLoopBackOff"
		}
	}
	for _, c := range p.Spec.Containers {
		ci := ContainerInfo{Name: c.Name, Image: c.Image}
		if st, ok := statusByName[c.Name]; ok {
			ci.Ready = st.Ready
		}
		info.Containers = append(info.Containers, ci)
	}
	info.Ready = fmt.Sprintf("%d/%d", readyCount, len(p.Spec.Containers))
	info.Restarts = restarts
	if p.Status.StartTime != nil {
		st := p.Status.StartTime.Time
		info.StartedAt = &st
	}
	return info
}

// GetPod 取單一 pod 釘 session 快照；container 空＝取 default annotation 或第一個容器
func GetPod(ctx context.Context, t Target) (*PodSnapshot, error) {
	cs, err := clientset(t)
	if err != nil {
		return nil, classifyErr(t.Namespace, err)
	}
	ctx, cancel := context.WithTimeout(ctx, listTimeout())
	defer cancel()
	p, err := cs.CoreV1().Pods(t.Namespace).Get(ctx, t.Pod, metav1.GetOptions{})
	if err != nil {
		return nil, classifyErr(t.Namespace, err)
	}
	container := t.Container
	if container == "" {
		container = p.Annotations[defaultContainerAnnotation]
	}
	if container == "" && len(p.Spec.Containers) > 0 {
		container = p.Spec.Containers[0].Name
	}
	image := ""
	for _, c := range p.Spec.Containers {
		if c.Name == container {
			image = c.Image
			break
		}
	}
	return &PodSnapshot{
		Namespace: t.Namespace,
		Pod:       p.Name,
		UID:       string(p.UID),
		Container: container,
		Image:     image,
		Node:      p.Spec.NodeName,
	}, nil
}

// CanExec 以 SelfSubjectAccessReview 預檢 token 是否可對 pod exec（D2 fail-fast UX）
func CanExec(ctx context.Context, t Target) (bool, error) {
	cs, err := clientset(t)
	if err != nil {
		return false, classifyErr(t.Namespace, err)
	}
	ctx, cancel := context.WithTimeout(ctx, listTimeout())
	defer cancel()
	ssar := &authv1.SelfSubjectAccessReview{
		Spec: authv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authv1.ResourceAttributes{
				Namespace:   t.Namespace,
				Verb:        "create",
				Resource:    "pods",
				Subresource: "exec",
			},
		},
	}
	res, err := cs.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, ssar, metav1.CreateOptions{})
	if err != nil {
		return false, classifyErr(t.Namespace, err)
	}
	return res.Status.Allowed, nil
}

// sweepResidualKubeconfigs 啟動期清掃殘留的臨時 kubeconfig 目錄（D8：補崩潰路徑）。
// 回傳清掉的目錄數。
func SweepResidualKubeconfigs() int {
	base := os.TempDir()
	entries, err := os.ReadDir(base)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "k8sproxy-") {
			if os.RemoveAll(base+string(os.PathSeparator)+e.Name()) == nil {
				n++
			}
		}
	}
	return n
}
