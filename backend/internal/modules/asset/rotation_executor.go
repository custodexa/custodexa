package asset

import (
	"context"
	"errors"
	"fmt"

	"github.com/custodexa/backend/internal/model"
	"golang.org/x/crypto/ssh"
)

// rotationExecutor 遠端改密的執行面。
//
// 狀態機（候選先落庫 → 動遠端 → 驗證 → 提交 → 脫組 → 記錄 → 告警）與「怎麼在
// 目標機上把密碼換掉」是兩件事：前者是本產品的可靠性語義，對每種目標都一樣；
// 後者隨作業系統與遠端管理協定而異。介面切在這裡，狀態機就不必認識任何一種
// 遠端協定，新通道也不必重寫一次候選與失敗三態的處理。
//
// # 錯誤分流契約（呼叫端以 errors.As 判定）
//
//	*localPreconditionError  本地前置失敗，完全未觸碰遠端 → failed，清候選
//	*remoteRejectedError     遠端確定未變更 → failed，清候選
//	*remoteStateUnknownError 遠端狀態不可知且成因已知 → unverified 帶專屬原因碼，保留候選
//	其餘（含逾時、連線中斷）  遠端狀態不可知 → unverified，保留候選交重試
//
// 前兩者都是「遠端此刻不是新秘密」的確定結論，故清候選是安全的；第三類不是，
// 硬清候選等於猜遠端狀態，猜錯就把還能用的憑證改壞。
type rotationExecutor interface {
	// Rotate 在目標機上把 t.username 的秘密自 oldSecret 換成 newSecret。
	Rotate(ctx context.Context, t rotationTarget, oldSecret, newSecret string) error
	// Verify 以新秘密對目標實連一次。成功才代表遠端確實已是新秘密。
	Verify(ctx context.Context, t rotationTarget, newSecret string) error
}

// rotationTarget 一次遠端改密操作的目標描述。
//
// 帶的是**資產本體**而非拆散的欄位：WinRM 執行器要看 scheme／埠／TLS 模式與 CA，
// SSH 執行器要看 host key 與埠，逐欄攤平會讓每加一個通道就得改一次共同結構。
type rotationTarget struct {
	// asset 目標資產（含改密通道設定）
	asset *model.Asset
	// channel 推導後的有效通道（呼叫端已收口，執行器不再自行推導）
	channel string
	// username 帳號名（執行開頭釘住的快照）
	username string
	// secretType 本次輪替的秘密型別（password／ssh_key）
	secretType string
	// addr SSH 家族通道的撥號位址（host:port）；WinRM 通道不使用
	addr string
	// hostKeyCB SSH 家族通道的 host key 驗證回呼（TOFU）
	hostKeyCB ssh.HostKeyCallback
}

// remoteRejectedError 遠端確定未變更。
//
// reason 為 model 的原因碼常數，直接落 record.error；cause 只進後端 log
// （遠端原文是攻擊者可控輸入，SHALL NOT 落庫或外送）。
type remoteRejectedError struct {
	reason string
	cause  error
}

func (e *remoteRejectedError) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %v", e.reason, e.cause)
	}
	return e.reason
}

func (e *remoteRejectedError) Unwrap() error { return e.cause }

// remoteStateUnknownError 遠端狀態不可知，但成因已知、有專屬原因碼。
//
// 屬於分流契約的第三類（unverified，保留候選），只是把原因碼從預設的「狀態不可知」
// 換成能指認成因的碼（例：目標自驗失敗且回滾也失敗）。呼叫端對它的處置與其他
// 不可知錯誤完全相同，不得因為成因已知就清候選。
type remoteStateUnknownError struct {
	reason string
	cause  error
}

func (e *remoteStateUnknownError) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %v", e.reason, e.cause)
	}
	return e.reason
}

func (e *remoteStateUnknownError) Unwrap() error { return e.cause }

// errExecutorNotWired 通道沒有對應的執行器（`none` 或值域外的值）。
//
// 正常流程走不到：resolveTargets 對 `none` 已先跳過，值域外的值在資產儲存時就被拒。
// 仍保留一個會乾淨失敗的執行器而非回 nil——回 nil 會讓呼叫端多一條「執行器不存在」
// 的分支，而那條分支的處置與「執行器拒絕了」完全相同；記為 failed 並帶
// 「未設定改密通道」也讓這種選路缺口在記錄上看得見，而不是一個 panic。
var errExecutorNotWired = errors.New("rotation executor not wired")

// rotationExecutorFor 依通道取執行器。
func rotationExecutorFor(channel string) rotationExecutor {
	switch channel {
	case model.RotationChannelPosixSSH:
		return posixSSHExecutor{}
	case model.RotationChannelWindowsWinRM:
		return newWindowsWinRMExecutor()
	case model.RotationChannelWindowsSSH:
		return newWindowsSSHExecutor()
	default:
		return notWiredExecutor{}
	}
}

// notWiredExecutor 沒有執行器的通道：不觸碰遠端，直接走乾淨失敗。
type notWiredExecutor struct{}

func (notWiredExecutor) Rotate(context.Context, rotationTarget, string, string) error {
	return &localPreconditionError{
		reason: model.ChangeSecretReasonChannelNotConfigured,
		cause:  errExecutorNotWired,
	}
}

func (notWiredExecutor) Verify(context.Context, rotationTarget, string) error {
	return &localPreconditionError{
		reason: model.ChangeSecretReasonChannelNotConfigured,
		cause:  errExecutorNotWired,
	}
}

// posixSSHExecutor SSH 到 POSIX shell 的改密執行器。
//
// **行為與本介面引入前逐項相同**：撥號、指令組裝與 stdin 投遞全部沿用同一組
// 包級函式（dialSSHPassword／dialSSHPrivateKey／runChpasswd），此型別只是把
// 「先以舊憑證登入、再跑改密指令」這段順序收進介面的形狀裡。
type posixSSHExecutor struct{}

// Rotate 以舊密碼登入後執行改密指令。
//
// 舊憑證登入失敗歸為 remoteRejectedError：那一刻遠端確定還沒被改過，處置與
// 「指令跑完但非零退出」相同——清候選、乾淨失敗。兩者的原因碼不同，
// 使記錄仍分得出是登不進去還是指令被拒。
func (posixSSHExecutor) Rotate(_ context.Context, t rotationTarget, oldSecret, newSecret string) error {
	client, err := dialSSHPassword(t.addr, t.username, oldSecret, t.hostKeyCB)
	if err != nil {
		return &remoteRejectedError{
			reason: model.ChangeSecretReasonOldCredentialLoginFailed,
			cause:  err,
		}
	}
	err = runChpasswd(client, t.username, oldSecret, newSecret)
	client.Close()
	if err != nil {
		// 本地前置驗證失敗＝完全未接觸遠端，原型別直接上拋供呼叫端分流
		var localErr *localPreconditionError
		if errors.As(err, &localErr) {
			return err
		}
		// 指令跑完但非零退出＝遠端確定未變更；其餘（連線中斷／逾時）狀態不可知
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			return &remoteRejectedError{reason: model.ChangeSecretReasonRemoteRejected, cause: err}
		}
		return err
	}
	return nil
}

// Verify 以新秘密對同一目標實連一次。
//
// 金鑰型別走私鑰認證、密碼型別走密碼認證——秘密型別在 target 上，
// 使重試執行器與改密執行器共用同一條驗證路徑（兩者分岔即會出現
// 「手動能過、自動不能」的行為差異）。
func (posixSSHExecutor) Verify(_ context.Context, t rotationTarget, newSecret string) error {
	var (
		client *ssh.Client
		err    error
	)
	if t.secretType == model.ChangeSecretTypeSSHKey {
		client, err = dialSSHPrivateKey(t.addr, t.username, newSecret, t.hostKeyCB)
	} else {
		client, err = dialSSHPassword(t.addr, t.username, newSecret, t.hostKeyCB)
	}
	if err != nil {
		return err
	}
	client.Close()
	return nil
}

// rotationAddr SSH 家族通道的撥號位址。
//
// posix_ssh 用資產本身的 port；windows_ssh 在 rdp 資產上用 rotation_ssh_port
// （rdp 的 port 是 3389，不是 SSH 服務），在 ssh 資產上仍是同一條 SSH 服務。
func rotationAddr(asset *model.Asset, channel string) string {
	port := asset.Port
	if channel == model.RotationChannelWindowsSSH {
		port = asset.EffectiveRotationSSHPort()
	}
	return fmt.Sprintf("%s:%d", asset.Host, port)
}
