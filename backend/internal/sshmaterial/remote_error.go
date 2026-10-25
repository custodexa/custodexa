package sshmaterial

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// RemoteErrorClass 把 SSH 交握後遠端可控的錯誤（channel 開啟被拒、子系統請求失敗、遠端離線訊息）
// 收斂成穩定原因碼加非秘密脈絡，不帶遠端送來的任何文字。
//
// 為何不只截字：冒充主機在收到登入憑證後，可以把密碼塞進 channel reject message 或 disconnect
// message；x/crypto 會把那段原文放進 error 字串。任何以 %v 寫日誌或回應的位置都會把密碼持久化。
// 本函式是所有進日誌、回應與審計之前的唯一收口；遠端原文一律不出去。
func RemoteErrorClass(err error) string {
	if err == nil {
		return ""
	}
	var open *ssh.OpenChannelError
	if errors.As(err, &open) {
		return fmt.Sprintf("channel_open_rejected reason=%s", open.Reason.String())
	}
	var exit *ssh.ExitError
	if errors.As(err, &exit) {
		return fmt.Sprintf("exit_status=%d", exit.ExitStatus())
	}
	if errors.Is(err, ssh.ErrNoAuth) {
		return "no_auth"
	}
	return fmt.Sprintf("%T", err)
}
