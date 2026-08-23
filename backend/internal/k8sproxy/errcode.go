package k8sproxy

import (
	"errors"

	"github.com/custodexa/backend/internal/apierror"
)

// ErrCodeOf 將 K8sError.Kind 映為 apierror 碼（置於本套件供多呼叫端共用）。
//
// 為何住在 k8sproxy 而非呼叫端：分類（classifyErr）與映射是同一份知識，
// 分散在 sshproxy 與 api 兩側會讓新增 Kind 時只改到一邊（pod 列表原本就
// 因此只回單一泛碼）。apierror 是無業務相依的葉套件（僅依 gin/notifycat），
// 本套件引用它不成環，也不必讓 apierror 反向認識 client-go。
//
// 六類各一碼，前端可依碼查譯並分流處置；非 K8sError 或未知 Kind 退回泛碼
// CodeK8sPodUnavailable（不 panic、不誤用他類碼）。人話文案（含 namespace
// 等脈絡）仍留在 K8sError.Message，經 WS 幀 Data／log 傳遞當 fallback。
func ErrCodeOf(err error) apierror.ErrCode {
	var ke *K8sError
	if !errors.As(err, &ke) {
		return apierror.CodeK8sPodUnavailable
	}
	switch ke.Kind {
	case KindUnauthorized:
		return apierror.CodeK8sUnauthorized
	case KindForbidden:
		return apierror.CodeK8sForbidden
	case KindNotFound:
		return apierror.CodeK8sNamespaceNotFound
	case KindTLS:
		return apierror.CodeK8sTLSFailed
	case KindUnreachable:
		return apierror.CodeK8sUnreachable
	case KindUnknown:
		return apierror.CodeK8sUnknown
	default:
		return apierror.CodeK8sPodUnavailable
	}
}
