package api

import (
	"github.com/custodexa/backend/internal/modules/policy"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
)

// respondTransmissionGate 傳輸政策門拒絕的統一出口（syslog 設定與通知通道共用）。
// 原為 legacy 小寫碼（ack_required/strict_reject）的裸 gin.H 回應；收斂為
// registry 碼後 error 文案由 ZhFallback 供 wire fallback、前端查譯，
// risks 經 Meta 平鋪保留供前端確認框列示（機器欄，非文案）
func respondTransmissionGate(c *gin.Context, gateErr *policy.TransmissionGateError) {
	code := apierror.CodeTransmissionAckRequired
	if gateErr.Code == policy.TransmissionGateStrictReject {
		code = apierror.CodeTransmissionSaveStrictReject
	}
	apierror.Write(c, http.StatusBadRequest, apierror.ErrorResponse{
		Code: code,
		Meta: map[string]any{"risks": gateErr.Risks},
	})
}
