package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/gin-gonic/gin"
)

// hostIdentityConfirmBodyLimit 重試請求 body 的上限：確認內容只有幾個短欄位。
const hostIdentityConfirmBodyLimit = 8 << 10

// hostIdentityConfirmer 人工承接服務對 handler 暴露的唯一動作。
type hostIdentityConfirmer interface {
	ConfirmHostIdentityAndVerify(ctx context.Context, kind string, jobID uint,
		req asset.HostIdentityConfirmRequest) error
}

// errHostIdentityConfirmBody 重試請求 body 不合法（形狀、多餘欄位或傳輸值域）。
var errHostIdentityConfirmBody = errors.New("重試請求內容不合法")

// parseHostIdentityConfirmBody 嚴格解析重試路由的選用 body。
// 沒有 body、空物件或 confirm_host_identity 為 null 都視為不帶確認（回 nil）；
// 頂層只接受 confirm_host_identity 一個鍵，其餘（例如 force）一律拒絕。
func parseHostIdentityConfirmBody(c *gin.Context) (*asset.HostIdentityConfirmRequest, error) {
	if c.Request.Body == nil {
		return nil, nil
	}
	raw, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, hostIdentityConfirmBodyLimit))
	if err != nil {
		return nil, errHostIdentityConfirmBody
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, nil
	}
	var top struct {
		Confirm json.RawMessage `json:"confirm_host_identity"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&top); err != nil || !errors.Is(dec.Decode(&struct{}{}), io.EOF) {
		return nil, errHostIdentityConfirmBody
	}
	inner := bytes.TrimSpace(top.Confirm)
	if len(inner) == 0 || bytes.Equal(inner, []byte("null")) {
		return nil, nil
	}
	req, err := asset.DecodeHostIdentityConfirmRequest(inner)
	if err != nil {
		return nil, errHostIdentityConfirmBody
	}
	return req, nil
}

// isHostIdentityTargetChanged 工作建立之後授權目標已改變。這不是主機身分的異動：
// 與不帶確認的補跑一致，以 200 回應並在 reason 帶既有原因碼，不使用身分衝突碼。
func isHostIdentityTargetChanged(err error) bool {
	return errors.Is(err, asset.ErrHostIdentityConfirmTargetChanged)
}

// respondHostIdentityConfirmError 把承接服務的錯誤對映成穩定的對外回應。
func respondHostIdentityConfirmError(c *gin.Context, internalCode apierror.ErrCode, err error) {
	var conflict *asset.HostIdentityConflictError
	switch {
	case errors.As(err, &conflict):
		resp := apierror.ErrorResponse{Code: apierror.CodeConflictHostIdentityMoved}
		if conflict.Detail != "" {
			resp.Meta = map[string]any{"detail": conflict.Detail}
		}
		apierror.Write(c, http.StatusConflict, resp)
	case errors.Is(err, asset.ErrHostIdentityMoved):
		apierror.Write(c, http.StatusConflict, apierror.ErrorResponse{Code: apierror.CodeConflictHostIdentityMoved})
	case errors.Is(err, asset.ErrHostIdentityConfirmInvalid):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
	case errors.Is(err, asset.ErrCredentialBindForbidden):
		// 能力拒絕：回應不變；依據取錯誤值所附的鍵，未附者記本路由的操作層級要求
		respondAssetCapabilityDenial(c, err)
	case errors.Is(err, asset.ErrCandidateNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeCandidateNotFound, nil)
	default:
		apierror.RespondInternal(c, http.StatusInternalServerError, internalCode, err)
	}
}
