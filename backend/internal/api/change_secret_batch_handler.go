package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
)

// 以帳號名為軸的批次改密端點（admin only，與計劃同閘）。
//
// 批次是一次性的處置動作：選帳號名、勾目標、送出後非同步執行，結果逐目標查詢。
// 執行與計劃走同一條狀態機，這裡只負責輸入驗證、觸發與投影。

// changeSecretBatchDTO 批次的對外表示。
//
// **刻意不含群組識別**：整批同一組模式的憑證群組識別只用於報告與帳號列表的
// 「共用憑證」布林投影，識別本身不出站（同帳號 DTO 的理由）。model 的欄位雖已
// 標 json:"-"，handler 仍一律回 DTO，使「不小心把 model 丟出去」在型別層即不成立。
type changeSecretBatchDTO struct {
	ID                       uint       `json:"id"`
	Username                 string     `json:"username"`
	PasswordMode             string     `json:"password_mode"`
	PasswordLength           int        `json:"password_length"`
	PasswordIncludeSymbol    bool       `json:"password_include_symbol"`
	PasswordExcludeAmbiguous bool       `json:"password_exclude_ambiguous"`
	TargetCount              int        `json:"target_count"`
	SuccessCount             int        `json:"success_count"`
	FailedCount              int        `json:"failed_count"`
	UnverifiedCount          int        `json:"unverified_count"`
	SkippedCount             int        `json:"skipped_count"`
	Status                   string     `json:"status"`
	RequestedBy              uint       `json:"requested_by"`
	RequestedByName          string     `json:"requested_by_name"`
	StartedAt                time.Time  `json:"started_at"`
	FinishedAt               *time.Time `json:"finished_at"`
	CreatedAt                time.Time  `json:"created_at"`
}

func newBatchDTO(b *model.ChangeSecretBatch) changeSecretBatchDTO {
	return changeSecretBatchDTO{
		ID: b.ID, Username: b.Username, PasswordMode: b.PasswordMode,
		PasswordLength: b.PasswordLength, PasswordIncludeSymbol: b.PasswordIncludeSymbol,
		PasswordExcludeAmbiguous: b.PasswordExcludeAmbiguous,
		TargetCount: b.TargetCount, SuccessCount: b.SuccessCount, FailedCount: b.FailedCount,
		UnverifiedCount: b.UnverifiedCount, SkippedCount: b.SkippedCount, Status: b.Status,
		RequestedBy: b.RequestedBy, RequestedByName: b.RequestedByName,
		StartedAt: b.StartedAt, FinishedAt: b.FinishedAt, CreatedAt: b.CreatedAt,
	}
}

// BatchUsernames 登記於系統的帳號名清單（附資產數）
func (h *ChangeSecretHandler) BatchUsernames(c *gin.Context) {
	names, err := h.batches.Usernames()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalChangeSecretBatchQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": names, "total": len(names)})
}

// BatchTargets 持有該帳號名的全部目標（報告列＋可改密性）
func (h *ChangeSecretHandler) BatchTargets(c *gin.Context) {
	asOf := time.Now()
	targets, err := h.batches.Targets(c.Query("username"), asOf)
	if err != nil {
		respondBatchError(c, apierror.CodeInternalChangeSecretBatchQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": targets, "total": len(targets), "as_of": asOf})
}

// CreateBatch 建立並非同步執行批次（202；結果經單一批次端點查詢）。
//
// **審計不填 asset_id**：一次批次作用於多台，挑一台填等於偽稱其餘沒被改；
// 逐台的事實由 runner 落地時的帳號變更審計各自帶 asset_id（沿計劃 Run 的理由）。
func (h *ChangeSecretHandler) CreateBatch(c *gin.Context) {
	var req asset.ChangeSecretBatchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	userID, username, _ := currentUser(c)
	batch, assetIDs, err := h.batches.Create(&req, userID, username)
	if err != nil {
		respondBatchError(c, apierror.CodeInternalChangeSecretBatchCreate, err)
		return
	}
	go h.runner.RunBatch(batch, assetIDs)
	c.JSON(http.StatusAccepted, gin.H{"data": newBatchDTO(batch)})
}

// ListBatches 最近批次
func (h *ChangeSecretHandler) ListBatches(c *gin.Context) {
	items, err := h.batches.List()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalChangeSecretBatchQuery, err)
		return
	}
	out := make([]changeSecretBatchDTO, 0, len(items))
	for i := range items {
		out = append(out, newBatchDTO(&items[i]))
	}
	c.JSON(http.StatusOK, gin.H{"data": out, "total": len(out)})
}

// GetBatch 單一批次含逐目標記錄
func (h *ChangeSecretHandler) GetBatch(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "change_secret_batch"})
		return
	}
	batch, err := h.batches.Get(uint(id))
	if err != nil {
		respondBatchError(c, apierror.CodeInternalChangeSecretBatchQuery, err)
		return
	}
	records, err := h.batches.Records(batch.ID)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalChangeSecretRecordQuery, err)
		return
	}
	if records == nil {
		records = []model.ChangeSecretRecord{}
	}
	c.JSON(http.StatusOK, gin.H{"data": gin.H{"batch": newBatchDTO(batch), "records": records}})
}

// respondBatchError 映射 service 錯誤：輸入問題 400、不存在 404，其餘走呼叫端指定的 internalCode
func respondBatchError(c *gin.Context, internalCode apierror.ErrCode, err error) {
	switch {
	case errors.Is(err, asset.ErrBatchUsernameRequired):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBatchUsernameRequired, nil)
	case errors.Is(err, asset.ErrBatchBadPasswordMode):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBatchBadPasswordMode, nil)
	case errors.Is(err, asset.ErrBatchNoTargets):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBatchNoTargets, nil)
	case errors.Is(err, asset.ErrBatchTargetMismatch):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBatchTargetMismatch, nil)
	case errors.Is(err, asset.ErrPasswordLengthOutOfRange):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodePlanBadPasswordLen, nil)
	case errors.Is(err, asset.ErrBatchNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeBatchNotFound, nil)
	default:
		apierror.RespondInternal(c, http.StatusInternalServerError, internalCode, err)
	}
}
