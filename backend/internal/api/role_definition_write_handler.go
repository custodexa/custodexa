package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strconv"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/gin-gonic/gin"
)

// RoleDefinitionWriter 角色定義的寫入服務（由 identity.RoleDefinitionService 實作）。
// 超級管理者身分、版本比對、引用檢查與授權變更分級都在服務的交易內裁決；handler 只轉呼叫與映射錯誤。
type RoleDefinitionWriter interface {
	Create(ctx context.Context, actorID uint, in identity.RoleInput) (*identity.RoleDefinition, error)
	Copy(ctx context.Context, actorID, sourceRoleID uint, name, description string) (*identity.RoleDefinition, error)
	Update(ctx context.Context, actorID, roleID uint, expectedVersion int64, in identity.RoleInput) (*identity.RoleDefinition, error)
	Delete(ctx context.Context, actorID, roleID uint, expectedVersion int64) error
}

// decodeStrictBody 嚴格解碼請求本文：頂層出現表列以外的鍵、型別不符、
// 本文尾端有多餘內容一律 400；失敗時已回應，回傳 false。
func decodeStrictBody(c *gin.Context, dst any) bool {
	raw, err := c.GetRawData()
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return false
	}
	// 第二次解碼必須恰為 EOF：More() 遇到多餘的右括號會回 false，無法證明本文已結束
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return false
	}
	return true
}

// 四種寫入的請求本文。未列的鍵一律 400；期望版本用指標以分辨「沒給」與 0。
type roleCreateBody struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Permissions    []string `json:"permissions"`
	TemplateRoleID *uint    `json:"template_role_id"`
}

type roleCopyBody struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type roleUpdateBody struct {
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	Permissions     []string `json:"permissions"`
	ExpectedVersion *int64   `json:"expected_version"`
}

// respondRoleDefinitionWriteError 把服務錯誤映射成機器碼：已知的業務拒絕沿用既有碼，
// 其餘（分級器或事件寫入器未注入、資料庫錯誤等）一律泛化為 INTERNAL_ROLE_DEFINITION_WRITE，
// 原因只進伺服器日誌，不回 err.Error()，拒絕回應也不帶角色名或權限名。
func respondRoleDefinitionWriteError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, identity.ErrRoleDefinitionForbidden):
		// 角色定義寫入限超管（服務層 requireSuperAdmin：操作者不存在、停用、agent、非超管同一哨兵）
		middleware.WriteCapabilityDenial(c, middleware.ReservedCapabilityDenial(authz.ReservedSuperAdmin))
	case errors.Is(err, identity.ErrRoleDefinitionNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeRoleNotFound, nil)
	case errors.Is(err, identity.ErrRoleDefinitionLocked):
		apierror.Respond(c, http.StatusConflict, apierror.CodeRoleDefinitionLocked, nil)
	case errors.Is(err, identity.ErrRoleDefinitionInUse):
		apierror.Respond(c, http.StatusConflict, apierror.CodeRoleDefinitionInUse, nil)
	case errors.Is(err, identity.ErrRoleDefinitionConflict):
		apierror.Respond(c, http.StatusConflict, apierror.CodeRoleDefinitionConflict, nil)
	case errors.Is(err, identity.ErrRoleDefinitionInput):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
	case authz.IsInvalidRolePermission(err):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeRolePermissionInvalid, nil)
	case errors.Is(err, identity.ErrAgentRoleForbidden):
		// 修改後的內容含 agent 不得持有的能力，而已有 agent 持有它：與指派 agent 時同一個拒絕碼；
		// 受影響 agent 數與受限權限點併入本次請求的審計列（服務層不另寫拒絕審計）
		noteAgentRoleUpdateRejection(c, err)
		respondPrincipalError(c, err)
	default:
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalRoleDefinitionWrite, err)
	}
}

// isNilWriter 同時涵蓋 nil 介面與持有 nil 指標的介面（typed-nil），兩者都不能進服務。
func isNilWriter(w RoleDefinitionWriter) bool {
	if w == nil {
		return true
	}
	v := reflect.ValueOf(w)
	return v.Kind() == reflect.Ptr && v.IsNil()
}

// writerOrFail 取寫入服務；未注入時以內部錯誤拒絕（fail-close，不當成功略過）。
func (h *RoleDefinitionHandler) writerOrFail(c *gin.Context) (RoleDefinitionWriter, uint, bool) {
	if isNilWriter(h.writer) {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalRoleDefinitionWrite,
			errors.New("role definition writer not wired"))
		return nil, 0, false
	}
	actorID, _ := middleware.GetCurrentUserID(c)
	return h.writer, actorID, true
}

func roleIDParam(c *gin.Context) (uint, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil || id == 0 {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, nil)
		return 0, false
	}
	return uint(id), true
}

// Create 新增自訂角色（可選起手範本 ID）。
func (h *RoleDefinitionHandler) Create(c *gin.Context) {
	var body roleCreateBody
	if !decodeStrictBody(c, &body) {
		return
	}
	w, actorID, ok := h.writerOrFail(c)
	if !ok {
		return
	}
	def, err := w.Create(c.Request.Context(), actorID, identity.RoleInput{
		Name: body.Name, Description: body.Description, Permissions: body.Permissions, TemplateRoleID: body.TemplateRoleID})
	if err != nil {
		respondRoleDefinitionWriteError(c, err)
		return
	}
	c.JSON(http.StatusCreated, identity.NewRoleDefinitionDetail(def))
}

// Copy 以既有角色為來源複製出新的自訂角色。
func (h *RoleDefinitionHandler) Copy(c *gin.Context) {
	id, ok := roleIDParam(c)
	if !ok {
		return
	}
	var body roleCopyBody
	if !decodeStrictBody(c, &body) {
		return
	}
	w, actorID, ok := h.writerOrFail(c)
	if !ok {
		return
	}
	def, err := w.Copy(c.Request.Context(), actorID, id, body.Name, body.Description)
	if err != nil {
		respondRoleDefinitionWriteError(c, err)
		return
	}
	c.JSON(http.StatusCreated, identity.NewRoleDefinitionDetail(def))
}

// Update 修改自訂角色（整組取代權限集合，帶期望版本）。權限集合與期望版本必須出現在本文。
func (h *RoleDefinitionHandler) Update(c *gin.Context) {
	id, ok := roleIDParam(c)
	if !ok {
		return
	}
	var body roleUpdateBody
	if !decodeStrictBody(c, &body) {
		return
	}
	if body.ExpectedVersion == nil || body.Permissions == nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	w, actorID, ok := h.writerOrFail(c)
	if !ok {
		return
	}
	def, err := w.Update(c.Request.Context(), actorID, id, *body.ExpectedVersion, identity.RoleInput{
		Name: body.Name, Description: body.Description, Permissions: body.Permissions})
	if err != nil {
		respondRoleDefinitionWriteError(c, err)
		return
	}
	c.JSON(http.StatusOK, identity.NewRoleDefinitionDetail(def))
}

// deleteHasNoBody 以實際讀取判定請求沒有本文：不依賴 ContentLength（chunked 等未知長度為 -1），
// 讀到任何位元組或讀取出錯都視為有本文。
func deleteHasNoBody(r *http.Request) bool {
	if r.Body == nil || r.Body == http.NoBody {
		return true
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, 1))
	return err == nil && len(b) == 0
}

// Delete 刪除自訂角色；期望版本由查詢參數 expected_version 帶入，不接受請求本文。
func (h *RoleDefinitionHandler) Delete(c *gin.Context) {
	id, ok := roleIDParam(c)
	if !ok {
		return
	}
	if !deleteHasNoBody(c.Request) {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	vals, err := url.ParseQuery(c.Request.URL.RawQuery)
	if err != nil || len(vals) != 1 || len(vals["expected_version"]) != 1 {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	v, err := strconv.ParseInt(vals["expected_version"][0], 10, 64)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	w, actorID, ok := h.writerOrFail(c)
	if !ok {
		return
	}
	if err := w.Delete(c.Request.Context(), actorID, id, v); err != nil {
		respondRoleDefinitionWriteError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
