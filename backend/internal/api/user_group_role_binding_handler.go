package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/gin-gonic/gin"
)

// roleBindingService 群組角色指派的讀取與整組替換（由 UserGroupService 實作）。
type roleBindingService interface {
	RoleBindings(groupID uint) ([]authz.GroupRoleBinding, error)
	ReplaceRoleBindings(op identity.Operator, groupID uint, req identity.GroupRoleBindingsRequest) ([]authz.GroupRoleBinding, error)
	NodeRangeNoEffect(groupID uint) ([]identity.NodeRangeNoEffect, error)
}

func (h *UserGroupHandler) roleBindings(c *gin.Context) (roleBindingService, bool) {
	svc, ok := h.groups.(roleBindingService)
	if !ok {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalUserGroupQuery, errors.New("群組角色指派服務未接線"))
	}
	return svc, ok
}

func respondRoleBindingError(c *gin.Context, internalCode apierror.ErrCode, err error) {
	if errors.Is(err, identity.ErrRoleNotFound) {
		noteAssignmentDenyReason(c, err)
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeRoleNotFound, nil)
		return
	}
	respondUserGroupError(c, internalCode, err)
}

// ListRoleBindings 讀取群組目前的角色指派。
func (h *UserGroupHandler) ListRoleBindings(c *gin.Context) {
	id, ok := parseUserGroupID(c)
	if !ok {
		return
	}
	svc, ok := h.roleBindings(c)
	if !ok {
		return
	}
	rows, err := svc.RoleBindings(id)
	if err != nil {
		respondRoleBindingError(c, apierror.CodeInternalUserGroupQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows, "total": len(rows)})
}

// ReplaceRoleBindings 整組替換群組的角色指派。主體收 role_ids 與選用的 role_nodes；帶 role_nodes 以外的範圍欄位整筆拒絕。
func (h *UserGroupHandler) ReplaceRoleBindings(c *gin.Context) {
	id, ok := parseUserGroupID(c)
	if !ok {
		return
	}
	svc, ok := h.roleBindings(c)
	if !ok {
		return
	}
	raw, err := c.GetRawData()
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	var req identity.GroupRoleBindingsRequest
	for k := range fields {
		if k != roleNodesKey && isRoleScopeField(k) {
			req.ScopeRequested = true
		}
	}
	if rawIDs, has := fields["role_ids"]; !has || bytes.Equal(bytes.TrimSpace(rawIDs), []byte("null")) {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	} else if err := json.Unmarshal(rawIDs, &req.RoleIDs); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	// role_nodes：省略保留、null 改全域、陣列改節點；鍵必須是 role_ids 內的角色編號，否則整筆拒絕
	nodes, ok := parseRoleNodes(fields[roleNodesKey])
	if !ok {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	listed := map[uint]bool{}
	for _, rid := range req.RoleIDs {
		listed[rid] = true
	}
	if len(nodes) > 0 {
		req.RoleNodes = make(map[uint]identity.RoleNodesValue, len(nodes))
	}
	for k, v := range nodes {
		rid, perr := strconv.ParseUint(k, 10, 32)
		if perr != nil || !listed[uint(rid)] {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
			return
		}
		req.RoleNodes[uint(rid)] = v
	}
	rows, err := svc.ReplaceRoleBindings(operatorFromRequest(c), id, req)
	if err != nil {
		respondRoleBindingError(c, apierror.CodeInternalUserGroupUpdate, err)
		return
	}
	resp := gin.H{"data": rows, "total": len(rows)}
	noEffect, err := svc.NodeRangeNoEffect(id)
	if err != nil {
		respondRoleBindingError(c, apierror.CodeInternalUserGroupQuery, err)
		return
	}
	if len(noEffect) > 0 {
		resp["node_range_no_effect"] = noEffect
	}
	c.JSON(http.StatusOK, resp)
}

// externalMappingService 讀取指向群組的啟用中外部映射規則（由 UserGroupService 實作）。
type externalMappingService interface {
	ExternalMappingSources(groupID uint) ([]identity.UserGroupExternalMappingSource, error)
}

// ListExternalMappings 唯讀列出把外部群組帶進此群組的啟用中映射規則。
func (h *UserGroupHandler) ListExternalMappings(c *gin.Context) {
	id, ok := parseUserGroupID(c)
	if !ok {
		return
	}
	svc, ok := h.groups.(externalMappingService)
	if !ok {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalUserGroupQuery, errors.New("群組外部映射讀取服務未接線"))
		return
	}
	rows, err := svc.ExternalMappingSources(id)
	if err != nil {
		respondUserGroupError(c, apierror.CodeInternalUserGroupQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows, "total": len(rows)})
}
