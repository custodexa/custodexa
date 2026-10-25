package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/gin-gonic/gin"
)

// RoleAssignmentPreviewer 唯讀的有效能力預覽。
type RoleAssignmentPreviewer interface {
	Preview(req authz.PreviewRequest) (authz.PreviewResult, error)
}

// RoleAssignmentPreviewHandler 危險組合預覽 API：不寫資料、不推進版本。
type RoleAssignmentPreviewHandler struct {
	previewer RoleAssignmentPreviewer
}

// NewRoleAssignmentPreviewHandler 建立 handler。
func NewRoleAssignmentPreviewHandler(p RoleAssignmentPreviewer) *RoleAssignmentPreviewHandler {
	return &RoleAssignmentPreviewHandler{previewer: p}
}

// idListField 記得 JSON 鍵是否出現：null 也算出現，解碼後的 nil 切片無法分辨省略與 null。
type idListField struct {
	present bool
	ids     []uint
}

// UnmarshalJSON 非指標欄位遇到 null 時同樣會被呼叫，故能記下鍵存在。
func (f *idListField) UnmarshalJSON(b []byte) error {
	f.present = true
	return json.Unmarshal(b, &f.ids)
}

type roleAssignmentPreviewBody struct {
	Kind    string `json:"kind"`
	UserID  uint   `json:"user_id"`
	GroupID uint   `json:"group_id"`
	RoleIDs []uint `json:"role_ids"`
	// RoleNodes 與寫入同形的節點範圍輸入：{"<角色編號>": [節點ID…] | null}，省略保留、null 全域、陣列節點。
	RoleNodes json.RawMessage `json:"role_nodes"`
	MemberIDs idListField     `json:"member_ids"`
	// ManualMemberIDs 變更後的手動成員集合（只改手動成分，與寫入同義）；與 member_ids 二擇一。
	ManualMemberIDs idListField `json:"manual_member_ids"`
	RoleID          uint        `json:"role_id"`
	Permissions     []string    `json:"permissions"`
	// IncludeManagedAssetCounts 選用：要求回可管理資產台數（只有直接指派與群組角色指派會回，其他種類忽略）。
	IncludeManagedAssetCounts bool `json:"include_managed_asset_counts"`
	// raw 解碼時留存的原始本文：只有映射規則變更種類用它做嚴格解碼，其餘種類不讀。
	raw []byte
}

// UnmarshalJSON 照現行方式解碼，並留存原始本文（綁定點維持單一的 ShouldBindJSON，不另讀請求本文）。
func (b *roleAssignmentPreviewBody) UnmarshalJSON(data []byte) error {
	type plain roleAssignmentPreviewBody
	if err := json.Unmarshal(data, (*plain)(b)); err != nil {
		return err
	}
	b.raw = append(b.raw[:0], data...)
	return nil
}

// previewAllowed 呼叫者須具備被預覽的那種寫入所需能力；角色定義變更預覽限超級管理者。
func previewAllowed(p *authz.Principal, kind string) bool {
	switch kind {
	case authz.PreviewDirectRoles:
		return p.Has(authz.PermUserManage)
	case authz.PreviewGroupRoles, authz.PreviewGroupMembers:
		return p.Has(authz.PermUserGroupManage)
	case authz.PreviewRoleDefinition:
		return p.IsSuperAdmin()
	case authz.PreviewMappingRuleChange:
		// 路由已要求 role:assign；映射規則的寫入另需身分來源管理能力
		return p.Has(authz.PermIdentitySourceManage)
	}
	return false
}

// previewDenial 預覽被拒時的能力拒絕依據，與 previewAllowed 逐種類對應。
// 呼叫前 kind 已限定為五種已知種類（未知種類回 400）。
func previewDenial(kind string) middleware.CapabilityDenial {
	switch kind {
	case authz.PreviewGroupRoles, authz.PreviewGroupMembers:
		return middleware.AllOfCapabilityDenial(authz.PermUserGroupManage)
	case authz.PreviewRoleDefinition:
		return middleware.ReservedCapabilityDenial(authz.ReservedSuperAdmin)
	case authz.PreviewMappingRuleChange:
		return middleware.AllOfCapabilityDenial(authz.PermIdentitySourceManage)
	default: // authz.PreviewDirectRoles
		return middleware.AllOfCapabilityDenial(authz.PermUserManage)
	}
}

// mappingRuleChangeBody 映射規則變更的嚴格輸入：表列以外的鍵（含 subject_ids）一律拒絕。
type mappingRuleChangeBody struct {
	Kind       string  `json:"kind"`
	RuleType   string  `json:"rule_type"`
	SourceType string  `json:"source_type"`
	SourceID   uint    `json:"source_id"`
	RuleID     uint    `json:"rule_id"`
	MatchValue *string `json:"match_value"`
	RoleID     uint    `json:"role_id"`
	GroupID    uint    `json:"group_id"`
	Enabled    *bool   `json:"enabled"`
	Delete     bool    `json:"delete"`
	// IncludeManagedAssetCounts 已知的選用鍵：映射規則變更沒有台數，收下並忽略其值。
	IncludeManagedAssetCounts json.RawMessage `json:"include_managed_asset_counts"`
}

// decodeMappingRuleChange 只對映射規則變更種類做嚴格解碼，既有四種維持現行解碼。
func decodeMappingRuleChange(raw []byte) (authz.MappingRuleChange, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var b mappingRuleChangeBody
	if err := dec.Decode(&b); err != nil || dec.More() {
		return authz.MappingRuleChange{}, false
	}
	return authz.MappingRuleChange{
		RuleType: b.RuleType, SourceType: b.SourceType, SourceID: b.SourceID, RuleID: b.RuleID,
		MatchValue: b.MatchValue, RoleID: b.RoleID, GroupID: b.GroupID, Enabled: b.Enabled, Delete: b.Delete,
	}, true
}

// previewRoleNodes 解析預覽的 role_nodes：鍵必須是角色編號的十進位字串；形狀錯誤回 false。
// 鍵是否在 role_ids 內、節點集合是否為空由預覽輸入檢查裁決。
func previewRoleNodes(raw json.RawMessage) (map[uint]authz.PreviewRoleRange, bool) {
	parsed, ok := parseRoleNodes(raw)
	if !ok {
		return nil, false
	}
	if len(parsed) == 0 {
		return nil, true
	}
	out := make(map[uint]authz.PreviewRoleRange, len(parsed))
	for k, v := range parsed {
		rid, err := strconv.ParseUint(k, 10, 32)
		if err != nil {
			return nil, false
		}
		out[uint(rid)] = authz.PreviewRoleRange{Global: v.Global, NodeIDs: v.NodeIDs}
	}
	return out, true
}

// Preview 計算預覽。
func (h *RoleAssignmentPreviewHandler) Preview(c *gin.Context) {
	var body roleAssignmentPreviewBody
	if err := c.ShouldBindJSON(&body); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	switch body.Kind {
	case authz.PreviewDirectRoles, authz.PreviewGroupRoles, authz.PreviewGroupMembers, authz.PreviewRoleDefinition,
		authz.PreviewMappingRuleChange:
	default:
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	if !previewAllowed(middleware.PrincipalFrom(c), body.Kind) {
		middleware.WriteCapabilityDenial(c, previewDenial(body.Kind))
		return
	}
	if body.ManualMemberIDs.present && body.MemberIDs.present {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	var rule *authz.MappingRuleChange
	if body.Kind == authz.PreviewMappingRuleChange {
		change, ok := decodeMappingRuleChange(body.raw)
		if !ok {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
			return
		}
		rule = &change
	}
	// 只送 manual_member_ids: null（沒有 member_ids）維持舊語義：視同未送手動成員輸入
	var manualIDs *[]uint
	if body.ManualMemberIDs.ids != nil {
		manualIDs = &body.ManualMemberIDs.ids
	}
	roleNodes, ok := previewRoleNodes(body.RoleNodes)
	if !ok {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	operatorID, _ := middleware.GetCurrentUserID(c)
	res, err := h.previewer.Preview(authz.PreviewRequest{
		Kind: body.Kind, OperatorID: operatorID, UserID: body.UserID, GroupID: body.GroupID,
		RoleIDs: body.RoleIDs, RoleNodes: roleNodes, MemberIDs: body.MemberIDs.ids, ManualMemberIDs: manualIDs, RoleID: body.RoleID, Permissions: body.Permissions,
		MappingRule: rule, IncludeManagedAssetCounts: body.IncludeManagedAssetCounts,
	})
	if err != nil {
		if errors.Is(err, authz.ErrPreviewInvalid) || errors.Is(err, authz.ErrPreviewRoleNotCustom) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalRoleAssignmentPreview, err)
		return
	}
	c.JSON(http.StatusOK, res)
}

// RegisterRoutes 註冊預覽路由（權限由路由登錄表裁決）。
func (h *RoleAssignmentPreviewHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	g := r.Group("/role-assignment-previews")
	g.Use(middleware.AuthMiddleware(authService), middleware.EnforceRegistry())
	g.POST("", h.Preview)
}
