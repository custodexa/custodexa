package api

import (
	"errors"
	"net/http"
	"sort"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
)

// assignmentNodeLister 指派畫面用的節點清單（由 asset 模組實作）。
type assignmentNodeLister interface {
	AssignmentNodes() ([]asset.AssignmentNode, error)
}

// roleNodeScopabilityLister 全部角色以節點範圍指派時的判定（由 identity 模組實作，
// 判定本身是 authz 的同一個函式，與寫入關卡一致）。
type roleNodeScopabilityLister interface {
	List() ([]identity.RoleNodeScopabilityEntry, error)
}

// RoleAssignmentOptionsHandler 指派角色畫面的選項：節點清單與角色能否限定節點。
// 只組裝兩個窄介面的結果，不直查任何資料表。
type RoleAssignmentOptionsHandler struct {
	nodes assignmentNodeLister
	roles roleNodeScopabilityLister
}

// NewRoleAssignmentOptionsHandler 建立 handler；兩個來源都由組裝根注入。
func NewRoleAssignmentOptionsHandler(nodes assignmentNodeLister, roles roleNodeScopabilityLister) *RoleAssignmentOptionsHandler {
	return &RoleAssignmentOptionsHandler{nodes: nodes, roles: roles}
}

type assignmentOptionNode struct {
	ID                uint   `json:"id"`
	Name              string `json:"name"`
	ParentID          *uint  `json:"parent_id"`
	Depth             int    `json:"depth"`
	Path              string `json:"path"`
	SubtreeAssetCount int    `json:"subtree_asset_count"`
}

type roleAssignmentOptionsResponse struct {
	Nodes                   []assignmentOptionNode `json:"nodes"`
	NodeAssignableRoleIDs   []uint                 `json:"node_assignable_role_ids"`
	NodeRangeNoEffectIDs    []uint                 `json:"node_range_no_effect_role_ids"`
	NodeRangeNoEffectReason map[string]string      `json:"node_range_no_effect_reasons"`
}

// Options 回傳指派選項。任一來源未注入或讀取失敗都回內部錯誤，不回部分資料。
func (h *RoleAssignmentOptionsHandler) Options(c *gin.Context) {
	if h == nil || h.nodes == nil || h.roles == nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalRoleQuery,
			errors.New("指派選項來源未接線"))
		return
	}
	nodes, err := h.nodes.AssignmentNodes()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalRoleQuery, err)
		return
	}
	roles, err := h.roles.List()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalRoleQuery, err)
		return
	}
	res := roleAssignmentOptionsResponse{
		Nodes:                   make([]assignmentOptionNode, 0, len(nodes)),
		NodeAssignableRoleIDs:   []uint{},
		NodeRangeNoEffectIDs:    []uint{},
		NodeRangeNoEffectReason: map[string]string{},
	}
	for _, n := range nodes {
		res.Nodes = append(res.Nodes, assignmentOptionNode{
			ID: n.ID, Name: n.Name, ParentID: n.ParentID, Depth: n.Depth, Path: n.Path, SubtreeAssetCount: n.SubtreeAssetCount,
		})
	}
	for _, r := range roles {
		if r.Class == authz.NodeScopabilityRejected {
			continue
		}
		res.NodeAssignableRoleIDs = append(res.NodeAssignableRoleIDs, r.RoleID)
		if r.Class == authz.NodeScopabilityNoEffect {
			res.NodeRangeNoEffectIDs = append(res.NodeRangeNoEffectIDs, r.RoleID)
			res.NodeRangeNoEffectReason[strconv.FormatUint(uint64(r.RoleID), 10)] = string(r.Reason)
		}
	}
	sort.Slice(res.NodeAssignableRoleIDs, func(i, j int) bool { return res.NodeAssignableRoleIDs[i] < res.NodeAssignableRoleIDs[j] })
	sort.Slice(res.NodeRangeNoEffectIDs, func(i, j int) bool { return res.NodeRangeNoEffectIDs[i] < res.NodeRangeNoEffectIDs[j] })
	c.JSON(http.StatusOK, res)
}

// RegisterRoutes 註冊路由（權限由路由登錄表裁決）。
func (h *RoleAssignmentOptionsHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	g := r.Group("/role-assignment-options")
	g.Use(middleware.AuthMiddleware(authService), middleware.EnforceRegistry())
	g.GET("", h.Options)
}
