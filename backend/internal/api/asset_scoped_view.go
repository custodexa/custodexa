package api

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sort"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/authz/disclosure"
)

// 資產頁的範圍化檢視者投影（接入層）：只對範圍化檢視者生效，其餘主體走現行路徑、回應鍵集不變。
//   - 列表＝管理可視 ∪ 連線可視，篩選在聯集內、分頁之前計算；
//   - 經管理可視的列只帶範圍內歸屬與範圍外計數，不帶連線欄；
//   - 每列附伺服器算出的動作旗標，頂層附管理範圍摘要。
// 揭露值（範圍外計數）只在本層由純整數轉出。

// AssetScopeSource 資產頁範圍化投影的來源（authz.AssetScopeReader 實作）。
type AssetScopeSource interface {
	View(ctx context.Context) (*authz.AssetScopeView, error)
	ManagementVisibleIDs(v *authz.AssetScopeView) ([]uint, error)
	ManagementVisibleAsset(ctx context.Context, assetID uint) (bool, *authz.AssetScopeView, error)
	AssetViewScopeDenial(ctx context.Context, assetID uint) (*authz.ErrScopeDenied, error)
}

// 回應欄名（只出現在範圍化檢視者的回應中）。
const (
	assetFieldActions         = "actions"
	assetFieldManagementScope = "management_scope"
)

type assetActionDTO struct {
	Allowed bool                       `json:"allowed"`
	Reason  string                     `json:"reason,omitempty"`
	Count   *disclosure.NodeCountValue `json:"count,omitempty"`
}

type assetRowActionsDTO struct {
	Edit           assetActionDTO `json:"edit"`
	Disable        assetActionDTO `json:"disable"`
	Delete         assetActionDTO `json:"delete"`
	TestConnection assetActionDTO `json:"test_connection"`
	ManageAccounts assetActionDTO `json:"manage_accounts"`
}

type managementScopeNodeDTO struct {
	ID   uint   `json:"id"`
	Path string `json:"path"`
}

type managementScopeDTO struct {
	EffectiveNodeCount int                      `json:"effective_node_count"`
	InactiveNodeCount  int                      `json:"inactive_node_count"`
	Nodes              []managementScopeNodeDTO `json:"nodes"`
}

func outOfScopeNodeCount(n int) disclosure.NodeCountValue {
	return disclosure.NodeCountValue{Value: disclosure.Count(disclosure.OutOfScopeNodeCount, n)}
}

func actionDTO(a authz.AssetAction) assetActionDTO {
	out := assetActionDTO{Allowed: a.Allowed, Reason: a.Reason}
	if a.Reason == authz.AssetActionReasonOutOfScopeNodes {
		v := outOfScopeNodeCount(a.OutOfScopeNodes)
		out.Count = &v
	}
	return out
}

func rowActionsDTO(a authz.AssetRowActions) assetRowActionsDTO {
	return assetRowActionsDTO{
		Edit: actionDTO(a.Edit), Disable: actionDTO(a.Disable), Delete: actionDTO(a.Delete),
		TestConnection: actionDTO(a.TestConnection), ManageAccounts: actionDTO(a.ManageAccounts),
	}
}

func managementScopeOf(v *authz.AssetScopeView) managementScopeDTO {
	out := managementScopeDTO{
		EffectiveNodeCount: v.Summary.EffectiveNodeCount,
		InactiveNodeCount:  v.Summary.InactiveNodeCount,
		Nodes:              make([]managementScopeNodeDTO, 0, len(v.Summary.Nodes)),
	}
	for _, n := range v.Summary.Nodes {
		out.Nodes = append(out.Nodes, managementScopeNodeDTO{ID: n.ID, Path: n.Path})
	}
	return out
}

// SetAssetScope 注入資產頁範圍化投影來源（組裝端呼叫）。未注入＝不帶範圍化欄位、只見連線可視，不擴大資料。
func (h *AssetHandler) SetAssetScope(s AssetScopeSource) { h.assetScope = s }

// assetScopeView 請求主體的範圍化投影；非範圍化檢視者或未注入時回 nil。
func (h *AssetHandler) assetScopeView(c *gin.Context) (*authz.AssetScopeView, error) {
	if h.assetScope == nil {
		return nil, nil
	}
	return h.assetScope.View(authz.ContextWithPrincipal(c.Request.Context(), middleware.PrincipalFrom(c)))
}

// scopedRow 以既有列的序列化結果為底，依投影改寫歸屬欄並加上旗標。masked＝該列經管理可視，
// 歸屬改為範圍內節點並附範圍外計數；否則歸屬欄維持原樣。nodeIDs 為該資產的全部歸屬。
func scopedRow(base any, nodeIDs []uint, paths map[uint]string, v *authz.AssetScopeView, masked bool) (map[string]any, error) {
	raw, err := json.Marshal(base)
	if err != nil {
		return nil, err
	}
	row := map[string]any{}
	if err := json.Unmarshal(raw, &row); err != nil {
		return nil, err
	}
	if masked {
		in, out := v.MaskNodes(nodeIDs)
		delete(row, "node_ids")
		delete(row, "node_paths")
		if len(in) > 0 {
			ps := make([]string, 0, len(in))
			for _, id := range in {
				ps = append(ps, paths[id])
			}
			row["node_ids"], row["node_paths"] = in, ps
		}
		row[disclosure.FieldOutOfScopeNodeCount] = disclosure.Count(disclosure.OutOfScopeNodeCount, out)
	}
	row[assetFieldActions] = rowActionsDTO(v.Actions(nodeIDs))
	return row, nil
}

// scopedVisibleUnion 範圍化檢視者的可視聯集：連線可視（現行授權集合）與管理可視（集合述詞）。
// 資產列表與儀表板資產卡共用，兩邊總數同源。
func scopedVisibleUnion(ctx context.Context, auth AssetAuthorizationServiceInterface, scope AssetScopeSource,
	v *authz.AssetScopeView, p *authz.Principal, userID uint) (map[uint]*authz.AuthorizedAssetDTO, map[uint]bool, []uint, error) {
	conn, err := authorizedAssetsOf(ctx, auth, p, userID)
	if err != nil {
		return nil, nil, nil, err
	}
	mgmtIDs, err := scope.ManagementVisibleIDs(v)
	if err != nil {
		return nil, nil, nil, err
	}
	connMap := make(map[uint]*authz.AuthorizedAssetDTO, len(conn))
	seen := map[uint]bool{}
	union := make([]uint, 0, len(conn)+len(mgmtIDs))
	for _, d := range conn {
		connMap[d.ID] = d
		if !seen[d.ID] {
			seen[d.ID] = true
			union = append(union, d.ID)
		}
	}
	mgmt := make(map[uint]bool, len(mgmtIDs))
	for _, id := range mgmtIDs {
		mgmt[id] = true
		if !seen[id] {
			seen[id] = true
			union = append(union, id)
		}
	}
	sort.Slice(union, func(i, j int) bool { return union[i] < union[j] })
	return connMap, mgmt, union, nil
}

// scopedNodeFilter 節點篩選的來源矩陣：只經連線可視的列以完整歸屬比對（現行語義）；
// 經管理可視的列只以範圍內歸屬比對，篩選節點在範圍外時不命中；未分組篩選對經管理可視的列不命中。
func (h *AssetHandler) scopedNodeFilter(ids []uint, mgmt map[uint]bool, v *authz.AssetScopeView,
	nodeID *uint, includeSubtree, ungrouped bool) ([]uint, error) {
	full, err := h.assetService.AssetIDsForNodeFilter(nodeID, includeSubtree, ungrouped)
	if err != nil {
		return nil, err
	}
	var filterNodes map[uint]bool
	var mounts map[uint][]uint
	if !ungrouped && nodeID != nil {
		if filterNodes, err = asset.NodeFilterNodeIDs(database.DB, *nodeID, includeSubtree); err != nil {
			return nil, err
		}
		cand := make([]uint, 0, len(ids))
		for _, id := range ids {
			if mgmt[id] && full[id] {
				cand = append(cand, id)
			}
		}
		if mounts, err = asset.NodeIDsOfAssets(database.DB, cand); err != nil {
			return nil, err
		}
	}
	kept := make([]uint, 0, len(ids))
	for _, id := range ids {
		if !mgmt[id] {
			if full[id] {
				kept = append(kept, id)
			}
			continue
		}
		if ungrouped || !full[id] {
			continue
		}
		in, _ := v.MaskNodes(mounts[id])
		for _, n := range in {
			if filterNodes[n] {
				kept = append(kept, id)
				break
			}
		}
	}
	return kept, nil
}

// scopedListQuery 範圍化列表的查詢參數（已由 List 解析）。
type scopedListQuery struct {
	page, pageSize    int
	nodeID            *uint
	includeSubtree    bool
	ungrouped         bool
	credentialPending bool
	tags              []string
}

// scopedList 非檢視捷徑的範圍化檢視者的資產列表。
func (h *AssetHandler) scopedList(c *gin.Context, v *authz.AssetScopeView, q scopedListQuery) {
	userID, exists := middleware.GetCurrentUserID(c)
	if !exists {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return
	}
	p := middleware.PrincipalFrom(c)
	connMap, mgmt, union, err := scopedVisibleUnion(c.Request.Context(), h.authorizationService, h.assetScope, v, p, userID)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAuthorizedAssetQuery, err)
		return
	}
	if q.nodeID != nil || q.ungrouped {
		if union, err = h.scopedNodeFilter(union, mgmt, v, q.nodeID, q.includeSubtree, q.ungrouped); err != nil {
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetNodeFilter, err)
			return
		}
	}
	filter := &asset.AssetFilter{
		Search: c.Query("search"), Protocol: model.ProtocolType(c.Query("protocol")),
		Page: q.page, PageSize: q.pageSize, CredentialPending: q.credentialPending, RestrictIDs: union,
		Tags: q.tags,
	}
	if activeStr := c.Query("active"); activeStr != "" {
		active := activeStr == "true"
		filter.Active = &active
	}
	result, err := h.assetService.List(filter)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetQuery, err)
		return
	}
	connRows := make([]*authz.AuthorizedAssetDTO, 0, len(result.Data))
	for _, a := range result.Data {
		if d, ok := connMap[a.ID]; ok {
			connRows = append(connRows, d)
		}
	}
	if h.accessState != nil && len(connRows) > 0 {
		if err := h.accessState.AnnotateConnectStates(userID, connRows); err != nil {
			logAssetList("三態標註失敗（列表照常回傳）", err)
		}
	}
	if err := h.authorizationService.FillNodeInfoForDTOs(connRows); err != nil {
		logAssetList("節點資訊填充失敗（列表照常回傳）", err)
	}
	paths, err := asset.NodePathMap(database.DB)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetQuery, err)
		return
	}
	rows := make([]map[string]any, 0, len(result.Data))
	for i := range result.Data {
		a := &result.Data[i]
		var base any = a
		if d, ok := connMap[a.ID]; ok {
			base = d
		}
		row, err := scopedRow(base, a.NodeIDs, paths, v, mgmt[a.ID])
		if err != nil {
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetQuery, err)
			return
		}
		rows = append(rows, row)
	}
	c.JSON(http.StatusOK, gin.H{
		"data": rows, "total": result.Total, "page": result.Page, "page_size": result.PageSize,
		assetFieldManagementScope: managementScopeOf(v),
	})
}

// decorateFullRows 檢視捷徑主體另帶節點範圍指派時：全量列附旗標與恆為零的範圍外計數（檢視範圍為全系統）。
func decorateFullRows[T any](rows []T, nodeIDsOf func(int) []uint, v *authz.AssetScopeView) ([]map[string]any, error) {
	out := make([]map[string]any, 0, len(rows))
	for i := range rows {
		row, err := scopedRow(rows[i], nodeIDsOf(i), nil, v, false)
		if err != nil {
			return nil, err
		}
		row[disclosure.FieldOutOfScopeNodeCount] = disclosure.Count(disclosure.OutOfScopeNodeCount, 0)
		out = append(out, row)
	}
	return out, nil
}

// scopedDetail 範圍化檢視者的詳情與寫入成功回應；一律附旗標。只經連線可視時歸屬維持原樣，
// 其餘情形遮蔽歸屬並附範圍外計數。gated＝請求已過逐資產守門（詳情）：管理可視不成立即表示連線可視成立。
// 寫入端點沒有該守門，管理可視不成立時另以同一判定查連線可視；兩者皆否（詳情對同一主體回不存在）時
// 同樣遮蔽，回應只剩範圍內歸屬（此時為空）與範圍外計數，不帶出範圍外節點的識別碼、名稱或路徑。
// served=false 表示請求主體不是範圍化檢視者，呼叫方回現行形狀。
func (h *AssetHandler) scopedDetail(c *gin.Context, a *model.Asset, gated bool) (map[string]any, bool, error) {
	ctx := authz.ContextWithPrincipal(c.Request.Context(), middleware.PrincipalFrom(c))
	managed, v, err := h.assetScope.ManagementVisibleAsset(ctx, a.ID)
	if err != nil || v == nil {
		return nil, false, err
	}
	masked := managed
	if !managed && !gated {
		visible, err := h.connectionVisible(c, ctx, a.ID)
		if err != nil {
			return nil, false, err
		}
		masked = !visible
	}
	paths := map[uint]string{}
	if masked && len(a.NodeIDs) > 0 {
		if paths, err = asset.NodePathMap(database.DB); err != nil {
			return nil, false, err
		}
	}
	row, err := scopedRow(a, a.NodeIDs, paths, v, masked)
	if err != nil {
		return nil, false, err
	}
	return row, true, nil
}

// connectionVisible 與逐資產守門相同的連線可視判定（授權的 view，含 connect／manage 推導）。
// 取不到使用者或未注入授權服務時視為不成立（回應遮蔽，不放寬）。
func (h *AssetHandler) connectionVisible(c *gin.Context, ctx context.Context, assetID uint) (bool, error) {
	userID, ok := middleware.GetCurrentUserID(c)
	if !ok || h.authorizationService == nil {
		return false, nil
	}
	return h.authorizationService.CheckPermission(ctx, userID, assetID, model.PermissionView)
}

// managementVisibility 逐資產守門的管理可視來源；未注入時回 nil（守門與現行相同）。
func (h *AssetHandler) managementVisibility() middleware.AssetManagementVisibility {
	if h.assetScope == nil {
		return nil
	}
	return h.assetScope
}

// requireManagedTest 只經管理可視讀 pod 清單時，測試連線能力的有效範圍須涵蓋該資產；否則單一 forbidden。
func (h *AssetHandler) requireManagedTest(c *gin.Context, assetID uint) bool {
	v, err := h.assetScopeView(c)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetQuery, err)
		return false
	}
	if v != nil {
		mounts, err := asset.NodeIDsOfAssets(database.DB, []uint{assetID})
		if err != nil {
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetQuery, err)
			return false
		}
		if v.HasOpScope(authz.PermAssetTest, mounts[assetID]) {
			return true
		}
	}
	middleware.WriteCapabilityDenial(c, middleware.AllOfCapabilityDenial(authz.PermAssetTest))
	return false
}

func logAssetList(msg string, err error) { log.Printf("[AssetList] %s: %v", msg, err) }
