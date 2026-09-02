package api

import (
	"context"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/sourceip"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"log"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/k8sproxy"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
)

// AssetServiceInterface 資產服務接口（用於測試注入）
type AssetServiceInterface interface {
	List(filter *asset.AssetFilter) (*asset.AssetListResponse, error)
	GetByID(id uint) (*model.Asset, error)
	Create(req *asset.CreateAssetRequest) (*model.Asset, error)
	Update(ctx context.Context, id uint, req *asset.UpdateAssetRequest) (*model.Asset, error)
	Delete(id uint) error
	TestConnection(ctx context.Context, id uint, timeout int) (*asset.ConnectionTestResult, error)
	ListK8sPods(ctx context.Context, id uint) ([]k8sproxy.PodInfo, error)
	K8sCopyToPod(ctx context.Context, id uint, pod, container, destPath, localPath string) error
	K8sCopyFromPod(ctx context.Context, id uint, pod, container, srcPath, localPath string) error
	AssetIDsForNodeFilter(nodeID *uint, includeSubtree, ungrouped bool) (map[uint]bool, error)
	ListTags() ([]asset.TagCount, error)
	RenameTag(ctx context.Context, from, to string) (int64, error)
	DeleteTag(ctx context.Context, name string) (int64, error)
}

// AssetAuthorizationServiceInterface 資產授權服務接口（用於測試注入）
type AssetAuthorizationServiceInterface interface {
	CheckPermission(ctx context.Context, userID, assetID uint, perm model.PermissionType) (bool, error)
	GetAuthorizedAssets(ctx context.Context, userID uint, perm model.PermissionType) ([]*authz.AuthorizedAssetDTO, error)
	ExplicitAuthorizedAssetIDs(userID uint, perm model.PermissionType) (map[uint]bool, error)
	// FillNodeInfoForDTOs 授權分支 DTO 的節點資訊填充。
	// **自 AssetServiceInterface 移來**：DTO 是授權服務的型別，
	// 填充是授權列表流程的一步；asset 只提供「一批資產的節點資訊」的能力。
	FillNodeInfoForDTOs(dtos []*authz.AuthorizedAssetDTO) error
}

// AccessStateAnnotator 連線入口三態標註
type AccessStateAnnotator interface {
	AnnotateConnectStates(userID uint, assets []*authz.AuthorizedAssetDTO) error
}

// AssetHandler 資產 API handler
type AssetHandler struct {
	assetService         AssetServiceInterface
	authorizationService AssetAuthorizationServiceInterface
	// accessState 一般 user 列表的連線入口三態標註；nil＝不標註
	//（既有測試路徑，前端沿 permission 欄渲染）
	accessState AccessStateAnnotator
	// auditSink k8s 檔案操作審計的投遞面（AP-04）。同 file_tap，
	// 本點現況直寫 database.DB 且不看 AuditLogEnabled，故注入的是 DirectSink
	auditSink gatewayapi.AsyncSink
	// dataTransfer 資料傳輸閘（data-transfer-control 4.3）：K8s 檔案進出與 SFTP
	// 面**同碼同語義**。nil＝不套閘（既有測試路徑，等同五鍵全允許）。
	//
	// 註：本端點的授權不對稱（只掛 PermAssetUpdate，不經 connect 授權／段位政策／
	// 帳號範圍複查，asset_handler.go 路由段）**不在本 change 修復**——本 change
	// 只補資料傳輸閘讓五鍵不說謊，完整對齊列為 #8 安全 backlog 清算輪的輸入
	dataTransfer *policy.DataTransferService
}

// SetDataTransfer 注入資料傳輸閘（組裝端呼叫）
func (h *AssetHandler) SetDataTransfer(dt *policy.DataTransferService) {
	h.dataTransfer = dt
}

// requireK8sTransferAllowed K8s 檔案端點的資料傳輸閘。被拒時已寫入 403 回應與
// StatusDenied 審計，回傳 false。與 SFTP 面同碼（apierror.CodeTransferDenied）
func (h *AssetHandler) requireK8sTransferAllowed(c *gin.Context, userID, assetID uint, action string, detail string) bool {
	if h.dataTransfer == nil {
		return true
	}
	allowed, err := h.dataTransfer.AllowsAction(c.Request.Context(), userID, assetID,
		policy.TransferChannelWeb, action)
	if err != nil {
		// fail-close：傳輸控制的失敗方向必須是擋住而非放行
		log.Printf("[AssetHandler] 傳輸能力解析失敗（fail-close 拒絕）: userID=%d assetID=%d action=%s err=%v",
			userID, assetID, action, err)
		allowed = false
	}
	if allowed {
		return true
	}
	auditAction := model.ActionFileUpload
	if action == policy.TransferActionFileDownload {
		auditAction = model.ActionFileDownload
	}
	// 被拒留痕：現行兩端點的審計皆在成功路徑，拒絕分支直接 return
	// 會讓「有沒有人試著把資料帶出去」無法回答
	h.auditK8sFileDenied(c, userID, assetID, auditAction, detail)
	apierror.Respond(c, http.StatusForbidden, apierror.CodeTransferDenied, map[string]any{
		"action": action,
		"reason": "global_policy",
	})
	return false
}

// SetAccessStateAnnotator 注入三態標註服務（組裝端呼叫）
func (h *AssetHandler) SetAccessStateAnnotator(a AccessStateAnnotator) {
	h.accessState = a
}

// NewAssetHandler 創建資產 handler
func NewAssetHandler(
	assetService AssetServiceInterface,
	authorizationService AssetAuthorizationServiceInterface,
	auditSink gatewayapi.AsyncSink,
) *AssetHandler {
	return &AssetHandler{
		assetService:         assetService,
		authorizationService: authorizationService,
		auditSink:            auditSink,
	}
}

// tagValidationCode 標籤驗證 sentinel → 機器碼。
// 第二回傳值 false＝非標籤驗證錯誤，交由呼叫端續判。
// 註：舊碼 Create/Update 對 ErrTagEmpty/ErrTagContainsComma 落 500、RenameTag 卻
// 落 400——同 sentinel 異狀態屬既有不一致；本表統一為語義正確的 400（刻意的
// 小幅正規化）。
func tagValidationCode(err error) (apierror.ErrCode, bool) {
	switch {
	case errors.Is(err, asset.ErrTagEmpty):
		return apierror.CodeTagEmpty, true
	case errors.Is(err, asset.ErrTagContainsComma):
		return apierror.CodeTagContainsComma, true
	case errors.Is(err, asset.ErrTagTooLong):
		return apierror.CodeTagTooLong, true
	case errors.Is(err, asset.ErrTooManyTags):
		return apierror.CodeTooManyTags, true
	case errors.Is(err, asset.ErrTagsTotalTooLong):
		return apierror.CodeTagsTotalTooLong, true
	}
	return "", false
}

// respondAssetError 資產寫入端點的統一錯誤出口：已知 sentinel 依 errors.Is 映射
// 到機器碼（狀態碼與遷移前逐一相同），未知一律 RespondInternal（成因只落日誌）。
// internalCode 為該端點的 INTERNAL_ASSET_<VERB> 碼。
func respondAssetError(c *gin.Context, internalCode apierror.ErrCode, err error) {
	if code, ok := tagValidationCode(err); ok {
		apierror.Respond(c, http.StatusBadRequest, code, nil)
		return
	}
	switch {
	case errors.Is(err, asset.ErrAssetNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetNotFound, nil)
	case errors.Is(err, asset.ErrAssetNoUsableAccount):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountNoneUsable, nil)
	case errors.Is(err, asset.ErrAssetAccountNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetAccountNotFound, nil)
	case errors.Is(err, asset.ErrAssetAccountUsernameExists):
		apierror.Respond(c, http.StatusConflict, apierror.CodeAccountUsernameExists, nil)
	case errors.Is(err, asset.ErrAssetAccountDefaultConflict):
		apierror.Respond(c, http.StatusConflict, apierror.CodeAccountDefaultConflict, nil)
	case errors.Is(err, asset.ErrAssetAccountDefaultMissing):
		apierror.Respond(c, http.StatusConflict, apierror.CodeAccountDefaultMissing, nil)
	case errors.Is(err, asset.ErrAssetAccountUsernameInvalid):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountUsernameInvalid, nil)
	case errors.Is(err, asset.ErrAssetAccountUsernameTooLong):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountUsernameTooLong, nil)
	case errors.Is(err, asset.ErrAssetNameExists):
		apierror.Respond(c, http.StatusConflict, apierror.CodeAssetNameExists, nil)
	case errors.Is(err, asset.ErrInvalidProtocol):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidProtocol, nil)
	case errors.Is(err, asset.ErrInvalidRDPSecurity):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidRDPSecurity, nil)
	case errors.Is(err, asset.ErrInvalidDBTLSMode):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidDBTLSMode, nil)
	case errors.Is(err, asset.ErrInvalidAllowedDatabases):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidAllowedDatabases, nil)
	case errors.Is(err, asset.ErrMSSQLHostComma):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeMSSQLHostComma, nil)
	case errors.Is(err, asset.ErrInvalidAccessPolicy):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidAccessPolicy, nil)
	default:
		apierror.RespondInternal(c, http.StatusInternalServerError, internalCode, err)
	}
}

// isPrivilegedRole 判斷請求者是否為 admin/auditor（角色缺失視為非特權，安全預設）
func isPrivilegedRole(c *gin.Context) bool {
	role, exists := c.Get("role")
	if !exists {
		return false
	}
	r, ok := role.(string)
	return ok && (r == model.RoleAdmin || r == model.RoleAuditor)
}

// isAuditorRole 判斷請求者是否為 auditor：
// 全量分支僅 auditor 需要入口判定欄，admin 回應形狀凍結
func isAuditorRole(c *gin.Context) bool {
	role, exists := c.Get("role")
	if !exists {
		return false
	}
	r, ok := role.(string)
	return ok && r == model.RoleAuditor
}

// assetWithEntryPermission auditor 全量列表的入口判定包裝：permission 僅供
// 連線入口判定（connect＝顯式 grant 命中／view＝其餘），非授權狀態欄資料
type assetWithEntryPermission struct {
	model.Asset
	Permission model.PermissionType `json:"permission"`
}

// filterAuthorizedAssets 在授權集合內套用 search/protocol/active 篩選——
// 收斂後一般 user 走授權分支，前端的搜尋/協議/狀態控制項須在伺服端於授權集合內
// 生效，否則參數被忽略、篩選對一般 user 全面失效。
func filterAuthorizedAssets(assets []*authz.AuthorizedAssetDTO, search, protocol, active string) []*authz.AuthorizedAssetDTO {
	search = strings.ToLower(strings.TrimSpace(search))
	out := make([]*authz.AuthorizedAssetDTO, 0, len(assets))
	for _, a := range assets {
		if search != "" &&
			!strings.Contains(strings.ToLower(a.Name), search) &&
			!strings.Contains(strings.ToLower(a.Host), search) {
			continue
		}
		if protocol != "" && string(a.Protocol) != protocol {
			continue
		}
		if active != "" && a.Active != (active == "true") {
			continue
		}
		out = append(out, a)
	}
	return out
}

// List 列出資產
func (h *AssetHandler) List(c *gin.Context) {
	// 分頁參數（授權分支與全量分支共用）
	page, pageSize := 1, 20
	if p, err := strconv.Atoi(c.Query("page")); err == nil && p > 0 {
		page = p
	}
	if ps, err := strconv.Atoi(c.Query("page_size")); err == nil && ps > 0 {
		pageSize = ps
	}

	// 伺服端強制授權收斂：非 admin/auditor 一律走授權
	// 資產集合，不信任客戶端 authorized_only 參數；管理角色保留參數自查行為
	authorizedOnly := c.Query("authorized_only") == "true"
	if !isPrivilegedRole(c) {
		authorizedOnly = true
	}

	// 節點過濾參數：node_id 點選節點、include_subtree
	// 預設含子樹（顯式 false 關）、ungrouped 僅未分組
	var nodeID *uint
	if raw := c.Query("node_id"); raw != "" {
		id64, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			// 非法值明確拒絕，不得靜默退化為無過濾
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidNodeID, nil)
			return
		}
		id := uint(id64)
		nodeID = &id
	}
	includeSubtree := c.Query("include_subtree") != "false"
	ungrouped := c.Query("ungrouped") == "true"

	// 標籤篩選參數：僅 admin/auditor 全量分支；
	// 非特權角色帶參數明確拒 400——不得靜默忽略（同型教訓：
	// 參數被忽略＝篩選對一般 user 全面失效）
	var tagFilters []string
	if raw := c.Query("tags"); raw != "" {
		if !isPrivilegedRole(c) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeTagFilterPrivilegedOnly, nil)
			return
		}
		parsed, err := asset.ParseTagsQuery(raw)
		if err != nil {
			// ParseTagsQuery 目前僅回 ErrTooManyTags；未知錯誤仍維持 400
			// （與遷移前 err.Error() 同狀態碼），以通用參數碼呈現
			code, ok := tagValidationCode(err)
			if !ok {
				code = apierror.CodeBadParams
			}
			apierror.Respond(c, http.StatusBadRequest, code, nil)
			return
		}
		tagFilters = parsed
	}

	if authorizedOnly {
		// 獲取目前用戶
		userID, exists := middleware.GetCurrentUserID(c)
		if !exists {
			apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
			return
		}

		// 獲取用戶已授權的資產（至少需要 view 權限）
		// 將 Gin Context 中的角色信息傳遞到 Go context
		ctx := c.Request.Context()
		if role, exists := c.Get("role"); exists {
			ctx = context.WithValue(ctx, "role", role)
		}

		assets, err := h.authorizationService.GetAuthorizedAssets(
			ctx,
			userID,
			model.PermissionView,
		)
		if err != nil {
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAuthorizedAssetQuery, err)
			return
		}

		// 授權集合內套用篩選與分頁（P2-1）：前端篩選/分頁控制項須在此生效
		filtered := filterAuthorizedAssets(assets, c.Query("search"), c.Query("protocol"), c.Query("active"))

		// 節點過濾在授權集合內生效（收斂樹點選同樣過濾右表）
		if nodeID != nil || ungrouped {
			nodeSet, err := h.assetService.AssetIDsForNodeFilter(nodeID, includeSubtree, ungrouped)
			if err != nil {
				apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetNodeFilter, err)
				return
			}
			kept := make([]*authz.AuthorizedAssetDTO, 0, len(filtered))
			for _, dto := range filtered {
				if nodeSet[dto.ID] {
					kept = append(kept, dto)
				}
			}
			filtered = kept
		}
		total := len(filtered)
		start := (page - 1) * pageSize
		if start > total {
			start = total
		}
		end := start + pageSize
		if end > total {
			end = total
		}
		pageRows := filtered[start:end]

		// 連線入口三態標註：僅一般 user
		// 分支、僅當頁列。標註失敗不擋列表（按鈕退回 permission 欄渲染，
		// 行為仍以簽發點政策閘為準）
		if h.accessState != nil && !isPrivilegedRole(c) {
			if err := h.accessState.AnnotateConnectStates(userID, pageRows); err != nil {
				log.Printf("[AssetList] 三態標註失敗（列表照常回傳）: %v", err)
			}
		}

		// 節點掛載資訊：僅當頁列，失敗不擋列表
		if err := h.authorizationService.FillNodeInfoForDTOs(pageRows); err != nil {
			log.Printf("[AssetList] 節點資訊填充失敗（列表照常回傳）: %v", err)
		}

		c.JSON(http.StatusOK, gin.H{
			"data":      pageRows,
			"total":     total,
			"page":      page,
			"page_size": pageSize,
		})
		return
	}

	// admin/auditor 全量分支（帶過濾），分頁參數已於函式開頭解析
	filter := &asset.AssetFilter{
		Search:         c.Query("search"),
		Protocol:       model.ProtocolType(c.Query("protocol")),
		Page:           page,
		PageSize:       pageSize,
		NodeID:         nodeID,
		IncludeSubtree: includeSubtree,
		Ungrouped:      ungrouped,
		Tags:           tagFilters,
	}

	// 解析啟用狀態
	if activeStr := c.Query("active"); activeStr != "" {
		active := activeStr == "true"
		filter.Active = &active
	}

	// 查詢資產
	result, err := h.assetService.List(filter)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetQuery, err)
		return
	}

	// auditor 連線入口判定欄：當頁列標
	// permission——顯式 connect grant 命中標 connect、餘標 view。集合查詢失敗
	// 不擋列表、當頁全標 view（寧缺勿假，行為以簽發點為準）。admin 回應形狀凍結
	if isAuditorRole(c) {
		var connectable map[uint]bool
		if userID, ok := middleware.GetCurrentUserID(c); ok {
			ids, err := h.authorizationService.ExplicitAuthorizedAssetIDs(userID, model.PermissionConnect)
			if err != nil {
				log.Printf("[AssetList] auditor 顯式授權集合查詢失敗（當頁標 view）: %v", err)
			} else {
				connectable = ids
			}
		}
		rows := make([]assetWithEntryPermission, len(result.Data))
		for i, a := range result.Data {
			perm := model.PermissionView
			if connectable[a.ID] {
				perm = model.PermissionConnect
			}
			rows[i] = assetWithEntryPermission{Asset: a, Permission: perm}
		}
		c.JSON(http.StatusOK, gin.H{
			"data":      rows,
			"total":     result.Total,
			"page":      result.Page,
			"page_size": result.PageSize,
		})
		return
	}

	c.JSON(http.StatusOK, result)
}

// Get 取得資產詳情
func (h *AssetHandler) Get(c *gin.Context) {
	// 解析 ID
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "asset"})
		return
	}

	// 逐資產授權由 RequireAssetVisible 中介層守門

	// 查詢資產
	assetRow, err := h.assetService.GetByID(uint(id))
	if err != nil {
		if errors.Is(err, asset.ErrAssetNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetNotFound, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetQuery, err)
		return
	}

	c.JSON(http.StatusOK, assetRow)
}

// ListTags 標籤清單：canonical 去重＋使用數，
// 供篩選下拉、表單自動完成與治理介面共用
func (h *AssetHandler) ListTags(c *gin.Context) {
	// 全表彙整含未授權資產的標籤詞彙，一般 user 拒絕（洩漏面，
	// 與「404 不洩漏資產存在性」紅線同源）
	if !isPrivilegedRole(c) {
		apierror.Respond(c, http.StatusForbidden, apierror.CodeTagListPrivilegedOnly, nil)
		return
	}
	tags, err := h.assetService.ListTags()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalTagListQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": tags})
}

// requireAdminRole 治理端點守衛：僅 admin（auditor 亦拒）
func requireAdminRole(c *gin.Context) bool {
	role, exists := c.Get("role")
	if !exists {
		apierror.Respond(c, http.StatusForbidden, apierror.CodeTagGovernanceAdminOnly, nil)
		return false
	}
	if r, ok := role.(string); !ok || r != model.RoleAdmin {
		apierror.Respond(c, http.StatusForbidden, apierror.CodeTagGovernanceAdminOnly, nil)
		return false
	}
	return true
}

// tagGovernanceContext 將操作者身分注入 ctx（審計 hook 取用）
func tagGovernanceContext(c *gin.Context) context.Context {
	ctx := c.Request.Context()
	if userID, exists := middleware.GetCurrentUserID(c); exists {
		ctx = context.WithValue(ctx, "userID", userID)
	}
	if username, exists := c.Get("username"); exists {
		ctx = context.WithValue(ctx, "username", username)
	}
	return ctx
}

// RenameTagRequest 標籤改名/合併請求
type RenameTagRequest struct {
	From string `json:"from" binding:"required"`
	To   string `json:"to" binding:"required"`
}

// RenameTag 標籤全面改名/合併
func (h *AssetHandler) RenameTag(c *gin.Context) {
	if !requireAdminRole(c) {
		return
	}
	var req RenameTagRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	affected, err := h.assetService.RenameTag(tagGovernanceContext(c), req.From, req.To)
	if err != nil {
		if code, ok := tagValidationCode(err); ok {
			apierror.Respond(c, http.StatusBadRequest, code, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalTagRename, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"affected": affected})
}

// DeleteTagRequest 標籤刪除請求（POST body 避免 URL 編碼 unicode 標籤名）
type DeleteTagRequest struct {
	Name string `json:"name" binding:"required"`
}

// DeleteTag 標籤全面刪除
func (h *AssetHandler) DeleteTag(c *gin.Context) {
	if !requireAdminRole(c) {
		return
	}
	var req DeleteTagRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	affected, err := h.assetService.DeleteTag(tagGovernanceContext(c), req.Name)
	if err != nil {
		// 統一改走 tagValidationCode：全部標籤驗證 sentinel 一律 400
		//（與 Create/Update/RenameTag 一致，不再只映 ErrTagEmpty）
		if code, ok := tagValidationCode(err); ok {
			apierror.Respond(c, http.StatusBadRequest, code, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalTagDelete, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"affected": affected})
}

// Create 創建資產
func (h *AssetHandler) Create(c *gin.Context) {
	var req asset.CreateAssetRequest

	// 綁定 JSON
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}

	// 從 JWT token 取得目前用戶 ID
	userID, exists := middleware.GetCurrentUserID(c)
	if !exists {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return
	}
	req.CreatedBy = userID
	if name, ok := c.Get("username"); ok {
		if n, ok := name.(string); ok {
			req.CreatedByName = n
		}
	}

	// 創建資產
	assetRow, err := h.assetService.Create(&req)
	if err != nil {
		respondAssetError(c, apierror.CodeInternalAssetCreate, err)
		return
	}

	// POST /assets 路徑上沒有 :id，中介層推導不出主體；資產 id 建立完才存在，
	// 只有此處知道（auditor-workbench）
	setAuditAssetIDValue(c, assetRow.ID)

	c.JSON(http.StatusCreated, assetRow)
}

// Update 更新資產
func (h *AssetHandler) Update(c *gin.Context) {
	// 解析 ID
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "asset"})
		return
	}

	var req asset.UpdateAssetRequest

	// 綁定 JSON
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}

	// 提取用戶資訊並放入 context
	ctx := c.Request.Context()
	if userID, exists := c.Get("userID"); exists {
		ctx = context.WithValue(ctx, "userID", userID)
	}
	if username, exists := c.Get("username"); exists {
		ctx = context.WithValue(ctx, "username", username)
	}

	// 更新資產（傳遞 context 以記錄審計）
	assetRow, err := h.assetService.Update(ctx, uint(id), &req)
	if err != nil {
		respondAssetError(c, apierror.CodeInternalAssetUpdate, err)
		return
	}

	c.JSON(http.StatusOK, assetRow)
}

// Delete 刪除資產
func (h *AssetHandler) Delete(c *gin.Context) {
	// 解析 ID
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "asset"})
		return
	}

	// 刪除資產
	if err := h.assetService.Delete(uint(id)); err != nil {
		if errors.Is(err, asset.ErrAssetNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetNotFound, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetDelete, err)
		return
	}

	// 成功回應不攜帶 UI 文案：前端以 $t('assets.deleted') 自有文案提示。
	// 仍回空 JSON 物件而非空 body，維持「200 一律是 JSON」的回應形狀慣例。
	c.JSON(http.StatusOK, gin.H{})
}

// TestConnectionRequest 測試連線請求
type TestConnectionRequest struct {
	Timeout int `json:"timeout"` // 超時秒數，可選，默認 10
}

// TestConnection 測試連線
func (h *AssetHandler) TestConnection(c *gin.Context) {
	// 解析 ID
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "asset"})
		return
	}

	// 解析請求參數（可選）
	var req TestConnectionRequest
	req.Timeout = 10 // 默認 10 秒

	// 嘗試綁定 JSON，如果失敗則使用默認值
	_ = c.ShouldBindJSON(&req)

	// 調用 Service 層執行連線測試
	result, err := h.assetService.TestConnection(c.Request.Context(), uint(id), req.Timeout)
	if err != nil {
		if errors.Is(err, asset.ErrAssetNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetNotFound, nil)
			return
		}
		// err 僅來自憑證讀取（撥接結果在 result 內），屬內部錯誤不外洩
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetTestConnection, err)
		return
	}

	// 返回測試結果
	c.JSON(http.StatusOK, result)
}

// ListK8sPods GET /assets/:id/k8s/pods — 列 namespace 內活 pod 供連線時選擇器
func (h *AssetHandler) ListK8sPods(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "asset"})
		return
	}
	// 逐資產授權由 RequireAssetVisible 中介層守門
	pods, err := h.assetService.ListK8sPods(c.Request.Context(), uint(id))
	if err != nil {
		if errors.Is(err, asset.ErrAssetNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetNotFound, nil)
			return
		}
		// 零帳號資產（空 token）於服務層即擋，不以匿名身分打叢集
		if errors.Is(err, asset.ErrAssetNoUsableAccount) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountNoneUsable, nil)
			return
		}
		// k8sproxy 的六類分類（不可達/TLS/401/403/404/unknown）逐類配碼——
		// 與 WS 撥號路徑共用 k8sproxy.ErrCodeOf（原本此處
		// 一律回泛碼 RULE_K8S_POD_UNAVAILABLE，同一分類在兩條路徑上碼不同）。
		// 機器欄 kind 仍經 Meta 保留（既有前端契約）。
		var ke *k8sproxy.K8sError
		if errors.As(err, &ke) {
			log.Printf("[ListK8sPods] k8s 錯誤: kind=%s err=%v", ke.Kind, ke)
			apierror.Write(c, http.StatusBadGateway, apierror.ErrorResponse{
				Code: k8sproxy.ErrCodeOf(err),
				Meta: map[string]any{"kind": ke.Kind},
			})
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalK8sPodList, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"pods": pods})
}

// auditK8sFile 直接落 audit_log（kubectl cp 檔名/大小/方向，k8s-exec）
func (h *AssetHandler) auditK8sFile(c *gin.Context, userID, assetID uint, action model.AuditAction, detail string) {
	username, _ := middleware.GetCurrentUsername(c)
	aid := assetID
	if h.auditSink == nil {
		log.Printf("[AssetHandler] 審計投遞面未注入，k8s 檔案操作留痕已丟失 (asset=%d action=%s)", assetID, action)
		return
	}
	// 收口（AP-04）：改經 AsyncSink，繞過 AuditLogEnabled 分支。
	// **error 仍然完全不檢查**——那是既有缺陷，修它是行為變更，不在等價搬遷範圍
	//（現況 database.DB.Create 的回傳同樣被丟棄）
	_ = h.auditSink.Submit(c.Request.Context(), gatewayapi.AuditEvent{
		Action:     string(action),
		Resource:   string(model.ResourceFile),
		ResourceID: &aid,
		// ResourceID 維持既有語義（resource=file 的既有查詢靠它），主體鍵另記：
		// 工作台的檔案傳輸類只讀 asset_id（auditor-workbench）
		AssetID: &aid,
		Status:  string(model.StatusSuccess),
		Actor:   gatewayapi.Actor{UserID: userID, Username: username},
		Request: gatewayapi.RequestMeta{
			Method:     c.Request.Method,
			Path:       c.FullPath(),
			ClientIP:   sourceip.Of(c),
			StatusCode: http.StatusOK,
			Body:       detail,
		},
	})
}

// auditK8sFileDenied 記錄被資料傳輸閘擋下的 K8s 檔案操作（status=denied）
func (h *AssetHandler) auditK8sFileDenied(c *gin.Context, userID, assetID uint, action model.AuditAction, detail string) {
	username, _ := middleware.GetCurrentUsername(c)
	aid := assetID
	if h.auditSink == nil {
		log.Printf("[AssetHandler] 審計投遞面未注入，k8s 檔案拒絕留痕已丟失 (asset=%d action=%s)", assetID, action)
		return
	}
	_ = h.auditSink.Submit(c.Request.Context(), gatewayapi.AuditEvent{
		Action:     string(action),
		Resource:   string(model.ResourceFile),
		ResourceID: &aid,
		// 同成功路徑：被拒的傳輸企圖同樣是「對這台資產做的事」，
		// 主體鍵缺了工作台就看不到它（auditor-workbench）
		AssetID: &aid,
		Status:  string(model.StatusDenied),
		Actor:   gatewayapi.Actor{UserID: userID, Username: username},
		Request: gatewayapi.RequestMeta{
			Method:     c.Request.Method,
			Path:       c.FullPath(),
			ClientIP:   sourceip.Of(c),
			StatusCode: http.StatusForbidden,
			Body:       detail,
		},
	})
}

// UploadK8sFile POST /assets/:id/k8s/upload — 上傳檔到選定 pod/container（kubectl cp）
func (h *AssetHandler) UploadK8sFile(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "asset"})
		return
	}
	userID, _ := middleware.GetCurrentUserID(c)
	pod := c.PostForm("pod")
	container := c.PostForm("container")
	destDir := c.PostForm("dest_path")
	if destDir == "" {
		destDir = "/tmp"
	}
	fileHeader, err := c.FormFile("file")
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeUploadFileMissing, nil)
		return
	}
	tmp, err := os.CreateTemp("", "k8scp-*")
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalTempFileCreate, err)
		return
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpPath)
	if err := c.SaveUploadedFile(fileHeader, tmpPath); err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalUploadFileSave, err)
		return
	}
	destPath := path.Join(destDir, path.Base(fileHeader.Filename))
	if !h.requireK8sTransferAllowed(c, userID, uint(id), policy.TransferActionFileUpload,
		fmt.Sprintf(`{"direction":"upload","pod":%q,"container":%q,"path":%q}`, pod, container, destPath)) {
		return
	}
	if err := h.assetService.K8sCopyToPod(c.Request.Context(), uint(id), pod, container, destPath, tmpPath); err != nil {
		apierror.RespondInternal(c, http.StatusBadGateway, apierror.CodeK8sCopy, err)
		return
	}
	h.auditK8sFile(c, userID, uint(id), model.ActionFileUpload,
		fmt.Sprintf(`{"direction":"upload","pod":%q,"container":%q,"path":%q,"size":%d}`, pod, container, destPath, fileHeader.Size))
	c.JSON(http.StatusOK, gin.H{"path": destPath, "size": fileHeader.Size})
}

// DownloadK8sFile GET /assets/:id/k8s/download?pod=&container=&path= — 從容器下載檔
func (h *AssetHandler) DownloadK8sFile(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "asset"})
		return
	}
	userID, _ := middleware.GetCurrentUserID(c)
	pod := c.Query("pod")
	container := c.Query("container")
	srcPath := c.Query("path")
	if srcPath == "" {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeFilePathMissing, nil)
		return
	}
	if !h.requireK8sTransferAllowed(c, userID, uint(id), policy.TransferActionFileDownload,
		fmt.Sprintf(`{"direction":"download","pod":%q,"container":%q,"path":%q}`, pod, container, srcPath)) {
		return
	}
	tmp, err := os.CreateTemp("", "k8scp-*")
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalTempFileCreate, err)
		return
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	// 先刪預建檔，讓 kubectl cp 自己建：kubectl cp 對「容器內不存在的來源」會 exit 0
	// 但不產生本地檔，故以「是否建出檔案」判斷來源是否真的存在（否則會把失敗的下載
	// 偽裝成 200 空檔，誤導使用者）。
	_ = os.Remove(tmpPath)
	defer os.Remove(tmpPath)
	if err := h.assetService.K8sCopyFromPod(c.Request.Context(), uint(id), pod, container, srcPath, tmpPath); err != nil {
		apierror.RespondInternal(c, http.StatusBadGateway, apierror.CodeK8sCopy, err)
		return
	}
	info, statErr := os.Stat(tmpPath)
	if statErr != nil {
		// 請求方自帶的 path 不再回填訊息（apierror params 僅收受控 enum/int）；
		// 前端已有該路徑，可自行組字
		apierror.Respond(c, http.StatusNotFound, apierror.CodeK8sFileNotFound, nil)
		return
	}
	if info.IsDir() {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeK8sPathIsDir, nil)
		return
	}
	h.auditK8sFile(c, userID, uint(id), model.ActionFileDownload,
		fmt.Sprintf(`{"direction":"download","pod":%q,"container":%q,"path":%q,"size":%d}`, pod, container, srcPath, info.Size()))
	c.FileAttachment(tmpPath, path.Base(srcPath))
}

// RegisterRoutes 註冊資產相關路由
func (h *AssetHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	assets := r.Group("/assets")
	assets.Use(middleware.AuthMiddleware(authService))

	// 逐資產可視性守門：無條件生效（權限旗標已退場；讀取端點無條件
	// 守門紅線），故在兩分支皆掛，且置於 RequirePermission 之後
	visible := middleware.RequireAssetVisible(h.authorizationService)

	assets.GET("", middleware.RequirePermission(middleware.PermAssetView), h.List)
	// 標籤清單/治理：/tags 與 /:id 共存已實測；
	// 角色細分（清單 admin/auditor、治理僅 admin）在 handler 內守衛
	assets.GET("/tags", middleware.RequirePermission(middleware.PermAssetView), h.ListTags)
	assets.POST("/tags/rename", middleware.RequirePermission(middleware.PermAssetUpdate), h.RenameTag)
	assets.POST("/tags/delete", middleware.RequirePermission(middleware.PermAssetUpdate), h.DeleteTag)
	assets.POST("", middleware.RequirePermission(middleware.PermAssetCreate), h.Create)
	assets.GET("/:id", middleware.RequirePermission(middleware.PermAssetView), visible, h.Get)
	assets.PUT("/:id", middleware.RequirePermission(middleware.PermAssetUpdate), h.Update)
	assets.DELETE("/:id", middleware.RequirePermission(middleware.PermAssetDelete), h.Delete)
	assets.POST("/:id/test-connection", middleware.RequirePermission(middleware.PermAssetTest), h.TestConnection)
	assets.GET("/:id/k8s/pods", middleware.RequirePermission(middleware.PermAssetView), visible, h.ListK8sPods)
	// 容器檔案進出＝寫級操作（傳檔進/出生產容器），需寫權限而非僅讀（security review HIGH）
	assets.POST("/:id/k8s/upload", middleware.RequirePermission(middleware.PermAssetUpdate), h.UploadK8sFile)
	assets.GET("/:id/k8s/download", middleware.RequirePermission(middleware.PermAssetUpdate), h.DownloadK8sFile)
}
