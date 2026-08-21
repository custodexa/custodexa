package api

import (
	"context"
	"errors"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
)

// AuthorizationServiceInterface 授權服務接口（用於測試注入）
type AuthorizationServiceInterface interface {
	Grant(ctx context.Context, spec authz.GrantSpec) (*model.AssetAuthorization, error)
	GrantBatch(ctx context.Context, userIDs, userGroupIDs, assetIDs, assetGroupIDs []uint, permission model.PermissionType, grantedBy uint, accounts *[]string) (*authz.BatchGrantResult, error)
	UpdateAccountScope(ctx context.Context, authorizationID uint, accounts *[]string) (*model.AssetAuthorization, error)
	RevokePermission(ctx context.Context, authorizationID uint) error
	ListAuthorizations(filters map[string]interface{}, page, pageSize int) ([]*model.AssetAuthorization, int64, error)
	ListUserAuthorizations(userID uint, page, pageSize int) ([]*model.AssetAuthorization, int64, error)
	ListAssetAuthorizations(assetID uint, page, pageSize int) ([]*model.AssetAuthorization, int64, error)
	ListUserGroupAuthorizations(userGroupID uint, page, pageSize int) ([]*model.AssetAuthorization, int64, error)
}

// EffectiveAccessResolverInterface 有效權限解析接口（用於測試注入，
// authorization-page-redesign D3）
type EffectiveAccessResolverInterface interface {
	ResolveEffectiveAssets(subjectUserID uint, now time.Time) (*authz.EffectiveAssetsResult, error)
	ResolveEffectiveUsers(assetID uint, now time.Time) (*authz.EffectiveUsersResult, error)
}

// AuthorizationHandler 授權管理 API handler
type AuthorizationHandler struct {
	authorizationService AuthorizationServiceInterface
	effectiveResolver    EffectiveAccessResolverInterface
	// authService 角色現況重判（codex 階段 4 high）：本群組以 RequireRole("admin")
	// 守門，但該中介讀的是 JWT 角色快照——已被降權／停用的前 admin 在 token 效期內
	// 仍可改任何授權的帳號範圍（把自己加回去）。由 RegisterRoutes 於組裝期注入；
	// 未注入時帳號範圍端點 fail-close（見 UpdateAccounts）
	authService *identity.AuthService
}

// NewAuthorizationHandler 創建授權管理 handler
func NewAuthorizationHandler(authorizationService AuthorizationServiceInterface, effectiveResolver EffectiveAccessResolverInterface) *AuthorizationHandler {
	return &AuthorizationHandler{
		authorizationService: authorizationService,
		effectiveResolver:    effectiveResolver,
	}
}

// CreateRequest 創建授權請求：asset_id 與 asset_group_id 二擇一
// CreateRequest 授權建立請求：主體 user_id XOR user_group_id、
// 客體 asset_id XOR asset_group_id（user-group-authorization）。
// 不接受時效欄位——時效唯一來源是核准流（Change 2）
type CreateRequest struct {
	UserID       uint   `json:"user_id"`
	UserGroupID  uint   `json:"user_group_id"`
	AssetID      uint   `json:"asset_id"`
	AssetGroupID uint   `json:"asset_group_id"`
	Permission   string `json:"permission" binding:"required,oneof=view connect"`
	// Accounts 帳號範圍（asset-multi-account D5）：**省略（nil）＝`@ALL`**（全部帳號，
	// 與多帳號維度引入前行為一致，舊前端不送此欄即維持既有語義）；
	// 顯式 `[]` 拒收——見 authz.NormalizeGrantAccounts 的 F1 說明
	Accounts *[]string `json:"accounts"`
}

// toGrantSpec 轉服務層規格（0 值＝該側未指定）
func (r *CreateRequest) toGrantSpec(grantedBy uint) authz.GrantSpec {
	spec := authz.GrantSpec{
		Permission: model.PermissionType(r.Permission),
		GrantedBy:  grantedBy,
		Accounts:   r.Accounts,
	}
	if r.UserID != 0 {
		spec.UserID = &r.UserID
	}
	if r.UserGroupID != 0 {
		spec.UserGroupID = &r.UserGroupID
	}
	if r.AssetID != 0 {
		spec.AssetID = &r.AssetID
	}
	if r.AssetGroupID != 0 {
		spec.AssetGroupID = &r.AssetGroupID
	}
	return spec
}

// Create 創建授權
func (h *AuthorizationHandler) Create(c *gin.Context) {
	// 解析請求
	var req CreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}

	// 獲取目前用戶（授權者）
	grantedBy, exists := middleware.GetCurrentUserID(c)
	if !exists {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return
	}

	if (req.UserID == 0) == (req.UserGroupID == 0) {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeGrantSubjectXOR, nil)
		return
	}
	if (req.AssetID == 0) == (req.AssetGroupID == 0) {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeGrantObjectXOR, nil)
		return
	}

	auth, err := h.authorizationService.Grant(c.Request.Context(), req.toGrantSpec(grantedBy))
	if err != nil {
		respondGrantError(c, err)
		return
	}

	setAuditAssetID(c, auth.AssetID)

	c.JSON(http.StatusOK, serializeAuthorization(auth, authNodePaths()))
}

// respondGrantError 授權建立錯誤映射：重複 409、引用不存在 404、形狀錯誤 400
func respondGrantError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, authz.ErrAuthorizationExists):
		apierror.Respond(c, http.StatusConflict, apierror.CodeAuthorizationExists, nil)
	case errors.Is(err, authz.ErrAccountScopeInvalid):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountScopeInvalid, nil)
	case errors.Is(err, authz.ErrInvalidGrantSubject):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidGrantSubject, nil)
	default:
		if entity, ok := grantMissingEntity(err); ok {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeGrantReferenceNotFound, map[string]any{"entity": entity})
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAuthorizationCreate, err)
	}
}

// grantMissingEntity 由 service 哨兵判定引用缺失的實體種類，回傳 API 契約用的
// entity 鍵（V2 對抗驗收 H2）。
//
// 原以中文子字串比對 err.Error()——service 文案一改（或翻譯、或補脈絡）即
// 靜默退化為 500，且無任何測試會紅。改 errors.Is 後種類判定由型別系統背書；
// 單筆與批次共用同一組哨兵，故本函式同時服務 Grant 與 GrantBatch 兩個呼叫點
// （兩者只是選用的 apierror 碼不同）。
func grantMissingEntity(err error) (string, bool) {
	switch {
	case errors.Is(err, authz.ErrGrantUserNotFound):
		return "user", true
	case errors.Is(err, authz.ErrGrantUserGroupNotFound):
		return "user_group", true
	case errors.Is(err, authz.ErrGrantAssetNotFound):
		return "asset", true
	case errors.Is(err, authz.ErrGrantAssetGroupNotFound):
		return "asset_group", true
	}
	return "", false
}

// serializeAuthorization 授權記錄序列化：主體（使用者或群組）與客體（資產或節點）
// 都必須可辨識（user-group-authorization spec「不得出現無法辨識的記錄」）。
// nodePaths 供節點客體帶全路徑（asset-node-tree：同層可重名，單名不可辨識——
// spec SHALL「授權列表以全路徑呈現節點目標」）；nil＝退回單名
func serializeAuthorization(auth *model.AssetAuthorization, nodePaths map[uint]string) gin.H {
	return serializeAuthorizationAt(auth, nodePaths, time.Now())
}

// serializeAuthorizationAt 帶時刻的序列化（authorization-page-redesign D2）：
// source/時效窗直出＋validity_state 三態＋ticket 的 request_id/revocable；
// 引用已軟刪實體（Preload 落空）的記錄以 *_deleted 標示，不得雙欄空白。
// now 由呼叫端一次捕捉（列表整批同一時刻，與解析引擎同語義）
func serializeAuthorizationAt(auth *model.AssetAuthorization, nodePaths map[uint]string, now time.Time) gin.H {
	resp := gin.H{
		"id":         auth.ID,
		"permission": auth.Permission,
		"granted_by": auth.GrantedBy,
		"created_at": auth.CreatedAt,
		"source":     auth.Source,
		// accounts 恆輸出且恆非空（asset-multi-account D5）：空值語義上等於 @ALL，
		// 但讓前端自行把「缺欄」解讀成全帳號，等於把安全語義的預設值散到 UI 層；
		// 伺服端直接把 @ALL 顯化，稽核截圖與 API 回應一致
		"accounts":       effectiveAccountScope(auth.Accounts),
		"validity_state": auth.ValidityStateAt(now),
	}
	if auth.DateStart != nil {
		resp["date_start"] = auth.DateStart
	}
	if auth.DateExpired != nil {
		resp["date_expired"] = auth.DateExpired
	}
	if auth.Source == model.AuthorizationSourceTicket {
		revocable := false
		if auth.RequestID != nil {
			resp["request_id"] = *auth.RequestID
			// 與 2b 撤銷資格一致：僅時窗內票證可撤（ErrTicketNotActive 同判定）
			revocable = auth.ActiveWithin(now)
		}
		resp["revocable"] = revocable
	}
	if auth.UserID != nil {
		resp["user_id"] = *auth.UserID
		if auth.User.ID != 0 {
			resp["username"] = auth.User.Username
		} else {
			resp["subject_deleted"] = true
		}
	}
	if auth.UserGroupID != nil {
		resp["user_group_id"] = *auth.UserGroupID
		if auth.UserGroup != nil {
			resp["user_group_name"] = auth.UserGroup.Name
		} else {
			resp["subject_deleted"] = true
		}
	}
	if auth.AssetID != nil {
		resp["asset_id"] = *auth.AssetID
		if auth.Asset != nil {
			resp["asset_name"] = auth.Asset.Name
			resp["asset_protocol"] = auth.Asset.Protocol
		} else {
			resp["target_deleted"] = true
		}
	}
	if auth.AssetGroupID != nil {
		resp["asset_group_id"] = *auth.AssetGroupID
		if auth.AssetGroup != nil {
			name := auth.AssetGroup.Name
			if nodePaths != nil {
				if p, ok := nodePaths[*auth.AssetGroupID]; ok {
					name = p
				}
			}
			resp["asset_group_name"] = name
		} else {
			resp["target_deleted"] = true
		}
	}
	return resp
}

// effectiveAccountScope 序列化用的帳號範圍：空值顯化為 `["@ALL"]`
// （既有列 migration 已回填，此處守住 sqlmock／單測等未經 migration 的路徑）
func effectiveAccountScope(scope model.AccountScope) []string {
	if scope.IsAll() {
		return []string{model.AccountScopeAll}
	}
	return []string(scope)
}

// UpdateAccountsRequest 調整授權帳號範圍請求（D5）。
//
// 指標型別為必要（F1）：本端點的唯一職責就是設定帳號範圍，`{}`／
// `{"accounts":null}` 代表請求沒說清楚要什麼，必須擋下而非猜——猜錯的方向是溢授
type UpdateAccountsRequest struct {
	Accounts *[]string `json:"accounts"`
}

// UpdateAccounts PUT /authorizations/:id/accounts：調整既有授權列的帳號範圍。
// 收緊即時生效——連線兌換點 DB 現查，不受既簽發 token 效期影響
func (h *AuthorizationHandler) UpdateAccounts(c *gin.Context) {
	// 角色現況重判（codex 階段 4 high）：RequireRole("admin") 讀的是 JWT 角色快照，
	// AuthMiddleware 不查 DB——已降權／停用的前 admin 在 token 效期內仍可改任何
	// 授權的帳號範圍（例如把自己加回被移除的帳號）。此端點直接改授權事實，
	// 必須與三個連線強制點同一事實源。未注入 authService 一律拒（fail-close：
	// 無法驗證現況角色時不得放行改授權）
	if h.authService == nil {
		apierror.RespondInternal(c, http.StatusInternalServerError,
			apierror.CodeInternalAuthorizationUpdate, errors.New("authService 未注入，無法重判現況角色"))
		return
	}
	actorID, exists := middleware.GetCurrentUserID(c)
	if !exists {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return
	}
	// 回應與 RequireRole 中介完全一致（403＋ROLE_REQUIRED{role:admin}）：現況降權者
	// 與從未有 admin 者收到同一個答案，不新增可據以推斷「你的 token 曾是 admin」的訊號
	currentRole, roleErr := h.authService.CurrentConnectRole(actorID)
	if roleErr != nil || currentRole != model.RoleAdmin {
		apierror.Respond(c, http.StatusForbidden, apierror.CodeRoleRequired, map[string]any{"role": model.RoleAdmin})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil || id == 0 {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidAuthorizationID, nil)
		return
	}
	var req UpdateAccountsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	auth, err := h.authorizationService.UpdateAccountScope(c.Request.Context(), uint(id), req.Accounts)
	if err != nil {
		switch {
		case errors.Is(err, authz.ErrAccountScopeRequired):
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountScopeRequired, nil)
		case errors.Is(err, authz.ErrAccountScopeInvalid):
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountScopeInvalid, nil)
		case errors.Is(err, authz.ErrAuthorizationNotFound):
			apierror.Respond(c, http.StatusNotFound, apierror.CodeAuthorizationNotFound, nil)
		case errors.Is(err, authz.ErrTicketAccountScopeImmutable):
			apierror.Respond(c, http.StatusConflict, apierror.CodeTicketAccountScopeImmutable, nil)
		default:
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAuthorizationUpdate, err)
		}
		return
	}
	setAuditAssetID(c, auth.AssetID)
	c.JSON(http.StatusOK, serializeAuthorization(auth, authNodePaths()))
}

// authNodePaths 節點路徑映射（序列化用）；失敗回 nil 退回單名不擋列表
// （database.DB 為 nil＝單測注入環境，同樣退回單名）
func authNodePaths() map[uint]string {
	if database.DB == nil {
		return nil
	}
	paths, err := asset.NodePathMap(database.DB)
	if err != nil {
		return nil
	}
	return paths
}

// authTargetAssetID 授權列的資產客體（審計主體鍵用）。
//
// **查詢留在 authz 側**（SD-2）：`asset_authorizations` 由 authz 擁有，接入層自查
// 會讓「這列指向哪台資產」出現第二份真相。形態沿同檔 authNodePaths 的既有作法——
// 傳句柄給擁有者的匯出函式，而非在 handler 內組 query。
// 不擴充 AuthorizationServiceInterface：那是測試注入面，為了一個審計欄位而擴充它，
// 會迫使每個既有 mock 補一個與被測行為無關的方法。
//
// 三種情況一律回 nil：DB 未注入（單測）、查不到、客體是節點（一次涵蓋多台資產，
// 沒有單一主體）。nil 即中介層不填 asset_id，而非填 0。
func authTargetAssetID(authorizationID uint) *uint {
	assetID, err := authz.AuthorizationTargetAssetID(database.DB, authorizationID)
	if err != nil {
		return nil
	}
	return assetID
}

// BatchCreateRequest 批次授權請求（user-group-authorization D6）：
// 主體集×客體集，伺服端展開為多筆單主體單客體記錄
type BatchCreateRequest struct {
	UserIDs       []uint `json:"user_ids"`
	UserGroupIDs  []uint `json:"user_group_ids"`
	AssetIDs      []uint `json:"asset_ids"`
	AssetGroupIDs []uint `json:"asset_group_ids"`
	Permission    string `json:"permission" binding:"required,oneof=view connect"`
	// Accounts 展開出的每一筆授權共用同一帳號範圍（省略＝@ALL；顯式 [] 拒收）
	Accounts *[]string `json:"accounts"`
}

// BatchCreate 批次授權：交易內展開、既有組合跳過、上限保護。
//
// **審計不填 asset_id**（auditor-workbench D4）：一次請求展開為主體集×客體集多筆授權，
// 沒有單一資產主體。挑其中一台填等於偽稱其餘幾台沒被授權；正確的逐資產事實
// 由展開後的各筆授權記錄承載，不由這一列的主體鍵表達。
func (h *AuthorizationHandler) BatchCreate(c *gin.Context) {
	var req BatchCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	grantedBy, exists := middleware.GetCurrentUserID(c)
	if !exists {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return
	}

	result, err := h.authorizationService.GrantBatch(
		c.Request.Context(),
		req.UserIDs, req.UserGroupIDs, req.AssetIDs, req.AssetGroupIDs,
		model.PermissionType(req.Permission), grantedBy, req.Accounts)
	if err != nil {
		switch {
		case errors.Is(err, authz.ErrAccountScopeInvalid):
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountScopeInvalid, nil)
		case errors.Is(err, authz.ErrBatchEmpty):
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeBatchEmpty, nil)
		case errors.Is(err, authz.ErrBatchTooLarge):
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeBatchTooLarge, map[string]any{"limit": authz.MaxBatchExpansion})
		default:
			if entity, ok := grantMissingEntity(err); ok {
				apierror.Respond(c, http.StatusNotFound, apierror.CodeBatchReferenceNotFound, map[string]any{"entity": entity})
				return
			}
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAuthorizationBatchGrant, err)
		}
		return
	}

	c.JSON(http.StatusOK, result)
}

// Delete 刪除授權
func (h *AuthorizationHandler) Delete(c *gin.Context) {
	// 解析 ID
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidAuthorizationID, nil)
		return
	}

	authID := uint(id)

	// 主體須在撤銷**之前**取——RevokePermission 是軟刪，事後再查得多帶 Unscoped，
	// 且撤銷成功與否不該影響「這列指向哪台資產」的判讀（auditor-workbench D4）
	assetID := authTargetAssetID(authID)

	// 調用 Service 撤銷授權
	err = h.authorizationService.RevokePermission(c.Request.Context(), authID)
	if err != nil {
		if errors.Is(err, authz.ErrAuthorizationNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeAuthorizationNotFound, nil)
			return
		}

		// ticket 裸刪守門（D4）：409 提示走撤銷流，不得落 500
		if errors.Is(err, authz.ErrTicketRevocationRequired) {
			apierror.Respond(c, http.StatusConflict, apierror.CodeTicketRevocationRequired, nil)
			return
		}

		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAuthorizationRevoke, err)
		return
	}

	setAuditAssetID(c, assetID)

	// message 欄已移除（D9：成功回應不攜帶 UI 文案，前端自有 $t 文案）
	c.JSON(http.StatusOK, gin.H{})
}

// List 查詢授權列表
func (h *AuthorizationHandler) List(c *gin.Context) {
	// 解析查詢參數：主體/客體維度至多一個；零維度＝全量列表
	//（authorization-page-redesign D1：授權列表以全量進頁為預設，維度篩選是收斂而非必填）
	userIDStr := c.Query("user_id")
	userGroupIDStr := c.Query("user_group_id")
	assetIDStr := c.Query("asset_id")
	nodeIDStr := c.Query("node_id")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	given := 0
	for _, s := range []string{userIDStr, userGroupIDStr, assetIDStr, nodeIDStr} {
		if s != "" {
			given++
		}
	}
	if given > 1 {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAuthFilterXOR, nil)
		return
	}

	// 確保分頁參數合法
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	parseID := func(s, field string) (uint, bool) {
		v, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidQueryParam, map[string]any{"field": field})
			return 0, false
		}
		return uint(v), true
	}

	filters := map[string]interface{}{}
	for field, s := range map[string]string{
		"user_id": userIDStr, "user_group_id": userGroupIDStr, "asset_id": assetIDStr,
		// node_id＝涵蓋盤點語義（authz-tag-node-filters D7：祖先/自身/後代＋
		// 多歸屬橋接＋子樹內資產客體）
		"node_id": nodeIDStr,
	} {
		if s == "" {
			continue
		}
		id, ok := parseID(s, field)
		if !ok {
			return
		}
		filters[field] = id
	}

	// 有效性/來源篩選（D7）：白名單校驗，於 COUNT 與分頁前生效（跨頁正確不漏報）。
	// now 一次捕捉，序列化沿用同一時刻
	now := time.Now()
	if v := c.Query("validity"); v != "" {
		switch v {
		case model.ValidityActive, model.ValidityScheduled, model.ValidityExpired:
			filters["validity"] = authz.ValidityFilter{State: v, Now: now}
		default:
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidValidityFilter, nil)
			return
		}
	}
	if v := c.Query("source"); v != "" {
		switch v {
		case model.AuthorizationSourceManual, model.AuthorizationSourceTicket:
			filters["source"] = v
		default:
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidSourceFilter, nil)
			return
		}
	}

	auths, total, err := h.authorizationService.ListAuthorizations(filters, page, pageSize)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAuthorizationQuery, err)
		return
	}

	// 格式化返回數據：主體與客體皆可辨識（serializeAuthorizationAt 統一序列化）
	nodePaths := authNodePaths()
	result := make([]gin.H, 0, len(auths))
	for _, auth := range auths {
		result = append(result, serializeAuthorizationAt(auth, nodePaths, now))
	}

	c.JSON(http.StatusOK, gin.H{
		"data":      result,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// EffectiveAssets 主體視角有效權限（authorization-page-redesign D3）
func (h *AuthorizationHandler) EffectiveAssets(c *gin.Context) {
	id, err := strconv.ParseUint(c.Query("user_id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidQueryParam, map[string]any{"field": "user_id"})
		return
	}
	result, err := h.effectiveResolver.ResolveEffectiveAssets(uint(id), time.Now())
	if err != nil {
		if errors.Is(err, authz.ErrEffectiveSubjectNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeUserNotFound, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAuthorizationEffective, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

// EffectiveUsers 客體視角有效權限（authorization-page-redesign D3）
func (h *AuthorizationHandler) EffectiveUsers(c *gin.Context) {
	id, err := strconv.ParseUint(c.Query("asset_id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidQueryParam, map[string]any{"field": "asset_id"})
		return
	}
	result, err := h.effectiveResolver.ResolveEffectiveUsers(uint(id), time.Now())
	if err != nil {
		if errors.Is(err, authz.ErrEffectiveAssetNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetNotFound, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAuthorizationEffective, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

// RegisterRoutes 註冊授權管理路由
func (h *AuthorizationHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	// 組裝期注入角色現況事實源：路由必經本函式，故生產路徑恆有值
	h.authService = authService
	authorizations := r.Group("/authorizations")
	authorizations.Use(middleware.AuthMiddleware(authService))
	authorizations.Use(middleware.RequireRole("admin")) // 僅管理員可操作
	{
		authorizations.POST("", h.Create)
		authorizations.POST("/batch", h.BatchCreate)
		authorizations.PUT("/:id/accounts", h.UpdateAccounts)
		authorizations.DELETE("/:id", h.Delete)
		authorizations.GET("", h.List)
		// 有效權限雙視角（D3）：唯讀溯因，admin only 隨群組守門
		authorizations.GET("/effective-assets", h.EffectiveAssets)
		authorizations.GET("/effective-users", h.EffectiveUsers)
	}
}
