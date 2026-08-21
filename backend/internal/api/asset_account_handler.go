package api

import (
	"context"
	"errors"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/asset"
)

// AssetAccountServiceInterface 資產帳號服務接口（用於測試注入）
type AssetAccountServiceInterface interface {
	List(assetID uint) ([]*asset.AssetAccountDTO, error)
	Create(ctx context.Context, assetID uint, req *asset.CreateAssetAccountRequest) (*asset.AssetAccountDTO, error)
	Update(ctx context.Context, assetID, accountID uint, req *asset.UpdateAssetAccountRequest) (*asset.AssetAccountDTO, error)
	Delete(ctx context.Context, assetID, accountID uint) error
	SetDefault(ctx context.Context, assetID, accountID uint) (*asset.AssetAccountDTO, error)
}

// AccountScopeResolver 有效帳號範圍解析（asset-multi-account D5）。
//
// 獨立於 AssetAuthorizationServiceInterface 的窄介面：帳號範圍只有帳號端點需要，
// 併入共用介面會逼 asset/asset_group 兩支 handler 的既有測試替身全部補實作
type AccountScopeResolver interface {
	EffectiveViewAccountScope(ctx context.Context, userID, assetID uint) (authz.EffectiveAccountScope, error)
}

// AssetAccountHandler 資產帳號 API（asset-multi-account 階段 2）。
//
// 回應一律走 asset.AssetAccountDTO：帳號密文欄位在 model 已是 json:"-"，
// DTO 再把「是否已設定憑證」降為布林——憑證本體與其密文都不出站（連線收口紅線）。
type AssetAccountHandler struct {
	accountService AssetAccountServiceInterface
	// scopeResolver 列表過濾用（D5）。**建構期必填**：設為可選欄位＋nil 時不過濾
	// 等於留一個「忘記注入就退回舊的全量外洩行為」的 fail-open 開關
	scopeResolver AccountScopeResolver
}

// NewAssetAccountHandler 建立 handler
func NewAssetAccountHandler(accountService AssetAccountServiceInterface, scopeResolver AccountScopeResolver) *AssetAccountHandler {
	return &AssetAccountHandler{accountService: accountService, scopeResolver: scopeResolver}
}

// respondAccountError 帳號端點的統一錯誤出口：已知 sentinel 依 errors.Is 映射到
// 機器碼，未知一律 RespondInternal（成因只落伺服端日誌）。
// internalCode 為該端點的 INTERNAL_ASSET_ACCOUNT_<VERB> 碼。
func respondAccountError(c *gin.Context, internalCode apierror.ErrCode, err error) {
	switch {
	case errors.Is(err, asset.ErrAssetNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetNotFound, nil)
	case errors.Is(err, asset.ErrAssetAccountNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetAccountNotFound, nil)
	case errors.Is(err, asset.ErrAssetAccountSourceNotFound),
		// 來源不可見與來源不存在共用一碼：分流即成為「哪些 account id 存在」的探測器
		errors.Is(err, asset.ErrAssetAccountSourceForbidden):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetAccountSourceNotFound, nil)
	case errors.Is(err, asset.ErrAssetAccountUsernameExists):
		apierror.Respond(c, http.StatusConflict, apierror.CodeAccountUsernameExists, nil)
	case errors.Is(err, asset.ErrAssetAccountDefaultConflict):
		apierror.Respond(c, http.StatusConflict, apierror.CodeAccountDefaultConflict, nil)
	case errors.Is(err, asset.ErrAssetNoUsableAccount):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountNoneUsable, nil)
	case errors.Is(err, asset.ErrAssetAccountUsernameInvalid):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountUsernameInvalid, nil)
	case errors.Is(err, asset.ErrAssetAccountUsernameReserved):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountUsernameReserved, nil)
	case errors.Is(err, asset.ErrAssetAccountUsernameTooLong):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountUsernameTooLong, nil)
	case errors.Is(err, asset.ErrAssetAccountNoteTooLong):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountNoteTooLong, nil)
	case errors.Is(err, asset.ErrAssetAccountAuthMethodInvalid):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountAuthMethod, nil)
	case errors.Is(err, asset.ErrAssetAccountAuthMethodUnsupported):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountAuthMethodUnsupported, nil)
	case errors.Is(err, asset.ErrAssetAccountDefaultRequired):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountDefaultRequired, nil)
	case errors.Is(err, asset.ErrAssetAccountDefaultMissing):
		apierror.Respond(c, http.StatusConflict, apierror.CodeAccountDefaultMissing, nil)
	default:
		apierror.RespondInternal(c, http.StatusInternalServerError, internalCode, err)
	}
}

// accountParams 解析 :id（資產）與 :accountId（帳號）路徑參數。
// wantAccount=false 時只解資產。第二回傳值 false＝已寫錯誤回應，呼叫端直接 return。
func accountParams(c *gin.Context, wantAccount bool) (uint, uint, bool) {
	assetID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "asset"})
		return 0, 0, false
	}
	if !wantAccount {
		return uint(assetID), 0, true
	}
	accountID, err := strconv.ParseUint(c.Param("accountId"), 10, 32)
	if err != nil || accountID == 0 {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidAccountID, nil)
		return 0, 0, false
	}
	return uint(assetID), uint(accountID), true
}

// accountContext 把操作者身分帶入 ctx（D7a 審計需要操作者，沿既有 asset 慣例）
func accountContext(c *gin.Context) context.Context {
	ctx := c.Request.Context()
	if userID, exists := c.Get("userID"); exists {
		ctx = context.WithValue(ctx, "userID", userID) //nolint:staticcheck // 沿用既有審計 context 慣例
	}
	if username, exists := c.Get("username"); exists {
		ctx = context.WithValue(ctx, "username", username) //nolint:staticcheck // 同上
	}
	// role 供跨資產複製的來源可見性判定短路 admin（D10）：不帶 role 會讓 admin
	// 落一般授權查詢，管理員複製自己管得到的資產帳號反而被擋
	if role, exists := c.Get("role"); exists {
		ctx = context.WithValue(ctx, "role", role) //nolint:staticcheck // 沿用既有 CheckPermission 慣例
	}
	return ctx
}

// List 列出資產的帳號（預設帳號排首），依請求者的有效帳號範圍過濾。
//
// 為何過濾（D5，opus 階段 2 MED）：本端點僅需 asset:view，過濾前對任何可視該
// 資產的使用者回傳全部帳號**含 privileged 標記**——等於把「這台機器上有哪些
// 特權帳號」公開給只該看到自己那組帳號的人，是攻擊面偵察的現成清單。
// admin 與 auditor 於解析器內短路全量（管理／稽核視圖語義不變）。
//
// 過濾而非 403：範圍外帳號在請求者的世界裡就是不存在，回空清單即可——
// 回 403 反而洩漏「這台有你看不到的帳號」
func (h *AssetAccountHandler) List(c *gin.Context) {
	assetID, _, ok := accountParams(c, false)
	if !ok {
		return
	}
	userID, exists := middleware.GetCurrentUserID(c)
	if !exists {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return
	}
	accounts, err := h.accountService.List(assetID)
	if err != nil {
		respondAccountError(c, apierror.CodeInternalAssetAccountList, err)
		return
	}

	scope, err := h.scopeResolver.EffectiveViewAccountScope(accountAuthzContext(c), userID, assetID)
	if err != nil {
		respondAccountError(c, apierror.CodeInternalAssetAccountList, err)
		return
	}
	filtered := make([]*asset.AssetAccountDTO, 0, len(accounts))
	for _, a := range accounts {
		if scope.Allows(a.Username) {
			filtered = append(filtered, a)
		}
	}
	c.JSON(http.StatusOK, gin.H{"data": filtered, "total": len(filtered)})
}

// accountAuthzContext 帶角色的授權判定 context（沿用既有 role string key 慣例）
func accountAuthzContext(c *gin.Context) context.Context {
	ctx := c.Request.Context()
	if role, ok := c.Get("role"); ok {
		ctx = context.WithValue(ctx, "role", role) //nolint:staticcheck // 沿用既有 CheckPermission 慣例
	}
	return ctx
}

// Create 建立帳號（支援 copy_from_account_id 由其他資產帳號複製）
func (h *AssetAccountHandler) Create(c *gin.Context) {
	assetID, _, ok := accountParams(c, false)
	if !ok {
		return
	}
	var req asset.CreateAssetAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	account, err := h.accountService.Create(accountContext(c), assetID, &req)
	if err != nil {
		respondAccountError(c, apierror.CodeInternalAssetAccountCreate, err)
		return
	}
	c.JSON(http.StatusCreated, account)
}

// Update 更新帳號（username／憑證／標記／備註；default 切換走 set-default）
func (h *AssetAccountHandler) Update(c *gin.Context) {
	assetID, accountID, ok := accountParams(c, true)
	if !ok {
		return
	}
	var req asset.UpdateAssetAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	account, err := h.accountService.Update(accountContext(c), assetID, accountID, &req)
	if err != nil {
		respondAccountError(c, apierror.CodeInternalAssetAccountUpdate, err)
		return
	}
	c.JSON(http.StatusOK, account)
}

// Delete 刪除帳號（禁刪最後一個預設帳號，D8）
func (h *AssetAccountHandler) Delete(c *gin.Context) {
	assetID, accountID, ok := accountParams(c, true)
	if !ok {
		return
	}
	if err := h.accountService.Delete(accountContext(c), assetID, accountID); err != nil {
		respondAccountError(c, apierror.CodeInternalAssetAccountDelete, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// SetDefault 指定預設帳號（交易式切換）
func (h *AssetAccountHandler) SetDefault(c *gin.Context) {
	assetID, accountID, ok := accountParams(c, true)
	if !ok {
		return
	}
	account, err := h.accountService.SetDefault(accountContext(c), assetID, accountID)
	if err != nil {
		respondAccountError(c, apierror.CodeInternalAssetAccountSetDefault, err)
		return
	}
	c.JSON(http.StatusOK, account)
}

// RegisterRoutes 註冊資產帳號路由。
//
// 讀取端（列表）與資產詳情同權（asset:view ＋ 逐資產可視守門）——階段 5 的
// 連線帳號選擇器需要一般 user 讀得到自己有權連的資產帳號。
// 寫入端一律 asset:update：帳號憑證是連線身分本體，寫入權不得低於改資產。
func (h *AssetAccountHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService, authz AssetAuthorizationServiceInterface) {
	accounts := r.Group("/assets/:id/accounts")
	accounts.Use(middleware.AuthMiddleware(authService))

	// 逐資產可視性守門：無條件生效（權限旗標已退場，security-backlog-settlement D5）
	//（session-access-scoping 讀取端點無條件守門紅線）
	visible := middleware.RequireAssetVisible(authz)

	accounts.GET("", middleware.RequirePermission(middleware.PermAssetView), visible, h.List)
	accounts.POST("", middleware.RequirePermission(middleware.PermAssetUpdate), h.Create)
	accounts.PUT("/:accountId", middleware.RequirePermission(middleware.PermAssetUpdate), h.Update)
	accounts.DELETE("/:accountId", middleware.RequirePermission(middleware.PermAssetUpdate), h.Delete)
	accounts.POST("/:accountId/set-default", middleware.RequirePermission(middleware.PermAssetUpdate), h.SetDefault)
}
