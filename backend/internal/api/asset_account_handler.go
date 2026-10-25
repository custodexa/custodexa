package api

import (
	"context"
	"errors"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"strconv"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/gin-gonic/gin"
)

// AssetAccountServiceInterface 資產帳號服務接口（用於測試注入）
type AssetAccountServiceInterface interface {
	List(assetID uint) ([]*asset.AssetAccountDTO, error)
	Create(ctx context.Context, assetID uint, req *asset.CreateAssetAccountRequest) (*asset.AssetAccountDTO, error)
	Update(ctx context.Context, assetID, accountID uint, req *asset.UpdateAssetAccountRequest) (*asset.AssetAccountDTO, error)
	Delete(ctx context.Context, assetID, accountID uint) error
	SetDefault(ctx context.Context, assetID, accountID uint) (*asset.AssetAccountDTO, error)
}

// AccountScopeResolver 有效帳號範圍解析。
//
// 獨立於 AssetAuthorizationServiceInterface 的窄介面：帳號範圍只有帳號端點需要，
// 併入共用介面會逼 asset/asset_group 兩支 handler 的既有測試替身全部補實作
type AccountScopeResolver interface {
	EffectiveViewAccountScope(ctx context.Context, userID, assetID uint) (authz.EffectiveAccountScope, error)
}

// AssetAccountHandler 資產帳號 API。
//
// 回應一律走 asset.AssetAccountDTO：帳號密文欄位在 model 已是 json:"-"，
// DTO 再把「是否已設定憑證」降為布林——憑證本體與其密文都不出站（連線收口紅線）。
type AssetAccountHandler struct {
	accountService AssetAccountServiceInterface
	// scopeResolver 列表過濾用。**建構期必填**：設為可選欄位＋nil 時不過濾
	// 等於留一個「忘記注入就退回舊的全量外洩行為」的 fail-open 開關
	scopeResolver AccountScopeResolver
	// scopeGate 登錄閘的目標範圍判定依賴（建構參數，組裝端傳入）；nil 時宣告了目標的登錄項不放行
	scopeGate *middleware.ScopeGate
	// mgmt 資產管理可視（範圍化檢視者）；注入後列表與逐資產守門接受管理可視，管理可視時回該資產全部帳號
	mgmt middleware.AssetManagementVisibility
	// credScope 帳號列的憑證投影（範圍化檢視者）；未注入時帳號列照現行輸出
	credScope AccountCredentialScope
	// rowActions 範圍外憑證帳號列的動作判定；未注入時該列不帶 actions
	rowActions AccountRowActionSource
}

// AccountRowActionSource 帳號列動作判定（與各寫入端點同一組判定函式，見 asset.AccountRowActionJudge）。
type AccountRowActionSource interface {
	AccountRowChecks(ctx context.Context, assetID, accountID, credentialID uint) asset.AccountRowChecks
}

// SetAccountRowActions 注入帳號列動作判定（組裝時）。
func (h *AssetAccountHandler) SetAccountRowActions(s AccountRowActionSource) {
	h.rowActions = s
}

// AccountCredentialScope 帳號列的憑證投影來源：以讀取當下重新解析的主體同時回傳回應形狀（精簡、完整、
// 範圍化）與範圍化時 ids 中落在其憑證檢視集合內者。形狀與集合由同一份主體決定，呼叫端不另以請求主體判定。
type AccountCredentialScope interface {
	AccountCredentialProjection(ctx context.Context, ids []uint) (authz.AccountCredentialShape, map[uint]bool, error)
}

// SetAssetManagementVisibility 注入資產管理可視判定（組裝時，須早於 RegisterRoutes）。
func (h *AssetAccountHandler) SetAssetManagementVisibility(m middleware.AssetManagementVisibility) {
	h.mgmt = m
}

// SetAccountCredentialScope 注入帳號列的憑證投影（組裝時）。
func (h *AssetAccountHandler) SetAccountCredentialScope(s AccountCredentialScope) {
	h.credScope = s
}

// NewAssetAccountHandler 建立 handler
func NewAssetAccountHandler(accountService AssetAccountServiceInterface, scopeResolver AccountScopeResolver,
	scopeGate ...*middleware.ScopeGate) *AssetAccountHandler {
	return &AssetAccountHandler{accountService: accountService, scopeResolver: scopeResolver,
		scopeGate: firstScopeGate(scopeGate)}
}

// respondAccountError 帳號端點的統一錯誤出口：已知 sentinel 依 errors.Is 映射到
// 機器碼，未知一律 RespondInternal（成因只落伺服端日誌）。
// internalCode 為該端點的 INTERNAL_ASSET_ACCOUNT_<VERB> 碼。
func respondAccountError(c *gin.Context, internalCode apierror.ErrCode, err error) {
	// 交易內範圍判定：範圍拒絕交共用出口（與不存在同形）、能力拒絕回單一 forbidden
	if respondTxScopeError(c, err) || respondAssetWriteScopeError(c, err) {
		return
	}
	switch {
	case errors.Is(err, asset.ErrAssetNotFound):
		middleware.RespondTargetNotFound(c, authz.ScopeTargetAssetAccount, authz.ScopeLayerAsset)
	case errors.Is(err, asset.ErrAssetAccountNotFound):
		middleware.RespondTargetNotFound(c, authz.ScopeTargetAssetAccount, authz.ScopeLayerAccount)
	case errors.Is(err, asset.ErrAssetAccountSourceNotFound),
		// 來源不可見與來源不存在共用一碼：分流即成為「哪些 account id 存在」的探測器
		errors.Is(err, asset.ErrAssetAccountSourceForbidden):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetAccountSourceNotFound, nil)
	case errors.Is(err, asset.ErrPrivateKeyInvalid):
		// 與資產、憑證庫入口同碼；原始解析錯誤不帶出
		respondPrivateKeyInvalid(c)
	// 帳號表單內嵌密碼／私鑰是 SetSecret 的同義入口：缺 credential:set-secret 回權限不足，
	// 不外露缺哪一項（與資產表單同一出口）
	case errors.Is(err, asset.ErrCredentialBindForbidden),
		// 帳號名稱的欄位能力不足：與資產表單同一出口，不帶權限名
		errors.Is(err, asset.ErrFieldCapabilityDenied):
		respondAssetCapabilityDenial(c, err)
	// 憑證來源二擇一、已退場的複製參數、共用憑證的單台寫密：三者都是請求形狀
	// 或規則層的攔截，回機器碼而非讓它落 500
	case errors.Is(err, asset.ErrCredentialSourceAmbiguous):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeCredentialSourceAmbiguous, nil)
	case errors.Is(err, asset.ErrAccountCopyFromRemoved):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountCopyFromRemoved, nil)
	case errors.Is(err, asset.ErrAccountSharedCredentialSecret):
		apierror.Respond(c, http.StatusConflict, apierror.CodeAccountSharedCredentialSecret, nil)
	case errors.Is(err, asset.ErrCredentialUsernameImmutable):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeCredentialUsernameImmutable, nil)
	case errors.Is(err, asset.ErrCredentialNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeCredentialNotFound, nil)
	case errors.Is(err, asset.ErrCredentialDedicatedSingleBinding):
		apierror.Respond(c, http.StatusConflict, apierror.CodeCredentialDedicatedSingle, nil)
	case errors.Is(err, asset.ErrCredentialProtocolMismatch):
		apierror.Respond(c, http.StatusConflict, apierror.CodeCredentialProtocolMismatch, nil)
	case errors.Is(err, asset.ErrCredentialRotationActive):
		apierror.Respond(c, http.StatusConflict, apierror.CodeCredentialRotationActive, nil)
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

// accountContext 把操作者身分帶入 ctx（審計需要操作者，沿既有 asset 慣例）
func accountContext(c *gin.Context) context.Context {
	ctx := c.Request.Context()
	if userID, exists := c.Get("userID"); exists {
		ctx = context.WithValue(ctx, "userID", userID) //nolint:staticcheck // 沿用既有審計 context 慣例
	}
	if username, exists := c.Get("username"); exists {
		ctx = context.WithValue(ctx, "username", username) //nolint:staticcheck // 同上
	}
	// 主體供跨資產複製的來源可見性判定短路超管：不帶主體會讓超管
	// 落一般授權查詢，管理員複製自己管得到的資產帳號反而被擋
	return authz.ContextWithPrincipal(ctx, middleware.PrincipalFrom(c))
}

// List 列出資產的帳號（預設帳號排首），依請求者的有效帳號範圍過濾。
//
// 為何過濾：本端點僅需 asset:view，過濾前對任何可視該
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
	// 資產管理可視：管理視圖回該資產全部帳號，不經連線帳號範圍過濾（憑證身分欄位仍照下方欄位能力）
	managed, err := h.managedVisible(c, assetID)
	if err != nil {
		respondAccountError(c, apierror.CodeInternalAssetAccountList, err)
		return
	}
	filtered := make([]*asset.AssetAccountDTO, 0, len(accounts))
	for _, a := range accounts {
		if managed || scope.Allows(a.Username) {
			filtered = append(filtered, a)
		}
	}
	// 憑證身分只給具憑證檢視能力者：本端點同時服務管理視圖（帳號表格）與連線
	// 選帳號，而後者只需要挑一個名字。回精簡版而非「回完整版但前端不顯示」——
	// 出站了就是出站了，畫面不顯示不改變回應內容
	out, err := h.accountProjector().rows(c, filtered)
	if err != nil {
		respondAccountError(c, apierror.CodeInternalAssetAccountList, err)
		return
	}
	respondScoped(c, http.StatusOK, out)
}

// accountProjector 帳號列投影器：與憑證 handler 的 bind、rebind 共用同一個判定。
func (h *AssetAccountHandler) accountProjector() *accountRowProjector {
	return &accountRowProjector{credScope: h.credScope, rowActions: h.rowActions}
}

// AccountRowProjectorWired 帳號列投影來源已注入（組裝自檢用）。
func (h *AssetAccountHandler) AccountRowProjectorWired() bool {
	return h != nil && h.credScope != nil
}

// accountRowActions 把各動作的判定結果轉成列級旗標：通過＝可操作；能力拒絕＝no_capability；
// 範圍拒絕＝out_of_scope；其他錯誤是判定本身失敗，整個列表回內部錯誤（不以猜測的旗標呈現）。
func accountRowActions(checks asset.AccountRowChecks) (map[string]asset.CredentialAction, error) {
	out := make(map[string]asset.CredentialAction, 4)
	for _, e := range []struct {
		key string
		err error
	}{
		{asset.AccountRowActionRebind, checks.Rebind},
		{asset.AccountRowActionRemove, checks.Remove},
		{asset.AccountRowActionSecretFix, checks.SecretFix},
		{asset.AccountRowActionDetach, checks.Detach},
	} {
		action, err := accountRowAction(e.err)
		if err != nil {
			return nil, err
		}
		out[e.key] = action
	}
	return out, nil
}

func accountRowAction(err error) (asset.CredentialAction, error) {
	if err == nil {
		return asset.CredentialAction{Allowed: true}, nil
	}
	var scope *authz.ErrScopeDenied
	if errors.As(err, &scope) {
		return asset.CredentialAction{Reason: asset.CredentialActionOutOfScope}, nil
	}
	var write *authz.AssetWriteCapabilityError
	if errors.As(err, &write) || errors.Is(err, asset.ErrCredentialBindForbidden) {
		return asset.CredentialAction{Reason: asset.CredentialActionNoCapability}, nil
	}
	return asset.CredentialAction{}, err
}

// managedVisible 本請求的資產是否經管理可視：守門已標記者直接成立；同時連線可視的資產另以管理可視判定。
func (h *AssetAccountHandler) managedVisible(c *gin.Context, assetID uint) (bool, error) {
	if middleware.AssetVisibleViaManagement(c) {
		return true, nil
	}
	if h.mgmt == nil {
		return false, nil
	}
	managed, _, err := h.mgmt.ManagementVisibleAsset(accountAuthzContext(c), assetID)
	return managed, err
}

// credentialFieldsVisible 請求者是否可見憑證身分欄位（只在投影來源未注入時使用）。
//
// 判準是憑證管理授權點本身，不是「角色是不是 admin」：授權點日後若授予其他角色，
// 這裡不必跟著改；而以角色字面比對的版本會在那一天靜默地繼續收窄。
func credentialFieldsVisible(c *gin.Context) bool {
	return authz.FieldCapability(http.MethodGet, accountListRoute, "credential_identity_fields", middleware.PrincipalFrom(c))
}

// accountListRoute 帳號列表的登錄鍵路徑（欄位條件能力宣告在該登錄項上）。
const accountListRoute = "/api/v1/assets/:id/accounts"

// accountAuthzContext 帶主體的授權判定 context
func accountAuthzContext(c *gin.Context) context.Context {
	return authz.ContextWithPrincipal(c.Request.Context(), middleware.PrincipalFrom(c))
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
	// 帳號名稱與資產表單的帳號名稱同一欄位能力（登錄項宣告），缺能力整筆拒絕
	account, err := h.accountService.Create(withFieldCapability(c, accountContext(c)), assetID, &req)
	if err != nil {
		respondAccountError(c, apierror.CodeInternalAssetAccountCreate, err)
		return
	}
	out, perr := h.accountProjector().one(c, account)
	if perr != nil {
		respondAccountError(c, apierror.CodeInternalAssetAccountCreate, perr)
		return
	}
	respondScoped(c, http.StatusCreated, out)
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
	account, err := h.accountService.Update(withFieldCapability(c, accountContext(c)), assetID, accountID, &req)
	if err != nil {
		respondAccountError(c, apierror.CodeInternalAssetAccountUpdate, err)
		return
	}
	out, perr := h.accountProjector().one(c, account)
	if perr != nil {
		respondAccountError(c, apierror.CodeInternalAssetAccountUpdate, perr)
		return
	}
	respondScoped(c, http.StatusOK, out)
}

// Delete 刪除帳號（禁刪最後一個預設帳號）
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
	out, perr := h.accountProjector().one(c, account)
	if perr != nil {
		respondAccountError(c, apierror.CodeInternalAssetAccountSetDefault, perr)
		return
	}
	respondScoped(c, http.StatusOK, out)
}

// RegisterRoutes 註冊資產帳號路由。
//
// 讀取端（列表）與資產詳情同權（asset:view ＋ 逐資產可視守門）——階段 5 的
// 連線帳號選擇器需要一般 user 讀得到自己有權連的資產帳號。
// 寫入端一律 asset:update：帳號憑證是連線身分本體，寫入權不得低於改資產。
func (h *AssetAccountHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService, authz AssetAuthorizationServiceInterface) {
	accounts := r.Group("/assets/:id/accounts")
	accounts.Use(middleware.AuthMiddleware(authService))

	// 逐資產可視性守門：無條件生效（權限旗標已退場）
	//（讀取端點無條件守門紅線）
	visible := middleware.RequireAssetVisible(authz)
	if h.mgmt != nil {
		visible = middleware.RequireAssetVisibleOrManaged(authz, h.mgmt)
	}

	accounts.GET("", middleware.EnforceRegistry(h.scopeGate), visible, h.List)
	accounts.POST("", middleware.EnforceRegistry(h.scopeGate), h.Create)
	accounts.PUT("/:accountId", middleware.EnforceRegistry(h.scopeGate), h.Update)
	accounts.DELETE("/:accountId", middleware.EnforceRegistry(h.scopeGate), h.Delete)
	accounts.POST("/:accountId/set-default", middleware.EnforceRegistry(h.scopeGate), h.SetDefault)
}
