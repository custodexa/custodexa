package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/authz/disclosure"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/gin-gonic/gin"
)

// ChangeSecretReloader 排程重載介面（避免 api 依賴 scheduler 具體型別）
type ChangeSecretReloader interface {
	Reload()
}

// ChangeSecretHandler 改密計劃 API（admin only）
type ChangeSecretHandler struct {
	planService *asset.ChangeSecretPlanService
	runner      *asset.ChangeSecretRunner
	candidates  *asset.ChangeSecretCandidateService
	retry       *asset.ChangeSecretRetryRunner
	batches     *asset.ChangeSecretBatchService
	reloader    ChangeSecretReloader
	// takeover 主機身分人工承接服務。組裝根在啟動時確認它完整就緒才注入；
	// 未注入的 handler 不處理帶確認的請求
	takeover *asset.HostIdentityTakeoverService
	// confirmer 帶確認的重試所呼叫的動作；由 SetHostIdentityTakeover 設為 takeover
	confirmer hostIdentityConfirmer
}

// SetHostIdentityTakeover 注入人工承接服務。
func (h *ChangeSecretHandler) SetHostIdentityTakeover(s *asset.HostIdentityTakeoverService) {
	h.takeover = s
	h.confirmer = nil
	if s != nil {
		h.confirmer = s
	}
}

// HostIdentityTakeoverWired 承接服務已注入且依賴完整（組裝自檢用）。
func (h *ChangeSecretHandler) HostIdentityTakeoverWired() bool {
	return h != nil && h.takeover != nil && len(h.takeover.WiringGaps()) == 0
}

// NewChangeSecretHandler 建立 handler
func NewChangeSecretHandler(planService *asset.ChangeSecretPlanService, runner *asset.ChangeSecretRunner,
	candidates *asset.ChangeSecretCandidateService, retry *asset.ChangeSecretRetryRunner,
	batches *asset.ChangeSecretBatchService, reloader ChangeSecretReloader) *ChangeSecretHandler {
	return &ChangeSecretHandler{
		planService: planService, runner: runner,
		candidates: candidates, retry: retry, batches: batches, reloader: reloader,
	}
}

// changeSecretCandidateDTO 候選憑證的對外表示。
//
// **本結構刻意不含任何秘密欄位**：model 的 PasswordEnc／PrivateKeyEnc
// 標 json:"-" 只擋住「直接序列化 model」這一種洩漏；handler 一律回 DTO，
// 使「不小心把 model 丟出去」在型別層即不成立。
type changeSecretCandidateDTO struct {
	ID              uint      `json:"id"`
	AssetID         uint      `json:"asset_id"`
	AccountID       uint      `json:"account_id"`
	AccountUsername string    `json:"account_username"`
	PlanID          uint      `json:"plan_id"`
	SecretType      string    `json:"secret_type"`
	Applied         bool      `json:"applied"`
	Abandoned       bool      `json:"abandoned"`
	AttemptCount    int       `json:"attempt_count"`
	LastAttemptAt   time.Time `json:"last_attempt_at"`
	NextAttemptAt   time.Time `json:"next_attempt_at"`
	LastError       string    `json:"last_error"`
	CreatedAt       time.Time `json:"created_at"`
}

func newCandidateDTO(c *model.ChangeSecretCandidate) changeSecretCandidateDTO {
	return changeSecretCandidateDTO{
		ID: c.ID, AssetID: c.AssetID, AccountID: c.AccountID,
		AccountUsername: c.AccountUsername, PlanID: c.PlanID,
		SecretType: c.SecretType, Applied: c.Applied, Abandoned: c.Abandoned,
		AttemptCount: c.AttemptCount, LastAttemptAt: c.LastAttemptAt,
		NextAttemptAt: c.NextAttemptAt, LastError: c.LastError, CreatedAt: c.CreatedAt,
	}
}

// ListCandidates 未驗證候選憑證清單（不含任何秘密材料）
func (h *ChangeSecretHandler) ListCandidates(c *gin.Context) {
	ctx, viewer := batchViewer(c)
	items, err := h.candidates.ListFor(ctx, viewer)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalChangeSecretCandidateQuery, err)
		return
	}
	out := make([]changeSecretCandidateDTO, 0, len(items))
	for i := range items {
		out = append(out, newCandidateDTO(&items[i]))
	}
	c.JSON(http.StatusOK, gin.H{"data": out, "total": len(out)})
}

// RetryCandidate 對單筆候選立即觸發一次重試（同步執行，回傳結果供 UI 立即反映）。
// 選用 body：{"confirm_host_identity": {...}} 明示承接主機身分停止的工作；
// 不帶 body 時行為與回應形狀不變，只在工作被主機身分守衛擋下時多帶 host_identity。
func (h *ChangeSecretHandler) RetryCandidate(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "change_secret_candidate"})
		return
	}
	// 形狀先於一切查詢與服務呼叫：不合法的 body 不會觸及任何狀態
	confirm, err := parseHostIdentityConfirmBody(c)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	ctx, viewer := batchViewer(c)
	cand, err := h.candidates.GetFor(ctx, viewer, uint(id))
	if err != nil {
		// 範圍外候選與不存在同形（範圍拒絕出口依候選種類回「候選不存在」）
		var denied *authz.ErrScopeDenied
		if errors.As(err, &denied) {
			middleware.RespondScopeDenied(c, denied)
			return
		}
		respondCandidateError(c, apierror.CodeInternalChangeSecretCandidateQuery, err)
		return
	}
	// 候選是單一資產單一帳號的憑證，路徑上的 :id 是候選 id——中介層推導不出主體，
	// 只有讀出候選後才知道打的是哪台機器（auditor-workbench）
	setAuditAssetIDValue(c, cand.AssetID)
	if confirm != nil {
		if h.confirmer == nil {
			apierror.RespondInternal(c, http.StatusInternalServerError,
				apierror.CodeInternalChangeSecretCandidateQuery, errors.New("人工承接服務未注入"))
			return
		}
		switch cerr := h.confirmer.ConfirmHostIdentityAndVerify(accountContext(c), "candidate", cand.ID, *confirm); {
		case cerr == nil:
			c.JSON(http.StatusOK, gin.H{"promoted": true})
		case errors.Is(cerr, asset.ErrHostIdentityVerifyFailed):
			// 驗證沒有通過：候選保留、可再次確認，失敗原因在候選的最近錯誤
			c.JSON(http.StatusOK, gin.H{"promoted": false})
		case isHostIdentityTargetChanged(cerr):
			// 授權目標已改變：不是身分異動，候選與工作列都沒被改動
			c.JSON(http.StatusOK, gin.H{"promoted": false, "reason": model.ChangeSecretReasonAuthzTargetChanged})
		default:
			respondHostIdentityConfirmError(c, apierror.CodeInternalChangeSecretCandidateQuery, cerr)
		}
		return
	}
	res := h.retry.RetryOneAsResult(accountContext(c), cand)
	if res.HostIdentity != nil {
		c.JSON(http.StatusOK, gin.H{"promoted": res.Promoted, "host_identity": res.HostIdentity})
		return
	}
	c.JSON(http.StatusOK, gin.H{"promoted": res.Promoted})
}

// DiscardCandidate admin 顯式清除候選（破壞性：候選是那把可能已在遠端生效的
// 秘密的唯一副本，清除後只能以帶外途徑救回該帳號）
func (h *ChangeSecretHandler) DiscardCandidate(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "change_secret_candidate"})
		return
	}
	_, username, _ := currentUser(c)
	ctx, viewer := batchViewer(c)
	// 範圍判定與刪除同一交易；主體（候選所屬資產）由清除交易在刪列前讀出帶回，刪後查不回
	assetID, err := h.candidates.DiscardFor(ctx, viewer, uint(id), username)
	if err != nil {
		// 範圍外候選與不存在同形（範圍拒絕出口依候選種類回「候選不存在」）
		var denied *authz.ErrScopeDenied
		if errors.As(err, &denied) {
			middleware.RespondScopeDenied(c, denied)
			return
		}
		respondCandidateError(c, apierror.CodeInternalChangeSecretCandidateDiscard, err)
		return
	}
	setAuditAssetIDValue(c, assetID)
	c.JSON(http.StatusOK, gin.H{})
}

func respondCandidateError(c *gin.Context, internalCode apierror.ErrCode, err error) {
	if errors.Is(err, asset.ErrCandidateNotFound) {
		apierror.Respond(c, http.StatusNotFound, apierror.CodeCandidateNotFound, nil)
		return
	}
	apierror.RespondInternal(c, http.StatusInternalServerError, internalCode, err)
}

// respondPlanError 映射 service 錯誤：輸入問題 400、名稱衝突 409、不存在 404，
// 其餘走呼叫端指定的 internalCode（各端點的 action 不同，訊息不同、碼各自獨立）
func respondPlanError(c *gin.Context, internalCode apierror.ErrCode, err error) {
	// 明列資產中有不存在或範圍外者：整份拒絕，只帶筆數（兩種原因同形）
	var unavailable *asset.BatchItemsUnavailableError
	if errors.As(err, &unavailable) {
		middleware.RespondBatchUnavailable(c, unavailable.Count)
		return
	}
	// 範圍外掛載須先確認：只帶範圍外台數（經揭露登錄），計畫未儲存
	var impactRequired *asset.CredentialImpactConfirmationRequiredError
	if errors.As(err, &impactRequired) {
		apierror.Respond(c, http.StatusConflict, apierror.CodeCredentialImpactConfirmationRequired, map[string]any{
			"count": disclosure.Count(disclosure.OutOfScopeAssetCount, impactRequired.Count),
		})
		return
	}
	switch {
	case errors.Is(err, asset.ErrPlanNoAssets):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodePlanNoAssets, nil)
	case errors.Is(err, asset.ErrPlanBadCron):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodePlanBadCron, nil)
	case errors.Is(err, asset.ErrPlanBadSecretType):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodePlanBadSecretType, nil)
	case errors.Is(err, asset.ErrPlanBadKeyStrategy):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodePlanBadKeyStrategy, nil)
	case errors.Is(err, asset.ErrPlanBadMaxAgeDays):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodePlanBadMaxAgeDays, nil)
	case errors.Is(err, asset.ErrPasswordLengthOutOfRange):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodePlanBadPasswordLen, nil)
	case errors.Is(err, asset.ErrPlanBadTargetKind):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodePlanTargetKind, nil)
	case errors.Is(err, asset.ErrPlanTargetCredentialRequired):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodePlanTargetCredentialRequire, nil)
	case errors.Is(err, asset.ErrPlanSharedCredentialTarget):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodePlanSharedCredentialTarget, nil)
	case errors.Is(err, asset.ErrPlanNameExists):
		apierror.Respond(c, http.StatusConflict, apierror.CodePlanNameExists, nil)
	case errors.Is(err, asset.ErrPlanNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodePlanNotFound, nil)
	// 目標憑證不存在與憑證庫端點同碼：「不存在／已刪除／對操作者不可見」在憑證
	// 這個資源上是同一個出口，分流即成為存在性探測器
	case errors.Is(err, asset.ErrPlanTargetCredentialNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeCredentialNotFound, nil)
	default:
		apierror.RespondInternal(c, http.StatusInternalServerError, internalCode, err)
	}
}

func (h *ChangeSecretHandler) reload() {
	if h.reloader != nil {
		h.reloader.Reload()
	}
}

// List 計劃列表
func (h *ChangeSecretHandler) List(c *gin.Context) {
	plans, err := h.planService.ListFor(accountContext(c))
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalChangeSecretPlanQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": plans, "total": len(plans)})
}

// Create 建立計劃
func (h *ChangeSecretHandler) Create(c *gin.Context) {
	var req asset.ChangeSecretPlanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	plan, err := h.planService.Create(accountContext(c), &req)
	if err != nil {
		respondPlanError(c, apierror.CodeInternalChangeSecretPlanCreate, err)
		return
	}
	h.reload()
	c.JSON(http.StatusCreated, plan)
}

// Update 更新計劃
func (h *ChangeSecretHandler) Update(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "change_secret_plan"})
		return
	}
	var req asset.ChangeSecretPlanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	plan, err := h.planService.Update(accountContext(c), uint(id), &req)
	if err != nil {
		respondPlanError(c, apierror.CodeInternalChangeSecretPlanUpdate, err)
		return
	}
	h.reload()
	c.JSON(http.StatusOK, plan)
}

// Delete 刪除計劃
func (h *ChangeSecretHandler) Delete(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "change_secret_plan"})
		return
	}
	if err := h.planService.DeleteFor(accountContext(c), uint(id)); err != nil {
		respondPlanError(c, apierror.CodeInternalChangeSecretPlanDelete, err)
		return
	}
	h.reload()
	c.JSON(http.StatusOK, gin.H{})
}

// Run 手動觸發（async：批次可能耗時，結果經 records 查詢）。
//
// **審計不填 asset_id**（auditor-workbench）：計畫的 AssetIDs 是一組資產，
// 觸發一次即對多台執行，沒有單一主體。逐資產的改密事實由 runner 落地時的
// 帳號變更審計（writeAssetAccountAudit，各自帶自己的 asset_id）承載——
// 在這一列挑一台填，等於偽稱其餘幾台沒被改密。
// 同理適用於本 handler 的計畫 Create／Update／Delete：改的是計畫本身，
// 受影響資產集只在計畫欄位裡，不是這次請求的主體。
func (h *ChangeSecretHandler) Run(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "change_secret_plan"})
		return
	}
	plan, err := h.planService.GetFor(accountContext(c), uint(id))
	if err != nil {
		respondPlanError(c, apierror.CodeInternalChangeSecretPlanQuery, err)
		return
	}
	// 手動執行以點擊者為發起者並重驗其能力，不改變排程的發起者
	go h.runner.RunPlanAs(accountContext(c), plan)
	c.JSON(http.StatusAccepted, gin.H{})
}

// Reauthorize 一鍵重新授權：升級時查不到可歸屬發起者而暫停的排程計畫，改以目前操作者為
// 發起者並恢復排程（cron 與啟用設定原樣保留）。之後每次執行仍以該操作者當下的能力重驗。
// 審計由路由審計中介層記錄（誰、何時、哪些計畫由回應的 plan_ids 帶出）。
func (h *ChangeSecretHandler) Reauthorize(c *gin.Context) {
	ids, skipped, err := h.planService.ReauthorizePending(accountContext(c))
	if err != nil {
		respondPlanError(c, apierror.CodeInternalChangeSecretPlanUpdate, err)
		return
	}
	h.reload()
	// skipped：點擊者對該計畫的目標能力不足，或承接的審計寫不進去；兩者都未承接、維持暫停
	c.JSON(http.StatusOK, gin.H{"plan_ids": ids, "count": len(ids), "skipped_plan_ids": skipped})
}

// Records 執行記錄
func (h *ChangeSecretHandler) Records(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "change_secret_plan"})
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	records, err := h.planService.RecordsFor(accountContext(c), uint(id), limit)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalChangeSecretRecordQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": records, "total": len(records)})
}

// RegisterRoutes 註冊路由（憑證生命週期屬高權限操作，整組 admin only）
func (h *ChangeSecretHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	g := r.Group("/change-secret-plans")
	g.Use(middleware.AuthMiddleware(authService))
	g.Use(middleware.EnforceRegistry())
	{
		g.GET("", h.List)
		g.POST("", h.Create)
		g.PUT("/:id", h.Update)
		g.DELETE("/:id", h.Delete)
		g.POST("/:id/run", h.Run)
		g.POST("/reauthorize", h.Reauthorize)
		g.GET("/:id/records", h.Records)
	}

	// 候選憑證：另立資源路徑——候選的生命週期
	// 跨計劃（計劃刪除後候選仍須被處置），掛在 plan 下會讓它隨計劃消失
	cg := r.Group("/change-secret-candidates")
	cg.Use(middleware.AuthMiddleware(authService))
	cg.Use(middleware.EnforceRegistry())
	{
		cg.GET("", h.ListCandidates)
		cg.POST("/:id/retry", h.RetryCandidate)
		cg.DELETE("/:id", h.DiscardCandidate)
	}

	// 批次改密：以帳號名為軸的一次性處置，與計劃並列而非掛在計劃下
	//（批次沒有排程、跑完即結束，它的記錄不屬於任何計劃）
	bg := r.Group("/change-secret-batches")
	bg.Use(middleware.AuthMiddleware(authService))
	bg.Use(middleware.EnforceRegistry())
	{
		bg.GET("/usernames", h.BatchUsernames)
		bg.GET("/targets", h.BatchTargets)
		bg.GET("", h.ListBatches)
		bg.POST("", h.CreateBatch)
		bg.GET("/:id", h.GetBatch)
	}
}
