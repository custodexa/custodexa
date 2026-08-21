package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/identity"
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
	reloader    ChangeSecretReloader
}

// NewChangeSecretHandler 建立 handler
func NewChangeSecretHandler(planService *asset.ChangeSecretPlanService, runner *asset.ChangeSecretRunner,
	candidates *asset.ChangeSecretCandidateService, retry *asset.ChangeSecretRetryRunner,
	reloader ChangeSecretReloader) *ChangeSecretHandler {
	return &ChangeSecretHandler{
		planService: planService, runner: runner,
		candidates: candidates, retry: retry, reloader: reloader,
	}
}

// changeSecretCandidateDTO 候選憑證的對外表示。
//
// **本結構刻意不含任何秘密欄位**（design D10）：model 的 PasswordEnc／PrivateKeyEnc
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
	items, err := h.candidates.List()
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

// RetryCandidate 對單筆候選立即觸發一次重試（同步執行，回傳結果供 UI 立即反映）
func (h *ChangeSecretHandler) RetryCandidate(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "change_secret_candidate"})
		return
	}
	cand, err := h.candidates.Get(uint(id))
	if err != nil {
		respondCandidateError(c, apierror.CodeInternalChangeSecretCandidateQuery, err)
		return
	}
	// 候選是單一資產單一帳號的憑證，路徑上的 :id 是候選 id——中介層推導不出主體，
	// 只有讀出候選後才知道打的是哪台機器（auditor-workbench D4）
	setAuditAssetIDValue(c, cand.AssetID)
	promoted := h.retry.RetryOne(cand)
	c.JSON(http.StatusOK, gin.H{"promoted": promoted})
}

// DiscardCandidate admin 顯式清除候選（破壞性：候選是那把可能已在遠端生效的
// 秘密的唯一副本，清除後只能以帶外途徑救回該帳號）
func (h *ChangeSecretHandler) DiscardCandidate(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "change_secret_candidate"})
		return
	}
	userID, username, _ := currentUser(c)
	// 主體在清除前取：DiscardByAdmin 成功後候選列已不在，事後查不回它屬於哪台資產
	var assetID uint
	if cand, gerr := h.candidates.Get(uint(id)); gerr == nil {
		assetID = cand.AssetID
	}
	if err := h.candidates.DiscardByAdmin(uint(id), userID, username); err != nil {
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
	switch {
	case errors.Is(err, asset.ErrPlanNoAssets):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodePlanNoAssets, nil)
	case errors.Is(err, asset.ErrPlanBadCron):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodePlanBadCron, nil)
	case errors.Is(err, asset.ErrPlanBadSecretType):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodePlanBadSecretType, nil)
	case errors.Is(err, asset.ErrPlanBadKeyStrategy):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodePlanBadKeyStrategy, nil)
	case errors.Is(err, asset.ErrPasswordLengthOutOfRange):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodePlanBadPasswordLen, nil)
	case errors.Is(err, asset.ErrPlanNameExists):
		apierror.Respond(c, http.StatusConflict, apierror.CodePlanNameExists, nil)
	case errors.Is(err, asset.ErrPlanNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodePlanNotFound, nil)
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
	plans, err := h.planService.List()
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
	plan, err := h.planService.Create(&req)
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
	plan, err := h.planService.Update(uint(id), &req)
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
	if err := h.planService.Delete(uint(id)); err != nil {
		respondPlanError(c, apierror.CodeInternalChangeSecretPlanDelete, err)
		return
	}
	h.reload()
	c.JSON(http.StatusOK, gin.H{})
}

// Run 手動觸發（async：批次可能耗時，結果經 records 查詢）。
//
// **審計不填 asset_id**（auditor-workbench D4）：計畫的 AssetIDs 是一組資產，
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
	plan, err := h.planService.Get(uint(id))
	if err != nil {
		respondPlanError(c, apierror.CodeInternalChangeSecretPlanQuery, err)
		return
	}
	go h.runner.RunPlan(plan)
	c.JSON(http.StatusAccepted, gin.H{})
}

// Records 執行記錄
func (h *ChangeSecretHandler) Records(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "change_secret_plan"})
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	records, err := h.planService.Records(uint(id), limit)
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
	g.Use(middleware.RequireRole("admin"))
	{
		g.GET("", h.List)
		g.POST("", h.Create)
		g.PUT("/:id", h.Update)
		g.DELETE("/:id", h.Delete)
		g.POST("/:id/run", h.Run)
		g.GET("/:id/records", h.Records)
	}

	// 候選憑證（change-secret-ssh-deepening D4）：另立資源路徑——候選的生命週期
	// 跨計劃（計劃刪除後候選仍須被處置），掛在 plan 下會讓它隨計劃消失
	cg := r.Group("/change-secret-candidates")
	cg.Use(middleware.AuthMiddleware(authService))
	cg.Use(middleware.RequireRole("admin"))
	{
		cg.GET("", h.ListCandidates)
		cg.POST("/:id/retry", h.RetryCandidate)
		cg.DELETE("/:id", h.DiscardCandidate)
	}
}
