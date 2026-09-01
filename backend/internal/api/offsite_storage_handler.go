package api

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/offsite"
	"github.com/custodexa/backend/internal/sourceip"
	"github.com/gin-gonic/gin"
)

// 離機儲存管理 API（admin-only）。
//
// **薄轉接層**：驗證、鎖、加密、審計、限流全在 `internal/offsite` 的服務層；
// 這裡只做三件事——(1) 綁定請求並自 JWT 填 actor（不接受請求端指定操作者）、
// (2) 把服務層的靜態拒因與哨兵映射為機器碼與 HTTP 狀態、(3) 回傳 DTO。
//
// # 憑證永不出站
//
// 讀取 DTO 是 **write-only 形態**：只有 `has_credentials` 布林、`credential_mode`
// 與 `credentials_cleared_at`，**沒有值、也沒有遮罩值**（遮罩值仍會洩漏長度與
// 前綴）。禁 request-body logging 由具名測試釘住，斷言面是 handler＋middleware 級的
// 回應體、審計列、operational log 與錯誤鏈全文。
//
// # 兩種失敗語義分立（連線測試）
//
//   - 測試**未能執行**（欄位驗證、限流、憑證不可解）→ 4xx／5xx，走 apierror 信封。
//   - 測試**已執行含失敗** → 一律 HTTP 200，失敗資訊在 body 的 `stages[]`。
//
// 把「bucket 不可達」回成 4xx 會使前端無從呈現「探測跑完但某一步失敗」的階梯結果，
// 而分階段定位正是這個端點存在的理由（沿 LDAP 目錄測試的同一裁決）。

// OffsiteLedgerReader 狀態與失敗清單所需的帳冊讀取面（消費者側窄介面）。
//
// **api 層不得直接 gorm 查 `offsite_objects`**（`TestAPILayerHasNoDirectModelQuery`
// 盯著），一律經本介面。
type OffsiteLedgerReader interface {
	Counts() (map[string]int64, error)
	TotalObjects() (int64, error)
	CountFailed() (int64, error)
	OldestPendingAges(now time.Time) (map[string]float64, error)
	ListFailed(page, size int) ([]model.OffsiteObject, int64, error)
	Get(id uint) (*model.OffsiteObject, error)
	RetryFailed(objectID uint) (int64, error)
}

// OffsiteOwnerDescriber 失敗清單的擁有者描述面（各 adapter 實作）。
type OffsiteOwnerDescriber interface {
	Kind() string
	Describe(ownerID uint) (offsite.OwnerDescription, error)
}

// OffsiteStorageHandler 離機儲存管理 handler。
type OffsiteStorageHandler struct {
	profiles *offsite.OffsiteProfileService
	ledger   OffsiteLedgerReader
	// describers kind → 擁有者描述面（失敗清單的顯示欄）
	describers map[string]OffsiteOwnerDescriber
}

// NewOffsiteStorageHandler 建立 handler。
func NewOffsiteStorageHandler(profiles *offsite.OffsiteProfileService,
	ledger OffsiteLedgerReader, describers ...OffsiteOwnerDescriber) *OffsiteStorageHandler {
	m := map[string]OffsiteOwnerDescriber{}
	for _, d := range describers {
		if d != nil {
			m[d.Kind()] = d
		}
	}
	return &OffsiteStorageHandler{profiles: profiles, ledger: ledger, describers: m}
}

// RegisterRoutes 註冊離機儲存路由（admin 限定，沿 LDAP 目錄設定的掛法）。
func (h *OffsiteStorageHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	g := r.Group("/offsite-storage")
	g.Use(middleware.AuthMiddleware(authService))
	g.Use(middleware.RequireRole("admin"))
	{
		g.GET("/status", h.Status)
		g.GET("/failures", h.Failures)
		g.POST("/test", h.Test)
		g.POST("/retry-failed", h.RetryFailed)
		g.POST("/objects/:id/retry", h.RetryObject)

		g.GET("/settings", h.GetSettings)
		g.PUT("/settings", h.SaveSettings)
		g.POST("/settings/confirm", h.ConfirmSettings)
		g.POST("/settings/disable", h.DisableSettings)

		g.GET("/profiles", h.ListProfiles)
		g.POST("/profiles/:id/revoke-credentials", h.RevokeCredentials)
	}
}

// currentOffsiteActor 由已認證脈絡取操作者（**不自請求 body 取**：
// 讓請求端指定 actor 等於讓被劫持的 session 自選署名）。
func currentOffsiteActor(c *gin.Context) offsite.OffsiteActor {
	userID, _ := middleware.GetCurrentUserID(c)
	username, _ := middleware.GetCurrentUsername(c)
	return offsite.OffsiteActor{ID: userID, Name: username, IP: sourceip.Of(c)}
}

// ── DTO ───────────────────────────────────────────────────────────────────

// offsiteProfileView 設定的出站投影。**恆不含憑證與其遮罩**。
func offsiteProfileView(v offsite.ProfileView) gin.H {
	return gin.H{
		"configured":             v.Configured,
		"disabled":               v.Disabled,
		"generation_id":          v.GenerationID,
		"profile_fingerprint":    v.ProfileFingerprint,
		"provider":               v.Provider,
		"endpoint_origin":        v.EndpointOrigin,
		"bucket":                 v.Bucket,
		"prefix":                 v.Prefix,
		"region":                 v.Region,
		"path_style":             v.PathStyle,
		"credential_mode":        v.CredentialMode,
		"has_credentials":        v.HasCredentials,
		"credentials_cleared_at": v.CredentialsClearedAt,
		"created_at":             v.CreatedAt,
		"activated_at":           v.ActivatedAt,
		"retired_at":             v.RetiredAt,
		"object_count":           v.ObjectCount,
	}
}

// offsiteSettingsRequest 設定寫入的 wire 形狀（PUT／confirm／test 共用）。
//
// 憑證欄的三種意圖見 `offsite.SettingsInput`：填值＝新憑證；`clear_credentials`
// ＝改走預設鏈；兩者皆無＝沿用既存（僅在落點未變時成立）。
type offsiteSettingsRequest struct {
	Provider  string `json:"provider"`
	Endpoint  string `json:"endpoint"`
	Bucket    string `json:"bucket"`
	Prefix    string `json:"prefix"`
	Region    string `json:"region"`
	PathStyle bool   `json:"path_style"`

	AccessKeyID        string `json:"access_key_id"`
	SecretAccessKey    string `json:"secret_access_key"`
	ServiceAccountJSON string `json:"service_account_json"`
	ClearCredentials   bool   `json:"clear_credentials"`

	// ExpectedCurrentGenerationID／SettingsDigest 僅 confirm 使用：
	// 由「需確認」回應**原樣攜回**（0＝預期目前無現行世代）
	ExpectedCurrentGenerationID uint   `json:"expected_current_generation_id"`
	SettingsDigest              string `json:"settings_digest"`
}

func (r offsiteSettingsRequest) toInput() offsite.SettingsInput {
	return offsite.SettingsInput{
		Provider: r.Provider, Endpoint: r.Endpoint, Bucket: r.Bucket,
		Prefix: r.Prefix, Region: r.Region, PathStyle: r.PathStyle,
		AccessKeyID: r.AccessKeyID, SecretAccessKey: r.SecretAccessKey,
		ServiceAccountJSON: r.ServiceAccountJSON, ClearCredentials: r.ClearCredentials,
	}
}

// ── 狀態與佇列 ────────────────────────────────────────────────────────────

// Status 離機儲存總覽：設定摘要（含指紋）、憑證三態、各態計數、最老待上傳年齡、
// bucket 治理現況揭露。
func (h *OffsiteStorageHandler) Status(c *gin.Context) {
	view, err := h.profiles.Get()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalOffsiteStatus, err)
		return
	}
	counts, err := h.ledger.Counts()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalOffsiteStatus, err)
		return
	}
	total, err := h.ledger.TotalObjects()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalOffsiteStatus, err)
		return
	}
	ages, err := h.ledger.OldestPendingAges(time.Now())
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalOffsiteStatus, err)
		return
	}
	credState, err := h.profiles.CredentialState(c.Request.Context())
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalOffsiteStatus, err)
		return
	}

	body := offsiteProfileView(view)
	body["credential_state"] = string(credState)
	body["counts"] = counts
	body["total_objects"] = total
	body["oldest_pending_age_seconds"] = ages

	// bucket 治理現況是**資訊性揭露**（第 0 段）：探測不到即 unknown，
	// **不使本端點失敗**——遠端出事時管理員更需要看得到佇列
	if gov, ok := h.profiles.ProbeCurrentGovernance(c.Request.Context()); ok {
		body["governance"] = gin.H{
			"versioning":       string(gov.Versioning),
			"retention":        string(gov.Retention),
			"retention_detail": gov.RetentionDetail,
		}
	}
	c.JSON(http.StatusOK, body)
}

// offsiteFailureListSize 失敗清單單頁上限。
const offsiteFailureListSize = 20

// Failures 失敗清單（分頁）。
//
// **排序的誠實界定**：分頁由帳冊以 id 遞減取出，本層再依「距到期日近者在前」
// 重排——`retention_deadline` 不在帳冊裡（它是擁有者模組的事實），跨頁的全域排序
// 需要把全部失敗列取出並逐列 Describe，那在大量失敗時是一次 O(全表) 的點查詢風暴。
// 故排序**在頁內成立**；到期在即的件不會因為排在第二頁而被漏看——第一欄的
// 「距到期天數」在每一頁都看得見。
func (h *OffsiteStorageHandler) Failures(c *gin.Context) {
	page, ok := parsePositiveIntQuery(c, "page", 1)
	if !ok {
		return
	}
	size, ok := parsePositiveIntQuery(c, "size", offsiteFailureListSize)
	if !ok {
		return
	}
	rows, total, err := h.ledger.ListFailed(page, size)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalOffsiteStatus, err)
		return
	}

	now := time.Now()
	items := make([]gin.H, 0, len(rows))
	deadlines := make([]*time.Time, 0, len(rows))
	for i := range rows {
		row := rows[i]
		item := gin.H{
			"object_id":     row.ID,
			"kind":          row.Kind,
			"owner_id":      row.OwnerID,
			"origin":        row.Origin,
			"provider":      row.Provider,
			"bucket":        row.Bucket,
			"attempts":      row.Attempts,
			"error_code":    row.ErrorCode,
			"generation_id": row.StorageGenerationID,
			"updated_at":    row.UpdatedAt,
		}
		var deadline *time.Time
		if d, ok := h.describers[row.Kind]; ok {
			if desc, err := d.Describe(row.OwnerID); err == nil {
				item["label"] = desc.Label
				item["ended_at"] = desc.EndedAt
				if desc.RetentionDeadline != nil {
					deadline = desc.RetentionDeadline
					item["retention_deadline"] = desc.RetentionDeadline
					item["days_to_deadline"] = int(desc.RetentionDeadline.Sub(now).Hours() / 24)
				}
			}
		}
		items = append(items, item)
		deadlines = append(deadlines, deadline)
	}
	// 距到期近者在前；無到期日者殿後（永久保留不急）
	idx := make([]int, len(items))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		da, db := deadlines[idx[a]], deadlines[idx[b]]
		switch {
		case da == nil && db == nil:
			return false
		case da == nil:
			return false
		case db == nil:
			return true
		default:
			return da.Before(*db)
		}
	})
	sorted := make([]gin.H, 0, len(items))
	for _, i := range idx {
		sorted = append(sorted, items[i])
	}

	c.JSON(http.StatusOK, gin.H{
		"data": sorted, "total": total, "page": page, "page_size": size,
	})
}

// Test 以表單當下值執行連線測試（未儲存）。
func (h *OffsiteStorageHandler) Test(c *gin.Context) {
	var req offsiteSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	result, err := h.profiles.TestSettings(c.Request.Context(), req.toInput(), currentOffsiteActor(c))
	if err != nil {
		respondOffsiteError(c, err, apierror.CodeInternalOffsiteTest)
		return
	}
	stages := make([]gin.H, 0, len(result.Steps))
	for _, s := range result.Steps {
		stages = append(stages, gin.H{
			"step": s.Step, "outcome": string(s.Outcome),
			"code": s.ErrorCode, "detail": s.Detail,
		})
	}
	c.JSON(http.StatusOK, gin.H{"passed": result.Passed, "stages": stages})
}

// RetryFailed 批次重試全部 failed 件。
func (h *OffsiteStorageHandler) RetryFailed(c *gin.Context) {
	n, err := h.ledger.RetryFailed(0)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalOffsiteRetry, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"retried": n})
}

// RetryObject 單筆重試。
//
// **不存在與「非本功能可重試列」收斂同一個 404**：兩者的差異只對攻擊者有意義
// （帳冊列的存在性），對管理員則是同一個修正動作。
func (h *OffsiteStorageHandler) RetryObject(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusNotFound, apierror.CodeNotFoundOffsiteObject, nil)
		return
	}
	n, err := h.ledger.RetryFailed(uint(id))
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalOffsiteRetry, err)
		return
	}
	if n == 0 {
		apierror.Respond(c, http.StatusNotFound, apierror.CodeNotFoundOffsiteObject, nil)
		return
	}
	c.JSON(http.StatusOK, gin.H{"retried": n})
}

// ── 設定 CRUD ───────────────────────────────────────────────

// GetSettings 讀取現行設定（write-only DTO）。
//
// 未設定回 `configured:false` 而非 404——「還沒設定」是本資源的正常狀態。
func (h *OffsiteStorageHandler) GetSettings(c *gin.Context) {
	view, err := h.profiles.Get()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalOffsiteStatus, err)
		return
	}
	c.JSON(http.StatusOK, offsiteProfileView(view))
}

// SaveSettings 儲存設定。
//
// 新指紋 ≠ 現行且帳冊有存量物件 → **不逕行儲存**，回「需確認」：帶物件數、
// `expected_current_generation_id` 與設定摘要，由前端原樣攜回 confirm。
func (h *OffsiteStorageHandler) SaveSettings(c *gin.Context) {
	var req offsiteSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	res, err := h.profiles.Save(c.Request.Context(), req.toInput(), currentOffsiteActor(c))
	if err != nil {
		respondOffsiteError(c, err, apierror.CodeInternalOffsiteSettingsSave)
		return
	}
	if res.NeedsConfirmation {
		c.JSON(http.StatusOK, gin.H{
			"needs_confirmation":             true,
			"object_count":                   res.ObjectCount,
			"expected_current_generation_id": res.ExpectedCurrentGenerationID,
			"settings_digest":                res.SettingsDigest,
		})
		return
	}
	body := offsiteProfileView(res.View)
	body["needs_confirmation"] = false
	c.JSON(http.StatusOK, body)
}

// ConfirmSettings 執行世代切換（鎖內 CAS ＋ digest 比對 ＋ **同一驗證核心重驗**）。
func (h *OffsiteStorageHandler) ConfirmSettings(c *gin.Context) {
	var req offsiteSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	view, err := h.profiles.ConfirmGenerationSwitch(c.Request.Context(), offsite.ConfirmRequest{
		Settings:                    req.toInput(),
		ExpectedCurrentGenerationID: req.ExpectedCurrentGenerationID,
		SettingsDigest:              req.SettingsDigest,
	}, currentOffsiteActor(c))
	if err != nil {
		respondOffsiteError(c, err, apierror.CodeInternalOffsiteSettingsSave)
		return
	}
	c.JSON(http.StatusOK, offsiteProfileView(view))
}

// DisableSettings 停止離機：退役現行世代而**不建新列**；憑證不隨停用撤銷
// （歷史取回要用）。
func (h *OffsiteStorageHandler) DisableSettings(c *gin.Context) {
	if err := h.profiles.Disable(c.Request.Context(), currentOffsiteActor(c)); err != nil {
		respondOffsiteError(c, err, apierror.CodeInternalOffsiteSettingsSave)
		return
	}
	view, err := h.profiles.Get()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalOffsiteStatus, err)
		return
	}
	c.JSON(http.StatusOK, offsiteProfileView(view))
}

// ListProfiles 歷史世代列表（新到舊，含物件數與憑證模式）。
func (h *OffsiteStorageHandler) ListProfiles(c *gin.Context) {
	views, err := h.profiles.ListHistory()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalOffsiteStatus, err)
		return
	}
	out := make([]gin.H, 0, len(views))
	for _, v := range views {
		out = append(out, offsiteProfileView(v))
	}
	c.JSON(http.StatusOK, gin.H{"data": out, "total": len(out)})
}

// RevokeCredentials 撤銷某歷史世代的憑證。
//
// 撤銷後該世代的物件取回一律 `offsite.foreign_credentials_missing`，
// 且**不會回退到雲端預設憑證鏈**。查無世代收斂同一 404。
func (h *OffsiteStorageHandler) RevokeCredentials(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusNotFound, apierror.CodeNotFoundOffsiteGeneration, nil)
		return
	}
	if err := h.profiles.RevokeCredentials(c.Request.Context(), uint(id), currentOffsiteActor(c)); err != nil {
		respondOffsiteError(c, err, apierror.CodeInternalOffsiteSettingsSave)
		return
	}
	c.Status(http.StatusNoContent)
}

// ── 錯誤映射 ──────────────────────────────────────────────────────────────

// offsiteReasonCodes 服務層靜態拒因 → 機器碼（逐因對應）。
//
// 守衛 `TestOffsiteReasonCodeTablesExhaustive` 對本表與
// `offsite.AllSettingsReasons()` 做**雙向**比對。
var offsiteReasonCodes = map[string]apierror.ErrCode{
	offsite.ReasonCredentialConflict:        apierror.CodeValidationOffsiteCredentialConflict,
	offsite.ReasonProviderInvalid:           apierror.CodeValidationOffsiteProviderInvalid,
	offsite.ReasonBucketRequired:            apierror.CodeValidationOffsiteBucketRequired,
	offsite.ReasonEndpointInvalid:           apierror.CodeValidationOffsiteEndpointInvalid,
	offsite.ReasonEndpointHasSecrets:        apierror.CodeValidationOffsiteEndpointHasSecrets,
	offsite.ReasonRegionOrEndpointRequired:  apierror.CodeValidationOffsiteRegionOrEndpointRequired,
	offsite.ReasonCredentialHalfSet:         apierror.CodeValidationOffsiteCredentialHalfSet,
	offsite.ReasonCredentialReuseOnMove:     apierror.CodeRuleOffsiteCredentialReuseOnMove,
	offsite.ReasonStaleConfirmation:         apierror.CodeConflictOffsiteSettingsStaleConfirmation,
	offsite.ReasonDigestMismatch:            apierror.CodeConflictOffsiteSettingsDigestMismatch,
	offsite.ReasonNoCurrentGeneration:       apierror.CodeConflictOffsiteNoCurrentGeneration,
	offsite.ReasonGenerationNotFound:        apierror.CodeNotFoundOffsiteGeneration,
	offsite.ReasonCredentialsAlreadyRevoked: apierror.CodeConflictOffsiteCredentialsAlreadyRevoked,
	offsite.ReasonEncryptFailed:             apierror.CodeInternalOffsiteCredentialEncrypt,
	offsite.ReasonDecryptFailed:             apierror.CodeInternalOffsiteCredentialDecrypt,
}

// offsiteReasonStatus 拒因的 HTTP 狀態（未列者預設 400）。
var offsiteReasonStatus = map[string]int{
	offsite.ReasonCredentialReuseOnMove:     http.StatusConflict,
	offsite.ReasonStaleConfirmation:         http.StatusConflict,
	offsite.ReasonDigestMismatch:            http.StatusConflict,
	offsite.ReasonNoCurrentGeneration:       http.StatusConflict,
	offsite.ReasonGenerationNotFound:        http.StatusNotFound,
	offsite.ReasonCredentialsAlreadyRevoked: http.StatusConflict,
	offsite.ReasonEncryptFailed:             http.StatusInternalServerError,
	offsite.ReasonDecryptFailed:             http.StatusInternalServerError,
}

// respondOffsiteError 服務層錯誤 → HTTP。
//
// **原始錯誤只進伺服端 log**（`RespondInternal` 的既有語義）：儲存端的錯誤字串
// 可能夾帶端點、bucket 路徑甚至簽章材料。
func respondOffsiteError(c *gin.Context, err error, fallback apierror.ErrCode) {
	if reason := offsite.ReasonOf(err); reason != "" {
		code, ok := offsiteReasonCodes[reason]
		if !ok {
			// 對照表漏一項＝守衛已紅；執行期收斂為 500 而**不是**把拒因字串外送
			apierror.RespondInternal(c, http.StatusInternalServerError, fallback, err)
			return
		}
		status := http.StatusBadRequest
		if s, ok := offsiteReasonStatus[reason]; ok {
			status = s
		}
		if status >= 500 {
			apierror.RespondInternal(c, status, code, err)
			return
		}
		apierror.Respond(c, status, code, nil)
		return
	}
	switch {
	case errors.Is(err, offsite.ErrOffsiteTestRateLimited):
		apierror.Respond(c, http.StatusTooManyRequests, apierror.CodeRuleOffsiteTestRateLimited, nil)
	case errors.Is(err, offsite.ErrOffsiteProfileBusy):
		apierror.Respond(c, http.StatusConflict, apierror.CodeConflictOffsiteProfileBusy, nil)
	case errors.Is(err, offsite.ErrNoCurrentGeneration):
		apierror.Respond(c, http.StatusConflict, apierror.CodeConflictOffsiteNoCurrentGeneration, nil)
	default:
		if code := offsiteFailureCode(err); code != "" {
			apierror.Respond(c, http.StatusConflict, code, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, fallback, err)
	}
}
