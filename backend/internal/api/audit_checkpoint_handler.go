package api

import (
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/keyvault"
)

// checkpointListMaxPageSize 列表單頁上限（鏈長可達萬級，不接受無界請求）
const checkpointListMaxPageSize = 200

// checkpointSigningPublicKeyProvider 公鑰出口的窄介面
// （實作為 keyvault.CheckpointSigningService；測試注入 fake）
type checkpointSigningPublicKeyProvider interface {
	ActiveVersion() int
	ActivePublicKeyBase64() string
	PublicKeyFingerprint(version int) (string, error)
}

// AuditCheckpointHandler 檢查點鏈的查詢／驗證／公鑰 API
// （audit-checkpoint-chain，admin 與 auditor 皆可讀，一律唯讀）。
//
// **本 handler 沒有任何寫入端點，這是設計而非疏漏**：檢查點的補蓋、重簽、
// 修鏈能力本身即偽造面（spec「無修鏈入口」）。日後若有人想加「重新計算
// 檢查點」的便利端點，請先讀那條 requirement
type AuditCheckpointHandler struct {
	verifier *audit.CheckpointVerifier
	signing  checkpointSigningPublicKeyProvider
	// autoVerify 自動驗證的營運狀態讀取端；nil＝不附帶該區塊
	autoVerify chainAutoVerifyStatusReader
}

// chainAutoVerifyStatusReader 自動驗證營運狀態的窄介面
// （實作為 *audit.ChainVerifyService）。**唯讀**：本端點是驗證面，
// 讀狀態不得建立或更新任何列
type chainAutoVerifyStatusReader interface {
	Status() (*audit.ChainAutoVerifyStatus, error)
}

// NewAuditCheckpointHandler 建立檢查點 handler
func NewAuditCheckpointHandler(verifier *audit.CheckpointVerifier,
	signing *keyvault.CheckpointSigningService) *AuditCheckpointHandler {
	h := &AuditCheckpointHandler{verifier: verifier}
	if signing != nil {
		h.signing = signing
	}
	return h
}

// SetAutoVerifyStatus 注入自動驗證營運狀態的讀取端。
//
// 未注入時 Verify 回應不含該區塊，驗證頁據此顯示「狀態無法取得」——
// **不得靜默隱藏整個區塊**：看不到區塊的稽核會讀成「沒有這個機制」，
// 那比顯示一個取不到值的區塊更糟
func (h *AuditCheckpointHandler) SetAutoVerifyStatus(r chainAutoVerifyStatusReader) {
	h.autoVerify = r
}

// checkpointItem 列表項：只曝露已在 DB 且非機密的欄位（簽章本身是公開可驗的）
type checkpointItem struct {
	model.AuditCheckpoint
}

// List 檢查點列表（seq 倒序、分頁、含 anchor 與 purged 狀態）
func (h *AuditCheckpointHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > checkpointListMaxPageSize {
		pageSize = 20
	}
	rows, total, err := h.verifier.List((page-1)*pageSize, pageSize)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalCheckpointQuery, err)
		return
	}
	items := make([]checkpointItem, 0, len(rows))
	for _, r := range rows {
		items = append(items, checkpointItem{AuditCheckpoint: r})
	}
	c.JSON(http.StatusOK, gin.H{"data": gin.H{"items": items, "total": total}})
}

// Verify 兩層驗證（8.1／8.2）。
//
// 結構層恆執行（只讀 audit_checkpoints，萬級列廉價）；內容層**必須帶範圍**，
// 未帶即回 4xx 機器碼而不啟動任何 audit_logs 掃描。範圍可用
// `seq_from`／`seq_to`，或 `from`／`to`（YYYY-MM-DD，經近似時間映射轉 seq）
func (h *AuditCheckpointHandler) Verify(c *gin.Context) {
	chain, err := h.verifier.VerifyChain()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalCheckpointVerify, err)
		return
	}
	// 自動驗證的營運狀態：**讀不到不擋主流程**——結構層報告本身是這個端點的
	// 職責，一張營運狀態表讀不到不該讓整頁失去鏈健康總覽。讀取失敗只留 log，
	// 回應中該欄缺席，頁面顯示為狀態無法取得
	if h.autoVerify != nil {
		if st, err := h.autoVerify.Status(); err != nil {
			log.Printf("[AuditCheckpoint] 讀取自動驗證狀態失敗: %v", err)
		} else {
			chain.AutoVerify = st
		}
	}
	resp := gin.H{"chain": chain}

	wantContent := c.Query("content") == "true" || c.Query("seq_from") != "" ||
		c.Query("seq_to") != "" || c.Query("from") != "" || c.Query("to") != ""
	if !wantContent {
		c.JSON(http.StatusOK, gin.H{"data": resp})
		return
	}

	seqFrom, seqTo, ok := h.contentRange(c)
	if !ok {
		return // contentRange 已回應錯誤
	}
	if seqFrom == 0 && seqTo == 0 {
		// 時間範圍映射不到任何檢查點：回空內容層結果。
		// **不得退化成全鏈**——把空範圍放大成全歷史正是本閘要擋的事
		resp["content"] = gin.H{"seq_from": 0, "seq_to": 0,
			"intervals": []any{}, "status_counts": gin.H{}}
		c.JSON(http.StatusOK, gin.H{"data": resp})
		return
	}
	content, err := h.verifier.VerifyContentBySeq(seqFrom, seqTo)
	if err != nil {
		if errors.Is(err, audit.ErrCheckpointRangeRequired) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeCheckpointRangeRequired, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalCheckpointVerify, err)
		return
	}
	resp["content"] = content
	c.JSON(http.StatusOK, gin.H{"data": resp})
}

// contentRange 解析內容層範圍；回 (from, to, ok)。ok=false 時已回應錯誤。
//
// seq 與日期兩種形態擇一，seq 優先。兩者皆缺＝拒絕（8.2）
func (h *AuditCheckpointHandler) contentRange(c *gin.Context) (uint, uint, bool) {
	rawFrom, rawTo := c.Query("seq_from"), c.Query("seq_to")
	if rawFrom != "" || rawTo != "" {
		from, errFrom := strconv.ParseUint(rawFrom, 10, 32)
		to, errTo := strconv.ParseUint(rawTo, 10, 32)
		if errFrom != nil || errTo != nil || from == 0 || to == 0 || from > to {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeCheckpointRangeFormat, nil)
			return 0, 0, false
		}
		return uint(from), uint(to), true
	}

	rawDateFrom, rawDateTo := c.Query("from"), c.Query("to")
	if rawDateFrom == "" || rawDateTo == "" {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeCheckpointRangeRequired, nil)
		return 0, 0, false
	}
	from, errFrom := time.ParseInLocation("2006-01-02", rawDateFrom, time.Local)
	to, errTo := time.ParseInLocation("2006-01-02", rawDateTo, time.Local)
	if errFrom != nil || errTo != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeCheckpointRangeFormat, nil)
		return 0, 0, false
	}
	to = to.AddDate(0, 0, 1) // 含當日
	if !to.After(from) {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeCheckpointRangeFormat, nil)
		return 0, 0, false
	}
	seqFrom, seqTo, err := h.verifier.SeqRangeByTime(from, to)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalCheckpointVerify, err)
		return 0, 0, false
	}
	return seqFrom, seqTo, true
}

// PublicKey 檢查點簽章公鑰（Ed25519 base64）＋版本＋指紋，供離線驗章。
//
// 與匯出簽章公鑰端點同形；**只出公鑰**——私鑰無任何匯出、下載或刪除路徑
func (h *AuditCheckpointHandler) PublicKey(c *gin.Context) {
	if h.signing == nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalCheckpointQuery,
			errors.New("檢查點簽章服務未注入"))
		return
	}
	version := h.signing.ActiveVersion()
	fingerprint, _ := h.signing.PublicKeyFingerprint(version)
	c.JSON(http.StatusOK, gin.H{"data": gin.H{
		"algorithm":   "Ed25519",
		"version":     version,
		"public_key":  h.signing.ActivePublicKeyBase64(),
		"fingerprint": fingerprint,
	}})
}

// RegisterRoutes 註冊檢查點路由。
//
// **admin 或 auditor**（見 spec「檢查點驗證的角色邊界」）：auditor 是出具
// 證明的人，若只能證序列而內容真偽仍須請 admin 代驗，「被監督者代為出具
// 監督證明」的角色錯配只解一半。授權走 RequireAnyRole 中間件而非 handler
// 內檢查——路由 golden 逐格記錄中間件鏈，寫在鏈上才是可被守衛觀察的事實
func (h *AuditCheckpointHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	g := r.Group("/audit-checkpoints")
	g.Use(middleware.AuthMiddleware(authService))
	g.Use(middleware.RequireAnyRole(model.RoleAdmin, model.RoleAuditor))
	{
		g.GET("", h.List)
		g.GET("/verify", h.Verify)
		g.GET("/public-key", h.PublicKey)
	}
}
