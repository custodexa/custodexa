package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/identity"
)

// 單實例守衛的狀態出口。
//
// 兩層出口、兩種資訊量：
//   - 粗狀態走既有 GET /seal/status（不要求 JWT、不寫審計列、供介面每 60 秒輪詢）：
//     只有狀態列舉、起始時間、原因、對等連線數——**不含**持鎖者指紋、確認碼、本實例主機名／pid。
//   - 全貌走本檔的 GET /instance-guard（JWT＋admin）：每次呼叫經審計中介層留一列讀取；
//     介面只在橫幅出現時取一次（與手動重新整理），不輪詢。
//
// 視圖型別定義在本包而非直接回傳 database 的快照：回應形狀是 API 契約，
// 轉換由組裝根的 adapter 承擔，api 層不 import infra 包。

// InstanceGuardStatus 粗狀態（seal status 的 `instance_guard` 欄）。
type InstanceGuardStatus struct {
	// State held／overridden／lost／stopping／released；空字串＝守衛尚未建立
	State string `json:"state"`
	// Since 狀態起始時間（RFC3339）；未知時為空字串
	Since string `json:"since"`
	// Reason ""／ack_startup／contention／db_unreachable／permanent／unknown
	Reason string `json:"reason"`
	// Peers 偵測到的其他守衛版實例連線數
	Peers int `json:"peers"`
}

// InstanceGuardInstance 本實例識別。
type InstanceGuardInstance struct {
	Hostname  string `json:"hostname"`
	PID       int    `json:"pid"`
	StartedAt string `json:"started_at"`
}

// InstanceGuardHolder 持鎖者指紋（可讀三欄＋確認碼＋來源）。
type InstanceGuardHolder struct {
	ApplicationName   string `json:"application_name"`
	PID               int64  `json:"pid"`
	BackendStart      string `json:"backend_start"`
	Code              string `json:"code"`
	FingerprintSource string `json:"fingerprint_source"`
}

// InstanceGuardView 守衛完整快照（管理者限定端點的回應）。
type InstanceGuardView struct {
	State        string                `json:"state"`
	Since        string                `json:"since"`
	Reason       string                `json:"reason"`
	Instance     InstanceGuardInstance `json:"instance"`
	DBSessionPID int                   `json:"db_session_pid"`
	Holder       *InstanceGuardHolder  `json:"holder"`
	Ack          string                `json:"ack"`
	LostTotal    uint64                `json:"lost_total"`
	Peers        int                   `json:"peers"`
}

// Coarse 由全貌取粗狀態：只留不含識別資訊的四欄。
func (v InstanceGuardView) Coarse() InstanceGuardStatus {
	return InstanceGuardStatus{State: v.State, Since: v.Since, Reason: v.Reason, Peers: v.Peers}
}

// InstanceGuardProbe 守衛全貌的現讀函式（由組裝根注入）。
type InstanceGuardProbe func() InstanceGuardView

// InstanceGuardHandler 管理者限定的守衛快照端點。
type InstanceGuardHandler struct {
	probe InstanceGuardProbe
}

// NewInstanceGuardHandler 建立 handler；probe 為 nil 時回零值視圖（僅單測／佔位）。
func NewInstanceGuardHandler(probe InstanceGuardProbe) *InstanceGuardHandler {
	return &InstanceGuardHandler{probe: probe}
}

// RegisterRoutes 註冊 GET /instance-guard（JWT＋admin）。
//
// 授權寫在鏈上而非 handler 內：路由 golden 逐格記錄中間件鏈，「這條路由由誰守」
// 是 golden 可觀察的事實（沿 RequireAnyRole 的說明）。
func (h *InstanceGuardHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	grp := r.Group("/instance-guard")
	grp.Use(middleware.AuthMiddleware(authService))
	grp.Use(middleware.RequireRole("admin"))
	{
		grp.GET("", h.Get)
	}
}

// Get 回傳守衛全貌。唯讀、無副作用；留痕由審計中介層承擔（每次呼叫一列讀取）。
func (h *InstanceGuardHandler) Get(c *gin.Context) {
	var view InstanceGuardView
	if h.probe != nil {
		view = h.probe()
	}
	c.JSON(http.StatusOK, view)
}
