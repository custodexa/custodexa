package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/robfig/cron/v3"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/identity"
)

// 排程時刻的預覽端點。
//
// **為什麼由後端算**：時區、日曆邊界（每月 31 日、閏年）與解析規則要與排程器
// 實際採用的完全一致，否則表單上寫著一個永遠不會發生的時間，而管理者要到
// 「該跑的沒跑」才會發現。前端因此只顯示、不換算。

// scheduleNextRunsDefaultCount 未指定筆數時回幾筆（選擇器預設呈現三筆）
const scheduleNextRunsDefaultCount = 3

// scheduleNextRunsMaxCount 單次可要求的上限。
//
// 有上限是因為每一筆都要往前推算一次日曆；沒有上限時一個「每年 2 月 29 日」
// 加上一個大數字就能讓單一請求推算數十萬次
const scheduleNextRunsMaxCount = 10

// scheduleCronParser 五欄解析器（分 時 日 月 週）。
//
// 欄位集與排程器載入計劃時所用的完全相同：預覽與實際觸發若各用一套解析，
// 兩者會在邊界形態上分岔，而分岔的方向剛好是「畫面說會跑、實際不跑」
var scheduleCronParser = cron.NewParser(
	cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

// ScheduleHandler 排程時刻預覽（admin）。
//
// 無狀態、無依賴：本端點不讀寫任何資料，只把一個字串解析成接下來的幾個時刻。
type ScheduleHandler struct{}

// NewScheduleHandler 建立排程預覽 handler。
func NewScheduleHandler() *ScheduleHandler { return &ScheduleHandler{} }

// scheduleNextRunsRequest 預覽請求
type scheduleNextRunsRequest struct {
	Cron string `json:"cron"`
	// Count 要幾筆；0（或未給）＝預設值
	Count int `json:"count"`
}

// NextRuns 接下來的執行時刻。
//
// 回應**不包 data 信封**：呼叫端讀的是頂層的 runs 與 timezone。
func (h *ScheduleHandler) NextRuns(c *gin.Context) {
	var req scheduleNextRunsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	count := req.Count
	if count == 0 {
		count = scheduleNextRunsDefaultCount
	}
	if count < 1 || count > scheduleNextRunsMaxCount {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeValidationScheduleRunCount, nil)
		return
	}
	schedule, err := scheduleCronParser.Parse(req.Cron)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeValidationScheduleBadCron, nil)
		return
	}

	// 由現在往後推：時刻以排程器採用的時區呈現，呼叫端原樣顯示
	runs := make([]string, 0, count)
	cursor := time.Now().In(time.Local)
	for i := 0; i < count; i++ {
		cursor = schedule.Next(cursor)
		if cursor.IsZero() {
			// 形狀合法但永遠不會發生（如 2 月 30 日）：回已算出的部分，
			// 呼叫端據此顯示「沒有下次執行」而不是一個假的時刻
			break
		}
		runs = append(runs, cursor.Format(time.RFC3339))
	}
	c.JSON(http.StatusOK, gin.H{"runs": runs, "timezone": time.Local.String()})
}

// RegisterRoutes 註冊排程預覽路由（admin）。
func (h *ScheduleHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	schedules := r.Group("/schedules")
	schedules.Use(middleware.AuthMiddleware(authService))
	schedules.Use(middleware.RequireRole(model.RoleAdmin))
	{
		schedules.POST("/next-runs", h.NextRuns)
	}
}
