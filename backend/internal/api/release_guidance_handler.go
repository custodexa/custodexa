package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
)

// 版本說明的三條讀寫面：
//   - GET／PUT /auth/me/release-guidance/:version：本人的關閉狀態（owner/self）。
//     主體只取自認證結果，路徑上沒有使用者識別，請求本文只接受 {"dismissed": true}。
//   - GET /dashboard/retention-adjustments：升級時保留天數調整的告知（安全政策讀取能力）。
//     不放進上面的本人狀態，因為那條對所有登入者開放。

// guidanceStateStore 本人關閉狀態的讀寫面（identity.ReleaseGuidanceService 實作）。
type guidanceStateStore interface {
	Dismissed(userID uint, version string) (bool, error)
	Dismiss(op identity.Operator, version string) error
}

// retentionFloorReporter 保留下限抬升紀錄與未涵蓋關係的唯讀介面（policy 模組實作）。
type retentionFloorReporter interface {
	RetentionFloorReport() (policy.FloorReport, error)
}

// ReleaseGuidanceHandler 版本說明相關端點。
type ReleaseGuidanceHandler struct {
	state    guidanceStateStore
	retained retentionFloorReporter
}

// NewReleaseGuidanceHandler 建構 handler。任何依賴缺少即回錯，不建出請求時才回空清單的 handler。
func NewReleaseGuidanceHandler(state guidanceStateStore, reporter retentionFloorReporter) (*ReleaseGuidanceHandler, error) {
	if guidanceDepMissing(state) || guidanceDepMissing(reporter) {
		return nil, identity.ErrGuidanceNotWired
	}
	return &ReleaseGuidanceHandler{state: state, retained: reporter}, nil
}

// guidanceDepMissing 依賴為 nil 或持有 nil 指標（具型別的 nil 存入介面不等於 nil 介面）。
func guidanceDepMissing(dep any) bool {
	if dep == nil {
		return true
	}
	v := reflect.ValueOf(dep)
	return v.Kind() == reflect.Ptr && v.IsNil()
}

// RegisterRoutes 註冊版本說明路由。
func (h *ReleaseGuidanceHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	// 本人關閉狀態：agent token 一律拒絕（owner/self 不代表 agent 可進）
	me := r.Group("/auth/me/release-guidance")
	me.Use(middleware.RejectAgentTokenOnHumanPaths(), middleware.AuthMiddleware(authService), middleware.EnforceRegistry())
	{
		me.GET("/:version", h.GetState)
		me.PUT("/:version", h.PutState)
	}

	dashboard := r.Group("/dashboard")
	dashboard.Use(middleware.AuthMiddleware(authService), middleware.EnforceRegistry())
	{
		dashboard.GET("/retention-adjustments", h.RetentionAdjustments)
	}
}

// guidanceStateResponse 本人關閉狀態。
type guidanceStateResponse struct {
	NoticeVersion string `json:"notice_version"`
	Dismissed     bool   `json:"dismissed"`
}

// GetState 讀取本人對該說明版本的關閉狀態；無列回 false，不寫庫。
func (h *ReleaseGuidanceHandler) GetState(c *gin.Context) {
	userID, ok := middleware.GetCurrentUserID(c)
	if !ok {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return
	}
	version := c.Param("version")
	if !identity.IsKnownGuidanceVersion(version) {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	dismissed, err := h.state.Dismissed(userID, version)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalUserInfoQuery, err)
		return
	}
	c.JSON(http.StatusOK, guidanceStateResponse{NoticeVersion: version, Dismissed: dismissed})
}

// PutState 關閉該說明版本（冪等）。本文只接受 {"dismissed": true}。
func (h *ReleaseGuidanceHandler) PutState(c *gin.Context) {
	userID, ok := middleware.GetCurrentUserID(c)
	if !ok {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return
	}
	// 審計歸類覆寫：與自助更新個人資料同一處理，歸 resource=user、resource_id=本人
	c.Set("audit_resource", model.ResourceUser)
	c.Set("audit_resource_id", userID)

	version := c.Param("version")
	if !identity.IsKnownGuidanceVersion(version) {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	if !decodeDismissBody(c) {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}

	op := operatorFromRequest(c)
	if err := h.state.Dismiss(op, version); err != nil {
		switch {
		case errors.Is(err, identity.ErrUnknownGuidanceVersion):
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		case errors.Is(err, identity.ErrUserInactive):
			apierror.Respond(c, http.StatusForbidden, apierror.CodeUserInactive, nil)
		case errors.Is(err, identity.ErrUserNotFound):
			apierror.Respond(c, http.StatusUnauthorized, apierror.CodeSessionExpired, nil)
		default:
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalUserUpdate, err)
		}
		return
	}
	c.JSON(http.StatusOK, guidanceStateResponse{NoticeVersion: version, Dismissed: true})
}

// decodeDismissBody 嚴格解析本文：恰好一個物件、只有 dismissed 欄位且值為 true。
func decodeDismissBody(c *gin.Context) bool {
	raw, err := io.ReadAll(io.LimitReader(c.Request.Body, 1025))
	if err != nil || len(raw) > 1024 {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var body struct {
		Dismissed *bool `json:"dismissed"`
	}
	if err := dec.Decode(&body); err != nil {
		return false
	}
	if dec.More() {
		return false
	}
	// 解完後不得有第二個 JSON 值
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return false
	}
	return body.Dismissed != nil && *body.Dismissed
}

// retentionNoticeItem 一個被抬升的保留鍵（升級時的調整紀錄，不是目前設定值）。
type retentionNoticeItem struct {
	Key      string    `json:"key"`
	OldDays  int       `json:"old_days"`
	NewDays  int       `json:"new_days"`
	Reason   string    `json:"reason"`
	RaisedAt time.Time `json:"raised_at"`
}

// retentionNoticeUncovered 目前未被檢查點保留涵蓋的資料保留關係（0＝永久）。
type retentionNoticeUncovered struct {
	DataKey        string `json:"data_key"`
	DataDays       int    `json:"data_days"`
	CheckpointDays int    `json:"checkpoint_days"`
}

// retentionNotice 保留調整告知。
type retentionNotice struct {
	NoticeVersion string                     `json:"notice_version"`
	Items         []retentionNoticeItem      `json:"items"`
	Uncovered     []retentionNoticeUncovered `json:"uncovered"`
}

// buildRetentionNotice 把 policy 的唯讀報告轉成端點形狀：字串值轉整數天數，
// 同鍵取 reader 排序（時間、寫入序）的最後一筆並保留其時間。任何一筆無法轉換即整體失敗，
// 不回部分結果。
func buildRetentionNotice(report policy.FloorReport) (retentionNotice, error) {
	latest := make(map[string]int, len(report.Raises))
	for i, r := range report.Raises {
		latest[r.Key] = i
	}
	items := make([]retentionNoticeItem, 0, len(latest))
	for i, r := range report.Raises {
		if latest[r.Key] != i {
			continue
		}
		oldDays, err := strconv.Atoi(r.OldValue)
		if err != nil {
			return retentionNotice{}, fmt.Errorf("抬升紀錄原值無法轉為天數（%s）: %w", r.Key, err)
		}
		newDays, err := strconv.Atoi(r.NewValue)
		if err != nil {
			return retentionNotice{}, fmt.Errorf("抬升紀錄新值無法轉為天數（%s）: %w", r.Key, err)
		}
		items = append(items, retentionNoticeItem{
			Key: r.Key, OldDays: oldDays, NewDays: newDays, Reason: r.Reason,
			RaisedAt: r.RaisedAt,
		})
	}
	uncovered := make([]retentionNoticeUncovered, 0, len(report.Uncovered))
	for _, u := range report.Uncovered {
		uncovered = append(uncovered, retentionNoticeUncovered{
			DataKey: u.Key, DataDays: u.DataDays, CheckpointDays: u.CheckpointDays,
		})
	}
	return retentionNotice{NoticeVersion: identity.ReleaseGuidanceVersion, Items: items, Uncovered: uncovered}, nil
}

// RetentionAdjustments 升級時保留天數調整的告知。
//
// 讀取失敗回既有的政策讀取錯誤碼與非 2xx，回應不含 items／uncovered，也不回部分結果；
// 只有真的沒有紀錄也沒有未涵蓋關係時才是成功的空清單。
func (h *ReleaseGuidanceHandler) RetentionAdjustments(c *gin.Context) {
	report, err := h.retained.RetentionFloorReport()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalComplianceSnapshot, err)
		return
	}
	notice, err := buildRetentionNotice(report)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalComplianceSnapshot, err)
		return
	}
	c.JSON(http.StatusOK, notice)
}
