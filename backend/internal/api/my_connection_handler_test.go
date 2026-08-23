package api

import (
	"encoding/json"
	"fmt"
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// fakeConnRegistry 記錄 Close 呼叫，驗證自助終止有實斷 WS
type fakeConnRegistry struct{ closed []uint }

func (f *fakeConnRegistry) Close(sessionID uint) error {
	f.closed = append(f.closed, sessionID)
	return nil
}

// setupMyConnectionEnv 真 sqlite＋真 JWT 經完整 RegisterRoutes 的整合環境：
// 自助端點的越權面（owner 固定、參數操縱免疫、欄位最小化）必須端到端鎖定
func setupMyConnectionEnv(t *testing.T) (*gin.Engine, *crypto.JWTManager, *gorm.DB, *fakeConnRegistry) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	// AuditLog 一併遷移：Asset 的 AfterCreate 審計 hook 會寫 audit_logs
	if err := db.AutoMigrate(&model.User{}, &model.Asset{}, &model.Session{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	// 建立測試中被簽發 token 的使用者：認證中介層的憑證世代閘會現查使用者
	// 查無即拒——已軟刪帳號的既簽 token 因此立即失效。
	// 測試本就宣稱這些使用者存在（session 掛在其名下），此處補齊事實
	for _, id := range []uint{1, 2, 3} {
		u := model.User{
			Username:           fmt.Sprintf("myconn-u%d", id),
			Password:           "x",
			Active:             true,
			ProvisioningOrigin: model.AuthSourceLocal,
		}
		u.ID = id
		if err := db.Create(&u).Error; err != nil {
			t.Fatalf("seed user %d: %v", id, err)
		}
	}

	gin.SetMode(gin.TestMode)
	jwtSecret := "my-conn-test-secret"
	authService := identity.NewAuthService(jwtSecret, time.Minute)

	registry := &fakeConnRegistry{}
	r := gin.New()
	NewMyConnectionHandler(session.NewMyConnectionService(session.NewSessionService(registry))).
		RegisterRoutes(r.Group("/api/v1"), authService)

	return r, crypto.NewJWTManager(jwtSecret, time.Minute), db, registry
}

func seedMyConnSession(t *testing.T, db *gorm.DB, userID uint, assetID *uint, status model.SessionStatus, start time.Time, duration int) *model.Session {
	t.Helper()
	sess := &model.Session{
		SessionID: time.Now().Format("20060102150405.000000000") + "-" + string(rune('a'+userID)) + start.Format("150405.000000000"),
		Status:    status,
		Protocol:  model.ProtocolSSH,
		UserID:    userID,
		AssetID:   assetID,
		ClientIP:  "10.0.0.99",
		StartTime: start,
		Duration:  duration,
	}
	if status != model.SessionStatusActive {
		end := start.Add(time.Duration(duration) * time.Second)
		sess.EndTime = &end
		sess.RecordingPath = "/recordings/secret.cast"
		sess.HasRecording = true
	}
	if err := db.Create(sess).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}
	return sess
}

func getMyConnections(t *testing.T, r *gin.Engine, mgr *crypto.JWTManager, userID uint, query string) (*httptest.ResponseRecorder, *session.MyConnectionListResponse) {
	t.Helper()
	token, err := mgr.GenerateToken(userID, "u", "u@example.com", "user", crypto.AuthContext{})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/my/connections"+query, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var resp session.MyConnectionListResponse
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v body=%s", err, w.Body.String())
		}
	}
	return w, &resp
}

// TestMyConnections_OnlyOwnSessions 只回自己的 session，且 ?user_id= 被忽略
func TestMyConnections_OnlyOwnSessions(t *testing.T) {
	r, mgr, db, _ := setupMyConnectionEnv(t)

	asset := &model.Asset{Name: "web-server", Protocol: model.ProtocolSSH, Host: "10.0.0.1", Port: 22}
	if err := db.Create(asset).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	now := time.Now()
	seedMyConnSession(t, db, 2, &asset.ID, model.SessionStatusClosed, now.Add(-2*time.Hour), 300)
	seedMyConnSession(t, db, 2, &asset.ID, model.SessionStatusActive, now.Add(-10*time.Minute), 0)
	// 他人（user 1 = admin）的 session 不得出現
	seedMyConnSession(t, db, 1, &asset.ID, model.SessionStatusClosed, now.Add(-1*time.Hour), 60)

	w, resp := getMyConnections(t, r, mgr, 2, "")
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d body = %s", w.Code, w.Body.String())
	}
	if resp.Total != 2 || len(resp.Data) != 2 {
		t.Fatalf("total = %d, len = %d, want 2/2（不得含他人 session）", resp.Total, len(resp.Data))
	}

	// 附 ?user_id=1 仍只回自己的（參數操縱免疫）
	w, resp = getMyConnections(t, r, mgr, 2, "?user_id=1")
	if w.Code != http.StatusOK || resp.Total != 2 {
		t.Fatalf("?user_id=1 應被忽略：code = %d total = %d, want 200/2", w.Code, resp.Total)
	}
}

// TestMyConnections_MinimalFieldsOnly 回應僅含契約五欄位，
// 不存在指令/錄影/IP/主機/K8s 等任何敏感鍵（資料面最小化）
func TestMyConnections_MinimalFieldsOnly(t *testing.T) {
	r, mgr, db, _ := setupMyConnectionEnv(t)

	asset := &model.Asset{Name: "db-server", Protocol: model.ProtocolSSH, Host: "10.0.0.2", Port: 22}
	if err := db.Create(asset).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	seedMyConnSession(t, db, 2, &asset.ID, model.SessionStatusClosed, time.Now().Add(-time.Hour), 120)

	w, _ := getMyConnections(t, r, mgr, 2, "")
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}

	var raw struct {
		Data []map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	if len(raw.Data) != 1 {
		t.Fatalf("len = %d, want 1", len(raw.Data))
	}

	allowed := map[string]bool{
		"id": true, "asset_name": true, "protocol": true, "connected_at": true,
		"duration_seconds": true, "status": true,
	}
	for key := range raw.Data[0] {
		if !allowed[key] {
			t.Errorf("回應含契約外欄位 %q（欄位面即洩漏面）", key)
		}
	}
	for _, required := range []string{"id", "asset_name", "protocol", "connected_at", "duration_seconds", "status"} {
		if _, ok := raw.Data[0][required]; !ok {
			t.Errorf("缺少契約欄位 %q", required)
		}
	}
}

// TestMyConnections_PageSizeClamped page_size 超過 100 夾為 100
func TestMyConnections_PageSizeClamped(t *testing.T) {
	r, mgr, _, _ := setupMyConnectionEnv(t)

	w, resp := getMyConnections(t, r, mgr, 2, "?page_size=500")
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	if resp.PageSize != 100 {
		t.Errorf("page_size = %d, want 100", resp.PageSize)
	}
}

// TestMyConnections_DurationContract 時長契約：
// ended 用持久化 Duration、active 用 floor(now-StartTime)、時鐘異常不回負值、
// connected_at＝StartTime
func TestMyConnections_DurationContract(t *testing.T) {
	r, mgr, db, _ := setupMyConnectionEnv(t)

	now := time.Now()
	start := now.Add(-30 * time.Minute).Truncate(time.Second)
	seedMyConnSession(t, db, 2, nil, model.SessionStatusClosed, start, 777)
	seedMyConnSession(t, db, 2, nil, model.SessionStatusActive, now.Add(-5*time.Minute), 0)
	// 時鐘異常：StartTime 在未來的 active session，時長須夾 0
	seedMyConnSession(t, db, 2, nil, model.SessionStatusActive, now.Add(time.Hour), 0)
	// disconnected 也歸 ended
	seedMyConnSession(t, db, 2, nil, model.SessionStatusDisconnected, start.Add(-time.Hour), 42)

	w, resp := getMyConnections(t, r, mgr, 2, "")
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	if len(resp.Data) != 4 {
		t.Fatalf("len = %d, want 4", len(resp.Data))
	}

	byStatus := map[string]int{}
	for _, item := range resp.Data {
		byStatus[item.Status]++
		if item.DurationSeconds < 0 {
			t.Errorf("duration_seconds = %d 不得為負", item.DurationSeconds)
		}
		if item.Status != "active" && item.Status != "ended" {
			t.Errorf("status = %q, want 機器值 active/ended", item.Status)
		}
	}
	if byStatus["active"] != 2 || byStatus["ended"] != 2 {
		t.Errorf("狀態分布 = %v, want active:2 ended:2（disconnected/closed 歸 ended）", byStatus)
	}

	// 排序 start_time DESC：未來的 active 排最前、其 duration 夾 0
	if resp.Data[0].Status != "active" || resp.Data[0].DurationSeconds != 0 {
		t.Errorf("未來 StartTime 的 active：status=%q duration=%d, want active/0",
			resp.Data[0].Status, resp.Data[0].DurationSeconds)
	}

	// ended 的持久化 Duration 與 connected_at=StartTime
	foundEnded := false
	for _, item := range resp.Data {
		if item.Status == "ended" && item.DurationSeconds == 777 {
			foundEnded = true
			if !item.ConnectedAt.Truncate(time.Second).Equal(start) {
				t.Errorf("connected_at = %v, want StartTime %v", item.ConnectedAt, start)
			}
		}
	}
	if !foundEnded {
		t.Error("找不到 duration=777 的 ended 紀錄（應用持久化 Duration）")
	}
}

// TestMyConnections_ExtremePageNoOverflow 極端 page 值不因 int 溢位回錯頁：
// 超出總數的頁回空 data，total 照實
func TestMyConnections_ExtremePageNoOverflow(t *testing.T) {
	r, mgr, db, _ := setupMyConnectionEnv(t)

	seedMyConnSession(t, db, 2, nil, model.SessionStatusClosed, time.Now().Add(-time.Hour), 60)

	// page=math.MaxInt64：(page-1)*pageSize 以 int 計算會溢位
	w, resp := getMyConnections(t, r, mgr, 2, "?page=9223372036854775807&page_size=20")
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d body = %s", w.Code, w.Body.String())
	}
	if len(resp.Data) != 0 {
		t.Errorf("超界頁 data 長度 = %d, want 0（不得因溢位回第一頁）", len(resp.Data))
	}
	if resp.Total != 1 {
		t.Errorf("total = %d, want 1（總數照實回）", resp.Total)
	}
}

// TestMyConnections_NegativePersistedDurationClamped 已結束列的持久化負 Duration 夾 0
func TestMyConnections_NegativePersistedDurationClamped(t *testing.T) {
	r, mgr, db, _ := setupMyConnectionEnv(t)

	// 直接插入負 Duration 的 ended 列（模擬 legacy/損毀資料）
	sess := &model.Session{
		SessionID: "sess-neg-dur",
		Status:    model.SessionStatusClosed,
		Protocol:  model.ProtocolSSH,
		UserID:    2,
		ClientIP:  "10.0.0.99",
		StartTime: time.Now().Add(-time.Hour),
		Duration:  -500,
	}
	if err := db.Create(sess).Error; err != nil {
		t.Fatalf("seed negative-duration session: %v", err)
	}

	w, resp := getMyConnections(t, r, mgr, 2, "")
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	if len(resp.Data) != 1 {
		t.Fatalf("len = %d, want 1", len(resp.Data))
	}
	if resp.Data[0].DurationSeconds != 0 {
		t.Errorf("負持久化 Duration 應夾 0, got %d", resp.Data[0].DurationSeconds)
	}
}

// TestMyConnections_Unauthenticated 無 token 401
func TestMyConnections_Unauthenticated(t *testing.T) {
	r, _, _, _ := setupMyConnectionEnv(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/my/connections", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", w.Code)
	}
}

func postTerminate(t *testing.T, r *gin.Engine, mgr *crypto.JWTManager, userID uint, connID string) *httptest.ResponseRecorder {
	t.Helper()
	token, err := mgr.GenerateToken(userID, "u", "u@example.com", "user", crypto.AuthContext{})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/my/connections/"+connID+"/terminate", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// TestMyConnections_TerminateOwnActive 終止自己的 active：狀態收斂、end_reason、實斷 WS
func TestMyConnections_TerminateOwnActive(t *testing.T) {
	r, mgr, db, registry := setupMyConnectionEnv(t)

	sess := seedMyConnSession(t, db, 2, nil, model.SessionStatusActive, time.Now().Add(-10*time.Minute), 0)

	w := postTerminate(t, r, mgr, 2, fmt.Sprintf("%d", sess.ID))
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d body = %s", w.Code, w.Body.String())
	}

	var got model.Session
	if err := db.First(&got, sess.ID).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.Status != model.SessionStatusDisconnected {
		t.Errorf("status = %s, want disconnected", got.Status)
	}
	if got.EndReason != model.EndReasonUserTerminate {
		t.Errorf("end_reason = %s, want user_terminate", got.EndReason)
	}
	if got.EndTime == nil {
		t.Errorf("end_time 應被寫入")
	}
	if len(registry.closed) != 1 || registry.closed[0] != sess.ID {
		t.Errorf("registry.Close 應收到 %d, got %v（未實斷 WS）", sess.ID, registry.closed)
	}
}

// TestMyConnections_TerminateOthersIndistinguishable 他人的與不存在的一律 404 無可區分
func TestMyConnections_TerminateOthersIndistinguishable(t *testing.T) {
	r, mgr, db, registry := setupMyConnectionEnv(t)

	other := seedMyConnSession(t, db, 1, nil, model.SessionStatusActive, time.Now().Add(-10*time.Minute), 0)

	wOther := postTerminate(t, r, mgr, 2, fmt.Sprintf("%d", other.ID))
	wMissing := postTerminate(t, r, mgr, 2, "99999")
	if wOther.Code != http.StatusNotFound || wMissing.Code != http.StatusNotFound {
		t.Fatalf("codes = %d/%d, want 404/404", wOther.Code, wMissing.Code)
	}
	if wOther.Body.String() != wMissing.Body.String() {
		t.Errorf("他人與不存在的回應應無可區分：%s vs %s", wOther.Body.String(), wMissing.Body.String())
	}

	var got model.Session
	if err := db.First(&got, other.ID).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.Status != model.SessionStatusActive {
		t.Errorf("他人 session 不得被影響：status = %s", got.Status)
	}
	if len(registry.closed) != 0 {
		t.Errorf("不得對他人 session 實斷：closed = %v", registry.closed)
	}
}

// TestMyConnections_TerminateEnded 非 active 回 400
func TestMyConnections_TerminateEnded(t *testing.T) {
	r, mgr, db, registry := setupMyConnectionEnv(t)

	sess := seedMyConnSession(t, db, 2, nil, model.SessionStatusClosed, time.Now().Add(-time.Hour), 60)

	w := postTerminate(t, r, mgr, 2, fmt.Sprintf("%d", sess.ID))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", w.Code)
	}
	if len(registry.closed) != 0 {
		t.Errorf("已結束的連線不得觸發實斷：closed = %v", registry.closed)
	}
}

// TestMyConnections_TerminateOwnerCheckIsTheOnlyGate 自助終止的授權由 owner 檢查
// 單獨承擔，與 RBAC 無關：他人的 session 一律 404（不洩漏存在性）。
//
// 原以 `FEATURE_PERMISSION_CHECK_ENABLED=false` 為前提，證明「旗標關閉也不放行」；
// 該旗標已退場，前提不復存在。契約本身不變，
// 故保留斷言、移除已無對象的環境變數設定
func TestMyConnections_TerminateOwnerCheckIsTheOnlyGate(t *testing.T) {
	r, mgr, db, _ := setupMyConnectionEnv(t)

	other := seedMyConnSession(t, db, 1, nil, model.SessionStatusActive, time.Now().Add(-10*time.Minute), 0)

	if w := postTerminate(t, r, mgr, 2, fmt.Sprintf("%d", other.ID)); w.Code != http.StatusNotFound {
		t.Errorf("他人 session 應 404（owner 檢查即授權）, got %d", w.Code)
	}
}

// TestMyConnections_TerminateUnauthenticated 無 token 401
func TestMyConnections_TerminateUnauthenticated(t *testing.T) {
	r, _, _, _ := setupMyConnectionEnv(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/my/connections/1/terminate", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", w.Code)
	}
}
