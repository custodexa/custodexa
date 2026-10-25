package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/internal/offsite"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/mock"
)

// `GET /sessions/:id` 帶錄影可讀狀態；列表與活動連線不帶、不探測。

// countingProber 計數替身：證明列表類端點完全沒有呼叫探測。
type countingProber struct {
	calls int
	probe session.RecordingProbe
	ok    bool
}

func (p *countingProber) ProbeRecordingState(*model.Session) (session.RecordingProbe, bool) {
	p.calls++
	return p.probe, p.ok
}

// failingLedger 離機面：帳冊查詢失敗；Fetch 計數（必須為 0）。
type failingLedger struct{ fetchCalls int }

func (f *failingLedger) Object(uint) (*model.OffsiteObject, error) {
	return nil, errors.New("ledger unavailable")
}

func (f *failingLedger) Fetch(context.Context, uint) (*offsite.FetchedObject, error) {
	f.fetchCalls++
	return nil, errors.New("不得取回")
}

// sessionDetailRouter 經真的 RegisterRoutes（真 AuthMiddleware＋session:view 閘）。
func sessionDetailRouter(t *testing.T, sessions []model.Session, prober RecordingStateProber) (*gin.Engine, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db := installEpochGateDB(t, 1)
	// 角色以資料庫為準（AuthMiddleware 不信任 token 的 role claim）
	grantLegacyRole(t, db, 1, model.RoleAuditor)
	jwtSecret := "recording-state-secret"
	svc := new(MockSessionService)
	for i := range sessions {
		svc.On("GetByID", sessions[i].ID).Return(&sessions[i], nil).Maybe()
	}
	svc.On("List", mock.Anything).Return(&session.SessionListResponse{Data: sessions, Total: int64(len(sessions))}, nil).Maybe()
	svc.On("GetActiveSessions").Return(sessions, nil).Maybe()

	h := NewSessionHandler(svc)
	if prober != nil {
		h.SetRecordingProbe(prober)
	}
	r := gin.New()
	h.RegisterRoutes(r.Group("/api/v1"), identity.NewAuthService(jwtSecret, time.Minute))

	// 角色表中沒有「只有 session:view」的角色；auditor 是詳情頁的實際讀者。
	// 詳情路由只掛 session:view 閘（RegisterRoutes），本測試證明該閘之後即帶欄位，
	// 不經任何 audit:view 檢查
	token, err := crypto.NewJWTManager(jwtSecret, time.Minute).
		GenerateToken(1, "auditor", "a@example.com", "auditor", crypto.AuthContext{})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	return r, token
}

func decodeObject(t *testing.T, body string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("回應應為 JSON 物件: %v（%s）", err, body)
	}
	return m
}

// TestSessionDetailCarriesRecordingState 真的錄影服務：可讀帶 available＋local，
// 讀不到帶 unreadable 且無 source；仍保留原有欄位（has_recording 等）。
func TestSessionDetailCarriesRecordingState(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "session-1.cast")
	if err := os.WriteFile(good, []byte("body"), 0o600); err != nil {
		t.Fatal(err)
	}
	asDir := filepath.Join(dir, "session-2.cast")
	if err := os.Mkdir(asDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sessions := []model.Session{
		{ID: 1, HasRecording: true, RecordingPath: good},
		{ID: 2, HasRecording: true, RecordingPath: asDir},
		{ID: 3, HasRecording: false},
	}
	r, token := sessionDetailRouter(t, sessions, session.NewRecordingService(dir))

	w := getWithToken(t, r, "/api/v1/sessions/1", token)
	if w.Code != http.StatusOK {
		t.Fatalf("詳情應 200，實得 %d", w.Code)
	}
	m := decodeObject(t, w.Body.String())
	if m["recording_state"] != "available" || m["recording_source"] != "local" {
		t.Errorf("可讀應帶 available／local，實得 %v／%v", m["recording_state"], m["recording_source"])
	}
	if m["has_recording"] != true || m["id"] == nil {
		t.Errorf("既有欄位應保留，實得 %v", m)
	}

	m = decodeObject(t, getWithToken(t, r, "/api/v1/sessions/2", token).Body.String())
	if m["recording_state"] != "unreadable" {
		t.Errorf("路徑為目錄應帶 unreadable，實得 %v", m["recording_state"])
	}
	if _, has := m["recording_source"]; has {
		t.Errorf("讀不到時不帶 recording_source，實得 %v", m["recording_source"])
	}

	// has_recording=false：兩欄皆缺席
	m = decodeObject(t, getWithToken(t, r, "/api/v1/sessions/3", token).Body.String())
	for _, k := range []string{"recording_state", "recording_source"} {
		if _, has := m[k]; has {
			t.Errorf("無錄影的會話不帶 %s", k)
		}
	}
}

// TestSessionDetailProbeInconclusiveOmitsFields 帳冊查詢失敗（無法下結論）：
// 詳情照常 200、兩欄缺席，且未觸發離機取回。
func TestSessionDetailProbeInconclusiveOmitsFields(t *testing.T) {
	dir := t.TempDir()
	objID := uint(9)
	sessions := []model.Session{{ID: 1, HasRecording: true,
		RecordingPath: filepath.Join(dir, "gone.cast"), OffsiteObjectID: &objID}}
	ledger := &failingLedger{}
	svc := session.NewRecordingService(dir)
	svc.SetOffsiteRetriever(ledger)
	r, token := sessionDetailRouter(t, sessions, svc)

	w := getWithToken(t, r, "/api/v1/sessions/1", token)
	if w.Code != http.StatusOK {
		t.Fatalf("探測無法下結論時詳情仍應 200，實得 %d", w.Code)
	}
	m := decodeObject(t, w.Body.String())
	for _, k := range []string{"recording_state", "recording_source"} {
		if _, has := m[k]; has {
			t.Errorf("無法下結論時不帶 %s，實得 %v", k, m[k])
		}
	}
	if ledger.fetchCalls != 0 {
		t.Errorf("詳情探測不得觸發離機取回，Fetch 被呼叫 %d 次", ledger.fetchCalls)
	}
}

// TestSessionListEndpointsNeverProbe 列表與活動連線：探測呼叫數為 0，回應不含欄位。
func TestSessionListEndpointsNeverProbe(t *testing.T) {
	sessions := []model.Session{
		{ID: 1, HasRecording: true, RecordingPath: "/nonexistent/a.cast"},
		{ID: 2, HasRecording: true, RecordingPath: "/nonexistent/b.cast"},
		{ID: 3, HasRecording: true, RecordingPath: "/nonexistent/c.cast"},
	}
	prober := &countingProber{probe: session.RecordingProbe{State: "missing"}, ok: true}
	r, token := sessionDetailRouter(t, sessions, prober)

	for _, path := range []string{"/api/v1/sessions", "/api/v1/sessions/active"} {
		w := getWithToken(t, r, path, token)
		if w.Code != http.StatusOK {
			t.Fatalf("%s 應 200，實得 %d", path, w.Code)
		}
		if strings.Contains(w.Body.String(), "recording_state") {
			t.Errorf("%s 回應不得含 recording_state", path)
		}
	}
	if prober.calls != 0 {
		t.Fatalf("列表類端點不得呼叫探測，實得 %d 次", prober.calls)
	}

	// 對照：詳情確實會呼叫（證明替身有接上，上面的 0 不是假綠）
	getWithToken(t, r, "/api/v1/sessions/1", token)
	if prober.calls != 1 {
		t.Fatalf("詳情應呼叫探測 1 次，實得 %d", prober.calls)
	}
}
