package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/crypto"
)

// guidanceSink 測試用交易內審計落地面：記錄事件；fail 為真時回錯（驗整筆回滾）。
type guidanceSink struct {
	mu     sync.Mutex
	events []port.AuditEvent
	fail   bool
}

func (s *guidanceSink) WriteInTx(_ *gorm.DB, ev port.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("注入審計失敗")
	}
	s.events = append(s.events, ev)
	return nil
}

func (s *guidanceSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

// TestUpgradeGuidanceState 本人版本說明關閉狀態：正式 migration 建表與冪等儲存（schema），
// 以及經真 AuthMiddleware 的本人路由行為（owner）。
func TestUpgradeGuidanceState(t *testing.T) {
	t.Run("schema", func(t *testing.T) {
		db := openEvidencePG(t, "ug_schema")
		oldDB := database.DB
		database.DB = db
		t.Cleanup(func() { database.DB = oldDB })

		require.NoError(t, database.RunMigrations())
		versions := database.MigrationVersions()
		var self, floor, hostKey int
		for _, v := range versions {
			switch v {
			case "20261028_user_release_guidance":
				self++
			case "20261026_security_policy_floor_raises":
				floor++
			case "20261025_host_key_mismatch":
				hostKey++
			}
		}
		assert.Equal(t, []int{1, 1, 1}, []int{self, floor, hostKey}, "三個 migration 版本各出現一次且互異")

		var applied int64
		require.NoError(t, db.Raw(`SELECT count(*) FROM schema_migrations WHERE version = ?`, "20261028_user_release_guidance").Scan(&applied).Error)
		assert.EqualValues(t, 1, applied)

		sink := &guidanceSink{}
		svc, err := identity.NewReleaseGuidanceService(db, sink)
		require.NoError(t, err)

		a := &model.User{Username: "guid-a", Password: "x", Active: true}
		b := &model.User{Username: "guid-b", Password: "x", Active: true}
		require.NoError(t, db.Create(a).Error)
		require.NoError(t, db.Create(b).Error)
		op := identity.Operator{UserID: a.ID, Username: a.Username}

		// 未關閉預設 false，且讀取不寫庫
		got, err := svc.Dismissed(a.ID, identity.ReleaseGuidanceVersion)
		require.NoError(t, err)
		assert.False(t, got)
		var rows int64
		require.NoError(t, db.Model(&model.UserReleaseGuidance{}).Count(&rows).Error)
		assert.Zero(t, rows)

		// 關閉一次、重複關閉冪等：只有一列、只有一筆審計
		require.NoError(t, svc.Dismiss(op, identity.ReleaseGuidanceVersion))
		require.NoError(t, svc.Dismiss(op, identity.ReleaseGuidanceVersion))
		require.NoError(t, db.Model(&model.UserReleaseGuidance{}).Count(&rows).Error)
		assert.EqualValues(t, 1, rows)
		assert.Equal(t, 1, sink.count(), "重複關閉不重複寫審計")
		ev := sink.events[0]
		assert.Equal(t, string(model.ActionUpdate), ev.Action)
		assert.Equal(t, string(model.ResourceUser), ev.Resource)
		var details map[string]any
		require.NoError(t, json.Unmarshal([]byte(ev.Details), &details))
		assert.Equal(t, identity.ReleaseGuidanceVersion, details["notice_version"])
		assert.Equal(t, true, details["dismissed"])
		got, err = svc.Dismissed(a.ID, identity.ReleaseGuidanceVersion)
		require.NoError(t, err)
		assert.True(t, got)
		other, err := svc.Dismissed(b.ID, identity.ReleaseGuidanceVersion)
		require.NoError(t, err)
		assert.False(t, other, "他人狀態不受影響")

		// 相同使用者與說明版本唯一（資料庫層）
		dup := db.Exec(`INSERT INTO user_release_guidance (user_id, notice_version, dismissed_at) VALUES (?, ?, now())`,
			a.ID, identity.ReleaseGuidanceVersion)
		assert.Error(t, dup.Error, "重複的（使用者，說明版本）必須被唯一鍵擋下")

		// 審計失敗：整筆回滾，狀態不變
		sink.fail = true
		err = svc.Dismiss(identity.Operator{UserID: b.ID, Username: b.Username}, identity.ReleaseGuidanceVersion)
		require.Error(t, err)
		sink.fail = false
		other, err = svc.Dismissed(b.ID, identity.ReleaseGuidanceVersion)
		require.NoError(t, err)
		assert.False(t, other, "審計失敗時關閉狀態不得落地")

		// 重跑 migration 不重複建列、不改內容
		require.NoError(t, database.RunMigrations())
		require.NoError(t, db.Model(&model.UserReleaseGuidance{}).Count(&rows).Error)
		assert.EqualValues(t, 1, rows)

		// 外鍵隨帳號刪除
		require.NoError(t, db.Exec(`DELETE FROM users WHERE id = ?`, a.ID).Error)
		require.NoError(t, db.Model(&model.UserReleaseGuidance{}).Count(&rows).Error)
		assert.Zero(t, rows, "帳號刪除後關閉狀態隨之清除")
	})

	t.Run("owner", func(t *testing.T) {
		env := newGuidanceEnv(t)
		a := env.user(t, "guid-owner-a", model.RoleUser)
		b := env.user(t, "guid-owner-b", model.RoleUser)
		tokA1 := env.token(t, a)
		tokB := env.token(t, b)
		path := "/api/v1/auth/me/release-guidance/" + identity.ReleaseGuidanceVersion

		// 未登入拒絕
		assert.Equal(t, http.StatusUnauthorized, env.do(http.MethodGet, path, "", nil).Code)
		assert.Equal(t, http.StatusUnauthorized, env.do(http.MethodPut, path, "", map[string]any{"dismissed": true}).Code)

		// 起始為 false 且不寫庫
		w := env.do(http.MethodGet, path, tokA1, nil)
		require.Equal(t, http.StatusOK, w.Code)
		assert.JSONEq(t, `{"notice_version":"1.18.0","dismissed":false}`, w.Body.String())
		assert.Zero(t, env.rows(t))

		// A 關閉；換會話（重新簽發 token）仍為 true，B 仍為 false
		w = env.do(http.MethodPut, path, tokA1, map[string]any{"dismissed": true})
		require.Equal(t, http.StatusOK, w.Code)
		assert.JSONEq(t, `{"notice_version":"1.18.0","dismissed":true}`, w.Body.String())
		tokA2 := env.token(t, a)
		assert.JSONEq(t, `{"notice_version":"1.18.0","dismissed":true}`, env.do(http.MethodGet, path, tokA2, nil).Body.String())
		assert.JSONEq(t, `{"notice_version":"1.18.0","dismissed":false}`, env.do(http.MethodGet, path, tokB, nil).Body.String())

		// 重開 GET 不重設關閉值；重複 PUT 冪等且不重複審計
		_ = env.do(http.MethodGet, path, tokA2, nil)
		require.Equal(t, http.StatusOK, env.do(http.MethodPut, path, tokA2, map[string]any{"dismissed": true}).Code)
		assert.EqualValues(t, 1, env.rows(t))
		assert.Equal(t, 1, env.sink.count())

		// 輸入他人 ID、未知欄位、非 true、空本文與多餘內容一律拒絕，且 B 不變
		for name, body := range map[string]string{
			"他人 ID":             `{"dismissed":true,"user_id":` + strconv.Itoa(int(b.ID)) + `}`,
			"owner 欄位":          `{"dismissed":true,"owner":"x"}`,
			"版本欄位":              `{"dismissed":true,"notice_version":"1.18.0"}`,
			"dismissed 為 false": `{"dismissed":false}`,
			"缺 dismissed":       `{}`,
			"空本文":               ``,
			"非物件":               `[true]`,
			"字串值":               `{"dismissed":"true"}`,
			"多個 JSON 值":         `{"dismissed":true}{"dismissed":true}`,
		} {
			req := httptest.NewRequest(http.MethodPut, path, bytes.NewBufferString(body))
			req.Header.Set("Authorization", "Bearer "+tokA1)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			env.r.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusBadRequest, rec.Code, name)
		}
		// 查詢字串帶他人 ID 無效：只動認證主體
		w = env.do(http.MethodPut, path+"?user_id="+strconv.Itoa(int(b.ID)), tokA1, map[string]any{"dismissed": true})
		require.Equal(t, http.StatusOK, w.Code)
		assert.JSONEq(t, `{"notice_version":"1.18.0","dismissed":false}`, env.do(http.MethodGet, path, tokB, nil).Body.String())

		// 未知說明版本：讀寫都拒絕，B 不變
		for _, v := range []string{"1.18.1", "9.9.9", "latest", "1.18.0%20"} {
			p := "/api/v1/auth/me/release-guidance/" + v
			assert.Equal(t, http.StatusBadRequest, env.do(http.MethodGet, p, tokA1, nil).Code, v)
			assert.Equal(t, http.StatusBadRequest, env.do(http.MethodPut, p, tokB, map[string]any{"dismissed": true}).Code, v)
		}
		assert.EqualValues(t, 1, env.rows(t), "拒絕的請求不得寫入任何列")

		// 審計失敗：B 的關閉不落地
		env.sink.fail = true
		assert.Equal(t, http.StatusInternalServerError, env.do(http.MethodPut, path, tokB, map[string]any{"dismissed": true}).Code)
		env.sink.fail = false
		assert.JSONEq(t, `{"notice_version":"1.18.0","dismissed":false}`, env.do(http.MethodGet, path, tokB, nil).Body.String())

		// agent 主體對兩條本人路由一律拒絕
		agentTok := identity.AgentTokenPrefix + "0123456789abcdef"
		assert.Equal(t, http.StatusForbidden, env.do(http.MethodGet, path, agentTok, nil).Code)
		assert.Equal(t, http.StatusForbidden, env.do(http.MethodPut, path, agentTok, map[string]any{"dismissed": true}).Code)
		for _, route := range []string{
			"GET /api/v1/auth/me/release-guidance/:version",
			"PUT /api/v1/auth/me/release-guidance/:version",
			"GET /api/v1/dashboard/retention-adjustments",
		} {
			var method, p string
			_, _ = fmt.Sscanf(route, "%s %s", &method, &p)
			allowed, registered := middleware.AgentRouteDecision(method, p)
			assert.False(t, allowed, route)
			assert.True(t, registered, route)
		}
	})
}

// guidanceEnv 經完整 RegisterRoutes（真 AuthMiddleware＋真 JWT＋sqlite）的版本說明環境。
type guidanceEnv struct {
	r    *gin.Engine
	db   *gorm.DB
	mgr  *crypto.JWTManager
	sink *guidanceSink
	svc  *policy.SecurityPolicyService
}

func newGuidanceEnv(t *testing.T) *guidanceEnv {
	return newGuidanceEnvWith(t, nil)
}

// newGuidanceEnvWith reporter 為 nil 時用真的 policy 服務。
func newGuidanceEnvWith(t *testing.T, reporter retentionFloorReporter) *guidanceEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, migrateWithAuthz(db,
		&model.User{}, &model.Role{}, &model.UserGroup{}, &model.Asset{}, &model.AssetGroup{},
		&model.AssetAuthorization{}, &model.ApproverScope{}, &model.AuditLog{}, &model.UserRole{},
		&model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{}, &model.AuthzState{},
		&model.SecurityPolicy{}, &model.SecurityPolicyHistory{}, &model.SecurityPolicyFloorRaise{},
		&model.UserReleaseGuidance{}))
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	sink := &guidanceSink{}
	state, err := identity.NewReleaseGuidanceService(db, sink)
	require.NoError(t, err)
	svc := policy.NewSecurityPolicyService(db)
	var rep retentionFloorReporter = svc
	if reporter != nil {
		rep = reporter
	}
	h, err := NewReleaseGuidanceHandler(state, rep)
	require.NoError(t, err)

	secret := "release-guidance-secret"
	authService := identity.NewAuthService(secret, time.Minute)
	r := gin.New()
	h.RegisterRoutes(r.Group("/api/v1"), authService)
	return &guidanceEnv{r: r, db: db, mgr: crypto.NewJWTManager(secret, time.Minute), sink: sink, svc: svc}
}

func (e *guidanceEnv) user(t *testing.T, name, role string) *model.User {
	t.Helper()
	u := &model.User{Username: name, Password: "x", Active: true, Email: emailPtr(name + "@x")}
	require.NoError(t, e.db.Create(u).Error)
	grantLegacyRole(t, e.db, u.ID, role)
	return u
}

func (e *guidanceEnv) token(t *testing.T, u *model.User) string {
	t.Helper()
	tok, err := e.mgr.GenerateToken(u.ID, u.Username, u.EmailString(), "user", crypto.AuthContext{})
	require.NoError(t, err)
	return tok
}

func (e *guidanceEnv) do(method, path, token string, body any) *httptest.ResponseRecorder {
	var buf *bytes.Buffer
	if body != nil {
		b, _ := json.Marshal(body)
		buf = bytes.NewBuffer(b)
	} else {
		buf = bytes.NewBuffer(nil)
	}
	req := httptest.NewRequest(method, path, buf)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.r.ServeHTTP(w, req)
	return w
}

func (e *guidanceEnv) rows(t *testing.T) int64 {
	t.Helper()
	var n int64
	require.NoError(t, e.db.Model(&model.UserReleaseGuidance{}).Count(&n).Error)
	return n
}

// stubReporter 測試用的 policy 唯讀替身。
type stubReporter struct {
	report policy.FloorReport
	err    error
}

func (s stubReporter) RetentionFloorReport() (policy.FloorReport, error) { return s.report, s.err }

type noopCounter struct{ raises, audits int64 }

func (e *guidanceEnv) writeSideCounts(t *testing.T) noopCounter {
	t.Helper()
	var c noopCounter
	require.NoError(t, e.db.Model(&model.SecurityPolicyFloorRaise{}).Count(&c.raises).Error)
	require.NoError(t, e.db.Model(&model.AuditLog{}).Count(&c.audits).Error)
	return c
}

func seedRetention(t *testing.T, db *gorm.DB, audit, cmd, alert, rec, cp int) {
	t.Helper()
	vals := map[string]int{
		policy.PolicyRetentionAuditLogDays: audit, policy.PolicyRetentionSessionCommandDays: cmd,
		policy.PolicyRetentionAlertDays: alert, policy.PolicyRetentionRecordingDays: rec,
		policy.PolicyRetentionCheckpointDays: cp,
	}
	for k, v := range vals {
		require.NoError(t, db.Save(&model.SecurityPolicy{Key: k, Value: strconv.Itoa(v), UpdatedBy: "legacy"}).Error)
	}
}

type noticeBody struct {
	NoticeVersion string `json:"notice_version"`
	Items         []struct {
		Key      string    `json:"key"`
		OldDays  int       `json:"old_days"`
		NewDays  int       `json:"new_days"`
		Reason   string    `json:"reason"`
		RaisedAt time.Time `json:"raised_at"`
	} `json:"items"`
	Uncovered []struct {
		DataKey        string `json:"data_key"`
		DataDays       int    `json:"data_days"`
		CheckpointDays int    `json:"checkpoint_days"`
	} `json:"uncovered"`
}

func (e *guidanceEnv) notice(t *testing.T, token string) (noticeBody, *httptest.ResponseRecorder) {
	t.Helper()
	w := e.do(http.MethodGet, "/api/v1/dashboard/retention-adjustments", token, nil)
	var out noticeBody
	if w.Code == http.StatusOK {
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
	}
	return out, w
}

func itemKeys(n noticeBody) []string {
	out := []string{}
	for _, it := range n.Items {
		out = append(out, it.Key)
	}
	sort.Strings(out)
	return out
}

// TestUpgradeRetentionNotice 保留調整告知端點：經 adapter 轉換保留下限的唯讀介面、讀失敗與未接線不冒充空清單、
// 只有安全政策讀取能力可讀、只讀不寫。
func TestUpgradeRetentionNotice(t *testing.T) {
	A, S := policy.PolicyRetentionAuditLogDays, policy.PolicyRetentionSessionCommandDays
	D, R, C := policy.PolicyRetentionAlertDays, policy.PolicyRetentionRecordingDays, policy.PolicyRetentionCheckpointDays
	noopAudit := func(tx *gorm.DB, r policy.FloorRaise) error { return nil }

	fixtures := []struct {
		name               string
		audit, cmd, alert  int
		rec, cp            int
		wantItems          []string
		wantCheckpointNew  int
		wantUncoveredCount int
	}{
		{"A", 3, 6, 5, 6, 6, []string{A, S, D, R, C}, 7, 0},
		{"B", 3, 0, 6, 90, 0, []string{A, D}, 0, 0},
		{"C", 30, 0, 6, 90, 10, []string{D}, 0, 3},
		{"D", 3, 0, 30, 90, 5, []string{A, C}, 7, 3},
	}
	for _, f := range fixtures {
		f := f
		t.Run("fixture "+f.name, func(t *testing.T) {
			env := newGuidanceEnv(t)
			admin := env.user(t, "retention-admin", model.RoleAdmin)
			seedRetention(t, env.db, f.audit, f.cmd, f.alert, f.rec, f.cp)
			_, err := env.svc.ReconcileRetentionFloor(noopAudit, "1.17.9")
			require.NoError(t, err)

			before := env.writeSideCounts(t)
			got, w := env.notice(t, env.token(t, admin))
			require.Equal(t, http.StatusOK, w.Code)
			wantKeys := append([]string{}, f.wantItems...)
			sort.Strings(wantKeys)
			assert.Equal(t, wantKeys, itemKeys(got))
			assert.Len(t, got.Uncovered, f.wantUncoveredCount)
			assert.Equal(t, "1.18.0", got.NoticeVersion)
			for _, it := range got.Items {
				assert.False(t, it.RaisedAt.IsZero(), "每項保留紀錄的真實時間")
				if it.Key == C {
					assert.Equal(t, "cross_key_follow", it.Reason, "檢查點標為跟隨調整")
					assert.Equal(t, f.wantCheckpointNew, it.NewDays, "檢查點新值取紀錄值")
				} else {
					assert.Equal(t, "below_floor", it.Reason)
					assert.Equal(t, 7, it.NewDays)
					assert.Less(t, it.OldDays, 7)
					assert.Greater(t, it.OldDays, 0, "0 與原本 >= 7 不列")
				}
			}
			assert.Equal(t, before, env.writeSideCounts(t), "端點不得新增抬升紀錄或審計列")
		})
	}

	t.Run("無紀錄且無未涵蓋時回成功的空清單", func(t *testing.T) {
		env := newGuidanceEnv(t)
		admin := env.user(t, "retention-admin", model.RoleAdmin)
		seedRetention(t, env.db, 30, 30, 30, 30, 30)
		got, w := env.notice(t, env.token(t, admin))
		require.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, got.Items)
		assert.Empty(t, got.Uncovered)
		var raw map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))
		assert.JSONEq(t, `[]`, string(raw["items"]), "空清單為陣列而非 null")
		assert.JSONEq(t, `[]`, string(raw["uncovered"]), "空清單為陣列而非 null")
	})

	t.Run("同鍵取最新並保留時間，產品版本不同的紀錄不漏，審計清除後仍可讀", func(t *testing.T) {
		env := newGuidanceEnv(t)
		admin := env.user(t, "retention-admin", model.RoleAdmin)
		seedRetention(t, env.db, 30, 30, 30, 30, 30)
		t0 := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
		t1 := t0.Add(48 * time.Hour)
		rows := []model.SecurityPolicyFloorRaise{
			{PolicyKey: A, OldValue: "2", NewValue: "7", Reason: "below_floor", RaisedAt: t0, ProductVersion: "1.17.5"},
			{PolicyKey: A, OldValue: "4", NewValue: "7", Reason: "below_floor", RaisedAt: t1, ProductVersion: "1.18.2"},
			{PolicyKey: D, OldValue: "1", NewValue: "7", Reason: "below_floor", RaisedAt: t0, ProductVersion: "1.17.5"},
			{PolicyKey: D, OldValue: "3", NewValue: "7", Reason: "below_floor", RaisedAt: t0, ProductVersion: "1.17.5"},
		}
		for i := range rows {
			require.NoError(t, env.db.Create(&rows[i]).Error)
		}
		require.NoError(t, env.db.Exec(`DELETE FROM audit_logs`).Error)
		got, w := env.notice(t, env.token(t, admin))
		require.Equal(t, http.StatusOK, w.Code)
		require.Len(t, got.Items, 2)
		byKey := map[string]int{}
		for i, it := range got.Items {
			byKey[it.Key] = i
		}
		ia, id := got.Items[byKey[A]], got.Items[byKey[D]]
		assert.Equal(t, 4, ia.OldDays, "同鍵取排序最後一筆（較晚的時間）")
		assert.True(t, ia.RaisedAt.Equal(t1), "保留該筆的真實時間")
		assert.Equal(t, 3, id.OldDays, "同時間由較大 id 勝出")
		assert.True(t, id.RaisedAt.Equal(t0))
	})

	t.Run("回應只含政策鍵、理由、天數與時間", func(t *testing.T) {
		env := newGuidanceEnv(t)
		admin := env.user(t, "retention-admin", model.RoleAdmin)
		seedRetention(t, env.db, 3, 0, 30, 90, 5)
		_, err := env.svc.ReconcileRetentionFloor(noopAudit, "1.17.9")
		require.NoError(t, err)
		w := env.do(http.MethodGet, "/api/v1/dashboard/retention-adjustments", env.token(t, admin), nil)
		require.Equal(t, http.StatusOK, w.Code)
		var raw struct {
			Items     []map[string]any `json:"items"`
			Uncovered []map[string]any `json:"uncovered"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))
		keys := func(m map[string]any) []string {
			out := []string{}
			for k := range m {
				out = append(out, k)
			}
			sort.Strings(out)
			return out
		}
		require.NotEmpty(t, raw.Items)
		require.NotEmpty(t, raw.Uncovered)
		assert.Equal(t, []string{"key", "new_days", "old_days", "raised_at", "reason"}, keys(raw.Items[0]))
		assert.Equal(t, []string{"checkpoint_days", "data_days", "data_key"}, keys(raw.Uncovered[0]))
	})

	t.Run("讀取失敗回既有錯誤碼與非 2xx，不帶任何項目", func(t *testing.T) {
		partial := policy.FloorReport{
			Raises:    []policy.FloorRaiseRecord{{Key: A, OldValue: "3", NewValue: "7", Reason: "below_floor", RaisedAt: time.Now()}},
			Uncovered: []policy.UncoveredRetention{{Key: R, DataDays: 90, CheckpointDays: 7}},
		}
		for name, rep := range map[string]stubReporter{
			"純錯誤":       {err: errors.New("注入讀取失敗")},
			"先回部分資料再回錯": {report: partial, err: errors.New("注入讀取失敗")},
		} {
			env := newGuidanceEnvWith(t, rep)
			admin := env.user(t, "retention-admin", model.RoleAdmin)
			w := env.do(http.MethodGet, "/api/v1/dashboard/retention-adjustments", env.token(t, admin), nil)
			assert.Equal(t, http.StatusInternalServerError, w.Code, name)
			var body map[string]any
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body), name)
			assert.Equal(t, "INTERNAL_COMPLIANCE_SNAPSHOT", body["code"], name)
			assert.NotContains(t, body, "items", name)
			assert.NotContains(t, body, "uncovered", name)
		}
	})

	t.Run("紀錄值無法轉為天數時整體失敗", func(t *testing.T) {
		bad := policy.FloorReport{Raises: []policy.FloorRaiseRecord{{Key: A, OldValue: "abc", NewValue: "7", Reason: "below_floor", RaisedAt: time.Now()}}}
		env := newGuidanceEnvWith(t, stubReporter{report: bad})
		admin := env.user(t, "retention-admin", model.RoleAdmin)
		w := env.do(http.MethodGet, "/api/v1/dashboard/retention-adjustments", env.token(t, admin), nil)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.NotContains(t, w.Body.String(), `"items"`)
	})

	t.Run("reader 未注入時 handler 建構回錯", func(t *testing.T) {
		state, err := identity.NewReleaseGuidanceService(openGuidanceSqlite(t), &guidanceSink{})
		require.NoError(t, err)
		_, err = NewReleaseGuidanceHandler(state, nil)
		require.Error(t, err)
		var typedNil *policy.SecurityPolicyService
		_, err = NewReleaseGuidanceHandler(state, typedNil)
		require.Error(t, err, "具型別的 nil 指標不得被當成已注入")
		_, err = NewReleaseGuidanceHandler(nil, stubReporter{})
		require.Error(t, err)
	})

	t.Run("沒有安全政策讀取能力拒絕", func(t *testing.T) {
		env := newGuidanceEnv(t)
		user := env.user(t, "plain-user", model.RoleUser)
		_, w := env.notice(t, env.token(t, user))
		assert.Equal(t, http.StatusForbidden, w.Code)
		_, w = env.notice(t, "")
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func openGuidanceSqlite(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	return db
}
