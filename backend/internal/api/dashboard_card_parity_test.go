package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/modules/session"
)

// parityEnv 卡片與各列表共用同一份真實資料與真實服務：卡片端點與列表 handler
// 掛在同一個路由上，由測試用的中介層注入主體（授權裁決本身另有 TestDashboardCardAuthorization）。
type parityEnv struct {
	t      *testing.T
	db     *gorm.DB
	r      *gin.Engine
	now    time.Time
	users  map[string]*model.User
	who    map[string]*authz.Principal
	alpha  uint
	beta   uint
	stats  *session.RecordingService
	review *authz.AccessReviewService
	// requests 與卡片、待審列表共用的真實申請服務（單筆核決、補審也走它）
	requests *authz.AccessRequestService
}

func (e *parityEnv) call(who, rawPath string) (*httptest.ResponseRecorder, map[string]json.RawMessage) {
	e.t.Helper()
	req := httptest.NewRequest(http.MethodGet, rawPath, nil)
	req.Header.Set("X-Test-Who", who)
	w := httptest.NewRecorder()
	e.r.ServeHTTP(w, req)
	var m map[string]json.RawMessage
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return w, m
}

func (e *parityEnv) total(who, rawPath string) int64 {
	e.t.Helper()
	w, m := e.call(who, rawPath)
	require.Equal(e.t, http.StatusOK, w.Code, "%s: %s", rawPath, w.Body.String())
	var n int64
	require.NoError(e.t, json.Unmarshal(m["total"], &n), rawPath)
	return n
}

type parityCard struct {
	Value   int64             `json:"value"`
	Filters map[string]string `json:"filters"`
}

func (e *parityEnv) card(who, key string) parityCard {
	e.t.Helper()
	w, _ := e.call(who, "/api/v1/dashboard/cards/"+key)
	require.Equal(e.t, http.StatusOK, w.Code, "%s: %s", key, w.Body.String())
	var c parityCard
	require.NoError(e.t, json.Unmarshal(w.Body.Bytes(), &c))
	return c
}

// landing 把卡片 filters 原樣組成跳轉 query（鍵值逐字，僅做 URL 編碼）。
func landing(f map[string]string) string {
	v := url.Values{}
	for k, val := range f {
		v.Set(k, val)
	}
	return v.Encode()
}

func newParityEnv(t *testing.T) *parityEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	f := setupCredentialAPIEnv(t)
	db := f.db
	require.NoError(t, migrateWithAuthz(db, &model.Session{}, &model.AccessRequest{},
		&model.AccessRequestItem{}, &model.AccessRequestApproval{}, &model.AccessReview{}, &model.SecurityPolicy{}))

	// sqlite 對 timestamptz 欄位會回字串而讀不進 time.Time，告警表沿 audit 測試的作法用原生 DDL
	require.NoError(t, db.Exec(`CREATE TABLE command_alerts (
		id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id INTEGER, rule_name TEXT NOT NULL,
		kind TEXT NOT NULL DEFAULT 'rule', reason_code TEXT NOT NULL DEFAULT '',
		session_id INTEGER, user_id INTEGER NOT NULL, asset_id INTEGER,
		command TEXT NOT NULL, severity TEXT NOT NULL, triggered_at DATETIME NOT NULL,
		reviewed_by INTEGER, reviewed_at DATETIME, disposition TEXT NOT NULL DEFAULT 'pending',
		note TEXT NOT NULL DEFAULT '', blocked BOOLEAN NOT NULL DEFAULT 0)`).Error)

	e := &parityEnv{t: t, db: db, users: map[string]*model.User{}, who: map[string]*authz.Principal{},
		alpha: f.assetIDs[0], beta: f.assetIDs[1],
		now: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)}
	for _, name := range []string{"admin", "user-a", "user-b"} {
		u := &model.User{Username: name, Password: "x", Active: true, Email: emailPtr(name + "@x")}
		require.NoError(t, db.Create(u).Error)
		e.users[name] = u
	}
	e.who["admin"] = authz.NewPrincipal(e.users["admin"].ID, authz.TokenFacts{}, []authz.Assignment{{
		RoleName: model.RoleAdmin, BuiltinKey: model.BuiltinSuperAdmin, Via: authz.ViaDirect, Scope: model.ScopeKindGlobal}})
	for _, name := range []string{"user-a", "user-b"} {
		// 自訂角色：只有資產檢視，不是檢視捷徑主體，資產列表走授權集合
		e.who[name] = authz.NewPrincipal(e.users[name].ID, authz.TokenFacts{}, []authz.Assignment{{
			RoleName: "custom-" + name, Via: authz.ViaDirect, Scope: model.ScopeKindGlobal, Custom: true,
			Permissions: []authz.Permission{authz.PermAssetView}}})
	}

	// 授權：user-a 對 alpha 有 view 與 connect 兩列（授權集合必須去重），beta 沒有；user-b 什麼都沒有
	a, alpha := e.users["user-a"].ID, e.alpha
	for _, perm := range []model.PermissionType{model.PermissionView, model.PermissionConnect} {
		require.NoError(t, db.Create(&model.AssetAuthorization{UserID: &a, AssetID: &alpha, Permission: perm, Source: model.AuthorizationSourceManual}).Error)
	}

	sessionSvc := session.NewSessionService(nil)
	recDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(recDir, "a.cast"), make([]byte, 10), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(recDir, "b.cast"), make([]byte, 25), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(recDir, ".hidden"), make([]byte, 99), 0o600))
	e.stats = session.NewRecordingService(recDir)
	e.review = authz.NewAccessReviewService(db)
	policies := policy.NewSecurityPolicyService(db)
	requests := authz.NewAccessRequestService(db, policies, policy.NewAccessPolicyService(db, policies, authz.NewAssetAuthorizationService(db)), nil, nil)

	e.requests = requests
	cards, err := NewDashboardCardHandler(DashboardCardDeps{
		Assets:        &dashboardAssetCounter{assets: f.assetSvc, auth: authz.NewAssetAuthorizationService(db)},
		Sessions:      sessionSvc,
		MyConnections: session.NewMyConnectionService(sessionSvc),
		Alerts:        audit.NewCommandAlertService(db),
		Recordings:    e.stats,
		Reviews:       e.review,
		Requests:      requests,
		DB:            db,
		Now:           func() time.Time { return e.now },
	})
	require.NoError(t, err)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		who := c.GetHeader("X-Test-Who")
		u := e.users[who]
		c.Set("userID", u.ID)
		c.Set("username", u.Username)
		middleware.SetPrincipal(c, e.who[who])
		c.Next()
	})
	r.GET("/api/v1/dashboard/cards/:key", cards.GetCard)
	sh := NewSessionHandler(sessionSvc)
	r.GET("/api/v1/sessions", sh.List)
	r.GET("/api/v1/sessions/active", sh.GetActive)
	r.GET("/api/v1/command-alerts", NewCommandAlertHandler(audit.NewCommandAlertService(db)).List)
	r.GET("/api/v1/assets", NewAssetHandler(f.assetSvc, authz.NewAssetAuthorizationService(db), nil).List)
	arh := NewAccessRequestHandler(requests, nil, db)
	r.GET("/api/v1/access-requests/mine", arh.ListMine)
	r.GET("/api/v1/access-requests/pending", arh.ListPending)
	r.GET("/api/v1/access-requests/pending/count", arh.PendingCount)
	r.GET("/api/v1/access-requests/reviews/pending", arh.ListPendingReview)
	r.GET("/api/v1/my/connections", NewMyConnectionHandler(session.NewMyConnectionService(sessionSvc)).List)
	r.GET("/api/v1/access-reviews", NewAccessReviewHandler(e.review, nil).List)
	e.r = r
	return e
}

// TestDashboardCardListParity 卡值與落點列表同源：同一份資料、同一個主體、同樣的篩選，
// 卡片值必須等於對應列表 API 回報的全量 total。
func TestDashboardCardListParity(t *testing.T) {
	t.Run("approvals", testApprovalsParity)
	t.Run("sources", func(t *testing.T) {
		e := newParityEnv(t)
		db := e.db
		today := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
		adminID, aID, bID := e.users["admin"].ID, e.users["user-a"].ID, e.users["user-b"].ID

		// 連線：今日兩筆邊界內（00:00:00 與 23:59:59.999500）、前一日尾端與次日 00:00 各一筆邊界外，
		// 另有分頁之外的一般資料；活動連線三筆，其中兩筆錄影失敗，一筆已結束的連線也帶錄影失敗（不計入活動卡）
		seq := 0
		mk := func(user uint, st time.Time, status model.SessionStatus, recErr string) model.Session {
			seq++
			return model.Session{SessionID: fmt.Sprintf("parity-%03d", seq), UserID: user, AssetID: &e.alpha, StartTime: st, Status: status, RecordingError: recErr,
				Protocol: model.ProtocolSSH, ClientIP: "10.0.0.1"}
		}
		var sessions []model.Session
		sessions = append(sessions,
			mk(adminID, today, model.SessionStatusClosed, ""),
			mk(aID, today.Add(24*time.Hour-500*time.Microsecond), model.SessionStatusClosed, ""),
			mk(adminID, today.Add(-time.Microsecond), model.SessionStatusClosed, ""),
			mk(adminID, today.Add(24*time.Hour), model.SessionStatusClosed, ""),
			mk(aID, today.Add(time.Hour), model.SessionStatusActive, "disk full"),
			mk(bID, today.Add(2*time.Hour), model.SessionStatusActive, "io"),
			mk(bID, today.Add(3*time.Hour), model.SessionStatusActive, ""),
			mk(adminID, today.Add(-48*time.Hour), model.SessionStatusClosed, "old failure"),
		)
		for i := 0; i < 25; i++ {
			sessions = append(sessions, mk(aID, today.Add(-time.Duration(72+i)*time.Hour), model.SessionStatusClosed, ""))
		}
		require.NoError(t, db.Create(&sessions).Error)

		// 告警：涵蓋各來源類別，含沒有會話的 system_security
		rule := uint(1)
		mkAlert := func(kind string, at time.Time, reviewed bool) model.CommandAlert {
			al := model.CommandAlert{Kind: kind, RuleName: "r", ReasonCode: "c", UserID: adminID, Command: "x", Severity: "high",
				TriggeredAt: at, Disposition: model.AlertDispositionPending}
			if kind == model.AlertKindRule {
				al.RuleID = &rule
			}
			if kind != "system_security" && kind != model.AlertKindAgentBreaker {
				al.SessionID = sessions[0].ID
			}
			if reviewed {
				rt := at
				al.ReviewedAt, al.Disposition = &rt, model.AlertDispositionBenign
			}
			return al
		}
		var alerts []model.CommandAlert
		alerts = append(alerts,
			mkAlert(model.AlertKindRule, today, false),
			mkAlert("system_security", today.Add(24*time.Hour-500*time.Microsecond), false),
			mkAlert(model.AlertKindNewSourceIP, today.Add(5*time.Hour), true),
			mkAlert(model.AlertKindAuditDegraded, today.Add(-time.Microsecond), false),
			mkAlert(model.AlertKindSensitiveReveal, today.Add(24*time.Hour), false),
		)
		for i := 0; i < 22; i++ {
			alerts = append(alerts, mkAlert(model.AlertKindRule, today.Add(-time.Duration(30+i)*time.Hour), i%2 == 0))
		}
		require.NoError(t, db.Create(&alerts).Error)

		// 本人申請：user-a 有 201 筆較舊的 pending 與 200 筆較新的已核准；user-b 有 3 筆 pending
		base := e.now.Add(-48 * time.Hour)
		// 建立時一律 pending（模型的建立鉤子只收 pending）；每筆用不同資產編號避開 pending 去重索引，
		// 之後把要當作已核准的那批改狀態
		reqSeq := uint(1000)
		mkReq := func(user uint, approved bool, created time.Time) {
			reqSeq++
			r := &model.AccessRequest{RequesterID: user, AssetID: reqSeq, Reason: "r", RequestedDurationMinutes: 30,
				Status: model.AccessRequestPending, PendingExpiresAt: e.now.Add(time.Hour), CreatedAt: created, UpdatedAt: created}
			require.NoError(t, db.Create(r).Error)
			if approved {
				require.NoError(t, db.Model(&model.AccessRequest{}).Where("id = ?", r.ID).
					Update("status", model.AccessRequestApproved).Error)
			}
		}
		for i := 0; i < 201; i++ {
			mkReq(aID, false, base.Add(time.Duration(i)*time.Second))
		}
		for i := 0; i < 200; i++ {
			mkReq(aID, true, base.Add(time.Hour+time.Duration(i)*time.Second))
		}
		for i := 0; i < 3; i++ {
			mkReq(bID, false, base.Add(time.Duration(i)*time.Second))
		}

		require.NoError(t, db.Create(&model.AccessReview{ReviewedBy: adminID, ReviewerName: "admin", Scope: "all", Note: "n",
			ReviewedAt: time.Now().Add(-200*24*time.Hour - time.Hour)}).Error)

		t.Run("資產", func(t *testing.T) {
			// 檢視捷徑主體：全量；一般主體：授權集合去重後的集合，授權集合外的 beta 不入計數
			cAdmin := e.card("admin", "assets")
			assert.EqualValues(t, 2, cAdmin.Value)
			assert.Equal(t, e.total("admin", "/api/v1/assets"), cAdmin.Value)
			cA := e.card("user-a", "assets")
			assert.EqualValues(t, 1, cA.Value, "alpha 有 view 與 connect 兩列授權，只算一台；beta 未授權")
			assert.Equal(t, e.total("user-a", "/api/v1/assets"), cA.Value)
			assert.EqualValues(t, 0, e.card("user-b", "assets").Value)
			assert.Equal(t, e.total("user-b", "/api/v1/assets"), e.card("user-b", "assets").Value)
		})

		t.Run("本人連線", func(t *testing.T) {
			c := e.card("user-a", "my-connections")
			assert.Equal(t, e.total("user-a", "/api/v1/my/connections"), c.Value)
			assert.EqualValues(t, 27, c.Value, "只計 user-a 自己的連線，含第一頁之外的資料")
			assert.Equal(t, e.total("user-b", "/api/v1/my/connections"), e.card("user-b", "my-connections").Value)
		})

		t.Run("本人待審申請", func(t *testing.T) {
			c := e.card("user-a", "my-pending-requests")
			assert.EqualValues(t, 201, c.Value, "全量 pending，不受列表 200 筆上限影響")
			assert.Equal(t, "pending", c.Filters["status"])
			// 原列表 API：形狀與 200 筆上限不變，total 仍代表載入數，且較新的 200 筆非 pending 把 pending 擠出了載入範圍
			w, m := e.call("user-a", "/api/v1/access-requests/mine")
			require.Equal(t, http.StatusOK, w.Code)
			var loaded int64
			require.NoError(t, json.Unmarshal(m["total"], &loaded))
			assert.EqualValues(t, 200, loaded)
			var data []struct{ Status string }
			require.NoError(t, json.Unmarshal(m["data"], &data))
			require.Len(t, data, 200)
			pendingLoaded := 0
			for _, d := range data {
				if d.Status == "pending" {
					pendingLoaded++
				}
			}
			assert.Zero(t, pendingLoaded, "舊算法只數載入範圍會得到 0")
			assert.EqualValues(t, 3, e.card("user-b", "my-pending-requests").Value, "他人的申請不入計數")
		})

		t.Run("連線卡", func(t *testing.T) {
			active := e.card("admin", "active-sessions")
			assert.Equal(t, map[string]string{"status": "active"}, active.Filters)
			assert.EqualValues(t, 3, active.Value)
			assert.Equal(t, e.total("admin", "/api/v1/sessions?"+landing(active.Filters)), active.Value)

			all := e.card("admin", "total-sessions")
			assert.EqualValues(t, len(sessions), all.Value)
			assert.Equal(t, e.total("admin", "/api/v1/sessions"), all.Value)
			_, m := e.call("admin", "/api/v1/sessions")
			var firstPage []json.RawMessage
			require.NoError(t, json.Unmarshal(m["data"], &firstPage))
			assert.Less(t, int64(len(firstPage)), all.Value, "卡值含第一頁之外的資料")
		})

		t.Run("今日共用日界線", func(t *testing.T) {
			c := e.card("admin", "today-sessions")
			assert.Equal(t, "2026-10-19T00:00:00.000000Z", c.Filters["start_time"])
			assert.Equal(t, "2026-10-19T23:59:59.999999Z", c.Filters["end_time"], "尾端保留微秒，不截成秒或毫秒")
			assert.EqualValues(t, 5, c.Value, "邊界內 00:00:00、23:59:59.999500 與當日三筆活動連線計入；前一日 23:59:59.999999 與次日 00:00 不計")
			// 卡片 filters、跳轉 query、列表實際 API 參數三者逐字相同
			q := landing(c.Filters)
			parsed, err := url.ParseQuery(q)
			require.NoError(t, err)
			assert.Equal(t, c.Filters["start_time"], parsed.Get("start_time"))
			assert.Equal(t, c.Filters["end_time"], parsed.Get("end_time"))
			assert.Equal(t, e.total("admin", "/api/v1/sessions?"+q), c.Value)
			// 列表端解析後再格式化，仍是同一個字串（無精度損失）
			for _, k := range []string{"start_time", "end_time"} {
				pt, err := time.Parse(time.RFC3339, parsed.Get(k))
				require.NoError(t, err)
				assert.Equal(t, c.Filters[k], pt.Format(cardTimeLayout), k)
			}

			// 次日的卡：次日 00:00 的紀錄只計入這一天
			e.now = e.now.Add(24 * time.Hour)
			next := e.card("admin", "today-sessions")
			assert.EqualValues(t, 1, next.Value)
			assert.Equal(t, e.total("admin", "/api/v1/sessions?"+landing(next.Filters)), next.Value)
			nextAlerts := e.card("admin", "today-alerts")
			assert.EqualValues(t, 1, nextAlerts.Value)
			e.now = e.now.Add(-24 * time.Hour)
		})

		t.Run("告警卡", func(t *testing.T) {
			today := e.card("admin", "today-alerts")
			assert.EqualValues(t, 3, today.Value, "含 system_security 與已審閱者，次日 00:00 與前一日尾端不計")
			assert.Equal(t, e.total("admin", "/api/v1/command-alerts?"+landing(today.Filters)), today.Value)
			un := e.card("admin", "unreviewed-alerts")
			assert.Equal(t, map[string]string{"unreviewed": "true"}, un.Filters)
			assert.Equal(t, e.total("admin", "/api/v1/command-alerts?"+landing(un.Filters)), un.Value)
			var unreviewed int64
			require.NoError(t, db.Model(&model.CommandAlert{}).Where("reviewed_at IS NULL").Count(&unreviewed).Error)
			assert.Equal(t, unreviewed, un.Value, "全部來源，不限 kind")
			var sys int64
			require.NoError(t, db.Model(&model.CommandAlert{}).Where("kind = ? AND reviewed_at IS NULL", "system_security").Count(&sys).Error)
			assert.EqualValues(t, 1, sys)
		})

		t.Run("活動錄影失敗", func(t *testing.T) {
			c := e.card("admin", "recording-failures")
			assert.Equal(t, map[string]string{"status": "active", "recording_error": "true"}, c.Filters)
			assert.EqualValues(t, 2, c.Value, "已結束連線的失敗不計入活動卡")
			// 落點列表是活動連線全量，再以同一述詞篩出
			w, _ := e.call("admin", "/api/v1/sessions/active")
			require.Equal(t, http.StatusOK, w.Code)
			var active []model.Session
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &active))
			assert.EqualValues(t, session.CountRecordingFailures(active), c.Value)
		})

		t.Run("容量與複審天數", func(t *testing.T) {
			stats, err := e.stats.GetRecordingStats()
			require.NoError(t, err)
			rs := e.card("admin", "recording-storage")
			assert.Equal(t, stats.TotalSize, rs.Value)
			assert.EqualValues(t, 35, rs.Value)
			days, err := e.review.LastReviewDaysAgo()
			require.NoError(t, err)
			rv := e.card("admin", "last-access-review")
			assert.EqualValues(t, days, rv.Value)
			assert.EqualValues(t, 200, rv.Value)
			_, m := e.call("admin", "/api/v1/access-reviews")
			var listed int
			require.NoError(t, json.Unmarshal(m["last_review_days_ago"], &listed))
			assert.EqualValues(t, listed, rv.Value)
		})

		t.Run("原列表回應形狀不變", func(t *testing.T) {
			for _, p := range []string{"/api/v1/sessions", "/api/v1/command-alerts", "/api/v1/assets", "/api/v1/access-requests/mine", "/api/v1/my/connections"} {
				w, m := e.call("admin", p)
				require.Equal(t, http.StatusOK, w.Code, p)
				assert.Contains(t, m, "data", p)
				assert.Contains(t, m, "total", p)
			}
		})
	})
}
