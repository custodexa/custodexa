package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/pkg/crypto"
)

type nopRoleEvents struct{}

func (nopRoleEvents) WriteRoleDefinitionEvent(*gorm.DB, identity.RoleDefinitionEvent) error {
	return nil
}

// revocationEnv 錄影票主動撤銷的測試環境：真權限解析、真角色定義寫入（推權限版本、
// 不推憑證世代）、真提交後通知。
type revocationEnv struct {
	db      *gorm.DB
	h       *RecordingHandler
	mgr     *RecordingTokenManager
	roles   *identity.RoleDefinitionService
	adminID uint
	// unregister 解除管理器在提交後通知上的登記（模擬通知漏發）
	unregister func()
	dir        string
}

func newRevocationEnv(t *testing.T, db *gorm.DB) *revocationEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	if err := db.AutoMigrate(database.SchemaParityModels()...); err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(evidenceSinkModels()...); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`INSERT INTO authz_state (id, version) VALUES (1, 0)`).Error; err != nil {
		t.Fatal(err)
	}
	prev := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = prev })
	dir := t.TempDir()
	rs := session.NewRecordingService(dir)
	rs.SetEvidenceSinks(audit.NewTxSink(), audit.NewSystemAlertSink(nil))
	h := NewRecordingHandler(rs, session.NewSessionService(nil),
		audit.NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true}))
	e := &revocationEnv{db: db, h: h, mgr: h.recordingTokens,
		roles: identity.NewRoleDefinitionService(db, audit.NewTxSink(), nopRoleEvents{},
			identity.NewGrantGrader(audit.NewTxSink(), audit.NewSystemAlertSink(nil))), dir: dir}
	e.unregister = authz.RegisterVersionCommitListener(e.mgr.OnPermissionVersionCommitted)
	t.Cleanup(e.unregister)
	admin := e.user(t, "rev-admin")
	e.adminID = admin
	sa := model.BuiltinSuperAdmin
	super := &model.Role{Name: "rev-super", BuiltinKey: &sa}
	if err := db.Create(super).Error; err != nil {
		t.Fatal(err)
	}
	e.bind(t, admin, super.ID)
	return e
}

func (e *revocationEnv) user(t *testing.T, name string) uint {
	t.Helper()
	u := &model.User{Username: name, Active: true}
	if err := e.db.Create(u).Error; err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func (e *revocationEnv) bind(t *testing.T, userID, roleID uint) {
	t.Helper()
	if err := e.db.Create(&model.UserRole{UserID: userID, RoleID: roleID, Source: "manual", ScopeKind: model.ScopeKindGlobal}).Error; err != nil {
		t.Fatal(err)
	}
}

// customViewer 建一個持錄影檢視權（audit:view）的自訂角色並指派給使用者，回傳角色。
func (e *revocationEnv) customViewer(t *testing.T, name string, userID uint) *identity.RoleDefinition {
	t.Helper()
	def, err := e.roles.Create(context.Background(), e.adminID, identity.RoleInput{Name: name, Permissions: []string{string(authz.PermAuditView), string(authz.PermSessionView)}})
	if err != nil {
		t.Fatal(err)
	}
	e.bind(t, userID, def.ID)
	return def
}

// revokeView 以角色定義修改拿掉 audit:view（推權限版本、不推任何持有者的憑證世代）。
func (e *revocationEnv) revokeView(t *testing.T, def *identity.RoleDefinition) {
	t.Helper()
	cur, err := e.roles.GetDefinition(context.Background(), def.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.roles.Update(context.Background(), e.adminID, def.ID, cur.DefinitionVersion,
		identity.RoleInput{Name: cur.Name, Permissions: []string{string(authz.PermSessionView)}}); err != nil {
		t.Fatal(err)
	}
}

func (e *revocationEnv) version(t *testing.T) int64 {
	t.Helper()
	v, err := authz.CurrentVersion(e.db)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (e *revocationEnv) issue(t *testing.T, userID, sessionID uint) (string, error) {
	t.Helper()
	return e.mgr.Issue(userID, sessionID, "holder", crypto.AuthContext{}, authz.TokenFacts{})
}

func (e *revocationEnv) issueHTTP(t *testing.T, userID, sessionID uint) *httptest.ResponseRecorder {
	t.Helper()
	w, _, _ := e.issueHTTPDenial(t, userID, sessionID)
	return w
}

// issueHTTPDenial 同 issueHTTP，另回傳 handler 存進請求脈絡的能力拒絕依據。
func (e *revocationEnv) issueHTTPDenial(t *testing.T, userID, sessionID uint) (*httptest.ResponseRecorder, middleware.CapabilityDenial, bool) {
	t.Helper()
	p, err := authz.ResolveUserOn(e.db, userID, authz.TokenFacts{})
	if err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", userID)
		c.Set("username", "holder")
		middleware.SetPrincipal(c, p)
	})
	var denial middleware.CapabilityDenial
	var hasDenial bool
	r.POST("/api/v1/sessions/:id/recording/token", func(c *gin.Context) {
		e.h.IssueRecordingToken(c)
		denial, hasDenial = middleware.CapabilityDenialFrom(c)
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+strconv.Itoa(int(sessionID))+"/recording/token", nil))
	return w, denial, hasDenial
}

func (e *revocationEnv) stream(t *testing.T, token string) int {
	t.Helper()
	r := gin.New()
	r.GET("/api/v1/recordings/stream", e.h.StreamRecordingByToken)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/recordings/stream?rtoken="+token, nil))
	return w.Code
}

// seedRecording 建一場有真錄影內容的會話（回傳內容標記字串）。
func (e *revocationEnv) seedRecording(t *testing.T, userID, sessionID uint) string {
	t.Helper()
	marker := fmt.Sprintf("RECORDING-CONTENT-%d", sessionID)
	path := filepath.Join(e.dir, fmt.Sprintf("s%d.cast", sessionID))
	if err := os.WriteFile(path, []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.db.Create(&model.Session{ID: sessionID, SessionID: fmt.Sprintf("s%d", sessionID), UserID: userID, Status: "closed",
		RecordingPath: path, RecordingSize: int64(len(marker)), HasRecording: true}).Error; err != nil {
		t.Fatal(err)
	}
	return marker
}

// streamBody 以票取流，回傳狀態碼與回應本文。
func (e *revocationEnv) streamBody(t *testing.T, token string) (int, string) {
	t.Helper()
	r := gin.New()
	r.GET("/api/v1/recordings/stream", e.h.StreamRecordingByToken)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/recordings/stream?rtoken="+token, nil))
	return w.Code, w.Body.String()
}

// armRootVersionFailure 讓下一次「以根連線」讀權限版本回錯一次（交易內的讀取不受影響），
// 即提交後通知的版本查詢；回傳實際被消耗的次數計數器。
func (e *revocationEnv) armRootVersionFailure() (arm func(), consumed *atomic.Int32) {
	base := e.mgr.versionOf
	var armed atomic.Bool
	consumed = &atomic.Int32{}
	e.mgr.versionOf = func(db *gorm.DB) (int64, error) {
		if db == database.DB && armed.CompareAndSwap(true, false) {
			consumed.Add(1)
			return 0, errors.New("注入通知版本查詢失敗")
		}
		return base(db)
	}
	return func() { armed.Store(true) }, consumed
}

func newRevocationSQLite(t *testing.T) *gorm.DB {
	t.Helper()
	// 檔案型 WAL、連線池多條：停在鎖交易內的簽發與另一條連線上的撤權可並存
	db, err := gorm.Open(sqlite.Open("file:"+filepath.Join(t.TempDir(), "rev.db")+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)"),
		&gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(4)
	t.Cleanup(func() { _ = sqlDB.Close() })
	return db
}

// TestRecordingTokenActiveRevocation 擋：持票者的錄影檢視權被拿掉後，票在 TTL 內仍可取流；
// 撤權後才簽出的票帶到新版本；重驗結果倒退或復活已刪除的票；重驗讀不到仍放行；版本未變時
// 熱路徑查庫；回滾的權限寫入誤發通知；刪錄影後該會話的票仍有效。
func TestRecordingTokenActiveRevocation(t *testing.T) {
	t.Run("稽核員持票後被移除稽核員角色，同一 TTL 內取流回 401", func(t *testing.T) {
		e := newRevocationEnv(t, newRevocationSQLite(t))
		u := e.user(t, "auditor-u")
		ak := model.BuiltinAuditor
		auditorRole := &model.Role{Name: "rev-auditor", BuiltinKey: &ak}
		e.db.Create(auditorRole)
		e.bind(t, u, auditorRole.ID)
		tok, err := e.issue(t, u, 100)
		if err != nil {
			t.Fatal(err)
		}
		if code := e.stream(t, tok); code == http.StatusUnauthorized {
			t.Fatal("撤權前取流不得為 401")
		}
		if err := identity.WithUserCredentialLock(e.db, u, func(tx *gorm.DB) error {
			if err := tx.Where("user_id = ? AND role_id = ?", u, auditorRole.ID).Delete(&model.UserRole{}).Error; err != nil {
				return err
			}
			return authz.AdvanceVersion(tx)
		}); err != nil {
			t.Fatal(err)
		}
		if code := e.stream(t, tok); code != http.StatusUnauthorized {
			t.Fatalf("撤權後取流應 401，得 %d", code)
		}
	})

	t.Run("撤權早於授權快照：Issue 拒發、handler 回 403、沒有新票", func(t *testing.T) {
		e := newRevocationEnv(t, newRevocationSQLite(t))
		u := e.user(t, "custom-u")
		def := e.customViewer(t, "rec-viewer-b", u)
		e.mgr.hooks.beforeJoin = func() { e.revokeView(t, def) }
		w, denial, hasDenial := e.issueHTTPDenial(t, u, 101)
		if w.Code != http.StatusForbidden {
			t.Fatalf("應 403，得 %d %s", w.Code, w.Body.String())
		}
		// 拒絕依據：與路由層同一寫出點，all_of=[audit:view]；拿掉依據則後續審計缺 denial=capability
		if !hasDenial || denial.Basis != authz.DenialAllOf || len(denial.Required) != 1 || denial.Required[0] != "audit:view" {
			t.Fatalf("拒絕依據應為 all_of=[audit:view]，得 has=%v %+v", hasDenial, denial)
		}
		// 回應本文與登錄閘能力拒絕逐位元相同
		sample := gin.New()
		sampleW := httptest.NewRecorder()
		sample.GET("/", func(c *gin.Context) {
			middleware.WriteCapabilityDenial(c, middleware.AllOfCapabilityDenial(authz.Permission("audit:view")))
		})
		sample.ServeHTTP(sampleW, httptest.NewRequest(http.MethodGet, "/", nil))
		if w.Body.String() != sampleW.Body.String() || w.Code != sampleW.Code {
			t.Fatalf("回應須與登錄閘能力拒絕逐位元相同：\n得 %q\n樣本 %q", w.Body.String(), sampleW.Body.String())
		}
		body := map[string]any{}
		_ = jsonUnmarshal(w.Body.Bytes(), &body)
		if _, hasErr := body["error"]; len(body) != 2 || !hasErr || body["code"] != "AUTH_PERMISSION_DENIED" {
			t.Fatalf("拒絕形狀不符（應只有 code、error）: %s", w.Body.String())
		}
		e.mgr.mu.Lock()
		n := len(e.mgr.grants)
		e.mgr.mu.Unlock()
		if n != 0 {
			t.Fatalf("map 中不得有新票，得 %d", n)
		}
	})

	t.Run("簽發途中撤權（SQLite 快照語義）：票帶撤權前版本，取流回 401 並刪票", func(t *testing.T) {
		e := newRevocationEnv(t, newRevocationSQLite(t))
		u := e.user(t, "custom-c")
		def := e.customViewer(t, "rec-viewer-c", u)
		vBefore := e.version(t)
		paused, release := make(chan struct{}), make(chan struct{})
		e.mgr.hooks.afterVersionRead = func() {
			close(paused)
			<-release
		}
		// 重驗套用前記下票當時的版本（簽發提交後的通知可能先於取流就重驗並刪票）
		var seenVersion atomic.Int64
		seenVersion.Store(-1)
		e.mgr.hooks.beforeApply = func(tok string) {
			e.mgr.mu.Lock()
			if g, ok := e.mgr.grants[tok]; ok && seenVersion.Load() < 0 {
				seenVersion.Store(g.Version)
			}
			e.mgr.mu.Unlock()
		}
		type result struct {
			tok string
			err error
		}
		done := make(chan result, 1)
		go func() {
			tok, err := e.issue(t, u, 102)
			done <- result{tok, err}
		}()
		<-paused
		revoked := make(chan struct{})
		go func() { e.revokeView(t, def); close(revoked) }()
		select {
		case <-revoked:
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatal("撤權交易在簽發停住期間 5 秒內未提交：鎖交易持有寫鎖，假設不成立")
		}
		close(release)
		res := <-done
		if res.err != nil {
			t.Fatalf("SQLite 下授權快照早於撤權，Issue 應放行，得 %v", res.err)
		}
		e.mgr.mu.Lock()
		if g, ok := e.mgr.grants[res.tok]; ok && seenVersion.Load() < 0 {
			seenVersion.Store(g.Version)
		}
		e.mgr.mu.Unlock()
		if seenVersion.Load() != vBefore {
			t.Fatalf("票的版本應為撤權前的 %d（不是撤權後的版本），得 %d", vBefore, seenVersion.Load())
		}
		if code := e.stream(t, res.tok); code != http.StatusUnauthorized {
			t.Fatalf("取流應 401，得 %d", code)
		}
		if _, ok := e.mgr.Resolve(res.tok); ok {
			t.Fatal("該票應已自 map 刪除")
		}
	})

	t.Run("撤權在 Issue 完成之後：下一次取流重驗並回 401、刪票", func(t *testing.T) {
		e := newRevocationEnv(t, newRevocationSQLite(t))
		u := e.user(t, "custom-d")
		def := e.customViewer(t, "rec-viewer-d", u)
		tok, err := e.issue(t, u, 103)
		if err != nil {
			t.Fatal(err)
		}
		e.revokeView(t, def)
		if code := e.stream(t, tok); code != http.StatusUnauthorized {
			t.Fatalf("取流應 401，得 %d", code)
		}
		if _, ok := e.mgr.Resolve(tok); ok {
			t.Fatal("票應已刪除")
		}
	})

	t.Run("單調：較舊的重驗不覆蓋較新版本；重驗期間撤銷的票不復活", func(t *testing.T) {
		e := newRevocationEnv(t, newRevocationSQLite(t))
		u := e.user(t, "custom-e")
		e.customViewer(t, "rec-viewer-e", u)
		tok, err := e.issue(t, u, 104)
		if err != nil {
			t.Fatal(err)
		}
		bump := func(name string) {
			if _, err := e.roles.Create(context.Background(), e.adminID, identity.RoleInput{Name: name, Permissions: []string{string(authz.PermSessionView)}}); err != nil {
				t.Fatal(err)
			}
		}
		// 第一次（較舊）的重驗停在套用前；期間完成一次較新的重驗
		pause, release := make(chan struct{}), make(chan struct{})
		var calls atomic.Int32
		e.mgr.hooks.beforeApply = func(string) {
			if calls.Add(1) == 1 {
				close(pause)
				<-release
			}
		}
		oldDone := make(chan struct{})
		go func() { bump("rev-bump-1"); close(oldDone) }()
		<-pause
		bump("rev-bump-2")
		newer := e.version(t)
		close(release)
		<-oldDone
		e.mgr.mu.Lock()
		got := e.mgr.grants[tok].Version
		e.mgr.mu.Unlock()
		if got != newer {
			t.Fatalf("grant 版本應停在較新的 %d，得 %d（被舊重驗倒退）", newer, got)
		}
		// 重驗期間撤銷：重驗結束後票仍不存在
		pause2, release2 := make(chan struct{}), make(chan struct{})
		calls.Store(0)
		e.mgr.hooks.beforeApply = func(string) {
			if calls.Add(1) == 1 {
				close(pause2)
				<-release2
			}
		}
		done := make(chan struct{})
		go func() { bump("rev-bump-3"); close(done) }()
		<-pause2
		e.mgr.RevokeByUser(u)
		close(release2)
		<-done
		e.mgr.hooks.beforeApply = nil
		if _, ok := e.mgr.Resolve(tok); ok {
			t.Fatal("重驗期間撤銷的票不得復活")
		}
	})

	t.Run("無關主體的權限變更不影響持票者取流", func(t *testing.T) {
		e := newRevocationEnv(t, newRevocationSQLite(t))
		u := e.user(t, "custom-f")
		e.customViewer(t, "rec-viewer-f", u)
		other := e.user(t, "custom-f2")
		otherDef := e.customViewer(t, "rec-viewer-f2", other)
		tok, err := e.issue(t, u, 105)
		if err != nil {
			t.Fatal(err)
		}
		e.revokeView(t, otherDef)
		if code := e.stream(t, tok); code == http.StatusUnauthorized {
			t.Fatal("無關主體的變更不得讓持票者 401")
		}
	})

	t.Run("重驗時資料庫讀取失敗：取流回 401", func(t *testing.T) {
		e := newRevocationEnv(t, newRevocationSQLite(t))
		u := e.user(t, "custom-g")
		e.customViewer(t, "rec-viewer-g", u)
		tok, err := e.issue(t, u, 106)
		if err != nil {
			t.Fatal(err)
		}
		e.mgr.decide = func(*gorm.DB, uint, authz.TokenFacts) (authz.Decision, error) {
			return authz.Decision{}, errors.New("注入資料庫讀取失敗")
		}
		if _, err := e.roles.Create(context.Background(), e.adminID, identity.RoleInput{Name: "rev-bump-g", Permissions: []string{string(authz.PermSessionView)}}); err != nil {
			t.Fatal(err)
		}
		if code := e.stream(t, tok); code != http.StatusUnauthorized {
			t.Fatalf("重驗讀不到應 401，得 %d", code)
		}
	})

	t.Run("版本未變時 Resolve 不查資料庫", func(t *testing.T) {
		e := newRevocationEnv(t, newRevocationSQLite(t))
		u := e.user(t, "custom-h")
		e.customViewer(t, "rec-viewer-h", u)
		tok, err := e.issue(t, u, 107)
		if err != nil {
			t.Fatal(err)
		}
		var n atomic.Int64
		if err := e.db.Callback().Query().Before("gorm:query").Register("p2g:count-h", func(*gorm.DB) { n.Add(1) }); err != nil {
			t.Fatal(err)
		}
		if err := e.db.Callback().Raw().Before("gorm:raw").Register("p2g:count-h-raw", func(*gorm.DB) { n.Add(1) }); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			if _, ok := e.mgr.Resolve(tok); !ok {
				t.Fatal("版本未變時票應有效")
			}
		}
		if got := n.Load(); got != 0 {
			t.Fatalf("Resolve 查了 %d 次資料庫，want 0", got)
		}
	})

	t.Run("權限寫入交易回滾時不發通知，持票者取流照常", func(t *testing.T) {
		e := newRevocationEnv(t, newRevocationSQLite(t))
		u := e.user(t, "custom-i")
		e.customViewer(t, "rec-viewer-i", u)
		tok, err := e.issue(t, u, 108)
		if err != nil {
			t.Fatal(err)
		}
		var notified atomic.Int32
		unreg := authz.RegisterVersionCommitListener(func() { notified.Add(1) })
		defer unreg()
		_ = identity.WithUserCredentialLock(e.db, u, func(tx *gorm.DB) error {
			if err := tx.Where("user_id = ?", u).Delete(&model.UserRole{}).Error; err != nil {
				return err
			}
			if err := authz.AdvanceVersion(tx); err != nil {
				return err
			}
			return errors.New("回滾")
		})
		if notified.Load() != 0 {
			t.Fatal("回滾的權限寫入不得通知")
		}
		if code := e.stream(t, tok); code == http.StatusUnauthorized {
			t.Fatal("回滾後持票者取流應照常")
		}
	})

	t.Run("版本在簽發讀取後、寫入前推進：下一次取流觸發重驗", func(t *testing.T) {
		e := newRevocationEnv(t, newRevocationSQLite(t))
		u := e.user(t, "custom-j")
		e.customViewer(t, "rec-viewer-j", u)
		var decides atomic.Int32
		base := e.mgr.decide
		e.mgr.decide = func(db *gorm.DB, uid uint, f authz.TokenFacts) (authz.Decision, error) {
			decides.Add(1)
			return base(db, uid, f)
		}
		e.mgr.hooks.afterVersionRead = func() {
			done := make(chan struct{})
			go func() {
				_, _ = e.roles.Create(context.Background(), e.adminID, identity.RoleInput{Name: "rev-bump-j", Permissions: []string{string(authz.PermSessionView)}})
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("版本推進未在 5 秒內提交")
			}
			// 推進的通知已到（此時 map 尚無此票）；之後的通知不再送達，
			// 使這張票只能由下一次取流的版本比對觸發重驗
			e.unregister()
		}
		tok, err := e.issue(t, u, 109)
		if err != nil {
			t.Fatal(err)
		}
		e.mgr.hooks.afterVersionRead = nil
		if _, ok := e.mgr.Resolve(tok); !ok {
			t.Fatal("無關推進後重驗應放行")
		}
		// 票簽發時帶的是推進前的版本，下一次取流就地重驗一次（簽發判定之外恰再一次）
		if decides.Load() != 2 {
			t.Fatalf("下一次取流應觸發一次重驗，判定次數 %d（want 2）", decides.Load())
		}
		e.mgr.mu.Lock()
		gv := e.mgr.grants[tok].Version
		e.mgr.mu.Unlock()
		if gv != e.version(t) {
			t.Fatalf("重驗後票的版本應為目前版本 %d，得 %d", e.version(t), gv)
		}
	})

	t.Run("刪錄影成功後（經 handler）該會話的票失效、其他會話的票仍有效", func(t *testing.T) {
		e := newRevocationEnv(t, newRevocationSQLite(t))
		u := e.user(t, "custom-k")
		e.customViewer(t, "rec-viewer-k", u)
		for _, id := range []uint{200, 201} {
			path := filepath.Join(e.dir, fmt.Sprintf("s%d.cast", id))
			if err := os.WriteFile(path, []byte("cast"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := e.db.Create(&model.Session{ID: id, SessionID: fmt.Sprintf("s%d", id), UserID: u, Status: "closed",
				RecordingPath: path, RecordingSize: 4, HasRecording: true}).Error; err != nil {
				t.Fatal(err)
			}
		}
		t200, err := e.issue(t, u, 200)
		if err != nil {
			t.Fatal(err)
		}
		t201, err := e.issue(t, u, 201)
		if err != nil {
			t.Fatal(err)
		}
		r := gin.New()
		r.Use(func(c *gin.Context) { c.Set("userID", e.adminID); c.Set("username", "rev-admin") })
		r.DELETE("/api/v1/sessions/:id/recording", e.h.DeleteRecording)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/200/recording", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("刪錄影應 200，得 %d %s", w.Code, w.Body.String())
		}
		if _, ok := e.mgr.Resolve(t200); ok {
			t.Fatal("被刪錄影的會話的票應失效")
		}
		if _, ok := e.mgr.Resolve(t201); !ok {
			t.Fatal("另一會話的票應仍有效")
		}
	})

	t.Run("通知的版本查詢失敗一次：撤權後下一次真取流 401、無錄影內容、票失效", func(t *testing.T) {
		e := newRevocationEnv(t, newRevocationSQLite(t))
		u := e.user(t, "custom-n1")
		def := e.customViewer(t, "rec-viewer-n1", u)
		marker := e.seedRecording(t, u, 300)
		tok, err := e.issue(t, u, 300)
		if err != nil {
			t.Fatal(err)
		}
		if code, body := e.streamBody(t, tok); code != http.StatusOK || !strings.Contains(body, marker) {
			t.Fatalf("撤權前應取得錄影內容，得 %d %q", code, body)
		}
		arm, consumed := e.armRootVersionFailure()
		arm()
		e.revokeView(t, def) // 真角色修改撤權；其提交後通知的版本查詢失敗一次
		if consumed.Load() != 1 {
			t.Fatalf("通知的版本查詢失敗應被消耗恰 1 次，得 %d", consumed.Load())
		}
		// 恢復查詢，不做任何會補發通知的權限操作
		code, body := e.streamBody(t, tok)
		if code != http.StatusUnauthorized {
			t.Fatalf("撤權後取流應 401，得 %d", code)
		}
		if strings.Contains(body, marker) {
			t.Fatal("回應不得含錄影內容")
		}
		e.mgr.mu.Lock()
		_, still := e.mgr.grants[tok]
		e.mgr.mu.Unlock()
		if still {
			t.Fatal("票應已失效")
		}
	})

	t.Run("通知的版本查詢失敗時 map 尚無簽發中的票：該票寫入後取流仍 401", func(t *testing.T) {
		e := newRevocationEnv(t, newRevocationSQLite(t))
		u := e.user(t, "custom-n2")
		def := e.customViewer(t, "rec-viewer-n2", u)
		marker := e.seedRecording(t, u, 301)
		arm, consumed := e.armRootVersionFailure()
		paused, release := make(chan struct{}), make(chan struct{})
		e.mgr.hooks.afterVersionRead = func() {
			close(paused)
			<-release
		}
		type result struct {
			tok string
			err error
		}
		done := make(chan result, 1)
		go func() {
			tok, err := e.issue(t, u, 301)
			done <- result{tok, err}
		}()
		<-paused
		arm()
		revoked := make(chan struct{})
		go func() { e.revokeView(t, def); close(revoked) }()
		select {
		case <-revoked:
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatal("撤權交易在簽發停住期間 5 秒內未提交")
		}
		// 簽發自己的鎖交易提交後也會發通知；解除登記，使撤權那一次失敗的通知成為唯一的通知
		e.unregister()
		close(release)
		res := <-done
		if res.err != nil {
			t.Fatalf("SQLite 下授權快照早於撤權，Issue 應放行，得 %v", res.err)
		}
		if consumed.Load() != 1 {
			t.Fatalf("通知的版本查詢失敗應被消耗恰 1 次，得 %d", consumed.Load())
		}
		code, body := e.streamBody(t, res.tok)
		if code != http.StatusUnauthorized {
			t.Fatalf("取流應 401，得 %d", code)
		}
		if strings.Contains(body, marker) {
			t.Fatal("回應不得含錄影內容")
		}
		if _, ok := e.mgr.Resolve(res.tok); ok {
			t.Fatal("該票應已失效")
		}
	})

	t.Run("postgres_after_version_read", func(t *testing.T) {
		db := openEvidencePG(t, "p2g_rectoken")
		e := newRevocationEnv(t, db)
		u := e.user(t, "custom-pg")
		def := e.customViewer(t, "rec-viewer-pg", u)
		base := e.mgr.decide
		var isolation string
		e.mgr.decide = func(tx *gorm.DB, uid uint, f authz.TokenFacts) (authz.Decision, error) {
			_ = tx.Raw("SHOW transaction_isolation").Scan(&isolation).Error
			return base(tx, uid, f)
		}
		paused, release := make(chan struct{}), make(chan struct{})
		e.mgr.hooks.afterVersionRead = func() {
			close(paused)
			<-release
		}
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() { done <- e.issueHTTP(t, u, 110) }()
		<-paused
		revoked := make(chan struct{})
		go func() { e.revokeView(t, def); close(revoked) }()
		select {
		case <-revoked:
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatal("撤權交易在簽發停住期間 5 秒內未提交")
		}
		close(release)
		w := <-done
		if isolation != "read committed" {
			t.Fatalf("簽發鎖交易的隔離等級 = %q", isolation)
		}
		fmt.Println("EVIDENCE isolation=" + isolation)
		if w.Code != http.StatusForbidden || !bytesContains(w.Body.Bytes(), "AUTH_PERMISSION_DENIED") {
			t.Fatalf("READ COMMITTED 下判定看得到撤權，應 403，得 %d %s", w.Code, w.Body.String())
		}
		e.mgr.mu.Lock()
		n := len(e.mgr.grants)
		e.mgr.mu.Unlock()
		if n != 0 {
			t.Fatalf("map 中不得有新票，得 %d", n)
		}
	})
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func bytesContains(b []byte, sub string) bool { return strings.Contains(string(b), sub) }
