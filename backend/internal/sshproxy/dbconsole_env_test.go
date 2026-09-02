package sshproxy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/dbconsole"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/internal/proxy"
)

// 主控台測試的共用鋪陳。與生產同構的最小鏈路：真 handler、真審計服務、
// 真 sqlite，審計刻意同步寫入——非同步下「等不到」與「根本沒寫」在失敗訊息上
// 無從分辨。

type consoleEnv struct {
	h  *Handler
	db *gorm.DB
}

// setupConsoleEnv 建一場可兌換的環境：使用者 1（一般）持資產 1 的 connect 授權。
// protocol 決定閘序在哪一道擋下——`mysql` 過得了 G-C1，`redis` 過不了
func setupConsoleEnv(t *testing.T, protocol string) *consoleEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	// 單連線：`:memory:` 配連線池時每條連線是各自獨立的空庫
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserGroup{}, &model.Asset{},
		&model.AssetAccount{}, &model.AssetGroup{}, &model.AssetNode{}, &model.AssetAuthorization{},
		&model.AccessRequest{}, &model.SecurityPolicy{}, &model.AuditLog{}, &model.Session{},
		&model.SessionCommand{}, &model.AlertRule{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	roles := []model.Role{{Name: model.RoleUser}, {Name: model.RoleAdmin}}
	for i := range roles {
		if err := db.Create(&roles[i]).Error; err != nil {
			t.Fatalf("seed role: %v", err)
		}
	}
	users := []model.User{
		{Username: "u1", Email: emailPtr("u1@x"), Active: true, Roles: []model.Role{roles[0]}},
		{Username: "u2", Email: emailPtr("u2@x"), Active: true, Roles: []model.Role{roles[1]}},
	}
	for i := range users {
		if err := db.Create(&users[i]).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
	}
	if err := db.Create(&model.Asset{
		Name: "target-db", Protocol: model.ProtocolType(protocol), Host: "127.0.0.1", Port: 3306,
		DBName: "app", CreatedBy: 2,
	}).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	if err := db.Model(&model.Asset{}).Where("id = ?", 1).
		Update("access_policy", model.AccessPolicyOpen).Error; err != nil {
		t.Fatalf("set policy: %v", err)
	}
	uid, aid := uint(1), uint(1)
	if err := db.Create(&model.AssetAuthorization{
		UserID: &uid, AssetID: &aid, Permission: model.PermissionConnect, GrantedBy: 2,
	}).Error; err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	// 資產建立經 hook 落一筆自己的審計列：清空後起算
	if err := db.Exec("DELETE FROM audit_logs").Error; err != nil {
		t.Fatalf("清空 seed 期審計列: %v", err)
	}

	assetSvc, err := asset.NewAssetService(aesColumnCodec(t, make([]byte, 32)), "localhost", 4822, audit.NewTxSink())
	if err != nil {
		t.Fatalf("asset service: %v", err)
	}
	authzSvc := authz.NewAssetAuthorizationService(db)
	auditService := audit.NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false,
	})
	h := NewHandler(assetSvc, identity.NewAuthService("db-console-secret", time.Hour),
		authzSvc, session.NewSessionService(nil), proxy.NewConnectionRegistry(),
		t.TempDir(), auditService)
	policies := policy.NewSecurityPolicyService(db)
	h.AccessPolicy = policy.NewAccessPolicyService(db, policies, authzSvc)
	h.DB = db
	return &consoleEnv{h: h, db: db}
}

// seedAccount 補一個預設帳號（G-S11 的零帳號 fail-close 要它）
func (e *consoleEnv) seedAccount(t *testing.T) {
	t.Helper()
	if err := e.db.Exec(
		`INSERT INTO asset_accounts (asset_id, username, password_enc, is_default, auth_method, created_at, updated_at)
		 VALUES (1, 'app', '', 1, 'sql', ?, ?)`, time.Now(), time.Now()).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}
}

// setAllowedDatabases 改資產的允許清單（模擬管理者縮限）
func (e *consoleEnv) setAllowedDatabases(t *testing.T, list model.StringList) {
	t.Helper()
	if err := e.db.Model(&model.Asset{}).Where("id = ?", 1).
		Update("allowed_databases", list).Error; err != nil {
		t.Fatalf("set allowed_databases: %v", err)
	}
}

// issueTicket 簽一張指向資產 1 的有效票
func (e *consoleEnv) issueTicket(t *testing.T) string {
	t.Helper()
	tok, err := e.h.ConnectTokens.IssueConnectToken(context.Background(),
		proxy.ConnectGrant{UserID: 1, AssetID: 1, AccountID: 0})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return tok
}

// consoleResponse 一次兌換嘗試的完整對外面
type consoleResponse struct {
	code   int
	body   string
	header http.Header
}

// redeem 走與生產同構的路由（含全域真審計中介層）
func (e *consoleEnv) redeem(query string) consoleResponse {
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(e.h.AuditService))
	r.GET("/api/v1/db-console", e.h.HandleDBConsole)
	req := httptest.NewRequest("GET", "/api/v1/db-console"+query, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return consoleResponse{code: w.Code, body: w.Body.String(), header: w.Header().Clone()}
}

func (e *consoleEnv) auditRows(t *testing.T) []model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	if err := e.db.Order("id asc").Find(&rows).Error; err != nil {
		t.Fatalf("查 audit_logs: %v", err)
	}
	return rows
}

// consoleCommandFacts 一列語句紀錄的結果事實（不含時戳）。
//
// 刻意逐欄取而不是掃進 model：`executed_at` 宣告為 timestamptz，
// 而測試用的 sqlite driver 不認這個宣告型別，整列掃描會在時戳那一欄壞掉。
// 本結構要驗的是結果事實，時戳的形狀由 parity 測試在真實資料庫上顧
type consoleCommandFacts struct {
	Status         string
	Reason         string
	TargetDatabase string
	ErrorCode      string
	TxStateAfter   string
	Seq            int
}

func (e *consoleEnv) commandFactsOf(t *testing.T, eventID string) (consoleCommandFacts, bool) {
	t.Helper()
	var f consoleCommandFacts
	row := e.db.Raw(`SELECT result_status, result_reason, target_database, error_code,
		tx_state_after, seq FROM session_commands WHERE event_id = ?`, eventID).Row()
	if err := row.Scan(&f.Status, &f.Reason, &f.TargetDatabase, &f.ErrorCode,
		&f.TxStateAfter, &f.Seq); err != nil {
		return f, false
	}
	return f, true
}

func (e *consoleEnv) commandRows(t *testing.T) []model.SessionCommand {
	t.Helper()
	var rows []model.SessionCommand
	if err := e.db.Order("id asc").Find(&rows).Error; err != nil {
		t.Fatalf("查 session_commands: %v", err)
	}
	return rows
}

// ---------------------------------------------------------------------------
// stub 方言：以它注入 driver 的各種回應形態，並記錄呼叫順序
// ---------------------------------------------------------------------------

type stubDialect struct {
	mu sync.Mutex
	// calls 依序記錄本方言收到的呼叫（順序斷言用）
	calls []string
	// execOutcomes 依序回傳；用盡後回最後一個
	execOutcomes []*dbconsole.ExecOutcome
	execErr      error
	execHook     func()
	currentDB    string
	databases    []dbconsole.DatabaseInfo
	tables       []dbconsole.TableInfo
	columns      []dbconsole.ColumnInfo
	listErr      error
	switchErr    error
	probe        dbconsole.State
	probeErr     error
	cancelOK     bool
	cancelErr    error
	// dialCount 我方重撥的次數。**正常會話恆為 0**——目標連線關閉後不自動重連
	dialCount int
	closed    bool
	execN     int
}

func (d *stubDialect) note(s string) {
	d.mu.Lock()
	d.calls = append(d.calls, s)
	d.mu.Unlock()
}

func (d *stubDialect) callLog() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.calls...)
}

func (d *stubDialect) ListDatabases(context.Context) ([]dbconsole.DatabaseInfo, error) {
	d.note("list_databases")
	return d.databases, d.listErr
}

func (d *stubDialect) ListTables(_ context.Context, _ string) ([]dbconsole.TableInfo, error) {
	d.note("list_tables")
	return d.tables, d.listErr
}

func (d *stubDialect) ListColumns(_ context.Context, _, _ string) ([]dbconsole.ColumnInfo, error) {
	d.note("list_columns")
	return d.columns, d.listErr
}

func (d *stubDialect) Switch(_ context.Context, name string) error {
	d.note("switch:" + name)
	if d.switchErr != nil {
		return d.switchErr
	}
	d.mu.Lock()
	d.currentDB = name
	d.mu.Unlock()
	return nil
}

func (d *stubDialect) Exec(_ context.Context, sql string) (*dbconsole.ExecOutcome, error) {
	d.note("exec:" + sql)
	if d.execHook != nil {
		d.execHook()
	}
	if d.execErr != nil {
		return nil, d.execErr
	}
	d.mu.Lock()
	i := d.execN
	if i >= len(d.execOutcomes) {
		i = len(d.execOutcomes) - 1
	}
	d.execN++
	d.mu.Unlock()
	if i < 0 {
		return &dbconsole.ExecOutcome{Status: dbconsole.StatusOK, TxState: dbconsole.TxStateNone}, nil
	}
	return d.execOutcomes[i], nil
}

func (d *stubDialect) Cancel(context.Context) (bool, error) {
	d.note("cancel")
	return d.cancelOK, d.cancelErr
}

func (d *stubDialect) ProbeState(context.Context) (dbconsole.State, error) {
	d.note("probe")
	return d.probe, d.probeErr
}

func (d *stubDialect) CurrentDatabase() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.currentDB
}

func (d *stubDialect) Close() error {
	d.note("close")
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()
	return nil
}

// ---------------------------------------------------------------------------
// stub 語句紀錄：與 stub 方言共用同一份順序紀錄
// ---------------------------------------------------------------------------

type stubRecorder struct {
	mu       sync.Mutex
	dialect  *stubDialect
	rows     []model.SessionCommand
	backfill map[uint]consoleResultFacts
	insertN  int
	// insertErrAt 第 n 次 Insert 回錯（1 起算；0＝不注入）
	insertErrAt int
	nextID      uint
}

func newStubRecorder(d *stubDialect) *stubRecorder {
	return &stubRecorder{dialect: d, backfill: map[uint]consoleResultFacts{}}
}

func (r *stubRecorder) Insert(row *model.SessionCommand) error {
	r.mu.Lock()
	r.insertN++
	n := r.insertN
	r.mu.Unlock()
	if r.dialect != nil {
		r.dialect.note("insert:" + row.ResultStatus)
	}
	if r.insertErrAt != 0 && n == r.insertErrAt {
		return errors.New("注入的語句紀錄寫入失敗")
	}
	r.mu.Lock()
	r.nextID++
	row.ID = r.nextID
	r.rows = append(r.rows, *row)
	r.mu.Unlock()
	return nil
}

func (r *stubRecorder) Backfill(rowID uint, f consoleResultFacts) error {
	if r.dialect != nil {
		r.dialect.note("backfill:" + f.Status)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.backfill[rowID] = f
	return nil
}

func (r *stubRecorder) snapshot() ([]model.SessionCommand, map[uint]consoleResultFacts) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]model.SessionCommand(nil), r.rows...),
		func() map[uint]consoleResultFacts {
			out := map[uint]consoleResultFacts{}
			for k, v := range r.backfill {
				out[k] = v
			}
			return out
		}()
}

// ---------------------------------------------------------------------------
// stub 比對器
// ---------------------------------------------------------------------------

type stubMatcher struct {
	rule      *model.AlertRule
	hit       bool
	health    error
	matched   []model.SessionCommand
	dialect   *stubDialect
	blockCall int
}

func (m *stubMatcher) MatchBlock(string, string) (*model.AlertRule, bool) {
	if m.dialect != nil {
		m.dialect.note("match_block")
	}
	m.blockCall++
	return m.rule, m.hit
}

func (m *stubMatcher) MatchAndStore(cmds []model.SessionCommand, _ string) {
	m.matched = append(m.matched, cmds...)
}

// BlockerHealth 讓「比對器活著但壞了」有一個可表達的形狀
func (m *stubMatcher) BlockerHealth() error { return m.health }

// ---------------------------------------------------------------------------
// 轉錄落地面：把寫入的位元組留下來供斷言
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 直接組一個會話（不經 WebSocket）：訊息以緩衝佇列取出
// ---------------------------------------------------------------------------

type consoleFixture struct {
	env      *consoleEnv
	s        *consoleSession
	dialect  *stubDialect
	recorder *stubRecorder
	matcher  *stubMatcher
	sink     *captureSink
}

func newConsoleFixture(t *testing.T, d *stubDialect) *consoleFixture {
	t.Helper()
	env := setupConsoleEnv(t, "mysql")
	sess := &model.Session{UserID: 1, Status: model.SessionStatusActive, DBConsole: true}
	aid := uint(1)
	sess.AssetID = &aid
	if err := env.db.Create(sess).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}
	rec := newStubRecorder(d)
	m := &stubMatcher{dialect: d}
	sink := &captureSink{}
	s := &consoleSession{
		handler:  env.h,
		sess:     sess,
		dialect:  d,
		protocol: dbconsole.ProtocolMySQL,
		userID:   1,
		assetID:  1,
		auditCtx: &consoleAuditContext{svc: env.h.AuditService, userID: 1, username: "u1",
			assetID: 1, sessionID: sess.ID, method: "GET", path: "/api/v1/db-console"},
		transcript: newConsoleTranscript(sink),
		recorder:   rec,
		matcher:    m,
		cache:      newConsoleResultCache(),
		out:        make(chan []byte, dbconsole.OutboundQueueDepth),
	}
	return &consoleFixture{env: env, s: s, dialect: d, recorder: rec, matcher: m, sink: sink}
}

// drain 取出目前佇列中的所有訊息（解碼為泛型 map）
func (f *consoleFixture) drain() []map[string]any {
	var out []map[string]any
	for {
		select {
		case raw, open := <-f.s.out:
			// 會話收尾會關閉佇列，而關閉的 channel 永遠可讀——
			// 不分辨這一點，取訊息就成了一個不會結束的迴圈
			if !open {
				return out
			}
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err == nil {
				out = append(out, m)
			}
		default:
			return out
		}
	}
}

// runQuery 同步跑完一次送出（測試不需要非同步）
func (f *consoleFixture) runQuery(text string) {
	units, err := dbconsole.SplitUnits(f.s.protocol, text)
	if err != nil {
		return
	}
	f.s.runSubmission(units)
}
