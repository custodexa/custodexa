package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/localpty"
	"github.com/custodexa/backend/internal/model"
)

// Authorization decision baseline: environment.
//
// The baseline runs every scenario against the real stage-2 service graph
// (full unseal, file-backed sqlite, synchronous audit). Background schedulers
// are held off through stage2BackgroundGate so that nothing changes state
// between scenarios on its own. Every outbound target in the fixture points
// at an in-process receiver (see authz_baseline_egress_test.go), so no real
// host is ever contacted.

// baselineEnv is one fully built baseline environment.
type baselineEnv struct {
	t      testing.TB
	seal   *sealIntegrationEnv
	graph  *appGraph
	db     *gorm.DB
	dir    string
	recv   *egressReceivers
	fsDirs map[string]string // logical name -> live directory

	// template is the VACUUM INTO snapshot taken after fixtures are seeded.
	template        string
	templateFS      string // copies of fsDirs at template time
	tables          []string
	resetWrites     int
	resetTime       time.Duration // cumulative table-reset time (task 1.3 measurement)
	projectionProbe bool          // schema projection probe applied (re-applied on rebuild)
	inProcess       []inProcessSlot
	lazyCollected   bool
	conn            *sql.Conn

	subjects map[string]*baselineSubject
	objects  map[string]any // placeholder name -> value

	engineMu sync.Mutex
}

// newBaselineEnv builds the environment, seeds subjects and objects, and
// takes the template snapshot. Callers get a ready-to-run environment.
func newBaselineEnv(t testing.TB) *baselineEnv {
	return buildBaselineEnv(t, startEgressReceivers(t))
}

// rebuild builds a fresh environment on the same receivers. Used after a
// scenario that sealed the instance: sealing releases the whole service
// graph, which no database reset can undo. Seeding is deterministic, so the
// rebuilt fixtures carry the same identifiers.
func (e *baselineEnv) rebuild() *baselineEnv {
	e.recv.take()
	nb := buildBaselineEnv(e.t, e.recv)
	if e.projectionProbe {
		nb.addProjectionProbe()
	}
	return nb
}

func buildBaselineEnv(t testing.TB, recv *egressReceivers) *baselineEnv {
	tt, ok := t.(*testing.T)
	if !ok {
		t.Fatalf("baseline environment requires *testing.T")
	}
	prevGate := stage2BackgroundGate
	stage2BackgroundGate = func(string) bool { return false }
	t.Cleanup(func() { stage2BackgroundGate = prevGate })

	dir := t.TempDir()
	baselinePathMasks = []string{dir}
	fsDirs := map[string]string{
		"recordings": filepath.Join(dir, "fs", "recordings"),
		"exports":    filepath.Join(dir, "fs", "exports"),
	}
	for _, d := range fsDirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	// Database terminal entries start their command-line client as the
	// de-privileged system account of the backend image, which requires
	// that account and root. Elsewhere those scenarios would record a
	// different (start-failure) outcome, so refuse to run rather than
	// capture or compare something else.
	if _, _, _, err := localpty.LookupUser(localpty.CLIUser); err != nil || os.Geteuid() != 0 {
		t.Fatalf("authorization baseline needs the backend image environment (root and the %q account): uid=%d err=%v",
			localpty.CLIUser, os.Geteuid(), err)
	}
	tt.Setenv("RECORDING_PATH", fsDirs["recordings"])
	tt.Setenv("EXPORT_ARTIFACT_PATH", fsDirs["exports"])
	tt.Setenv("LDAP_ALLOWED_LOOPBACK_ENDPOINTS", recv.addr("ldap"))
	tt.Setenv("PATH", recv.stubDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	// Ambient cloud credentials differ between machines (CI sets static
	// keys, a developer container has none), and the object-storage client
	// resolves them from the environment: without fixed values the offsite
	// scenarios would reach the receiver on one machine and stop before it
	// on another. Pin them so every machine records the same outcome.
	for k, v := range map[string]string{
		"AWS_ACCESS_KEY_ID": "baseline-access-key", "AWS_SECRET_ACCESS_KEY": "baseline-secret-key",
		"AWS_REGION": "us-east-1", "AWS_SESSION_TOKEN": "", "AWS_PROFILE": "", "AWS_CONFIG_FILE": "/dev/null",
		"AWS_SHARED_CREDENTIALS_FILE": "/dev/null", "AWS_EC2_METADATA_DISABLED": "true",
		"GOOGLE_APPLICATION_CREDENTIALS": "", "TZ": "UTC",
	} {
		tt.Setenv(k, v)
	}

	sealEnv := newSealIntegrationEnvWith(tt, func(s1 *stage1) {
		completeBaselineSchema(tt)
		s1.cfg.Guacamole.Host = "127.0.0.1"
		s1.cfg.Guacamole.Port = recv.port("guacd")
		s1.cfg.OIDC.AllowedInternalHosts = []string{"127.0.0.1"}
		// Offsite retrieval spools under this root before it contacts the
		// object store; the default root is not writable in a test.
		s1.cfg.Offsite.SpoolPath = filepath.Join(dir, "offsite-spool")
	})
	if w := sealEnv.do(http.MethodPost, "/api/v1/seal/unseal", initPayload(testInitialKEK)); w.Code != http.StatusOK {
		t.Fatalf("baseline unseal returned %d: %s", w.Code, w.Body.String())
	}
	graph, ok := sealEnv.machine.Snapshot().Services.(*appGraph)
	if !ok || graph == nil {
		t.Fatalf("baseline: stage-2 graph unavailable after unseal")
	}

	env := &baselineEnv{
		t: t, seal: sealEnv, graph: graph, db: database.DB, dir: dir,
		recv: recv, fsDirs: fsDirs,
		subjects: map[string]*baselineSubject{},
		objects:  map[string]any{},
	}
	env.disableOffsiteHotStart()
	env.seedSubjects()
	env.seedObjects()
	env.finalizeSubjects()
	env.takeTemplate()
	return env
}

// baselineExtraModels 共用整合環境沒涵蓋、但路由會碰到的表（以模型建表）。
// 通道寫入與系統告警同交易，所以告警明細、投遞佇列與分級覆寫三張表缺一不可。
// 改密計畫與批次建立時同交易寫入工作授權脈絡，缺該表時種子階段的計畫建立回 500。
func baselineExtraModels() []any {
	return []any{
		&model.UserGroupMember{}, &model.AlertRule{}, &model.ApproverScope{}, &model.CommandAlert{},
		&model.NotificationChannel{}, &model.SessionCommand{},
		&model.SystemAlertDetail{}, &model.SystemAlertOutbox{}, &model.SystemAlertSeverityOverride{},
		&model.CredentialJobAuthorization{},
	}
}

// completeBaselineSchema adds the tables the shared integration environment
// leaves out (it migrates only the schema-parity model list) and the columns
// later migrations add to join tables, so every route can reach its data.
// sqlite cannot run the production DDL, hence model-driven creation here.
func completeBaselineSchema(t testing.TB) {
	reopenBaselineDB(t)
	if err := database.DB.AutoMigrate(baselineExtraModels()...); err != nil {
		t.Fatalf("baseline schema: %v", err)
	}
	if !database.DB.Migrator().HasColumn("user_group_members", "manual") {
		if err := database.DB.Exec(`ALTER TABLE user_group_members ADD COLUMN manual boolean NOT NULL DEFAULT true`).Error; err != nil {
			t.Fatalf("baseline schema: %v", err)
		}
	}
	if err := database.DB.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version varchar(50) NOT NULL PRIMARY KEY, applied_at timestamp NOT NULL)`).Error; err != nil {
		t.Fatalf("baseline schema: %v", err)
	}
	if err := database.SeedDatabase(testAdminPassword); err != nil {
		t.Fatalf("baseline seed: %v", err)
	}
	// 權限版本的初始列：正式庫由權限模型遷移建立；本環境以模型建表而不跑遷移，
	// 缺此列時所有經 authz.AdvanceVersion 的寫入路徑會回 ErrAuthzStateMissing
	if err := database.DB.Exec(`INSERT INTO authz_state (id, version) VALUES (1, 0) ON CONFLICT (id) DO NOTHING`).Error; err != nil {
		t.Fatalf("baseline authz_state: %v", err)
	}
}

// engine builds a fresh router over the same service graph. Middleware
// instances (anonymous rejection throttles and similar) are created per
// engine, so a new engine per scenario keeps their counters from leaking
// between scenarios; handlers and services are shared.
func (e *baselineEnv) engine() *gin.Engine {
	e.engineMu.Lock()
	defer e.engineMu.Unlock()
	r, err := buildStage2Engine(e.seal.s1, e.seal.machine, e.seal.handler, e.graph)
	if err != nil {
		e.t.Fatalf("baseline: build engine: %v", err)
	}
	return r
}

// serve sends one request through a fresh engine.
func (e *baselineEnv) serve(req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	e.engine().ServeHTTP(w, req)
	return w
}

// object resolves a placeholder; unknown names fail the test.
func (e *baselineEnv) object(name string) any {
	v, ok := e.objects[name]
	if !ok {
		e.t.Fatalf("baseline: unknown fixture placeholder {%s}", name)
	}
	return v
}

func (e *baselineEnv) setObject(name string, v any) {
	if _, dup := e.objects[name]; dup {
		e.t.Fatalf("baseline: fixture placeholder {%s} defined twice", name)
	}
	e.objects[name] = v
}

// objectNames lists defined placeholders (sorted), for coverage reports.
func (e *baselineEnv) objectNames() []string {
	out := make([]string, 0, len(e.objects))
	for k := range e.objects {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// substitute replaces "{name}" placeholders inside a string.
func (e *baselineEnv) substitute(s string) string {
	if !strings.Contains(s, "{") {
		return s
	}
	var b strings.Builder
	for {
		i := strings.Index(s, "{")
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		j := strings.Index(s[i:], "}")
		if j < 0 {
			b.WriteString(s)
			return b.String()
		}
		name := s[i+1 : i+j]
		b.WriteString(s[:i])
		if isPlaceholderName(name) {
			b.WriteString(fmt.Sprint(e.object(name)))
		} else {
			b.WriteString(s[i : i+j+1])
		}
		s = s[i+j+1:]
	}
}

// resolveValue walks a decoded JSON value; a string that is exactly a
// placeholder becomes the object's native value.
func (e *baselineEnv) resolveValue(v any) any {
	switch x := v.(type) {
	case string:
		if strings.HasPrefix(x, "{") && strings.HasSuffix(x, "}") && isPlaceholderName(x[1:len(x)-1]) {
			return e.object(x[1 : len(x)-1])
		}
		return e.substitute(x)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = e.resolveValue(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = e.resolveValue(val)
		}
		return out
	default:
		return v
	}
}

// isPlaceholderName accepts "kind.name" identifiers only, so JSON-looking
// text inside strings is left alone.
func isPlaceholderName(s string) bool {
	if s == "" || !strings.Contains(s, ".") {
		return false
	}
	for _, r := range s {
		if !(r == '.' || r == '_' || r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// release tears the graph down early (used by T08 to rebuild on the same DB).
func (e *baselineEnv) release() {
	if snap := e.seal.machine.Snapshot(); snap.Services != nil {
		_ = snap.Services.Release(context.Background())
	}
}

// reopenBaselineDB swaps database.DB for a handle on the same file with WAL,
// a busy timeout and a small pool (see authz_baseline_state_test.go).
func reopenBaselineDB(t testing.TB) {
	var path string
	row := database.DB.Raw(`SELECT file FROM pragma_database_list WHERE name = 'main'`).Row()
	if err := row.Scan(&path); err != nil || path == "" {
		t.Fatalf("baseline db path: %v", err)
	}
	db, err := gorm.Open(sqlite.Open("file:"+path+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)"),
		&gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("reopen baseline db: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("reopen baseline db: %v", err)
	}
	sqlDB.SetMaxOpenConns(6)
	sqlDB.SetMaxIdleConns(6)
	t.Cleanup(func() { _ = sqlDB.Close() })
	database.DB = db
}
