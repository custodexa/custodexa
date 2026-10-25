package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/testgate"
)

// TestPermissionWriteLockOrder 拓撲寫入與權限寫入（使用者／群組／映射規則刪除）同時進行時的 PostgreSQL 真交錯。
// 每個子案例兩個真服務入口各用一個連線池（各自的 application_name），另有觀測連線；
// 先行交易以測試掛點停在「已取得共用資源、尚未提交」，後行交易以自然流程走到同一資源，觀測連線以
// 嚴格等待證明（permission_write_lock_order_proof_test.go）確認後行在等先行持有的那把鎖，再放行。
// 每條交易的 backend pid 在交易開始時（連線池的 BeginTx）以 pg_backend_pid() 取得。
//
//	TEST_PG_DSN="host=... user=... password=... dbname=... sslmode=disable" \
//	  REQUIRE_INTEGRATION=1 go test ./cmd/server/ -run '^TestPermissionWriteLockOrder$' -count=1 -v
//
// 單一子案例重跑：-run '^TestPermissionWriteLockOrder$/^<子案例>$'。

const (
	pwloSchema   = "perm_write_lock_order"
	pwloDeadline = 90 * time.Second
	pwloRounds   = 20
)

// pwloPidPool 包住 *sql.DB：每開一筆交易，就在該交易上以 pg_backend_pid() 取得本交易的 backend pid。
type pwloPidPool struct {
	*sql.DB
	mu   sync.Mutex
	pids []int64
}

func (p *pwloPidPool) BeginTx(ctx context.Context, opts *sql.TxOptions) (gorm.ConnPool, error) {
	tx, err := p.DB.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	var pid int64
	if err := tx.QueryRowContext(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	p.mu.Lock()
	p.pids = append(p.pids, pid)
	p.mu.Unlock()
	return tx, nil
}

func (p *pwloPidPool) GetDBConn() (*sql.DB, error) { return p.DB, nil }

func (p *pwloPidPool) reset() {
	p.mu.Lock()
	p.pids = nil
	p.mu.Unlock()
}

func (p *pwloPidPool) began() []int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]int64(nil), p.pids...)
}

type pwloActor struct {
	name string
	app  string
	db   *gorm.DB
	pool *pwloPidPool
}

// pwloStop 先行交易的停點：走到時回報本交易 pid，等放行。
type pwloStop struct {
	site    string
	reached chan int64
	release chan struct{}
	fired   sync.Once
	rel     sync.Once
}

func (st *pwloStop) open() { st.rel.Do(func() { close(st.release) }) }

type pwloStops struct {
	mu    sync.Mutex
	armed *pwloStop
}

func (s *pwloStops) arm(site string) *pwloStop {
	st := &pwloStop{site: site, reached: make(chan int64, 1), release: make(chan struct{})}
	s.mu.Lock()
	s.armed = st
	s.mu.Unlock()
	return st
}

func (s *pwloStops) disarm() {
	s.mu.Lock()
	s.armed = nil
	s.mu.Unlock()
}

func (s *pwloStops) hit(site string, tx *gorm.DB) {
	s.mu.Lock()
	st := s.armed
	s.mu.Unlock()
	if st == nil || st.site != site || tx == nil {
		return
	}
	first := false
	st.fired.Do(func() { first = true })
	if !first {
		return
	}
	pid := int64(-1)
	var got int64
	if err := tx.Raw("SELECT pg_backend_pid()").Scan(&got).Error; err == nil {
		pid = got
	}
	st.reached <- pid
	select {
	case <-st.release:
	case <-time.After(pwloDeadline):
	}
}

// pwloRevoker 真的 authz 級聯撤銷，成功後經停點：先行交易停在「已寫到共用列、尚未提交」。
// 寫共用列的是正式的 RevokeBy*（不是裸鎖）。
type pwloRevoker struct {
	inner *authz.AssetAuthorizationService
	stops *pwloStops
}

func (r pwloRevoker) RevokeByUser(tx *gorm.DB, userID uint) error {
	if err := r.inner.RevokeByUser(tx, userID); err != nil {
		return err
	}
	r.stops.hit("revoke_by_user", tx)
	return nil
}

func (r pwloRevoker) RevokeByUserGroup(tx *gorm.DB, groupID uint) (int64, error) {
	n, err := r.inner.RevokeByUserGroup(tx, groupID)
	if err != nil {
		return n, err
	}
	r.stops.hit("revoke_by_user_group", tx)
	return n, nil
}

func (r pwloRevoker) RevokeByAssetGroup(tx *gorm.DB, groupID uint) (int64, int64, error) {
	a, s, err := r.inner.RevokeByAssetGroup(tx, groupID)
	if err != nil {
		return a, s, err
	}
	r.stops.hit("revoke_by_asset_group", tx)
	return a, s, nil
}

func (r pwloRevoker) RevokeByAsset(tx *gorm.DB, assetID uint) (int64, int64, error) {
	a, s, err := r.inner.RevokeByAsset(tx, assetID)
	if err != nil {
		return a, s, err
	}
	r.stops.hit("revoke_by_asset", tx)
	return a, s, nil
}

type pwloEnv struct {
	subcase  string
	admin    *gorm.DB
	fix      *gorm.DB // fixture 與 migration 用
	obs      *gorm.DB // 觀測專屬連線池
	scoped   string
	token    string
	dbOID    int64
	actors   map[string]*pwloActor
	stops    pwloStops
	root     uint
	attested bool
	pidsMu   sync.Mutex
	pids     map[string][]int64
}

func pwloOpen(t *testing.T, dsn string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err, "postgres 連線失敗")
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(6)
	t.Cleanup(func() { _ = sqlDB.Close() })
	return db
}

func pwloOpenActor(t *testing.T, dsn string) (*gorm.DB, *pwloPidPool) {
	t.Helper()
	cfg, err := pgx.ParseConfig(dsn)
	require.NoError(t, err)
	pool := &pwloPidPool{DB: stdlib.OpenDB(*cfg)}
	pool.DB.SetMaxOpenConns(6)
	t.Cleanup(func() { _ = pool.DB.Close() })
	db, err := gorm.Open(postgres.New(postgres.Config{Conn: pool}), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	return db, pool
}

// newPWLOEnv 建一個子案例的環境：獨立 schema、正式 migration（含正式外鍵）、每個參與者一個連線池。
func newPWLOEnv(t *testing.T, subcase string, migrate bool, actorNames ...string) *pwloEnv {
	t.Helper()
	base := testgate.Value(t, testgate.EnvPGDSN)
	admin := pwloOpen(t, fmt.Sprintf("%s lock_timeout=%d", base, pwloDeadline.Milliseconds()))
	drop := "DROP SCHEMA IF EXISTS " + pwloSchema + " CASCADE"
	require.NoError(t, admin.Exec(drop).Error, "測試 schema 重建失敗")
	require.NoError(t, admin.Exec("CREATE SCHEMA "+pwloSchema).Error)
	t.Cleanup(func() {
		if err := admin.Exec(drop).Error; err != nil {
			t.Errorf("測試 schema 清理失敗（請手動 DROP SCHEMA %s CASCADE）: %v", pwloSchema, err)
		}
	})
	e := &pwloEnv{subcase: subcase, admin: admin, token: fmt.Sprintf("%d", time.Now().UnixNano()),
		actors: map[string]*pwloActor{}, pids: map[string][]int64{}}
	e.scoped = base + " search_path=" + pwloSchema + " lock_timeout=30000"
	e.fix = pwloOpen(t, e.scoped+" application_name=pwlo_fix_"+e.token)
	e.obs = pwloOpen(t, e.scoped+" application_name=pwlo_obs_"+e.token)
	require.NoError(t, e.obs.Raw("SELECT oid::bigint FROM pg_database WHERE datname = current_database()").Scan(&e.dbOID).Error)
	require.NotZero(t, e.dbOID)
	for _, name := range actorNames {
		app := "pwlo_" + name + "_" + e.token
		db, pool := pwloOpenActor(t, e.scoped+" application_name="+app)
		e.actors[name] = &pwloActor{name: name, app: app, db: db, pool: pool}
	}
	// 實際 dialector 必須是 postgres（不得回退 SQLite）
	require.Equal(t, "postgres", e.fix.Dialector.Name())
	require.Equal(t, "postgres", e.obs.Dialector.Name())
	for _, a := range e.actors {
		require.Equal(t, "postgres", a.db.Dialector.Name(), "參與者 %s 的 dialector", a.name)
	}
	oldDB := database.DB
	database.DB = e.fix
	t.Cleanup(func() { database.DB = oldDB })
	if !migrate {
		return e
	}
	require.NoError(t, database.RunMigrations(), "正式 migration 失敗")
	e.root = e.human(t, "pwlo-root")
	var adminRole model.Role
	require.NoError(t, e.fix.Where("name = ?", model.RoleAdmin).First(&adminRole).Error)
	require.NoError(t, e.fix.Create(&model.UserRole{UserID: e.root, RoleID: adminRole.ID, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
	return e
}

func (e *pwloEnv) actor(name string) *pwloActor { return e.actors[name] }

func (e *pwloEnv) revoker(name string) pwloRevoker {
	return pwloRevoker{inner: authz.NewAssetAuthorizationService(e.actor(name).db), stops: &e.stops}
}

// selfCheckPool 等待證明自測用的原生連線池（不經 GORM 交易）。
func (e *pwloEnv) selfCheckPool(t *testing.T) *sql.DB {
	t.Helper()
	cfg, err := pgx.ParseConfig(e.scoped + " application_name=pwlo_self_" + e.token)
	require.NoError(t, err)
	db := stdlib.OpenDB(*cfg)
	db.SetMaxOpenConns(8)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func (e *pwloEnv) human(t *testing.T, name string) uint {
	t.Helper()
	u := model.User{Username: name, Active: true, Kind: model.KindHuman}
	require.NoError(t, e.fix.Create(&u).Error)
	return u.ID
}

func (e *pwloEnv) scalar(t *testing.T, q string, args ...any) int64 {
	t.Helper()
	var n int64
	require.NoError(t, e.obs.Raw(q, args...).Scan(&n).Error)
	return n
}

func (e *pwloEnv) version(t *testing.T) int64 {
	t.Helper()
	return e.scalar(t, "SELECT version FROM authz_state WHERE id = 1")
}

func (e *pwloEnv) notePIDs(party string, pids ...int64) {
	e.pidsMu.Lock()
	defer e.pidsMu.Unlock()
	for _, p := range pids {
		seen := false
		for _, q := range e.pids[party] {
			if q == p {
				seen = true
			}
		}
		if !seen {
			e.pids[party] = append(e.pids[party], p)
		}
	}
}

func (e *pwloEnv) pidSummary() string {
	e.pidsMu.Lock()
	defer e.pidsMu.Unlock()
	parties := make([]string, 0, len(e.pids))
	for p := range e.pids {
		parties = append(parties, p)
	}
	sort.Strings(parties)
	parts := make([]string, 0, len(parties))
	for _, p := range parties {
		ids := append([]int64(nil), e.pids[p]...)
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		strs := make([]string, len(ids))
		for i, id := range ids {
			strs[i] = fmt.Sprint(id)
		}
		parts = append(parts, p+":"+strings.Join(strs, ","))
	}
	return strings.Join(parts, ";")
}

// checkAttestation 附證漂移前置斷言：附證未啟用（未注入權限來源，或鏈頭不存在）回 false；
// 啟用時鏈頭必須與當下快照一致（以 RecordUntracedPermissionDrift 在一筆會回滾的交易裡判定），
// 否則 BeginPermissionChange 會寫 untraced 事件並持其保留，40P01 可能來自已知範圍的 N4／N4′（假紅）。
func (e *pwloEnv) checkAttestation(t *testing.T) bool {
	t.Helper()
	if !audit.PermissionSourcesWired() {
		return false
	}
	heads := e.scalar(t, "SELECT count(*) FROM permission_state_events")
	if heads == 0 {
		return false
	}
	tx := e.fix.Begin()
	require.NoError(t, tx.Error)
	drift, err := audit.RecordUntracedPermissionDrift(context.Background(), tx)
	require.NoError(t, tx.Rollback().Error)
	require.NoError(t, err)
	require.False(t, drift, "附證已啟用且鏈頭與當下快照不一致：fixture 帶未追蹤的權限狀態漂移")
	return true
}

func pwloSQLState(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

func pwloStateLabel(err error) string {
	if err == nil {
		return "none"
	}
	if code := pwloSQLState(err); code != "" {
		return code
	}
	return "non_pg_error"
}

func pwloErrText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func requirePWLOClean(t *testing.T, party string, err error) {
	t.Helper()
	code := pwloSQLState(err)
	require.NotEqual(t, "40P01", code, "%s 回死結：%v", party, err)
	require.NotEqual(t, "55P03", code, "%s 回 lock_timeout：%v", party, err)
	require.NoError(t, err, "%s 未成功（sqlstate=%q）", party, code)
}

// pwloFixture 一輪的資料：各子案例只用到其中幾個欄位。
type pwloFixture struct {
	user, node, group, asset, scope, authz uint
	provider, rule, role                   uint
	other, cred                            uint // (e) 未刪節點 M；(f)(g) 共用憑證 C
	channel                                string
	version                                int64
}

// pwloParty 一個參與交易：run 走正式服務入口；stopSite 是它當先行者時停的位置；
// topology 為真表示它持拓撲鎖寫權限列（停點與等待時都必須已持拓撲鎖，拓撲鎖先於權限列）。
type pwloParty struct {
	name     string
	actor    string
	stopSite string
	topology bool
	run      func(fx *pwloFixture) error
}

type pwloCase struct {
	parties [2]pwloParty
	// target 後行者要等的共用資源（兩種先後相同）
	target func(fx *pwloFixture) pwloTarget
	setup  func(t *testing.T, tag string) *pwloFixture
	// snap 讀出本輪可觀測的最終資料（含權限版本增量），與依序執行的結果比對
	snap func(t *testing.T, fx *pwloFixture) map[string]int64
	// atStop 先行者停在停點時的附加斷言（可為 nil）；onWait 嚴格等待證明成立後、放行前的附加斷言（可為 nil）
	atStop func(t *testing.T, fx *pwloFixture, lead pwloParty, leadPID int64)
	onWait func(t *testing.T, fx *pwloFixture, follow pwloParty, followPID int64)
}

func pwloSnapKey(m map[string]int64) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s=%d", k, m[k])
	}
	return strings.Join(parts, ",")
}

// runPWLOCase 先以兩種順序各依序執行一次，得到合法結果集合；再跑 20 輪交錯（兩種先後各半）。
func runPWLOCase(t *testing.T, e *pwloEnv, c pwloCase) {
	e.attested = e.checkAttestation(t)
	legal := map[string]string{}
	for lead := 0; lead < 2; lead++ {
		fx := c.setup(t, fmt.Sprintf("seq%d", lead))
		require.Equal(t, e.attested, e.checkAttestation(t), "附證狀態在子案例內改變")
		first, second := c.parties[lead], c.parties[1-lead]
		requirePWLOClean(t, first.name, first.run(fx))
		requirePWLOClean(t, second.name, second.run(fx))
		key := pwloSnapKey(c.snap(t, fx))
		if legal[key] != "" {
			legal[key] += "|"
		}
		legal[key] += first.name + "->" + second.name
		fmt.Printf("SEQUENTIAL subcase=%s order=%s->%s result=%s\n", e.subcase, first.name, second.name, key)
	}
	confirmed := [2]int{}
	for r := 0; r < pwloRounds; r++ {
		lead := r % 2
		fx := c.setup(t, fmt.Sprintf("r%02d", r))
		require.Equal(t, e.attested, e.checkAttestation(t), "附證狀態在子案例內改變")
		if e.runPWLORound(t, c, fx, lead, r, legal) {
			confirmed[lead]++
		}
	}
	fmt.Printf("SUMMARY subcase=%s rounds=%d confirmed_%s_first=%d confirmed_%s_first=%d\n", e.subcase, pwloRounds,
		c.parties[0].name, confirmed[0], c.parties[1].name, confirmed[1])
	require.GreaterOrEqual(t, confirmed[0], 1, "%s 先行的輪次沒有任何一輪確認重疊", c.parties[0].name)
	require.GreaterOrEqual(t, confirmed[1], 1, "%s 先行的輪次沒有任何一輪確認重疊", c.parties[1].name)
	fmt.Printf("EVIDENCE dialect=%s subcase=%s pids=%s attested=%v\n", e.fix.Dialector.Name(), e.subcase, e.pidSummary(), e.attested)
}

// runPWLORound 一輪交錯；回傳本輪是否以嚴格等待證明確認重疊。
func (e *pwloEnv) runPWLORound(t *testing.T, c pwloCase, fx *pwloFixture, leadIdx, round int, legal map[string]string) bool {
	t.Helper()
	lead, follow := c.parties[leadIdx], c.parties[1-leadIdx]
	la, fa := e.actor(lead.actor), e.actor(follow.actor)
	la.pool.reset()
	fa.pool.reset()
	st := e.stops.arm(lead.stopSite)
	defer e.stops.disarm()
	defer st.open() // 提前失敗時一律放行先行者

	leadRun := pwloGo(func() error { return lead.run(fx) })
	var leadPID int64
	select {
	case leadPID = <-st.reached:
	case <-leadRun.done:
		t.Fatalf("round %d：%s 未走到停點 %s 就結束（err=%v）", round, lead.name, lead.stopSite, leadRun.err)
	case <-time.After(pwloDeadline):
		t.Fatalf("round %d：%s 未在期限內走到停點 %s", round, lead.name, lead.stopSite)
	}
	require.NotEqual(t, int64(-1), leadPID, "停點取 pid 失敗")
	leadBegan := la.pool.began()
	require.Len(t, leadBegan, 1, "%s 在停點前應只開了一筆交易", lead.name)
	require.Equal(t, leadBegan[0], leadPID, "停點的 pid 應等於 %s 交易開始時取得的 pid", lead.name)
	if lead.topology {
		require.EqualValues(t, 1, pwloAdvisoryHeld(t, e.obs, leadPID, authz.TopologySerializationLockClass, 1),
			"round %d：%s 停在已寫到權限列時應已持有拓撲鎖（拓撲鎖先於權限列）", round, lead.name)
	}
	if c.atStop != nil {
		c.atStop(t, fx, lead, leadPID)
	}

	followRun := pwloGo(func() error { return follow.run(fx) })
	followPID := e.awaitBegin(t, fa, followRun, follow.name, round)
	tg := c.target(fx)
	proof, ok, why := pwloProveWait(t, e.obs, followPID, leadPID, tg, pwloProofBound, followRun)
	if ok && follow.topology {
		require.EqualValues(t, 1, pwloAdvisoryHeld(t, e.obs, followPID, authz.TopologySerializationLockClass, 1),
			"round %d：%s 在權限列上等待時應已持有拓撲鎖（拓撲鎖先於權限列）", round, follow.name)
	}
	if ok && c.onWait != nil {
		c.onWait(t, fx, follow, followPID)
	}
	st.open()
	errLead := leadRun.wait(t, lead.name)
	errFollow := followRun.wait(t, follow.name)
	e.notePIDs(lead.name, leadPID)
	e.notePIDs(follow.name, followPID)
	fmt.Printf("ROUND subcase=%s round=%02d lead=%s lead_pid=%d follow=%s follow_pid=%d confirmed=%v proof=%s lead_sqlstate=%s follow_sqlstate=%s lead_err=%q follow_err=%q reason=%q\n",
		e.subcase, round, lead.name, leadPID, follow.name, followPID, ok, proof,
		pwloStateLabel(errLead), pwloStateLabel(errFollow), pwloErrText(errLead), pwloErrText(errFollow), why)
	requirePWLOClean(t, lead.name, errLead)
	requirePWLOClean(t, follow.name, errFollow)

	key := pwloSnapKey(c.snap(t, fx))
	order, legalOK := legal[key]
	require.True(t, legalOK, "round %d：最終資料 %s 不等於任何一種依序執行的結果 %v", round, key, legal)
	fmt.Printf("ROUND-DATA subcase=%s round=%02d result=%s matches=%s\n", e.subcase, round, key, order)
	return ok
}

// awaitBegin 等後行者開出交易並回傳其 pid（交易開始時取得）。
func (e *pwloEnv) awaitBegin(t *testing.T, a *pwloActor, run *pwloRun, name string, round int) int64 {
	t.Helper()
	ticker := time.NewTicker(pwloProofInterval)
	defer ticker.Stop()
	timeout := time.NewTimer(pwloDeadline)
	defer timeout.Stop()
	for {
		if pids := a.pool.began(); len(pids) > 0 {
			return pids[0]
		}
		if run.finished() {
			t.Fatalf("round %d：%s 未開交易就結束（err=%v）", round, name, run.err)
		}
		select {
		case <-ticker.C:
		case <-timeout.C:
			t.Fatalf("round %d：%s 未在期限內開出交易", round, name)
		}
	}
}

func TestPermissionWriteLockOrder(t *testing.T) {
	if os.Getenv(testgate.EnvPGDSN) == "" && !testgate.RequireIntegration() {
		t.Skipf("%s 未設：本測試只在 PostgreSQL 跑（SQLite 不做交錯測試，SQLite 的取鎖順序由動態鎖序守衛涵蓋）", testgate.EnvPGDSN)
	}
	testgate.Value(t, testgate.EnvPGDSN)

	t.Run("strict_wait_proof_self_check", func(t *testing.T) {
		e := newPWLOEnv(t, "strict_wait_proof_self_check", false)
		runStrictWaitProofSelfCheck(t, e)
		fmt.Printf("EVIDENCE dialect=%s subcase=%s pids=%s attested=%v\n", e.fix.Dialector.Name(), e.subcase, e.pidSummary(), audit.PermissionSourcesWired())
	})
	t.Run("user_delete_vs_node_delete", func(t *testing.T) {
		e, c := pwloBuildCase(t, "user_delete_vs_node_delete")
		runPWLOCase(t, e, c)
	})
	t.Run("group_delete_vs_node_delete", func(t *testing.T) {
		e, c := pwloBuildCase(t, "group_delete_vs_node_delete")
		runPWLOCase(t, e, c)
	})
	t.Run("asset_delete_vs_user_delete", func(t *testing.T) {
		e, c := pwloBuildCase(t, "asset_delete_vs_user_delete")
		runPWLOCase(t, e, c)
	})
	t.Run("mapping_rule_delete_vs_user_delete", func(t *testing.T) {
		e, c := pwloBuildCase(t, "mapping_rule_delete_vs_user_delete")
		runPWLOCase(t, e, c)
	})
	t.Run("three_way_group_delete", func(t *testing.T) {
		for _, leaf := range []string{"node_delete", "asset_delete"} {
			t.Run(leaf, func(t *testing.T) { runThreeWayGroupDelete(t, leaf) })
		}
	})
	t.Run("asset_create_vs_credential_rotate", func(t *testing.T) {
		e, c := pwloBuildCase(t, "asset_create_vs_credential_rotate")
		runPWLOCase(t, e, c)
	})
	t.Run("serialization_point_blocks_before_first_write", func(t *testing.T) {
		runSerializationPointCase(t)
	})
}
