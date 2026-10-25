package session

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/testgate"
)

// 會話建立與使用者層鎖序的真 PostgreSQL 交錯測試夾具。
//
// 與身分模組的同型夾具行為一致（不同套件的測試檔無法互相引用，故自備）：
// 兩個獨立連線池各代表一個後端副本，另有一條觀測連線；交錯以測試掛點固定；
// pid 由當事交易自己取得；等待以 pg_locks 正向證明（advisory 綁資料庫、classid、objid）；
// 後行者先結束即失敗；連線層 lock_timeout 30 秒、測試 deadline 90 秒；出現 55P03 判失敗。
// 測試 schema 與連線池名稱與身分模組的鎖序測試區隔，兩者可在同一個資料庫並行。
//
// 會話建立走全域資料庫連線（database.DB），所以會話一方恆使用連線池 A，其他入口使用連線池 B。
//
//	TEST_PG_DSN="host=... user=... password=... dbname=... sslmode=disable" \
//	  REQUIRE_INTEGRATION=1 go test ./internal/modules/session -run '^TestSessionUserLockOrderPG$' -count=1 -v

const (
	sessionLockSchema   = "session_lock_order_test"
	sessionLockDeadline = 90 * time.Second
	// 使用者憑證鎖的 advisory classid（身分模組的未匯出常數；兩邊以 pg_locks 的實際鎖鍵核對）
	sessionLockCredentialClass = 0x6F74_6B03
)

type sessionLockEnv struct {
	dbA, dbB, obs      *gorm.DB
	appA, appB, appObs string
	dbOID              int64
	fks                []string
	root               uint
	users              *identity.UserService // 副本 B
}

func openSessionLockDB(t *testing.T, dsn string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err, "postgres 連線失敗")
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(6)
	t.Cleanup(func() { _ = sqlDB.Close() })
	return db
}

func newSessionLockEnv(t *testing.T, wantFKs ...string) *sessionLockEnv {
	t.Helper()
	base := testgate.Value(t, testgate.EnvPGDSN)
	// 管理連線也設 lock_timeout：上一個案例若留下未結束的交易，DROP SCHEMA 會在期限內失敗並列出殘留連線
	admin := openSessionLockDB(t, fmt.Sprintf("%s lock_timeout=%d", base, sessionLockDeadline.Milliseconds()))
	require.Equal(t, "postgres", admin.Dialector.Name())
	drop := "DROP SCHEMA IF EXISTS " + sessionLockSchema + " CASCADE"
	if err := admin.Exec(drop).Error; err != nil {
		t.Fatalf("測試 schema 重建失敗：%v；殘留連線：%s", err, sessionLingeringBackends(admin))
	}
	require.NoError(t, admin.Exec("CREATE SCHEMA "+sessionLockSchema).Error)
	t.Cleanup(func() {
		if err := admin.Exec(drop).Error; err != nil {
			t.Errorf("測試 schema 清理失敗（請手動 DROP SCHEMA %s CASCADE）: %v；殘留連線：%s", sessionLockSchema, err, sessionLingeringBackends(admin))
		}
	})
	scoped := base + " search_path=" + sessionLockSchema + " lock_timeout=30000"
	token := fmt.Sprintf("%d", time.Now().UnixNano())
	e := &sessionLockEnv{appA: "session_lo_a_" + token, appB: "session_lo_b_" + token, appObs: "session_lo_obs_" + token}
	e.dbA = openSessionLockDB(t, scoped+" application_name="+e.appA)
	e.dbB = openSessionLockDB(t, scoped+" application_name="+e.appB)
	e.obs = openSessionLockDB(t, scoped+" application_name="+e.appObs)
	require.NoError(t, e.obs.Raw("SELECT oid::bigint FROM pg_database WHERE datname = current_database()").Scan(&e.dbOID).Error)
	require.NotZero(t, e.dbOID)

	oldDB := database.DB
	database.DB = e.dbA
	t.Cleanup(func() { database.DB = oldDB })
	require.NoError(t, database.RunMigrations(), "正式 migration 失敗")

	// 附證未啟用：不注入權限來源，Begin 不寫 untraced 事件
	require.False(t, audit.PermissionSourcesWired(), "附證不得啟用（否則死結可能來自 untraced 保留而非要證的環）")

	var names []string
	require.NoError(t, e.obs.Raw(`SELECT c.conname FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace
 WHERE n.nspname = ? AND c.contype = 'f' ORDER BY c.conname`, sessionLockSchema).Scan(&names).Error)
	have := map[string]bool{}
	for _, n := range names {
		have[n] = true
	}
	for _, want := range wantFKs {
		require.True(t, have[want], "正式外鍵 %s 不存在", want)
	}
	e.fks = wantFKs

	db := e.dbA
	var admRole model.Role
	if err := db.Where("name = ?", model.RoleAdmin).First(&admRole).Error; err != nil {
		admRole = model.Role{Name: model.RoleAdmin}
		require.NoError(t, db.Create(&admRole).Error)
	}
	e.root = e.humanUser(t, "slo-root")
	require.NoError(t, db.Create(&model.UserRole{UserID: e.root, RoleID: admRole.ID, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
	e.users = identity.NewUserService(e.dbB, authz.NewAssetAuthorizationService(e.dbB))
	e.users.SetOwnerTransferGuard(authz.SelfGrantGuard{})
	e.users.SetAssignmentGuard(identity.NewAssignmentGuard(identity.FullCatalog()))
	return e
}

func (e *sessionLockEnv) humanUser(t *testing.T, name string) uint {
	t.Helper()
	u := model.User{Username: name, Active: true, Kind: model.KindHuman}
	require.NoError(t, e.dbA.Create(&u).Error)
	return u.ID
}

func (e *sessionLockEnv) agentUser(t *testing.T, name string, owner uint) uint {
	t.Helper()
	u := model.User{Username: name, Active: true, Kind: model.KindAgent, OwnerUserID: &owner}
	require.NoError(t, e.dbA.Create(&u).Error)
	return u.ID
}

// fkNameOn 以 pg_constraint 實查某表某欄上的正式外鍵名稱（必須恰有一條）並記入證據。
func (e *sessionLockEnv) fkNameOn(t *testing.T, table, column string) string {
	t.Helper()
	var names []string
	require.NoError(t, e.obs.Raw(`SELECT c.conname FROM pg_constraint c
 JOIN pg_class r ON r.oid = c.conrelid JOIN pg_namespace n ON n.oid = r.relnamespace
 JOIN pg_attribute a ON a.attrelid = r.oid AND a.attnum = ANY (c.conkey)
 WHERE n.nspname = ? AND r.relname = ? AND a.attname = ? AND c.contype = 'f' ORDER BY c.conname`,
		sessionLockSchema, table, column).Scan(&names).Error)
	require.Len(t, names, 1, "%s.%s 上的外鍵", table, column)
	e.fks = append(append([]string{}, e.fks...), names[0])
	return names[0]
}

// sessionLingeringBackends 列出本測試連線池中仍在交易內的連線，供清理失敗時定位。
func sessionLingeringBackends(admin *gorm.DB) string {
	var rows []string
	if err := admin.Raw(`SELECT pid || ' ' || application_name || ' ' || state || ' ' || coalesce((now() - xact_start)::text, '-')
 FROM pg_stat_activity WHERE datname = current_database() AND application_name LIKE 'session\_lo\_%' AND xact_start IS NOT NULL`).Scan(&rows).Error; err != nil {
		return "查詢失敗：" + err.Error()
	}
	return strings.Join(rows, "; ")
}

func (e *sessionLockEnv) op() identity.Operator {
	return identity.Operator{UserID: e.root, Username: "slo-root", ClientIP: "127.0.0.1"}
}

// installAppHooks 以「停點名稱@連線池名稱」分派的通用停點（身分與授權兩個套件的掛點都設）；
// 只有 filter 回 true 的呼叫才停。回傳的函式放行全部停點並解除掛點。
func (e *sessionLockEnv) installAppHooks(stops map[string]*sessionLockStop, filter func(point string, ids []uint) bool) func() {
	dispatch := func(point string, tx *gorm.DB, ids ...uint) {
		if tx == nil || !filter(point, ids) {
			return
		}
		var app string
		if err := tx.Raw("SELECT current_setting('application_name')").Scan(&app).Error; err != nil {
			return
		}
		if st := stops[point+"@"+app]; st != nil {
			st.hit(tx)
		}
	}
	restoreIdentity := identity.SetLockOrderHookForTest(dispatch)
	restoreAuthz := authz.SetLockOrderHookForTest(dispatch)
	return func() {
		for _, st := range stops {
			st.open()
		}
		restoreAuthz()
		restoreIdentity()
	}
}

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// eachOrder 兩種先後。名稱中的參與者是 design 子案例表的先行者。
func eachOrder(t *testing.T, a, b string, fn func(t *testing.T, order string)) {
	for _, order := range []string{a + "_released_first", b + "_released_first"} {
		t.Run(order, func(t *testing.T) { fn(t, order) })
	}
}

// sessionLockStop 一個停點：交易走到時回報自己的 backend pid，然後等待放行。
type sessionLockStop struct {
	reached chan int64
	release chan struct{}
	once    sync.Once
	rel     sync.Once
}

func newSessionLockStop() *sessionLockStop {
	return &sessionLockStop{reached: make(chan int64, 1), release: make(chan struct{})}
}

func (s *sessionLockStop) hit(tx *gorm.DB) {
	var pid int64 // 0 表示掛點不帶交易，pid 由呼叫端依連線池名稱解析
	if tx != nil {
		if err := tx.Raw("SELECT pg_backend_pid()").Scan(&pid).Error; err != nil {
			pid = -1
		}
	}
	s.once.Do(func() { s.reached <- pid })
	<-s.release
}

func (s *sessionLockStop) open() { s.rel.Do(func() { close(s.release) }) }

func awaitSessionStop(t *testing.T, s *sessionLockStop, what string) int64 {
	t.Helper()
	select {
	case pid := <-s.reached:
		require.NotEqual(t, int64(-1), pid)
		return pid
	case <-time.After(sessionLockDeadline):
		t.Fatalf("%s 未走到停點", what)
		return 0
	}
}

// sessionBlockProof 一筆等待證明：waiter 有未授予的鎖，holder 有已授予、指向同一資源的鎖，且 holder 在 waiter 的 blockers 內。
type sessionBlockProof struct {
	locktype, wmode, hmode string
	kind                   string // advisory | row
	key                    string // 實際鎖鍵（advisory：資料庫 OID、classid、objid、objsubid；row：交易 ID）
}

// caseBackends 斷言兩個 pid 都是本次執行的連線池在本資料庫的連線（連線歸屬）。
func (e *sessionLockEnv) caseBackends(t *testing.T, pids ...int64) {
	t.Helper()
	for _, pid := range pids {
		var n int64
		require.NoError(t, e.obs.Raw(`SELECT count(*) FROM pg_stat_activity
 WHERE pid = ? AND datname = current_database() AND application_name IN (?, ?)`, pid, e.appA, e.appB).Scan(&n).Error)
		require.EqualValues(t, 1, n, "pid %d 不是本次執行的連線池在本資料庫的連線", pid)
	}
}

// awaitBlocked 觀測連線正向證明 waiter 正在等 holder。
//   - advisory 支路：資料庫 OID、classid（sessionLockCredentialClass）、objid（使用者 id）、objsubid（兩參數空間為 2）
//     都必須等於預期；advisoryUser 為 0 表示本情境不應出現 advisory 等待。
//   - 列鎖支路（transactionid／tuple）：保留 waiter 與 holder 同一 transactionid 等欄位的配對與 pg_blocking_pids 檢查；
//     pid 的資料庫歸屬以 pg_stat_activity 核對（transactionid 鎖的 database 欄為 NULL，不直接比）。
//   - waiterDone 是 waiter 那一方入口的結束通道：waiter 在被證明等待之前就結束，表示它沒有被 holder 擋住，
//     立即以清楚訊息失敗，不空等到 deadline。
func (e *sessionLockEnv) awaitBlocked(t *testing.T, waiter, holder int64, advisoryUser uint, waiterDone <-chan error) sessionBlockProof {
	t.Helper()
	e.caseBackends(t, waiter, holder)
	deadline := time.Now().Add(sessionLockDeadline)
	for time.Now().Before(deadline) {
		var rows []struct {
			Locktype, Wmode, Hmode string
			Database, Classid      *int64
			Objid                  *int64
			Objsubid               *int64
			Xid                    *string
		}
		require.NoError(t, e.obs.Raw(`SELECT w.locktype AS locktype, w.mode AS wmode, h.mode AS hmode,
   w.database::bigint AS database, w.classid::bigint AS classid, w.objid::bigint AS objid,
   w.objsubid::bigint AS objsubid, w.transactionid::text AS xid
 FROM pg_locks w JOIN pg_locks h
   ON h.pid = ? AND h.granted
  AND h.locktype = w.locktype
  AND h.database IS NOT DISTINCT FROM w.database
  AND h.relation IS NOT DISTINCT FROM w.relation
  AND h.page IS NOT DISTINCT FROM w.page
  AND h.tuple IS NOT DISTINCT FROM w.tuple
  AND h.virtualxid IS NOT DISTINCT FROM w.virtualxid
  AND h.transactionid IS NOT DISTINCT FROM w.transactionid
  AND h.classid IS NOT DISTINCT FROM w.classid
  AND h.objid IS NOT DISTINCT FROM w.objid
  AND h.objsubid IS NOT DISTINCT FROM w.objsubid
 WHERE w.pid = ? AND NOT w.granted AND ? = ANY(pg_blocking_pids(w.pid))
 ORDER BY (w.locktype = 'advisory') DESC`, holder, waiter, holder).Scan(&rows).Error)
		if len(rows) > 0 {
			r := rows[0]
			pf := sessionBlockProof{locktype: r.Locktype, wmode: r.Wmode, hmode: r.Hmode}
			switch r.Locktype {
			case "advisory":
				pf.kind = "advisory"
				require.NotZero(t, advisoryUser, "此情境不預期 advisory 等待（實際鎖鍵 class=%v id=%v）", r.Classid, r.Objid)
				require.NotNil(t, r.Database)
				require.NotNil(t, r.Classid)
				require.NotNil(t, r.Objid)
				require.NotNil(t, r.Objsubid)
				require.Equal(t, e.dbOID, *r.Database, "advisory 鎖的資料庫 OID")
				require.EqualValues(t, sessionLockCredentialClass, *r.Classid, "advisory 鎖的 classid")
				require.EqualValues(t, advisoryUser, *r.Objid, "advisory 鎖的 objid（本案例使用者 id）")
				require.EqualValues(t, 2, *r.Objsubid, "兩參數 advisory 空間的 objsubid")
				pf.key = fmt.Sprintf("db=%d,class=%d,id=%d,sub=%d", *r.Database, *r.Classid, *r.Objid, *r.Objsubid)
			case "transactionid", "tuple":
				pf.kind = "row"
				if r.Xid != nil {
					pf.key = "xid=" + *r.Xid
				} else {
					pf.key = "tuple"
				}
			default:
				t.Fatalf("非預期的等待鎖型別 %s", r.Locktype)
			}
			return pf
		}
		select {
		case err := <-waiterDone:
			t.Fatalf("pid %d 在被觀測到等待 pid %d 之前就已結束（err=%v）：後行者沒有被先行者擋住", waiter, holder, err)
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("pid %d 未被觀測到正在等 pid %d 已持有的同一把鎖", waiter, holder)
	return sessionBlockProof{}
}

// pidBlockedBy 某連線池中被 holder 擋住的連線 pid（0＝目前沒有）。
// 用於後行者尚未走到自己的停點、因修後鎖序更早被擋時，仍由「被本案例先行交易擋住」這個事實綁定其 pid。
func (e *sessionLockEnv) pidBlockedBy(t *testing.T, app string, holder int64) int64 {
	t.Helper()
	var pids []int64
	require.NoError(t, e.obs.Raw(`SELECT pid FROM pg_stat_activity
 WHERE datname = current_database() AND application_name = ? AND ? = ANY(pg_blocking_pids(pid))`, app, holder).Scan(&pids).Error)
	if len(pids) == 1 {
		return pids[0]
	}
	return 0
}

// pidOfApp 取本次執行的某個連線池（名稱含隨機尾碼、限本資料庫）下唯一一條「停在交易中」的連線 pid，
// 只在掛點簽名不帶交易時使用（群組刪除的兩個停點與帳號憑證寫入前的停點）。並驗證該連線確實在交易中。
func (e *sessionLockEnv) pidOfApp(t *testing.T, app string) int64 {
	t.Helper()
	deadline := time.Now().Add(sessionLockDeadline)
	for time.Now().Before(deadline) {
		var pids []int64
		require.NoError(t, e.obs.Raw(`SELECT pid FROM pg_stat_activity
 WHERE datname = current_database() AND application_name = ? AND usename = current_user
   AND state = 'idle in transaction' AND xact_start IS NOT NULL AND pid <> pg_backend_pid()`, app).Scan(&pids).Error)
		if len(pids) == 1 {
			e.caseBackends(t, pids[0])
			return pids[0]
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("連線池 %s 沒有恰好一條停在交易中的連線", app)
	return 0
}

func pgCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

func recvErr(t *testing.T, ch <-chan error, what string) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(sessionLockDeadline):
		t.Fatalf("%s 在 deadline 內未返回", what)
		return nil
	}
}

func (e *sessionLockEnv) scalar(t *testing.T, sql string, args ...any) int64 {
	t.Helper()
	var n int64
	require.NoError(t, e.obs.Raw(sql, args...).Scan(&n).Error)
	return n
}

func (e *sessionLockEnv) auditCount(t *testing.T, resource model.AuditResource, id uint, action model.AuditAction) int64 {
	return e.scalar(t, `SELECT count(*) FROM audit_logs WHERE resource = ? AND resource_id = ? AND action = ?`, string(resource), id, string(action))
}

// sessionLockActor 一個交錯參與者：start 啟動它的入口並回傳結束時的錯誤，
// stop 是它的停點，app 是它所用連線池的名稱（掛點不帶交易時用來解析 pid）。
type sessionLockActor struct {
	name  string
	stop  *sessionLockStop
	app   string
	start func() error
}

// sessionCyclePlan design 子案例表對「某一方當先行者」的修後類別：
// class 為 wait 或 nowait；wait 時 kind 為修後等待的鎖種類（advisory 或 row），advisoryUser 為 advisory 的使用者 id。
type sessionCyclePlan struct {
	class        string
	kind         string
	advisoryUser uint
}

// sessionCycleSpec 一個交錯：兩個參與者各有停點，之後互相請求對方的資源。
// plans 以先行者名稱為鍵；order 的名稱（"<參與者名>_released_first"）即 design 子案例表的先行者。
// snap 讀出交錯前後的可觀測資料，want 依實際提交者算出預期的資料。
type sessionCycleSpec struct {
	subcase string
	shared  string // 例：users:12
	a, b    sessionLockActor
	plans   map[string]sessionCyclePlan
	snap    func() map[string]int64
	want    func(base map[string]int64, committed map[string]bool, lead string) map[string]int64
}

// followerStatus 後行者在 wait 類：要嘛走到自己的停點（紅燈，或綠燈中該停點早於被擋處），
// 要嘛在到達停點前就被先行者擋住（綠燈鎖序更早取鎖）。回傳 pid 與是否已停在停點。
func (e *sessionLockEnv) awaitFollower(t *testing.T, f sessionLockActor, pidLead int64, done <-chan error) (int64, bool) {
	t.Helper()
	deadline := time.Now().Add(sessionLockDeadline)
	for time.Now().Before(deadline) {
		select {
		case pid := <-f.stop.reached:
			if pid == 0 {
				pid = e.pidOfApp(t, f.app)
			}
			require.NotEqual(t, int64(-1), pid)
			return pid, true
		case err := <-done:
			t.Fatalf("%s 在證明等待之前就返回了（err=%v）：wait 類不應如此", f.name, err)
		default:
		}
		if pid := e.pidBlockedBy(t, f.app, pidLead); pid != 0 {
			return pid, false
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s 既未走到停點也未被先行者擋住", f.name)
	return 0, false
}

// runCycle 依 order 的先行者與 plans 的類別調度：
//   - wait：先行者停住；後行者若到達自己的停點就放行它（它會被先行者擋住），若在停點之前就被擋則直接取證；
//     以 pg_locks 正向證明後行者在等先行者之後才放行先行者。紅燈與綠燈共用這個調度：紅燈中後行者放行後等先行者、
//     先行者放行後回頭等後行者，成環；綠燈中先行者放行後完成，後行者隨後完成。
//   - nowait：先行者停住；後行者放行並應完成，此時先行者仍須停在交易內（pg_stat_activity.state = idle in transaction），之後才放行先行者。
//     紅燈中後行者被先行者擋住（取證後放行先行者，成環）。
//
// 回傳 sqlstate 與 victim；死結時先驗 survivor／victim 的資料，再以未死結的斷言使本案例失敗。
func (e *sessionLockEnv) runCycle(t *testing.T, sp sessionCycleSpec, order string) (sqlstate, victim string) {
	t.Helper()
	leadName := strings.TrimSuffix(order, "_released_first")
	lead, follow := sp.a, sp.b
	switch leadName {
	case sp.a.name:
	case sp.b.name:
		lead, follow = sp.b, sp.a
	default:
		t.Fatalf("order %q 不屬於此子案例的參與者", order)
	}
	plan, ok := sp.plans[leadName]
	require.True(t, ok, "缺少先行者 %s 的類別", leadName)
	require.Contains(t, []string{"wait", "nowait"}, plan.class)
	base := sp.snap()

	doneLead, doneFollow := make(chan error, 1), make(chan error, 1)
	go func() { doneLead <- lead.start() }()
	pidLead := awaitSessionStop(t, lead.stop, lead.name)
	if pidLead == 0 {
		pidLead = e.pidOfApp(t, lead.app)
	}
	e.caseBackends(t, pidLead)
	go func() { doneFollow <- follow.start() }()

	var (
		proof     *sessionBlockProof
		pidFollow int64
		leadState string
		errFollow error
		gotFollow bool
	)
	if plan.class == "wait" {
		pid, atStop := e.awaitFollower(t, follow, pidLead, doneFollow)
		pidFollow = pid
		if atStop {
			follow.stop.open()
		}
		pf := e.awaitBlocked(t, pidFollow, pidLead, plan.advisoryUser, doneFollow)
		proof = &pf
		follow.stop.open()
		lead.stop.open()
	} else {
		deadline := time.Now().Add(sessionLockDeadline)
		for !gotFollow && proof == nil {
			if time.Now().After(deadline) {
				t.Fatalf("nowait 後行者 %s 既未完成也未被擋住", follow.name)
			}
			select {
			case pid := <-follow.stop.reached:
				if pid == 0 {
					pid = e.pidOfApp(t, follow.app)
				}
				pidFollow = pid
				follow.stop.open()
				continue
			case errFollow = <-doneFollow:
				gotFollow = true
				continue
			default:
			}
			if pid := e.pidBlockedBy(t, follow.app, pidLead); pid != 0 {
				pidFollow = pid
				pf := e.awaitBlocked(t, pid, pidLead, 0, doneFollow)
				proof = &pf
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if gotFollow {
			require.NotZero(t, pidFollow, "%s 沒有走到自己的停點就完成", follow.name)
			require.NoError(t, e.obs.Raw("SELECT state FROM pg_stat_activity WHERE pid = ?", pidLead).Scan(&leadState).Error)
		}
		follow.stop.open()
		lead.stop.open()
	}

	errLead := recvErr(t, doneLead, lead.name)
	if !gotFollow {
		errFollow = recvErr(t, doneFollow, follow.name)
	}
	errs := map[string]error{lead.name: errLead, follow.name: errFollow}
	sqlstate, victim = "none", "none"
	victims := 0
	committed := map[string]bool{}
	for _, name := range []string{sp.a.name, sp.b.name} {
		c := pgCode(errs[name])
		require.NotEqual(t, "55P03", c, "lock_timeout 先於死結偵測觸發，不算死結證據")
		if c == "40P01" {
			sqlstate, victim = c, name
			victims++
		} else {
			committed[name] = true
		}
	}
	mode, key, blocked, kind := "nowait", "-", "-", "-"
	if proof != nil {
		mode, key, blocked, kind = "wait", proof.key, proof.locktype+"/"+proof.wmode+"/"+proof.hmode, proof.kind
	}
	pids := fmt.Sprintf("%d,%d", pidLead, pidFollow)
	if lead.name == sp.b.name {
		pids = fmt.Sprintf("%d,%d", pidFollow, pidLead)
	}
	t.Logf("EVIDENCE dialect=postgres subcase=%s order=%s lead=%s pids=%s shared=%s attested=false mode=%s expected_mode=%s sqlstate=%s victim=%s blocked=%s kind=%s key=%s lead_state=%q fks=%s",
		sp.subcase, order, lead.name, pids, sp.shared, mode, plan.class, sqlstate, victim, blocked, kind, key, leadState, strings.Join(e.fks, ","))

	if sqlstate == "40P01" {
		// 紅燈：恰一方為 victim，另一方（survivor）的錯誤為 nil；survivor 的提交效果在、victim 全部回滾
		require.Equal(t, 1, victims, "恰一方為 victim")
		for _, name := range []string{sp.a.name, sp.b.name} {
			if name != victim {
				require.NoError(t, errs[name], "survivor %s 必須成功", name)
			}
		}
		got := sp.snap()
		wantData := sp.want(base, committed, leadName)
		require.Equal(t, wantData, got, "紅燈後的資料：survivor 的提交效果在、victim 全回滾（committed=%v）", committed)
		t.Logf("RED_DATA_OK subcase=%s order=%s victim=%s committed=%v", sp.subcase, order, victim, committed)
		require.Equal(t, "none", sqlstate, "兩筆交易不得互相死結（%s=%v %s=%v）", lead.name, errLead, follow.name, errFollow)
	}
	require.NoError(t, errLead, lead.name)
	require.NoError(t, errFollow, follow.name)
	require.Equal(t, plan.class, mode, "實跑類別必須等於 design 的綠燈類別")
	if plan.class == "wait" {
		require.Equal(t, plan.kind, proof.kind, "修後等待的鎖種類")
	} else {
		require.Equal(t, "idle in transaction", leadState, "nowait：後行完成時先行必須仍停在交易內")
	}
	got := sp.snap()
	wantData := sp.want(base, map[string]bool{sp.a.name: true, sp.b.name: true}, leadName)
	require.Equal(t, wantData, got, "綠燈後的資料等於依序執行（先行者 %s 在前）的結果", leadName)
	t.Logf("GREEN_DATA_OK subcase=%s order=%s", sp.subcase, order)
	return sqlstate, victim
}
