package identity

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
	"github.com/custodexa/backend/internal/testgate"
)

// 使用者層鎖序的真 PostgreSQL 交錯測試。
//
// fixture 用正式 migration 建表（含正式外鍵），兩個獨立連線池各代表一個後端副本，
// 另有一條觀測連線。交錯以測試掛點固定：先行交易停在已取得共用資源處，後行交易以自然流程
// 取得另一把後請求前者。連線層 lock_timeout 30 秒、測試 deadline 90 秒；
// 出現 55P03 判失敗（表示 lock_timeout 先擋，不是死結偵測）。
//
//	TEST_PG_DSN="host=... user=... password=... dbname=... sslmode=disable" \
//	  REQUIRE_INTEGRATION=1 go test ./internal/modules/identity -run '^TestUserLockOrderPG$' -count=1 -v

const (
	lockOrderSchema   = "lock_order_test"
	lockOrderDeadline = 90 * time.Second
)

// lockOrderFKs 清冊用到的正式外鍵名稱，開跑前以 pg_constraint 斷言存在。
var lockOrderFKs = []string{
	"fk_users_owner",
	"fk_user_group_members_user",
	"fk_user_group_members_user_group",
}

type lockOrderEnv struct {
	dbA, dbB, obs *gorm.DB
	// 本次執行唯一的連線池名稱（加隨機尾碼）與資料庫 OID：解析 pid 與等待證明都只認這組身分
	appA, appB, appObs string
	dbOID              int64
	groups             *UserGroupService // 副本 A
	users              *UserService      // 副本 B
	root               uint
	owner              uint
	newOwner           uint
	agent              uint
	group              uint
	role               uint
	fks                []string
}

func openLockOrderDB(t *testing.T, dsn string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err, "postgres 連線失敗")
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(6)
	t.Cleanup(func() { _ = sqlDB.Close() })
	return db
}

func newLockOrderEnv(t *testing.T, extraFKs ...string) *lockOrderEnv {
	t.Helper()
	base := testgate.Value(t, testgate.EnvPGDSN)
	// 管理連線也設 lock_timeout：上一個案例若留下未結束的交易，DROP SCHEMA 會在期限內失敗並列出殘留連線，而不是無限等待
	admin := openLockOrderDB(t, fmt.Sprintf("%s lock_timeout=%d", base, lockOrderDeadline.Milliseconds()))
	require.Equal(t, "postgres", admin.Dialector.Name())
	drop := "DROP SCHEMA IF EXISTS " + lockOrderSchema + " CASCADE"
	if err := admin.Exec(drop).Error; err != nil {
		t.Fatalf("測試 schema 重建失敗：%v；殘留連線：%s", err, lingeringBackends(admin))
	}
	require.NoError(t, admin.Exec("CREATE SCHEMA "+lockOrderSchema).Error)
	t.Cleanup(func() {
		if err := admin.Exec(drop).Error; err != nil {
			t.Errorf("測試 schema 清理失敗（請手動 DROP SCHEMA %s CASCADE）: %v；殘留連線：%s", lockOrderSchema, err, lingeringBackends(admin))
		}
	})
	scoped := base + " search_path=" + lockOrderSchema + " lock_timeout=30000"
	token := fmt.Sprintf("%d", time.Now().UnixNano())
	e := &lockOrderEnv{appA: "lock_order_a_" + token, appB: "lock_order_b_" + token, appObs: "lock_order_obs_" + token}
	e.dbA = openLockOrderDB(t, scoped+" application_name="+e.appA)
	e.dbB = openLockOrderDB(t, scoped+" application_name="+e.appB)
	e.obs = openLockOrderDB(t, scoped+" application_name="+e.appObs)
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
 WHERE n.nspname = ? AND c.contype = 'f' ORDER BY c.conname`, lockOrderSchema).Scan(&names).Error)
	have := map[string]bool{}
	for _, n := range names {
		have[n] = true
	}
	for _, want := range append(append([]string{}, lockOrderFKs...), extraFKs...) {
		require.True(t, have[want], "正式外鍵 %s 不存在", want)
	}
	e.fks = append(append([]string{}, lockOrderFKs...), extraFKs...)

	db := e.dbA
	role := func(name string) uint {
		var r model.Role
		if err := db.Where("name = ?", name).First(&r).Error; err != nil {
			r = model.Role{Name: name}
			require.NoError(t, db.Create(&r).Error)
		}
		return r.ID
	}
	human := func(name string) uint {
		u := model.User{Username: name, Active: true, Kind: model.KindHuman}
		require.NoError(t, db.Create(&u).Error)
		return u.ID
	}
	e.root = human("lo-root")
	e.owner = human("lo-owner")
	e.newOwner = human("lo-new-owner")
	adminRole := role(model.RoleAdmin)
	require.NoError(t, db.Create(&model.UserRole{UserID: e.root, RoleID: adminRole, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
	owner := e.owner
	agent := model.User{Username: "lo-agent", Active: true, Kind: model.KindAgent, OwnerUserID: &owner}
	require.NoError(t, db.Create(&agent).Error)
	e.agent = agent.ID
	e.role = role("lo-group-role")
	g := model.UserGroup{Name: "lo-group"}
	require.NoError(t, db.Create(&g).Error)
	e.group = g.ID
	require.NoError(t, db.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: e.agent, Manual: true}).Error)
	require.NoError(t, authz.ReplaceUserGroupRoleRows(db, g.ID, []uint{e.role}, nil))

	authzSvc := authz.NewAssetAuthorizationService(e.dbA)
	e.groups = NewUserGroupService(e.dbA, audit.NewTxSink(), authzSvc)
	e.groups.SetAssignmentGuard(NewAssignmentGuard(FullCatalog()))
	e.users = NewUserService(e.dbB, authz.NewAssetAuthorizationService(e.dbB))
	e.users.SetOwnerTransferGuard(authz.SelfGrantGuard{})
	e.users.SetAssignmentGuard(NewAssignmentGuard(FullCatalog()))
	return e
}

// lingeringBackends 列出本測試連線池中仍在交易內的連線（pid、連線池、狀態、交易時長），供清理失敗時定位。
func lingeringBackends(admin *gorm.DB) string {
	var rows []string
	if err := admin.Raw(`SELECT pid || ' ' || application_name || ' ' || state || ' ' || coalesce((now() - xact_start)::text, '-')
 FROM pg_stat_activity WHERE datname = current_database() AND application_name LIKE 'lock_order_%' AND xact_start IS NOT NULL`).Scan(&rows).Error; err != nil {
		return "查詢失敗：" + err.Error()
	}
	return strings.Join(rows, "; ")
}

func (e *lockOrderEnv) op() Operator {
	return Operator{UserID: e.root, Username: "lo-root", ClientIP: "127.0.0.1"}
}

// lockStop 一個停點：交易走到時回報自己的 backend pid，然後等待放行。
type lockStop struct {
	reached chan int64
	release chan struct{}
	once    sync.Once
	rel     sync.Once
}

func newLockStop() *lockStop {
	return &lockStop{reached: make(chan int64, 1), release: make(chan struct{})}
}

func (s *lockStop) hit(tx *gorm.DB) {
	var pid int64 // 0 表示掛點不帶交易，pid 由呼叫端依連線池名稱解析
	if tx != nil {
		if err := tx.Raw("SELECT pg_backend_pid()").Scan(&pid).Error; err != nil {
			pid = -1
		}
	}
	s.once.Do(func() { s.reached <- pid })
	<-s.release
}

func (s *lockStop) open() { s.rel.Do(func() { close(s.release) }) }

// installLockOrderHooks 以停點名稱分派；回傳的函式放行全部停點並解除掛點。
func installLockOrderHooks(stops map[string]*lockStop) func() {
	restore := SetLockOrderHookForTest(func(point string, tx *gorm.DB, _ ...uint) {
		if st := stops[point]; st != nil {
			st.hit(tx)
		}
	})
	return func() {
		for _, st := range stops {
			st.open()
		}
		restore()
	}
}

func awaitStop(t *testing.T, s *lockStop, what string) int64 {
	t.Helper()
	select {
	case pid := <-s.reached:
		require.NotEqual(t, int64(-1), pid)
		return pid
	case <-time.After(lockOrderDeadline):
		t.Fatalf("%s 未走到停點", what)
		return 0
	}
}

// blockProof 一筆等待證明：waiter 有未授予的鎖，holder 有已授予、指向同一資源的鎖，且 holder 在 waiter 的 blockers 內。
type blockProof struct {
	locktype, wmode, hmode string
	kind                   string // advisory | row
	key                    string // 實際鎖鍵（advisory：資料庫 OID、classid、objid、objsubid；row：交易 ID）
}

// caseBackends 斷言兩個 pid 都是本次執行的連線池在本資料庫的連線（連線歸屬）。
func (e *lockOrderEnv) caseBackends(t *testing.T, pids ...int64) {
	t.Helper()
	for _, pid := range pids {
		var n int64
		require.NoError(t, e.obs.Raw(`SELECT count(*) FROM pg_stat_activity
 WHERE pid = ? AND datname = current_database() AND application_name IN (?, ?)`, pid, e.appA, e.appB).Scan(&n).Error)
		require.EqualValues(t, 1, n, "pid %d 不是本次執行的連線池在本資料庫的連線", pid)
	}
}

// awaitBlocked 觀測連線正向證明 waiter 正在等 holder。
//   - advisory 支路：資料庫 OID、classid（userCredentialLockClass）、objid（使用者 id）、objsubid（兩參數空間為 2）
//     都必須等於預期；advisoryUser 為 0 表示本情境不應出現 advisory 等待。
//   - 列鎖支路（transactionid／tuple）：保留 waiter 與 holder 同一 transactionid 等欄位的配對與 pg_blocking_pids 檢查；
//     pid 的資料庫歸屬以 pg_stat_activity 核對（transactionid 鎖的 database 欄為 NULL，不直接比）。
//   - waiterDone 是 waiter 那一方入口的結束通道：waiter 在被證明等待之前就結束，表示它沒有被 holder 擋住，
//     立即以清楚訊息失敗，不空等到 deadline。
func (e *lockOrderEnv) awaitBlocked(t *testing.T, waiter, holder int64, advisoryUser uint, waiterDone <-chan error) blockProof {
	t.Helper()
	e.caseBackends(t, waiter, holder)
	deadline := time.Now().Add(lockOrderDeadline)
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
			pf := blockProof{locktype: r.Locktype, wmode: r.Wmode, hmode: r.Hmode}
			switch r.Locktype {
			case "advisory":
				pf.kind = "advisory"
				require.NotZero(t, advisoryUser, "此情境不預期 advisory 等待（實際鎖鍵 class=%v id=%v）", r.Classid, r.Objid)
				require.NotNil(t, r.Database)
				require.NotNil(t, r.Classid)
				require.NotNil(t, r.Objid)
				require.NotNil(t, r.Objsubid)
				require.Equal(t, e.dbOID, *r.Database, "advisory 鎖的資料庫 OID")
				require.EqualValues(t, userCredentialLockClass, *r.Classid, "advisory 鎖的 classid")
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
	return blockProof{}
}

// pidBlockedBy 某連線池中被 holder 擋住的連線 pid（0＝目前沒有）。
// 用於後行者尚未走到自己的停點、因修後鎖序更早被擋時，仍由「被本案例先行交易擋住」這個事實綁定其 pid。
func (e *lockOrderEnv) pidBlockedBy(t *testing.T, app string, holder int64) int64 {
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
func (e *lockOrderEnv) pidOfApp(t *testing.T, app string) int64 {
	t.Helper()
	deadline := time.Now().Add(lockOrderDeadline)
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
	case <-time.After(lockOrderDeadline):
		t.Fatalf("%s 在 deadline 內未返回", what)
		return nil
	}
}

func (e *lockOrderEnv) scalar(t *testing.T, sql string, args ...any) int64 {
	t.Helper()
	var n int64
	require.NoError(t, e.obs.Raw(sql, args...).Scan(&n).Error)
	return n
}

func (e *lockOrderEnv) auditCount(t *testing.T, resource model.AuditResource, id uint, action model.AuditAction) int64 {
	return e.scalar(t, `SELECT count(*) FROM audit_logs WHERE resource = ? AND resource_id = ? AND action = ?`, string(resource), id, string(action))
}

// lockActor 一個交錯參與者：start 啟動它的入口並回傳結束時的錯誤，
// stop 是它的停點，app 是它所用連線池的名稱（掛點不帶交易時用來解析 pid）。
type lockActor struct {
	name  string
	stop  *lockStop
	app   string
	start func() error
}

// cyclePlan design 子案例表對「某一方當先行者」的修後類別：
// class 為 wait 或 nowait；wait 時 kind 為修後等待的鎖種類（advisory 或 row），advisoryUser 為 advisory 的使用者 id。
type cyclePlan struct {
	class        string
	kind         string
	advisoryUser uint
}

// cycleSpec 一個交錯：兩個參與者各有停點，之後互相請求對方的資源。
// plans 以先行者名稱為鍵；order 的名稱（"<參與者名>_released_first"）即 design 子案例表的先行者。
// snap 讀出交錯前後的可觀測資料，want 依實際提交者算出預期的資料。
type cycleSpec struct {
	subcase string
	shared  string // 例：users:12
	a, b    lockActor
	plans   map[string]cyclePlan
	snap    func() map[string]int64
	want    func(base map[string]int64, committed map[string]bool, lead string) map[string]int64
}

// followerStatus 後行者在 wait 類：要嘛走到自己的停點（紅燈，或綠燈中該停點早於被擋處），
// 要嘛在到達停點前就被先行者擋住（綠燈鎖序更早取鎖）。回傳 pid 與是否已停在停點。
func (e *lockOrderEnv) awaitFollower(t *testing.T, f lockActor, pidLead int64, done <-chan error) (int64, bool) {
	t.Helper()
	deadline := time.Now().Add(lockOrderDeadline)
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
func (e *lockOrderEnv) runCycle(t *testing.T, sp cycleSpec, order string) (sqlstate, victim string) {
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
	pidLead := awaitStop(t, lead.stop, lead.name)
	if pidLead == 0 {
		pidLead = e.pidOfApp(t, lead.app)
	}
	e.caseBackends(t, pidLead)
	go func() { doneFollow <- follow.start() }()

	var (
		proof     *blockProof
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
		deadline := time.Now().Add(lockOrderDeadline)
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

func TestUserLockOrderPG(t *testing.T) {
	t.Run("m1_group_role_remove_vs_owner_transfer", func(t *testing.T) { runM1(t) })
	t.Run("group_member_fk_vs_group_role_replace", func(t *testing.T) { runG1(t) })
	t.Run("group_delete_prefetch", func(t *testing.T) { runG2(t) })
	t.Run("mapping_creator_fk_vs_user_write", func(t *testing.T) {
		t.Run("role", func(t *testing.T) { runMappingCreator(t, "role") })
		t.Run("group", func(t *testing.T) { runMappingCreator(t, "group") })
	})
	t.Run("mapping_replacement_same_creator", func(t *testing.T) { runMappingReplacementSameCreator(t) })
	t.Run("token_owner_after_agent_vs_sorted_subjects", func(t *testing.T) { runTokenOwnerVsSortedSubjects(t) })
	t.Run("agent_self_create_vs_owner_role_revoke", func(t *testing.T) { runAgentSelfCreateVsOwnerRoleRevoke(t) })
	t.Run("owner_transfer_fk_vs_group_add", func(t *testing.T) { runOwnerTransferVsGroupAdd(t) })
	t.Run("member_replace_prefetch", func(t *testing.T) { runMemberReplacePrefetch(t) })
	t.Run("mapping_join_between_prefetch_and_losers", func(t *testing.T) { runMappingJoinBetweenPrefetchAndLosers(t) })
	t.Run("mapping_revoke_multi_user", func(t *testing.T) {
		t.Run("normal", func(t *testing.T) { runMappingRevokeMultiUser(t, "normal") })
		t.Run("expiry", func(t *testing.T) { runMappingRevokeMultiUser(t, "expiry") })
		// 取鎖順序：憑證鎖（advisory）早於第一次推進為回歸守衛；users 列鎖早於第一次推進需要正式修正
		for _, sub := range []string{"normal", "expiry"} {
			for _, kind := range []string{"advisory", "row"} {
				sub, kind := sub, kind
				t.Run(sub+"_"+kind+"_lock_before_advance", func(t *testing.T) { runMappingRevokeLockOrder(t, sub, kind) })
			}
		}
	})
	t.Run("request_fk_vs_group_add", func(t *testing.T) {
		t.Run("submit_executor", func(t *testing.T) { runRequestFKVsGroupAdd(t, "submit_executor") })
		t.Run("decide_approver", func(t *testing.T) { runRequestFKVsGroupAdd(t, "decide_approver") })
	})
	t.Run("grant_actor_fk_vs_group_add", func(t *testing.T) {
		t.Run("single", func(t *testing.T) { runGrantActorVsGroupAdd(t, "single") })
		t.Run("batch", func(t *testing.T) { runGrantActorVsGroupAdd(t, "batch") })
	})
	t.Run("row_only_sorted_users", func(t *testing.T) { runRowOnlySortedUsers(t) })
	t.Run("orphan_and_soft_deleted", func(t *testing.T) { runOrphanAndSoftDeleted(t) })
	t.Run("auth_capability_paths", func(t *testing.T) { runAuthCapabilityPaths(t) })
}

// eachOrder 兩種先後。名稱中的參與者是 design 子案例表的先行者（綠燈中先取得共用資源並停住的一方），
// 後綴沿用既有的 released_first 以維持證據檔的連續性。
func eachOrder(t *testing.T, a, b string, fn func(t *testing.T, order string)) {
	for _, order := range []string{a + "_released_first", b + "_released_first"} {
		t.Run(order, func(t *testing.T) { fn(t, order) })
	}
}

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// runM1：群組角色替換（移除成員 A 唯一的角色，A 是真 loser）與 A 的擁有者轉移。
// 群組停在推進版本之後、loser 世代更新之前（持 authz_state 列）；
// 轉移停在 guard 鎖 A 之後、推進版本之前（持 A 的使用者列）。
// 兩種先後修後都是 wait（等 A 的使用者列鎖）；兩者互不影響，最終資料等於兩者都提交。
func runM1(t *testing.T) {
	eachOrder(t, "group", "transfer", func(t *testing.T, order string) {
		e := newLockOrderEnv(t)

		// fixture 自檢：A 只經群組 G 擁有被移除的角色；新擁有者不會被轉移 guard 拒絕
		losers, err := authz.MembersLosingRoles(e.dbA, e.group, []uint{e.role})
		require.NoError(t, err)
		require.Contains(t, losers, e.agent, "A 必須是真 loser")
		probe := errors.New("rollback-probe")
		var guard authz.SelfGrantGuard
		err = e.dbA.Transaction(func(tx *gorm.DB) error {
			if gerr := guard.CheckOwnerTransfer(tx, e.agent, e.newOwner); gerr != nil {
				return gerr
			}
			return probe
		})
		require.ErrorIs(t, err, probe, "轉移 guard 不得拒絕新擁有者")

		stops := map[string]*lockStop{
			"group_roles_after_advance":  newLockStop(),
			"owner_transfer_after_guard": newLockStop(),
		}
		release := installLockOrderHooks(stops)
		defer release()
		snap := func() map[string]int64 {
			return map[string]int64{
				"authz_version":           e.scalar(t, "SELECT version FROM authz_state WHERE id = 1"),
				"agent_epoch":             e.scalar(t, "SELECT credential_epoch FROM users WHERE id = ?", e.agent),
				"group_roles":             e.scalar(t, "SELECT count(*) FROM user_group_roles WHERE user_group_id = ?", e.group),
				"owner_is_new":            e.scalar(t, "SELECT count(*) FROM users WHERE id = ? AND owner_user_id = ?", e.agent, e.newOwner),
				"audit_group_role_revoke": e.auditCount(t, model.ResourceUserGroupRole, e.group, model.ActionRevoke),
				"audit_agent_update":      e.auditCount(t, model.ResourceUser, e.agent, model.ActionUpdate),
			}
		}
		want := func(base map[string]int64, c map[string]bool, _ string) map[string]int64 {
			g, x := b2i(c["group"]), b2i(c["transfer"])
			return map[string]int64{
				// 兩個入口各自推進一次權限版本；loser 的憑證世代只由群組推進
				"authz_version":           base["authz_version"] + g + x,
				"agent_epoch":             base["agent_epoch"] + g,
				"group_roles":             base["group_roles"] - g,
				"owner_is_new":            base["owner_is_new"] + x,
				"audit_group_role_revoke": base["audit_group_role_revoke"] + g,
				"audit_agent_update":      base["audit_agent_update"] + x,
			}
		}
		e.runCycle(t, cycleSpec{
			subcase: "m1_group_role_remove_vs_owner_transfer",
			shared:  fmt.Sprintf("users:%d", e.agent),
			a: lockActor{name: "group", stop: stops["group_roles_after_advance"], app: e.appA, start: func() error {
				_, err := e.groups.ReplaceRoleBindings(e.op(), e.group, GroupRoleBindingsRequest{RoleIDs: nil})
				return err
			}},
			b: lockActor{name: "transfer", stop: stops["owner_transfer_after_guard"], app: e.appB, start: func() error {
				no := e.newOwner
				_, _, err := e.users.Update(e.agent, &UpdateUserRequest{OwnerUserID: &no})
				return err
			}},
			plans: map[string]cyclePlan{
				"group":    {class: "wait", kind: "row"},
				"transfer": {class: "wait", kind: "row"},
			},
			snap: snap, want: want,
		}, order)
	})
}

func (e *lockOrderEnv) externalUser(t *testing.T, name string) uint {
	t.Helper()
	u := model.User{Username: name, Active: true, Kind: model.KindHuman, ExternalCredential: true}
	require.NoError(t, e.dbA.Create(&u).Error)
	return u.ID
}

// runG1：U 是群組 G 的手動成員；群組角色替換停在取得 G 列鎖之後、取成員鎖之前，
// U 的登入重算持 U 的憑證鎖後寫 G 的映射支持列（指向 G 的外鍵取 G 的列鎖）。
// 群組先行修後是 nowait（外鍵 KS 與 G 的 NKU 相容，登入在群組停住時就完成）；登入先行是 wait（群組的預取等 U 的憑證鎖）。
func runG1(t *testing.T) {
	eachOrder(t, "group", "login", func(t *testing.T, order string) {
		e := newLockOrderEnv(t, "fk_ugmrs_group")
		u := e.externalUser(t, "lo-g1-user")
		g := model.UserGroup{Name: "lo-g1-group"}
		require.NoError(t, e.dbA.Create(&g).Error)
		require.NoError(t, e.dbA.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: u, Manual: true}).Error)
		p := model.OIDCProvider{Name: "lo-g1-provider", Issuer: "https://id.example.test", ClientID: "client", Enabled: true, AdmissionMode: model.AdmissionPreboundOnly, AdmissionRules: "{}"}
		require.NoError(t, e.dbA.Create(&p).Error)
		ext := model.ExternalGroup{OIDCProviderID: &p.ID, MatchValue: "lo-g1-ext"}
		require.NoError(t, e.dbA.Create(&ext).Error)
		rule := model.GroupUserGroupMapping{OIDCProviderID: &p.ID, ExternalGroupID: ext.ID, UserGroupID: g.ID, Enabled: true, CreatedBy: e.root}
		require.NoError(t, e.dbA.Create(&rule).Error)

		// fixture 自檢：U 是 G 的手動成員，支持列尚不存在
		var manual, supports int64
		require.NoError(t, e.obs.Table("user_group_members").Where("user_group_id = ? AND user_id = ? AND manual", g.ID, u).Count(&manual).Error)
		require.EqualValues(t, 1, manual)
		require.NoError(t, e.obs.Table("user_group_mapping_rule_supports").Where("user_id = ? AND user_group_id = ?", u, g.ID).Count(&supports).Error)
		require.EqualValues(t, 0, supports)

		stops := map[string]*lockStop{
			"group_roles_before_upfront": newLockStop(),
			"recompute_after_user_lock":  newLockStop(),
		}
		release := installLockOrderHooks(stops)
		defer release()
		var user model.User
		require.NoError(t, e.dbB.First(&user, u).Error)
		snap := func() map[string]int64 {
			return map[string]int64{
				"authz_version": e.scalar(t, "SELECT version FROM authz_state WHERE id = 1"),
				"group_roles":   e.scalar(t, "SELECT count(*) FROM user_group_roles WHERE user_group_id = ? AND role_id = ?", g.ID, e.role),
				"supports":      e.scalar(t, "SELECT count(*) FROM user_group_mapping_rule_supports WHERE user_id = ? AND user_group_id = ?", u, g.ID),
				"manual_member": e.scalar(t, "SELECT count(*) FROM user_group_members WHERE user_id = ? AND user_group_id = ? AND manual", u, g.ID),
				"audit_assign":  e.auditCount(t, model.ResourceUserGroupRole, g.ID, model.ActionAssign),
				// 登入方的群組映射審計（對象為 U、事件碼固定）與 U 的憑證世代：純新增支持列不得推進世代
				"audit_login_applied": e.scalar(t, `SELECT count(*) FROM audit_logs WHERE resource = ? AND resource_id = ? AND action = ? AND error_msg = ?`,
					string(model.ResourceUser), u, string(model.ActionUpdate), UserGroupMappingEventApplied),
				"user_epoch": e.scalar(t, "SELECT credential_epoch FROM users WHERE id = ?", u),
			}
		}
		want := func(base map[string]int64, c map[string]bool, _ string) map[string]int64 {
			gr, lg := b2i(c["group"]), b2i(c["login"])
			return map[string]int64{
				// 只有群組角色替換推進權限版本；登入只新增支持列，手動成員資格保留
				"authz_version": base["authz_version"] + gr,
				"group_roles":   base["group_roles"] + gr,
				"supports":      base["supports"] + lg,
				"manual_member": base["manual_member"],
				"audit_assign":  base["audit_assign"] + gr,
				// 登入方提交才有那一筆審計（victim 為登入方時隨交易回滾）；世代恆不變
				"audit_login_applied": base["audit_login_applied"] + lg,
				"user_epoch":          base["user_epoch"],
			}
		}
		e.runCycle(t, cycleSpec{
			subcase: "group_member_fk_vs_group_role_replace",
			shared:  fmt.Sprintf("users:%d,user_groups:%d", u, g.ID),
			a: lockActor{name: "group", stop: stops["group_roles_before_upfront"], app: e.appA, start: func() error {
				_, err := e.groups.ReplaceRoleBindings(e.op(), g.ID, GroupRoleBindingsRequest{RoleIDs: []uint{e.role}})
				return err
			}},
			b: lockActor{name: "login", stop: stops["recompute_after_user_lock"], app: e.appB, start: func() error {
				_, err := RecomputeMappedRoles(e.dbB, audit.NewTxSink(), &user, GroupObservation{
					Kind: model.RoleMappingChannelKindProvider, SourceID: p.ID,
					State: GroupObservationKnown, Groups: []string{"lo-g1-ext"}})
				return err
			}},
			plans: map[string]cyclePlan{
				"group": {class: "nowait"},
				"login": {class: "wait", kind: "advisory", advisoryUser: u},
			},
			snap: snap, want: want,
		}, order)
	})
}

// runG2：U 是群組 G 的成員，審核範圍 X 的申請群組為 G、審核人為 U。
// 群組刪除停在級聯撤銷之後（持被軟刪的 X），刪帳號 U 停在取得 U 的憑證鎖之後。
// 兩種先後修後都是 wait（等 U 的憑證鎖）；最終資料等於先行者在前的依序執行。
func runG2(t *testing.T) {
	eachOrder(t, "group_delete", "user_delete", func(t *testing.T, order string) {
		e := newLockOrderEnv(t)
		u := e.externalUser(t, "lo-g2-user")
		g := model.UserGroup{Name: "lo-g2-group"}
		require.NoError(t, e.dbA.Create(&g).Error)
		require.NoError(t, e.dbA.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: u, Manual: true}).Error)
		x := model.ApproverScope{ApproverID: &u, SubjectGroupID: &g.ID, GrantedBy: e.root}
		require.NoError(t, e.dbA.Create(&x).Error)

		// fixture 自檢：U ∈ G；X 的申請群組為 G、審核人為 U
		var member, scope int64
		require.NoError(t, e.obs.Table("user_group_members").Where("user_group_id = ? AND user_id = ?", g.ID, u).Count(&member).Error)
		require.EqualValues(t, 1, member)
		require.NoError(t, e.obs.Table("approver_scopes").Where("id = ? AND subject_group_id = ? AND approver_id = ? AND deleted_at IS NULL", x.ID, g.ID, u).Count(&scope).Error)
		require.EqualValues(t, 1, scope)

		groupStop, userStop := newLockStop(), newLockStop()
		restore := SetGroupDeleteLockHooksForTest(nil, func() { groupStop.hit(nil) })
		defer restore()
		oldHook := userCredentialPreWriteHook
		userCredentialPreWriteHook = func() { userStop.hit(nil) }
		defer func() { userCredentialPreWriteHook = oldHook }()
		defer groupStop.open()
		defer userStop.open()
		snap := func() map[string]int64 {
			return map[string]int64{
				"authz_version": e.scalar(t, "SELECT version FROM authz_state WHERE id = 1"),
				"scope_live":    e.scalar(t, "SELECT count(*) FROM approver_scopes WHERE id = ? AND deleted_at IS NULL", x.ID),
				// 原列必須仍在（軟刪而非硬刪），且 deleted_at 有值
				"scope_rows":        e.scalar(t, "SELECT count(*) FROM approver_scopes WHERE id = ?", x.ID),
				"scope_soft_marked": e.scalar(t, "SELECT count(*) FROM approver_scopes WHERE id = ? AND deleted_at IS NOT NULL", x.ID),
				"group_live":        e.scalar(t, "SELECT count(*) FROM user_groups WHERE id = ? AND deleted_at IS NULL", g.ID),
				"user_live":         e.scalar(t, "SELECT count(*) FROM users WHERE id = ? AND deleted_at IS NULL", u),
				"members":           e.scalar(t, "SELECT count(*) FROM user_group_members WHERE user_group_id = ?", g.ID),
				"user_epoch":        e.scalar(t, "SELECT credential_epoch FROM users WHERE id = ?", u),
				"audit_group_del":   e.auditCount(t, model.ResourceUserGroup, g.ID, model.ActionDelete),
				"audit_user_delete": e.auditCount(t, model.ResourceUser, u, model.ActionDelete),
			}
		}
		want := func(base map[string]int64, c map[string]bool, lead string) map[string]int64 {
			gd, ud := c["group_delete"], c["user_delete"]
			// 群組刪除只對提交當下仍是成員的 U 推進世代：帳號刪除先提交時 U 已不在成員列
			groupBumps := gd && !(ud && lead == "user_delete")
			return map[string]int64{
				"authz_version":     base["authz_version"] + b2i(gd) + b2i(ud),
				"scope_live":        base["scope_live"] - b2i(gd || ud),
				"scope_rows":        base["scope_rows"],
				"scope_soft_marked": base["scope_soft_marked"] + b2i(gd || ud),
				"group_live":        base["group_live"] - b2i(gd),
				"user_live":         base["user_live"] - b2i(ud),
				"members":           base["members"] - b2i(gd || ud),
				"user_epoch":        base["user_epoch"] + b2i(ud) + b2i(groupBumps),
				"audit_group_del":   base["audit_group_del"] + b2i(gd),
				"audit_user_delete": base["audit_user_delete"] + b2i(ud),
			}
		}
		e.runCycle(t, cycleSpec{
			subcase: "group_delete_prefetch",
			shared:  fmt.Sprintf("approver_scopes:%d,users:%d", x.ID, u),
			a: lockActor{name: "group_delete", stop: groupStop, app: e.appA, start: func() error {
				_, err := e.groups.DeleteBy(e.op(), g.ID)
				return err
			}},
			b: lockActor{name: "user_delete", stop: userStop, app: e.appB, start: func() error {
				_, err := e.users.DeleteWithSummary(u)
				return err
			}},
			plans: map[string]cyclePlan{
				"group_delete": {class: "wait", kind: "advisory", advisoryUser: u},
				"user_delete":  {class: "wait", kind: "advisory", advisoryUser: u},
			},
			snap: snap, want: want,
		}, order)
	})
}
