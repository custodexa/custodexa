package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
)

const bumpLockOrderSchema = "bump_lockorder_test"

// bumpLockOrderPG 是 TestAuthzStateVersionBump 的 `pg_lock_order` 子案例（PG-gated）。
//
// 擋的失敗：多使用者撤權迴圈邊走邊取使用者鎖，迴圈內的權限版本推進（authz_state 列鎖，持有到
// 交易結束）早於最後一把使用者鎖，與「先取使用者鎖、再推進」的單一使用者路徑反向等待，
// PostgreSQL 判定死結並中止其中一筆。
//
// 情境（確定性，不靠賽跑）：T2 先持有使用者 B 的鎖並通知，T1（撤權 A、B 兩人）才啟動，
// 之後 T2 才去推進版本。舊鎖序下 T1 持 authz_state 等 B 的鎖、T2 持 B 的鎖等 authz_state，
// 必然死結；新鎖序下 T1 先取齊 A、B 的鎖，T2 的推進排在 T1 之後，兩筆都成功。
//
// 範圍註記：本案例只是 seed 級冒煙（兩筆交易都成功、版本有推進），其中的固定等待沒有鎖等待的
// 觀測證據，不算鎖序交錯的證明；鎖序交錯的正向證明由另一組以鎖等待觀測為準的測試承擔。
func bumpLockOrderPG(t *testing.T) {
	dsn := pgLockTestDSN(t)
	admin := openPGLockDB(t, dsn)
	drop := "DROP SCHEMA IF EXISTS " + bumpLockOrderSchema + " CASCADE"
	if err := admin.Exec(drop).Error; err != nil {
		t.Fatalf("清理舊測試 schema: %v", err)
	}
	if err := admin.Exec("CREATE SCHEMA " + bumpLockOrderSchema).Error; err != nil {
		t.Fatalf("建立測試 schema: %v", err)
	}
	t.Cleanup(func() {
		if err := admin.Exec(drop).Error; err != nil {
			t.Errorf("測試 schema 清理失敗（請手動 DROP SCHEMA %s CASCADE）: %v", bumpLockOrderSchema, err)
		}
	})
	db := openPGLockDB(t, dsn+" search_path="+bumpLockOrderSchema)
	if db.Dialector.Name() != "postgres" {
		t.Fatalf("必須跑在 postgres，實得 %q", db.Dialector.Name())
	}
	extIdentityMigrate(t, db)
	if err := db.AutoMigrate(&model.UserGroup{}, &model.PasswordHistory{}, &model.SecurityPolicy{},
		&model.LDAPDirectory{}, &model.GroupRoleMapping{}, &model.ExternalGroup{},
		&model.GroupUserGroupMapping{}, &model.UserRoleMapping{},
		&model.UserRoleMappingRuleSupport{}, &model.UserGroupMappingRuleSupport{}, &model.UserChannelObservation{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.AutoMigrate(&model.UserGroupMember{}); err != nil {
		t.Fatalf("migrate user_group_members: %v", err)
	}
	seedAuthzState(t, db)
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })

	// 規則目標只認可直接映射的內建範本（自訂角色回 MAPPING_ROLE_NOT_DIRECT_MAPPABLE），
	// 寫入映射規則的操作者須是超級管理者
	root := seedAccount(t, db, adminSpec{username: "root-admin", active: true})
	ensureFixtureSuperAdmin(t, db, root.ID)
	actor := GroupRoleMappingActor{ID: root.ID, Name: "root-admin", IP: "10.0.0.1"}
	provider := seedExtProvider(t, db, "corp", "https://idp.example.com", "cid-1")
	channel := model.RoleMappingChannel(model.RoleMappingChannelKindProvider, provider.ID)
	role := &model.Role{Name: "auditor"}
	if err := db.Create(role).Error; err != nil {
		t.Fatalf("seed role: %v", err)
	}
	mapping := NewIdentitySourceService(db, audit.NewTxSink())
	rule, err := mapping.CreateMapping(model.RoleMappingChannelKindProvider, provider.ID,
		GroupRoleMappingInput{MatchValue: "ops", Role: role.Name, RiskAcknowledged: true, Actor: actor})
	if err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	var users []*model.User
	for _, name := range []string{"alice", "bob"} {
		u := seedAccount(t, db, adminSpec{username: name, active: true})
		if err := db.Create(&model.UserRole{UserID: u.ID, RoleID: role.ID, Source: model.RoleSourceMapped}).Error; err != nil {
			t.Fatalf("seed user_role: %v", err)
		}
		if err := upsertRoleMappingFact(db, u.ID, role.ID, channel, time.Now()); err != nil {
			t.Fatalf("seed mapping fact: %v", err)
		}
		if err := db.Create(&model.UserRoleMappingRuleSupport{UserID: u.ID, RoleID: role.ID, Channel: channel, RuleID: rule.ID}).Error; err != nil {
			t.Fatalf("seed support: %v", err)
		}
		users = append(users, u)
	}
	lo, hi := users[0], users[1]
	if lo.ID > hi.ID {
		lo, hi = hi, lo
	}
	before, err := authz.CurrentVersion(db)
	if err != nil {
		t.Fatalf("CurrentVersion: %v", err)
	}

	holding := make(chan struct{})
	var wg sync.WaitGroup
	var errMulti, errSingle error
	wg.Add(2)
	// T2：單一使用者路徑（先取使用者鎖，再推進版本），持鎖後等 T1 起跑
	go func() {
		defer wg.Done()
		errSingle = db.Transaction(func(tx *gorm.DB) error {
			return withUserCredentialLockTx(tx, hi.ID, func(locked *gorm.DB) error {
				close(holding)
				time.Sleep(1500 * time.Millisecond)
				return authz.AdvanceVersion(locked)
			})
		})
	}()
	// T1：多使用者撤權迴圈
	go func() {
		defer wg.Done()
		<-holding
		errMulti = db.Transaction(func(tx *gorm.DB) error {
			return revokeMappingSupportsLocked(tx, audit.NewTxSink(), model.RoleMappingChannelKindProvider,
				provider.ID, "source", 0)
		})
	}()
	wg.Wait()

	for name, e := range map[string]error{"多使用者撤權": errMulti, "單一使用者推進": errSingle} {
		if e != nil {
			hint := ""
			if strings.Contains(e.Error(), "deadlock") {
				hint = "（PostgreSQL 判定死結：多使用者迴圈內的版本推進早於最後一把使用者鎖）"
			}
			t.Errorf("%s失敗: %v%s", name, e, hint)
		}
	}
	after, err := authz.CurrentVersion(db)
	if err != nil {
		t.Fatalf("CurrentVersion: %v", err)
	}
	if after <= before {
		t.Fatalf("版本 %d -> %d：兩筆交易都成功卻沒有推進", before, after)
	}
}

const untracedUserLockSchema = "untraced_userlock_test"

// pidRecorder 在服務交易自己的連線上取後端 pid（以交易的連線池直接查，不另開連線）。
type pidRecorder struct {
	pid atomic.Int64
	err atomic.Value // error
}

func (r *pidRecorder) capture(tx *gorm.DB) {
	if r.pid.Load() != 0 {
		return
	}
	var pid int64
	if err := tx.Statement.ConnPool.QueryRowContext(tx.Statement.Context, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		r.err.Store(err)
		return
	}
	r.pid.CompareAndSwap(0, pid)
}

// installPermissionTestKey 註冊測試用完整性服務（與正式啟動同一建構路徑），使權限狀態事件帶驗證碼。
func installPermissionTestKey(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := db.AutoMigrate(&model.DataKey{}, &model.IntegrityBaseline{}); err != nil {
		t.Fatalf("migrate integrity tables: %v", err)
	}
	kek, err := crypto.NewEnvKEKProvider(make([]byte, 32))
	if err != nil {
		t.Fatalf("kek: %v", err)
	}
	km, err := keyvault.InitKeyManager(db, kek)
	if err != nil {
		t.Fatalf("key manager: %v", err)
	}
	if _, err := audit.InitAuditIntegrityVersioned(db, km); err != nil {
		t.Fatalf("integrity: %v", err)
	}
	t.Cleanup(func() { audit.ResetAuditIntegritySingleton(); model.SetAgentToolCallStampHook(nil) })
}

// replayPermissionEventsEqualActual 自啟用事件的事後狀態起，逐筆驗證碼、串接、摘要並重放差集，
// 最後的重放狀態須與資料庫現況的摘要相同（victim 的任何變更都不得留在差集或現況的任一邊）。
func replayPermissionEventsEqualActual(t *testing.T, db *gorm.DB) []model.PermissionStateEvent {
	t.Helper()
	var evs []model.PermissionStateEvent
	if err := db.Order("seq").Find(&evs).Error; err != nil {
		t.Fatalf("read events: %v", err)
	}
	if len(evs) == 0 {
		t.Fatal("事件鏈為空")
	}
	svc := audit.GetAuditIntegrity()
	if svc == nil {
		t.Fatal("完整性服務未註冊")
	}
	for i := range evs {
		if evs[i].Seq != int64(i+1) {
			t.Fatalf("事件鏈序號不連續：index=%d seq=%d", i, evs[i].Seq)
		}
		if i > 0 && evs[i].PrevDigest != evs[i-1].Digest {
			t.Fatalf("事件鏈 seq=%d 未串接", evs[i].Seq)
		}
		if !svc.VerifyPermissionEvent(&evs[i]) {
			t.Fatalf("事件 seq=%d 的完整性驗證碼不符", evs[i].Seq)
		}
	}
	state, err := audit.DecodePermissionState([]byte(evs[0].AfterBody))
	if err != nil {
		t.Fatalf("decode 啟用事件: %v", err)
	}
	for _, e := range evs[1:] {
		var d struct {
			audit.PermissionDelta
			Meta *audit.PermissionMeta `json:"meta"`
		}
		if err := json.Unmarshal([]byte(e.Delta), &d); err != nil || d.Meta == nil {
			t.Fatalf("seq=%d 差集無法解析: %v", e.Seq, err)
		}
		next, err := state.Apply(d.PermissionDelta)
		if err != nil {
			t.Fatalf("seq=%d 重放失敗: %v", e.Seq, err)
		}
		next.Meta = *d.Meta
		next.Meta.FormatVersion = audit.PermissionStateFormatVersion
		got, err := next.Digest()
		if err != nil || got != e.AfterDigest {
			t.Fatalf("seq=%d 重放後摘要與事件記載不符: %v", e.Seq, err)
		}
		state = next
	}
	replayed, err := state.Digest()
	if err != nil {
		t.Fatalf("replayed digest: %v", err)
	}
	actual, err := audit.ReadPermissionState(context.Background(), db)
	if err != nil {
		t.Fatalf("read actual state: %v", err)
	}
	want, err := actual.Digest()
	if err != nil {
		t.Fatalf("actual digest: %v", err)
	}
	if replayed != want {
		t.Fatalf("重放狀態與資料庫現況摘要不同：replayed=%s actual=%s", replayed, want)
	}
	return evs
}

// untracedVsUserLockDeadlockPG 是 TestAuthzStateVersionBump 的 `untraced_vs_user_lock_deadlock` 子案例（PG-gated）。
//
// 已知範圍的實測：附證已啟用、有一筆不經應用層的直寫漂移時，映射規則刪除先在 Begin 寫入未提交的
// untraced 事件、其後才取受影響使用者的鎖；同一位使用者的改密持該鎖後才進 Begin，也要寫同一序號的
// untraced 事件而等前者。兩邊互等，PostgreSQL 判定死結，恰一方 40P01、另一方提交，沒有半筆變更。
//
// 排程（不靠賽跑）：映射刪除停在取使用者鎖之前（untraced 已寫入、未提交）；改密取得使用者鎖後進 Begin，
// 以 pg_blocking_pids 與 pg_locks 證明改密交易的 pid 正被映射刪除交易的 pid 阻擋，之後才放行映射刪除去取鎖。
// 兩個服務各用獨立連線池與唯一的 application_name，pid 在各自交易內取得；觀測只看這兩個 pid。
func untracedVsUserLockDeadlockPG(t *testing.T) {
	dsn := pgLockTestDSN(t)
	admin := openPGLockDB(t, dsn)
	drop := "DROP SCHEMA IF EXISTS " + untracedUserLockSchema + " CASCADE"
	if err := admin.Exec(drop).Error; err != nil {
		t.Fatalf("清理舊測試 schema: %v", err)
	}
	if err := admin.Exec("CREATE SCHEMA " + untracedUserLockSchema).Error; err != nil {
		t.Fatalf("建立測試 schema: %v", err)
	}
	t.Cleanup(func() {
		if err := admin.Exec(drop).Error; err != nil {
			t.Errorf("測試 schema 清理失敗（請手動 DROP SCHEMA %s CASCADE）: %v", untracedUserLockSchema, err)
		}
	})
	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	appUser, appMap := "tuser_"+suffix, "tmap_"+suffix
	base := dsn + " search_path=" + untracedUserLockSchema
	db := openPGLockDB(t, base)
	dbUser := openPGLockDB(t, base+" application_name="+appUser)
	dbMap := openPGLockDB(t, base+" application_name="+appMap)
	if db.Dialector.Name() != "postgres" {
		t.Fatalf("必須跑在 postgres，實得 %q", db.Dialector.Name())
	}
	extIdentityMigrate(t, db)
	if err := db.AutoMigrate(&model.UserGroup{}, &model.PasswordHistory{}, &model.SecurityPolicy{},
		&model.LDAPDirectory{}, &model.GroupRoleMapping{}, &model.ExternalGroup{},
		&model.GroupUserGroupMapping{}, &model.UserRoleMapping{},
		&model.UserRoleMappingRuleSupport{}, &model.UserGroupMappingRuleSupport{}, &model.UserChannelObservation{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.AutoMigrate(&model.UserGroupMember{}); err != nil {
		t.Fatalf("migrate user_group_members: %v", err)
	}
	seedAuthzState(t, db)
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })
	installPermissionTestKey(t, db)

	root := seedAccount(t, db, adminSpec{username: "root-admin", active: true})
	ensureFixtureSuperAdmin(t, db, root.ID)
	actor := GroupRoleMappingActor{ID: root.ID, Name: "root-admin", IP: "10.0.0.1"}
	provider := seedExtProvider(t, db, "corp", "https://idp.example.com", "cid-1")
	channel := model.RoleMappingChannel(model.RoleMappingChannelKindProvider, provider.ID)
	role := &model.Role{Name: "auditor"}
	if err := db.Create(role).Error; err != nil {
		t.Fatalf("seed role: %v", err)
	}
	mapping := NewIdentitySourceService(dbMap, audit.NewTxSink())
	rule, err := mapping.CreateMapping(model.RoleMappingChannelKindProvider, provider.ID,
		GroupRoleMappingInput{MatchValue: "ops", Role: role.Name, RiskAcknowledged: true, Actor: actor})
	if err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	u := seedAccount(t, db, adminSpec{username: "target-user", active: true})
	if err := db.Create(&model.UserRole{UserID: u.ID, RoleID: role.ID, Source: model.RoleSourceMapped}).Error; err != nil {
		t.Fatalf("seed user_role: %v", err)
	}
	if err := upsertRoleMappingFact(db, u.ID, role.ID, channel, time.Now()); err != nil {
		t.Fatalf("seed mapping fact: %v", err)
	}
	if err := db.Create(&model.UserRoleMappingRuleSupport{UserID: u.ID, RoleID: role.ID, Channel: channel, RuleID: rule.ID}).Error; err != nil {
		t.Fatalf("seed support: %v", err)
	}
	users := newExtIdentityEnv(t, dbUser).svc

	activatePermissionEvents(t, db) // 啟用事件鏈（帶驗證碼）並植入一筆直寫漂移

	// 前置狀態快照（所有 Count 都檢查 .Error）
	count := func(what string, q *gorm.DB) int64 {
		t.Helper()
		var n int64
		if err := q.Count(&n).Error; err != nil {
			t.Fatalf("count %s: %v", what, err)
		}
		return n
	}
	type snap struct {
		rule, support, fact, effective, audits, history int64
		untraced, changes                               int64
		auditRevoke, auditDelete, auditRole             int64
		version                                         int64
		epoch                                           int
		hash                                            string
		pwChangedAt                                     string
		mustChange                                      bool
	}
	take := func() snap {
		t.Helper()
		var s snap
		s.rule = count("rule", db.Model(&model.GroupRoleMapping{}).Where("id = ?", rule.ID))
		s.support = count("support", db.Model(&model.UserRoleMappingRuleSupport{}).Where("rule_id = ?", rule.ID))
		s.fact = count("fact", db.Model(&model.UserRoleMapping{}).Where("user_id = ? AND role_id = ? AND channel = ?", u.ID, role.ID, channel))
		s.effective = count("effective", db.Model(&model.UserRole{}).Where("user_id = ? AND role_id = ?", u.ID, role.ID))
		s.audits = count("audits", db.Model(&model.AuditLog{}))
		// 映射刪除的三筆審計逐筆以對象與動作定址：有效角色撤銷與個人撤權（對象皆為該使用者）、規則刪除（對象為該規則）
		s.auditRevoke = count("audit revoke", db.Model(&model.AuditLog{}).Where(
			"action = ? AND resource = ? AND resource_id = ? AND error_msg = ?",
			model.ActionUpdate, model.ResourceUser, u.ID, MappingRuleRevokedEvent))
		s.auditRole = count("audit role", db.Model(&model.AuditLog{}).Where(
			"action = ? AND resource = ? AND resource_id = ?", model.ActionRevoke, model.ResourceUserRole, u.ID))
		s.auditDelete = count("audit delete", db.Model(&model.AuditLog{}).Where(
			"action = ? AND resource = ? AND resource_id = ?", model.ActionDelete, model.ResourceAuth, rule.ID))
		s.history = count("history", db.Model(&model.PasswordHistory{}).Where("user_id = ?", u.ID))
		s.untraced = count("untraced", db.Model(&model.PermissionStateEvent{}).Where("kind = ?", model.PermEventUntraced))
		s.changes = count("changes", db.Model(&model.PermissionStateEvent{}).Where("kind = ?", model.PermEventChange))
		var err error
		if s.version, err = authz.CurrentVersion(db); err != nil {
			t.Fatalf("CurrentVersion: %v", err)
		}
		if err := db.Raw(`SELECT password, credential_epoch, coalesce(password_changed_at::text, ''), must_change_password FROM users WHERE id = ?`,
			u.ID).Row().Scan(&s.hash, &s.epoch, &s.pwChangedAt, &s.mustChange); err != nil {
			t.Fatalf("read user: %v", err)
		}
		return s
	}
	before := take()
	if before.rule != 1 || before.support != 1 || before.fact != 1 || before.effective != 1 {
		t.Fatalf("前置狀態不符：%+v", before)
	}

	// 掛點：各服務的連線池各自取 pid、計 untraced 的 SAVEPOINT；映射刪除停在取使用者鎖之前。
	var savepoints atomic.Int32
	var pidUser, pidMap pidRecorder
	abort := make(chan struct{})
	var abortOnce sync.Once
	closeAbort := func() { abortOnce.Do(func() { close(abort) }) }
	t.Cleanup(closeAbort) // 提前失敗時一律放行所有掛點
	atLock, resume := make(chan struct{}), make(chan struct{})
	var resumeOnce, atLockOnce sync.Once
	resumeFn := func() { resumeOnce.Do(func() { close(resume) }) }
	t.Cleanup(resumeFn)
	register := func(d *gorm.DB, name string, rec *pidRecorder, pause bool) {
		cb := func(tx *gorm.DB) {
			sql := tx.Statement.SQL.String()
			if strings.HasPrefix(sql, "SAVEPOINT perm_untraced") {
				savepoints.Add(1)
				rec.capture(tx)
			}
			if pause && strings.Contains(sql, "pg_advisory_xact_lock") && len(tx.Statement.Vars) == 2 &&
				tx.Statement.Vars[0] == userCredentialLockClass && tx.Statement.Vars[1] == int32(u.ID) {
				atLockOnce.Do(func() { close(atLock) })
				select {
				case <-resume:
				case <-abort:
				case <-time.After(60 * time.Second):
				}
			}
		}
		if err := d.Callback().Raw().Before("gorm:raw").Register(name, cb); err != nil {
			t.Fatalf("register callback: %v", err)
		}
		t.Cleanup(func() { _ = d.Callback().Raw().Remove(name) })
	}
	register(dbUser, "pid_user", &pidUser, false)
	register(dbMap, "pid_map", &pidMap, true)

	waitUntil := func(what string, ok func() (bool, error)) {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		var last error
		for time.Now().Before(deadline) {
			done, err := ok()
			if err != nil {
				t.Fatalf("%s: %v", what, err)
			}
			if done {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("等待逾時: %s（%v）", what, last)
	}

	var errUser, errMap error
	userDone, mapDone := make(chan struct{}), make(chan struct{})
	go func() { // T_map：Begin 先寫 untraced，之後才取使用者鎖（停在取鎖前）
		defer close(mapDone)
		errMap = mapping.DeleteMapping(model.RoleMappingChannelKindProvider, provider.ID, rule.ID, actor)
	}()
	select {
	case <-atLock:
	case <-time.After(30 * time.Second):
		t.Fatal("映射刪除未到達取使用者鎖之前")
	}
	if pidMap.pid.Load() == 0 {
		t.Fatalf("未取得映射刪除交易的 pid：%v", pidMap.err.Load())
	}
	go func() { // T_user：取得使用者鎖後才進 Begin
		defer close(userDone)
		errUser = users.ChangePassword(u.ID, "Another-Password-9876")
	}()

	// 證明 T_user 的 pid 被 T_map 的 pid 阻擋（限定這兩個 pid；等的是 T_map 尚未提交的 transactionid）
	waitUntil("改密交易取得 pid 並被映射刪除交易阻擋", func() (bool, error) {
		pu, pm := pidUser.pid.Load(), pidMap.pid.Load()
		if pu == 0 {
			return false, nil
		}
		var by string
		if err := admin.Raw(`SELECT coalesce(array_to_string(pg_blocking_pids(?::int), ','), '')`, pu).Row().Scan(&by); err != nil {
			return false, err
		}
		if by != strconv.FormatInt(pm, 10) {
			return false, nil
		}
		var app string
		var locktype string
		var granted bool
		if err := admin.Raw(`SELECT a.application_name, l.locktype, l.granted FROM pg_stat_activity a
			JOIN pg_locks l ON l.pid = a.pid WHERE a.pid = ?::int AND NOT l.granted`, pu).Row().Scan(&app, &locktype, &granted); err != nil {
			return false, nil // 尚未出現未授予的鎖
		}
		if app != appUser || locktype != "transactionid" {
			return false, fmt.Errorf("改密 pid=%d 等待的鎖不符：application=%s locktype=%s", pu, app, locktype)
		}
		return true, nil
	})
	if pidUser.pid.Load() == pidMap.pid.Load() {
		t.Fatal("兩個服務交易不應共用同一個後端")
	}
	resumeFn() // 阻擋關係成立後才放行映射刪除去取使用者鎖

	waitBoth := func() {
		t.Helper()
		deadline := time.After(60 * time.Second)
		for _, c := range []chan struct{}{userDone, mapDone} {
			select {
			case <-c:
			case <-deadline:
				closeAbort()
				t.Fatal("等待逾時: 兩筆交易未在期限內結束")
			}
		}
	}
	waitBoth()

	isDeadlock := func(err error) bool {
		var pgErr *pgconn.PgError
		return errors.As(err, &pgErr) && pgErr.Code == "40P01"
	}
	deadlocks := 0
	for _, e := range []error{errUser, errMap} {
		if isDeadlock(e) {
			deadlocks++
		}
	}
	if deadlocks != 1 || (errUser == nil) == (errMap == nil) {
		t.Fatalf("應恰一方 40P01、另一方提交：改密=%v 映射刪除=%v", errUser, errMap)
	}

	after := take()
	vict := "delete_mapping"
	if isDeadlock(errUser) {
		vict = "change_password"
		// 改密為 victim：密碼、密碼時間戳、強制改密旗標與歷史不變；世代只因映射撤銷推進一次；映射刪除完整提交
		if after.hash != before.hash || after.pwChangedAt != before.pwChangedAt || after.mustChange != before.mustChange ||
			after.epoch != before.epoch+1 || after.history != before.history {
			t.Fatalf("改密為 victim 卻留下變更：hash 變=%v changed_at %q->%q must_change %v->%v epoch %d->%d history %d->%d",
				after.hash != before.hash, before.pwChangedAt, after.pwChangedAt, before.mustChange, after.mustChange,
				before.epoch, after.epoch, before.history, after.history)
		}
		if after.rule != 0 || after.support != 0 || after.fact != 0 || after.effective != 0 {
			t.Fatalf("映射刪除提交後應移除規則、支撐、映射事實與有效角色：%+v", after)
		}
		// 精確增量：有效角色撤銷、個人撤權、規則刪除各一筆審計，全表合計恰三筆（改密 victim 的審計為零）
		if after.auditRole != before.auditRole+1 || after.auditRevoke != before.auditRevoke+1 ||
			after.auditDelete != before.auditDelete+1 || after.audits != before.audits+3 {
			t.Fatalf("審計應恰增加角色撤銷、個人撤權、規則刪除各一筆：role %d->%d revoke %d->%d delete %d->%d 全表 %d->%d",
				before.auditRole, after.auditRole, before.auditRevoke, after.auditRevoke,
				before.auditDelete, after.auditDelete, before.audits, after.audits)
		}
		// 精確增量：版本 +2（移除撤權與規則軟刪各推進一次）、變更事件 +3
		if after.version != before.version+2 || after.changes != before.changes+3 {
			t.Fatalf("映射刪除提交的版本應 +2、變更事件應 +3：version %d->%d changes %d->%d",
				before.version, after.version, before.changes, after.changes)
		}
	} else {
		// 映射刪除為 victim：規則、支撐、映射事實、有效角色、審計、版本、事件差集全回滾；改密完整提交
		if after.rule != before.rule || after.support != before.support || after.fact != before.fact || after.effective != before.effective {
			t.Fatalf("映射刪除為 victim 卻留下半筆變更：前 %+v 後 %+v", before, after)
		}
		if after.audits != before.audits || after.auditRole != before.auditRole ||
			after.auditRevoke != before.auditRevoke || after.auditDelete != before.auditDelete {
			t.Fatalf("映射刪除為 victim 卻留下審計列：全表 %d->%d role %d->%d revoke %d->%d delete %d->%d",
				before.audits, after.audits, before.auditRole, after.auditRole,
				before.auditRevoke, after.auditRevoke, before.auditDelete, after.auditDelete)
		}
		// 精確增量：改密只改「可本地登入」以外的欄位，投影不變，不推進版本也不記變更事件
		if after.version != before.version || after.changes != before.changes {
			t.Fatalf("映射刪除為 victim 卻推進版本或事件：version %d->%d changes %d->%d",
				before.version, after.version, before.changes, after.changes)
		}
		// 映射刪除回滾，世代只因改密推進一次；密碼時間戳更新、不強制再次改密
		if after.hash == before.hash || after.epoch != before.epoch+1 || after.history != before.history+1 ||
			after.pwChangedAt == before.pwChangedAt || after.mustChange {
			t.Fatalf("改密提交後應改密碼、時間戳更新、世代加一、歷史加一且不強制改密：epoch %d->%d history %d->%d changed_at %q->%q must_change=%v",
				before.epoch, after.epoch, before.history, after.history, before.pwChangedAt, after.pwChangedAt, after.mustChange)
		}
	}
	if after.untraced != before.untraced+1 {
		t.Fatalf("全鏈 untraced 應恰增加一筆：前 %d 後 %d", before.untraced, after.untraced)
	}
	evs := replayPermissionEventsEqualActual(t, db)
	if n := savepoints.Load(); n != 2 {
		t.Fatalf("untraced 的嘗試次數應為 2（兩方各一次，未因 40P01 增加），實得 %d", n)
	}
	t.Logf("EVIDENCE dialect=postgres subcase=untraced_vs_user_lock_deadlock attempts=%d sqlstate=40P01 victim=%s chain_len=%d untraced_added=%d pid_user=%d pid_map=%d blocked_by=map",
		savepoints.Load()/2, vict, len(evs), after.untraced-before.untraced, pidUser.pid.Load(), pidMap.pid.Load())
}
