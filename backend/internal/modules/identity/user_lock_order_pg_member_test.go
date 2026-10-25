package identity

import (
	"bytes"
	"fmt"
	"log"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 成員替換的預取，以及「預取之後才加入的成員」與帳號停用的交錯。

// sqlRecord 交易內一句已執行的 SQL 與其綁定參數。
type sqlRecord struct {
	sql  string
	vars []any
}

// collectSQL 在連線池上掛 GORM callback，依執行順序收集所有語句；回傳讀取函式與解除函式。
func collectSQL(db *gorm.DB, name string) (get func() []sqlRecord, stop func()) {
	var mu sync.Mutex
	var recs []sqlRecord
	rec := func(tx *gorm.DB) {
		if tx.Statement == nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		recs = append(recs, sqlRecord{sql: tx.Statement.SQL.String(), vars: append([]any{}, tx.Statement.Vars...)})
	}
	cb := db.Callback()
	require.NoError(nil2t{}, cb.Create().After("gorm:create").Register(name, rec))
	require.NoError(nil2t{}, cb.Query().After("gorm:query").Register(name, rec))
	require.NoError(nil2t{}, cb.Update().After("gorm:update").Register(name, rec))
	require.NoError(nil2t{}, cb.Delete().After("gorm:delete").Register(name, rec))
	require.NoError(nil2t{}, cb.Raw().After("gorm:raw").Register(name, rec))
	require.NoError(nil2t{}, cb.Row().After("gorm:row").Register(name, rec))
	return func() []sqlRecord {
			mu.Lock()
			defer mu.Unlock()
			return append([]sqlRecord{}, recs...)
		}, func() {
			_ = cb.Create().Remove(name)
			_ = cb.Query().Remove(name)
			_ = cb.Update().Remove(name)
			_ = cb.Delete().Remove(name)
			_ = cb.Raw().Remove(name)
			_ = cb.Row().Remove(name)
		}
}

// nil2t 讓 collectSQL 可在沒有 *testing.T 的位置用 require（註冊失敗直接 panic）。
type nil2t struct{}

func (nil2t) Errorf(format string, args ...interface{}) { panic(fmt.Sprintf(format, args...)) }
func (nil2t) FailNow()                                  { panic("FailNow") }

// userCredentialAdvisoryUser 判斷一句語句是否為「使用者憑證鎖」並取出使用者編號。
// 只在 SQL 含 pg_advisory_xact_lock、恰兩個參數、第一個參數等於 userCredentialLockClass 時為真；
// 拓撲序列化鎖用同一個函式但 class 不同，不會被誤認。
func userCredentialAdvisoryUser(sql string, vars []any) (uint, bool) {
	if !strings.Contains(sql, "pg_advisory_xact_lock") || len(vars) != 2 {
		return 0, false
	}
	var class int64
	switch c := vars[0].(type) {
	case int32:
		class = int64(c)
	case int64:
		class = c
	case int:
		class = int64(c)
	default:
		return 0, false
	}
	if class != int64(userCredentialLockClass) {
		return 0, false
	}
	ids := numericVars(vars[1:])
	if len(ids) != 1 {
		return 0, false
	}
	return ids[0], true
}

func numericVars(vars []any) []uint {
	var out []uint
	var walk func(v reflect.Value)
	walk = func(v reflect.Value) {
		switch v.Kind() {
		case reflect.Slice, reflect.Array:
			for i := 0; i < v.Len(); i++ {
				walk(v.Index(i))
			}
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			out = append(out, uint(v.Int()))
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			out = append(out, uint(v.Uint()))
		}
	}
	for _, v := range vars {
		walk(reflect.ValueOf(v))
	}
	return out
}

var lockOrderWriteRe = regexp.MustCompile(`(?i)^\s*(INSERT|UPDATE|DELETE)\b`)

// memberReplaceFixture A<B 兩位人類使用者，A 是群組唯一手動成員並有一枚有效 refresh token。
func (e *lockOrderEnv) memberReplaceFixture(t *testing.T) (a, b, gid uint) {
	t.Helper()
	a, b = e.humanUser(t, "lo-mr-a"), e.humanUser(t, "lo-mr-b")
	require.Less(t, a, b)
	gid = e.groupAddGroup(t, "lo-mr-group", a)
	e.refreshFixture(t, a)
	return
}

func (e *lockOrderEnv) replaceMembersTo(gid uint, ids ...uint) error {
	manual := append([]uint{}, ids...)
	_, err := e.groups.ReplaceMembersBy(e.op(), gid, &manual, nil)
	return err
}

func runMemberReplacePrefetch(t *testing.T) {
	// 預取怎麼驗：預取集合 P＝{A,B} 每位的第一句 advisory 與第一句 users 列鎖，都早於交易內第一筆寫入；
	// 之後的這兩種語句只允許 id ∈ P；集合外 id 0 句。需要預取實作（正式修正）才會綠。
	t.Run("sql_order", func(t *testing.T) {
		e := newLockOrderEnv(t)
		a, b, gid := e.memberReplaceFixture(t)
		get, stop := collectSQL(e.dbA, "lock_order_sql_"+e.appA)
		defer stop()
		require.NoError(t, e.replaceMembersTo(gid, b))
		stop()
		inP := map[uint]bool{a: true, b: true}
		firstWrite := -1
		firstAdv, firstRow := map[uint]int{}, map[uint]int{}
		var outside []string
		for i, r := range get() {
			_, isAdv := userCredentialAdvisoryUser(r.sql, r.vars)
			isRow := strings.Contains(r.sql, `FROM "users"`) && (strings.Contains(r.sql, "FOR UPDATE") || strings.Contains(r.sql, "FOR NO KEY UPDATE"))
			if firstWrite < 0 && lockOrderWriteRe.MatchString(r.sql) {
				firstWrite = i
			}
			if !isAdv && !isRow {
				continue
			}
			ids := numericVars(r.vars)
			if isAdv && len(ids) == 2 {
				ids = ids[1:]
			}
			for _, id := range ids {
				if !inP[id] {
					outside = append(outside, fmt.Sprintf("#%d id=%d %s", i, id, r.sql))
				}
				m := firstRow
				if isAdv {
					m = firstAdv
				}
				if _, ok := m[id]; !ok {
					m[id] = i
				}
			}
		}
		require.GreaterOrEqual(t, firstWrite, 0, "交易內必須有寫入語句")
		for _, id := range []uint{a, b} {
			ai, ok := firstAdv[id]
			require.True(t, ok, "使用者 %d 沒有任何 advisory 取鎖語句", id)
			require.Less(t, ai, firstWrite, "使用者 %d 的第一句 advisory（#%d）必須早於第一筆寫入（#%d）", id, ai, firstWrite)
			ri, ok := firstRow[id]
			require.True(t, ok, "使用者 %d 沒有任何 users 列鎖語句", id)
			require.Less(t, ri, firstWrite, "使用者 %d 的第一句 users 列鎖（#%d）必須早於第一筆寫入（#%d）", id, ri, firstWrite)
		}
		require.Empty(t, outside, "預取集合外的使用者不得出現取鎖語句")
		t.Logf("EVIDENCE dialect=postgres subcase=member_replace_prefetch/sql_order first_write=%d adv=%v row=%v", firstWrite, firstAdv, firstRow)
	})

	eachOrder(t, "replace", "disable", func(t *testing.T, order string) {
		e := newLockOrderEnv(t)
		a, b, gid := e.memberReplaceFixture(t)
		replaceStop, disableStop := newLockStop(), newLockStop()
		release := e.installAppHooks(map[string]*lockStop{
			"group_members_before_loop@" + e.appA:  replaceStop,
			"user_status_before_advance@" + e.appB: disableStop,
		}, func(point string, ids []uint) bool { return point == "group_members_before_loop" || len(ids) > 0 })
		defer release()
		liveRefresh := func() int64 {
			return e.scalar(t, "SELECT count(*) FROM refresh_tokens WHERE user_id = ? AND revoked_at IS NULL", a)
		}
		memberAudit := func(ev string) int64 {
			return e.scalar(t, `SELECT count(*) FROM audit_logs WHERE resource = ? AND resource_id = ? AND details::jsonb->>'event' = ?`,
				string(model.ResourceUserGroup), gid, ev)
		}
		snap := func() map[string]int64 {
			return map[string]int64{
				"authz_version": e.scalar(t, "SELECT version FROM authz_state WHERE id = 1"),
				"member_a":      e.scalar(t, "SELECT count(*) FROM user_group_members WHERE user_group_id = ? AND user_id = ?", gid, a),
				"member_b":      e.scalar(t, "SELECT count(*) FROM user_group_members WHERE user_group_id = ? AND user_id = ?", gid, b),
				"a_epoch":       e.scalar(t, "SELECT credential_epoch FROM users WHERE id = ?", a),
				"a_active":      e.scalar(t, "SELECT count(*) FROM users WHERE id = ? AND active", a),
				"a_refresh":     liveRefresh(),
				"audit_removed": memberAudit("user_group_manual_member_removed"),
				"audit_added":   memberAudit("user_group_manual_member_added"),
			}
		}
		want := func(base map[string]int64, c map[string]bool, _ string) map[string]int64 {
			r, d := b2i(c["replace"]), b2i(c["disable"])
			return map[string]int64{
				"authz_version": base["authz_version"] + r + d,
				"member_a":      base["member_a"] - r,
				"member_b":      base["member_b"] + r,
				"a_epoch":       base["a_epoch"] + r + d, // 移除成員與停用各推進一次
				"a_active":      base["a_active"] - d,
				"a_refresh":     base["a_refresh"] - b2i(c["replace"] || c["disable"]),
				"audit_removed": base["audit_removed"] + r,
				"audit_added":   base["audit_added"] + r,
			}
		}
		e.runCycle(t, cycleSpec{
			subcase: "member_replace_prefetch",
			shared:  fmt.Sprintf("users:%d", a),
			a: lockActor{name: "replace", stop: replaceStop, app: e.appA, start: func() error {
				return e.replaceMembersTo(gid, b)
			}},
			b: lockActor{name: "disable", stop: disableStop, app: e.appB, start: func() error {
				return e.users.UpdateStatusBy(e.op(), a, false)
			}},
			plans: map[string]cyclePlan{
				"replace": {class: "wait", kind: "advisory", advisoryUser: a},
				"disable": {class: "wait", kind: "advisory", advisoryUser: a},
			},
			snap: snap, want: want,
		}, order)
	})
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// runMappingJoinBetweenPrefetchAndLosers：群組 G 有角色 R，U 原非成員。
// 群組角色替換（移除 R）停在預取之後、取 loser 之前；映射把 U 加入 G 並提交；
// 帳號停用 U 停在寫入之後、推進版本之前（持 U 的憑證鎖）；放行群組後，群組在持有版本列時補鎖 U（等停用方），
// 放行停用方後它要推進版本（等群組方）而成環。結果依實際分支驗：兩者提交，或恰一方 40P01。
func runMappingJoinBetweenPrefetchAndLosers(t *testing.T) {
	e := newLockOrderEnv(t, "fk_ugmrs_group")
	u := e.externalUser(t, "lo-mj-user")
	g := model.UserGroup{Name: "lo-mj-group"}
	require.NoError(t, e.dbA.Create(&g).Error)
	require.NoError(t, authz.ReplaceUserGroupRoleRows(e.dbA, g.ID, []uint{e.role}, nil))
	p := e.mappingProvider(t, "lo-mj-provider")
	ext := model.ExternalGroup{OIDCProviderID: &p.ID, MatchValue: "lo-mj-ext"}
	require.NoError(t, e.dbA.Create(&ext).Error)
	require.NoError(t, e.dbA.Create(&model.GroupUserGroupMapping{OIDCProviderID: &p.ID, ExternalGroupID: ext.ID, UserGroupID: g.ID, Enabled: true, CreatedBy: e.root}).Error)
	require.EqualValues(t, 1, e.scalar(t, "SELECT count(*) FROM user_group_roles WHERE user_group_id = ? AND role_id = ?", g.ID, e.role), "fixture：G 有角色 R")
	require.EqualValues(t, 0, e.scalar(t, "SELECT count(*) FROM user_group_members WHERE user_group_id = ? AND user_id = ?", g.ID, u), "fixture：U 原非成員")

	buf := &lockedBuf{}
	oldOut := log.Writer()
	log.SetOutput(buf)
	defer log.SetOutput(oldOut)

	groupStop, disableStop := newLockStop(), newLockStop()
	oldHook := groupRoleBindingsPreWriteHook
	groupRoleBindingsPreWriteHook = func() { groupStop.hit(nil) }
	releaseHooks := installLockOrderHooks(map[string]*lockStop{"user_status_before_advance": disableStop})
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			groupStop.open()
			disableStop.open()
			releaseHooks()
			groupRoleBindingsPreWriteHook = oldHook
		})
	}
	defer cleanup()

	doneGroup := make(chan error, 1)
	go func() {
		_, err := e.groups.ReplaceRoleBindings(e.op(), g.ID, GroupRoleBindingsRequest{RoleIDs: nil})
		doneGroup <- err
	}()
	awaitStop(t, groupStop, "群組角色替換")
	pidGroup := e.pidOfApp(t, e.appA)

	var user model.User
	require.NoError(t, e.dbB.First(&user, u).Error)
	_, err := RecomputeMappedRoles(e.dbB, audit.NewTxSink(), &user, GroupObservation{
		Kind: model.RoleMappingChannelKindProvider, SourceID: p.ID, State: GroupObservationKnown, Groups: []string{"lo-mj-ext"}})
	require.NoError(t, err, "映射加入 U 必須能在群組持有 G 列鎖期間完成並提交（G 為 FOR UPDATE 時外鍵 KEY SHARE 被擋，屬修後才綠）")
	require.EqualValues(t, 1, e.scalar(t, "SELECT count(*) FROM user_group_members WHERE user_group_id = ? AND user_id = ?", g.ID, u), "映射應已把 U 加入 G 並提交")

	snap := func() map[string]int64 {
		return map[string]int64{
			"authz_version": e.scalar(t, "SELECT version FROM authz_state WHERE id = 1"),
			"u_epoch":       e.scalar(t, "SELECT credential_epoch FROM users WHERE id = ?", u),
			"u_active":      e.scalar(t, "SELECT count(*) FROM users WHERE id = ? AND active", u),
			"group_role":    e.scalar(t, "SELECT count(*) FROM user_group_roles WHERE user_group_id = ? AND role_id = ?", g.ID, e.role),
			"audit_revoke":  e.groupRoleAudit(t, g.ID, e.role, model.ActionRevoke),
			// service 層的停用沒有稽核出口（停用留痕在管理入口）；此處斷言兩方任一為 victim 時，
			// 該使用者在 service 層都不留下任何 user 資源的稽核列，回滾不殘留成功停用的痕跡
			"u_user_audit": e.scalar(t, "SELECT count(*) FROM audit_logs WHERE resource = ? AND resource_id = ?", string(model.ResourceUser), u),
		}
	}
	base := snap() // 映射提交後的基準 v、e

	doneDisable := make(chan error, 1)
	go func() { doneDisable <- e.users.UpdateStatusBy(e.op(), u, false) }()
	pidDisable := awaitStop(t, disableStop, "帳號停用")
	e.caseBackends(t, pidGroup, pidDisable)

	groupStop.open()
	proof := e.awaitBlocked(t, pidGroup, pidDisable, u, doneGroup)
	disableStop.open()
	errGroup, errDisable := recvErr(t, doneGroup, "群組角色替換"), recvErr(t, doneDisable, "帳號停用")

	victim := "none"
	if pgCode(errGroup) == "40P01" {
		victim = "group"
	}
	if pgCode(errDisable) == "40P01" {
		require.Equal(t, "none", victim, "恰一方為 victim")
		victim = "disable"
	}
	for _, err := range []error{errGroup, errDisable} {
		require.NotEqual(t, "55P03", pgCode(err), "lock_timeout 先於死結偵測觸發，不算死結證據")
	}
	t.Logf("EVIDENCE dialect=postgres subcase=mapping_join_between_prefetch_and_losers order=single pids=%d,%d shared=users:%d,user_groups:%d attested=false mode=wait expected_mode=wait sqlstate=%s victim=%s blocked=%s/%s/%s kind=%s key=%s",
		pidGroup, pidDisable, u, g.ID, map[bool]string{true: "40P01", false: "none"}[victim != "none"], victim, proof.locktype, proof.wmode, proof.hmode, proof.kind, proof.key)
	cleanup()

	got := snap()
	switch victim {
	case "none":
		require.NoError(t, errGroup)
		require.NoError(t, errDisable)
		require.Equal(t, map[string]int64{"authz_version": base["authz_version"] + 2, "u_epoch": base["u_epoch"] + 2, "u_active": 0, "group_role": 0, "audit_revoke": base["audit_revoke"] + 1, "u_user_audit": base["u_user_audit"]}, got, "兩者提交")
	case "group": // 停用提交：G 的 R 指派與群組審計維持原狀
		require.NoError(t, errDisable)
		require.Equal(t, map[string]int64{"authz_version": base["authz_version"] + 1, "u_epoch": base["u_epoch"] + 1, "u_active": 0, "group_role": base["group_role"], "audit_revoke": base["audit_revoke"], "u_user_audit": base["u_user_audit"]}, got, "群組方為 victim")
		require.NoError(t, e.groupsReplaceNone(g.ID), "重送群組角色替換")
		after := snap()
		require.EqualValues(t, 0, after["group_role"])
		require.Equal(t, base["audit_revoke"]+1, after["audit_revoke"])
		require.Equal(t, base["authz_version"]+2, after["authz_version"])
		require.Equal(t, base["u_epoch"]+2, after["u_epoch"])
	case "disable": // 群組提交：U 仍為啟用、無停用效果
		require.NoError(t, errGroup)
		require.Equal(t, map[string]int64{"authz_version": base["authz_version"] + 1, "u_epoch": base["u_epoch"] + 1, "u_active": base["u_active"], "group_role": 0, "audit_revoke": base["audit_revoke"] + 1, "u_user_audit": base["u_user_audit"]}, got, "停用方為 victim")
		require.NoError(t, e.users.UpdateStatusBy(e.op(), u, false), "重送停用")
		after := snap()
		require.EqualValues(t, 0, after["u_active"])
		require.Equal(t, base["authz_version"]+2, after["authz_version"])
		require.Equal(t, base["u_epoch"]+2, after["u_epoch"])
	}
	// 補鎖超出預取集合的 late joiner 前記一行警告（群組 id 與 U 的 id）。警告行格式在正式修正時對齊，
	// 此處先要求同一行含兩個編號與警告字樣；未修碼上此斷言必紅（等 3.5）。
	warn := regexp.MustCompile(fmt.Sprintf(`(?m)^.*(?i:warn|警告).*\b%d\b.*\b%d\b.*$|^.*(?i:warn|警告).*\b%d\b.*\b%d\b.*$`, g.ID, u, u, g.ID))
	require.Regexp(t, warn, buf.String(), "late joiner 補鎖前必須有一行警告（群組 %d、使用者 %d）", g.ID, u)
}

func (e *lockOrderEnv) groupsReplaceNone(gid uint) error {
	_, err := e.groups.ReplaceRoleBindings(e.op(), gid, GroupRoleBindingsRequest{RoleIDs: nil})
	return err
}
