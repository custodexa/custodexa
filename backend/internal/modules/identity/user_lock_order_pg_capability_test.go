package identity

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/crypto"
)

// 只讀列鎖守衛的排序、外部身分清理遇軟刪與不存在的帳號、以及三條能力簽發路徑
// （刷新、簽交棒憑證、兌換）與帳號停用的交錯。

var lockSelectRe = regexp.MustCompile(`(?i)\bFOR (NO KEY )?UPDATE\b`)

// 排序欄必須是 users 的 id（可帶引號與表名限定，可帶 ASC），其後緊接鎖定子句；DESC 與其他欄位都不符。
var orderByIDRe = regexp.MustCompile(`(?i)\bORDER BY\s+(?:"?users"?\.)?(?:"id"|id)(?:\s+ASC)?\s+FOR\b`)

// runRowOnlySortedUsers：以 [hi,lo] 與 [lo,hi] 兩種輸入呼叫真守衛（只有列鎖的路徑）。
// sql_order：以 GORM callback 記錄實際送出的鎖定語句，含 ORDER BY id。
// 交錯：兩個連線池各以相反的輸入順序呼叫同一個守衛，先行者鎖齊兩列後停住，後行者被擋、放行後都完成。
func runRowOnlySortedUsers(t *testing.T) {
	fixture := func(t *testing.T) (*lockOrderEnv, uint, uint) {
		e := newLockOrderEnv(t)
		lo, hi := e.humanUser(t, "lo-ro-lo"), e.humanUser(t, "lo-ro-hi")
		require.Less(t, lo, hi)
		return e, lo, hi
	}
	guard := func(db *gorm.DB, operator uint, ids []uint) error {
		return db.Transaction(func(tx *gorm.DB) error {
			return authz.SelfGrantGuard{}.CheckRuleSubjects(tx, operator, ids, nil)
		})
	}

	t.Run("sql_order", func(t *testing.T) {
		e, lo, hi := fixture(t)
		for _, input := range [][]uint{{hi, lo}, {lo, hi}} {
			get, stop := collectSQL(e.dbA, fmt.Sprintf("lock_order_ro_%d_%d", input[0], input[1]))
			require.NoError(t, guard(e.dbA, e.root, input))
			stop()
			var locks []string
			var lockVars []any
			for _, r := range get() {
				if strings.Contains(r.sql, `FROM "users"`) && lockSelectRe.MatchString(r.sql) {
					locks = append(locks, r.sql)
					lockVars = append(lockVars, r.vars...)
				}
			}
			require.NotEmpty(t, locks, "輸入 %v 沒有任何 users 列鎖語句", input)
			for _, s := range locks {
				require.Regexp(t, orderByIDRe, s, "輸入 %v 的鎖定語句必須依 id 排序：%s", input, s)
			}
			// 整批取鎖順序：單一語句涵蓋全部目標，綁定的使用者編號集合等於輸入（去重），語句帶升冪排序，
			// 因此兩種輸入順序的實際取鎖序列相同（升冪）
			require.Len(t, locks, 1, "輸入 %v 的鎖定必須是單一語句，實際 %d 句", input, len(locks))
			require.Equal(t, []uint{lo, hi}, sortedUnique(numericVars(lockVars)), "輸入 %v 的鎖定語句綁定的使用者集合", input)
			t.Logf("EVIDENCE dialect=postgres subcase=row_only_sorted_users/sql_order input=%v lock_statements=%d sql=%q", input, len(locks), locks[0])
		}
	})

	t.Run("order_clause_shapes", func(t *testing.T) {
		for _, ok := range []string{
			`SELECT * FROM "users" WHERE id IN ($1,$2) ORDER BY id FOR NO KEY UPDATE`,
			`SELECT * FROM "users" WHERE id IN ($1,$2) ORDER BY "id" FOR NO KEY UPDATE`,
			`SELECT * FROM "users" WHERE id IN ($1,$2) ORDER BY "users"."id" FOR NO KEY UPDATE`,
			`SELECT * FROM "users" WHERE id IN ($1,$2) ORDER BY users.id ASC FOR UPDATE`,
			`SELECT * FROM "users" WHERE id IN ($1,$2) order by "id" asc for no key update`,
		} {
			require.Regexp(t, orderByIDRe, ok)
		}
		for _, bad := range []string{
			`SELECT * FROM "users" WHERE id IN ($1,$2) FOR NO KEY UPDATE`,
			`SELECT * FROM "users" WHERE id IN ($1,$2) ORDER BY id DESC FOR NO KEY UPDATE`,
			`SELECT * FROM "users" WHERE id IN ($1,$2) ORDER BY "id" DESC FOR NO KEY UPDATE`,
			`SELECT * FROM "users" WHERE id IN ($1,$2) ORDER BY username FOR NO KEY UPDATE`,
			`SELECT * FROM "users" WHERE id IN ($1,$2) ORDER BY "users"."id_x" FOR NO KEY UPDATE`,
			`SELECT * FROM "users" WHERE id IN ($1,$2) ORDER BY "other"."id" FOR NO KEY UPDATE`,
			`SELECT * FROM "users" WHERE id IN ($1,$2) ORDER BY id`,
		} {
			require.NotRegexp(t, orderByIDRe, bad)
		}
	})

	eachOrder(t, "desc_input", "asc_input", func(t *testing.T, order string) {
		e, lo, hi := fixture(t)
		descStop, ascStop := newLockStop(), newLockStop()
		release := e.installAppHooks(map[string]*lockStop{
			"user_rows_locked@" + e.appA: descStop,
			"user_rows_locked@" + e.appB: ascStop,
		}, func(point string, ids []uint) bool { return point == "user_rows_locked" && len(ids) == 2 })
		defer release()
		snap := func() map[string]int64 {
			return map[string]int64{
				"authz_version": e.scalar(t, "SELECT version FROM authz_state WHERE id = 1"),
				"users":         e.scalar(t, "SELECT count(*) FROM users WHERE id IN (?, ?) AND deleted_at IS NULL", lo, hi),
				"epochs":        e.scalar(t, "SELECT coalesce(sum(credential_epoch), 0) FROM users WHERE id IN (?, ?)", lo, hi),
			}
		}
		want := func(base map[string]int64, _ map[string]bool, _ string) map[string]int64 { return base }
		e.runCycle(t, cycleSpec{
			subcase: "row_only_sorted_users",
			shared:  fmt.Sprintf("users:%d,%d", lo, hi),
			a: lockActor{name: "desc_input", stop: descStop, app: e.appA, start: func() error {
				return guard(e.dbA, e.root, []uint{hi, lo})
			}},
			b: lockActor{name: "asc_input", stop: ascStop, app: e.appB, start: func() error {
				return guard(e.dbB, e.root, []uint{lo, hi})
			}},
			plans: map[string]cyclePlan{
				"desc_input": {class: "wait", kind: "row"},
				"asc_input":  {class: "wait", kind: "row"},
			},
			snap: snap, want: want,
		}, order)
	})
}

// sortedUnique 升冪去重。
func sortedUnique(ids []uint) []uint {
	seen := map[uint]bool{}
	var out []uint
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// runOrphanAndSoftDeleted：外部身分清理遇軟刪與不存在的使用者。單一交易、非交錯，
// 比對的是結果本身：helper 不得替不存在的使用者虛構 NotFound，也不得略過原 callback。
// 正式 schema 的外鍵讓「綁定指向不存在的帳號」只可能出現在記憶體中的綁定值
// （例如較早版本留下、帳號列已被清除的資料），所以不存在的案例以直接呼叫 callback 的入口驗。
func runOrphanAndSoftDeleted(t *testing.T) {
	e := newLockOrderEnv(t)
	p := e.mappingProvider(t, "lo-orphan-provider")
	mk := func(name string) uint { return e.humanUser(t, name) }
	bind := func(userID uint, subject string) model.UserExternalIdentity {
		id := model.UserExternalIdentity{UserID: userID, ProviderID: p.ID, Issuer: p.Issuer, ClientID: p.ClientID, Subject: subject}
		require.NoError(t, e.dbA.Create(&id).Error)
		return id
	}
	live := func(id uint) int64 {
		return e.scalar(t, "SELECT count(*) FROM user_external_identities WHERE id = ? AND deleted_at IS NULL", id)
	}
	rows := func(id uint) int64 {
		return e.scalar(t, "SELECT count(*) FROM user_external_identities WHERE id = ?", id)
	}
	svc := e.users
	sink := &orphanAuditSink{}
	svc.audit = sink

	t.Run("soft_deleted_user", func(t *testing.T) {
		gone := mk("lo-orphan-gone")
		existing := bind(gone, "sub-soft")
		require.NoError(t, e.dbA.Delete(&model.User{}, gone).Error)
		require.EqualValues(t, 1, e.scalar(t, "SELECT count(*) FROM users WHERE id = ? AND deleted_at IS NOT NULL", gone), "fixture：帳號為軟刪")
		epochBefore := e.scalar(t, "SELECT version FROM authz_state WHERE id = 1")

		orphan, revoked, err := svc.revokeOrphanBinding(&existing)
		require.NoError(t, err, "軟刪的使用者不得被當成錯誤")
		require.True(t, orphan)
		require.True(t, revoked)
		require.EqualValues(t, 0, live(existing.ID), "綁定被作廢")
		require.EqualValues(t, 1, rows(existing.ID), "軟刪而非硬刪")
		require.EqualValues(t, 1, e.scalar(t, "SELECT count(*) FROM users WHERE id = ? AND deleted_at IS NOT NULL", gone), "帳號列不被改動")
		require.EqualValues(t, epochBefore, e.scalar(t, "SELECT version FROM authz_state WHERE id = 1"), "清理不推進權限版本")

		// 第二次：綁定已被作廢，仍判為懸空，但這次沒有作廢到任何列
		orphan, revoked, err = svc.revokeOrphanBinding(&existing)
		require.NoError(t, err)
		require.True(t, orphan)
		require.False(t, revoked)
		t.Logf("EVIDENCE dialect=postgres subcase=orphan_and_soft_deleted/soft_deleted_user user=%d identity=%d orphan=true revoked=true second_revoked=false", gone, existing.ID)
	})

	t.Run("missing_user", func(t *testing.T) {
		keep := mk("lo-orphan-keep")
		real := bind(keep, "sub-missing-real")
		const missing uint = 987654
		require.Zero(t, e.scalar(t, "SELECT count(*) FROM users WHERE id = ?", missing), "fixture：該編號沒有使用者列（含軟刪）")
		// 綁定值指向不存在的帳號，且編號也不是任何現存綁定：callback 照跑，回懸空、沒有作廢到列
		ghost := model.UserExternalIdentity{ID: 999999, UserID: missing, ProviderID: p.ID, Issuer: p.Issuer, ClientID: p.ClientID, Subject: "sub-missing"}
		orphan, revoked, err := svc.revokeOrphanBinding(&ghost)
		require.NoError(t, err, "不存在的使用者不得被當成錯誤")
		require.True(t, orphan)
		require.False(t, revoked)
		require.EqualValues(t, 1, live(real.ID), "不相干的綁定不被波及")
		t.Logf("EVIDENCE dialect=postgres subcase=orphan_and_soft_deleted/missing_user user=%d orphan=true revoked=false", missing)
	})

	t.Run("active_user", func(t *testing.T) {
		u := mk("lo-orphan-active")
		existing := bind(u, "sub-active")
		orphan, revoked, err := svc.revokeOrphanBinding(&existing)
		require.NoError(t, err)
		require.False(t, orphan)
		require.False(t, revoked)
		require.EqualValues(t, 1, live(existing.ID), "仍在使用的帳號，其綁定不被作廢")
		t.Logf("EVIDENCE dialect=postgres subcase=orphan_and_soft_deleted/active_user user=%d orphan=false revoked=false", u)
	})

	t.Run("bind_over_orphan", func(t *testing.T) {
		gone, next := mk("lo-orphan-bind-gone"), mk("lo-orphan-bind-next")
		existing := bind(gone, "sub-rebind")
		require.NoError(t, e.dbA.Delete(&model.User{}, gone).Error)
		dto, err := svc.BindExternalIdentity(next, p.ID, "sub-rebind", IdentityAdminActor{UserID: e.root, Username: "lo-root", ClientIP: "127.0.0.1"})
		require.NoError(t, err)
		require.NotNil(t, dto)
		require.Equal(t, next, dto.UserID)
		require.EqualValues(t, 0, live(existing.ID), "舊綁定被作廢")
		require.EqualValues(t, 1, e.scalar(t, "SELECT count(*) FROM user_external_identities WHERE user_id = ? AND subject = ? AND deleted_at IS NULL", next, "sub-rebind"))
		require.Equal(t, 1, sink.count("external_identity_orphan_revoked"), "作廢審計恰一筆")
		t.Logf("EVIDENCE dialect=postgres subcase=orphan_and_soft_deleted/bind_over_orphan from=%d to=%d", gone, next)
	})
}

type orphanAuditSink struct{ entries []*audit.AuditLogEntry }

func (o *orphanAuditSink) Log(entry *audit.AuditLogEntry) { o.entries = append(o.entries, entry) }

func (o *orphanAuditSink) count(event string) int {
	n := 0
	for _, e := range o.entries {
		if strings.Contains(e.Details, `"event":"`+event+`"`) {
			n++
		}
	}
	return n
}

// capabilityFixture 一位人類使用者（有外部身分綁定）、一個啟用中的 provider，與指向它們的服務。
type capabilityFixture struct {
	e     *lockOrderEnv
	u     uint
	p     model.OIDCProvider
	auth  *AuthService
	login *OIDCLoginService
}

func (e *lockOrderEnv) newCapabilityFixture(t *testing.T, name string) *capabilityFixture {
	t.Helper()
	p := e.mappingProvider(t, name+"-provider")
	u := model.User{Username: name, Active: true, Kind: model.KindHuman, ExternalCredential: true}
	require.NoError(t, e.dbA.Create(&u).Error)
	require.NoError(t, e.dbA.Create(&model.UserExternalIdentity{UserID: u.ID, ProviderID: p.ID, Issuer: p.Issuer, ClientID: p.ClientID, Subject: name + "-sub"}).Error)
	auth := NewAuthService("lock-order-secret", 15*time.Minute)
	auth.SetSecurityPolicies(policy.NewSecurityPolicyService(e.dbA))
	login := NewOIDCLoginService(e.dbA, nil, nil, auth, nil)
	return &capabilityFixture{e: e, u: u.ID, p: p, auth: auth, login: login}
}

func (f *capabilityFixture) snap(t *testing.T) map[string]int64 {
	e, u := f.e, f.u
	return map[string]int64{
		"active":          e.scalar(t, "SELECT count(*) FROM users WHERE id = ? AND active", u),
		"epoch":           e.scalar(t, "SELECT credential_epoch FROM users WHERE id = ?", u),
		"authz_version":   e.scalar(t, "SELECT version FROM authz_state WHERE id = 1"),
		"refresh_total":   e.scalar(t, "SELECT count(*) FROM refresh_tokens WHERE user_id = ?", u),
		"refresh_live":    e.scalar(t, "SELECT count(*) FROM refresh_tokens WHERE user_id = ? AND revoked_at IS NULL", u),
		"refresh_rotated": e.scalar(t, "SELECT count(*) FROM refresh_tokens WHERE user_id = ? AND revoked_reason = ?", u, model.RefreshRevokeRotated),
		// 仍可用的 refresh：未撤銷、且攜帶的世代等於使用者現行世代
		"refresh_usable": e.scalar(t, `SELECT count(*) FROM refresh_tokens r JOIN users x ON x.id = r.user_id
 WHERE r.user_id = ? AND r.revoked_at IS NULL AND r.cred_epoch = x.credential_epoch`, u),
		"tickets": e.scalar(t, "SELECT count(*) FROM oidc_login_tickets WHERE user_id = ?", u),
		// 交棒憑證攜帶的世代等於使用者現行世代者：停用之後仍為 1 代表憑證是用停用之後的世代簽的
		"tickets_current": e.scalar(t, `SELECT count(*) FROM oidc_login_tickets k JOIN users x ON x.id = k.user_id
 WHERE k.user_id = ? AND k.cred_epoch = x.credential_epoch`, u),
	}
}

func (f *capabilityFixture) refreshFixture(t *testing.T, plain string) {
	t.Helper()
	now := time.Now()
	var epoch int
	require.NoError(t, f.e.obs.Raw("SELECT credential_epoch FROM users WHERE id = ?", f.u).Scan(&epoch).Error)
	require.NoError(t, f.e.dbA.Create(&model.RefreshToken{
		UserID: f.u, TokenHash: hashRefreshToken(plain), SessionStartedAt: now, ExpiresAt: now.Add(time.Hour), LastUsedAt: now,
		AuthMethod: crypto.AuthMethodOIDC, ProviderID: f.p.ID, AuthEpoch: f.p.AuthEpoch, CredEpoch: epoch,
	}).Error)
}

// runAuthCapabilityPaths：三條「以既有憑證產生新長效能力」的路徑各與帳號停用交錯。
// 三者都在 provider 列鎖之後取該使用者的憑證鎖，在鎖內重驗世代；停用在同一把憑證鎖內推進世代並撤銷 refresh。
// 能力路徑先行：它在停用之前完成，停用隨後撤銷；停用先行：能力路徑在鎖內看到世代已變而拒絕，不留下可用憑證。
func runAuthCapabilityPaths(t *testing.T) {
	disabledBy := func(f *capabilityFixture) func() error {
		return func() error { return f.e.users.UpdateStatusBy(f.e.op(), f.u, false) }
	}
	sharedOf := func(f *capabilityFixture) string { return fmt.Sprintf("users:%d,oidc_providers:%d", f.u, f.p.ID) }

	t.Run("refresh", func(t *testing.T) {
		eachOrder(t, "refresh", "disable", func(t *testing.T, order string) {
			e := newLockOrderEnv(t)
			f := e.newCapabilityFixture(t, "lo-cap-refresh")
			f.refreshFixture(t, "lo-refresh-plain")
			refreshStop, disableStop := newLockStop(), newLockStop()
			release := e.installAppHooks(map[string]*lockStop{
				"user_credential_lock_acquired@" + e.appA: refreshStop,
				"user_status_before_advance@" + e.appB:    disableStop,
			}, func(point string, ids []uint) bool { return len(ids) > 0 && ids[0] == f.u })
			defer release()
			var refreshErr error
			var resp *RefreshResponse
			want := func(base map[string]int64, _ map[string]bool, lead string) map[string]int64 {
				rotated := b2i(lead == "refresh")
				return map[string]int64{
					"active": base["active"] - 1, "epoch": base["epoch"] + 1, "authz_version": base["authz_version"] + 1, // 停用推進一次權限版本
					// 刷新先行：舊列輪替、新列誕生，隨後被停用撤銷；停用先行：刷新被世代閘拒絕，不新增任何列
					"refresh_total": base["refresh_total"] + rotated, "refresh_live": 0, "refresh_rotated": base["refresh_rotated"] + rotated,
					"refresh_usable": 0, "tickets": base["tickets"], "tickets_current": base["tickets_current"],
				}
			}
			e.runCycle(t, cycleSpec{
				subcase: "auth_capability_paths/refresh", shared: sharedOf(f),
				a: lockActor{name: "refresh", stop: refreshStop, app: e.appA, start: func() error {
					resp, refreshErr = f.auth.RefreshSession("lo-refresh-plain", "127.0.0.1")
					if errors.Is(refreshErr, ErrRefreshInvalid) {
						return nil // 世代閘的合法業務拒絕，結果由資料斷言
					}
					return refreshErr
				}},
				b: lockActor{name: "disable", stop: disableStop, app: e.appB, start: disabledBy(f)},
				plans: map[string]cyclePlan{
					"refresh": {class: "wait", kind: "advisory", advisoryUser: f.u},
					"disable": {class: "wait", kind: "advisory", advisoryUser: f.u},
				},
				snap: func() map[string]int64 { return f.snap(t) }, want: want,
			}, order)
			if order == "refresh_released_first" {
				require.NoError(t, refreshErr)
				require.NotNil(t, resp)
			} else {
				require.ErrorIs(t, refreshErr, ErrRefreshInvalid, "停用先行：刷新必須被世代閘拒絕")
			}
		})
	})

	t.Run("issue_ticket", func(t *testing.T) {
		eachOrder(t, "issue", "disable", func(t *testing.T, order string) {
			e := newLockOrderEnv(t)
			f := e.newCapabilityFixture(t, "lo-cap-issue")
			issueStop, disableStop := newLockStop(), newLockStop()
			restoreSite := SetOIDCProviderPreWriteStopForTest(func(site string) {
				if site == oidcSiteTicketIssue {
					issueStop.hit(nil)
				}
			})
			defer restoreSite()
			release := e.installAppHooks(map[string]*lockStop{"user_status_before_advance@" + e.appB: disableStop},
				func(point string, ids []uint) bool { return len(ids) > 0 && ids[0] == f.u })
			defer release()
			defer issueStop.open()
			var issueErr error
			var user model.User
			require.NoError(t, e.dbA.First(&user, f.u).Error)
			want := func(base map[string]int64, _ map[string]bool, lead string) map[string]int64 {
				issued := b2i(lead == "issue")
				return map[string]int64{
					"active": base["active"] - 1, "epoch": base["epoch"] + 1, "authz_version": base["authz_version"] + 1, // 停用推進一次權限版本
					"refresh_total": base["refresh_total"], "refresh_live": base["refresh_live"], "refresh_rotated": base["refresh_rotated"],
					"refresh_usable": base["refresh_usable"],
					// 簽發先行：憑證攜帶簽發當下的世代，停用推進後它已不是現行世代；停用先行：不簽出任何憑證
					"tickets": base["tickets"] + issued, "tickets_current": base["tickets_current"],
				}
			}
			e.runCycle(t, cycleSpec{
				subcase: "auth_capability_paths/issue_ticket", shared: sharedOf(f),
				a: lockActor{name: "issue", stop: issueStop, app: e.appA, start: func() error {
					_, issueErr = f.login.issueTicket(&user, &f.p, sha256Hex("browser-secret"), "/dashboard")
					if errors.Is(issueErr, ErrUserInactive) {
						return nil
					}
					return issueErr
				}},
				b: lockActor{name: "disable", stop: disableStop, app: e.appB, start: disabledBy(f)},
				plans: map[string]cyclePlan{
					"issue":   {class: "wait", kind: "advisory", advisoryUser: f.u},
					"disable": {class: "wait", kind: "advisory", advisoryUser: f.u},
				},
				snap: func() map[string]int64 { return f.snap(t) }, want: want,
			}, order)
			if order == "issue_released_first" {
				require.NoError(t, issueErr)
			} else {
				require.ErrorIs(t, issueErr, ErrUserInactive, "停用先行：鎖內重讀必須看到帳號已停用")
			}
		})
	})

	t.Run("exchange", func(t *testing.T) {
		eachOrder(t, "exchange", "disable", func(t *testing.T, order string) {
			e := newLockOrderEnv(t)
			f := e.newCapabilityFixture(t, "lo-cap-exchange")
			var user model.User
			require.NoError(t, e.dbA.First(&user, f.u).Error)
			ticket, err := f.login.issueTicket(&user, &f.p, sha256Hex("browser-secret"), "/dashboard")
			require.NoError(t, err, "fixture：無並發下簽出一張交棒憑證")
			require.EqualValues(t, 1, f.snap(t)["tickets_current"])
			exchangeStop, disableStop := newLockStop(), newLockStop()
			restoreSite := SetOIDCProviderPreWriteStopForTest(func(site string) {
				if site == oidcSiteTicketExchange {
					exchangeStop.hit(nil)
				}
			})
			defer restoreSite()
			release := e.installAppHooks(map[string]*lockStop{"user_status_before_advance@" + e.appB: disableStop},
				func(point string, ids []uint) bool { return len(ids) > 0 && ids[0] == f.u })
			defer release()
			defer exchangeStop.open()
			var exchangeErr error
			var exchangeResp *LoginResponse
			exchangeFirst := order == "exchange_released_first"
			want := func(base map[string]int64, _ map[string]bool, lead string) map[string]int64 {
				consumed := b2i(lead == "exchange")
				out := map[string]int64{
					"active": base["active"] - 1, "epoch": base["epoch"] + 1, "authz_version": base["authz_version"] + 1, // 停用推進一次權限版本
					"tickets": base["tickets"] - consumed, "tickets_current": 0,
					"refresh_rotated": base["refresh_rotated"], "refresh_usable": 0,
					// 兌換先行：鎖內消耗憑證後於鎖外登入，恰簽出一枚 refresh（帶舊世代）；停用先行：被世代比對拒絕，不新增任何列
					"refresh_total": base["refresh_total"] + consumed,
				}
				if !exchangeFirst {
					out["refresh_live"] = base["refresh_live"]
				}
				return out
			}
			// 兌換先行時，鎖外的登入後段可能在停用的 refresh 撤銷之前或之後才寫入（帶舊世代）：
			// 這枚 refresh 是否已被撤銷取決於這兩件事的先後，不固定，所以只有兌換先行不比對 refresh_live
			// （改由下方範圍檢查與 refresh_usable＝0 承擔）；其餘欄位兩序都精確比對
			exchangeSnap := func() map[string]int64 {
				m := f.snap(t)
				if exchangeFirst {
					delete(m, "refresh_live")
				}
				return m
			}
			e.runCycle(t, cycleSpec{
				subcase: "auth_capability_paths/exchange", shared: sharedOf(f),
				a: lockActor{name: "exchange", stop: exchangeStop, app: e.appA, start: func() error {
					exchangeResp, _, exchangeErr = f.login.Exchange(ticket, "browser-secret")
					// 只有停用先行時，世代比對拒絕是合法結果（錯誤碼與副作用由下方與資料斷言逐項核對）；
					// 兌換先行的世代驗證與消耗已在停用之前完成，任何錯誤都是失敗
					if !exchangeFirst && errors.Is(exchangeErr, ErrOIDCTicketInvalid) {
						return nil
					}
					return exchangeErr
				}},
				b: lockActor{name: "disable", stop: disableStop, app: e.appB, start: disabledBy(f)},
				plans: map[string]cyclePlan{
					"exchange": {class: "wait", kind: "advisory", advisoryUser: f.u},
					"disable":  {class: "wait", kind: "advisory", advisoryUser: f.u},
				},
				snap: exchangeSnap, want: want,
			}, order)
			if exchangeFirst {
				require.NoError(t, exchangeErr, "兌換先行：世代驗證與消耗在停用之前完成，必須成功")
				require.NotNil(t, exchangeResp, "兌換先行：回傳登入結果")
				require.NotEmpty(t, exchangeResp.Token, "兌換先行：簽出會話")
				require.False(t, exchangeResp.MFARequired)
				require.EqualValues(t, 1, f.e.scalar(t, "SELECT count(*) FROM refresh_tokens WHERE user_id = ? AND cred_epoch < (SELECT credential_epoch FROM users WHERE id = ?)", f.u, f.u),
					"兌換先行簽出的 refresh 帶舊世代")
				live := f.e.scalar(t, "SELECT count(*) FROM refresh_tokens WHERE user_id = ? AND revoked_at IS NULL", f.u)
				require.Contains(t, []int64{0, 1}, live, "兌換先行：該 refresh 要嘛已被停用撤銷、要嘛尚未撤銷（帶舊世代而不可用）")
			} else {
				require.ErrorIs(t, exchangeErr, ErrOIDCTicketInvalid, "停用先行：鎖內世代比對必須拒絕")
				require.Nil(t, exchangeResp, "停用先行：不回傳登入結果")
				post := f.snap(t)
				require.EqualValues(t, 1, post["tickets"], "拒絕時憑證不被消耗（交易回滾）")
				require.EqualValues(t, 0, post["refresh_total"], "拒絕時不留下任何 refresh")
			}
		})
	})
}
