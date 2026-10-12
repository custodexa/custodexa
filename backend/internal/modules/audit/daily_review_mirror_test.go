package audit

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/testgate"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 同一件事只算一列：每一種鏡像形態三案——配到帶路徑列只算 1、帶路徑列缺席照算 1、
// 另一件同形態的事只有帶路徑列時不誤配（算 2）。sqlite 與 PostgreSQL 各跑一次。

const mirrorDay = "2026-10-10"

type mirrorEnv struct {
	t   *testing.T
	db  *gorm.DB
	svc *DailyReviewService
}

// newMirrorEnv 每日簽核已啟用（UTC），時鐘停在所屬日次日
func newMirrorEnv(t *testing.T, kind string) *mirrorEnv {
	t.Helper()
	var svc *DailyReviewService
	var db *gorm.DB
	if kind == "postgres" {
		db = openMirrorPG(t)
		svc = NewDailyReviewService(db, policy.NewSecurityPolicyService(db), nil)
	} else {
		svc, db, _ = setupDailyReviewDB(t)
	}
	enableFrom(t, db, "UTC", time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	fixedClock(svc, time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC))
	return &mirrorEnv{t: t, db: db, svc: svc}
}

func openMirrorPG(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	cfg := &gorm.Config{Logger: logger.Discard, DisableForeignKeyConstraintWhenMigrating: true}
	schema := fmt.Sprintf("daily_review_mirror_%d", time.Now().UnixNano())
	admin, err := gorm.Open(postgres.Open(dsn), cfg)
	if err != nil {
		t.Fatalf("postgres 連線失敗: %v", err)
	}
	if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE")
		if s, err := admin.DB(); err == nil {
			_ = s.Close()
		}
	})
	db, err := gorm.Open(postgres.Open(dsn+" search_path="+schema), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if s, err := db.DB(); err == nil {
			_ = s.Close()
		}
	})
	if err := db.AutoMigrate(&model.AuditLog{}, &model.SecurityPolicy{}, &model.SecurityPolicyHistory{},
		&model.DailyReviewLog{}, &model.AuditRetentionWatermark{}, &model.CommandAlert{},
		&model.User{}, &model.Asset{}); err != nil {
		t.Fatal(err)
	}
	return db
}

// row 以直寫 SQL 植入一列審計（不經寫入端）；回傳編號
func (e *mirrorEnv) row(at time.Time, r model.AuditLog) uint {
	e.t.Helper()
	if err := e.db.Exec(`INSERT INTO audit_logs (created_at, action, resource, resource_id, status, user_id, username,
		path, duration, request_body, error_msg, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		at.UTC(), r.Action, r.Resource, r.ResourceID, r.Status, r.UserID, r.Username,
		r.Path, r.Duration, r.RequestBody, r.ErrorMsg, r.Details).Error; err != nil {
		e.t.Fatalf("植入審計列: %v", err)
	}
	var id uint
	e.db.Raw("SELECT MAX(id) FROM audit_logs").Scan(&id)
	return id
}

func (e *mirrorEnv) asset(id uint, deletedAt time.Time) {
	e.t.Helper()
	if err := e.db.Exec(`INSERT INTO assets (id, created_at, updated_at, deleted_at, name, protocol, host, port, created_by)
		VALUES (?, ?, ?, ?, ?, 'ssh', 'h', 22, 1)`, id, deletedAt.UTC(), deletedAt.UTC(), deletedAt.UTC(),
		"a"+strconv.Itoa(int(id))).Error; err != nil {
		e.t.Fatalf("植入資產: %v", err)
	}
}

func (e *mirrorEnv) user(id uint, name string) {
	e.t.Helper()
	if err := e.db.Exec(`INSERT INTO users (id, created_at, updated_at, username, password) VALUES (?, ?, ?, ?, 'x')`,
		id, time.Now().UTC(), time.Now().UTC(), name).Error; err != nil {
		e.t.Fatalf("植入帳號: %v", err)
	}
}

// expect 單日明細的計數與總數皆為 want；items 非 nil 時明細恰為這幾列
func (e *mirrorEnv) expect(date string, want int64, items ...uint) {
	e.t.Helper()
	d, err := e.svc.Day(date)
	if err != nil {
		e.t.Fatal(err)
	}
	if val(d.Counts.HighRiskOps) != want || d.HighRiskOps.Total != want {
		e.t.Errorf("%s 高危 計數 %d／明細總數 %d, want %d", date, val(d.Counts.HighRiskOps), d.HighRiskOps.Total, want)
	}
	if items == nil {
		return
	}
	got := map[uint]bool{}
	for _, it := range d.HighRiskOps.Items {
		got[it.ID] = true
	}
	for _, id := range items {
		if !got[id] {
			e.t.Errorf("%s 明細缺少列 %d（明細 %v）", date, id, got)
		}
	}
}

// mirrorKey 一件事：對象編號、操作者、第二個編號（帳號、來源）
type mirrorKey struct{ target, actor, aux uint }

// mirrorForm 一種鏡像形態的植入方式（形狀照抄寫入端）
type mirrorForm struct {
	name   string
	mirror func(e *mirrorEnv, at time.Time, k mirrorKey) uint
	path   func(e *mirrorEnv, at time.Time, k mirrorKey) uint
	// other 不誤配案中「另一件同形態的事」
	other func(k mirrorKey) mirrorKey
}

func ptr(v uint) *uint { return &v }

func ok() model.AuditStatus { return model.StatusSuccess }

// httpRow 請求層的帶路徑列（耗時 100 毫秒）
func httpRow(action model.AuditAction, resource model.AuditResource, path string, actor uint, id *uint) model.AuditLog {
	return model.AuditLog{Action: action, Resource: resource, ResourceID: id, Status: ok(), UserID: actor,
		Username: "u" + strconv.Itoa(int(actor)), Path: path, Duration: 100}
}

// svcRow 服務層的無路徑列
func svcRow(action model.AuditAction, resource model.AuditResource, actor uint, id *uint, details string) model.AuditLog {
	return model.AuditLog{Action: action, Resource: resource, ResourceID: id, Status: ok(), UserID: actor,
		Username: "u" + strconv.Itoa(int(actor)), Details: details}
}

func systemRow(action model.AuditAction, id *uint, details string) model.AuditLog {
	return model.AuditLog{Action: action, Resource: model.ResourceUser, ResourceID: id, Status: ok(), Username: "system", Details: details}
}

func principalDetails(id uint) string {
	return fmt.Sprintf(`{"kind":"human","owner_user_id":null,"state_table":"user_principals","user_id":%d}`, id)
}

func otherTarget(k mirrorKey) mirrorKey { return mirrorKey{k.target + 100, k.actor, k.aux} }
func otherActor(k mirrorKey) mirrorKey  { return mirrorKey{k.target, k.actor + 100, k.aux} }
func otherAux(k mirrorKey) mirrorKey    { return mirrorKey{k.target, k.actor, k.aux + 100} }

var mirrorForms = []mirrorForm{
	{name: "資產刪除的資料層留痕", other: otherTarget,
		mirror: func(e *mirrorEnv, at time.Time, k mirrorKey) uint {
			e.asset(k.target, at.Add(-10*time.Millisecond))
			return e.row(at, model.AuditLog{Action: model.ActionDelete, Resource: model.ResourceAsset, ResourceID: ptr(0), Status: ok(), Username: "system"})
		},
		path: func(e *mirrorEnv, at time.Time, k mirrorKey) uint {
			if k.target > 100 { // 另一件事：資產在本件鏡像列之後才刪
				e.asset(k.target, at.Add(-10*time.Millisecond))
			}
			return e.row(at, httpRow(model.ActionDelete, model.ResourceAsset, fmt.Sprintf("/api/v1/assets/%d", k.target), k.actor, ptr(k.target)))
		}},
	{name: "帳號狀態投影（修改）", other: otherTarget,
		mirror: func(e *mirrorEnv, at time.Time, k mirrorKey) uint {
			return e.row(at, systemRow(model.ActionUpdate, ptr(k.target), principalDetails(k.target)))
		},
		path: func(e *mirrorEnv, at time.Time, k mirrorKey) uint {
			return e.row(at, httpRow(model.ActionUpdate, model.ResourceUser, fmt.Sprintf("/api/v1/users/%d", k.target), k.actor, ptr(k.target)))
		}},
	{name: "帳號狀態投影（建立）", other: otherTarget,
		mirror: func(e *mirrorEnv, at time.Time, k mirrorKey) uint {
			e.user(k.target, "name"+strconv.Itoa(int(k.target)))
			return e.row(at, systemRow(model.ActionCreate, ptr(k.target), principalDetails(k.target)))
		},
		path: func(e *mirrorEnv, at time.Time, k mirrorKey) uint {
			r := httpRow(model.ActionCreate, model.ResourceUser, "/api/v1/users", k.actor, nil)
			r.RequestBody = fmt.Sprintf(`{"username":" name%d ","password":"***MASKED***"}`, k.target)
			return e.row(at, r)
		}},
	{name: "資產帳號刪除", other: otherAux,
		mirror: func(e *mirrorEnv, at time.Time, k mirrorKey) uint {
			return e.row(at, svcRow(model.ActionDelete, model.ResourceAsset, k.actor, ptr(k.target),
				fmt.Sprintf(`{"resource":"asset_account","account_id":%d,"account_username":"root","operation":"delete"}`, k.aux)))
		},
		path: func(e *mirrorEnv, at time.Time, k mirrorKey) uint {
			return e.row(at, httpRow(model.ActionDelete, model.ResourceAsset, fmt.Sprintf("/api/v1/assets/%d/accounts/%d", k.target, k.aux), k.actor, ptr(k.target)))
		}},
	{name: "資產分組刪除", other: otherTarget,
		mirror: func(e *mirrorEnv, at time.Time, k mirrorKey) uint {
			return e.row(at, svcRow(model.ActionDelete, model.ResourceAsset, k.actor, ptr(k.target),
				`{"asset_node_name":"prod","revoked_authorizations":2,"revoked_approver_scopes":0}`))
		},
		path: func(e *mirrorEnv, at time.Time, k mirrorKey) uint {
			return e.row(at, httpRow(model.ActionDelete, model.ResourceAssetGroup, fmt.Sprintf("/api/v1/asset-groups/%d", k.target), k.actor, ptr(k.target)))
		}},
	{name: "憑證刪除", other: otherTarget,
		mirror: func(e *mirrorEnv, at time.Time, k mirrorKey) uint {
			return e.row(at, svcRow(model.ActionDelete, model.ResourceCredential, k.actor, ptr(k.target),
				fmt.Sprintf(`{"resource":"credential","credential_id":%d,"operation":"delete"}`, k.target)))
		},
		path: func(e *mirrorEnv, at time.Time, k mirrorKey) uint {
			return e.row(at, httpRow(model.ActionDelete, model.ResourceCredential, fmt.Sprintf("/api/v1/credentials/%d", k.target), k.actor, ptr(k.target)))
		}},
	{name: "使用者群組刪除", other: otherActor,
		mirror: func(e *mirrorEnv, at time.Time, k mirrorKey) uint {
			return e.row(at, svcRow(model.ActionDelete, model.ResourceUserGroup, k.actor, ptr(k.target), `{"group_name":"ops","revoked_authorizations":1}`))
		},
		path: func(e *mirrorEnv, at time.Time, k mirrorKey) uint {
			return e.row(at, httpRow(model.ActionDelete, model.ResourceUserGroup, fmt.Sprintf("/api/v1/user-groups/%d", k.target), k.actor, ptr(k.target)))
		}},
	{name: "群組對角色映射刪除", other: otherAux,
		mirror: func(e *mirrorEnv, at time.Time, k mirrorKey) uint {
			return e.row(at, svcRow(model.ActionDelete, model.ResourceAuth, k.actor, ptr(k.target),
				fmt.Sprintf(`{"enabled":true,"event":"group_role_mapping_delete","rule_id":%d,"source_id":%d,"source_kind":"directory"}`, k.target, k.aux)))
		},
		path: func(e *mirrorEnv, at time.Time, k mirrorKey) uint {
			return e.row(at, httpRow(model.ActionDelete, model.ResourceAuth, fmt.Sprintf("/api/v1/identity-sources/directory/%d/role-mappings/%d", k.aux, k.target), k.actor, nil))
		}},
	{name: "群組對群組映射刪除", other: otherTarget,
		mirror: func(e *mirrorEnv, at time.Time, k mirrorKey) uint {
			r := svcRow(model.ActionDelete, model.ResourceUserGroup, k.actor, ptr(k.target),
				fmt.Sprintf(`{"enabled":true,"event":"group_user_group_mapping_delete","rule_id":%d,"source_id":%d,"user_group_id":3}`, k.target, k.aux))
			r.ErrorMsg = "group_user_group_mapping_delete"
			return e.row(at, r)
		},
		path: func(e *mirrorEnv, at time.Time, k mirrorKey) uint {
			return e.row(at, httpRow(model.ActionDelete, model.ResourceAuth, fmt.Sprintf("/api/v1/identity-sources/provider/%d/user-group-mappings/%d", k.aux, k.target), k.actor, nil))
		}},
	{name: "目錄服務設定刪除", other: otherActor,
		mirror: func(e *mirrorEnv, at time.Time, k mirrorKey) uint {
			return e.row(at, svcRow(model.ActionDelete, model.ResourceAuth, k.actor, ptr(1), `{"directory_id":1,"enabled":true,"event":"ldap_directory_delete","url":"ldaps://dir"}`))
		},
		path: func(e *mirrorEnv, at time.Time, k mirrorKey) uint {
			return e.row(at, httpRow(model.ActionDelete, model.ResourceLDAPDirectory, "/api/v1/ldap-directory", k.actor, nil))
		}},
	{name: "外部身分解綁並停用", other: otherTarget,
		mirror: func(e *mirrorEnv, at time.Time, k mirrorKey) uint {
			return e.row(at, svcRow(model.ActionDelete, model.ResourceUser, k.actor, ptr(k.target),
				fmt.Sprintf(`{"event":"external_identity_unbound_and_account_disabled","identity_id":7,"target_user_id":%d}`, k.target)))
		},
		path: func(e *mirrorEnv, at time.Time, k mirrorKey) uint {
			return e.row(at, httpRow(model.ActionCreate, model.ResourceUser, fmt.Sprintf("/api/v1/users/%d/external-identities/7/unbind-and-disable", k.target), k.actor, ptr(k.target)))
		}},
	{name: "解除代理熔斷", other: otherActor,
		mirror: func(e *mirrorEnv, at time.Time, k mirrorKey) uint {
			return e.row(at, svcRow(model.ActionUpdate, model.ResourceUser, k.actor, ptr(k.target),
				fmt.Sprintf(`{"event":"agent_breaker_released","owner_id":%d,"reason":"ok","user_id":%d}`, k.actor, k.target)))
		},
		path: func(e *mirrorEnv, at time.Time, k mirrorKey) uint {
			return e.row(at, httpRow(model.ActionCreate, model.ResourceUser, fmt.Sprintf("/api/v1/users/%d/agent-breaker/release", k.target), k.actor, ptr(k.target)))
		}},
	{name: "自助建立代理", other: otherTarget,
		mirror: func(e *mirrorEnv, at time.Time, k mirrorKey) uint {
			e.user(k.target, "agent"+strconv.Itoa(int(k.target)))
			return e.row(at, svcRow(model.ActionCreate, model.ResourceUser, k.actor, ptr(k.target),
				fmt.Sprintf(`{"agent_self_create_enabled":true,"agent_self_create_max_per_owner":3,"owner_user_id":%d,"purpose":"ci","self_service":true}`, k.actor)))
		},
		path: func(e *mirrorEnv, at time.Time, k mirrorKey) uint {
			r := httpRow(model.ActionCreate, model.ResourceUser, "/api/v1/my/agents", k.actor, nil)
			r.RequestBody = fmt.Sprintf(`{"username":"agent%d","purpose":"ci"}`, k.target)
			return e.row(at, r)
		}},
}

func mirrorKinds(t *testing.T, run func(t *testing.T, kind string)) {
	for _, kind := range []string{"sqlite", "postgres"} {
		kind := kind
		t.Run(kind, func(t *testing.T) { run(t, kind) })
	}
}

// TestDailyReviewHighRiskMirrorPairing 擋：操作從高危消失、同一件事算兩次
func TestDailyReviewHighRiskMirrorPairing(t *testing.T) {
	at := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	k := mirrorKey{target: 7, actor: 3, aux: 11}
	mirrorKinds(t, func(t *testing.T, kind string) {
		for _, f := range mirrorForms {
			f := f
			t.Run(f.name+"/配對成立只算帶路徑那一列", func(t *testing.T) {
				e := newMirrorEnv(t, kind)
				f.mirror(e, at, k)
				p := f.path(e, at.Add(50*time.Millisecond), k)
				e.expect(mirrorDay, 1, p)
			})
			t.Run(f.name+"/帶路徑列缺席照算", func(t *testing.T) {
				e := newMirrorEnv(t, kind)
				m := f.mirror(e, at, k)
				e.expect(mirrorDay, 1, m)
			})
			t.Run(f.name+"/另一件事的帶路徑列不誤配", func(t *testing.T) {
				e := newMirrorEnv(t, kind)
				m := f.mirror(e, at, k)
				p := f.path(e, at.Add(50*time.Millisecond), f.other(k))
				e.expect(mirrorDay, 2, m, p)
			})
		}
	})
}

// TestDailyReviewHighRiskMirrorEdgeCases 擋：形態相近的人為操作被當成鏡像吃掉、跨日配對、
// 一對一失守、請求內容取不到時誤排除、帶路徑列晚到時計數跳動
func TestDailyReviewHighRiskMirrorEdgeCases(t *testing.T) {
	at := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	byName := map[string]mirrorForm{}
	for _, f := range mirrorForms {
		byName[f.name] = f
	}
	k := mirrorKey{target: 7, actor: 3, aux: 11}
	mirrorKinds(t, func(t *testing.T, kind string) {
		t.Run("帶真實帳號的資產刪除照計", func(t *testing.T) {
			e := newMirrorEnv(t, kind)
			e.asset(9, at.Add(-10*time.Millisecond))
			e.row(at, model.AuditLog{Action: model.ActionDelete, Resource: model.ResourceAsset, ResourceID: ptr(9), Status: ok(), UserID: 5, Username: "alice"})
			byName["資產刪除的資料層留痕"].path(e, at.Add(50*time.Millisecond), mirrorKey{target: 9, actor: 5})
			e.expect(mirrorDay, 2)
		})
		t.Run("其他事件碼的認證類刪除照計", func(t *testing.T) {
			e := newMirrorEnv(t, kind)
			e.row(at, svcRow(model.ActionDelete, model.ResourceAuth, 3, ptr(7), `{"event":"group_role_mapping_update","rule_id":7,"source_id":11}`))
			byName["群組對角色映射刪除"].path(e, at.Add(50*time.Millisecond), k)
			e.row(at.Add(time.Hour), svcRow(model.ActionDelete, model.ResourceAuth, 3, ptr(1), `{"event":"ldap_directory_save","directory_id":1}`))
			byName["目錄服務設定刪除"].path(e, at.Add(time.Hour+50*time.Millisecond), k)
			e.expect(mirrorDay, 4)
		})
		t.Run("沒有目標帳號鍵的帳號修改照計", func(t *testing.T) {
			e := newMirrorEnv(t, kind)
			e.row(at, svcRow(model.ActionUpdate, model.ResourceUser, 3, ptr(7), `{"event":"external_identity_bound","provider_id":1}`))
			e.row(at.Add(50*time.Millisecond), httpRow(model.ActionCreate, model.ResourceUser, "/api/v1/users/7/external-only", 3, ptr(7)))
			e.expect(mirrorDay, 2)
		})
		t.Run("目錄首登只有一列照計", func(t *testing.T) {
			e := newMirrorEnv(t, kind)
			m := byName["帳號狀態投影（建立）"].mirror(e, at, k)
			e.expect(mirrorDay, 1, m)
		})
		t.Run("跨日的請求兩天各算一次", func(t *testing.T) {
			e := newMirrorEnv(t, kind)
			f := byName["使用者群組刪除"]
			m := f.mirror(e, time.Date(2026, 10, 10, 23, 59, 59, 900_000_000, time.UTC), k)
			p := f.path(e, time.Date(2026, 10, 11, 0, 0, 0, 100_000_000, time.UTC), k)
			e.expect(mirrorDay, 1, m)
			e.expect("2026-10-11", 1, p)
		})
		t.Run("緊接兩次資產刪除只剩一筆帶路徑列", func(t *testing.T) {
			e := newMirrorEnv(t, kind)
			// 先刪 B 再刪 A；A 的帶路徑列沒有落庫。兩筆鏡像都落進 B 的窗口，配對不唯一
			e.asset(21, at)
			mb := e.row(at.Add(5*time.Millisecond), model.AuditLog{Action: model.ActionDelete, Resource: model.ResourceAsset, ResourceID: ptr(0), Status: ok(), Username: "system"})
			e.asset(22, at.Add(20*time.Millisecond))
			ma := e.row(at.Add(25*time.Millisecond), model.AuditLog{Action: model.ActionDelete, Resource: model.ResourceAsset, ResourceID: ptr(0), Status: ok(), Username: "system"})
			pb := e.row(at.Add(60*time.Millisecond), httpRow(model.ActionDelete, model.ResourceAsset, "/api/v1/assets/21", 3, ptr(21)))
			e.expect(mirrorDay, 3, mb, ma, pb)
		})
		t.Run("一筆鏡像列對到兩筆候選帶路徑列照算", func(t *testing.T) {
			e := newMirrorEnv(t, kind)
			f := byName["使用者群組刪除"]
			m := f.mirror(e, at, k)
			p1 := f.path(e, at.Add(50*time.Millisecond), k)
			p2 := f.path(e, at.Add(80*time.Millisecond), k)
			e.expect(mirrorDay, 3, m, p1, p2)
		})
		t.Run("排除數超過上限時一律不排除", func(t *testing.T) {
			e := newMirrorEnv(t, kind)
			saved := mirrorExclusionCap
			mirrorExclusionCap = 0
			t.Cleanup(func() { mirrorExclusionCap = saved })
			f := byName["使用者群組刪除"]
			m := f.mirror(e, at, k)
			p := f.path(e, at.Add(50*time.Millisecond), k)
			e.expect(mirrorDay, 2, m, p)
		})
		t.Run("建帳號請求內容被截斷時照算", func(t *testing.T) {
			e := newMirrorEnv(t, kind)
			byName["帳號狀態投影（建立）"].mirror(e, at, k)
			r := httpRow(model.ActionCreate, model.ResourceUser, "/api/v1/users", 3, nil)
			r.RequestBody = "[TRUNCATED: audit capture limit 65536 bytes]"
			e.row(at.Add(50*time.Millisecond), r)
			e.expect(mirrorDay, 2)
		})
		t.Run("帶路徑列晚到前後計數相同", func(t *testing.T) {
			e := newMirrorEnv(t, kind)
			f := byName["使用者群組刪除"]
			m := f.mirror(e, at, k)
			e.expect(mirrorDay, 1, m)
			p := f.path(e, at.Add(50*time.Millisecond), k)
			e.expect(mirrorDay, 1, p)
		})
		t.Run("外部登入首登的回呼紀錄配對", func(t *testing.T) {
			e := newMirrorEnv(t, kind)
			byName["帳號狀態投影（建立）"].mirror(e, at, k)
			h := e.row(at.Add(2*time.Second), model.AuditLog{Action: model.ActionCreate, Resource: model.ResourceUser, ResourceID: ptr(7),
				Status: ok(), UserID: 7, Username: "name7", Path: "/api/v1/auth/oidc/callback", ErrorMsg: "[auth_method=oidc]",
				Details: `{"auth_method":"oidc","event":"oidc_user_provisioned","provider_id":1,"provider_name":"corp","subject_fingerprint":"ab"}`})
			e.expect(mirrorDay, 1, h)
		})
		t.Run("自助建立代理一個請求三列只算一列", func(t *testing.T) {
			e := newMirrorEnv(t, kind)
			byName["自助建立代理"].mirror(e, at, k)
			e.row(at.Add(10*time.Millisecond), systemRow(model.ActionCreate, ptr(7), principalDetails(7)))
			p := byName["自助建立代理"].path(e, at.Add(50*time.Millisecond), k)
			e.expect(mirrorDay, 1, p)
		})
	})
}
