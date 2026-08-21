package authz

import (
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// approverEligibilityFixtures 六類資格 fixture 的 user id。
type approverEligibilityFixtures struct {
	db *gorm.DB
	// roleApprover 具 approver 角色
	roleApprover uint
	// groupApprover 無 approver 角色但屬某審核方群組（D-7 群組即資格）
	groupApprover uint
	// disabledApprover 角色仍在、帳號已停用
	disabledApprover uint
	// plainUser 純 user，不屬任何審核方群組
	plainUser uint
	// adminOnly 僅具 admin（D-12 的核心案例）
	adminOnly uint
	// adminApprover admin ＋ approver
	adminApprover uint
}

func seedApproverEligibilityFixtures(t *testing.T) approverEligibilityFixtures {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserGroup{},
		&model.Asset{}, &model.ApproverScope{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// 角色主檔：admin／approver／user 三筆
	roles := map[string]uint{}
	for _, name := range []string{model.RoleAdmin, model.RoleApprover, model.RoleUser} {
		r := model.Role{Name: name}
		if err := db.Create(&r).Error; err != nil {
			t.Fatalf("seed role %s: %v", name, err)
		}
		roles[name] = r.ID
	}
	mkUser := func(name string, roleNames ...string) uint {
		u := model.User{Username: name, Email: strPtr(name + "@x"), Active: true}
		if err := db.Create(&u).Error; err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
		for _, rn := range roleNames {
			if err := db.Exec("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", u.ID, roles[rn]).Error; err != nil {
				t.Fatalf("seed user_roles %s/%s: %v", name, rn, err)
			}
		}
		return u.ID
	}
	mkGroupMember := func(userID uint, groupName string) uint {
		g := model.UserGroup{Name: groupName}
		if err := db.Create(&g).Error; err != nil {
			t.Fatalf("seed group %s: %v", groupName, err)
		}
		if err := db.Exec("INSERT INTO user_group_members (user_group_id, user_id) VALUES (?, ?)", g.ID, userID).Error; err != nil {
			t.Fatalf("seed member: %v", err)
		}
		return g.ID
	}
	aid := uint(1)
	if err := db.Create(&model.Asset{Name: "a1", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1}).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}

	f := approverEligibilityFixtures{db: db}
	f.roleApprover = mkUser("role-approver", model.RoleApprover)
	f.groupApprover = mkUser("group-approver", model.RoleUser)
	gid := mkGroupMember(f.groupApprover, "approver-group")
	if err := db.Create(&model.ApproverScope{ApproverGroupID: &gid, AssetID: &aid, GrantedBy: 1}).Error; err != nil {
		t.Fatalf("seed group scope: %v", err)
	}
	// 停用者：兩個入口都不看 active，故仍應放行；列進來是為了證明「停用」這一維
	// 不是分歧點（停用的攔截在 AuthMiddleware）
	f.disabledApprover = mkUser("disabled-approver", model.RoleApprover)
	if err := db.Model(&model.User{}).Where("id = ?", f.disabledApprover).Update("active", false).Error; err != nil {
		t.Fatalf("disable user: %v", err)
	}
	f.plainUser = mkUser("plain-user", model.RoleUser)
	f.adminOnly = mkUser("admin-only", model.RoleAdmin)
	f.adminApprover = mkUser("admin-approver", model.RoleAdmin, model.RoleApprover)
	return f
}

// SD-3「審批者資格兩份真相」的等價守衛（W7 7.3 建立，**W7b 8.10 收斂後改為斷言等價**）。
//
// 兩個匯出入口：
//   - **審核端點守衛入口**＝`EvaluateApproverRouteEligibility`（`middleware.RequireApproverRole` 消費）
//   - **入口／badge 判定**＝`(*AssetAuthorizationService).IsEffectiveApprover`
//     （identity 的登入回應 `is_approver` 消費）
//
// **D-12 收斂（W7b 8.1）後兩個入口必須逐例一致，含 admin 兩類。** 收斂前守衛入口
// 另有一份含 admin 放行的 SQL，W7 的本測試以 `mustAgree=false` 把該落差釘成機器
// 事實；本波把落差消滅，故六類 fixture 一律要求一致，且「僅具 admin」的期望值
// 由 true 改為 **false**（資格改由 approver 角色／審核方群組決定，非 admin 身分）。
//
// **守衛的現實失效模式**：有人在任一入口重新加回 admin 放行分支（例如為了讓
// admin「看得到待審清單」而順手改回），此測試立刻轉紅。突變自檢見 round-log W7b。
//
// 撤銷端點**不在**本等價關係內——`EvaluateRevokeRouteEligibility` 刻意保留
// admin 放行（遏制動作非審核，design.md D-12 訂正），其行為由
// `TestRevokeRouteEligibilityKeepsAdmin` 釘住。
func TestApproverEligibilityParity(t *testing.T) {
	f := seedApproverEligibilityFixtures(t)
	svc := NewAssetAuthorizationService(f.db)

	cases := []struct {
		name string
		id   uint
		// wantGuard 審核端點守衛入口的期望（D-12 後不含 admin）
		wantGuard bool
		// wantEffective IsEffectiveApprover 的期望
		wantEffective bool
	}{
		{"a. 角色審核者", f.roleApprover, true, true},
		{"b. 群組審核者", f.groupApprover, true, true},
		{"c. 已停用的角色審核者", f.disabledApprover, true, true},
		{"d. 範圍不匹配的一般使用者", f.plainUser, false, false},
		// D-12 行為變更（W7b）：admin 身分本身不再構成審核資格
		{"e. 僅具 admin（無 approver、無群組）", f.adminOnly, false, false},
		{"f. admin ＋ approver", f.adminApprover, true, true},
	}

	for _, c := range cases {
		verdict, err := EvaluateApproverRouteEligibility(f.db, c.id)
		if err != nil {
			t.Fatalf("%s：守衛入口查詢失敗: %v", c.name, err)
		}
		effective, err := svc.IsEffectiveApprover(c.id)
		if err != nil {
			t.Fatalf("%s：IsEffectiveApprover 查詢失敗: %v", c.name, err)
		}
		if verdict.Allowed != c.wantGuard {
			t.Errorf("%s：守衛入口 = %v, want %v", c.name, verdict.Allowed, c.wantGuard)
		}
		if effective != c.wantEffective {
			t.Errorf("%s：IsEffectiveApprover = %v, want %v", c.name, effective, c.wantEffective)
		}
		if verdict.Allowed != effective {
			t.Errorf("%s：兩個入口**必須**逐例一致卻分歧（守衛=%v／有效審核者=%v）——"+
				"D-12 收斂後審核資格只有一份真相，分歧代表有人在某一側加回了獨立判準",
				c.name, verdict.Allowed, effective)
		}
	}
}

// TestRevokeRouteEligibilityKeepsAdmin 撤銷端點守衛**刻意不收斂**（W7b 8.2 端點分離）：
// 撤銷是遏制動作不是審核，既有 spec 明定資格＝admin OR 原核准人；一併收斂會使
// admin 無法撤銷已核出的票證＝安全倒退（design.md D-12 訂正）
func TestRevokeRouteEligibilityKeepsAdmin(t *testing.T) {
	f := seedApproverEligibilityFixtures(t)

	cases := []struct {
		name        string
		id          uint
		wantAllowed bool
		wantIsAdmin bool
	}{
		{"僅具 admin：撤銷仍放行且帶 admin 旗標", f.adminOnly, true, true},
		{"有效審核者：放行且非 admin", f.roleApprover, true, false},
		{"審核方群組成員：放行且非 admin", f.groupApprover, true, false},
		{"一般使用者：不放行", f.plainUser, false, false},
	}
	for _, c := range cases {
		v, err := EvaluateRevokeRouteEligibility(f.db, c.id)
		if err != nil {
			t.Fatalf("%s：查詢失敗: %v", c.name, err)
		}
		if v.Allowed != c.wantAllowed {
			t.Errorf("%s：Allowed = %v, want %v", c.name, v.Allowed, c.wantAllowed)
		}
		if v.IsAdmin != c.wantIsAdmin {
			t.Errorf("%s：IsAdmin = %v, want %v", c.name, v.IsAdmin, c.wantIsAdmin)
		}
	}

	// 收斂的邊界：撤銷放行 admin、審核不放行——兩者對「僅具 admin」必須分歧
	approverVerdict, err := EvaluateApproverRouteEligibility(f.db, f.adminOnly)
	if err != nil {
		t.Fatalf("審核入口查詢失敗: %v", err)
	}
	if approverVerdict.Allowed {
		t.Error("僅具 admin 者不應通過審核端點守衛（D-12）")
	}
}
