package identity

import (
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 管理面兩條角色端點的作用範圍（外部群組映射落地後）。
//
// 替換端點的主體描述的是**管理者指派集**，不是有效角色集。這一組釘住三件事：
//
//  1. 僅由映射賦予的列不因替換而被刪、被升格；
//  2. 憑證世代的推進判準是「有效角色集是否有列被移除」，純追加不推進；
//  3. 冪等追加端點是把映射列固定下來的原語（升為並存態，不新建列）。
//
// 第 1 點是這一組存在的理由：介面以有效集預填再整包送出，不收斂作用範圍的話，
// 每一次確認都把映射賦予的角色靜默轉成管理者指派，而審計上與正常指派無從區分。

// manualEndpointDB 帶本組所需六張表的單連線 :memory: fixture。
//
// UserRole 必須排在 User／Role 之後（many2many 標籤建出的兩欄關聯表會蓋掉
// 排在它之前的宣告，症狀是無關斷言上的 no such column: user_roles.source）。
func manualEndpointDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db handle: %v", err)
	}
	// **單連線**：`:memory:` 配連線池時每條連線是各自獨立的空 DB
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.AuditLog{},
		&model.RefreshToken{}, &model.PasswordHistory{},
		&model.UserRole{}, &model.UserRoleMapping{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })
	return db
}

// manualEndpointSubject 一個帳號與三個非管理員角色（本組刻意避開 admin：
// 本地管理員不變式是另一條被獨立測試蓋住的分支）。
func manualEndpointSubject(t *testing.T, db *gorm.DB) (userID uint, roleIDs map[string]uint) {
	t.Helper()
	u := &model.User{Username: "scope-subject", Password: "x", Active: true}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("建帳號: %v", err)
	}
	roleIDs = map[string]uint{}
	for _, name := range []string{"role-a", "role-b", "role-c"} {
		r := &model.Role{Name: name}
		if err := db.Create(r).Error; err != nil {
			t.Fatalf("建角色 %s: %v", name, err)
		}
		roleIDs[name] = r.ID
	}
	return u.ID, roleIDs
}

// manualEndpointChannel 測試用的映射通道識別（形態由 model 產生，不自行拼字串）
func manualEndpointChannel(t *testing.T) string {
	t.Helper()
	return model.RoleMappingChannel(model.RoleMappingChannelKindDirectory, 1)
}

// giveManualRole 讓（帳號，角色）成為管理者指派的列
func giveManualRole(t *testing.T, db *gorm.DB, userID, roleID uint) {
	t.Helper()
	if err := db.Create(&model.UserRole{
		UserID: userID, RoleID: roleID, Source: model.RoleSourceManual,
	}).Error; err != nil {
		t.Fatalf("建手動列: %v", err)
	}
}

// giveMappedRole 讓（帳號，角色）成為僅由映射賦予的列（來源欄與映射事實一併落）
func giveMappedRole(t *testing.T, db *gorm.DB, userID, roleID uint, channel string) {
	t.Helper()
	if err := db.Create(&model.UserRole{
		UserID: userID, RoleID: roleID, Source: model.RoleSourceMapped,
	}).Error; err != nil {
		t.Fatalf("建映射列: %v", err)
	}
	if err := db.Create(&model.UserRoleMapping{
		UserID: userID, RoleID: roleID, Channel: channel,
		MatchedAt: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC),
	}).Error; err != nil {
		t.Fatalf("建映射事實: %v", err)
	}
}

// roleSourceValue 讀回關聯列的來源（不存在時回 "absent"）
func roleSourceValue(t *testing.T, db *gorm.DB, userID, roleID uint) string {
	t.Helper()
	source, exists, err := model.UserRoleSourceOf(db, userID, roleID)
	if err != nil {
		t.Fatalf("讀來源: %v", err)
	}
	if !exists {
		return "absent"
	}
	return source
}

// currentEpoch 讀回憑證世代
func currentEpoch(t *testing.T, db *gorm.DB, userID uint) int64 {
	t.Helper()
	var u model.User
	if err := db.First(&u, userID).Error; err != nil {
		t.Fatalf("讀帳號: %v", err)
	}
	return int64(u.CredentialEpoch)
}

// TestAssignRolesLeavesMappedRows 替換端點不動僅由映射賦予的列。
//
// 這是本案的必修項：不收斂作用範圍，替換就會把映射列一併刪掉，
// 而那些權限下一次登入才會回來——中間這段時間權限是錯的，且刪列會推進世代把人踢下線。
func TestAssignRolesLeavesMappedRows(t *testing.T) {
	db := manualEndpointDB(t)
	svc := NewUserService(db, nil)
	userID, roles := manualEndpointSubject(t, db)
	channel := manualEndpointChannel(t)
	giveManualRole(t, db, userID, roles["role-b"])
	giveMappedRole(t, db, userID, roles["role-a"], channel)
	epochBefore := currentEpoch(t, db, userID)

	// 主體只描述管理者指派集：映射賦予的 role-a 不在其中
	result, err := svc.AssignRoles(userID, []string{"role-b"})
	if err != nil {
		t.Fatalf("AssignRoles: %v", err)
	}

	if got := roleSourceValue(t, db, userID, roles["role-a"]); got != model.RoleSourceMapped {
		t.Errorf("映射列的來源 = %q, want %q（替換端點不得動它）", got, model.RoleSourceMapped)
	}
	var facts int64
	if err := db.Model(&model.UserRoleMapping{}).
		Where("user_id = ? AND role_id = ?", userID, roles["role-a"]).
		Count(&facts).Error; err != nil {
		t.Fatalf("數映射事實: %v", err)
	}
	if facts != 1 {
		t.Errorf("映射事實列數 = %d, want 1（事實源被替換端點刪掉即等於失去該權限）", facts)
	}
	if got := currentEpoch(t, db, userID); got != epochBefore {
		t.Errorf("憑證世代 = %d, want %d（無撤除不得推進）", got, epochBefore)
	}
	// 讀取端拆兩份集合：兩者並存以外的角色只出現在自己那一份
	if len(result.Sets.Manual) != 1 || result.Sets.Manual[0] != "role-b" {
		t.Errorf("管理者指派集 = %v, want [role-b]", result.Sets.Manual)
	}
	if len(result.Sets.Mapped) != 1 || result.Sets.Mapped[0] != "role-a" {
		t.Errorf("映射集 = %v, want [role-a]", result.Sets.Mapped)
	}
}

// TestAssignRolesEffectiveSetShrinkBumps 有效集確有列被移除時推進世代。
//
// 反向護欄在 TestAssignRolesPureAdditionNoBump：兩者一起才說得清判準是「有沒有撤除」
// 而不是「集合有沒有變」。
func TestAssignRolesEffectiveSetShrinkBumps(t *testing.T) {
	db := manualEndpointDB(t)
	svc := NewUserService(db, nil)
	userID, roles := manualEndpointSubject(t, db)
	giveManualRole(t, db, userID, roles["role-a"])
	giveManualRole(t, db, userID, roles["role-b"])
	epochBefore := currentEpoch(t, db, userID)

	if _, err := svc.AssignRoles(userID, []string{"role-a"}); err != nil {
		t.Fatalf("AssignRoles: %v", err)
	}

	if got := roleSourceValue(t, db, userID, roles["role-b"]); got != "absent" {
		t.Fatalf("role-b 應已被移除，實得來源 %q（前提不成立則本測試無意義）", got)
	}
	if got := currentEpoch(t, db, userID); got != epochBefore+1 {
		t.Errorf("憑證世代 = %d, want %d（有效集縮減必須推進）", got, epochBefore+1)
	}
}

// TestAssignRolesSwapRolesBumps 角色數量不變但確有撤除時推進世代。
//
// 判準若寫成「角色數量是否變少」，一個特權角色換成另一個就完全不推進——
// 被撤走的那個角色仍在既簽憑證的快照裡，管理端判定照樣放行。
func TestAssignRolesSwapRolesBumps(t *testing.T) {
	db := manualEndpointDB(t)
	svc := NewUserService(db, nil)
	userID, roles := manualEndpointSubject(t, db)
	giveManualRole(t, db, userID, roles["role-a"])
	giveManualRole(t, db, userID, roles["role-b"])
	epochBefore := currentEpoch(t, db, userID)

	// 兩個換兩個：數量不變，role-b 被撤除
	if _, err := svc.AssignRoles(userID, []string{"role-a", "role-c"}); err != nil {
		t.Fatalf("AssignRoles: %v", err)
	}

	if got := roleSourceValue(t, db, userID, roles["role-b"]); got != "absent" {
		t.Fatalf("role-b 應已被移除，實得來源 %q", got)
	}
	if got := roleSourceValue(t, db, userID, roles["role-c"]); got != model.RoleSourceManual {
		t.Fatalf("role-c 應已加入管理者指派集，實得來源 %q", got)
	}
	if got := currentEpoch(t, db, userID); got != epochBefore+1 {
		t.Errorf("憑證世代 = %d, want %d（數量不變但有撤除，仍須推進）", got, epochBefore+1)
	}
}

// TestAssignRolesPureAdditionNoBump 純追加不推進世代。
//
// 純追加不撤走任何憑證已賦予的能力，推進世代只是把人無故踢下線；
// 冪等追加端點本就不推進，兩條路徑於此不再不對稱。
func TestAssignRolesPureAdditionNoBump(t *testing.T) {
	db := manualEndpointDB(t)
	svc := NewUserService(db, nil)
	userID, roles := manualEndpointSubject(t, db)
	giveManualRole(t, db, userID, roles["role-a"])
	epochBefore := currentEpoch(t, db, userID)

	if _, err := svc.AssignRoles(userID, []string{"role-a", "role-b"}); err != nil {
		t.Fatalf("AssignRoles: %v", err)
	}

	if got := roleSourceValue(t, db, userID, roles["role-b"]); got != model.RoleSourceManual {
		t.Fatalf("role-b 應已加入管理者指派集，實得來源 %q（前提不成立則本測試無意義）", got)
	}
	if got := currentEpoch(t, db, userID); got != epochBefore {
		t.Errorf("憑證世代 = %d, want %d（純追加不得推進）", got, epochBefore)
	}
}

// TestAssignRolesIgnoresMappedOnlyInBody 主體含僅由映射賦予的角色時忽略之，並於揭露欄告知。
//
// 這正是「讀出來整包回寫」的形狀：用戶端把兩份集合併起來送回。
// 升為並存態會讓那一次確認靜默變成釘住，報錯則會讓既有用法全數壞掉。
func TestAssignRolesIgnoresMappedOnlyInBody(t *testing.T) {
	db := manualEndpointDB(t)
	svc := NewUserService(db, nil)
	userID, roles := manualEndpointSubject(t, db)
	channel := manualEndpointChannel(t)
	giveManualRole(t, db, userID, roles["role-b"])
	giveMappedRole(t, db, userID, roles["role-a"], channel)
	epochBefore := currentEpoch(t, db, userID)

	// 有效角色集原樣回送
	result, err := svc.AssignRoles(userID, []string{"role-a", "role-b"})
	if err != nil {
		t.Fatalf("AssignRoles: %v", err)
	}

	if got := roleSourceValue(t, db, userID, roles["role-a"]); got != model.RoleSourceMapped {
		t.Errorf("role-a 的來源 = %q, want %q（回送有效集不得升格為並存態）",
			got, model.RoleSourceMapped)
	}
	if got := currentEpoch(t, db, userID); got != epochBefore {
		t.Errorf("憑證世代 = %d, want %d", got, epochBefore)
	}
	if len(result.Disclosures) != 1 {
		t.Fatalf("揭露欄筆數 = %d, want 1：%+v（被忽略的角色不揭露，介面就無從提示釘住）",
			len(result.Disclosures), result.Disclosures)
	}
	if result.Disclosures[0].Code != DisclosureRoleMappedIgnored {
		t.Errorf("揭露碼 = %q, want %q", result.Disclosures[0].Code, DisclosureRoleMappedIgnored)
	}
	if got := result.Disclosures[0].Params["roles"]; got != "role-a" {
		t.Errorf("揭露參數 roles = %q, want %q", got, "role-a")
	}
}

// TestAddRolePromotesMappedToBoth 冪等追加端點把映射列升為並存態。
//
// 這是把外部群組賦予的角色固定下來的原語：升為並存之後，該角色不再隨群組異動消失。
// 不新建列、不改變有效集，故不推進世代、也不留痕（來源欄是投影）。
func TestAddRolePromotesMappedToBoth(t *testing.T) {
	db := manualEndpointDB(t)
	svc := NewUserService(db, nil)
	userID, roles := manualEndpointSubject(t, db)
	channel := manualEndpointChannel(t)
	giveMappedRole(t, db, userID, roles["role-a"], channel)
	epochBefore := currentEpoch(t, db, userID)

	if err := svc.AddRole(userID, "role-a"); err != nil {
		t.Fatalf("AddRole: %v", err)
	}

	if got := roleSourceValue(t, db, userID, roles["role-a"]); got != model.RoleSourceBoth {
		t.Errorf("role-a 的來源 = %q, want %q", got, model.RoleSourceBoth)
	}
	var rows int64
	if err := db.Model(&model.UserRole{}).
		Where("user_id = ? AND role_id = ?", userID, roles["role-a"]).
		Count(&rows).Error; err != nil {
		t.Fatalf("數關聯列: %v", err)
	}
	if rows != 1 {
		t.Errorf("關聯列數 = %d, want 1（固定是單條更新，不是新建列）", rows)
	}
	var facts int64
	if err := db.Model(&model.UserRoleMapping{}).
		Where("user_id = ? AND role_id = ?", userID, roles["role-a"]).
		Count(&facts).Error; err != nil {
		t.Fatalf("數映射事實: %v", err)
	}
	if facts != 1 {
		t.Errorf("映射事實列數 = %d, want 1（固定不抹掉映射成分）", facts)
	}
	if got := currentEpoch(t, db, userID); got != epochBefore {
		t.Errorf("憑證世代 = %d, want %d（固定不擴張也不縮減有效集）", got, epochBefore)
	}
}
