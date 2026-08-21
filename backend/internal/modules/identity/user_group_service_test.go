package identity

import (
	"context"
	"errors"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// uptrScope／strPtr 測試助手（原宣告於隨 W7 遷入 authz 的
// access_request_service_test.go；本包多處仍在用，故留同名同義的複本）
func uptrScope(v uint) *uint { return &v }

func strPtr(s string) *string { return &s }

func setupUserGroupDB(t *testing.T) (*UserGroupService, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.UserGroup{}, &model.Asset{},
		&model.AssetGroup{}, &model.AssetNode{}, &model.AssetAuthorization{},
		&model.ApproverScope{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewUserGroupService(db, audit.NewTxSink(), authz.NewAssetAuthorizationService(db)), db
}

func seedUsers(t *testing.T, db *gorm.DB, names ...string) []model.User {
	t.Helper()
	users := make([]model.User, len(names))
	for i, n := range names {
		users[i] = model.User{Username: n, Email: strPtr(n + "@x")}
		if err := db.Create(&users[i]).Error; err != nil {
			t.Fatalf("seed user %s: %v", n, err)
		}
	}
	return users
}

func TestUserGroupCRUD(t *testing.T) {
	svc, _ := setupUserGroupDB(t)

	g, err := svc.Create(&UserGroupRequest{Name: "營運組", Description: "ops"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := svc.Create(&UserGroupRequest{Name: "營運組"}); !errors.Is(err, ErrUserGroupNameExists) {
		t.Errorf("重名 = %v, want ErrUserGroupNameExists", err)
	}

	updated, err := svc.Update(g.ID, &UserGroupRequest{Name: "維運組", Description: "renamed"})
	if err != nil || updated.Name != "維運組" {
		t.Fatalf("Update = %+v, %v", updated, err)
	}
	if _, err := svc.Update(999, &UserGroupRequest{Name: "x"}); !errors.Is(err, ErrUserGroupNotFound) {
		t.Errorf("更新不存在 = %v", err)
	}

	groups, err := svc.List()
	if err != nil || len(groups) != 1 {
		t.Fatalf("List = %d, %v", len(groups), err)
	}
}

func TestUserGroupReplaceMembers(t *testing.T) {
	svc, db := setupUserGroupDB(t)
	users := seedUsers(t, db, "u1", "u2", "u3")
	g, _ := svc.Create(&UserGroupRequest{Name: "G"})

	// 全量替換：u1+u2
	got, err := svc.ReplaceMembers(g.ID, []uint{users[0].ID, users[1].ID})
	if err != nil || len(got.Users) != 2 {
		t.Fatalf("ReplaceMembers = %d members, %v", len(got.Users), err)
	}

	// 再替換成 u3（穿梭框語義：舊成員被移出）
	got, err = svc.ReplaceMembers(g.ID, []uint{users[2].ID})
	if err != nil || len(got.Users) != 1 || got.Users[0].Username != "u3" {
		t.Fatalf("second Replace = %+v, %v", got.Users, err)
	}

	// 名單含不存在使用者整批拒
	if _, err := svc.ReplaceMembers(g.ID, []uint{users[0].ID, 999}); !errors.Is(err, ErrUserGroupMemberNotFound) {
		t.Errorf("幽靈成員 = %v, want ErrUserGroupMemberNotFound", err)
	}

	// 清空成員
	got, err = svc.ReplaceMembers(g.ID, nil)
	if err != nil || len(got.Users) != 0 {
		t.Fatalf("clear members = %d, %v", len(got.Users), err)
	}
}

// TestUserGroupDeleteCascade 刪群組連動：成員關係清除＋授權軟刪＋審計留痕
func TestUserGroupDeleteCascade(t *testing.T) {
	svc, db := setupUserGroupDB(t)
	users := seedUsers(t, db, "u1")
	g, _ := svc.Create(&UserGroupRequest{Name: "G"})
	if _, err := svc.ReplaceMembers(g.ID, []uint{users[0].ID}); err != nil {
		t.Fatalf("seed members: %v", err)
	}

	db.Create(&model.Asset{Name: "a1", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1})
	aid := uint(1)
	if err := db.Create(&model.AssetAuthorization{
		UserGroupID: &g.ID, AssetID: &aid, Permission: model.PermissionConnect, GrantedBy: 1,
	}).Error; err != nil {
		t.Fatalf("seed grant: %v", err)
	}

	if n, err := svc.AuthorizationCount(g.ID); err != nil || n != 1 {
		t.Fatalf("AuthorizationCount = %d, %v", n, err)
	}

	// 審核範圍：群組作審核方＋作申請人群組各一筆（approval-routing-quorum D-7）——
	// 刪群組應連動軟刪，防幽靈引用與殘留成員回復資格（對抗驗證 aaa2018）
	if err := db.Create(&model.ApproverScope{ApproverGroupID: &g.ID, AssetID: &aid, GrantedBy: 1}).Error; err != nil {
		t.Fatalf("seed actor scope: %v", err)
	}
	if err := db.Create(&model.ApproverScope{ApproverID: uptrScope(1), SubjectGroupID: &g.ID, GrantedBy: 1}).Error; err != nil {
		t.Fatalf("seed subject-group scope: %v", err)
	}

	revoked, err := svc.Delete(g.ID, 1, "admin", "127.0.0.1")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if revoked != 1 {
		t.Fatalf("revoked = %d, want 1", revoked)
	}

	// 審核範圍連動軟刪（活躍 0，兩筆皆失效）
	var activeScopes int64
	db.Model(&model.ApproverScope{}).
		Where("approver_group_id = ? OR subject_group_id = ?", g.ID, g.ID).
		Count(&activeScopes)
	if activeScopes != 0 {
		t.Errorf("群組審核範圍應連動軟刪, got %d 活躍", activeScopes)
	}

	// 群組消失
	if _, err := svc.Update(g.ID, &UserGroupRequest{Name: "x"}); !errors.Is(err, ErrUserGroupNotFound) {
		t.Errorf("刪後更新 = %v", err)
	}
	// 成員關係清除
	var members int64
	db.Table("user_group_members").Where("user_group_id = ?", g.ID).Count(&members)
	if members != 0 {
		t.Errorf("成員關係應清除, got %d", members)
	}
	// 授權軟刪（活躍 0、留痕 1）
	var active, all int64
	db.Model(&model.AssetAuthorization{}).Where("user_group_id = ?", g.ID).Count(&active)
	db.Unscoped().Model(&model.AssetAuthorization{}).Where("user_group_id = ?", g.ID).Count(&all)
	if active != 0 || all != 1 {
		t.Errorf("授權應軟刪留痕: active=%d all=%d", active, all)
	}
	// 審計留痕
	var entry model.AuditLog
	if err := db.Where("resource = ?", model.ResourceUserGroup).First(&entry).Error; err != nil {
		t.Fatalf("審計記錄應存在: %v", err)
	}
	if !strings.Contains(entry.Details, "revoked_authorizations") || entry.Username != "admin" {
		t.Errorf("審計內容不完整: %+v", entry)
	}

	if _, err := svc.Delete(999, 1, "admin", ""); !errors.Is(err, ErrUserGroupNotFound) {
		t.Errorf("刪不存在 = %v", err)
	}
}

// --- 批次授權（GrantBatch，SQLite 真語義）---

func setupBatchEnv(t *testing.T) (*authz.AssetAuthorizationService, *gorm.DB, []model.User, model.UserGroup) {
	t.Helper()
	_, db := setupUserGroupDB(t)
	svc := authz.NewAssetAuthorizationService(db)
	users := seedUsers(t, db, "b1", "b2")
	var group model.UserGroup
	group = model.UserGroup{Name: "bg"}
	if err := db.Create(&group).Error; err != nil {
		t.Fatalf("seed group: %v", err)
	}
	db.Create(&model.Asset{Name: "a1", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1})
	db.Create(&model.Asset{Name: "a2", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1})
	db.Create(&model.AssetGroup{Name: "ag"})
	return svc, db, users, group
}

func TestGrantBatch_ExpandAndSkip(t *testing.T) {
	svc, db, users, group := setupBatchEnv(t)
	ctx := context.Background()

	// 預先存在一筆（u1×a1×connect）→ 批次時跳過
	u1 := users[0].ID
	a1 := uint(1)
	if err := db.Create(&model.AssetAuthorization{
		UserID: &u1, AssetID: &a1, Permission: model.PermissionConnect, GrantedBy: 1,
	}).Error; err != nil {
		t.Fatalf("seed existing: %v", err)
	}

	// 主體：2 user + 1 group；客體：2 asset + 1 asset_group → 展開 9，跳過 1
	res, err := svc.GrantBatch(ctx,
		[]uint{users[0].ID, users[1].ID}, []uint{group.ID},
		[]uint{1, 2}, []uint{1},
		model.PermissionConnect, 1, nil)
	if err != nil {
		t.Fatalf("GrantBatch: %v", err)
	}
	if res.Created != 8 || res.Skipped != 1 {
		t.Fatalf("created=%d skipped=%d, want 8/1", res.Created, res.Skipped)
	}

	var total int64
	db.Model(&model.AssetAuthorization{}).Count(&total)
	if total != 9 {
		t.Fatalf("總筆數 = %d, want 9", total)
	}

	// 每筆主體/客體恰一（BeforeCreate 擋，這裡驗資料面）
	var bad int64
	db.Model(&model.AssetAuthorization{}).
		Where("(user_id IS NULL) = (user_group_id IS NULL) OR (asset_id IS NULL) = (asset_group_id IS NULL)").
		Count(&bad)
	if bad != 0 {
		t.Fatalf("有 %d 筆主體/客體形狀非法", bad)
	}

	// 冪等：重跑全部跳過
	res2, err := svc.GrantBatch(ctx,
		[]uint{users[0].ID, users[1].ID}, []uint{group.ID},
		[]uint{1, 2}, []uint{1},
		model.PermissionConnect, 1, nil)
	if err != nil || res2.Created != 0 || res2.Skipped != 9 {
		t.Fatalf("重跑 created=%d skipped=%d err=%v, want 0/9", res2.Created, res2.Skipped, err)
	}
}

// TestGrantBatch_ConflictSkipNotError 既有組合以 ON CONFLICT DO NOTHING 原子跳過，
// 不因唯一索引衝突整批回滾回錯（codex P2：先查後寫並發不安全，改交 DB 兜底）
func TestGrantBatch_ConflictSkipNotError(t *testing.T) {
	svc, db, users, _ := setupBatchEnv(t)
	ctx := context.Background()

	// 預置 u1×a1×view
	u1 := users[0].ID
	a1 := uint(1)
	if err := db.Create(&model.AssetAuthorization{
		UserID: &u1, AssetID: &a1, Permission: model.PermissionView, GrantedBy: 1,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	// 批次含既有組合 + 新組合，不得報錯
	res, err := svc.GrantBatch(ctx, []uint{users[0].ID}, nil, []uint{1, 2}, nil, model.PermissionView, 1, nil)
	if err != nil {
		t.Fatalf("批次遇既有組合不應報錯: %v", err)
	}
	if res.Created != 1 || res.Skipped != 1 {
		t.Fatalf("created=%d skipped=%d, want 1/1（u1×a2 新增、u1×a1 跳過）", res.Created, res.Skipped)
	}

	var total int64
	db.Model(&model.AssetAuthorization{}).Count(&total)
	if total != 2 {
		t.Fatalf("總筆數 = %d, want 2（無重複插入）", total)
	}
}

func TestGrantBatch_Validation(t *testing.T) {
	svc, _, users, _ := setupBatchEnv(t)
	ctx := context.Background()

	// 空主體/空客體
	if _, err := svc.GrantBatch(ctx, nil, nil, []uint{1}, nil, model.PermissionView, 1, nil); !errors.Is(err, authz.ErrBatchEmpty) {
		t.Errorf("空主體 = %v", err)
	}
	if _, err := svc.GrantBatch(ctx, []uint{users[0].ID}, nil, nil, nil, model.PermissionView, 1, nil); !errors.Is(err, authz.ErrBatchEmpty) {
		t.Errorf("空客體 = %v", err)
	}

	// 引用不存在整批拒（不部分寫入）
	if _, err := svc.GrantBatch(ctx, []uint{users[0].ID, 999}, nil, []uint{1}, nil, model.PermissionView, 1, nil); err == nil ||
		!strings.Contains(err.Error(), "不存在") {
		t.Errorf("幽靈使用者 = %v", err)
	}
	if _, err := svc.GrantBatch(ctx, []uint{users[0].ID}, nil, []uint{999}, nil, model.PermissionView, 1, nil); err == nil ||
		!strings.Contains(err.Error(), "不存在") {
		t.Errorf("幽靈資產 = %v", err)
	}
}

func TestGrantBatch_ExpansionLimit(t *testing.T) {
	svc, _, users, _ := setupBatchEnv(t)

	// 展開上限：構造超過 authz.MaxBatchExpansion 的 id 集（不觸 DB——上限先於引用驗證）
	manyAssets := make([]uint, authz.MaxBatchExpansion+1)
	for i := range manyAssets {
		manyAssets[i] = uint(i + 1)
	}
	if _, err := svc.GrantBatch(context.Background(), []uint{users[0].ID}, nil, manyAssets, nil, model.PermissionView, 1, nil); !errors.Is(err, authz.ErrBatchTooLarge) {
		t.Errorf("超上限 = %v, want authz.ErrBatchTooLarge", err)
	}
}
