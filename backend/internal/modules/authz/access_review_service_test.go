package authz

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupAccessReviewDB(t *testing.T) (*AccessReviewService, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	// AuditLog 必須一併建：Asset 的 AfterCreate hook 會寫 audit_logs，缺表則 hook
	// 報錯回滾 asset 建立，導致矩陣 join 找不到資產。UserGroup：群組主體 join
	if err := db.AutoMigrate(&model.AssetAuthorization{}, &model.User{}, &model.UserGroup{},
		&model.Asset{}, &model.AssetGroup{}, &model.AssetNode{}, &model.AccessReview{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewAccessReviewService(db), db
}

func seedAuth(t *testing.T, db *gorm.DB, userID uint, assetID *uint, groupID *uint, perm model.PermissionType) {
	t.Helper()
	if err := db.Create(&model.AssetAuthorization{
		UserID: &userID, AssetID: assetID, AssetGroupID: groupID, Permission: perm, GrantedBy: 1,
	}).Error; err != nil {
		t.Fatalf("seed auth: %v", err)
	}
}

// seedGroupAuth 群組主體授權（user_id 為 NULL）
func seedGroupAuth(t *testing.T, db *gorm.DB, userGroupID uint, assetID *uint, groupID *uint, perm model.PermissionType) {
	t.Helper()
	if err := db.Create(&model.AssetAuthorization{
		UserGroupID: &userGroupID, AssetID: assetID, AssetGroupID: groupID, Permission: perm, GrantedBy: 1,
	}).Error; err != nil {
		t.Fatalf("seed group auth: %v", err)
	}
}

// TestAccessMatrixListsAllAuthorizations 矩陣列出全部授權（含 asset 與 group 兩型）
func TestAccessMatrixListsAllAuthorizations(t *testing.T) {
	svc, db := setupAccessReviewDB(t)
	db.Create(&model.User{Username: "alice"})                                                   // id 1
	db.Create(&model.Asset{Name: "web-01", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1}) // id 1
	db.Create(&model.AssetGroup{Name: "prod"})                                                  // id 1

	aid := uint(1)
	gid := uint(1)
	seedAuth(t, db, 1, &aid, nil, model.PermissionConnect)
	seedAuth(t, db, 1, nil, &gid, model.PermissionView)

	matrix, err := svc.GetMatrix()
	if err != nil {
		t.Fatalf("GetMatrix: %v", err)
	}
	if len(matrix) != 2 {
		t.Fatalf("矩陣列數 = %d, want 2", len(matrix))
	}
	// 名稱 join 正確
	var sawAsset, sawGroup bool
	for _, e := range matrix {
		if e.Username != "alice" {
			t.Errorf("username join 錯誤: %s", e.Username)
		}
		if e.AssetName == "web-01" {
			sawAsset = true
		}
		if e.GroupName == "prod" {
			sawGroup = true
		}
	}
	if !sawAsset || !sawGroup {
		t.Error("矩陣應同時涵蓋 asset 授權與 group 授權")
	}
}

// TestAccessMatrixHandlesGroupSubject 群組主體授權（user_id NULL）不得使矩陣崩壞，
// 且須帶群組主體識別資訊（user_id 改 nullable 後 raw select 掃進 uint 會壞）
func TestAccessMatrixHandlesGroupSubject(t *testing.T) {
	svc, db := setupAccessReviewDB(t)
	db.Create(&model.User{Username: "alice"}) // id 1
	db.Create(&model.UserGroup{Name: "ops"})  // id 1
	db.Create(&model.Asset{Name: "web-01", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1})

	aid := uint(1)
	seedAuth(t, db, 1, &aid, nil, model.PermissionConnect)   // 個人主體
	seedGroupAuth(t, db, 1, &aid, nil, model.PermissionView) // 群組主體（user_id NULL）

	matrix, err := svc.GetMatrix()
	if err != nil {
		t.Fatalf("GetMatrix 不得因群組主體崩壞: %v", err)
	}
	if len(matrix) != 2 {
		t.Fatalf("矩陣列數 = %d, want 2", len(matrix))
	}

	var sawUserSubject, sawGroupSubject bool
	for _, e := range matrix {
		if e.UserID != nil && *e.UserID == 1 && e.Username == "alice" {
			sawUserSubject = true
		}
		if e.UserGroupID != nil && *e.UserGroupID == 1 {
			sawGroupSubject = true
			if e.UserGroupName != "ops" {
				t.Errorf("群組主體名稱 = %q, want ops", e.UserGroupName)
			}
			if e.UserID != nil {
				t.Error("群組主體列的 user_id 應為 nil")
			}
		}
	}
	if !sawUserSubject || !sawGroupSubject {
		t.Error("矩陣應同時涵蓋使用者主體與群組主體，且各自可辨識")
	}

	// 簽核（快照序列化）也不得崩壞
	if _, err := svc.CreateReview(1, "admin", "含群組主體授權"); err != nil {
		t.Fatalf("CreateReview 不得因群組主體崩壞: %v", err)
	}
}

// TestCreateReviewSnapshotsMatrix 簽核快照當下矩陣為不可變證據
func TestCreateReviewSnapshotsMatrix(t *testing.T) {
	svc, db := setupAccessReviewDB(t)
	db.Create(&model.User{Username: "bob"})
	db.Create(&model.Asset{Name: "db-01", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1})
	aid := uint(1)
	seedAuth(t, db, 1, &aid, nil, model.PermissionConnect)

	review, err := svc.CreateReview(9, "admin", "季度複審，無異常")
	if err != nil {
		t.Fatalf("CreateReview: %v", err)
	}
	if review.AuthorizationCount != 1 {
		t.Errorf("授權筆數 = %d, want 1", review.AuthorizationCount)
	}
	// 回應不帶大型快照
	if review.MatrixSnapshot != "" {
		t.Error("回應不應含 MatrixSnapshot")
	}

	// 快照落庫且可解析（不可變證據）
	snap, err := svc.GetReviewSnapshot(review.ID)
	if err != nil {
		t.Fatalf("GetReviewSnapshot: %v", err)
	}
	var entries []AccessMatrixEntry
	if err := json.Unmarshal([]byte(snap), &entries); err != nil {
		t.Fatalf("快照不可解析: %v", err)
	}
	if len(entries) != 1 || entries[0].Username != "bob" {
		t.Errorf("快照內容錯誤: %+v", entries)
	}

	// 複審後再改授權，不影響已存快照（不可變）
	seedAuth(t, db, 1, func() *uint { v := uint(2); return &v }(), nil, model.PermissionView)
	snap2, _ := svc.GetReviewSnapshot(review.ID)
	var entries2 []AccessMatrixEntry
	json.Unmarshal([]byte(snap2), &entries2)
	if len(entries2) != 1 {
		t.Error("既存複審快照不應隨後續授權變動（不可變證據）")
	}
}

// TestLastReviewDaysAgo 上次複審天數；從未複審回 -1
func TestLastReviewDaysAgo(t *testing.T) {
	svc, db := setupAccessReviewDB(t)

	if d, _ := svc.LastReviewDaysAgo(); d != -1 {
		t.Errorf("從未複審應回 -1, got %d", d)
	}

	// 種一筆 10 天前的複審
	db.Create(&model.AccessReview{
		ReviewedBy: 1, ReviewerName: "admin", ReviewedAt: time.Now().AddDate(0, 0, -10),
		Scope: "全部", Note: "", AuthorizationCount: 0, MatrixSnapshot: "[]",
	})
	d, err := svc.LastReviewDaysAgo()
	if err != nil {
		t.Fatalf("LastReviewDaysAgo: %v", err)
	}
	if d != 10 {
		t.Errorf("距今天數 = %d, want 10", d)
	}
}

// TestListReviewsExcludesSnapshot 列表附距今天數且不含大型快照
func TestListReviewsExcludesSnapshot(t *testing.T) {
	svc, db := setupAccessReviewDB(t)
	db.Create(&model.AccessReview{
		ReviewedBy: 1, ReviewerName: "admin", ReviewedAt: time.Now().AddDate(0, 0, -3),
		Scope: "全部", Note: "ok", AuthorizationCount: 5, MatrixSnapshot: `[{"big":"data"}]`,
	})
	views, err := svc.ListReviews(10)
	if err != nil {
		t.Fatalf("ListReviews: %v", err)
	}
	if len(views) != 1 {
		t.Fatalf("複審數 = %d, want 1", len(views))
	}
	if views[0].DaysAgo != 3 {
		t.Errorf("DaysAgo = %d, want 3", views[0].DaysAgo)
	}
	if views[0].MatrixSnapshot != "" {
		t.Error("列表不應帶 MatrixSnapshot")
	}
}

// TestAccessReviewImmutable：簽核不可 UPDATE/DELETE（ORM 層縱深防禦）
func TestAccessReviewImmutable(t *testing.T) {
	_, db := setupAccessReviewDB(t)
	review := &model.AccessReview{
		ReviewedBy: 1, ReviewerName: "admin", ReviewedAt: time.Now(),
		Scope: "全部", Note: "初版", AuthorizationCount: 0, MatrixSnapshot: "[]",
	}
	if err := db.Create(review).Error; err != nil {
		t.Fatalf("create: %v", err)
	}

	// UPDATE 應被 BeforeUpdate 擋
	if err := db.Model(review).Update("note", "竄改").Error; err == nil {
		t.Error("簽核 UPDATE 應被拒（不可變證據）")
	}
	// DELETE 應被 BeforeDelete 擋
	if err := db.Delete(review).Error; err == nil {
		t.Error("簽核 DELETE 應被拒（append-only）")
	}
	// 快照未變
	var reloaded model.AccessReview
	db.First(&reloaded, review.ID)
	if reloaded.Note != "初版" {
		t.Error("簽核內容不應被竄改")
	}
}

// ===== 單筆複審檢視 =====

// TestGetReviewDetail_TypedMatrix 快照解析為型別化矩陣陣列＋中繼資料齊全
func TestGetReviewDetail_TypedMatrix(t *testing.T) {
	svc, db := setupAccessReviewDB(t)

	u := &model.User{Username: "u1", Password: "x", Email: strPtr("u1@test.local"), Active: true}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("user: %v", err)
	}
	a := &model.Asset{Name: "srv", Protocol: model.ProtocolSSH, Host: "h", Port: 22}
	if err := db.Create(a).Error; err != nil {
		t.Fatalf("asset: %v", err)
	}
	uid, aid := u.ID, a.ID
	if err := db.Create(&model.AssetAuthorization{
		UserID: &uid, AssetID: &aid, Permission: model.PermissionConnect, GrantedBy: 1,
	}).Error; err != nil {
		t.Fatalf("grant: %v", err)
	}

	review, err := svc.CreateReview(1, "admin", "季度複審")
	if err != nil {
		t.Fatalf("create review: %v", err)
	}

	detail, err := svc.GetReviewDetail(review.ID)
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	if detail.ReviewerName != "admin" || detail.Note != "季度複審" {
		t.Fatalf("中繼資料不齊: %+v", detail)
	}
	if len(detail.Matrix) != 1 {
		t.Fatalf("矩陣應為型別化陣列且含 1 列，got %d", len(detail.Matrix))
	}
	if detail.Matrix[0].Username != "u1" || detail.Matrix[0].Permission != "connect" {
		t.Fatalf("矩陣列內容錯誤: %+v", detail.Matrix[0])
	}
}

// TestGetReviewDetail_NotFound 不存在回 ErrReviewNotFound
func TestGetReviewDetail_NotFound(t *testing.T) {
	svc, _ := setupAccessReviewDB(t)
	if _, err := svc.GetReviewDetail(9999); err != ErrReviewNotFound {
		t.Fatalf("expected ErrReviewNotFound, got %v", err)
	}
}

// TestGetReviewDetail_CorruptedSnapshot 損壞快照回明確錯誤而非空內容
func TestGetReviewDetail_CorruptedSnapshot(t *testing.T) {
	svc, db := setupAccessReviewDB(t)

	review := &model.AccessReview{
		ReviewedBy: 1, ReviewerName: "admin", ReviewedAt: time.Now(),
		Scope: "all", Note: "x", AuthorizationCount: 0, MatrixSnapshot: "{not-json",
	}
	if err := db.Create(review).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := svc.GetReviewDetail(review.ID); err != ErrReviewSnapshotCorrupted {
		t.Fatalf("expected ErrReviewSnapshotCorrupted, got %v", err)
	}
}
