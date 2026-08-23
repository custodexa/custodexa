package api

import (
	"context"
	"github.com/custodexa/backend/internal/modules/authz"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 授權引用缺失：service 實際回傳的錯誤 → handler 映射的端到端耦合測試。
//
// 為什麼要真的呼叫 DB 而不是餵造好的錯誤：修正前 handler 以中文子字串比對
// service 的 fmt.Errorf 文案，兩端的一致性沒有任何測試看守——handler 測試餵
// 自己捏的 errors.New("用戶不存在") 恆綠，service 改一個字就在生產環境靜默
// 退化成 500。本測試讓 service 對著真 DB 產生錯誤，再交給 handler 的映射，
// 兩端任一改動導致對不上就紅。
func setupGrantRefDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:grantref?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	t.Cleanup(func() {
		sqlDB, err := db.DB()
		if err == nil {
			_ = sqlDB.Close()
		}
	})
	if err := db.AutoMigrate(&model.User{}, &model.UserGroup{}, &model.Asset{},
		&model.AssetGroup{}, &model.AssetAuthorization{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// 各建一筆存在的實體，讓「不存在」只可能來自刻意指定的 999
	db.Create(&model.User{Username: "u1", Email: emailPtr("u1@x"), Active: true})
	db.Create(&model.UserGroup{Name: "g1"})
	db.Create(&model.Asset{Name: "a1", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1})
	db.Create(&model.AssetGroup{Name: "ag1"})
	return db
}

// entityAllowed entity 值必須落在碼的 ZhLabels 允許清單內，否則 apierror 會
// 判定參數違規、整組 params 被丟棄，前端只剩「{entity}不存在」的空殼文案。
func entityAllowed(t *testing.T, code apierror.ErrCode, entity string) {
	t.Helper()
	d, ok := apierror.DescriptorOf(code)
	if !ok || len(d.Params) == 0 {
		t.Fatalf("碼 %s 應宣告 entity 參數", code)
	}
	if _, allowed := d.Params[0].ZhLabels[entity]; !allowed {
		t.Fatalf("entity %q 不在碼 %s 的允許清單內（params 會被整組丟棄）", entity, code)
	}
}

func TestGrantRefNotFound_ServiceToHandlerMapping(t *testing.T) {
	db := setupGrantRefDB(t)
	svc := authz.NewAssetAuthorizationService(db)
	ctx := context.Background()
	missing := uint(999)
	ok := uint(1)

	cases := []struct {
		name string
		spec authz.GrantSpec
		want string
	}{
		{"使用者不存在", authz.GrantSpec{UserID: &missing, AssetID: &ok, Permission: model.PermissionView}, "user"},
		{"使用者群組不存在", authz.GrantSpec{UserGroupID: &missing, AssetID: &ok, Permission: model.PermissionView}, "user_group"},
		{"資產不存在", authz.GrantSpec{UserID: &ok, AssetID: &missing, Permission: model.PermissionView}, "asset"},
		{"資產分組不存在", authz.GrantSpec{UserID: &ok, AssetGroupID: &missing, Permission: model.PermissionView}, "asset_group"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.Grant(ctx, tc.spec)
			if err == nil {
				t.Fatal("引用不存在應回錯誤")
			}
			entity, mapped := grantMissingEntity(err)
			if !mapped {
				t.Fatalf("handler 未能由錯誤判定實體種類（將誤回 500）: %v", err)
			}
			if entity != tc.want {
				t.Fatalf("entity = %q，預期 %q（err=%v）", entity, tc.want, err)
			}
			entityAllowed(t, apierror.CodeGrantReferenceNotFound, entity)
		})
	}
}

func TestGrantBatchRefNotFound_ServiceToHandlerMapping(t *testing.T) {
	db := setupGrantRefDB(t)
	svc := authz.NewAssetAuthorizationService(db)
	ctx := context.Background()

	cases := []struct {
		name                                           string
		userIDs, userGroupIDs, assetIDs, assetGroupIDs []uint
		want                                           string
	}{
		{"使用者名單", []uint{999}, nil, []uint{1}, nil, "user"},
		{"使用者群組名單", nil, []uint{999}, []uint{1}, nil, "user_group"},
		{"資產名單", []uint{1}, nil, []uint{999}, nil, "asset"},
		{"資產分組名單", []uint{1}, nil, nil, []uint{999}, "asset_group"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.GrantBatch(ctx, tc.userIDs, tc.userGroupIDs, tc.assetIDs, tc.assetGroupIDs,
				model.PermissionView, 1, nil)
			if err == nil {
				t.Fatal("引用不存在應整批拒絕")
			}
			entity, mapped := grantMissingEntity(err)
			if !mapped {
				t.Fatalf("handler 未能由錯誤判定實體種類（將誤回 500）: %v", err)
			}
			if entity != tc.want {
				t.Fatalf("entity = %q，預期 %q（err=%v）", entity, tc.want, err)
			}
			entityAllowed(t, apierror.CodeBatchReferenceNotFound, entity)
		})
	}
}

// TestGrantRefMappingIgnoresUnrelatedErrors 非引用缺失的錯誤不得被誤判為 404
// （子字串比對時代「查詢資產失敗: ...」也可能誤命中）
func TestGrantRefMappingIgnoresUnrelatedErrors(t *testing.T) {
	if entity, ok := grantMissingEntity(gorm.ErrInvalidDB); ok {
		t.Fatalf("無關錯誤不應映射為引用缺失，實得 %q", entity)
	}
	if entity, ok := grantMissingEntity(authz.ErrAuthorizationExists); ok {
		t.Fatalf("授權已存在不應映射為引用缺失，實得 %q", entity)
	}
}
