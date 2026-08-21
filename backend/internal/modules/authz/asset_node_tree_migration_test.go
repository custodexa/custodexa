package authz

import (
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// strP 測試用字串指標助手（隨本測試自 internal/database 遷入）。
func strP(s string) *string { return &s }

// **W7 7.7 遷移說明（是否放寬：否）**：本測試原住 `internal/database`
// （原 `internal/repository`）的 migrations_test.go。授權資料存取層內化為 authz 的
// 未匯出 `assetAuthorizationRepository` 後，database 的測試已無法取得它，
// 而 database 的測試包也不得 import authz（authz→database 存在，會構成
// `import cycle not allowed in test`）。斷言與夾具逐字未動，只換了所在包。

// TestAssetNodeTreeMigrationEquivalence 3b 遷移等價測試（asset-node-tree D7
// 行為零變化鐵則）：模擬舊 schema（assets 帶 group_id 單員籍）灌資料與授權，
// 執行成員遷移 SQL 後，逐使用者以新解析（節點含子樹）驗證授權資產集合
// 與舊語義（組內資產）完全相同——根節點無子樹時兩者等價
func TestAssetNodeTreeMigrationEquivalence(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.UserGroup{}, &model.Asset{}, &model.AssetGroup{},
		&model.AssetNode{}, &model.AssetAuthorization{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// 舊 schema：assets 帶 group_id（新 model 已無，手動補）
	if err := db.Exec("ALTER TABLE assets ADD COLUMN group_id bigint").Error; err != nil {
		t.Fatalf("add legacy group_id: %v", err)
	}

	db.Create(&model.User{Username: "u1", Email: strP("u1@x")})
	db.Create(&model.User{Username: "u2", Email: strP("u2@x")})
	db.Create(&model.AssetGroup{Name: "g1"}) // id 1
	db.Create(&model.AssetGroup{Name: "g2"}) // id 2
	// 軟刪組（殘留員籍不得遷移）
	db.Exec("INSERT INTO asset_groups (id, name, deleted_at) VALUES (99, 'g-deleted', CURRENT_TIMESTAMP)")

	seedAsset := func(name string, groupID *uint) uint {
		a := model.Asset{Name: name, Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1}
		if err := db.Create(&a).Error; err != nil {
			t.Fatalf("seed asset %s: %v", name, err)
		}
		if groupID != nil {
			db.Exec("UPDATE assets SET group_id = ? WHERE id = ?", *groupID, a.ID)
		}
		return a.ID
	}
	g1, g2, gDel := uint(1), uint(2), uint(99)
	a1 := seedAsset("a1", &g1)
	a2 := seedAsset("a2", nil)
	a3 := seedAsset("a3", &g2)
	a4 := seedAsset("a4", &gDel) // 指向軟刪組的歷史髒資料

	// 舊語義授權：user1×組 g1（涵蓋 a1）、user2×直授 a3
	u1, u2 := uint(1), uint(2)
	db.Create(&model.AssetAuthorization{UserID: &u1, AssetGroupID: &g1, Permission: model.PermissionConnect, GrantedBy: 1})
	db.Create(&model.AssetAuthorization{UserID: &u2, AssetID: &a3, Permission: model.PermissionView, GrantedBy: 1})

	// 唯一索引先於灌值（與 migrations.go 20260721 同順序——ON CONFLICT
	// 的冪等語義依賴它；AutoMigrate 的 index tag 非 unique）
	if err := db.Exec("CREATE UNIQUE INDEX idx_asset_nodes_asset_node ON asset_nodes (asset_id, node_id)").Error; err != nil {
		t.Fatalf("create unique index: %v", err)
	}

	// 軟刪資產帶 group_id（舊資料常態）：不得遷成員——幽靈成員會讓
	// 空節點永不可刪（codex 對抗審查 P1）
	deletedAsset := seedAsset("a-deleted", &g1)
	if err := db.Exec("UPDATE assets SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?", deletedAsset).Error; err != nil {
		t.Fatalf("soft-delete asset: %v", err)
	}

	// 執行遷移的成員灌值 SQL（與 migrations.go 20260721 同語義；
	// SQLite 支援 INSERT...SELECT JOIN 與 ON CONFLICT，幾乎原樣）
	if err := db.Exec(`INSERT INTO asset_nodes (asset_id, node_id, created_at)
		SELECT a.id, a.group_id, CURRENT_TIMESTAMP FROM assets a
		JOIN asset_groups g ON g.id = a.group_id AND g.deleted_at IS NULL
		WHERE a.group_id IS NOT NULL AND a.deleted_at IS NULL
		ON CONFLICT DO NOTHING`).Error; err != nil {
		t.Fatalf("migration insert: %v", err)
	}

	// 等價斷言：新解析的授權集合＝舊語義集合
	repo := newAssetAuthorizationRepository(db)
	perms := []model.PermissionType{model.PermissionView, model.PermissionConnect}
	cases := []struct {
		userID uint
		want   map[uint]bool
	}{
		{1, map[uint]bool{a1: true}},
		{2, map[uint]bool{a3: true}},
	}
	for _, c := range cases {
		assets, _, err := repo.GetAuthorizedAssets(c.userID, perms)
		if err != nil {
			t.Fatalf("user %d 解析: %v", c.userID, err)
		}
		got := map[uint]bool{}
		for _, a := range assets {
			got[a.ID] = true
		}
		if len(got) != len(c.want) {
			t.Fatalf("user %d 授權集合 = %v, want %v", c.userID, got, c.want)
		}
		for id := range c.want {
			if !got[id] {
				t.Fatalf("user %d 缺 asset %d", c.userID, id)
			}
		}
	}

	// 成員列：a1→g1、a3→g2；a2 未分組、a4 指向軟刪組均無成員列
	var count int64
	db.Model(&model.AssetNode{}).Count(&count)
	if count != 2 {
		t.Fatalf("成員列應 2, got %d", count)
	}
	var orphanCount int64
	db.Model(&model.AssetNode{}).Where("asset_id IN ?", []uint{a2, a4, deletedAsset}).Count(&orphanCount)
	if orphanCount != 0 {
		t.Fatalf("未分組/軟刪組/軟刪資產不得有成員列, got %d", orphanCount)
	}
	// 重跑冪等（ON CONFLICT DO NOTHING）
	if err := db.Exec(`INSERT INTO asset_nodes (asset_id, node_id, created_at)
		SELECT a.id, a.group_id, CURRENT_TIMESTAMP FROM assets a
		JOIN asset_groups g ON g.id = a.group_id AND g.deleted_at IS NULL
		WHERE a.group_id IS NOT NULL AND a.deleted_at IS NULL
		ON CONFLICT DO NOTHING`).Error; err != nil {
		t.Fatalf("rerun: %v", err)
	}
	db.Model(&model.AssetNode{}).Count(&count)
	if count != 2 {
		t.Fatalf("重跑後成員列應仍 2, got %d", count)
	}
}
