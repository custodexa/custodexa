package database

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 關聯表帶額外欄位時，既有預載入路徑的行為。
//
// # 這支測試要回答什麼
//
// `user_roles` 由 `User.Roles`／`Role.Users` 的 many2many 標籤消費。標籤只描述
// 兩個外鍵欄，關聯表的第三欄不在它的認知內。加欄之前這個問題不存在；加欄之後，
// 「預載入會不會因為表上多了一欄而查錯、掃錯或整支失敗」變成整個資料層的前提
// ——若它會壞，來源欄就不能加在這張表上，整份設計要改成另立一張表。
//
// **推論不算數**：ORM 對 SELECT 欄位清單的產生方式是實作細節，版本之間會變。
// 故以真的建表、真的塞列、真的預載入來釘住它，並在關聯表的列上放一個非預設的
// 來源值——若預載入把該欄一併掃回某個結構，值會出現在斷言裡。
func TestUserRoleJoinModelPreloadIgnoresExtraColumns(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	// `:memory:` 配連線池時每條連線是各自獨立的空 DB
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db handle: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)

	// 關聯表由 model 建（單一定義來源），不手寫 DDL
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserRole{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// 建表確實帶了第三欄——否則後面的斷言是在兩欄表上跑，什麼都沒驗到
	cols, err := db.Migrator().ColumnTypes(&model.UserRole{})
	if err != nil {
		t.Fatalf("讀關聯表欄位: %v", err)
	}
	names := map[string]bool{}
	for _, c := range cols {
		names[c.Name()] = true
	}
	for _, want := range []string{"role_id", "user_id", "source"} {
		if !names[want] {
			t.Fatalf("關聯表缺欄位 %s（實際：%v）：本測試的前提不成立", want, names)
		}
	}

	u := &model.User{Username: "join-model-probe", Password: "x", Active: true}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("建帳號: %v", err)
	}
	r := &model.Role{Name: "join-model-role"}
	if err := db.Create(r).Error; err != nil {
		t.Fatalf("建角色: %v", err)
	}
	// 刻意寫非預設的來源值：預載入若把它掃進任何結構，值會露出來
	if err := db.Create(&model.UserRole{
		RoleID: r.ID, UserID: u.ID, Source: model.RoleSourceBoth,
	}).Error; err != nil {
		t.Fatalf("建關聯列: %v", err)
	}

	var got model.User
	if err := db.Preload("Roles").First(&got, u.ID).Error; err != nil {
		t.Fatalf("預載入角色: %v", err)
	}
	if len(got.Roles) != 1 {
		t.Fatalf("預載入取回 %d 個角色, want 1：關聯表多一欄即讓既有讀取路徑失效，"+
			"來源欄不能加在這張表上", len(got.Roles))
	}
	if got.Roles[0].ID != r.ID || got.Roles[0].Name != r.Name {
		t.Fatalf("預載入取回的角色 = (%d, %q), want (%d, %q)：欄位對位錯亂",
			got.Roles[0].ID, got.Roles[0].Name, r.ID, r.Name)
	}

	// 反向：關聯列本身讀得回來，且來源值就是寫進去的那個。
	// 少了這一格，「預載入忽略該欄」與「該欄根本沒寫進去」不可區分
	var stored model.UserRole
	if err := db.Where("user_id = ? AND role_id = ?", u.ID, r.ID).First(&stored).Error; err != nil {
		t.Fatalf("讀關聯列: %v", err)
	}
	if stored.Source != model.RoleSourceBoth {
		t.Fatalf("關聯列的來源 = %q, want %q", stored.Source, model.RoleSourceBoth)
	}

	// 不帶來源欄的兩欄寫入落地為管理者指派。既有五條角色寫入路徑寫的都是兩欄
	// INSERT，靠的就是這個預設值；改成別的值，那些路徑供應的角色會被本地管理員
	// 計數排除，而症狀要到「最後一個管理員被移除」才出現
	if err := db.Exec("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)",
		u.ID, r.ID+1).Error; err != nil {
		t.Fatalf("兩欄寫入: %v", err)
	}
	var defaulted model.UserRole
	if err := db.Where("user_id = ? AND role_id = ?", u.ID, r.ID+1).
		First(&defaulted).Error; err != nil {
		t.Fatalf("讀回兩欄寫入的列: %v", err)
	}
	if defaulted.Source != model.RoleSourceManual {
		t.Fatalf("不帶來源欄寫入後的來源 = %q, want %q", defaulted.Source, model.RoleSourceManual)
	}

	// 另一個方向的關聯也要驗：Role.Users 走的是同一張關聯表的反向
	var gotRole model.Role
	if err := db.Preload("Users").First(&gotRole, r.ID).Error; err != nil {
		t.Fatalf("預載入使用者: %v", err)
	}
	if len(gotRole.Users) != 1 || gotRole.Users[0].ID != u.ID {
		t.Fatalf("反向預載入取回 %d 位使用者, want 1 位且為 %d", len(gotRole.Users), u.ID)
	}
}
