package authz

import (
	"fmt"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupAuthzRepoDB 真 SQL 整合測試（in-memory SQLite）：解析查詢的四路徑
// 聯集與時效窗語義用實際執行驗證，sqlmock 只能驗 SQL 形狀驗不了語義。
// AuditLog 必須一併建：Asset 的 AfterCreate hook 會寫 audit_logs
func setupAuthzRepoDB(t *testing.T) (*assetAuthorizationRepository, *gorm.DB) {
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
	return newAssetAuthorizationRepository(db), db
}

// attachNode 掛載資產到節點（asset-node-tree M2M 成員）
func attachNode(t *testing.T, db *gorm.DB, assetID, nodeID uint) {
	t.Helper()
	if err := db.Create(&model.AssetNode{AssetID: assetID, NodeID: nodeID}).Error; err != nil {
		t.Fatalf("attach node: %v", err)
	}
}

// seedAuthzFixture 基礎夾具：user 1（屬群組 1）、user 2（無群組）、
// asset 1（掛節點 ag1）、asset 2（未掛載）、asset 3（掛節點 ag2）
func seedAuthzFixture(t *testing.T, db *gorm.DB) {
	t.Helper()
	users := []model.User{{Username: "u1", Email: strP("u1@x")}, {Username: "u2", Email: strP("u2@x")}}
	for i := range users {
		if err := db.Create(&users[i]).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
	}
	groups := []model.UserGroup{{Name: "ug1"}, {Name: "ug2"}}
	for i := range groups {
		if err := db.Create(&groups[i]).Error; err != nil {
			t.Fatalf("seed user group: %v", err)
		}
	}
	// user 1 ∈ ug1
	if err := db.Model(&groups[0]).Association("Users").Append(&users[0]); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
	db.Create(&model.AssetGroup{Name: "ag1"}) // id 1
	db.Create(&model.AssetGroup{Name: "ag2"}) // id 2
	db.Create(&model.Asset{Name: "a1", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1})
	db.Create(&model.Asset{Name: "a2", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1})
	db.Create(&model.Asset{Name: "a3", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1})
	attachNode(t, db, 1, 1) // asset 1 ∈ node ag1
	attachNode(t, db, 3, 2) // asset 3 ∈ node ag2
}

// repoGrant 建授權：主體（userID XOR userGroupID）×客體（assetID XOR assetGroupID）
func repoGrant(t *testing.T, db *gorm.DB, userID, userGroupID, assetID, assetGroupID *uint,
	perm model.PermissionType, start, expired *time.Time) uint {
	t.Helper()
	auth := model.AssetAuthorization{
		UserID: userID, UserGroupID: userGroupID,
		AssetID: assetID, AssetGroupID: assetGroupID,
		Permission: perm, GrantedBy: 1,
		DateStart: start, DateExpired: expired,
	}
	if err := db.Create(&auth).Error; err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	return auth.ID
}

func up(v uint) *uint { return &v }

var viewHierarchy = []model.PermissionType{model.PermissionView, model.PermissionConnect}

// TestAuthzResolution_FourPaths 四路徑各自命中：個人直授/個人組授/群組直授/群組組授
func TestAuthzResolution_FourPaths(t *testing.T) {
	cases := []struct {
		name    string
		userID  *uint
		groupID *uint // 主體群組（user 1 ∈ ug1）
		assetID *uint
		agID    *uint // 客體資產組（asset 1 ∈ ag1）
	}{
		{"個人直授", up(1), nil, up(1), nil},
		{"個人組授", up(1), nil, nil, up(1)},
		{"群組直授", nil, up(1), up(1), nil},
		{"群組組授", nil, up(1), nil, up(1)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			repo, db := setupAuthzRepoDB(t)
			seedAuthzFixture(t, db)
			repoGrant(t, db, c.userID, c.groupID, c.assetID, c.agID, model.PermissionConnect, nil, nil)

			ok, err := repo.CheckPermission(1, 1, viewHierarchy)
			if err != nil || !ok {
				t.Fatalf("user 1 對 asset 1 應命中（%s）: ok=%v err=%v", c.name, ok, err)
			}

			assets, levels, err := repo.GetAuthorizedAssets(1, viewHierarchy)
			if err != nil {
				t.Fatalf("GetAuthorizedAssets: %v", err)
			}
			if len(assets) != 1 || assets[0].ID != 1 {
				t.Fatalf("清單應只含 asset 1, got %d 筆", len(assets))
			}
			if levels[1] != model.PermissionConnect {
				t.Fatalf("等級應為 connect, got %s", levels[1])
			}

			// 反向：user 2（無群組、無授權）不得命中——群組授權不外溢
			ok2, err := repo.CheckPermission(2, 1, viewHierarchy)
			if err != nil || ok2 {
				t.Fatalf("user 2 不應命中: ok=%v err=%v", ok2, err)
			}
		})
	}
}

// TestAuthzResolution_UnionTakesHighest 四路徑混合聯集取最高（無 deny、無個人優先）
func TestAuthzResolution_UnionTakesHighest(t *testing.T) {
	repo, db := setupAuthzRepoDB(t)
	seedAuthzFixture(t, db)
	repoGrant(t, db, up(1), nil, up(1), nil, model.PermissionView, nil, nil)    // 個人直授 view
	repoGrant(t, db, up(1), nil, nil, up(1), model.PermissionView, nil, nil)    // 個人組授 view
	repoGrant(t, db, nil, up(1), up(1), nil, model.PermissionView, nil, nil)    // 群組直授 view
	repoGrant(t, db, nil, up(1), nil, up(1), model.PermissionConnect, nil, nil) // 群組組授 connect

	assets, levels, err := repo.GetAuthorizedAssets(1, viewHierarchy)
	if err != nil {
		t.Fatalf("GetAuthorizedAssets: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("DISTINCT 後應只有 asset 1, got %d", len(assets))
	}
	if levels[1] != model.PermissionConnect {
		t.Fatalf("聯集取最高應為 connect（J 兩階）, got %s", levels[1])
	}

	// connect 層級判定也應命中（群組組授 connect 路徑）
	ok, err := repo.CheckPermission(1, 1, []model.PermissionType{model.PermissionConnect})
	if err != nil || !ok {
		t.Fatalf("connect 層級應命中: ok=%v err=%v", ok, err)
	}
}

// TestAuthzResolution_ValidityWindow 時效窗：未到不命中/已過期不命中/窗內命中/空值永久
func TestAuthzResolution_ValidityWindow(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	farPast := time.Now().Add(-2 * time.Hour)

	cases := []struct {
		name    string
		start   *time.Time
		expired *time.Time
		want    bool
	}{
		{"空時效永久生效", nil, nil, true},
		{"時窗內生效", &past, &future, true},
		{"未達起始不生效", &future, nil, false},
		{"已過期不生效", nil, &past, false},
		{"起訖皆過期不生效", &farPast, &past, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			repo, db := setupAuthzRepoDB(t)
			seedAuthzFixture(t, db)
			repoGrant(t, db, up(1), nil, up(2), nil, model.PermissionConnect, c.start, c.expired)

			ok, err := repo.CheckPermission(1, 2, viewHierarchy)
			if err != nil {
				t.Fatalf("CheckPermission: %v", err)
			}
			if ok != c.want {
				t.Fatalf("命中應為 %v, got %v", c.want, ok)
			}

			assets, _, err := repo.GetAuthorizedAssets(1, viewHierarchy)
			if err != nil {
				t.Fatalf("GetAuthorizedAssets: %v", err)
			}
			inList := len(assets) == 1
			if inList != c.want {
				t.Fatalf("清單出現應為 %v, got %v", c.want, inList)
			}
		})
	}
}

// TestAuthzResolution_MembershipRemoval 移出群組即失效（成員關係即時反映）
func TestAuthzResolution_MembershipRemoval(t *testing.T) {
	repo, db := setupAuthzRepoDB(t)
	seedAuthzFixture(t, db)
	repoGrant(t, db, nil, up(1), up(2), nil, model.PermissionConnect, nil, nil)

	if ok, _ := repo.CheckPermission(1, 2, viewHierarchy); !ok {
		t.Fatal("移出前應命中")
	}

	var group model.UserGroup
	var user model.User
	db.First(&group, 1)
	db.First(&user, 1)
	if err := db.Model(&group).Association("Users").Delete(&user); err != nil {
		t.Fatalf("移出群組: %v", err)
	}

	if ok, _ := repo.CheckPermission(1, 2, viewHierarchy); ok {
		t.Fatal("移出群組後不應命中")
	}
	assets, _, _ := repo.GetAuthorizedAssets(1, viewHierarchy)
	if len(assets) != 0 {
		t.Fatalf("移出群組後清單應為空, got %d", len(assets))
	}
}

// TestAuthzResolution_SoftDeletedGrantExcluded 軟刪授權不計入
func TestAuthzResolution_SoftDeletedGrantExcluded(t *testing.T) {
	repo, db := setupAuthzRepoDB(t)
	seedAuthzFixture(t, db)
	id := repoGrant(t, db, nil, up(1), up(2), nil, model.PermissionConnect, nil, nil)

	if err := db.Delete(&model.AssetAuthorization{}, id).Error; err != nil {
		t.Fatalf("軟刪授權: %v", err)
	}

	if ok, _ := repo.CheckPermission(1, 2, viewHierarchy); ok {
		t.Fatal("軟刪授權不應命中")
	}
	assets, _, _ := repo.GetAuthorizedAssets(1, viewHierarchy)
	if len(assets) != 0 {
		t.Fatalf("軟刪授權後清單應為空, got %d", len(assets))
	}
}

// TestAuthzResolution_RegrantAfterRevoke 撤銷（軟刪）後重授同組合必須成功——
// 唯一索引為 partial（WHERE deleted_at IS NULL），非 partial 會撞 23505（既有 bug）
func TestAuthzResolution_RegrantAfterRevoke(t *testing.T) {
	repo, db := setupAuthzRepoDB(t)
	seedAuthzFixture(t, db)
	id := repoGrant(t, db, up(1), nil, up(2), nil, model.PermissionView, nil, nil)

	if err := db.Delete(&model.AssetAuthorization{}, id).Error; err != nil {
		t.Fatalf("撤銷: %v", err)
	}

	// 重授同組合（user 1 × asset 2 × view）
	auth := model.AssetAuthorization{UserID: up(1), AssetID: up(2), Permission: model.PermissionView, GrantedBy: 1}
	if err := db.Create(&auth).Error; err != nil {
		t.Fatalf("撤銷後重授同組合應成功: %v", err)
	}
	if ok, _ := repo.CheckPermission(1, 2, viewHierarchy); !ok {
		t.Fatal("重授後應命中")
	}

	// 同組合活躍重複仍被唯一索引擋（去重語義不因 partial 而失守）
	dup := model.AssetAuthorization{UserID: up(1), AssetID: up(2), Permission: model.PermissionView, GrantedBy: 1}
	if err := db.Create(&dup).Error; err == nil {
		t.Fatal("活躍重複組合應被唯一索引擋下")
	}
}

// TestResolveConnectSources 來源感知查詢矩陣（access-policy-approval D4）：
// 常設命中/臨時命中/到期不命中/未達 start 不命中；view 不參與；四路徑主體條件沿用
func TestResolveConnectSources(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)
	farPast := now.Add(-2 * time.Hour)

	// ticketGrant 建核准流來源授權（grant helper 預設 manual，此處顯式 ticket）
	ticketGrant := func(t *testing.T, db *gorm.DB, start, expired *time.Time) {
		t.Helper()
		auth := model.AssetAuthorization{
			UserID: up(1), AssetID: up(2), Permission: model.PermissionConnect,
			GrantedBy: 1, Source: model.AuthorizationSourceTicket,
			DateStart: start, DateExpired: expired,
		}
		if err := db.Create(&auth).Error; err != nil {
			t.Fatalf("seed ticket grant: %v", err)
		}
	}

	t.Run("常設命中", func(t *testing.T) {
		repo, db := setupAuthzRepoDB(t)
		seedAuthzFixture(t, db)
		repoGrant(t, db, up(1), nil, up(2), nil, model.PermissionConnect, nil, nil)

		s, err := repo.ResolveConnectSources(1, 2, now)
		if err != nil || !s.Standing || s.Ticket {
			t.Fatalf("常設應命中且無 ticket: %+v err=%v", s, err)
		}
	})

	t.Run("臨時命中", func(t *testing.T) {
		repo, db := setupAuthzRepoDB(t)
		seedAuthzFixture(t, db)
		ticketGrant(t, db, &past, &future)

		s, err := repo.ResolveConnectSources(1, 2, now)
		if err != nil || !s.Ticket || s.Standing {
			t.Fatalf("時窗內 ticket 應命中且無常設: %+v err=%v", s, err)
		}
	})

	t.Run("常設與臨時並存", func(t *testing.T) {
		repo, db := setupAuthzRepoDB(t)
		seedAuthzFixture(t, db)
		repoGrant(t, db, up(1), nil, up(2), nil, model.PermissionConnect, nil, nil)
		ticketGrant(t, db, &past, &future)

		s, err := repo.ResolveConnectSources(1, 2, now)
		if err != nil || !s.Standing || !s.Ticket {
			t.Fatalf("兩來源應同時命中: %+v err=%v", s, err)
		}
	})

	t.Run("到期不命中", func(t *testing.T) {
		repo, db := setupAuthzRepoDB(t)
		seedAuthzFixture(t, db)
		ticketGrant(t, db, &farPast, &past)

		s, err := repo.ResolveConnectSources(1, 2, now)
		if err != nil || s.Ticket || s.Standing {
			t.Fatalf("到期 ticket 不應命中: %+v err=%v", s, err)
		}
	})

	t.Run("未達起始不命中", func(t *testing.T) {
		repo, db := setupAuthzRepoDB(t)
		seedAuthzFixture(t, db)
		ticketGrant(t, db, &future, nil)

		s, err := repo.ResolveConnectSources(1, 2, now)
		if err != nil || s.Ticket || s.Standing {
			t.Fatalf("未達 start 的 ticket 不應命中: %+v err=%v", s, err)
		}
	})

	t.Run("view 不參與", func(t *testing.T) {
		repo, db := setupAuthzRepoDB(t)
		seedAuthzFixture(t, db)
		repoGrant(t, db, up(1), nil, up(2), nil, model.PermissionView, nil, nil)

		s, err := repo.ResolveConnectSources(1, 2, now)
		if err != nil || s.Standing || s.Ticket {
			t.Fatalf("view 授權不應參與 connect 來源: %+v err=%v", s, err)
		}
	})

	t.Run("群組路徑常設命中", func(t *testing.T) {
		repo, db := setupAuthzRepoDB(t)
		seedAuthzFixture(t, db)
		// 群組組授 connect（user 1 ∈ ug1、asset 1 ∈ ag1）——主體條件沿四路徑
		repoGrant(t, db, nil, up(1), nil, up(1), model.PermissionConnect, nil, nil)

		s, err := repo.ResolveConnectSources(1, 1, now)
		if err != nil || !s.Standing {
			t.Fatalf("群組路徑常設應命中: %+v err=%v", s, err)
		}
	})
}

// TestApproverScopeVisibility 審核範圍＝可視第三來源（access-policy-approval D5）：
// 範圍內可視（直配/經資產組）、不隱含連線、移除範圍即失效
func TestApproverScopeVisibility(t *testing.T) {
	scope := func(t *testing.T, db *gorm.DB, assetID, agID *uint) uint {
		t.Helper()
		s := model.ApproverScope{ApproverID: up(1), AssetID: assetID, AssetGroupID: agID, GrantedBy: 2}
		if err := db.Create(&s).Error; err != nil {
			t.Fatalf("seed scope: %v", err)
		}
		return s.ID
	}

	t.Run("直配範圍可視", func(t *testing.T) {
		repo, db := setupAuthzRepoDB(t)
		seedAuthzFixture(t, db)
		scope(t, db, up(2), nil)

		covered, err := repo.ApproverScopeCoversAsset(1, 2)
		if err != nil || !covered {
			t.Fatalf("直配範圍應命中: %v err=%v", covered, err)
		}
		assets, err := repo.ApproverScopedAssets(1)
		if err != nil || len(assets) != 1 || assets[0].ID != 2 {
			t.Fatalf("範圍資產應只含 asset 2: %d err=%v", len(assets), err)
		}
	})

	t.Run("經資產組範圍可視", func(t *testing.T) {
		repo, db := setupAuthzRepoDB(t)
		seedAuthzFixture(t, db)
		scope(t, db, nil, up(1)) // ag1 含 asset 1

		covered, err := repo.ApproverScopeCoversAsset(1, 1)
		if err != nil || !covered {
			t.Fatalf("經組範圍應命中: %v err=%v", covered, err)
		}
		if covered, _ := repo.ApproverScopeCoversAsset(1, 2); covered {
			t.Fatal("組外資產不應命中")
		}
	})

	t.Run("範圍不隱含連線", func(t *testing.T) {
		repo, db := setupAuthzRepoDB(t)
		seedAuthzFixture(t, db)
		scope(t, db, up(2), nil)

		// connect 判定僅走授權表——範圍不是授權記錄
		ok, err := repo.CheckPermission(1, 2, []model.PermissionType{model.PermissionConnect})
		if err != nil || ok {
			t.Fatalf("範圍不應給 connect: ok=%v err=%v", ok, err)
		}
		s, err := repo.ResolveConnectSources(1, 2, time.Now())
		if err != nil || s.Standing || s.Ticket {
			t.Fatalf("範圍不應出現在 connect 來源: %+v err=%v", s, err)
		}
	})

	t.Run("移除範圍即失效", func(t *testing.T) {
		repo, db := setupAuthzRepoDB(t)
		seedAuthzFixture(t, db)
		id := scope(t, db, up(2), nil)

		if covered, _ := repo.ApproverScopeCoversAsset(1, 2); !covered {
			t.Fatal("移除前應命中")
		}
		if err := db.Delete(&model.ApproverScope{}, id).Error; err != nil {
			t.Fatalf("delete scope: %v", err)
		}
		if covered, _ := repo.ApproverScopeCoversAsset(1, 2); covered {
			t.Fatal("軟刪後應即刻失效")
		}
		assets, _ := repo.ApproverScopedAssets(1)
		if len(assets) != 0 {
			t.Fatalf("軟刪後範圍資產應為空, got %d", len(assets))
		}
	})
}

// TestAuthzResolution_OtherGroupNotLeaked 他群組授權不外溢（ug2 授權、user 1 僅屬 ug1）
func TestAuthzResolution_OtherGroupNotLeaked(t *testing.T) {
	repo, db := setupAuthzRepoDB(t)
	seedAuthzFixture(t, db)
	repoGrant(t, db, nil, up(2), up(3), nil, model.PermissionConnect, nil, nil)

	if ok, _ := repo.CheckPermission(1, 3, viewHierarchy); ok {
		t.Fatal("非成員群組的授權不應命中")
	}
	assets, _, _ := repo.GetAuthorizedAssets(1, viewHierarchy)
	if len(assets) != 0 {
		t.Fatalf("非成員不應見任何資產, got %d", len(assets))
	}
}

// mkRepoNode 建節點（可帶父）
func mkRepoNode(t *testing.T, db *gorm.DB, name string, parentID *uint) uint {
	t.Helper()
	n := model.AssetGroup{Name: name, ParentID: parentID}
	if err := db.Create(&n).Error; err != nil {
		t.Fatalf("seed node: %v", err)
	}
	return n.ID
}

// TestSubtreeAuthorization 授權掛節點含子樹（asset-node-tree D3）：
// 樹 prod(→kafka→broker)；資產掛不同層，授 prod 應涵蓋全子樹資產
func TestSubtreeAuthorization(t *testing.T) {
	repo, db := setupAuthzRepoDB(t)
	seedAuthzFixture(t, db)
	prod := mkRepoNode(t, db, "prod", nil)
	kafka := mkRepoNode(t, db, "kafka", &prod)
	broker := mkRepoNode(t, db, "broker", &kafka)
	sit := mkRepoNode(t, db, "sit", nil)

	// asset 1 已掛 ag1（fixture）；再掛 kafka（多歸屬）；asset 2 掛 broker（深層）；
	// asset 3 掛 sit（無關子樹）
	attachNode(t, db, 1, kafka)
	attachNode(t, db, 2, broker)
	attachNode(t, db, 3, sit)

	// 授 user 1 節點 prod（含子樹）connect
	repoGrant(t, db, up(1), nil, nil, &prod, model.PermissionConnect, nil, nil)

	// 子樹內兩資產均命中；無關子樹資產不命中
	for _, c := range []struct {
		assetID uint
		want    bool
	}{{1, true}, {2, true}, {3, false}} {
		ok, err := repo.CheckPermission(1, c.assetID, viewHierarchy)
		if err != nil || ok != c.want {
			t.Fatalf("asset %d 命中應為 %v: ok=%v err=%v", c.assetID, c.want, ok, err)
		}
	}

	assets, levels, err := repo.GetAuthorizedAssets(1, viewHierarchy)
	if err != nil || len(assets) != 2 {
		t.Fatalf("清單應含子樹內 2 資產, got %d err=%v", len(assets), err)
	}
	for _, a := range assets {
		if levels[a.ID] != model.PermissionConnect {
			t.Fatalf("asset %d 等級應為 connect, got %s", a.ID, levels[a.ID])
		}
	}

	// 來源感知同語義：深層資產經子樹命中常設
	s, err := repo.ResolveConnectSources(1, 2, time.Now())
	if err != nil || !s.Standing {
		t.Fatalf("子樹常設應命中: %+v err=%v", s, err)
	}
	standing, err := repo.StandingConnectAssetIDs(1, []uint{1, 2, 3}, time.Now())
	if err != nil || !standing[1] || !standing[2] || standing[3] {
		t.Fatalf("bulk 常設判定錯: %v err=%v", standing, err)
	}
}

// TestSubtreeAuthorization_NewAssetImmediateCoverage 新資產掛入已授權節點
// 即時被涵蓋（即時查詢天然成立，無需信號失效）；移除掛載即失效
func TestSubtreeAuthorization_NewAssetImmediateCoverage(t *testing.T) {
	repo, db := setupAuthzRepoDB(t)
	seedAuthzFixture(t, db)
	prod := mkRepoNode(t, db, "prod", nil)
	kafka := mkRepoNode(t, db, "kafka", &prod)
	repoGrant(t, db, up(1), nil, nil, &prod, model.PermissionConnect, nil, nil)

	// asset 2（未掛載）此刻不命中
	if ok, _ := repo.CheckPermission(1, 2, viewHierarchy); ok {
		t.Fatal("未掛載資產不應命中")
	}
	// 掛入子樹節點 → 即時命中
	attachNode(t, db, 2, kafka)
	if ok, _ := repo.CheckPermission(1, 2, viewHierarchy); !ok {
		t.Fatal("掛入已授權節點子樹應即時命中")
	}
	// 摘除 → 即時失效
	if err := db.Where("asset_id = ? AND node_id = ?", 2, kafka).Delete(&model.AssetNode{}).Error; err != nil {
		t.Fatalf("detach: %v", err)
	}
	if ok, _ := repo.CheckPermission(1, 2, viewHierarchy); ok {
		t.Fatal("摘除掛載後應即時失效")
	}
}

// TestSubtreeAuthorization_MultiMembershipAnyPath 多歸屬：任一掛載位置的
// 節點授權都構成命中（聯集語義）
func TestSubtreeAuthorization_MultiMembershipAnyPath(t *testing.T) {
	repo, db := setupAuthzRepoDB(t)
	seedAuthzFixture(t, db)
	prod := mkRepoNode(t, db, "prod", nil)
	sit := mkRepoNode(t, db, "sit", nil)
	// asset 2 同時掛 prod 與 sit；僅授 sit
	attachNode(t, db, 2, prod)
	attachNode(t, db, 2, sit)
	repoGrant(t, db, up(1), nil, nil, &sit, model.PermissionView, nil, nil)

	if ok, _ := repo.CheckPermission(1, 2, viewHierarchy); !ok {
		t.Fatal("任一掛載位置授權應命中")
	}
	assets, levels, err := repo.GetAuthorizedAssets(1, viewHierarchy)
	if err != nil || len(assets) != 1 || levels[2] != model.PermissionView {
		t.Fatalf("多歸屬聯集: %d 筆 levels=%v err=%v", len(assets), levels, err)
	}
}

// TestApproverScopeSubtree 審核範圍配節點含子樹（同構原則）
func TestApproverScopeSubtree(t *testing.T) {
	repo, db := setupAuthzRepoDB(t)
	seedAuthzFixture(t, db)
	prod := mkRepoNode(t, db, "prod", nil)
	kafka := mkRepoNode(t, db, "kafka", &prod)
	attachNode(t, db, 2, kafka)

	s := model.ApproverScope{ApproverID: up(1), AssetGroupID: &prod, GrantedBy: 2}
	if err := db.Create(&s).Error; err != nil {
		t.Fatalf("seed scope: %v", err)
	}

	covered, err := repo.ApproverScopeCoversAsset(1, 2)
	if err != nil || !covered {
		t.Fatalf("子樹深層資產應在範圍內: %v err=%v", covered, err)
	}
	if covered, _ := repo.ApproverScopeCoversAsset(1, 3); covered {
		t.Fatal("範圍外資產不應命中")
	}
	assets, err := repo.ApproverScopedAssets(1)
	if err != nil || len(assets) != 1 || assets[0].ID != 2 {
		t.Fatalf("範圍資產應只含 asset 2: %d err=%v", len(assets), err)
	}
}

// TestAssetAncestorNodes 批次祖先映射（等級聚合/可視鏈依據）
func TestAssetAncestorNodes(t *testing.T) {
	repo, db := setupAuthzRepoDB(t)
	seedAuthzFixture(t, db)
	prod := mkRepoNode(t, db, "prod", nil)
	kafka := mkRepoNode(t, db, "kafka", &prod)
	attachNode(t, db, 2, kafka)

	anc, err := repo.AssetAncestorNodes([]uint{1, 2})
	if err != nil {
		t.Fatalf("AssetAncestorNodes: %v", err)
	}
	// asset 1 掛 ag1（根）→ 祖先集 {ag1}；asset 2 掛 kafka → {kafka, prod}
	if len(anc[1]) != 1 {
		t.Fatalf("asset 1 祖先集 = %v", anc[1])
	}
	got := map[uint]bool{}
	for _, id := range anc[2] {
		got[id] = true
	}
	if !got[kafka] || !got[prod] || len(anc[2]) != 2 {
		t.Fatalf("asset 2 祖先集 = %v, want {kafka, prod}", anc[2])
	}
}

// TestSubtreeResolutionPerformance 效能基準（asset-node-tree D1 風險驗證）：
// 100 節點×深度 10 樹＋500 資產多歸屬掛載，CTE 即時解析（無快取路線）延遲
// 量化。上限取寬鬆值（2s）防 CI 環境 flaky——實際量級見 t.Log（本機 SQLite
// in-memory 預期毫秒級；live Postgres 另於瀏覽器實走驗證）
func TestSubtreeResolutionPerformance(t *testing.T) {
	repo, db := setupAuthzRepoDB(t)
	db.Create(&model.User{Username: "perf", Email: strP("p@x")})

	// 100 節點：10 條深度 10 的鏈
	nodeIDs := make([]uint, 0, 100)
	for chain := 0; chain < 10; chain++ {
		var parent *uint
		for depth := 0; depth < 10; depth++ {
			n := model.AssetGroup{Name: fmt.Sprintf("c%d-d%d", chain, depth), ParentID: parent}
			if err := db.Create(&n).Error; err != nil {
				t.Fatalf("seed node: %v", err)
			}
			nodeIDs = append(nodeIDs, n.ID)
			parent = &n.ID
		}
	}

	// 500 資產，每台掛 2 節點（多歸屬）
	assetIDs := make([]uint, 0, 500)
	for i := 0; i < 500; i++ {
		a := model.Asset{Name: fmt.Sprintf("perf-a%d", i), Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1}
		if err := db.Create(&a).Error; err != nil {
			t.Fatalf("seed asset: %v", err)
		}
		assetIDs = append(assetIDs, a.ID)
		attachNode(t, db, a.ID, nodeIDs[i%len(nodeIDs)])
		attachNode(t, db, a.ID, nodeIDs[(i*7+3)%len(nodeIDs)])
	}

	// 授權：10 條鏈的根節點各授 connect（涵蓋全樹）＋50 筆直授
	uid := uint(1)
	for chain := 0; chain < 10; chain++ {
		root := nodeIDs[chain*10]
		repoGrant(t, db, &uid, nil, nil, &root, model.PermissionConnect, nil, nil)
	}
	for i := 0; i < 50; i++ {
		repoGrant(t, db, &uid, nil, &assetIDs[i], nil, model.PermissionView, nil, nil)
	}

	start := time.Now()
	assets, levels, err := repo.GetAuthorizedAssets(1, viewHierarchy)
	listElapsed := time.Since(start)
	if err != nil {
		t.Fatalf("GetAuthorizedAssets: %v", err)
	}
	if len(assets) != 500 {
		t.Fatalf("應涵蓋全部 500 資產, got %d", len(assets))
	}
	if len(levels) != 500 {
		t.Fatalf("等級映射應 500, got %d", len(levels))
	}

	start = time.Now()
	for i := 0; i < 20; i++ {
		if ok, err := repo.CheckPermission(1, assetIDs[i*20], viewHierarchy); err != nil || !ok {
			t.Fatalf("CheckPermission asset %d: ok=%v err=%v", assetIDs[i*20], ok, err)
		}
	}
	checkElapsed := time.Since(start) / 20

	t.Logf("500 資產×100 節點×深度10：GetAuthorizedAssets=%v、CheckPermission 均值=%v", listElapsed, checkElapsed)
	if listElapsed > 2*time.Second {
		t.Fatalf("清單解析超過寬鬆上限: %v", listElapsed)
	}
	if checkElapsed > 200*time.Millisecond {
		t.Fatalf("單資產判定超過寬鬆上限: %v", checkElapsed)
	}
}

// TestListNodeCoverageFilter（authz-tag-node-filters D7）：授權列表 node_id
// 涵蓋盤點三分支——祖先/自身/後代（結構）、多歸屬橋接、子樹內資產客體；
// 範圍外排除；每筆授權僅出現一次；與 validity 疊加。
func TestListNodeCoverageFilter(t *testing.T) {
	repo, db := setupAuthzRepoDB(t)

	// 樹：root(1) → A(2) → B(3)；C(4)、E(5) 與 A 無祖先/後代關係
	db.Create(&model.AssetGroup{Name: "root"})               // id 1
	db.Create(&model.AssetGroup{Name: "A", ParentID: up(1)}) // id 2
	db.Create(&model.AssetGroup{Name: "B", ParentID: up(2)}) // id 3
	db.Create(&model.AssetGroup{Name: "C"})                  // id 4
	db.Create(&model.AssetGroup{Name: "E"})                  // id 5

	// 資產：X(1) 多歸屬掛 B 與 C（橋接）；Y(2) 僅掛 C；Z(3) 僅掛 E
	for _, name := range []string{"X", "Y", "Z"} {
		if err := db.Create(&model.Asset{Name: name, Protocol: model.ProtocolSSH,
			Host: "h", Port: 22, Username: "u", Active: true}).Error; err != nil {
			t.Fatalf("seed asset %s: %v", name, err)
		}
	}
	attachNode(t, db, 1, 3) // X on B
	attachNode(t, db, 1, 4) // X on C（多歸屬）
	attachNode(t, db, 2, 4) // Y on C
	attachNode(t, db, 3, 5) // Z on E

	if err := db.Create(&model.User{Username: "u1", Email: strP("u1@x")}).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// 授權：依序 id 1..6
	repoGrant(t, db, up(1), nil, nil, up(1), model.PermissionConnect, nil, nil) // 1: 節點 root——祖先涵蓋
	repoGrant(t, db, up(1), nil, nil, up(3), model.PermissionConnect, nil, nil) // 2: 節點 B——後代
	repoGrant(t, db, up(1), nil, up(1), nil, model.PermissionConnect, nil, nil) // 3: 資產 X——子樹內資產客體
	repoGrant(t, db, up(1), nil, nil, up(4), model.PermissionConnect, nil, nil) // 4: 節點 C——多歸屬橋接（經 X）
	repoGrant(t, db, up(1), nil, up(2), nil, model.PermissionConnect, nil, nil) // 5: 資產 Y——僅掛 C，範圍外
	repoGrant(t, db, up(1), nil, nil, up(5), model.PermissionConnect, nil, nil) // 6: 節點 E——無橋接資產，範圍外

	rows, total, err := repo.List(map[string]interface{}{"node_id": uint(2)}, 1, 50)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 4 {
		t.Fatalf("涵蓋盤點應命中 4 筆（root/B/X/C 橋接）, got total=%d", total)
	}
	seen := map[uint]int{}
	for _, r := range rows {
		seen[r.ID]++
	}
	for _, want := range []uint{1, 2, 3, 4} {
		if seen[want] != 1 {
			t.Fatalf("授權 %d 應恰出現一次, got %d（不重複列鐵則）", want, seen[want])
		}
	}
	if seen[5] != 0 || seen[6] != 0 {
		t.Fatalf("範圍外授權（5:資產僅掛C, 6:節點E）不得出現: %v", seen)
	}

	// 與 validity 疊加：授權 2 設為已過期，node_id＋expired 應僅回它
	past := time.Now().Add(-time.Hour)
	if err := db.Model(&model.AssetAuthorization{}).Where("id = ?", 2).
		Update("date_expired", past).Error; err != nil {
		t.Fatalf("set expired: %v", err)
	}
	rows, total, err = repo.List(map[string]interface{}{
		"node_id":  uint(2),
		"validity": ValidityFilter{State: model.ValidityExpired, Now: time.Now()},
	}, 1, 50)
	if err != nil {
		t.Fatalf("List stacked: %v", err)
	}
	if total != 1 || len(rows) != 1 || rows[0].ID != 2 {
		t.Fatalf("node+validity 疊加應僅命中授權 2, got total=%d", total)
	}

	// 節點 E 盤點：僅掛 E 自身的授權 6 命中（X/Y 不在 E 子樹、無橋接進 A 分支）
	rows, total, err = repo.List(map[string]interface{}{"node_id": uint(5)}, 1, 50)
	if err != nil {
		t.Fatalf("List E: %v", err)
	}
	if total != 1 || len(rows) != 1 || rows[0].ID != 6 {
		t.Fatalf("節點 E 盤點應僅命中授權 6, got total=%d", total)
	}
}
