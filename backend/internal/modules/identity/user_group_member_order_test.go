package identity

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/testgate"
)

// 群組成員物件的順序：列表與單筆讀取的 users 陣列依使用者識別遞增排列，與 user_ids 同序，
// 不隨成員加入順序或資料列的實體存放位置而變。PostgreSQL 版本以更新過的使用者列改變實體順序
// （未排序的掃描會照實體順序回傳），驗證順序是查詢明定的，而不是剛好如此。
//
//	TEST_PG_DSN="host=... user=... password=... dbname=... sslmode=disable" \
//	  REQUIRE_INTEGRATION=1 go test ./internal/modules/identity -run 'UserGroupMemberOrder'

const pgUserGroupMemberOrderSchema = "user_group_member_order_test"

// runUserGroupMemberOrderCase 成員以非識別順序加入、部分使用者列更新後，列表元素與單筆的 users 皆依識別排序。
func runUserGroupMemberOrderCase(t *testing.T, svc *UserGroupService, db *gorm.DB) {
	t.Helper()
	users := seedUsers(t, db, "order-a", "order-b", "order-c", "order-d")
	group := model.UserGroup{Name: "member-order"}
	require.NoError(t, db.Create(&group).Error)
	for _, i := range []int{2, 0, 3, 1} {
		require.NoError(t, db.Exec("INSERT INTO user_group_members (user_group_id, user_id, manual) VALUES (?, ?, ?)",
			group.ID, users[i].ID, true).Error)
	}
	// 更新前兩位使用者：PostgreSQL 的更新會把新版本的列寫在實體位置的後段
	for _, u := range users[:2] {
		require.NoError(t, db.Model(&model.User{}).Where("id = ?", u.ID).Update("username", u.Username+"-renamed").Error)
	}
	var want []uint
	for _, u := range users {
		want = append(want, u.ID)
	}

	usersOf := func(g *model.UserGroup) []uint {
		var out []uint
		for _, u := range g.Users {
			out = append(out, u.ID)
		}
		return out
	}

	list, err := svc.List()
	require.NoError(t, err)
	var listed *model.UserGroup
	for i := range list {
		if list[i].ID == group.ID {
			listed = &list[i]
		}
	}
	require.NotNil(t, listed, "群組在列表中")
	assert.Equal(t, want, usersOf(listed), "列表元素的 users 依使用者識別排序")
	assert.Equal(t, want, listed.UserIDs, "user_ids 依使用者識別排序")

	one, err := svc.Get(group.ID)
	require.NoError(t, err)
	assert.Equal(t, want, usersOf(one), "單筆的 users 依使用者識別排序")
	assert.Equal(t, usersOf(listed), usersOf(one), "列表與單筆的 users 同序")
}

func TestUserGroupMemberOrder(t *testing.T) {
	svc, db := setupUserGroupDB(t)
	runUserGroupMemberOrderCase(t, svc, db)
}

func TestUserGroupMemberOrderPG(t *testing.T) {
	base := testgate.Value(t, testgate.EnvPGDSN)
	admin := openPGRaceDB(t, base)
	drop := "DROP SCHEMA IF EXISTS " + pgUserGroupMemberOrderSchema + " CASCADE"
	require.NoError(t, admin.Exec(drop).Error)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+pgUserGroupMemberOrderSchema).Error)
	t.Cleanup(func() {
		if err := admin.Exec(drop).Error; err != nil {
			t.Errorf("測試 schema 清理失敗（請手動 DROP SCHEMA %s CASCADE）: %v", pgUserGroupMemberOrderSchema, err)
		}
	})
	db := openPGRaceDB(t, base+" search_path="+pgUserGroupMemberOrderSchema)
	require.NoError(t, migrateWithAuthz(db, &model.User{}, &model.UserGroup{}, &model.Asset{},
		&model.AssetGroup{}, &model.AssetNode{}, &model.AssetAuthorization{}, &model.ApproverScope{},
		&model.AuditLog{}, &model.UserRole{}, &model.GroupUserGroupMapping{}, &model.UserGroupMappingRuleSupport{},
		&model.UserChannelObservation{}, &model.UserGroupMember{}, &model.UserGroupRole{}, &model.RefreshToken{},
		&model.UserRoleMappingRuleSupport{}, &model.PermissionStateEvent{}))
	seedAuthzState(t, db)
	svc := NewUserGroupService(db, audit.NewTxSink(), authz.NewAssetAuthorizationService(db))
	runUserGroupMemberOrderCase(t, svc, db)
}
