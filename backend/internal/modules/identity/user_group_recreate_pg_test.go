package identity

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/testgate"
)

// 同名群組的並發建立只成功一筆（PostgreSQL；未設 TEST_PG_DSN 即 skip，REQUIRE_INTEGRATION=1 時 skip 轉 fail）。
// 名稱唯一性完全由資料庫的部分唯一索引承擔，服務層沒有另外的鎖；兩個連線池代表兩個後端副本。
//
//	TEST_PG_DSN="host=... user=... password=... dbname=... sslmode=disable" \
//	  REQUIRE_INTEGRATION=1 go test ./internal/modules/identity -run 'UserGroup.*Recreate.*PG'

const pgUserGroupRecreateSchema = "user_group_recreate_test"

func newUserGroupRecreatePG(t *testing.T) (svcA, svcB *UserGroupService, dbA *gorm.DB) {
	t.Helper()
	base := testgate.Value(t, testgate.EnvPGDSN)
	admin := openPGRaceDB(t, base)
	drop := "DROP SCHEMA IF EXISTS " + pgUserGroupRecreateSchema + " CASCADE"
	require.NoError(t, admin.Exec(drop).Error)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+pgUserGroupRecreateSchema).Error)
	t.Cleanup(func() {
		if err := admin.Exec(drop).Error; err != nil {
			t.Errorf("測試 schema 清理失敗（請手動 DROP SCHEMA %s CASCADE）: %v", pgUserGroupRecreateSchema, err)
		}
	})
	scoped := base + " search_path=" + pgUserGroupRecreateSchema
	dbA = openPGRaceDB(t, scoped)
	dbB := openPGRaceDB(t, scoped)
	require.NoError(t, migrateWithAuthz(dbA, &model.User{}, &model.UserGroup{}, &model.Asset{},
		&model.AssetGroup{}, &model.AssetNode{}, &model.AssetAuthorization{}, &model.ApproverScope{},
		&model.AuditLog{}, &model.UserRole{}, &model.GroupUserGroupMapping{}, &model.UserGroupMappingRuleSupport{},
		&model.UserChannelObservation{}, &model.UserGroupMember{}, &model.UserGroupRole{}, &model.RefreshToken{},
		&model.UserRoleMappingRuleSupport{}, &model.PermissionStateEvent{}))
	seedAuthzState(t, dbA)
	useLiveUniqueGroupName(t, dbA)
	var def string
	require.NoError(t, dbA.Raw(`SELECT indexdef FROM pg_indexes WHERE schemaname = ? AND indexname = 'idx_user_groups_name'`,
		pgUserGroupRecreateSchema).Scan(&def).Error)
	require.Contains(t, def, "WHERE (deleted_at IS NULL)", "前提：群組名稱為部分唯一索引")
	svcA = NewUserGroupService(dbA, audit.NewTxSink(), authz.NewAssetAuthorizationService(dbA))
	svcB = NewUserGroupService(dbB, audit.NewTxSink(), authz.NewAssetAuthorizationService(dbB))
	return svcA, svcB, dbA
}

// concurrentCreate 以兩個連線池交錯送出 n 筆同名建立，同時起跑；回傳成功數與名稱重複數。
func concurrentCreate(t *testing.T, svcA, svcB *UserGroupService, name string, n int) (ok, dup int) {
	t.Helper()
	start := make(chan struct{})
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		svc := svcA
		if i%2 == 1 {
			svc = svcB
		}
		wg.Add(1)
		go func(i int, svc *UserGroupService) {
			defer wg.Done()
			<-start
			_, errs[i] = svc.Create(&UserGroupRequest{Name: name, Description: fmt.Sprintf("racer-%d", i)})
		}(i, svc)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrUserGroupNameExists):
			dup++
		default:
			t.Errorf("第 %d 筆建立回非預期錯誤: %v", i, err)
		}
	}
	return ok, dup
}

func TestUserGroupRecreateConcurrentPG(t *testing.T) {
	svcA, svcB, db := newUserGroupRecreatePG(t)
	const racers = 8

	t.Run("fresh_name", func(t *testing.T) {
		ok, dup := concurrentCreate(t, svcA, svcB, "race-fresh", racers)
		if ok != 1 || dup != racers-1 {
			t.Fatalf("同名並發建立應恰一筆成功：成功 %d、名稱重複 %d", ok, dup)
		}
		var live int64
		require.NoError(t, db.Model(&model.UserGroup{}).Where("name = ?", "race-fresh").Count(&live).Error)
		require.EqualValues(t, 1, live)
	})

	t.Run("name_of_a_deleted_group", func(t *testing.T) {
		g, err := svcA.Create(&UserGroupRequest{Name: "race-recreate"})
		require.NoError(t, err)
		_, err = svcA.Delete(g.ID, 1, "admin", "203.0.113.5")
		require.NoError(t, err)
		ok, dup := concurrentCreate(t, svcA, svcB, "race-recreate", racers)
		if ok != 1 || dup != racers-1 {
			t.Fatalf("已刪除群組的名稱並發重建應恰一筆成功：成功 %d、名稱重複 %d", ok, dup)
		}
		var live, all int64
		require.NoError(t, db.Model(&model.UserGroup{}).Where("name = ?", "race-recreate").Count(&live).Error)
		require.NoError(t, db.Unscoped().Model(&model.UserGroup{}).Where("name = ?", "race-recreate").Count(&all).Error)
		require.EqualValues(t, 1, live, "未刪除的同名群組恰一筆")
		require.EqualValues(t, 2, all, "已刪除的舊列保留原名")
	})
}
