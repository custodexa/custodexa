package identity

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// TestMappingDuplicateConcurrent 兩個連線同時建立群組值與目標皆相同的規則：
// 只有一個成功，另一個得到「規則已存在」，不得是其他錯誤；落地只有一列。
//
// 需要真正的並發連線與正式 migration（唯一索引、外鍵），故只在 PostgreSQL 上執行。
func TestMappingDuplicateConcurrent(t *testing.T) {
	e := newLockOrderEnv(t)
	admin := e.newAdmin(t, "dup-admin")
	p := e.mappingProvider(t, "dup")
	group := model.UserGroup{Name: "dup-group"}
	require.NoError(t, e.dbA.Create(&group).Error)
	actor := GroupRoleMappingActor{Principal: testSessionPrincipal(admin), ID: admin, Name: "dup-admin", IP: "127.0.0.1"}
	kind := model.RoleMappingChannelKindProvider
	svcA, svcB := e.mappingService(e.dbA), e.mappingService(e.dbB)

	race := func(t *testing.T, create func(svc *IdentitySourceService, match string) error, countSQL string) {
		const rounds = 8
		for i := 0; i < rounds; i++ {
			match := fmt.Sprintf("dup-%d", i)
			start := make(chan struct{})
			errs := make([]error, 2)
			var wg sync.WaitGroup
			for n, svc := range []*IdentitySourceService{svcA, svcB} {
				wg.Add(1)
				go func(n int, svc *IdentitySourceService) {
					defer wg.Done()
					<-start
					errs[n] = create(svc, match)
				}(n, svc)
			}
			close(start)
			wg.Wait()

			var ok, dup int
			for _, err := range errs {
				switch {
				case err == nil:
					ok++
				case errors.Is(err, ErrMappingRuleExists):
					dup++
				default:
					t.Fatalf("第 %d 輪出現非預期錯誤：%v", i, err)
				}
			}
			require.Equal(t, 1, ok, "第 %d 輪應恰有一個成功", i)
			require.Equal(t, 1, dup, "第 %d 輪另一個應得到規則已存在", i)
			require.EqualValues(t, 1, e.scalar(t, countSQL, p.ID, match), "第 %d 輪落地應只有一列", i)
		}
	}

	t.Run("角色規則", func(t *testing.T) {
		race(t, func(svc *IdentitySourceService, match string) error {
			_, err := svc.CreateMapping(kind, p.ID, GroupRoleMappingInput{MatchValue: match, Role: model.RoleUser, RiskAcknowledged: true, Actor: actor})
			return err
		}, "SELECT count(*) FROM group_role_mappings WHERE oidc_provider_id = ? AND match_value = ? AND deleted_at IS NULL")
	})

	t.Run("使用者群組規則", func(t *testing.T) {
		race(t, func(svc *IdentitySourceService, match string) error {
			_, err := svc.CreateUserGroupMapping(kind, p.ID, UserGroupMappingInput{MatchValue: match, UserGroupID: group.ID, RiskAcknowledged: true, SourceConfigAcknowledged: true, Actor: actor})
			return err
		}, `SELECT count(*) FROM group_user_group_mappings m JOIN external_groups g ON g.id = m.external_group_id
 WHERE m.oidc_provider_id = ? AND g.match_value = ? AND m.deleted_at IS NULL`)
	})
}

// TestMappingDuplicateConcurrentDirectory 目錄型來源的並發建立：寫入互斥不排隊，
// 所以敗方得到的是「另一項操作進行中」或「規則已存在」兩者之一，不得是其他錯誤；
// 落地只有一列，敗方重送後得到規則已存在。
func TestMappingDuplicateConcurrentDirectory(t *testing.T) {
	e := newLockOrderEnv(t)
	admin := e.newAdmin(t, "dup-dir-admin")
	var dir model.LDAPDirectory
	if err := e.dbA.First(&dir).Error; err != nil {
		dir = model.LDAPDirectory{Name: "dup-dir", URL: "ldaps://dir.example.com", BaseDN: "dc=example,dc=com", AttrGroup: "memberOf", Enabled: true}
		require.NoError(t, e.dbA.Create(&dir).Error)
	}
	group := model.UserGroup{Name: "dup-dir-group"}
	require.NoError(t, e.dbA.Create(&group).Error)
	actor := GroupRoleMappingActor{Principal: testSessionPrincipal(admin), ID: admin, Name: "dup-dir-admin", IP: "127.0.0.1"}
	kind := model.RoleMappingChannelKindDirectory
	svcA, svcB := e.mappingService(e.dbA), e.mappingService(e.dbB)

	race := func(t *testing.T, create func(svc *IdentitySourceService, match string) error, countSQL string) {
		const rounds = 8
		for i := 0; i < rounds; i++ {
			match := fmt.Sprintf("cn=dup-%d,ou=groups,dc=example,dc=com", i)
			start := make(chan struct{})
			errs := make([]error, 2)
			var wg sync.WaitGroup
			for n, svc := range []*IdentitySourceService{svcA, svcB} {
				wg.Add(1)
				go func(n int, svc *IdentitySourceService) {
					defer wg.Done()
					<-start
					errs[n] = create(svc, match)
				}(n, svc)
			}
			close(start)
			wg.Wait()

			var ok int
			for _, err := range errs {
				switch {
				case err == nil:
					ok++
				case errors.Is(err, ErrMappingRuleExists), errors.Is(err, ErrLDAPDirectoryBusy):
				default:
					t.Fatalf("第 %d 輪出現非預期錯誤：%v", i, err)
				}
			}
			require.Equal(t, 1, ok, "第 %d 輪應恰有一個成功", i)
			require.EqualValues(t, 1, e.scalar(t, countSQL, dir.ID, match), "第 %d 輪落地應只有一列", i)
			require.ErrorIs(t, create(svcB, match), ErrMappingRuleExists, "第 %d 輪重送應得到規則已存在", i)
		}
	}

	t.Run("角色規則", func(t *testing.T) {
		race(t, func(svc *IdentitySourceService, match string) error {
			_, err := svc.CreateMapping(kind, dir.ID, GroupRoleMappingInput{MatchValue: match, Role: model.RoleUser, RiskAcknowledged: true, Actor: actor})
			return err
		}, "SELECT count(*) FROM group_role_mappings WHERE ldap_directory_id = ? AND match_value = ? AND deleted_at IS NULL")
	})

	t.Run("使用者群組規則", func(t *testing.T) {
		race(t, func(svc *IdentitySourceService, match string) error {
			_, err := svc.CreateUserGroupMapping(kind, dir.ID, UserGroupMappingInput{MatchValue: match, UserGroupID: group.ID, RiskAcknowledged: true, SourceConfigAcknowledged: true, Actor: actor})
			return err
		}, `SELECT count(*) FROM group_user_group_mappings m JOIN external_groups g ON g.id = m.external_group_id
 WHERE m.ldap_directory_id = ? AND g.match_value = ? AND m.deleted_at IS NULL`)
	})
}
