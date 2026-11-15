package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
)

// 名稱精確查找與建立時的重複判定一致：對五種資源各以一組名稱變體（大小寫、前後空白）走正式的建立路徑，
// 記下每個變體是否被判為名稱重複，再以同一個字串查找：被判重複者查找回原本那一筆，未被判重複者只回
// 名稱完全相同的那一筆（即剛建立的變體），兩種結果都驗。另驗撞名不賦予查閱資格：撞名的那一筆對呼叫者
// 不可見或不符其他篩選時，查找回應與不存在的名稱相同。SQLite 與 PostgreSQL 各跑一次。

const exactLookupBase = "Lookup-Alpha"

// exactLookupResource 一種資源的建立與查找。
type exactLookupResource struct {
	kind string
	// create 走正式建立路徑；回新列識別或錯誤
	create func(t *testing.T, name string) (uint, error)
	// isDuplicate 錯誤是否為該資源的名稱重複判定
	isDuplicate func(error) bool
	// lookup 以超級管理者帶名稱查找，回識別清單
	lookup func(t *testing.T, name string) []uint
	// same 建立時預期被判為與基準名稱重複的變體（基準本身除外）
	same []string
}

var exactLookupVariants = []string{exactLookupBase, "lookup-alpha", "LOOKUP-ALPHA", " Lookup-Alpha", "Lookup-Alpha ", "Lookup-Alpha\t"}

type exactLookupEnv struct {
	*scEnv
	groups *asset.AssetGroupService
	ugroup *identity.UserGroupService
	users  *identity.UserService
}

func newExactLookupEnv(t *testing.T, sc *scEnv) *exactLookupEnv {
	t.Helper()
	if sc.db.Dialector.Name() != "postgres" {
		require.NoError(t, sc.db.AutoMigrate(&model.PermissionStateEvent{}, &model.UserGroupMappingRuleSupport{},
			&model.OIDCProvider{}, &model.UserExternalIdentity{}, &model.SecurityPolicy{}, &model.PasswordHistory{}))
	}
	groups := asset.NewAssetGroupService(sc.db, audit.NewTxSink(), sc.authzSvc)
	groups.SetTopologyPermissionPort(authz.TopologyPermissionAdapter{})
	groups.SetNodeWriteScopePort(authz.NewNodeWriteScope(sc.eval))
	groups.SetNodeScopeReferencePort(authz.NewNodeScopeReferenceReader())
	groups.SetCoverageSnapshotPort(authz.NewTopologyCoverageReader(asset.NewScopeTopologyReader()))
	return &exactLookupEnv{scEnv: sc, groups: groups,
		ugroup: identity.NewUserGroupService(sc.db, audit.NewTxSink(), nil),
		users:  identity.NewUserService(sc.db, nil)}
}

// actorCtx 以資料庫解析出的主體為服務層脈絡（與正式請求同一份主體）。
func (e *exactLookupEnv) actorCtx(uid uint) context.Context {
	e.t.Helper()
	p, err := authz.ResolveUserOnWithCatalogue(e.db, e.cat, uid, authz.TokenFacts{})
	require.NoError(e.t, err)
	ctx := authz.ContextWithPrincipal(context.Background(), p)
	ctx = context.WithValue(ctx, "userID", uid)                        //nolint:staticcheck // 沿用審計 context 慣例
	return context.WithValue(ctx, "username", fmt.Sprintf("u%d", uid)) //nolint:staticcheck
}

// listRouter 掛節點、使用者、使用者群組列表（每請求自資料庫解析主體）。
func (e *exactLookupEnv) listRouter(uid uint) *gin.Engine {
	r := gin.New()
	r.Use(func(c *gin.Context) {
		p, err := authz.ResolveUserOnWithCatalogue(e.db, e.cat, uid, authz.TokenFacts{})
		require.NoError(e.t, err)
		middleware.SetPrincipal(c, p)
		c.Set("userID", uid)
		c.Set("username", fmt.Sprintf("u%d", uid))
		c.Next()
	})
	nh := api.NewAssetGroupHandler(e.groups, e.authzSvc, e.authzSvc)
	nh.SetNodeTreeScope(authz.NewNodeTreeScopeReader(e.eval, e.db))
	r.GET("/api/v1/asset-groups", nh.List)
	r.GET("/api/v1/users", api.NewUserHandler(e.users).List)
	r.GET("/api/v1/user-groups", api.NewUserGroupHandler(e.ugroup).List)
	return r
}

// get 送出列表請求：回狀態碼、識別清單（排序）與原始本文。
func (e *exactLookupEnv) get(r http.Handler, path string, q url.Values) (int, []uint, string) {
	e.t.Helper()
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path+"?"+q.Encode(), nil))
	var resp struct {
		Data []struct {
			ID uint `json:"id"`
		} `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	ids := make([]uint, 0, len(resp.Data))
	for _, d := range resp.Data {
		ids = append(ids, d.ID)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return w.Code, ids, w.Body.String()
}

func (e *exactLookupEnv) mustGet(t *testing.T, r http.Handler, path string, q url.Values) ([]uint, string) {
	t.Helper()
	code, ids, raw := e.get(r, path, q)
	require.Equal(t, http.StatusOK, code, raw)
	return ids, raw
}

func (e *exactLookupEnv) resources() []exactLookupResource {
	admin := e.super
	host := 10
	return []exactLookupResource{
		{
			kind: "asset",
			create: func(t *testing.T, name string) (uint, error) {
				host++
				a, err := e.assets.Create(asset.WithSystemCaller(e.actorCtx(admin)), &asset.CreateAssetRequest{
					Name: name, Protocol: model.ProtocolSSH, Host: fmt.Sprintf("198.51.100.%d", host), Port: 22, CreatedBy: admin,
				})
				if err != nil {
					return 0, err
				}
				return a.ID, nil
			},
			isDuplicate: func(err error) bool { return errors.Is(err, asset.ErrAssetNameExists) },
			lookup: func(t *testing.T, name string) []uint {
				ids, _ := e.mustGet(t, e.router(admin, true), "/api/v1/assets", url.Values{"name": {name}, "page_size": {"100"}})
				return ids
			},
		},
		{
			kind: "node",
			create: func(t *testing.T, name string) (uint, error) {
				g, err := e.groups.Create(e.actorCtx(admin), &asset.AssetGroupRequest{Name: name}, admin, "admin", "203.0.113.5")
				if err != nil {
					return 0, err
				}
				return g.ID, nil
			},
			isDuplicate: func(err error) bool { return errors.Is(err, asset.ErrGroupNameExists) },
			lookup: func(t *testing.T, name string) []uint {
				ids, _ := e.mustGet(t, e.listRouter(admin), "/api/v1/asset-groups", url.Values{"name": {name}})
				return ids
			},
		},
		{
			kind: "user_group",
			create: func(t *testing.T, name string) (uint, error) {
				g, err := e.ugroup.Create(&identity.UserGroupRequest{Name: name})
				if err != nil {
					return 0, err
				}
				return g.ID, nil
			},
			isDuplicate: func(err error) bool { return errors.Is(err, identity.ErrUserGroupNameExists) },
			lookup: func(t *testing.T, name string) []uint {
				ids, _ := e.mustGet(t, e.listRouter(admin), "/api/v1/user-groups", url.Values{"name": {name}})
				return ids
			},
		},
		{
			kind: "user",
			create: func(t *testing.T, name string) (uint, error) {
				u, err := e.users.Create(&identity.CreateUserRequest{Username: name, Password: "Lookup-Test-Passw0rd!"})
				if err != nil {
					return 0, err
				}
				return u.ID, nil
			},
			isDuplicate: func(err error) bool { return errors.Is(err, identity.ErrUsernameExists) },
			lookup: func(t *testing.T, name string) []uint {
				ids, _ := e.mustGet(t, e.listRouter(admin), "/api/v1/users", url.Values{"username": {name}})
				return ids
			},
		},
		{
			kind: "credential",
			create: func(t *testing.T, name string) (uint, error) {
				c, err := e.creds.Create(e.actorCtx(admin), &asset.CreateCredentialRequest{
					Name: name, Username: "svc", ProtocolFamily: model.ProtocolFamilySSH, Password: "pw-for-test",
				})
				if err != nil {
					return 0, err
				}
				return c.ID, nil
			},
			isDuplicate: func(err error) bool { return errors.Is(err, asset.ErrCredentialNameExists) },
			lookup: func(t *testing.T, name string) []uint {
				code, raw := e.call(admin, http.MethodGet, "/api/v1/credentials?"+url.Values{"name": {name}}.Encode(), "")
				require.Equal(t, http.StatusOK, code, raw)
				var resp struct {
					Data []struct {
						ID uint `json:"id"`
					} `json:"data"`
				}
				require.NoError(t, json.Unmarshal([]byte(raw), &resp))
				ids := []uint{}
				for _, d := range resp.Data {
					ids = append(ids, d.ID)
				}
				return ids
			},
			// 共用憑證建立時先去頭尾空白再判重
			same: []string{" Lookup-Alpha", "Lookup-Alpha ", "Lookup-Alpha\t"},
		},
	}
}

func runExactLookupAgreesWithUniqueness(t *testing.T, e *exactLookupEnv) {
	for _, res := range e.resources() {
		res := res
		t.Run(res.kind, func(t *testing.T) {
			orig, err := res.create(t, exactLookupBase)
			require.NoError(t, err, "基準名稱建立成功")
			same := map[string]bool{exactLookupBase: true}
			for _, v := range res.same {
				same[v] = true
			}
			for _, v := range exactLookupVariants {
				id, err := res.create(t, v)
				dup := err != nil && res.isDuplicate(err)
				if !dup {
					require.NoError(t, err, "%q：非重複時建立成功（不因其他原因失敗）", v)
				}
				assert.Equal(t, same[v], dup, "%q：建立時%s判為名稱重複", v, map[bool]string{true: "應", false: "不應"}[same[v]])
				got := res.lookup(t, v)
				if dup {
					assert.Equal(t, []uint{orig}, got, "%q：被判重複，查找回原本那一筆", v)
					t.Logf("variant=%q verdict=duplicate lookup=%v", v, got)
				} else {
					assert.Equal(t, []uint{id}, got, "%q：不被判重複，查找只回名稱完全相同的那一筆", v)
					t.Logf("variant=%q verdict=distinct lookup=%v", v, got)
				}
			}
			assert.Equal(t, []uint{orig}, res.lookup(t, exactLookupBase), "基準名稱仍只回原本那一筆")
		})
	}

	t.Run("collision_does_not_grant_visibility", func(t *testing.T) {
		admin := e.super
		in, out := e.node("zz-lk-in", ""), e.node("zz-lk-out", "")
		_ = in
		viewer := e.user("zz-lk-viewer")
		e.grant(viewer, []string{"zz-lk-in"}, authz.PermAssetView, authz.PermCredentialView)

		// 資產：範圍外資產的名稱建立時被判重複，範圍化檢視者查找與不存在相同
		e.asset("zz-lk-asset-in", "zz-lk-in")
		e.asset("zz-lk-asset-out", "zz-lk-out")
		_, err := e.assets.Create(asset.WithSystemCaller(e.actorCtx(admin)), &asset.CreateAssetRequest{
			Name: "zz-lk-asset-out", Protocol: model.ProtocolSSH, Host: "198.51.100.200", Port: 22, CreatedBy: admin})
		require.ErrorIs(t, err, asset.ErrAssetNameExists)
		ar := e.router(viewer, true)
		ids, _ := e.mustGet(t, ar, "/api/v1/assets", url.Values{"name": {"zz-lk-asset-in"}})
		require.Len(t, ids, 1, "範圍內的資產查得到（排除空集合假綠）")
		_, missing := e.mustGet(t, ar, "/api/v1/assets", url.Values{"name": {"zz-lk-no-such"}})
		_, hidden := e.mustGet(t, ar, "/api/v1/assets", url.Values{"name": {"zz-lk-asset-out"}})
		assert.Equal(t, missing, hidden, "資產：撞名的範圍外資產與不存在同本文")

		// 共用憑證：歸屬範圍外節點者
		e.cred("zz-lk-cred-in", e.nodeID("zz-lk-in"))
		e.cred("zz-lk-cred-out", e.nodeID("zz-lk-out"))
		_, err = e.creds.Create(e.actorCtx(admin), &asset.CreateCredentialRequest{
			Name: " zz-lk-cred-out ", Username: "svc", ProtocolFamily: model.ProtocolFamilySSH, Password: "pw-for-test"})
		require.ErrorIs(t, err, asset.ErrCredentialNameExists)
		inList := e.list(viewer, "name=zz-lk-cred-in")
		require.Len(t, inList.Data, 1, "範圍內的憑證查得到")
		missingCred := e.list(viewer, "name=zz-lk-no-such")
		hiddenCred := e.list(viewer, "name=zz-lk-cred-out")
		assert.Equal(t, missingCred.raw, hiddenCred.raw, "共用憑證：撞名的範圍外憑證與不存在同本文")

		// 節點：範圍外節點之下的同名節點
		e.node("zz-lk-node", "zz-lk-out")
		_, err = e.groups.Create(e.actorCtx(admin), &asset.AssetGroupRequest{Name: "zz-lk-node", ParentID: &out}, admin, "admin", "203.0.113.5")
		require.ErrorIs(t, err, asset.ErrGroupNameExists)
		lr := e.listRouter(viewer)
		ids, _ = e.mustGet(t, lr, "/api/v1/asset-groups", url.Values{"name": {"zz-lk-in"}})
		require.Len(t, ids, 1, "範圍內的節點查得到")
		_, missingNode := e.mustGet(t, lr, "/api/v1/asset-groups", url.Values{"name": {"zz-lk-no-such"}})
		_, hiddenNode := e.mustGet(t, lr, "/api/v1/asset-groups", url.Values{"name": {"zz-lk-node"}})
		assert.Equal(t, missingNode, hiddenNode, "節點：撞名的範圍外節點與不存在同本文")

		// 使用者：與自動化帳號撞名；預設列表不含自動化帳號，查找不回它
		owner := e.user("zz-lk-owner")
		bot := model.User{Username: "zz-lk-bot", Password: "!", Kind: model.KindAgent, OwnerUserID: &owner, Active: true}
		require.NoError(t, e.db.Create(&bot).Error)
		_, err = e.users.Create(&identity.CreateUserRequest{Username: "zz-lk-bot", Password: "Lookup-Test-Passw0rd!"})
		require.ErrorIs(t, err, identity.ErrUsernameExists, "使用者名稱的撞名判定不分種類")
		ar2 := e.listRouter(admin)
		_, missingUser := e.mustGet(t, ar2, "/api/v1/users", url.Values{"username": {"zz-lk-no-such"}})
		_, hiddenUser := e.mustGet(t, ar2, "/api/v1/users", url.Values{"username": {"zz-lk-bot"}})
		assert.Equal(t, missingUser, hiddenUser, "使用者：未要求包含自動化帳號時，撞名的自動化帳號與不存在同本文")
		ids, _ = e.mustGet(t, ar2, "/api/v1/users", url.Values{"username": {"zz-lk-bot"}, "include_agents": {"true"}})
		assert.Equal(t, []uint{bot.ID}, ids, "明確要求包含自動化帳號時查得到")
	})
}

func TestExactLookupAgreesWithUniqueness(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		runExactLookupAgreesWithUniqueness(t, newExactLookupEnv(t, newSCEnv(t)))
	})
	t.Run("postgres", func(t *testing.T) {
		sc := newSCEnvPG(t, "exact_lookup_uniq")
		var dbColl struct{ Datcollate, Datctype string }
		require.NoError(t, sc.db.Raw("SELECT datcollate, datctype FROM pg_database WHERE datname = current_database()").Scan(&dbColl).Error)
		fmt.Printf("EVIDENCE pg_database collate=%s ctype=%s\n", dbColl.Datcollate, dbColl.Datctype)
		var cols []struct{ TableName, ColumnName, CollationName string }
		require.NoError(t, sc.db.Raw(`SELECT table_name, column_name, COALESCE(collation_name, '(database default)') AS collation_name
			FROM information_schema.columns WHERE table_schema = current_schema()
			AND ((table_name IN ('assets','asset_groups','user_groups','credentials') AND column_name = 'name')
			  OR (table_name = 'users' AND column_name = 'username')) ORDER BY table_name`).Scan(&cols).Error)
		require.Len(t, cols, 5)
		for _, c := range cols {
			fmt.Printf("EVIDENCE column %s.%s collation=%s\n", c.TableName, c.ColumnName, c.CollationName)
		}
		var deterministic bool
		require.NoError(t, sc.db.Raw("SELECT collisdeterministic FROM pg_collation WHERE collname = 'default'").Scan(&deterministic).Error)
		fmt.Printf("EVIDENCE default collation deterministic=%v\n", deterministic)
		runExactLookupAgreesWithUniqueness(t, newExactLookupEnv(t, sc))
	})
}
