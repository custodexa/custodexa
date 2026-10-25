package authz

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// scopedComboEnv 危險組合預覽的夾具：沿用判定夾具的節點樹與資產
// （n1─n2─n3、n4、n5；a1 掛 n3、a2 掛 n4、a4 同掛 n2 與 n4），加上各類角色與判定器。
type scopedComboEnv struct {
	f                     *decideFixture
	ev                    *ScopeEvaluator
	rAuthz, rAsset, rCred uint
	rSecurity, rIdentity  uint
}

func newScopedComboEnv(t *testing.T) *scopedComboEnv {
	t.Helper()
	f := newDecideFixture(t)
	require.NoError(t, f.db.AutoMigrate(&model.Credential{}, &model.AssetAuthorization{}))
	// 判定夾具的兩個帳號掛載引用憑證 1、2：先佔住這兩個編號，之後建的憑證才不會被夾具的掛載列誤認
	for i := 0; i < 2; i++ {
		require.NoError(t, f.db.Create(&model.Credential{Scope: model.CredentialScopeShared, Username: "filler",
			SecretType: "password", ProtocolFamily: model.ProtocolFamilySSH}).Error)
	}
	return &scopedComboEnv{
		f: f, ev: NewScopeEvaluator(ProductCatalogue(), f.topo),
		rAuthz: f.role(t, PermAuthorizationManage), rAsset: f.role(t, PermAssetUpdate),
		rCred: f.role(t, PermCredentialUpdate), rSecurity: f.role(t, PermSecurityPolicyManage),
		rIdentity: f.role(t, PermRoleAssign),
	}
}

// nodeCred 建立歸屬於節點的共用憑證。
func (e *scopedComboEnv) nodeCred(t *testing.T, node uint) uint {
	t.Helper()
	kind, name := model.CredentialOwnerNode, e.f.uniq("cred")
	c := model.Credential{Name: &name, Scope: model.CredentialScopeShared, Username: "app", SecretType: "password",
		ProtocolFamily: model.ProtocolFamilySSH, OwnerKind: &kind, OwnerNodeID: &node}
	require.NoError(t, e.f.db.Create(&c).Error)
	return c.ID
}

// dedicatedCred 建立專用憑證並掛在資產上（最早一筆掛載）。
func (e *scopedComboEnv) dedicatedCred(t *testing.T, assetID uint) uint {
	t.Helper()
	kind := model.CredentialOwnerAsset
	c := model.Credential{Scope: model.CredentialScopeDedicated, Username: "app", SecretType: "password",
		ProtocolFamily: model.ProtocolFamilySSH, OwnerKind: &kind}
	require.NoError(t, e.f.db.Create(&c).Error)
	require.NoError(t, e.f.db.Create(&model.AssetAccount{AssetID: assetID, CredentialID: c.ID}).Error)
	return c.ID
}

// connectRule 給使用者一條 connect 授權規則（資產或節點目標二擇一）。
func (e *scopedComboEnv) connectRule(t *testing.T, uid uint, assetID, nodeID *uint) {
	t.Helper()
	require.NoError(t, e.f.db.Create(&model.AssetAuthorization{UserID: &uid, AssetID: assetID, AssetGroupID: nodeID,
		Permission: model.PermissionConnect, GrantedBy: 1, Source: "manual"}).Error)
}

// preview 以直接指派預覽：roles 全為請求的角色，ranges 為 role_nodes（缺的角色為全域）。
func (e *scopedComboEnv) preview(t *testing.T, uid uint, roles []uint, ranges map[uint]PreviewRoleRange) PreviewSubject {
	t.Helper()
	res, err := PreviewEffectiveCapabilities(e.f.db, PreviewRequest{Kind: PreviewDirectRoles, OperatorID: uid, UserID: uid,
		RoleIDs: roles, RoleNodes: ranges, Scope: e.ev})
	require.NoError(t, err)
	require.Len(t, res.Subjects, 1, "操作者本人一律列出")
	return res.Subjects[0]
}

func nodes(ids ...uint) PreviewRoleRange { return PreviewRoleRange{NodeIDs: ids} }

// realCombos 把同一組指派實際寫入另一位使用者，以正式解析出的指派求組合碼（與預覽共用同一個求值函式）。
func (e *scopedComboEnv) realCombos(t *testing.T, roles []uint, ranges map[uint]PreviewRoleRange, rules func(uid uint)) []string {
	t.Helper()
	uid := e.f.user(t)
	for _, r := range roles {
		if rg, ok := ranges[r]; ok && !rg.Global {
			e.f.bindDirect(t, uid, r, rg.NodeIDs...)
		} else {
			e.f.global(t, uid, r)
		}
	}
	if rules != nil {
		rules(uid)
	}
	p, err := ResolveUserOn(e.f.db, uid, TokenFacts{})
	require.NoError(t, err)
	groups, err := userGroupIDs(e.f.db, uid)
	require.NoError(t, err)
	st, err := evalState(e.f.db, e.ev, uid, model.KindHuman, subjectState{assignments: p.Assignments, groupIDs: groups})
	require.NoError(t, err)
	return st.combos
}

func has(combos []string, code string) bool {
	for _, c := range combos {
		if c == code {
			return true
		}
	}
	return false
}

// TestScopedDangerComboIntersection 擋：授權規則管理與資產或憑證管理的組合、資產管理與可連線資產的組合
// 依實際節點交集計算（不相交不列、父子或任一方全域列出、同一資產同掛兩節點列出、憑證歸屬同時在兩方內列出）；
// 其餘三種組合與全域版本逐案相同；預覽唯讀；預覽的假設指派與實寫後的正式解析結果相同。
func TestScopedDangerComboIntersection(t *testing.T) {
	env := newScopedComboEnv(t)
	n, a := env.f.n, env.f.a
	const comboAuthz, comboConnect = ComboAuthzRulesWithAssetOrCredential, ComboAssetManagementWithConnect
	// 乙（n4）下沒有任何資產的子節點：日後掛進乙下的資產會同時落入兩方
	emptyChild := mkNode(t, env.f.db, env.f.uniq("empty"), &n[4]).ID

	t.Run("授權規則管理與資產管理：依節點與資產的實際交集", func(t *testing.T) {
		roles := []uint{env.rAuthz, env.rAsset}
		for name, tc := range map[string]struct {
			ranges map[uint]PreviewRoleRange
			want   bool
		}{
			"甲乙不相交且無同掛資產不列":        {map[uint]PreviewRoleRange{env.rAuthz: nodes(n[3]), env.rAsset: nodes(n[4])}, false},
			"改為乙的父節點後列出":           {map[uint]PreviewRoleRange{env.rAuthz: nodes(n[3]), env.rAsset: nodes(n[2])}, true},
			"授權規則管理改為資產管理的父節點":     {map[uint]PreviewRoleRange{env.rAuthz: nodes(n[1]), env.rAsset: nodes(n[3])}, true},
			"沒有資產的子節點也列出":          {map[uint]PreviewRoleRange{env.rAuthz: nodes(emptyChild), env.rAsset: nodes(n[4])}, true},
			"授權規則管理為全域時列出":         {map[uint]PreviewRoleRange{env.rAuthz: {Global: true}, env.rAsset: nodes(n[4])}, true},
			"資產管理為全域時列出":           {map[uint]PreviewRoleRange{env.rAsset: {Global: true}, env.rAuthz: nodes(n[3])}, true},
			"兩者互不涵蓋但有一台資產同掛兩節點時列出": {map[uint]PreviewRoleRange{env.rAuthz: nodes(n[2]), env.rAsset: nodes(n[4])}, true},
			"兩者不相交、已刪節點不計":         {map[uint]PreviewRoleRange{env.rAuthz: nodes(n[3]), env.rAsset: nodes(n[5])}, false},
		} {
			if name == "兩者不相交、已刪節點不計" {
				require.NoError(t, env.f.db.Delete(&model.AssetGroup{}, n[5]).Error)
			}
			uid := env.f.user(t)
			got := env.preview(t, uid, roles, tc.ranges)
			assert.Equal(t, tc.want, has(got.Combos, comboAuthz), name)
			assert.Equal(t, got.Combos, env.realCombos(t, roles, tc.ranges, nil), name+"：預覽與實寫後的正式解析相同")
		}
		require.NotZero(t, a[1]) // 夾具資產存在
	})

	t.Run("授權規則管理與憑證管理：憑證歸屬同時在兩方範圍內", func(t *testing.T) {
		env.nodeCred(t, n[3])
		roles := []uint{env.rAuthz, env.rCred}
		uid := env.f.user(t)
		got := env.preview(t, uid, roles, map[uint]PreviewRoleRange{env.rAuthz: nodes(n[2]), env.rCred: nodes(n[3])})
		assert.True(t, has(got.Combos, comboAuthz), "歸屬節點在兩方範圍內")
		got = env.preview(t, uid, roles, map[uint]PreviewRoleRange{env.rAuthz: nodes(n[4]), env.rCred: nodes(n[3])})
		assert.False(t, has(got.Combos, comboAuthz), "歸屬只在憑證管理一方內")

		// 專用憑證步驟本身：掛載資產（最早一筆）同時在兩方範圍內才成立；a4 同掛 n2 與 n4
		dedicated := env.dedicatedCred(t, a[4])
		set := func(role uint, ids ...uint) ScopeSet {
			s, err := env.ev.ScopeSetForAssignments(env.f.db, AssignmentSet{Items: []AssignmentInput{{
				BindingSubject: model.BindingSubjectUser, RoleID: role, Scope: model.ScopeKindNodes, NodeIDs: ids}}}, PermCredentialUpdate)
			require.NoError(t, err)
			return s
		}
		ok, err := env.ev.credentialInBoth(env.f.db, set(env.rCred, n[2]), set(env.rCred, n[4]))
		require.NoError(t, err)
		assert.True(t, ok, "專用憑證 %d 的掛載資產在兩方內", dedicated)
		ok, err = env.ev.credentialInBoth(env.f.db, set(env.rCred, n[3]), set(env.rCred, n[4]))
		require.NoError(t, err)
		assert.False(t, ok)
		got = env.preview(t, uid, roles, map[uint]PreviewRoleRange{env.rAuthz: nodes(n[2]), env.rCred: nodes(n[4])})
		assert.True(t, has(got.Combos, comboAuthz), "專用憑證掛在同時於兩方範圍內的資產上")
	})

	t.Run("資產管理與可連線資產：依連線授權涵蓋的資產是否落在管理範圍內", func(t *testing.T) {
		roles := []uint{env.rAsset}
		for name, tc := range map[string]struct {
			rng  PreviewRoleRange
			rule func(uid uint)
			want bool
		}{
			"甲範圍資產管理、只連線乙下資產不列":        {nodes(n[3]), func(uid uint) { env.connectRule(t, uid, &a[2], nil) }, false},
			"改為乙範圍後列出":                 {nodes(n[4]), func(uid uint) { env.connectRule(t, uid, &a[2], nil) }, true},
			"連線授權以節點為目標：子樹內資產算":        {nodes(n[3]), func(uid uint) { env.connectRule(t, uid, nil, &n[2]) }, true},
			"連線授權節點在管理範圍外不列":           {nodes(n[3]), func(uid uint) { env.connectRule(t, uid, nil, &n[4]) }, false},
			"連線授權的節點子樹內有一台資產同掛管理範圍時列出": {nodes(n[4]), func(uid uint) { env.connectRule(t, uid, nil, &n[1]) }, true},
			"全域資產管理加任一連線授權列出":          {PreviewRoleRange{Global: true}, func(uid uint) { env.connectRule(t, uid, &a[3], nil) }, true},
			"沒有連線授權不列":                 {nodes(n[3]), nil, false},
		} {
			uid := env.f.user(t)
			if tc.rule != nil {
				tc.rule(uid)
			}
			ranges := map[uint]PreviewRoleRange{env.rAsset: tc.rng}
			got := env.preview(t, uid, roles, ranges)
			assert.Equal(t, tc.want, has(got.Combos, comboConnect), name)
			real := env.realCombos(t, roles, ranges, tc.rule)
			assert.Equal(t, tc.want, has(real, comboConnect), name+"：實寫後的正式解析")
		}
	})

	t.Run("其餘三種組合與全域版本逐案相同", func(t *testing.T) {
		others := func(cs []string) []string {
			var out []string
			for _, c := range cs {
				if c != comboAuthz && c != comboConnect {
					out = append(out, c)
				}
			}
			sort.Strings(out)
			return out
		}
		for name, roles := range map[string][]uint{
			"系統安全加資產管理":      {env.rSecurity, env.rAsset},
			"系統安全加授權規則管理":    {env.rSecurity, env.rAuthz},
			"身分加系統安全":        {env.rIdentity, env.rSecurity},
			"身分加資產管理":        {env.rIdentity, env.rAsset},
			"身分加授權規則管理加資產管理": {env.rIdentity, env.rAuthz, env.rAsset},
		} {
			scoped := map[uint]PreviewRoleRange{}
			for _, r := range roles {
				if r == env.rAsset || r == env.rAuthz {
					scoped[r] = nodes(n[3])
				}
			}
			global := env.preview(t, env.f.user(t), roles, nil)
			narrowed := env.preview(t, env.f.user(t), roles, scoped)
			assert.Equal(t, others(global.Combos), others(narrowed.Combos), name)
			assert.NotEmpty(t, others(narrowed.Combos), name+"：該案確實命中其餘組合")
		}
	})

	t.Run("群組角色指派預覽接受 role_nodes，保留群組現有的節點範圍", func(t *testing.T) {
		g := &model.UserGroup{Name: env.f.uniq("pg")}
		require.NoError(t, env.f.db.Create(g).Error)
		member := env.f.user(t)
		require.NoError(t, env.f.db.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: member, Manual: true}).Error)
		run := func(ranges map[uint]PreviewRoleRange) PreviewSubject {
			res, err := PreviewEffectiveCapabilities(env.f.db, PreviewRequest{Kind: PreviewGroupRoles, OperatorID: member,
				GroupID: g.ID, RoleIDs: []uint{env.rAuthz, env.rAsset}, RoleNodes: ranges, Scope: env.ev})
			require.NoError(t, err)
			require.Len(t, res.Subjects, 1)
			return res.Subjects[0]
		}
		assert.False(t, has(run(map[uint]PreviewRoleRange{env.rAuthz: nodes(n[3]), env.rAsset: nodes(n[4])}).Combos, comboAuthz))
		assert.True(t, has(run(map[uint]PreviewRoleRange{env.rAuthz: nodes(n[3]), env.rAsset: nodes(n[2])}).Combos, comboAuthz))
		// 群組已持有的節點範圍指派，省略 role_nodes 時保留其範圍（不退回全域）
		require.NoError(t, env.f.db.Create(&model.UserGroupRole{UserGroupID: g.ID, RoleID: env.rAuthz, ScopeKind: model.ScopeKindNodes}).Error)
		require.NoError(t, env.f.db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUserGroup, SubjectID: g.ID,
			RoleID: env.rAuthz, NodeID: n[3]}).Error)
		assert.False(t, has(run(map[uint]PreviewRoleRange{env.rAsset: nodes(n[4])}).Combos, comboAuthz), "保留群組現有的甲範圍")
		assert.True(t, has(run(map[uint]PreviewRoleRange{env.rAsset: {Global: true}}).Combos, comboAuthz), "資產管理改全域")
	})

	t.Run("role_nodes 的輸入檢查", func(t *testing.T) {
		uid := env.f.user(t)
		for name, req := range map[string]PreviewRequest{
			"鍵不在 role_ids 內": {Kind: PreviewDirectRoles, UserID: uid, RoleIDs: []uint{env.rAuthz},
				RoleNodes: map[uint]PreviewRoleRange{env.rAsset: nodes(n[3])}},
			"節點集合為空": {Kind: PreviewDirectRoles, UserID: uid, RoleIDs: []uint{env.rAuthz},
				RoleNodes: map[uint]PreviewRoleRange{env.rAuthz: {}}},
			"成員預覽不接受": {Kind: PreviewGroupMembers, GroupID: 1, RoleIDs: []uint{env.rAuthz},
				RoleNodes: map[uint]PreviewRoleRange{env.rAuthz: nodes(n[3])}},
		} {
			_, err := PreviewEffectiveCapabilities(env.f.db, req)
			assert.ErrorIs(t, err, ErrPreviewInvalid, name)
		}
	})

	t.Run("預覽唯讀：各表列數與權限版本前後相同", func(t *testing.T) {
		version := func() int64 {
			var v int64
			require.NoError(t, env.f.db.Raw("SELECT version FROM authz_state WHERE id = 1").Scan(&v).Error)
			return v
		}
		uid := env.f.user(t)
		before, v0 := tableRowCounts(t, env.f.db), version()
		env.preview(t, uid, []uint{env.rAuthz, env.rAsset}, map[uint]PreviewRoleRange{env.rAuthz: nodes(n[3]), env.rAsset: nodes(n[2])})
		assert.Equal(t, before, tableRowCounts(t, env.f.db))
		assert.Equal(t, v0, version())
	})

	t.Run("沒有節點範圍指派時不經交集路徑，與舊結果相同", func(t *testing.T) {
		got := env.preview(t, env.f.user(t), []uint{env.rAuthz, env.rAsset}, nil)
		assert.True(t, has(got.Combos, comboAuthz))
	})

	t.Run("種入範本：資產管理員與授權管理員範圍有交集時列出，無交集時不列", func(t *testing.T) {
		asset := seededScopedTemplateRole(t, env.f.db, model.BuiltinAssetAdmin)
		authzTpl := seededScopedTemplateRole(t, env.f.db, model.BuiltinAuthzAdmin)
		roles := []uint{asset, authzTpl}
		for name, tc := range map[string]struct {
			ranges map[uint]PreviewRoleRange
			want   bool
		}{
			"甲乙不相交不列":     {map[uint]PreviewRoleRange{authzTpl: nodes(n[3]), asset: nodes(n[4])}, false},
			"改為乙的父節點後列出":  {map[uint]PreviewRoleRange{authzTpl: nodes(n[3]), asset: nodes(n[2])}, true},
			"授權管理員為全域時列出": {map[uint]PreviewRoleRange{authzTpl: {Global: true}, asset: nodes(n[4])}, true},
		} {
			got := env.preview(t, env.f.user(t), roles, tc.ranges)
			assert.Equal(t, tc.want, has(got.Combos, comboAuthz), name)
			assert.Equal(t, got.Combos, env.realCombos(t, roles, tc.ranges, nil), name+"：預覽與實寫後的正式解析相同")
		}
	})
}
