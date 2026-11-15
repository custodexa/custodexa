package identity

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
)

// 對應規則供宣告式工具使用的契約：重複回衝突、依識別讀單筆、列表精確查找。

const contractKind = model.RoleMappingChannelKindProvider

func (e *mappingGuardEnv) secondProvider(t *testing.T) uint {
	t.Helper()
	p := model.OIDCProvider{Name: "idp-2", Issuer: "https://idp2.example.com", ClientID: "c2", GroupsClaim: "groups",
		Enabled: true, AdmissionMode: model.AdmissionPreboundOnly, ClientSecretEnc: "enc"}
	require.NoError(t, e.db.Create(&p).Error)
	return p.ID
}

func uintp(n uint) *uint { return &n }

func asJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}

// TestMappingDuplicateRoleRule 同一來源內群組值與角色皆相同的角色規則只能有一條。
func TestMappingDuplicateRoleRule(t *testing.T) {
	e := newMappingGuardEnv(t, true)
	su := e.actor(e.admin, "root")
	first := e.roleRule(t, su, "grp-a", "auditor")
	other := e.roleRule(t, su, "grp-b", "auditor")

	t.Run("重複建立回衝突且不寫入", func(t *testing.T) {
		rr0, _, g0 := e.ruleCounts(t)
		for _, enabled := range []*bool{nil, boolp(false)} {
			_, err := e.src.CreateMapping(contractKind, e.provider, GroupRoleMappingInput{MatchValue: "grp-a", Role: "auditor", Enabled: enabled, RiskAcknowledged: true, Actor: su})
			require.ErrorIs(t, err, ErrMappingRuleExists)
		}
		rr1, _, g1 := e.ruleCounts(t)
		assert.Equal(t, rr0, rr1, "被拒的建立不得寫入規則列")
		assert.Equal(t, g0, g1, "被拒的建立不得寫入字典列")
	})

	t.Run("同一群組值對應另一個角色不算重複", func(t *testing.T) {
		v, err := e.src.CreateMapping(contractKind, e.provider, GroupRoleMappingInput{MatchValue: "grp-a", Role: "user", RiskAcknowledged: true, Actor: su})
		require.NoError(t, err)
		assert.NotEqual(t, first.ID, v.ID)
	})

	t.Run("只差大小寫的群組值是不同規則", func(t *testing.T) {
		_, err := e.src.CreateMapping(contractKind, e.provider, GroupRoleMappingInput{MatchValue: "GRP-A", Role: "auditor", RiskAcknowledged: true, Actor: su})
		require.NoError(t, err)
	})

	t.Run("修改成與另一條相同回衝突且原規則不變", func(t *testing.T) {
		before := e.roleRuleState(t, other.ID)
		_, err := e.src.UpdateMapping(contractKind, e.provider, other.ID, GroupRoleMappingInput{MatchValue: "grp-a", Role: "auditor", RiskAcknowledged: true, Actor: su})
		require.ErrorIs(t, err, ErrMappingRuleExists)
		assert.Equal(t, before, e.roleRuleState(t, other.ID))
	})

	t.Run("原樣重送成功", func(t *testing.T) {
		v, err := e.src.UpdateMapping(contractKind, e.provider, other.ID, GroupRoleMappingInput{MatchValue: "grp-b", Role: "auditor", RiskAcknowledged: true, Actor: su})
		require.NoError(t, err)
		assert.Equal(t, other.ID, v.ID, "內容未變的修改不換新列")
	})

	t.Run("刪除後可重建", func(t *testing.T) {
		require.NoError(t, e.src.DeleteMapping(contractKind, e.provider, first.ID, su))
		_, err := e.src.CreateMapping(contractKind, e.provider, GroupRoleMappingInput{MatchValue: "grp-a", Role: "auditor", RiskAcknowledged: true, Actor: su})
		require.NoError(t, err)
	})

	t.Run("不同來源互不影響", func(t *testing.T) {
		p2 := e.secondProvider(t)
		_, err := e.src.CreateMapping(contractKind, p2, GroupRoleMappingInput{MatchValue: "grp-a", Role: "auditor", RiskAcknowledged: true, Actor: su})
		require.NoError(t, err)
	})
}

// TestMappingDuplicateUserGroupRule 同一來源內群組值與目標群組皆相同的使用者群組規則只能有一條。
func TestMappingDuplicateUserGroupRule(t *testing.T) {
	e := newMappingGuardEnv(t, true)
	su := e.actor(e.admin, "root")
	gA := e.group(t, "ug-a")
	gB := e.group(t, "ug-b")
	first := e.groupRule(t, su, "grp-a", gA)
	other := e.groupRule(t, su, "grp-b", gA)
	in := func(match string, group uint) UserGroupMappingInput {
		return UserGroupMappingInput{MatchValue: match, UserGroupID: group, RiskAcknowledged: true, SourceConfigAcknowledged: true, Actor: su}
	}

	t.Run("重複建立回衝突且不寫入", func(t *testing.T) {
		_, gr0, g0 := e.ruleCounts(t)
		_, err := e.src.CreateUserGroupMapping(contractKind, e.provider, in("grp-a", gA))
		require.ErrorIs(t, err, ErrMappingRuleExists)
		_, gr1, g1 := e.ruleCounts(t)
		assert.Equal(t, gr0, gr1)
		assert.Equal(t, g0, g1)
	})

	t.Run("同一群組值對應另一個群組不算重複", func(t *testing.T) {
		_, err := e.src.CreateUserGroupMapping(contractKind, e.provider, in("grp-a", gB))
		require.NoError(t, err)
	})

	t.Run("修改成與另一條相同回衝突且原規則不變", func(t *testing.T) {
		before := e.groupRuleState(t, other.ID)
		_, err := e.src.UpdateUserGroupMapping(contractKind, e.provider, other.ID, in("grp-a", gA))
		require.ErrorIs(t, err, ErrMappingRuleExists)
		assert.Equal(t, before, e.groupRuleState(t, other.ID))
	})

	t.Run("原樣重送成功", func(t *testing.T) {
		r, err := e.src.UpdateUserGroupMapping(contractKind, e.provider, other.ID, in("grp-b", gA))
		require.NoError(t, err)
		assert.Equal(t, other.ID, r.ID)
	})

	t.Run("刪除後可重建", func(t *testing.T) {
		require.NoError(t, e.src.DeleteUserGroupMapping(contractKind, e.provider, first.ID, su))
		_, err := e.src.CreateUserGroupMapping(contractKind, e.provider, in("grp-a", gA))
		require.NoError(t, err)
	})

	t.Run("不同來源互不影響", func(t *testing.T) {
		p2 := e.secondProvider(t)
		_, err := e.src.CreateUserGroupMapping(contractKind, p2, in("grp-a", gA))
		require.NoError(t, err)
	})
}

// TestMappingDuplicateAfterGate 指派關卡先於重複判定：無權寫入受保護目標的操作者，
// 對已存在與不存在的組合得到相同的拒絕，看不出規則是否存在。
func TestMappingDuplicateAfterGate(t *testing.T) {
	e := newMappingGuardEnv(t, true)
	su := e.actor(e.admin, "root")
	ida := e.actor(e.mkUser(t, "ida", "identity_admin"), "ida")
	denied := apierror.CodeAuthProtectedRoleAssignment

	e.roleRule(t, su, "exists", "admin")
	protectedGroup := e.group(t, "ug-protected", "admin")
	e.groupRule(t, su, "exists", protectedGroup)

	for _, match := range []string{"exists", "absent"} {
		_, err := e.src.CreateMapping(contractKind, e.provider, GroupRoleMappingInput{MatchValue: match, Role: "admin", RiskAcknowledged: true, Actor: ida})
		assertCode(t, err, denied)
		_, err = e.src.CreateUserGroupMapping(contractKind, e.provider, UserGroupMappingInput{MatchValue: match, UserGroupID: protectedGroup, RiskAcknowledged: true, SourceConfigAcknowledged: true, Actor: ida})
		assertCode(t, err, denied)
	}

	// 風險確認同樣先於重複判定：未確認時不因組合已存在而改回衝突
	_, err := e.src.CreateMapping(contractKind, e.provider, GroupRoleMappingInput{MatchValue: "exists", Role: "admin", Actor: su})
	var ack *MappingAckRequiredError
	require.ErrorAs(t, err, &ack)
}

// TestMappingExactLookup 列表依群組值與目標精確查找，取交集；群組值逐字相等。
func TestMappingExactLookup(t *testing.T) {
	e := newMappingGuardEnv(t, true)
	su := e.actor(e.admin, "root")
	gA := e.group(t, "ug-a")
	gB := e.group(t, "ug-b")
	rLower := e.roleRule(t, su, "team", "auditor")
	rUpper := e.roleRule(t, su, "TEAM", "auditor")
	rUser := e.roleRule(t, su, "team", "user")
	uLower := e.groupRule(t, su, "team", gA)
	uUpper := e.groupRule(t, su, "TEAM", gA)
	uB := e.groupRule(t, su, "team", gB)

	roleIDs := func(l RoleMappingLookup) []uint {
		rows, err := e.src.LookupMappings(contractKind, e.provider, l)
		require.NoError(t, err)
		ids := make([]uint, 0, len(rows))
		for _, r := range rows {
			ids = append(ids, r.ID)
		}
		return ids
	}
	groupIDs := func(l UserGroupMappingLookup) []uint {
		rows, err := e.src.LookupUserGroupMappings(contractKind, e.provider, l)
		require.NoError(t, err)
		ids := make([]uint, 0, len(rows))
		for _, r := range rows {
			ids = append(ids, r.ID)
		}
		return ids
	}

	t.Run("角色規則", func(t *testing.T) {
		assert.ElementsMatch(t, []uint{rLower.ID, rUpper.ID, rUser.ID}, roleIDs(RoleMappingLookup{}), "不帶條件回全部")
		assert.ElementsMatch(t, []uint{rLower.ID, rUser.ID}, roleIDs(RoleMappingLookup{MatchValue: strp("team")}), "只差大小寫的不命中")
		assert.ElementsMatch(t, []uint{rUpper.ID}, roleIDs(RoleMappingLookup{MatchValue: strp("TEAM")}))
		assert.ElementsMatch(t, []uint{rLower.ID, rUpper.ID}, roleIDs(RoleMappingLookup{Role: strp("auditor")}))
		assert.ElementsMatch(t, []uint{rUser.ID}, roleIDs(RoleMappingLookup{MatchValue: strp("team"), Role: strp("user")}), "兩個條件取交集")
		assert.Empty(t, roleIDs(RoleMappingLookup{MatchValue: strp("tea")}), "部分相符不命中")
		assert.ElementsMatch(t, []uint{rLower.ID, rUser.ID}, roleIDs(RoleMappingLookup{MatchValue: strp("  team ")}), "查找值與寫入時一樣去除前後空白")
		assert.ElementsMatch(t, []uint{rLower.ID, rUpper.ID}, roleIDs(RoleMappingLookup{Role: strp(" auditor ")}), "角色名稱同樣去除前後空白")
		assert.Empty(t, roleIDs(RoleMappingLookup{Role: strp("no-such-role")}), "不存在的角色名稱回空清單")
		for _, l := range []RoleMappingLookup{{MatchValue: strp("")}, {Role: strp("")}, {MatchValue: strp("   ")}, {Role: strp(" \t")}} {
			_, err := e.src.LookupMappings(contractKind, e.provider, l)
			require.ErrorIs(t, err, ErrMappingLookupParam)
		}
	})

	t.Run("使用者群組規則", func(t *testing.T) {
		assert.ElementsMatch(t, []uint{uLower.ID, uUpper.ID, uB.ID}, groupIDs(UserGroupMappingLookup{}))
		assert.ElementsMatch(t, []uint{uLower.ID, uB.ID}, groupIDs(UserGroupMappingLookup{MatchValue: strp("team")}))
		assert.ElementsMatch(t, []uint{uLower.ID, uUpper.ID}, groupIDs(UserGroupMappingLookup{UserGroupID: uintp(gA)}))
		assert.ElementsMatch(t, []uint{uB.ID}, groupIDs(UserGroupMappingLookup{MatchValue: strp("team"), UserGroupID: uintp(gB)}))
		assert.Empty(t, groupIDs(UserGroupMappingLookup{UserGroupID: uintp(987654)}), "不存在的群組回空清單")
		assert.ElementsMatch(t, []uint{uLower.ID, uB.ID}, groupIDs(UserGroupMappingLookup{MatchValue: strp(" team\t")}), "查找值與寫入時一樣去除前後空白")
		for _, v := range []string{"", "  "} {
			_, err := e.src.LookupUserGroupMappings(contractKind, e.provider, UserGroupMappingLookup{MatchValue: strp(v)})
			require.ErrorIs(t, err, ErrMappingLookupParam)
		}
	})

	t.Run("查找與重複判定一致", func(t *testing.T) {
		// 對每個寫法（大小寫、前後空白、部分相符），兩類規則都要成立：
		// 查找找得到，若且唯若以相同內容建立會回衝突。不允許「查不到卻建不進去」或「查得到卻建得進去」。
		for _, variant := range []string{"team", "TEAM", "Team", " team", "team ", "\tteam\n", "tea", "te am"} {
			roleFound := len(roleIDs(RoleMappingLookup{MatchValue: strp(variant), Role: strp(" auditor")})) > 0
			_, err := e.src.CreateMapping(contractKind, e.provider, GroupRoleMappingInput{MatchValue: variant, Role: " auditor", Enabled: boolp(false), RiskAcknowledged: true, Actor: su})
			if roleFound {
				require.ErrorIs(t, err, ErrMappingRuleExists, "角色規則：寫法 %q 查得到，建立應回衝突", variant)
			} else {
				require.NoError(t, err, "角色規則：寫法 %q 查不到，建立應成功", variant)
			}

			groupFound := len(groupIDs(UserGroupMappingLookup{MatchValue: strp(variant), UserGroupID: uintp(gA)})) > 0
			_, err = e.src.CreateUserGroupMapping(contractKind, e.provider, UserGroupMappingInput{MatchValue: variant, UserGroupID: gA, Enabled: boolp(false), RiskAcknowledged: true, SourceConfigAcknowledged: true, Actor: su})
			if groupFound {
				require.ErrorIs(t, err, ErrMappingRuleExists, "使用者群組規則：寫法 %q 查得到，建立應回衝突", variant)
			} else {
				require.NoError(t, err, "使用者群組規則：寫法 %q 查不到，建立應成功", variant)
			}
		}
	})
}

// TestMappingContractDirectorySource 目錄型來源：群組值是辨識名稱，重複判定與查找都以
// 去除前後空白後的字串逐字相等為準（辨識名稱內部的大小寫與空白寫法不同即視為不同規則）。
func TestMappingContractDirectorySource(t *testing.T) {
	e := newMappingGuardEnv(t, true)
	su := e.actor(e.admin, "root")
	dir := model.LDAPDirectory{Name: "dir", URL: "ldaps://dir.example.com", BaseDN: "dc=example,dc=com", AttrGroup: "memberOf", Enabled: true}
	require.NoError(t, e.db.Create(&dir).Error)
	kind := model.RoleMappingChannelKindDirectory
	const dn = "cn=PAM-Admins,ou=groups,dc=example,dc=com"
	gA := e.group(t, "ug-dir")

	role, err := e.src.CreateMapping(kind, dir.ID, GroupRoleMappingInput{MatchValue: dn, Role: "auditor", RiskAcknowledged: true, Actor: su})
	require.NoError(t, err)
	group, err := e.src.CreateUserGroupMapping(kind, dir.ID, UserGroupMappingInput{MatchValue: dn, UserGroupID: gA, RiskAcknowledged: true, SourceConfigAcknowledged: true, Actor: su})
	require.NoError(t, err)

	for _, same := range []string{dn, "  " + dn + " "} {
		_, err := e.src.CreateMapping(kind, dir.ID, GroupRoleMappingInput{MatchValue: same, Role: "auditor", RiskAcknowledged: true, Actor: su})
		require.ErrorIs(t, err, ErrMappingRuleExists, "寫法 %q", same)
		_, err = e.src.CreateUserGroupMapping(kind, dir.ID, UserGroupMappingInput{MatchValue: same, UserGroupID: gA, RiskAcknowledged: true, SourceConfigAcknowledged: true, Actor: su})
		require.ErrorIs(t, err, ErrMappingRuleExists, "寫法 %q", same)

		rows, err := e.src.LookupMappings(kind, dir.ID, RoleMappingLookup{MatchValue: strp(same)})
		require.NoError(t, err)
		require.Len(t, rows, 1)
		assert.Equal(t, role.ID, rows[0].ID)
		grows, err := e.src.LookupUserGroupMappings(kind, dir.ID, UserGroupMappingLookup{MatchValue: strp(same)})
		require.NoError(t, err)
		require.Len(t, grows, 1)
		assert.Equal(t, group.ID, grows[0].ID)
	}

	// 辨識名稱內部寫法不同（屬性型別大小寫）：儲存字串不同，查找查不到、建立也不算重複
	const other = "CN=PAM-Admins,ou=groups,dc=example,dc=com"
	rows, err := e.src.LookupMappings(kind, dir.ID, RoleMappingLookup{MatchValue: strp(other)})
	require.NoError(t, err)
	assert.Empty(t, rows)
	_, err = e.src.CreateMapping(kind, dir.ID, GroupRoleMappingInput{MatchValue: other, Role: "auditor", Enabled: boolp(false), RiskAcknowledged: true, Actor: su})
	require.NoError(t, err)

	// 單筆讀取與提供者型同一套行為；同一個識別用另一種來源型別讀不到
	got, err := e.src.GetMapping(kind, dir.ID, role.ID)
	require.NoError(t, err)
	assert.Equal(t, dn, got.MatchValue)
	_, err = e.src.GetMapping(contractKind, e.provider, role.ID)
	require.ErrorIs(t, err, ErrMappingRuleNotFound)
}

// TestMappingGetOne 依識別讀單條規則：內容與列表中的那一列相同；
// 不存在、已刪除、屬於另一個來源、屬於另一類規則皆為同一個錯誤。
// TestMappingDirectorySourceBusy 目錄型來源的規則寫入與目錄設定共用一把不排隊的互斥：
// 互斥被占用時，兩類規則的建立與修改都回「另一項操作進行中」，不寫入任何資料；
// 放開之後同一個請求照常判定（已存在的組合回規則重複）。
func TestMappingDirectorySourceBusy(t *testing.T) {
	e := newMappingGuardEnv(t, true)
	su := e.actor(e.admin, "root")
	dir := model.LDAPDirectory{Name: "dir", URL: "ldaps://dir.example.com", BaseDN: "dc=example,dc=com", AttrGroup: "memberOf", Enabled: true}
	require.NoError(t, e.db.Create(&dir).Error)
	kind := model.RoleMappingChannelKindDirectory
	const dn = "cn=ops,ou=groups,dc=example,dc=com"
	gA := e.group(t, "ug-busy")
	role, err := e.src.CreateMapping(kind, dir.ID, GroupRoleMappingInput{MatchValue: dn, Role: "auditor", RiskAcknowledged: true, Actor: su})
	require.NoError(t, err)
	group, err := e.src.CreateUserGroupMapping(kind, dir.ID, UserGroupMappingInput{MatchValue: dn, UserGroupID: gA, RiskAcknowledged: true, SourceConfigAcknowledged: true, Actor: su})
	require.NoError(t, err)

	roleIn := GroupRoleMappingInput{MatchValue: dn, Role: "auditor", RiskAcknowledged: true, Actor: su}
	groupIn := UserGroupMappingInput{MatchValue: dn, UserGroupID: gA, RiskAcknowledged: true, SourceConfigAcknowledged: true, Actor: su}
	const moved = "cn=moved,ou=groups,dc=example,dc=com"
	roleMove := GroupRoleMappingInput{MatchValue: moved, Role: "auditor", RiskAcknowledged: true, Actor: su}
	groupMove := UserGroupMappingInput{MatchValue: moved, UserGroupID: gA, RiskAcknowledged: true, SourceConfigAcknowledged: true, Actor: su}

	count := func() (n int64) {
		var a, b int64
		require.NoError(t, e.db.Model(&model.GroupRoleMapping{}).Count(&a).Error)
		require.NoError(t, e.db.Model(&model.GroupUserGroupMapping{}).Count(&b).Error)
		return a + b
	}
	before := count()

	ldapDirectoryProcessMu.Lock()
	_, errCreateRole := e.src.CreateMapping(kind, dir.ID, roleIn)
	_, errCreateGroup := e.src.CreateUserGroupMapping(kind, dir.ID, groupIn)
	_, errUpdateRole := e.src.UpdateMapping(kind, dir.ID, role.ID, roleMove)
	_, errUpdateGroup := e.src.UpdateUserGroupMapping(kind, dir.ID, group.ID, groupMove)
	ldapDirectoryProcessMu.Unlock()

	for name, err := range map[string]error{"建立角色規則": errCreateRole, "建立群組規則": errCreateGroup, "修改角色規則": errUpdateRole, "修改群組規則": errUpdateGroup} {
		require.ErrorIs(t, err, ErrLDAPDirectoryBusy, name)
	}
	assert.Equal(t, before, count(), "互斥中的寫入不落地")
	got, err := e.src.GetMapping(kind, dir.ID, role.ID)
	require.NoError(t, err)
	assert.Equal(t, dn, got.MatchValue, "互斥中的修改不改動原規則")

	_, err = e.src.CreateMapping(kind, dir.ID, roleIn)
	require.ErrorIs(t, err, ErrMappingRuleExists)
	_, err = e.src.CreateUserGroupMapping(kind, dir.ID, groupIn)
	require.ErrorIs(t, err, ErrMappingRuleExists)
}

// TestMappingGetOneQueryFailure 單筆讀取在查詢本身失敗時不得回「規則不存在」：
// 宣告式工具把不存在當成資源已被移除，暫時的讀取失敗不能落到同一個結果。
func TestMappingGetOneQueryFailure(t *testing.T) {
	e := newMappingGuardEnv(t, true)
	su := e.actor(e.admin, "root")
	gA := e.group(t, "ug-qf")
	role := e.roleRule(t, su, "grp-qf", "auditor")
	group := e.groupRule(t, su, "grp-qf", gA)

	require.NoError(t, e.db.Migrator().DropTable(&model.GroupUserGroupMapping{}))
	_, err := e.src.GetUserGroupMapping(contractKind, e.provider, group.ID)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrMappingRuleNotFound)

	require.NoError(t, e.db.Migrator().DropTable(&model.GroupRoleMapping{}))
	_, err = e.src.GetMapping(contractKind, e.provider, role.ID)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrMappingRuleNotFound)
}

func TestMappingGetOne(t *testing.T) {
	e := newMappingGuardEnv(t, true)
	su := e.actor(e.admin, "root")
	p2 := e.secondProvider(t)
	gA := e.group(t, "ug-a")

	role := e.roleRule(t, su, "grp-a", "auditor")
	group := e.groupRule(t, su, "grp-a", gA)
	// 讓兩類規則的識別錯開，才驗得出「識別互不相通」
	var onlyRoleID uint
	for i := 0; i < 3; i++ {
		onlyRoleID = e.roleRule(t, su, "pad-"+itoa(uint(i)), "auditor").ID
	}
	foreign, err := e.src.CreateMapping(contractKind, p2, GroupRoleMappingInput{MatchValue: "grp-x", Role: "auditor", RiskAcknowledged: true, Actor: su})
	require.NoError(t, err)
	foreignGroup, err := e.src.CreateUserGroupMapping(contractKind, p2, UserGroupMappingInput{MatchValue: "grp-x", UserGroupID: gA, RiskAcknowledged: true, SourceConfigAcknowledged: true, Actor: su})
	require.NoError(t, err)

	t.Run("角色規則與列表中的那一列相同", func(t *testing.T) {
		got, err := e.src.GetMapping(contractKind, e.provider, role.ID)
		require.NoError(t, err)
		list, err := e.src.ListMappings(contractKind, e.provider)
		require.NoError(t, err)
		var want *GroupRoleMappingView
		for i := range list {
			if list[i].ID == role.ID {
				want = &list[i]
			}
		}
		require.NotNil(t, want)
		assert.JSONEq(t, asJSON(t, want), asJSON(t, got))
	})

	t.Run("使用者群組規則與列表中的那一列相同", func(t *testing.T) {
		got, err := e.src.GetUserGroupMapping(contractKind, e.provider, group.ID)
		require.NoError(t, err)
		list, err := e.src.ListUserGroupMappings(contractKind, e.provider)
		require.NoError(t, err)
		var want *UserGroupMappingView
		for i := range list {
			if list[i].ID == group.ID {
				want = &list[i]
			}
		}
		require.NotNil(t, want)
		assert.JSONEq(t, asJSON(t, want), asJSON(t, got))
	})

	t.Run("不存在、他來源、他類規則、已刪除皆為規則不存在", func(t *testing.T) {
		_, err := e.src.GetMapping(contractKind, e.provider, 987654)
		require.ErrorIs(t, err, ErrMappingRuleNotFound)
		_, err = e.src.GetMapping(contractKind, e.provider, foreign.ID)
		require.ErrorIs(t, err, ErrMappingRuleNotFound, "另一個來源的規則")
		_, err = e.src.GetUserGroupMapping(contractKind, e.provider, foreignGroup.ID)
		require.ErrorIs(t, err, ErrMappingRuleNotFound, "另一個來源的規則")
		_, err = e.src.GetUserGroupMapping(contractKind, e.provider, onlyRoleID)
		require.ErrorIs(t, err, ErrMappingRuleNotFound, "只存在於角色規則的識別")

		require.NoError(t, e.src.DeleteMapping(contractKind, e.provider, role.ID, su))
		_, err = e.src.GetMapping(contractKind, e.provider, role.ID)
		require.ErrorIs(t, err, ErrMappingRuleNotFound, "已刪除")
		require.NoError(t, e.src.DeleteUserGroupMapping(contractKind, e.provider, group.ID, su))
		_, err = e.src.GetUserGroupMapping(contractKind, e.provider, group.ID)
		require.ErrorIs(t, err, ErrMappingRuleNotFound, "已刪除")
	})

	t.Run("來源不存在與列表同一個錯誤", func(t *testing.T) {
		_, listErr := e.src.ListMappings(contractKind, 987654)
		_, getErr := e.src.GetMapping(contractKind, 987654, 1)
		require.Error(t, listErr)
		assert.ErrorIs(t, getErr, listErr)
		_, listErr = e.src.ListUserGroupMappings(contractKind, 987654)
		_, getErr = e.src.GetUserGroupMapping(contractKind, 987654, 1)
		require.Error(t, listErr)
		assert.ErrorIs(t, getErr, listErr)
	})
}
