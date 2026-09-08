package identity

import (
	"context"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"gorm.io/gorm"
)

// 身分提供者途徑的登入重算：宣告名未設定的兩格、三態判定、命中升權與降權、
// 通道分域、混合帳號不吃映射、群組觀測快照，以及宣告對應三欄的讀取。
//
// 全部走真 sqlite ＋ fake IdP 的完整授權碼流程——重算掛在 callback 的固定順序上，
// 以替身跳過任何一段都會讓「接在哪裡」這件事失去斷言。

// oidcMappingGroup 受映射群組值（與開發靶機同值，便於對照）
const oidcMappingGroup = "pam-auditors"

// seedMappingRole 補一個角色（基本角色由 setupOIDCEnv 建，映射目標另建）
func seedMappingRole(t *testing.T, db *gorm.DB, name string) uint {
	t.Helper()
	var role model.Role
	if err := db.Where("name = ?", name).First(&role).Error; err == nil {
		return role.ID
	}
	role = model.Role{Name: name}
	if err := db.Create(&role).Error; err != nil {
		t.Fatalf("建角色 %s: %v", name, err)
	}
	return role.ID
}

// seedProviderMappingRule 建一條啟用中的提供者映射規則
func seedProviderMappingRule(t *testing.T, db *gorm.DB, providerID uint, matchValue, roleName string) {
	t.Helper()
	pid := providerID
	rule := &model.GroupRoleMapping{
		OIDCProviderID: &pid,
		MatchValue:     matchValue,
		RoleID:         seedMappingRole(t, db, roleName),
		Enabled:        true,
		CreatedBy:      1,
	}
	if err := db.Create(rule).Error; err != nil {
		t.Fatalf("建映射規則: %v", err)
	}
}

// oidcLoginOnce 走一次完整流程（begin → callback），回傳 callback 結果。
// extra 為要塞進身分權杖的額外宣告
func oidcLoginOnce(t *testing.T, login *OIDCLoginService, idp *fakeIdP, p *model.OIDCProvider,
	code, subject string, extra map[string]any) (*CallbackResult, error) {
	t.Helper()
	state, nonce := beginFlow(t, login, p, "browser-secret", idp)
	idp.stageCode(code, idp.issueIDToken(t, idTokenOpts{
		subject: subject, audience: p.ClientID, nonce: nonce, extra: extra,
	}))
	return login.Callback(context.Background(), state, code)
}

// mappingClaims 一組能通過准入並供應帳號的基本宣告，另可疊加群組宣告
func mappingClaims(extra map[string]any) map[string]any {
	base := map[string]any{
		"hd": "corp.example", "preferred_username": "bob",
		"email": "bob@corp.example", "email_verified": true,
	}
	for k, v := range extra {
		base[k] = v
	}
	return base
}

// userRolesOf 帳號現行的有效角色名（依角色名排序）
func userRolesOf(t *testing.T, db *gorm.DB, userID uint) []string {
	t.Helper()
	var names []string
	if err := db.Table("user_roles").
		Joins("JOIN roles ON roles.id = user_roles.role_id").
		Where("user_roles.user_id = ?", userID).
		Order("roles.name").
		Pluck("roles.name", &names).Error; err != nil {
		t.Fatalf("讀有效角色: %v", err)
	}
	return names
}

func containsRole(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

// oidcUserByName 依帳號名取回使用者（含世代與快照欄）
func oidcUserByName(t *testing.T, db *gorm.DB, username string) model.User {
	t.Helper()
	var u model.User
	if err := db.Where("username = ?", username).First(&u).Error; err != nil {
		t.Fatalf("查帳號 %s: %v", username, err)
	}
	return u
}

// mappingAuditRows 取指定機器碼的映射審計列
func mappingAuditRows(t *testing.T, db *gorm.DB, code string) []model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	if err := db.Where("error_msg = ?", code).Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("讀審計列: %v", err)
	}
	return rows
}

// ── 4.1 群組宣告名未設定的兩格 ─────────────────────────────────────────

// TestOIDCProviderGroupsClaimUnsetClosesMapping 未設群組宣告名＝映射關閉。
//
// 權杖裡帶著群組、規則表裡沒有規則，登入完成後不得產生任何映射事實列或角色變動。
// 這一格是「未啟用映射的部署零影響」在提供者側的形態。
func TestOIDCProviderGroupsClaimUnsetClosesMapping(t *testing.T) {
	login, _, idp, p := setupLiveFlow(t)
	db := login.db
	// provider 的 GroupsClaim 為空（seedProvider 預設），且該來源無任何規則

	res, err := oidcLoginOnce(t, login, idp, p, "code-1", "sub-1",
		mappingClaims(map[string]any{"groups": []any{oidcMappingGroup}}))
	if err != nil {
		t.Fatalf("登入不應失敗: %v", err)
	}
	if res.Ticket == "" {
		t.Fatal("應簽出交棒憑證")
	}

	user := oidcUserByName(t, db, "bob")
	if roles := userRolesOf(t, db, user.ID); len(roles) != 1 || roles[0] != model.RoleUser {
		t.Errorf("角色集應只有供應時的基本角色，實得 %v", roles)
	}
	var facts int64
	if err := db.Model(&model.UserRoleMapping{}).Count(&facts).Error; err != nil {
		t.Fatalf("數映射事實列: %v", err)
	}
	if facts != 0 {
		t.Errorf("映射事實列 = %d, want 0（未設宣告名不得產生認定）", facts)
	}
	// 完全短路：連跳過事件都不該有（沒有規則就沒有要揭露的狀態）
	for _, code := range []string{RoleMappingEventApplied, RoleMappingSkipSourceAttrUnset,
		RoleMappingSkipGroupsUnknown} {
		if rows := mappingAuditRows(t, db, code); len(rows) != 0 {
			t.Errorf("%s 審計列 = %d, want 0", code, len(rows))
		}
	}
	if user.GroupSnapshotAt != nil {
		t.Error("未設宣告名不得寫群組觀測快照")
	}
}

// TestOIDCGroupsClaimUnsetWithRuleWritesSkipEvent 未設宣告名但有啟用規則＝留痕跳過。
//
// 沒有這一筆，「規則設好了但宣告名沒設」的部署會永遠零命中而沒有任何訊號——
// 管理者看到規則列在頁上、狀態是啟用，卻沒有一個人拿到角色。
func TestOIDCGroupsClaimUnsetWithRuleWritesSkipEvent(t *testing.T) {
	login, _, idp, p := setupLiveFlow(t)
	db := login.db
	seedProviderMappingRule(t, db, p.ID, oidcMappingGroup, model.RoleAuditor)

	if _, err := oidcLoginOnce(t, login, idp, p, "code-1", "sub-1",
		mappingClaims(map[string]any{"groups": []any{oidcMappingGroup}})); err != nil {
		t.Fatalf("登入不應失敗: %v", err)
	}

	rows := mappingAuditRows(t, db, RoleMappingSkipSourceAttrUnset)
	if len(rows) != 1 {
		t.Fatalf("跳過事件 = %d 筆, want 1", len(rows))
	}
	user := oidcUserByName(t, db, "bob")
	if containsRole(userRolesOf(t, db, user.ID), model.RoleAuditor) {
		t.Error("宣告名未設定時不得賦予映射角色")
	}
	if user.GroupSnapshotAt != nil {
		t.Error("未設宣告名不得寫群組觀測快照")
	}
}

// ── 4.2 三態判定 ───────────────────────────────────────────────────────

// TestGroupsClaimTriState 六種輸入的表驅動判定。
//
// 三態各自的失敗方向不同，混為一談就會選錯邊：空集合要撤權、未知要保留。
// 溢出指示與型別不符都歸未知——前者是「群組不在這張權杖裡」，
// 後者是「這不是一份群組清單」，兩者都不足以據以撤權。
func TestGroupsClaimTriState(t *testing.T) {
	cases := []struct {
		name       string
		raw        map[string]any
		wantState  GroupObservationState
		wantGroups []string
	}{
		{
			name:       "字串陣列",
			raw:        map[string]any{"groups": []any{"a", "b"}},
			wantState:  GroupObservationKnown,
			wantGroups: []string{"a", "b"},
		},
		{
			name:       "空陣列",
			raw:        map[string]any{"groups": []any{}},
			wantState:  GroupObservationKnown,
			wantGroups: []string{},
		},
		{
			name:       "鍵缺席",
			raw:        map[string]any{"sub": "x"},
			wantState:  GroupObservationKnown,
			wantGroups: nil,
		},
		{
			name: "溢出指示",
			raw: map[string]any{
				"_claim_names":   map[string]any{"groups": "src1"},
				"_claim_sources": map[string]any{"src1": map[string]any{"endpoint": "https://example.test/groups"}},
			},
			wantState: GroupObservationUnknown,
		},
		{
			name:      "字串",
			raw:       map[string]any{"groups": "a"},
			wantState: GroupObservationUnknown,
		},
		{
			name:      "數字",
			raw:       map[string]any{"groups": float64(7)},
			wantState: GroupObservationUnknown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state, groups := groupsClaimTriState(tc.raw, "groups")
			if state != tc.wantState {
				t.Fatalf("state = %q, want %q", state, tc.wantState)
			}
			if len(groups) != len(tc.wantGroups) {
				t.Fatalf("groups = %v, want %v", groups, tc.wantGroups)
			}
			for i := range groups {
				if groups[i] != tc.wantGroups[i] {
					t.Fatalf("groups = %v, want %v", groups, tc.wantGroups)
				}
			}
		})
	}
}

// TestGroupsClaimTriStateOverflowWinsOverPresentClaim 溢出指示優先於宣告本身。
//
// 部分清單加溢出指示時，那份清單不是完整事實；據以重算會撤掉沒被列進去的
// 那些群組所給的角色。
func TestGroupsClaimTriStateOverflowWinsOverPresentClaim(t *testing.T) {
	state, groups := groupsClaimTriState(map[string]any{
		"groups": []any{"a"}, "hasgroups": true,
	}, "groups")
	if state != GroupObservationUnknown {
		t.Errorf("state = %q, want unknown", state)
	}
	if groups != nil {
		t.Errorf("未知態不得交出群組值，實得 %v", groups)
	}
}

// ── 4.3 登入接點 ───────────────────────────────────────────────────────

// mappingProvider 一個設好群組宣告名與一條規則的 provider
func mappingProvider(t *testing.T, login *OIDCLoginService, p *model.OIDCProvider,
	roleName string) {
	t.Helper()
	if err := login.db.Model(p).Update("groups_claim", "groups").Error; err != nil {
		t.Fatalf("設群組宣告名: %v", err)
	}
	p.GroupsClaim = "groups"
	seedProviderMappingRule(t, login.db, p.ID, oidcMappingGroup, roleName)
}

// TestOIDCLoginRecomputesMappedRoles 命中即取得角色、移出群組後再登入即失去。
func TestOIDCLoginRecomputesMappedRoles(t *testing.T) {
	login, _, idp, p := setupLiveFlow(t)
	db := login.db
	mappingProvider(t, login, p, model.RoleAuditor)

	if _, err := oidcLoginOnce(t, login, idp, p, "code-1", "sub-1",
		mappingClaims(map[string]any{"groups": []any{oidcMappingGroup}})); err != nil {
		t.Fatalf("首次登入: %v", err)
	}
	user := oidcUserByName(t, db, "bob")
	if !containsRole(userRolesOf(t, db, user.ID), model.RoleAuditor) {
		t.Fatalf("命中規則應取得映射角色，實得 %v", userRolesOf(t, db, user.ID))
	}
	if rows := mappingAuditRows(t, db, RoleMappingEventApplied); len(rows) != 1 {
		t.Errorf("套用事件 = %d 筆, want 1", len(rows))
	}

	// 於來源端被移出群組後再次登入
	if _, err := oidcLoginOnce(t, login, idp, p, "code-2", "sub-1",
		mappingClaims(map[string]any{"groups": []any{"other-group"}})); err != nil {
		t.Fatalf("再次登入: %v", err)
	}
	if containsRole(userRolesOf(t, db, user.ID), model.RoleAuditor) {
		t.Errorf("移出群組後應失去映射角色，實得 %v", userRolesOf(t, db, user.ID))
	}
	after := oidcUserByName(t, db, "bob")
	if after.CredentialEpoch <= user.CredentialEpoch {
		t.Errorf("有列被移除應推進憑證世代：%d → %d", user.CredentialEpoch, after.CredentialEpoch)
	}
}

// TestOIDCInactiveUserSkipsRecompute 停用帳號不重算。
//
// 接點早於交棒憑證的啟用複查，不跳過的話，一個進不來的人的權限仍會隨群組漂移，
// 而管理者看到的是一筆沒有登入的角色變動。
func TestOIDCInactiveUserSkipsRecompute(t *testing.T) {
	login, _, idp, p := setupLiveFlow(t)
	db := login.db
	mappingProvider(t, login, p, model.RoleAuditor)

	// 先供應帳號，再停用
	if _, err := oidcLoginOnce(t, login, idp, p, "code-1", "sub-1",
		mappingClaims(map[string]any{"groups": []any{"none"}})); err != nil {
		t.Fatalf("首次登入: %v", err)
	}
	user := oidcUserByName(t, db, "bob")
	if err := db.Model(&model.User{}).Where("id = ?", user.ID).
		Update("active", false).Error; err != nil {
		t.Fatalf("停用帳號: %v", err)
	}

	// 停用後的登入嘗試終究會被拒，但不得改寫角色列
	_, _ = oidcLoginOnce(t, login, idp, p, "code-2", "sub-1",
		mappingClaims(map[string]any{"groups": []any{oidcMappingGroup}}))

	if containsRole(userRolesOf(t, db, user.ID), model.RoleAuditor) {
		t.Errorf("停用帳號不得因映射取得角色，實得 %v", userRolesOf(t, db, user.ID))
	}
	var facts int64
	if err := db.Model(&model.UserRoleMapping{}).Count(&facts).Error; err != nil {
		t.Fatalf("數映射事實列: %v", err)
	}
	if facts != 0 {
		t.Errorf("映射事實列 = %d, want 0", facts)
	}
}

// TestOIDCTicketCarriesBumpedEpoch 交棒憑證帶推進後的世代。
//
// 重算若晚於簽票，被降權的那次登入會拿到帶舊世代的票，兌換時比對不過——
// 每一次降權都把當事人鎖死在門外。斷言直接落在票上，不靠順序的間接證據。
func TestOIDCTicketCarriesBumpedEpoch(t *testing.T) {
	login, _, idp, p := setupLiveFlow(t)
	db := login.db
	mappingProvider(t, login, p, model.RoleAuditor)

	if _, err := oidcLoginOnce(t, login, idp, p, "code-1", "sub-1",
		mappingClaims(map[string]any{"groups": []any{oidcMappingGroup}})); err != nil {
		t.Fatalf("首次登入: %v", err)
	}
	before := oidcUserByName(t, db, "bob")

	res, err := oidcLoginOnce(t, login, idp, p, "code-2", "sub-1",
		mappingClaims(map[string]any{"groups": []any{}}))
	if err != nil {
		t.Fatalf("降權登入: %v", err)
	}
	after := oidcUserByName(t, db, "bob")
	if after.CredentialEpoch == before.CredentialEpoch {
		t.Fatalf("本格前提不成立：世代未推進（%d）", after.CredentialEpoch)
	}

	var ticket model.OIDCLoginTicket
	if err := db.Where("token_hash = ?", sha256Hex(res.Ticket)).First(&ticket).Error; err != nil {
		t.Fatalf("查交棒憑證: %v", err)
	}
	if ticket.CredEpoch != after.CredentialEpoch {
		t.Errorf("憑證世代 = %d, want %d（推進後）", ticket.CredEpoch, after.CredentialEpoch)
	}
	// 兌換必須成立：世代比對不過的話，降權即等於自我鎖死
	if _, _, err := login.Exchange(res.Ticket, "browser-secret"); err != nil {
		t.Errorf("降權後的交棒憑證應可兌換: %v", err)
	}
}

// ── 4.4 通道分域 ───────────────────────────────────────────────────────

// TestChannelScopedRecomputeDoesNotClearOtherChannel 重算只動本次途徑的認定。
//
// 先經提供者取得角色，再經目錄登入且目錄側不命中：提供者那一列不得被清除、
// 世代不得推進。不含通道的話，同一人交替經兩條途徑登入會互相清除對方的認定，
// 每次都被判為角色縮減而把對方踢下線。
func TestChannelScopedRecomputeDoesNotClearOtherChannel(t *testing.T) {
	// 兩條途徑要在同一個帳號上交會，故用目錄側那一組環境（它有真的登入路徑），
	// 提供者那一段以重算服務直接餵入——本格要驗的是**第二次登入會不會清掉
	// 第一次的認定**，故非真不可的是後者
	authService, _, db := setupRoleMappingEnv(t)
	user := roleMappingUser(t, db, "testldap")

	const providerID = 7
	seedProviderMappingRule(t, db, providerID, oidcMappingGroup, model.RoleAuditor)
	if _, err := RecomputeMappedRoles(db, audit.NewTxSink(), user, GroupObservation{
		Kind: model.RoleMappingChannelKindProvider, SourceID: providerID,
		State: GroupObservationKnown, Groups: []string{oidcMappingGroup},
	}); err != nil {
		t.Fatalf("提供者途徑重算: %v", err)
	}
	if !containsRole(effectiveRoles(t, db, user.ID), model.RoleAuditor) {
		t.Fatal("提供者途徑應先取得角色")
	}
	epochBefore := credentialEpochOf(t, db, user.ID)
	providerChannel := model.RoleMappingChannel(model.RoleMappingChannelKindProvider, providerID)

	// 同一人改經目錄途徑登入：目錄已設群組屬性名、群組讀得到，但該目錄一條
	// 映射規則也沒有 ⇒ 目錄通道應認定為空，且**不得動到提供者通道那一列**
	authService.SetLDAPResolver(mappingResolver(1, "memberOf",
		ldapInfoWithGroups("testldap", roleMappingInnerGroup)))
	if _, err := authService.Login(&LoginRequest{Username: "testldap", Password: "pass"}); err != nil {
		t.Fatalf("目錄途徑登入不應失敗: %v", err)
	}

	// 前提：目錄那次登入真的走到了重算（否則以下三條斷言恆綠）。
	// 快照只在已知態寫入，故它同時證明「重算跑過」與「跑的是目錄通道」
	var after model.User
	if err := db.First(&after, user.ID).Error; err != nil {
		t.Fatalf("重讀帳號: %v", err)
	}
	wantDirChannel := model.RoleMappingChannel(model.RoleMappingChannelKindDirectory, 1)
	if after.GroupSnapshotChannel != wantDirChannel {
		t.Fatalf("本格前提不成立：目錄登入未走到重算（快照途徑 = %q, want %q）",
			after.GroupSnapshotChannel, wantDirChannel)
	}

	var kept int64
	if err := db.Model(&model.UserRoleMapping{}).
		Where("user_id = ? AND channel = ?", user.ID, providerChannel).
		Count(&kept).Error; err != nil {
		t.Fatalf("數提供者通道的映射列: %v", err)
	}
	if kept != 1 {
		t.Errorf("提供者通道的映射列 = %d, want 1（另一條途徑的重算不得清除它）", kept)
	}
	if !containsRole(effectiveRoles(t, db, user.ID), model.RoleAuditor) {
		t.Errorf("提供者途徑賦予的角色應保留，實得 %v", effectiveRoles(t, db, user.ID))
	}
	if now := credentialEpochOf(t, db, user.ID); now != epochBefore {
		t.Errorf("世代 = %d, want %d（沒有列被移除即不推進）", now, epochBefore)
	}
}

// ── 4.5 帳號射程 ───────────────────────────────────────────────────────

// TestMixedAccountNotInMappingScope 同時具本地密碼與外部身分者不吃映射。
//
// 本地密碼路徑不經外部來源，經外部途徑拿到角色之後改用本地密碼登入即永久保留
// ——那條線必須自己劃，不能沿用「這個帳號是不是外部的」那個較寬的述詞。
func TestMixedAccountNotInMappingScope(t *testing.T) {
	login, _, _, p := setupLiveFlow(t)
	db := login.db
	seedProviderMappingRule(t, db, p.ID, oidcMappingGroup, model.RoleAuditor)

	// 混合帳號：由外部供應（provisioning_origin=oidc）但仍有本地密碼，
	// 即 ExternalCredential 與 IsLDAP 皆為 false
	mixed := &model.User{
		Username: "mixed", Password: "local-hash", Active: true,
		ProvisioningOrigin: model.AuthSourceOIDC,
	}
	if err := db.Create(mixed).Error; err != nil {
		t.Fatalf("建混合帳號: %v", err)
	}
	if !mixed.IsExternal() {
		t.Fatal("本格前提：該帳號在既有的外部帳號述詞下為真，映射射程必須比它窄")
	}

	outcome, err := RecomputeMappedRoles(db, login.mappingAudit, mixed, GroupObservation{
		Kind: model.RoleMappingChannelKindProvider, SourceID: p.ID,
		State: GroupObservationKnown, Groups: []string{oidcMappingGroup},
	})
	if err != nil {
		t.Fatalf("重算: %v", err)
	}
	if outcome.Changed() {
		t.Errorf("混合帳號不得吃映射：added=%v removed=%v", outcome.Added, outcome.Removed)
	}
	if containsRole(userRolesOf(t, db, mixed.ID), model.RoleAuditor) {
		t.Error("混合帳號不得取得映射角色")
	}
	var facts int64
	if err := db.Model(&model.UserRoleMapping{}).Count(&facts).Error; err != nil {
		t.Fatalf("數映射事實列: %v", err)
	}
	if facts != 0 {
		t.Errorf("映射事實列 = %d, want 0", facts)
	}
}

// ── 4.6 群組觀測快照 ───────────────────────────────────────────────────

// TestGroupObservationSnapshotStored 已知態存下本次觀測到的群組原始值與時間。
//
// 快照的用途只有一個：回答「我明明在群組裡卻沒拿到角色」。故存的是**原始值**，
// 不做正規化——正規化過的值與管理者在來源端看到的字串對不起來，也就答不了那個問題。
func TestGroupObservationSnapshotStored(t *testing.T) {
	login, _, idp, p := setupLiveFlow(t)
	db := login.db
	mappingProvider(t, login, p, model.RoleAuditor)

	// 命中規則之外另帶一個不命中的群組：快照存的是觀測到的全部，不只命中的
	if _, err := oidcLoginOnce(t, login, idp, p, "code-1", "sub-1",
		mappingClaims(map[string]any{"groups": []any{oidcMappingGroup, "Sales Team"}})); err != nil {
		t.Fatalf("登入: %v", err)
	}

	user := oidcUserByName(t, db, "bob")
	if user.GroupSnapshotAt == nil {
		t.Fatal("應寫入群組觀測時間")
	}
	wantChannel := model.RoleMappingChannel(model.RoleMappingChannelKindProvider, p.ID)
	if user.GroupSnapshotChannel != wantChannel {
		t.Errorf("快照途徑 = %q, want %q", user.GroupSnapshotChannel, wantChannel)
	}
	if got, want := user.GroupSnapshotGroups, `["`+oidcMappingGroup+`","Sales Team"]`; got != want {
		t.Errorf("快照群組值 = %q, want %q", got, want)
	}

	// 空集合要留下「讀到了，他不屬於任何群組」的證據，而不是看起來像沒觀測
	if _, err := oidcLoginOnce(t, login, idp, p, "code-2", "sub-1",
		mappingClaims(map[string]any{"groups": []any{}})); err != nil {
		t.Fatalf("再次登入: %v", err)
	}
	if got := oidcUserByName(t, db, "bob").GroupSnapshotGroups; got != "[]" {
		t.Errorf("空集合的快照 = %q, want []", got)
	}
}

// ── 4.8 宣告對應三欄 ───────────────────────────────────────────────────

// verifyClaimsWith 以指定 provider 設定解析一張身分權杖
func verifyClaimsWith(t *testing.T, login *OIDCLoginService, idp *fakeIdP,
	p *model.OIDCProvider, raw map[string]any) *VerifiedClaims {
	t.Helper()
	token := idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: p.ClientID, nonce: "n-1", extra: raw,
	})
	vc, err := login.discovery.VerifyIDToken(context.Background(), p, token, "n-1")
	if err != nil {
		t.Fatalf("驗證身分權杖: %v", err)
	}
	return vc
}

// TestClaimMappingUnsetMatchesCurrentParsing 三欄皆空時逐一沿用現行預設。
//
// 加設定不是改預設：未設定的部署解析結果必須與這三欄存在之前完全相同。
func TestClaimMappingUnsetMatchesCurrentParsing(t *testing.T) {
	login, _, idp, p := setupLiveFlow(t)
	if p.UsernameClaim != "" || p.EmailClaim != "" || p.DisplayNameClaim != "" {
		t.Fatal("本格前提：三欄皆未設定")
	}
	vc := verifyClaimsWith(t, login, idp, p, map[string]any{
		"preferred_username": "bob", "email": "bob@corp.example",
		"email_verified": true, "name": "Bob Chen",
	})
	if vc.PreferredUsername != "bob" {
		t.Errorf("帳號名 = %q, want bob", vc.PreferredUsername)
	}
	if vc.Email != "bob@corp.example" {
		t.Errorf("電郵 = %q", vc.Email)
	}
	if !vc.EmailVerified {
		t.Error("email_verified 應為真")
	}
	if vc.Name != "Bob Chen" {
		t.Errorf("顯示名 = %q, want Bob Chen", vc.Name)
	}
	// 設定值不影響身分對應鍵
	if vc.Subject != "sub-1" {
		t.Errorf("subject = %q, want sub-1", vc.Subject)
	}
}

// TestClaimMappingReadsConfiguredClaim 設定後改讀指定的宣告。
//
// **不回頭讀預設鍵**：管理者明確指定的宣告在缺值時被另一個宣告悄悄頂替，
// 那個值可能來自完全不同的語義。
func TestClaimMappingReadsConfiguredClaim(t *testing.T) {
	login, _, idp, p := setupLiveFlow(t)
	p.UsernameClaim = "upn"
	p.EmailClaim = "mail"
	p.DisplayNameClaim = "displayName"

	vc := verifyClaimsWith(t, login, idp, p, map[string]any{
		"upn": "bob@corp.example", "mail": "bob.chen@corp.example",
		"displayName": "Bob C", "email_verified": true,
		// 預設鍵同時存在且值不同：讀到它們即代表設定沒有生效
		"preferred_username": "wrong", "email": "wrong@corp.example", "name": "Wrong Name",
	})
	if vc.PreferredUsername != "bob@corp.example" {
		t.Errorf("帳號名 = %q, want bob@corp.example", vc.PreferredUsername)
	}
	if vc.Email != "bob.chen@corp.example" {
		t.Errorf("電郵 = %q, want bob.chen@corp.example", vc.Email)
	}
	if vc.Name != "Bob C" {
		t.Errorf("顯示名 = %q, want Bob C", vc.Name)
	}

	// 設定的鍵在權杖裡缺席時交出空值，不回頭讀預設鍵
	vc2 := verifyClaimsWith(t, login, idp, p, map[string]any{
		"preferred_username": "fallback-must-not-happen",
	})
	if vc2.PreferredUsername != "" {
		t.Errorf("設定的宣告缺席時應為空，實得 %q", vc2.PreferredUsername)
	}
}

// TestClaimMappingChangeKeepsIdentityLink 改宣告對應不使既有使用者被認成新帳號。
//
// 身分對應鍵是 issuer 與 subject；改一個顯示欄位就換帳號的話，
// 管理者調整宣告對應的代價會是全體使用者失聯。
func TestClaimMappingChangeKeepsIdentityLink(t *testing.T) {
	login, providers, idp, p := setupLiveFlow(t)
	db := login.db

	if _, err := oidcLoginOnce(t, login, idp, p, "code-1", "sub-1",
		mappingClaims(nil)); err != nil {
		t.Fatalf("首次登入: %v", err)
	}
	first := oidcUserByName(t, db, "bob")

	// 管理者改宣告對應：帳號名改自 upn 取
	upn := "bob.chen@corp.example"
	if _, err := providers.Update(p.ID, &OIDCProviderRequest{
		Name: p.Name, UsernameClaim: &[]string{"upn"}[0],
	}); err != nil {
		t.Fatalf("改宣告對應: %v", err)
	}
	var updated model.OIDCProvider
	if err := db.First(&updated, p.ID).Error; err != nil {
		t.Fatalf("重讀 provider: %v", err)
	}
	if updated.UsernameClaim != "upn" {
		t.Fatalf("宣告對應應已寫入，實得 %q", updated.UsernameClaim)
	}

	// 同一個 subject 再次登入：帳號名的來源變了，但身分仍對到同一個帳號
	if _, err := oidcLoginOnce(t, login, idp, &updated, "code-2", "sub-1",
		mappingClaims(map[string]any{"upn": upn})); err != nil {
		t.Fatalf("改設定後登入: %v", err)
	}
	var users int64
	if err := db.Model(&model.User{}).Count(&users).Error; err != nil {
		t.Fatalf("數帳號: %v", err)
	}
	if users != 1 {
		t.Errorf("帳號數 = %d, want 1（改宣告對應不得建出新帳號）", users)
	}
	if again := oidcUserByName(t, db, "bob"); again.ID != first.ID {
		t.Errorf("帳號識別 = %d, want %d", again.ID, first.ID)
	}
	var identities int64
	if err := db.Model(&model.UserExternalIdentity{}).Count(&identities).Error; err != nil {
		t.Fatalf("數外部身分: %v", err)
	}
	if identities != 1 {
		t.Errorf("外部身分列 = %d, want 1", identities)
	}
}
