package authz

import "sort"

// 角色編輯的第一層功能描述與白話摘要資料。
//
// 只描述後端契約：入口穩定識別、群組、各態精確權限集合與第二層細項。畫面由角色編輯頁消費。
// 節點指派、角色預覽、權限一覽尚未上線，不出現在任何描述中。固定入口（登入即可、
// 依本人資格呈現者，如我的連線、我的申請、我的 agent）不是可勾選項，只列在 FixedEntries。

// 入口狀態名稱。
const (
	StateHidden    = "hidden"
	StateRead      = "read"
	StateManage    = "manage"
	StateAvailable = "available"
)

// EntryState 入口的一個狀態與它的精確權限集合（含該態的依賴鍵）。
type EntryState struct {
	Name string
	Keys []Permission
}

// EntryDetail 第二層細項（只有資產、資產帳號、憑證庫、節點提供）。
type EntryDetail struct {
	ID  string
	Key Permission
}

// 入口出現的位置。零值讀作頁面，取值一律經 PlacementKind。
const (
	PlacementPage     = "page"     // 有自己的頁面
	PlacementEmbedded = "embedded" // 另一入口頁面內的設定卡
	PlacementHelper   = "helper"   // 嵌在其他入口表單內的輔助能力
	PlacementBanner   = "banner"   // 只出現在全域橫幅
)

// EntryDescriptor 一個側欄入口。States[0] 恆為 hidden（空集合）。
//
// Placement、PlacementEntries、ReadVia 只是描述，不改變任何態的權限集合、依賴或授權判定。
type EntryDescriptor struct {
	ID      string
	Group   PermGroup
	States  []EntryState
	Details []EntryDetail
	// Placement 入口出現的位置；零值讀作頁面。
	Placement string
	// PlacementEntries embedded 為所在頁面的入口（恰一個）；helper 為使用它的入口（至少一個）；其餘為空。
	PlacementEntries []string
	// ReadVia 隨附檢視的來源入口：持有來源入口即看得到本入口的頁面內容。沒有為空字串。
	ReadVia string
}

// PlacementKind 入口位置的明確值（零值讀作頁面）。
func (e EntryDescriptor) PlacementKind() string {
	if e.Placement == "" {
		return PlacementPage
	}
	return e.Placement
}

// TwoState 無管理動作的入口只有隱藏／可用兩態；沒有獨立讀取鍵的管理入口為隱藏／管理兩態。
func (e EntryDescriptor) TwoState() bool { return len(e.States) == 2 }

// CapabilityDescriptor 不屬於單一入口的獨立能力（指派角色）。
type CapabilityDescriptor struct {
	ID            string
	Key           Permission
	TrustHint     bool // 廣泛發權語義與人選信任提示
	RequiresEntry bool
}

func st(name string, keys ...Permission) EntryState { return EntryState{Name: name, Keys: keys} }
func hid() EntryState                               { return EntryState{Name: StateHidden} }

// entryDescriptors 入口表（凍結表，以本函式與 TestRoleEditorDescriptors 為準）。
func entryDescriptors() []EntryDescriptor {
	return []EntryDescriptor{
		{ID: "assets", Group: GroupAsset, States: []EntryState{hid(), st(StateRead, PermAssetView),
			st(StateManage, PermAssetView, PermAssetCreate, PermAssetUpdate, PermAssetDelete, PermAssetTest, PermAssetGroupManage)},
			Details: []EntryDetail{{"asset.view", PermAssetView}, {"asset.create", PermAssetCreate}, {"asset.update", PermAssetUpdate},
				{"asset.delete", PermAssetDelete}, {"asset.test", PermAssetTest},
				{"asset_account.view", PermAssetView}, {"asset_account.update", PermAssetUpdate},
				{"node.manage", PermAssetGroupManage}}},
		{ID: "credentials", Group: GroupAsset, States: []EntryState{hid(), st(StateRead, PermCredentialView, PermAssetView),
			st(StateManage, PermCredentialManage, PermCredentialView, PermCredentialCreate, PermCredentialUpdate, PermCredentialSetSecret,
				PermCredentialRotate, PermCredentialConvertScope, PermCredentialDetach, PermCredentialDelete, PermCredentialBind,
				PermAccountRotate, PermAssetView)},
			Details: []EntryDetail{{"credential.manage", PermCredentialManage}, {"credential.view", PermCredentialView},
				{"credential.create", PermCredentialCreate}, {"credential.update", PermCredentialUpdate},
				{"credential.set_secret", PermCredentialSetSecret}, {"credential.rotate", PermCredentialRotate},
				{"credential.convert_scope", PermCredentialConvertScope}, {"credential.detach", PermCredentialDetach},
				{"credential.delete", PermCredentialDelete}, {"credential.bind", PermCredentialBind},
				{"credential.account_rotate", PermAccountRotate}}},
		{ID: "change_secret", Group: GroupAsset, States: []EntryState{hid(), st(StateManage, PermChangeSecretManage, PermAssetView)}},
		{ID: "authorizations", Group: GroupAuthzRule, States: []EntryState{hid(), st(StateManage, PermAuthorizationManage)}},
		{ID: "approver_scopes", Group: GroupAuthzRule, States: []EntryState{hid(), st(StateManage, PermApproverScopeManage, PermApproverScopeApplicantManage)}},
		{ID: "users", Group: GroupIdentity, States: []EntryState{hid(), st(StateManage, PermUserManage)}},
		{ID: "user_groups", Group: GroupIdentity, States: []EntryState{hid(), st(StateManage, PermUserGroupManage, PermUserManage)}},
		{ID: "roles", Group: GroupIdentity, States: []EntryState{hid(), st(StateAvailable, PermRoleView)}},
		{ID: "identity_sources", Group: GroupIdentity, States: []EntryState{hid(), st(StateManage, PermIdentitySourceManage, PermLDAPManage, PermOIDCManage)}},
		{ID: "sessions", Group: GroupAudit, States: []EntryState{hid(), st(StateRead, PermSessionView), st(StateManage, PermSessionView, PermSessionTerminate)}},
		{ID: "audit_logs", Group: GroupAudit, States: []EntryState{hid(), st(StateAvailable, PermAuditView)}},
		{ID: "checkpoint_verification", Group: GroupAudit, States: []EntryState{hid(), st(StateAvailable, PermAuditView, PermAuditIntegrityView)}},
		{ID: "alerts", Group: GroupAudit, States: []EntryState{hid(), st(StateRead, PermAlertView, PermAuditView), st(StateManage, PermAlertView, PermAlertManage, PermAuditView)},
			ReadVia: "audit_logs"},
		{ID: "compliance_map", Group: GroupAudit, States: []EntryState{hid(), st(StateAvailable, PermComplianceView)}},
		{ID: "access_reviews", Group: GroupAudit, States: []EntryState{hid(), st(StateManage, PermAccessReviewManage, PermAuditView)},
			ReadVia: "audit_logs"},
		{ID: "security_policies", Group: GroupSettings, States: []EntryState{hid(), st(StateManage, PermSecurityPolicyManage)}},
		{ID: "policy_groups", Group: GroupSettings, States: []EntryState{hid(), st(StateRead, PermPolicyGroupView), st(StateManage, PermPolicyGroupView, PermPolicyGroupManage)}},
		{ID: "key_management", Group: GroupSettings, States: []EntryState{hid(), st(StateManage, PermKeyManage)}},
		{ID: "transmission", Group: GroupSettings, States: []EntryState{hid(), st(StateManage, PermTransmissionManage)}},
		{ID: "offsite_storage", Group: GroupSettings, States: []EntryState{hid(), st(StateManage, PermOffsiteManage)}},
		{ID: "syslog", Group: GroupSettings, States: []EntryState{hid(), st(StateManage, PermSyslogManage)},
			Placement: PlacementEmbedded, PlacementEntries: []string{"security_policies"}},
		{ID: "notification_channels", Group: GroupSettings, States: []EntryState{hid(), st(StateManage, PermNotificationChannel)}},
		{ID: "system_alerts", Group: GroupSettings, States: []EntryState{hid(), st(StateManage, PermSystemAlertManage)}},
		{ID: "alert_rules", Group: GroupSettings, States: []EntryState{hid(), st(StateManage, PermAlertRuleManage)}},
		{ID: "schedules", Group: GroupSettings, States: []EntryState{hid(), st(StateAvailable, PermScheduleManage)},
			Placement: PlacementHelper, PlacementEntries: []string{"change_secret", "rotation_schedules"}},
		{ID: "rotation_schedules", Group: GroupSettings, States: []EntryState{hid(), st(StateManage, PermRotationSchedule)}},
		{ID: "instance_guard", Group: GroupSettings, States: []EntryState{hid(), st(StateAvailable, PermInstanceGuardView)},
			Placement: PlacementBanner},
	}
}

// EntryDescriptors 回傳入口描述（副本，依表序）。
func EntryDescriptors() []EntryDescriptor { return entryDescriptors() }

// CapabilityDescriptors 獨立能力描述（沒有側欄入口的能力：指派角色、單台存取政策覆寫、刪除錄影）。
func CapabilityDescriptors() []CapabilityDescriptor {
	return []CapabilityDescriptor{
		{ID: "role_assign", Key: PermRoleAssign, TrustHint: true},
		{ID: "access_policy_override", Key: PermAccessPolicyManage},
		{ID: "recording_delete", Key: PermRecordingDelete},
	}
}

// FixedEntries 固定入口：登入即可或依本人資格呈現，不可指派為權限。
func FixedEntries() []string {
	return []string{"dashboard", "workspace", "profile", "my_connections", "my_requests", "my_agents", "approvals"}
}

// DeferredFeatures 尚未上線、描述中不得顯示為可用的功能。
func DeferredFeatures() []string {
	return []string{"role_preview", "permission_overview"}
}

// RoleSummary 結構化的白話摘要（可翻譯 token，不含自由文字）。
type RoleSummary struct {
	Manage              []string // 可管理的入口
	Read                []string // 只能檢視
	Available           []string // 可使用（兩態入口）
	Partial             []string // 部分管理：持有該入口的寫入鍵，但未涵蓋管理態全部鍵
	Hidden              []string // 沒有授予的入口
	PermissionCount     int
	CatalogCount        int
	ScopeGlobalOnly     bool // 範圍僅全系統
	ConnectionSeparate  bool // 管理權不自動授予平台內連線權
	AssignmentTrustHint bool // 持有指派角色能力
	Unattributed        []Permission
}

// SummarizeRole 由真實集合產生摘要。keys 為已儲存的權限鍵；入口取「集合完整涵蓋的最高態」，
// 未涵蓋管理態全部鍵、卻持有該入口任一寫入鍵者歸為部分管理（不稱為只能檢視）。
// 判定分兩輪：第一輪逐入口歸類；第二輪處理隨附檢視，帶 ReadVia 的入口若第一輪沒有授予、
// 而來源入口第一輪不是沒有授予，改歸可檢視（只是呈現，不補不移除任何鍵）。
// 計數由目錄產生，不硬寫數量。
func SummarizeRole(keys []Permission) RoleSummary {
	have := map[Permission]bool{}
	for _, k := range keys {
		have[k] = true
	}
	covered := map[Permission]bool{}
	s := RoleSummary{PermissionCount: len(have), CatalogCount: len(permissionCatalog), ScopeGlobalOnly: true, ConnectionSeparate: true, AssignmentTrustHint: have[PermRoleAssign]}
	entries := entryDescriptors()
	levels := make(map[string]string, len(entries))
	for _, e := range entries {
		level := StateHidden
		var levelKeys []Permission
		for _, stt := range e.States[1:] {
			all := true
			for _, k := range stt.Keys {
				if !have[k] {
					all = false
					break
				}
			}
			if all {
				level, levelKeys = stt.Name, stt.Keys
			}
		}
		for _, k := range levelKeys {
			covered[k] = true
		}
		if level != StateManage && holdsAny(have, EntryWriteKeys(e)) {
			level = statePartial
			for _, stt := range e.States {
				for _, k := range stt.Keys {
					if have[k] {
						covered[k] = true
					}
				}
			}
		}
		levels[e.ID] = level
	}
	// 第二輪：隨附檢視。來源入口的鍵已由來源入口歸屬，covered 不變。
	first := make(map[string]string, len(levels))
	for id, l := range levels {
		first[id] = l
	}
	for _, e := range entries {
		if e.ReadVia != "" && first[e.ID] == StateHidden && first[e.ReadVia] != StateHidden {
			levels[e.ID] = StateRead
		}
	}
	for _, e := range entries {
		switch levels[e.ID] {
		case statePartial:
			s.Partial = append(s.Partial, e.ID)
		case StateManage:
			s.Manage = append(s.Manage, e.ID)
		case StateRead:
			s.Read = append(s.Read, e.ID)
		case StateAvailable:
			s.Available = append(s.Available, e.ID)
		default:
			s.Hidden = append(s.Hidden, e.ID)
		}
	}
	for _, c := range CapabilityDescriptors() {
		covered[c.Key] = true
	}
	for k := range have {
		if !covered[k] {
			s.Unattributed = append(s.Unattributed, k)
		}
	}
	sort.Slice(s.Unattributed, func(i, j int) bool { return s.Unattributed[i] < s.Unattributed[j] })
	return s
}

// BlockedScreen 持有者因缺必要依賴而無法使用的畫面（入口或獨立能力的穩定 ID）與缺少的鍵。
type BlockedScreen struct {
	ID      string       `json:"id"`
	Missing []Permission `json:"missing"`
}

// ownKeys 入口各態中「屬於該入口本身」的鍵：排除同態內只是別鍵依賴的鍵。
func ownKeys(e EntryDescriptor) map[Permission]bool {
	deps := permissionDependencies()
	own := map[Permission]bool{}
	for _, stt := range e.States {
		isDep := map[Permission]bool{}
		for _, k := range stt.Keys {
			for _, d := range deps[k] {
				isDep[d] = true
			}
		}
		for _, k := range stt.Keys {
			if !isDep[k] {
				own[k] = true
			}
		}
	}
	return own
}

// BlockedScreens 由真實集合推出持有者無法使用的畫面（缺依賴允許儲存，改以明示取代拒絕）。
// 依入口表序、再接獨立能力；同一畫面的缺少鍵合併去重排序。
func BlockedScreens(perms []Permission) []BlockedScreen {
	miss := map[Permission][]Permission{}
	for _, m := range MissingDependencies(perms) {
		miss[m.Permission] = m.Missing
	}
	out := []BlockedScreen{}
	add := func(id string, own func(Permission) bool) {
		set := map[Permission]bool{}
		for k, ms := range miss {
			if own(k) {
				for _, m := range ms {
					set[m] = true
				}
			}
		}
		if len(set) == 0 {
			return
		}
		ms := make([]Permission, 0, len(set))
		for m := range set {
			ms = append(ms, m)
		}
		sort.Slice(ms, func(i, j int) bool { return ms[i] < ms[j] })
		out = append(out, BlockedScreen{ID: id, Missing: ms})
	}
	for _, e := range entryDescriptors() {
		own := ownKeys(e)
		add(e.ID, func(k Permission) bool { return own[k] })
	}
	for _, c := range CapabilityDescriptors() {
		key := c.Key
		add(c.ID, func(k Permission) bool { return k == key })
	}
	return out
}

// statePartial 摘要內部的分級名稱：不是可點選的態。
const statePartial = "partial"

func holdsAny(have map[Permission]bool, keys []Permission) bool {
	for _, k := range keys {
		if have[k] {
			return true
		}
	}
	return false
}

// writeKeyOwners 管理態的每個鍵歸屬哪些入口。
//
// 歸屬規則：鍵 k 在入口各態中被當作自有鍵（ownKeys 含 k）的入口即為歸屬入口；
// 沒有任何入口把 k 當自有鍵時（同入口內被另一個動作依賴，例如審核範圍的管理鍵），
// 歸屬為所有含 k 的入口。正常情況下每個鍵恰有一個歸屬入口，由測試守住。
func writeKeyOwners() map[Permission][]string {
	entries := entryDescriptors()
	own := make(map[string]map[Permission]bool, len(entries))
	for _, e := range entries {
		own[e.ID] = ownKeys(e)
	}
	owners := map[Permission][]string{}
	for _, e := range entries {
		for _, stt := range e.States {
			if stt.Name != StateManage {
				continue
			}
			for _, k := range stt.Keys {
				if _, done := owners[k]; done {
					continue
				}
				var o []string
				for _, e2 := range entries {
					if own[e2.ID][k] {
						o = append(o, e2.ID)
					}
				}
				if len(o) == 0 {
					for _, e2 := range entries {
						if entryHasKey(e2, k) {
							o = append(o, e2.ID)
						}
					}
				}
				owners[k] = o
			}
		}
	}
	return owners
}

func entryHasKey(e EntryDescriptor, k Permission) bool {
	for _, stt := range e.States {
		for _, x := range stt.Keys {
			if x == k {
				return true
			}
		}
	}
	return false
}

// EntryWriteKeys 入口的寫入鍵：管理態中歸屬於該入口、且不在該入口唯讀態的鍵（依鍵排序）。
// 部分管理的判定唯一來源；ownKeys 與 BlockedScreens 不使用它。
func EntryWriteKeys(e EntryDescriptor) []Permission {
	owners := writeKeyOwners()
	readKeys := map[Permission]bool{}
	for _, stt := range e.States {
		if stt.Name == StateRead {
			for _, k := range stt.Keys {
				readKeys[k] = true
			}
		}
	}
	out := []Permission{}
	for _, stt := range e.States {
		if stt.Name != StateManage {
			continue
		}
		for _, k := range stt.Keys {
			if readKeys[k] {
				continue
			}
			for _, id := range owners[k] {
				if id == e.ID {
					out = append(out, k)
					break
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
