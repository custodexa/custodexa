package authz

import (
	"errors"
	"time"

	"github.com/custodexa/backend/internal/modules/authz/disclosure"
)

// 單一使用者的權限一覽：回應型別。
//
// 內容全部由伺服器依執行期同一套主體解析與範圍判定算出，前端只呈現，不推算集合、範圍或交集。
// 管理者指派的來源只有「管理者指派」一句，不帶指派者、日期或固定標示：現有痕跡無法證明
// 目前的管理者成分由誰、何時建立，系統不推測。

// 來源種類（值域封閉）。
const (
	OverviewSourceDirect        = "direct"         // 管理者直接指派
	OverviewSourceMapped        = "mapped"         // 外部群組映射賦予
	OverviewSourceGroup         = "group"          // 經使用者群組
	OverviewSourceCompatDefault = "compat_default" // 沒有指派角色時的一般使用者預設
	OverviewSourceAgentFixed    = "agent_fixed"    // AI agent 的固定能力
)

// 不生效原因（值域封閉）。
const (
	// OverviewReasonNodesAllDeleted 節點範圍指派的範圍節點已全部刪除（整筆不生效）。
	OverviewReasonNodesAllDeleted = "nodes_all_deleted"
	// OverviewReasonNotNodeScopable 權限點不支援節點範圍（只限全系統），節點範圍的指派對它不生效。
	OverviewReasonNotNodeScopable = "permission_not_node_scopable"
	// OverviewReasonBuiltinRequiresGlobal 內建身分範本只認全系統指派，節點範圍的指派對它不生效。
	OverviewReasonBuiltinRequiresGlobal = "builtin_requires_global"
)

// 連線項種類。
const (
	OverviewItemAuthorization = "authorization"
	OverviewItemUndisclosed   = "undisclosed_authorization"
	OverviewItemApproverScope = "approver_scope"
)

// 範圍種類。
const (
	OverviewScopeGlobal = "global"
	OverviewScopeNodes  = "nodes"
)

// 連線政策混合值：項內可視資產的有效連線政策不一致。
const OverviewPolicyMixed = "mixed"

// 判定入口錯誤。
var (
	// ErrPermissionOverviewUnwired 組裝時缺必要依賴：端點回內部錯誤，不回空集合冒充「沒有權限」。
	ErrPermissionOverviewUnwired = errors.New("authz: permission overview without required dependencies")
	// ErrPermissionOverviewNoViewer 請求脈絡沒有檢視者主體。
	ErrPermissionOverviewNoViewer = errors.New("authz: permission overview without viewer principal")
)

// OverviewNode 範圍節點與由根起的名稱路徑。
type OverviewNode struct {
	ID   uint   `json:"id"`
	Path string `json:"path"`
}

// OverviewScope 範圍：全系統，或節點清單。
// 全系統時 nodes 為空陣列、inactive_node_count 為 0；節點範圍時 nodes 只含仍存在的節點，
// 已刪除或不存在的節點只給筆數，不帶名稱。
type OverviewScope struct {
	Kind              string         `json:"kind"`
	Nodes             []OverviewNode `json:"nodes"`
	InactiveNodeCount int            `json:"inactive_node_count"`
}

// OverviewRole 角色（合成來源沒有角色）。
type OverviewRole struct {
	ID         uint    `json:"id"`
	Name       string  `json:"name"`
	BuiltinKey *string `json:"builtin_key"`
}

// OverviewRuleRef 支持一個映射的規則：規則編號、身分來源顯示名、外部群組標籤。
type OverviewRuleRef struct {
	RuleID        uint   `json:"rule_id"`
	SourceName    string `json:"source_name"`
	ExternalGroup string `json:"external_group"`
}

// OverviewGroupInfo 經使用者群組的來源附帶資料。
type OverviewGroupInfo struct {
	ID   uint   `json:"id"`
	Name string `json:"name"`
	// MemberSource 被檢視者在該群組的成員來源：manual、mapped、both。
	MemberSource string `json:"member_source"`
	// MappingRules 成員經映射加入時，把他帶進群組的規則；否則為空陣列。
	MappingRules []OverviewRuleRef `json:"mapping_rules"`
}

// OverviewIneffective 來源中不生效的權限點與原因。
type OverviewIneffective struct {
	Permission string `json:"permission"`
	Reason     string `json:"reason"`
}

// OverviewSource 一個來源。direct 來源只含六個共同欄位；mapped 另有 mapping_rules，group 另有 group。
type OverviewSource struct {
	SourceRef            string                `json:"source_ref"`
	Kind                 string                `json:"kind"`
	Role                 *OverviewRole         `json:"role"`
	Scope                OverviewScope         `json:"scope"`
	EffectivePermissions []string              `json:"effective_permissions"`
	Ineffective          []OverviewIneffective `json:"ineffective"`
	Group                *OverviewGroupInfo    `json:"group,omitempty"`
	MappingRules         *[]OverviewRuleRef    `json:"mapping_rules,omitempty"`
}

// OverviewIneffectiveSource 整筆不生效的來源與原因。
type OverviewIneffectiveSource struct {
	OverviewSource
	Reason string `json:"reason"`
}

// OverviewEntries 一張角色卡的第一層入口狀態（取自入口摘要，不列沒有授予者）。
type OverviewEntries struct {
	Manage    []string `json:"manage"`
	Partial   []string `json:"partial"`
	Read      []string `json:"read"`
	Available []string `json:"available"`
}

// OverviewBinding 依角色分組的呈現摘要：同一角色的多個來源合為一張卡，範圍與生效以 sources 為準。
type OverviewBinding struct {
	Role       *OverviewRole   `json:"role"`
	SourceRefs []string        `json:"source_refs"`
	Entries    OverviewEntries `json:"entries"`
	// ManageableAssetCount 範圍內的管理可視資產台數；全系統（含超管）為 null。
	ManageableAssetCount *int64 `json:"manageable_asset_count"`
}

// OverviewPermission 一個有效權限點：範圍與至少一個來源。
type OverviewPermission struct {
	Permission string        `json:"permission"`
	Scopes     OverviewScope `json:"scopes"`
	SourceRefs []string      `json:"source_refs"`
}

// OverviewIdentity 內建身分旗標，取自被檢視者已解析的主體（經群組或映射取得者同樣成立）。
type OverviewIdentity struct {
	SuperAdmin    bool `json:"super_admin"`
	Auditor       bool `json:"auditor"`
	Approver      bool `json:"approver"`
	Agent         bool `json:"agent"`
	CompatDefault bool `json:"compat_default"`
}

// OverviewManagement 管理面。
type OverviewManagement struct {
	Identity           OverviewIdentity            `json:"identity"`
	Sources            []OverviewSource            `json:"sources"`
	Bindings           []OverviewBinding           `json:"bindings"`
	Permissions        []OverviewPermission        `json:"permissions"`
	IneffectiveSources []OverviewIneffectiveSource `json:"ineffective_sources"`
}

// OverviewTarget 連線項的目標：資產名稱，或節點路徑。
type OverviewTarget struct {
	Type string `json:"type"` // asset、node
	Name string `json:"name"`
}

// OverviewVia 經由：本人或群組。
type OverviewVia struct {
	Type      string `json:"type"` // self、group
	GroupName string `json:"group_name,omitempty"`
}

// OverviewValidity 時效；兩者皆為 null 即常設。
type OverviewValidity struct {
	DateStart   *time.Time `json:"date_start"`
	DateExpired *time.Time `json:"date_expired"`
}

// OverviewItemDetail 出現在檢視者授權列表投影中的授權記錄才帶的欄位。
type OverviewItemDetail struct {
	AuthorizationID uint             `json:"authorization_id"`
	Target          OverviewTarget   `json:"target"`
	Via             OverviewVia      `json:"via"`
	AccountScope    []string         `json:"account_scope"` // null＝全部帳號
	Validity        OverviewValidity `json:"validity"`
	// AccessPolicy 項內可視資產的有效連線政策：全部相同時給該值，不同時為 mixed。
	AccessPolicy string `json:"access_policy"`
}

// OverviewConnectionItem 連線面的一項。檢視者看不到的授權記錄只以不具名項呈現等級與台數。
type OverviewConnectionItem struct {
	Kind              string `json:"kind"`
	Permission        string `json:"permission"`
	VisibleAssetCount int    `json:"visible_asset_count"`
	ManagedAssetCount int    `json:"managed_asset_count"`
	*OverviewItemDetail
}

// OverviewManageOnly 能管理但沒有任何連線授權的範圍節點與台數（每列各自計算該節點子樹，不跨列去重）。
type OverviewManageOnly struct {
	NodePath   string `json:"node_path"`
	AssetCount int    `json:"asset_count"`
}

// OverviewConnection 連線面。檢視者不具檢視有效權限的能力時 available 為 false，不回任何項或台數。
type OverviewConnection struct {
	Available bool `json:"available"`
	// RoleOverride 被檢視者因內建身分隱含的連線摘要：admin（超管，可連線所有主機）或 auditor（可檢視全部資產）。
	RoleOverride string                    `json:"role_override,omitempty"`
	Items        *[]OverviewConnectionItem `json:"items,omitempty"`
	ManageOnly   *[]OverviewManageOnly     `json:"manage_only,omitempty"`
	// 範圍外資產台數：只經揭露登錄的載體輸出；檢視者為全域、連線區段不可用、被檢視者為有效超管時不帶。
	*disclosure.AssetCountField
}

// PermissionOverview 權限一覽。
type PermissionOverview struct {
	UserID     uint               `json:"user_id"`
	Username   string             `json:"username"`
	Management OverviewManagement `json:"management"`
	Connection OverviewConnection `json:"connection"`
}

// OverviewManageGrant 查一台資產：放行管理的一筆指派。
type OverviewManageGrant struct {
	Role  *OverviewRole `json:"role"`
	Scope OverviewScope `json:"scope"`
}

// OverviewProbeManage 能否管理。
type OverviewProbeManage struct {
	Allowed bool                  `json:"allowed"`
	Grants  []OverviewManageGrant `json:"grants"`
}

// OverviewProbeConnect 能否連線。available 為 false 時只有這一欄。
type OverviewProbeConnect struct {
	Available    bool                      `json:"available"`
	Allowed      *bool                     `json:"allowed,omitempty"`
	RoleOverride string                    `json:"role_override,omitempty"`
	Items        *[]OverviewConnectionItem `json:"items,omitempty"`
}

// OverviewAssetProbe 查一台資產的回應。
type OverviewAssetProbe struct {
	UserID  uint                 `json:"user_id"`
	AssetID uint                 `json:"asset_id"`
	Manage  OverviewProbeManage  `json:"manage"`
	Connect OverviewProbeConnect `json:"connect"`
}
