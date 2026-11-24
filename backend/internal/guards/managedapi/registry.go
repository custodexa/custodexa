// Package managedapi 納管資源登錄表與路由歸屬表。
//
// 納管資源登錄表列出可由宣告式工具建立、讀取、修改、刪除的資源：每個資源一列，記載各操作的路由、精確查找、
// 識別的唯一範圍、秘密欄位，以及每一條納管資源規則的狀態。狀態只有四種：符合、已知例外（封閉列舉，
// 每個例外對應一條規則）、不適用（只在規則所依賴的操作或欄位不存在時可用）、待查（只限初始名單，
// 表示現況尚未查證，不代表符合）。
//
// 路由歸屬表讓「不登錄」本身會被擋下：對 API token 開放的每一條路由都要歸到某個納管資源的某個操作、
// 非資源的查詢或動作、唯讀的資源家族，或已開放寫入但尚未納管的既有家族其中一類。尚未納管的家族名單凍結，
// 新增家族要改這份名單。
//
// 本套件的測試是結構面的守衛（不需資料庫）；讀取面的行為規則由後端整合測試逐列執行（以 Resources 為準）。
// 兩張表另以測試產生機器可讀的副本 testdata/managed-api-registry.json，改動任一張表都要重生副本並逐條審視 diff。
package managedapi

import "sort"

// Rule 納管資源規則。
type Rule string

// 納管資源規則（封閉列舉）。新增規則要同步規格與每一列的狀態。
const (
	RuleSingleRead            Rule = "single_read"
	RuleSingleMatchesList     Rule = "single_read_matches_list"
	RuleHiddenTargetNotFound  Rule = "hidden_target_not_found"
	RuleListDataTotal         Rule = "list_data_total"
	RuleListPaging            Rule = "list_paging"
	RuleExactLookup           Rule = "exact_lookup"
	RuleCreate201             Rule = "create_201"
	RuleSameEnvelope          Rule = "same_envelope_read_write"
	RuleWriteEqualsRead       Rule = "write_response_equals_read"
	RuleUpdatePartial         Rule = "update_missing_fields_unchanged"
	RuleUpdateKeepsIdentity   Rule = "update_keeps_identity"
	RuleDelete204             Rule = "delete_204"
	RuleRecreateSameName      Rule = "recreate_same_name"
	RuleIdentityGlobal        Rule = "identity_globally_unique"
	RuleTimeFields            Rule = "time_fields_rfc3339"
	RuleServerRewriteReturned Rule = "server_rewrite_returned"
	RuleSecretWriteOnly       Rule = "secret_write_only"
	RuleSecretClearPath       Rule = "secret_clear_path"
	RuleDuplicate409          Rule = "duplicate_409"
	RuleConcurrentWriteNo500  Rule = "concurrent_write_no_500"
	RuleErrorEnvelope         Rule = "error_envelope"
	RuleResendNoChange        Rule = "resend_no_change"
)

// Rules 全部規則，依規格的面向排序。
func Rules() []Rule {
	return []Rule{
		RuleSingleRead, RuleSingleMatchesList, RuleHiddenTargetNotFound, RuleListDataTotal, RuleListPaging,
		RuleExactLookup, RuleCreate201, RuleSameEnvelope, RuleWriteEqualsRead, RuleUpdatePartial,
		RuleUpdateKeepsIdentity, RuleDelete204, RuleRecreateSameName, RuleIdentityGlobal, RuleTimeFields,
		RuleServerRewriteReturned, RuleSecretWriteOnly, RuleSecretClearPath, RuleDuplicate409,
		RuleConcurrentWriteNo500, RuleErrorEnvelope, RuleResendNoChange,
	}
}

// Exception 已知例外（封閉列舉）。每個例外對應恰一條規則。
type Exception string

// 已知例外。全部僅限初始名單引用：之後新增的資源不得引用，確有需要時要新增一個不限初始名單的例外，
// 並同步規格。
const (
	ExcResponseEnvelopeMixed   Exception = "response_envelope_mixed"
	ExcListWithoutTotal        Exception = "list_without_total"
	ExcDeleteResponseShape     Exception = "delete_response_shape"
	ExcUpdateFullReplace       Exception = "update_full_replace"
	ExcUpdateReissuesIdentity  Exception = "update_reissues_identity"
	ExcTimeFieldFormat         Exception = "time_field_format"
	ExcNoTimeFields            Exception = "no_time_fields"
	ExcIdentityUniqueInKind    Exception = "identity_unique_within_kind"
	ExcDetailProjectionDiffers Exception = "detail_projection_differs"
	ExcWriteResponseShape      Exception = "write_response_shape_differs"
	ExcServerRewritesInput     Exception = "server_rewrites_input"
	ExcConcurrentRetriable     Exception = "concurrent_write_retriable_conflict"
	ExcResendAdvances          Exception = "resend_advances_time_or_version"
	ExcNoExactLookup           Exception = "no_exact_lookup"
	ExcNoSingleRead            Exception = "no_single_read"
	ExcSecretNoClearPath       Exception = "secret_no_clear_path"
	ExcCreateReturns200        Exception = "create_returns_200"
	ExcSecretNoFingerprint     Exception = "secret_without_fingerprint"
	ExcLookupNotUnique         Exception = "lookup_not_unique"
	ExcSecretStateImplicit     Exception = "secret_state_implicit"
)

// ExceptionSpec 一個例外對應的規則、是否僅限初始名單，與一句說明。
type ExceptionSpec struct {
	Rule        Rule   `json:"rule"`
	InitialOnly bool   `json:"initial_only"`
	Description string `json:"description"`
}

var exceptionSpecs = map[Exception]ExceptionSpec{
	ExcResponseEnvelopeMixed:   {RuleSameEnvelope, true, "同一資源的讀取與寫入回應外層不同（裸物件或包在 data 內）"},
	ExcListWithoutTotal:        {RuleListDataTotal, true, "列表沒有總數"},
	ExcDeleteResponseShape:     {RuleDelete204, true, "刪除成功回 200 與本文，而非 204"},
	ExcUpdateFullReplace:       {RuleUpdatePartial, true, "修改為整筆替換：請求中沒有出現的欄位會被清除或必填"},
	ExcUpdateReissuesIdentity:  {RuleUpdateKeepsIdentity, true, "修改特定欄位時以新識別取代舊識別"},
	ExcTimeFieldFormat:         {RuleTimeFields, true, "時間欄位是合法的 RFC 3339，但只到秒，精度與其他資源（到微秒）不同"},
	ExcNoTimeFields:            {RuleTimeFields, true, "沒有時間欄位，或缺少修改時間"},
	ExcIdentityUniqueInKind:    {RuleIdentityGlobal, true, "識別只在同類資源內唯一，匯入時要帶上類別"},
	ExcDetailProjectionDiffers: {RuleSingleMatchesList, true, "單筆讀取的投影與列表不同，只比對登錄的共同欄位"},
	ExcWriteResponseShape:      {RuleWriteEqualsRead, true, "寫入回應與讀取的形狀不同"},
	ExcServerRewritesInput:     {RuleServerRewriteReturned, true, "伺服器改寫輸入而寫入回應未完整反映"},
	ExcConcurrentRetriable:     {RuleConcurrentWriteNo500, true, "並行寫入不排隊，回可重試的衝突"},
	ExcResendAdvances:          {RuleResendNoChange, true, "原樣重送會推進時間或版本"},
	ExcNoExactLookup:           {RuleExactLookup, true, "列表沒有精確查找參數"},
	ExcNoSingleRead:            {RuleSingleRead, true, "沒有依識別讀取單筆的端點"},
	ExcSecretNoClearPath:       {RuleSecretClearPath, true, "秘密欄位沒有明確的清除途徑"},
	ExcCreateReturns200:        {RuleCreate201, true, "建立成功回 200，而非 201"},
	ExcSecretNoFingerprint:     {RuleSecretWriteOnly, true, "讀取只回是否已設定，部分秘密沒有可比對的指紋"},
	ExcLookupNotUnique:         {RuleExactLookup, true, "有精確查找參數，但唯一性的範圍比參數窄，一次查找可能回多筆"},
	ExcSecretStateImplicit:     {RuleSecretWriteOnly, true, "讀取不含秘密，但沒有直接回報是否已設定的欄位，要由其他欄位推得"},
}

// ExceptionSpecs 例外列舉的副本。
func ExceptionSpecs() map[Exception]ExceptionSpec {
	out := make(map[Exception]ExceptionSpec, len(exceptionSpecs))
	for k, v := range exceptionSpecs {
		out[k] = v
	}
	return out
}

// CellStatus 一個「資源乘規則」格子的狀態。
type CellStatus string

const (
	// StatusConforms 符合。
	StatusConforms CellStatus = "conforms"
	// StatusException 已知例外（Exception 欄必填）。
	StatusException CellStatus = "exception"
	// StatusNotApplicable 不適用：只在規則所依賴的操作或欄位不存在時可用（Note 必填）。
	StatusNotApplicable CellStatus = "not_applicable"
	// StatusPending 待查：現況尚未查證，不代表符合。只限初始名單（Note 必填）。
	StatusPending CellStatus = "pending"
)

// Cell 一個格子的值。
type Cell struct {
	Status    CellStatus `json:"status"`
	Exception Exception  `json:"exception,omitempty"`
	Note      string     `json:"note,omitempty"`
}

func ok(note ...string) Cell {
	if len(note) > 0 {
		return Cell{Status: StatusConforms, Note: note[0]}
	}
	// 沒有附說明的符合格
	return Cell{Status: StatusConforms}
}

func exc(e Exception, note string) Cell {
	return Cell{Status: StatusException, Exception: e, Note: note}
}
func na(note string) Cell      { return Cell{Status: StatusNotApplicable, Note: note} }
func pending(note string) Cell { return Cell{Status: StatusPending, Note: note} }

// Lookup 精確查找。Params 為參數名（多個時取交集）；Match 為比對規則。
type Lookup struct {
	Params []string `json:"params,omitempty"`
	Match  string   `json:"match,omitempty"`
}

// 精確查找的比對規則。
const (
	MatchExact   = "逐字相等（不去空白、不改大小寫）"
	MatchTrimmed = "去除前後空白後逐字相等"
)

// Secret 秘密欄位與讀取時的呈現。
type Secret struct {
	Field  string `json:"field"`
	ReadAs string `json:"read_as"`
}

// Resource 納管資源登錄表的一列。路由鍵為「方法 樣板路徑」，與 API token 路由登錄同一格式。
type Resource struct {
	Name  string `json:"name"`
	Title string `json:"title"`

	List   []string `json:"list"`
	Read   []string `json:"read"`
	Create []string `json:"create"`
	Update []string `json:"update"`
	Delete []string `json:"delete"`

	// Paged 列表是否分頁（不分頁時分頁規則不適用）。
	Paged bool `json:"paged"`
	// ReadWrapped 單筆讀取的資源本體是否包在 data 內。
	ReadWrapped bool `json:"read_wrapped"`
	// ListPassthrough 列表請求須帶的查詢參數（例如一頁裝得下測試資料的每頁筆數）；空字串表示不帶。
	ListPassthrough string `json:"list_query,omitempty"`

	Lookup        Lookup   `json:"lookup"`
	IdentityScope string   `json:"identity_scope"`
	Secrets       []Secret `json:"secrets,omitempty"`
	// CommonFields 登錄「詳情投影與列表不同」時，單筆讀取與列表比對的共同欄位。
	CommonFields []string `json:"common_fields,omitempty"`
	// ListOnlyFields 登錄「詳情投影與列表不同」的另一種寫法：只有這些欄位可能出現在列表而單筆讀取沒有，
	// 其餘欄位照常逐欄比對。與 CommonFields 二擇一。超級管理者的列表不得出現這些欄位。
	ListOnlyFields []string `json:"list_only_fields,omitempty"`

	Cells map[Rule]Cell `json:"cells"`
}

// 識別範圍的寫法。
const (
	ScopeGlobal = "全域"
)

const prefix = "/api/v1"

func r(method, path string) string { return method + " " + prefix + path }

// initialResources 初始名單的 11 列。
var initialResources = []Resource{
	{
		Name: "asset_node", Title: "節點",
		List:   []string{r("GET", "/asset-groups"), r("GET", "/asset-groups/tree")},
		Read:   []string{r("GET", "/asset-groups/:id")},
		Create: []string{r("POST", "/asset-groups")},
		Update: []string{r("PUT", "/asset-groups/:id"), r("PUT", "/asset-groups/:id/move")},
		Delete: []string{r("DELETE", "/asset-groups/:id")},
		Lookup: Lookup{Params: []string{"name"}, Match: MatchExact}, IdentityScope: "名稱在同一個上層節點之下唯一；識別全域唯一",
		CommonFields: []string{"id", "name", "description", "parent_id", "path"},
		Cells: map[Rule]Cell{
			RuleSingleRead:            ok(),
			RuleSingleMatchesList:     exc(ExcDetailProjectionDiffers, "列表另帶直掛資產與用途旗標，單筆讀取不帶"),
			RuleHiddenTargetNotFound:  ok(),
			RuleListDataTotal:         ok(),
			RuleListPaging:            na("列表不分頁"),
			RuleExactLookup:           exc(ExcLookupNotUnique, "名稱只在同一個上層節點之下唯一，以名稱查找可能回多筆，帶上層識別也不會縮小結果"),
			RuleCreate201:             ok(),
			RuleSameEnvelope:          ok(),
			RuleWriteEqualsRead:       ok(),
			RuleUpdatePartial:         exc(ExcUpdateFullReplace, "名稱必填，說明送空字串即清空"),
			RuleUpdateKeepsIdentity:   ok(),
			RuleDelete204:             exc(ExcDeleteResponseShape, "200 並回報連帶撤銷的授權筆數"),
			RuleRecreateSameName:      ok(),
			RuleIdentityGlobal:        ok(),
			RuleTimeFields:            exc(ExcNoTimeFields, "單筆讀取與列表都沒有時間欄位"),
			RuleServerRewriteReturned: ok("不改寫輸入：名稱與說明的前後空白原樣保存與回傳"),
			RuleSecretWriteOnly:       na("沒有秘密欄位"),
			RuleSecretClearPath:       na("沒有秘密欄位"),
			RuleDuplicate409:          ok(),
			RuleConcurrentWriteNo500:  ok("交易內取拓撲序列化鎖，阻塞排隊"),
			RuleErrorEnvelope:         ok(),
			RuleResendNoChange:        ok("沒有時間與版本欄位，原樣重送後讀取沒有差異"),
		},
	},
	{
		Name: "asset", Title: "資產",
		List:   []string{r("GET", "/assets")},
		Read:   []string{r("GET", "/assets/:id")},
		Create: []string{r("POST", "/assets")},
		Update: []string{r("PUT", "/assets/:id")},
		Delete: []string{r("DELETE", "/assets/:id")},
		Paged:  true, ListPassthrough: "page_size=1000",
		Lookup: Lookup{Params: []string{"name"}, Match: MatchExact}, IdentityScope: ScopeGlobal,
		Secrets: []Secret{
			{Field: "password", ReadAs: "has_password"},
			{Field: "private_key", ReadAs: "has_private_key"},
			{Field: "sftp_password", ReadAs: "has_sftp_password"},
		},
		ListOnlyFields: []string{"permission", "access_state"},
		Cells: map[Rule]Cell{
			RuleSingleRead:            ok(),
			RuleSingleMatchesList:     exc(ExcDetailProjectionDiffers, "只有連線授權的一般使用者，列表那一筆另帶授權等級與存取狀態，單筆讀取不帶；管理者讀到的兩者相同"),
			RuleHiddenTargetNotFound:  ok(),
			RuleListDataTotal:         ok(),
			RuleListPaging:            ok("每頁上限 1000，回報實際套用的值"),
			RuleExactLookup:           ok(),
			RuleCreate201:             ok(),
			RuleSameEnvelope:          ok(),
			RuleWriteEqualsRead:       ok(),
			RuleUpdatePartial:         ok("全部為選填欄位，缺欄位代表不動"),
			RuleUpdateKeepsIdentity:   ok(),
			RuleDelete204:             exc(ExcDeleteResponseShape, "200 並回空物件"),
			RuleRecreateSameName:      ok(),
			RuleIdentityGlobal:        ok(),
			RuleTimeFields:            ok(),
			RuleServerRewriteReturned: ok("標籤正規化後的值出現在寫入回應"),
			RuleSecretWriteOnly:       exc(ExcSecretNoFingerprint, "只回是否已設定；資產本身的讀取不帶私鑰指紋（指紋在帳號列），密碼與檔案傳輸密碼沒有可比對的指紋"),
			RuleSecretClearPath:       exc(ExcSecretNoClearPath, "密碼、私鑰沒有清除途徑"),
			RuleDuplicate409:          ok(),
			RuleConcurrentWriteNo500:  ok("拓撲序列化鎖，阻塞排隊"),
			RuleErrorEnvelope:         ok(),
			RuleResendNoChange:        exc(ExcResendAdvances, "同一個說明原樣重送也會推進修改時間"),
		},
	},
	{
		Name: "asset_account", Title: "資產帳號",
		List:   []string{r("GET", "/assets/:id/accounts")},
		Read:   []string{r("GET", "/assets/:id/accounts/:accountId")},
		Create: []string{r("POST", "/assets/:id/accounts")},
		Update: []string{r("PUT", "/assets/:id/accounts/:accountId"), r("POST", "/assets/:id/accounts/:accountId/set-default")},
		Delete: []string{r("DELETE", "/assets/:id/accounts/:accountId")},
		Lookup: Lookup{}, IdentityScope: "帳號名稱在同一台資產內唯一；識別全域唯一，路由掛在資產之下",
		Secrets: []Secret{
			{Field: "password", ReadAs: "has_password"},
			{Field: "private_key", ReadAs: "has_private_key"},
		},
		Cells: map[Rule]Cell{
			RuleSingleRead:            ok(),
			RuleSingleMatchesList:     ok(),
			RuleHiddenTargetNotFound:  ok(),
			RuleListDataTotal:         ok(),
			RuleListPaging:            na("列表不分頁"),
			RuleExactLookup:           exc(ExcNoExactLookup, "沒有以帳號名稱查找的參數"),
			RuleCreate201:             ok(),
			RuleSameEnvelope:          ok(),
			RuleWriteEqualsRead:       ok(),
			RuleUpdatePartial:         ok("選填欄位，缺欄位代表不動"),
			RuleUpdateKeepsIdentity:   ok(),
			RuleDelete204:             ok(),
			RuleRecreateSameName:      ok(),
			RuleIdentityGlobal:        ok(),
			RuleTimeFields:            exc(ExcTimeFieldFormat, "時間只到秒（合法的 RFC 3339）"),
			RuleServerRewriteReturned: ok("不改寫輸入：帳號名與備註的前後空白原樣保存與回傳"),
			RuleSecretWriteOnly:       exc(ExcSecretNoFingerprint, "只回是否已設定與生效版本；私鑰回報公鑰指紋，未保存公鑰的既有私鑰、DSA 型別的私鑰、呼叫者沒有該憑證檢視能力時與範圍外收窄的帳號列不帶；密碼沒有可比對的指紋"),
			RuleSecretClearPath:       exc(ExcSecretNoClearPath, "密碼、私鑰沒有清除途徑"),
			RuleDuplicate409:          ok(),
			RuleConcurrentWriteNo500:  ok("拓撲序列化鎖；改密進行中回可辨識的衝突"),
			RuleErrorEnvelope:         ok(),
			RuleResendNoChange:        exc(ExcResendAdvances, "同一個密碼重送也會推進版本"),
		},
	},
	{
		Name: "credential", Title: "共用憑證",
		List:   []string{r("GET", "/credentials")},
		Read:   []string{r("GET", "/credentials/:id")},
		Create: []string{r("POST", "/credentials")},
		Update: []string{r("PUT", "/credentials/:id"), r("POST", "/credentials/:id/secret")},
		Delete: []string{r("DELETE", "/credentials/:id")},
		Paged:  true, ReadWrapped: true,
		Lookup: Lookup{Params: []string{"name"}, Match: MatchTrimmed}, IdentityScope: "共用範圍的憑證名稱唯一；識別全域唯一",
		Secrets: []Secret{
			{Field: "password", ReadAs: "has_password"},
			{Field: "private_key", ReadAs: "has_private_key"},
		},
		CommonFields: []string{"id", "name", "note", "username", "scope", "protocol_family", "secret_type",
			"has_password", "has_private_key", "created_at", "updated_at"},
		Cells: map[Rule]Cell{
			RuleSingleRead:            ok(),
			RuleSingleMatchesList:     exc(ExcDetailProjectionDiffers, "單筆讀取為含掛載的詳情投影"),
			RuleHiddenTargetNotFound:  ok(),
			RuleListDataTotal:         ok(),
			RuleListPaging:            ok("選用分頁，每頁上限 200，回報實際套用的值"),
			RuleExactLookup:           ok(),
			RuleCreate201:             ok(),
			RuleSameEnvelope:          exc(ExcResponseEnvelopeMixed, "單筆讀取包在 data 內，建立回裸物件"),
			RuleWriteEqualsRead:       ok(),
			RuleUpdatePartial:         ok("選填欄位，缺欄位代表不動；秘密另走專屬路由"),
			RuleUpdateKeepsIdentity:   ok(),
			RuleDelete204:             ok(),
			RuleRecreateSameName:      ok(),
			RuleIdentityGlobal:        ok(),
			RuleTimeFields:            exc(ExcTimeFieldFormat, "時間只到秒（合法的 RFC 3339）"),
			RuleServerRewriteReturned: ok("名稱去除前後空白後的值出現在寫入回應"),
			RuleSecretWriteOnly:       exc(ExcSecretNoFingerprint, "只回是否已設定；私鑰回報公鑰指紋，未保存公鑰的既有私鑰、DSA 型別的私鑰，以及呼叫者沒有該憑證檢視能力時不帶；密碼沒有可比對的指紋"),
			RuleSecretClearPath:       exc(ExcSecretNoClearPath, "密碼、私鑰沒有清除途徑"),
			RuleDuplicate409:          ok(),
			RuleConcurrentWriteNo500:  pending("改密進行中回可辨識的衝突；並行修改備註抽樣未見內部錯誤，並行改密未查證"),
			RuleErrorEnvelope:         ok(),
			RuleResendNoChange:        ok("同一個備註原樣重送後修改時間不變"),
		},
	},
	{
		Name: "user", Title: "使用者",
		List:   []string{r("GET", "/users")},
		Read:   []string{r("GET", "/users/:id")},
		Create: []string{r("POST", "/users")},
		Update: []string{r("PUT", "/users/:id")},
		Delete: []string{r("DELETE", "/users/:id")},
		Paged:  true, ReadWrapped: true, ListPassthrough: "page_size=1000",
		Lookup: Lookup{Params: []string{"username"}, Match: MatchExact}, IdentityScope: ScopeGlobal,
		Secrets: []Secret{{Field: "password", ReadAs: "不輸出"}},
		Cells: map[Rule]Cell{
			RuleSingleRead:            ok(),
			RuleSingleMatchesList:     ok(),
			RuleHiddenTargetNotFound:  ok(),
			RuleListDataTotal:         ok(),
			RuleListPaging:            ok("每頁上限 1000，回報實際套用的值"),
			RuleExactLookup:           ok(),
			RuleCreate201:             ok(),
			RuleSameEnvelope:          ok("單筆讀取與建立都包在 data 內"),
			RuleWriteEqualsRead:       ok(),
			RuleUpdatePartial:         ok("空字串與缺欄位代表不動"),
			RuleUpdateKeepsIdentity:   ok(),
			RuleDelete204:             exc(ExcDeleteResponseShape, "200 並回空物件"),
			RuleRecreateSameName:      ok(),
			RuleIdentityGlobal:        ok(),
			RuleTimeFields:            ok(),
			RuleServerRewriteReturned: ok("電子郵件與來源網段正規化後的值出現在寫入回應"),
			RuleSecretWriteOnly:       exc(ExcSecretStateImplicit, "密碼永不輸出，也沒有是否已設定的欄位：本地的人類帳號建立時必設密碼，自動化帳號（kind 為 agent）與憑證外部化的帳號（external_credential 為真）沒有可用的本地密碼"),
			RuleSecretClearPath:       exc(ExcSecretNoClearPath, "本地密碼沒有單獨的清除途徑"),
			RuleDuplicate409:          ok("建立時使用者名稱重複回名稱衝突碼、電子郵件重複回電子郵件衝突碼，修改時電子郵件重複回電子郵件衝突碼，皆為 409"),
			RuleConcurrentWriteNo500:  ok("並行建立撞唯一索引時回與預查相同的衝突碼；並行修改電子郵件撞唯一索引回電子郵件衝突碼"),
			RuleErrorEnvelope:         ok(),
			RuleResendNoChange:        ok("同一個電子郵件與全名原樣重送後修改時間不變"),
		},
	},
	{
		Name: "user_group", Title: "使用者群組",
		List:   []string{r("GET", "/user-groups")},
		Read:   []string{r("GET", "/user-groups/:id")},
		Create: []string{r("POST", "/user-groups")},
		Update: []string{r("PUT", "/user-groups/:id"), r("PUT", "/user-groups/:id/members")},
		Delete: []string{r("DELETE", "/user-groups/:id")},
		Lookup: Lookup{Params: []string{"name"}, Match: MatchExact}, IdentityScope: ScopeGlobal,
		Cells: map[Rule]Cell{
			RuleSingleRead:            ok(),
			RuleSingleMatchesList:     ok(),
			RuleHiddenTargetNotFound:  ok(),
			RuleListDataTotal:         ok(),
			RuleListPaging:            na("列表不分頁"),
			RuleExactLookup:           ok(),
			RuleCreate201:             ok(),
			RuleSameEnvelope:          ok(),
			RuleWriteEqualsRead:       ok(),
			RuleUpdatePartial:         exc(ExcUpdateFullReplace, "名稱必填，說明直接覆寫；成員為整組替換"),
			RuleUpdateKeepsIdentity:   ok(),
			RuleDelete204:             exc(ExcDeleteResponseShape, "200 並回報連帶撤銷的授權筆數"),
			RuleRecreateSameName:      ok(),
			RuleIdentityGlobal:        ok(),
			RuleTimeFields:            ok(),
			RuleServerRewriteReturned: ok("不改寫輸入：名稱與說明的前後空白原樣保存與回傳"),
			RuleSecretWriteOnly:       na("沒有秘密欄位"),
			RuleSecretClearPath:       na("沒有秘密欄位"),
			RuleDuplicate409:          ok(),
			RuleConcurrentWriteNo500:  pending("並行修改、並行替換成員與並行同名建立抽樣未見內部錯誤；群組列鎖是否排隊未查證"),
			RuleErrorEnvelope:         ok(),
			RuleResendNoChange:        exc(ExcResendAdvances, "同樣的名稱與說明原樣重送也會推進修改時間"),
		},
	},
	{
		Name: "user_group_role_binding", Title: "使用者群組角色指派",
		List:   []string{r("GET", "/user-groups/:id/role-bindings")},
		Update: []string{r("PUT", "/user-groups/:id/role-bindings")},
		Lookup: Lookup{}, IdentityScope: "以群組識別定位整組指派，沒有自有識別",
		Cells: map[Rule]Cell{
			RuleSingleRead:            exc(ExcNoSingleRead, "整組指派以群組讀取，沒有單筆讀取"),
			RuleSingleMatchesList:     na("沒有單筆讀取"),
			RuleHiddenTargetNotFound:  na("沒有單筆讀取；看不到的群組其指派列表另由群組的範圍規則約束"),
			RuleListDataTotal:         ok(),
			RuleListPaging:            na("列表不分頁"),
			RuleExactLookup:           exc(ExcNoExactLookup, "沒有以角色查找的參數"),
			RuleCreate201:             na("沒有建立路由，整組以修改替換"),
			RuleSameEnvelope:          ok("讀取與修改都回 data 與總數"),
			RuleWriteEqualsRead:       ok(),
			RuleUpdatePartial:         exc(ExcUpdateFullReplace, "整組替換"),
			RuleUpdateKeepsIdentity:   ok("沒有自有識別"),
			RuleDelete204:             na("沒有刪除路由，以空集合替換"),
			RuleRecreateSameName:      na("沒有刪除路由"),
			RuleIdentityGlobal:        ok("沒有自有識別，以群組與角色定位"),
			RuleTimeFields:            exc(ExcNoTimeFields, "每一筆指派只有角色與範圍，沒有時間欄位"),
			RuleServerRewriteReturned: ok("請求內重複的角色去重並排序，寫入回應即為改寫後的值"),
			RuleSecretWriteOnly:       na("沒有秘密欄位"),
			RuleSecretClearPath:       na("沒有秘密欄位"),
			RuleDuplicate409:          ok("沒有建立路由也沒有自有識別，整組替換不會產生重複；請求內重複的角色由伺服器去重"),
			RuleConcurrentWriteNo500:  pending("並行替換抽樣未見內部錯誤，鎖未查證"),
			RuleErrorEnvelope:         ok(),
			RuleResendNoChange:        ok("原樣重送相同的角色集合，回應相同"),
		},
	},
	{
		Name: "authorization", Title: "授權規則",
		List:   []string{r("GET", "/authorizations")},
		Read:   []string{r("GET", "/authorizations/:id")},
		Create: []string{r("POST", "/authorizations"), r("POST", "/authorizations/batch")},
		Update: []string{r("PUT", "/authorizations/:id/accounts")},
		Delete: []string{r("DELETE", "/authorizations/:id")},
		Paged:  true, ListPassthrough: "page_size=100",
		Lookup: Lookup{}, IdentityScope: "同一主體、客體、等級唯一；識別全域唯一",
		Cells: map[Rule]Cell{
			RuleSingleRead:            ok(),
			RuleSingleMatchesList:     ok(),
			RuleHiddenTargetNotFound:  ok(),
			RuleListDataTotal:         ok(),
			RuleListPaging:            ok("每頁上限 100，回報實際套用的值"),
			RuleExactLookup:           exc(ExcNoExactLookup, "沒有名稱；自然鍵只能以篩選參數近似"),
			RuleCreate201:             exc(ExcCreateReturns200, "建立與批次建立都回 200"),
			RuleSameEnvelope:          ok(),
			RuleWriteEqualsRead:       ok(),
			RuleUpdatePartial:         ok("只能修改帳號範圍這一個欄位"),
			RuleUpdateKeepsIdentity:   ok(),
			RuleDelete204:             exc(ExcDeleteResponseShape, "200 並回空物件"),
			RuleRecreateSameName:      ok("同一主體、客體、等級可重建"),
			RuleIdentityGlobal:        ok(),
			RuleTimeFields:            exc(ExcNoTimeFields, "沒有修改時間"),
			RuleServerRewriteReturned: ok("帳號範圍正規化後的值出現在寫入回應"),
			RuleSecretWriteOnly:       na("沒有秘密欄位"),
			RuleSecretClearPath:       na("沒有秘密欄位"),
			RuleDuplicate409:          ok(),
			RuleConcurrentWriteNo500:  pending("並行重複建立抽樣回一筆成功、其餘為可辨識的衝突；交易內先查再建，鎖未查證"),
			RuleErrorEnvelope:         ok(),
			RuleResendNoChange:        pending("修改帳號範圍的原樣重送是否產生差異未查證"),
		},
	},
	{
		Name: "role_definition", Title: "自訂角色",
		List:   []string{r("GET", "/role-definitions")},
		Read:   []string{r("GET", "/role-definitions/:id")},
		Create: []string{r("POST", "/role-definitions"), r("POST", "/role-definitions/:id/copy")},
		Update: []string{r("PUT", "/role-definitions/:id")},
		Delete: []string{r("DELETE", "/role-definitions/:id")},
		Lookup: Lookup{Params: []string{"name"}, Match: MatchTrimmed}, IdentityScope: ScopeGlobal,
		CommonFields: []string{"id", "name", "description", "builtin_key", "locked", "definition_version",
			"template_role_id", "summary"},
		Cells: map[Rule]Cell{
			RuleSingleRead:            ok(),
			RuleSingleMatchesList:     exc(ExcDetailProjectionDiffers, "列表另帶唯讀判定欄位，單筆讀取另帶權限與依賴"),
			RuleHiddenTargetNotFound:  ok(),
			RuleListDataTotal:         ok(),
			RuleListPaging:            na("列表不分頁"),
			RuleExactLookup:           ok(),
			RuleCreate201:             ok(),
			RuleSameEnvelope:          ok(),
			RuleWriteEqualsRead:       ok(),
			RuleUpdatePartial:         exc(ExcUpdateFullReplace, "權限與期望版本必填"),
			RuleUpdateKeepsIdentity:   ok(),
			RuleDelete204:             ok(),
			RuleRecreateSameName:      ok("刪除時釋出名稱"),
			RuleIdentityGlobal:        ok(),
			RuleTimeFields:            exc(ExcNoTimeFields, "沒有時間欄位"),
			RuleServerRewriteReturned: ok("名稱去空白、權限去重排序後的值出現在寫入回應"),
			RuleSecretWriteOnly:       na("沒有秘密欄位"),
			RuleSecretClearPath:       na("沒有秘密欄位"),
			RuleDuplicate409:          ok("名稱重複與版本過期各有專屬機器碼"),
			RuleConcurrentWriteNo500:  ok("修改與刪除為樂觀鎖，版本過期回專屬機器碼；並行建立或改成同一個名稱撞唯一索引時回名稱衝突碼"),
			RuleErrorEnvelope:         ok(),
			RuleResendNoChange:        exc(ExcResendAdvances, "原樣重送會推進定義版本"),
		},
	},
	{
		Name: "group_role_mapping", Title: "外部群組對應到角色的規則",
		List: []string{r("GET", "/identity-sources/:type/:sourceId/role-mappings"),
			r("GET", "/identity-sources/:type/:sourceId/mappings")},
		Read: []string{r("GET", "/identity-sources/:type/:sourceId/role-mappings/:ruleId")},
		Create: []string{r("POST", "/identity-sources/:type/:sourceId/role-mappings"),
			r("POST", "/identity-sources/:type/:sourceId/mappings")},
		Update: []string{r("PUT", "/identity-sources/:type/:sourceId/role-mappings/:ruleId"),
			r("PUT", "/identity-sources/:type/:sourceId/mappings/:ruleId")},
		Delete: []string{r("DELETE", "/identity-sources/:type/:sourceId/role-mappings/:ruleId"),
			r("DELETE", "/identity-sources/:type/:sourceId/mappings/:ruleId")},
		ReadWrapped:   true,
		Lookup:        Lookup{Params: []string{"match_value", "role"}, Match: MatchTrimmed},
		IdentityScope: "同一來源內群組值與目標角色的組合唯一；識別只在同類規則內唯一",
		Cells:         mappingCells(),
	},
	{
		Name: "group_user_group_mapping", Title: "外部群組對應到使用者群組的規則",
		List:          []string{r("GET", "/identity-sources/:type/:sourceId/user-group-mappings")},
		Read:          []string{r("GET", "/identity-sources/:type/:sourceId/user-group-mappings/:ruleId")},
		Create:        []string{r("POST", "/identity-sources/:type/:sourceId/user-group-mappings")},
		Update:        []string{r("PUT", "/identity-sources/:type/:sourceId/user-group-mappings/:ruleId")},
		Delete:        []string{r("DELETE", "/identity-sources/:type/:sourceId/user-group-mappings/:ruleId")},
		ReadWrapped:   true,
		Lookup:        Lookup{Params: []string{"match_value", "user_group_id"}, Match: MatchTrimmed},
		IdentityScope: "同一來源內群組值與目標群組的組合唯一；識別只在同類規則內唯一",
		Cells:         mappingCells(),
	},
}

// mappingCells 兩類外部群組對應規則的格子相同。
func mappingCells() map[Rule]Cell {
	return map[Rule]Cell{
		RuleSingleRead:            ok(),
		RuleSingleMatchesList:     ok(),
		RuleHiddenTargetNotFound:  ok(),
		RuleListDataTotal:         exc(ExcListWithoutTotal, "列表只回 data"),
		RuleListPaging:            na("列表不分頁"),
		RuleExactLookup:           ok("同一參數出現多次回 400"),
		RuleCreate201:             ok(),
		RuleSameEnvelope:          ok("讀取與寫入都包在 data 內"),
		RuleWriteEqualsRead:       ok(),
		RuleUpdatePartial:         exc(ExcUpdateFullReplace, "整筆替換"),
		RuleUpdateKeepsIdentity:   exc(ExcUpdateReissuesIdentity, "修改群組值或目標時以新規則取代舊規則"),
		RuleDelete204:             ok(),
		RuleRecreateSameName:      ok(),
		RuleIdentityGlobal:        exc(ExcIdentityUniqueInKind, "識別只在同類規則內唯一"),
		RuleTimeFields:            ok(),
		RuleServerRewriteReturned: ok("群組值去除前後空白後的值出現在寫入回應"),
		RuleSecretWriteOnly:       na("沒有秘密欄位"),
		RuleSecretClearPath:       na("沒有秘密欄位"),
		RuleDuplicate409:          ok(),
		RuleConcurrentWriteNo500:  exc(ExcConcurrentRetriable, "目錄型來源不排隊，回可重試的衝突"),
		RuleErrorEnvelope:         ok(),
		RuleResendNoChange:        exc(ExcResendAdvances, "原樣重送會推進修改時間"),
	}
}

// laterResources 初始名單之後列入的資源。新增的列放在這裡，不得引用僅限初始名單的例外，也不得使用待查。
var laterResources = []Resource{}

// initialNames 凍結的初始名單：本表生效時列入登錄表的資源。這份名單不得增加；新資源一律列在 laterResources。
var initialNames = []string{
	"asset_node", "asset", "asset_account", "credential", "user", "user_group", "user_group_role_binding",
	"authorization", "role_definition", "group_role_mapping", "group_user_group_mapping",
}

// Resources 登錄表全部的列（初始名單在前）。回傳副本。
func Resources() []Resource {
	out := make([]Resource, 0, len(initialResources)+len(laterResources))
	for _, src := range append(append([]Resource{}, initialResources...), laterResources...) {
		cp := src
		cp.Cells = make(map[Rule]Cell, len(src.Cells))
		for k, v := range src.Cells {
			cp.Cells[k] = v
		}
		out = append(out, cp)
	}
	return out
}

// InitialNames 凍結的初始名單副本。
func InitialNames() []string { return append([]string{}, initialNames...) }

// IsInitial 資源是否在初始名單內。
func IsInitial(name string) bool {
	for _, n := range initialNames {
		if n == name {
			return true
		}
	}
	return false
}

// Category 路由歸屬的類別。
type Category string

const (
	// CategoryManaged 某個納管資源的某個操作（由登錄表導出，不在歸屬表手填）。
	CategoryManaged Category = "managed_resource"
	// CategoryNonResource 非資源的查詢或動作（選項、預覽、試算、自我查驗等）。
	CategoryNonResource Category = "non_resource"
	// CategoryReadOnlyFamily 唯讀的資源家族：家族內每條路由的性質都必須是讀。
	CategoryReadOnlyFamily Category = "read_only_family"
	// CategoryUnmanagedFamily 已開放寫入但尚未納管的既有家族：家族名必須在凍結名單內。
	CategoryUnmanagedFamily Category = "unmanaged_family"
)

// Attribution 一條路由的歸屬。Family 在家族類別必填，非資源類別為空。
type Attribution struct {
	Category Category `json:"category"`
	Family   string   `json:"family,omitempty"`
}

func nonRes() Attribution           { return Attribution{Category: CategoryNonResource} }
func readOnly(f string) Attribution { return Attribution{Category: CategoryReadOnlyFamily, Family: f} }
func unmanaged(f string) Attribution {
	return Attribution{Category: CategoryUnmanagedFamily, Family: f}
}

// frozenUnmanagedFamilies 已開放寫入但尚未納管的既有家族（凍結）。新增家族要改這份名單；
// 家族改為納管時，把路由移到登錄表並從名單移除。
var frozenUnmanagedFamilies = map[string]string{
	"asset_bulk":                "資產批次操作與匯入",
	"asset_tags":                "資產標籤",
	"asset_executor":            "堡壘機專用帳號",
	"account_inventory":         "帳號盤點",
	"change_secret_candidates":  "改密候選",
	"change_secret_plans":       "改密計劃",
	"credential_mounts":         "共用憑證的掛載、範圍、歸屬與輪替",
	"external_groups":           "外部群組字典",
	"notification_channels":     "通知通道",
	"oidc_providers":            "OIDC 身分提供者",
	"policy_groups":             "政策群組",
	"rotation_report_schedules": "輪替報表排程",
	"security_policies":         "安全政策",
	"syslog_settings":           "日誌轉發",
	"user_actions":              "使用者的狀態類動作",
	"user_role_assignments":     "使用者角色指派",
	"user_external_identities":  "使用者外部身分綁定",
	"alert_rules":               "告警規則",
	"approver_scopes":           "簽核範圍",
}

// FrozenUnmanagedFamilies 凍結名單副本（值為說明）。
func FrozenUnmanagedFamilies() map[string]string {
	out := make(map[string]string, len(frozenUnmanagedFamilies))
	for k, v := range frozenUnmanagedFamilies {
		out[k] = v
	}
	return out
}

// attributions 不屬於納管資源的開放路由的歸屬。納管資源的路由由登錄表導出，不重複填在這裡。
var attributions = map[string]Attribution{
	// 非資源的查詢或動作
	r("GET", "/api-tokens/verify"):                                              nonRes(),
	r("GET", "/approver-scopes/approver-options"):                               nonRes(),
	r("GET", "/approver-scopes/target-options"):                                 nonRes(),
	r("GET", "/assets/access-policy-overrides"):                                 nonRes(),
	r("GET", "/authorizations/effective-assets"):                                nonRes(),
	r("GET", "/authorizations/effective-users"):                                 nonRes(),
	r("GET", "/authorizations/self-subjects"):                                   nonRes(),
	r("GET", "/authorizations/subject-options"):                                 nonRes(),
	r("GET", "/authorizations/target-options"):                                  nonRes(),
	r("GET", "/dashboard/retention-adjustments"):                                nonRes(),
	r("GET", "/identity-sources/:type/:sourceId/user-group-usage/:userGroupId"): nonRes(),
	r("GET", "/role-assignment-options"):                                        nonRes(),
	r("POST", "/role-assignment-previews"):                                      nonRes(),
	r("GET", "/role-definitions/descriptors"):                                   nonRes(),
	r("GET", "/role-definitions/:id/preview-capabilities"):                      nonRes(),
	r("POST", "/role-definitions/summary"):                                      nonRes(),
	r("POST", "/schedules/next-runs"):                                           nonRes(),
	r("GET", "/users/:id/permission-overview"):                                  nonRes(),
	r("GET", "/users/:id/permission-overview/assets/:asset_id"):                 nonRes(),
	r("GET", "/users/local-admin-count"):                                        nonRes(),
	r("POST", "/users/source-policy/check"):                                     nonRes(),
	r("GET", "/user-groups/:id/authorization-count"):                            nonRes(),
	r("GET", "/user-groups/:id/external-mappings"):                              nonRes(),

	// 唯讀的資源家族
	r("GET", "/assets/:id/host-key"):             readOnly("host_keys"),
	r("GET", "/change-secret-batches"):           readOnly("change_secret_batches"),
	r("GET", "/change-secret-batches/:id"):       readOnly("change_secret_batches"),
	r("GET", "/change-secret-batches/targets"):   readOnly("change_secret_batches"),
	r("GET", "/change-secret-batches/usernames"): readOnly("change_secret_batches"),
	r("GET", "/identity-sources"):                readOnly("identity_sources"),
	r("GET", "/ldap-directory"):                  readOnly("ldap_directory"),
	r("GET", "/ldap-directory/status"):           readOnly("ldap_directory"),
	r("GET", "/offsite-storage/failures"):        readOnly("offsite_storage"),
	r("GET", "/offsite-storage/profiles"):        readOnly("offsite_storage"),
	r("GET", "/offsite-storage/settings"):        readOnly("offsite_storage"),
	r("GET", "/offsite-storage/status"):          readOnly("offsite_storage"),
	r("GET", "/roles"):                           readOnly("roles"),
	r("GET", "/system-alert-types"):              readOnly("system_alert_types"),

	// 已開放寫入但尚未納管的既有家族
	r("POST", "/assets/batch/delete"):   unmanaged("asset_bulk"),
	r("POST", "/assets/batch/move"):     unmanaged("asset_bulk"),
	r("POST", "/assets/batch/tags"):     unmanaged("asset_bulk"),
	r("POST", "/assets/import"):         unmanaged("asset_bulk"),
	r("POST", "/assets/import/preview"): unmanaged("asset_bulk"),

	r("GET", "/assets/tags"):         unmanaged("asset_tags"),
	r("POST", "/assets/tags/delete"): unmanaged("asset_tags"),
	r("POST", "/assets/tags/rename"): unmanaged("asset_tags"),

	r("GET", "/assets/:id/executor"):             unmanaged("asset_executor"),
	r("DELETE", "/assets/:id/executor"):          unmanaged("asset_executor"),
	r("GET", "/assets/:id/executor/login-check"): unmanaged("asset_executor"),
	r("GET", "/assets/:id/executor/public-key"):  unmanaged("asset_executor"),

	r("GET", "/account-inventory/findings"):                               unmanaged("account_inventory"),
	r("GET", "/assets/:id/account-inventory"):                             unmanaged("account_inventory"),
	r("POST", "/assets/:id/account-inventory/findings/:findingId/ignore"): unmanaged("account_inventory"),
	r("POST", "/assets/:id/account-inventory/findings/:findingId/reopen"): unmanaged("account_inventory"),

	r("GET", "/change-secret-candidates"):        unmanaged("change_secret_candidates"),
	r("DELETE", "/change-secret-candidates/:id"): unmanaged("change_secret_candidates"),

	r("GET", "/change-secret-plans"):              unmanaged("change_secret_plans"),
	r("POST", "/change-secret-plans"):             unmanaged("change_secret_plans"),
	r("PUT", "/change-secret-plans/:id"):          unmanaged("change_secret_plans"),
	r("DELETE", "/change-secret-plans/:id"):       unmanaged("change_secret_plans"),
	r("GET", "/change-secret-plans/:id/records"):  unmanaged("change_secret_plans"),
	r("POST", "/change-secret-plans/reauthorize"): unmanaged("change_secret_plans"),

	r("POST", "/credentials/:id/bindings"):                 unmanaged("credential_mounts"),
	r("DELETE", "/credentials/:id/bindings/:accountId"):    unmanaged("credential_mounts"),
	r("POST", "/credentials/:id/impact-confirmations"):     unmanaged("credential_mounts"),
	r("POST", "/credentials/:id/scope"):                    unmanaged("credential_mounts"),
	r("POST", "/credentials/ownership"):                    unmanaged("credential_mounts"),
	r("PUT", "/assets/:id/accounts/:accountId/credential"): unmanaged("credential_mounts"),
	r("GET", "/credentials/:id/rotations/:rid"):            unmanaged("credential_mounts"),
	r("POST", "/credentials/:id/rotations/:rid/abandon"):   unmanaged("credential_mounts"),

	r("GET", "/identity-sources/:type/:sourceId/external-groups"):                  unmanaged("external_groups"),
	r("PUT", "/identity-sources/:type/:sourceId/external-groups/:externalGroupId"): unmanaged("external_groups"),

	r("GET", "/notification-channels"):                unmanaged("notification_channels"),
	r("POST", "/notification-channels"):               unmanaged("notification_channels"),
	r("PUT", "/notification-channels/:id"):            unmanaged("notification_channels"),
	r("DELETE", "/notification-channels/:id"):         unmanaged("notification_channels"),
	r("GET", "/notification-channels/:id/deliveries"): unmanaged("notification_channels"),

	r("GET", "/oidc-providers"):            unmanaged("oidc_providers"),
	r("GET", "/oidc-providers/:id"):        unmanaged("oidc_providers"),
	r("GET", "/oidc-providers/:id/status"): unmanaged("oidc_providers"),
	r("POST", "/oidc-providers"):           unmanaged("oidc_providers"),
	r("PUT", "/oidc-providers/:id"):        unmanaged("oidc_providers"),
	r("DELETE", "/oidc-providers/:id"):     unmanaged("oidc_providers"),

	r("GET", "/policy-groups"):                                     unmanaged("policy_groups"),
	r("POST", "/policy-groups"):                                    unmanaged("policy_groups"),
	r("GET", "/policy-groups/:code"):                               unmanaged("policy_groups"),
	r("PUT", "/policy-groups/:code"):                               unmanaged("policy_groups"),
	r("DELETE", "/policy-groups/:code"):                            unmanaged("policy_groups"),
	r("PUT", "/policy-groups/:code/enabled"):                       unmanaged("policy_groups"),
	r("PUT", "/policy-groups/:code/clauses/:clause_no"):            unmanaged("policy_groups"),
	r("DELETE", "/policy-groups/:code/clauses/:clause_no"):         unmanaged("policy_groups"),
	r("PUT", "/policy-groups/:code/clauses/:clause_no/annotation"): unmanaged("policy_groups"),
	r("POST", "/policy-groups/:code/clauses/:clause_no/confirm"):   unmanaged("policy_groups"),

	r("GET", "/rotation-report/schedules"):        unmanaged("rotation_report_schedules"),
	r("POST", "/rotation-report/schedules"):       unmanaged("rotation_report_schedules"),
	r("PUT", "/rotation-report/schedules/:id"):    unmanaged("rotation_report_schedules"),
	r("DELETE", "/rotation-report/schedules/:id"): unmanaged("rotation_report_schedules"),

	r("GET", "/security-policies"):           unmanaged("security_policies"),
	r("GET", "/security-policies/defs/:key"): unmanaged("security_policies"),
	r("PUT", "/security-policies"):           unmanaged("security_policies"),

	r("GET", "/syslog-settings"): unmanaged("syslog_settings"),
	r("PUT", "/syslog-settings"): unmanaged("syslog_settings"),

	r("PUT", "/users/:id/status"):            unmanaged("user_actions"),
	r("PUT", "/users/:id/password"):          unmanaged("user_actions"),
	r("POST", "/users/:id/unlock"):           unmanaged("user_actions"),
	r("PUT", "/users/:id/inactivity-exempt"): unmanaged("user_actions"),
	r("POST", "/users/:id/mfa/disable"):      unmanaged("user_actions"),
	r("POST", "/users/:id/external-only"):    unmanaged("user_actions"),

	r("GET", "/users/:id/role-bindings"): unmanaged("user_role_assignments"),
	r("PUT", "/users/:id/roles"):         unmanaged("user_role_assignments"),
	r("POST", "/users/:id/roles/:role"):  unmanaged("user_role_assignments"),
	r("POST", "/users/:id/roles/pin"):    unmanaged("user_role_assignments"),

	r("GET", "/users/:id/external-identities"):                                 unmanaged("user_external_identities"),
	r("POST", "/users/:id/external-identities"):                                unmanaged("user_external_identities"),
	r("DELETE", "/users/:id/external-identities/:identityId"):                  unmanaged("user_external_identities"),
	r("POST", "/users/:id/external-identities/:identityId/unbind-and-disable"): unmanaged("user_external_identities"),

	r("GET", "/alert-rules"):        unmanaged("alert_rules"),
	r("POST", "/alert-rules"):       unmanaged("alert_rules"),
	r("PUT", "/alert-rules/:id"):    unmanaged("alert_rules"),
	r("DELETE", "/alert-rules/:id"): unmanaged("alert_rules"),

	r("GET", "/approver-scopes"):        unmanaged("approver_scopes"),
	r("POST", "/approver-scopes"):       unmanaged("approver_scopes"),
	r("DELETE", "/approver-scopes/:id"): unmanaged("approver_scopes"),
}

// Attributions 不屬於納管資源的開放路由的歸屬副本。
func Attributions() map[string]Attribution {
	out := make(map[string]Attribution, len(attributions))
	for k, v := range attributions {
		out[k] = v
	}
	return out
}

// Op 納管資源的操作。
type Op string

const (
	OpList   Op = "list"
	OpRead   Op = "read"
	OpCreate Op = "create"
	OpUpdate Op = "update"
	OpDelete Op = "delete"
)

// Routes 一列各操作的路由。
func (res Resource) Routes() map[Op][]string {
	return map[Op][]string{OpList: res.List, OpRead: res.Read, OpCreate: res.Create, OpUpdate: res.Update, OpDelete: res.Delete}
}

// ManagedRouteOwners 由登錄表導出的納管路由歸屬：路由鍵 → 「資源 操作」（一條路由出現在多處時全部列出、已排序）。
func ManagedRouteOwners() map[string][]string {
	out := map[string][]string{}
	for _, res := range Resources() {
		for op, keys := range res.Routes() {
			for _, k := range keys {
				out[k] = append(out[k], res.Name+" "+string(op))
			}
		}
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out
}
