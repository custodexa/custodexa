// Package disclosure 是「回應中可提及管理範圍外資訊」的封閉登錄。
//
// 範圍外、無權與不存在的目標一律同形回應；本登錄列出的是僅有的例外，恰四條。
// 三條計數類例外的輸出欄名由本套件固定，其值只能經 Count 產生；第四條（全域
// 唯一名稱衝突）不輸出任何欄位，只宣告「同形 409、無參數」是刻意的設計。
//
// # 值的來源如何受控
//
// Count 回傳 Value。Value 的欄位全數未匯出，其他套件只拿得到它的零值
// （`disclosure.Value{}` 或 `var v disclosure.Value`），而零值無法序列化
// （MarshalJSON 回錯誤），所以「自己填一個數字假裝是登錄產生的計數」在編譯期
// 就做不到，退一步寫零值也會在輸出時大聲失敗。回應結構體的計數欄位宣告為
// Value，型別系統即擋住所有繞過。兩個可嵌入的載體另以欄位型別在序列化時核對
// 所裝 Value 的種類：別種例外的計數放進載體欄位同樣回錯誤。
//
// 型別系統管不到的位置是 `map[string]any`／params 字面值組裝：那裡的值是 any。
// 這部分由靜態守衛補漏：以本套件的欄名常數（或計數類規則碼的 params `count`）
// 為鍵的值，必須直接是 Count 呼叫；以 `out_of_scope` 開頭的字串字面值作為 map
// 鍵或 JSON 欄名，只准出現在本套件。
//
// 刻意不防的：以 unsafe 或 reflect 改寫未匯出欄位。那是存心繞過而非誤用，
// 不在型別防護的射程內。
//
// 本套件不 import 任何專案套件，可被任何層引用而不引入依賴環。
package disclosure

import (
	"errors"
	"fmt"
	"strconv"
)

// Kind 一條最小揭露例外。合法值只有下列四個具名常數。
type Kind uint8

// 四條例外。零值刻意不用，避免未初始化的 Kind 被誤認為某條例外。
const (
	// OutOfScopeAssetCount 共用憑證影響範圍外資產的匿名台數。
	OutOfScopeAssetCount Kind = iota + 1
	// OutOfScopeNodeCount 多歸屬資產「另有 N 個範圍外節點」的匿名計數
	// （單位：該操作權限點範圍外的歸屬節點數）。
	OutOfScopeNodeCount
	// NodeDeleteScopeReferenced 節點被管理範圍引用而無法刪除：不列引用者，只給筆數。
	NodeDeleteScopeReferenced
	// GlobalNameConflict 全域唯一名稱衝突：衝突對象在範圍內或外回應逐位元相同，
	// 不輸出任何欄位。
	GlobalNameConflict
)

// 三個固定輸出欄名。刻意宣告為無型別字串常數：才能直接作為
// `map[string]any`／`gin.H` 的鍵。
const (
	// FieldOutOfScopeAssetCount 回應欄：範圍外資產台數。
	FieldOutOfScopeAssetCount = "out_of_scope_asset_count"
	// FieldOutOfScopeNodeCount 回應欄：範圍外歸屬節點數。
	FieldOutOfScopeNodeCount = "out_of_scope_node_count"
	// FieldCount 列級旗標（原因為 FlagReasonOutOfScopeNodes）的 count，
	// 以及計數類規則碼的 params `count`。
	FieldCount = "count"
)

// AssetCountField 可嵌入回應結構體的範圍外台數欄。
//
// JSON 欄名寫在 struct tag，而 tag 只能是字面值；為了讓欄名字面值只出現在本套件，
// 回應結構體以嵌入本型別取得這個欄位（encoding/json 會把嵌入結構體的欄位攤平到
// 外層）。本型別刻意不實作 MarshalJSON：嵌入型別的方法會提升到外層，那會讓外層
// 整個只序列化成這一欄。欄位的種類核對因此放在欄位型別 AssetCountValue 上。
type AssetCountField struct {
	OutOfScopeAssetCount AssetCountValue `json:"out_of_scope_asset_count"`
}

// NodeCountField 可嵌入回應結構體的範圍外歸屬節點數欄；嵌入理由同 AssetCountField。
type NodeCountField struct {
	OutOfScopeNodeCount NodeCountValue `json:"out_of_scope_node_count"`
}

// AssetCountValue 載體 AssetCountField 的欄位值：裝一個 Value，序列化時核對其種類為
// OutOfScopeAssetCount。Value 本身不知道自己被放在哪個欄位，別種例外的計數放進
// 這一欄（單位錯置）只能在這一層擋下。
//
//	disclosure.AssetCountField{OutOfScopeAssetCount: disclosure.AssetCountValue{Value: disclosure.Count(disclosure.OutOfScopeAssetCount, n)}}
type AssetCountValue struct{ Value }

// NodeCountValue 載體 NodeCountField 的欄位值；序列化時核對種類為 OutOfScopeNodeCount。
type NodeCountValue struct{ Value }

// MarshalJSON 種類不是 OutOfScopeAssetCount 時回錯誤；零值同 Value。
func (v AssetCountValue) MarshalJSON() ([]byte, error) {
	return v.marshalAs(OutOfScopeAssetCount)
}

// MarshalJSON 種類不是 OutOfScopeNodeCount 時回錯誤；零值同 Value。
func (v NodeCountValue) MarshalJSON() ([]byte, error) {
	return v.marshalAs(OutOfScopeNodeCount)
}

// errWrongKind 載體欄位裝了別種例外的計數。
var errWrongKind = errors.New("disclosure: 載體欄位所裝計數的種類與欄位所屬例外不符")

// marshalAs 先套零值判定，再核對種類。
func (v Value) marshalAs(want Kind) ([]byte, error) {
	if !v.Valid() {
		return nil, errUnbuilt
	}
	if v.kind != want {
		return nil, fmt.Errorf("%w：欄位屬 %s，所裝為 %s", errWrongKind, want, v.kind)
	}
	return v.MarshalJSON()
}

// FlagReasonOutOfScopeNodes 列級動作旗標的原因值：該動作因範圍外歸屬節點而不可用。
// 帶此原因的旗標，其 count 屬 OutOfScopeNodeCount。
const FlagReasonOutOfScopeNodes = "out_of_scope_nodes"

// AuditDetailOutOfScopeCount 審計細節鍵：範圍外影響筆數的內部留痕。
//
// 它只共用欄名，不是對外輸出欄位：審計細節是 map[string]string，值不受 Value
// 型別限制。其他套件寫這個鍵時引用本常數，不自行寫字面值。
const AuditDetailOutOfScopeCount = "out_of_scope_count"

// 計數類規則碼。登錄只以字串持有，不 import 錯誤碼套件（保持本套件為葉節點）；
// 守衛以這些值辨認哪些碼的 params `count` 必須來自 Count。
const (
	ruleAssetHasOutOfScopeNodes              = "RULE_ASSET_HAS_OUT_OF_SCOPE_NODES"
	ruleNodeScopeReferenced                  = "RULE_NODE_SCOPE_REFERENCED"
	ruleCredentialImpactConfirmationRequired = "RULE_CREDENTIAL_IMPACT_CONFIRMATION_REQUIRED"
)

// Entry 一條例外的登錄內容。
type Entry struct {
	Kind Kind
	// Name 具名常數的名稱（穩定識別，供守衛與測試比對）。
	Name string
	// Exception 例外內容。
	Exception string
	// Fields 本例外允許的輸出欄名；空表示不輸出任何欄位。
	Fields []string
	// RuleCodes params `count` 承載本例外計數的規則碼。
	RuleCodes []string
	// Wiring 輸出點所在的位置（接線前即固定，接線者照此落點）。
	Wiring string
}

// Entries 回傳完整登錄（每次新建，呼叫端修改不影響登錄本身）。
func Entries() []Entry {
	return []Entry{
		{
			Kind:      OutOfScopeAssetCount,
			Name:      "OutOfScopeAssetCount",
			Exception: "共用憑證影響範圍外資產的匿名台數",
			Fields:    []string{FieldOutOfScopeAssetCount, FieldCount},
			RuleCodes: []string{ruleCredentialImpactConfirmationRequired},
			Wiring: "共用憑證的影響範圍回應（列表、詳情、影響確認）、輪替成員清單、改密計畫的列表與建立／更新回應、刪除被引用阻擋的回應欄、" +
				"宣告新秘密與遠端輪替要求先確認的規則碼 params",
		},
		{
			Kind:      OutOfScopeNodeCount,
			Name:      "OutOfScopeNodeCount",
			Exception: "多歸屬資產另有 N 個範圍外節點",
			Fields:    []string{FieldOutOfScopeNodeCount, FieldCount},
			RuleCodes: []string{ruleAssetHasOutOfScopeNodes},
			Wiring: "資產列表與詳情的回應欄、列級動作旗標的 count（原因 " +
				FlagReasonOutOfScopeNodes + "）、資產刪除與停用被擋的規則碼 params",
		},
		{
			Kind:      NodeDeleteScopeReferenced,
			Name:      "NodeDeleteScopeReferenced",
			Exception: "節點被管理範圍引用而無法刪除，只給引用筆數",
			Fields:    []string{FieldCount},
			RuleCodes: []string{ruleNodeScopeReferenced},
			Wiring:    "節點刪除被引用阻擋的規則碼 params",
		},
		{
			Kind:      GlobalNameConflict,
			Name:      "GlobalNameConflict",
			Exception: "全域唯一名稱衝突同形（固化無參數 409）",
			Wiring:    "名稱唯一性衝突的錯誤回應",
		},
	}
}

// String 回傳具名常數的名稱；不在登錄內的值回 "Kind(<n>)"。
func (k Kind) String() string {
	for _, e := range Entries() {
		if e.Kind == k {
			return e.Name
		}
	}
	return "Kind(" + strconv.Itoa(int(k)) + ")"
}

// countsAllowed 只有三條計數類例外能產出計數。
func (k Kind) countsAllowed() bool {
	switch k {
	case OutOfScopeAssetCount, OutOfScopeNodeCount, NodeDeleteScopeReferenced:
		return true
	}
	return false
}

// Value 經登錄產出的計數。只有本套件能建構非零值。
type Value struct {
	kind Kind
	n    int
}

// errUnbuilt 零值或不合法參數產出的 Value 被序列化。
var errUnbuilt = errors.New("disclosure: 計數值未經 Count 以合法的例外與非負整數建構")

// Count 產出一條計數類例外的輸出值。
//
// kind 不是計數類例外（GlobalNameConflict 或登錄外的值）或 n 為負時，回傳零值：
// 零值序列化即失敗，誤用在第一次輸出時就會被看見，而不是悄悄送出一個數字。
func Count(kind Kind, n int) Value {
	if !kind.countsAllowed() || n < 0 {
		return Value{}
	}
	return Value{kind: kind, n: n}
}

// Kind 這個值屬於哪條例外；零值回 0。
func (v Value) Kind() Kind { return v.kind }

// Valid 是否經 Count 以合法參數建構。
func (v Value) Valid() bool { return v.kind != 0 }

// MarshalJSON 輸出整數；零值回錯誤。
func (v Value) MarshalJSON() ([]byte, error) {
	if !v.Valid() {
		return nil, errUnbuilt
	}
	return []byte(strconv.Itoa(v.n)), nil
}

// DisclosedCount 供錯誤碼參數驗證辨認：回整數與是否經 Count 以合法參數建構。
func (v Value) DisclosedCount() (int, bool) { return v.n, v.Valid() }

// String 供文案插值：輸出整數；零值回空字串。
func (v Value) String() string {
	if !v.Valid() {
		return ""
	}
	return strconv.Itoa(v.n)
}
