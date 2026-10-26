package main

import (
	"encoding/json"
	"go/ast"
	"go/token"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/modules/authz/disclosure"
)

// 最小揭露例外的封閉登錄守衛。
//
// 範圍外、無權與不存在的目標一律同形回應；回應中能提及範圍外資訊的例外只有
// 登錄（internal/modules/authz/disclosure）列出的四條。本檔釘住兩件事：
//
//	登錄本身：恰四條、三條計數類的輸出欄名固定、輸出值為整數。
//	登錄以外：沒有第二個地方能寫出範圍外欄位，也沒有地方能繞過 disclosure.Count 填值。
//
// 第二件事的主防線是型別：disclosure.Value 只有登錄套件能建構非零值。型別管不到
// 的是 `map[string]any`／params 字面值組裝，本檔以 AST 補漏，判準：
//
//	(a) 以 `out_of_scope` 開頭（不分大小寫）的字串作為 map 鍵（複合字面值的鍵、索引式）
//	    或 JSON 欄名（struct tag；無 tag 時即 Go 欄位名），只准出現在登錄套件。鍵先解析
//	    成字串值再判定：括號、函式內以 const／var／:= 宣告的識別字、同包或他包的套件層
//	    const／var，以及沿識別字串接的常數鏈都會解析。作為「值」出現的字串（例如
//	    原因碼、狀態值）不在此限。
//	(b) 以登錄輸出欄名常數為鍵時，值必須直接是 disclosure.Count 呼叫，且第一個引數是
//	    該欄位所屬例外的具名常數。
//	(c) 函式內引用計數類規則碼時，該函式內 params 的 `count` 鍵同 (b)。
//	(d) 複合字面值帶列級旗標原因 out_of_scope_nodes 時，同一字面值的 count 同 (b)。
//
// 審計細節鍵 disclosure.AuditDetailOutOfScopeCount 只共用欄名：寫成字面值違反 (a)，
// 引用常數則不受 (b) 的值限制（審計細節是內部留痕）。
//
// 不防清單（語法層判定的射程之外）：
//
//	- 手寫 JSON 本文片段，例如格式化字串裡的 `{"out_of_scope_…":%d}`。
//	- 字串拼接或格式化產生的鍵、不帶 out_of_scope 前綴的名稱、去掉底線的駝峰欄位名。
//	- 列級旗標的原因值經變數傳遞、旗標結構體的 count 以其他 Go 欄位名宣告：這兩處
//	  由型別承擔，旗標 DTO 的 count 欄位宣告為 disclosure.Value。
//	- 經變數或函式參數傳遞的錯誤碼；常數鏈中途經他包引用的部分。
//	- 以 unsafe／reflect 改寫未匯出欄位。
//
// 這些形態的揭露由範圍拒絕本身與範圍內外同形測試承擔。本守衛通過只代表沒有以
// out_of_scope 為名的登錄外欄位，不代表回應沒有其他揭露。

const (
	discRegistryDir   = "internal/modules/authz/disclosure"
	discRegistryPath  = auditPointModulePath + "/" + discRegistryDir
	discAPIErrorDir   = "internal/apierror"
	discAPIErrorPath  = auditPointModulePath + "/" + discAPIErrorDir
	discFieldPrefix   = "out_of_scope"
	discCountKey      = "count"
	discCountFuncName = "Count"
)

// wantDisclosureEntry 登錄的期望內容（具名常數 → 輸出欄名與承載計數的規則碼）。
type wantDisclosureEntry struct {
	fields []string
	codes  []string
	// phrases 例外說明必含的片語（nil 不核對）。
	phrases []string
}

var wantDisclosureEntries = map[string]wantDisclosureEntry{
	"OutOfScopeAssetCount": {
		fields:  []string{"out_of_scope_asset_count", "count"},
		codes:   []string{"RULE_CREDENTIAL_IMPACT_CONFIRMATION_REQUIRED"},
		phrases: []string{"共用憑證影響範圍外資產的匿名台數", "權限一覽連線區段"},
	},
	"OutOfScopeNodeCount": {
		fields: []string{"out_of_scope_node_count", "count"},
		codes:  []string{"RULE_ASSET_HAS_OUT_OF_SCOPE_NODES"},
	},
	"NodeDeleteScopeReferenced": {
		fields: []string{"count"},
		codes:  []string{"RULE_NODE_SCOPE_REFERENCED"},
	},
	"GlobalNameConflict": {},
}

// wantDisclosureFields 三個固定輸出欄名。
var wantDisclosureFields = []string{"count", "out_of_scope_asset_count", "out_of_scope_node_count"}

// discKnownValueConsts 既有、以 out_of_scope 為值但不是欄名的常數。掃描必須看見它們
// （證明常數收集有在運作），且不得回報（證明判準只認鍵與欄名）。
var discKnownValueConsts = []string{
	"internal/modules/audit/daily_review_query.go:DailyReviewDayOutOfScope",
	"internal/modules/authz/scope_result.go:ScopeReasonOutOfScope",
}

// 生產碼掃描的下限：低於此數代表鍵或 tag 的辨識已失真，「零違規」不成立。
const (
	minDiscLiteralMapKeys = 1000
	minDiscJSONTags       = 1000
)

func TestMinimalDisclosureRegistry(t *testing.T) {
	root := auditPointModuleRoot(t)
	regFiles := discParseRegistry(t, root)

	t.Run("登錄恰四條且欄名固定", func(t *testing.T) {
		discCheckRegistryContent(t, regFiles)
	})

	t.Run("生產碼只經登錄輸出範圍外欄位", func(t *testing.T) {
		files, scanned := parseModuleFiles(t, root)
		if scanned < minScannedGoFiles {
			t.Fatalf("只掃到 %d 個非測試 .go 檔（下限 %d）：掃描根已失真", scanned, minScannedGoFiles)
		}
		sawRegistry := 0
		for _, pf := range files {
			if discInRegistry(pf.Rel) {
				sawRegistry++
			}
		}
		if sawRegistry == 0 {
			t.Fatalf("掃描結果中沒有登錄套件 %s 的檔：掃描根或登錄位置已失真", discRegistryDir)
		}
		sc := newDiscScanner(t, regFiles)
		res := sc.scan(files)
		t.Logf("掃描 %d 檔：字串字面值 map 鍵 %d、JSON tag %d、以 %s 為值的套件層常數或變數 %v",
			scanned, res.literalMapKeys, res.jsonTags, discFieldPrefix, res.prefixedConsts)
		if res.literalMapKeys < minDiscLiteralMapKeys || res.jsonTags < minDiscJSONTags {
			t.Fatalf("字串字面值 map 鍵 %d（下限 %d）、JSON tag %d（下限 %d）：辨識已失真",
				res.literalMapKeys, minDiscLiteralMapKeys, res.jsonTags, minDiscJSONTags)
		}
		seen := map[string]bool{}
		for _, c := range res.prefixedConsts {
			seen[c] = true
		}
		for _, c := range discKnownValueConsts {
			if !seen[c] {
				t.Errorf("掃描沒有看見既有常數 %s：常數收集失真，判準可能在空集合上通過", c)
			}
		}
		for _, v := range res.violations {
			t.Errorf("%s:%d %s\n  回應中提及範圍外資訊只准經揭露登錄（%s）：欄名引用登錄常數或嵌入登錄的載體型別，"+
				"值以 disclosure.Count(<例外>, n) 產出。登錄以外的範圍外揭露一律視為缺陷；"+
				"確有新的例外時先在登錄新增條目並經設計核可。", v.file, v.line, v.msg, discRegistryDir)
		}
	})

	t.Run("合成原始碼反例皆被回報", func(t *testing.T) {
		sc := newDiscScanner(t, regFiles)
		apiErr := discSynthetic(t, "internal/apierror/codes_synthetic.go", `package apierror
var (
	CodeAssetHasOutOfScopeNodes = register("RULE_ASSET_HAS_OUT_OF_SCOPE_NODES", Descriptor{})
	CodeNodeScopeReferenced     = register("RULE_NODE_SCOPE_REFERENCED", Descriptor{})
	CodeUnrelated               = register("RULE_UNRELATED", Descriptor{})
)
`)
		bad := map[string]string{
			// 反例一：登錄外寫出範圍外計數欄位（三種寫法各一檔）
			"internal/api/synthetic_literal_key.go": `package api
import "github.com/gin-gonic/gin"
func h(c *gin.Context, n int) { c.JSON(200, gin.H{"id": 1, "out_of_scope_asset_count": n}) }
`,
			"internal/api/synthetic_index_key.go": `package api
func h(n int) map[string]any { m := map[string]any{}; m["out_of_scope_node_count"] = n; return m }
`,
			"internal/api/synthetic_json_tag.go": `package api
type row struct { ID int ` + "`json:\"id\"`" + `; Hidden int ` + "`json:\"out_of_scope_node_count,omitempty\"`" + ` }
`,
			"internal/api/synthetic_const_key.go": `package api
const hiddenKey = "out_of_scope_count"
func h(n string) map[string]string { return map[string]string{hiddenKey: n} }
`,
			// 鍵經解析才看得出前綴的寫法：套件層 var、函式內宣告、常數鏈、括號
			"internal/api/synthetic_var_key.go": `package api
import "github.com/gin-gonic/gin"
var hiddenKey = "out_of_scope_node_count"
func h(c *gin.Context, n int) { c.JSON(200, gin.H{"id": 1, hiddenKey: n}) }
`,
			"internal/api/synthetic_local_const_key.go": `package api
func h(n int) map[string]any {
	const k = "out_of_scope_node_count"
	return map[string]any{k: n}
}
`,
			"internal/api/synthetic_local_define_key.go": `package api
func h(n int) map[string]any {
	m := map[string]any{}
	k := "out_of_scope_asset_count"
	m[k] = n
	return m
}
`,
			"internal/api/synthetic_const_chain_key.go": `package api
const (
	aliasKey = baseKey
	baseKey  = "out_of_scope_node_count"
)
func h(n int) map[string]any { return map[string]any{aliasKey: n} }
`,
			"internal/api/synthetic_paren_key.go": `package api
func h(n int) map[string]any { return map[string]any{("out_of_scope_node_count"): n} }
`,
			// 大小寫異名：JSON 鍵不分大小寫同樣可讀
			"internal/api/synthetic_case_literal_key.go": `package api
func h(n int) map[string]any { return map[string]any{"Out_Of_Scope_count": n} }
`,
			"internal/api/synthetic_case_const_key.go": `package api
const hiddenKey = "OUT_OF_SCOPE_COUNT"
func h(n int) map[string]any { m := map[string]any{}; m[hiddenKey] = n; return m }
`,
			"internal/api/synthetic_case_json_tag.go": `package api
type row struct { ID int ` + "`json:\"id\"`" + `; Hidden int ` + "`json:\"Out_Of_Scope_Node_Count\"`" + ` }
`,
			"internal/api/synthetic_untagged_field.go": `package api
type row struct { ID int ` + "`json:\"id\"`" + `; Out_of_scope_node_count int }
`,
			// 反例二：引用合法欄名常數，但值是節點 ID 陣列或自行計算的整數
			"internal/api/synthetic_field_ids.go": `package api
import "github.com/custodexa/backend/internal/modules/authz/disclosure"
func h(ids []uint) map[string]any { return map[string]any{disclosure.FieldOutOfScopeNodeCount: ids} }
`,
			"internal/api/synthetic_field_int.go": `package api
import "github.com/custodexa/backend/internal/modules/authz/disclosure"
func h(ids []uint) map[string]any { m := map[string]any{}; m[disclosure.FieldOutOfScopeAssetCount] = len(ids); return m }
`,
			"internal/api/synthetic_field_wrong_kind.go": `package api
import "github.com/custodexa/backend/internal/modules/authz/disclosure"
func h(n int) map[string]any { return map[string]any{disclosure.FieldOutOfScopeAssetCount: disclosure.Count(disclosure.OutOfScopeNodeCount, n)} }
`,
			// 反例三：計數類規則碼的 params count 不經 disclosure.Count
			"internal/api/synthetic_rule_params.go": `package api
import "github.com/custodexa/backend/internal/apierror"
func h(c *gin.Context, nodes []uint) {
	apierror.Respond(c, 409, apierror.CodeAssetHasOutOfScopeNodes, map[string]any{"count": len(nodes)})
}
`,
			"internal/api/synthetic_rule_params_var.go": `package api
import "github.com/custodexa/backend/internal/apierror"
func h(c *gin.Context, n int) {
	params := map[string]any{}
	params["count"] = n
	apierror.Respond(c, 409, apierror.CodeNodeScopeReferenced, params)
}
`,
			// 列級旗標：原因為 out_of_scope_nodes 的 count 不經 disclosure.Count
			"internal/api/synthetic_flag_count.go": `package api
import "github.com/custodexa/backend/internal/modules/authz/disclosure"
func h(n int) map[string]any { return map[string]any{"reason": disclosure.FlagReasonOutOfScopeNodes, "count": n} }
`,
			// 以 . import 登錄套件會讓常數失去套件前綴，判準無從辨認
			"internal/api/synthetic_dot_import.go": `package api
import . "github.com/custodexa/backend/internal/modules/authz/disclosure"
func h() any { return Count(OutOfScopeNodeCount, 1) }
`,
		}
		good := map[string]string{
			// 審計細節以欄名常數寫 out_of_scope_count：合法
			"internal/api/synthetic_audit_detail.go": `package api
import (
	"strconv"
	"github.com/custodexa/backend/internal/modules/authz/disclosure"
)
func h(details map[string]string, n int) map[string]string {
	details[disclosure.AuditDetailOutOfScopeCount] = strconv.Itoa(n)
	return map[string]string{"denial": "scope", disclosure.AuditDetailOutOfScopeCount: strconv.Itoa(n)}
}
`,
			// 經登錄輸出：合法
			"internal/api/synthetic_registry_ok.go": `package api
import (
	"github.com/custodexa/backend/internal/apierror"
	dsc "github.com/custodexa/backend/internal/modules/authz/disclosure"
)
type row struct { ID int ` + "`json:\"id\"`" + `; dsc.NodeCountField }
func h(c *gin.Context, n int) map[string]any {
	apierror.Respond(c, 409, apierror.CodeNodeScopeReferenced, map[string]any{dsc.FieldCount: dsc.Count(dsc.NodeDeleteScopeReferenced, n)})
	_ = row{ID: 1, NodeCountField: dsc.NodeCountField{OutOfScopeNodeCount: dsc.NodeCountValue{Value: dsc.Count(dsc.OutOfScopeNodeCount, n)}}}
	_ = map[string]any{"reason": dsc.FlagReasonOutOfScopeNodes, "count": dsc.Count(dsc.OutOfScopeNodeCount, n)}
	return map[string]any{dsc.FieldOutOfScopeNodeCount: dsc.Count(dsc.OutOfScopeNodeCount, n)}
}
`,
			// 以 out_of_scope 為值的常數（狀態、原因碼）：不是欄名
			"internal/api/synthetic_value_const.go": `package api
const DayOutOfScope = "out_of_scope"
type detail struct { Status string ` + "`json:\"status\"`" + ` }
func h(n int) any {
	_ = map[string]any{"status": DayOutOfScope, "reason": "out_of_scope", "count": n}
	return detail{Status: DayOutOfScope}
}
`,
			// 經解析的鍵與值：以 out_of_scope 為值的 var 與區域變數、登錄常數的區域別名
			"internal/api/synthetic_resolved_ok.go": `package api
import "github.com/custodexa/backend/internal/modules/authz/disclosure"
var dayOutOfScope = "out_of_scope"
const statusKey = "status"
type view struct { Status string ` + "`json:\"status\"`" + `; OutOfScopeHint string ` + "`json:\"-\"`" + ` }
func h(n int) any {
	reason := dayOutOfScope
	key := disclosure.FieldOutOfScopeNodeCount
	_ = view{Status: reason}
	_ = map[string]any{statusKey: reason, ("reason"): "Out_Of_Scope"}
	return map[string]any{key: disclosure.Count(disclosure.OutOfScopeNodeCount, n)}
}
`,
			// 與計數類規則碼無關的函式裡的 count：不受限
			"internal/api/synthetic_unrelated_count.go": `package api
import "github.com/custodexa/backend/internal/apierror"
func h(c *gin.Context, n int) {
	apierror.Respond(c, 409, apierror.CodeUnrelated, map[string]any{"count": n})
}
`,
		}
		for rel, src := range bad {
			res := sc.scan([]*parsedFile{apiErr, discSynthetic(t, rel, src)})
			if !res.reported(rel) {
				t.Errorf("合成反例 %s 未被回報：守衛對此形態失效", rel)
				continue
			}
			for _, v := range res.violations {
				t.Logf("反例 %s → %s:%d %s", rel, v.file, v.line, v.msg)
			}
		}
		for rel, src := range good {
			res := sc.scan([]*parsedFile{apiErr, discSynthetic(t, rel, src)})
			for _, v := range res.violations {
				t.Errorf("合法用法 %s 被誤報：%s:%d %s", rel, v.file, v.line, v.msg)
			}
		}
	})
}

// ── 登錄本身 ─────────────────────────────────────────────────────────────

func discCheckRegistryContent(t *testing.T, regFiles []*parsedFile) {
	t.Helper()
	entries := disclosure.Entries()
	if len(entries) != len(wantDisclosureEntries) {
		t.Fatalf("登錄有 %d 條，應恰為 %d 條", len(entries), len(wantDisclosureEntries))
	}
	kinds := map[disclosure.Kind]bool{}
	fieldSet := map[string]bool{}
	for _, e := range entries {
		want, ok := wantDisclosureEntries[e.Name]
		if !ok {
			t.Errorf("登錄條目 %s 不在期望表內", e.Name)
			continue
		}
		if kinds[e.Kind] {
			t.Errorf("登錄條目 %s 的 Kind 值 %d 重複", e.Name, e.Kind)
		}
		kinds[e.Kind] = true
		if e.Kind.String() != e.Name {
			t.Errorf("Kind(%d).String()＝%q，應為 %q", e.Kind, e.Kind.String(), e.Name)
		}
		if !reflect.DeepEqual(discNilIfEmpty(e.Fields), discNilIfEmpty(want.fields)) {
			t.Errorf("%s 的輸出欄名 %v，應為 %v", e.Name, e.Fields, want.fields)
		}
		if !reflect.DeepEqual(discNilIfEmpty(e.RuleCodes), discNilIfEmpty(want.codes)) {
			t.Errorf("%s 的規則碼 %v，應為 %v", e.Name, e.RuleCodes, want.codes)
		}
		if strings.TrimSpace(e.Exception) == "" || strings.TrimSpace(e.Wiring) == "" {
			t.Errorf("%s 缺例外說明或輸出點位置", e.Name)
		}
		for _, p := range want.phrases {
			if !strings.Contains(e.Exception, p) {
				t.Errorf("%s 的例外說明缺片語 %q", e.Name, p)
			}
		}
		for _, f := range e.Fields {
			fieldSet[f] = true
		}
		v := disclosure.Count(e.Kind, 4)
		if len(want.fields) == 0 {
			if v.Valid() {
				t.Errorf("%s 不輸出欄位，Count 卻產出了合法值", e.Name)
			}
			continue
		}
		for _, f := range e.Fields {
			b, err := json.Marshal(map[string]any{f: v})
			if err != nil {
				t.Errorf("%s 的 %s 序列化失敗: %v", e.Name, f, err)
				continue
			}
			var got map[string]json.RawMessage
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatalf("解回 %s 失敗: %v", b, err)
			}
			if n, err := strconv.Atoi(string(got[f])); err != nil || n != 4 {
				t.Errorf("%s 的 %s 輸出 %s，應為整數 4", e.Name, f, got[f])
			}
		}
	}
	var fields []string
	for f := range fieldSet {
		fields = append(fields, f)
	}
	sort.Strings(fields)
	if !reflect.DeepEqual(fields, wantDisclosureFields) {
		t.Errorf("輸出欄名集合 %v，應恰為 %v", fields, wantDisclosureFields)
	}

	// 原始碼層：Kind 具名常數恰四個、Field 常數恰三個且值等於欄名集合。
	// 只看 Entries 會漏掉「新增了常數卻沒登記」：那個常數照樣能傳給 Count。
	kindConsts, fieldConsts := discRegistryDecls(regFiles)
	var wantNames []string
	for n := range wantDisclosureEntries {
		wantNames = append(wantNames, n)
	}
	sort.Strings(wantNames)
	if !reflect.DeepEqual(kindConsts, wantNames) {
		t.Errorf("登錄套件宣告的 Kind 常數 %v，應恰為 %v", kindConsts, wantNames)
	}
	var fieldVals []string
	for _, v := range fieldConsts {
		fieldVals = append(fieldVals, v)
	}
	sort.Strings(fieldVals)
	if !reflect.DeepEqual(fieldVals, wantDisclosureFields) {
		t.Errorf("登錄套件宣告的 Field 常數值 %v，應恰為 %v", fieldVals, wantDisclosureFields)
	}
}

func discNilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

// discRegistryDecls 回傳登錄套件中型別為 Kind 的常數名（含 iota 延續）與 Field* 常數。
func discRegistryDecls(files []*parsedFile) (kinds []string, fields map[string]string) {
	fields = map[string]string{}
	for _, pf := range files {
		for _, d := range pf.File.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			current := ""
			for _, s := range gd.Specs {
				vs := s.(*ast.ValueSpec)
				switch {
				case vs.Type != nil:
					current = discTypeName(vs.Type)
				case len(vs.Values) > 0:
					current = ""
				}
				for i, n := range vs.Names {
					if current == "Kind" {
						kinds = append(kinds, n.Name)
					}
					if strings.HasPrefix(n.Name, "Field") && i < len(vs.Values) {
						if lit, ok := discStringLit(vs.Values[i]); ok {
							fields[n.Name] = lit
						}
					}
				}
			}
		}
	}
	sort.Strings(kinds)
	return kinds, fields
}

func discTypeName(e ast.Expr) string {
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}
