package notifycat

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"

	"go/types"

	"github.com/custodexa/backend/internal/model"
	"golang.org/x/tools/go/packages"
)

// 詞庫完備性守衛。
//
// 與 checkCatalog 同體例：純函式 checkLexicons 供「刻意破壞的副本」做敏感度
// 自檢——只斷言正本為綠不能證明守衛會紅。
//
// 涵蓋四件事：
//  1. 宣告的每個詞庫在三語都存在、鍵集雙向相等、值非空。
//  2. 語系檔不得有未宣告的詞庫（多鍵＝死譯文，長年無人清）。
//  3. ParamSpec.Lexicon 必須指向已宣告詞庫；enum+lexicon 者其 Enum 集合
//     必須等於詞庫鍵集（registry 與詞庫任一側漏掉都紅）。
//  4. 與 model 常數對照（TestCauseEnumMatchesModel/TestSeverityLexicon…）：
//     光「引用 model 常數」只擋改名，擋不住新增。

const (
	vLexMissingLang = "lexicon_missing_in_locale"
	vLexKeyMismatch = "lexicon_key_mismatch"
	vLexEmptyPhrase = "lexicon_empty_phrase"
	vLexUndeclared  = "lexicon_undeclared"
	vLexParamRef    = "lexicon_param_ref"
	vLexEnumSync    = "lexicon_enum_out_of_sync"
)

// checkLexicons 回傳全部違規（空 slice＝通過）。純函式：只讀入參。
func checkLexicons(
	reg map[Event]EventSpec,
	lex map[string]map[Lexicon]map[string]string,
	declared []Lexicon,
	langs []string,
	refLang string,
) []string {
	var v []string
	add := func(kind, format string, args ...any) {
		v = append(v, kind+": "+fmt.Sprintf(format, args...))
	}

	declaredSet := map[Lexicon]bool{}
	for _, name := range declared {
		declaredSet[name] = true
	}
	if len(declaredSet) == 0 {
		add(vLexUndeclared, "未宣告任何詞庫——所有下游檢查將無條件通過")
		return v
	}

	// 1/2. 三語鍵集相等、值非空、無多餘詞庫
	refKeys := map[Lexicon]map[string]bool{}
	for _, name := range declared {
		refKeys[name] = map[string]bool{}
		for k := range lex[refLang][name] {
			refKeys[name][k] = true
		}
		if len(refKeys[name]) == 0 {
			add(vLexMissingLang, "參考語系 %s 的詞庫 %s 為空或缺檔", refLang, name)
		}
	}
	for _, lang := range langs {
		byLex, ok := lex[lang]
		if !ok {
			add(vLexMissingLang, "語系 %s 完全缺詞庫檔", lang)
			continue
		}
		for _, name := range declared {
			entries, ok := byLex[name]
			if !ok {
				add(vLexMissingLang, "語系 %s 缺詞庫 %s", lang, name)
				continue
			}
			got := map[string]bool{}
			for k, phrase := range entries {
				got[k] = true
				if strings.TrimSpace(phrase) == "" {
					add(vLexEmptyPhrase, "語系 %s 詞庫 %s 的鍵 %s 短語為空", lang, name, k)
				}
			}
			if !sameSet(refKeys[name], got) {
				add(vLexKeyMismatch, "語系 %s 詞庫 %s 鍵集與 %s 不一致：%v vs %v",
					lang, name, refLang, sortedKeys(got), sortedKeys(refKeys[name]))
			}
		}
		for name := range byLex {
			if !declaredSet[name] {
				add(vLexUndeclared, "語系 %s 有未宣告的詞庫 %s", lang, name)
			}
		}
	}

	// 3. ParamSpec.Lexicon 引用與 enum 同步
	for ev, spec := range reg {
		for _, p := range spec.Params {
			if p.Lexicon == "" {
				continue
			}
			if !declaredSet[p.Lexicon] {
				add(vLexParamRef, "%s 的參數 %s 引用未宣告詞庫 %s", ev, p.Name, p.Lexicon)
				continue
			}
			if p.Kind != KindEnum {
				continue // opaque+lexicon 允許（值域開放，缺鍵回吐機器碼）
			}
			enumSet := map[string]bool{}
			for _, e := range p.Enum {
				enumSet[e] = true
			}
			if !sameSet(enumSet, refKeys[p.Lexicon]) {
				add(vLexEnumSync, "%s 的參數 %s：Enum 與詞庫 %s 鍵集不一致：%v vs %v",
					ev, p.Name, p.Lexicon, sortedKeys(enumSet), sortedKeys(refKeys[p.Lexicon]))
			}
		}
	}

	sort.Strings(v)
	return v
}

// TestLexiconCompleteness 正本必須零違規。
func TestLexiconCompleteness(t *testing.T) {
	got := checkLexicons(registry, lexiconCat, Lexicons(), SupportedLangs, DefaultLang)
	if len(got) > 0 {
		t.Fatalf("詞庫完備性違規 %d 項:\n  %s", len(got), strings.Join(got, "\n  "))
	}
	if len(causeEnum) < 12 {
		t.Fatalf("cause 碼只有 %d 個，少於已實查的 16 個生產者原因——疑似漏註冊", len(causeEnum))
	}
}

// TestLexiconGuardSensitivity 敏感度自檢：每種破壞都必須被對應種類的檢查抓到。
func TestLexiconGuardSensitivity(t *testing.T) {
	cases := []struct {
		name   string
		kind   string
		mutate func(reg map[Event]EventSpec, lex map[string]map[Lexicon]map[string]string) []Lexicon
	}{
		{"語系缺詞庫", vLexMissingLang, func(_ map[Event]EventSpec, lex map[string]map[Lexicon]map[string]string) []Lexicon {
			delete(lex["ja-JP"], LexiconSeverity)
			return Lexicons()
		}},
		{"語系缺鍵", vLexKeyMismatch, func(_ map[Event]EventSpec, lex map[string]map[Lexicon]map[string]string) []Lexicon {
			delete(lex["en-US"][LexiconCause], model.CauseRecordingProbeFailed)
			return Lexicons()
		}},
		{"短語為空", vLexEmptyPhrase, func(_ map[Event]EventSpec, lex map[string]map[Lexicon]map[string]string) []Lexicon {
			lex["ja-JP"][LexiconAlertState][AlertStateBlocked] = "  "
			return Lexicons()
		}},
		{"未宣告詞庫", vLexUndeclared, func(_ map[Event]EventSpec, lex map[string]map[Lexicon]map[string]string) []Lexicon {
			lex["zh-TW"]["ghost"] = map[string]string{"a": "b"}
			return Lexicons()
		}},
		{"參數引用不存在的詞庫", vLexParamRef, func(reg map[Event]EventSpec, _ map[string]map[Lexicon]map[string]string) []Lexicon {
			spec := reg[EventTest]
			spec.Params = append(append([]ParamSpec(nil), spec.Params...),
				ParamSpec{Name: "ghost", Kind: KindOpaque, Lexicon: "nowhere"})
			reg[EventTest] = spec
			return Lexicons()
		}},
		{"enum 與詞庫不同步", vLexEnumSync, func(reg map[Event]EventSpec, _ map[string]map[Lexicon]map[string]string) []Lexicon {
			spec := reg[EventAuditFailure]
			params := append([]ParamSpec(nil), spec.Params...)
			for i := range params {
				if params[i].Name == "cause_code" {
					params[i].Enum = append(append([]string(nil), params[i].Enum...), "phantom_cause")
				}
			}
			spec.Params = params
			reg[EventAuditFailure] = spec
			return Lexicons()
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg, lex := cloneRegistry(), cloneLexicons()
			declared := tc.mutate(reg, lex)
			got := checkLexicons(reg, lex, declared, SupportedLangs, DefaultLang)
			if !hasKind(got, tc.kind) {
				t.Fatalf("破壞 %q 後守衛未回報 %s；實得: %v", tc.name, tc.kind, got)
			}
		})
	}
}

func cloneLexicons() map[string]map[Lexicon]map[string]string {
	out := make(map[string]map[Lexicon]map[string]string, len(lexiconCat))
	for lang, byLex := range lexiconCat {
		lm := make(map[Lexicon]map[string]string, len(byLex))
		for name, entries := range byLex {
			em := make(map[string]string, len(entries))
			for k, phrase := range entries {
				em[k] = phrase
			}
			lm[name] = em
		}
		out[lang] = lm
	}
	return out
}

// TestPhraseFallbacks 未知語系落 zh-TW；未知鍵回吐機器碼而非空字串。
func TestPhraseFallbacks(t *testing.T) {
	zh := Phrase(DefaultLang, LexiconCause, model.CauseRecordingFileMissing)
	if got := Phrase("de-DE", LexiconCause, model.CauseRecordingFileMissing); got != zh {
		t.Fatalf("未知語系應 fallback zh-TW，got %q want %q", got, zh)
	}
	if got := Phrase("en-US", LexiconCause, "no_such_cause"); got != "no_such_cause" {
		t.Fatalf("未知鍵應回吐機器碼，got %q", got)
	}
	if got := Phrase("en-US", "no_such_lexicon", "k"); got != "k" {
		t.Fatalf("未知詞庫應回吐機器碼，got %q", got)
	}
	if got := Phrase("en-US", LexiconSeverity, ""); got != "" {
		t.Fatalf("空鍵應回空字串，got %q", got)
	}
}

// TestCauseEnumMatchesModel cause 詞庫與 model 的 Cause* 常數集合相等。
//
// 以 go/types 列舉 model 套件常數，故「新增 cause 碼但沒補三語」會被抓到
// （比照 TestMechanismEnumMatchesModel；單靠引用常數只能擋改名）。
func TestCauseEnumMatchesModel(t *testing.T) {
	want := modelConstValues(t, "Cause", func(name string) bool {
		// CauseParamDetail 是參數鍵名不是原因碼，排除
		return name != "CauseParamDetail"
	})
	if len(want) == 0 {
		t.Fatal("model 套件找不到任何 Cause* 常數——比對基準失效（防假綠）")
	}

	got := map[string]bool{}
	for _, c := range causeEnum {
		got[c] = true
	}
	if !sameSet(want, got) {
		t.Fatalf("cause enum 與 model 常數不一致:\n  model: %v\n  notifycat: %v",
			sortedKeys(want), sortedKeys(got))
	}

	inLexicon := map[string]bool{}
	for k := range lexiconCat[DefaultLang][LexiconCause] {
		inLexicon[k] = true
	}
	if !sameSet(want, inLexicon) {
		t.Fatalf("cause 詞庫鍵集與 model 常數不一致:\n  model: %v\n  詞庫: %v",
			sortedKeys(want), sortedKeys(inLexicon))
	}
}

// TestSeverityLexiconMatchesModel severity 詞庫與 model 的 AlertSeverity* 常數相等。
func TestSeverityLexiconMatchesModel(t *testing.T) {
	want := modelConstValues(t, "AlertSeverity", func(string) bool { return true })
	if len(want) == 0 {
		t.Fatal("model 套件找不到任何 AlertSeverity* 常數——比對基準失效（防假綠）")
	}
	got := map[string]bool{}
	for k := range lexiconCat[DefaultLang][LexiconSeverity] {
		got[k] = true
	}
	if !sameSet(want, got) {
		t.Fatalf("severity 詞庫與 model 常數不一致:\n  model: %v\n  詞庫: %v",
			sortedKeys(want), sortedKeys(got))
	}
}

// modelConstValues 以 go/types 取 model 套件中指定前綴的字串常數值集合。
func modelConstValues(t *testing.T, prefix string, keep func(name string) bool) map[string]bool {
	t.Helper()
	pkgs := loadBackend(t)

	var modelPkg *packages.Package
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.PkgPath == "github.com/custodexa/backend/internal/model" && p.Types != nil {
			modelPkg = p
		}
	})
	if modelPkg == nil {
		t.Fatal("找不到 internal/model 套件（比對基準缺失）")
	}

	out := map[string]bool{}
	scope := modelPkg.Types.Scope()
	for _, name := range scope.Names() {
		if !strings.HasPrefix(name, prefix) || !keep(name) {
			continue
		}
		c, ok := scope.Lookup(name).(*types.Const)
		if !ok {
			continue
		}
		v, err := strconv.Unquote(c.Val().String())
		if err != nil {
			t.Fatalf("model.%s 常數值非字串: %s", name, c.Val().String())
		}
		out[v] = true
	}
	return out
}
