package notifycat

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// 目錄完備性守衛。
//
// 檢查以純函式 checkCatalog 實作，故可用「刻意破壞的副本」做敏感度自檢
// （TestCatalogGuardSensitivity）——避免守衛本身失效而長年假綠：
// 只斷言正本為綠不能證明守衛會紅。

// 違規種類前綴（敏感度自檢逐案例斷言種類，防「A 檢查命中掩蓋 B 檢查失效」）。
const (
	vRegistryEmpty   = "registry_empty"
	vSpecInvalid     = "spec_invalid"
	vMissingInLang   = "missing_in_locale"
	vExtraInLang     = "extra_in_locale"
	vVariantMismatch = "variant_mismatch"
	vEmptyTemplate   = "empty_template"
	vBracket         = "bracket_malformed"
	vUndeclared      = "undeclared_placeholder"
	vPlaceholderX    = "placeholder_mismatch"
	vOptionalX       = "optional_mismatch"
	vRequiredUnused  = "required_param_unused"
	vDeadParam       = "dead_param"
)

type tmplFacts struct {
	all      map[string]bool // 全部佔位符
	optional map[string]bool // 位於 [...] 可選段內的佔位符
	bad      []string        // 括號語法問題
}

// parseTemplate 抽取模板的佔位符事實與括號語法問題。
func parseTemplate(tmpl string) tmplFacts {
	f := tmplFacts{all: map[string]bool{}, optional: map[string]bool{}}
	depth := 0
	segCount := 0
	runes := []rune(tmpl)
	for i := 0; i < len(runes); i++ {
		switch runes[i] {
		case '[':
			if depth > 0 {
				f.bad = append(f.bad, "巢狀可選段")
			}
			depth++
			segCount = 0
		case ']':
			if depth == 0 {
				f.bad = append(f.bad, "多餘的 ]")
				continue
			}
			depth--
			if segCount == 0 {
				f.bad = append(f.bad, "可選段內無佔位符（恆保留，等同無意義）")
			}
		case '{':
			end := indexRuneFrom(runes, i+1, '}')
			if end < 0 {
				f.bad = append(f.bad, "未閉合的 {")
				continue
			}
			name := string(runes[i+1 : end])
			if name == "" {
				f.bad = append(f.bad, "空佔位符名")
			}
			f.all[name] = true
			if depth > 0 {
				f.optional[name] = true
				segCount++
			}
			i = end
		case '}':
			f.bad = append(f.bad, "多餘的 }")
		}
	}
	if depth != 0 {
		f.bad = append(f.bad, "未閉合的 [")
	}
	return f
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// checkCatalog 回傳全部違規（空 slice＝通過）。純函式：只讀入參，不碰套件變數。
func checkCatalog(
	reg map[Event]EventSpec,
	cat map[string]map[Event]map[string]message,
	langs []string,
	refLang string,
) []string {
	var v []string
	add := func(kind, format string, args ...any) {
		v = append(v, kind+": "+fmt.Sprintf(format, args...))
	}

	if len(reg) == 0 {
		add(vRegistryEmpty, "registry 為空——所有下游檢查將無條件通過")
		return v
	}

	// 1. EventSpec 自身合法性
	for ev, spec := range reg {
		seen := map[string]bool{}
		for _, p := range spec.Params {
			if seen[p.Name] {
				add(vSpecInvalid, "%s 參數 %s 重複宣告", ev, p.Name)
			}
			seen[p.Name] = true
			if p.Kind == KindEnum && len(p.Enum) == 0 {
				add(vSpecInvalid, "%s 參數 %s 為 enum 卻無允許清單", ev, p.Name)
			}
			if p.Kind != KindEnum && len(p.Enum) > 0 {
				add(vSpecInvalid, "%s 參數 %s 非 enum 卻帶允許清單", ev, p.Name)
			}
			if p.Kind != KindEnum && p.Kind != KindInt && p.Kind != KindOpaque {
				add(vSpecInvalid, "%s 參數 %s 種類 %q 不合法", ev, p.Name, p.Kind)
			}
		}
		if spec.VariantParam != "" {
			p, ok := spec.param(spec.VariantParam)
			if !ok || p.Kind != KindEnum || !p.Required {
				add(vSpecInvalid, "%s 的 VariantParam %s 必須是必要的 enum 參數",
					ev, spec.VariantParam)
			}
		}
	}

	// 2. 每個語系：鍵集雙向相等、variant 集相等、模板非空、括號合法、佔位符已宣告
	facts := map[string]map[string]tmplFacts{} // lang -> "event|variant|field" -> facts
	for _, lang := range langs {
		byEvent, ok := cat[lang]
		if !ok {
			add(vMissingInLang, "語系 %s 完全缺檔", lang)
			continue
		}
		facts[lang] = map[string]tmplFacts{}
		for ev, spec := range reg {
			variants, ok := byEvent[ev]
			if !ok {
				add(vMissingInLang, "語系 %s 缺事件 %s", lang, ev)
				continue
			}
			want := spec.variants()
			gotSet := map[string]bool{}
			for name := range variants {
				gotSet[name] = true
			}
			wantSet := map[string]bool{}
			for _, name := range want {
				wantSet[name] = true
				if !gotSet[name] {
					add(vVariantMismatch, "語系 %s 事件 %s 缺 variant %s", lang, ev, name)
				}
			}
			for name := range gotSet {
				if !wantSet[name] {
					add(vVariantMismatch, "語系 %s 事件 %s 多出 variant %s", lang, ev, name)
				}
			}
			for name, msg := range variants {
				if strings.TrimSpace(msg.Title) == "" || strings.TrimSpace(msg.Text) == "" {
					add(vEmptyTemplate, "語系 %s 事件 %s variant %s 的 title/text 有空值",
						lang, ev, name)
				}
				for field, tmpl := range map[string]string{"title": msg.Title, "text": msg.Text} {
					f := parseTemplate(tmpl)
					for _, b := range f.bad {
						add(vBracket, "語系 %s %s/%s/%s：%s", lang, ev, name, field, b)
					}
					for _, ph := range sortedKeys(f.all) {
						if _, ok := spec.param(ph); !ok {
							add(vUndeclared, "語系 %s %s/%s/%s 佔位符 {%s} 未在 EventSpec 宣告",
								lang, ev, name, field, ph)
						}
					}
					facts[lang][ev.key(name, field)] = f
				}
			}
		}
		for ev := range byEvent {
			if _, ok := reg[ev]; !ok {
				add(vExtraInLang, "語系 %s 有 registry 未註冊的事件 %s", lang, ev)
			}
		}
	}

	// 3. 跨語系：同鍵佔位符集合一致、可選性一致
	ref, ok := facts[refLang]
	if !ok {
		add(vMissingInLang, "參考語系 %s 不可用，跨語系比對無法進行", refLang)
		return v
	}
	for _, lang := range langs {
		if lang == refLang {
			continue
		}
		for key, rf := range ref {
			lf, ok := facts[lang][key]
			if !ok {
				continue // 缺鍵已於步驟 2 記錄
			}
			if !sameSet(rf.all, lf.all) {
				add(vPlaceholderX, "%s 的 %s 佔位符與 %s 不一致：%v vs %v",
					lang, key, refLang, sortedKeys(lf.all), sortedKeys(rf.all))
			}
			if !sameSet(rf.optional, lf.optional) {
				add(vOptionalX, "%s 的 %s 可選段佔位符與 %s 不一致：%v vs %v",
					lang, key, refLang, sortedKeys(lf.optional), sortedKeys(rf.optional))
			}
		}
	}

	// 4. 參數使用面：必要參數（VariantParam 除外）須現身於每個 variant；
	//    宣告的參數不得全無模板使用（死參數）
	for _, lang := range langs {
		if facts[lang] == nil {
			continue
		}
		for ev, spec := range reg {
			usedAnywhere := map[string]bool{}
			for _, variant := range spec.variants() {
				used := map[string]bool{}
				for _, field := range []string{"title", "text"} {
					for ph := range facts[lang][ev.key(variant, field)].all {
						used[ph] = true
						usedAnywhere[ph] = true
					}
				}
				for _, p := range spec.Params {
					if p.Required && p.Name != spec.VariantParam && !used[p.Name] {
						add(vRequiredUnused, "語系 %s %s/%s 未使用必要參數 %s",
							lang, ev, variant, p.Name)
					}
				}
			}
			for _, p := range spec.Params {
				if p.Name == spec.VariantParam {
					continue
				}
				if !usedAnywhere[p.Name] {
					add(vDeadParam, "語系 %s 事件 %s 的參數 %s 未被任何 variant 使用",
						lang, ev, p.Name)
				}
			}
		}
	}

	sort.Strings(v)
	return v
}

func (e Event) key(variant, field string) string {
	return string(e) + "|" + variant + "|" + field
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// TestCatalogCompleteness 正本必須零違規。
func TestCatalogCompleteness(t *testing.T) {
	if got := checkCatalog(registry, catalog, SupportedLangs, DefaultLang); len(got) > 0 {
		t.Fatalf("目錄完備性違規 %d 項:\n  %s", len(got), strings.Join(got, "\n  "))
	}
	if len(registry) < 12 {
		t.Fatalf("registry 只有 %d 個事件，少於已知的 12 個組字點——疑似漏註冊", len(registry))
	}
	for _, lang := range SupportedLangs {
		if len(catalog[lang]) != len(registry) {
			t.Fatalf("語系 %s 事件數 %d 與 registry %d 不符", lang, len(catalog[lang]), len(registry))
		}
	}
}

// TestCatalogGuardSensitivity 敏感度自檢：每種破壞都必須被對應種類的檢查抓到。
func TestCatalogGuardSensitivity(t *testing.T) {
	cases := []struct {
		name   string
		kind   string
		mutate func(reg map[Event]EventSpec, cat map[string]map[Event]map[string]message)
	}{
		{"registry 為空", vRegistryEmpty, func(reg map[Event]EventSpec, _ map[string]map[Event]map[string]message) {
			for k := range reg {
				delete(reg, k)
			}
		}},
		{"語系缺鍵", vMissingInLang, func(_ map[Event]EventSpec, cat map[string]map[Event]map[string]message) {
			delete(cat["ja-JP"], EventTest)
		}},
		{"語系多鍵", vExtraInLang, func(_ map[Event]EventSpec, cat map[string]map[Event]map[string]message) {
			cat["en-US"]["ghost.event"] = map[string]message{"default": {Title: "x", Text: "y"}}
		}},
		{"registry 多事件而三語皆缺", vMissingInLang, func(reg map[Event]EventSpec, _ map[string]map[Event]map[string]message) {
			reg["ghost.event"] = EventSpec{Params: []ParamSpec{{Name: "a", Kind: KindOpaque, Required: true}}}
		}},
		{"variant 缺一", vVariantMismatch, func(_ map[Event]EventSpec, cat map[string]map[Event]map[string]message) {
			delete(cat["zh-TW"][EventAccessRequestApproved], ApprovalModeAuto)
		}},
		{"variant 多一", vVariantMismatch, func(_ map[Event]EventSpec, cat map[string]map[Event]map[string]message) {
			cat["en-US"][EventTest]["bogus"] = message{Title: "a", Text: "b"}
		}},
		{"模板空字串", vEmptyTemplate, func(_ map[Event]EventSpec, cat map[string]map[Event]map[string]message) {
			cat["ja-JP"][EventTicketRevoked][variantDefault] = message{Title: "", Text: "x {request_id}"}
		}},
		{"括號不平衡", vBracket, func(_ map[Event]EventSpec, cat map[string]map[Event]map[string]message) {
			m := cat["en-US"][EventTicketRevoked][variantDefault]
			m.Title = "Access request #{request_id}[: {asset_name}"
			cat["en-US"][EventTicketRevoked][variantDefault] = m
		}},
		{"佔位符未宣告", vUndeclared, func(_ map[Event]EventSpec, cat map[string]map[Event]map[string]message) {
			m := cat["zh-TW"][EventDailyReviewOverdue][variantDefault]
			m.Text = m.Text + "{unknown_thing}"
			cat["zh-TW"][EventDailyReviewOverdue][variantDefault] = m
		}},
		{"跨語系佔位符不一致", vPlaceholderX, func(_ map[Event]EventSpec, cat map[string]map[Event]map[string]message) {
			m := cat["en-US"][EventBreakGlassUsed][variantDefault]
			m.Text = strings.ReplaceAll(m.Text, "{duration_minutes}", "a while")
			cat["en-US"][EventBreakGlassUsed][variantDefault] = m
		}},
		{"跨語系可選性不一致", vOptionalX, func(_ map[Event]EventSpec, cat map[string]map[Event]map[string]message) {
			m := cat["ja-JP"][EventAccessRequestCreated][variantDefault]
			m.Title = "接続申請 #{request_id}：{asset_name}"
			cat["ja-JP"][EventAccessRequestCreated][variantDefault] = m
		}},
		{"必要參數未現身", vRequiredUnused, func(_ map[Event]EventSpec, cat map[string]map[Event]map[string]message) {
			m := cat["zh-TW"][EventAuditFailure][variantDefault]
			m.Text = strings.ReplaceAll(m.Text, "{cause_code}", "（略）")
			cat["zh-TW"][EventAuditFailure][variantDefault] = m
		}},
		{"死參數", vDeadParam, func(reg map[Event]EventSpec, _ map[string]map[Event]map[string]message) {
			spec := reg[EventTest]
			spec.Params = append(append([]ParamSpec(nil), spec.Params...),
				ParamSpec{Name: "never_used", Kind: KindOpaque})
			reg[EventTest] = spec
		}},
		{"EventSpec 非法", vSpecInvalid, func(reg map[Event]EventSpec, _ map[string]map[Event]map[string]message) {
			spec := reg[EventTest]
			spec.Params = append(append([]ParamSpec(nil), spec.Params...),
				ParamSpec{Name: "broken", Kind: KindEnum})
			reg[EventTest] = spec
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg, cat := cloneRegistry(), cloneCatalog()
			tc.mutate(reg, cat)
			got := checkCatalog(reg, cat, SupportedLangs, DefaultLang)
			if !hasKind(got, tc.kind) {
				t.Fatalf("破壞 %q 後守衛未回報 %s；實得: %v", tc.name, tc.kind, got)
			}
		})
	}
}

func hasKind(violations []string, kind string) bool {
	for _, s := range violations {
		if strings.HasPrefix(s, kind+": ") {
			return true
		}
	}
	return false
}

func cloneRegistry() map[Event]EventSpec {
	out := make(map[Event]EventSpec, len(registry))
	for k, v := range registry {
		v.Params = append([]ParamSpec(nil), v.Params...)
		out[k] = v
	}
	return out
}

func cloneCatalog() map[string]map[Event]map[string]message {
	out := make(map[string]map[Event]map[string]message, len(catalog))
	for lang, byEvent := range catalog {
		le := make(map[Event]map[string]message, len(byEvent))
		for ev, variants := range byEvent {
			mv := make(map[string]message, len(variants))
			for name, m := range variants {
				mv[name] = m
			}
			le[ev] = mv
		}
		out[lang] = le
	}
	return out
}
