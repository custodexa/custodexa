package notifycat

import (
	"embed"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
)

//go:embed locales/*.json
var localeFS embed.FS

// DefaultLang 未知/空語系的 fallback。zh-TW 為文案源語言。
const DefaultLang = "zh-TW"

// SupportedLangs 目錄支援的語系（順序即完備性守衛的比對順序）。
var SupportedLangs = []string{"zh-TW", "en-US", "ja-JP"}

// message 單一 (event, variant) 的模板對。
type message struct {
	Title string `json:"title"`
	Text  string `json:"text"`
}

// catalog[lang][event][variant] → 模板。啟動時 init 載入並固化。
var catalog = map[string]map[Event]map[string]message{}

func init() {
	for _, lang := range SupportedLangs {
		raw, err := localeFS.ReadFile(path.Join("locales", lang+".json"))
		if err != nil {
			// embed 缺檔屬建置期錯誤，不可能在執行期修復
			panic(fmt.Sprintf("notifycat: 載入語系檔 %s 失敗: %v", lang, err))
		}
		var parsed map[Event]map[string]message
		if err := json.Unmarshal(raw, &parsed); err != nil {
			panic(fmt.Sprintf("notifycat: 解析語系檔 %s 失敗: %v", lang, err))
		}
		catalog[lang] = parsed
	}
}

// Render 渲染出站 Slack 標題與內文。
//
// 語系未支援即 fallback DefaultLang；事件或 variant 於目錄缺鍵時再降一級走
// RenderDegraded——本函式永不回空字串對，合規告警不因目錄問題消失。
//
// params 期望為 Validate 的回傳值（已淨化）；未經驗證直接呼叫亦安全：
// opaque 值在插值前仍會過 SanitizeOpaque。插值後的值一律經 Slack mrkdwn 轉義，
// 模板本體不轉義（保留自家文案的 mrkdwn 能力）——呼叫端**不得**再對整串二次轉義。
func Render(lang string, event Event, params map[string]string) (title, text string) {
	lang = resolveLang(lang)
	msg, ok := lookup(lang, event, params)
	if !ok {
		return RenderDegraded(lang, event, params)
	}
	values := renderValues(lang, event, params)
	return interpolate(msg.Title, values), interpolate(msg.Text, values)
}

// resolveLang 未支援語系一律落 DefaultLang（Render 與 Phrase 共用同一判準）。
func resolveLang(lang string) string {
	if _, ok := catalog[lang]; ok {
		return lang
	}
	return DefaultLang
}

// lookup 依 lang → event → variant 取模板（lang 已由 resolveLang 收斂）。
func lookup(lang string, event Event, params map[string]string) (message, bool) {
	byEvent, ok := catalog[lang]
	if !ok {
		byEvent = catalog[DefaultLang]
	}
	variants, ok := byEvent[event]
	if !ok {
		return message{}, false
	}
	msg, ok := variants[variantKey(event, params)]
	return msg, ok
}

// variantKey 依 EventSpec.VariantParam 取 variant 鍵；無宣告或值缺失即 default。
func variantKey(event Event, params map[string]string) string {
	spec, ok := registry[event]
	if !ok || spec.VariantParam == "" {
		return variantDefault
	}
	if v := params[spec.VariantParam]; v != "" {
		return v
	}
	return variantDefault
}

// renderValues 將 params 轉為插值用值：
//   - 宣告 Lexicon 者：值視為詞庫鍵，換成該語系短語（缺鍵回吐機器碼）
//   - 其餘（opaque / enum / int）：值本身直接插值
//
// 淨化紀律：**所有** kind 的值一律過 SanitizeOpaque，
// 不因宣告的 kind 而豁免。理由是 Render 的契約明載「未經 Validate 直接呼叫
// 亦安全」——只有 Validate 走過的路徑才保證 enum 值落在允許清單內；免驗證
// 路徑（降級投遞、單測、未來新呼叫點）的 enum/int 值可以是任意字串，把
// 「值域封閉」當既成事實就是把注入面留給最沒人看守的那條路。已驗證過的
// 值再淨化一次是冪等的無害操作，代價僅一次字串掃描。
// Lexicon 分支同理：Phrase 缺鍵時會回吐傳入的機器碼原文，同屬未驗證輸入。
func renderValues(lang string, event Event, params map[string]string) map[string]string {
	spec := registry[event]
	out := make(map[string]string, len(params))
	for k, v := range params {
		if v == "" {
			continue
		}
		if p, ok := spec.param(k); ok && p.Lexicon != "" {
			out[k] = slackEscape(SanitizeOpaque(Phrase(lang, p.Lexicon, v)))
			continue
		}
		out[k] = slackEscape(SanitizeOpaque(v))
	}
	return out
}

// RenderDegraded 目錄無鍵／參數不合契約時的 generic 文案。
//
// 不依賴任何 per-event 鍵，但**依賴收件通道語系**：標題與骨幹文案取自
// LexiconDegraded 詞庫（三語，受 checkLexicons 完備性守衛保護），event
// 識別字以 {event} 佔位符插入——降級是給人看的異常告知，用收件人看不懂的
// 語言等於少講一件事。
//
// 參數只列 EventSpec 宣告的鍵（FilterDeclared）：未註冊 event 一鍵不列。
// 呼叫端多半已先過 FilterDeclared，此處重跑一次是冪等的縱深防禦——
// Render 的目錄缺鍵分支與未來的新呼叫點都會落到這裡，不能假設誰先過濾了。
//
// 呼叫端既有的 Slack 外框（`:warning: *<title>*\n<text>`）套上後即為
// design 所述的降級形態。
func RenderDegraded(lang string, event Event, params map[string]string) (title, text string) {
	lang = resolveLang(lang)
	title = Phrase(lang, LexiconDegraded, DegradedKeyTitle)
	text = interpolate(Phrase(lang, LexiconDegraded, DegradedKeyText), map[string]string{
		"event": slackEscape(SanitizeOpaque(string(event))),
	})

	kept, _ := FilterDeclared(event, params)
	if len(kept) == 0 {
		return title, text
	}
	keys := make([]string, 0, len(kept))
	for k := range kept {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	lines := make([]string, 0, len(keys))
	for _, k := range keys {
		lines = append(lines, slackEscape(k)+": "+slackEscape(kept[k]))
	}
	return title, text + "\n" + strings.Join(lines, "\n")
}

// interpolate 展開模板。
//
// 語法：
//   - `{name}` 佔位符：以 values[name] 取代；缺值或空值時視為未解析。
//   - `[...]` 可選段：段內含佔位符且其中任一未解析時，整段捨去；
//     段內無佔位符時恆保留。用於「資產名查不到就不出現分隔符」這類條件。
//
// 未解析且不在可選段內的佔位符以空字串取代（絕不回吐 `{name}` 給使用者）。
func interpolate(tmpl string, values map[string]string) string {
	var out strings.Builder
	out.Grow(len(tmpl))

	var seg strings.Builder // 可選段暫存；段外直接寫 out
	inOptional := false
	segHasPlaceholder := false
	segResolved := true

	write := func(s string) {
		if inOptional {
			seg.WriteString(s)
			return
		}
		out.WriteString(s)
	}

	runes := []rune(tmpl)
	for i := 0; i < len(runes); i++ {
		switch runes[i] {
		case '[':
			if inOptional {
				break // 不支援巢狀：視為字面量（完備性守衛已擋不平衡括號）
			}
			inOptional, segHasPlaceholder, segResolved = true, false, true
			continue
		case ']':
			if !inOptional {
				break
			}
			inOptional = false
			if !segHasPlaceholder || segResolved {
				out.WriteString(seg.String())
			}
			seg.Reset()
			continue
		case '{':
			end := indexRuneFrom(runes, i+1, '}')
			if end < 0 {
				break // 無閉合括號：當字面量
			}
			v := values[string(runes[i+1:end])]
			if v == "" {
				segResolved = false
			}
			segHasPlaceholder = true
			write(v)
			i = end
			continue
		}
		write(string(runes[i]))
	}
	// 未閉合的可選段（模板守衛已擋，此處保底原樣輸出而非吞掉）
	out.WriteString(seg.String())
	return out.String()
}

func indexRuneFrom(runes []rune, from int, target rune) int {
	for i := from; i < len(runes); i++ {
		if runes[i] == target {
			return i
		}
	}
	return -1
}
