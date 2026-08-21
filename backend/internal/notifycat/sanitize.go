package notifycat

import (
	"strings"
	"unicode"
)

// MaxOpaqueRunes opaque 值長度上限（rune 而非 byte——中日文合法名不受傷；
// asset name 上限 100、username 50，合法值永不觸限）。超限即可見截斷，
// 不拒發不靜默：合規通知不因單一長值消失（design D3）。
const MaxOpaqueRunes = 128

// truncationMark 截斷標記；計入 MaxOpaqueRunes。
const truncationMark = "…"

// SanitizeOpaque 淨化自由字串值（design D3 的單一共用淨化契約，
// notifycat 與後續 WS 幀共用；D7 的 MsgNotice params 亦走本函式）。
//
// 三件事，順序固定：
//  1. 移除 ANSI/ESC 逸出序列（CSI/OSC/SS/兩字元序列）——AlertRule.Name 等來源
//     現僅驗 required，可含任意字元，直送終端或 Slack 均為注入面。
//  2. 換行/回車/tab/垂直定位/換頁與 U+2028/U+2029 改為空白（保留詞界，不讓
//     "a\nb" 併成 "ab"），連續者折成單一空白、首尾者去除；其餘控制字元
//     （含 C1 U+0080-U+009F 與 DEL）與整個 Unicode Cf 類（格式字元）一律移除。
//  3. 超過 MaxOpaqueRunes 即截斷並附「…」，截斷後總長仍為 MaxOpaqueRunes。
//
// 為何 Cf 整類與 U+2028/U+2029 也要處理（V2 對抗驗收 C2/C3）：
//   - U+2028/U+2029 是 Unicode 行/段分隔符，unicode.IsControl 為 false，
//     卻在 JS/JSON 與部分渲染器中構成換行——放行等於留了一條偽造多行訊息
//     （假造「系統通知」段落）的路。折成空白與 \n 同級處置。
//   - Cf 類含零寬字元（U+200B/U+200D/U+FEFF）與 bidi 覆寫（U+202E 等）。
//     零寬可用來在告警文字中藏字或讓兩個不同的名字看起來完全一樣；bidi
//     覆寫可讓顯示順序與實際字串相反（經典的視覺欺騙）。合法的告警文字
//     不需要這些字元，整類移除是可承擔的取捨（代價：emoji ZWJ 組合字會拆開）。
//
// 冪等：對已淨化字串再呼叫結果不變（截斷不會二次縮短）。
func SanitizeOpaque(s string) string {
	if s == "" {
		return ""
	}
	stripped := stripEscapeSequences(s)

	var b strings.Builder
	b.Grow(len(stripped))
	pendingSpace := false // 連續的空白型控制字元（如 CRLF）只折成一個空白
	for _, r := range stripped {
		switch {
		case r == '\n' || r == '\r' || r == '\t' || r == '\v' || r == '\f' ||
			r == '\u2028' || r == '\u2029':
			pendingSpace = true
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			// 丟棄（ESC 已於上一階段處理，此處為殘餘控制字元與零寬/bidi 格式字元）
		default:
			if pendingSpace {
				b.WriteRune(' ')
				pendingSpace = false
			}
			b.WriteRune(r)
		}
	}
	if pendingSpace {
		b.WriteRune(' ')
	}
	return truncateRunes(strings.TrimSpace(b.String()))
}

// truncateRunes 依 rune 數截斷並附截斷標記。
func truncateRunes(s string) string {
	runes := []rune(s)
	if len(runes) <= MaxOpaqueRunes {
		return s
	}
	return string(runes[:MaxOpaqueRunes-1]) + truncationMark
}

// stripEscapeSequences 移除 ESC (U+001B) 起始的逸出序列整段。
//
// 涵蓋形態：
//   - CSI  `ESC [` … 參數/中間位元組 … 終結位元組 (0x40-0x7E)
//   - OSC  `ESC ]` … 至 BEL (0x07) 或 ST (`ESC \`)；未終結則吃到字串尾
//   - DCS/SOS/PM/APC `ESC P/X/^/_` … 同 OSC 之 ST 終結規則
//   - 其餘兩字元序列 `ESC <單一字元>`（如 `ESC c` reset）
//
// 單獨的 ESC（字串尾）直接丟棄。
func stripEscapeSequences(s string) string {
	if !strings.ContainsRune(s, 0x1b) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		if runes[i] != 0x1b {
			b.WriteRune(runes[i])
			continue
		}
		i = skipEscapeSequence(runes, i)
	}
	return b.String()
}

// skipEscapeSequence 回傳逸出序列最後一個 rune 的索引（供 for 迴圈 i++ 續行）。
func skipEscapeSequence(runes []rune, start int) int {
	i := start + 1
	if i >= len(runes) {
		return len(runes) // 尾端孤兒 ESC
	}
	switch runes[i] {
	case '[': // CSI：吃到 0x40-0x7E 終結位元組
		for i++; i < len(runes); i++ {
			if runes[i] >= 0x40 && runes[i] <= 0x7e {
				return i
			}
		}
		return len(runes)
	case ']', 'P', 'X', '^', '_': // OSC/DCS/SOS/PM/APC：吃到 BEL 或 ST
		for i++; i < len(runes); i++ {
			if runes[i] == 0x07 {
				return i
			}
			if runes[i] == 0x1b && i+1 < len(runes) && runes[i+1] == '\\' {
				return i + 1
			}
		}
		return len(runes)
	default: // 兩字元序列
		return i
	}
}

// 註：原 SanitizeParams（降級路徑「全 params 淨化後照發」）已由
// FilterDeclared 取代（codex 批 2 M1）——淨化只管形狀，管不了「該不該出站」。
// 唯一呼叫端改走 FilterDeclared 後本函式無人使用，一併移除以免回潮。

// slackEscape 轉義 Slack mrkdwn 控制字元（與 service.slackEscape 同語義；
// 本套件為 i18n 葉節點，不反向依賴 service）。順序重要：& 先轉，
// 否則會二次轉義後續產生的實體。
//
// 只作用於插值後的 opaque 值，不作用於模板本體——模板是自家文案，
// 需要保留 mrkdwn 語法能力（呼叫端因此**不得**再對整串二次轉義）。
func slackEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
