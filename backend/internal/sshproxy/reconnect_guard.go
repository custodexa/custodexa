package sshproxy

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/dbproxy"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 資料庫命令列會話的「改連目標」輸入側守衛。
//
// 受管憑證只用於本次會話所指向的資產：mariadb、redis-cli、sqlcmd 會話中，
// 送出的整行含改連指令時，該行不得轉送。判定函式在
// dbproxy.ReconnectDirective；本檔負責「整行」的追蹤與接線：
//
//   - 逐行判定：一個輸入幀含多行時逐行判定；跨幀組成的整行、貼上的內容與
//     AI agent 入口送出的輸入（同一個輸入泵）受同一判定。
//   - 追蹤不了的輸入（游標移動、歷史叫回、補全、刪字鍵、其他控制字元）使該行
//     進入「無法確定」，Enter 時不轉送並提示重新輸入；不以「無法判讀即放行」處理。
//   - ESC 起頭的序列只轉送游標與編輯類標準序列（方向鍵、Home、End、Delete、
//     PageUp、PageDown 的 CSI 與 SS3 形式），轉送後該行進入「無法確定」；其餘
//     （ESC 加任意字元、其他 CSI、OSC 等字串序列）靜默不轉送。命令列子程序收不到
//     的位元組，守衛也不計入行內容，兩邊的行因此保持一致。
//   - 括號貼上的開始與結束標記不轉送，標記之間的內容視同鍵入逐行判定。
//   - 固定行為：不依指令規則設定開關，也不出現在規則管理頁。
//
// 被攔下時：該行（及其後同幀的內容）不轉送，送中斷位元組清掉 CLI 當前輸入，
// 向終端與錄影留下可讀警告，命中者另以阻斷事件的既有紀錄形態留痕。

// reconnectLineMax 單行追蹤上限；超過即視為無法確定（貼入超長內容不累積記憶體）。
const reconnectLineMax = 64 * 1024

// escSeqMax ESC 序列的追蹤上限（位元組）；超過即放棄該序列，其後的位元組照一般輸入處理。
const escSeqMax = 64

// escStringMax 字串型序列（OSC、DCS 等）的追蹤上限（位元組）；超過即放棄、行內容不可信。
const escStringMax = 4096

// escKind 目前正在比對的 ESC 序列種類。
type escKind int

const (
	escNone      escKind = iota
	escStart             // 剛收到 ESC
	escCSI               // ESC [
	escSS3               // ESC O
	escString            // ESC ] / P / _ / ^ / X：直到 BEL 或 ESC \ 為止
	escStringEsc         // 字串序列中收到 ESC，等待 \
)

// reconnectBlock 一次攔截的結果。
type reconnectBlock struct {
	verdict dbproxy.ReconnectVerdict
	// line 被攔下的整行（未淨化；寫進任何輸出前須淨化）
	line string
	// dropped 本幀未轉送的位元組（供鍵盤紀錄的 blocked 旁路）
	dropped []byte
}

// reconnectGuard 單一會話的守衛狀態。只由輸入泵這一個 goroutine 讀寫，故無鎖。
type reconnectGuard struct {
	protocol  string
	alerts    gatewayapi.AlertSink
	sessionID uint
	userID    uint
	assetID   uint

	line      []byte  // 目前這一行已追蹤到的內容
	unsynced  bool    // 行內容已不可信（編輯鍵、游標移動、歷史叫回、超長）
	escKind   escKind // 非 escNone：正在比對 ESC 序列
	esc       []byte  // 已收的 ESC 序列（含開頭的 ESC）
	discarded []byte  // 本幀不轉送的 ESC 序列（供鍵盤紀錄的 blocked 旁路，由 takeDiscarded 取走）
}

// newReconnectGuard 建立守衛；協議不適用時回 nil（直通）。
func newReconnectGuard(protocol string, alerts gatewayapi.AlertSink, sessionID, userID, assetID uint) *reconnectGuard {
	if !dbproxy.ReconnectGuardedProtocol(protocol) {
		return nil
	}
	return &reconnectGuard{protocol: protocol, alerts: alerts, sessionID: sessionID, userID: userID, assetID: assetID}
}

// Filter 檢視一個輸入幀：回傳可轉送的部分；整行被攔下時回傳該次攔截的描述。
// 被攔下那一行在本幀內的位元組與其後同幀的內容都不在回傳的可轉送部分內；
// 不轉送的 ESC 序列也不在其內（另由 takeDiscarded 取得）。
func (g *reconnectGuard) Filter(data []byte) ([]byte, *reconnectBlock) {
	out := make([]byte, 0, len(data)+len(g.esc))
	g.discarded = g.discarded[:0]
	lineStart := 0        // 目前這一行在本幀內的起點
	outLineStart := 0     // 目前這一行在可轉送部分內的起點
	discardLineStart := 0 // 目前這一行在不轉送序列內的起點
	for i := 0; i < len(data); i++ {
		c := data[i]

		if g.escKind != escNone {
			fwd, reprocess := g.escByte(c)
			out = append(out, fwd...)
			if !reprocess {
				continue
			}
		}

		switch {
		case c == '\r' || c == '\n':
			verdict, text := g.settleLine()
			if verdict != dbproxy.ReconnectAllow {
				// 這一行本幀的原始位元組已整段列入 dropped，不重複列入不轉送序列
				g.discarded = g.discarded[:discardLineStart]
				return out[:outLineStart], &reconnectBlock{verdict: verdict, line: text, dropped: data[lineStart:]}
			}
			out = append(out, c)
			lineStart = i + 1
			outLineStart = len(out)
			discardLineStart = len(g.discarded)
			continue
		case c == 0x1b:
			g.escKind = escStart
			g.esc = append(g.esc[:0], c)
			continue
		case c == 0x03: // Ctrl+C：CLI 放棄目前這一行
			g.resetLine()
		case c == 0x15: // Ctrl+U：游標在行尾時清整行；游標位置不可知時行內容仍不可信
			if !g.unsynced {
				g.line = g.line[:0]
			}
		case c == 0x7f || c == 0x08:
			g.backspace()
		case c >= 0x20:
			if len(g.line) >= reconnectLineMax {
				g.unsynced = true
			} else {
				g.line = append(g.line, c)
			}
		default:
			// Tab（補全）、Ctrl+W／K／Y（刪字與貼回）、游標與歷史類控制字元等：
			// 它們對行內容的影響這裡追蹤不了
			g.unsynced = true
		}
		out = append(out, c)
	}
	return out, nil
}

// takeDiscarded 取走最近一次 Filter 不轉送的 ESC 序列。
func (g *reconnectGuard) takeDiscarded() []byte {
	if len(g.discarded) == 0 {
		return nil
	}
	d := append([]byte(nil), g.discarded...)
	g.discarded = g.discarded[:0]
	return d
}

// escByte 在 ESC 序列比對中處理一個位元組。fwd 為序列完成且可轉送時的完整序列；
// reprocess 為 true 時序列已放棄（未轉送任何部分），c 須照一般輸入處理。
func (g *reconnectGuard) escByte(c byte) (fwd []byte, reprocess bool) {
	printable := c >= 0x20 && c <= 0x7e
	switch g.escKind {
	case escStart:
		switch {
		case c == '[':
			g.escKind = escCSI
		case c == 'O':
			g.escKind = escSS3
		case c == ']' || c == 'P' || c == '_' || c == '^' || c == 'X':
			g.escKind = escString
		case printable: // ESC 加一個字元：不轉送
			g.discardEsc(c)
			return nil, false
		default: // ESC 後接控制字元或非 ASCII：只捨棄 ESC
			g.discardEsc()
			return nil, true
		}
		g.esc = append(g.esc, c)
		return nil, false
	case escSS3:
		switch {
		case isCursorFinal(c):
			seq := append(append([]byte(nil), g.esc...), c)
			g.endEsc()
			g.unsynced = true
			return seq, false
		case printable:
			g.discardEsc(c)
			return nil, false
		default:
			g.discardEsc()
			return nil, true
		}
	case escCSI:
		switch {
		case c >= 0x20 && c <= 0x3f: // 參數與中間位元組
			if len(g.esc) >= escSeqMax {
				g.discardEsc()
				return nil, true
			}
			g.esc = append(g.esc, c)
			return nil, false
		case c >= 0x40 && c <= 0x7e: // 結尾位元組
			if isForwardedCSI(string(g.esc[2:]), c) {
				seq := append(append([]byte(nil), g.esc...), c)
				g.endEsc()
				g.unsynced = true
				return seq, false
			}
			// 其他 CSI（含括號貼上的開始與結束標記）：不轉送
			g.discardEsc(c)
			return nil, false
		default:
			g.discardEsc()
			return nil, true
		}
	case escString:
		switch c {
		case 0x07:
			g.discardEsc(c)
		case 0x1b:
			g.escKind = escStringEsc
		default:
			if len(g.esc) >= escStringMax {
				g.discardEsc()
				g.unsynced = true
				return nil, true
			}
			g.esc = append(g.esc, c)
		}
		return nil, false
	case escStringEsc:
		if c == '\\' {
			g.discardEsc(0x1b, c)
			return nil, false
		}
		// 字串序列結束，這個 ESC 視為新序列的開頭
		g.discardEsc()
		g.escKind = escStart
		g.esc = append(g.esc, 0x1b)
		return g.escByte(c)
	}
	g.endEsc()
	return nil, true
}

// discardEsc 放棄目前的 ESC 序列：已收的位元組（加上 extra）列入不轉送序列。
func (g *reconnectGuard) discardEsc(extra ...byte) {
	g.discarded = append(g.discarded, g.esc...)
	g.discarded = append(g.discarded, extra...)
	g.endEsc()
}

// endEsc 結束目前的 ESC 序列比對。
func (g *reconnectGuard) endEsc() {
	g.escKind = escNone
	g.esc = g.esc[:0]
}

// isCursorFinal 方向鍵、Home、End 的結尾位元組。
func isCursorFinal(c byte) bool {
	switch c {
	case 'A', 'B', 'C', 'D', 'H', 'F':
		return true
	}
	return false
}

// isForwardedCSI 是否為轉送的游標與編輯類標準 CSI 序列：方向鍵、Home、End
// （ESC [ X 或帶修飾鍵的 ESC [ 1 ; m X），以及 Home、Delete、End、PageUp、PageDown
// 的 ESC [ n ~（n 為 1、3、4、5、6、7、8，可帶 ; m 修飾鍵）。
func isForwardedCSI(params string, final byte) bool {
	key, mod, hasMod := strings.Cut(params, ";")
	if hasMod && !isModifierParam(mod) {
		return false
	}
	switch {
	case isCursorFinal(final):
		return (key == "" && !hasMod) || (key == "1" && hasMod)
	case final == '~':
		switch key {
		case "1", "3", "4", "5", "6", "7", "8":
			return true
		}
	}
	return false
}

// isModifierParam 修飾鍵參數：一到兩位數字。
func isModifierParam(s string) bool {
	if len(s) == 0 || len(s) > 2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// settleLine Enter：對整行下判定並重置追蹤狀態。
// 文字命中改連指令時一律判命中（資訊最完整）；其次，行內容不可信或正規化失敗判無法確定。
func (g *reconnectGuard) settleLine() (dbproxy.ReconnectVerdict, string) {
	text := string(g.line)
	verdict := dbproxy.ReconnectDirective(g.protocol, text)
	if verdict != dbproxy.ReconnectHit && (g.unsynced || verdict == dbproxy.ReconnectUncertain) {
		verdict = dbproxy.ReconnectUncertain
	}
	g.resetLine()
	return verdict, text
}

// resetLine 清空追蹤狀態（Enter 之後、Ctrl+C，或攔下後送出中斷之後）。
func (g *reconnectGuard) resetLine() {
	g.line = g.line[:0]
	g.unsynced = false
	g.endEsc()
}

// backspace 退一個 UTF-8 字元。
func (g *reconnectGuard) backspace() {
	n := len(g.line)
	if n == 0 {
		return
	}
	i := n - 1
	for i > 0 && (g.line[i]&0xC0) == 0x80 {
		i--
	}
	g.line = g.line[:i]
}

// recordBlocked 命中時以阻斷事件的既有紀錄形態留痕（規則名為內建識別，不需要規則列）。
func (g *reconnectGuard) recordBlocked(line string) {
	if g.sessionID == 0 {
		return
	}
	var assetRef *uint
	if g.assetID != 0 {
		id := g.assetID
		assetRef = &id
	}
	var ruleID uint // 內建守衛沒有規則列；command_alerts 無外鍵，rule 類告警要求 rule_id 非空
	alert := gatewayapi.CommandAlert{
		Kind:        model.AlertKindRule,
		RuleID:      &ruleID,
		RuleName:    apierror.DBReconnectRuleName,
		Level:       "high",
		Command:     truncateForAlert(line),
		OccurredAt:  time.Now(),
		SessionID:   g.sessionID,
		Actor:       gatewayapi.Actor{UserID: g.userID},
		AssetID:     assetRef,
		Disposition: model.AlertDispositionPending,
		Blocked:     true,
	}
	if err := gatewayapi.RecordAlert(context.Background(), g.alerts, alert); err != nil {
		log.Printf("[ReconnectGuard] 阻斷告警落地失敗（該行已阻斷，紀錄未留存）: %v", err)
	}
}

// alertCommandMax 告警內容的長度上限（位元組）。
const alertCommandMax = 2048

func truncateForAlert(s string) string {
	if len(s) <= alertCommandMax {
		return s
	}
	cut := alertCommandMax
	for cut > 0 && (s[cut]&0xC0) == 0x80 { // 退到 UTF-8 字元邊界
		cut--
	}
	return s[:cut]
}
