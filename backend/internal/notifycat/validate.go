package notifycat

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ErrUnregisteredEvent 事件未註冊的哨兵。
//
// 呼叫端據此**降級投遞而非拒發**：webhook 分支送
// {event, params, degraded:true}、Slack 分支改用 RenderDegraded——
// 合規告警不因目錄缺鍵而靜默消失。
var ErrUnregisteredEvent = errors.New("notifycat: unregistered event")

// UnregisteredEventError 未註冊事件錯誤，攜帶事件識別字供 log 與降級 payload。
type UnregisteredEventError struct{ Event Event }

func (e *UnregisteredEventError) Error() string {
	return fmt.Sprintf("notifycat: unregistered event %q", string(e.Event))
}

func (e *UnregisteredEventError) Unwrap() error { return ErrUnregisteredEvent }

// 參數違規原因（機器碼；本錯誤面向開發者與 log，不面向終端使用者）。
const (
	ReasonUnknownParam    = "unknown_param"
	ReasonMissingRequired = "missing_required"
	ReasonEnumOutOfRange  = "enum_out_of_range"
	ReasonNotAnInteger    = "not_an_integer"
)

// ParamError 單一參數違規。
type ParamError struct {
	Event  Event
	Param  string
	Reason string
}

func (e *ParamError) Error() string {
	return fmt.Sprintf("notifycat: event %q param %q: %s", string(e.Event), e.Param, e.Reason)
}

// ParamErrors 一次驗證中的全部違規（一次回報完整清單，避免逐輪修）。
type ParamErrors []*ParamError

func (errs ParamErrors) Error() string {
	parts := make([]string, 0, len(errs))
	for _, e := range errs {
		parts = append(parts, e.Error())
	}
	return strings.Join(parts, "; ")
}

// Validate 驗證事件參數並回傳淨化後的 map。
//
// 規則：
//   - 事件未註冊 → *UnregisteredEventError（errors.Is(err, ErrUnregisteredEvent) 為真）
//   - 未宣告的鍵 → 拒（unknown_param）
//   - 缺必要鍵 → 拒（missing_required；空字串視同缺）
//   - enum 值域外 → 拒（enum_out_of_range）
//   - int 非十進位整數 → 拒（not_an_integer）
//   - opaque 值 → 過 SanitizeOpaque 淨化後放進回傳 map
//
// 回傳 map 為新配置，不改動呼叫端傳入的 map。可選參數若給空字串，
// 視同未提供並自回傳 map 移除（模板的可選段據此略過）。
func Validate(event Event, params map[string]string) (map[string]string, error) {
	spec, ok := registry[event]
	if !ok {
		return nil, &UnregisteredEventError{Event: event}
	}

	var errs ParamErrors
	out := make(map[string]string, len(params))
	// 已因格式/值域違規記錄過的鍵：不得再以 missing_required 重複記一筆。
	// 「votes=abc」的真因是 not_an_integer，
	// 同時回報 missing_required 會誤導修錯方向——一個違規只出一個錯。
	rejected := map[string]bool{}

	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys) // 錯誤順序穩定，測試可斷言

	for _, k := range keys {
		p, declared := spec.param(k)
		if !declared {
			errs = append(errs, &ParamError{event, k, ReasonUnknownParam})
			continue
		}
		v := params[k]
		if v == "" {
			continue // 空值一律不進 out；必要性由下方 required 檢查統一裁定
		}
		switch p.Kind {
		case KindEnum:
			if !containsString(p.Enum, v) {
				errs = append(errs, &ParamError{event, k, ReasonEnumOutOfRange})
				rejected[k] = true
				continue
			}
			out[k] = v
		case KindInt:
			if _, err := strconv.ParseInt(v, 10, 64); err != nil {
				errs = append(errs, &ParamError{event, k, ReasonNotAnInteger})
				rejected[k] = true
				continue
			}
			out[k] = v
		default: // KindOpaque
			// 淨化後可能變空（例如整串都是控制字元）：此時視同未提供，
			// 由下方 required 檢查裁定，不留空值進 out
			if sanitized := SanitizeOpaque(v); sanitized != "" {
				out[k] = sanitized
			}
		}
	}

	for _, p := range spec.Params {
		if p.Required && out[p.Name] == "" && !rejected[p.Name] {
			errs = append(errs, &ParamError{event, p.Name, ReasonMissingRequired})
		}
	}

	if len(errs) > 0 {
		sort.SliceStable(errs, func(i, j int) bool { return errs[i].Param < errs[j].Param })
		return nil, errs
	}
	return out, nil
}

// FilterDeclared 降級路徑的參數收口：只留 EventSpec 宣告的鍵，
// 值過 SanitizeOpaque；回傳被剔除的鍵名（已排序）供呼叫端 log。
//
// 為何降級不能「淨化後照發全部 params」：淨化只處理形狀（控制字元、長度），
// 不處理**內容該不該出站**。宣告的鍵是設計時逐一審過可外送的（去識別紅線
// 就是靠 EventSpec 把 forensic detail 擋在 params 之外）；未宣告的鍵沒經過
// 任何審查——降級路徑正是呼叫端契約已經出錯的時刻，此時最不該放寬出站面。
//
// 未註冊 event：無契約可依，**全部鍵剔除**（回空 map，非 nil），只留 event
// 身分與 degraded 旗標出站。合規告警的「發生了什麼事」由 event 識別字承載，
// 不需要值；值留在本地 log（信任邊界內）供維運追。
func FilterDeclared(event Event, params map[string]string) (kept map[string]string, dropped []string) {
	spec, registered := registry[event]
	kept = make(map[string]string, len(params))
	for k, v := range params {
		if !registered {
			dropped = append(dropped, k)
			continue
		}
		if _, declared := spec.param(k); !declared {
			dropped = append(dropped, k)
			continue
		}
		if sanitized := SanitizeOpaque(v); sanitized != "" {
			kept[k] = sanitized
		}
	}
	sort.Strings(dropped)
	return kept, dropped
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
