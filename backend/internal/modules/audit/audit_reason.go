package audit

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
)

// 審計列的原因分類：後端只回碼與參數，文案在前端三語
// （`dailyReview.reason.<碼>`），與時間軸摘要同一形態。
//
// 判定順序（先中先用）：
//  1. 保留期限清除
//  2. error_msg 是登記過的機器碼（auditReasonMachineCodes）
//  3. details.event 是登記過的事件（auditReasonEvents，碼＝"event."＋事件名）
//  4. 已知的 details 形狀（auditReasonShapes）
//  5. 以上皆非而 error_msg 或 path 非空：不給碼，畫面照舊顯示該欄原文
//  6. 其餘：generic／generic_event，畫面以動作與資源組句，不會空白
//
// 新增一個事件只需在 auditReasonEvents 加一列，並在三語補
// `dailyReview.reason.event.<事件名>`；漏補時 audit_reason_completeness_test.go 會指出語系與碼。

// AuditReasonInput 分類只讀這六個欄位
type AuditReasonInput struct {
	Action   string
	Resource string
	Status   string
	ErrorMsg string
	Details  string
	Path     string
}

const (
	// ReasonGeneric 通用退路：參數 action、resource（機器值，前端查 enum 譯名）
	ReasonGeneric = "generic"
	// ReasonGenericEvent 通用退路且帶未登記的事件名：多一個參數 event（原值）
	ReasonGenericEvent = "generic_event"

	reasonRetentionPurge       = "retention_purge"
	reasonRetentionPurgeFailed = "retention_purge_failed"
	reasonEventPrefix          = "event."
	reasonInactiveDaysKey      = "inactive_days"

	// reasonListSeparator 多值參數（角色名清單）的分隔字元
	reasonListSeparator = ","
)

// reasonDetails details JSON 的寬鬆讀取；解析失敗視為沒有 details
type reasonDetails map[string]any

func parseReasonDetails(raw string) reasonDetails {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw[0] != '{' {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.UseNumber()
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		return nil
	}
	return out
}

func (d reasonDetails) str(key string) string {
	s, _ := d[key].(string)
	return s
}

// num 整數值（JSON 數字或數字字串）轉字串；不是整數時 ok=false
func (d reasonDetails) num(key string) (string, bool) {
	var raw string
	switch v := d[key].(type) {
	case json.Number:
		raw = v.String()
	case string:
		raw = v
	default:
		return "", false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return "", false
	}
	return strconv.FormatInt(n, 10), true
}

func (d reasonDetails) numOr(key, fallback string) string {
	if v, ok := d.num(key); ok {
		return v
	}
	return fallback
}

func (d reasonDetails) strList(key string) []string {
	arr, _ := d[key].([]any)
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		if s, ok := v.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// opaque 自由字串一律淨化（長度上限、去換行與控制字元）
func opaque(s string) string { return notifycat.SanitizeOpaque(s) }

// opaqueList 清單逐項淨化後以分隔字元串接；項內的分隔字元換成空白，前端拆分時不會錯位
func opaqueList(items []string) string {
	out := make([]string, 0, len(items))
	for _, s := range items {
		if c := opaque(strings.ReplaceAll(s, reasonListSeparator, " ")); c != "" {
			out = append(out, c)
		}
	}
	return strings.Join(out, reasonListSeparator)
}

type reasonParams = map[string]string

// auditReasonMachineCode 寫在 error_msg 的機器碼。Variants 列出這一列可能產出的全部碼
// （含 Code 本身）；Build 為 nil 時固定回 Code、不帶參數
type auditReasonMachineCode struct {
	Code     string
	Variants []string
	Build    func(d reasonDetails) (string, reasonParams)
}

// auditReasonEvent 以 details.event 辨識的事件；碼＝"event."＋Event，Params 為 nil 時不帶參數
type auditReasonEvent struct {
	Event  string
	Params func(d reasonDetails) reasonParams
}

// auditReasonShape 以 details 形狀辨識；Codes 列出 Match 可能回傳的全部碼
type auditReasonShape struct {
	Codes []string
	Match func(in AuditReasonInput, d reasonDetails) (string, reasonParams, bool)
}

var (
	reasonMachineIndex = map[string]auditReasonMachineCode{}
	reasonEventIndex   = map[string]auditReasonEvent{}

	// AuditReasonCodes 全部可能的原因碼（排序、不重複）；三語完備性守衛由它展開
	AuditReasonCodes []string
)

func init() {
	codes := []string{ReasonGeneric, ReasonGenericEvent, reasonRetentionPurge, reasonRetentionPurgeFailed}
	for _, m := range auditReasonMachineCodes {
		reasonMachineIndex[m.Code] = m
		if len(m.Variants) == 0 {
			codes = append(codes, m.Code)
		}
		codes = append(codes, m.Variants...)
	}
	for _, e := range auditReasonEvents {
		reasonEventIndex[e.Event] = e
		codes = append(codes, reasonEventPrefix+e.Event)
	}
	for _, s := range auditReasonShapes {
		codes = append(codes, s.Codes...)
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if !seen[c] {
			seen[c] = true
			AuditReasonCodes = append(AuditReasonCodes, c)
		}
	}
	sort.Strings(AuditReasonCodes)
}

// ClassifyAuditReason 依判定順序回傳原因碼與參數；碼為空表示畫面照舊顯示 error_msg 或 path
func ClassifyAuditReason(in AuditReasonInput) (string, map[string]string) {
	d := parseReasonDetails(in.Details)
	if in.Resource == string(model.ResourceRetention) {
		return retentionReason(in, d)
	}
	if m, ok := reasonMachineIndex[in.ErrorMsg]; ok {
		if m.Build == nil {
			return m.Code, nil
		}
		return m.Build(d)
	}
	event := d.str("event")
	if e, ok := reasonEventIndex[event]; ok && event != "" {
		if e.Params == nil {
			return reasonEventPrefix + event, nil
		}
		return reasonEventPrefix + event, e.Params(d)
	}
	for _, s := range auditReasonShapes {
		if code, params, ok := s.Match(in, d); ok {
			return code, params
		}
	}
	if in.ErrorMsg != "" || in.Path != "" {
		return "", nil
	}
	params := reasonParams{"action": opaque(in.Action), "resource": opaque(in.Resource)}
	if event != "" {
		params["event"] = opaque(event)
		return ReasonGenericEvent, params
	}
	return ReasonGeneric, params
}

// retentionReason 保留期限清除；target 是資料表名，前端以 dailyReview.reasonTarget.<表名> 翻譯
func retentionReason(in AuditReasonInput, d reasonDetails) (string, map[string]string) {
	target := opaque(d.str("target"))
	if in.Status != string(model.StatusSuccess) || d.str("error") != "" {
		return reasonRetentionPurgeFailed, reasonParams{"target": target}
	}
	return reasonRetentionPurge, reasonParams{"target": target,
		"deleted": d.numOr("deleted", "0"), "days": d.numOr("days", "—")}
}

// InactiveDisableDetails 閒置停用列的 details（逾期天數）；寫入端與分類器共用同一個鍵名
func InactiveDisableDetails(days int) string {
	return `{"` + reasonInactiveDaysKey + `":` + strconv.Itoa(days) + `}`
}
