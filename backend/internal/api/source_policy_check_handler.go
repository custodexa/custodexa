package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/sourceip"
)

// 允許來源網段清單的判定端點。
//
// # 為什麼判定要有一支端點，而不是讓表單自己算
//
// IPv6 縮寫、IPv4-mapped 位址對 IPv4 前綴、遮罩正規化（`10.1.2.3/8` → `10.0.0.0/8`）
// 這些行為在兩套實作之間**必然分歧**。表單若自行判斷「這個位址落不落在清單內」，
// 分歧的後果不是顯示錯字——是自鎖警告與實際強制點不一致：介面說「你還進得來」
// 而下一次登入被擋在門外，或反過來。
//
// 故判定權單一化：表單只做**格式**層的就近提示（看起來像不像位址），
// 任何「落入／不落入」「正規化後長什麼樣」「等同不限」一律問這支端點，
// 而它與登入、刷新、簽發、兌換各判定點共用同一份 `sourceip` 實作。
//
// # 純判定
//
// 不寫任何狀態、不產生自鎖判定的副作用。讀取留痕沿 `users` 資源分類（中介層既有）；
// 動作欄由中介層依路徑訂正為讀取（動詞推導會把 POST 一律當成新增，見
// `middleware/audit_log.go` 的 `/source-policy/check` 分支），查詢摘要由本檔補。
// 回覆的 `source` 只回本請求的來源或呼叫端自己給的位址——不揭露任何其他使用者的清單。

// SourcePolicyCheckRequest 判定請求。
type SourcePolicyCheckRequest struct {
	// AllowedCIDRs 待判定的清單草稿（尚未儲存）
	AllowedCIDRs []string `json:"allowed_cidrs"`
	// Address 省略＝以**本請求的來源**判定（表單的自鎖預警即走這條）；
	// 指定時以該位址判定，供管理者預演「某個位址進不進得來」
	Address string `json:"address"`
}

// SourcePolicyCheckSource 判定所依據的來源位址。
type SourcePolicyCheckSource struct {
	// Address 判定用的位址；不可解析時為 null（顯式，不是空字串）
	Address *string `json:"address"`
	// Reason Address 為 null 時的原因
	Reason string `json:"reason,omitempty"`
}

// 來源欄的原因值域
const (
	// sourceReasonRequest 位址取自本請求（呼叫端未指定）
	sourceReasonRequest = "request"
	// sourceReasonProvided 位址由呼叫端指定
	sourceReasonProvided = "provided"
	// sourceReasonUnresolvable 位址無法解析（呼叫端給了非位址字串，
	// 或本請求的來源取不出來）
	sourceReasonUnresolvable = "unresolvable"
)

// SourcePolicyCheckResponse 判定回覆。
type SourcePolicyCheckResponse struct {
	// Valid 清單整體是否合法（任一項不合法或去重後超過上限即 false）
	Valid bool `json:"valid"`
	// Items 逐項結果（合法項亦回其正規化形式，供介面就近預覽）
	Items []sourceip.Item `json:"items"`
	// Normalized 去重排序後的正規化清單
	Normalized []string `json:"normalized"`
	// Status 有效涵蓋狀態：unrestricted／effectively_unrestricted／restricted
	Status string `json:"status"`
	// Families Status 為 effectively_unrestricted 時，被全放行的位址家族
	Families []string `json:"families,omitempty"`
	// Source 本次判定所依據的來源位址
	Source SourcePolicyCheckSource `json:"source"`
	// Allowed 該來源在此清單下是否放行。
	//
	// **與各強制點同一個 fail-close 判準**：清單不合法、或清單非空而來源不可解析
	// 皆為 false；清單為空為 true。介面的自鎖警告直接消費本欄，不自行推導
	Allowed bool `json:"allowed"`
}

// SourcePolicyCheck POST /api/v1/users/source-policy/check
func (h *UserHandler) SourcePolicyCheck(c *gin.Context) {
	var req SourcePolicyCheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}

	prefixes, normalized, items, valid := sourceip.Inspect(req.AllowedCIDRs)
	status, families := sourceip.CoverageStatus(prefixes)

	// 來源：呼叫端指定者優先，否則取本請求來源（一律經 Canonical，
	// 與強制點比對前的處置相同）
	raw, reason := req.Address, sourceReasonProvided
	if raw == "" {
		raw, reason = sourceip.Of(c), sourceReasonRequest
	}
	src := SourcePolicyCheckSource{Reason: sourceReasonUnresolvable}
	canon, ok := sourceip.Canonical(raw)
	if ok {
		src.Address, src.Reason = &canon, reason
	}

	// fail-close：清單壞掉不放行，清單非空而來源不可解析不放行；
	// 清單為空（不限）才無條件放行
	allowed := false
	switch {
	case len(normalized) == 0 && valid:
		allowed = true
	case valid && ok:
		allowed = sourceip.Allowed(canon, prefixes)
	}

	// 讀取留痕的查詢摘要。中介層已為這次呼叫寫一列，此處補「查了什麼」——
	// 沒有它，那一列只說得出「有人打了判定端點」。
	//
	// **記形狀不記內容**：清單草稿與被試算的位址一律不進 details。這與拒絕留痕
	// 的取捨方向相反，而兩邊都成立——拒絕時位址與清單就是課責的內容本身（少了
	// 它就答不出「這次為什麼被擋」），這裡則是一份**從未儲存**的草稿與呼叫端
	// 任意指定的位址，寫進去等於把試算輸入永久封存在受檢查點鏈保護、刪不掉的
	// 紀錄裡，卻換不到任何課責。
	//
	// 註（2026-08-26）：`allowed_cidrs` 已登記為審計放行的實質欄位（理由見
	// `modules/audit` 的 safeAuditSubstanceFields），遮罩又以鍵名為單位、分不出
	// 端點，故草稿清單事實上會經 request_body 入庫。本段仍成立的是 details 這一
	// 側的取捨：摘要記形狀不記內容，被試算的 `address` 亦不放行。
	details := map[string]string{
		"check":          "source_policy",
		"cidr_count":     strconv.Itoa(len(req.AllowedCIDRs)),
		"valid":          strconv.FormatBool(valid),
		"address_source": src.Reason,
		"allowed":        strconv.FormatBool(allowed),
	}
	// status 只在清單合法時有定義：不合法時涵蓋狀態算出來也不具意義，
	// 寫進審計只會讓讀者以為那份草稿是好的
	if valid {
		details["status"] = status
	}
	c.Set("audit_details", details)

	c.JSON(http.StatusOK, SourcePolicyCheckResponse{
		Valid:      valid,
		Items:      items,
		Normalized: normalized,
		Status:     status,
		Families:   families,
		Source:     src,
		Allowed:    allowed,
	})
}
