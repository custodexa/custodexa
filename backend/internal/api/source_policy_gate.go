package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/sourceip"
)

// web 面的來源限定強制點（G1）。
//
// # 一個 helper，十八個呼叫點
//
// 判定要素只有三個：現讀清單、正規化、比對。三者若在各端點各寫一次，
// 遲早會出現「某一點忘了正規化 IPv4-mapped 位址」這種偏差——而它的症狀是
// 某條登入路徑對某類位址靜默放行，沒有任何測試會轉紅。故全部呼叫點共用
// `requireSourceAllowed`，各點只加一次呼叫；哪些點該加由
// `cmd/server/source_gate_coverage_guard_test.go` 以閉集合機械強制。
//
// # 判定一律在憑證驗證之後
//
// 帳號的允許網段是帳號屬性；在憑證驗證之前判定，等於對未認證者開一個
// 「這個帳號存不存在」的預言機。憑證已驗者收到專屬碼不構成洩漏——
// 正當使用者需要知道該找管理員，而不是重試密碼。
//
// # 對外只有機器碼
//
// 回應是 403 ＋ `AUTH_SOURCE_NOT_ALLOWED`，**不回顯來源位址，也不回顯清單**。
// 位址、命中的清單快照、政策損壞的成因一律只進審計列——那是稽核要看的，
// 不是攻擊者該拿到的。政策不可用（清單讀不到或字串損壞）對外走**同一個碼**，
// 歸因只在審計；對外分岔等於告訴呼叫端「這個帳號的政策壞了」。

// sourcePolicyReader 判定點的清單讀取面（窄 port）。
//
// 由 `identity.AuthService` 滿足。宣告在消費端而非提供端，是為了讓判定點
// 只依賴「讀一個字串」這件事，不把整個認證服務拖進來。
type sourcePolicyReader interface {
	// ReadSourcePolicy 現讀該使用者的允許來源網段儲存字串。
	// 讀取失敗時回傳的 error 必須交給 sourceip.Evaluate（fail-close），不得忽略
	ReadSourcePolicy(userID uint) (string, error)
}

// sourceDenyAudit 拒絕留痕的轉接。
//
// helper 只產生「拒絕註記」字串，由呼叫端沿其**既有**的審計形狀寫出
// （`auditLogin`／`auditAuthEvent*`／`auditPasswordChange`）。不在 helper 內
// 自建一份審計列，是因為那會與各端點既有的列各自演化欄位集，而
// 「某條路徑的拒絕列少了 provider 或來源位址」不會讓任何測試轉紅。
//
// **nil 有明確語義**：該路由掛 `AuditLogMiddleware`，拒絕本來就會被中介層
// 記成一列；helper 改以 `audit_details` 把判定依據併進那一列，不另寫一列
// ——同一次拒絕記兩列會讓稽核報表的「被擋幾次」當場翻倍。
type sourceDenyAudit func(note string)

// requireSourceAllowed 來源限定的單一判定點。
//
// 回傳 true＝放行；false＝已寫出 403 回應與留痕，呼叫端必須立刻 return。
//
// reader 為 nil（未接線）一律**拒絕**：閘門讀不到判定所需的事實時證明不了
// 來源合法，這與世代閘 `ErrEpochGateUnavailable` 同一條 fail-close 紀律。
// 一條漏接的組裝路徑不得讓整套來源限定靜默關掉。
func requireSourceAllowed(reader sourcePolicyReader, c *gin.Context, userID uint,
	deny sourceDenyAudit) bool {
	// 來源位址走全庫唯一取法（未約定可信代理鏈時只採信 socket peer）：
	// 判定與審計列的 ClientIP 必須是同一個值，否則稽核看到的位址不是被判的那個
	ip := sourceip.Of(c)

	var (
		raw     string
		readErr error
	)
	if reader == nil {
		readErr = errSourcePolicyGateUnwired
	} else {
		raw, readErr = reader.ReadSourcePolicy(userID)
	}

	// 判定邏輯全庫一份：讀取失敗＝read_error、字串損壞＝parse_error、
	// 空清單＝不限放行，三態都在 Evaluate 內
	v := sourceip.Evaluate(raw, readErr, ip)
	if v.Allowed {
		return true
	}

	note := sourceDenyNote(v, ip)
	if deny != nil {
		deny(note)
	} else {
		mergeSourceDenyAuditDetails(c, v, ip)
	}
	apierror.Respond(c, http.StatusForbidden, apierror.CodeAuthSourceNotAllowed, nil)
	return false
}

// errSourcePolicyGateUnwired 讀取面未接線。
//
// 走 error 路徑而非布林旗標，是為了讓它與 DB 讀取失敗**收斂到同一條處置**
// （拒絕＋政策不可讀留痕）：兩者對呼叫者而言是同一件事——判定所需的事實取不到。
var errSourcePolicyGateUnwired = errSourcePolicyUnwired{}

type errSourcePolicyUnwired struct{}

func (errSourcePolicyUnwired) Error() string {
	return "來源限定閘未接線：判定點取不到清單讀取面"
}

// sourceDenyNote 拒絕註記（**只進審計**）。
//
// 兩種形狀分得開，正是規格要的：稽核要能把「被擋」歸因到「政策壞了」
// 而不是「來源不對」——後者要找管理員加網段，前者要修資料。
func sourceDenyNote(v sourceip.Verdict, ip string) string {
	parts := []string{v.Reason}
	if v.Cause != "" {
		parts = append(parts, "cause="+v.Cause)
	}
	if ip != "" {
		parts = append(parts, "ip="+ip)
	}
	if len(v.Policy) > 0 {
		parts = append(parts, "policy="+strings.Join(v.Policy, ","))
	}
	return strings.Join(parts, "; ")
}

// mergeSourceDenyAuditDetails 把判定依據併進中介層那一列的 details。
//
// 只用於掛了 `AuditLogMiddleware` 的路由（管理者對他人的三個認證因子端點）：
// 中介層已經會為這次 403 寫一列，此處補上「為什麼被擋」——沒有它，
// 那一列只說得出「403」，稽核分不出來源被擋與權限不足。
func mergeSourceDenyAuditDetails(c *gin.Context, v sourceip.Verdict, ip string) {
	extra := map[string]string{"source_deny": v.Reason}
	if v.Cause != "" {
		extra["source_deny_cause"] = v.Cause
	}
	if ip != "" {
		extra["source_ip"] = ip
	}
	if len(v.Policy) > 0 {
		extra["source_policy"] = strings.Join(v.Policy, ",")
	}
	if existing, ok := c.Get("audit_details"); ok {
		if m, ok := existing.(map[string]string); ok {
			for k, val := range m {
				if _, taken := extra[k]; !taken {
					extra[k] = val
				}
			}
		}
	}
	c.Set("audit_details", extra)
}

// SetSourcePolicyReader 注入清單讀取面（組裝根呼叫）。
//
// 走 setter 而非建構子參數，沿本包既有的 `SetSourceIPBaseline`／
// `SetAuditService` 形態：不需顯式注入的呼叫端零改動，啟用方在組裝階段開啟。
// **未注入即 fail-close**（見 requireSourceAllowed），故遺漏不會變成靜默放行。
func (h *AuthHandler) SetSourcePolicyReader(r sourcePolicyReader) {
	h.sourcePolicy = r
}

// requireSourceAllowed 本地認證流的來源判定（薄包覆，見套件級同名函式）
func (h *AuthHandler) requireSourceAllowed(c *gin.Context, userID uint, deny sourceDenyAudit) bool {
	return requireSourceAllowed(h.sourcePolicy, c, userID, deny)
}

// SetSourcePolicyReader OIDC 流（同上）
func (h *OIDCHandler) SetSourcePolicyReader(r sourcePolicyReader) {
	h.sourcePolicy = r
}

// requireSourceAllowed OIDC 交換點的來源判定
func (h *OIDCHandler) requireSourceAllowed(c *gin.Context, userID uint, deny sourceDenyAudit) bool {
	return requireSourceAllowed(h.sourcePolicy, c, userID, deny)
}

// SetSourcePolicyReader 使用者管理流（管理者對他人認證因子的三個端點）
func (h *UserHandler) SetSourcePolicyReader(r sourcePolicyReader) {
	h.sourcePolicy = r
}

// requireSourceAllowed 管理者端點的來源判定：**依操作者本人的清單**。
//
// 不是依目標帳號的清單——被救援的帳號可能正因為來源受限而進不來，
// 用它的清單判會讓救援永遠做不成。這三個端點是救援路徑，價值最高，
// 而成本只是一次已載入列的欄位比對。
func (h *UserHandler) requireSourceAllowed(c *gin.Context, actorID uint, deny sourceDenyAudit) bool {
	return requireSourceAllowed(h.sourcePolicy, c, actorID, deny)
}

// currentActorID 目前操作者的 userID（管理者端點的判定主體）。
//
// **取自 token claims，不取路徑參數**：判的是「誰在操作」，不是「操作誰」。
// 取不到（理論上不可達——這些路由都掛 AuthMiddleware）回 0，
// 而 0 在 requireSourceAllowed 內讀不到使用者列 → fail-close 拒絕
func currentActorID(c *gin.Context) uint {
	id, _ := middleware.GetCurrentUserID(c)
	return id
}
