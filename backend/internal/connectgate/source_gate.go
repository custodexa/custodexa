package connectgate

import (
	"net/http"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/sourceip"
)

// 來源限定閘（G1）的**共用判定**：簽發側與兩條兌換側共三處消費它。
//
// # 為何三處共用一份
//
// 三道閘的判定內容逐字相同（現讀清單 → 正規化 → 比對來源）。各寫一份的症狀
// 不是重複程式碼，而是**分歧**：某一側漏了 IPv4-mapped 位址的 Unmap，
// 於是「簽發擋、兌換放行」或反過來，而兩者的測試各自都會過。
//
// # 為何住在骨架包
//
// `internal/sshproxy` 與 `internal/proxy` 之間沒有共用的下游包可放它，而讓
// sshproxy 去 import proxy 的內部判定會把「兩條協議入口」的依賴方向弄反。
// 骨架包本來就是兩者共用的下游，且它已經是 `Outcome` 的家。

// SourceOutcome 依儲存的清單字串與來源位址作成一次來源限定判定。
//
// 回傳 (nil, "") 代表通過。拒絕時回 403：
//
//	對外碼固定為 `AUTH_SOURCE_NOT_ALLOWED`，機器欄 `reason` 固定為
//	`source_not_allowed`——**政策不可用（讀不到或字串損壞）走同一組值**，
//	對外不分岔。分岔等於告訴呼叫端「這個帳號的政策壞了」，那是探測面。
//
// 第二個回傳值是**成因類別**（`read_error`／`parse_error`，通過或單純不落清單時
// 為空）：它只進審計，讓稽核能把「被擋」歸因到「政策壞了」而非「來源不對」。
// 兩者的處置完全不同——後者要找管理員加網段，前者要修資料。
//
// **回應不回顯位址與清單**（`Meta` 只有 reason）：位址與命中的清單快照
// 只出現在拒絕留痕裡。
func SourceOutcome(raw, ip string) (*Outcome, string) {
	// readErr 恆為 nil：清單由呼叫端在角色現查的同一次載入取得，
	// 「讀不到使用者列」在那一步就已經是 connectionAuthError 的拒絕，
	// 走不到本閘。字串損壞則由 Evaluate 判為 parse_error
	v := sourceip.Evaluate(raw, nil, ip)
	if v.Allowed {
		return nil, ""
	}
	return Deny(http.StatusForbidden, string(apierror.CodeAuthSourceNotAllowed),
		map[string]any{"reason": sourceip.ReasonSourceNotAllowed}), v.Cause
}
