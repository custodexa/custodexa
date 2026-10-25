package asset

import "github.com/custodexa/backend/internal/model"

// 輪替成員首次派送前的「派送證據分類」。
//
// 判定分兩層，資料契約各自獨立：
//
//   - 分流層（classifyMemberDelivery）：成員在轉 changing 之後、建回呼與重建候選副本之前，
//     以讀到的成員列、所屬輪替的模式、（整組模式）當下該帳號的候選列是否存在算出路線。
//     模式與重建前的候選列只在這一層可知：握手時 ensureCandidate 已改變候選列，不可重驗。
//   - 交易層（memberBindEligibleSQL）：綁定寫入的條件式 UPDATE 在 assets 列鎖內只重驗
//     state、host_key_binding、secret_sent_at 三項，擋住「讀列到寫入之間標記被寫入」的競態。
//     「候選列存在」只是分流層的執行期防禦，不進這一層。

// deliveryRoute 成員首次派送的路線。
type deliveryRoute int

const (
	// deliveryRouteBind 尚無已送出的證據：派送前寫入（或重寫）主機身分快照
	deliveryRouteBind deliveryRoute = iota
	// deliveryRoutePinned 已綁定且秘密已送出或結果未知：沿原快照比對，不重綁
	deliveryRoutePinned
	// deliveryRouteBlocked 沒有可比對的歷史身分，而秘密已送出或結果未知：撥號前停止
	deliveryRouteBlocked
)

// memberBindEligibleSQL 交易層的綁定資格條件（接在 `WHERE id = ? AND ` 之後）。
// 與 classifyMemberDelivery 的 deliveryRouteBind 在「鎖內可重驗」的部分一致：
// 成員在 changing；且 pending，或 bound／legacy 且派送標記為 NULL。
const memberBindEligibleSQL = `state = 'changing' AND (host_key_binding = 'pending' OR ` +
	`(host_key_binding IN ('bound', 'legacy') AND secret_sent_at IS NULL))`

// classifyMemberDelivery 依派送證據決定成員首次派送的路線。
//
// mode 為所屬輪替的模式；groupCandidateExists 為分流當下（尚未 ensureCandidate）整組模式下
// 該帳號的候選列是否存在，拆分模式不看候選列（起始交易就替每個成員建好候選，
// 乾淨失敗也不刪，存在與否都不是送出證據）。
//
// 不看 LastError、成員狀態名或候選的 applied 旗標。未知的綁定值 fail-closed（Blocked）。
func classifyMemberDelivery(m *model.CredentialRotationMember, mode string, groupCandidateExists bool) deliveryRoute {
	sent := m.SecretSentAt != nil
	switch m.HostKeyBinding {
	case model.HostKeyBindingPending:
		// pending 證明沒有完成過任何金鑰交換，一定沒有送出過認證
		return deliveryRouteBind
	case model.HostKeyBindingBound:
		if sent {
			return deliveryRoutePinned
		}
		return deliveryRouteBind
	case model.HostKeyBindingLegacy:
		if sent {
			return deliveryRouteBlocked
		}
		if mode != model.CredentialRotationModeSplit && groupCandidateExists {
			return deliveryRouteBlocked
		}
		// 歷史無從得知：視為未送出，首次派送照常綁定
		return deliveryRouteBind
	}
	return deliveryRouteBlocked
}
