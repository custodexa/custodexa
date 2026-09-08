package identity

import (
	"strings"

	"github.com/custodexa/backend/internal/model"
)

// 身分提供者途徑的群組觀測：把已驗證身分權杖裡的宣告，判成三態之一。
//
// # 為什麼只讀身分權杖
//
// 群組資訊只取自登入當次的身分權杖：不呼叫使用者資訊端點、不索取離線存取範圍、
// 不保存提供者的刷新權杖。多一條取值管道就多一條需要憑證、需要輪替、需要在
// 提供者停用後同步收線的路徑，而它換到的只是「權杖裡本來就該有的東西」。
//
// # 溢出指示為什麼必須偵測
//
// 群組數超過提供者的權杖容量上限時，有的提供者不是截斷、也不是回空陣列，
// 而是把群組宣告整個拿掉，改放一組「請自己去另一個端點取」的指示鍵。
// 若只看「鍵在不在」，這種使用者會被判成不屬於任何群組——他往往正是群組最多、
// 權限最高的那一位，而失敗方向是把他默默降權。故指示鍵一出現即判未知，
// 保留既有映射列。

// oidcGroupOverflowClaims 提供者的群組溢出指示鍵。
//
// 任一鍵存在即代表「群組資訊不在這張權杖裡，要另外去取」，與「這個人沒有群組」
// 是完全不同的事實。三個鍵並列而不是只認一個：同一家提供者在不同權杖尺寸下
// 走的是不同的指示形態。
var oidcGroupOverflowClaims = []string{"_claim_names", "_claim_sources", "hasgroups"}

// oidcGroupObservation 由 provider 設定與已驗證的原始宣告組出群組觀測。
//
// 三態的判準（缺一即選錯失敗方向）：
//
//	宣告名未設定          unconfigured——此 provider 不依外部群組決定角色
//	偵測到溢出指示        unknown——群組不在這張權杖裡，既有映射一律保留
//	鍵存在且為字串陣列    known
//	鍵不存在且無溢出指示  known ＋ 空集合（該收回的角色要收回）
//	鍵存在但型別不符      unknown——不做寬鬆轉型，猜錯的方向是誤配角色
func oidcGroupObservation(p *model.OIDCProvider, raw map[string]any, hasActiveRules bool) GroupObservation {
	obs := GroupObservation{
		Kind:     model.RoleMappingChannelKindProvider,
		SourceID: p.ID,
	}
	claim := strings.TrimSpace(p.GroupsClaim)
	if claim == "" {
		obs.State = GroupObservationUnconfigured
		obs.HasActiveRules = hasActiveRules
		return obs
	}
	state, groups := groupsClaimTriState(raw, claim)
	obs.State = state
	obs.Groups = groups
	return obs
}

// groupsClaimTriState 單一宣告的三態判定。
//
// **溢出指示先於鍵本身判斷**：指示鍵與群組宣告可能同時出現（提供者送出部分
// 清單並標示尚有更多），此時那份部分清單不是完整事實，據以重算會撤掉沒被
// 列進去的那些群組所給的角色。
func groupsClaimTriState(raw map[string]any, claimName string) (GroupObservationState, []string) {
	if raw == nil {
		return GroupObservationUnknown, nil
	}
	for _, key := range oidcGroupOverflowClaims {
		if _, ok := raw[key]; ok {
			return GroupObservationUnknown, nil
		}
	}
	v, ok := raw[claimName]
	if !ok {
		// 鍵不存在且無溢出指示＝這個人不屬於任何群組。判成未知的話，
		// 「被移出最後一個群組」的人永遠不會被撤權——那正是本能力要解的事
		return GroupObservationKnown, nil
	}
	items, ok := v.([]any)
	if !ok {
		return GroupObservationUnknown, nil
	}
	groups := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			// 陣列裡混進非字串＝這不是一份群組清單。只取得出來的那幾個
			// 等於拿殘缺集合當完整事實，會撤掉沒被解出來的那些角色
			return GroupObservationUnknown, nil
		}
		groups = append(groups, s)
	}
	return GroupObservationKnown, groups
}
