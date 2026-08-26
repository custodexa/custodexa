package identity

import (
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sourceip"
)

// 使用者允許來源網段清單的 service 層轉換：DB 存逗號分隔的正規化前綴字串，
// API 以字串陣列進出；驗證、正規化與涵蓋狀態一律經 sourceip 單一實作——
// 介面不自行推算，避免兩套涵蓋邏輯分歧。

// normalizeAllowedCIDRs 驗證並正規化清單，回傳儲存形式。
// 任一項不合法或去重後超過上限即整體回錯（sourceip.ErrPrefixInvalid／
// ErrTooManyPrefixes，handler 據此對映機器碼）；不靜默丟棄任何項目。
func normalizeAllowedCIDRs(list []string) (string, error) {
	if len(list) == 0 {
		return "", nil
	}
	_, normalized, _, valid := sourceip.Inspect(list)
	if !valid {
		if _, err := sourceip.ParsePrefixes(list); err != nil {
			return "", err
		}
	}
	return sourceip.JoinStored(normalized), nil
}

// DecorateSourcePolicy 把儲存字串攤成 API 形狀：清單陣列＋有效涵蓋狀態＋家族。
//
// 儲存值一律經驗證後寫入，正常情況必可解析；若解析失敗（資料庫直寫或程式缺陷，
// 判定點對此 fail-close 拒絕），此處仍把原始項目攤給管理端看——管理者要能看見
// 損壞的內容才修得掉，狀態以可解析的項目計算。
func DecorateSourcePolicy(u *model.User) {
	if u == nil {
		return
	}
	list := sourceip.SplitStored(u.AllowedCIDRs)
	prefixes, _, _, _ := sourceip.Inspect(list)
	status, families := sourceip.CoverageStatus(prefixes)
	if len(list) > 0 && len(prefixes) == 0 {
		// 全部項目都解析失敗：不是「不限」，判定點會拒絕一切來源
		status = sourceip.StatusRestricted
	}
	u.AllowedCIDRList = list
	u.AllowedCIDRsStatus = status
	u.AllowedCIDRFamilies = families
}

// decorateSourcePolicyAll 列表版。
func decorateSourcePolicyAll(users []model.User) {
	for i := range users {
		DecorateSourcePolicy(&users[i])
	}
}
