package api

// 來源限定閘的測試支援。
//
// 閘門 fail-close（讀取面未接線即拒絕），故**任何走來源強制點的 handler 測試
// 都必須顯式表態**「這個案例的來源政策是什麼」。這是刻意的成本：
// 預設放行才是危險的那一側——一條漏接注入的組裝路徑會讓整套來源限定
// 靜默關掉，而沒有任何測試會轉紅。
//
// 既有案例一律注入「空清單＝不限」的替身，使其判定行為與本功能上線前逐字相同；
// 來源判定本身由 source_policy_gate_test.go 專測。

// fixedSourcePolicy 固定回覆的政策讀取替身。
type fixedSourcePolicy struct {
	raw string
	err error
}

func (p fixedSourcePolicy) ReadSourcePolicy(uint) (string, error) { return p.raw, p.err }

// unrestrictedSourcePolicy 空清單＝不限（既有案例的預設表態）。
func unrestrictedSourcePolicy() sourcePolicyReader { return fixedSourcePolicy{} }

// newTestUserHandler 建 UserHandler 並表態「不限來源」。
func newTestUserHandler(svc UserServiceInterface) *UserHandler {
	h := NewUserHandler(svc)
	h.SetSourcePolicyReader(unrestrictedSourcePolicy())
	return h
}
