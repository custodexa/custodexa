package policy

import "strings"

// LDAP 設定的執行期風險視圖（自 identity 遷入，modular-architecture W3 3.2／R3.1 §3.5）。
//
// **為何整組遷入而非只搬兩型**：R3 §4.1 原只搬 `LDAPRiskResult`／`LDAPRiskView`，
// 環未斷——policy 仍消費 identity 的 `LDAPRisksOf` 與 `LDAPResolveState`＋3 常數。
// R3.1 §3.5 訂正為 6 項一併遷入（型別＋3 常數＋兩個視圖型別＋純函式），identity
// 反過來以 `policy.LDAPRisksOf` 消費（方向 identity→policy ✔）。
//
// 型別本體逐字未改；identity 側的 `LDAPDialSnapshot` 仍內嵌本檔的 `LDAPRiskView`
// （跨包內嵌，欄名不變仍為 `LDAPRiskView`），故「閘檢查與撥號同一次解析」的型別
// 保證不受搬遷影響。

// ── 執行期解析：三態與兩型（2.7 / D2）────────────────────────────────────

// LDAPResolveState 設定解析的三態。
//
// **故障不得以 nil 併吞成「未設定」**（D2／R2-opus N3）：DEK 事故下若清冊顯示
// 「LDAP 未啟用」而設定頁顯示「已啟用」，兩個管理面互相打臉且指向錯誤的排錯
// 方向（管理者會去找「誰把 LDAP 關掉了」，而真因是金鑰）。
type LDAPResolveState string

const (
	// LDAPResolveUnconfigured 無 live 列——功能未設定，登入流程與 LDAP 未啟用同語義
	LDAPResolveUnconfigured LDAPResolveState = "unconfigured"
	// LDAPResolveOK 解析成功。**注意 View.Enabled 仍可能為 false**（草稿列）：
	// 「有設定但停用」與「根本沒設定」在清冊上是兩種不同的呈現
	LDAPResolveOK LDAPResolveState = "ok"
	// LDAPResolveFailed 解析失敗（DB 查詢錯誤或密文解密失敗）——fail-close
	LDAPResolveFailed LDAPResolveState = "failed"
)

// LDAPRiskView 非撥號消費端的設定視圖：**不含 bind 密碼**。
//
// 風險判定只需三個值，卻與撥號共用同一型別會使明文 bind 密碼被帶進清冊、資產
// 徽章等非撥號呼叫棧（TransmissionPolicyService 為多處共用），與「write-only、
// 讀取回應不含明文」的收口方向相反。故拆型（D2）。
type LDAPRiskView struct {
	Enabled       bool
	URL           string
	SkipTLSVerify bool
}

// LDAPRiskResult 供 policy／清冊消費的三態解析結果
type LDAPRiskResult struct {
	State LDAPResolveState
	View  LDAPRiskView
	// Err 僅於 State=failed 時非 nil；供伺服端 log 使用，不供對外呈現
	Err error
}

// LDAPRisksOf 由設定視圖判定傳輸風險（純函式版本）。
//
// **判準與 TransmissionPolicyService.LDAPRisks 逐行等價**，含兩個刻意保留的
// 細節：(1) 以 `ldaps://` 字面前綴判定而非解析後的 scheme——兩者對合法輸入
// 同義，但保持與既有實作 byte-level 一致，使 2.9 的來源切換是純粹的「換資料
// 來源」而非「順手改判準」；(2) 明文與跳過驗證**互斥回報**（非 ldaps 時不再
// 檢查 skip_tls_verify），因為明文連線下憑證驗證本就不存在，兩項並列會讓
// 使用者以為修好 skip 就沒事。
//
// 未啟用＝通道不存在，無風險項。
func LDAPRisksOf(view LDAPRiskView) []RiskItem {
	if !view.Enabled {
		return nil
	}
	if !strings.HasPrefix(strings.ToLower(view.URL), "ldaps://") {
		return []RiskItem{newRisk(RiskLDAPPlaintext, nil)}
	}
	if view.SkipTLSVerify {
		return []RiskItem{newRisk(RiskLDAPSkipVerify, nil)}
	}
	return nil
}
