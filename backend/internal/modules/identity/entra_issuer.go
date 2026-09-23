package identity

import (
	"net/url"
	"strings"
)

// entraIssuerHost Microsoft Entra ID 的 issuer 主機（全球雲）
const entraIssuerHost = "login.microsoftonline.com"

// isEntraIssuer issuer 是否指向 Microsoft Entra ID。
//
// 只看主機：租戶專屬（/<tenant>/v2.0）與多租戶端點（common 等）都屬同一家，
// 而建議的正式設定是租戶專屬 issuer，路徑比對會把它漏掉。
// 解析失敗回 false——此判斷只用於放寬「缺 groups 範圍」的確認，認不出來時
// 維持較嚴的一般行為是安全的方向
func isEntraIssuer(issuer string) bool {
	u, err := url.Parse(strings.TrimSpace(issuer))
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Hostname(), entraIssuerHost)
}

// groupsScopeMissing 設了群組宣告名卻沒帶 groups 授權範圍，且該提供者需要這個範圍。
//
// Entra 的群組宣告由其權杖設定決定，與授權範圍無關；且它不接受名為 groups 的
// 範圍（帶了反而登入被拒），故對 Entra 不成立
func groupsScopeMissing(issuer, groupsClaim, scopes string) bool {
	if groupsClaim == "" || scopesContainGroups(scopes) {
		return false
	}
	return !isEntraIssuer(issuer)
}
