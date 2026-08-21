package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// DedicatedIssuerDeclarationDigest 部署層專用 issuer 宣告的內容指紋
// （idp-oidc-integration 3.10a）。
//
// 為什麼需要它：`OIDC_DEDICATED_ISSUERS` 是**部署層**設定，多副本部署下每個副本
// 各讀各的環境變數。滾動更新期間、或某個副本的環境檔漏改，就會出現「同一個 issuer
// 在副本 A 判為專用、在副本 B 判為共用」——症狀是使用者的自動供應時靈時不靈，
// 且任何單一副本的管理端畫面都顯示為正確。把指紋放進健康檢查輸出後，副本間的
// 設定分歧可由外部（監控／部署腳本比對各副本 /health）直接偵測。
//
// **輸出指紋而非原文**：健康檢查端點無須認證，原文會把部署方的 IdP 拓樸
// （自架 IdP 主機名、租戶識別）洩漏給任何可觸及該端點的人。指紋只能回答
// 「兩個副本是否一致」，這正是此處唯一需要的問題。
//
// 正規化與 EffectiveIssuerKind **同源**（normalizeIssuer）並經排序去重，
// 故指紋相等等價於「兩副本的宣告在判定上等效」：尾斜線、大小寫、順序與重複項的
// 差異不會製造假分歧警報，而任何會改變判定結果的差異必然改變指紋。
//
// 空宣告亦回傳固定指紋（非空字串）——「未宣告」與「有宣告」必須可被區分，
// 若空值回空字串，一個環境變數整個漏掉的副本在輸出上會與「欄位不存在」混淆。
func DedicatedIssuerDeclarationDigest(declared []string) string {
	canonical := make([]string, 0, len(declared))
	seen := make(map[string]bool, len(declared))
	for _, d := range declared {
		v := normalizeIssuer(d)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		canonical = append(canonical, v)
	}
	sort.Strings(canonical)
	// 以換行分隔而非直接串接：避免 ["ab","c"] 與 ["a","bc"] 折疊成同一輸入
	sum := sha256.Sum256([]byte(strings.Join(canonical, "\n")))
	return hex.EncodeToString(sum[:])[:12]
}
