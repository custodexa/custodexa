package auditmask

import (
	"sort"
	"strings"
	"testing"
)

// 掃描射程的封口守衛。
//
// `discoverBindSites` 認得的是 **gin 的 body binding**。任何繞過它、自己讀
// `c.Request.Body` 再解 JSON 的端點，會整個逃出 G1／G2 的判定——而且逃得很安靜：
// 守衛照樣全綠，只是那個端點從來不在射程內。
//
// 故此處反過來釘住射程的邊界：碰 gin `*Context.Request.Body` 的檔案必須具名登記。
// 新出現一處未登記的原始 body 讀取即紅，逼人回答「這個端點的審計本文長什麼樣」。
//
// 判定用型別資訊（見 scanResult.RawBodyFiles）而非字串比對：gatewayapi 的
// `ev.Request.Body` 長得一模一樣卻與 HTTP 請求本文無關，字串比對會誤報。
var rawRequestBodyReaders = map[string]string{
	"internal/agentmcp/entry.go":       "MCP JSON-RPC preflight restores the bounded request body for the SDK; HTTP middleware retains default-deny body masking, entry details include only tool/reason/time, and the tool ledger independently strips secrets before Redact",
	"internal/middleware/audit_log.go": "審計中介層本體——它就是那個讀 body 再套遮罩的地方",
	"internal/api/key_management_handler.go": "POST /keys/rewrap：KEK 材料不進 gin binding" +
		"（避免明文停留在結構體），本文全為金鑰材料，遮罩後無可放行內容",
	"internal/api/seal_handler.go": "POST /seal/unseal：解封材料早於認證系統可用，" +
		"留痕由 seal journal 承擔（見 audit-coverage 規格「他體系留痕的明載定調」）",
	"internal/api/seal_authorize.go": "POST /seal/authorize：帳號與密碼於封存期輸入，" +
		"密碼須以可覆寫的 []byte 承載（gin binding 必產生不可覆寫的 string 副本）；" +
		"本文只有 username 與 password，遮罩後無可放行內容，" +
		"留痕由封存期的行程日誌與解封端點的既有機制承擔",
	"internal/api/kek_topology_handler.go": "PUT /keys/topology：請求本文以「該服務商的精確鍵集」" +
		"逐鍵比對（多一鍵少一鍵皆拒），gin binding 的寬鬆語義表達不了這個約束；" +
		"課責不靠 request_body 而靠 handler 自寫的 kek_topology_update 審計列（帶完整前後值摘要），" +
		"另於 audit.endpointAuditFieldSet 為本端點登記 address／region／role_id 為可追蹤",
}

// TestRawRequestBodyReadersAreDeclared 原始 body 讀取點必須具名登記
func TestRawRequestBodyReadersAreDeclared(t *testing.T) {
	scan := scanTree(t)
	if len(scan.Sites) < discoveredAllowlistLowerBound {
		t.Fatalf("只掃到 %d 個請求綁定點（下界 %d）——掃描器失效時集合會退化為空而全綠，"+
			"拒絕在殘缺輸入上判定", len(scan.Sites), discoveredAllowlistLowerBound)
	}
	if len(scan.RawBodyFiles) == 0 {
		t.Fatal("掃不到任何 gin Request.Body 讀取點——審計中介層本身就是一處，" +
			"零結果表示掃描器已失效")
	}

	var undeclared []string
	for f := range scan.RawBodyFiles {
		if _, ok := rawRequestBodyReaders[f]; !ok {
			undeclared = append(undeclared, f)
		}
	}
	sort.Strings(undeclared)
	if len(undeclared) > 0 {
		t.Errorf("以下檔案直接讀 c.Request.Body 卻未登記：%s\n"+
			"繞過 gin binding 的端點會逃出 auditmask 的掃描射程（審計本文無人判定）。"+
			"請在 rawRequestBodyReaders 具名登記理由，並確認該端點的 request_body 內容合乎遮罩判準。",
			strings.Join(undeclared, ", "))
	}

	var stale []string
	for f := range rawRequestBodyReaders {
		if !scan.RawBodyFiles[f] {
			stale = append(stale, f)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("rawRequestBodyReaders 登記了已不再讀 body 的檔案：%s——登記已成化石，請刪除",
			strings.Join(stale, ", "))
	}
}
