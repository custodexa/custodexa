package auditmask

import (
	"sort"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/modules/audit"
)

// 審計遮罩允許清單的機械守衛（任務 6.4）。
//
// # 為什麼可以機械判定
//
// 「哪些欄位課責必要」是語義題，機器判不了。但缺陷的**形狀**是機械的，本檔守的
// 就是形狀，不是語義：
//
//	G1 死鍵：清單裡有一個鍵，全庫卻沒有任何請求 DTO 綁定它 → 那個鍵是錯字或殘留。
//	        這正是既往缺陷的指紋：清單有 `role`（單數），上線的鍵卻是 `roles`。
//	G2 課責空白：某端點的請求本文所有頂層鍵**全部**落在清單外 → 它的審計列
//	        `request_body` 會是清一色 `***MASKED***`，等於有列無內容。
//	G2b 實質空白：可見的頂層鍵**全是識別欄位**，實質欄位一個都不可見 → 審計列
//	        答得出「動到哪一個」，答不出「動成什麼」。見下方判準說明。
//	G3 機密誤放行：清單裡出現名字就帶機密語義的鍵 → 反向的外洩風險。
//
// # G2b 為什麼存在（G2 有系統性漏報）
//
// G2 的觸發條件是「頂層鍵**全部**落在清單外」，於是只要有**一個**無關緊要的鍵
// 可見，它就永遠不報。實測 44 個「有可見欄位」的綁定點中多處只靠一個 `name`
// 撐著：`PUT /oidc-providers/:id` 把 issuer 指到攻擊者控制的端點，寫出的審計列
// 與單純改名逐字相同（`{"name":"...", "issuer":"***MASKED***", ...}`），G2 全綠。
//
// G2b 的判準：**可見欄位全屬識別角色 ＋ 存在非自由文字的隱藏欄位 → 報**。
//
//   - 角色（識別／實質）不是本檔的人工註記，而是 `audit` 套件裡放行清單的**結構**：
//     放行集合由兩個角色 map union 而成，新增放行鍵時沒有「不選角色」這個選項。
//     新端點更不需要任何人填表——綁定點是掃出來的。
//   - **自由文字欄豁免**（`note`／`reason`／`content`／`description`）：這四個名字
//     是放行判準 1 **明文永久禁止**登記的。若一個端點的隱藏欄位只剩它們，G2b 再
//     報也無事可做——那不是課責缺口，是判準的必然結果。要求做不到的事只會逼人
//     關掉守衛。名單與判準 1 的文字逐字對應，擴充它等同修改判準 1。
//   - **刻意不豁免機密語義名**（`secret`／`key`／`token`…）：那份片段清單是 G3 用來
//     **攔阻**放行的，過度攔截在該方向是安全側；反過來用作豁免時，過度匹配會讓
//     `secret_type`／`key_strategy` 這類**實質**欄位把整個端點變成免報，方向剛好相反。
//
// # 為什麼不是「新增端點要有人記得填表」
//
// 綁定點是**掃出來的**（`packages.Load` 帶型別資訊掃整棵 internal 樹），不是人維護
// 的清冊。新端點一出現就自動進入判定：它若沒有任何課責欄位，G2 立刻紅，且必須
// 具名登記理由才能綠。忘了做事的後果是測試紅，不是靜默通過——這與「靠記憶維護
// 的清單」是相反的失效方向。
//
// # 為什麼不改成 default-allow
//
// 守衛好不好寫不是遮罩策略的判準。default-allow 會讓日後新增的欄位在無人察覺下
// 進入不可篡改的審計記錄；default-deny 的代價只是「課責欄位要登記」，而那個代價
// 正由本檔的 G1／G2 承擔。

// discoveredAllowlistLowerBound 綁定點數量下界（fail-close）。
//
// 掃描器一旦壞掉（型別載入退化、AST 形狀改變）會安靜地回空集合，三個守衛同時
// 變成永遠通過。盤查當下為 63 個綁定點，下界取 50：足以擋住「掃描器歸零」，
// 又不會因正常增刪端點而誤報。
const discoveredAllowlistLowerBound = 50

// secretishKeyMarkers 名字即帶機密語義的鍵片段（G3）。
//
// 判準是**名字**而非值：值在執行期才知道，而守衛要在編譯期就擋住「有人把
// client_secret 加進放行清單」這種動作。誤報的代價（要改名或明確論證）遠低於
// 漏報（憑證永久寫進不可刪的審計列）。
var secretishKeyMarkers = []string{
	"password", "passwd", "secret", "token", "credential", "private",
	"cert", "hash", "salt", "signature", "kek", "dek", "otp", "seed",
	"cookie", "key",
}

// freeTextKeys 自由文字欄的鍵名（G2b 的豁免）。
//
// 逐字對應放行判準 1 的括號內容（`note`／`reason`／`content`／`description`）：
// 那條判準**永久**禁止登記它們，故「隱藏欄位只剩自由文字」不是可修的課責缺口。
// 用**全等比對**而非片段比對——片段比對會把 `secret_type` 這種實質欄位一起豁免掉，
// 而 G2b 的每一次豁免都是一次不報。
var freeTextKeys = map[string]bool{
	"note": true, "reason": true, "content": true, "description": true,
}

// knownAccountabilityVoids 具名登記的課責空白（G2／G2b 的例外）。
//
// 鍵＝綁定點識別字（`<package>.<接收者>.<方法>`），值＝為什麼這一列沒有可放行的
// 本文內容。**登記不是赦免**：每一條都是「這個端點的審計列答不出動了什麼」的
// 白紙黑字，數量本身就是債務刻度。
//
// 三類合法理由：
//   - 本文全為機密（憑證／權杖／一次性碼）——放行任何一個都是外洩
//   - 課責由他體系承擔（handler 或 service 自寫專屬審計列）
//   - 本文不含課責內容（純參數，動了什麼由路徑與 resource_id 即可判定）
//
// 清單**不得**用來塞「懶得判斷」的端點：`TestNoStaleAccountabilityVoidEntries`
// 會擋下已經不再空白的登記，逼它下架。
var knownAccountabilityVoids = map[string]string{
	// ── 本文全為機密 ──────────────────────────────────────────────
	"api.(*AuthHandler).ChangePassword": "old_password／new_password 皆為密碼本體",
	// Logout／Refresh 不再綁定任何 request body
	//（憑證改由 httpOnly cookie 攜帶），故已無綁定點可登記——留著即成化石，
	// 由 TestNoStaleAccountabilityVoidEntries 擋下
	"api.(*AuthHandler).MFADisable":       "password 為密碼本體",
	"api.(*AuthHandler).MFAEnable":        "code 為 TOTP 一次性碼",
	"api.(*AuthHandler).MFAEnrollConfirm": "code 為 TOTP 一次性碼",
	"api.(*AuthHandler).MFAVerify":        "code 為一次性碼、pending_token 為持有型憑證",
	"api.(*UserHandler).ChangePassword":   "password 為密碼本體；改密事實由路徑與 resource_id 課責",
	"api.(*OIDCHandler).Exchange":         "browser_secret／ticket 為一次性兌換憑證",
	// Login 的隱藏欄位只有 password（判準 1 永不放行），可見的 username 屬識別角色。
	// 登入的課責不靠 request_body：成功／失敗、來源位址（已改為不可偽造）、
	// MFA 狀態都由登入專屬審計列承擔
	"api.(*AuthHandler).Login": "password 為密碼本體；登入事實、結果與來源位址由登入審計列本身課責",

	// ── 課責由他體系承擔 ──────────────────────────────────────────
	"api.(*SecurityPolicyHandler).Update": "policies 為巢狀 map（違反登記判準 3）；" +
		"handler 逐鍵寫 old→new 專屬審計列（PCI 10.2.2），課責不靠 request_body",

	"sshproxy.(*Handler).HandleCreateTransmissionConsent": "risk_keys 命中 G3 機密語義片段（key）故不放行；" +
		"同意的對象由 asset_id 課責，同意內容由 TransmissionConsent.Record 寫入的立據紀錄承載",

	// ── 本文不含課責內容 ──────────────────────────────────────────
	"api.(*AccessRequestHandler).Reject":    "note 為自由文字；拒絕事實與對象由路徑、resource_id 與 action=reject 課責",
	"api.(*AccessRequestHandler).Revoke":    "note 為自由文字；撤銷事實與對象由路徑、resource_id 與 action=revoke 課責",
	"api.(*AccessReviewHandler).Create":     "note 為自由文字；覆核事實由 access_reviews 表承載",
	"api.(*DailyReviewHandler).Sign":        "note 為自由文字；簽核事實由 daily_reviews 表承載",
	"api.(*AssetHandler).TestConnection":    "timeout 為連線測試參數，非變更內容；測試對象即 resource_id",
	"api.(*AssetHandler).RenameTag":         "from／to 為標籤字面，屬資產標籤維護而非權限變更",
	"api.(*SFTPHandler).Mkdir":              "path 為檔案路徑，檔案操作的課責由 file_transfers／檔案稽核體系承擔",
	"sshproxy.(*Handler).HandleCreateShare": "ttl_minutes 為分享時效參數；分享事實與對象由 session 分享紀錄承載",
}

// TestAuditAllowlistHasNoDeadKeys G1：放行清單不得有沒人綁定的死鍵。
//
// 死鍵有兩種來源，兩種都是缺陷：
//   - 錯字／單複數不符（`role` vs `roles`）——課責欄位其實根本沒被放行
//   - 端點下架後殘留——保留了一個任何請求都能塞任意文字進不可篡改紀錄的鍵
func TestAuditAllowlistHasNoDeadKeys(t *testing.T) {
	sites := discoverBindSites(t)
	if len(sites) < discoveredAllowlistLowerBound {
		t.Fatalf("只掃到 %d 個請求綁定點（下界 %d）——掃描器失效時集合會退化為空而全綠，"+
			"拒絕在殘缺輸入上判定", len(sites), discoveredAllowlistLowerBound)
	}

	bound := map[string][]string{}
	for _, s := range sites {
		for _, f := range s.Fields {
			bound[f] = append(bound[f], s.Key)
		}
	}

	var dead []string
	for _, key := range audit.SafeAuditFieldNames() {
		if len(bound[key]) == 0 {
			dead = append(dead, key)
		}
	}
	sort.Strings(dead)
	if len(dead) > 0 {
		t.Errorf("放行清單有 %d 個死鍵（沒有任何請求 DTO 綁定）：%s\n"+
			"死鍵的意思是「清單與真正上線的欄位名對不上」——既往缺陷即此形態："+
			"清單有 role（單數），上線的鍵是 roles（複數），於是升權審計列全是遮罩標記。\n"+
			"修法二擇一：改成真正被綁定的鍵名，或把該鍵刪掉。",
			len(dead), strings.Join(dead, ", "))
	}
}

// TestNoEndpointHasFullyMaskedAuditBody G2：沒有端點的審計本文全是遮罩標記。
func TestNoEndpointHasFullyMaskedAuditBody(t *testing.T) {
	sites := discoverBindSites(t)
	if len(sites) < discoveredAllowlistLowerBound {
		t.Fatalf("只掃到 %d 個請求綁定點（下界 %d）——拒絕在殘缺輸入上判定",
			len(sites), discoveredAllowlistLowerBound)
	}

	allowed := map[string]bool{}
	for _, k := range audit.SafeAuditFieldNames() {
		allowed[k] = true
	}

	for _, s := range sites {
		visible := visibleFields(s.Fields, allowed)
		if len(visible) > 0 {
			continue
		}
		if _, declared := knownAccountabilityVoids[s.Key]; declared {
			continue
		}
		t.Errorf("%s（%s:%d）的請求本文全被遮罩：欄位 %s 沒有任何一個在放行清單內。\n"+
			"這一列寫進 audit_logs 後 request_body 會是清一色 ***MASKED***，"+
			"稽核答不出「動了什麼、變成什麼」。\n"+
			"修法二擇一：把課責必要的非機密欄位登記進 audit.safeAuditFields（判準見該處註解），"+
			"或在 knownAccountabilityVoids 具名登記理由。",
			s.Key, s.File, s.Line, strings.Join(s.Fields, ", "))
	}
}

// TestNoEndpointIsIdentityOnlyVisible G2b：沒有端點的審計本文只剩識別欄位可見。
//
// 判準與豁免的理由見檔頭「G2b 為什麼存在」。與 G2 的關係是**擴張而非取代**：
// G2 管「一個都看不見」，G2b 管「看得見的都答不出動成什麼」。
func TestNoEndpointIsIdentityOnlyVisible(t *testing.T) {
	sites := discoverBindSites(t)
	if len(sites) < discoveredAllowlistLowerBound {
		t.Fatalf("只掃到 %d 個請求綁定點（下界 %d）——拒絕在殘缺輸入上判定",
			len(sites), discoveredAllowlistLowerBound)
	}

	for _, s := range sites {
		reason, ok := identityOnlyReport(s)
		if !ok {
			continue
		}
		if _, declared := knownAccountabilityVoids[s.Key]; declared {
			continue
		}
		t.Errorf("%s（%s:%d）的審計本文只剩識別欄位可見：%s。\n"+
			"實質欄位 %s 全被遮成 ***MASKED***——這一列答得出「動到哪一個」，"+
			"答不出「動成什麼」，於是「把安全開關關掉」與「改個名字」寫出同一列。\n"+
			"修法二擇一：把課責必要的非機密欄位登記進 audit.safeAuditSubstanceFields"+
			"（判準見該處註解），或在 knownAccountabilityVoids 具名登記理由。",
			s.Key, s.File, s.Line, reason,
			strings.Join(nonFreeTextHidden(s, allowedFieldSet()), ", "))
	}
}

// identityOnlyReport 判定綁定點是否命中 G2b，並回傳可讀的可見欄位描述。
func identityOnlyReport(s bindSite) (string, bool) {
	allowed := allowedFieldSet()
	substance := map[string]bool{}
	for _, k := range audit.SafeAuditSubstanceFieldNames() {
		substance[k] = true
	}
	for _, f := range s.Fields {
		if substance[f] {
			return "", false // 有實質欄位可見
		}
	}
	visible := visibleFields(s.Fields, allowed)
	if len(visible) == 0 {
		return "", false // 全遮：屬 G2 的射程，不重複報
	}
	if len(nonFreeTextHidden(s, allowed)) == 0 {
		return "", false // 隱藏的只剩自由文字欄（判準 1 永不放行），無事可做
	}
	return strings.Join(visible, ", "), true
}

// nonFreeTextHidden 取被遮罩且**不是**自由文字欄的鍵。
func nonFreeTextHidden(s bindSite, allowed map[string]bool) []string {
	var out []string
	for _, f := range s.Fields {
		if !allowed[f] && !freeTextKeys[f] {
			out = append(out, f)
		}
	}
	return out
}

func allowedFieldSet() map[string]bool {
	allowed := map[string]bool{}
	for _, k := range audit.SafeAuditFieldNames() {
		allowed[k] = true
	}
	return allowed
}

// TestAuditFieldRolesAreDisjoint 兩個角色互斥。
//
// 同一個鍵若同時登記在識別與實質兩組，G2b 的判定就沒有意義了（它永遠有實質
// 欄位可見）。角色由結構保證「一定要選一個」，本測試補上「不能兩個都選」。
func TestAuditFieldRolesAreDisjoint(t *testing.T) {
	identity := map[string]bool{}
	for _, k := range audit.SafeAuditIdentityFieldNames() {
		identity[k] = true
	}
	var both []string
	for _, k := range audit.SafeAuditSubstanceFieldNames() {
		if identity[k] {
			both = append(both, k)
		}
	}
	sort.Strings(both)
	if len(both) > 0 {
		t.Errorf("放行鍵 %s 同時登記為識別與實質角色——角色必須二擇一，"+
			"否則 G2b 的「只剩識別欄位可見」判定會被自己的輸入抵銷",
			strings.Join(both, ", "))
	}
	total := len(audit.SafeAuditFieldNames())
	if want := len(identity) + len(audit.SafeAuditSubstanceFieldNames()); total != want {
		t.Errorf("放行集合 %d 個鍵，兩角色合計 %d ——union 與角色來源已不一致", total, want)
	}
}

// TestNoStaleAccountabilityVoidEntries 空白登記表本身的保鮮。
//
// 兩種失效：登記的綁定點已經不存在（handler 改名／下架），或它已經不會被 G2／G2b
// 報了（課責空白已補上，或欄位形態改變）。兩種都會讓表變成沒人看的化石——而化石
// 條目會**吸收**日後真正的回歸（該端點新增的實質欄位被遮，卻因登記而免報），
// 故一律紅。
func TestNoStaleAccountabilityVoidEntries(t *testing.T) {
	sites := discoverBindSites(t)
	if len(sites) < discoveredAllowlistLowerBound {
		t.Fatalf("只掃到 %d 個請求綁定點（下界 %d）——拒絕在殘缺輸入上判定",
			len(sites), discoveredAllowlistLowerBound)
	}

	allowed := map[string]bool{}
	for _, k := range audit.SafeAuditFieldNames() {
		allowed[k] = true
	}
	byKey := map[string]bindSite{}
	for _, s := range sites {
		byKey[s.Key] = s
	}

	keys := make([]string, 0, len(knownAccountabilityVoids))
	for k := range knownAccountabilityVoids {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		site, ok := byKey[k]
		if !ok {
			t.Errorf("knownAccountabilityVoids 登記了 %q，但全庫掃不到這個請求綁定點——"+
				"登記已成化石（handler 改名或下架？），請刪除或更新", k)
			continue
		}
		visible := visibleFields(site.Fields, allowed)
		if _, hit := identityOnlyReport(site); len(visible) > 0 && !hit {
			t.Errorf("knownAccountabilityVoids 仍登記 %q，但它已有可見的實質欄位（可見欄位 %s）——"+
				"課責空白已補上，登記須下架（留著會遮蔽日後真正的回歸）",
				k, strings.Join(visible, ", "))
		}
	}
}

// TestAuditAllowlistRejectsSecretishKeys G3：放行清單不得出現機密語義的鍵。
//
// 反向風險：課責的壓力會誘使人「順手」把 client_secret／bind_password 之類加進來，
// 而那會讓憑證明文永久封存在受檢查點鏈保護、刪不掉的審計列裡。
func TestAuditAllowlistRejectsSecretishKeys(t *testing.T) {
	for _, key := range audit.SafeAuditFieldNames() {
		lower := strings.ToLower(key)
		for _, marker := range secretishKeyMarkers {
			if strings.Contains(lower, marker) {
				t.Errorf("放行清單含機密語義的鍵 %q（命中片段 %q）——"+
					"憑證、金鑰、權杖、密碼一律維持遮罩，不因課責需求而放行", key, marker)
			}
		}
	}
}

// TestBindSitesAreJSONTagged 綁定 DTO 的欄位一律要有 json tag。
//
// 無 tag 的欄位其 JSON 鍵名取決於 encoding/json 的預設規則，掃描器與遮罩清單
// 會對不上同一個名字——那是 G1／G2 靜默失效的入口。
func TestBindSitesAreJSONTagged(t *testing.T) {
	for _, s := range discoverBindSites(t) {
		if len(s.Untagged) > 0 {
			t.Errorf("%s（%s:%d）的綁定結構有無 json tag 的欄位 %s——"+
				"請補上 tag，否則遮罩清單與實際 JSON 鍵名會對不上",
				s.Key, s.File, s.Line, strings.Join(s.Untagged, ", "))
		}
	}
}

// visibleFields 取綁定欄位中會原樣入審計的那些
func visibleFields(fields []string, allowed map[string]bool) []string {
	var out []string
	for _, f := range fields {
		if allowed[f] {
			out = append(out, f)
		}
	}
	return out
}
