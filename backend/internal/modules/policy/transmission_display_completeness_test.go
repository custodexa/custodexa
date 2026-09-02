package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// 後端顯示字串 i18n 完備性測試：三個 registry / policy 表為
// 單一事實源，locale 三語必與之 bijection、zh 不漂移、placeholder 三語一致、en/ja
// 非複製 zh。重用 error-codes 建立的 docker locale mount（APIERROR_LOCALE_DIR），
// host `go test` 走 module 錨點 fallback（見 displayLocaleDir）。

// displayLocaleDir 定位三語 locale 目錄。
//
// 容器內走 APIERROR_LOCALE_DIR 唯讀掛載（error-codes 既有的掛載，刻意共用）；
// host 直跑走 fallback。**fallback 不再以「本測試檔往上三層」推算**——那與本
// package 的樹深綁死，package 下移一層就指到不存在的目錄，而 locale 讀不到時
// 的失敗訊息會指向錯的原因。改以 repoParent（go.mod module 錨點上溯一層＋
// marker 存在性驗證，見 aad_write_guard_test.go）。
func displayLocaleDir(t *testing.T) string {
	t.Helper()
	if d := os.Getenv(displayLocaleEnv); d != "" {
		return d
	}
	return displayLocaleFallbackDir(repoParent(t, displayLocaleRel))
}

// displayLocaleEnv locale 目錄的環境覆寫鍵（容器內走唯讀掛載）
const displayLocaleEnv = "APIERROR_LOCALE_DIR"

// displayLocaleFallbackDir 由**專案根**（backend module 根的上一層）算出 locale 目錄。
//
// 抽成純函式是為了讓 fallback 路徑本身可被測試：`repoParent` 在容器內必然 Fatal
// （backend 掛在 /app，其上一層沒有 frontend/），故容器裡永遠走不到 fallback 分支，
// 「fallback 算得對不對」在 docker 內無從以整合方式驗證。
// TestDisplayLocaleFallbackIsProjectRootAnchored 改以合成的專案根目錄驗它。
func displayLocaleFallbackDir(projectRoot string) string {
	return filepath.Join(projectRoot, filepath.FromSlash(displayLocaleRel))
}

// displayLocaleRel locale 目錄相對專案根（backend 的上一層）的路徑。
const displayLocaleRel = "frontend/src/i18n/locales"

// minDisplayLocaleKeys 單一 locale 檔在受管 namespace 下的鍵數下限（防空集合假綠）。
// 2026-08-09 三語各實測 65 鍵（見 TestBackendDisplayTranslationsComplete 的 t.Logf），門檻取 58。
const minDisplayLocaleKeys = 58

var displayLocales = []string{"zh-TW", "en-US", "ja-JP"}

// displayNamespaces 本 change 新增的 6 個後端顯示字串 namespace
var displayNamespaces = []string{
	"policyLabel", "policyUnit", "riskLabel",
	"transportNote", "transportPreflight", "transportDetail",
}

func loadDisplayLocale(t *testing.T, dir, locale string) map[string]map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, locale+".json"))
	if err != nil {
		t.Fatalf("read %s locale: %v", locale, err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s locale: %v", locale, err)
	}
	out := map[string]map[string]string{}
	for _, ns := range displayNamespaces {
		m := map[string]string{}
		if rm, ok := doc[ns]; ok {
			if err := json.Unmarshal(rm, &m); err != nil {
				t.Fatalf("parse %s.%s: %v", locale, ns, err)
			}
		}
		out[ns] = m
	}
	return out
}

// expectedZhByNamespace 由後端單一事實源導出各 namespace 的 zh template（zh-drift 基準）
func expectedZhByNamespace() map[string]map[string]string {
	m := map[string]map[string]string{}
	for _, ns := range displayNamespaces {
		m[ns] = map[string]string{}
	}
	for _, d := range policyDefs {
		m["policyLabel"][d.Key] = d.Label
		if d.UnitKey != "" {
			m["policyUnit"][d.UnitKey] = d.Unit
		}
	}
	for k, d := range AllRiskDescriptors() {
		m["riskLabel"][k] = d.ZhTemplate
	}
	for code, d := range AllInventoryDescriptors() {
		if d.Kind == invKindNote {
			m["transportNote"][code] = d.ZhTemplate
		} else {
			m["transportPreflight"][code] = d.ZhTemplate
		}
	}
	m["transportDetail"]["unset"] = detailUnsetZh
	return m
}

// displaySameValueAllowlist 列 en/ja 合法與 zh 相同的 "ns.code"。
// policyUnit.persons：日文計數人的單位亦為「人」（nin），與 zh 同字屬正確翻譯非漏譯。
// policyUnit.seconds：日文的秒亦寫作「秒」（byō），與 zh 同字屬正確翻譯非漏譯。
var displaySameValueAllowlist = map[string]bool{
	"policyUnit.persons": true,
	"policyUnit.seconds": true,
}

func equalStrSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// checkDisplayTranslations 完備性判準**純函式版**：回傳違規訊息清單。
//
// **為何抽成純函式**：原本判準直接寫在 t.Errorf 裡，於是「判準本身是否真的會抓」
// 無從證明——locale 檔全部正確時它必然零輸出，而「零輸出」與「判準失效」在
// 斷言上不可分辨。抽出後，TestDisplayTranslationCheckerCatchesMissing 得以餵入
// 刻意缺譯／漂移／孤兒的 fixture，逐形態證明它會紅。
func checkDisplayTranslations(byLocale map[string]map[string]map[string]string, expected map[string]map[string]string) []string {
	var out []string
	add := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }
	for _, ns := range displayNamespaces {
		exp := expected[ns]
		codes := make([]string, 0, len(exp))
		for code := range exp {
			codes = append(codes, code)
		}
		sort.Strings(codes)
		for _, code := range codes {
			zhTmpl := exp[code]
			// forward: 三語非空
			for _, l := range displayLocales {
				if v, ok := byLocale[l][ns][code]; !ok || v == "" {
					add("%s.%s missing/empty in %s", ns, code, l)
				}
			}
			// zh 不漂移：locale zh-TW == registry template（template 對 template）
			if zh := byLocale["zh-TW"][ns][code]; zh != zhTmpl {
				add("%s.%s zh drift: registry %q vs locale %q", ns, code, zhTmpl, zh)
			}
			// placeholder 三語一致（與 template 相同）
			want := templatePlaceholders(zhTmpl)
			for _, l := range displayLocales {
				if got := templatePlaceholders(byLocale[l][ns][code]); !equalStrSet(got, want) {
					add("%s.%s %s placeholders %v != template %v", ns, code, l, sortedKeys(got), sortedKeys(want))
				}
			}
			// same-value heuristic：en/ja 與 zh byte-identical 者紅燈（除 allowlist）
			zh := byLocale["zh-TW"][ns][code]
			for _, l := range []string{"en-US", "ja-JP"} {
				if byLocale[l][ns][code] == zh && !displaySameValueAllowlist[ns+"."+code] {
					add("%s.%s %s text identical to zh (%q) — likely untranslated copy", ns, code, l, zh)
				}
			}
		}
		// reverse: 無孤兒鍵
		for _, l := range displayLocales {
			orphans := make([]string, 0)
			for code := range byLocale[l][ns] {
				if _, ok := exp[code]; !ok {
					orphans = append(orphans, code)
				}
			}
			sort.Strings(orphans)
			for _, code := range orphans {
				add("orphan %s.%s in %s (not in backend registry)", ns, code, l)
			}
		}
	}
	return out
}

// TestBackendDisplayTranslationsComplete 是「漏譯一筆就有使用者看到原始鍵」的硬約束：每個註冊碼
// 三語都有非空譯文、zh 不漂移、placeholder 三語一致、無孤兒、en/ja 非複製 zh。
func TestBackendDisplayTranslationsComplete(t *testing.T) {
	dir := displayLocaleDir(t)
	byLocale := map[string]map[string]map[string]string{}
	for _, l := range displayLocales {
		byLocale[l] = loadDisplayLocale(t, dir, l)
		n := 0
		for _, ns := range displayNamespaces {
			n += len(byLocale[l][ns])
		}
		if n < minDisplayLocaleKeys {
			t.Fatalf("%s 於受管 namespace 只載到 %d 個鍵（下限 %d，locale 目錄 %s）："+
				"載入範圍已失真，反向（孤兒）與正向（三語非空）兩側都會在空集合下假綠",
				l, n, minDisplayLocaleKeys, dir)
		}
		t.Logf("locale %s 受管 namespace 鍵數=%d（下限 %d）", l, n, minDisplayLocaleKeys)
	}
	for _, v := range checkDisplayTranslations(byLocale, expectedZhByNamespace()) {
		t.Error(v)
	}
}

// TestDisplayLocaleFallbackIsProjectRootAnchored fallback 路徑的定位驗證。
//
// **為什麼需要它**：容器內 `APIERROR_LOCALE_DIR` 恆有值（dev compose 掛
// `./frontend/src/i18n/locales:/app/testdata/locales:ro`），fallback 分支在 docker
// 內**永遠不會被執行**；而 host 直跑才走 fallback。若只在 docker 驗，fallback 算錯
// 了也不會有人知道——host 那次才炸，而且錯誤訊息會指向「locale 讀不到」而非
// 「路徑算錯」。本格以合成的專案根驗它：路徑必須自 **module 根的上一層**推得，
// 與本測試檔目前住在樹的第幾層無關（去耦後的不變式）。
func TestDisplayLocaleFallbackIsProjectRootAnchored(t *testing.T) {
	projectRoot := t.TempDir()
	want := filepath.Join(projectRoot, "frontend", "src", "i18n", "locales")
	if got := displayLocaleFallbackDir(projectRoot); got != want {
		t.Fatalf("fallback 路徑 = %q, want %q", got, want)
	}
	// 合成一份最小 locale 樹並確認它真的載得起來——證明 fallback 指到的形狀
	// 與 env 覆寫分支一致（兩條路徑共用 loadDisplayLocale）
	if err := os.MkdirAll(want, 0o755); err != nil {
		t.Fatalf("建立合成 locale 目錄失敗: %v", err)
	}
	for _, l := range displayLocales {
		body := `{"riskLabel":{"synthetic":"合成"}}`
		if err := os.WriteFile(filepath.Join(want, l+".json"), []byte(body), 0o644); err != nil {
			t.Fatalf("寫入合成 locale 失敗: %v", err)
		}
	}
	got := loadDisplayLocale(t, displayLocaleFallbackDir(projectRoot), "zh-TW")
	if got["riskLabel"]["synthetic"] != "合成" {
		t.Fatalf("fallback 目錄載入結果不符: %v", got)
	}
	// 真實環境：env 覆寫存在時必須優先於 fallback（容器內的實際路徑）
	t.Setenv(displayLocaleEnv, want)
	if dir := displayLocaleDir(t); dir != want {
		t.Fatalf("env 覆寫未優先：得 %q, want %q", dir, want)
	}
}

// TestDisplayTranslationCheckerCatchesMissing 缺譯 fixture 突變自檢。
//
// 以**真實 locale 內容**為基底，逐形態植入缺陷，斷言判準逐條抓得到。
// 任一形態漏抓，主測試的「零違規」即不成立。
func TestDisplayTranslationCheckerCatchesMissing(t *testing.T) {
	dir := displayLocaleDir(t)
	base := map[string]map[string]map[string]string{}
	for _, l := range displayLocales {
		base[l] = loadDisplayLocale(t, dir, l)
	}
	expected := expectedZhByNamespace()
	if v := checkDisplayTranslations(base, expected); len(v) != 0 {
		t.Fatalf("基底 fixture 本身就有 %d 條違規，突變自檢無從歸因:\n  %s",
			len(v), strings.Join(v, "\n  "))
	}

	clone := func() map[string]map[string]map[string]string {
		out := map[string]map[string]map[string]string{}
		for l, nss := range base {
			out[l] = map[string]map[string]string{}
			for ns, m := range nss {
				cp := map[string]string{}
				for k, v := range m {
					cp[k] = v
				}
				out[l][ns] = cp
			}
		}
		return out
	}

	cases := []struct {
		name    string
		mutate  func(m map[string]map[string]map[string]string)
		wantSub string
	}{
		{"en 缺譯（刪鍵）", func(m map[string]map[string]map[string]string) {
			delete(m["en-US"]["riskLabel"], RiskVNCUnencrypted)
		}, "missing/empty in en-US"},
		{"ja 空字串", func(m map[string]map[string]map[string]string) {
			m["ja-JP"]["riskLabel"][RiskVNCUnencrypted] = ""
		}, "missing/empty in ja-JP"},
		{"zh 漂移", func(m map[string]map[string]map[string]string) {
			m["zh-TW"]["riskLabel"][RiskVNCUnencrypted] = "被改過的中文"
		}, "zh drift"},
		{"placeholder 不一致", func(m map[string]map[string]map[string]string) {
			m["en-US"]["riskLabel"][RiskSyslogNonTLS] = "syslog forwarding is unencrypted"
		}, "placeholders"},
		{"en 複製 zh", func(m map[string]map[string]map[string]string) {
			m["en-US"]["riskLabel"][RiskVNCUnencrypted] = m["zh-TW"]["riskLabel"][RiskVNCUnencrypted]
		}, "identical to zh"},
		{"孤兒鍵", func(m map[string]map[string]map[string]string) {
			m["zh-TW"]["riskLabel"]["ghost_risk"] = "幽靈"
		}, "orphan riskLabel.ghost_risk"},
	}
	for _, c := range cases {
		m := clone()
		c.mutate(m)
		got := checkDisplayTranslations(m, expected)
		hit := false
		for _, v := range got {
			if strings.Contains(v, c.wantSub) {
				hit = true
			}
		}
		if !hit {
			t.Errorf("突變「%s」未被判準抓到（期望訊息含 %q），實得 %d 條：%v",
				c.name, c.wantSub, len(got), got)
		}
	}
}

// TestDisplayNamespaceCardinality 釘死各 namespace 基數：expected 由
// map 導出，若來源 list 有重複鍵會被靜默覆蓋而基數變小——固定基數＋policyDefs 鍵唯一性雙檢。
func TestDisplayNamespaceCardinality(t *testing.T) {
	exp := expectedZhByNamespace()
	want := map[string]int{
		// policyLabel 由 36 增為 37：audit-checkpoint-chain 新增 retention_checkpoint_days
		// 再由 37 增為 42：data-transfer-control 新增資料傳輸五鍵
		// 再由 42 增為 44、policyUnit 由 7 增為 8：封章週期與筆數門檻搬進政策頁（新單位「秒」）
		// 再由 44 增為 47：三個營運調校鍵搬進政策頁
		//（retention_max_per_run／key_rotation_max_per_run／k8s_list_timeout_seconds；
		// 單位沿用既有的「筆」與「秒」，故 policyUnit 不變）
		// 再由 47 增為 50、policyUnit 由 8 增為 9：鏈自動驗證的三個鍵
		// （新單位「筆/小時」＝速率，與批次大小的「筆」刻意分開）
		// 再由 50 增為 51：refresh_cookie_secure
		//（bool 鍵無單位，故 policyUnit 不變）
		// 再由 51 增為 52：evidence-offsite-storage 的 offsite_local_retention_days
		//（單位沿用既有的「天」，故 policyUnit 不變）
		// 再由 52 增為 54：登入前告示的標題與內文兩鍵
		//（文字型鍵無單位，故 policyUnit 不變）
		"policyLabel": 54, "policyUnit": 9, "riskLabel": 8,
		// transportNote 由 8 增為 9：LDAP 的兩碼改名（deploy_managed→ui_managed）
		// 之外另加故障態專屬碼 ldap_resolve_failed
		"transportNote": 9, "transportPreflight": 4, "transportDetail": 1,
	}
	for ns, n := range want {
		if got := len(exp[ns]); got != n {
			t.Errorf("%s 基數 = %d, want %d（重複鍵覆蓋？新碼未計入？）", ns, got, n)
		}
	}
	seen := map[string]bool{}
	for _, d := range policyDefs {
		if seen[d.Key] {
			t.Errorf("policyDef 鍵重複 %q", d.Key)
		}
		seen[d.Key] = true
	}
}

// TestRiskSliceJSONShape 持久化形狀 golden：consent risk_items 與各類
// 審計 details 皆 marshal `[]RiskItem`——斷言切片每元素恰 {key,label} 兩欄，鎖住真實序列化形狀。
func TestRiskSliceJSONShape(t *testing.T) {
	risks := []RiskItem{
		newRisk(RiskVNCUnencrypted, nil),
		newRisk(RiskSyslogNonTLS, map[string]any{"protocol": "tcp"}),
	}
	b, err := json.Marshal(risks)
	if err != nil {
		t.Fatal(err)
	}
	var arr []map[string]json.RawMessage
	if err := json.Unmarshal(b, &arr); err != nil {
		t.Fatal(err)
	}
	if len(arr) != 2 {
		t.Fatalf("got %d risks, want 2", len(arr))
	}
	for i, m := range arr {
		if len(m) != 2 || m["key"] == nil || m["label"] == nil {
			t.Errorf("risk[%d] fields=%v, want exactly {key,label}: %s", i, keysOfRaw(m), b)
		}
	}
}

func keysOfRaw(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestInventoryConstructorFailFast 兩個 inventory constructor 缺 required param／kind 不符即 panic
// （原僅測 newRisk）。
func TestInventoryConstructorFailFast(t *testing.T) {
	mustPanic := func(name string, fn func()) {
		defer func() {
			if recover() == nil {
				t.Errorf("%s 應 panic，實際未 panic", name)
			}
		}()
		fn()
	}
	mustPanic("setNote 缺 protocol", func() { var ch InventoryChannel; setNote(&ch, "syslog_protocol", nil) })
	mustPanic("setPreflight 缺 n", func() { var ch InventoryChannel; setPreflight(&ch, "rdp_reject", nil) })
	mustPanic("setNote 用 preflight 碼（kind 不符）", func() { var ch InventoryChannel; setNote(&ch, "rdp_reject", nil) })
	mustPanic("setPreflight 用 note 碼（kind 不符）", func() { var ch InventoryChannel; setPreflight(&ch, "ssh_encrypted", nil) })
}

// TestValidateTemplateParams 驗證 registry 註冊時的雙向 template↔params 檢查
func TestValidateTemplateParams(t *testing.T) {
	cases := []struct {
		name    string
		tmpl    string
		req     []string
		wantErr bool
	}{
		{"no slots no params", "純文字", nil, false},
		{"one slot declared", "值 {protocol}", []string{"protocol"}, false},
		{"undeclared placeholder", "值 {protocol}", nil, true},
		{"declared but absent", "純文字", []string{"protocol"}, true},
		{"duplicate param", "值 {a}", []string{"a", "a"}, true},
		{"empty param name", "值 {a}", []string{""}, true},
		{"extra param", "值 {a}", []string{"a", "b"}, true},
	}
	for _, c := range cases {
		err := validateTemplateParams("test", c.name, c.tmpl, c.req)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err=%v wantErr=%v", c.name, err, c.wantErr)
		}
	}
}

// TestSyslogRiskParamsIntegrity 驗證 syslog risk 恰內插 protocol（4.6）
func TestSyslogRiskParamsIntegrity(t *testing.T) {
	svc := &TransmissionPolicyService{}
	risks := svc.SyslogRisks("tcp")
	if len(risks) != 1 {
		t.Fatalf("SyslogRisks(tcp) got %d risks, want 1", len(risks))
	}
	if got, want := risks[0].Label, "syslog 轉發未加密（tcp）"; got != want {
		t.Errorf("syslog label = %q, want %q", got, want)
	}
	if risks[0].Key != RiskSyslogNonTLS {
		t.Errorf("syslog key = %q, want %q", risks[0].Key, RiskSyslogNonTLS)
	}
	// TLS 傳輸無風險
	if r := svc.SyslogRisks(model.SyslogProtocolTCPTLS); len(r) != 0 {
		t.Errorf("SyslogRisks(tcp+tls) got %d risks, want 0", len(r))
	}
}

// TestNewRiskFailFastOnMissingParam 驗證 constructor 缺 required param 即 panic（不送裸 slot）
func TestNewRiskFailFastOnMissingParam(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("newRisk(syslog_non_tls, nil) 應 panic（缺 protocol），實際未 panic")
		}
	}()
	_ = newRisk(RiskSyslogNonTLS, nil)
}

// TestRiskJSONShapeUnchanged 持久化形狀 golden test（rr-Minor1）：risk wire 結構恰
// {key,label} 兩欄——consent risk_items 與各類審計 snapshot 皆 marshal 同型，故一併守。
func TestRiskJSONShapeUnchanged(t *testing.T) {
	r := newRisk(RiskSyslogNonTLS, map[string]any{"protocol": "tcp"})
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 {
		t.Errorf("risk JSON has %d fields, want exactly 2 {key,label}: %s", len(m), b)
	}
	for _, want := range []string{"key", "label"} {
		if _, ok := m[want]; !ok {
			t.Errorf("risk JSON missing %q: %s", want, b)
		}
	}
	for k := range m {
		if k != "key" && k != "label" {
			t.Errorf("risk JSON has unexpected field %q (params must NOT leak into wire/persistence): %s", k, b)
		}
	}
}

// TestValidatePolicyDefsUnitInvariant 驗證 Unit↔UnitKey invariant
func TestValidatePolicyDefsUnitInvariant(t *testing.T) {
	if err := validatePolicyDefs(); err != nil {
		t.Fatalf("validatePolicyDefs: %v", err)
	}
	// 每個有 Unit 的列都有映射一致的 UnitKey
	for _, d := range policyDefs {
		if d.Unit != "" && unitKeyByZh[d.Unit] != d.UnitKey {
			t.Errorf("%s: Unit %q → UnitKey %q，映射應為 %q", d.Key, d.Unit, d.UnitKey, unitKeyByZh[d.Unit])
		}
		if d.Unit == "" && d.UnitKey != "" {
			t.Errorf("%s: 無 Unit 卻有 UnitKey %q", d.Key, d.UnitKey)
		}
	}
}
