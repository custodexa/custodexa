package main

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// 端點索引 marker parser 的結構不變式測試（api-docs spec）。
//
// 為何每條不變式都要有 fixture：parser 的失效模式不是 crash 而是**靜默退化**——
// 少解析出幾列、或多認一個區塊，雙向比對依然「全綠」，只是保護範圍悄悄縮小。
// 唯有以刻意破壞的輸入斷言它確實失敗，才能證明防線活著。

// fixtureDoc 包出一份最小的文件：marker 區塊前後各有散文，用於同時驗證
// 「區塊外的內容不影響解析」與「重寫時區塊外逐字不動」。
func fixtureDoc(block string) string {
	return "# API 規格\n\n前置散文。\n\n" +
		apiIndexBegin + "\n" + block + apiIndexEnd + "\n\n後置散文。\n"
}

func validBlock() string {
	return apiIndexHeader + "\n" + apiIndexSeparator + "\n" +
		"| GET | `/api/v1/assets` | always |\n" +
		"| POST | `/api/v1/audit-logs` | FEATURE_AUDIT_LOG_ENABLED |\n"
}

func TestParseAPIIndexValid(t *testing.T) {
	got, err := parseAPIIndex(fixtureDoc(validBlock()))
	if err != nil {
		t.Fatalf("正常輸入不應失敗: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("解析出 %d 列（預期 2）：%+v", len(got), got)
	}
	if got[0].Method != "GET" || got[0].Path != "/api/v1/assets" || got[0].Condition != condAlways {
		t.Errorf("第 1 列解析錯誤：%+v", got[0])
	}
	if got[1].Condition != condAuditFlag {
		t.Errorf("第 2 列的註冊條件解析錯誤：%+v", got[1])
	}
}

// TestParseAPIIndexInvariants 逐項破壞結構不變式，每項都須失敗。
func TestParseAPIIndexInvariants(t *testing.T) {
	cases := []struct {
		name    string
		content string
		wantErr string // 錯誤訊息須含的片段，確認是「因該原因」而非碰巧失敗
	}{
		{
			name:    "duplicate-marker",
			content: fixtureDoc(validBlock()) + "\n" + apiIndexBegin + "\n" + validBlock() + apiIndexEnd + "\n",
			wantErr: "2 次",
		},
		{
			name:    "missing-END",
			content: "# API\n\n" + apiIndexBegin + "\n" + validBlock(),
			wantErr: "END marker 出現 0 次",
		},
		{
			name:    "missing-BEGIN",
			content: "# API\n\n" + validBlock() + apiIndexEnd + "\n",
			wantErr: "BEGIN marker 出現 0 次",
		},
		{
			name:    "END-before-BEGIN",
			content: "# API\n\n" + apiIndexEnd + "\n" + validBlock() + apiIndexBegin + "\n",
			wantErr: "之後",
		},
		{
			name: "extra-column",
			content: fixtureDoc(apiIndexHeader + "\n" + apiIndexSeparator + "\n" +
				"| GET | `/api/v1/assets` | always | 多餘欄 |\n"),
			wantErr: "欄數",
		},
		{
			name: "malformed-row",
			content: fixtureDoc(apiIndexHeader + "\n" + apiIndexSeparator + "\n" +
				"GET /api/v1/assets always\n"),
			wantErr: "不是表格列",
		},
		{
			name:    "empty-block",
			content: fixtureDoc(""),
			wantErr: "0 列",
		},
		{
			name:    "header-only",
			content: fixtureDoc(apiIndexHeader + "\n" + apiIndexSeparator + "\n"),
			wantErr: "0 列",
		},
		{
			name: "unknown-condition",
			content: fixtureDoc(apiIndexHeader + "\n" + apiIndexSeparator + "\n" +
				"| GET | `/api/v1/assets` | SOME_NEW_FLAG |\n"),
			wantErr: "註冊條件",
		},
		{
			name: "path-not-absolute",
			content: fixtureDoc(apiIndexHeader + "\n" + apiIndexSeparator + "\n" +
				"| GET | `api/v1/assets` | always |\n"),
			wantErr: "不以 / 開頭",
		},
		{
			name: "empty-cell",
			content: fixtureDoc(apiIndexHeader + "\n" + apiIndexSeparator + "\n" +
				"| GET |  | always |\n"),
			wantErr: "空欄位",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseAPIIndex(c.content)
			if err == nil {
				t.Fatalf("破壞 %s 後 parser 仍成功（解析出 %d 列）——該防線失效", c.name, len(got))
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("錯誤訊息未指出真正原因\n  預期含: %q\n  實際  : %v", c.wantErr, err)
			}
		})
	}
}

// TestParseAPIIndexRejectsSilentSkip 明確鎖住「無法解析的列不得被靜默略過」。
//
// 與 malformed-row 的差別：此處壞列**混在合法列之間**。若 parser 選擇跳過壞列，
// 它仍會回傳 2 條合法條目而不報錯——比對照樣全綠，但那一條端點已失去保護。
func TestParseAPIIndexRejectsSilentSkip(t *testing.T) {
	content := fixtureDoc(apiIndexHeader + "\n" + apiIndexSeparator + "\n" +
		"| GET | `/api/v1/assets` | always |\n" +
		"這一列不是表格\n" +
		"| POST | `/api/v1/assets` | always |\n")

	got, err := parseAPIIndex(content)
	if err == nil {
		t.Fatalf("壞列被靜默略過，仍回傳 %d 條——該端點自此失去保護且無人察覺", len(got))
	}
	if !strings.Contains(err.Error(), "無法解析") {
		t.Errorf("錯誤訊息未指出解析失敗：%v", err)
	}
}

// TestReplaceIndexBlockPreservesRest 重寫索引區塊時，marker 以外的內容須逐字不動。
func TestReplaceIndexBlockPreservesRest(t *testing.T) {
	orig := fixtureDoc(validBlock())
	rendered := renderIndex([]indexEntry{
		{Method: "DELETE", Path: "/api/v1/keys/rewrap", Condition: condAlways},
	})

	updated, err := replaceIndexBlock(orig, rendered)
	if err != nil {
		t.Fatalf("重寫失敗: %v", err)
	}

	for _, prose := range []string{"# API 規格", "前置散文。", "後置散文。"} {
		if !strings.Contains(updated, prose) {
			t.Errorf("重寫後遺失區塊外內容: %q", prose)
		}
	}
	if strings.Contains(updated, "/api/v1/assets") {
		t.Error("重寫後仍殘留舊索引內容——區塊未被完整取代")
	}
	if !strings.Contains(updated, "/api/v1/keys/rewrap") {
		t.Error("重寫後未含新索引內容")
	}

	// 冪等：對已重寫的內容再寫一次同樣結果，須逐字相同（確定性輸出）
	again, err := replaceIndexBlock(updated, rendered)
	if err != nil {
		t.Fatalf("二次重寫失敗: %v", err)
	}
	if again != updated {
		t.Error("重寫非冪等——同樣輸入產生不同輸出，diff 會混入雜訊")
	}

	// 重寫的結果須能被 parser 讀回（生成器與解析器同源）
	back, err := parseAPIIndex(updated)
	if err != nil {
		t.Fatalf("重寫後的文件無法被 parser 讀回: %v", err)
	}
	if len(back) != 1 || back[0].Path != "/api/v1/keys/rewrap" {
		t.Errorf("讀回結果與寫入不符: %+v", back)
	}
}

// TestConditionForMask 鎖住註冊條件的封閉值域（codex 審查 Finding 1 的回歸測試）。
//
// 關鍵案例是 0b0111：條件為 `audit || permission` 的端點會出現於 {on,on}、{on,off}、
// {off,on} 三格而不出現於 {off,off}。初版把四格壓縮成「audit on/off」兩個布林，
// 該 mask 同時滿足 inAuditOn 與 inAuditOff，被誤判為 always——索引寫成無條件註冊，
// 守衛全綠，而「這個端點其實是條件註冊」的事實就此從文件消失。
func TestConditionForMask(t *testing.T) {
	cases := []struct {
		mask    int
		want    string
		wantErr bool
		why     string
	}{
		{0b11, condAlways, false, "兩格全有＝無條件註冊"},
		{0b01, condAuditFlag, false, "僅 audit-on 格＝受 audit 旗標控制"},
		{0b10, "", true, "僅 audit-off 才出現（關閉旗標才註冊）"},
		{0b00, "", true, "兩格皆無（不應進入 membership）"},
		// 超出兩格值域者一律拒絕：permission 維度退場後，1xx 這類 mask 只可能來自
		// 「有人加了新維度但沒同步值域」，此時必須撞牆而非以錯誤條件混入索引
		{0b111, "", true, "超出組態格數（新增了維度而未擴充值域）"},
		{0b100, "", true, "超出組態格數且兩格皆無"},
	}

	for _, c := range cases {
		got, err := conditionForMask(c.mask)
		switch {
		case c.wantErr && err == nil:
			t.Errorf("mask %02b（%s）應被拒絕，卻回傳 %q——值域不再封閉，"+
				"新的條件註冊機制會以錯誤條件混入索引", c.mask, c.why, got)
		case !c.wantErr && err != nil:
			t.Errorf("mask %02b（%s）應為 %q，卻回報錯誤: %v", c.mask, c.why, c.want, err)
		case !c.wantErr && got != c.want:
			t.Errorf("mask %02b（%s）得到 %q，預期 %q", c.mask, c.why, got, c.want)
		}
	}
}

// TestDeployConfigsMatchMaskConstants 位序是契約：maskAlways／maskAuditFlag 的常數值
// 依賴 deployConfigs 的順序。若有人重排順序而忘了改常數，條件推導會整片錯亂且無聲。
func TestDeployConfigsMatchMaskConstants(t *testing.T) {
	if len(deployConfigs) != 2 {
		t.Fatalf("deployConfigs 有 %d 組（預期 2：audit on/off。permission 維度已隨旗標退場）",
			len(deployConfigs))
	}
	if maskAlways != (1<<len(deployConfigs))-1 {
		t.Errorf("maskAlways=%02b 與組態數 %d 不符", maskAlways, len(deployConfigs))
	}

	var auditOnMask int
	for bit, c := range deployConfigs {
		if c.auditLogEnabled {
			auditOnMask |= 1 << bit
		}
	}
	if auditOnMask != maskAuditFlag {
		t.Errorf("由 deployConfigs 算出的 audit-on 位元遮罩為 %02b，但 maskAuditFlag=%02b——"+
			"deployConfigs 的順序被改動而常數未同步，條件推導會整片錯誤",
			auditOnMask, maskAuditFlag)
	}

	// 組態必須互異且涵蓋 audit 維度的完整值域
	seen := map[bool]bool{}
	for _, c := range deployConfigs {
		if seen[c.auditLogEnabled] {
			t.Errorf("deployConfigs 有重複組態 %v", c.auditLogEnabled)
		}
		seen[c.auditLogEnabled] = true
	}
	if len(seen) != 2 {
		t.Errorf("deployConfigs 未涵蓋 audit on/off 兩種組合，實得 %d 種", len(seen))
	}
}

// TestRouteDepsFlagsCoveredByMatrix 鎖住「routeDeps 的旗標集合」與「組態矩陣」同步
// （codex 第二輪 Finding 1 的回歸測試）。
//
// 失效情境：若有人為 routeDeps 新增 `featureX bool` 並在 registerRoutes 中條件註冊，
// 而 testDeps 未設定它（零值 false），該路由在四次 buildRouter 中**都不存在**，
// 因此根本不會進入 membership——conditionForMask 連被呼叫的機會都沒有，
// 索引悄悄漏掉一條 production 路由，而所有測試全綠。
//
// 值域檢查擋不住這種缺席，唯有結構檢查可以：新增旗標即紅，強迫新增者擴充矩陣。
//
// **已知邊界**：只涵蓋 bool 欄位。以「nil 即不註冊」形式做條件註冊的欄位
// （例如曾經的 swaggerHandler gin.HandlerFunc）無法由型別自動辨識，同樣需要擴充
// 矩陣，但本守衛看不見。這是刻意接受的邊界，非疏漏。
func TestRouteDepsFlagsCoveredByMatrix(t *testing.T) {
	typ := reflect.TypeOf(routeDeps{})

	var flags []string
	for i := 0; i < typ.NumField(); i++ {
		if f := typ.Field(i); f.Type.Kind() == reflect.Bool {
			flags = append(flags, f.Name)
		}
	}
	sort.Strings(flags)

	// 矩陣目前涵蓋的旗標（deployConfigs 的維度）
	want := []string{"auditLogEnabled"}

	// **只做減法的旗標不進矩陣**：本守衛要擋的是「旗標為 true 時才出現的路由
	// 在索引中缺席」。sealOnly 為真時註冊的是完整路由表的**真子集**（只有
	// seal 端點群與健康檢查），不可能引入任何未被索引的端點，把它加進矩陣只會
	// 讓 golden 與索引條件欄多出一個永遠不會有新端點的維度。
	//
	// 這個豁免不是口頭承諾：TestSealOnlyRoutesAreStrictSubset 以機器檢查
	// 「子集」性質，豁免的前提一旦被打破，那個測試就會紅。
	subtractive := map[string]string{"sealOnly": "TestSealOnlyRoutesAreStrictSubset"}
	kept := flags[:0]
	for _, f := range flags {
		if _, ok := subtractive[f]; !ok {
			kept = append(kept, f)
		}
	}
	flags = kept

	if strings.Join(flags, ",") != strings.Join(want, ",") {
		t.Fatalf("routeDeps 的 bool 旗標為 [%s]，組態矩陣涵蓋 [%s]——兩者必須一致。\n"+
			"新增旗標卻未擴充 deployConfigs 時，testDeps 會讓它恆為 false：\n"+
			"受它控制的路由在所有 buildRouter 中都不存在，不會進入 membership，\n"+
			"索引將漏掉該 production 路由而測試全綠。\n"+
			"請同步：(1) deployConfigs 增加維度 (2) maskAlways/maskAuditFlag 等常數 "+
			"(3) conditionForMask 的值域 (4) docs/API_SPEC.md 索引的註冊條件欄。",
			strings.Join(flags, ", "), strings.Join(want, ", "))
	}
}

// TestReplaceIndexBlockRejectsBrokenMarkers 重寫同樣受 marker 結構不變式約束——
// 否則在 marker 已壞的文件上執行 -update 會把索引寫到錯誤的位置。
func TestReplaceIndexBlockRejectsBrokenMarkers(t *testing.T) {
	rendered := renderIndex([]indexEntry{{Method: "GET", Path: "/x", Condition: condAlways}})
	cases := map[string]string{
		"no-marker":        "# API\n\n沒有任何 marker。\n",
		"duplicate":        fixtureDoc(validBlock()) + apiIndexBegin + "\n" + apiIndexEnd + "\n",
		"END-before-BEGIN": apiIndexEnd + "\n" + apiIndexBegin + "\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := replaceIndexBlock(content, rendered); err == nil {
				t.Errorf("marker 已壞（%s）仍允許重寫——索引可能被寫到錯誤位置", name)
			}
		})
	}
}
