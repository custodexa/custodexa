package policy

import (
	"encoding/json"
	"strconv"
	"testing"
)

// 下界守衛（policy-numeric-lower-bounds）。
//
// **守的是什麼**：數值型政策鍵一上安全政策頁，若沒有下界，就開出一條
// 「調到極小＝實質關閉，而畫面上看起來還在跑」的靜默路徑。這違反本專案的
// 既有紅線——稽核機制不得可被靜默關閉。
//
// **判準是危險方向朝哪邊，不是「是不是數值型」**：
//   - 危險方向朝「大」的鍵（如封存週期設成 24 小時＝實質不封存），既有的 Max
//     ＋ ZeroDisables:false 已經蓋住，**不需要也不應該有 Min**。
//   - 危險方向朝「小」的鍵（預算／逾時型：單輪刪除上限、單輪重加密上限、
//     列表逾時秒數），調小即使機制永遠完成不了工作，ZeroDisables:false 只擋 0、
//     `1` 一路放行——**這類鍵必須有 Min**。
//
// 下列兩張表是**窮舉分類**：policyDefs 內每個 int 型鍵都必須恰好出現在其中一張。
// 新增 int 型鍵而未分類會讓 TestEveryIntPolicyKeyIsClassifiedForMinBound 轉紅，
// 迫使作者對「這個鍵調小會怎樣」做一次明確判斷——這正是本守衛的用意，
// 它擋的不只是漏設 Min，更是漏想。

// keysRequiringMin 危險方向朝「小」的鍵：調小即使機制永遠完成不了工作，
// 而介面上仍顯示在運作。每個鍵的下界須有結構性理由（見 policyDefs 的註解）
var keysRequiringMin = map[string]string{
	PolicyRetentionMaxPerRun:    "單輪刪除上限低於一個批次即代表清理速率必然追不上新增量，保留政策實質失效",
	PolicyKeyRotationMaxPerRun:  "單輪重加密上限低於一個掃描頁即代表一次觸發推不動任何進度，換鑰永遠跑不完",
	PolicyK8sListTimeoutSeconds: "逾時低於正常叢集的正常回應時間即代表每次列表都逾時，叢集功能實質不可用",
	PolicyAuditChainVerifyRowsPerHour: "掃描速率低於「繞行一輪≈一個完整保留期」的那一點，" +
		"即代表舊區間在被合法清除前永遠輪不到重驗，內容層對那段歷史實質關閉而畫面上仍在推進",
}

// keysNotRequiringMin 不需要 Min 的 int 型鍵，附不需要的理由。
// 理由分兩類：(a) 危險方向朝「大」，Max 已蓋住；(b) 調小是誠實且可見的政策選擇
// （例如保留天數調短＝少留資料，會在 PCI 偏離摘要中顯示，不是偽裝成還開著）
var keysNotRequiringMin = map[string]string{
	PolicyLockoutMaxAttempts:              "危險方向朝大（次數放寬），Direction=max ＋ PCI 偏離已蓋住；調小是更嚴格",
	PolicyLockoutDurationMinutes:          "調小是更寬鬆但可見的政策選擇，非機制停擺；PCI 偏離會顯示",
	PolicyPasswordMinLength:               "危險方向朝小但為誠實可見的政策選擇：Direction=min ＋ PCI 偏離摘要即時顯示，非偽裝成還開著",
	PolicyPasswordHistoryCount:            "同上，調小＝歷史比對筆數變少，PCI 偏離會顯示",
	PolicyPasswordMaxAgeDays:              "危險方向朝大（密碼可用更久），Direction=max 已蓋住",
	PolicyWebIdleMinutes:                  "危險方向朝大（閒置更久才登出），Direction=max 已蓋住；調小是更嚴格",
	PolicyWebMaxSessionHours:              "危險方向朝大，調小是更嚴格",
	PolicySessionIdleMinutes:              "危險方向朝大，調小是更嚴格",
	PolicySessionMaxMinutes:               "危險方向朝大，調小是更嚴格",
	PolicyInactiveDisableDays:             "危險方向朝大（閒置帳號更久才停用），調小是更嚴格",
	PolicyRetentionAuditLogDays:           "調小＝少留資料，是誠實且可見的政策選擇（PCI 偏離摘要顯示），非機制停擺",
	PolicyRetentionSessionCommandDays:     "同上",
	PolicyRetentionAlertDays:              "同上",
	PolicyRetentionRecordingDays:          "同上",
	PolicyRetentionCheckpointDays:         "同上，另受跨鍵約束（不得低於四個資料保留鍵）",
	PolicyAuditCheckpointIntervalSeconds:  "危險方向朝大（週期設成 24 小時＝實質不封存），Max=86400 ＋ 不可為 0 已蓋住",
	PolicyAuditCheckpointRowThreshold:     "危險方向朝大（門檻設到極高＝實質不提前封存），Max=1000000 ＋ 不可為 0 已蓋住",
	PolicyAuditChainRecentVerifyDays: "危險方向朝大（窗口大到與全鏈層重疊，只多出成本），Max=30 已蓋住；" +
		"朝小則最小合法值 1 天仍含鏈尾最新區間，機制不會歸零",
	PolicyAuditChainVerifyIntervalSeconds: "危險方向朝大（間隔拉長＝鏈尾異常在全鏈層的發現時延放大），" +
		"Max=604800 ＋ 不可為 0 已蓋住。調小不會使機制失效——每輪列預算＝速率×間隔，繞行週期不變",
	PolicyKeyCryptoperiodReminderDays:     "純提醒、不觸發任何動作；危險方向朝大，且 0=不提醒為出廠預設",
	PolicyTransportConsentTTLDays:         "危險方向朝大（同意記得更久＝更少重新確認），調小是更嚴格；0=永不過期由 ZeroDisables 承擔",
	PolicyAccessRequestMaxDurationMinutes: "危險方向朝大（申請超長時窗繞道成永久授權），Direction=max ＋ PCI 偏離已蓋住",
	PolicyAccessRequestPendingTimeoutHours: "危險方向朝大（待審單長期不作廢），Direction=max 已蓋住。" +
		"調小雖會使申請在核准前就過期，但那是 fail-close——存取被拒且申請人立刻看得見，" +
		"不是「看起來還開著而其實關了」的靜默停擺",
	PolicyAccessRequestMinApprovals: "下界已由「非 ZeroDisables 的 int 不得為 0」承擔；" +
		"1＝出廠預設即最小有意義值（等同單人核准），不存在更低的失效區間",
	PolicyBreakGlassDurationMinutes:    "危險方向朝大（破窗票證時窗拉長），Direction=max ＋ PCI 偏離已蓋住",
	PolicyBreakGlassReviewTimeoutHours: "危險方向朝大（補審可以拖更久），Direction=max 已蓋住",
}

// TestEveryIntPolicyKeyIsClassifiedForMinBound 窮舉分類守衛：
// 每個 int 型政策鍵都必須恰好落在一張分類表內。**新增同類鍵未分類即轉紅。**
func TestEveryIntPolicyKeyIsClassifiedForMinBound(t *testing.T) {
	for i := range policyDefs {
		def := &policyDefs[i]
		if def.Type != PolicyTypeInt {
			continue
		}
		_, requires := keysRequiringMin[def.Key]
		_, exempt := keysNotRequiringMin[def.Key]
		switch {
		case requires && exempt:
			t.Errorf("政策鍵 %s 同時出現在兩張分類表，分類必須互斥", def.Key)
		case !requires && !exempt:
			t.Errorf("政策鍵 %s 是 int 型但未分類。"+
				"請判斷它調小會怎樣：若調小即使機制永遠完成不了工作（而介面上仍顯示在跑），"+
				"加入 keysRequiringMin 並為它設 PolicyDef.Min；否則加入 keysNotRequiringMin 並寫明理由",
				def.Key)
		}
	}
}

// TestKeysRequiringMinHaveMin 分類表 → 定義表：需要下界的鍵必須真的設了 Min，
// 且 Min 須在有效值域內。**拿掉任一 Min 即轉紅。**
func TestKeysRequiringMinHaveMin(t *testing.T) {
	for key, why := range keysRequiringMin {
		def := findDef(key)
		if def == nil {
			t.Errorf("keysRequiringMin 列了不存在的鍵 %s", key)
			continue
		}
		if def.Min <= 0 {
			t.Errorf("政策鍵 %s 需要下界但 Min=%d。理由：%s", key, def.Min, why)
			continue
		}
		effectiveMax := def.Max
		if effectiveMax == 0 {
			effectiveMax = defaultPolicyIntMax
		}
		if def.Min > effectiveMax {
			t.Errorf("政策鍵 %s 的 Min=%d 高於有效上界 %d，值域為空", key, def.Min, effectiveMax)
		}
	}
}

// TestKeysNotRequiringMinHaveNoMin 反向釘死：不需要下界的鍵不得有 Min。
// 防「為了讓守衛變綠而到處補 Min」——那會把分類判準稀釋成無意義的形式
func TestKeysNotRequiringMinHaveNoMin(t *testing.T) {
	for key, why := range keysNotRequiringMin {
		def := findDef(key)
		if def == nil {
			t.Errorf("keysNotRequiringMin 列了不存在的鍵 %s", key)
			continue
		}
		if def.Min != 0 {
			t.Errorf("政策鍵 %s 被歸類為不需要下界（%s）卻設了 Min=%d；"+
				"若判斷已改變，請把它移到 keysRequiringMin", key, why, def.Min)
		}
	}
}

// TestMinBoundRejectsBelowFloor 三個搬遷鍵各自拒絕低於下界的值。
// **這是本 change 的核心行為斷言**：拿掉 validatePolicyValue 的下界檢查即轉紅
func TestMinBoundRejectsBelowFloor(t *testing.T) {
	for key := range keysRequiringMin {
		def := findDef(key)
		if def == nil {
			t.Fatalf("政策鍵 %s 不存在", key)
		}
		// 1 是盤點指認的具體攻擊值（「設成 1 使清理永遠追不上」）
		for _, bad := range []int{1, def.Min - 1} {
			if bad < 1 {
				continue
			}
			err := validatePolicyValue(def, strconv.Itoa(bad))
			if err == nil {
				t.Errorf("政策鍵 %s 接受了 %d（下界 %d）——"+
					"這正是「調到極小＝實質關閉，而畫面上看起來還在跑」的靜默路徑",
					key, bad, def.Min)
			}
		}
		// 下界本身與下界之上須放行
		for _, ok := range []int{def.Min, def.Min + 1} {
			if err := validatePolicyValue(def, strconv.Itoa(ok)); err != nil {
				t.Errorf("政策鍵 %s 拒絕了合法值 %d（下界 %d）: %v", key, ok, def.Min, err)
			}
		}
		// 出廠預設必須自己合法（validatePolicyDefs 亦驗，此處就地再釘一次）
		if err := validatePolicyValue(def, def.Default); err != nil {
			t.Errorf("政策鍵 %s 的出廠預設 %q 不合法: %v", key, def.Default, err)
		}
	}
}

// TestMinAndZeroDisablesAreOrthogonal 釘住 Min 與 ZeroDisables 的交互語義：
// 合法值域為 {0 若 ZeroDisables} ∪ [Min, Max]。
//
// 這個不連續值域是刻意的——ZeroDisables 管「能不能明著關」，Min 管
// 「能不能偽裝成還開著而其實關了」，兩者堵的是不同的門
func TestMinAndZeroDisablesAreOrthogonal(t *testing.T) {
	cases := []struct {
		name         string
		zeroDisables bool
		value        string
		wantErr      bool
	}{
		{"ZeroDisables 開時 0 合法", true, "0", false},
		{"ZeroDisables 開時仍擋下界以下", true, "9", true},
		{"ZeroDisables 開時下界本身合法", true, "10", false},
		{"ZeroDisables 關時 0 非法", false, "0", true},
		{"ZeroDisables 關時下界以下非法", false, "9", true},
		{"ZeroDisables 關時下界本身合法", false, "10", false},
		{"上界之上一律非法", true, "101", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			def := &PolicyDef{
				Key: "orthogonality_probe", Type: PolicyTypeInt, Default: "10",
				Min: 10, Max: 100, ZeroDisables: tc.zeroDisables,
			}
			err := validatePolicyValue(def, tc.value)
			if tc.wantErr && err == nil {
				t.Errorf("值 %s 應被拒絕（Min=10, Max=100, ZeroDisables=%v）", tc.value, tc.zeroDisables)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("值 %s 應被接受（Min=10, Max=100, ZeroDisables=%v）: %v", tc.value, tc.zeroDisables, err)
			}
		})
	}
}

// TestMinIsExposedToFrontend Min 須隨政策定義送到前端，否則輸入框擋不住、
// 使用者只會在存檔時撞牆——下界要在輸入當下就可見
func TestMinIsExposedToFrontend(t *testing.T) {
	for key := range keysRequiringMin {
		def := findDef(key)
		if def == nil {
			t.Fatalf("政策鍵 %s 不存在", key)
		}
		blob, err := json.Marshal(PolicyView{PolicyDef: *def, Value: def.Default})
		if err != nil {
			t.Fatalf("政策鍵 %s 序列化失敗: %v", key, err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(blob, &decoded); err != nil {
			t.Fatalf("政策鍵 %s 反序列化失敗: %v", key, err)
		}
		got, ok := decoded["min"]
		if !ok {
			t.Errorf("政策鍵 %s 的 API 回應沒有 min 欄位——前端輸入框讀不到下界，"+
				"使用者只會在存檔時撞牆", key)
			continue
		}
		if int(got.(float64)) != def.Min {
			t.Errorf("政策鍵 %s 的 API min=%v 與定義 Min=%d 不符", key, got, def.Min)
		}
	}
}
