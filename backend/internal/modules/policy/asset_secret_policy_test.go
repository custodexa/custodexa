package policy

import (
	"strconv"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/require"
)

// TestAssetSecretMaxAgePolicyDef 釘住資產帳號憑證最長使用天數的定義與兩組要求。
//
// **值本身要被釘住**：出廠 0 是「升級零行為變更」的承諾，上界 3650 是防呆，
// 兩組內建規範各自的要求值與條號來自法規與條文核對。任一格被改動時應該紅，
// 而不是靜默生效。**要求的受測對象是內建組的種子**——判定讀的就是那一批列。
func TestAssetSecretMaxAgePolicyDef(t *testing.T) {
	def := findDef(PolicyAssetSecretMaxAgeDays)
	require.NotNil(t, def, "政策鍵不存在")

	require.Equal(t, PolicyTypeInt, def.Type)
	require.Equal(t, "0", def.Default, "出廠須為 0（關閉），升級零行為變更")
	require.True(t, def.ZeroDisables, "0 是關閉 sentinel，不是「零天」")
	require.Equal(t, DirectionMax, def.Direction, "值須不大於基準")
	require.Equal(t, 3650, def.Max)
	require.Equal(t, "天", def.Unit)

	type requirement struct {
		clauseNo, comparator, value string
		referenceOnly               bool
	}
	want := map[string]requirement{
		pciGroupCode:      {"8.6.3", model.PolicyControlComparatorMax, "90", true},
		ePaymentGroupCode: {"15-8", model.PolicyControlComparatorMax, "90", false},
	}
	got := map[string]requirement{}
	for _, seed := range builtinPolicyGroupSeeds() {
		controls, err := buildSeedControls(seed)
		require.NoError(t, err, "組 %s 的種子建不出來", seed.Code)
		for _, c := range controls {
			if c.PolicyKey != PolicyAssetSecretMaxAgeDays {
				continue
			}
			got[seed.Code] = requirement{c.ClauseNo, c.Comparator, c.ExpectedValue, c.ReferenceOnly}
		}
	}
	require.Equal(t, want, got,
		"兩組對本鍵的要求與條文對照不符——PCI 未定固定天數故標為參考值，電支 §15-8 明定至少每三個月")
}

// TestAssetSecretMaxAgeValueDomain 值域＝0（關閉）或 1–3650。
//
// **以行為斷言取代對 PolicyDef.Min 的欄位斷言**：本鍵的危險方向朝大（憑證可用
// 更久），依下界守衛的窮舉分類屬「不需要 Min」那一類，而該分類禁止設 Min
// （設了會被 TestKeysNotRequiringMinHaveNoMin 判紅，且 TestMinBoundRejectsBelowFloor
// 會要求 Min 本身被拒絕，與「1 天是合法設定」互相矛盾）。
// ZeroDisables 與非負驗證已使有效值域恰為 {0} ∪ [1, 3650]，與規格逐字相同。
func TestAssetSecretMaxAgeValueDomain(t *testing.T) {
	def := findDef(PolicyAssetSecretMaxAgeDays)
	require.NotNil(t, def)

	for _, ok := range []int{0, 1, 90, 3650} {
		require.NoError(t, validatePolicyValue(def, strconv.Itoa(ok)),
			"值 %d 應合法", ok)
	}
	for _, bad := range []string{"-1", "3651", "abc", ""} {
		require.Error(t, validatePolicyValue(def, bad), "值 %q 應被拒絕", bad)
	}
}

// TestReferenceOnlyRequirementCarriesValue 參考值必有要求值：拿掉資料存取層
// 那一條校驗即轉紅。空的要求值會在條文上掛出一個沒有數字的參考值，
// 而判定與一次滿足所有政策都會靜默略過該鍵（條文真的沒有給值時走未定值）。
func TestReferenceOnlyRequirementCarriesValue(t *testing.T) {
	def := findDef(PolicyAssetSecretMaxAgeDays)
	require.NotNil(t, def)

	empty := model.PolicyClauseControl{
		PolicyKey: PolicyAssetSecretMaxAgeDays, Comparator: model.PolicyControlComparatorMax,
		ExpectedValue: "", ReferenceOnly: true,
	}
	require.Error(t, assertExpectedValueFitsComparator(def, empty),
		"標為參考值卻無要求值應被校驗擋下")

	empty.ExpectedValue = "90"
	require.NoError(t, assertExpectedValueFitsComparator(def, empty),
		"補上要求值後應通過")
}
