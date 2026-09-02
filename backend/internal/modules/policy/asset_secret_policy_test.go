package policy

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAssetSecretMaxAgePolicyDef 釘住資產帳號憑證最長使用天數的定義。
//
// **值本身要被釘住**：出廠 0 是「升級零行為變更」的承諾，上界 3650 是防呆，
// 兩個基準值與條號來自法規與條文核對。任一格被改動時應該紅，而不是靜默生效。
func TestAssetSecretMaxAgePolicyDef(t *testing.T) {
	def := findDef(PolicyAssetSecretMaxAgeDays)
	require.NotNil(t, def, "政策鍵不存在")

	require.Equal(t, PolicyTypeInt, def.Type)
	require.Equal(t, "0", def.Default, "出廠須為 0（關閉），升級零行為變更")
	require.True(t, def.ZeroDisables, "0 是關閉 sentinel，不是「零天」")
	require.Equal(t, DirectionMax, def.Direction, "值須不大於基準")
	require.Equal(t, 3650, def.Max)

	require.Equal(t, "90", def.PCIValue)
	require.True(t, def.PCIReference, "PCI 條文未定固定天數，此值須標為參考值")
	require.Equal(t, "8.6.3", def.Requirement)

	require.Equal(t, "90", def.EPaymentValue)
	require.Equal(t, "15-8", def.EPaymentRequirement)
	require.Equal(t, "天", def.Unit)
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

// TestPCIReferenceRequiresValue 參考值必有 PCI 建議值：拿掉 validatePolicyDefs
// 的這一條即轉紅。空的參考值會在設定頁掛出一個沒有數字的標籤，
// 而符合性評估與一鍵套用都會靜默略過該鍵。
func TestPCIReferenceRequiresValue(t *testing.T) {
	orig := policyDefs
	t.Cleanup(func() { policyDefs = orig })

	policyDefs = []PolicyDef{{
		Key: "reference_without_value_probe", Type: PolicyTypeInt, Default: "0",
		PCIReference: true, ZeroDisables: true, Max: 10, Label: "探針",
	}}
	require.Error(t, validatePolicyDefs(), "標為參考值卻無 PCIValue 應被自檢擋下")

	policyDefs[0].PCIValue = "5"
	require.NoError(t, validatePolicyDefs(), "補上 PCIValue 後應通過")
}
