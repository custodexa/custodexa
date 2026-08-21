package main

import (
	"context"
	"fmt"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/pkg/crypto"
	kmskek "github.com/custodexa/backend/pkg/crypto/kms"
)

// buildKEKProvider 依組態段判定結果建構 KEK provider（kek-provider-modularization D4）。
//
// A（env）與 B（ui）**共用同一本地實作** localAESKEKProvider——差別僅在材料注入
// 時機（啟動期 env vs 解封期 API）。此共用即「A↔B 同鑰互換免遷移」（D9）的
// 實作根據：同材料下 KeyRef 相同、格式標記相同、互相可解。
//
// P3 範圍：env／kms 模式可建構；ui 模式的解封狀態機屬 P2、hsm 屬 P4，
// 此處 fail-close 並明示尚未交付，SHALL NOT 靜默回落其他 provider。
//
// **ctx 參數的存在理由**：委託模式於建構期即向 KMS 探測（DescribeKey，D11.1
// 裁決 1），該探測 SHALL 尊重呼叫端取消——不吞成逾時是 round-2 明列的守衛。
func buildKEKProvider(ctx context.Context, d *config.KEKDecision) (crypto.KEKProvider, error) {
	switch d.Mode {
	case config.KEKModeEnv:
		// 材料的三種寫法（原字元／十六進位／base64）在此解為 32 位元組金鑰。
		// **列 1（相容路徑）與列 3（顯式 env）共用本處**：列 3 的格式政策已於
		// DecideKEK 內套過，列 1 刻意不套政策——故此處只解碼、不再加任何政策，
		// 否則相容路徑會在升級後突然多出一道它從來沒有的閘。
		key, reason := config.DecodeKEKMaterialKey(d.Material)
		if reason != "" {
			return nil, fmt.Errorf("KEK 材料無法解為 32 bytes 金鑰（來源 %s：%s）", d.MaterialSource, reason)
		}
		return crypto.NewLocalAESKEKProvider(key, crypto.KEKModeEnv)
	case config.KEKModeUI:
		// B 模式的材料只由解封 API 進入記憶體：段 1 建構不出 provider 是正常狀態。
		// 呼叫端 SHALL 於段 1 跳過本函式，並於解封時改走 buildUIKEKProvider。
		// 此處仍回錯而非 nil，使「誤把 ui 模式接進啟動期建構」立刻可見。
		return nil, fmt.Errorf("KEK_PROVIDER=ui（介面填鑰）的材料須由解封端點提供：啟動期不建構，請改走解封路徑")
	case config.KEKModeKMS:
		// **KMS 不可達即拒啟動（D11 可用性取捨、tasks 3.2）**：本呼叫內含
		// DescribeKey 探測，探測失敗即回錯，呼叫端（stage1）以 log.Fatalf 收場，
		// SHALL NOT 降級啟動。運行期不受影響（D1 紅利：KEK 不在熱路徑）。
		//
		// **顯式攤開回傳值而非 `return kmskek.New(...)`**：後者會把
		// `(*kms.Provider)(nil)` 裝箱成一個**非 nil 的介面值**，使呼叫端的
		// `provider != nil` 判定得到相反答案——典型的 Go typed-nil 陷阱，
		// 而這條路徑上的誤判等於「拿著空 provider 繼續啟動」。
		p, err := kmskek.New(ctx, kmsSettings(d.KMS))
		if err != nil {
			return nil, err
		}
		return p, nil
	case config.KEKModeHSM:
		return nil, fmt.Errorf("KEK_PROVIDER=hsm（硬體模組委託）尚未交付：拒絕啟動，不回落其他 provider")
	default:
		return nil, fmt.Errorf("未知的 KEK 來源模式 %q", d.Mode)
	}
}

// kmsSettings 由組態判定結果轉出 KMS provider 建構參數。
//
// **刻意不提供端點覆寫的產品 env 鍵**：端點覆寫是「把 KMS 呼叫導向別處」的能力，
// 對一個以委託金鑰為信任根的部署而言，多一個這樣的旋鈕就多一條可被誤設或濫用的
// 路徑。測試靶機（localstack）改由 Settings.Endpoint 以**程式注入**取得。
//
// **SDK 自身的 AWS_ENDPOINT_URL_KMS 不是「交給 SDK 處理」而是被明確拒絕**
// （round-4 codex high #2）：先前這裡寫的是「由 AWS SDK 自身的標準機制處理」，
// 但那條機制會把**含明文 DEK 的 Encrypt 請求**導向任意端點甚至 HTTP。
// 生產路徑於 kms.newAWSClient 對它 fail-close；本函式不設 Endpoint 這件事，
// 由 TestNoProductionEndpointOverride 以 AST 釘住。
func kmsSettings(s config.KMSSettings) kmskek.Settings {
	return kmskek.Settings{Provider: s.Provider, KeyID: s.KeyID, Region: s.Region}
}

// buildDelegatedRewrapProvider 換鑰精靈的委託目標 provider 建構器（tasks 3.3）。
//
// **目標的 region／服務商／信任帳號一律沿用本行程的 KEK_KMS_* 組態，
// 只有 key_ref 由請求帶入**：精靈請求體是 union 的委託分支（`{mode, key_ref}`，
// D7），不含區域——讓請求體攜帶區域等於允許操作者於單次請求內把材料重包到任意
// 雲端帳號，那是遠比換鑰更大的動作，不該藏在換鑰精靈裡。
//
// **只沿用 region 並不足夠（round-4 codex high #1）**：完整 key_ref 仍可指定
// **同 region 的任意 AWS 帳號**，只要對方 key policy／grant 放行，材料就被重包
// 進外部信任域——裁決 6 想防的事實際上沒被擋住。故本函式另由
// KEK_KMS_KEY_ID 推導信任帳號範圍（見 kms.ResolveAccountScope），並交由
// kms.New 於 DescribeKey 正規化**之後**比對 partition＋account，不符即 fail-close。
// 這使「重包目標必須屬於部署已表態信任的那個 KMS 帳號」成為建構期的硬條件。
//
// 故 A/B→C 的操作順序是：先設好 KEK_KMS_PROVIDER／KEK_KMS_REGION／KEK_KMS_KEY_ID
// （此時仍以 env／ui 模式運行，矩陣列 3／6 不受影響），再於精靈指定目標金鑰，
// 最後才切 KEK_PROVIDER=kms。
//
// 建構本身即完成 DescribeKey 正規化、金鑰可用性驗證、信任帳號比對，以及一次真實
// Wrap→Unwrap 往返驗 Encrypt／Decrypt 權限（D7 的「連通性預檢」，現已內建於
// kms.New，故此處不再另呼叫 Preflight——兩者是同一段程式碼）。
func buildDelegatedRewrapProvider(ctx context.Context, mode, keyRef string) (crypto.KEKProvider, error) {
	if mode != crypto.KeyRefProviderKMS {
		return nil, fmt.Errorf("委託目標模式 %q 尚未交付：拒絕受理，不回落其他 provider", mode)
	}
	base := config.KMSSettingsFromEnv(config.OSEnvLookup)
	if base.Provider == "" || base.Region == "" || base.KeyID == "" {
		return nil, fmt.Errorf("委託重包目標需要本行程已設定 %s、%s 與 %s：請先補齊組態再執行重包"+
			"（%s 同時是信任帳號範圍的唯一來源——沒有它就無法判定目標金鑰是否屬於本部署信任的雲端帳號）",
			config.EnvKeyKMSProvider, config.EnvKeyKMSRegion, config.EnvKeyKMSKeyID, config.EnvKeyKMSKeyID)
	}
	scope, err := kmskek.ResolveAccountScope(ctx, kmsSettings(base))
	if err != nil {
		return nil, err
	}
	settings := kmsSettings(base)
	settings.KeyID = keyRef
	settings.Scope = scope
	p, err := kmskek.New(ctx, settings)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// buildUIKEKProvider 以解封端點提交的材料建構 B（ui）模式的 KEK provider。
//
// 與 A（env）模式共用同一本地實作，差別僅在材料注入時機——此共用即
// 「A↔B 同鑰互換免遷移」（D9）的實作根據：同材料下 KeyRef 相同、格式標記相同、
// 互相可解。**Mode 只影響清冊顯示與稽核對照，不影響任何落庫值**。
//
// material 為解封 payload 持有的可覆寫 buffer。解碼器回傳的是**新配置**的切片，
// 故不需要另行複製——payload 於驗證結束時就地歸零，而 provider 持有的是解碼產物，
// 兩者已是不同的 buffer。（原實作直接把 payload 的 buffer 交給 provider，
// 必須自行複製才不會在 Zeroize 之後持有一段全零的「金鑰」；解碼後這件事由
// 解碼器的所有權語義承擔。）
//
// **此處只解碼、不套格式政策**：一般解封路徑刻意不驗格式（既有部署的 KEK 可能
// 早於格式規則），初始化路徑的政策驗證已於 verifyInitializeUnseal 完成。
func buildUIKEKProvider(material []byte) (crypto.KEKProvider, error) {
	key, reason := config.DecodeKEKMaterialKeyBytes(material)
	if reason != "" {
		// 原因只作為 Cause 進伺服端錯誤鏈；對外一律收斂為 SEAL_MATERIAL_INVALID
		return nil, fmt.Errorf("KEK 材料無法解為 32 bytes 金鑰：%s", reason)
	}
	return crypto.NewLocalAESKEKProvider(key, crypto.KEKModeUI)
}
