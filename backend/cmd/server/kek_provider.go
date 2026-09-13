package main

import (
	"context"
	"fmt"
	"reflect"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/crypto/gcpkms"
	kmskek "github.com/custodexa/backend/pkg/crypto/kms"
	"github.com/custodexa/backend/pkg/crypto/vaulttransit"
)

// buildKEKProvider 依組態段判定結果建構 KEK provider。
//
// A（env）與 B（ui）**共用同一本地實作** localAESKEKProvider——差別僅在材料注入
// 時機（啟動期 env vs 解封期 API）。此共用即「A↔B 同鑰互換免遷移」的
// 實作根據：同材料下 KeyRef 相同、格式標記相同、互相可解。
//
// 本函式的建構射程是 env 與 kms 兩種模式：ui 模式的材料只由解封端點注入，
// hsm 委託尚未交付；兩者於此 fail-close 並明示原因，SHALL NOT 靜默回落其他 provider。
//
// **ctx 參數的存在理由**：委託模式於建構期即向 KMS 探測（DescribeKey），
// 該探測 SHALL 尊重呼叫端取消——不吞成逾時是審查明列的守衛。
func buildKEKProvider(ctx context.Context, d *config.KEKDecision) (crypto.KEKProvider, error) {
	return buildKEKProviderWithVault(ctx, d, nil)
}

// delegatedCredentialSource 供給委託建構所需的拓撲與該解封世代的秘密。
//
// 以窄介面而非具體型別注入：建構路徑只需要「把這一組設定拿來」這一件事，
// 而 credentialOwner 另有生命週期管理的責任面，不該一起暴露給建構函式。
type delegatedCredentialSource interface {
	settings() (config.KMSSettings, error)
}

// The client implementation supplies this constructor once its preflight is available.
type vaultProviderConstructor func(context.Context, vaulttransit.Settings) (crypto.KEKProvider, error)

func buildKEKProviderWithVault(ctx context.Context, d *config.KEKDecision, construct vaultProviderConstructor) (crypto.KEKProvider, error) {
	return buildKEKProviderWithConstructors(ctx, d, construct, nil)
}

type gcpProviderConstructor func(context.Context, gcpkms.Settings) (crypto.KEKProvider, error)

func buildKEKProviderWithConstructors(ctx context.Context, d *config.KEKDecision, construct vaultProviderConstructor, gcpConstruct gcpProviderConstructor) (crypto.KEKProvider, error) {
	p, _, err := buildOwnedKEKProviderWithConstructors(ctx, d, nil, construct, gcpConstruct)
	return p, err
}

func buildOwnedKEKProvider(ctx context.Context, d *config.KEKDecision) (crypto.KEKProvider, *material.Secret, error) {
	return buildOwnedKEKProviderWithConstructors(ctx, d, nil, nil, nil)
}

// The shared factory preserves local material ownership and delegated constructor injection.
func buildOwnedKEKProviderWithConstructors(ctx context.Context, d *config.KEKDecision, cred delegatedCredentialSource, construct vaultProviderConstructor, gcpConstruct gcpProviderConstructor) (crypto.KEKProvider, *material.Secret, error) {
	if d == nil {
		return nil, nil, fmt.Errorf("KEK decision is missing")
	}
	switch d.Mode {
	case config.KEKModeEnv:
		// 材料的三種寫法（原字元／十六進位／base64）在此解為 32 位元組金鑰。
		// **列 1（相容路徑）與列 3（顯式 env）共用本處**：列 3 的格式政策已於
		// DecideKEK 內套過，列 1 刻意不套政策——故此處只解碼、不再加任何政策，
		// 否則相容路徑會在升級後突然多出一道它從來沒有的閘。
		key, reason := config.DecodeKEKMaterialKey(d.Material)
		if reason != "" {
			return nil, nil, fmt.Errorf("KEK 材料無法解為 32 bytes 金鑰（來源 %s：%s）", d.MaterialSource, reason)
		}
		owner := material.Adopt(key)
		p, err := crypto.NewLocalAESKEKProvider(key, crypto.KEKModeEnv)
		if err != nil {
			owner.Destroy()
			return nil, nil, err
		}
		return p, owner, nil
	case config.KEKModeUI:
		// B 模式的材料只由解封 API 進入記憶體：段 1 建構不出 provider 是正常狀態。
		// 呼叫端 SHALL 於段 1 跳過本函式，並於解封時改走 buildUIKEKProvider。
		// 此處仍回錯而非 nil，使「誤把 ui 模式接進啟動期建構」立刻可見。
		return nil, nil, fmt.Errorf("KEK_PROVIDER=ui（介面填鑰）的材料須由解封端點提供：啟動期不建構，請改走解封路徑")
	case config.KEKModeKMS:
		// 委託模式的拓撲與憑證皆不在部署檔：拓撲讀自資料庫、秘密來自解封世代的
		// 記憶體持有者。缺持有者即拒絕建構——**這是正常狀態而非組態錯誤**，
		// 委託部署的冷啟動因此停在已封存等待人工解封（見 spec 的破壞性變更）。
		if cred == nil {
			return nil, nil, fmt.Errorf("KEK_PROVIDER=kms（委託）的憑證須由解封端點提供：啟動期不建構，請改走解封路徑")
		}
		base, err := cred.settings()
		if err != nil {
			return nil, nil, err
		}
		if err := config.ValidateKMSSettings(base); err != nil {
			return nil, nil, err
		}
		if base.Provider == vaulttransit.ProviderVault {
			p, err := buildVaultProvider(ctx, base, "", construct)
			return p, nil, err
		}
		if base.Provider == gcpkms.ProviderGCP {
			p, err := buildGCPProvider(ctx, base, "", gcpConstruct)
			return p, nil, err
		}
		// **KMS 不可達即拒啟動（可用性取捨）**：本呼叫內含
		// DescribeKey 探測，探測失敗即回錯，呼叫端（stage1）以 log.Fatalf 收場，
		// SHALL NOT 降級啟動。運行期不受影響：KEK 不在熱路徑。
		//
		// **顯式攤開回傳值而非 `return kmskek.New(...)`**：後者會把
		// `(*kms.Provider)(nil)` 裝箱成一個**非 nil 的介面值**，使呼叫端的
		// `provider != nil` 判定得到相反答案——典型的 Go typed-nil 陷阱，
		// 而這條路徑上的誤判等於「拿著空 provider 繼續啟動」。
		p, err := kmskek.New(ctx, kmsSettings(base))
		if err != nil {
			return nil, nil, err
		}
		return p, nil, nil
	case config.KEKModeHSM:
		return nil, nil, fmt.Errorf("KEK_PROVIDER=hsm（硬體模組委託）尚未交付：拒絕啟動，不回落其他 provider")
	default:
		return nil, nil, fmt.Errorf("未知的 KEK 來源模式 %q", d.Mode)
	}
}

// kmsSettings 由組態判定結果轉出 KMS provider 建構參數。
//
// **刻意不提供端點覆寫的產品 env 鍵**：端點覆寫是「把 KMS 呼叫導向別處」的能力，
// 對一個以委託金鑰為信任根的部署而言，多一個這樣的旋鈕就多一條可被誤設或濫用的
// 路徑。測試靶機（localstack）改由 Settings.Endpoint 以**程式注入**取得。
//
// **SDK 自身的 AWS_ENDPOINT_URL_KMS 不是「交給 SDK 處理」而是被明確拒絕**
// （安全審查 high #2）：先前這裡寫的是「由 AWS SDK 自身的標準機制處理」，
// 但那條機制會把**含明文 DEK 的 Encrypt 請求**導向任意端點甚至 HTTP。
// 生產路徑於 kms.newAWSClient 對它 fail-close；本函式不設 Endpoint 這件事，
// 由 TestNoProductionEndpointOverride 以 AST 釘住。
func kmsSettings(s config.KMSSettings) kmskek.Settings {
	return kmskek.Settings{Provider: s.Provider, KeyID: s.KeyID, Region: s.Region,
		Credentials: awsCredentialsProvider(s)}
}

// buildDelegatedRewrapProvider 換鑰精靈的委託目標 provider 建構器。
//
// **目標的 region／服務商／信任帳號一律沿用本行程的 KEK_KMS_* 組態，
// 只有 key_ref 由請求帶入**：精靈請求體是 union 的委託分支（`{mode, key_ref}`），
// 不含區域——讓請求體攜帶區域等於允許操作者於單次請求內把材料重包到任意
// 雲端帳號，那是遠比換鑰更大的動作，不該藏在換鑰精靈裡。
//
// **只沿用 region 並不足夠（安全審查 high #1）**：完整 key_ref 仍可指定
// **同 region 的任意 AWS 帳號**，只要對方 key policy／grant 放行，材料就被重包
// 進外部信任域——只沿用 region 想防的那件事，實際上沒被擋住。故本函式另由
// KEK_KMS_KEY_ID 推導信任帳號範圍（見 kms.ResolveAccountScope），並交由
// kms.New 於 DescribeKey 正規化**之後**比對 partition＋account，不符即 fail-close。
// 這使「重包目標必須屬於部署已表態信任的那個 KMS 帳號」成為建構期的硬條件。
//
// 故 A/B→C 的操作順序是：先設好 KEK_KMS_PROVIDER／KEK_KMS_REGION／KEK_KMS_KEY_ID
// （此時仍以 env／ui 模式運行，矩陣列 3／6 不受影響），再於精靈指定目標金鑰，
// 最後才切 KEK_PROVIDER=kms。
//
// 建構本身即完成 DescribeKey 正規化、金鑰可用性驗證、信任帳號比對，以及一次真實
// Wrap→Unwrap 往返驗 Encrypt／Decrypt 權限（即「連通性預檢」，現已內建於
// kms.New，故此處不再另呼叫 Preflight——兩者是同一段程式碼）。
func buildDelegatedRewrapProvider(ctx context.Context, mode, keyRef string) (crypto.KEKProvider, error) {
	return buildDelegatedRewrapProviderWithVault(ctx, mode, keyRef, nil)
}

func buildDelegatedRewrapProviderWithVault(ctx context.Context, mode, keyRef string, construct vaultProviderConstructor) (crypto.KEKProvider, error) {
	return buildDelegatedRewrapProviderWithConstructors(ctx, mode, keyRef, nil, construct, nil)
}

func buildDelegatedRewrapProviderWithConstructors(ctx context.Context, mode, keyRef string, cred delegatedCredentialSource, construct vaultProviderConstructor, gcpConstruct gcpProviderConstructor) (crypto.KEKProvider, error) {
	if mode != crypto.KeyRefProviderKMS && mode != crypto.KeyRefProviderVault && mode != crypto.KeyRefProviderGCP {
		return nil, fmt.Errorf("delegated target mode is not supported")
	}
	// **拓撲與憑證改自解封世代的持有者取得，不再讀環境**：原實作直接呼叫
	// config.KMSSettingsFromEnv，而區域／位址／角色識別已移入資料庫、秘密只存在
	// 於記憶體。DelegatedProviderFactory 的簽名不因此放寬——供給拓撲與憑證是
	// 組裝根的職責，服務層仍只傳 (mode, keyRef)。
	if cred == nil {
		return nil, fmt.Errorf("delegated target requires the generation credential owner")
	}
	base, err := cred.settings()
	if err != nil {
		return nil, err
	}
	if mode == crypto.KeyRefProviderGCP {
		if keyRef == "" {
			return nil, fmt.Errorf("target key reference is required")
		}
		return buildGCPProvider(ctx, base, keyRef, gcpConstruct)
	}
	if mode == crypto.KeyRefProviderVault {
		if keyRef == "" {
			return nil, fmt.Errorf("target key reference is required")
		}
		if base.Provider != vaulttransit.ProviderVault {
			return nil, fmt.Errorf("target provider differs from deployment")
		}
		return buildVaultProvider(ctx, base, keyRef, construct)
	}
	if base.Provider != "aws" {
		return nil, fmt.Errorf("target provider differs from deployment")
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

// GCP settings are derived from deployment configuration; targets supply only a reference.
func buildGCPProvider(ctx context.Context, base config.KMSSettings, target string, construct gcpProviderConstructor) (crypto.KEKProvider, error) {
	if err := config.ValidateKMSSettings(base); err != nil {
		return nil, err
	}
	if base.Provider != gcpkms.ProviderGCP {
		return nil, fmt.Errorf("target provider differs from deployment")
	}
	scope, err := gcpkms.ResolveProjectScope(base.KeyID)
	if err != nil {
		return nil, err
	}
	id := base.KeyID
	if target != "" {
		id, err = scope.ResolveKey(target)
		if err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if construct == nil {
		return nil, fmt.Errorf("GCP client constructor is not connected")
	}
	p, err := construct(ctx, gcpkms.Settings{KeyID: id, Scope: scope, ServiceAccountJSON: base.GCPServiceAccountJSON})
	if err != nil {
		return nil, fmt.Errorf("GCP constructor failed: %w", err)
	}
	if p == nil || (reflect.ValueOf(p).Kind() == reflect.Pointer && reflect.ValueOf(p).IsNil()) {
		return nil, fmt.Errorf("GCP constructor returned no provider")
	}
	if p.KeyRef() != (crypto.KeyRef{Provider: crypto.KeyRefProviderGCP, KeyID: id}) || p.Mode() != crypto.KEKModeKMS || p.FormatTag() != crypto.WrappedFormatGCP {
		return nil, fmt.Errorf("GCP constructor identity mismatch")
	}
	return p, nil
}

// Reference and scope checks precede the constructor, including test injection.
func buildVaultProvider(ctx context.Context, base config.KMSSettings, target string, construct vaultProviderConstructor) (crypto.KEKProvider, error) {
	if err := config.ValidateKMSSettings(base); err != nil {
		return nil, err
	}
	scope, id, err := vaulttransit.ResolveScope(base.Vault.Address, base.KeyID)
	if err != nil {
		return nil, err
	}
	if target != "" {
		id, err = scope.ResolveKey(target)
		if err != nil {
			return nil, err
		}
	}
	if construct == nil {
		return nil, fmt.Errorf("Vault client lifetime owner is not connected")
	}
	p, err := construct(ctx, vaulttransit.Settings{Address: scope.Origin(), RoleID: base.Vault.RoleID,
		SecretID: base.Vault.SecretID, Token: base.Vault.Token, KeyID: id, Scope: scope})
	if err != nil {
		return nil, fmt.Errorf("Vault constructor failed: %w", err)
	}
	if p == nil || (reflect.ValueOf(p).Kind() == reflect.Pointer && reflect.ValueOf(p).IsNil()) {
		return nil, fmt.Errorf("Vault constructor returned no provider")
	}
	if p.KeyRef() != (crypto.KeyRef{Provider: crypto.KeyRefProviderVault, KeyID: id}) || p.Mode() != crypto.KEKModeKMS || p.FormatTag() != crypto.WrappedFormatVault {
		return nil, fmt.Errorf("Vault constructor identity mismatch")
	}
	return p, nil
}

// buildUIKEKProvider 以解封端點提交的材料建構 B（ui）模式的 KEK provider。
//
// 與 A（env）模式共用同一本地實作，差別僅在材料注入時機——此共用即
// 「A↔B 同鑰互換免遷移」的實作根據：同材料下 KeyRef 相同、格式標記相同、
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
func buildUIKEKProvider(raw []byte) (crypto.KEKProvider, error) {
	p, _, err := buildOwnedUIKEKProvider(raw)
	return p, err
}
func buildOwnedUIKEKProvider(raw []byte) (crypto.KEKProvider, *material.Secret, error) {
	key, reason := config.DecodeKEKMaterialKeyBytes(raw)
	if reason != "" {
		// 原因只作為 Cause 進伺服端錯誤鏈；對外一律收斂為 SEAL_MATERIAL_INVALID
		return nil, nil, fmt.Errorf("KEK 材料無法解為 32 bytes 金鑰：%s", reason)
	}
	owner := material.Adopt(key)
	p, err := crypto.NewLocalAESKEKProvider(key, crypto.KEKModeUI)
	if err != nil {
		owner.Destroy()
		return nil, nil, err
	}
	return p, owner, nil
}

// newGCPProviderOwner 供給本解封世代所擁有的 GCP client 與共用建構子，形狀比照
// Vault 的持有者：client 綁定該世代的生命週期，服務帳號金鑰檔內容由解封頁注入的
// 憑證持有者供給。**不讀 GOOGLE_APPLICATION_CREDENTIALS、不觸發環境自動發現**
// ——gcpkms.NewClient 在憑證缺席時直接拒絕建構，沒有回落路徑。
// 呼叫端須於收束或回滾時關閉它。
func newGCPProviderOwner(lifetime context.Context, base config.KMSSettings) (*gcpkms.Client, gcpProviderConstructor, error) {
	if err := config.ValidateKMSSettings(base); err != nil {
		return nil, nil, err
	}
	if base.Provider != gcpkms.ProviderGCP {
		return nil, nil, fmt.Errorf("GCP provider required")
	}
	scope, err := gcpkms.ResolveProjectScope(base.KeyID)
	if err != nil {
		return nil, nil, err
	}
	client, err := gcpkms.NewClient(lifetime, gcpkms.Settings{KeyID: base.KeyID, Scope: scope,
		ServiceAccountJSON: base.GCPServiceAccountJSON})
	if err != nil {
		// **保留錯誤鏈**：委託解封要分辨「不可達／憑證被拒／端點被拒」，
		// classifyDelegatedFailure 依 gcpkms 的哨兵錯誤判定。gcpkms 的錯誤已
		// 過 safeError 收斂，不含憑證內容，包起來不會外洩材料。
		return nil, nil, fmt.Errorf("GCP initialization failed: %w", err)
	}
	construct := func(ctx context.Context, s gcpkms.Settings) (crypto.KEKProvider, error) {
		if s.Scope != scope {
			return nil, fmt.Errorf("GCP deployment differs from owner")
		}
		p, err := client.Provider(ctx, s.KeyID)
		if err != nil {
			return nil, err
		}
		return p, nil
	}
	return client, construct, nil
}

// newVaultProviderOwner supplies one owned client and a constructor shared by
// startup and delegated targets. The caller must close it on shutdown or rollback.
// The generation owner shares this constructor across startup and targets.
func newVaultProviderOwner(lifetime context.Context, base config.KMSSettings) (*vaulttransit.Client, vaultProviderConstructor, error) {
	if err := config.ValidateKMSSettings(base); err != nil {
		return nil, nil, err
	}
	if base.Provider != vaulttransit.ProviderVault {
		return nil, nil, fmt.Errorf("Vault provider required")
	}
	scope, id, err := vaulttransit.ResolveScope(base.Vault.Address, base.KeyID)
	if err != nil {
		return nil, nil, err
	}
	settings := vaulttransit.Settings{Address: scope.Origin(), Scope: scope, KeyID: id,
		RoleID: base.Vault.RoleID, SecretID: base.Vault.SecretID, Token: base.Vault.Token}
	client, _, err := vaulttransit.New(lifetime, settings)
	if err != nil {
		return nil, nil, fmt.Errorf("Vault initialization failed")
	}
	construct := func(ctx context.Context, s vaulttransit.Settings) (crypto.KEKProvider, error) {
		if !client.MatchesDeployment(s) {
			return nil, fmt.Errorf("Vault deployment differs from owner")
		}
		p, err := client.Provider(ctx, s.KeyID)
		if err != nil {
			return nil, err
		}
		return p, nil
	}
	return client, construct, nil
}
