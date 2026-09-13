package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/pkg/crypto"
	kmskek "github.com/custodexa/backend/pkg/crypto/kms"
)

// 組裝根的 KEK provider 建構。
//
// **語義變更（委託拓撲與憑證改由介面管理）**：委託模式的拓撲與
// 憑證不再來自環境變數——拓撲讀自資料庫、秘密由解封頁於每次解封輸入並交由該
// 解封世代的 credentialOwner 持有。本檔因此一律以「建一個世代持有者並 adopt
// 一組拓撲＋秘密」取代原本的 t.Setenv 供給；`KEK_KMS_*` 五鍵已自產品碼退場。

// retiredTrustAnchorEnvKey 信任錨點在 pkg/crypto/kms 錯誤訊息中的字面。
// config 端的同名常數已隨五鍵退場刪除，故本字面只在測試檔內宣告。
const retiredTrustAnchorEnvKey = "KEK_KMS_KEY_ID"

// awsFixtureSettings 委託部署的非秘密拓撲（介面設定、資料庫持久化）。
func awsFixtureSettings(keyID, region string) config.KMSSettings {
	return config.KMSSettings{Provider: "aws", KeyID: keyID, Region: region}
}

// awsFixtureSecrets 本解封世代持有的存取金鑰對（解封時輸入）。
func awsFixtureSecrets() delegatedSecrets {
	return delegatedSecrets{
		awsAccessKeyID:     []byte("fixture-access-key-id"),
		awsSecretAccessKey: []byte("fixture-secret-access-key"),
	}
}

// delegatedFixtureOwner 一個已接手拓撲與秘密的解封世代持有者。
func delegatedFixtureOwner(t *testing.T, settings config.KMSSettings, secrets delegatedSecrets) *credentialOwner {
	t.Helper()
	o := newCredentialOwner()
	t.Cleanup(o.Close)
	o.adopt(settings, secrets)
	return o
}

// buildKMSWithGeneration 走委託啟動建構，憑證來自本解封世代。
func buildKMSWithGeneration(ctx context.Context, t *testing.T, settings config.KMSSettings) (crypto.KEKProvider, error) {
	t.Helper()
	o := delegatedFixtureOwner(t, settings, awsFixtureSecrets())
	p, _, err := buildOwnedKEKProviderWithConstructors(ctx, &config.KEKDecision{Mode: config.KEKModeKMS}, o, nil, nil)
	return p, err
}

// clearAWSEnvironment 證明憑證確實來自解封世代而非環境：SDK 預設鏈的入口一律清空。
func clearAWSEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{"AWS_ENDPOINT_URL_KMS", "AWS_ENDPOINT_URL", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"} {
		t.Setenv(key, "")
	}
}

// TestBuildKEKProviderKMSFailsCloseWhenUnreachable **KMS 不可達即拒絕建構**。
// 失敗判準：KMS 不可達時降級啟動。
//
// region 指向一個不存在的 AWS 區域：端點 DNS 解不出來，建構 SHALL 回錯。
// 呼叫端於冷啟動不再是 log.Fatalf——委託模式冷啟動已改為進入已封存等待人工
// 解封（見 stage1.sealedMode），此建構發生在解封請求之內，失敗即解封被拒。
//
// 此路徑同時證明「探測發生在建構期」——本測試完全沒有 DB。
func TestBuildKEKProviderKMSFailsCloseWhenUnreachable(t *testing.T) {
	// 有界等待：建構期重試的總預算 <10s，故 20s 已足夠涵蓋且不會讓測試掛住
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	clearAWSEnvironment(t)

	p, err := buildKMSWithGeneration(ctx, t, awsFixtureSettings("alias/custodexa-kek", "xx-nowhere-1"))
	if err == nil {
		t.Fatal("KMS 不可達時 MUST fail-close，不得回傳可用 provider")
	}
	if p != nil {
		t.Fatal("失敗路徑不得回傳 provider（避免呼叫端誤用）")
	}
	// 錯誤須指出所需權限，否則「組態齊備但缺權限」的部署會拿到誤導性訊息
	if !strings.Contains(err.Error(), "kms:DescribeKey") {
		t.Fatalf("錯誤訊息未列出 kms:DescribeKey：%v", err)
	}
}

// TestBuildKEKProviderKMSRejectsEndpointOverride **端點覆寫在組裝層的 fail-close**
// （安全審查 high #2）。
//
// AWS_ENDPOINT_URL_KMS／AWS_ENDPOINT_URL 由 SDK 自行解析，能把**含明文 DEK 的
// kms:Encrypt 請求**導向任意端點甚至 HTTP。生產路徑 SHALL 明確拒絕，
// 且錯誤須指名觸發的變數。
func TestBuildKEKProviderKMSRejectsEndpointOverride(t *testing.T) {
	for _, key := range []string{"AWS_ENDPOINT_URL_KMS", "AWS_ENDPOINT_URL"} {
		t.Run(key, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			clearAWSEnvironment(t)
			t.Setenv(key, "http://127.0.0.1:1")

			p, err := buildKMSWithGeneration(ctx, t, awsFixtureSettings("alias/custodexa-kek", "ap-northeast-1"))
			if !errors.Is(err, kmskek.ErrEndpointOverride) {
				t.Fatalf("端點覆寫 MUST fail-close（ErrEndpointOverride），得 %v", err)
			}
			if p != nil {
				t.Fatal("失敗路徑不得回傳 provider")
			}
			if !strings.Contains(err.Error(), key) {
				t.Fatalf("錯誤未指名觸發的變數 %s：%v", key, err)
			}
		})
	}
}

// TestDelegatedConstructionRequiresGenerationCredentials 憑證來源收口於解封世代。
//
// 三條互補的性質：
//   - 沒有世代持有者（冷啟動）即拒絕建構，且**這是正常狀態**而非組態錯誤；
//   - 世代持有者收束（封存）之後取用一律失敗，不得拿到一段全零的位元組繼續走；
//   - 存取金鑰缺席時，SDK 的預設憑證鏈 SHALL NOT 被當成回落——即使環境中
//     恰好有一組可用的 AWS_* 憑證。
func TestDelegatedConstructionRequiresGenerationCredentials(t *testing.T) {
	ctx := context.Background()
	t.Run("no-owner", func(t *testing.T) {
		p, _, err := buildOwnedKEKProviderWithConstructors(ctx, &config.KEKDecision{Mode: config.KEKModeKMS}, nil, nil, nil)
		if p != nil || err == nil {
			t.Fatal("委託模式在無憑證持有者時建構出了 provider")
		}
		if _, err := buildDelegatedRewrapProviderWithConstructors(ctx, crypto.KeyRefProviderKMS, "alias/x", nil, nil, nil); err == nil {
			t.Fatal("委託重包目標在無憑證持有者時被受理")
		}
	})
	t.Run("closed-owner", func(t *testing.T) {
		o := delegatedFixtureOwner(t, awsFixtureSettings("alias/custodexa-kek", "ap-northeast-1"), awsFixtureSecrets())
		o.Close()
		p, _, err := buildOwnedKEKProviderWithConstructors(ctx, &config.KEKDecision{Mode: config.KEKModeKMS}, o, nil, nil)
		if p != nil || !errors.Is(err, errCredentialOwnerClosed) {
			t.Fatalf("已收束的世代仍可建構：%v", err)
		}
	})
	t.Run("missing-access-key-does-not-fall-back", func(t *testing.T) {
		t.Setenv("AWS_ACCESS_KEY_ID", "environment-access-key")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "environment-secret-key")
		o := delegatedFixtureOwner(t, awsFixtureSettings("alias/custodexa-kek", "ap-northeast-1"), delegatedSecrets{})
		p, _, err := buildOwnedKEKProviderWithConstructors(ctx, &config.KEKDecision{Mode: config.KEKModeKMS}, o, nil, nil)
		if p != nil || err == nil {
			t.Fatal("缺存取金鑰時回落了環境憑證")
		}
		for _, field := range []string{config.FieldAWSAccessKeyID, config.FieldAWSSecretAccessKey} {
			if !strings.Contains(err.Error(), field) {
				t.Fatalf("錯誤未指名缺少的欄位 %s：%v", field, err)
			}
		}
		// 同一條紅線在 kms 套件內亦成立：Credentials 缺席即 ErrCredentialsMissing，
		// 不因環境中存在 AWS_* 而放行。
		if _, err := kmskek.New(ctx, kmskek.Settings{Provider: "aws", KeyID: "alias/k", Region: "ap-northeast-1"}); !errors.Is(err, kmskek.ErrCredentialsMissing) {
			t.Fatalf("kms 套件回落了 SDK 預設憑證鏈：%v", err)
		}
	})
}

// TestTrustAnchorMissingIsIdentified 信任錨點缺席時，錯誤須指名它。
//
// 原格（TestTrustAnchorEnvKeyMatchesConfig）比對的是 pkg/crypto/kms 與
// config.EnvKeyKMSKeyID 兩處**環境變數鍵名字面**不漂移。config 端的常數已隨
// 五鍵退場刪除，比對對象只剩一邊，故本格改守「錨點缺席時錯誤可辨識」。
// **註**：kms 套件的訊息仍以退場的環境變數鍵名指路，該訊息宜改列
// config.FieldKMSKeyID；那屬產品碼側的後續工作。
func TestTrustAnchorMissingIsIdentified(t *testing.T) {
	_, err := kmskek.ResolveAccountScope(context.Background(), kmskek.Settings{
		Provider: "aws", KeyID: "", Region: "ap-northeast-1",
	})
	if err == nil {
		t.Fatal("缺信任錨點時應回錯")
	}
	if !strings.Contains(err.Error(), retiredTrustAnchorEnvKey) {
		t.Fatalf("錨點缺席的錯誤未指名信任錨點：%v", err)
	}
}

// TestBuildKEKProviderUnsupportedModes 未交付模式一律 fail-close，
// SHALL NOT 靜默回落其他 provider。
//
// kms 於此清單內的理由已改變：不是「未交付」，而是「憑證只由解封端點提供，
// 啟動期建構不出來」——buildKEKProvider 不帶世代持有者，故委託分支必拒。
func TestBuildKEKProviderUnsupportedModes(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{config.KEKModeUI, config.KEKModeHSM, config.KEKModeKMS, "bogus"} {
		p, err := buildKEKProvider(ctx, &config.KEKDecision{Mode: mode})
		if err == nil {
			t.Fatalf("模式 %q 應回錯", mode)
		}
		if p != nil {
			t.Fatalf("模式 %q 不得回傳 provider", mode)
		}
	}
}

// TestBuildKEKProviderEnvUnchanged env 模式的行為不得因委託模式的改動而改變
// （既有部署零可見變化的硬條件）：材料仍在部署檔內，啟動期即建構，不需要
// 任何解封世代的憑證。
func TestBuildKEKProviderEnvUnchanged(t *testing.T) {
	material := "TestKEKMaterial00000000000000123"
	p, err := buildKEKProvider(context.Background(), &config.KEKDecision{
		Mode: config.KEKModeEnv, Material: material,
	})
	if err != nil {
		t.Fatalf("env 模式建構失敗: %v", err)
	}
	if p.Mode() != crypto.KEKModeEnv {
		t.Fatalf("Mode 應為 env，得 %q", p.Mode())
	}
	if p.KeyRef().Provider != crypto.KeyRefProviderLocal {
		t.Fatalf("KeyRef().Provider 應為 local，得 %q", p.KeyRef().Provider)
	}
	if p.KeyRef().KeyID != crypto.Fingerprint([]byte(material)) {
		t.Fatal("env 模式的金鑰引用應為材料指紋")
	}
}

// TestDelegatedRewrapProviderRequiresDeploymentTopology 委託重包目標的區域／
// 服務商／信任帳號沿用**本解封世代的拓撲**（原為本行程的 KEK_KMS_* 組態）；
// 缺項時錯誤 SHALL 指名缺的是什麼，而非籠統「建構失敗」。
//
// **金鑰引用亦為必要項（安全審查 high #1）**：它是信任帳號範圍的唯一來源，
// 沒有它就無從判定請求指定的 key_ref 是否屬於本部署信任的雲端帳號。
func TestDelegatedRewrapProviderRequiresDeploymentTopology(t *testing.T) {
	ctx := context.Background()
	t.Run("empty-topology", func(t *testing.T) {
		o := delegatedFixtureOwner(t, config.KMSSettings{}, awsFixtureSecrets())
		p, err := buildDelegatedRewrapProviderWithConstructors(ctx, crypto.KeyRefProviderKMS, "alias/x", o, nil, nil)
		if p != nil || err == nil {
			t.Fatal("缺拓撲時 MUST 拒絕受理")
		}
	})
	t.Run("field-completeness-at-construction", func(t *testing.T) {
		o := delegatedFixtureOwner(t, config.KMSSettings{Provider: "aws"}, delegatedSecrets{})
		base, err := o.settings()
		if err != nil {
			t.Fatal(err)
		}
		err = config.ValidateKMSSettings(base)
		if err == nil {
			t.Fatal("空拓撲通過了建構期驗證")
		}
		for _, field := range []string{config.FieldKMSKeyID, config.FieldKMSRegion,
			config.FieldAWSAccessKeyID, config.FieldAWSSecretAccessKey} {
			if !strings.Contains(err.Error(), field) {
				t.Fatalf("建構期錯誤未指名缺少的欄位 %s：%v", field, err)
			}
		}
	})
}

// TestDelegatedRewrapProviderRequiresTrustAnchor 信任錨點單獨缺席時亦拒絕受理。
//
// **這是信任錨點在組裝層的 fail-close**：沒有錨點就沒有信任範圍，若此時放行，
// kms.New 會收到零值 Scope 而**完全不做帳號檢查**——正是修補要消滅的狀態。
func TestDelegatedRewrapProviderRequiresTrustAnchor(t *testing.T) {
	o := delegatedFixtureOwner(t, awsFixtureSettings("", "ap-northeast-1"), awsFixtureSecrets())
	p, err := buildDelegatedRewrapProviderWithConstructors(context.Background(), crypto.KeyRefProviderKMS,
		"arn:aws:kms:ap-northeast-1:999999999999:key/abcd1234-12ab-34cd-56ef-1234567890ab", o, nil, nil)
	if err == nil {
		t.Fatal("缺信任錨點時 MUST 拒絕受理（否則等同不做跨帳號檢查）")
	}
	if p != nil {
		t.Fatal("失敗路徑不得回傳 provider")
	}
	if !strings.Contains(err.Error(), retiredTrustAnchorEnvKey) {
		t.Fatalf("錯誤未指名信任錨點：%v", err)
	}
}

// TestDelegatedRewrapProviderRejectsForeignAccountTarget **跨帳號目標在組裝層的
// fail-close**。
//
// 信任錨點是 123456789012 的金鑰；請求指定的 key_ref 是**同 region、他帳號**的
// 完整 ARN。region 沿用完全擋不住這條路徑，故必須在此拒絕，
// 且錯誤須指出目標帳號號碼（操作者要能分辨是誤設還是有人在試）。
func TestDelegatedRewrapProviderRejectsForeignAccountTarget(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	clearAWSEnvironment(t)
	o := delegatedFixtureOwner(t, awsFixtureSettings(
		"arn:aws:kms:xx-nowhere-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab", "xx-nowhere-1"),
		awsFixtureSecrets())

	foreign := "arn:aws:kms:xx-nowhere-1:999999999999:key/abcd1234-12ab-34cd-56ef-1234567890ab"
	p, err := buildDelegatedRewrapProviderWithConstructors(ctx, crypto.KeyRefProviderKMS, foreign, o, nil, nil)
	if err == nil {
		t.Fatal("他帳號目標 MUST 拒絕受理")
	}
	if p != nil {
		t.Fatal("失敗路徑不得回傳 provider")
	}
	// **注意**：此處若走到真的連線才失敗，錯誤會是「不可達」而非「不在信任範圍」，
	// 那代表帳號比對沒有發生在建構的最前段——本斷言正是要擋住這種退化。
	if !errors.Is(err, kmskek.ErrKeyOutsideTrustedAccount) {
		t.Fatalf("應以 ErrKeyOutsideTrustedAccount 拒絕（不得等到連線失敗才報錯），得 %v", err)
	}
	if !strings.Contains(err.Error(), "999999999999") {
		t.Fatalf("錯誤未指出目標帳號：%v", err)
	}
}

// TestDelegatedRewrapProviderRejectsHSM hsm 委託尚未交付：明示拒絕而非靜默回落
func TestDelegatedRewrapProviderRejectsHSM(t *testing.T) {
	o := delegatedFixtureOwner(t, awsFixtureSettings("alias/custodexa-kek", "ap-northeast-1"), awsFixtureSecrets())
	if _, err := buildDelegatedRewrapProviderWithConstructors(context.Background(),
		crypto.KeyRefProviderHSM, "token:label", o, nil, nil); err == nil {
		t.Fatal("hsm 目標尚未交付，應拒絕")
	}
}
