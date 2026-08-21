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

// 組裝根的 KEK provider 建構（kek-provider-modularization tasks 3.1／3.2）。

// kmsDecision 建構期 KMS 判定結果的測試樣本
func kmsDecision(keyID, region string) *config.KEKDecision {
	return &config.KEKDecision{
		Mode: config.KEKModeKMS,
		KMS:  config.KMSSettings{Provider: "aws", KeyID: keyID, Region: region},
	}
}

// TestBuildKEKProviderKMSFailsCloseWhenUnreachable **KMS 不可達即拒啟動**
// （tasks 3.2 的失敗判準：KMS 不可達時降級啟動）。
//
// region 指向一個不存在的 AWS 區域：端點 DNS 解不出來，建構 SHALL 回錯，
// 呼叫端（stage1）以 log.Fatalf 收場。SHALL NOT 回落任何其他 provider、
// SHALL NOT 回 nil error。
//
// **不再以 AWS_ENDPOINT_URL_KMS 模擬不可達（round-4 codex high #2）**：
// 該變數現在會被生產路徑直接拒絕（見下一格），拿它模擬會測到錯的東西。
//
// 此路徑同時證明「探測發生在建構期」——本測試完全沒有 DB。
func TestBuildKEKProviderKMSFailsCloseWhenUnreachable(t *testing.T) {
	// 有界等待：建構期重試的總預算 <10s，故 20s 已足夠涵蓋且不會讓測試掛住
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	t.Setenv("AWS_ENDPOINT_URL_KMS", "")
	t.Setenv("AWS_ENDPOINT_URL", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")

	p, err := buildKEKProvider(ctx, kmsDecision("alias/custodexa-kek", "xx-nowhere-1"))
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

// TestBuildKEKProviderKMSRejectsEndpointOverride **H2 的組裝層 fail-close**
// （round-4 codex high #2）。
//
// 原立論「不新增產品 env 鍵即消除端點覆寫」不成立：AWS_ENDPOINT_URL_KMS／
// AWS_ENDPOINT_URL 由 SDK 自行解析，能把**含明文 DEK 的 kms:Encrypt 請求**
// 導向任意端點甚至 HTTP。生產路徑 SHALL 明確拒絕，且錯誤須指名觸發的變數。
func TestBuildKEKProviderKMSRejectsEndpointOverride(t *testing.T) {
	for _, key := range []string{"AWS_ENDPOINT_URL_KMS", "AWS_ENDPOINT_URL"} {
		t.Run(key, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			t.Setenv("AWS_ENDPOINT_URL_KMS", "")
			t.Setenv("AWS_ENDPOINT_URL", "")
			t.Setenv(key, "http://127.0.0.1:1")
			t.Setenv("AWS_ACCESS_KEY_ID", "test")
			t.Setenv("AWS_SECRET_ACCESS_KEY", "test")

			p, err := buildKEKProvider(ctx, kmsDecision("alias/custodexa-kek", "ap-northeast-1"))
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

// TestTrustAnchorEnvKeyMatchesConfig pkg/crypto/kms 以字面 "KEK_KMS_KEY_ID"
// 表述信任錨點（pkg 層不得反向相依 config），本格釘住兩處字面不漂移。
func TestTrustAnchorEnvKeyMatchesConfig(t *testing.T) {
	_, err := kmskek.ResolveAccountScope(context.Background(), kmskek.Settings{
		Provider: "aws", KeyID: "", Region: "ap-northeast-1",
	})
	if err == nil {
		t.Fatal("缺信任錨點時應回錯")
	}
	if !strings.Contains(err.Error(), config.EnvKeyKMSKeyID) {
		t.Fatalf("kms 套件的錨點鍵名字面已與 config.EnvKeyKMSKeyID（%s）漂移：%v",
			config.EnvKeyKMSKeyID, err)
	}
}

// TestBuildKEKProviderUnsupportedModes 未交付模式一律 fail-close，
// SHALL NOT 靜默回落其他 provider
func TestBuildKEKProviderUnsupportedModes(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{config.KEKModeUI, config.KEKModeHSM, "bogus"} {
		p, err := buildKEKProvider(ctx, &config.KEKDecision{Mode: mode})
		if err == nil {
			t.Fatalf("模式 %q 應回錯", mode)
		}
		if p != nil {
			t.Fatalf("模式 %q 不得回傳 provider", mode)
		}
	}
}

// TestBuildKEKProviderEnvUnchanged env 模式的行為不因 P3 而改變
// （既有部署零可見變化的硬條件）
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

// TestDelegatedRewrapProviderRequiresProcessKMSConfig 委託重包目標的 region／
// 服務商／信任帳號沿用本行程組態；缺項時錯誤 SHALL 逐鍵指名，而非籠統「建構失敗」。
//
// **KEK_KMS_KEY_ID 自本輪起也是必要鍵（round-4 codex high #1）**：
// 它是信任帳號範圍的唯一來源，沒有它就無從判定請求指定的 key_ref 是否屬於
// 本部署信任的雲端帳號。
func TestDelegatedRewrapProviderRequiresProcessKMSConfig(t *testing.T) {
	t.Setenv(config.EnvKeyKMSProvider, "")
	t.Setenv(config.EnvKeyKMSRegion, "")
	t.Setenv(config.EnvKeyKMSKeyID, "")
	_, err := buildDelegatedRewrapProvider(context.Background(), crypto.KeyRefProviderKMS, "alias/x")
	if err == nil {
		t.Fatal("缺 KMS 組態時 MUST 拒絕受理")
	}
	for _, key := range []string{config.EnvKeyKMSProvider, config.EnvKeyKMSRegion, config.EnvKeyKMSKeyID} {
		if !strings.Contains(err.Error(), key) {
			t.Fatalf("錯誤未指名缺少的鍵 %s：%v", key, err)
		}
	}
}

// TestDelegatedRewrapProviderRequiresTrustAnchor 信任錨點單獨缺席時亦拒絕受理。
//
// **這是 H1 在組裝層的 fail-close**：沒有錨點就沒有信任範圍，若此時放行，
// kms.New 會收到零值 Scope 而**完全不做帳號檢查**——正是修補要消滅的狀態。
// 故錨點缺席 SHALL NOT 靜默退化為「不檢查」。
func TestDelegatedRewrapProviderRequiresTrustAnchor(t *testing.T) {
	t.Setenv(config.EnvKeyKMSProvider, "aws")
	t.Setenv(config.EnvKeyKMSRegion, "ap-northeast-1")
	t.Setenv(config.EnvKeyKMSKeyID, "")
	p, err := buildDelegatedRewrapProvider(context.Background(), crypto.KeyRefProviderKMS,
		"arn:aws:kms:ap-northeast-1:999999999999:key/abcd1234-12ab-34cd-56ef-1234567890ab")
	if err == nil {
		t.Fatal("缺信任錨點時 MUST 拒絕受理（否則等同不做跨帳號檢查）")
	}
	if p != nil {
		t.Fatal("失敗路徑不得回傳 provider")
	}
	if !strings.Contains(err.Error(), config.EnvKeyKMSKeyID) {
		t.Fatalf("錯誤未指名 %s：%v", config.EnvKeyKMSKeyID, err)
	}
}

// TestDelegatedRewrapProviderRejectsForeignAccountTarget **H1 的組裝層 fail-close**。
//
// 信任錨點是 123456789012 的金鑰；請求指定的 key_ref 是**同 region、他帳號**的
// 完整 ARN。裁決 6 的 region 沿用完全擋不住這條路徑，故必須在此拒絕，
// 且錯誤須指出目標帳號號碼（操作者要能分辨是誤設還是有人在試）。
//
// 本格於信任範圍推導完成後即拒絕，不需要真的連到 KMS——因為錨點本身是完整 ARN
// （零 KMS 呼叫即可解析出帳號），而目標的帳號段在語法層就已經不符。
func TestDelegatedRewrapProviderRejectsForeignAccountTarget(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	t.Setenv("AWS_ENDPOINT_URL_KMS", "")
	t.Setenv("AWS_ENDPOINT_URL", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv(config.EnvKeyKMSProvider, "aws")
	t.Setenv(config.EnvKeyKMSRegion, "xx-nowhere-1")
	t.Setenv(config.EnvKeyKMSKeyID,
		"arn:aws:kms:xx-nowhere-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab")

	foreign := "arn:aws:kms:xx-nowhere-1:999999999999:key/abcd1234-12ab-34cd-56ef-1234567890ab"
	p, err := buildDelegatedRewrapProvider(ctx, crypto.KeyRefProviderKMS, foreign)
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

// TestDelegatedRewrapProviderRejectsHSM P4 尚未交付：明示拒絕而非靜默回落
func TestDelegatedRewrapProviderRejectsHSM(t *testing.T) {
	if _, err := buildDelegatedRewrapProvider(context.Background(), crypto.KeyRefProviderHSM, "token:label"); err == nil {
		t.Fatal("hsm 目標尚未交付，應拒絕")
	}
}
