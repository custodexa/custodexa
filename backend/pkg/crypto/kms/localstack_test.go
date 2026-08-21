package kms

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/custodexa/backend/internal/testgate"
	"github.com/custodexa/backend/pkg/crypto"
)

// localstack 實測（D11.1 裁決 4 的雙軌驗收之 (b)）。
//
// **雙軌的分工**：fake client 負責「我們送出去的請求恆帶 KeyId 與
// EncryptionContext」這條確定性斷言；本檔負責**語義行為**——「他金鑰包裹的 blob
// ＋竄改 kek_id MUST 解包失敗」是否真的被 KMS 端拒絕。後者取決於實作端是否真的
// 強制比對，那不是我們能斷言的，只能實測。
//
// gating：TEST_KMS_ENDPOINT（未設即 skip；REQUIRE_INTEGRATION=1 時 skip 轉 fail）。
// 跑法（compose 內）：
//
//	docker compose up -d localstack
//	docker compose exec -T backend sh -c \
//	  'TEST_KMS_ENDPOINT=http://localstack:4566 REQUIRE_INTEGRATION=1 \
//	   go test ./pkg/crypto/kms -run Localstack -v'

const localstackRegion = "us-east-1"

// localstackClient 直連 localstack 的真 SDK 客戶端（測試自行建金鑰用）
func localstackClient(t *testing.T, endpoint string) *awskms.Client {
	t.Helper()
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(localstackRegion),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")))
	if err != nil {
		t.Fatalf("載入 AWS 組態失敗: %v", err)
	}
	return awskms.NewFromConfig(cfg, func(o *awskms.Options) { o.BaseEndpoint = &endpoint })
}

// createLocalstackKey 建一把對稱加密 CMK 並掛上 alias，回傳 (arn, alias)。
//
// **alias 加上唯一後綴**：localstack 於容器存活期間保留金鑰與 alias，
// 固定名稱會在第二次執行時 AlreadyExistsException——那是一個與被測行為無關的
// 假紅，且會逼人去 recreate 容器才敢重跑測試。
func createLocalstackKey(t *testing.T, c *awskms.Client, aliasBase string) (string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	alias := fmt.Sprintf("%s-%d", aliasBase, time.Now().UnixNano())
	out, err := c.CreateKey(ctx, &awskms.CreateKeyInput{
		KeySpec:     types.KeySpecSymmetricDefault,
		KeyUsage:    types.KeyUsageTypeEncryptDecrypt,
		Description: strptr("custodexa KEK 整合測試"),
	})
	if err != nil {
		t.Fatalf("CreateKey 失敗（localstack 是否已啟動？）: %v", err)
	}
	arn := *out.KeyMetadata.Arn
	if _, err := c.CreateAlias(ctx, &awskms.CreateAliasInput{
		AliasName: &alias, TargetKeyId: out.KeyMetadata.KeyId,
	}); err != nil {
		t.Fatalf("CreateAlias 失敗: %v", err)
	}
	return arn, alias
}

func localstackProvider(t *testing.T, endpoint, keyInput string) *Provider {
	t.Helper()
	p, err := New(context.Background(), Settings{
		Provider: ProviderAWS, KeyID: keyInput, Region: localstackRegion, Endpoint: endpoint,
	})
	if err != nil {
		t.Fatalf("New(%s): %v", keyInput, err)
	}
	return p
}

// TestLocalstackNormalizationAndRoundtrip alias 與 ARN 兩種輸入形式解析到
// 同一個正規 ARN，且往返可解——「把組態自 alias 改為 ARN 後仍可正常開機」
// 在真實 KMS 語義下的實證
func TestLocalstackNormalizationAndRoundtrip(t *testing.T) {
	endpoint := testgate.Value(t, testgate.EnvKMSEndpoint)
	c := localstackClient(t, endpoint)
	arn, alias := createLocalstackKey(t, c, "alias/custodexa-kek-roundtrip")

	byAlias := localstackProvider(t, endpoint, alias)
	byARN := localstackProvider(t, endpoint, arn)
	if byAlias.KeyRef().KeyID != arn || byARN.KeyRef().KeyID != arn {
		t.Fatalf("兩種輸入形式應解析到同一正規 ARN：alias→%s ARN→%s（期望 %s）",
			byAlias.KeyRef().KeyID, byARN.KeyRef().KeyID, arn)
	}
	if !IsCanonicalKeyARN(byAlias.KeyRef().KeyID) {
		t.Fatalf("解析結果非正規 key ARN：%s", byAlias.KeyRef().KeyID)
	}

	ctx := context.Background()
	aad := crypto.DEKAAD("data", 1)
	dek := bytes.Repeat([]byte{6}, 32)
	wrapped, err := byAlias.Wrap(ctx, dek, aad)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	// 以 ARN 建構的 provider 解 alias 建構的 provider 所包裹的材料——
	// 這正是「改寫組態形式後仍可開機」的實質內容
	got, err := byARN.Unwrap(ctx, wrapped, aad)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("往返材料不符")
	}
}

// TestLocalstackForeignKeyBlobRejected **本檔的核心語義斷言**：
// 以他金鑰包裹的 blob 配上被竄改的 kek_id（＝以本 provider 解包）MUST 失敗。
//
// 這條在 D5 剔除 KeyID 出 AAD 之後，唯一的承載機制就是 Decrypt 顯式帶 KeyId
// （MED-1）。若哪天有人把 KeyId 拿掉，本測試會轉紅。
func TestLocalstackForeignKeyBlobRejected(t *testing.T) {
	endpoint := testgate.Value(t, testgate.EnvKMSEndpoint)
	c := localstackClient(t, endpoint)
	_, aliasA := createLocalstackKey(t, c, "alias/custodexa-kek-a")
	_, aliasB := createLocalstackKey(t, c, "alias/custodexa-kek-b")

	pa := localstackProvider(t, endpoint, aliasA)
	pb := localstackProvider(t, endpoint, aliasB)

	ctx := context.Background()
	aad := crypto.DEKAAD("data", 1)
	wrapped, err := pb.Wrap(ctx, bytes.Repeat([]byte{2}, 32), aad)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if _, err := pa.Unwrap(ctx, wrapped, aad); err == nil {
		t.Fatal("他金鑰包裹的 blob MUST 解包失敗（顯式 KeyId 未生效）")
	}
}

// TestLocalstackWrongEncryptionContextRejected AAD 不符 MUST 解包失敗
// （EncryptionContext 確實參與 KMS 的認證加密）
func TestLocalstackWrongEncryptionContextRejected(t *testing.T) {
	endpoint := testgate.Value(t, testgate.EnvKMSEndpoint)
	c := localstackClient(t, endpoint)
	_, alias := createLocalstackKey(t, c, "alias/custodexa-kek-aad")
	p := localstackProvider(t, endpoint, alias)

	ctx := context.Background()
	wrapped, err := p.Wrap(ctx, bytes.Repeat([]byte{3}, 32), crypto.DEKAAD("data", 1))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if _, err := p.Unwrap(ctx, wrapped, crypto.DEKAAD("data", 2)); err == nil {
		t.Fatal("AAD 不符 MUST 解包失敗（EncryptionContext 未生效）")
	}
	if _, err := p.Unwrap(ctx, wrapped, crypto.DEKAAD("audit", 1)); err == nil {
		t.Fatal("purpose 不同的 AAD MUST 解包失敗")
	}
}

// localstackNotImplemented 判定錯誤是否為 localstack 社群版的**能力缺口**
// （該 API 未實作／屬 pro 功能），而非我方實作錯誤。
//
// **為何允許這一格 skip、而其他一律 fail**：REQUIRE_INTEGRATION 要消滅的假綠是
// 「靶機在場卻沒跑」；本格是「靶機在場、但該 API 根本不存在」，兩者不同。
// 判定條件收得極窄（必須是 501 且訊息明言未實作），任何其他錯誤照樣紅。
// 該路徑的確定性覆蓋在 TestReEncryptNativeCarriesFourExplicitParams（fake client），
// 那才是四項參數的權威守衛——正是「安全斷言不依賴模擬器保真度」的實例。
func localstackNotImplemented(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "StatusCode: 501") &&
		strings.Contains(msg, "not yet implemented or pro feature")
}

// TestLocalstackNativeReEncryptSameFamily C1↔C1 換金鑰走原生 ReEncrypt，
// 四項顯式參數在真 API 上成立（省 DestinationEncryptionContext 會讓後續帶 AAD
// 的 Decrypt 失敗——本測試的最後一步正是驗這件事）
func TestLocalstackNativeReEncryptSameFamily(t *testing.T) {
	endpoint := testgate.Value(t, testgate.EnvKMSEndpoint)
	c := localstackClient(t, endpoint)
	_, aliasSrc := createLocalstackKey(t, c, "alias/custodexa-kek-re-src")
	_, aliasDst := createLocalstackKey(t, c, "alias/custodexa-kek-re-dst")

	src := localstackProvider(t, endpoint, aliasSrc)
	dst := localstackProvider(t, endpoint, aliasDst)

	ctx := context.Background()
	aad := crypto.DEKAAD("data", 4)
	dek := bytes.Repeat([]byte{8}, 32)
	wrapped, err := src.Wrap(ctx, dek, aad)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	out, err := dst.ReEncrypt(ctx, wrapped, aad, src)
	if localstackNotImplemented(err) {
		t.Skipf("localstack 社群版未實作 kms:ReEncrypt——原生路徑的四項顯式參數"+
			"由 TestReEncryptNativeCarriesFourExplicitParams（fake client）確定性覆蓋；原始錯誤: %v", err)
	}
	if err != nil {
		t.Fatalf("原生 ReEncrypt: %v", err)
	}
	got, err := dst.Unwrap(ctx, out, aad)
	if err != nil {
		t.Fatalf("重包後以目標金鑰解包失敗（DestinationEncryptionContext 是否沿用？）: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("原生重包後材料不符")
	}
	// 來源金鑰不得再解得開新 blob（確實換了金鑰，不是原樣回傳）
	if _, err := src.Unwrap(ctx, out, aad); err == nil {
		t.Fatal("重包後來源金鑰不應仍能解開新 blob")
	}
}

// TestLocalstackLocalToKMSFallback A/B→C 的主場景實測：來源為本地 AES blob，
// 走回落分支而非原生（原生會 InvalidCiphertextException）
func TestLocalstackLocalToKMSFallback(t *testing.T) {
	endpoint := testgate.Value(t, testgate.EnvKMSEndpoint)
	c := localstackClient(t, endpoint)
	_, alias := createLocalstackKey(t, c, "alias/custodexa-kek-fallback")
	p := localstackProvider(t, endpoint, alias)

	local, err := crypto.NewEnvKEKProvider(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatalf("local provider: %v", err)
	}
	ctx := context.Background()
	aad := crypto.DEKAAD("data", 1)
	dek := bytes.Repeat([]byte{5}, 32)
	localWrapped, err := local.Wrap(ctx, dek, aad)
	if err != nil {
		t.Fatalf("local Wrap: %v", err)
	}
	out, err := p.ReEncrypt(ctx, localWrapped, aad, local)
	if err != nil {
		t.Fatalf("A/B→C 回落重包失敗: %v", err)
	}
	got, err := p.Unwrap(ctx, out, aad)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("回落重包結果不可解或材料不符: %v", err)
	}
	// 委託格式恆編為 wk:2:kms:
	col, err := crypto.EncodeWrappedKey(p.FormatTag(), out)
	if err != nil {
		t.Fatalf("EncodeWrappedKey: %v", err)
	}
	if !strings.HasPrefix(col, "wk:2:kms:") {
		t.Fatalf("委託格式前綴不符：%.16s", col)
	}
}

// TestLocalstackUnusableKeyRejected 停用中的金鑰於建構期即拒（不合用金鑰
// 不得等到解包時才失敗）
func TestLocalstackUnusableKeyRejected(t *testing.T) {
	endpoint := testgate.Value(t, testgate.EnvKMSEndpoint)
	c := localstackClient(t, endpoint)
	arn, alias := createLocalstackKey(t, c, "alias/custodexa-kek-disabled")
	if _, err := c.DisableKey(context.Background(), &awskms.DisableKeyInput{KeyId: &arn}); err != nil {
		t.Fatalf("DisableKey: %v", err)
	}
	_, err := New(context.Background(), Settings{
		Provider: ProviderAWS, KeyID: alias, Region: localstackRegion, Endpoint: endpoint,
	})
	if err == nil {
		t.Fatal("停用中的金鑰 MUST 於建構期被拒")
	}
}
