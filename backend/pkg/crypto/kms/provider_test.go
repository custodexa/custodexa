package kms

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"

	"github.com/custodexa/backend/pkg/crypto"
)

const (
	testKeyARN   = "arn:aws:kms:ap-northeast-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
	testKeyID    = "1234abcd-12ab-34cd-56ef-1234567890ab"
	testKeyAlias = "alias/custodexa-kek"
	testRegion   = "ap-northeast-1"

	otherKeyARN   = "arn:aws:kms:ap-northeast-1:123456789012:key/9999abcd-12ab-34cd-56ef-1234567890ab"
	otherKeyID    = "9999abcd-12ab-34cd-56ef-1234567890ab"
	otherKeyAlias = "alias/custodexa-kek-2"
)

// newTestProvider 建構 provider 並**清空建構期 canary 留下的加解密呼叫紀錄**。
//
// New 於建構期跑一次 Encrypt→Decrypt 往返（安全審查 med #5：DescribeKey
// 只證明 metadata 合格，不證明有加解密權限）。各測試斷言的是**自己觸發的**請求
// 次數，故此處把加解密計數歸零，使「Wrap 一次 ⇒ encryptCalls==1」這類斷言仍然
// 表達它字面上的意思。**describeCalls 刻意不清**——重試分流的測試正是要數它。
// canary 自身的行為由 TestNewRunsEncryptDecryptCanary 專門覆蓋。
func newTestProvider(t *testing.T, f *fakeKMS, keyInput string) *Provider {
	t.Helper()
	p, err := New(context.Background(), Settings{
		Provider: ProviderAWS, KeyID: keyInput, Region: testRegion, Client: f,
	})
	if err != nil {
		t.Fatalf("New(%s): %v", keyInput, err)
	}
	f.resetCryptoCalls()
	return p
}

func newFakeWithKey(t *testing.T) (*fakeKMS, *Provider) {
	t.Helper()
	f := newFakeKMS()
	f.addKey(testKeyAlias, testKeyID, testKeyARN)
	return f, newTestProvider(t, f, testKeyAlias)
}

// ---- 3.1a 輸入端正規化 ----

// TestKeyIDInputFormsNormalizeToSameARN 「把 KEK_KMS_KEY_ID 自 alias 改為 ARN
// （無語義變更）後仍可正常開機」——**本項的存在理由**。三種輸入形式必須解析到
// 同一個正規 ARN，否則代表列篩選會落空而 ErrKEKMismatch 拒啟動。
func TestKeyIDInputFormsNormalizeToSameARN(t *testing.T) {
	f := newFakeKMS()
	f.addKey(testKeyAlias, testKeyID, testKeyARN)
	for _, input := range []string{testKeyAlias, testKeyID, testKeyARN} {
		p := newTestProvider(t, f, input)
		if got := p.KeyRef().KeyID; got != testKeyARN {
			t.Fatalf("輸入 %q 的 KeyRef().KeyID 應正規化為 %q，得 %q", input, testKeyARN, got)
		}
		if p.KeyRef().Provider != crypto.KeyRefProviderKMS {
			t.Fatalf("KeyRef().Provider 應為 kms，得 %q", p.KeyRef().Provider)
		}
	}
}

// TestNewRejectsUnusableKey 建構期即驗金鑰可用性：非對稱／錯 KeyUsage／停用
// 三類各自 fail-close（不驗則會先寫 DB 才在解包時失敗）
func TestNewRejectsUnusableKey(t *testing.T) {
	cases := []struct {
		name  string
		mutar func(*types.KeyMetadata)
		want  string
	}{
		{"非對稱金鑰", func(m *types.KeyMetadata) { m.KeySpec = types.KeySpecRsa4096 }, "KeySpec"},
		{"錯 KeyUsage", func(m *types.KeyMetadata) { m.KeyUsage = types.KeyUsageTypeSignVerify }, "KeyUsage"},
		{"金鑰停用", func(m *types.KeyMetadata) { m.KeyState = types.KeyStateDisabled }, "KeyState"},
		{"待刪除", func(m *types.KeyMetadata) { m.KeyState = types.KeyStatePendingDeletion }, "KeyState"},
		{"Enabled 為 false", func(m *types.KeyMetadata) { m.Enabled = false }, "已停用"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeKMS()
			meta := f.addKey(testKeyAlias, testKeyID, testKeyARN)
			c.mutar(meta)
			_, err := New(context.Background(), Settings{
				Provider: ProviderAWS, KeyID: testKeyAlias, Region: testRegion, Client: f,
			})
			if !errors.Is(err, ErrKeyUnusable) {
				t.Fatalf("應以 ErrKeyUnusable 拒絕，得 %v", err)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("錯誤訊息未指出 %s：%v", c.want, err)
			}
		})
	}
}

// TestNewRejectsUnsupportedProvider GCP／Azure 留介面不實作：顯式拒絕而非猜測
func TestNewRejectsUnsupportedProvider(t *testing.T) {
	f, _ := newFakeWithKey(t)
	if _, err := New(context.Background(), Settings{
		Provider: "gcp", KeyID: testKeyAlias, Region: testRegion, Client: f,
	}); err == nil {
		t.Fatal("非 aws 服務商應拒絕")
	}
}

// TestValidateKeyIDSyntaxUsesARNGrammar 「非正規」的判定式是 **ARN 語法**，
// SHALL NOT 是「不等於當前 KeyID」。
//
// 正向斷言是本測試的重點（收窄三的失敗判準）：**語法合格的他把 ARN
// 不得被判為非正規**——否則退役 KEK 與重包過渡期的舊列會被一律誤殺。
func TestValidateKeyIDSyntaxUsesARNGrammar(t *testing.T) {
	_, p := newFakeWithKey(t)

	// 正向：他把合法 ARN（不等於當前 KeyID）不得被判非正規
	if err := p.ValidateKeyIDSyntax(otherKeyARN); err != nil {
		t.Fatalf("語法合格的他把 ARN 不得判為非正規：%v", err)
	}
	// 正向：多區域金鑰（mrk-）
	if err := p.ValidateKeyIDSyntax("arn:aws:kms:us-east-1:123456789012:key/mrk-1234567890abcdef1234567890abcdef"); err != nil {
		t.Fatalf("MRK ARN 不得判為非正規：%v", err)
	}
	// 正向：其他 partition（值域收窄後仍須放行 aws-cn／aws-us-gov 的**真實形狀** ARN；
	// 舊版此格用的是 `key/abc-123`，那不是 KMS 產得出來的 key-id）
	for _, ok := range []string{
		"arn:aws-cn:kms:cn-north-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		"arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		"arn:aws:kms:ap-southeast-3:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		"arn:aws-cn:kms:cn-northwest-1:123456789012:key/mrk-1234567890abcdef1234567890abcdef",
	} {
		if err := p.ValidateKeyIDSyntax(ok); err != nil {
			t.Fatalf("合法他把 ARN %q 不得判為非正規（收窄不得誤殺）：%v", ok, err)
		}
	}

	// 反向：alias／裸 key-id／alias ARN／本地指紋，以及**值域收窄後才擋得住的形態**
	for _, bad := range []string{
		testKeyAlias, testKeyID, "",
		"arn:aws:kms:ap-northeast-1:123456789012:alias/custodexa-kek",
		"a1b2c3d4e5f60718",                         // 本地 KEK 指紋（16 hex）
		"arn:aws:kms:ap-northeast-1:12345:key/abc", // 帳號段長度不符
		// 以下六格在收窄前**全部通過**（安全審查 med #3 的實例）
		"arn:x:kms:-:000000000000:key/A", // 任意 partition＋退化 region＋單字元資源
		"arn:aws:kms:not-a-region:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab",    // region 形狀不符
		"arn:evil:kms:ap-northeast-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab", // partition 不在列舉
		"arn:aws:kms:ap-northeast-1:123456789012:key/1234ABCD-12AB-34CD-56EF-1234567890AB",  // 大寫資源
		"arn:aws:kms:ap-northeast-1:123456789012:key/mrk-XYZ",                               // 假 MRK
		"arn:aws:kms:ap-northeast-1:123456789012:key/" + strings.Repeat("a", 300),           // 超長
	} {
		if err := p.ValidateKeyIDSyntax(bad); !errors.Is(err, ErrKeyIDNotCanonical) {
			t.Fatalf("%q 應判為非正規，得 %v", bad, err)
		}
	}
}

// TestParseKeyARNSegments ParseKeyARN 是帳號信任範圍檢查與非正規偵測的**共用**
// 解析入口：兩者不可能對「什麼算正規」有不同理解。本格釘住各段的切分正確。
func TestParseKeyARNSegments(t *testing.T) {
	parts, ok := ParseKeyARN("arn:aws-us-gov:kms:us-gov-west-1:210987654321:key/mrk-1234567890abcdef1234567890abcdef")
	if !ok {
		t.Fatal("合法 ARN 應解析成功")
	}
	if parts.Partition != "aws-us-gov" || parts.Region != "us-gov-west-1" ||
		parts.Account != "210987654321" || parts.KeyID != "mrk-1234567890abcdef1234567890abcdef" {
		t.Fatalf("切分錯誤：%+v", parts)
	}
	if !parts.IsMultiRegion() {
		t.Fatal("mrk- 前綴應判為多區域金鑰")
	}
	plain, _ := ParseKeyARN(testKeyARN)
	if plain.IsMultiRegion() {
		t.Fatal("一般 UUID 金鑰不得判為多區域金鑰")
	}
	if _, ok := ParseKeyARN("arn:x:kms:-:000000000000:key/A"); ok {
		t.Fatal("非正規形式不得解析成功")
	}
}

// ---- 3.1 有界重試與立即失敗分流 ----

// TestDescribeRetriesThrottlingWithinBudget 節流類錯誤有界退避重試；
// 總嘗試上限 3 次（首次＋2 次重試）
func TestDescribeRetriesThrottlingWithinBudget(t *testing.T) {
	f := newFakeKMS()
	f.addKey(testKeyAlias, testKeyID, testKeyARN)
	f.describeErrs = []error{
		&smithy.GenericAPIError{Code: "ThrottlingException", Message: "slow down"},
		&smithy.GenericAPIError{Code: "ThrottlingException", Message: "slow down"},
	}
	start := time.Now()
	p := newTestProvider(t, f, testKeyAlias)
	if p.KeyRef().KeyID != testKeyARN {
		t.Fatal("重試成功後仍應取得正規 ARN")
	}
	if len(f.describeCalls) != 3 {
		t.Fatalf("應恰嘗試 3 次（首次＋2 次重試），得 %d", len(f.describeCalls))
	}
	if elapsed := time.Since(start); elapsed >= describeTotalBudget {
		t.Fatalf("重試耗時 %s 應遠低於總預算 %s", elapsed, describeTotalBudget)
	}
}

// TestDescribeRetryExhaustsAtThreeAttempts 節流不止息時於第 3 次嘗試後放棄，
// SHALL NOT 無限重試（那會把組態錯誤拖成「服務永遠不就緒」）
func TestDescribeRetryExhaustsAtThreeAttempts(t *testing.T) {
	f := newFakeKMS()
	f.addKey(testKeyAlias, testKeyID, testKeyARN)
	for i := 0; i < 10; i++ {
		f.describeErrs = append(f.describeErrs, &smithy.GenericAPIError{Code: "ThrottlingException"})
	}
	_, err := New(context.Background(), Settings{
		Provider: ProviderAWS, KeyID: testKeyAlias, Region: testRegion, Client: f,
	})
	if !errors.Is(err, ErrKMSUnavailable) {
		t.Fatalf("重試耗盡應回 ErrKMSUnavailable，得 %v", err)
	}
	if len(f.describeCalls) != describeMaxAttempts {
		t.Fatalf("嘗試次數應為 %d，得 %d", describeMaxAttempts, len(f.describeCalls))
	}
	// 權限清單須完整（漏列 DescribeKey 會使「組態齊備但缺該權限」得到誤導性錯誤）
	for _, action := range []string{"kms:DescribeKey", "kms:Encrypt", "kms:Decrypt", "kms:ReEncryptFrom", "kms:ReEncryptTo"} {
		if !strings.Contains(err.Error(), action) {
			t.Fatalf("錯誤訊息未列出所需 IAM action %s：%v", action, err)
		}
	}
}

// TestDescribeFailsImmediatelyOnDenial AccessDenied／NotFound 立即失敗、不重試
func TestDescribeFailsImmediatelyOnDenial(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"AccessDenied", &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "denied"}},
		{"NotFound", &types.NotFoundException{Message: strptr("no such key")}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeKMS()
			f.addKey(testKeyAlias, testKeyID, testKeyARN)
			f.describeErrs = []error{c.err, c.err, c.err}
			_, err := New(context.Background(), Settings{
				Provider: ProviderAWS, KeyID: testKeyAlias, Region: testRegion, Client: f,
			})
			if !errors.Is(err, ErrKMSRejected) {
				t.Fatalf("應立即失敗（ErrKMSRejected），得 %v", err)
			}
			if len(f.describeCalls) != 1 {
				t.Fatalf("明確拒絕不得重試：嘗試了 %d 次", len(f.describeCalls))
			}
		})
	}
}

// TestDescribeRespectsContextCancel context 取消即中止並回原因，
// **不吞成逾時**（安全審查 low 明列）
func TestDescribeRespectsContextCancel(t *testing.T) {
	f := newFakeKMS()
	f.addKey(testKeyAlias, testKeyID, testKeyARN)
	f.describeErrs = []error{
		&smithy.GenericAPIError{Code: "ThrottlingException"},
		&smithy.GenericAPIError{Code: "ThrottlingException"},
		&smithy.GenericAPIError{Code: "ThrottlingException"},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := New(ctx, Settings{Provider: ProviderAWS, KeyID: testKeyAlias, Region: testRegion, Client: f})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("應回報呼叫端取消，得 %v", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("取消不得被吞成逾時")
	}
}

// ---- 3.1(a) EncryptionContext wire contract ----

// TestEncryptionContextWireContract 鍵名與編碼是**永久 wire contract**：
// 改動等同既有委託密文全不可解。本測試釘死 `{"aad": base64Std(aadBytes)}` 單鍵形狀。
func TestEncryptionContextWireContract(t *testing.T) {
	f, p := newFakeWithKey(t)
	aad := crypto.DEKAAD("data", 7)
	if _, err := p.Wrap(context.Background(), make([]byte, 32), aad); err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if len(f.encryptCalls) != 1 {
		t.Fatalf("應恰一次 Encrypt，得 %d", len(f.encryptCalls))
	}
	ec := f.encryptCalls[0].EncryptionContext
	if len(ec) != 1 {
		t.Fatalf("EncryptionContext SHALL 為單鍵不透明映射，得 %d 鍵：%v", len(ec), ec)
	}
	got, ok := ec[EncryptionContextAADKey]
	if !ok {
		t.Fatalf("鍵名 SHALL 為 %q，得 %v", EncryptionContextAADKey, ec)
	}
	if EncryptionContextAADKey != "aad" {
		t.Fatalf("wire contract 鍵名不得改動：得 %q", EncryptionContextAADKey)
	}
	if want := base64.StdEncoding.EncodeToString(aad); got != want {
		t.Fatalf("值 SHALL 為 base64.StdEncoding(aad)：want %q got %q", want, got)
	}
	// SHALL NOT 反解 AAD 內部結構成語義多鍵
	for _, forbidden := range []string{"purpose", "version", "kek_id"} {
		if _, exists := ec[forbidden]; exists {
			t.Fatalf("SHALL NOT 出現語義鍵 %q（provider 對 AAD 內容須完全不可知）", forbidden)
		}
	}
}

// TestWrapUnwrapRejectEmptyAAD len(aad)==0 直接回錯，**不送出空 context**
// （與委託不變式對齊：EncodeWrappedKey 對委託格式一律要求 AAD）
func TestWrapUnwrapRejectEmptyAAD(t *testing.T) {
	f, p := newFakeWithKey(t)
	for _, aad := range [][]byte{nil, {}} {
		if _, err := p.Wrap(context.Background(), make([]byte, 32), aad); !errors.Is(err, ErrAADRequired) {
			t.Fatalf("空 AAD 的 Wrap 應回 ErrAADRequired，得 %v", err)
		}
		if _, err := p.Unwrap(context.Background(), []byte("x"), aad); !errors.Is(err, ErrAADRequired) {
			t.Fatalf("空 AAD 的 Unwrap 應回 ErrAADRequired，得 %v", err)
		}
	}
	if len(f.encryptCalls) != 0 || len(f.decryptCalls) != 0 {
		t.Fatalf("空 AAD 時 SHALL NOT 送出任何請求：encrypt=%d decrypt=%d",
			len(f.encryptCalls), len(f.decryptCalls))
	}
}

// TestDecryptAlwaysCarriesKeyIDAndContext 雙軌驗收 (i)：每次 Decrypt 入參
// **恆帶** KeyId 與 EncryptionContext（跨金鑰解包防線的顯式承載機制）
func TestDecryptAlwaysCarriesKeyIDAndContext(t *testing.T) {
	f, p := newFakeWithKey(t)
	aad := crypto.DEKAAD("data", 1)
	dek := bytes.Repeat([]byte{7}, 32)
	wrapped, err := p.Wrap(context.Background(), dek, aad)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	got, err := p.Unwrap(context.Background(), wrapped, aad)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("往返材料不符")
	}
	if len(f.decryptCalls) != 1 {
		t.Fatalf("應恰一次 Decrypt，得 %d", len(f.decryptCalls))
	}
	in := f.decryptCalls[0]
	if in.KeyId == nil || *in.KeyId != testKeyARN {
		t.Fatalf("Decrypt SHALL 顯式帶正規化 KeyId，得 %v", in.KeyId)
	}
	if len(in.EncryptionContext) != 1 || in.EncryptionContext[EncryptionContextAADKey] == "" {
		t.Fatalf("Decrypt SHALL 帶 EncryptionContext，得 %v", in.EncryptionContext)
	}
}

// TestUnwrapRejectsForeignKeyBlob 他金鑰包裹的 blob 以本 provider 解包 MUST 失敗
// （顯式 KeyId 的實際效果；語義面另以 localstack 實測）
func TestUnwrapRejectsForeignKeyBlob(t *testing.T) {
	f := newFakeKMS()
	f.addKey(testKeyAlias, testKeyID, testKeyARN)
	f.addKey(otherKeyAlias, otherKeyID, otherKeyARN)
	p := newTestProvider(t, f, testKeyAlias)
	other := newTestProvider(t, f, otherKeyAlias)

	aad := crypto.DEKAAD("data", 1)
	foreign, err := other.Wrap(context.Background(), make([]byte, 32), aad)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if _, err := p.Unwrap(context.Background(), foreign, aad); err == nil {
		t.Fatal("他金鑰包裹的 blob MUST 解包失敗")
	}
}

// TestUnwrapRejectsWrongAAD AAD 不符即解包失敗（EncryptionContext 綁定生效）
func TestUnwrapRejectsWrongAAD(t *testing.T) {
	_, p := newFakeWithKey(t)
	wrapped, err := p.Wrap(context.Background(), make([]byte, 32), crypto.DEKAAD("data", 1))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if _, err := p.Unwrap(context.Background(), wrapped, crypto.DEKAAD("data", 2)); err == nil {
		t.Fatal("AAD 不符 MUST 解包失敗")
	}
}

// ---- 3.1(b) ReEncrypt 分派 ----

// TestReEncryptFallsBackForNonKMSSource A/B→C 的主場景：來源是本地 AES blob，
// **SHALL 走回落分支**（AWS ReEncrypt 只吃 KMS 密文，走原生必
// InvalidCiphertextException）
func TestReEncryptFallsBackForNonKMSSource(t *testing.T) {
	f, p := newFakeWithKey(t)
	local, err := crypto.NewEnvKEKProvider(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatalf("local provider: %v", err)
	}
	aad := crypto.DEKAAD("data", 1)
	dek := bytes.Repeat([]byte{9}, 32)
	localWrapped, err := local.Wrap(context.Background(), dek, aad)
	if err != nil {
		t.Fatalf("local Wrap: %v", err)
	}

	out, err := p.ReEncrypt(context.Background(), localWrapped, aad, local)
	if err != nil {
		t.Fatalf("ReEncrypt 回落分支: %v", err)
	}
	if len(f.reEncryptCalls) != 0 {
		t.Fatal("非同族來源 SHALL NOT 走原生 ReEncrypt")
	}
	if len(f.encryptCalls) != 1 {
		t.Fatalf("回落分支應以本 provider Encrypt 一次，得 %d", len(f.encryptCalls))
	}
	got, err := p.Unwrap(context.Background(), out, aad)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("回落重包結果不可解或材料不符: %v", err)
	}
}

// TestReEncryptNativeCarriesFourExplicitParams 同族 KMS 來源走原生路徑，
// 且 SHALL 顯式帶四項參數——**缺一即實作缺陷**：
// 省 SourceKeyId＝跨金鑰解包漏洞重現；省 DestinationEncryptionContext＝變成空 context
func TestReEncryptNativeCarriesFourExplicitParams(t *testing.T) {
	f := newFakeKMS()
	f.addKey(testKeyAlias, testKeyID, testKeyARN)
	f.addKey(otherKeyAlias, otherKeyID, otherKeyARN)
	src := newTestProvider(t, f, testKeyAlias)
	dst := newTestProvider(t, f, otherKeyAlias)

	aad := crypto.DEKAAD("data", 5)
	dek := bytes.Repeat([]byte{4}, 32)
	wrapped, err := src.Wrap(context.Background(), dek, aad)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	out, err := dst.ReEncrypt(context.Background(), wrapped, aad, src)
	if err != nil {
		t.Fatalf("原生 ReEncrypt: %v", err)
	}
	if len(f.reEncryptCalls) != 1 {
		t.Fatalf("同族來源應走原生 ReEncrypt 一次，得 %d", len(f.reEncryptCalls))
	}
	in := f.reEncryptCalls[0]
	if in.SourceKeyId == nil || *in.SourceKeyId != testKeyARN {
		t.Fatalf("缺 SourceKeyId（跨金鑰解包漏洞重現）：%v", in.SourceKeyId)
	}
	if in.DestinationKeyId == nil || *in.DestinationKeyId != otherKeyARN {
		t.Fatalf("缺 DestinationKeyId：%v", in.DestinationKeyId)
	}
	wantCtx := base64.StdEncoding.EncodeToString(aad)
	if in.SourceEncryptionContext[EncryptionContextAADKey] != wantCtx {
		t.Fatalf("缺 SourceEncryptionContext：%v", in.SourceEncryptionContext)
	}
	if in.DestinationEncryptionContext[EncryptionContextAADKey] != wantCtx {
		t.Fatalf("缺 DestinationEncryptionContext（省略會變成空 context 而非沿用）：%v",
			in.DestinationEncryptionContext)
	}
	got, err := dst.Unwrap(context.Background(), out, aad)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("原生重包結果不可解或材料不符: %v", err)
	}
}

// TestReEncryptFallsBackAcrossRegions 跨 region 的 KMS provider 不視為同族
// （區域字串相同但金鑰域不同者亦然，見 sameFamily 的端點比較）
func TestReEncryptFallsBackAcrossRegions(t *testing.T) {
	f := newFakeKMS()
	f.addKey(testKeyAlias, testKeyID, testKeyARN)
	f.addKey(otherKeyAlias, otherKeyID, otherKeyARN)
	src, err := New(context.Background(), Settings{
		Provider: ProviderAWS, KeyID: testKeyAlias, Region: "us-east-1", Client: f,
	})
	if err != nil {
		t.Fatalf("src: %v", err)
	}
	dst := newTestProvider(t, f, otherKeyAlias) // region = ap-northeast-1

	aad := crypto.DEKAAD("data", 1)
	wrapped, err := src.Wrap(context.Background(), bytes.Repeat([]byte{1}, 32), aad)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if _, err := dst.ReEncrypt(context.Background(), wrapped, aad, src); err != nil {
		t.Fatalf("跨 region 回落分支應成功: %v", err)
	}
	if len(f.reEncryptCalls) != 0 {
		t.Fatal("跨 region SHALL NOT 走原生 ReEncrypt")
	}
}

// TestPreflightRoundTrip 連通性預檢實走一次 Encrypt／Decrypt 往返
func TestPreflightRoundTrip(t *testing.T) {
	f, p := newFakeWithKey(t)
	if err := p.Preflight(context.Background()); err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if len(f.encryptCalls) != 1 || len(f.decryptCalls) != 1 {
		t.Fatalf("預檢應各呼叫一次 Encrypt／Decrypt：%d／%d", len(f.encryptCalls), len(f.decryptCalls))
	}
}

// TestProviderIdentity Mode／FormatTag 的固定值（清冊與格式分派的來源）
func TestProviderIdentity(t *testing.T) {
	_, p := newFakeWithKey(t)
	if p.Mode() != crypto.KEKModeKMS {
		t.Fatalf("Mode 應為 kms，得 %q", p.Mode())
	}
	if p.FormatTag() != crypto.WrappedFormatKMS {
		t.Fatalf("FormatTag 應為 kms，得 %q", p.FormatTag())
	}
	if p.Region() != testRegion {
		t.Fatalf("Region 應為 %q，得 %q", testRegion, p.Region())
	}
}

// TestWrappedKeyEncodingIsAADBoundKMS 委託格式恆編為 `wk:2:kms:`
// （`wk:1:kms` 在 EncodeWrappedKey 被建構上拒絕）
func TestWrappedKeyEncodingIsAADBoundKMS(t *testing.T) {
	_, p := newFakeWithKey(t)
	aad := crypto.DEKAAD("data", 1)
	wrapped, err := p.Wrap(context.Background(), make([]byte, 32), aad)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	col, err := crypto.EncodeWrappedKey(p.FormatTag(), wrapped)
	if err != nil {
		t.Fatalf("EncodeWrappedKey: %v", err)
	}
	if !strings.HasPrefix(col, "wk:2:kms:") {
		t.Fatalf("委託格式應恆帶 wk:2:kms: 前綴，得 %.16s", col)
	}
	// 無 AAD 包裹的**編碼能力本身**已刪除：
	// 簽章不再有 AAD 在場性參數，故不存在可產出 `wk:1:kms:` 的呼叫形式
}

var _ API = (*fakeKMS)(nil)
var _ crypto.KEKProvider = (*Provider)(nil)
var _ crypto.KeyIDSyntaxValidator = (*Provider)(nil)
var _ = awskms.DescribeKeyInput{}
