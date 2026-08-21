package kms

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/custodexa/backend/pkg/crypto"
)

// EncryptionContextAADKey KMS EncryptionContext 承載 DEK 層 AAD 的**唯一鍵名**
// （D11.1 裁決 2）。
//
// **永久 wire contract**：本鍵名與下方的編碼一旦出貨即不可改——改動等同既有委託
// 密文全不可解（EncryptionContext 逐位元參與 KMS 的認證加密）。故定為具名常數
// 並由 TestEncryptionContextWireContract 釘住。
const EncryptionContextAADKey = "aad"

// ErrAADRequired 委託 provider 於 len(aad)==0 時的 fail-close（D11.1 裁決 2）。
//
// **與本地 provider 的行為刻意相反**：介面註解的「aad 為 nil 時不綁定」是
// **本地語義**；委託格式在 EncodeWrappedKey（wrapped_key.go:95-98）上一律要求
// AAD，送出空 EncryptionContext 會產出無綁定的 KMS blob，且不應依賴 KMS 對空
// context 的接受行為。故委託側直接回錯。
var ErrAADRequired = errors.New("委託 KEK provider 不接受空 AAD：包裹與解包一律須帶 AAD 綁定")

// ErrKeyIDNotCanonical kek_id 非正規 KMS key ARN 形式（資料異常，fail-close）
var ErrKeyIDNotCanonical = errors.New("kek_id 非正規 KMS key ARN 形式")

// ErrKeyUnusable 組態指定的金鑰不合用（非對稱／錯 KeyUsage／狀態不可用）
var ErrKeyUnusable = errors.New("KMS 金鑰不合用於 KEK 包裹")

// ErrKeyOutsideTrustedAccount 目標金鑰所屬帳號不在部署宣告的信任範圍內
// （round-4 codex high #1）
var ErrKeyOutsideTrustedAccount = errors.New("KMS 目標金鑰不在信任帳號範圍內：拒絕重包")

// canaryAADPurpose 建構期／預檢用的往返探針 AAD purpose。
//
// **必須帶 AAD**：委託 provider 於 len(aad)==0 時回 ErrAADRequired，
// 無 AAD 的探針會撞上自己的 fail-close 而測不到任何東西。
const canaryAADPurpose = "kek-preflight"

// Provider AWS KMS 委託型 KEK provider（crypto.KEKProvider 實作）。
//
// **DEK 仍由本地 CSPRNG 生成（D11）**：本 provider 只做 Encrypt／Decrypt 包裹，
// SHALL NOT 改用 GenerateDataKey——那會使 DEK 生命週期與 A／B 分岔，
// provider 就不再真正可互換。
//
// ---
//
// **已知限制：多區域金鑰（MRK）不支援跨區 replica 切換（round-4 codex med #4）**
//
// MRK 的原生賣點是「primary 與 replica 共用金鑰材料，任一區皆可解另一區的密文」。
// 本版**不利用**該能力：落庫的 kek_id 是**含 region 的完整 key ARN**，而 primary
// 與 replica 的 ARN 只有 region 段不同（`arn:aws:kms:us-east-1:…:key/mrk-X` 與
// `arn:aws:kms:eu-west-1:…:key/mrk-X`）。代表列篩選是精確字串比對，故一旦把
// KEK_KMS_REGION 切到 replica，既有列全數失配而 fail-close。
//
// **實務後果**：對本系統而言，**切到 replica 等同換一把鑰，須走換鑰精靈重包**。
// MRK 可正常作為 KEK 使用（語法守衛認得 `mrk-<32 hex>`），只是拿不到「切區免重包」
// 這項好處。
//
// **為何本期不做**：要支援它得把「落庫的邏輯身分」與「本區的操作 ARN」拆成兩個
// 概念——kek_id 欄的語義、代表列篩選、D11.1 裁決 1 釘死的「不得改寫既有 kek_id」
// 三者都得重新定案。那是資料模型層級的改動，不該夾帶在一次安全修補裡。
// TestMultiRegionKeyIsRegionScopedIdentity 釘住此限制，使日後沒有人會**誤以為**
// 它已被支援（沒有那格測試，這段註解會在第一次有人試切區時才被發現是真的）。
type Provider struct {
	client API
	// keyARN 建構期經 DescribeKey 解析出的**正規 key ARN**；
	// 落 kek_id 的值恆為此形式（D11.1 裁決 1）
	keyARN string
	// arnParts keyARN 的解析結果（partition／region／account／key-id）
	arnParts KeyARNParts
	region   string
	// endpoint 端點覆寫（測試靶機）；參與 ReEncrypt 的同族判定
	endpoint string
}

// New 建構 KMS provider。
//
// **DescribeKey 於此（＝連 DB 之前）呼叫（D11.1 裁決 1）**：組態段 DB-independent
// 的立約要求任一 fail-close 路徑不產生 DB 寫入；把探測移到 DB 連線之後即破壞該
// 立約，且會讓「組態錯誤」在 migration／seed 之後才浮現。
//
// 五件事在此一次做完，缺一即拒啟動：
//  1. 把 alias／裸 key-id／ARN 三種輸入解析為**正規 key ARN**——這使
//     「把 KEK_KMS_KEY_ID 自 alias 改寫為 ARN」（無語義變更）不會使代表列篩選落空；
//  2. 驗金鑰**可用性**：對稱加密金鑰、KeyUsage=ENCRYPT_DECRYPT、狀態可用
//     ——不驗則會先寫 DB 才在解包時失敗；
//  3. 節流／逾時類錯誤有界重試，AccessDenied／NotFound 立即失敗；
//  4. 若呼叫端宣告了信任帳號範圍（Settings.Scope），驗解析出的 ARN 落在範圍內
//     ——**這是「請求指定的 key_ref 不得把材料重包到外部帳號」的承載機制**；
//  5. 跑一次不落庫的 Encrypt→Decrypt 往返（canary）。
//
// **為何 (5) 不能省（round-4 codex med #5）**：DescribeKey 只證明 metadata 合格，
// **不證明本角色有 Encrypt／Decrypt 權限**（IAM 可以只給 kms:DescribeKey），
// 也不證明 XKS 外部金鑰存放區可達。少了這一步，一個「驗證通過」的部署會在
// **首次真的要包裹金鑰時**才失敗——那時已經過了啟動關卡，錯誤面遠比啟動期難處理。
func New(ctx context.Context, s Settings) (*Provider, error) {
	if s.Provider != ProviderAWS {
		return nil, fmt.Errorf("KEK_KMS_PROVIDER=%q 尚未支援：本版僅實作 %q（GCP KMS／Azure Key Vault 留介面不實作）",
			s.Provider, ProviderAWS)
	}
	if s.KeyID == "" {
		return nil, errors.New("KEK_KMS_KEY_ID 為空：拒絕啟動")
	}
	if s.Region == "" {
		return nil, errors.New("KEK_KMS_REGION 為空：拒絕啟動")
	}

	// **信任帳號的前置比對**：輸入本身已是完整 ARN 時，帳號段在語法層就看得出來，
	// 不必等 DescribeKey 回來才判。提前拒絕有兩個實質好處：
	// (a) 對外部帳號的金鑰**一個 outbound 請求都不會發出**（探測行為本身也是資訊洩漏）；
	// (b) 錯誤直指「不在信任範圍」，而不是被下游的連線失敗蓋成「KMS 不可達」。
	// alias／裸 key-id 形式看不出帳號，仍由下方 DescribeKey 之後的比對承擔。
	if parts, ok := ParseKeyARN(s.KeyID); ok {
		if err := checkTrustedAccount(s.Scope, parts, s.KeyID); err != nil {
			return nil, err
		}
	}

	client := s.Client
	if client == nil {
		c, err := newAWSClient(ctx, s)
		if err != nil {
			return nil, err
		}
		client = c
	}

	keyID := s.KeyID
	out, err := retryDescribe(ctx, "DescribeKey", func(c context.Context) (*awskms.DescribeKeyOutput, error) {
		return client.DescribeKey(c, &awskms.DescribeKeyInput{KeyId: &keyID}, describeCallOptions()...)
	})
	if err != nil {
		// 權限清單完整化（D7／D11.1 裁決 5 的 opus L-c）：漏列 DescribeKey 會使
		// 「組態齊備但缺該權限」的部署得到誤導性錯誤
		return nil, fmt.Errorf("%w（所需 IAM action：kms:DescribeKey、kms:Encrypt、kms:Decrypt；"+
			"C1↔C1 換金鑰另需 kms:ReEncryptFrom 與 kms:ReEncryptTo）", err)
	}
	meta := out.KeyMetadata
	if meta == nil || meta.Arn == nil || *meta.Arn == "" {
		return nil, fmt.Errorf("%w：DescribeKey 未回傳金鑰 ARN（%s）", ErrKeyUnusable, keyID)
	}
	arn := *meta.Arn
	parts, ok := ParseKeyARN(arn)
	if !ok {
		return nil, fmt.Errorf("%w：DescribeKey 回傳的 ARN %q 不符 key ARN 語法", ErrKeyUnusable, arn)
	}
	if err := checkTrustedAccount(s.Scope, parts, s.KeyID); err != nil {
		return nil, err
	}
	if err := checkKeyUsable(meta); err != nil {
		return nil, err
	}

	p := &Provider{client: client, keyARN: arn, arnParts: parts, region: s.Region, endpoint: s.Endpoint}
	if err := p.canary(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

// describeCallOptions 建構期 DescribeKey 的**每次呼叫**選項（round-4 codex med #1）。
//
// 關掉 SDK 內層重試，使「總嘗試 3 次」是實際的 HTTP 請求數而非本層迴圈數
// （原本 3×3＝最多 9 個請求）。只作用於 DescribeKey：Encrypt／Decrypt 走執行期
// 路徑，SDK 重試對它們是淨益。
// 實測依據見 TestDescribeIssuesExactlyThreeHTTPRequests（真 SDK ＋ httptest 計數）。
func describeCallOptions() []func(*awskms.Options) {
	return []func(*awskms.Options){func(o *awskms.Options) { o.RetryMaxAttempts = 1 }}
}

// checkTrustedAccount 目標金鑰所屬帳號／partition 是否落在部署宣告的信任範圍內。
//
// **未宣告範圍時不檢查**：啟動期建構的目標就是 KEK_KMS_* 組態自身，拿組態去驗
// 組態沒有意義。檢查只施加於「請求可指定目標」的委託重包路徑（見 AccountScope）。
func checkTrustedAccount(scope AccountScope, parts KeyARNParts, input string) error {
	if !scope.declared() || scope.permits(parts) {
		return nil
	}
	return fmt.Errorf("%w：目標帳號 %s（partition %s）不在信任範圍 %s 內。"+
		"輸入 %q 解析為 %s——即使該金鑰的 key policy 放行，把 DEK 材料重包進外部帳號"+
		"也會使本部署的金鑰材料落入不受本組態控制的信任域。"+
		"若確要重包至該帳號，請先把 %s 指向該帳號的金鑰",
		ErrKeyOutsideTrustedAccount, parts.Account, parts.Partition, scope,
		input, parts.Partition+":"+parts.Account, trustAnchorEnvKeyName)
}

// trustAnchorEnvKeyName 信任範圍的組態來源鍵名。
//
// **以字面而非引用 config.EnvKeyKMSKeyID**：pkg/crypto/kms 是 pkg 層，
// 引入 config 會造成 pkg → config 的反向相依（config 已相依 pkg/crypto）。
// 兩處字面由 TestTrustAnchorEnvKeyMatchesConfig（cmd/server）比對釘住。
const trustAnchorEnvKeyName = "KEK_KMS_KEY_ID"

// checkKeyUsable 建構期金鑰可用性驗證（D11.1 裁決 1「金鑰可用性」）。
//
// 三項逐一列出而非合併回一句：操作者要能直接看出是「用錯金鑰種類」還是
// 「金鑰被停用」，兩者的處置完全不同。
//
// **本函式只看 metadata，不證明可用（codex med #5）**：Enabled＋
// SYMMETRIC_DEFAULT＋ENCRYPT_DECRYPT 三者全過，仍可能缺 kms:Encrypt 權限或
// XKS 存放區不可達。實際可用性由 canary 承擔。
func checkKeyUsable(meta *types.KeyMetadata) error {
	if meta.KeySpec != types.KeySpecSymmetricDefault {
		return fmt.Errorf("%w：KeySpec=%s（須為 %s——非對稱金鑰無法作為 KEK 包裹 DEK）",
			ErrKeyUnusable, meta.KeySpec, types.KeySpecSymmetricDefault)
	}
	if meta.KeyUsage != types.KeyUsageTypeEncryptDecrypt {
		return fmt.Errorf("%w：KeyUsage=%s（須為 %s）",
			ErrKeyUnusable, meta.KeyUsage, types.KeyUsageTypeEncryptDecrypt)
	}
	if meta.KeyState != types.KeyStateEnabled {
		return fmt.Errorf("%w：KeyState=%s（須為 %s）",
			ErrKeyUnusable, meta.KeyState, types.KeyStateEnabled)
	}
	if !meta.Enabled {
		return fmt.Errorf("%w：金鑰已停用（Enabled=false）", ErrKeyUnusable)
	}
	return nil
}

// encryptionContext 把 DEK 層 AAD 映射為 KMS EncryptionContext（D11.1 裁決 2）。
//
// **單鍵不透明映射，SHALL NOT 反解 AAD 內部結構**：語義多鍵
// （{"purpose":…,"version":…}）要求本 provider 反解 crypto.DEKAAD 的 canonical
// 編碼，使 provider 與該編碼**永久耦合**——日後 AAD 組成一改 provider 就得跟著改，
// 且兩處對「canonical」的理解可能漂移。單鍵映射下 provider 對 AAD 內容完全不可知。
//
// **稽核力的取捨（刻意，非無損）**：CloudTrail 仍可見該值且具確定性，
// 但稽核者須本地重算才知對應哪個 purpose/version——稽核力由「可直讀」轉為
// 「可比對」，runbook 須提供重算指令。
func encryptionContext(aad []byte) (map[string]string, error) {
	if len(aad) == 0 {
		return nil, ErrAADRequired
	}
	return map[string]string{EncryptionContextAADKey: base64.StdEncoding.EncodeToString(aad)}, nil
}

// Wrap 以 KMS Encrypt 包裹金鑰材料。
//
// **KeyId 顯式傳入**：Encrypt 本就必填，此處與 Decrypt 的顯式傳入形成對稱。
func (p *Provider) Wrap(ctx context.Context, plaintext, aad []byte) ([]byte, error) {
	ec, err := encryptionContext(aad)
	if err != nil {
		return nil, err
	}
	out, err := p.client.Encrypt(ctx, &awskms.EncryptInput{
		KeyId:             &p.keyARN,
		Plaintext:         plaintext,
		EncryptionContext: ec,
	})
	if err != nil {
		return nil, fmt.Errorf("KMS Encrypt 失敗（金鑰 %s）: %w", p.keyARN, err)
	}
	if len(out.CiphertextBlob) == 0 {
		return nil, fmt.Errorf("KMS Encrypt 回傳空密文（金鑰 %s）", p.keyARN)
	}
	return out.CiphertextBlob, nil
}

// Unwrap 以 KMS Decrypt 解包。
//
// **KeyId SHALL 顯式傳入（D11 MED-1）**：AWS KMS 對對稱金鑰的 Decrypt **不要求**
// 指定 KeyId（密文自帶金鑰識別），故只要本服務的角色對某把舊金鑰仍有 Decrypt
// 權限，一個以**其他金鑰**包裹的 blob 配上被竄改的 kek_id 欄仍會解包成功。
// 顯式帶 KeyId 使 KMS 端強制驗證「此密文確由該金鑰產生」——這是委託模式下
// 「blob 綁定於被組態指定的那把金鑰」的**唯一**承載機制。
func (p *Provider) Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error) {
	ec, err := encryptionContext(aad)
	if err != nil {
		return nil, err
	}
	out, err := p.client.Decrypt(ctx, &awskms.DecryptInput{
		CiphertextBlob:    wrapped,
		KeyId:             &p.keyARN,
		EncryptionContext: ec,
	})
	if err != nil {
		return nil, fmt.Errorf("KMS Decrypt 失敗（金鑰 %s）: %w", p.keyARN, err)
	}
	return out.Plaintext, nil
}

// KeyRef 金鑰引用；KeyID 恆為正規 key ARN（建構期已解析）。
//
// **含 region 段**：見 Provider 型別註解的「MRK 已知限制」——replica 的 ARN
// 與 primary 不同，故切區等同換鑰。
func (p *Provider) KeyRef() crypto.KeyRef {
	return crypto.KeyRef{Provider: crypto.KeyRefProviderKMS, KeyID: p.keyARN}
}

// Mode 執行期模式（D10 雙軌互證的清冊來源）
func (p *Provider) Mode() string { return crypto.KEKModeKMS }

// FormatTag 委託格式標記
func (p *Provider) FormatTag() string { return crypto.WrappedFormatKMS }

// Region 本 provider 綁定的 AWS 區域（清冊／診斷用，非機密）
func (p *Provider) Region() string { return p.region }

// Account 本 provider 金鑰所屬的 AWS 帳號（清冊／診斷用，非機密）
func (p *Provider) Account() string { return p.arnParts.Account }

// sameFamily 來源是否為可走原生 ReEncrypt 的同族 provider。
//
// 同族＝同一套 EncryptionContext 映射（同套件型別即保證）＋同 region ＋同端點。
// 端點納入比較的理由：測試靶機與真 KMS 是兩個不相干的金鑰域，區域字串可能相同
// 但金鑰不互通，原生 ReEncrypt 必失敗。
func (p *Provider) sameFamily(o *Provider) bool {
	return o != nil && o.region == p.region && o.endpoint == p.endpoint
}

// ReEncrypt 由舊 wrapped 直接產出本 provider 的 wrapped。
//
// **分派（D11.1 裁決 5(a)）**：AWS ReEncrypt 的來源**必須是 KMS 密文**。
// P3 的主場景（tasks 3.3 的 A/B→C）來源是本地 AES-GCM blob，照「原生」字面
// 實作主路徑執行期即 InvalidCiphertextException。故僅在 from 為同族 KMS
// provider 時走原生，否則一律回落 crypto.DefaultReEncrypt（unwrap→wrap）。
// **A/B→C 走的是回落分支**；原生路徑服務的是 C1↔C1 換金鑰場景。
//
// **四項顯式參數（D11.1 裁決 5(b)），缺一即實作缺陷**：
//   - SourceKeyId：原生 ReEncrypt 同樣會解密，省略即讓 MED-1 漏洞原樣重現；
//   - DestinationKeyId：目標金鑰；
//   - SourceEncryptionContext：來源 blob 的 AAD 綁定；
//   - DestinationEncryptionContext：**省略不會沿用 source context 而是變成空
//     context**，之後帶 AAD 的 Decrypt 必敗。
func (p *Provider) ReEncrypt(ctx context.Context, wrapped, aad []byte, from crypto.KEKProvider) ([]byte, error) {
	src, ok := from.(*Provider)
	if !ok || !p.sameFamily(src) {
		return crypto.DefaultReEncrypt(ctx, p, wrapped, aad, from)
	}
	ec, err := encryptionContext(aad)
	if err != nil {
		return nil, err
	}
	out, err := p.client.ReEncrypt(ctx, &awskms.ReEncryptInput{
		CiphertextBlob:               wrapped,
		SourceKeyId:                  &src.keyARN,
		DestinationKeyId:             &p.keyARN,
		SourceEncryptionContext:      ec,
		DestinationEncryptionContext: ec,
	})
	if err != nil {
		return nil, fmt.Errorf("KMS ReEncrypt 失敗（%s → %s）: %w", src.keyARN, p.keyARN, err)
	}
	if len(out.CiphertextBlob) == 0 {
		return nil, fmt.Errorf("KMS ReEncrypt 回傳空密文（%s → %s）", src.keyARN, p.keyARN)
	}
	return out.CiphertextBlob, nil
}

// Preflight 連通性與權限預檢（D7 的 C 模式重包前置）。
//
// **與 New 的 canary 同一件事**：New 已於建構期跑過一次，故正常路徑上呼叫端
// 不需要再呼叫本方法。保留為公開方法的理由是「在任意時點重驗一次」仍是合理需求
// （例如長時間持有的 provider 於重包前想確認權限未被撤銷）。
func (p *Provider) Preflight(ctx context.Context) error { return p.canary(ctx) }

// canary 一次**不落庫**的真實 Encrypt→Decrypt 往返（round-4 codex med #5）。
//
// 以實際往返驗證 Encrypt／Decrypt 權限與 EncryptionContext 行為——比逐一查
// IAM policy 誠實：實際能不能用，只有打過一次才知道。這同時涵蓋 XKS
// （外部金鑰存放區）可達性，那是 DescribeKey 完全看不到的失敗面。
//
// 探針為固定長度的零值材料，**不是任何金鑰**：它不落庫、不進日誌，
// 只在本函式的生命週期內存在。**必須帶 AAD**，否則會撞上自身的
// len(aad)==0 fail-close（ErrAADRequired）而什麼都沒驗到。
func (p *Provider) canary(ctx context.Context) error {
	probe := make([]byte, 32)
	aad := crypto.DEKAAD(canaryAADPurpose, 0)
	wrapped, err := p.Wrap(ctx, probe, aad)
	if err != nil {
		return fmt.Errorf("連通性預檢失敗（kms:Encrypt，金鑰 %s——DescribeKey 通過不代表有加密權限）: %w",
			p.keyARN, err)
	}
	got, err := p.Unwrap(ctx, wrapped, aad)
	if err != nil {
		return fmt.Errorf("連通性預檢失敗（kms:Decrypt，金鑰 %s）: %w", p.keyARN, err)
	}
	if subtle.ConstantTimeCompare(got, probe) != 1 {
		return fmt.Errorf("連通性預檢失敗：往返材料不符（金鑰 %s）", p.keyARN)
	}
	return nil
}
