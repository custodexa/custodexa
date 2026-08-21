package kms

import (
	"context"
	"fmt"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
)

// ResolveAccountScope 由**部署組態**（KEK_KMS_KEY_ID）推導信任帳號範圍
// （round-4 codex high #1）。
//
// **為何信任範圍的來源是組態而非請求**：委託重包精靈的請求體只帶 `key_ref`。
// 裁決 6 讓 region／provider 沿用本行程組態，目的是「不讓單次請求把材料重包到
// 任意雲端帳號」——但 region 沿用擋不住**同 region 的其他 AWS 帳號**：完整 ARN
// 可以指定任何帳號，只要對方 key policy／grant 放行就會成功，而材料自此落入
// 不受本部署組態控制的信任域。組態宣告的那把鑰所屬的帳號，就是這個部署已經
// 表態信任的帳號；除此之外沒有任何來源有資格擴張這個範圍。
//
// 兩條路徑，**同一個結論**：
//   - KEK_KMS_KEY_ID 已是完整 ARN → 直接解析，零 KMS 呼叫；
//   - 是 alias 或裸 key-id → 以 DescribeKey 正規化後取其帳號段（一次呼叫）。
//
// 後者刻意**不建構整個 Provider**：那會連帶跑金鑰可用性檢查與 canary（共三次
// KMS 呼叫），而此處只需要「這把鑰屬於哪個帳號」這一個事實。
func ResolveAccountScope(ctx context.Context, s Settings) (AccountScope, error) {
	if s.Provider != ProviderAWS {
		return AccountScope{}, fmt.Errorf("KEK_KMS_PROVIDER=%q 尚未支援：無法推導信任帳號範圍", s.Provider)
	}
	if s.KeyID == "" {
		return AccountScope{}, fmt.Errorf("%s 未設定：無法推導信任帳號範圍。"+
			"委託重包必須先由部署組態宣告它信任哪個 KMS 帳號，否則請求可指定任意帳號的金鑰",
			trustAnchorEnvKeyName)
	}
	if parts, ok := ParseKeyARN(s.KeyID); ok {
		return AccountScope{Partition: parts.Partition, Account: parts.Account}, nil
	}
	if s.Region == "" {
		return AccountScope{}, fmt.Errorf("KEK_KMS_REGION 為空：無法以 DescribeKey 正規化 %s", trustAnchorEnvKeyName)
	}

	client := s.Client
	if client == nil {
		c, err := newAWSClient(ctx, s)
		if err != nil {
			return AccountScope{}, err
		}
		client = c
	}
	keyID := s.KeyID
	out, err := retryDescribe(ctx, "DescribeKey（信任帳號範圍推導）", func(c context.Context) (*awskms.DescribeKeyOutput, error) {
		return client.DescribeKey(c, &awskms.DescribeKeyInput{KeyId: &keyID}, describeCallOptions()...)
	})
	if err != nil {
		return AccountScope{}, fmt.Errorf("無法由 %s=%q 推導信任帳號範圍: %w", trustAnchorEnvKeyName, keyID, err)
	}
	if out.KeyMetadata == nil || out.KeyMetadata.Arn == nil {
		return AccountScope{}, fmt.Errorf("%w：DescribeKey 未回傳金鑰 ARN（%s=%q）",
			ErrKeyUnusable, trustAnchorEnvKeyName, keyID)
	}
	parts, ok := ParseKeyARN(*out.KeyMetadata.Arn)
	if !ok {
		return AccountScope{}, fmt.Errorf("%w：%s 解析出的 ARN %q 不符 key ARN 語法",
			ErrKeyUnusable, trustAnchorEnvKeyName, *out.KeyMetadata.Arn)
	}
	return AccountScope{Partition: parts.Partition, Account: parts.Account}, nil
}
