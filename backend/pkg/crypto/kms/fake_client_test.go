package kms

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
)

// fakeKMS 捕獲請求的假 KMS 客戶端（雙軌驗收之 (a)）。
//
// **存在理由**：「每次 Decrypt／ReEncrypt 入參恆帶 KeyId 與 EncryptionContext」
// 這條斷言的價值在於**不依賴模擬器保真度**——localstack 是否真的強制比對，
// 我們無法保證；但「我們送出去的請求長什麼樣」是可以確定性斷言的。
//
// 密文格式刻意模仿 KMS 的**綁定行為**（金鑰 ARN 與 EncryptionContext 皆參與），
// 使「他金鑰 blob」「錯 AAD」在本地也會被拒——不是為了取代 localstack 的語義驗證，
// 而是讓服務層的測試不必連外。
type fakeKMS struct {
	mu sync.Mutex

	// keys 可用金鑰：查詢鍵為 alias／裸 key-id／ARN，值為該金鑰的中繼資料
	keys map[string]*types.KeyMetadata

	// 捕獲的入參（斷言對象）
	encryptCalls   []*awskms.EncryptInput
	decryptCalls   []*awskms.DecryptInput
	reEncryptCalls []*awskms.ReEncryptInput
	describeCalls  []*awskms.DescribeKeyInput

	// describeErrs 依序回傳的 DescribeKey 錯誤（用盡後改回正常）；供重試分流測試
	describeErrs []error
	// encryptErr／decryptErr 恆定的加解密錯誤（非 nil 即每次都回）。
	// 用途：模擬「DescribeKey 過得去、但 IAM 沒給 kms:Encrypt／kms:Decrypt」
	// ——正是安全審查 med #5 指出的、metadata 檢查看不見的失敗面。
	encryptErr error
	decryptErr error
}

func newFakeKMS() *fakeKMS {
	return &fakeKMS{keys: map[string]*types.KeyMetadata{}}
}

// resetCryptoCalls 清空加解密類的捕獲紀錄（**不動 describeCalls**）。
//
// 用途單一：New 於建構期跑 canary 往返（各一次 Encrypt／Decrypt），
// 而各測試斷言的是自己觸發的次數。describeCalls 保留，因為重試分流測試要數它。
func (f *fakeKMS) resetCryptoCalls() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.encryptCalls = nil
	f.decryptCalls = nil
	f.reEncryptCalls = nil
}

// addKey 登記一把可用的對稱加密金鑰，並同時以 alias／裸 key-id／ARN 三種形式可查
func (f *fakeKMS) addKey(alias, keyID, arn string) *types.KeyMetadata {
	meta := &types.KeyMetadata{
		Arn:      &arn,
		KeyId:    &keyID,
		KeySpec:  types.KeySpecSymmetricDefault,
		KeyUsage: types.KeyUsageTypeEncryptDecrypt,
		KeyState: types.KeyStateEnabled,
		Enabled:  true,
	}
	f.keys[alias] = meta
	f.keys[keyID] = meta
	f.keys[arn] = meta
	return meta
}

func (f *fakeKMS) DescribeKey(_ context.Context, in *awskms.DescribeKeyInput, _ ...func(*awskms.Options)) (*awskms.DescribeKeyOutput, error) {
	f.mu.Lock()
	f.describeCalls = append(f.describeCalls, in)
	if len(f.describeErrs) > 0 {
		err := f.describeErrs[0]
		f.describeErrs = f.describeErrs[1:]
		f.mu.Unlock()
		return nil, err
	}
	f.mu.Unlock()
	if in.KeyId == nil {
		return nil, &smithy.GenericAPIError{Code: "InvalidArnException", Message: "缺 KeyId"}
	}
	meta, ok := f.keys[*in.KeyId]
	if !ok {
		return nil, &types.NotFoundException{Message: strptr("金鑰不存在")}
	}
	return &awskms.DescribeKeyOutput{KeyMetadata: meta}, nil
}

// 假密文格式：`fake|<keyARN>|<base64(aad)>|<base64(plaintext)>`。
// 金鑰 ARN 與 EncryptionContext 皆參與，解密時逐項比對——模仿 KMS 的綁定語義。
const fakeBlobPrefix = "fake|"

func (f *fakeKMS) Encrypt(_ context.Context, in *awskms.EncryptInput, _ ...func(*awskms.Options)) (*awskms.EncryptOutput, error) {
	f.mu.Lock()
	f.encryptCalls = append(f.encryptCalls, in)
	injected := f.encryptErr
	f.mu.Unlock()
	if injected != nil {
		return nil, injected
	}
	if in.KeyId == nil || *in.KeyId == "" {
		return nil, errors.New("fake: Encrypt 未帶 KeyId")
	}
	meta, ok := f.keys[*in.KeyId]
	if !ok {
		return nil, &types.NotFoundException{Message: strptr("金鑰不存在")}
	}
	blob := fmt.Sprintf("%s%s|%s|%s", fakeBlobPrefix, *meta.Arn,
		encodeContext(in.EncryptionContext), base64.StdEncoding.EncodeToString(in.Plaintext))
	return &awskms.EncryptOutput{CiphertextBlob: []byte(blob), KeyId: meta.Arn}, nil
}

func (f *fakeKMS) Decrypt(_ context.Context, in *awskms.DecryptInput, _ ...func(*awskms.Options)) (*awskms.DecryptOutput, error) {
	f.mu.Lock()
	f.decryptCalls = append(f.decryptCalls, in)
	injected := f.decryptErr
	f.mu.Unlock()
	if injected != nil {
		return nil, injected
	}
	arn, ctxEnc, plaintext, err := parseFakeBlob(in.CiphertextBlob)
	if err != nil {
		return nil, err
	}
	// 顯式 KeyId 比對（跨金鑰解包防線的承載機制）：未帶或不符一律拒
	if in.KeyId == nil || *in.KeyId == "" {
		return nil, &smithy.GenericAPIError{Code: "InvalidCiphertextException", Message: "fake: Decrypt 未帶 KeyId"}
	}
	meta, ok := f.keys[*in.KeyId]
	if !ok || *meta.Arn != arn {
		return nil, &smithy.GenericAPIError{Code: "IncorrectKeyException", Message: "fake: 密文非由該金鑰產生"}
	}
	if encodeContext(in.EncryptionContext) != ctxEnc {
		return nil, &smithy.GenericAPIError{Code: "InvalidCiphertextException", Message: "fake: EncryptionContext 不符"}
	}
	return &awskms.DecryptOutput{Plaintext: plaintext, KeyId: meta.Arn}, nil
}

func (f *fakeKMS) ReEncrypt(_ context.Context, in *awskms.ReEncryptInput, _ ...func(*awskms.Options)) (*awskms.ReEncryptOutput, error) {
	f.mu.Lock()
	f.reEncryptCalls = append(f.reEncryptCalls, in)
	f.mu.Unlock()
	arn, ctxEnc, plaintext, err := parseFakeBlob(in.CiphertextBlob)
	if err != nil {
		return nil, err
	}
	if in.SourceKeyId == nil || *in.SourceKeyId == "" {
		return nil, &smithy.GenericAPIError{Code: "InvalidCiphertextException", Message: "fake: 未帶 SourceKeyId"}
	}
	srcMeta, ok := f.keys[*in.SourceKeyId]
	if !ok || *srcMeta.Arn != arn {
		return nil, &smithy.GenericAPIError{Code: "IncorrectKeyException", Message: "fake: 密文非由來源金鑰產生"}
	}
	if encodeContext(in.SourceEncryptionContext) != ctxEnc {
		return nil, &smithy.GenericAPIError{Code: "InvalidCiphertextException", Message: "fake: SourceEncryptionContext 不符"}
	}
	if in.DestinationKeyId == nil || *in.DestinationKeyId == "" {
		return nil, &smithy.GenericAPIError{Code: "InvalidArnException", Message: "fake: 未帶 DestinationKeyId"}
	}
	dstMeta, ok := f.keys[*in.DestinationKeyId]
	if !ok {
		return nil, &types.NotFoundException{Message: strptr("目標金鑰不存在")}
	}
	blob := fmt.Sprintf("%s%s|%s|%s", fakeBlobPrefix, *dstMeta.Arn,
		encodeContext(in.DestinationEncryptionContext), base64.StdEncoding.EncodeToString(plaintext))
	return &awskms.ReEncryptOutput{CiphertextBlob: []byte(blob), KeyId: dstMeta.Arn}, nil
}

// encodeContext 把 EncryptionContext 攤平為可比對字串。
// 空 map 與 nil 一律得 ""——正是「送出空 context」該被看見的樣子。
func encodeContext(ec map[string]string) string {
	if len(ec) == 0 {
		return ""
	}
	// 本產品只送單鍵，故不需排序；多鍵時直接拒絕（守衛：SHALL NOT 反解為語義多鍵）
	if len(ec) != 1 {
		return "MULTI_KEY_CONTEXT"
	}
	for k, v := range ec {
		return k + "=" + v
	}
	return ""
}

func parseFakeBlob(blob []byte) (arn, ctxEnc string, plaintext []byte, err error) {
	if !bytes.HasPrefix(blob, []byte(fakeBlobPrefix)) {
		return "", "", nil, &smithy.GenericAPIError{Code: "InvalidCiphertextException", Message: "fake: 非 KMS 密文"}
	}
	parts := bytes.SplitN(blob[len(fakeBlobPrefix):], []byte("|"), 3)
	if len(parts) != 3 {
		return "", "", nil, &smithy.GenericAPIError{Code: "InvalidCiphertextException", Message: "fake: 密文損毀"}
	}
	raw, derr := base64.StdEncoding.DecodeString(string(parts[2]))
	if derr != nil {
		return "", "", nil, &smithy.GenericAPIError{Code: "InvalidCiphertextException", Message: "fake: 密文損毀"}
	}
	return string(parts[0]), string(parts[1]), raw, nil
}

func strptr(s string) *string { return &s }
