package kms

import (
	"context"
	"errors"
	"fmt"
	"os"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
)

// ProviderAWS KEK_KMS_PROVIDER 目前唯一支援值。
// GCP KMS／Azure Key Vault 留介面不實作、誠實記載（D11）。
const ProviderAWS = "aws"

// API 本套件使用到的 KMS 操作面（**只列真的會呼叫的四個**）。
//
// **為何抽介面**：D11.1 裁決 4 的雙軌驗收要求「以 fake client 捕獲請求，斷言
// 每次 Decrypt／ReEncrypt 入參恆帶 KeyId 與 EncryptionContext」——該斷言的價值
// 在於**不依賴模擬器保真度**，故必須能在不連任何服務的情況下取得真實入參。
type API interface {
	Encrypt(ctx context.Context, params *awskms.EncryptInput, optFns ...func(*awskms.Options)) (*awskms.EncryptOutput, error)
	Decrypt(ctx context.Context, params *awskms.DecryptInput, optFns ...func(*awskms.Options)) (*awskms.DecryptOutput, error)
	ReEncrypt(ctx context.Context, params *awskms.ReEncryptInput, optFns ...func(*awskms.Options)) (*awskms.ReEncryptOutput, error)
	DescribeKey(ctx context.Context, params *awskms.DescribeKeyInput, optFns ...func(*awskms.Options)) (*awskms.DescribeKeyOutput, error)
}

// Settings 建構 KMS provider 所需的組態（由 config.KMSSettings 轉入）。
type Settings struct {
	// Provider 委託服務商，目前僅 aws
	Provider string
	// KeyID 組態輸入形式：alias／裸 key-id／完整 ARN 三者皆可，
	// 建構期一律經 DescribeKey 正規化為 key ARN（D11.1 裁決 1）
	KeyID string
	// Region AWS 區域
	Region string
	// Endpoint 選用的端點覆寫；**僅供測試靶機（localstack）**，
	// 生產部署不設此值。空字串＝走 SDK 預設端點解析。
	//
	// **本欄位受結構守衛保護**：TestNoProductionEndpointOverride（endpoint_gate_test.go）
	// 以 AST 斷言全 backend 的非測試碼中沒有任何一處設定本欄位——
	// 「只有測試碼設得到它」是一個可被檢查的事實，不是一句註解上的期望。
	Endpoint string
	// Client 選用的注入客戶端（fake／預建）；為 nil 時依上列組態建構官方 SDK 客戶端
	Client API
	// Scope 目標金鑰的**信任帳號範圍**；零值＝不檢查（見 AccountScope）
	Scope AccountScope
}

// ErrEndpointOverride 生產路徑偵測到端點覆寫（round-4 codex high #2）
var ErrEndpointOverride = errors.New("KMS 端點覆寫遭拒：生產路徑不接受任何端點改導")

// endpointOverrideEnvKeys AWS SDK v2 自身解析的端點覆寫環境變數。
//
// **這是 SDK 契約而非本產品組態鍵**，故不入 .env.example、不進 env 漂移守衛的
// 必要鍵集——但**正因為它不是本產品的旋鈕，才更需要在生產路徑上被明確拒絕**：
// 部署者可能為了別的 AWS 服務而全域設了 AWS_ENDPOINT_URL，卻不知道它同時把
// KMS 也改導了。
var endpointOverrideEnvKeys = []string{"AWS_ENDPOINT_URL_KMS", "AWS_ENDPOINT_URL"}

// newAWSClient 依 Settings 建構官方 SDK v2 的 KMS 客戶端。
//
// **憑證來源不自建（D11）**：走 SDK 預設鏈（IRSA／instance profile／AWS_* env／
// SSO），產品不代管雲端憑證、也不新增自家 secret 存放。
//
// **端點覆寫在生產路徑一律 fail-close（round-4 codex high #2）**：
// 先前的註解宣稱「生產路徑（Endpoint 為空）完全不經此分支」——該說法**只對本檔的
// 程式分支成立，對 SDK 自身的 env 解析不成立**。實測（aws-sdk-go-v2 config
// v1.32.34 / kms v1.55.3）：`AWS_ENDPOINT_URL_KMS` 會被 `awskms.NewFromConfig`
// 解析進 `client.Options().BaseEndpoint`，而 Wrap 送出的 `Encrypt` 請求**內含
// 明文 DEK**——一個 env 變數就能把明文材料導向任意主機，甚至走 HTTP 明文。
// 故生產路徑做兩道檢查：
//
//  1. 環境變數面：上列任一鍵有值即拒，並指名是哪一個（可操作的錯誤訊息）；
//  2. 解析結果面：客戶端最終的 BaseEndpoint 須為空（涵蓋共用組態檔的
//     `endpoint_url =` 等本檔沒有列舉到的覆寫管道），且預設解析出的端點須為 https。
//
// 第 2 道是「不列舉來源、只看結果」的檢查，故它擋得住我們沒想到的覆寫管道——
// 這正是第 1 道單獨不足的地方。
//
// **Endpoint 覆寫的靜態憑證是測試靶機專用**：localstack 不驗簽章但 SDK 仍要求
// 憑證鏈可解析，且 CI 上不存在預設鏈可用的憑證；於是僅在顯式設定 Endpoint 時
// 補一組佔位憑證。
func newAWSClient(ctx context.Context, s Settings) (API, error) {
	testHarness := s.Endpoint != ""
	if !testHarness {
		if err := rejectEnvEndpointOverride(); err != nil {
			return nil, err
		}
	}

	opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(s.Region)}
	if testHarness {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider("test", "test", "")))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("載入 AWS 組態失敗（region %s）: %w", s.Region, err)
	}
	client := awskms.NewFromConfig(cfg, func(o *awskms.Options) {
		if testHarness {
			o.BaseEndpoint = &s.Endpoint
		}
	})
	if !testHarness {
		if err := verifyResolvedEndpoint(ctx, client, s.Region); err != nil {
			return nil, err
		}
	}
	return client, nil
}

// rejectEnvEndpointOverride 生產路徑的環境變數面檢查
func rejectEnvEndpointOverride() error {
	for _, key := range endpointOverrideEnvKeys {
		if v, ok := os.LookupEnv(key); ok && v != "" {
			return fmt.Errorf("%w：偵測到 %s=%q。該變數由 AWS SDK 直接解析，會把**含明文 DEK 的 "+
				"kms:Encrypt 請求**導向該位址（可為 HTTP 明文）。要接測試靶機請以程式注入 "+
				"Settings.Endpoint，不要用環境變數改導生產行程",
				ErrEndpointOverride, key, v)
		}
	}
	return nil
}

// verifyResolvedEndpoint 生產路徑的解析結果面檢查（不列舉來源，只看結果）
func verifyResolvedEndpoint(ctx context.Context, client *awskms.Client, region string) error {
	if be := client.Options().BaseEndpoint; be != nil && *be != "" {
		return fmt.Errorf("%w：SDK 最終解析出的端點為 %q（非預設 KMS 端點）。"+
			"除環境變數外，共用組態檔（~/.aws/config）的 endpoint_url 亦會造成此結果；"+
			"請移除該設定後再啟動", ErrEndpointOverride, *be)
	}
	resolved, err := awskms.NewDefaultEndpointResolverV2().ResolveEndpoint(ctx,
		awskms.EndpointParameters{Region: &region})
	if err != nil {
		return fmt.Errorf("%w：無法解析 region %s 的預設 KMS 端點: %v", ErrKMSUnavailable, region, err)
	}
	return requireHTTPSEndpoint(resolved.URI.Scheme, resolved.URI.String())
}

// requireHTTPSEndpoint 端點傳輸層檢查：明文 DEK 不得走 HTTP。
//
// **抽成獨立函式是為了可測**：真實 region 的預設解析器恆回 https，
// 沿呼叫鏈根本構造不出 http 的情形——沒有這個接縫，這條規則就只是一段
// 永遠不會被執行的程式碼（守衛假綠的另一種形態）。
func requireHTTPSEndpoint(scheme, uri string) error {
	if scheme == "https" {
		return nil
	}
	return fmt.Errorf("%w：解析出的端點 %s 非 https（scheme=%q）。"+
		"委託包裹請求（kms:Encrypt）內含明文 DEK，SHALL NOT 走明文傳輸",
		ErrEndpointOverride, uri, scheme)
}
