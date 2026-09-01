package offsite

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"
)

// GCSParams gcs driver 的建構參數（factory 形狀，同 S3Params 的定位）。
// 全部值由組裝根自 config 帶入，本包不讀 env。
type GCSParams struct {
	// Bucket 現行 bucket
	Bucket string
	// CredentialsJSON service account JSON 的**內容**（設定全 UI 化後的現行來源：
	// 密文存於 offsite_profiles.credentials_enc，解密後直接交給建構函式）。
	// **不落磁碟**：明文只存在受控的程序記憶體生命期內（憑證記憶體語義）。
	// 空＝改看 CredentialsFile，兩者皆空＝ADC 鏈。
	// 與 CredentialsFile 同時非空時以本欄優先（DB 是執行期的事實源，env 只 seed 一次）。
	CredentialsJSON string
	// CredentialsFile service account JSON **檔路徑**。
	// 初次 seed 的來源（OFFSITE_GCS_CREDENTIALS_FILE）與測試靶機用；
	// 空＝Application Default Credentials 鏈
	CredentialsFile string
	// Endpoint 自訂端點（模擬器／私有連接點）；空＝正式 GCS
	Endpoint string
}

// gcsDefaultJSONEndpoint 正式 GCS 的 JSON API 端點。
//
// **端點鍵為空時仍顯式釘住本值**：cloud.google.com/go/storage 會讀全域
// `STORAGE_EMULATOR_HOST` 並把它注入為 default endpoint（http_client.go），
// 而 default 只在使用者未給 option.WithEndpoint 時生效——一律顯式給端點，
// 全域環境變數就改導不了本功能（不讀全域，與 s3 側不讀
// AWS_ENDPOINT_URL 同一紀律）。
const gcsDefaultJSONEndpoint = "https://storage.googleapis.com/storage/v1/"

// gcsBuildParams gcs client 的最終建構參數（純函式產物，供
// TestGCSClientIgnoresGlobalEnv 逐格斷言——全域 env 不得出現在任何欄位）。
type gcsBuildParams struct {
	// Endpoint 實際交給 option.WithEndpoint 的值（恆非空：顯式釘住）
	Endpoint string
	// CredentialsJSON 實際交給 option.WithCredentialsJSON 的內容；空＝不注入。
	// 與 CredentialsFile 互斥（本欄非空時取本欄）
	CredentialsJSON string
	// CredentialsFile 實際交給 option.WithCredentialsFile 的值；空＝走 ADC 鏈、
	// 不注入 credentials 選項
	CredentialsFile string
	// NoAuth true＝注入 option.WithoutAuthentication（測試靶機通道，見
	// resolveGCSBuildParams 的判準說明）
	NoAuth bool
}

// resolveGCSBuildParams 由 GCSParams 推導最終建構參數。
//
// **純函式、只看入參**：本功能的設定來源只有 OFFSITE_GCS_* 鍵（經組裝根帶入），
// 全域 `GOOGLE_APPLICATION_CREDENTIALS`／`STORAGE_EMULATOR_HOST` 不在入參之列，
// 故不可能被採用——這正是 TestGCSClientIgnoresGlobalEnv 釘住的形狀。
// （憑證檔鍵為空時 SDK 走 ADC 鏈；ADC 鏈自身的解析順序屬 SDK 契約，
// 本功能不攔截、也不把它當成自己的設定鍵。）
//
// **NoAuth 的判準（沿 pkg/crypto/kms 測試靶機先例）**：顯式 http 端點＋
// 無憑證檔＝模擬器靶機（fake-gcs-server 不驗認證，而 SDK 無憑證時建構即失敗）。
// 正式 GCS 與私有連接點皆為 https，不會落入本格；顯式寫下 http 位址本身
// 就是非生產靶機的顯式訊號（與 refresh cookie 對 http:// 的解讀同一慣例）。
func resolveGCSBuildParams(p GCSParams) gcsBuildParams {
	out := gcsBuildParams{Endpoint: gcsDefaultJSONEndpoint, CredentialsJSON: p.CredentialsJSON}
	if p.CredentialsJSON == "" {
		out.CredentialsFile = p.CredentialsFile
	}
	if p.Endpoint != "" {
		out.Endpoint = p.Endpoint
	}
	if out.CredentialsJSON == "" && out.CredentialsFile == "" && strings.HasPrefix(out.Endpoint, "http://") {
		out.NoAuth = true
	}
	return out
}

// gcsClient Client 介面的 gcs driver（GCS 原生，**只走 JSON API 預設 HTTP
// transport、不啟用 gRPC**——SDK 原始碼明載 ObjectRetention 不經 gRPC API 報告，
// 而 ProbeBucket 的治理揭露要讀 bucket 保留設定；此為不啟用 gRPC 的兩個理由之一）。
type gcsClient struct {
	c      *storage.Client
	bucket string
}

// NewGCSClient 建構 gcs driver（storage.NewClient＝HTTP transport；
// 不得改用 NewGRPCClient，理由見 gcsClient 型別註解）。
func NewGCSClient(ctx context.Context, p GCSParams) (Client, error) {
	bp := resolveGCSBuildParams(p)
	opts := []option.ClientOption{option.WithEndpoint(bp.Endpoint)}
	if bp.CredentialsJSON != "" {
		opts = append(opts, option.WithCredentialsJSON([]byte(bp.CredentialsJSON)))
	} else if bp.CredentialsFile != "" {
		opts = append(opts, option.WithCredentialsFile(bp.CredentialsFile))
	}
	if bp.NoAuth {
		opts = append(opts, option.WithoutAuthentication())
	}
	c, err := storage.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("offsite: 建構 GCS 客戶端失敗: %w", err)
	}
	return &gcsClient{c: c, bucket: p.Bucket}, nil
}

func (g *gcsClient) refBucket(ref ObjectRef) string {
	if ref.Bucket != "" {
		return ref.Bucket
	}
	return g.bucket
}

func (g *gcsClient) Put(ctx context.Context, key string, r io.Reader, opts PutOpts) (PutResult, error) {
	ctx, cancel := context.WithTimeout(ctx, transferTimeout(opts.ContentLength))
	defer cancel()
	w := g.c.Bucket(g.bucket).Object(key).NewWriter(ctx)
	// Writer 預設自動計算並驗證 CRC32C（SDK 傳輸完整性，對應 s3 側
	// ChecksumAlgorithm；已查證確認）。metadata 照上傳契約；
	// **無任何保留欄位**（不設 Retention、不設任何 hold）。
	w.ObjectAttrs.Metadata = opts.Metadata
	if _, err := io.Copy(w, r); err != nil {
		_ = w.Close()
		return PutResult{}, fmt.Errorf("offsite: gcs 上傳失敗（key %s）: %w", key, err)
	}
	if err := w.Close(); err != nil {
		return PutResult{}, fmt.Errorf("offsite: gcs 上傳收尾失敗（key %s）: %w", key, err)
	}
	// generation 十進位入 version（參考性記錄）
	return PutResult{Version: strconv.FormatInt(w.Attrs().Generation, 10)}, nil
}

func (g *gcsClient) Head(ctx context.Context, ref ObjectRef) (ObjectInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeoutShort)
	defer cancel()
	// 對 key 的目前內容（無 generation 綁定）
	attrs, err := g.c.Bucket(g.refBucket(ref)).Object(ref.Key).Attrs(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return ObjectInfo{}, fmt.Errorf("offsite: gcs head（key %s）: %w", ref.Key, ErrObjectNotFound)
		}
		return ObjectInfo{}, fmt.Errorf("offsite: gcs head 失敗（key %s）: %w", ref.Key, err)
	}
	return ObjectInfo{
		Size:     attrs.Size,
		Metadata: attrs.Metadata,
		Version:  strconv.FormatInt(attrs.Generation, 10),
	}, nil
}

func (g *gcsClient) Fetch(ctx context.Context, ref ObjectRef, expectedSize int64) (io.ReadCloser, error) {
	ctx, cancel := context.WithTimeout(ctx, transferTimeout(expectedSize))
	rd, err := g.c.Bucket(g.refBucket(ref)).Object(ref.Key).NewReader(ctx)
	if err != nil {
		cancel()
		if errors.Is(err, storage.ErrObjectNotExist) {
			return nil, fmt.Errorf("offsite: gcs fetch（key %s）: %w", ref.Key, ErrObjectNotFound)
		}
		return nil, fmt.Errorf("offsite: gcs fetch 失敗（key %s）: %w", ref.Key, err)
	}
	return &deadlineReadCloser{ReadCloser: rd, cancel: cancel}, nil
}

func (g *gcsClient) Delete(ctx context.Context, ref ObjectRef) error {
	ctx, cancel := context.WithTimeout(ctx, opTimeoutShort)
	defer cancel()
	if err := g.c.Bucket(g.refBucket(ref)).Object(ref.Key).Delete(ctx); err != nil {
		return fmt.Errorf("offsite: gcs delete 失敗（key %s）: %w", ref.Key, err)
	}
	return nil
}

func (g *gcsClient) ProbeBucket(ctx context.Context) (BucketGovernance, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeoutShort)
	defer cancel()
	// BucketHandle.Attrs 一次回 VersioningEnabled／RetentionPolicy／
	// ObjectRetentionMode（driver 契約的判定理由——互通層讀不到這些）
	attrs, err := g.c.Bucket(g.bucket).Attrs(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrBucketNotExist) {
			return BucketGovernance{}, fmt.Errorf("offsite: gcs probe（bucket %s）: %w", g.bucket, ErrBucketNotFound)
		}
		return BucketGovernance{}, fmt.Errorf("offsite: gcs probe 失敗（bucket %s）: %w", g.bucket, err)
	}
	gov := BucketGovernance{Versioning: VersioningDisabled, Retention: RetentionNone}
	if attrs.VersioningEnabled {
		gov.Versioning = VersioningEnabled
	}
	switch {
	case attrs.RetentionPolicy != nil:
		// bucket retention policy（可加 lock）＝指引的基準建議
		gov.Retention = RetentionBucketPolicy
		gov.RetentionDetail = "retention_period=" + attrs.RetentionPolicy.RetentionPeriod.String() +
			" locked=" + strconv.FormatBool(attrs.RetentionPolicy.IsLocked)
	case attrs.ObjectRetentionMode == "Enabled":
		// 逐物件保留**能力**已啟用。本產品不設定每物件保留期，單獨啟用
		// 不保護本產品上傳的物件（指引警示；揭露照實陳述、不判好壞）
		gov.Retention = RetentionPerObject
		gov.RetentionDetail = "object_retention=Enabled（本產品不逐物件設保留期）"
	}
	// 誠實界定：JSON 回應缺欄（模擬器不支援 retentionPolicy）與「真的沒設」
	// 在 Attrs 產物上不可分辨，皆讀為 None——TestConnection 的「無法確認」warn
	// 降級路徑由探測呼叫本身失敗（權限不足）觸發，模擬器情境見
	// gcs_fakeserver_test.go 的記載。
	return gov, nil
}
