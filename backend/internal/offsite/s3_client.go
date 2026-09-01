package offsite

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// S3Params s3 driver 的建構參數（factory 形狀：依 provider＋profile 參數建
// client，不綁死現行設定的單例——歷史世代（foreign）的取回可另建參數不同的
// client）。全部值由組裝根自 config 帶入，本包不讀 env。
type S3Params struct {
	// Bucket 現行 bucket（Put／ProbeBucket 的對象；ObjectRef.Bucket 空時的預設）
	Bucket string
	// Endpoint 端點 URL（OFFSITE_S3_ENDPOINT；空＝SDK 依 region 解析 AWS 預設端點）
	Endpoint string
	// Region region（自建端點下為名義值）
	Region string
	// PathStyle true＝path-style 位址（MinIO 慣用）
	PathStyle bool
	// AccessKeyID／SecretAccessKey 靜態憑證；兩者皆空＝SDK 預設鏈
	AccessKeyID     string
	SecretAccessKey string
}

// s3Client Client 介面的 s3 driver（AWS／MinIO／S3 相容端點）。
type s3Client struct {
	api    *s3.Client
	up     *manager.Uploader
	bucket string
}

// ErrS3EndpointDrift 結果面端點核對失敗：SDK 最終解析出的端點
// 不等於本功能鍵所給者——多半是 AWS_ENDPOINT_URL 或 ~/.aws/config 的
// endpoint_url 滲入。fail-close，且訊息不回顯任何值。
var ErrS3EndpointDrift = errors.New(
	"offsite: S3 客戶端解析出的端點不是來自 OFFSITE_S3_ENDPOINT。" +
		"本功能只認 OFFSITE_S3_ENDPOINT（含留空＝AWS 預設端點）；" +
		"請移除 AWS_ENDPOINT_URL／AWS_ENDPOINT_URL_S3 環境變數或共用組態檔的 endpoint_url 後重啟")

// NewS3Client 建構 s3 driver。
//
// 端點紀律（與 KMS 閘互不牽連）：
//   - 端點一律以 o.BaseEndpoint **顯式**設定（本鍵非空時），不經 SDK 的
//     全域端點環境變數承載；
//   - 建構後做**結果面核對**（沿 pkg/crypto/kms verifyResolvedEndpoint 的
//     「不列舉來源、只看結果」思路）：client.Options().BaseEndpoint 必須等於
//     本鍵（本鍵空時必須為空）——SDK 從 AWS_ENDPOINT_URL／~/.aws/config 推了
//     別的值進來即 fail-close 並指名只認本功能鍵，**不回顯值**。
//
// 憑證：靜態鍵皆設＝WithCredentialsProvider 明確覆蓋（不會流入
// KMS 客戶端——各自 LoadDefaultConfig）；皆空＝SDK 預設鏈（IRSA／instance
// profile／SSO）。半套矛盾由段 1 純組態驗證擋下，不在本函式射程。
func NewS3Client(ctx context.Context, p S3Params) (Client, error) {
	opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(p.Region)}
	if p.AccessKeyID != "" && p.SecretAccessKey != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(p.AccessKeyID, p.SecretAccessKey, "")))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("offsite: 載入 AWS 組態失敗（region %s）: %w", p.Region, err)
	}
	api := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if p.Endpoint != "" {
			o.BaseEndpoint = &p.Endpoint
		}
		o.UsePathStyle = p.PathStyle
	})
	if err := verifyS3ResolvedEndpoint(api.Options().BaseEndpoint, p.Endpoint); err != nil {
		return nil, err
	}
	return &s3Client{
		api:    api,
		up:     manager.NewUploader(api),
		bucket: p.Bucket,
	}, nil
}

// verifyS3ResolvedEndpoint 結果面核對（抽成純函式供測試逐格驗證）。
// resolved＝客戶端最終的 BaseEndpoint；configured＝本功能鍵的值。
func verifyS3ResolvedEndpoint(resolved *string, configured string) error {
	got := ""
	if resolved != nil {
		got = *resolved
	}
	if got != configured {
		return ErrS3EndpointDrift
	}
	return nil
}

// refBucket ObjectRef.Bucket 空＝現行 bucket。
func (c *s3Client) refBucket(ref ObjectRef) string {
	if ref.Bucket != "" {
		return ref.Bucket
	}
	return c.bucket
}

func (c *s3Client) Put(ctx context.Context, key string, r io.Reader, opts PutOpts) (PutResult, error) {
	ctx, cancel := context.WithTimeout(ctx, transferTimeout(opts.ContentLength))
	defer cancel()
	// manager.Uploader：小檔單一 PutObject、大檔 multipart，皆帶
	// ChecksumAlgorithm=SHA256（SDK 計算、伺服端驗證傳輸完整性；multipart 下為
	// 分段雜湊組合值，與整檔 SHA-256 不可比——整檔值由呼叫端存帳冊）。
	// **無任何保留欄位**。
	out, err := c.up.Upload(ctx, &s3.PutObjectInput{
		Bucket:            &c.bucket,
		Key:               &key,
		Body:              r,
		Metadata:          opts.Metadata,
		ChecksumAlgorithm: s3types.ChecksumAlgorithmSha256,
	})
	if err != nil {
		return PutResult{}, fmt.Errorf("offsite: s3 上傳失敗（key %s）: %w", key, err)
	}
	res := PutResult{}
	if out.VersionID != nil {
		res.Version = *out.VersionID
	}
	return res, nil
}

func (c *s3Client) Head(ctx context.Context, ref ObjectRef) (ObjectInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeoutShort)
	defer cancel()
	bucket := c.refBucket(ref)
	out, err := c.api.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &ref.Key})
	if err != nil {
		if isS3NotFound(err) {
			return ObjectInfo{}, fmt.Errorf("offsite: s3 head（key %s）: %w", ref.Key, ErrObjectNotFound)
		}
		return ObjectInfo{}, fmt.Errorf("offsite: s3 head 失敗（key %s）: %w", ref.Key, err)
	}
	info := ObjectInfo{Metadata: out.Metadata}
	if out.ContentLength != nil {
		info.Size = *out.ContentLength
	}
	if out.VersionId != nil {
		info.Version = *out.VersionId
	}
	return info, nil
}

func (c *s3Client) Fetch(ctx context.Context, ref ObjectRef, expectedSize int64) (io.ReadCloser, error) {
	// deadline 覆蓋整段串流：cancel 綁到 ReadCloser.Close（deadlineReadCloser）
	ctx, cancel := context.WithTimeout(ctx, transferTimeout(expectedSize))
	bucket := c.refBucket(ref)
	out, err := c.api.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &ref.Key})
	if err != nil {
		cancel()
		if isS3NotFound(err) {
			return nil, fmt.Errorf("offsite: s3 fetch（key %s）: %w", ref.Key, ErrObjectNotFound)
		}
		return nil, fmt.Errorf("offsite: s3 fetch 失敗（key %s）: %w", ref.Key, err)
	}
	return &deadlineReadCloser{ReadCloser: out.Body, cancel: cancel}, nil
}

func (c *s3Client) Delete(ctx context.Context, ref ObjectRef) error {
	ctx, cancel := context.WithTimeout(ctx, opTimeoutShort)
	defer cancel()
	bucket := c.refBucket(ref)
	if _, err := c.api.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &ref.Key}); err != nil {
		return fmt.Errorf("offsite: s3 delete 失敗（key %s）: %w", ref.Key, err)
	}
	return nil
}

func (c *s3Client) ProbeBucket(ctx context.Context) (BucketGovernance, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeoutShort)
	defer cancel()
	if _, err := c.api.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &c.bucket}); err != nil {
		if isS3NotFound(err) {
			return BucketGovernance{}, fmt.Errorf("offsite: s3 probe（bucket %s）: %w", c.bucket, ErrBucketNotFound)
		}
		return BucketGovernance{}, fmt.Errorf("offsite: s3 probe 失敗（bucket %s）: %w", c.bucket, err)
	}
	gov := BucketGovernance{Versioning: VersioningUnknown, Retention: RetentionUnknown}

	// versioning：讀不到（權限不足）降級 Unknown，不回錯誤
	if v, err := c.api.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: &c.bucket}); err == nil {
		if v.Status == s3types.BucketVersioningStatusEnabled {
			gov.Versioning = VersioningEnabled
		} else {
			gov.Versioning = VersioningDisabled
		}
	}

	// Object Lock 組態：未設定（專屬錯誤碼）＝None；設定存在依 default rule
	// 區分 bucket 級與僅能力啟用；其他錯誤（權限）＝Unknown
	lock, err := c.api.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{Bucket: &c.bucket})
	switch {
	case err == nil && lock.ObjectLockConfiguration != nil &&
		lock.ObjectLockConfiguration.ObjectLockEnabled == s3types.ObjectLockEnabledEnabled:
		if rule := lock.ObjectLockConfiguration.Rule; rule != nil && rule.DefaultRetention != nil {
			gov.Retention = RetentionBucketPolicy
			gov.RetentionDetail = describeS3DefaultRetention(rule.DefaultRetention)
		} else {
			gov.Retention = RetentionPerObject
			gov.RetentionDetail = "Object Lock 已啟用、無 default retention rule"
		}
	case err == nil:
		gov.Retention = RetentionNone
	case isS3ObjectLockNotConfigured(err):
		gov.Retention = RetentionNone
	default:
		// 讀不到＝Unknown（warn「無法確認，不影響上傳」由 TestConnection 承載）
	}
	return gov, nil
}

func describeS3DefaultRetention(r *s3types.DefaultRetention) string {
	out := "mode=" + string(r.Mode)
	if r.Days != nil {
		out += " days=" + strconv.FormatInt(int64(*r.Days), 10)
	}
	if r.Years != nil {
		out += " years=" + strconv.FormatInt(int64(*r.Years), 10)
	}
	return out
}

// isS3NotFound s3 的 not-found 形狀（NoSuchKey／NoSuchBucket／NotFound=404）。
func isS3NotFound(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case "NoSuchKey", "NoSuchBucket", "NotFound":
		return true
	}
	return false
}

// isS3ObjectLockNotConfigured bucket 未啟用 Object Lock 的專屬錯誤。
func isS3ObjectLockNotConfigured(err error) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) &&
		apiErr.ErrorCode() == "ObjectLockConfigurationNotFoundError"
}
