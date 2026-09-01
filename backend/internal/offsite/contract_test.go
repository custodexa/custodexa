package offsite

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"cloud.google.com/go/storage"
	"google.golang.org/api/option"

	"github.com/custodexa/backend/internal/testgate"
)

// driver contract test：同一組行為斷言分別跑
// s3Client（localstack，gated TEST_S3_ENDPOINT）、gcsClient（fake-gcs-server，
// gated TEST_GCS_ENDPOINT）與 FakeClient（恆跑），防三個實作語義漂移。
// worker／Ledger／Fetcher 全部只面向 Client 介面，語義的權威就是這份契約。

// contractFactory 建一個指到乾淨 bucket 的 Client。
type contractFactory func(t *testing.T) Client

func TestClientContractFake(t *testing.T) {
	runClientContract(t, func(t *testing.T) Client {
		f := NewFakeClient("contract-bucket")
		f.SetVersioned(false)
		return f
	})
}

func TestClientContractS3(t *testing.T) {
	endpoint := testgate.Value(t, testgate.EnvS3Endpoint)
	runClientContract(t, func(t *testing.T) Client {
		bucket := createLocalstackBucket(t, endpoint)
		c, err := NewS3Client(context.Background(), S3Params{
			Bucket: bucket, Endpoint: endpoint, Region: "us-east-1", PathStyle: true,
			AccessKeyID: "test", SecretAccessKey: "test",
		})
		if err != nil {
			t.Fatalf("NewS3Client: %v", err)
		}
		return c
	})
}

func TestClientContractGCS(t *testing.T) {
	endpoint := testgate.Value(t, testgate.EnvGCSEndpoint)
	runClientContract(t, func(t *testing.T) Client {
		bucket := createFakeGCSBucket(t, endpoint, false)
		c, err := NewGCSClient(context.Background(), GCSParams{Bucket: bucket, Endpoint: endpoint})
		if err != nil {
			t.Fatalf("NewGCSClient: %v", err)
		}
		return c
	})
}

// runClientContract 契約本體。
func runClientContract(t *testing.T, mk contractFactory) {
	ctx := context.Background()

	t.Run("PutHeadFetchRoundtrip", func(t *testing.T) {
		c := mk(t)
		body := []byte("contract-body-v1")
		meta := map[string]string{
			"sha256":              "deadbeef",
			"custodexa-object-id": "17",
			"custodexa-profile":   "0123456789abcdef",
		}
		if _, err := c.Put(ctx, "contract/a.bin", bytes.NewReader(body), PutOpts{
			Metadata: meta, ContentLength: int64(len(body)),
		}); err != nil {
			t.Fatalf("Put: %v", err)
		}
		info, err := c.Head(ctx, ObjectRef{Key: "contract/a.bin"})
		if err != nil {
			t.Fatalf("Head: %v", err)
		}
		if info.Size != int64(len(body)) {
			t.Fatalf("Head.Size=%d, want %d", info.Size, len(body))
		}
		for k, want := range meta {
			if got := metadataValue(info.Metadata, k); got != want {
				t.Errorf("metadata[%s]=%q, want %q（讀回全集：%v）", k, got, want, info.Metadata)
			}
		}
		rd, err := c.Fetch(ctx, ObjectRef{Key: "contract/a.bin"}, int64(len(body)))
		if err != nil {
			t.Fatalf("Fetch: %v", err)
		}
		got, err := io.ReadAll(rd)
		_ = rd.Close()
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("Fetch 內容不符（err=%v）: %q", err, got)
		}
	})

	t.Run("OverwriteSameKeyServesCurrentContent", func(t *testing.T) {
		// 重試＝重傳同 key；Head/Fetch 一律取目前內容、無版本綁定
		c := mk(t)
		if _, err := c.Put(ctx, "contract/b.bin", bytes.NewReader([]byte("old")), PutOpts{ContentLength: 3}); err != nil {
			t.Fatalf("Put old: %v", err)
		}
		if _, err := c.Put(ctx, "contract/b.bin", bytes.NewReader([]byte("newer")), PutOpts{ContentLength: 5}); err != nil {
			t.Fatalf("Put newer: %v", err)
		}
		rd, err := c.Fetch(ctx, ObjectRef{Key: "contract/b.bin"}, 5)
		if err != nil {
			t.Fatalf("Fetch: %v", err)
		}
		got, _ := io.ReadAll(rd)
		_ = rd.Close()
		if string(got) != "newer" {
			t.Fatalf("覆寫後取回=%q, want newer", got)
		}
		if info, err := c.Head(ctx, ObjectRef{Key: "contract/b.bin"}); err != nil || info.Size != 5 {
			t.Fatalf("覆寫後 Head=%+v err=%v, want size 5", info, err)
		}
	})

	t.Run("NotFoundConvergesToSentinel", func(t *testing.T) {
		c := mk(t)
		if _, err := c.Head(ctx, ObjectRef{Key: "contract/absent"}); !errors.Is(err, ErrObjectNotFound) {
			t.Errorf("Head 缺件應回 ErrObjectNotFound，got %v", err)
		}
		if _, err := c.Fetch(ctx, ObjectRef{Key: "contract/absent"}, 0); !errors.Is(err, ErrObjectNotFound) {
			t.Errorf("Fetch 缺件應回 ErrObjectNotFound，got %v", err)
		}
	})

	t.Run("DeleteRemovesObject", func(t *testing.T) {
		// Delete 契約在此涵蓋（未來擴充點）；正式路徑不呼叫它的不變式由
		// internal/guards/offsitedelete 靜態守衛＋fake 的行為斷言承擔
		c := mk(t)
		if _, err := c.Put(ctx, "contract/c.bin", bytes.NewReader([]byte("x")), PutOpts{ContentLength: 1}); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := c.Delete(ctx, ObjectRef{Key: "contract/c.bin"}); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if _, err := c.Head(ctx, ObjectRef{Key: "contract/c.bin"}); !errors.Is(err, ErrObjectNotFound) {
			t.Errorf("刪除後 Head 應回 ErrObjectNotFound，got %v", err)
		}
	})

	t.Run("VersionAbsenceDoesNotAffectBehavior", func(t *testing.T) {
		// spec「版本識別為參考性記錄」：非版本化 bucket 下 Version 為空、
		// 上傳與取回行為不變
		c := mk(t)
		res, err := c.Put(ctx, "contract/d.bin", bytes.NewReader([]byte("v")), PutOpts{ContentLength: 1})
		if err != nil {
			t.Fatalf("Put: %v", err)
		}
		_ = res.Version // 有帶就記、沒帶就空——兩態皆合法，不得據以分支
		rd, err := c.Fetch(ctx, ObjectRef{Key: "contract/d.bin"}, 1)
		if err != nil {
			t.Fatalf("Fetch: %v", err)
		}
		_ = rd.Close()
	})

	t.Run("ProbeBucketDisclosesGovernance", func(t *testing.T) {
		c := mk(t)
		gov, err := c.ProbeBucket(ctx)
		if err != nil {
			t.Fatalf("ProbeBucket: %v", err)
		}
		switch gov.Versioning {
		case VersioningEnabled, VersioningDisabled, VersioningUnknown:
		default:
			t.Errorf("Versioning 值域外：%q", gov.Versioning)
		}
		switch gov.Retention {
		case RetentionNone, RetentionBucketPolicy, RetentionPerObject, RetentionUnknown:
		default:
			t.Errorf("Retention 值域外：%q", gov.Retention)
		}
	})
}

// metadataValue 各後端 metadata key 大小寫慣例不同（s3 標頭化為小寫、gcs 原樣），
// 契約以不分大小寫取值。
func metadataValue(m map[string]string, key string) string {
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

// ---- 整合靶機的 bucket 佈建（測試自建，唯一名稱防跨執行互撞） ----

// createLocalstackBucket 直連 localstack 建一個唯一 bucket。
func createLocalstackBucket(t *testing.T, endpoint string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	api := rawLocalstackS3(t, endpoint)
	name := fmt.Sprintf("custodexa-offsite-%d", time.Now().UnixNano())
	if _, err := api.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &name}); err != nil {
		t.Fatalf("CreateBucket 失敗（localstack 是否已啟動、SERVICES 是否含 s3？）: %v", err)
	}
	return name
}

// rawLocalstackS3 測試佈建用的原生 SDK 客戶端（不經被測 driver）。
func rawLocalstackS3(t *testing.T, endpoint string) *s3.Client {
	t.Helper()
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")))
	if err != nil {
		t.Fatalf("載入 AWS 組態失敗: %v", err)
	}
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = &endpoint
		o.UsePathStyle = true
	})
}

// createFakeGCSBucket 直連 fake-gcs-server 建一個唯一 bucket。
func createFakeGCSBucket(t *testing.T, endpoint string, versioned bool) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	raw, err := storage.NewClient(ctx,
		option.WithEndpoint(endpoint), option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("建構佈建用 GCS 客戶端失敗: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	name := fmt.Sprintf("custodexa-offsite-%d", time.Now().UnixNano())
	attrs := &storage.BucketAttrs{VersioningEnabled: versioned}
	if err := raw.Bucket(name).Create(ctx, "test-project", attrs); err != nil {
		t.Fatalf("建 bucket 失敗（fake-gcs-server 是否已啟動？）: %v", err)
	}
	return name
}
