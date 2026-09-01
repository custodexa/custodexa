package offsite

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/custodexa/backend/internal/testgate"
)

// s3 driver 的 localstack 實測。
//
// 分工：contract test（TestClientContractS3）承擔行為契約；本檔補真 SDK 語義——
// metadata 讀回、ProbeBucket 對 versioning 兩態的揭露、測試連線全步驟
// （含探測物的刪除實際發生）。
//
// gating：TEST_S3_ENDPOINT（未設即 skip；REQUIRE_INTEGRATION=1 時 skip 轉 fail）。
// 跑法（compose 內；dev compose 的 localstack 已含 SERVICES: kms,s3）：
//
//	docker compose up -d localstack
//	docker compose exec -T backend sh -c \
//	  'TEST_S3_ENDPOINT=http://localstack:4566 REQUIRE_INTEGRATION=1 \
//	   go test ./internal/offsite -run Localstack -count=1 -v'

// localstackDriver 建 bucket＋被測 driver。
func localstackDriver(t *testing.T, endpoint string) (Client, string) {
	t.Helper()
	bucket := createLocalstackBucket(t, endpoint)
	c, err := NewS3Client(context.Background(), S3Params{
		Bucket: bucket, Endpoint: endpoint, Region: "us-east-1", PathStyle: true,
		AccessKeyID: "test", SecretAccessKey: "test",
	})
	if err != nil {
		t.Fatalf("NewS3Client: %v", err)
	}
	return c, bucket
}

// TestLocalstackPutMetadataRoundtrip 真 SDK 的 put 帶 metadata 讀回與內容比對。
func TestLocalstackPutMetadataRoundtrip(t *testing.T) {
	endpoint := testgate.Value(t, testgate.EnvS3Endpoint)
	c, _ := localstackDriver(t, endpoint)
	ctx := context.Background()

	body := []byte("localstack-roundtrip")
	meta := map[string]string{
		"sha256":              "cafebabe",
		"custodexa-object-id": "99",
		"custodexa-profile":   "fedcba9876543210",
	}
	res, err := c.Put(ctx, "recordings/2026/08/session-99.cast", bytes.NewReader(body), PutOpts{
		Metadata: meta, ContentLength: int64(len(body)),
	})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	// 非版本化 bucket：版本識別缺席不影響行為（spec「版本識別為參考性記錄」）
	if res.Version != "" {
		t.Logf("localstack 回了 version=%q（照記，不依賴）", res.Version)
	}
	info, err := c.Head(ctx, ObjectRef{Key: "recordings/2026/08/session-99.cast"})
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if info.Size != int64(len(body)) {
		t.Fatalf("Head.Size=%d, want %d", info.Size, len(body))
	}
	for k, want := range meta {
		if got := metadataValue(info.Metadata, k); got != want {
			t.Errorf("metadata[%s]=%q, want %q（全集 %v）", k, got, want, info.Metadata)
		}
	}
	rd, err := c.Fetch(ctx, ObjectRef{Key: "recordings/2026/08/session-99.cast"}, info.Size)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	got, _ := io.ReadAll(rd)
	_ = rd.Close()
	if !bytes.Equal(got, body) {
		t.Fatalf("Fetch 內容不符：%q", got)
	}
}

// TestLocalstackProbeBucketVersioningStates ProbeBucket 對 versioning 兩態的
// 中性揭露（第 0 段：只回報、不判好壞）。
func TestLocalstackProbeBucketVersioningStates(t *testing.T) {
	endpoint := testgate.Value(t, testgate.EnvS3Endpoint)
	c, bucket := localstackDriver(t, endpoint)
	ctx := context.Background()

	gov, err := c.ProbeBucket(ctx)
	if err != nil {
		t.Fatalf("ProbeBucket（未版本化）: %v", err)
	}
	if gov.Versioning != VersioningDisabled {
		t.Fatalf("新 bucket 的 versioning 揭露=%q, want disabled", gov.Versioning)
	}

	// 開啟 versioning 後重探
	raw := rawLocalstackS3(t, endpoint)
	pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := raw.PutBucketVersioning(pctx, &s3.PutBucketVersioningInput{
		Bucket: &bucket,
		VersioningConfiguration: &s3types.VersioningConfiguration{
			Status: s3types.BucketVersioningStatusEnabled,
		},
	}); err != nil {
		t.Fatalf("PutBucketVersioning: %v", err)
	}
	gov, err = c.ProbeBucket(ctx)
	if err != nil {
		t.Fatalf("ProbeBucket（版本化後）: %v", err)
	}
	if gov.Versioning != VersioningEnabled {
		t.Fatalf("版本化後揭露=%q, want enabled", gov.Versioning)
	}
	// Object Lock 未設定的 bucket：保留揭露＝none（不是 unknown）
	if gov.Retention != RetentionNone {
		t.Fatalf("無 Object Lock 的 bucket 保留揭露=%q, want none", gov.Retention)
	}
}

// TestLocalstackConnectionTestFullSteps 測試連線全步驟：兩段全 ok、
// 探測物在儲存端**確實被刪除**（第 1 段的清理不是宣稱是實測）。
func TestLocalstackConnectionTestFullSteps(t *testing.T) {
	endpoint := testgate.Value(t, testgate.EnvS3Endpoint)
	c, bucket := localstackDriver(t, endpoint)
	ctx := context.Background()

	steps := RunConnectionTest(ctx, c, "probe-prefix", time.Now)
	if len(steps) != 6 {
		t.Fatalf("步驟數=%d, want 6: %+v", len(steps), steps)
	}
	for _, s := range steps {
		if s.Outcome != StepOK {
			t.Errorf("步驟 %s outcome=%s（code=%s detail=%s）, want ok", s.Step, s.Outcome, s.ErrorCode, s.Detail)
		}
	}

	// 儲存端零殘留：list prefix 下應無任何物件
	raw := rawLocalstackS3(t, endpoint)
	lctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	prefix := "probe-prefix/"
	out, err := raw.ListObjectsV2(lctx, &s3.ListObjectsV2Input{Bucket: &bucket, Prefix: &prefix})
	if err != nil {
		t.Fatalf("ListObjectsV2: %v", err)
	}
	if len(out.Contents) != 0 {
		t.Fatalf("測試連線後殘留 %d 件探測物", len(out.Contents))
	}
}
