package offsite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/testgate"
)

// gcs driver 的 fake-gcs-server 實測。
//
// 誠實邊界（design §6 第 16 條）：模擬器只驗欄位與 generation 行為；
// bucket 保留設定（retentionPolicy 欄）模擬器不支援——其 Attrs 回應**缺該欄**，
// 與「真的沒設保留」在 JSON 產物上不可分辨，故揭露讀為 none 而非 unknown；
// 「讀不到→warn 無法確認」的降級路徑由 FakeClient 注入格覆蓋
// （TestConnectionGovernanceUnknownWarns），真 GCS 的揭露正確性留 1.14 人工驗收。
//
// gating：TEST_GCS_ENDPOINT（未設即 skip；REQUIRE_INTEGRATION=1 時 skip 轉 fail）。
// 跑法（compose 內；dev compose 已常設 fake-gcs 服務）：
//
//	docker compose up -d fake-gcs
//	docker compose exec -T backend sh -c \
//	  'TEST_GCS_ENDPOINT=http://fake-gcs:4443/storage/v1/ REQUIRE_INTEGRATION=1 \
//	   go test ./internal/offsite -run FakeGCS -count=1 -v'

func fakeGCSDriver(t *testing.T, endpoint string, versioned bool) Client {
	t.Helper()
	bucket := createFakeGCSBucket(t, endpoint, versioned)
	c, err := NewGCSClient(context.Background(), GCSParams{Bucket: bucket, Endpoint: endpoint})
	if err != nil {
		t.Fatalf("NewGCSClient: %v", err)
	}
	return c
}

// TestFakeGCSPutMetadataRoundtrip put 帶 metadata 讀回、內容比對、
// generation 作參考性版本識別。
func TestFakeGCSPutMetadataRoundtrip(t *testing.T) {
	endpoint := testgate.Value(t, testgate.EnvGCSEndpoint)
	c := fakeGCSDriver(t, endpoint, false)
	ctx := context.Background()

	body := []byte("fake-gcs-roundtrip")
	meta := map[string]string{
		"sha256":              "0011223344",
		"custodexa-object-id": "7",
		"custodexa-profile":   "00112233aabbccdd",
	}
	res, err := c.Put(ctx, "exports/job-7.zip", bytes.NewReader(body), PutOpts{
		Metadata: meta, ContentLength: int64(len(body)),
	})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if res.Version == "" {
		t.Error("gcs 恆回 generation，Version 不應為空（參考性記錄，記而不依賴）")
	}
	info, err := c.Head(ctx, ObjectRef{Key: "exports/job-7.zip"})
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
	rd, err := c.Fetch(ctx, ObjectRef{Key: "exports/job-7.zip"}, info.Size)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	got, _ := io.ReadAll(rd)
	_ = rd.Close()
	if !bytes.Equal(got, body) {
		t.Fatalf("Fetch 內容不符：%q", got)
	}
}

// TestFakeGCSOverwriteDetectableBySHA256 覆寫同 key 後取回為新內容，
// 且與帳冊記載的 SHA-256 不符——這正是「取回先驗後送」的拒付判準：
// Fetcher 以本判準拒絕交付；本測試在真 JSON API 語義上釘住判準本身
// （取回＝目前內容、原雜湊必然失配）。
func TestFakeGCSOverwriteDetectableBySHA256(t *testing.T) {
	endpoint := testgate.Value(t, testgate.EnvGCSEndpoint)
	c := fakeGCSDriver(t, endpoint, false)
	ctx := context.Background()

	original := []byte("original-evidence")
	ledgerSHA := sha256.Sum256(original)
	if _, err := c.Put(ctx, "recordings/2026/08/session-1.cast", bytes.NewReader(original), PutOpts{
		ContentLength: int64(len(original)),
	}); err != nil {
		t.Fatalf("Put original: %v", err)
	}
	// 外力覆寫同 key（模擬儲存端內容被替換）
	tampered := []byte("tampered-content!!")
	if _, err := c.Put(ctx, "recordings/2026/08/session-1.cast", bytes.NewReader(tampered), PutOpts{
		ContentLength: int64(len(tampered)),
	}); err != nil {
		t.Fatalf("Put tampered: %v", err)
	}
	rd, err := c.Fetch(ctx, ObjectRef{Key: "recordings/2026/08/session-1.cast"}, int64(len(tampered)))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	got, _ := io.ReadAll(rd)
	_ = rd.Close()
	if !bytes.Equal(got, tampered) {
		t.Fatalf("取回應為 key 的目前內容（無版本綁定），got %q", got)
	}
	gotSHA := sha256.Sum256(got)
	if hex.EncodeToString(gotSHA[:]) == hex.EncodeToString(ledgerSHA[:]) {
		t.Fatal("覆寫後雜湊不應與原記載相符——拒付判準失效")
	}
}

// TestFakeGCSProbeBucketVersioningStates ProbeBucket 對 versioning 兩態的揭露。
func TestFakeGCSProbeBucketVersioningStates(t *testing.T) {
	endpoint := testgate.Value(t, testgate.EnvGCSEndpoint)
	ctx := context.Background()

	plain := fakeGCSDriver(t, endpoint, false)
	gov, err := plain.ProbeBucket(ctx)
	if err != nil {
		t.Fatalf("ProbeBucket（未版本化）: %v", err)
	}
	if gov.Versioning != VersioningDisabled {
		t.Fatalf("未版本化 bucket 揭露=%q, want disabled", gov.Versioning)
	}

	versioned := fakeGCSDriver(t, endpoint, true)
	gov, err = versioned.ProbeBucket(ctx)
	if err != nil {
		t.Fatalf("ProbeBucket（版本化）: %v", err)
	}
	if gov.Versioning != VersioningEnabled {
		t.Fatalf("版本化 bucket 揭露=%q, want enabled", gov.Versioning)
	}
}

// TestFakeGCSConnectionTestFullSteps 測試連線全步驟走 gcs driver：
// 兩段全 ok、探測物刪除實際發生（刪後 Head 缺件）。
func TestFakeGCSConnectionTestFullSteps(t *testing.T) {
	endpoint := testgate.Value(t, testgate.EnvGCSEndpoint)
	c := fakeGCSDriver(t, endpoint, false)
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
}
