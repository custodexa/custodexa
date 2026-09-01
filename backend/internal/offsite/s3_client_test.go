package offsite

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestOffsiteEndpointIgnoresSDKGlobal（不讀 SDK 全域端點的守衛）：
// 設 AWS_ENDPOINT_URL 而本功能端點鍵空→建構 **fail-close**，訊息指名只認
// OFFSITE_S3_ENDPOINT 且**不回顯**環境變數的值（結果面核對＋端點淨化）。
func TestOffsiteEndpointIgnoresSDKGlobal(t *testing.T) {
	const leaked = "http://attacker.example:9999"
	t.Setenv("AWS_ENDPOINT_URL", leaked)

	_, err := NewS3Client(context.Background(), S3Params{
		Bucket: "b", Endpoint: "", Region: "us-east-1",
	})
	if err == nil {
		t.Fatal("AWS_ENDPOINT_URL 有值而本鍵空時 MUST fail-close（SDK 會把它解析進 BaseEndpoint）")
	}
	if !errors.Is(err, ErrS3EndpointDrift) {
		t.Fatalf("錯誤應為 ErrS3EndpointDrift，got %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "OFFSITE_S3_ENDPOINT") {
		t.Errorf("訊息未指名本功能鍵：%s", msg)
	}
	if strings.Contains(msg, "attacker.example") || strings.Contains(msg, leaked) {
		t.Errorf("訊息回顯了環境變數的值（端點紀律禁止）：%s", msg)
	}
}

// TestS3ClientExplicitEndpointWinsOverSDKGlobal 本鍵非空時：顯式端點生效、
// 全域變數不改導、建構成功（部署方為別的 AWS 服務全域設端點不會殃及本功能）。
func TestS3ClientExplicitEndpointWinsOverSDKGlobal(t *testing.T) {
	t.Setenv("AWS_ENDPOINT_URL", "http://attacker.example:9999")

	c, err := NewS3Client(context.Background(), S3Params{
		Bucket: "b", Endpoint: "http://minio.internal:9000", Region: "us-east-1",
		PathStyle: true, AccessKeyID: "ak", SecretAccessKey: "sk",
	})
	if err != nil {
		t.Fatalf("顯式端點下建構不應失敗: %v", err)
	}
	got := c.(*s3Client).api.Options().BaseEndpoint
	if got == nil || *got != "http://minio.internal:9000" {
		t.Fatalf("BaseEndpoint 不是本功能鍵的值: %v", got)
	}
}

// TestS3ClientCleanEnvironmentBuilds 無全域覆寫、本鍵空＝AWS 預設端點解析，
// 建構成功（對照組：fail-close 只發生在解析結果與本鍵不符時）。
func TestS3ClientCleanEnvironmentBuilds(t *testing.T) {
	t.Setenv("AWS_ENDPOINT_URL", "")
	t.Setenv("AWS_ENDPOINT_URL_S3", "")

	if _, err := NewS3Client(context.Background(), S3Params{
		Bucket: "b", Endpoint: "", Region: "us-east-1",
	}); err != nil {
		t.Fatalf("乾淨環境下空端點建構不應失敗: %v", err)
	}
}

// TestVerifyS3ResolvedEndpointGrid 結果面核對的純函式逐格。
func TestVerifyS3ResolvedEndpointGrid(t *testing.T) {
	s := func(v string) *string { return &v }
	cases := []struct {
		name       string
		resolved   *string
		configured string
		wantErr    bool
	}{
		{"皆空", nil, "", false},
		{"空指標視同空值", s(""), "", false},
		{"一致", s("http://e:9000"), "http://e:9000", false},
		{"SDK 推了別的值", s("http://sneaky:1"), "", true},
		{"本鍵被蓋掉", s("http://sneaky:1"), "http://e:9000", true},
		{"本鍵沒生效", nil, "http://e:9000", true},
	}
	for _, c := range cases {
		err := verifyS3ResolvedEndpoint(c.resolved, c.configured)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err=%v, wantErr=%v", c.name, err, c.wantErr)
		}
		if err != nil && !errors.Is(err, ErrS3EndpointDrift) {
			t.Errorf("%s: 錯誤應收斂 ErrS3EndpointDrift", c.name)
		}
	}
}
