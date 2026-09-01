package offsite

import (
	"testing"
)

// TestGCSClientIgnoresGlobalEnv（不讀全域環境變數的守衛）：
// 設 STORAGE_EMULATOR_HOST 與 GOOGLE_APPLICATION_CREDENTIALS 而本功能鍵空→
// 兩者皆不被採用為建構參數（不讀全域，與 s3 側不讀
// AWS_ENDPOINT_URL 同一紀律）。
//
// 斷言對象＝resolveGCSBuildParams 的產物（純函式、只看 GCSParams 入參）：
// 端點恆顯式（本鍵空時釘住正式 GCS JSON API 端點——顯式端點使 SDK 的
// STORAGE_EMULATOR_HOST default-endpoint 注入永遠被蓋過，見
// gcsDefaultJSONEndpoint 註解）；憑證檔只來自本功能鍵。
func TestGCSClientIgnoresGlobalEnv(t *testing.T) {
	t.Setenv("STORAGE_EMULATOR_HOST", "attacker-emulator:4443")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/tmp/attacker-sa.json")

	bp := resolveGCSBuildParams(GCSParams{Bucket: "b"})
	if bp.Endpoint != gcsDefaultJSONEndpoint {
		t.Fatalf("本鍵空時端點應釘住正式 GCS 端點，got %q", bp.Endpoint)
	}
	if bp.CredentialsFile != "" {
		t.Fatalf("本鍵空時不得注入任何憑證檔（GOOGLE_APPLICATION_CREDENTIALS 不是本功能的設定鍵），got %q", bp.CredentialsFile)
	}
	if bp.NoAuth {
		t.Fatal("正式端點下不得落入無認證通道")
	}
}

// TestGCSBuildParamsHonorOwnKeys 本功能鍵非空時逐項生效。
func TestGCSBuildParamsHonorOwnKeys(t *testing.T) {
	t.Setenv("STORAGE_EMULATOR_HOST", "attacker-emulator:4443")

	bp := resolveGCSBuildParams(GCSParams{
		Bucket:          "b",
		Endpoint:        "https://private.endpoint.example/storage/v1/",
		CredentialsFile: "/etc/custodexa/sa.json",
	})
	if bp.Endpoint != "https://private.endpoint.example/storage/v1/" {
		t.Fatalf("顯式端點未生效: %q", bp.Endpoint)
	}
	if bp.CredentialsFile != "/etc/custodexa/sa.json" {
		t.Fatalf("憑證檔鍵未生效: %q", bp.CredentialsFile)
	}
	if bp.NoAuth {
		t.Fatal("https 端點＋憑證檔不得落入無認證通道")
	}
}

// TestGCSBuildParamsEmulatorLane 無認證通道的判準（沿 kms 測試靶機先例）：
// 顯式 http 端點＋無憑證檔＝模擬器靶機；其餘組合一律不落入。
func TestGCSBuildParamsEmulatorLane(t *testing.T) {
	cases := []struct {
		name    string
		p       GCSParams
		wantNoAuth bool
	}{
		{"http端點無憑證＝靶機", GCSParams{Endpoint: "http://fake-gcs:4443/storage/v1/"}, true},
		{"http端點有憑證", GCSParams{Endpoint: "http://fake-gcs:4443/storage/v1/", CredentialsFile: "/x.json"}, false},
		{"https端點無憑證", GCSParams{Endpoint: "https://private.example/storage/v1/"}, false},
		{"全空（正式 GCS＋ADC）", GCSParams{}, false},
	}
	for _, c := range cases {
		if got := resolveGCSBuildParams(c.p).NoAuth; got != c.wantNoAuth {
			t.Errorf("%s: NoAuth=%v, want %v", c.name, got, c.wantNoAuth)
		}
	}
}
