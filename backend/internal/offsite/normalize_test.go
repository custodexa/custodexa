package offsite

import "testing"

// 設定指紋的**成分敏感度**守衛。
//
// 這組斷言原本落在 `config/offsite_test.go`，設定全 UI 化後
// 純函式隨語義搬入本包（normalize.go），測試未隨之搬移——本檔補回，語義照舊。
//
// 為什麼值得有機器盯著：世代確認流程的觸發判準**就是**指紋比較。
// 「憑證輪替不改指紋、不觸發世代切換」是寫進營運程序的對外承諾，
// 而 path-style／憑證是否入指紋只是 `ComputeProfileID` 的參數表裡看不見的一行
// ——多帶一個成分進去，輪替就會誤觸世代切換；少帶一個（region、端點 path），
// 落點變了卻不觸發確認。兩個方向都必須有斷言。
//
// 測試對象刻意取 `validateAndNormalizeOffsiteSettings` → `fingerprintOf`
// 這條**實際路徑**而非直呼 `ComputeProfileID`：path-style 與憑證根本不是後者的
// 參數，只有走完正規化才能證明「它們沒有偷偷被帶進去」。

// baseFingerprintInput 指紋敏感度的基準設定（s3、含端點與 region、帶靜態憑證）。
func baseFingerprintInput() SettingsInput {
	return SettingsInput{
		Provider: ProviderS3, Endpoint: "http://minio.internal:9000",
		Bucket: "evidence", Region: "us-east-1",
		AccessKeyID: "ak", SecretAccessKey: "sk",
	}
}

// fingerprintOfInput 走正規化核心算指紋；驗證失敗即 t.Fatal（案例本身寫壞了）。
func fingerprintOfInput(t *testing.T, in SettingsInput) string {
	t.Helper()
	norm, err := validateAndNormalizeOffsiteSettings(in)
	if err != nil {
		t.Fatalf("基準設定應通過驗證: %v", err)
	}
	return norm.fingerprintOf()
}

// TestProfileIDComposition 指紋成分敏感度：
// region／bucket／prefix／端點 path／provider 變更即變；
// path-style 與憑證變更不變。
func TestProfileIDComposition(t *testing.T) {
	baseID := fingerprintOfInput(t, baseFingerprintInput())
	if len(baseID) != 16 {
		t.Fatalf("指紋長度=%d, want 16", len(baseID))
	}

	same := map[string]func(*SettingsInput){
		"path-style 切換": func(in *SettingsInput) { in.PathStyle = true },
		"憑證輪替": func(in *SettingsInput) {
			in.AccessKeyID, in.SecretAccessKey = "ak2", "sk2"
		},
		"憑證改走 SDK 預設鏈": func(in *SettingsInput) {
			in.AccessKeyID, in.SecretAccessKey = "", ""
			in.ClearCredentials = true
		},
		"端點大小寫與預設埠寫法": func(in *SettingsInput) {
			in.Endpoint = "HTTP://MINIO.INTERNAL:9000"
		},
	}
	for name, mutate := range same {
		in := baseFingerprintInput()
		mutate(&in)
		if got := fingerprintOfInput(t, in); got != baseID {
			t.Errorf("%s 不應改變指紋（落點沒變，改變即誤觸世代切換）：%s → %s", name, baseID, got)
		}
	}

	diff := map[string]func(*SettingsInput){
		"region 變更":        func(in *SettingsInput) { in.Region = "ap-northeast-1" },
		"bucket 變更":        func(in *SettingsInput) { in.Bucket = "evidence-2" },
		"prefix 變更":        func(in *SettingsInput) { in.Prefix = "corp" },
		"endpoint host 變更": func(in *SettingsInput) { in.Endpoint = "http://minio-2.internal:9000" },
		"endpoint path 變更": func(in *SettingsInput) {
			// 反向代理前綴不同＝落點不同（顯示面只印 origin，指紋仍須含 path）
			in.Endpoint = "http://minio.internal:9000/s3-prefix"
		},
		"provider 變更": func(in *SettingsInput) {
			in.Provider = ProviderGCS
			in.Endpoint, in.Region = "", ""
			in.AccessKeyID, in.SecretAccessKey = "", ""
			in.ServiceAccountJSON = `{"type":"service_account"}`
		},
	}
	for name, mutate := range diff {
		in := baseFingerprintInput()
		mutate(&in)
		if got := fingerprintOfInput(t, in); got == baseID {
			t.Errorf("%s 應改變指紋（落點已不同，不變即落點變了卻不觸發世代確認）", name)
		}
	}
}

// TestFingerprintEndpointTokenEmptyEndpoint 端點未指定時的指紋成分：
// s3 為空字串、gcs 為常數——兩者是**不同落點**，不得算出相同指紋。
func TestFingerprintEndpointTokenEmptyEndpoint(t *testing.T) {
	if tok := FingerprintEndpointToken(ProviderS3, ""); tok != "" {
		t.Errorf("s3 空端點的指紋成分=%q, want 空字串", tok)
	}
	if tok := FingerprintEndpointToken(ProviderGCS, ""); tok != gcsEmptyEndpointFingerprintToken {
		t.Errorf("gcs 空端點的指紋成分=%q, want %q", tok, gcsEmptyEndpointFingerprintToken)
	}
	// 兩者以相同 bucket／prefix 入雜湊時指紋必不同（只改 provider 也算落點變更）
	s3ID := ComputeProfileID(ProviderS3, FingerprintEndpointToken(ProviderS3, ""), "b", "p", "")
	gcsID := ComputeProfileID(ProviderGCS, FingerprintEndpointToken(ProviderGCS, ""), "b", "p", "")
	if s3ID == gcsID {
		t.Fatal("s3 與 gcs 的空端點設定不得算出相同指紋")
	}
}
