package config

import (
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/custodexa/backend/pkg/crypto/gcpkms"
)

const gcpConfigKey = "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/key"

// gcpConfigValues 委託部署於**環境**中僅存的組態（見 kek_vault_test.go 的
// 語義變更說明：金鑰識別與憑證都不再來自環境）。
func gcpConfigValues() map[string]string {
	return map[string]string{EnvKeyKEKProvider: KEKModeKMS, EnvKeyKMSProvider: gcpkms.ProviderGCP}
}

// gcpSettingsFixture 一份齊備的 GCP 委託設定：金鑰資源取自金鑰列／介面設定，
// 服務帳號金鑰檔取自本解封世代的記憶體持有者。
func gcpSettingsFixture() KMSSettings {
	return KMSSettings{Provider: gcpkms.ProviderGCP, KeyID: gcpConfigKey,
		GCPServiceAccountJSON: []byte(`{"type":"service_account","private_key":"gcp-secret-fixture"}`)}
}

func TestGCPKMSSettings(t *testing.T) {
	t.Run("startup-reads-provider-only", func(t *testing.T) {
		values := gcpConfigValues()
		d, err := DecideKEK(MapEnvLookup(values), false)
		if err != nil {
			t.Fatal("valid deployment refused")
		}
		provider, err := KMSProviderFromEnv(MapEnvLookup(values))
		if err != nil || d.KMS.Provider != provider || d.MatrixRow != "9" {
			t.Fatal("readers disagree")
		}
		if !reflect.DeepEqual(d.KMS, KMSSettings{Provider: gcpkms.ProviderGCP}) {
			t.Fatalf("startup decision carried topology or secrets: %+v", d.KMS)
		}
	})
	for _, region := range []string{"", "unused-region-value"} {
		t.Run("ignored-region-"+region, func(t *testing.T) {
			// 區域對 GCP 無意義：有值時以 notice 明說被忽略，而不是靜默吃掉。
			// 區域現在隨拓撲自資料庫進入設定，故本格改在設定層而非環境層驗。
			s := gcpSettingsFixture()
			s.Region = region
			if err := ValidateKMSSettings(s); err != nil {
				t.Fatalf("region changed acceptance: %v", err)
			}
			if (s.Notice() != "") != (region != "") {
				t.Fatal("ignored region diagnostic invalid")
			}
			if region != "" && (!strings.Contains(s.Notice(), FieldKMSRegion) || strings.Contains(s.Notice(), region)) {
				t.Fatal("notice must name the field, never its value")
			}
			if _, err := gcpkms.ParseKeyResource(s.KeyID); err != nil {
				t.Fatal("region changed resource identity")
			}
		})
	}
	for _, change := range []struct {
		name, field string
		mutate      func(*KMSSettings)
	}{
		{"missing-reference", FieldKMSKeyID, func(s *KMSSettings) { s.KeyID = "" }},
		{"blank-reference", FieldKMSKeyID, func(s *KMSSettings) { s.KeyID = " \t" }},
		{"version-reference", FieldKMSKeyID, func(s *KMSSettings) { s.KeyID = gcpConfigKey + "/cryptoKeyVersions/1" }},
		{"bare-reference", FieldKMSKeyID, func(s *KMSSettings) { s.KeyID = "secret-ref-value" }},
		{"missing-service-account", FieldGCPServiceAccount, func(s *KMSSettings) { s.GCPServiceAccountJSON = nil }},
		{"empty-service-account", FieldGCPServiceAccount, func(s *KMSSettings) { s.GCPServiceAccountJSON = []byte{} }},
	} {
		t.Run(change.name, func(t *testing.T) {
			s := gcpSettingsFixture()
			before := string(s.GCPServiceAccountJSON)
			change.mutate(&s)
			err := ValidateKMSSettings(s)
			if err == nil || !strings.Contains(err.Error(), change.field) {
				t.Fatalf("invalid settings accepted or not identified: %v", err)
			}
			if strings.Contains(err.Error(), gcpConfigKey) || strings.Contains(err.Error(), before) ||
				strings.Contains(err.Error(), "secret-ref-value") {
				t.Fatal("configuration value or credential reflected")
			}
		})
	}
	t.Run("complete-settings-accepted", func(t *testing.T) {
		if err := ValidateKMSSettings(gcpSettingsFixture()); err != nil {
			t.Fatalf("complete GCP settings refused: %v", err)
		}
	})
	t.Run("unknown-provider", func(t *testing.T) {
		values := gcpConfigValues()
		values[EnvKeyKMSProvider] = "secret-provider-value"
		_, a := DecideKEK(MapEnvLookup(values), false)
		_, b := KMSProviderFromEnv(MapEnvLookup(values))
		for _, err := range []error{a, b} {
			if err == nil || !strings.Contains(err.Error(), EnvKeyKMSProvider) || strings.Contains(err.Error(), "secret-provider-value") {
				t.Fatal("unknown provider accepted or reflected")
			}
		}
	})
	t.Run("local-material-refused", func(t *testing.T) {
		values := gcpConfigValues()
		values[EnvKeyEncryptionKey] = "local-material-fixture"
		d, err := DecideKEK(MapEnvLookup(values), false)
		if d != nil || err == nil || !strings.Contains(err.Error(), "[列 7]") || strings.Contains(err.Error(), values[EnvKeyEncryptionKey]) {
			t.Fatal("local material accepted or reflected")
		}
	})
	t.Run("existing-providers-preserved", func(t *testing.T) {
		aws := gcpSettingsFixture()
		aws.Provider = "aws"
		aws.GCPServiceAccountJSON = nil
		if err := ValidateKMSSettings(aws); err == nil || !strings.Contains(err.Error(), FieldKMSRegion) {
			t.Fatal("AWS region became optional")
		}
		if err := ValidateKMSSettings(vaultSettingsFixture()); err != nil {
			t.Fatalf("Vault settings regressed: %v", err)
		}
	})
}

// TestGCPEnvSurface 委託模式的**環境面**：只剩服務商一鍵，且不得長出憑證或
// 端點旋鈕。
//
// 原測試要求五個 KEK_* 鍵同時「登記於安全網、被產品碼消費、記載於範本」；
// 那三條在本次 change 之後只對 KEK_KMS_PROVIDER 成立，其餘五鍵的正確狀態是
// **不被消費**（由 TestRetiredDelegatedEnvKeysAreNotRead 承擔）。
func TestGCPEnvSurface(t *testing.T) {
	root := backendRoot(t)
	consumed := collectConsumedKeys(t, root)
	data, err := os.ReadFile(envExamplePath(t, root))
	if err != nil {
		t.Fatal(err)
	}
	documented := parseEnvExampleKeys(t, envExamplePath(t, root))
	for _, key := range []string{EnvKeyKEKProvider, EnvKeyKMSProvider} {
		if !slices.Contains(knownIndirectKeys, key) || !consumed[key] || !documented[key] {
			t.Fatalf("configuration registration missing: %s", key)
		}
	}
	// 憑證與端點永遠不是環境面的旋鈕：憑證只由解封頁進記憶體，端點改導是
	// 「把含明文材料的請求導向別處」的能力，產品不提供這個鍵。
	for key := range consumed {
		if strings.HasPrefix(key, "KEK_GCP_") || (strings.HasPrefix(key, "KEK_") && strings.Contains(key, "ENDPOINT")) {
			t.Fatal("product credential or endpoint surface added")
		}
	}
	for key := range documented {
		if strings.HasPrefix(key, "KEK_GCP_") || (strings.HasPrefix(key, "KEK_") && strings.Contains(key, "ENDPOINT")) {
			t.Fatal("product credential or endpoint declaration added")
		}
	}
	// 範本仍須說明服務商值域與 GCP 金鑰資源的完整形式——那兩件事沒有改變。
	// **原清單中的「Application Default Credentials (ADC)」一句已不再是本產品的
	// 行為**（憑證改為顯式注入，resolveADC 已由 resolveExplicit 取代），故不再
	// 要求它出現；範本本身的更新屬產品碼側的文件工作，不在測試檔的射程內。
	for _, phrase := range []string{"aws, vault, or gcp", "projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>"} {
		if !strings.Contains(string(data), phrase) {
			t.Fatal("GCP configuration explanation missing")
		}
	}
}
