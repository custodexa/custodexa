package config

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// 委託組態的驗證面（Vault 分支）。
//
// **語義變更（委託拓撲與憑證改由介面管理）**：
// 原本這一檔驗的是「五個 KEK_* 環境變數齊備才准啟動」。該五鍵已自產品碼退場
// ——非秘密拓撲（位址、角色識別、區域、Transit 金鑰名）改由介面設定並持久化於
// 資料庫，秘密（角色密鑰／權杖／存取金鑰對／服務帳號金鑰檔）改由解封頁於每次
// 解封輸入，只存在於該解封世代的記憶體。環境只剩 KEK_KMS_PROVIDER 一鍵。
//
// 於是「齊備驗證」這條性質**沒有消失，只是換了位置與尺**：
// 自啟動期（讀 env）移到 provider 建構期（讀 ValidateKMSSettings 的欄位），
// 錯誤訊息改列欄位名常數而非環境變數鍵名。本檔照這個新位置重新表達它。

// 退場的五個環境變數鍵名。**只在測試檔內宣告**：產品碼不得再持有這些字面，
// 而測試需要它們正是為了斷言「產品碼不再讀它們」（見
// TestRetiredDelegatedEnvKeysAreNotRead）。
const (
	retiredEnvKMSKeyID      = "KEK_KMS_KEY_ID"
	retiredEnvKMSRegion     = "KEK_KMS_REGION"
	retiredEnvVaultAddr     = "KEK_VAULT_ADDR"
	retiredEnvVaultRoleID   = "KEK_VAULT_ROLE_ID"
	retiredEnvVaultSecretID = "KEK_VAULT_SECRET_ID"
)

func retiredDelegatedEnvKeys() []string {
	return []string{retiredEnvKMSKeyID, retiredEnvKMSRegion, retiredEnvVaultAddr,
		retiredEnvVaultRoleID, retiredEnvVaultSecretID}
}

// vaultConfigFixture 委託部署於**環境**中僅存的組態。
func vaultConfigFixture() map[string]string {
	return map[string]string{EnvKeyKEKProvider: KEKModeKMS, EnvKeyKMSProvider: "vault"}
}

// vaultSettingsFixture 一份齊備的 Vault 委託設定：拓撲取自資料庫、秘密取自
// 本解封世代。欄位值刻意可辨識，供「錯誤訊息不得回聲設定值」的斷言使用。
func vaultSettingsFixture() KMSSettings {
	s := KMSSettings{Provider: "vault", KeyID: "example-key"}
	s.Vault.Address = "https://vault.example"
	s.Vault.RoleID = "fixture-role"
	s.Vault.SecretID = "fixture-secret"
	return s
}

func vaultFixtureValues() []string {
	return []string{"example-key", "https://vault.example", "fixture-role", "fixture-secret", "fixture-token"}
}

func TestVaultKMSSettings(t *testing.T) {
	t.Run("startup-reads-provider-only", func(t *testing.T) {
		values := vaultConfigFixture()
		d, err := DecideKEK(MapEnvLookup(values), false)
		if err != nil {
			t.Fatal(err)
		}
		provider, err := KMSProviderFromEnv(MapEnvLookup(values))
		if err != nil || d.KMS.Provider != provider || d.MatrixRow != "9" {
			t.Fatal("readers disagree")
		}
		// 拓撲與秘密**不得**於啟動期出現在判定結果內：它們此刻還不存在
		//（資料庫未連線、解封世代未建立）。
		if !reflect.DeepEqual(d.KMS, KMSSettings{Provider: "vault"}) {
			t.Fatalf("startup decision carried topology or secrets: %+v", d.KMS)
		}
	})
	t.Run("startup-does-not-require-completeness", func(t *testing.T) {
		// **破壞性變更**：委託組態不齊不再是啟動失敗。齊備驗證延後到建構期，
		// 因為拓撲讀自資料庫、秘密來自解封世代，啟動期兩者皆不可得。
		values := vaultConfigFixture()
		d, err := DecideKEK(MapEnvLookup(values), false)
		if err != nil || d.Mode != KEKModeKMS {
			t.Fatal("delegated startup refused without topology or secrets")
		}
		// 而同一份設定在建構期仍被擋下——性質沒有放寬，只是換了位置。
		if err := ValidateKMSSettings(d.KMS); err == nil {
			t.Fatal("construction accepted an empty delegated configuration")
		}
	})
	t.Run("complete-settings-accepted", func(t *testing.T) {
		if err := ValidateKMSSettings(vaultSettingsFixture()); err != nil {
			t.Fatalf("complete Vault settings refused: %v", err)
		}
		byToken := vaultSettingsFixture()
		byToken.Vault.RoleID, byToken.Vault.SecretID = "", ""
		byToken.Vault.Token = "fixture-token"
		if err := ValidateKMSSettings(byToken); err != nil {
			t.Fatalf("direct token path refused: %v", err)
		}
	})
	for _, missing := range []struct {
		field string
		strip func(*KMSSettings)
	}{
		{FieldKMSKeyID, func(s *KMSSettings) { s.KeyID = "" }},
		{FieldKMSKeyID, func(s *KMSSettings) { s.KeyID = " \t " }},
		{FieldVaultAddress, func(s *KMSSettings) { s.Vault.Address = "" }},
		{FieldVaultAddress, func(s *KMSSettings) { s.Vault.Address = " \t " }},
		{FieldVaultRoleID, func(s *KMSSettings) { s.Vault.RoleID = "" }},
		{FieldVaultSecretID, func(s *KMSSettings) { s.Vault.SecretID = "" }},
		{FieldVaultSecretID, func(s *KMSSettings) { s.Vault.SecretID = " \t " }},
	} {
		t.Run("missing-"+missing.field, func(t *testing.T) {
			s := vaultSettingsFixture()
			missing.strip(&s)
			err := ValidateKMSSettings(s)
			if err == nil || !strings.Contains(err.Error(), missing.field) {
				t.Fatalf("missing configuration accepted or not identified: %v", err)
			}
			for _, value := range vaultFixtureValues() {
				if strings.Contains(err.Error(), value) {
					t.Fatal("configuration value leaked")
				}
			}
		})
	}
	t.Run("role-and-token-exactly-one", func(t *testing.T) {
		// 角色路徑與權杖路徑**恰一**：皆無即缺憑證，皆有即組態矛盾。
		// 不做優先序猜測——猜錯的後果是「以為用短期權杖，實際走了長壽命的那條」。
		both := vaultSettingsFixture()
		both.Vault.Token = "fixture-token"
		err := ValidateKMSSettings(both)
		if err == nil || !strings.Contains(err.Error(), FieldVaultSecretID) {
			t.Fatalf("ambiguous credential accepted: %v", err)
		}
		for _, value := range vaultFixtureValues() {
			if strings.Contains(err.Error(), value) {
				t.Fatal("configuration value leaked")
			}
		}
		none := vaultSettingsFixture()
		none.Vault.SecretID = ""
		if err := ValidateKMSSettings(none); err == nil || !strings.Contains(err.Error(), FieldVaultSecretID) {
			t.Fatalf("credential-free deployment accepted: %v", err)
		}
	})
	t.Run("unknown-provider-redacted", func(t *testing.T) {
		values := vaultConfigFixture()
		values[EnvKeyKMSProvider] = "do-not-echo-provider"
		for _, read := range []func() error{
			func() error { _, e := KMSProviderFromEnv(MapEnvLookup(values)); return e },
			func() error { _, e := DecideKEK(MapEnvLookup(values), false); return e },
		} {
			err := read()
			if err == nil || strings.Contains(err.Error(), values[EnvKeyKMSProvider]) {
				t.Fatal("unknown provider accepted or leaked")
			}
		}
		s := vaultSettingsFixture()
		s.Provider = "do-not-echo-provider"
		if err := ValidateKMSSettings(s); err == nil || !strings.Contains(err.Error(), FieldKMSProvider) {
			t.Fatalf("unknown provider accepted at construction: %v", err)
		}
	})
	t.Run("missing-provider-key", func(t *testing.T) {
		for _, empty := range []string{"", " \t "} {
			values := vaultConfigFixture()
			values[EnvKeyKMSProvider] = empty
			_, directErr := KMSProviderFromEnv(MapEnvLookup(values))
			_, decisionErr := DecideKEK(MapEnvLookup(values), false)
			for _, err := range []error{directErr, decisionErr} {
				if err == nil || !strings.Contains(err.Error(), EnvKeyKMSProvider) {
					t.Fatal("missing provider accepted or not identified")
				}
			}
		}
	})
	t.Run("aws-requires-region-and-access-keys", func(t *testing.T) {
		s := vaultSettingsFixture()
		s.Provider = "aws"
		s.Vault = VaultSettings{}
		err := ValidateKMSSettings(s)
		if err == nil {
			t.Fatal("AWS settings accepted without region or access keys")
		}
		for _, field := range []string{FieldKMSRegion, FieldAWSAccessKeyID, FieldAWSSecretAccessKey} {
			if !strings.Contains(err.Error(), field) {
				t.Fatalf("AWS requirement %s was made optional: %v", field, err)
			}
		}
	})
	t.Run("local-material-refused", func(t *testing.T) {
		values := vaultConfigFixture()
		values[EnvKeyEncryptionKey] = "fixture-local-material"
		_, err := DecideKEK(MapEnvLookup(values), false)
		if err == nil || !strings.Contains(err.Error(), "[列 7]") || strings.Contains(err.Error(), values[EnvKeyEncryptionKey]) {
			t.Fatal("local material guard failed")
		}
	})
}

// TestRetiredDelegatedEnvKeysAreNotRead 五個委託鍵的**退場**本身是驗收條件。
//
// 原測試（TestVaultSecretPlaceholders）守的是「範本必須有這三個鍵的空註解佔位、
// 且產品碼確實消費它們」。退場後該性質反轉：這些鍵**不得再成為任何組態的來源**
// ——若有人為了讓某條路徑「省事」而把任一鍵接回讀取路徑，部署就會重新擁有一條
// 繞過介面設定與解封輸入的來源，本測試即紅。
//
// **唯一的例外已知且經過審視**：升級時把舊 `.env` 的非秘密值一次性搬進資料庫的
// `cmd/server/kek_topology_import.go`。它以區域變數傳鍵、不走本守衛認得的
// env 讀取函式，故本掃描看不到它；那條路徑讀入之後即忽略環境，且不讀秘密鍵。
// 本格守的是「除此之外沒有第二個讀取點」。
//
// **掃描刻意不經 collectConsumedKeys**：後者會把 knownIndirectKeys 併入結果，
// 而那份安全網正是本測試要檢查的對象之外的東西——併進來會讓「已登記」看起來
// 像「仍被消費」，守衛因此永遠不可能紅（假綠的典型形態）。
func TestRetiredDelegatedEnvKeysAreNotRead(t *testing.T) {
	root := backendRoot(t)
	consumed := consumedKeysFromSource(t, root)
	for _, key := range retiredDelegatedEnvKeys() {
		if consumed[key] {
			t.Fatalf("retired delegated key is read by product code again: %s", key)
		}
	}
	// 仍在使用的兩鍵必須留在掃描結果內，否則上一段只是掃了個空集合。
	for _, key := range []string{EnvKeyKEKProvider, EnvKeyEncryptionKey} {
		if !consumed[key] && !containsKnownIndirect(key) {
			t.Fatalf("live key vanished from the scan: %s", key)
		}
	}
}

// TestDelegatedProviderDeclarationIsDrift 漂移守衛的控制組：範本少了一條宣告
// 就必須紅。原控制組以 KEK_VAULT_SECRET_ID 為對象，該鍵已退場，改由委託模式
// **唯一仍由部署檔宣告**的鍵承擔同一條控制。
func TestDelegatedProviderDeclarationIsDrift(t *testing.T) {
	root := backendRoot(t)
	data, err := os.ReadFile(envExamplePath(t, root))
	if err != nil {
		t.Fatal(err)
	}
	altered := strings.Replace(string(data), "# "+EnvKeyKMSProvider+"=\n", "", 1)
	if altered == string(data) {
		t.Fatalf("範本已不含 %s 的空註解佔位：控制組失去對象", EnvKeyKMSProvider)
	}
	path := filepath.Join(t.TempDir(), "example")
	if err := os.WriteFile(path, []byte(altered), 0600); err != nil {
		t.Fatal(err)
	}
	missing := missingDocumentedKeys(collectConsumedKeys(t, root), parseEnvExampleKeys(t, path))
	if len(missing) != 1 || missing[0] != EnvKeyKMSProvider {
		t.Fatalf("removed declaration did not trigger the drift guard: %v", missing)
	}
}

func containsKnownIndirect(key string) bool {
	for _, k := range knownIndirectKeys {
		if k == key {
			return true
		}
	}
	return false
}

// consumedKeysFromSource 只掃產品碼的 AST，不併入任何安全網登記。
func consumedKeysFromSource(t *testing.T, root string) map[string]bool {
	t.Helper()
	keys := map[string]bool{}
	scanned := 0
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case "vendor", "testdata", "scripts", ".git":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if perr != nil {
			return perr
		}
		scanned++
		collectKeysFromAST(f, keys)
		return nil
	})
	if err != nil {
		t.Fatalf("掃描 backend 失敗: %v", err)
	}
	if scanned < minEnvDriftScannedFiles {
		t.Fatalf("只掃到 %d 個非測試 .go（下限 %d）：掃描範圍已失真", scanned, minEnvDriftScannedFiles)
	}
	return keys
}
