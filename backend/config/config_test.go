package config

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"reflect"
	"strings"
	"testing"
)

// TestDefaultSecretViolations 2.2.2：出廠預設密鑰偵測（release 啟動自檢依此 fail-close）
func TestDefaultSecretViolations(t *testing.T) {
	cases := []struct {
		name string
		jwt  string
		enc  string
		want []string
	}{
		{"全預設", DefaultJWTSecret, DefaultEncryptionKey, []string{"JWT_SECRET", "ENCRYPTION_KEY"}},
		{"僅 JWT 預設", DefaultJWTSecret, "a-real-32-byte-encryption-key-ok", []string{"JWT_SECRET"}},
		{"僅金鑰預設", "a-real-jwt-secret", DefaultEncryptionKey, []string{"ENCRYPTION_KEY"}},
		{"全部已改", "a-real-jwt-secret", "a-real-32-byte-encryption-key-ok", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &Config{Security: SecurityConfig{JWTSecret: c.jwt, EncryptionKey: c.enc}}
			// kek=nil＝未經 KEK 判定的舊呼叫形態（保守視為 env 模式，紅線不放寬）
			if got := cfg.DefaultSecretViolations(nil); !reflect.DeepEqual(got, c.want) {
				t.Errorf("DefaultSecretViolations() = %v, want %v", got, c.want)
			}
		})
	}
}

// TestDefaultSecretViolationsIsEncodingAgnostic PCI 2.2.2 出廠預設值閘的**編碼無關性**常設守衛
// （config.go 的 `DefaultSecretViolations` 兩處判定）。
//
// **為什麼需要一支專門的測試**：KEK 材料接受三種寫法之後，字串字面比對式的閘會被
// `hex(出廠預設值)` 與 `base64(出廠預設值)` 直接繞過——那些不是別的祕密，是同一把
// 出廠預設金鑰的不同寫法，解碼後逐位元組相同。此前該性質只靠「與材料驗證共用
// `validateDecodedKEK`」的靜態推論撐著，沒有任何測試會在它被改回字串比對時轉紅。
//
// 涵蓋兩條路徑：kek==nil（早期呼叫端，直接檢材料鍵原始讀值，config.go:374）與
// kek!=nil 且 env 模式（檢 KEK 判定結果攜帶的材料，config.go:387）。
//
// **反向對照組不可省**：若閘退化成「什麼都判違規」，只驗正向的測試照樣全綠。
func TestDefaultSecretViolationsIsEncodingAgnostic(t *testing.T) {
	// 非出廠預設的合法 32 位元組金鑰，供反向對照（與 TestDefaultSecretViolations 同值）
	const nonDefault = "a-real-32-byte-encryption-key-ok"
	// JWT 一律給非預設值，使違規清單只反映 KEK 這一格
	const realJWT = "a-real-jwt-secret"

	forms := []struct {
		name   string
		encode func(string) string
	}{
		{"原字元形態", func(s string) string { return s }},
		{"十六進位（小寫）", func(s string) string { return hex.EncodeToString([]byte(s)) }},
		{"十六進位（大寫）", func(s string) string { return strings.ToUpper(hex.EncodeToString([]byte(s))) }},
		{"base64（標準、有 padding）", func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }},
		{"base64（標準、無 padding）", func(s string) string { return base64.RawStdEncoding.EncodeToString([]byte(s)) }},
		{"base64（URL-safe、無 padding）", func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }},
		// 操作者把指令輸出直接貼進 .env 的實際形狀：結尾換行由解碼器 trim 掉，
		// 不得因此逃過本閘
		{"十六進位＋結尾換行", func(s string) string { return hex.EncodeToString([]byte(s)) + "\n" }},
	}

	wantKEKViolation := []string{EnvKeyEncryptionKey}
	for _, f := range forms {
		t.Run(f.name, func(t *testing.T) {
			bad := f.encode(DefaultEncryptionKey)

			// 路徑 1：kek==nil（保守視為 env 模式，讀 Security.EncryptionKey 原始值）
			cfg := &Config{Security: SecurityConfig{JWTSecret: realJWT, EncryptionKey: bad}}
			if got := cfg.DefaultSecretViolations(nil); !reflect.DeepEqual(got, wantKEKViolation) {
				t.Errorf("kek==nil：出廠預設值的「%s」寫法未被判為違規（got %v, want %v）——"+
					"該閘若退回字串字面比對即為此形態，PCI 2.2.2 紅線被繞過",
					f.name, got, wantKEKViolation)
			}

			// 路徑 2：kek!=nil 且 env 模式（讀判定結果攜帶的材料）
			d := &KEKDecision{Mode: KEKModeEnv, Material: bad, MaterialSource: EnvKeyEncryptionKey}
			cfgKEK := &Config{Security: SecurityConfig{JWTSecret: realJWT}}
			if got := cfgKEK.DefaultSecretViolations(d); !reflect.DeepEqual(got, wantKEKViolation) {
				t.Errorf("kek!=nil（env）：出廠預設值的「%s」寫法未被判為違規（got %v, want %v）",
					f.name, got, wantKEKViolation)
			}

			// 反向對照：非出廠預設的金鑰在**同一種寫法**下不得被誤判為違規
			ok := f.encode(nonDefault)
			cfgOK := &Config{Security: SecurityConfig{JWTSecret: realJWT, EncryptionKey: ok}}
			if got := cfgOK.DefaultSecretViolations(nil); got != nil {
				t.Errorf("kek==nil：非出廠預設金鑰的「%s」寫法被誤判為違規（got %v）——"+
					"閘若退化為「一律違規」，正向斷言會假綠", f.name, got)
			}
			dOK := &KEKDecision{Mode: KEKModeEnv, Material: ok, MaterialSource: EnvKeyEncryptionKey}
			if got := (&Config{Security: SecurityConfig{JWTSecret: realJWT}}).DefaultSecretViolations(dOK); got != nil {
				t.Errorf("kek!=nil（env）：非出廠預設金鑰的「%s」寫法被誤判為違規（got %v）", f.name, got)
			}
		})
	}
}

// TestIsReleaseMode 模式判定
func TestIsReleaseMode(t *testing.T) {
	if !(&Config{Server: ServerConfig{Mode: "release"}}).IsReleaseMode() {
		t.Error("release 應判為 release 模式")
	}
	for _, m := range []string{"debug", "test", ""} {
		if (&Config{Server: ServerConfig{Mode: m}}).IsReleaseMode() {
			t.Errorf("%q 不應判為 release 模式", m)
		}
	}
}

// TestParseCSV CORS allowlist 解析：去空白、去空項
func TestParseCSV(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"https://a.com", []string{"https://a.com"}},
		{"https://a.com, https://b.com ", []string{"https://a.com", "https://b.com"}},
		{" , ,https://a.com,,", []string{"https://a.com"}},
	}
	for _, c := range cases {
		if got := parseCSV(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseCSV(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestLoadDefaults 未設環境變數時的預設值（含出廠密鑰＝觸發 release 自檢的前提）。
// 顯式清空相關 env（docker 環境會注入 JWT_SECRET 等），確保測的是編譯內建預設
func TestLoadDefaults(t *testing.T) {
	for _, k := range []string{"JWT_SECRET", "ENCRYPTION_KEY", "CORS_ALLOWED_ORIGINS", "DB_DRIVER"} {
		old := os.Getenv(k)
		os.Unsetenv(k)
		t.Cleanup(func() {
			if old != "" {
				os.Setenv(k, old)
			}
		})
	}

	cfg := Load()
	if cfg.Security.JWTSecret != DefaultJWTSecret {
		t.Errorf("JWT 預設 = %q, want %q", cfg.Security.JWTSecret, DefaultJWTSecret)
	}
	if cfg.Server.CORSAllowedOrigins != nil {
		t.Errorf("CORS 未設應為 nil, got %v", cfg.Server.CORSAllowedOrigins)
	}
	// ENCRYPTION_KEY 的出廠預設值注入已廢除：
	// 未設即為空字串，由 DecideKEK 依矩陣列 2 fail-close，而非靜默使用公開已知材料。
	if cfg.Security.EncryptionKey != "" {
		t.Errorf("ENCRYPTION_KEY 未設時應為空字串（不得回落出廠預設值），got %q", cfg.Security.EncryptionKey)
	}
	// JWT_SECRET 仍保有出廠預設 → release 自檢仍偵測到該項違規
	if got := cfg.DefaultSecretViolations(nil); !reflect.DeepEqual(got, []string{"JWT_SECRET"}) {
		t.Errorf("出廠預設應僅偵測到 JWT_SECRET 違規, got %v", got)
	}
	// DB_DRIVER 亦無出廠預設值回落：未設即空字串，由 ValidateDatabaseDriver 拒絕啟動。
	// 舊值 "sqlite" 與「PostgreSQL 是唯一正式部署目標」矛盾，且會讓手動啟動靜默
	// 走進必崩的遷移路徑；本斷言即是防它被順手加回來的守衛
	if cfg.Database.Driver != "" {
		t.Errorf("DB_DRIVER 未設時應為空字串（不得回落任何預設驅動），got %q", cfg.Database.Driver)
	}
	if err := ValidateDatabaseDriver(cfg.Database.Driver); err == nil {
		t.Error("DB_DRIVER 未設時 ValidateDatabaseDriver 應回錯誤（fail-close），got nil")
	}
}

// TestValidateDatabaseDriver DB_DRIVER 的 fail-close 判定與訊息可操作性。
//
// 訊息斷言不是形式主義：本項的價值全在「操作者看到訊息後知不知道要做什麼」。
// 只斷言 err != nil 的版本，會讓「DB_DRIVER 未設定」這種等於沒說的訊息照樣通過。
func TestValidateDatabaseDriver(t *testing.T) {
	for _, d := range []string{DBDriverPostgres, DBDriverSQLite} {
		if err := ValidateDatabaseDriver(d); err != nil {
			t.Errorf("ValidateDatabaseDriver(%q) 應通過, got %v", d, err)
		}
	}
	for _, d := range []string{"", "mysql", "postgresql", "SQLite", " postgres"} {
		if err := ValidateDatabaseDriver(d); err == nil {
			t.Errorf("ValidateDatabaseDriver(%q) 應拒絕（fail-close）, got nil", d)
		}
	}

	// 缺值訊息須回答：該設什麼、compose 使用者為何不會遇到、為何不能改填 sqlite
	msg := ValidateDatabaseDriver("").Error()
	for _, want := range []string{"DB_DRIVER=" + DBDriverPostgres, "compose", DBDriverSQLite, "遷移"} {
		if !strings.Contains(msg, want) {
			t.Errorf("缺值訊息未包含 %q，操作者無從照做：%s", want, msg)
		}
	}
	// 不支援值的訊息須帶回原值，否則操作者不知道自己打錯的是哪個字
	if bad := ValidateDatabaseDriver("mysql").Error(); !strings.Contains(bad, "mysql") ||
		!strings.Contains(bad, DBDriverPostgres) {
		t.Errorf("不支援值訊息應同時含原值與正確值：%s", bad)
	}
}
