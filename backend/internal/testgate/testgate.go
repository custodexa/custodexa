// Package testgate 提供整合測試的**單一 gating 入口**。
//
// 存在理由：以環境變數 gating 的整合
// 測試在 CI 上若變數未設，`t.Skip` 會讓整包測試「全綠」而該測試從未執行——
// 這正是本專案既有的假綠（CI 的 backend job 未設 TEST_PG_DSN，pg-lock／
// session-lock 測試自加入起就是永久 skip）。
//
// 解法是引入 **REQUIRE_INTEGRATION=1 語義：skip 一律轉 fail**，並於 CI 開啟。
// 設此值時，「gating 測試在 CI 沒跑」會是紅燈而非靜默。
//
// **為何是非測試套件**：三個以上的測試套件（internal/repository、
// internal/service、pkg/crypto/kms）需要同一份語義，各自複製一份就是漂移的溫床
// ——而漂移的後果正是本套件要消滅的假綠。本套件不被任何生產程式碼引用。
//
// 本套件消費的三個環境變數（REQUIRE_INTEGRATION／TEST_PG_DSN／TEST_KMS_ENDPOINT）
// 皆為測試專用，故列於 config/env_drift_test.go 的 driftAllowlist 而非 .env.example。
package testgate

import (
	"os"
	"testing"
)

// EnvRequireIntegration 設為 "1" 時，缺 gating 變數由 skip 轉為 fail
const EnvRequireIntegration = "REQUIRE_INTEGRATION"

// 各整合測試靶機的 gating 變數（單一事實源；CI 與 runbook 引用同一組字面）
const (
	// EnvPGDSN postgres 靶機 DSN
	EnvPGDSN = "TEST_PG_DSN"
	// EnvKMSEndpoint KMS 模擬器（localstack）端點
	EnvKMSEndpoint = "TEST_KMS_ENDPOINT"
	// EnvS3Endpoint S3 模擬器（localstack，SERVICES 含 s3）端點——
	// 離機儲存 s3 driver 的整合測試靶機（internal/offsite）
	EnvS3Endpoint = "TEST_S3_ENDPOINT"
	// EnvGCSEndpoint GCS 模擬器（fake-gcs-server）端點——
	// 離機儲存 gcs driver 的整合測試靶機（internal/offsite）
	EnvGCSEndpoint = "TEST_GCS_ENDPOINT"
)

// RequireIntegration 是否要求整合測試必須實際執行
func RequireIntegration() bool { return os.Getenv(EnvRequireIntegration) == "1" }

// Value 取得 gating 變數值。
//
//   - 有值 → 回傳該值，測試照跑；
//   - 無值且未要求整合 → t.Skip（本機 `go test ./...` 維持全綠）；
//   - 無值且 REQUIRE_INTEGRATION=1 → **t.Fatal**（CI 上的假綠變紅燈）。
//
// 回傳型別刻意不含 ok 旗標：呼叫端拿到值就是可以往下跑，
// 拿不到就已經被 Skip／Fatal 中止——不留「忘了判斷 ok」的縫隙。
func Value(t *testing.T, key string) string {
	t.Helper()
	if v := os.Getenv(key); v != "" {
		return v
	}
	if RequireIntegration() {
		t.Fatalf("%s 未設，但 %s=1 要求整合測試必須實際執行："+
			"請於 CI／compose 提供該靶機，或明確移除 %s",
			key, EnvRequireIntegration, EnvRequireIntegration)
	}
	t.Skipf("%s 未設，跳過整合測試（設 %s=1 可使此 skip 轉為失敗）", key, EnvRequireIntegration)
	return ""
}
