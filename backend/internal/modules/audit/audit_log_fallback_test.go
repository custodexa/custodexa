package audit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/custodexa/backend/config"
)

// TestResolveFallbackDir 驗證審計降級 fallback 目錄由 AUDIT_LOG_PATH 決定、
// 未設時退回內建相對路徑（audit-failure-alerting spec：降級 fallback 檔案持久化落地）。
func TestResolveFallbackDir(t *testing.T) {
	t.Run("未設時退回內建相對路徑", func(t *testing.T) {
		t.Setenv("AUDIT_LOG_PATH", "")
		want := filepath.Join("logs", "audit_fallback")
		if got := resolveFallbackDir(); got != want {
			t.Errorf("未設 AUDIT_LOG_PATH 應為 %q，得 %q", want, got)
		}
	})

	t.Run("設定時採用該持久化路徑", func(t *testing.T) {
		const persistent = "/var/log/custodexa/audit"
		t.Setenv("AUDIT_LOG_PATH", persistent)
		if got := resolveFallbackDir(); got != persistent {
			t.Errorf("設定 AUDIT_LOG_PATH 應採用 %q，得 %q", persistent, got)
		}
	})
}

// TestNewAuditLogServiceWiresFallbackDir 端到端驗證建構器將 AUDIT_LOG_PATH 接到
// fallbackDir 並於啟用檔案降級時建立該目錄（防接線退化）。
func TestNewAuditLogServiceWiresFallbackDir(t *testing.T) {
	target := filepath.Join(t.TempDir(), "audit")
	t.Setenv("AUDIT_LOG_PATH", target)

	// AsyncAuditEnabled=false 避免啟動 worker goroutine；僅驗建構期接線與建目錄。
	svc := NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled:     true,
		AuditFallbackToFile: true,
	})

	if svc.fallbackDir != target {
		t.Errorf("fallbackDir 應接自 AUDIT_LOG_PATH=%q，得 %q", target, svc.fallbackDir)
	}
	if fi, err := os.Stat(target); err != nil || !fi.IsDir() {
		t.Errorf("啟用 AuditFallbackToFile 時應建立 fallback 目錄 %q：err=%v", target, err)
	}
}

// TestNewAuditLogServiceRespectsFallbackDisabled 驗證關閉檔案降級時不建 fallback 目錄——
// 與 Log() 中 channel 滿載／DB 寫失敗分支的 AuditFallbackToFile 守衛語意一致。
func TestNewAuditLogServiceRespectsFallbackDisabled(t *testing.T) {
	target := filepath.Join(t.TempDir(), "audit")
	t.Setenv("AUDIT_LOG_PATH", target)

	NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled:     true,
		AuditFallbackToFile: false,
	})

	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("關閉 AuditFallbackToFile 時不應建立 fallback 目錄 %q（err=%v）", target, err)
	}
}
