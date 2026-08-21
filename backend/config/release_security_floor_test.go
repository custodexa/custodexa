package config

import (
	"sort"
	"testing"
)

// release 安全底線守衛（audit-release-floor，deployment-hardening spec
// 「release 安全底線不得由 feature flag 關閉」）。
//
// **守的是什麼**：`FEATURE_AUDIT_LOG_ENABLED=false` 曾可在 release 模式下靜默
// 關閉全操作審計——審計中間件不掛、`/audit-logs` 不註冊、寫入路徑短路，而稽核
// 工作台與檢查點驗證頁只會顯示「沒有事件」，與「這段期間確實沒人操作」同形。
// 同一段程式的權限旗標當時已有 release 強制，審計沒有。
//
// **為何測在 config 層**：強制邏輯原本內聯於 `runStage1`，而該函式含 `log.Fatalf`
// 與資料庫 I/O，測不動——缺陷能存活至今，一部分原因就是它埋在不可測的位置。
// 端到端後果（路由與中間件鏈）另由 cmd/server 的守衛涵蓋。

func floorTestConfig(mode string, audit bool) *Config {
	return &Config{
		Server: ServerConfig{Mode: mode},
		Features: FeatureFlags{
			AuditLogEnabled: audit,
			// 非底線成員：一併設為 false，斷言強制 SHALL NOT 波及它們
			AsyncAuditEnabled:       false,
			AuditFallbackToFile:     false,
			AnomalyDetectionEnabled: false,
			AlertingEnabled:         false,
		},
	}
}

// TestReleaseFloorForcesAudit release 模式下底線旗標即使被 env
// 設為 false 仍須實得 true，且回報的鍵名精確等於實際被強制者。
//
// 權限檢查已不在底線成員之列（security-backlog-settlement D5）：其開關本身已移除，
// 不存在可被強制的旗標。
func TestReleaseFloorForcesAudit(t *testing.T) {
	cfg := floorTestConfig("release", false)

	forced := cfg.EnforceReleaseSecurityFloor()

	if !cfg.Features.AuditLogEnabled {
		t.Error("release 模式 FEATURE_AUDIT_LOG_ENABLED=false 仍應被強制為 true：" +
			"全操作審計是安全紅線，可由環境變數靜默取消等於整條稽核鏈可被無聲關閉")
	}

	got := append([]string(nil), forced...)
	sort.Strings(got)
	want := []string{"FEATURE_AUDIT_LOG_ENABLED"}
	if len(got) != len(want) {
		t.Fatalf("回報的被強制鍵名數不符：實得 %v，預期 %v（鍵名要具名列入啟動日誌，"+
			"部署者必須看得見自己的停用設定被拒絕）", forced, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("回報鍵名不符：實得 %v，預期 %v", got, want)
			break
		}
	}
}

// TestReleaseFloorDoesNotTouchNonMembers 強制只作用於底線成員；有訊號的降級選擇
// （同步寫入、檔案降級關閉）與空旗標 SHALL NOT 被順手打開。
func TestReleaseFloorDoesNotTouchNonMembers(t *testing.T) {
	cfg := floorTestConfig("release", false)

	cfg.EnforceReleaseSecurityFloor()

	for _, c := range []struct {
		name string
		got  bool
	}{
		{"AsyncAuditEnabled", cfg.Features.AsyncAuditEnabled},
		{"AuditFallbackToFile", cfg.Features.AuditFallbackToFile},
		{"AnomalyDetectionEnabled", cfg.Features.AnomalyDetectionEnabled},
		{"AlertingEnabled", cfg.Features.AlertingEnabled},
	} {
		if c.got {
			t.Errorf("%s 不屬 release 安全底線（關閉時有訊號或不 gate 任何機制），"+
				"SHALL NOT 被強制開啟——擴大強制範圍等於改變部署者的合法選擇", c.name)
		}
	}
}

// TestReleaseFloorReportsOnlyActuallyForced 已為 true 的旗標不列入回報，
// 否則啟動日誌會對沒設過該鍵的部署者宣稱「你的停用設定已被忽略」。
func TestReleaseFloorReportsOnlyActuallyForced(t *testing.T) {
	cfg := floorTestConfig("release", false)

	forced := cfg.EnforceReleaseSecurityFloor()

	if len(forced) != 1 || forced[0] != "FEATURE_AUDIT_LOG_ENABLED" {
		t.Fatalf("只有實際被強制者應入回報：實得 %v，預期僅 FEATURE_AUDIT_LOG_ENABLED", forced)
	}

	clean := floorTestConfig("release", true)
	if got := clean.EnforceReleaseSecurityFloor(); len(got) != 0 {
		t.Errorf("旗標本就啟用時不應回報任何鍵名，實得 %v", got)
	}
}

// TestReleaseFloorLeavesNonReleaseUntouched 非 release 模式一律不動值。
//
// **這是雙向守衛的另一半**：dev 的可關閉性有數項現存依賴——路由 golden 的
// dev-auditoff 格、api-docs spec 的條件註冊 scenario、audit 服務層的「關閉即
// 靜默丟棄／回錯」單測，以及開發時降噪。把強制擴大到全模式會靜默廢掉它們，
// 故此處明確釘住，而非只測 release 那一半。
func TestReleaseFloorLeavesNonReleaseUntouched(t *testing.T) {
	for _, mode := range []string{"debug", "test", ""} {
		cfg := floorTestConfig(mode, false)

		forced := cfg.EnforceReleaseSecurityFloor()

		if len(forced) != 0 {
			t.Errorf("模式 %q 不應強制任何旗標，實得 %v", mode, forced)
		}
		if cfg.Features.AuditLogEnabled {
			t.Errorf("模式 %q 下旗標值被更動：audit=%v（非 release 模式須維持可關閉）",
				mode, cfg.Features.AuditLogEnabled)
		}
	}
}

// TestReleaseFloorMembership 底線清單的成員為契約，增刪皆須有意識地改本測試。
//
// 逐條斷言而非只數個數：刪掉審計成員再補一個無關鍵名，個數比對會通過。
func TestReleaseFloorMembership(t *testing.T) {
	members := releaseSecurityFloorMembers()
	got := make([]string, 0, len(members))
	for _, item := range members {
		got = append(got, item.EnvKey)
	}
	sort.Strings(got)

	want := []string{"FEATURE_AUDIT_LOG_ENABLED"}
	if len(got) != len(want) {
		t.Fatalf("底線成員數不符：實得 %v，預期 %v（新增成員請同步本清單與 "+
			"deployment-hardening spec）", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("底線成員不符：實得 %v，預期 %v", got, want)
		}
	}

	// 取址函式須真的指向對應欄位（登記錯欄位時，上方的鍵名比對仍會過）
	for _, item := range releaseSecurityFloorMembers() {
		f := FeatureFlags{}
		p := item.Field(&f)
		*p = true
		switch item.EnvKey {
		case "FEATURE_AUDIT_LOG_ENABLED":
			if !f.AuditLogEnabled {
				t.Errorf("%s 的取址函式未指向 AuditLogEnabled", item.EnvKey)
			}
		}
	}
}
