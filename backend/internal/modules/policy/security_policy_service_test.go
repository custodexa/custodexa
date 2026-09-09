package policy

import (
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupPolicyDB(t *testing.T) (*SecurityPolicyService, *gorm.DB) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.SecurityPolicy{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewSecurityPolicyService(db), db
}

func TestPolicyDefaultsWhenNoRows(t *testing.T) {
	svc, _ := setupPolicyDB(t)

	if got := svc.GetInt(PolicyLockoutMaxAttempts); got != 10 {
		t.Errorf("lockout_max_attempts 預設 = %d, want 10", got)
	}
	if got := svc.GetInt(PolicyPasswordMinLength); got != 12 {
		t.Errorf("password_min_length 預設 = %d, want 12", got)
	}
	if !svc.GetBool(PolicyPasswordRequireAlnum) {
		t.Error("password_require_alnum 預設應為 true")
	}
	if !svc.GetBool(PolicyForceChangeOnReset) {
		t.Error("force_change_on_reset 預設應為 true")
	}
}

func TestPolicyUpdateInvalidatesCacheImmediately(t *testing.T) {
	svc, _ := setupPolicyDB(t)

	// 先讀一次讓值進快取
	if got := svc.GetInt(PolicyLockoutMaxAttempts); got != 10 {
		t.Fatalf("初值 = %d", got)
	}

	old, err := svc.Update(PolicyLockoutMaxAttempts, "5", "admin")
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if old != "10" {
		t.Errorf("舊值 = %s, want 10", old)
	}

	// 更新即失效：TTL 內立即讀到新值（task 8.1 政策快取失效行為）
	if got := svc.GetInt(PolicyLockoutMaxAttempts); got != 5 {
		t.Errorf("更新後 = %d, want 5（快取未失效）", got)
	}
}

func TestPolicyCacheServesWithinTTL(t *testing.T) {
	svc, db := setupPolicyDB(t)
	svc.cacheTTL = time.Hour

	if got := svc.GetInt(PolicyPasswordHistoryCount); got != 4 {
		t.Fatalf("初值 = %d", got)
	}

	// 繞過 service 直改 DB：TTL 內應仍回快取舊值（證明快取真的在用）
	db.Save(&model.SecurityPolicy{Key: PolicyPasswordHistoryCount, Value: "8", UpdatedBy: "raw"})
	if got := svc.GetInt(PolicyPasswordHistoryCount); got != 4 {
		t.Errorf("TTL 內 = %d, want 4（快取被繞過）", got)
	}

	// TTL 過期後讀到 DB 新值
	svc.mu.Lock()
	svc.cache = map[string]policyCacheEntry{}
	svc.mu.Unlock()
	if got := svc.GetInt(PolicyPasswordHistoryCount); got != 8 {
		t.Errorf("快取清空後 = %d, want 8", got)
	}
}

func TestPolicyUpdateValidation(t *testing.T) {
	svc, _ := setupPolicyDB(t)

	if _, err := svc.Update("nonexistent_key", "1", "admin"); !errors.Is(err, ErrPolicyUnknownKey) {
		t.Errorf("未知鍵 = %v, want ErrPolicyUnknownKey", err)
	}
	if _, err := svc.Update(PolicyLockoutMaxAttempts, "abc", "admin"); !errors.Is(err, ErrPolicyInvalidValue) {
		t.Errorf("非數字 = %v, want ErrPolicyInvalidValue", err)
	}
	if _, err := svc.Update(PolicyLockoutMaxAttempts, "-1", "admin"); !errors.Is(err, ErrPolicyInvalidValue) {
		t.Errorf("負數 = %v, want ErrPolicyInvalidValue", err)
	}
	// lockout_duration_minutes 非 ZeroDisables：0 不合法
	if _, err := svc.Update(PolicyLockoutDurationMinutes, "0", "admin"); !errors.Is(err, ErrPolicyInvalidValue) {
		t.Errorf("非 sentinel 欄位設 0 = %v, want ErrPolicyInvalidValue", err)
	}
	// lockout_max_attempts 是 ZeroDisables：0 合法（=停用）
	if _, err := svc.Update(PolicyLockoutMaxAttempts, "0", "admin"); err != nil {
		t.Errorf("sentinel 欄位設 0 = %v, want nil", err)
	}
	if _, err := svc.Update(PolicyPasswordRequireAlnum, "yes", "admin"); !errors.Is(err, ErrPolicyInvalidValue) {
		t.Errorf("bool 非 true/false = %v, want ErrPolicyInvalidValue", err)
	}
	// LOCK-1：超上界的整數被拒（防 int64 溢位——lockout_duration Max=10080）
	if _, err := svc.Update(PolicyLockoutDurationMinutes, "200000000", "admin"); !errors.Is(err, ErrPolicyInvalidValue) {
		t.Errorf("溢位級數字 = %v, want ErrPolicyInvalidValue", err)
	}
	if _, err := svc.Update(PolicyLockoutDurationMinutes, "10081", "admin"); !errors.Is(err, ErrPolicyInvalidValue) {
		t.Errorf("超 Max = %v, want ErrPolicyInvalidValue", err)
	}
	if _, err := svc.Update(PolicyLockoutDurationMinutes, "10080", "admin"); err != nil {
		t.Errorf("等於 Max = %v, want nil", err)
	}
}

// TestPolicyDefsSelfCheck 常數表自檢：真常數表應通過；打錯字的表應被抓
func TestPolicyDefsSelfCheck(t *testing.T) {
	if err := validatePolicyDefs(); err != nil {
		t.Fatalf("正式常數表自檢應通過，got %v", err)
	}

	// 手工構造：enum 出廠值打錯字（非 EnumOrder 成員）→ 自檢應抓到。
	// 出廠值不在枚舉序內時，值域驗證與判定都會以一個不存在的值為起點
	orig := policyDefs
	t.Cleanup(func() { policyDefs = orig })
	policyDefs = []PolicyDef{{
		Key: "enum_default_typo_probe", Type: PolicyTypeEnum, Default: "ALL",
		EnumOrder: []string{"off", "admin_only", "all"}, Label: "探針",
	}}
	if err := validatePolicyDefs(); err == nil {
		t.Error("出廠值不在 EnumOrder 內應被自檢擋下")
	}
	policyDefs[0].Default = "all"
	if err := validatePolicyDefs(); err != nil {
		t.Errorf("改回合法枚舉值後應通過, got %v", err)
	}
}

// newSeededComplianceStack 一個寫入兩個內建組的記憶體庫上的政策服務與合規服務。
func newSeededComplianceStack(t *testing.T) (*SecurityPolicyService, *ComplianceService) {
	t.Helper()
	svc, db := setupPolicyDB(t)
	if err := db.AutoMigrate(&model.PolicyGroup{}, &model.PolicyClause{},
		&model.PolicyClauseControl{}, &model.PolicyClauseAnnotation{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := SeedBuiltinPolicyGroups(db); err != nil {
		t.Fatalf("內建組種子: %v", err)
	}
	return svc, NewComplianceService(svc, NewPolicyGroupRepository(db))
}

// TestUpdateBatchTransactional 批次更新原子性＋審計回報僅含有變動者
func TestUpdateBatchTransactional(t *testing.T) {
	svc, _ := setupPolicyDB(t)

	// 一項有效、一項無效 → 整批拒絕，無任何一項落庫
	_, err := svc.UpdateBatch(map[string]string{
		PolicyLockoutMaxAttempts: "5",
		PolicyPasswordMinLength:  "abc", // 非法
	}, "admin")
	if !errors.Is(err, ErrPolicyInvalidValue) {
		t.Fatalf("含非法項 = %v, want ErrPolicyInvalidValue", err)
	}
	if svc.GetInt(PolicyLockoutMaxAttempts) != 10 {
		t.Errorf("整批應回滾，lockout 仍為預設 10，got %d", svc.GetInt(PolicyLockoutMaxAttempts))
	}

	// 全有效：回報僅含有變動者（min_length 12→12 無變動不回報）
	changes, err := svc.UpdateBatch(map[string]string{
		PolicyLockoutMaxAttempts: "5",  // 10→5 有變動
		PolicyPasswordMinLength:  "12", // 12→12 無變動
	}, "admin")
	if err != nil {
		t.Fatalf("批次更新: %v", err)
	}
	if len(changes) != 1 || changes[0].Key != PolicyLockoutMaxAttempts ||
		changes[0].OldValue != "10" || changes[0].NewValue != "5" {
		t.Errorf("變更回報 = %+v, want 僅 lockout 10→5", changes)
	}
	if svc.GetInt(PolicyLockoutMaxAttempts) != 5 {
		t.Errorf("更新後 = %d, want 5", svc.GetInt(PolicyLockoutMaxAttempts))
	}
}

// factoryPCIDeviations 出廠預設對 PCI 組的偏離鍵數。
// 逐鍵清單見 TestPolicyComplianceComparator 的三張表；出廠值改動或組內要求
// 增減時這個數字必須被有意識地同步
const factoryPCIDeviations = 15

// TestPolicyComplianceComparator 比較器：0=停用 sentinel 先判偏離、至少／至多方向、開關、枚舉
func TestPolicyComplianceComparator(t *testing.T) {
	svc, cs := newSeededComplianceStack(t)

	pciVerdict := func(key string) string {
		t.Helper()
		snap, err := cs.Snapshot("", nil)
		if err != nil {
			t.Fatalf("判定: %v", err)
		}
		return verdictResult(snap, key, pciGroupCode)
	}
	pciDeviations := func() int {
		t.Helper()
		snap, err := cs.Snapshot("", nil)
		if err != nil {
			t.Fatalf("判定: %v", err)
		}
		return snap.GroupDeviationCount(pciGroupCode)
	}

	// 出廠預設（易用取向的刻意偏離）對 PCI 組的逐鍵判定。
	// **四張表加「其餘皆符合」**：漏列一個鍵時最後那一條會紅，
	// 而不是靜默把新鍵當成已經合規
	factoryDeviations := map[string]bool{
		PolicyAccessPolicyDefault:         true,
		PolicyAccessRevokeDisconnect:      true,
		PolicyDailyReviewEnabled:          true,
		PolicyFailureAlertEnabled:         true,
		PolicyInactiveDisableDays:         true,
		PolicyKeyCryptoperiodReminderDays: true,
		PolicyMFARequired:                 true,
		PolicyPasswordMaxAgeDays:          true,
		PolicyRecordingFailCloseEnabled:   true,
		PolicyRetentionAlertDays:          true,
		PolicyRetentionAuditLogDays:       true,
		PolicyRetentionRecordingDays:      true,
		PolicyRetentionSessionCommandDays: true,
		PolicySessionIdleMinutes:          true,
		PolicyWebIdleMinutes:              true,
	}
	// 條文有涉及這個鍵但沒有給定值：列出目前值由稽核人員判讀
	pendingAuditReview := map[string]bool{
		PolicyTransportDBLevel:     true,
		PolicyTransportLDAPLevel:   true,
		PolicyTransportNotifyLevel: true,
		PolicyTransportRDPLevel:    true,
		PolicyTransportSyslogLevel: true,
		PolicyTransportVNCLevel:    true,
	}
	// 條文給的是參考值而非明定值，機構尚未確認
	pendingConfirmation := map[string]bool{
		PolicyAssetSecretMaxAgeDays: true,
	}
	// 本組沒有對照這個鍵：不產生判定（見各鍵定義處的排除理由）
	notMapped := map[string]bool{
		PolicyAccessRequestMaxDurationMinutes:  true,
		PolicyAccessRequestMinApprovals:        true,
		PolicyAccessRequestPendingTimeoutHours: true,
		PolicyAuditChainRecentVerifyDays:       true,
		PolicyAuditChainVerifyIntervalSeconds:  true,
		PolicyAuditChainVerifyRowsPerHour:      true,
		PolicyAuditCheckpointIntervalSeconds:   true,
		PolicyAuditCheckpointRowThreshold:      true,
		PolicyClipboardRecvEnabled:             true,
		PolicyClipboardSendEnabled:             true,
		PolicyFileDeleteEnabled:                true,
		PolicyFileDownloadEnabled:              true,
		PolicyFileUploadEnabled:                true,
		PolicyK8sListTimeoutSeconds:            true,
		PolicyKeyRotationMaxPerRun:             true,
		PolicyLoginBannerBody:                  true,
		PolicyLoginBannerTitle:                 true,
		PolicyOffsiteLocalRetentionDays:        true,
		PolicyRefreshCookieSecure:              true,
		PolicyRetentionCheckpointDays:          true,
		PolicyRetentionMaxPerRun:               true,
		PolicySessionMaxMinutes:                true,
		PolicyTransportConsentTTLDays:          true,
		PolicyWebMaxSessionHours:               true,
	}
	snap, err := cs.Snapshot("", nil)
	if err != nil {
		t.Fatalf("判定: %v", err)
	}
	for _, def := range policyDefs {
		got := verdictResult(snap, def.Key, pciGroupCode)
		want := ComplianceResultCompliant
		switch {
		case factoryDeviations[def.Key]:
			want = ComplianceResultDeviating
		case pendingAuditReview[def.Key]:
			want = ComplianceResultAuditReview
		case pendingConfirmation[def.Key]:
			want = ComplianceResultNeedsReview
		case notMapped[def.Key]:
			want = ""
		}
		if got != want {
			t.Errorf("%s 出廠判定 = %q, want %q", def.Key, got, want)
		}
	}
	if got := snap.GroupDeviationCount(pciGroupCode); got != factoryPCIDeviations {
		t.Errorf("出廠偏離數 = %d, want %d", got, factoryPCIDeviations)
	}

	// 0=停用：即使 0 <= 10 也必須判偏離（sentinel 先判）
	if _, err := svc.Update(PolicyLockoutMaxAttempts, "0", "admin"); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got := pciVerdict(PolicyLockoutMaxAttempts); got != ComplianceResultDeviating {
		t.Errorf("鎖定停用（0）判定 = %s, want %s", got, ComplianceResultDeviating)
	}

	// 至多型：值 <= 要求為符合（8 次比 10 次更嚴）
	svc.Update(PolicyLockoutMaxAttempts, "8", "admin")
	if got := pciVerdict(PolicyLockoutMaxAttempts); got != ComplianceResultCompliant {
		t.Errorf("8 次（更嚴）判定 = %s, want %s", got, ComplianceResultCompliant)
	}
	svc.Update(PolicyLockoutMaxAttempts, "15", "admin")
	if got := pciVerdict(PolicyLockoutMaxAttempts); got != ComplianceResultDeviating {
		t.Errorf("15 次（放寬）判定 = %s, want %s", got, ComplianceResultDeviating)
	}

	// 至少型：值 >= 要求為符合
	svc.Update(PolicyPasswordMinLength, "8", "admin")
	if got := pciVerdict(PolicyPasswordMinLength); got != ComplianceResultDeviating {
		t.Errorf("長度 8（放寬）判定 = %s, want %s", got, ComplianceResultDeviating)
	}
	svc.Update(PolicyPasswordMinLength, "16", "admin")
	if got := pciVerdict(PolicyPasswordMinLength); got != ComplianceResultCompliant {
		t.Errorf("長度 16（更嚴）判定 = %s, want %s", got, ComplianceResultCompliant)
	}

	// 開關型
	svc.Update(PolicyPasswordRequireAlnum, "false", "admin")
	if got := pciVerdict(PolicyPasswordRequireAlnum); got != ComplianceResultDeviating {
		t.Errorf("關閉字母數字要求判定 = %s, want %s", got, ComplianceResultDeviating)
	}

	// 偏離：lockout=15（放寬）＋require_alnum=false＋出廠偏離
	if got, want := pciDeviations(), factoryPCIDeviations+2; got != want {
		t.Errorf("偏離數 = %d, want %d（lockout 放寬＋alnum 關＋%d 項出廠偏離）",
			got, want, factoryPCIDeviations)
	}
}

// TestPolicyEnumComparator 枚舉比較器：要求是明確值，只有相等才算達到
func TestPolicyEnumComparator(t *testing.T) {
	def := &PolicyDef{
		Key: "test_enum", Type: PolicyTypeEnum,
		EnumOrder: []string{"off", "admin_only", "all"},
	}
	equals := model.PolicyControlComparatorEquals
	if ok, _ := compareExpectation(def, "off", equals, "all"); ok {
		t.Error("off 不等於 all 應不符")
	}
	if ok, _ := compareExpectation(def, "admin_only", equals, "all"); ok {
		t.Error("admin_only 不等於 all 應不符")
	}
	if ok, _ := compareExpectation(def, "all", equals, "all"); !ok {
		t.Error("all 等於 all 應符合")
	}
	if ok, _ := compareExpectation(def, "bogus", equals, "all"); ok {
		t.Error("未知枚舉值應不符")
	}
}

// TestPolicyKeyWithoutRequirementSkipsVerdict 沒有任何一組對照的鍵不產生判定，
// 而是列進「未對照」的分母
func TestPolicyKeyWithoutRequirementSkipsVerdict(t *testing.T) {
	defs := []PolicyDef{{Key: "no_requirement", Type: PolicyTypeInt,
		Direction: DirectionMin, Default: "999", Max: 1000}}
	groups := []model.PolicyGroup{
		{Code: pciGroupCode, Source: model.PolicyGroupSourceBuiltin, Enabled: true},
	}
	snap := BuildSnapshot(defs, map[string]string{"no_requirement": "999"},
		nil, groups, nil, nil, nil)
	if got := verdictResult(snap, "no_requirement", pciGroupCode); got != "" {
		t.Errorf("無要求的鍵對 %s 組產生了判定 %q", pciGroupCode, got)
	}
	if len(snap.UnmappedKeys) != 1 || snap.UnmappedKeys[0] != "no_requirement" {
		t.Errorf("未對照鍵 = %v, want [no_requirement]", snap.UnmappedKeys)
	}
}

// TestSeedFromEnv env 初始化：僅在 DB 無列時寫入、非法值忽略、顯式設定不被覆蓋
func TestSeedFromEnv(t *testing.T) {
	t.Run("env 值初始化政策列", func(t *testing.T) {
		svc, _ := setupPolicyDB(t)
		t.Setenv("TEST_SSH_IDLE", "30")
		svc.SeedFromEnv(PolicySessionIdleMinutes, "TEST_SSH_IDLE")
		if got := svc.GetInt(PolicySessionIdleMinutes); got != 30 {
			t.Errorf("GetInt = %d, want 30（env 初始化）", got)
		}
	})

	t.Run("env 未設維持出廠預設", func(t *testing.T) {
		svc, _ := setupPolicyDB(t)
		svc.SeedFromEnv(PolicySessionIdleMinutes, "TEST_UNSET_ENV_KEY")
		if got := svc.GetInt(PolicySessionIdleMinutes); got != 60 {
			t.Errorf("GetInt = %d, want 60（出廠預設）", got)
		}
	})

	t.Run("顯式設定不被 env 覆蓋", func(t *testing.T) {
		svc, _ := setupPolicyDB(t)
		svc.Update(PolicySessionIdleMinutes, "15", "admin")
		t.Setenv("TEST_SSH_IDLE", "120")
		svc.SeedFromEnv(PolicySessionIdleMinutes, "TEST_SSH_IDLE")
		if got := svc.GetInt(PolicySessionIdleMinutes); got != 15 {
			t.Errorf("GetInt = %d, want 15（admin 設定優先）", got)
		}
	})

	t.Run("非法 env 值忽略", func(t *testing.T) {
		svc, _ := setupPolicyDB(t)
		t.Setenv("TEST_SSH_IDLE", "not-a-number")
		svc.SeedFromEnv(PolicySessionIdleMinutes, "TEST_SSH_IDLE")
		if got := svc.GetInt(PolicySessionIdleMinutes); got != 60 {
			t.Errorf("GetInt = %d, want 60（非法值沿用預設）", got)
		}
	})
}

// --- refresh cookie Secure 政策鍵（決策 8）---

// TestRefreshCookieSecureDefaultsToTrue 出廠預設＝安全側。
//
// **這一格是 fallback 方向的最終防線**：政策 DB 讀不到或該鍵無列時，
// Get 都退回出廠預設，故出廠值一旦翻成 false，所有「讀不到」的情境都會靜默
// 發出不帶 Secure 的 cookie。
func TestRefreshCookieSecureDefaultsToTrue(t *testing.T) {
	svc, _ := setupPolicyDB(t)

	if !svc.GetBool(PolicyRefreshCookieSecure) {
		t.Error("refresh_cookie_secure 出廠預設 = false：政策不可讀時會靜默失去傳輸保護")
	}
	for _, v := range svc.List() {
		if v.Key != PolicyRefreshCookieSecure {
			continue
		}
		if v.Type != PolicyTypeBool {
			t.Errorf("Type = %q, want %q", v.Type, PolicyTypeBool)
		}
		if reqs := builtinSeedRequirements(t, PolicyRefreshCookieSecure); len(reqs) != 0 {
			t.Errorf("不得被內建組掛上要求（%v）：本鍵取值由部署對外協定決定，"+
				"掛一條要求會讓「一次滿足所有政策」把明文部署翻成開啟＝整站續期失敗", reqs)
		}
		return
	}
	t.Fatal("List 未含 refresh_cookie_secure")
}

// TestSeedValue 值播種：僅在無列時寫入、非法值忽略、**政策頁設定過的值永不被覆蓋**。
func TestSeedValue(t *testing.T) {
	t.Run("無列時寫入並記為播種來源", func(t *testing.T) {
		svc, _ := setupPolicyDB(t)
		svc.SeedValue(PolicyRefreshCookieSecure, "false", "PUBLIC_BASE_URL 的 scheme")
		if svc.GetBool(PolicyRefreshCookieSecure) {
			t.Error("播種值 false 未生效")
		}
		if got := svc.ValueSource(PolicyRefreshCookieSecure); got != PolicySourceSeed {
			t.Errorf("ValueSource = %q, want %q", got, PolicySourceSeed)
		}
	})

	t.Run("政策頁設定過的值不被播種覆蓋", func(t *testing.T) {
		svc, _ := setupPolicyDB(t)
		if _, err := svc.Update(PolicyRefreshCookieSecure, "false", "admin"); err != nil {
			t.Fatalf("admin 設定: %v", err)
		}
		// 重啟後以相反的部署組態再播一次：管理員的線上修正不得被悄悄改回
		svc.SeedValue(PolicyRefreshCookieSecure, "true", "AUTH_REFRESH_COOKIE_SECURE=true")
		if svc.GetBool(PolicyRefreshCookieSecure) {
			t.Error("播種覆蓋了管理端設定值：管理員在政策頁的修正會在下次重啟被部署檔推翻")
		}
		if got := svc.ValueSource(PolicyRefreshCookieSecure); got != PolicySourceAdmin {
			t.Errorf("ValueSource = %q, want %q（來源被播種改寫等於歸因說謊）", got, PolicySourceAdmin)
		}
	})

	t.Run("非法值忽略且不擋啟動", func(t *testing.T) {
		svc, _ := setupPolicyDB(t)
		svc.SeedValue(PolicyRefreshCookieSecure, "yes-please", "AUTH_REFRESH_COOKIE_SECURE=yes-please")
		if !svc.GetBool(PolicyRefreshCookieSecure) {
			t.Error("非法播種值改變了現值，應沿用出廠預設 true")
		}
		if got := svc.ValueSource(PolicyRefreshCookieSecure); got != PolicySourceDefault {
			t.Errorf("ValueSource = %q, want %q（非法值不得寫列）", got, PolicySourceDefault)
		}
	})

	t.Run("空值不播種", func(t *testing.T) {
		svc, _ := setupPolicyDB(t)
		svc.SeedValue(PolicyRefreshCookieSecure, "", "未設定")
		if got := svc.ValueSource(PolicyRefreshCookieSecure); got != PolicySourceDefault {
			t.Errorf("ValueSource = %q, want %q", got, PolicySourceDefault)
		}
	})
}

// --- 傳輸安全政策鍵（task 1.1）---

func TestTransportPolicyKeyDefaults(t *testing.T) {
	svc, _ := setupPolicyDB(t)

	levelKeys := []string{
		PolicyTransportRDPLevel, PolicyTransportVNCLevel, PolicyTransportDBLevel,
		PolicyTransportLDAPLevel, PolicyTransportSyslogLevel, PolicyTransportNotifyLevel,
	}
	for _, key := range levelKeys {
		if got := svc.Get(key); got != TransportLevelOff {
			t.Errorf("%s 預設 = %q, want off（零影響原則）", key, got)
		}
	}
	if got := svc.GetInt(PolicyTransportConsentTTLDays); got != 90 {
		t.Errorf("transport_consent_ttl_days 預設 = %d, want 90", got)
	}
}

func TestTransportLevelRejectsInvalidValue(t *testing.T) {
	svc, _ := setupPolicyDB(t)

	if _, err := svc.Update(PolicyTransportRDPLevel, "block", "admin"); !errors.Is(err, ErrPolicyInvalidValue) {
		t.Fatalf("非法枚舉值應被拒，err = %v", err)
	}
	if got := svc.Get(PolicyTransportRDPLevel); got != TransportLevelOff {
		t.Errorf("拒絕後值 = %q, want 原值 off", got)
	}
}

func TestTransportLevelCompliance(t *testing.T) {
	svc, cs := newSeededComplianceStack(t)

	// 條文要求的是足夠強度的加密，不是本產品三段枚舉裡的某一段：三個取值都
	// 走待稽核判讀並附目前值，不判符合也不判偏離
	assertCompliance := func(value string) {
		t.Helper()
		if _, err := svc.Update(PolicyTransportVNCLevel, value, "admin"); err != nil {
			t.Fatalf("update %s: %v", value, err)
		}
		snap, err := cs.Snapshot("", nil)
		if err != nil {
			t.Fatalf("判定: %v", err)
		}
		for _, v := range snap.Verdicts {
			if v.Key != PolicyTransportVNCLevel || v.GroupCode != pciGroupCode {
				continue
			}
			if v.Result != ComplianceResultAuditReview {
				t.Errorf("value=%s 判定 = %s, want %s", value, v.Result, ComplianceResultAuditReview)
			}
			if v.Current != value {
				t.Errorf("value=%s 判定帶的目前值 = %q", value, v.Current)
			}
			return
		}
		t.Fatalf("判定中未含 transport_vnc_level 對 %s 組的結果", pciGroupCode)
	}
	assertCompliance(TransportLevelOff)
	assertCompliance(TransportLevelWarn)
	assertCompliance(TransportLevelStrict)
}

func TestTransportConsentTTLNoCompliance(t *testing.T) {
	svc, _ := setupPolicyDB(t)

	// TTL 不在任何內建組的對照內：不產生判定；0=永不過期為合法值
	if reqs := builtinSeedRequirements(t, PolicyTransportConsentTTLDays); len(reqs) != 0 {
		t.Errorf("transport_consent_ttl_days 被內建組掛了要求 %v，want 一條都沒有", reqs)
	}
	if _, err := svc.Update(PolicyTransportConsentTTLDays, "0", "admin"); err != nil {
		t.Errorf("0=永不過期應為合法值, err = %v", err)
	}
}

// TestCheckpointPolicyKeysRejectDisablingValues 政策層本身不得接受「實質關閉封章」
// 的值：0 一律擋（ZeroDisables 未開），且上限釘死 24 小時／100 萬筆
func TestCheckpointPolicyKeysRejectDisablingValues(t *testing.T) {
	defs := map[string]PolicyDef{}
	for _, d := range policyDefs {
		defs[d.Key] = d
	}
	for key, wantMax := range map[string]int{
		PolicyAuditCheckpointIntervalSeconds: 86400,
		PolicyAuditCheckpointRowThreshold:    1000000,
	} {
		d, ok := defs[key]
		if !ok {
			t.Fatalf("政策鍵 %s 未定義", key)
		}
		if d.ZeroDisables {
			t.Errorf("%s 不得開 ZeroDisables：0 會被解讀為停用＝封章可被關閉", key)
		}
		if d.Max != wantMax {
			t.Errorf("%s Max = %d, want %d（上限放寬等於允許以極大值實質關閉封章）", key, d.Max, wantMax)
		}
	}
}
