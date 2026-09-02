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

	// 手工構造：enum PCIValue 打錯字（非 EnumOrder 成員）→ evaluateCompliance 會把最弱值誤報合規
	bad := &PolicyDef{
		Key: "x", Type: PolicyTypeEnum, Default: "off", PCIValue: "ALL",
		EnumOrder: []string{"off", "admin_only", "all"},
	}
	// 直接驗比較器：PCIValue 不在序列，任何值都應判不符
	if c := evaluateCompliance(bad, "off"); c == nil || *c {
		t.Error("PCIValue 打錯字時，最弱值 off 不應被誤報合規")
	}
	if c := evaluateCompliance(bad, "all"); c == nil || *c {
		t.Error("PCIValue 打錯字時，任何值都應判不符（rank -1）")
	}
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

// TestPolicyComplianceComparator 比較器：0=停用 sentinel 先判不符、min/max 方向、bool、枚舉序
func TestPolicyComplianceComparator(t *testing.T) {
	boolPtr := func(vs []PolicyView, key string) *bool {
		for _, v := range vs {
			if v.Key == key {
				return v.Compliant
			}
		}
		return nil
	}

	svc, _ := setupPolicyDB(t)

	// 出廠預設（易用取向的刻意偏離）：mfa_required=off（PCI 要 all）、
	// web_idle_minutes/session_idle_minutes=60（PCI 要 ≤15）判不符；
	// web_max_session_hours/session_max_minutes 無 PCI 建議不評估（nil）；其餘全數符合
	factoryDeviations := map[string]bool{
		PolicyMFARequired:         true,
		PolicyWebIdleMinutes:      true,
		PolicySessionIdleMinutes:  true,
		PolicyInactiveDisableDays: true, // 出廠 0=關閉，偏離 PCI 90（易用取向）
		// 出廠 0=關閉，偏離 PCI 8.3.9 的 90 天
		PolicyPasswordMaxAgeDays: true,
		// 出廠 0=關閉，偏離 PCI 8.6.3 的參考值 90 天。**參考值照常參與符合性
		// 評估**：值是給了的，只是出處性質是常見實務而非條文明定
		PolicyAssetSecretMaxAgeDays: true,
		// 稽核紀錄合規六鍵出廠全偏離（日常模式）：保留 0=永久視為未定義
		// 保留政策、錄影 90 < 365、簽核與失效告警預設關
		PolicyRetentionAuditLogDays:       true,
		PolicyRetentionSessionCommandDays: true,
		PolicyRetentionAlertDays:          true,
		PolicyRetentionRecordingDays:      true,
		PolicyDailyReviewEnabled:          true,
		PolicyFailureAlertEnabled:         true,
		// 金鑰信封：出廠 0=不提醒，偏離 PCI 365（cryptoperiod 提醒）
		PolicyKeyCryptoperiodReminderDays: true,
		// 傳輸安全政策：六通道出廠 off（零影響原則），偏離 PCI 建議 warn
		PolicyTransportRDPLevel:    true,
		PolicyTransportVNCLevel:    true,
		PolicyTransportDBLevel:     true,
		PolicyTransportLDAPLevel:   true,
		PolicyTransportSyslogLevel: true,
		PolicyTransportNotifyLevel: true,
		// 存取政策核准：全域段位出廠 open（零破壞 opt-in），偏離 PCI 建議 approval；
		// 時長上限/超時出廠即建議值，符合
		PolicyAccessPolicyDefault: true,
		// 破窗與撤銷：撤銷即斷線出廠關（H 決議，與到期語義一致），
		// 偏離建議 true；破窗開關出廠關即建議值、短窗/補審時限出廠即建議值，符合
		PolicyAccessRevokeDisconnect: true,
		// 錄影失效處置：錄影 fail-close 出廠關（升級不改變現狀），
		// 偏離建議 true
		PolicyRecordingFailCloseEnabled: true,
	}
	noPCIRecommendation := map[string]bool{
		PolicyWebMaxSessionHours: true,
		PolicySessionMaxMinutes:  true,
		// refresh cookie 的 Secure 屬性無合規建議值（決策 8）：
		// 正確取值由部署對外協定決定（https 開、刻意明文關），不是合規基準線。
		// 掛建議值會讓「套用本頁建議值」把明文部署的本鍵翻成開啟＝整站續期失敗
		PolicyRefreshCookieSecure: true,
		// 同意效期無 PCI 門檻
		PolicyTransportConsentTTLDays: true,
		// 最少核准人數＝內控強化非 PCI 要求
		// （dual control 僅金鑰管理 Req 3.7.6，存取核准 Req 7.2.3 單人即符合）
		PolicyAccessRequestMinApprovals: true,
		// 檢查點保留天數無 PCI 建議值（audit-checkpoint-chain）：其合規語義
		// 是「檢查點必須活得比它所證明的資料久」＝跨鍵關係，不是單鍵與常數比較。
		// 掛 PCIValue 會讓它進「套用本頁建議值」並在偏離摘要與資料保留鍵並列
		PolicyRetentionCheckpointDays: true,
		// 封章門檻無 PCI 建議值：PCI 未規定封存頻率。其安全語義是「未封窗口
		// 多大」＝與離機備份的分工，不是單鍵與常數比較
		PolicyAuditCheckpointIntervalSeconds: true,
		PolicyAuditCheckpointRowThreshold:    true,
		// 鏈自動驗證三鍵無 PCI 建議值：
		// PCI 未就「鏈驗證頻率／近期窗口／掃描速率」給出建議值。掛假的 PCIValue
		// 會讓它們進「套用本頁建議值」並在偏離摘要中與真有條號的鍵並列。
		// 其不可被實質關閉的保證由上界＋不可為 0（前兩鍵）與 Min 下界（速率鍵）承擔
		PolicyAuditChainRecentVerifyDays:      true,
		PolicyAuditChainVerifyIntervalSeconds: true,
		PolicyAuditChainVerifyRowsPerHour:     true,
		// 三個營運調校鍵無 PCI 建議值：PCI 未就
		// 單輪清理／重加密的批次預算或叢集列表逾時給出建議值。掛假的 PCIValue
		// 會讓它們進「套用本頁建議值」並在偏離摘要中與真有條號的鍵並列，
		// 違反政策鍵的合規標示誠實紀律。其安全語義由 Min 下界承擔，不由 PCI 比較承擔
		PolicyRetentionMaxPerRun:    true,
		PolicyKeyRotationMaxPerRun:  true,
		PolicyK8sListTimeoutSeconds: true,
		// 離機儲存的本機快取期（evidence-offsite-storage）：它是磁碟預算旋鈕，
		// 不是保留期——到期只刪本機檔，錄影仍可自離機副本取回。PCI 10.5.1 管的是
		// 「證據留多久」，而那由 retention_recording_days 承擔；掛 PCIValue 會使
		// 「套用本頁建議值」替部署方決定本機要留幾天，並在偏離摘要中與真的保留鍵並列
		PolicyOffsiteLocalRetentionDays: true,
		// data-transfer-control：五鍵法源是電支基準 §16-6／§21-8(七) 而非 PCI 條文。
		// 掛假 PCIValue 會讓它進「套用本頁建議值」並被標成 PCI 要求；電支基準值
		// （皆為 false）由 G3 電支建議值雙軌承接
		PolicyClipboardSendEnabled: true,
		PolicyClipboardRecvEnabled: true,
		PolicyFileUploadEnabled:    true,
		PolicyFileDownloadEnabled:  true,
		PolicyFileDeleteEnabled:    true,
		// 登入前告示：內容由部署方自填，沒有一個通用的正確字串可以拿來比對；
		// 掛建議值會讓「套用本頁建議值」替部署方寫他們的告示
		PolicyLoginBannerTitle: true,
		PolicyLoginBannerBody:  true,
	}
	for _, v := range svc.List() {
		if factoryDeviations[v.Key] {
			if v.Compliant == nil || *v.Compliant {
				t.Errorf("%s 出廠預設應判不符 PCI 建議", v.Key)
			}
			continue
		}
		if noPCIRecommendation[v.Key] {
			if v.Compliant != nil {
				t.Errorf("%s 無 PCI 建議值，不應評估符合性", v.Key)
			}
			continue
		}
		if v.Compliant == nil || !*v.Compliant {
			t.Errorf("出廠預設 %s 應符合 PCI 建議", v.Key)
		}
	}
	if svc.DeviationCount() != 22 {
		t.Errorf("出廠偏離數 = %d, want 22（mfa_required＋web_idle＋session_idle＋inactive_days＋password_max_age＋asset_secret_max_age＋審計合規六鍵＋金鑰提醒＋傳輸六通道＋存取政策段位＋撤銷即斷線＋錄影 fail-close）", svc.DeviationCount())
	}

	// 0=停用：即使 0 <= 10 也必須判不符（sentinel 先判）
	svc.Update(PolicyLockoutMaxAttempts, "0", "admin")
	if c := boolPtr(svc.List(), PolicyLockoutMaxAttempts); c == nil || *c {
		t.Error("鎖定停用（0）應判不符 PCI 建議")
	}

	// max 型：值 <= PCI 為符合（8 次比 10 次更嚴）
	svc.Update(PolicyLockoutMaxAttempts, "8", "admin")
	if c := boolPtr(svc.List(), PolicyLockoutMaxAttempts); c == nil || !*c {
		t.Error("8 次（更嚴）應符合")
	}
	svc.Update(PolicyLockoutMaxAttempts, "15", "admin")
	if c := boolPtr(svc.List(), PolicyLockoutMaxAttempts); c == nil || *c {
		t.Error("15 次（放寬）應不符")
	}

	// min 型：值 >= PCI 為符合
	svc.Update(PolicyPasswordMinLength, "8", "admin")
	if c := boolPtr(svc.List(), PolicyPasswordMinLength); c == nil || *c {
		t.Error("長度 8（放寬）應不符")
	}
	svc.Update(PolicyPasswordMinLength, "16", "admin")
	if c := boolPtr(svc.List(), PolicyPasswordMinLength); c == nil || !*c {
		t.Error("長度 16（更嚴）應符合")
	}

	// bool 型
	svc.Update(PolicyPasswordRequireAlnum, "false", "admin")
	if c := boolPtr(svc.List(), PolicyPasswordRequireAlnum); c == nil || *c {
		t.Error("關閉字母數字要求應不符")
	}

	// 偏離：lockout=15（放寬）＋require_alnum=false＋22 項出廠偏離
	if svc.DeviationCount() != 24 {
		t.Errorf("偏離數 = %d, want 24（lockout 放寬＋alnum 關＋22 項出廠偏離）", svc.DeviationCount())
	}
}

// TestPolicyEnumComparator 枚舉比較器（mfa_required 於後續階段加入常數表，先驗證機制本身）
func TestPolicyEnumComparator(t *testing.T) {
	def := &PolicyDef{
		Key: "test_enum", Type: PolicyTypeEnum, PCIValue: "all",
		EnumOrder: []string{"off", "admin_only", "all"},
	}
	if c := evaluateCompliance(def, "off"); c == nil || *c {
		t.Error("off < all 應不符")
	}
	if c := evaluateCompliance(def, "admin_only"); c == nil || *c {
		t.Error("admin_only < all 應不符")
	}
	if c := evaluateCompliance(def, "all"); c == nil || !*c {
		t.Error("all >= all 應符合")
	}
	if c := evaluateCompliance(def, "bogus"); c == nil || *c {
		t.Error("未知枚舉值應不符")
	}
}

// TestPolicyNoPCIValueSkipsCompliance 無 PCI 建議值的欄位不做符合性評估
func TestPolicyNoPCIValueSkipsCompliance(t *testing.T) {
	def := &PolicyDef{Key: "no_pci", Type: PolicyTypeInt, PCIValue: ""}
	if c := evaluateCompliance(def, "999"); c != nil {
		t.Error("無 PCI 建議值應回 nil（不評估）")
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
		if v.PCIValue != "" || v.EPaymentValue != "" {
			t.Errorf("不得帶合規建議值（PCI=%q 電支=%q）：本鍵取值由部署對外協定決定，"+
				"掛建議值會讓「套用本頁建議值」把明文部署翻成開啟＝整站續期失敗",
				v.PCIValue, v.EPaymentValue)
		}
		if v.Compliant != nil || v.EPaymentCompliant != nil {
			t.Error("不得計入任何基準的符合性評估")
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
	svc, _ := setupPolicyDB(t)

	// off = 不符 PCI 建議（warn 起）；warn/strict = 符合（枚舉序位比較）
	assertCompliance := func(value string, want bool) {
		t.Helper()
		if _, err := svc.Update(PolicyTransportVNCLevel, value, "admin"); err != nil {
			t.Fatalf("update %s: %v", value, err)
		}
		for _, v := range svc.List() {
			if v.Key != PolicyTransportVNCLevel {
				continue
			}
			if v.Compliant == nil || *v.Compliant != want {
				t.Errorf("value=%s compliant = %v, want %v", value, v.Compliant, want)
			}
			return
		}
		t.Fatal("List 未含 transport_vnc_level")
	}
	assertCompliance(TransportLevelOff, false)
	assertCompliance(TransportLevelWarn, true)
	assertCompliance(TransportLevelStrict, true)
}

func TestTransportConsentTTLNoCompliance(t *testing.T) {
	svc, _ := setupPolicyDB(t)

	// TTL 無 PCI 建議值：不做符合性評估；0=永不過期為合法值
	for _, v := range svc.List() {
		if v.Key == PolicyTransportConsentTTLDays && v.Compliant != nil {
			t.Errorf("transport_consent_ttl_days 不應有符合性評估, got %v", *v.Compliant)
		}
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
