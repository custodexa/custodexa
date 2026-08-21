package audit

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/policy"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/notifycat"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// kek-rewrap-hygiene-hardening D5 測試組：degraded 謂詞、啟動/週期評估三態、
// 重啟不假恢復、以及「promote 未完成的殘缺態不可帶病開機」不變式
//（該不變式是「謂詞不含 finalize_pending」的推理前提，推理失效時本測試先紅）。

// degradedFixture 金鑰表＋失效事件服務（同一 db），通知投遞以 notify 注入攔截
type degradedFixture struct {
	db       *gorm.DB
	km       *keyvault.KeyManagerService
	af       *AuditFailureService
	notified []notifycat.Event
	// notifiedParams 與 notified 同索引：出站 params 的斷言依據（V2 對抗驗收 L1）
	notifiedParams []map[string]string
}

func newDegradedFixture(t *testing.T) *degradedFixture {
	t.Helper()
	db, km := setupKM(t)
	if err := db.AutoMigrate(&model.AuditFailureEvent{}, &model.SecurityPolicy{}); err != nil {
		t.Fatalf("migrate failure tables: %v", err)
	}
	// 與生產同構：migration 20260801_failure_event_single_open 的 partial unique index
	// （每機制至多一筆進行中事件的 DB 層強制），否則測試環境放行重複開列
	if err := db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_failure_events_single_open " +
		"ON audit_failure_events (mechanism) WHERE ended_at IS NULL").Error; err != nil {
		t.Fatalf("create partial unique index: %v", err)
	}
	// 政策開啟才會外送——本組驗的是「政策具備時持續告警」路徑
	if err := db.Create(&model.SecurityPolicy{Key: policy.PolicyFailureAlertEnabled, Value: "true"}).Error; err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	f := &degradedFixture{db: db, km: km}
	// 直接建構不註冊單例：避免污染其他測試的 GetAuditFailure()
	f.af = &AuditFailureService{db: db, policy: policy.NewSecurityPolicyService(db)}
	f.af.notify = func(event notifycat.Event, params map[string]string) {
		f.notified = append(f.notified, event)
		f.notifiedParams = append(f.notifiedParams, params)
	}
	return f
}

// openEvents 該機制未結束的事件數
func (f *degradedFixture) openEvents(mechanism string) int64 {
	var n int64
	f.db.Model(&model.AuditFailureEvent{}).
		Where("mechanism = ? AND ended_at IS NULL", mechanism).Count(&n)
	return n
}

// TestRetireBacklogPredicate degraded 謂詞：正常切換完成後為 0；
// 收尾失敗殘留（舊 KEK live 列）即 > 0。清冊端點與告警偵測共用同一方法
func TestRetireBacklogPredicate(t *testing.T) {
	db, km := setupKM(t)
	km2, oldKEK, _ := rewrapAndReinit(t, db, km)

	n, err := km2.RetireBacklogCount()
	if err != nil {
		t.Fatalf("backlog count: %v", err)
	}
	if n != 0 {
		t.Fatalf("正常切換收尾後 backlog 應為 0，得 %d", n)
	}

	makeBacklog(db, oldKEK) // 模擬收尾失敗殘留
	n, err = km2.RetireBacklogCount()
	if err != nil {
		t.Fatalf("backlog count: %v", err)
	}
	if n == 0 {
		t.Fatal("收尾失敗殘留時 backlog 謂詞必須 > 0")
	}

	// degraded 不降服務（spec：degraded 期間加解密與清冊查詢完全正常）
	ct := encryptColumn(t, km2, "assets", "password_enc", "still-working")
	if got, err := decryptColumn(km2, "assets", "password_enc", ct); err != nil || got != "still-working" {
		t.Fatalf("degraded 期間 Decrypt 失敗: %q err=%v", got, err)
	}
	if keys, err := km2.ListKeys(); err != nil || len(keys) == 0 {
		t.Fatalf("degraded 期間清冊查詢失敗: %d 列 err=%v", len(keys), err)
	}
}

// TestFinalizePendingResidueUnbootable 不變式：帶著「promote 未完成」的殘缺態
// （env pending 殘留、某 slot 無現行 KEK 代表列）成功開機不可達——必 fail-close。
// 這是 degraded 謂詞刻意不聯集 finalize_pending 的推理前提：post-boot 可達的
// 失敗殘留態唯有 retire backlog。推理失效（該態變成可帶病開機）時本測試先紅
func TestFinalizePendingResidueUnbootable(t *testing.T) {
	db, km := setupKM(t)
	resMaterial, res := mustRewrapKEK(t, km)
	newProvider, err := crypto.NewEnvKEKProvider([]byte(resMaterial))
	if err != nil {
		t.Fatalf("provider: %v", err)
	}

	// 手工造殘缺態：抹去 data v1 的 pending clone，使該 slot 對新 KEK 無任何代表列，
	// 其餘 slot 的 pending clone 保留（finalize_pending 殘留仍在）
	if err := db.Where("kek_id = ? AND purpose = ? AND version = ?",
		res.NewKEKID, model.DataKeyPurposeData, 1).
		Delete(&model.DataKey{}).Error; err != nil {
		t.Fatalf("造殘缺態失敗: %v", err)
	}
	var finalizePending int64
	db.Model(&model.DataKey{}).Where("kek_id = ? AND kek_pending = ?", res.NewKEKID, true).
		Count(&finalizePending)
	if finalizePending == 0 {
		t.Fatal("前置：殘缺態必須確有 finalize_pending 殘留，否則本測試證不了推理前提")
	}

	if _, err := keyvault.InitKeyManager(db, newProvider); !errors.Is(err, keyvault.ErrKEKMismatch) {
		t.Fatalf("promote 未完成的殘缺態必須 fail-close 拒啟動，得 %v", err)
	}

	// 對照組：完整 pending clones 開機成功，且收尾後 finalize_pending 歸零
	// （pending 不會成為靜默殘留態）
	db2, km2 := setupKM(t)
	km3, _, newKEKID := rewrapAndReinit(t, db2, km2)
	var stillPending int64
	db2.Model(&model.DataKey{}).Where("kek_id = ? AND kek_pending = ?", newKEKID, true).
		Count(&stillPending)
	if stillPending != 0 {
		t.Fatalf("成功開機後 finalize_pending 應歸零，得 %d", stillPending)
	}
	if km3 == nil {
		t.Fatal("切換開機應成功")
	}
}

// TestReconcileOnStartupExcludesKEKRetirement 重啟不假恢復（D5）：
// 啟動回填必須排除 kek_retirement（狀態可由 DB 謂詞導出，以重評估取代盲目關閉），
// 其他機制照舊回填
func TestReconcileOnStartupExcludesKEKRetirement(t *testing.T) {
	svc, db := setupFailureDB(t)
	started := time.Now().Add(-time.Hour)
	db.Create(&model.AuditFailureEvent{
		Mechanism: model.MechanismKEKRetirement, StartedAt: started, Cause: "重啟前的退役 backlog",
	})
	db.Create(&model.AuditFailureEvent{
		Mechanism: model.MechanismSyslogForward, StartedAt: started, Cause: "重啟前的斷線",
	})

	svc.ReconcileOnStartup()

	var kek model.AuditFailureEvent
	if err := db.Where("mechanism = ?", model.MechanismKEKRetirement).First(&kek).Error; err != nil {
		t.Fatalf("find kek event: %v", err)
	}
	if kek.EndedAt != nil {
		t.Fatal("kek_retirement 事件不得被啟動回填假記為已恢復（backlog 可能仍在）")
	}
	var syslog model.AuditFailureEvent
	if err := db.Where("mechanism = ?", model.MechanismSyslogForward).First(&syslog).Error; err != nil {
		t.Fatalf("find syslog event: %v", err)
	}
	if syslog.EndedAt == nil {
		t.Fatal("其他機制的遺留事件仍應照舊回填")
	}
}

// TestKEKRetirementMonitorStates 週期評估三態：
// (1) backlog 持續 → 每日重發提醒（不受 Report 進行中去重抑制、不重複開列）
// (2) backlog 由 >0 轉 0 → 結束 open 事件＋恢復通知，之後不再重發
// (3) 無 backlog 無 open 事件 → 完全無動作
func TestKEKRetirementMonitorStates(t *testing.T) {
	f := newDegradedFixture(t)
	km2, oldKEK, _ := rewrapAndReinit(t, f.db, f.km)
	makeBacklog(f.db, oldKEK)

	day0 := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	m := keyvault.NewKEKRetirementMonitor(km2, f.af)

	// 啟動評估：開列＋首次通知
	m.ReportOnStartup(day0)
	if f.openEvents(model.MechanismKEKRetirement) != 1 {
		t.Fatal("啟動評估應開一筆 kek_retirement 失效事件")
	}
	if len(f.notified) != 1 || f.notified[0] != notifycat.EventAuditFailure {
		t.Fatalf("啟動評估應發一次失效通知，得 %v", f.notified)
	}
	var ev model.AuditFailureEvent
	f.db.Where("mechanism = ?", model.MechanismKEKRetirement).First(&ev)
	if ev.Cause == "" {
		t.Error("Cause 必須記錄（PCI 10.7.3）")
	}

	// (1a) 同日週期評估：不重複投遞
	m.Evaluate(day0.Add(2 * time.Hour))
	if len(f.notified) != 1 {
		t.Fatalf("同日不應重複投遞，得 %v", f.notified)
	}

	// (1b) 隔日仍未收斂：重發提醒（Report 的進行中去重不得抑制週期重發），
	// 且不得重複開列
	day1 := day0.AddDate(0, 0, 1)
	m.Evaluate(day1)
	if len(f.notified) != 2 || f.notified[1] != notifycat.EventAuditFailureOngoing {
		t.Fatalf("backlog 長存應由週期評估重發提醒，得 %v", f.notified)
	}
	var total int64
	f.db.Model(&model.AuditFailureEvent{}).
		Where("mechanism = ?", model.MechanismKEKRetirement).Count(&total)
	if total != 1 {
		t.Fatalf("週期重發不得重複開列，事件列數 = %d", total)
	}

	// (2) 收斂：backlog 歸零（模擬重啟收尾成功）→ 結束事件＋恢復通知
	if err := f.db.Model(&model.DataKey{}).Where("kek_id = ?", oldKEK).
		Updates(map[string]interface{}{
			"kek_retired_at": time.Now(), "kek_retired_by": km2.KEKKeyID(),
			"kek_retired_reason": model.KEKRetireReasonSwitched,
		}).Error; err != nil {
		t.Fatalf("模擬收斂失敗: %v", err)
	}
	m.Evaluate(day1.AddDate(0, 0, 1))
	if f.openEvents(model.MechanismKEKRetirement) != 0 {
		t.Fatal("收斂後 open 事件應被結束")
	}
	if len(f.notified) != 3 || f.notified[2] != notifycat.EventAuditFailureResolved {
		t.Fatalf("收斂應發恢復通知與先前告警配對，得 %v", f.notified)
	}

	// (3) 已收斂後續評估：無動作
	m.Evaluate(day1.AddDate(0, 0, 2))
	if len(f.notified) != 3 {
		t.Fatalf("收斂後不應再有任何投遞，得 %v", f.notified)
	}
}

// TestKEKRetirementMonitorCleanBoot 無 backlog 無 open 事件的乾淨啟動：不開列不投遞
func TestKEKRetirementMonitorCleanBoot(t *testing.T) {
	f := newDegradedFixture(t)
	m := keyvault.NewKEKRetirementMonitor(f.km, f.af)

	m.ReportOnStartup(time.Now())
	m.Evaluate(time.Now().AddDate(0, 0, 1))

	var total int64
	f.db.Model(&model.AuditFailureEvent{}).Count(&total)
	if total != 0 {
		t.Fatalf("無 backlog 不應開列，事件列數 = %d", total)
	}
	if len(f.notified) != 0 {
		t.Fatalf("無 backlog 不應投遞，得 %v", f.notified)
	}
}

// TestKEKRetirementRestartConvergedResolves 重啟後謂詞重評估結案（D5）：
// 上一個行程留下的 open 事件（ReconcileOnStartup 不再關閉它）在 backlog 已
// 收斂時，須由啟動評估認領並結束——重啟不假恢復，但也不永久懸掛
func TestKEKRetirementRestartConvergedResolves(t *testing.T) {
	f := newDegradedFixture(t)
	f.db.Create(&model.AuditFailureEvent{
		Mechanism: model.MechanismKEKRetirement,
		StartedAt: time.Now().Add(-2 * time.Hour),
		Cause:     "上一個行程的退役 backlog",
	})

	m := keyvault.NewKEKRetirementMonitor(f.km, f.af) // backlog 已收斂（乾淨金鑰表）
	m.ReportOnStartup(time.Now())

	if f.openEvents(model.MechanismKEKRetirement) != 0 {
		t.Fatal("重啟後 backlog 已收斂：遺留 open 事件須以謂詞重評估結案")
	}
	if len(f.notified) != 1 || f.notified[0] != notifycat.EventAuditFailureResolved {
		t.Fatalf("結案應發恢復通知，得 %v", f.notified)
	}
}

// TestEvaluateOpensEventForPostBootEpisode（codex 第一輪審 #5／opus HIGH 回歸）：
// 啟動時乾淨、backlog 於執行期才出現的 episode，週期評估 MUST 開失效事件列
// （PCI 證據），收斂時 MUST 配對結案——不得只投遞提醒而無事件列
func TestEvaluateOpensEventForPostBootEpisode(t *testing.T) {
	f := newDegradedFixture(t)
	base := time.Now()
	mon := keyvault.NewKEKRetirementMonitor(f.km, f.af)
	mon.ReportOnStartup(base)
	if n := f.openEvents(model.MechanismKEKRetirement); n != 0 {
		t.Fatalf("乾淨啟動不應開列，得 %d", n)
	}
	// 執行期出現 backlog（等價於另一實例完成切換後本實例視角的殘留）
	if err := f.db.Create(&model.DataKey{Purpose: model.DataKeyPurposeData, Version: 1,
		KEKID: "deadbeefdeadbeef", WrappedKey: "foreign-material",
		Status: model.DataKeyStatusRetired}).Error; err != nil {
		t.Fatalf("造 backlog: %v", err)
	}
	mon.Evaluate(base.Add(48 * time.Hour))
	if n := f.openEvents(model.MechanismKEKRetirement); n != 1 {
		t.Fatalf("post-boot episode 週期評估應開恰一列失效事件，得 %d", n)
	}
	if len(f.notified) == 0 {
		t.Fatal("post-boot episode 應發失效通知")
	}
	// 收斂：移除 backlog → 事件結案＋恢復通知
	f.db.Where("kek_id = ?", "deadbeefdeadbeef").Delete(&model.DataKey{})
	mon.Evaluate(base.Add(72 * time.Hour))
	if n := f.openEvents(model.MechanismKEKRetirement); n != 0 {
		t.Fatalf("收斂後事件應結案，得 %d open", n)
	}
	last := f.notified[len(f.notified)-1]
	if last != notifycat.EventAuditFailureResolved {
		t.Fatalf("收斂應發恢復通知配對，最後通知為 %q", last)
	}
}

// TestEnsureEventRowSingleOpenUnderRace（第三輪審查 H1/H2 回歸）：
// 兩個 service 實例（等價多後端副本）同輪補列，DB partial unique index
// MUST 使進行中事件恰一筆；補列事件 MUST 於 Details 誠實註明起點不精確
func TestEnsureEventRowSingleOpenUnderRace(t *testing.T) {
	f := newDegradedFixture(t)
	af2 := &AuditFailureService{db: f.db, policy: policy.NewSecurityPolicyService(f.db)}
	af2.notify = func(event notifycat.Event, params map[string]string) {}

	f.af.EnsureEventRow(model.MechanismKEKRetirement, model.CauseKEKRetirementBacklog,
		map[string]string{"backlog": "1"})
	af2.EnsureEventRow(model.MechanismKEKRetirement, model.CauseKEKRetirementBacklog,
		map[string]string{"backlog": "2"})

	if n := f.openEvents(model.MechanismKEKRetirement); n != 1 {
		t.Fatalf("多實例補列後進行中事件應恰一筆，得 %d", n)
	}
	var ev model.AuditFailureEvent
	if err := f.db.Where("mechanism = ? AND ended_at IS NULL", model.MechanismKEKRetirement).
		First(&ev).Error; err != nil {
		t.Fatalf("讀事件: %v", err)
	}
	if !strings.Contains(ev.Details, "起始時間為補列時刻") {
		t.Fatalf("補列事件須註明起點不精確，得 Details=%q", ev.Details)
	}
}

// TestKEKReminderStateOnlyAdvancesWhenAlertEnabled（codex 批 2 M5 回歸）：
// 提醒節流狀態（lastReminded）不得在「政策關閉、投遞其實被靜默丟棄」的評估中
// 推進——否則政策當日稍後才開啟時，整日收不到任何 degraded 提醒
func TestKEKReminderStateOnlyAdvancesWhenAlertEnabled(t *testing.T) {
	f := newDegradedFixture(t)
	if _, err := f.af.policy.Update(policy.PolicyFailureAlertEnabled, "false", "test"); err != nil {
		t.Fatalf("關閉告警政策: %v", err)
	}
	km2, oldKEK, _ := rewrapAndReinit(t, f.db, f.km)
	makeBacklog(f.db, oldKEK)

	day0 := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	m := keyvault.NewKEKRetirementMonitor(km2, f.af)

	// 政策關：啟動評估與同日週期評估都不投遞（但事件列照開，記錄恆開）
	m.ReportOnStartup(day0)
	m.Evaluate(day0.Add(time.Hour))
	if len(f.notified) != 0 {
		t.Fatalf("政策關閉時不應有任何投遞，得 %v", f.notified)
	}
	if f.openEvents(model.MechanismKEKRetirement) != 1 {
		t.Fatal("政策關閉不影響失效事件記錄（記錄恆開）")
	}

	// 同日開啟政策：本日尚未真正提醒過，這一輪必須投遞
	if _, err := f.af.policy.Update(policy.PolicyFailureAlertEnabled, "true", "test"); err != nil {
		t.Fatalf("開啟告警政策: %v", err)
	}
	m.Evaluate(day0.Add(2 * time.Hour))
	if len(f.notified) != 1 || f.notified[0] != notifycat.EventAuditFailureOngoing {
		t.Fatalf("政策當日開啟後同日評估須補上提醒，得 %v", f.notified)
	}

	// 政策開啟後的同日再評估：回到正常的每日至多一次節流
	m.Evaluate(day0.Add(3 * time.Hour))
	if len(f.notified) != 1 {
		t.Fatalf("已提醒過的同日不應重複投遞，得 %v", f.notified)
	}
}

// TestKEKRetirementOngoingCarriesBacklog 週期重發帶積壓筆數（V2 對抗驗收 L1）。
//
// 遷移前的本地 log 文案是「N 筆舊 KEK 包裹列仍未退役」，碼化後出站只剩機制與
// 時刻——收件人失去唯一的量化訊號（積壓在擴大還是收斂中）。筆數是聚合指標，
// 不屬 forensic 明細，與 D8「收尾錯誤原文不出站」不衝突。
func TestKEKRetirementOngoingCarriesBacklog(t *testing.T) {
	f := newDegradedFixture(t)
	km2, oldKEK, _ := rewrapAndReinit(t, f.db, f.km)
	makeBacklog(f.db, oldKEK)

	var want int64
	f.db.Model(&model.DataKey{}).Where("kek_id = ?", oldKEK).Count(&want)
	if want == 0 {
		t.Fatal("前置條件不成立：應有未退役的舊 KEK 包裹列")
	}

	day0 := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	m := keyvault.NewKEKRetirementMonitor(km2, f.af)
	m.ReportOnStartup(day0)
	m.Evaluate(day0.AddDate(0, 0, 1)) // 隔日重發

	var params map[string]string
	for i, ev := range f.notified {
		if ev == notifycat.EventAuditFailureOngoing {
			params = f.notifiedParams[i]
		}
	}
	if params == nil {
		t.Fatalf("應有一則週期重發通知，得 %v", f.notified)
	}
	if got := params["backlog"]; got != strconv.FormatInt(want, 10) {
		t.Fatalf("backlog = %q，預期 %d", got, want)
	}
	// 出站 payload 仍不得帶 forensic 明細（D8）
	if _, leaked := params["detail"]; leaked {
		t.Fatalf("出站 params 不得含 forensic detail: %v", params)
	}

	// 出站文案實際帶出筆數（三語模板皆有可選段）
	if _, text := notifycat.Render("zh-TW", notifycat.EventAuditFailureOngoing, params); !strings.Contains(text, strconv.FormatInt(want, 10)) {
		t.Fatalf("渲染文案應含積壓筆數，實得 %q", text)
	}
}

// 以下自 `key_manager_hygiene_test.go` 遷入（modular-architecture W2 2.5）：
// 本測試以 newDegradedFixture（定義於本檔）取得 audit failure service 的內部殘態，
// 而該服務留在 internal/service，故測試隨 fixture 留下；斷言逐字未改。

// TestEnsureEventRowBackfills（codex 第二輪審 H1 回歸）：Report 當時事件表
// 拒寫留下「in-memory failing、DB 無列」殘態時，週期評估 MUST 補列
func TestEnsureEventRowBackfills(t *testing.T) {
	f := newDegradedFixture(t)
	// 直接構造殘態：in-memory failing=true、DB 無 open 列
	f.af.mu.Lock()
	if f.af.failing == nil {
		f.af.failing = map[string]bool{}
	}
	f.af.failing[model.MechanismKEKRetirement] = true
	f.af.mu.Unlock()
	// 造 backlog 使評估走進行中分支
	if err := f.db.Create(&model.DataKey{Purpose: model.DataKeyPurposeData, Version: 1,
		KEKID: "feedfacefeedface", WrappedKey: "foreign-material",
		Status: model.DataKeyStatusRetired}).Error; err != nil {
		t.Fatalf("造 backlog: %v", err)
	}
	mon := keyvault.NewKEKRetirementMonitor(f.km, f.af)
	mon.Evaluate(time.Now().Add(48 * time.Hour))
	if n := f.openEvents(model.MechanismKEKRetirement); n != 1 {
		t.Fatalf("殘態下週期評估應補開恰一列事件，得 %d", n)
	}
}
