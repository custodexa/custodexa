package policy

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/model"
)

// highRiskCall 一次審計或告警呼叫的紀錄（依呼叫次序）。
type highRiskCall struct {
	kind          string // "audit"／"alert"
	key           string
	correlationID string
	actorID       uint
	clientIP      string
	alert         HighRiskAlert
}

// highRiskRecorder 同時當審計寫入者與告警落地面，記錄呼叫次序；可分別注入失敗。
// 告警拒收零值操作者（與系統告警落地面相同）。
type highRiskRecorder struct {
	actor     PolicyActor
	calls     []highRiskCall
	failAudit bool
	failAlert bool
}

func (r *highRiskRecorder) auditor() PolicyChangeAuditor {
	return func(_ *gorm.DB, ch PolicyChange) error {
		if r.failAudit {
			return errors.New("注入審計失敗")
		}
		r.calls = append(r.calls, highRiskCall{kind: "audit", key: ch.Key, correlationID: ch.CorrelationID,
			actorID: r.actor.ID, clientIP: r.actor.ClientIP})
		return nil
	}
}

func (r *highRiskRecorder) RaiseHighRiskInTx(_ *gorm.DB, a HighRiskAlert) error {
	if a.ActorID == 0 {
		return errors.New("系統告警缺操作者")
	}
	if r.failAlert {
		return errors.New("注入告警失敗")
	}
	r.calls = append(r.calls, highRiskCall{kind: "alert", key: a.Key, correlationID: a.CorrelationID,
		actorID: a.ActorID, clientIP: a.ClientIP, alert: a})
	return nil
}

func (r *highRiskRecorder) alerts() []HighRiskAlert {
	var out []HighRiskAlert
	for _, c := range r.calls {
		if c.kind == "alert" {
			out = append(out, c.alert)
		}
	}
	return out
}

func (r *highRiskRecorder) audits() []highRiskCall {
	var out []highRiskCall
	for _, c := range r.calls {
		if c.kind == "audit" {
			out = append(out, c)
		}
	}
	return out
}

func newHighRiskDB(t *testing.T) (*SecurityPolicyService, *gorm.DB, *highRiskRecorder) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "hr.db")), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&model.SecurityPolicy{}, &model.SecurityPolicyHistory{}, &model.Asset{}, &model.AuditLog{}))
	svc := NewSecurityPolicyService(db)
	rec := &highRiskRecorder{actor: PolicyActor{ID: 9, Name: "sec-admin", ClientIP: "198.51.100.9"}}
	svc.SetHighRiskAlertRaiser(rec)
	return svc, db, rec
}

func seedPolicy(t *testing.T, db *gorm.DB, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		require.NoError(t, db.Save(&model.SecurityPolicy{Key: k, Value: v, UpdatedBy: "init"}).Error)
	}
}

// TestSecurityPolicyHighRiskAlerts 擋：高危鍵的變更沒有告警、告警先於審計、告警與審計的關聯識別或
// 操作者對不上、審計或告警失敗卻半套生效、無操作者入口能下調保留、播種走進掛點，以及
// 保留下調、錄影故障阻擋關閉、全系統預設降級三類分類錯誤。
func TestSecurityPolicyHighRiskAlerts(t *testing.T) {
	t.Run("掛點：高危鍵＋一般鍵的批次，審計或告警失敗兩鍵都維持原值且快取未失效", func(t *testing.T) {
		for _, inject := range []string{"audit", "alert"} {
			svc, db, rec := newHighRiskDB(t)
			seedPolicy(t, db, map[string]string{PolicyRetentionAuditLogDays: "365", PolicyLockoutMaxAttempts: "10"})
			require.Equal(t, 365, svc.GetInt(PolicyRetentionAuditLogDays))
			require.Equal(t, 10, svc.GetInt(PolicyLockoutMaxAttempts))
			gen := svc.generation.Load()
			rec.failAudit, rec.failAlert = inject == "audit", inject == "alert"
			_, err := svc.UpdateBatchAudited(map[string]string{PolicyRetentionAuditLogDays: "30", PolicyLockoutMaxAttempts: "5"},
				rec.actor, rec.auditor())
			require.Error(t, err, "注入 %s 失敗應回錯", inject)
			if inject == "alert" {
				assert.True(t, errors.Is(err, ErrHighRiskAlertRaise))
			}
			assert.Equal(t, gen, svc.generation.Load(), "快取不得失效")
			svc.mu.RLock()
			_, cached := svc.cache[PolicyRetentionAuditLogDays]
			svc.mu.RUnlock()
			assert.True(t, cached, "快取條目仍在")
			var a, l model.SecurityPolicy
			require.NoError(t, db.Where("key = ?", PolicyRetentionAuditLogDays).First(&a).Error)
			require.NoError(t, db.Where("key = ?", PolicyLockoutMaxAttempts).First(&l).Error)
			assert.Equal(t, "365", a.Value)
			assert.Equal(t, "10", l.Value)
		}
	})

	t.Run("掛點：只含一般鍵的批次，審計失敗值不變；不注入時審計照舊、0 筆告警", func(t *testing.T) {
		svc, _, rec := newHighRiskDB(t)
		rec.failAudit = true
		_, err := svc.UpdateBatchAudited(map[string]string{PolicyLockoutMaxAttempts: "5"}, rec.actor, rec.auditor())
		require.Error(t, err)
		assert.Equal(t, 10, svc.GetInt(PolicyLockoutMaxAttempts))
		rec.failAudit = false
		_, err = svc.UpdateBatchAudited(map[string]string{PolicyLockoutMaxAttempts: "5"}, rec.actor, rec.auditor())
		require.NoError(t, err)
		require.Len(t, rec.audits(), 1)
		assert.Equal(t, "", rec.audits()[0].correlationID, "一般鍵的審計不帶關聯識別（與改動前相同）")
		assert.Empty(t, rec.alerts())
	})

	t.Run("掛點：審計先於告警，關聯識別、來源位址與操作者一致", func(t *testing.T) {
		svc, _, rec := newHighRiskDB(t)
		_, err := svc.UpdateBatchAudited(map[string]string{PolicyRetentionRecordingDays: "30"}, rec.actor, rec.auditor())
		require.NoError(t, err)
		require.Len(t, rec.calls, 2)
		assert.Equal(t, "audit", rec.calls[0].kind)
		assert.Equal(t, "alert", rec.calls[1].kind)
		assert.NotEmpty(t, rec.calls[0].correlationID)
		assert.Equal(t, rec.calls[0].correlationID, rec.calls[1].correlationID)
		assert.Equal(t, rec.calls[0].clientIP, rec.calls[1].clientIP)
		assert.Equal(t, rec.calls[0].actorID, rec.calls[1].actorID)
		assert.Equal(t, "sec-admin", rec.calls[1].alert.ActorName)
	})

	t.Run("掛點：批次含任一高危鍵時讀舊值前先取鎖", func(t *testing.T) {
		svc, _, rec := newHighRiskDB(t)
		locks := 0
		policyHistoryHooks.beforeLock = func(string) { locks++ }
		t.Cleanup(func() { policyHistoryHooks.beforeLock = nil })
		for _, key := range []string{PolicyRetentionAuditLogDays, PolicyRetentionSessionCommandDays, PolicyRetentionAlertDays,
			PolicyRetentionRecordingDays, PolicyRecordingFailCloseEnabled, PolicyAccessPolicyDefault, PolicyMappingRevalidationHours} {
			before := locks
			value := map[string]string{PolicyRecordingFailCloseEnabled: "true", PolicyAccessPolicyDefault: model.AccessPolicyReason,
				PolicyMappingRevalidationHours: "6"}[key]
			if value == "" {
				value = "400"
			}
			_, err := svc.UpdateBatchAudited(map[string]string{key: value, PolicyLockoutMaxAttempts: "6"}, rec.actor, rec.auditor())
			require.NoError(t, err, key)
			assert.Equal(t, before+1, locks, "含 %s 的批次須先取鎖", key)
		}
		before := locks
		_, err := svc.UpdateBatchAudited(map[string]string{PolicyLockoutMaxAttempts: "7"}, rec.actor, rec.auditor())
		require.NoError(t, err)
		assert.Equal(t, before, locks, "只含一般鍵不取鎖")
	})

	t.Run("掛點：無操作者入口下調保留回錯且整批不生效", func(t *testing.T) {
		svc, db, _ := newHighRiskDB(t)
		seedPolicy(t, db, map[string]string{PolicyRetentionAlertDays: "365"})
		_, err := svc.UpdateBatch(map[string]string{PolicyRetentionAlertDays: "30", PolicyLockoutMaxAttempts: "5"}, "root")
		require.Error(t, err)
		assert.Equal(t, 365, svc.GetInt(PolicyRetentionAlertDays))
		assert.Equal(t, 10, svc.GetInt(PolicyLockoutMaxAttempts))
	})

	t.Run("掛點：播種路徑不經掛點", func(t *testing.T) {
		svc, _, rec := newHighRiskDB(t)
		t.Setenv("RECORDING_RETENTION_DAYS", "30")
		svc.SeedFromEnv(PolicyRetentionRecordingDays, "RECORDING_RETENTION_DAYS")
		assert.Equal(t, 30, svc.GetInt(PolicyRetentionRecordingDays), "播種 30（自出廠 90 下調）照常寫入")
		assert.Empty(t, rec.calls, "播種不呼叫審計或告警")
	})

	// 跨鍵驗證在鎖內以同一交易讀現值：A 調長資料鍵、B 調短檢查點，各自單看都合法，
	// 合起來違反約束。B 必須等 A 提交後才驗證，因此被拒，終態自洽。
	t.Run("postgres_cross_key_serialized", func(t *testing.T) {
		db := openPolicyPG(t, fmt.Sprintf("p2g_crosskey_%d", time.Now().UnixNano()))
		require.Equal(t, "postgres", db.Dialector.Name())
		fmt.Println("EVIDENCE dialect=postgres")
		require.NoError(t, db.AutoMigrate(&model.Asset{}, &model.AuditLog{}))
		svc := NewSecurityPolicyService(db)
		rec := &highRiskRecorder{actor: PolicyActor{ID: 9, Name: "sec-admin", ClientIP: "198.51.100.9"}}
		svc.SetHighRiskAlertRaiser(rec)
		seedPolicy(t, db, map[string]string{PolicyRetentionAuditLogDays: "30", PolicyRetentionSessionCommandDays: "30",
			PolicyRetentionAlertDays: "30", PolicyRetentionRecordingDays: "30", PolicyRetentionCheckpointDays: "90"})

		aValidated, releaseA := make(chan struct{}), make(chan struct{})
		policyHistoryHooks.afterValidate = func(by string) {
			if by == "A" {
				close(aValidated)
				<-releaseA
			}
		}
		t.Cleanup(func() { policyHistoryHooks.afterValidate = nil })
		// 斷言失敗時也放行 A，否則停住的交易會讓清理時的 DROP SCHEMA 永遠等鎖
		releaseOnce := sync.OnceFunc(func() { close(releaseA) })
		t.Cleanup(releaseOnce)

		errA, errB := make(chan error, 1), make(chan error, 1)
		go func() {
			_, err := svc.UpdateBatchAudited(map[string]string{PolicyRetentionAuditLogDays: "90"},
				PolicyActor{ID: 9, Name: "A"}, rec.auditor())
			errA <- err
		}()
		select {
		case <-aValidated:
		case <-time.After(10 * time.Second):
			t.Fatal("A 沒有走到鎖內驗證")
		}
		go func() {
			_, err := svc.UpdateBatchAudited(map[string]string{PolicyRetentionCheckpointDays: "30"},
				PolicyActor{ID: 9, Name: "B"}, rec.auditor())
			errB <- err
		}()
		deadline := time.Now().Add(10 * time.Second)
		for waitingOnHistoryLock(t, db) < 1 {
			if time.Now().After(deadline) {
				t.Fatal("B 沒有在等保留序列化鎖：跨鍵驗證未被序列化")
			}
			time.Sleep(10 * time.Millisecond)
		}
		releaseOnce()
		require.NoError(t, <-errA, "A 單看合法，應成功")
		err := <-errB
		var ck *PolicyRetentionCrossKeyError
		require.True(t, errors.As(err, &ck), "B 應在 A 提交後以新現值驗證而被拒，實得 %v", err)
		dbValue := func(k string) int {
			var row model.SecurityPolicy
			require.NoError(t, db.Where("key = ?", k).First(&row).Error)
			n, _ := strconv.Atoi(row.Value)
			return n
		}
		assert.Equal(t, 90, dbValue(PolicyRetentionAuditLogDays))
		assert.Equal(t, 90, dbValue(PolicyRetentionCheckpointDays))
		for _, k := range dataRetentionKeys {
			assert.True(t, RetentionCovers(dbValue(PolicyRetentionCheckpointDays), dbValue(k)), "終態自洽：%s", k)
		}
	})

	dataClass := map[string]string{
		PolicyRetentionAuditLogDays: "audit_log", PolicyRetentionSessionCommandDays: "session_command",
		PolicyRetentionAlertDays: "alert", PolicyRetentionRecordingDays: "recording",
	}
	for key, class := range dataClass {
		key, class := key, class
		t.Run("分類："+key+" 下調告警、調長與改 0 只審計", func(t *testing.T) {
			for _, tc := range []struct{ from, to string }{{"365", "30"}, {"0", "30"}} {
				svc, db, rec := newHighRiskDB(t)
				seedPolicy(t, db, map[string]string{key: tc.from, PolicyRetentionCheckpointDays: "0"})
				_, err := svc.UpdateBatchAudited(map[string]string{key: tc.to}, rec.actor, rec.auditor())
				require.NoError(t, err)
				al := rec.alerts()
				require.Len(t, al, 1, "%s→%s", tc.from, tc.to)
				assert.Equal(t, HighRiskRetentionShortened, al[0].Type)
				assert.Equal(t, key, al[0].Key)
				assert.Equal(t, map[string]string{"data_class": class, "days_before": tc.from, "days_after": tc.to}, al[0].Params)
				require.Len(t, rec.audits(), 1)
				assert.Equal(t, rec.audits()[0].correlationID, al[0].CorrelationID)
			}
			for _, tc := range []struct{ from, to string }{{"30", "365"}, {"30", "0"}} {
				svc, db, rec := newHighRiskDB(t)
				seedPolicy(t, db, map[string]string{key: tc.from, PolicyRetentionCheckpointDays: "0"})
				_, err := svc.UpdateBatchAudited(map[string]string{key: tc.to}, rec.actor, rec.auditor())
				require.NoError(t, err)
				assert.Empty(t, rec.alerts(), "%s→%s 不告警", tc.from, tc.to)
				assert.Len(t, rec.audits(), 1)
			}
		})
	}

	t.Run("分類：檢查點保留 0→30 只審計", func(t *testing.T) {
		svc, db, rec := newHighRiskDB(t)
		seedPolicy(t, db, map[string]string{PolicyRetentionAuditLogDays: "30", PolicyRetentionSessionCommandDays: "30",
			PolicyRetentionAlertDays: "30", PolicyRetentionRecordingDays: "30", PolicyRetentionCheckpointDays: "0"})
		_, err := svc.UpdateBatchAudited(map[string]string{PolicyRetentionCheckpointDays: "30"}, rec.actor, rec.auditor())
		require.NoError(t, err)
		assert.Equal(t, 30, svc.GetInt(PolicyRetentionCheckpointDays))
		assert.Len(t, rec.audits(), 1)
		assert.Empty(t, rec.alerts())
	})

	t.Run("分類：錄影故障阻擋開改關告警、關改開不告警", func(t *testing.T) {
		svc, db, rec := newHighRiskDB(t)
		seedPolicy(t, db, map[string]string{PolicyRecordingFailCloseEnabled: "true"})
		_, err := svc.UpdateBatchAudited(map[string]string{PolicyRecordingFailCloseEnabled: "false"}, rec.actor, rec.auditor())
		require.NoError(t, err)
		require.Len(t, rec.alerts(), 1)
		assert.Equal(t, HighRiskRecordingFailcloseOff, rec.alerts()[0].Type)
		assert.Empty(t, rec.alerts()[0].Params)
		_, err = svc.UpdateBatchAudited(map[string]string{PolicyRecordingFailCloseEnabled: "true"}, rec.actor, rec.auditor())
		require.NoError(t, err)
		assert.Len(t, rec.alerts(), 1, "關改開不告警")
	})

	t.Run("分類：同批下調兩鍵得兩筆告警、關聯識別各不相同", func(t *testing.T) {
		svc, db, rec := newHighRiskDB(t)
		seedPolicy(t, db, map[string]string{PolicyRetentionAuditLogDays: "365", PolicyRetentionAlertDays: "365", PolicyRetentionCheckpointDays: "0"})
		_, err := svc.UpdateBatchAudited(map[string]string{PolicyRetentionAuditLogDays: "30", PolicyRetentionAlertDays: "60"},
			rec.actor, rec.auditor())
		require.NoError(t, err)
		al := rec.alerts()
		require.Len(t, al, 2)
		assert.NotEqual(t, al[0].CorrelationID, al[1].CorrelationID)
	})

	t.Run("分類：全系統預設由 approval 改 open 告警並附受影響資產數", func(t *testing.T) {
		svc, db, rec := newHighRiskDB(t)
		str := func(s string) *string { return &s }
		assets := []model.Asset{
			{Name: "a-none-1"}, {Name: "a-none-2"},
			{Name: "a-invalid", AccessPolicy: str("bogus")},
			{Name: "a-approval", AccessPolicy: str(model.AccessPolicyApproval)},
			{Name: "a-reason", AccessPolicy: str(model.AccessPolicyReason)},
			{Name: "a-deleted"},
		}
		for i := range assets {
			require.NoError(t, db.Create(&assets[i]).Error)
		}
		require.NoError(t, db.Delete(&assets[5]).Error)
		// 受影響數由有效段位算出（不以硬編常數代替）
		want := 0
		var live []model.Asset
		require.NoError(t, db.Find(&live).Error)
		for _, a := range live {
			if TierRank(EffectiveTier(a.AccessPolicy, model.AccessPolicyOpen)) < TierRank(EffectiveTier(a.AccessPolicy, model.AccessPolicyApproval)) {
				want++
			}
		}
		require.Equal(t, 3, want, "fixture 前提：兩台無覆寫＋一台覆寫不合法")

		seedPolicy(t, db, map[string]string{PolicyAccessPolicyDefault: model.AccessPolicyApproval})
		_, err := svc.UpdateBatchAudited(map[string]string{PolicyAccessPolicyDefault: model.AccessPolicyOpen}, rec.actor, rec.auditor())
		require.NoError(t, err)
		al := rec.alerts()
		require.Len(t, al, 1)
		assert.Equal(t, HighRiskAccessPolicyRelaxed, al[0].Type)
		assert.Equal(t, map[string]string{"relax_type": "default_lowered", "before_level": model.AccessPolicyApproval,
			"after_level": model.AccessPolicyOpen, "affected_assets": strconv.Itoa(want)}, al[0].Params)

		_, err = svc.UpdateBatchAudited(map[string]string{PolicyAccessPolicyDefault: model.AccessPolicyApproval}, rec.actor, rec.auditor())
		require.NoError(t, err)
		assert.Len(t, rec.alerts(), 1, "open 改 approval 不告警")

		seedPolicy(t, db, map[string]string{PolicyAccessPolicyDefault: model.AccessPolicyReason})
		svc.mu.Lock()
		delete(svc.cache, PolicyAccessPolicyDefault)
		svc.mu.Unlock()
		audits := len(rec.audits())
		_, err = svc.UpdateBatchAudited(map[string]string{PolicyAccessPolicyDefault: model.AccessPolicyReason}, rec.actor, rec.auditor())
		require.NoError(t, err)
		assert.Len(t, rec.alerts(), 1, "reason 改 reason 不告警")
		assert.Len(t, rec.audits(), audits, "reason 改 reason 無審計列")
	})
}
