package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/testgate"
)

// floorDBKind 對帳測試的資料庫種類：檔案型 SQLite 或 PG（PG 子案例取 TEST_PG_DSN 的獨立 schema）。
func newFloorReconcileDB(t *testing.T, kind string) (*SecurityPolicyService, *gorm.DB) {
	t.Helper()
	cfg := &gorm.Config{Logger: logger.Discard}
	var db *gorm.DB
	var err error
	if kind == "postgres" {
		dsn := testgate.Value(t, testgate.EnvPGDSN)
		schema := fmt.Sprintf("p2g_floor_%d", time.Now().UnixNano())
		admin, err := gorm.Open(postgres.Open(dsn), cfg)
		require.NoError(t, err)
		require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
		t.Cleanup(func() {
			_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE")
			if s, err := admin.DB(); err == nil {
				_ = s.Close()
			}
		})
		db, err = gorm.Open(postgres.Open(dsn+" search_path="+schema), cfg)
		require.NoError(t, err)
		require.Equal(t, "postgres", db.Dialector.Name())
		t.Logf("EVIDENCE dialect=postgres")
		fmt.Println("EVIDENCE dialect=postgres")
	} else {
		db, err = gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "floor.db")), cfg)
		require.NoError(t, err)
	}
	t.Cleanup(func() {
		if s, err := db.DB(); err == nil {
			_ = s.Close()
		}
	})
	require.NoError(t, db.AutoMigrate(&model.SecurityPolicy{}, &model.SecurityPolicyHistory{},
		&model.SecurityPolicyFloorRaise{}, &model.AuditLog{}))
	return NewSecurityPolicyService(db), db
}

// floorAuditor 測試用的交易內審計寫入者：在呼叫端交易寫 audit_logs，failAt>0 時第 failAt 筆回錯。
func floorAuditor(failAt int) FloorRaiseAuditor {
	n := 0
	return func(tx *gorm.DB, r FloorRaise) error {
		n++
		if failAt > 0 && n == failAt {
			return errors.New("注入審計失敗")
		}
		details, _ := json.Marshal(map[string]any{"key": r.Key, "old": r.OldValue, "new": r.NewValue, "floor": r.Floor, "reason": r.Reason})
		return tx.Create(&model.AuditLog{Username: "system", Action: model.ActionRetentionFloorRaised,
			Resource: model.ResourceSecurityPolicy, Status: model.StatusSuccess, Details: string(details)}).Error
	}
}

type floorFixture struct {
	name                 string
	audit, cmd, alert    int
	rec, cp              int
	want                 [5]int
	wantRaises           int
	wantReasons          map[string]string
	wantUncoveredBefore  []string
	wantUncoveredAfter   []string
	wantIncidental       []string
	afterEqualsBeforeSet bool
}

func seedFloorFixture(t *testing.T, db *gorm.DB, f floorFixture) {
	t.Helper()
	vals := map[string]int{
		PolicyRetentionAuditLogDays: f.audit, PolicyRetentionSessionCommandDays: f.cmd,
		PolicyRetentionAlertDays: f.alert, PolicyRetentionRecordingDays: f.rec, PolicyRetentionCheckpointDays: f.cp,
	}
	for k, v := range vals {
		require.NoError(t, db.Save(&model.SecurityPolicy{Key: k, Value: strconv.Itoa(v), UpdatedBy: "legacy"}).Error)
	}
}

func readFloorValues(t *testing.T, db *gorm.DB) [5]int {
	t.Helper()
	var out [5]int
	for i, k := range []string{PolicyRetentionAuditLogDays, PolicyRetentionSessionCommandDays, PolicyRetentionAlertDays,
		PolicyRetentionRecordingDays, PolicyRetentionCheckpointDays} {
		var row model.SecurityPolicy
		require.NoError(t, db.Where("key = ?", k).First(&row).Error)
		n, err := strconv.Atoi(row.Value)
		require.NoError(t, err)
		out[i] = n
	}
	return out
}

func uncoveredKeys(u []UncoveredRetention) []string {
	out := []string{}
	for _, x := range u {
		out = append(out, x.Key)
	}
	sort.Strings(out)
	return out
}

func coveredSet(v [5]int) map[string]bool {
	out := map[string]bool{}
	for i, k := range []string{PolicyRetentionAuditLogDays, PolicyRetentionSessionCommandDays, PolicyRetentionAlertDays, PolicyRetentionRecordingDays} {
		out[k] = RetentionCovers(v[4], v[i])
	}
	return out
}

func countRows(t *testing.T, db *gorm.DB, m any) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(m).Count(&n).Error)
	return n
}

// captureFloorLog 把對帳 log 換成紀錄器替身，回傳取出已記錄行的函式。
func captureFloorLog(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var lines []string
	orig := floorReconcileLog
	floorReconcileLog = func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, fmt.Sprintf(format, args...))
	}
	t.Cleanup(func() { floorReconcileLog = orig })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string{}, lines...)
	}
}

// TestRetentionFloorUpgradeRaise 擋：升級對帳沒把 1–6 天抬到 7、檢查點沒跟隨而打破原本成立的
// 涵蓋關係、替管理者改寫原本違反的關係、重跑重複寫入、審計失敗卻半套生效、產生系統告警，
// 或讓跨鍵驗證因對帳而被削弱。
func TestRetentionFloorUpgradeRaise(t *testing.T) {
	A, D, C := PolicyRetentionAuditLogDays, PolicyRetentionAlertDays, PolicyRetentionCheckpointDays
	S, R := PolicyRetentionSessionCommandDays, PolicyRetentionRecordingDays
	fixtures := []floorFixture{
		{name: "A", audit: 3, cmd: 6, alert: 5, rec: 6, cp: 6, want: [5]int{7, 7, 7, 7, 7}, wantRaises: 5,
			wantReasons:         map[string]string{A: "below_floor", S: "below_floor", D: "below_floor", R: "below_floor", C: "cross_key_follow"},
			wantUncoveredBefore: []string{}, wantUncoveredAfter: []string{}, wantIncidental: []string{}, afterEqualsBeforeSet: true},
		{name: "B", audit: 3, cmd: 0, alert: 6, rec: 90, cp: 0, want: [5]int{7, 0, 7, 90, 0}, wantRaises: 2,
			wantReasons:         map[string]string{A: "below_floor", D: "below_floor"},
			wantUncoveredBefore: []string{}, wantUncoveredAfter: []string{}, wantIncidental: []string{}, afterEqualsBeforeSet: true},
		{name: "C", audit: 30, cmd: 0, alert: 6, rec: 90, cp: 10, want: [5]int{30, 0, 7, 90, 10}, wantRaises: 1,
			wantReasons:         map[string]string{D: "below_floor"},
			wantUncoveredBefore: floorKeysSorted(A, S, R), wantUncoveredAfter: floorKeysSorted(A, S, R), wantIncidental: []string{}, afterEqualsBeforeSet: true},
		{name: "D", audit: 3, cmd: 0, alert: 30, rec: 90, cp: 5, want: [5]int{7, 0, 30, 90, 7}, wantRaises: 2,
			wantReasons:         map[string]string{A: "below_floor", C: "cross_key_follow"},
			wantUncoveredBefore: floorKeysSorted(S, D, R), wantUncoveredAfter: floorKeysSorted(S, D, R), wantIncidental: []string{}, afterEqualsBeforeSet: true},
		{name: "E", audit: 3, cmd: 6, alert: 30, rec: 90, cp: 5, want: [5]int{7, 7, 30, 90, 7}, wantRaises: 3,
			wantReasons:         map[string]string{A: "below_floor", S: "below_floor", C: "cross_key_follow"},
			wantUncoveredBefore: floorKeysSorted(S, D, R), wantUncoveredAfter: floorKeysSorted(D, R), wantIncidental: []string{S}},
	}

	for _, f := range fixtures {
		f := f
		t.Run(f.name, func(t *testing.T) {
			logs := captureFloorLog(t)
			svc, db := newFloorReconcileDB(t, "sqlite")
			raiser := &countingRelaxRaiser{}
			svc.SetHighRiskAlertRaiser(raiser)
			seedFloorFixture(t, db, f)
			pre := [5]int{f.audit, f.cmd, f.alert, f.rec, f.cp}

			res, err := svc.ReconcileRetentionFloor(floorAuditor(0), "test-1.18.0")
			require.NoError(t, err, "對帳回 nil、啟動不失敗")
			post := readFloorValues(t, db)
			assert.Equal(t, f.want, post)
			assert.Len(t, res.Raised, f.wantRaises)
			assert.EqualValues(t, f.wantRaises, countRows(t, db, &model.AuditLog{}), "每個被改的鍵一筆審計")
			assert.EqualValues(t, f.wantRaises, countRows(t, db, &model.SecurityPolicyFloorRaise{}), "每個被改的鍵一筆抬升紀錄")
			var recs []model.SecurityPolicyFloorRaise
			require.NoError(t, db.Find(&recs).Error)
			got := map[string]string{}
			for _, r := range recs {
				got[r.PolicyKey] = r.Reason
				assert.Equal(t, "test-1.18.0", r.ProductVersion)
			}
			assert.Equal(t, f.wantReasons, got)
			for k := range f.wantReasons {
				var row model.SecurityPolicy
				require.NoError(t, db.Where("key = ?", k).First(&row).Error)
				assert.Equal(t, PolicyFloorRaisedBy, row.UpdatedBy)
			}

			assert.Equal(t, f.wantUncoveredBefore, uncoveredKeys(res.UncoveredBefore))
			assert.Equal(t, f.wantUncoveredAfter, uncoveredKeys(res.UncoveredAfter))
			assert.Equal(t, f.wantIncidental, uncoveredKeys(res.IncidentallyCovered))

			// 不變式：前狀態成立的每一組關係對帳後仍成立；對帳後未成立集合是前狀態未成立集合的子集
			preCov, postCov := coveredSet(pre), coveredSet(post)
			for k, ok := range preCov {
				if ok {
					assert.True(t, postCov[k], "前狀態成立的 %s 對帳後必須仍成立", k)
				}
			}
			for k, ok := range postCov {
				if !ok {
					assert.False(t, preCov[k], "對帳後未成立的 %s 必須是前狀態就未成立", k)
				}
			}
			if f.afterEqualsBeforeSet {
				assert.Equal(t, uncoveredKeys(res.UncoveredBefore), uncoveredKeys(res.UncoveredAfter))
			}

			// 唯讀介面：抬升紀錄與目前未涵蓋關係
			rep, err := svc.RetentionFloorReport()
			require.NoError(t, err)
			assert.Len(t, rep.Raises, f.wantRaises)
			assert.Equal(t, f.wantUncoveredAfter, uncoveredKeys(rep.Uncovered))

			// E：log 記下指令流因檢查點跟隨抬升而改為受涵蓋
			if f.name == "E" {
				found := false
				for _, l := range logs() {
					if strings.Contains(l, S) && strings.Contains(l, "改為受涵蓋") {
						found = true
					}
				}
				assert.True(t, found, "應有一行記下指令流因跟隨抬升而受涵蓋：%v", logs())
			}
			// 未消除的違反逐組記 log
			for _, u := range res.UncoveredAfter {
				found := false
				for _, l := range logs() {
					if strings.Contains(l, u.Key) && strings.Contains(l, "未成立") {
						found = true
					}
				}
				assert.True(t, found, "未涵蓋關係 %s 應記 log", u.Key)
			}

			// 對帳不產生系統告警
			assert.Zero(t, raiser.calls, "抬升是收緊，不得產生系統告警")

			// 第二次對帳 0 寫入
			res2, err := svc.ReconcileRetentionFloor(floorAuditor(0), "test-1.18.0")
			require.NoError(t, err)
			assert.Empty(t, res2.Raised)
			assert.EqualValues(t, f.wantRaises, countRows(t, db, &model.AuditLog{}))
			assert.EqualValues(t, f.wantRaises, countRows(t, db, &model.SecurityPolicyFloorRaise{}))
			assert.Equal(t, f.want, readFloorValues(t, db))

			// C：全域跨鍵驗證未被削弱
			if f.name == "C" {
				_, err := svc.UpdateBatchAudited(map[string]string{D: "8"}, PolicyActor{ID: 1, Name: "admin"}, floorNoopAuditor)
				var ck *PolicyRetentionCrossKeyError
				require.True(t, errors.As(err, &ck), "應回跨鍵驗證錯誤，實得 %v", err)
				assert.Equal(t, 7, readFloorValues(t, db)[2], "政策值不變")
			}
		})
	}

	t.Run("注入審計失敗時政策列與紀錄全部不變並回錯", func(t *testing.T) {
		svc, db := newFloorReconcileDB(t, "sqlite")
		f := fixtures[0]
		seedFloorFixture(t, db, f)
		_, err := svc.ReconcileRetentionFloor(floorAuditor(3), "test")
		require.Error(t, err)
		assert.Equal(t, [5]int{3, 6, 5, 6, 6}, readFloorValues(t, db))
		assert.Zero(t, countRows(t, db, &model.SecurityPolicyFloorRaise{}))
		assert.Zero(t, countRows(t, db, &model.AuditLog{}))
	})

	t.Run("唯讀介面：政策列查詢失敗時回錯，不回成功的空清單", func(t *testing.T) {
		svc, db := newFloorReconcileDB(t, "sqlite")
		// 實際有未涵蓋關係：錄影 90 > 檢查點 30
		seedFloorFixture(t, db, floorFixture{audit: 30, cmd: 30, alert: 30, rec: 90, cp: 30})
		rep, err := svc.RetentionFloorReport()
		require.NoError(t, err)
		require.Equal(t, []string{R}, uncoveredKeys(rep.Uncovered), "前提：正常讀取時列出錄影")
		fresh := NewSecurityPolicyService(db)
		require.NoError(t, db.Callback().Query().Before("gorm:query").Register("p2g:fail-security-policies", func(d *gorm.DB) {
			if d.Statement.Table == "security_policies" {
				_ = d.AddError(errors.New("注入政策列查詢失敗"))
			}
		}))
		t.Cleanup(func() { _ = db.Callback().Query().Remove("p2g:fail-security-policies") })
		rep, err = fresh.RetentionFloorReport()
		require.Error(t, err, "讀不到現值時不得回成功")
		assert.Empty(t, rep.Uncovered)
		assert.Empty(t, rep.Raises)
	})

	t.Run("postgres", func(t *testing.T) {
		t.Run("fixture A", func(t *testing.T) {
			svc, db := newFloorReconcileDB(t, "postgres")
			seedFloorFixture(t, db, fixtures[0])
			res, err := svc.ReconcileRetentionFloor(floorAuditor(0), "test")
			require.NoError(t, err)
			assert.Len(t, res.Raised, 5)
			assert.Equal(t, [5]int{7, 7, 7, 7, 7}, readFloorValues(t, db))
			assert.EqualValues(t, 5, countRows(t, db, &model.AuditLog{}))
			assert.EqualValues(t, 5, countRows(t, db, &model.SecurityPolicyFloorRaise{}))
			res2, err := svc.ReconcileRetentionFloor(floorAuditor(0), "test")
			require.NoError(t, err)
			assert.Empty(t, res2.Raised)
		})
		t.Run("注入審計失敗", func(t *testing.T) {
			svc, db := newFloorReconcileDB(t, "postgres")
			seedFloorFixture(t, db, fixtures[0])
			_, err := svc.ReconcileRetentionFloor(floorAuditor(2), "test")
			require.Error(t, err)
			assert.Equal(t, [5]int{3, 6, 5, 6, 6}, readFloorValues(t, db))
			assert.Zero(t, countRows(t, db, &model.SecurityPolicyFloorRaise{}))
			assert.Zero(t, countRows(t, db, &model.AuditLog{}))
		})
	})
}

func floorKeysSorted(keys ...string) []string {
	out := append([]string{}, keys...)
	sort.Strings(out)
	return out
}

// countingRelaxRaiser 計數告警掛點的呼叫次數（對帳不得呼叫）。
type countingRelaxRaiser struct{ calls int }

func (c *countingRelaxRaiser) RaiseHighRiskInTx(_ *gorm.DB, _ HighRiskAlert) error {
	c.calls++
	return nil
}
