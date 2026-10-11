package policy

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/testgate"
	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupHistoryDB(t *testing.T) (*SecurityPolicyService, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.AutoMigrate(&model.SecurityPolicy{}, &model.SecurityPolicyHistory{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewSecurityPolicyService(db), db
}

func noLocaltime() (string, error) { return "", os.ErrNotExist }

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// TestDailyReviewTimezonePolicyValidation 擋：映像缺時區資料時非 UTC 時區全被拒，
// 或不合法名稱被收下而讓切日退回本地時區；首次啟動的播種覆蓋管理者設定的值
func TestDailyReviewTimezonePolicyValidation(t *testing.T) {
	t.Run("合法值收下", func(t *testing.T) {
		svc, _ := setupHistoryDB(t)
		for _, v := range []string{"Asia/Taipei", "UTC", "America/New_York"} {
			if _, err := svc.Update(PolicyDailyReviewTimezone, v, "admin"); err != nil {
				t.Errorf("%s 被拒: %v", v, err)
			}
			if got := svc.Get(PolicyDailyReviewTimezone); got != v {
				t.Errorf("現值 = %q, want %q", got, v)
			}
		}
	})
	t.Run("不合法值拒絕且不寫入", func(t *testing.T) {
		svc, db := setupHistoryDB(t)
		for _, v := range []string{"Mars/Olympus", "Local", ""} {
			_, err := svc.Update(PolicyDailyReviewTimezone, v, "admin")
			var invalid *PolicyInvalidValueError
			if !errors.As(err, &invalid) || invalid.Key != PolicyDailyReviewTimezone {
				t.Errorf("%q: err=%v, want PolicyInvalidValueError{Key: daily_review_timezone}（handler 轉 VALIDATION_POLICY_INVALID_VALUE）", v, err)
			}
		}
		var rows, hist int64
		db.Model(&model.SecurityPolicy{}).Count(&rows)
		db.Model(&model.SecurityPolicyHistory{}).Count(&hist)
		if rows != 0 || hist != 0 {
			t.Errorf("被拒的值留下了政策列 %d／歷史 %d", rows, hist)
		}
	})
	t.Run("出廠值為 UTC", func(t *testing.T) {
		svc, _ := setupHistoryDB(t)
		if got := svc.Get(PolicyDailyReviewTimezone); got != "UTC" {
			t.Errorf("出廠值 = %q, want UTC", got)
		}
	})

	seedCases := []struct {
		name    string
		env     map[string]string
		preset  string
		want    string
		histLen int
	}{
		{"TZ 可載入即採用", map[string]string{"TZ": "Asia/Taipei"}, "", "Asia/Taipei", 1},
		{"無 TZ 無 localtime 得 UTC", map[string]string{}, "", "UTC", 0},
		{"TZ 不可載入且無 localtime 得 UTC", map[string]string{"TZ": "Mars/Olympus"}, "", "UTC", 0},
		{"已設 UTC 後以 TZ 啟動仍為 UTC", map[string]string{"TZ": "Asia/Taipei"}, "UTC", "UTC", 0},
	}
	for _, tc := range seedCases {
		t.Run("播種/"+tc.name, func(t *testing.T) {
			svc, db := setupHistoryDB(t)
			if tc.preset != "" {
				// 管理者設定過（含與出廠同值的設定：政策列存在即不動）
				if err := db.Create(&model.SecurityPolicy{Key: PolicyDailyReviewTimezone, Value: tc.preset, UpdatedBy: "admin", UpdatedAt: time.Now()}).Error; err != nil {
					t.Fatal(err)
				}
			}
			svc.SeedDailyReviewTimezone(envOf(tc.env), noLocaltime)
			if got := svc.Get(PolicyDailyReviewTimezone); got != tc.want {
				t.Errorf("播種後 = %q, want %q", got, tc.want)
			}
			hist, err := svc.History(PolicyDailyReviewTimezone)
			if err != nil {
				t.Fatal(err)
			}
			if len(hist) != tc.histLen {
				t.Errorf("歷史 %d 列, want %d", len(hist), tc.histLen)
			}
			if len(hist) == 1 && hist[0].Source != model.PolicyHistorySourceSeed {
				t.Errorf("播種歷史來源 = %q, want seed", hist[0].Source)
			}
		})
	}
	t.Run("播種/localtime 指向的時區", func(t *testing.T) {
		svc, _ := setupHistoryDB(t)
		svc.SeedDailyReviewTimezone(envOf(nil), func() (string, error) { return "/usr/share/zoneinfo/Asia/Tokyo", nil })
		if got := svc.Get(PolicyDailyReviewTimezone); got != "Asia/Tokyo" {
			t.Errorf("播種後 = %q, want Asia/Tokyo", got)
		}
	})
}

// openPolicyPG 在獨立 schema 建政策兩表
func openPolicyPG(t *testing.T, schema string) *gorm.DB {
	t.Helper()
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("postgres 連線失敗: %v", err)
	}
	drop := "DROP SCHEMA IF EXISTS " + schema + " CASCADE"
	if err := admin.Exec(drop).Error; err != nil {
		t.Fatal(err)
	}
	if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = admin.Exec(drop)
		if s, err := admin.DB(); err == nil {
			_ = s.Close()
		}
	})
	db, err := gorm.Open(postgres.Open(dsn+" search_path="+schema), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if s, err := db.DB(); err == nil {
			_ = s.Close()
		}
	})
	if err := db.AutoMigrate(&model.SecurityPolicy{}, &model.SecurityPolicyHistory{}); err != nil {
		t.Fatal(err)
	}
	return db
}

// waitingOnHistoryLock 有多少個交易正在等政策歷史鎖（advisory lock 以 bigint 鍵
// 取得時，pg_locks 的 classid／objid 是鍵的高低 32 位元）
func waitingOnHistoryLock(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	key := policyHistoryLockKey
	hi, lo := uint32(key>>32), uint32(key)
	if err := db.Raw(`SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND classid = ? AND objid = ? AND objsubid = 1 AND NOT granted`, hi, lo).Scan(&n).Error; err != nil {
		t.Fatalf("查 pg_locks: %v", err)
	}
	return n
}

func replayLast(rows []model.SecurityPolicyHistory, key, initial string) string {
	v := initial
	for _, r := range rows {
		if r.PolicyKey == key {
			v = r.NewValue
		}
	}
	return v
}

// TestPolicyHistorySerializedWrites 擋：兩個並行寫入讀到同一舊值，歷史只記一次啟用
// 而重播結果與現值相反，行事曆把關閉區間算成應簽
func TestPolicyHistorySerializedWrites(t *testing.T) {
	for _, first := range []string{"true", "false"} {
		first := first
		t.Run("先取鎖者寫"+first, func(t *testing.T) {
			db := openPolicyPG(t, fmt.Sprintf("policy_history_%s_%d", first, time.Now().UnixNano()))
			svc := NewSecurityPolicyService(db)
			if err := db.Create(&model.SecurityPolicy{Key: PolicyDailyReviewEnabled, Value: "false", UpdatedBy: "init", UpdatedAt: time.Now()}).Error; err != nil {
				t.Fatal(err)
			}
			second := map[string]string{"true": "false", "false": "true"}[first]
			actorOf := map[string]string{first: "first", second: "second"}

			var arrived sync.WaitGroup
			arrived.Add(2)
			goFirst, goSecond := make(chan struct{}), make(chan struct{})
			firstLocked, releaseFirst := make(chan struct{}), make(chan struct{})
			policyHistoryHooks.beforeLock = func(by string) {
				// barrier：兩個交易都已開啟才放行取鎖
				arrived.Done()
				if by == "first" {
					<-goFirst
				} else {
					<-goSecond
				}
			}
			policyHistoryHooks.afterLock = func(by string) {
				if by == "first" {
					close(firstLocked)
					<-releaseFirst
				}
			}
			t.Cleanup(func() { policyHistoryHooks.beforeLock, policyHistoryHooks.afterLock = nil, nil })

			errs := make(chan error, 2)
			for _, v := range []string{first, second} {
				v := v
				go func() {
					_, err := svc.UpdateBatch(map[string]string{PolicyDailyReviewEnabled: v}, actorOf[v])
					errs <- err
				}()
			}
			arrived.Wait()
			close(goFirst)
			<-firstLocked
			close(goSecond)
			// 確認另一方正在等同一把鎖，才放行先行者
			deadline := time.Now().Add(10 * time.Second)
			for waitingOnHistoryLock(t, db) < 1 {
				if time.Now().After(deadline) {
					t.Fatal("後行者未在等政策歷史鎖：寫入沒有被序列化")
				}
				time.Sleep(10 * time.Millisecond)
			}
			close(releaseFirst)
			for i := 0; i < 2; i++ {
				if err := <-errs; err != nil {
					t.Fatalf("寫入失敗: %v", err)
				}
			}

			hist, err := svc.History(PolicyDailyReviewEnabled)
			if err != nil {
				t.Fatal(err)
			}
			var cur model.SecurityPolicy
			db.Where("key = ?", PolicyDailyReviewEnabled).First(&cur)
			if first == "true" {
				if len(hist) != 2 || hist[0].OldValue != "false" || hist[0].NewValue != "true" || hist[1].OldValue != "true" || hist[1].NewValue != "false" {
					t.Errorf("歷史 = %+v, want false→true、true→false 依序銜接", hist)
				}
				if cur.Value != "false" {
					t.Errorf("現值 = %q, want false", cur.Value)
				}
			} else {
				if len(hist) != 1 || hist[0].OldValue != "false" || hist[0].NewValue != "true" {
					t.Errorf("歷史 = %+v, want 只有一筆 false→true（先行者同值不留歷史）", hist)
				}
				if cur.Value != "true" {
					t.Errorf("現值 = %q, want true", cur.Value)
				}
			}
			if got := replayLast(hist, PolicyDailyReviewEnabled, "false"); got != cur.Value {
				t.Errorf("重播末值 %q ≠ 現值 %q", got, cur.Value)
			}
		})
	}

	t.Run("交易內失敗則現值與歷史皆未寫入", func(t *testing.T) {
		db := openPolicyPG(t, fmt.Sprintf("policy_history_fail_%d", time.Now().UnixNano()))
		svc := NewSecurityPolicyService(db)
		policyHistoryHooks.afterWrite = func(string) error { return errors.New("注入失敗") }
		t.Cleanup(func() { policyHistoryHooks.afterWrite = nil })
		if _, err := svc.UpdateBatch(map[string]string{PolicyDailyReviewEnabled: "true", PolicyDailyReviewTimezone: "Asia/Taipei"}, "admin"); err == nil {
			t.Fatal("注入失敗卻回成功")
		}
		var rows, hist int64
		db.Model(&model.SecurityPolicy{}).Count(&rows)
		db.Model(&model.SecurityPolicyHistory{}).Count(&hist)
		if rows != 0 || hist != 0 {
			t.Errorf("回滾後仍有政策列 %d／歷史 %d", rows, hist)
		}
	})

	t.Run("同值儲存不新增歷史", func(t *testing.T) {
		db := openPolicyPG(t, fmt.Sprintf("policy_history_same_%d", time.Now().UnixNano()))
		svc := NewSecurityPolicyService(db)
		if _, err := svc.Update(PolicyDailyReviewEnabled, "true", "admin"); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.UpdateBatch(map[string]string{PolicyDailyReviewEnabled: "true", PolicyLockoutMaxAttempts: "5"}, "admin"); err != nil {
			t.Fatal(err)
		}
		hist, _ := svc.History()
		if len(hist) != 1 {
			t.Errorf("歷史 %d 列, want 1（同值儲存與非保留歷史鍵都不留歷史）", len(hist))
		}
	})
}
