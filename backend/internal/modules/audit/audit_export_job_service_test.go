package audit

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 匯出 job 受理面（服務層部分）。
//
// 本檔釘五件事：
//  1. 去重僅及 pending/running；failed 不阻擋重新發起、done 舊包不復用。
//  2. 每申請者與全域進行中上限；上限檢查與建立在同一交易內，並行發起不穿透。
//  3. 清單只含本人、id 降冪穩定排序、分頁正確。
//  4. GetForDownload 對「不存在」與「非申請者」收斂同一哨兵。
//  5. 篩選快照可往返（worker 重建打包範圍的前提）。
//
// 邊界明載：sqlite 單寫者使交易天然序列化，postgres 的表鎖分支
// （SHARE ROW EXCLUSIVE）在單元測試打不到——其射程由 admission 全程單交易
// ＋pg 部分唯一索引（migration）承擔，並行測試在此驗的是「檢查與建立不可分割」。

func newJobServiceDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	// sqlite :memory: 連線池陷阱（ff51836）：收斂單連線
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.AuditExportJob{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func jobFilterForUser(userID uint) *ExportFilter {
	id := userID
	return &ExportFilter{UserID: &id}
}

func jobFilterForSession(sessionID uint) *ExportFilter {
	id := sessionID
	return &ExportFilter{SessionID: &id}
}

func TestExportJobDedupOnlyPendingRunning(t *testing.T) {
	svc := NewAuditExportJobService(newJobServiceDB(t))

	first, created, err := svc.CreateJob(1, "auditor", jobFilterForUser(9))
	if err != nil || !created {
		t.Fatalf("首次發起: created=%v err=%v", created, err)
	}

	// 同人同範圍、pending 中：去重回同一 job
	dup, created, err := svc.CreateJob(1, "auditor", jobFilterForUser(9))
	if err != nil {
		t.Fatalf("去重發起: %v", err)
	}
	if created || dup.ID != first.ID {
		t.Fatalf("pending 去重失效: created=%v dup.ID=%d want %d", created, dup.ID, first.ID)
	}

	// running 同樣去重
	if err := svc.db.Model(&model.AuditExportJob{}).Where("id = ?", first.ID).
		Update("status", model.ExportJobRunning).Error; err != nil {
		t.Fatalf("轉 running: %v", err)
	}
	dup, created, err = svc.CreateJob(1, "auditor", jobFilterForUser(9))
	if err != nil || created || dup.ID != first.ID {
		t.Fatalf("running 去重失效: created=%v err=%v", created, err)
	}

	// failed 不阻擋重新發起（spec：失敗態不參與去重阻擋）
	if err := svc.db.Model(&model.AuditExportJob{}).Where("id = ?", first.ID).
		Update("status", model.ExportJobFailed).Error; err != nil {
		t.Fatalf("轉 failed: %v", err)
	}
	refire, created, err := svc.CreateJob(1, "auditor", jobFilterForUser(9))
	if err != nil || !created || refire.ID == first.ID {
		t.Fatalf("failed 阻擋了重新發起: created=%v err=%v id=%d", created, err, refire.ID)
	}

	// done 不復用（舊包冒充新申請＝錯置時點）
	if err := svc.db.Model(&model.AuditExportJob{}).Where("id = ?", refire.ID).
		Update("status", model.ExportJobDone).Error; err != nil {
		t.Fatalf("轉 done: %v", err)
	}
	again, created, err := svc.CreateJob(1, "auditor", jobFilterForUser(9))
	if err != nil || !created || again.ID == refire.ID {
		t.Fatalf("done 被當新申請復用: created=%v err=%v", created, err)
	}
}

// 不同申請者同範圍不互相去重（去重鍵含 requester）
func TestExportJobDedupScopedToRequester(t *testing.T) {
	svc := NewAuditExportJobService(newJobServiceDB(t))
	a, _, err := svc.CreateJob(1, "a", jobFilterForUser(9))
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, created, err := svc.CreateJob(2, "b", jobFilterForUser(9))
	if err != nil || !created || b.ID == a.ID {
		t.Fatalf("跨申請者被去重: created=%v err=%v", created, err)
	}
}

func TestExportJobPerRequesterLimit(t *testing.T) {
	svc := NewAuditExportJobService(newJobServiceDB(t))
	for i := uint(0); i < exportJobPerRequesterLimit; i++ {
		if _, _, err := svc.CreateJob(1, "auditor", jobFilterForSession(100+i)); err != nil {
			t.Fatalf("第 %d 件: %v", i+1, err)
		}
	}
	_, _, err := svc.CreateJob(1, "auditor", jobFilterForSession(999))
	if !errors.Is(err, ErrExportJobLimitExceeded) {
		t.Fatalf("超額發起未被擋: err=%v", err)
	}
	// 他人不受影響（額度是 per-requester）
	if _, _, err := svc.CreateJob(2, "other", jobFilterForSession(999)); err != nil {
		t.Fatalf("他人發起被錯誤波及: %v", err)
	}
}

func TestExportJobGlobalLimit(t *testing.T) {
	svc := NewAuditExportJobService(newJobServiceDB(t))
	created := 0
	requester := uint(1)
	for created < exportJobGlobalLimit {
		for i := 0; i < exportJobPerRequesterLimit && created < exportJobGlobalLimit; i++ {
			if _, _, err := svc.CreateJob(requester, "u", jobFilterForSession(uint(1000+created))); err != nil {
				t.Fatalf("填充第 %d 件: %v", created+1, err)
			}
			created++
		}
		requester++
	}
	_, _, err := svc.CreateJob(99, "z", jobFilterForSession(2000))
	if !errors.Is(err, ErrExportJobLimitExceeded) {
		t.Fatalf("全域超額未被擋: err=%v", err)
	}
}

// 並行發起不得同時穿透上限：檢查與建立同一交易，10 路併發打同一申請者，
// 成功數必須恰為上限、其餘收斂上限錯誤，總列數不得超額
func TestExportJobParallelAdmissionDoesNotPierceLimit(t *testing.T) {
	db := newJobServiceDB(t)
	svc := NewAuditExportJobService(db)

	const parallel = 10
	var wg sync.WaitGroup
	errs := make([]error, parallel)
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, errs[i] = svc.CreateJob(1, "auditor", jobFilterForSession(uint(3000+i)))
		}(i)
	}
	wg.Wait()

	okCount, limitCount := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			okCount++
		case errors.Is(err, ErrExportJobLimitExceeded):
			limitCount++
		default:
			t.Fatalf("非預期錯誤: %v", err)
		}
	}
	if okCount != exportJobPerRequesterLimit || limitCount != parallel-exportJobPerRequesterLimit {
		t.Fatalf("並行受理穿透: ok=%d limit=%d（上限 %d）", okCount, limitCount, exportJobPerRequesterLimit)
	}
	var rows int64
	if err := db.Model(&model.AuditExportJob{}).Count(&rows).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != int64(exportJobPerRequesterLimit) {
		t.Fatalf("落庫列數超額: %d", rows)
	}
}

func TestExportJobListOnlyOwnStableOrder(t *testing.T) {
	svc := NewAuditExportJobService(newJobServiceDB(t))
	var mineIDs []uint
	for i := 0; i < 3; i++ {
		j, _, err := svc.CreateJob(1, "mine", jobFilterForSession(uint(10+i)))
		if err != nil {
			t.Fatalf("mine %d: %v", i, err)
		}
		mineIDs = append(mineIDs, j.ID)
	}
	if _, _, err := svc.CreateJob(2, "other", jobFilterForSession(88)); err != nil {
		t.Fatalf("other: %v", err)
	}

	jobs, total, err := svc.List(1, model.ExportJobKindEvidenceBundle, 1, 2)
	if err != nil {
		t.Fatalf("list p1: %v", err)
	}
	if total != 3 || len(jobs) != 2 {
		t.Fatalf("分頁一: total=%d len=%d", total, len(jobs))
	}
	// id 降冪穩定排序
	if jobs[0].ID != mineIDs[2] || jobs[1].ID != mineIDs[1] {
		t.Fatalf("排序不穩定: got [%d %d] want [%d %d]", jobs[0].ID, jobs[1].ID, mineIDs[2], mineIDs[1])
	}
	jobs, _, err = svc.List(1, model.ExportJobKindEvidenceBundle, 2, 2)
	if err != nil || len(jobs) != 1 || jobs[0].ID != mineIDs[0] {
		t.Fatalf("分頁二: err=%v", err)
	}
	// 只含本人
	for _, j := range jobs {
		if j.RequesterID != 1 {
			t.Fatalf("清單洩出他人 job: requester=%d", j.RequesterID)
		}
	}
}

func TestExportJobGetForDownloadConverges(t *testing.T) {
	svc := NewAuditExportJobService(newJobServiceDB(t))
	j, _, err := svc.CreateJob(1, "mine", jobFilterForSession(5))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := svc.GetForDownload(j.ID, 1); err != nil {
		t.Fatalf("本人取件: %v", err)
	}
	// 非申請者與不存在收斂同一哨兵（不洩存在性）
	if _, err := svc.GetForDownload(j.ID, 2); !errors.Is(err, ErrExportJobNotFound) {
		t.Fatalf("他人取件未收斂: %v", err)
	}
	if _, err := svc.GetForDownload(99999, 1); !errors.Is(err, ErrExportJobNotFound) {
		t.Fatalf("不存在未收斂: %v", err)
	}
}

func TestExportFilterSnapshotRoundTrip(t *testing.T) {
	uid := uint(7)
	from := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(24 * time.Hour)
	filter := &ExportFilter{UserID: &uid, StartTime: &from, EndTime: &to}

	snapshot, hash, err := exportFilterSnapshot(filter)
	if err != nil || hash == "" {
		t.Fatalf("snapshot: %v", err)
	}
	back, err := ParseExportFilterSnapshot(snapshot)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if back.UserID == nil || *back.UserID != uid ||
		back.StartTime == nil || !back.StartTime.Equal(from) ||
		back.EndTime == nil || !back.EndTime.Equal(to) || back.SessionID != nil {
		t.Fatalf("快照往返失真: %+v", back)
	}
	// 同條件同雜湊（去重鍵的前提）
	_, hash2, err := exportFilterSnapshot(filter)
	if err != nil || hash2 != hash {
		t.Fatalf("同條件雜湊不穩定: %s vs %s", hash, hash2)
	}
}
