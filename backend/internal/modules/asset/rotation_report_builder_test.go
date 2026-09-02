package asset

import (
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/model"
)

// 報告資料集的計算規則。每一條規則對應報告上的一個數字，而那些數字會被
// 當成證據使用——算錯不會有人在畫面上看出來。

// reportFixture 一組建構者與其底層 DB。
type reportFixture struct {
	db      *gorm.DB
	plans   *ChangeSecretPlanService
	builder *RotationReportBuilder
	global  int
}

func newReportFixture(t *testing.T) *reportFixture {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	// 單連線：`:memory:` 每條連線是各自獨立的空庫
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&model.Asset{}, &model.AssetAccount{},
		&model.AssetGroup{}, &model.AssetNode{}, &model.AuditLog{}, &model.ChangeSecretPlan{},
		&model.ChangeSecretRecord{}, &model.ChangeSecretCandidate{}))

	f := &reportFixture{db: db, plans: NewChangeSecretPlanService(db)}
	f.builder = NewRotationReportBuilder(db, f.plans, func() int { return f.global })
	return f
}

func (f *reportFixture) asset(t *testing.T, name string) *model.Asset {
	t.Helper()
	a := &model.Asset{Name: name, Protocol: model.ProtocolSSH, Host: "10.0.0.1", Port: 22}
	require.NoError(t, f.db.Create(a).Error)
	return a
}

func (f *reportFixture) account(t *testing.T, assetID uint, username string) *model.AssetAccount {
	t.Helper()
	acc := &model.AssetAccount{AssetID: assetID, Username: username, PasswordEnc: "enc"}
	require.NoError(t, f.db.Create(acc).Error)
	return acc
}

func (f *reportFixture) success(t *testing.T, acc *model.AssetAccount, at time.Time) {
	t.Helper()
	require.NoError(t, f.db.Create(&model.ChangeSecretRecord{
		PlanID: 1, AssetID: acc.AssetID, AccountID: acc.ID, AccountUsername: acc.Username,
		Status: model.ChangeSecretSuccess, ExecutedAt: at,
	}).Error)
}

func (f *reportFixture) build(t *testing.T, scope ReportScope, asOf time.Time) *RotationReport {
	t.Helper()
	rep, err := f.builder.Build(scope, asOf.Add(-30*24*time.Hour), asOf, asOf, "zh-TW")
	require.NoError(t, err)
	return rep
}

func bucketOfAccount(rep *RotationReport, accountID uint) string {
	for i := range rep.Rows {
		if rep.Rows[i].AccountID == accountID {
			return rep.Rows[i].Bucket
		}
	}
	return "<not-in-report>"
}

func rowOfAccount(t *testing.T, rep *RotationReport, accountID uint) AccountRow {
	t.Helper()
	for i := range rep.Rows {
		if rep.Rows[i].AccountID == accountID {
			return rep.Rows[i]
		}
	}
	t.Fatalf("帳號 %d 不在報告中", accountID)
	return AccountRow{}
}

// TestRotationReportBuckets 六個桶各至少一案，並釘住三個邊界：A=0 與 A=30 屬
// 「即將到期」、A=-1 才是逾期。
//
// 邊界寫死在測試裡的理由：這三個值決定一個帳號在稽核報告上是「合規」還是
// 「違規」，差一天的判定錯誤在畫面上完全看不出來。
func TestRotationReportBuckets(t *testing.T) {
	f := newReportFixture(t)
	f.global = 90
	asOf := mustTime(t, "2026-09-02T00:00:00Z")
	a := f.asset(t, "host-a")

	// 合規：60 天前改過，剩 30 天以上
	compliant := f.account(t, a.ID, "compliant")
	f.success(t, compliant, asOf.Add(-31*24*time.Hour))

	// A = 0（今天到期）與 A = 30（預警窗上緣）皆屬即將到期
	dueZero := f.account(t, a.ID, "due-zero")
	f.success(t, dueZero, asOf.Add(-90*24*time.Hour))
	dueEdge := f.account(t, a.ID, "due-edge")
	f.success(t, dueEdge, asOf.Add(-60*24*time.Hour))

	// A = -1：逾期
	overdue := f.account(t, a.ID, "overdue")
	f.success(t, overdue, asOf.Add(-91*24*time.Hour))

	// 無成功記錄
	noRecord := f.account(t, a.ID, "no-record")
	require.NoError(t, f.db.Create(&model.ChangeSecretRecord{
		PlanID: 1, AssetID: a.ID, AccountID: noRecord.ID, AccountUsername: "no-record",
		Status: model.ChangeSecretFailed, ExecutedAt: asOf.Add(-time.Hour),
	}).Error)

	// 未驗證候選：即使早就改過也優先落此桶
	unverified := f.account(t, a.ID, "unverified")
	f.success(t, unverified, asOf.Add(-1*24*time.Hour))
	require.NoError(t, f.db.Create(&model.ChangeSecretCandidate{
		AccountID: unverified.ID, AssetID: a.ID, SecretType: model.ChangeSecretTypePassword,
	}).Error)

	rep := f.build(t, ReportScope{Kind: model.RotationScopeAll}, asOf)

	assert.Equal(t, BucketCompliant, bucketOfAccount(rep, compliant.ID))
	assert.Equal(t, BucketDueSoon, bucketOfAccount(rep, dueZero.ID), "A=0 屬即將到期")
	assert.Equal(t, BucketDueSoon, bucketOfAccount(rep, dueEdge.ID), "A=30 屬即將到期")
	assert.Equal(t, BucketOverdue, bucketOfAccount(rep, overdue.ID), "A=-1 才是逾期")
	assert.Equal(t, BucketNoRecord, bucketOfAccount(rep, noRecord.ID))
	assert.Equal(t, BucketUnverified, bucketOfAccount(rep, unverified.ID))

	// 無政策：全域關閉時的另一份報告
	f.global = 0
	noPolicy := f.build(t, ReportScope{Kind: model.RotationScopeAll}, asOf)
	assert.Equal(t, BucketNoPolicy, bucketOfAccount(noPolicy, compliant.ID),
		"全域未設定且無計劃覆蓋時無從判定逾期")
	assert.Equal(t, BucketUnverified, bucketOfAccount(noPolicy, unverified.ID),
		"未驗證的優先序高於無政策")

	// 邊界值本身
	assert.Equal(t, 0, *rowOfAccount(t, rep, dueZero.ID).RemainingDaysA)
	assert.Equal(t, 30, *rowOfAccount(t, rep, dueEdge.ID).RemainingDaysA)
	assert.Equal(t, -1, *rowOfAccount(t, rep, overdue.ID).RemainingDaysA)

	// 摘要數字＝各桶列數
	assert.Equal(t, 6, rep.Summary.TotalAccounts)
	assert.Equal(t, 1, rep.Summary.Compliant)
	assert.Equal(t, 2, rep.Summary.DueWithin30)
	assert.Equal(t, 1, rep.Summary.Overdue)
	assert.Equal(t, 1, rep.Summary.NoRecord)
	assert.Equal(t, 1, rep.Summary.Unverified)
}

// TestRotationReportMultiPlanStrictest 多計劃涵蓋時天數取最小、排程取最近，
// 並列出全部計劃名。
func TestRotationReportMultiPlanStrictest(t *testing.T) {
	f := newReportFixture(t)
	f.global = 90
	asOf := mustTime(t, "2026-09-02T00:00:00Z")
	a := f.asset(t, "host-a")
	acc := f.account(t, a.ID, "root")

	_, err := f.plans.Create(&ChangeSecretPlanRequest{
		Name: "甲", AssetIDs: []uint{a.ID}, MaxAgeDays: 60, Cron: "0 3 1 * *",
	})
	require.NoError(t, err)
	_, err = f.plans.Create(&ChangeSecretPlanRequest{
		Name: "乙", AssetIDs: []uint{a.ID}, MaxAgeDays: 90, Cron: "0 3 * * *",
	})
	require.NoError(t, err)

	f.success(t, acc, asOf.Add(-10*24*time.Hour))
	rep := f.build(t, ReportScope{Kind: model.RotationScopeAll}, asOf)
	row := rowOfAccount(t, rep, acc.ID)

	assert.Equal(t, 60, row.MaxAgeDays, "取最嚴＝天數最小")
	assert.Equal(t, MaxAgeSourcePlanPrefix+"甲", row.MaxAgeSource)
	assert.True(t, row.MultiPlan)
	assert.Equal(t, []string{"乙", "甲"}, row.Plans)
	require.NotNil(t, row.NextScheduleAt)
	assert.Equal(t, mustTime(t, "2026-09-02T03:00:00Z"), row.NextScheduleAt.UTC(),
		"排程取最近的一次（每日排程勝過每月）")
	require.NotNil(t, row.RemainingDaysB)
	assert.Equal(t, 0, *row.RemainingDaysB)
	assert.Equal(t, 50, *row.RemainingDaysA)
	assert.Equal(t, 1, rep.Summary.MultiPlan)
}

// TestRotationReportRatesDenominatorZero 分母為零時合規率為「不適用」而非 0%。
func TestRotationReportRatesDenominatorZero(t *testing.T) {
	f := newReportFixture(t)
	f.global = 0 // 全域未設定：全部落 no_policy
	asOf := mustTime(t, "2026-09-02T00:00:00Z")
	a := f.asset(t, "host-a")
	f.account(t, a.ID, "one")
	f.account(t, a.ID, "two")

	rep := f.build(t, ReportScope{Kind: model.RotationScopeAll}, asOf)
	assert.Equal(t, 2, rep.Summary.NoPolicy)
	assert.Nil(t, rep.Summary.RateCountingNoRecord, "分母為零不得輸出 0%")
	assert.Nil(t, rep.Summary.RateExcludingNoRecord)

	// 對照組：有分母時兩種率各自算得出來
	f.global = 90
	acc := f.account(t, a.ID, "three")
	f.success(t, acc, asOf.Add(-1*24*time.Hour))
	rep2 := f.build(t, ReportScope{Kind: model.RotationScopeAll}, asOf)
	require.NotNil(t, rep2.Summary.RateCountingNoRecord)
	require.NotNil(t, rep2.Summary.RateExcludingNoRecord)
	// 三個帳號：一個合規、兩個無記錄
	assert.InDelta(t, 1.0/3.0, *rep2.Summary.RateCountingNoRecord, 1e-9)
	assert.InDelta(t, 1.0, *rep2.Summary.RateExcludingNoRecord, 1e-9)
}

// TestRotationReportScopeNodeSubtree 節點範圍含子樹，且同一資產多掛載只算一次。
func TestRotationReportScopeNodeSubtree(t *testing.T) {
	f := newReportFixture(t)
	f.global = 90
	asOf := mustTime(t, "2026-09-02T00:00:00Z")

	root := &model.AssetGroup{Name: "核心系統"}
	require.NoError(t, f.db.Create(root).Error)
	child := &model.AssetGroup{Name: "子節點", ParentID: &root.ID}
	require.NoError(t, f.db.Create(child).Error)
	other := &model.AssetGroup{Name: "無關節點"}
	require.NoError(t, f.db.Create(other).Error)

	inRoot := f.asset(t, "in-root")
	inChild := f.asset(t, "in-child")
	outside := f.asset(t, "outside")
	for _, n := range []struct{ a, g uint }{
		{inRoot.ID, root.ID},
		{inRoot.ID, child.ID}, // 多掛載：同一資產掛在父與子
		{inChild.ID, child.ID},
		{outside.ID, other.ID},
	} {
		require.NoError(t, f.db.Create(&model.AssetNode{AssetID: n.a, NodeID: n.g}).Error)
	}
	accRoot := f.account(t, inRoot.ID, "a")
	accChild := f.account(t, inChild.ID, "b")
	accOut := f.account(t, outside.ID, "c")

	rep := f.build(t, ReportScope{Kind: model.RotationScopeNode, ID: root.ID}, asOf)
	assert.Equal(t, "核心系統", rep.Meta.ScopeLabel)
	assert.Equal(t, 2, rep.Summary.TotalAccounts, "多掛載的資產只計一次")
	assert.NotEqual(t, "<not-in-report>", bucketOfAccount(rep, accRoot.ID))
	assert.NotEqual(t, "<not-in-report>", bucketOfAccount(rep, accChild.ID))
	assert.Equal(t, "<not-in-report>", bucketOfAccount(rep, accOut.ID))
}

// TestRotationReportScopePlanIntersection 計劃範圍＝資產集合與帳號範圍的交集。
func TestRotationReportScopePlanIntersection(t *testing.T) {
	f := newReportFixture(t)
	f.global = 90
	asOf := mustTime(t, "2026-09-02T00:00:00Z")
	inPlan := f.asset(t, "in-plan")
	outPlan := f.asset(t, "out-plan")

	accRoot := f.account(t, inPlan.ID, "root")
	accOps := f.account(t, inPlan.ID, "ops")
	accElsewhere := f.account(t, outPlan.ID, "root")

	plan, err := f.plans.Create(&ChangeSecretPlanRequest{
		Name: "只改 root", AssetIDs: []uint{inPlan.ID}, Accounts: []string{"root"},
	})
	require.NoError(t, err)

	rep := f.build(t, ReportScope{Kind: model.RotationScopePlan, ID: plan.ID}, asOf)
	assert.Equal(t, "只改 root", rep.Meta.ScopeLabel)
	assert.Equal(t, 1, rep.Summary.TotalAccounts)
	assert.NotEqual(t, "<not-in-report>", bucketOfAccount(rep, accRoot.ID))
	assert.Equal(t, "<not-in-report>", bucketOfAccount(rep, accOps.ID), "帳號名不在範圍內")
	assert.Equal(t, "<not-in-report>", bucketOfAccount(rep, accElsewhere.ID), "資產不在範圍內")
}

// TestRotationReportRenamedAccountStillMatches 帳號改名後仍對得上改名前的記錄。
func TestRotationReportRenamedAccountStillMatches(t *testing.T) {
	f := newReportFixture(t)
	f.global = 90
	asOf := mustTime(t, "2026-09-02T00:00:00Z")
	a := f.asset(t, "host-a")
	acc := f.account(t, a.ID, "old-name")
	last := asOf.Add(-10 * 24 * time.Hour)
	f.success(t, acc, last)

	require.NoError(t, f.db.Model(acc).Update("username", "new-name").Error)

	rep := f.build(t, ReportScope{Kind: model.RotationScopeAll}, asOf)
	row := rowOfAccount(t, rep, acc.ID)
	assert.Equal(t, "new-name", row.Username)
	require.NotNil(t, row.LastSuccessAt, "改名不得讓最後成功改密時刻消失")
	assert.Equal(t, last.UTC(), row.LastSuccessAt.UTC())
	assert.Equal(t, BucketCompliant, row.Bucket)
}

// TestRotationReportTruncation 超過上限即截斷並標示，絕不靜默。
func TestRotationReportTruncation(t *testing.T) {
	f := newReportFixture(t)
	f.global = 90
	asOf := mustTime(t, "2026-09-02T00:00:00Z")
	a := f.asset(t, "host-a")

	accounts := make([]model.AssetAccount, 0, ReportRowsCap+5)
	for i := 0; i < ReportRowsCap+5; i++ {
		accounts = append(accounts, model.AssetAccount{
			AssetID: a.ID, Username: "u" + itoaTest(i), PasswordEnc: "enc",
		})
	}
	require.NoError(t, f.db.CreateInBatches(accounts, 1000).Error)

	rep := f.build(t, ReportScope{Kind: model.RotationScopeAll}, asOf)
	assert.Len(t, rep.Rows, ReportRowsCap)
	assert.True(t, rep.Truncation.RowsTruncated, "截斷必須標示")
	assert.Equal(t, ReportRowsCap, rep.Truncation.RowsCap)
	assert.Equal(t, ReportRowsCap, rep.Summary.TotalAccounts,
		"摘要以實際產出的列為準，否則摘要與明細對不上")
	assert.False(t, rep.Truncation.RecordsTruncated)
}

func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

// TestRotationReportAsOfBoundsRecords 截止時點之後發生的改密不得進入報告：
// 派生值取的最後成功時刻與明細清單都以 asOf 為上界。
//
// 這是把報告的截止時點往回移時的正確性條件——沒有上界的話，「三個月前的狀態」
// 會混入之後才發生的改密，算出來的剩餘天數描述一件當時還沒發生的事。
func TestRotationReportAsOfBoundsRecords(t *testing.T) {
	f := newReportFixture(t)
	f.global = 90
	a := f.asset(t, "核心-01")
	acc := f.account(t, a.ID, "root")

	asOf := time.Now().Add(-60 * 24 * time.Hour)
	before := asOf.Add(-10 * 24 * time.Hour)
	after := asOf.Add(10 * 24 * time.Hour)
	f.success(t, acc, before)
	f.success(t, acc, after)

	// 區間刻意跨過 asOf：明細的右界應被 asOf 夾住
	rep, err := f.builder.Build(ReportScope{Kind: model.RotationScopeAll},
		asOf.Add(-30*24*time.Hour), asOf.Add(30*24*time.Hour), asOf, "zh-TW")
	require.NoError(t, err)

	row := rowOfAccount(t, rep, acc.ID)
	require.NotNil(t, row.LastSuccessAt, "asOf 之前有一筆成功記錄")
	assert.True(t, row.LastSuccessAt.Before(asOf),
		"最後成功時刻不得晚於截止時點，got=%v asOf=%v", *row.LastSuccessAt, asOf)
	assert.True(t, row.LastSuccessAt.Equal(before.UTC()) ||
		row.LastSuccessAt.Equal(before) || row.LastSuccessAt.Sub(before).Abs() < time.Second,
		"應取截止時點之前的那一筆，got=%v want=%v", *row.LastSuccessAt, before)

	require.Len(t, rep.Records, 1, "明細只含截止時點之前的記錄，got=%d", len(rep.Records))
	assert.True(t, rep.Records[0].ExecutedAt.Before(asOf),
		"明細記錄不得晚於截止時點，got=%v", rep.Records[0].ExecutedAt)

	// 反向：截止時點推到未來時，兩筆都要在（否則上面的斷言可能只是驗到查詢壞掉）
	full, err := f.builder.Build(ReportScope{Kind: model.RotationScopeAll},
		asOf.Add(-30*24*time.Hour), after.Add(time.Hour), after.Add(time.Hour), "zh-TW")
	require.NoError(t, err)
	assert.Len(t, full.Records, 2, "不設回溯時兩筆都應在")
}
