package asset

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// 依帳號查改密記錄：報告推導「最後成功改密時刻」與區間明細的唯一來源。

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	require.NoError(t, err)
	return ts
}

// TestRecordsByAccountsIgnoresUsername 以 account_id 比對：帳號改名後，
// 改名前的記錄仍查得到，且其帳號名快照維持舊名。
//
// **這正是不能用名字比對的理由**：改名後以名字查會漏掉改名前的全部記錄，
// 而報告據此算出的最後改密時刻會憑空變舊，或整個帳號掉進「無記錄」桶。
func TestRecordsByAccountsIgnoresUsername(t *testing.T) {
	svc := setupPlanDB(t)
	plan, err := svc.Create(&ChangeSecretPlanRequest{Name: "p", AssetIDs: []uint{1}})
	require.NoError(t, err)

	const accountID = 42
	require.NoError(t, svc.db.Create(&model.ChangeSecretRecord{
		PlanID: plan.ID, AssetID: 1, AccountID: accountID, AccountUsername: "old-name",
		Status: model.ChangeSecretSuccess, ExecutedAt: mustTime(t, "2026-07-01T00:00:00Z"),
	}).Error)
	require.NoError(t, svc.db.Create(&model.ChangeSecretRecord{
		PlanID: plan.ID, AssetID: 1, AccountID: accountID, AccountUsername: "new-name",
		Status: model.ChangeSecretSuccess, ExecutedAt: mustTime(t, "2026-09-01T00:00:00Z"),
	}).Error)
	// 另一個帳號的記錄不得混入
	require.NoError(t, svc.db.Create(&model.ChangeSecretRecord{
		PlanID: plan.ID, AssetID: 1, AccountID: 43, AccountUsername: "other",
		Status: model.ChangeSecretSuccess, ExecutedAt: mustTime(t, "2026-08-01T00:00:00Z"),
	}).Error)

	got, err := svc.RecordsByAccounts([]uint{accountID}, nil, nil, "")
	require.NoError(t, err)
	require.Len(t, got, 2, "改名前後兩筆都要查到")

	names := []string{got[0].AccountUsername, got[1].AccountUsername}
	assert.Contains(t, names, "old-name", "改名前的快照維持舊名")
	assert.Contains(t, names, "new-name")
	for _, r := range got {
		assert.Equal(t, uint(accountID), r.AccountID)
	}
}

// TestRecordsByAccountsFiltersIntervalAndStatus 區間為 [from, to)，
// 右開使連續兩期不重複計入同一筆；狀態為空即含 failed 與 skipped。
func TestRecordsByAccountsFiltersIntervalAndStatus(t *testing.T) {
	svc := setupPlanDB(t)
	plan, err := svc.Create(&ChangeSecretPlanRequest{Name: "p", AssetIDs: []uint{1}})
	require.NoError(t, err)

	const accountID = 7
	for _, c := range []struct {
		at     string
		status string
	}{
		{"2026-08-31T23:59:59Z", model.ChangeSecretSuccess},
		{"2026-09-01T00:00:00Z", model.ChangeSecretFailed},
		{"2026-09-15T12:00:00Z", model.ChangeSecretSkipped},
		{"2026-09-30T00:00:00Z", model.ChangeSecretSuccess},
	} {
		require.NoError(t, svc.db.Create(&model.ChangeSecretRecord{
			PlanID: plan.ID, AssetID: 1, AccountID: accountID,
			Status: c.status, ExecutedAt: mustTime(t, c.at),
		}).Error)
	}

	from := mustTime(t, "2026-09-01T00:00:00Z")
	to := mustTime(t, "2026-09-30T00:00:00Z")

	got, err := svc.RecordsByAccounts([]uint{accountID}, &from, &to, "")
	require.NoError(t, err)
	require.Len(t, got, 2, "區間左閉右開：起點那筆算進來、終點那筆不算")
	assert.Equal(t, model.ChangeSecretSkipped, got[0].Status, "新到舊")
	assert.Equal(t, model.ChangeSecretFailed, got[1].Status)

	onlySuccess, err := svc.RecordsByAccounts([]uint{accountID}, nil, nil, model.ChangeSecretSuccess)
	require.NoError(t, err)
	assert.Len(t, onlySuccess, 2)

	none, err := svc.RecordsByAccounts(nil, nil, nil, "")
	require.NoError(t, err)
	assert.Empty(t, none, "空帳號集合不得退化成查全表")
}

// TestLastSuccessByAccountPicksMax 每帳號取最大的成功執行時刻；
// failed 不算；無成功記錄者不出現在 map 內（與「很久以前改過」可分辨）。
func TestLastSuccessByAccountPicksMax(t *testing.T) {
	svc := setupPlanDB(t)
	plan, err := svc.Create(&ChangeSecretPlanRequest{Name: "p", AssetIDs: []uint{1}})
	require.NoError(t, err)

	add := func(accountID uint, at, status string) {
		require.NoError(t, svc.db.Create(&model.ChangeSecretRecord{
			PlanID: plan.ID, AssetID: 1, AccountID: accountID,
			Status: status, ExecutedAt: mustTime(t, at),
		}).Error)
	}
	add(1, "2026-07-01T00:00:00Z", model.ChangeSecretSuccess)
	add(1, "2026-08-01T00:00:00Z", model.ChangeSecretFailed)
	add(1, "2026-09-01T00:00:00Z", model.ChangeSecretSuccess)
	add(2, "2026-06-01T00:00:00Z", model.ChangeSecretSuccess)
	add(3, "2026-09-20T00:00:00Z", model.ChangeSecretFailed)
	add(3, "2026-09-21T00:00:00Z", model.ChangeSecretUnverified)

	got, err := svc.LastSuccessByAccount([]uint{1, 2, 3, 4}, time.Time{})
	require.NoError(t, err)
	require.Len(t, got, 2, "只有帳號 1 與 2 有成功記錄")

	assert.True(t, got[1].Equal(mustTime(t, "2026-09-01T00:00:00Z")),
		"取最大的成功時刻，failed 不得覆蓋它，got=%v", got[1])
	assert.True(t, got[2].Equal(mustTime(t, "2026-06-01T00:00:00Z")))

	_, ok := got[3]
	assert.False(t, ok, "只有失敗與未驗證＝無成功記錄，不得以零值時間混入")
	_, ok = got[4]
	assert.False(t, ok, "完全無記錄的帳號不得出現")
}
