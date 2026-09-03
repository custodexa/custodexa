package asset

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// TestRotationReportShowsWindowsChannelLastSuccess 輪替證據報告的「最後成功改密時刻」
// 只看改密記錄的狀態與執行時刻，不看資產走哪條改密通道：經 WinRM 通道成功改密的
// Windows 帳號，其報告列必須帶出那一次的成功時刻，與 POSIX 路徑同一資料來源。
func TestRotationReportShowsWindowsChannelLastSuccess(t *testing.T) {
	f := newFakeWinRMServer(t, "winoldpass")
	host, port := f.hostPort()
	fx := setupChangeSecretFixture(t, "root", "oldpass123")
	id := fx.addRotationAsset(t, &CreateAssetRequest{
		Name: "win-report", Protocol: model.ProtocolRDP, Host: host, Port: 3389,
		Username: "Administrator", Password: "winoldpass",
		RotationChannel: model.RotationChannelWindowsWinRM, WinrmScheme: model.WinrmSchemeHTTP, WinrmPort: port,
	})
	fx.runner.executors = func(string) rotationExecutor { return testWinRMExecutor(f, nil) }

	records := fx.runner.RunPlan(fx.planForAssets(t, []uint{id}, nil))
	require.Len(t, records, 1)
	require.Equal(t, model.ChangeSecretSuccess, records[0].Status, "錯誤: %s", records[0].Error)
	require.NotZero(t, records[0].AccountID)

	builder := NewRotationReportBuilder(fx.db, NewChangeSecretPlanService(fx.db), func() int { return 90 })
	asOf := time.Now().Add(time.Minute)
	rep, err := builder.Build(ReportScope{Kind: model.RotationScopeAll},
		asOf.Add(-24*time.Hour), asOf, asOf, "zh-TW")
	require.NoError(t, err)

	row := rowOfAccount(t, rep, records[0].AccountID)
	assert.Equal(t, string(model.ProtocolRDP), row.Protocol)
	require.NotNil(t, row.LastSuccessAt, "WinRM 通道的成功改密必須出現在報告的最後成功時刻")
	assert.WithinDuration(t, records[0].ExecutedAt, *row.LastSuccessAt, time.Second)
	assert.Equal(t, model.ChangeSecretSuccess, row.LastRecordStatus)
}
