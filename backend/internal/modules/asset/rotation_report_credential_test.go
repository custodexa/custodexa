package asset

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// 報告的憑證投影：共用標記取自憑證範圍、憑證名與就位版本序號隨列出站、
// 區間明細帶執行當下的憑證與版本快照。
//
// 這幾個欄位是稽核用來核對共用關係的依據——標錯的方向是「同一組密碼在多台生效」
// 這件事在報告上看不出來，而那正是報告存在的理由之一。

// sharedCredentialRow 於報告裝配內直接造一筆憑證與其版本（不經服務層：
// 本檔驗的是投影，不是建立路徑）
func (f *reportFixture) credential(t *testing.T, name, username, scope string) (*model.Credential, *model.CredentialSecretVersion) {
	t.Helper()
	cred := &model.Credential{
		Scope: scope, Username: username, SecretType: model.ChangeSecretTypePassword,
		AuthMethod: AuthMethodSQL, ProtocolFamily: model.ProtocolFamilySSH,
	}
	if scope == model.CredentialScopeShared {
		n := name
		cred.Name = &n
	}
	require.NoError(t, f.db.Create(cred).Error)
	version := &model.CredentialSecretVersion{
		CredentialID: cred.ID, VersionNo: 1, SecretType: model.ChangeSecretTypePassword,
		PasswordEnc: "enc", CreatedReason: model.CredentialVersionReasonManual,
	}
	require.NoError(t, f.db.Create(version).Error)
	require.NoError(t, f.db.Model(&model.Credential{}).Where("id = ?", cred.ID).
		Update("current_version_id", version.ID).Error)
	cred.CurrentVersionID = &version.ID
	return cred, version
}

// boundAccount 建一筆掛在指定憑證上的掛載
func (f *reportFixture) boundAccount(t *testing.T, assetID uint, cred *model.Credential,
	version *model.CredentialSecretVersion) *model.AssetAccount {
	t.Helper()
	acc := &model.AssetAccount{
		AssetID: assetID, Username: cred.Username,
		CredentialID: cred.ID, EffectiveVersionID: &version.ID,
	}
	require.NoError(t, f.db.Create(acc).Error)
	return acc
}

// 共用標記取自憑證範圍；憑證名與就位版本序號隨列出站
func TestRotationReportSharedFlagFromCredentialScope(t *testing.T) {
	f := newReportFixture(t)
	f.global = 90
	shared, sharedV1 := f.credential(t, "維運共用", "ops", model.CredentialScopeShared)
	dedicated, dedicatedV1 := f.credential(t, "", "ops", model.CredentialScopeDedicated)

	var members []uint
	for _, name := range []string{"srv-a", "srv-b", "srv-c"} {
		asset := f.asset(t, name)
		members = append(members, f.boundAccount(t, asset.ID, shared, sharedV1).ID)
	}
	lone := f.asset(t, "srv-d")
	loneAcc := f.boundAccount(t, lone.ID, dedicated, dedicatedV1)

	rep := f.build(t, ReportScope{Kind: model.RotationScopeAll}, time.Now())
	require.Len(t, rep.Rows, 4)
	for _, accountID := range members {
		row := rowOfAccount(t, rep, accountID)
		assert.True(t, row.SharedCredential, "引用共用憑證的掛載標為共用")
		assert.Equal(t, "維運共用", row.CredentialName, "共用憑證的名稱即落庫名稱")
		assert.Equal(t, 1, row.EffectiveVersionNo)
	}
	row := rowOfAccount(t, rep, loneAcc.ID)
	assert.False(t, row.SharedCredential)
	assert.Equal(t, "srv-d / ops", row.CredentialName, "專用憑證的名稱是計算顯示名")
	assert.Equal(t, 1, row.EffectiveVersionNo)
	assert.Equal(t, 3, rep.Summary.SharedCredential, "摘要的共用計數同源")
}

// 區間明細帶執行當下的憑證名稱與版本快照，且不隨掛載改綁而改變
func TestRotationReportRecordCredentialSnapshot(t *testing.T) {
	f := newReportFixture(t)
	f.global = 90
	shared, sharedV1 := f.credential(t, "當時的共用", "ops", model.CredentialScopeShared)
	dedicated, dedicatedV1 := f.credential(t, "", "ops", model.CredentialScopeDedicated)
	asset := f.asset(t, "srv-a")
	acc := f.boundAccount(t, asset.ID, shared, sharedV1)

	at := time.Now().Add(-24 * time.Hour)
	require.NoError(t, f.db.Create(&model.ChangeSecretRecord{
		PlanID: 1, AssetID: asset.ID, AccountID: acc.ID, AccountUsername: acc.Username,
		CredentialID: shared.ID, CredentialName: "當時的共用", TargetVersionID: sharedV1.ID,
		SecretType: model.ChangeSecretTypePassword,
		Status:     model.ChangeSecretSuccess, ExecutedAt: at,
	}).Error)

	rep := f.build(t, ReportScope{Kind: model.RotationScopeAll}, time.Now())
	require.Len(t, rep.Records, 1)
	assert.Equal(t, "當時的共用", rep.Records[0].CredentialName)
	assert.Equal(t, 1, rep.Records[0].VersionNo)

	// 之後改綁到專用憑證：明細的快照必須維持執行當下的值
	require.NoError(t, f.db.Model(&model.AssetAccount{}).Where("id = ?", acc.ID).
		Updates(map[string]any{
			"credential_id": dedicated.ID, "effective_version_id": dedicatedV1.ID,
		}).Error)
	rep = f.build(t, ReportScope{Kind: model.RotationScopeAll}, time.Now())
	require.Len(t, rep.Records, 1)
	assert.Equal(t, "當時的共用", rep.Records[0].CredentialName,
		"改綁後的憑證不得覆蓋記錄的快照")
	assert.Equal(t, 1, rep.Records[0].VersionNo)
	assert.False(t, rowOfAccount(t, rep, acc.ID).SharedCredential, "現況列則跟著改綁走")
	assert.Equal(t, "srv-a / ops", rowOfAccount(t, rep, acc.ID).CredentialName)
}

// 憑證庫左表的輪替狀態＝該憑證全部掛載的狀態桶取最嚴，優先序與報告同源
func TestCredentialLibraryRotationStatusStrictest(t *testing.T) {
	// 1) 優先序的字面釘子：與報告共用同一份常數，順序即語義
	assert.Equal(t, []string{
		BucketOverdue, BucketDueSoon, BucketUnverified,
		BucketNoRecord, BucketNoPolicy, BucketCompliant,
	}, bucketSeverity, "嚴重度優先序被改動：憑證庫與報告會就此各說一套")

	// 2) 逐對比較：前者恆勝於後者
	for i := 0; i < len(bucketSeverity)-1; i++ {
		assert.Equal(t, bucketSeverity[i],
			strictestBucket([]string{bucketSeverity[i+1], bucketSeverity[i]}),
			"%s 應勝於 %s", bucketSeverity[i], bucketSeverity[i+1])
	}
	assert.Equal(t, "", strictestBucket(nil), "沒有掛載就沒有可判定的狀態")

	// 3) 端到端：一筆共用憑證掛三台，狀態各異，取最嚴
	f := newReportFixture(t)
	f.global = 90
	shared, v1 := f.credential(t, "三台共用", "ops", model.CredentialScopeShared)
	now := time.Now()
	overdueAsset := f.asset(t, "srv-overdue")
	overdue := f.boundAccount(t, overdueAsset.ID, shared, v1)
	f.success(t, overdue, now.Add(-200*24*time.Hour))
	compliantAsset := f.asset(t, "srv-compliant")
	compliant := f.boundAccount(t, compliantAsset.ID, shared, v1)
	f.success(t, compliant, now.Add(-24*time.Hour))
	noRecordAsset := f.asset(t, "srv-no-record")
	f.boundAccount(t, noRecordAsset.ID, shared, v1)

	got, err := f.builder.CredentialRotationStatus(shared.ID, now)
	require.NoError(t, err)
	assert.Equal(t, BucketOverdue, got, "三台裡有一台逾期，整筆憑證即逾期")

	// 逾期那台補上一次成功後，最嚴的變成「無記錄」
	f.success(t, overdue, now.Add(-24*time.Hour))
	got, err = f.builder.CredentialRotationStatus(shared.ID, now)
	require.NoError(t, err)
	assert.Equal(t, BucketNoRecord, got)

	// 零掛載的憑證沒有可判定的狀態
	empty, _ := f.credential(t, "沒人用", "ops", model.CredentialScopeShared)
	got, err = f.builder.CredentialRotationStatus(empty.ID, now)
	require.NoError(t, err)
	assert.Equal(t, "", got)
}
