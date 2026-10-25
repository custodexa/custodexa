package asset

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 整批同一組模式新共用憑證的歸屬：runner 建立憑證時以批次列上的持久值重驗並寫入，
// 成功目標改綁到該憑證。建立面的判定與回應見同名外部測試（正式判定器）。

// recordingOwnershipScope 記錄每次被要求判定的歸屬，判定本身同全域假判定器
type recordingOwnershipScope struct {
	globalOwnershipScopeForTest
	mu    sync.Mutex
	asked []*CredentialOwnershipInput
}

func (r *recordingOwnershipScope) AuthorizeSharedOwnership(ctx context.Context, tx *gorm.DB, uid uint, capability string,
	requested *CredentialOwnershipInput) (CredentialOwnership, error) {
	r.mu.Lock()
	var cp *CredentialOwnershipInput
	if requested != nil {
		v := *requested
		cp = &v
	}
	r.asked = append(r.asked, cp)
	r.mu.Unlock()
	return r.globalOwnershipScopeForTest.AuthorizeSharedOwnership(ctx, tx, uid, capability, requested)
}

func TestScopedBatchSharedOwnership(t *testing.T) {
	f := setupBatchFixture(t)
	rec := &recordingOwnershipScope{}
	f.batches.WithOwnershipScope(rec)
	f.runner.WithOwnershipScope(rec)
	_, acc1 := f.addHost(t, "own-h1", "10.2.7.1", "ops")
	_, acc2 := f.addHost(t, "own-h2", "10.2.7.2", "ops")
	n := model.AssetGroup{Name: "own-node"}
	require.NoError(t, f.db.Create(&n).Error)
	exec := newSecretRecorder()
	f.useExecutor(exec)

	req := sharedBatchRequest("ops", "歸屬批次 node")
	nid := n.ID
	req.SharedCredentialOwnership = &CredentialOwnershipInput{Kind: model.CredentialOwnerNode, NodeID: &nid}
	batch, assetIDs, err := f.batches.Create(req, 1, "admin")
	require.NoError(t, err)
	require.Equal(t, model.CredentialOwnerNode, batch.SharedCredentialOwnerKind)

	// runner 只拿到批次列（與背景執行相同的來源）：從庫重讀，不沿用建立時的記憶體結構
	var stored model.ChangeSecretBatch
	require.NoError(t, f.db.First(&stored, batch.ID).Error)
	stored.SharedCredentialName = batch.SharedCredentialName
	records := f.runner.RunBatch(&stored, assetIDs)
	require.Len(t, records, 2)
	for _, r := range records {
		assert.Equal(t, model.ChangeSecretSuccess, r.Status, "錯誤: %s", r.Error)
	}
	require.NotZero(t, stored.SharedCredentialID)
	cred := f.credentialOf(t, stored.SharedCredentialID)
	require.NotNil(t, cred.OwnerKind)
	assert.Equal(t, model.CredentialOwnerNode, *cred.OwnerKind, "新憑證歸屬為指定節點")
	require.NotNil(t, cred.OwnerNodeID)
	assert.Equal(t, n.ID, *cred.OwnerNodeID)
	for _, accountID := range []uint{acc1, acc2} {
		assert.Equal(t, cred.ID, f.bindingOf(t, accountID).CredentialID, "成功目標改綁到該憑證")
	}
	// 建立批次一次、runner 建立憑證一次，兩次判定的輸入都是那個節點（runner 用持久值，不是空值）
	require.Len(t, rec.asked, 2)
	for i, a := range rec.asked {
		require.NotNil(t, a, "第 %d 次判定", i)
		assert.Equal(t, model.CredentialOwnerNode, a.Kind)
		require.NotNil(t, a.NodeID)
		assert.Equal(t, n.ID, *a.NodeID)
	}

	// 未帶歸屬：建立時判為全域並持久化，runner 以全域重驗、新憑證為全域
	rec.asked = nil
	_, acc3 := f.addHost(t, "own-h3", "10.2.7.3", "dba")
	_, acc4 := f.addHost(t, "own-h4", "10.2.7.4", "dba")
	gb, gIDs, err := f.batches.Create(sharedBatchRequest("dba", "歸屬批次 global"), 1, "admin")
	require.NoError(t, err)
	assert.Equal(t, model.CredentialOwnerGlobal, gb.SharedCredentialOwnerKind)
	assert.Nil(t, gb.SharedCredentialOwnerNodeID)
	grecs := f.runner.RunBatch(gb, gIDs)
	require.Len(t, grecs, 2)
	for _, r := range grecs {
		require.Equal(t, model.ChangeSecretSuccess, r.Status, r.Error)
	}
	gcred := f.credentialOf(t, gb.SharedCredentialID)
	require.NotNil(t, gcred.OwnerKind)
	assert.Equal(t, model.CredentialOwnerGlobal, *gcred.OwnerKind)
	assert.Nil(t, gcred.OwnerNodeID)
	assert.Equal(t, gcred.ID, f.bindingOf(t, acc3).CredentialID)
	assert.Equal(t, gcred.ID, f.bindingOf(t, acc4).CredentialID)
	require.Len(t, rec.asked, 2)
	assert.Nil(t, rec.asked[0], "建立時未帶")
	require.NotNil(t, rec.asked[1], "runner 以持久值重驗")
	assert.Equal(t, model.CredentialOwnerGlobal, rec.asked[1].Kind)
}
