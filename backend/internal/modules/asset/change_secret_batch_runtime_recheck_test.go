package asset

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
)

// 批次建立之後、背景執行時的授權重驗：撤權或移出範圍後，遠端零觸碰。
//
// 判定替身與正式轉接頭同一口徑：帶目標時只判憑證歸屬（CredentialIDs）與明確目標資產（AssetIDs），
// 不判影響集合（MountedAssetIDs）；每次判定以呼叫方連線讀當下的資產節點與憑證歸屬。

// assetOutOfScopeForTest 資產種類的範圍拒絕值替身。
type assetOutOfScopeForTest struct{}

func (assetOutOfScopeForTest) Error() string                 { return "asset out of scope" }
func (assetOutOfScopeForTest) ScopeDeniedTargetKind() string { return scopeDeniedKindAsset }

// nodeScopedAuthorizer 對 user 依「權限點 → 持有節點」判定；其他主體交給 inner。
type nodeScopedAuthorizer struct {
	inner *fakeCredentialAuthorizer
	user  uint
	mu    sync.Mutex
	held  map[string]map[uint]bool
	asked int
	// global 該能力另有全系統來源（不限範圍）；targetlessGlobalOnly 為真時不帶目標的判定只認全系統來源
	// （同正式轉接頭：查詢與建立以外的操作），預設為假以維持既有夾具的口徑
	global               map[string]bool
	targetlessGlobalOnly bool
}

func newNodeScopedAuthorizer(inner *fakeCredentialAuthorizer, user uint) *nodeScopedAuthorizer {
	return &nodeScopedAuthorizer{inner: inner, user: user, held: map[string]map[uint]bool{}}
}

func (a *nodeScopedAuthorizer) grant(capability string, nodes ...uint) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.held[capability] == nil {
		a.held[capability] = map[uint]bool{}
	}
	for _, n := range nodes {
		a.held[capability][n] = true
	}
}

func (a *nodeScopedAuthorizer) revoke(capability string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.held, capability)
}

func (a *nodeScopedAuthorizer) askedCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.asked
}

func (a *nodeScopedAuthorizer) AuthorizeCredentialManagement(ctx context.Context, db *gorm.DB,
	actor CredentialManagementActor, req CredentialManagementRequest) (CredentialManagementDecision, error) {
	if actor.UserID != a.user {
		return a.inner.AuthorizeCredentialManagement(ctx, db, actor, req)
	}
	a.mu.Lock()
	a.asked++
	held := make(map[string]map[uint]bool, len(a.held))
	for c, set := range a.held {
		cp := make(map[uint]bool, len(set))
		for n := range set {
			cp[n] = true
		}
		held[c] = cp
	}
	a.mu.Unlock()
	q := db
	if q == nil {
		q = database.DB
	}
	targetless := len(req.CredentialIDs) == 0 && len(req.AssetIDs) == 0 &&
		req.Operation != CredOpView && req.Operation != CredOpCreate
	for _, c := range req.Capabilities {
		if a.global[c] {
			continue
		}
		set := held[c]
		if len(set) == 0 || (targetless && a.targetlessGlobalOnly) {
			return CredentialManagementDecision{Missing: c, AuthzVersion: 1}, nil
		}
		assetIn := func(id uint) (bool, error) {
			var rows []model.AssetNode
			if err := q.Where("asset_id = ?", id).Find(&rows).Error; err != nil {
				return false, err
			}
			for _, r := range rows {
				if set[r.NodeID] {
					return true, nil
				}
			}
			return false, nil
		}
		for _, id := range req.CredentialIDs {
			var cred model.Credential
			if err := q.Unscoped().Select("id", "owner_kind", "owner_node_id").First(&cred, id).Error; err != nil {
				return CredentialManagementDecision{}, err
			}
			ok := false
			switch {
			case cred.OwnerKind != nil && *cred.OwnerKind == model.CredentialOwnerAsset:
				// 隨資產歸屬：以第一個掛載所在的資產判定（同正式解析器）
				var mount model.AssetAccount
				if err := q.Where("credential_id = ?", id).Order("id asc").First(&mount).Error; err == nil {
					in, err := assetIn(mount.AssetID)
					if err != nil {
						return CredentialManagementDecision{}, err
					}
					ok = in
				}
			case cred.OwnerNodeID != nil:
				ok = set[*cred.OwnerNodeID]
			}
			if !ok {
				return CredentialManagementDecision{ScopeDenial: errOwnershipOutOfScopeForTest}, nil
			}
		}
		for _, id := range req.AssetIDs {
			in, err := assetIn(id)
			if err != nil {
				return CredentialManagementDecision{}, err
			}
			if !in {
				return CredentialManagementDecision{ScopeDenial: assetOutOfScopeForTest{}}, nil
			}
		}
	}
	return CredentialManagementDecision{Allowed: true, AuthzVersion: 1}, nil
}

func (a *nodeScopedAuthorizer) RestoreGeneration(db *gorm.DB) (string, error) {
	return a.inner.RestoreGeneration(db)
}

const rtScopedUser uint = 9

// rtFixture 批次夾具＋兩個節點（範圍內 in、範圍外 out）＋範圍化判定替身（批次、執行器、輪替引擎共用）。
type rtFixture struct {
	*batchFixture
	az      *nodeScopedAuthorizer
	in, out uint
	rec     *secretRecorder
}

func newRtFixture(t *testing.T) *rtFixture {
	t.Helper()
	f := setupBatchFixture(t)
	g := &rtFixture{batchFixture: f, az: newNodeScopedAuthorizer(f.authz, rtScopedUser), rec: newSecretRecorder()}
	for name, p := range map[string]*uint{"rt-in": &g.in, "rt-out": &g.out} {
		n := model.AssetGroup{Name: name}
		require.NoError(t, f.db.Create(&n).Error)
		*p = n.ID
	}
	f.batches.WithManagementAuthorizer(g.az)
	f.runner.WithManagementAuthorizer(g.az)
	f.rotations.mgmt = credentialManagementGate{authorizer: g.az}
	f.useExecutor(g.rec)
	f.rotations.executors = func(string) rotationExecutor { return g.rec }
	return g
}

// place 把資產放到指定節點（取代既有節點歸屬）
func (g *rtFixture) place(t *testing.T, assetID, node uint) {
	t.Helper()
	require.NoError(t, g.db.Where("asset_id = ?", assetID).Delete(&model.AssetNode{}).Error)
	require.NoError(t, g.db.Create(&model.AssetNode{AssetID: assetID, NodeID: node}).Error)
}

// rotateCalls 某台主機的遠端改密呼叫次數
func (g *rtFixture) rotateCalls(host string) int {
	_, rc, _ := g.rec.snapshotCalls()
	return rc[host]
}

// sharedInNode 建一筆歸屬 node 的共用憑證並掛到兩台（放在 node）；回傳憑證、兩台資產與掛載
func (g *rtFixture) sharedInNode(t *testing.T, h1, h2 string, node uint) (uint, [2]uint, [2]uint) {
	t.Helper()
	credID, accounts := g.sharedOn(t, "rt-shared-"+h1, "ops", "old-shared", h1, h2)
	require.NoError(t, g.db.Model(&model.Credential{}).Where("id = ?", credID).
		Updates(map[string]any{"owner_kind": model.CredentialOwnerNode, "owner_node_id": node}).Error)
	var assets [2]uint
	for i, acc := range accounts {
		assets[i] = g.bindingOf(t, acc).AssetID
		g.place(t, assets[i], node)
	}
	return credID, assets, [2]uint{accounts[0], accounts[1]}
}

// 每台各自隨機遇到共用憑證成員：拆分延續批次的資產上界與能力。批次建立後資產移出範圍，或首台派送後
// 撤回帳號改密，移出／其後的那一台遠端零觸碰；來源憑證仍在範圍內不能替資產範圍背書。
func TestStartSplitForScope(t *testing.T) {
	grantSplit := func(g *rtFixture) {
		for _, c := range []string{CredCapAccountRotate, CredCapRotate, CredCapDetach} {
			g.az.grant(c, g.in)
		}
	}

	t.Run("batch_asset_moved_out_after_create", func(t *testing.T) {
		g := newRtFixture(t)
		grantSplit(g)
		credID, assets, accounts := g.sharedInNode(t, "10.3.1.1", "10.3.1.2", g.in)
		batch, assetIDs, err := g.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, true), rtScopedUser, "rt-scoped")
		require.NoError(t, err)
		require.Len(t, assetIDs, 2)

		g.place(t, assets[0], g.out)
		records := g.runner.RunBatch(batch, assetIDs)
		assert.Equal(t, 0, g.rotateCalls("10.3.1.1"), "移出範圍的那一台遠端零觸碰")
		assert.Equal(t, 0, g.rotateCalls("10.3.1.2"), "同組拆分整筆不建立")
		require.Len(t, records, 2)
		for _, r := range records {
			assert.Equal(t, model.ChangeSecretSkipped, r.Status)
			assert.Equal(t, model.ChangeSecretReasonAuthzRevoked, r.Error)
		}
		for _, acc := range accounts {
			assert.Equal(t, credID, g.bindingOf(t, acc).CredentialID, "掛載不動")
		}
		var rots int64
		require.NoError(t, g.db.Model(&model.CredentialRotation{}).Count(&rots).Error)
		assert.EqualValues(t, 0, rots, "起始交易整筆回滾")
	})

	t.Run("batch_account_rotate_revoked_after_first_member", func(t *testing.T) {
		g := newRtFixture(t)
		grantSplit(g)
		_, _, _ = g.sharedInNode(t, "10.3.2.1", "10.3.2.2", g.in)
		batch, assetIDs, err := g.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, true), rtScopedUser, "rt-scoped")
		require.NoError(t, err)

		first := ""
		g.rec.afterVerify = func(host string) {
			if first == "" {
				first = host
				g.az.revoke(CredCapAccountRotate)
			}
		}
		g.runner.RunBatch(batch, assetIDs)
		require.NotEmpty(t, first, "第一台確實派送")
		other := "10.3.2.2"
		if first == other {
			other = "10.3.2.1"
		}
		assert.Equal(t, 1, g.rotateCalls(first))
		assert.Equal(t, 0, g.rotateCalls(other), "撤回帳號改密之後的那一台遠端零觸碰")
		var m model.CredentialRotationMember
		require.NoError(t, g.db.Where("state <> ?", model.CredentialMemberApplied).First(&m).Error)
		assert.Equal(t, model.ChangeSecretReasonAuthzRevoked, m.LastError)
	})

	t.Run("batch_in_scope_succeeds_and_bound_persisted", func(t *testing.T) {
		g := newRtFixture(t)
		grantSplit(g)
		_, assets, _ := g.sharedInNode(t, "10.3.3.1", "10.3.3.2", g.in)
		batch, assetIDs, err := g.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, true), rtScopedUser, "rt-scoped")
		require.NoError(t, err)
		records := g.runner.RunBatch(batch, assetIDs)
		require.Len(t, records, 2)
		for _, r := range records {
			assert.Equal(t, model.ChangeSecretSuccess, r.Status, r.Error)
		}
		var rot model.CredentialRotation
		require.NoError(t, g.db.First(&rot).Error)
		require.NotNil(t, rot.AuthorizationID)
		var auth model.CredentialJobAuthorization
		require.NoError(t, g.db.First(&auth, *rot.AuthorizationID).Error)
		bound, err := authorizationTargetBound(&auth)
		require.NoError(t, err)
		assert.ElementsMatch(t, assets[:], bound, "輪替授權脈絡帶批次選定的資產上界")
	})

	t.Run("global_owned_source_split_by_selected_assets", testGlobalOwnedSourceSplitBySelectedAssets)
	t.Run("direct_call_mixed_scope_rejected", testBoundedSplitDirectCallMixedScopeRejected)
	t.Run("batch_rejection_skips_group_others_proceed", testBoundedSplitBatchRejectionOthersProceed)
	t.Run("bounded_caps_fail_close", testBoundedSplitCapabilitiesFailClose)
	t.Run("bounded_global_positive", testBoundedSplitGlobalPositive)
}

// grantRtSplit 範圍化主體在 in 節點持有帳號改密、憑證改密與脫離。
func grantRtSplit(g *rtFixture) {
	for _, c := range []string{CredCapAccountRotate, CredCapRotate, CredCapDetach} {
		g.az.grant(c, g.in)
	}
}

// globalSharedOn 建一筆全域歸屬的共用憑證並掛到 hosts，依 nodes 逐台放節點；回傳憑證、資產與掛載。
func (g *rtFixture) globalSharedOn(t *testing.T, name string, hosts []string, nodes []uint) (uint, []uint, []uint) {
	t.Helper()
	credID, accounts := g.sharedOn(t, name, "ops", "old-shared", hosts...)
	cred := g.credentialOf(t, credID)
	require.True(t, cred.OwnerKind == nil || *cred.OwnerKind == model.CredentialOwnerGlobal, "夾具：來源憑證為全域歸屬")
	assets := make([]uint, len(accounts))
	for i, acc := range accounts {
		assets[i] = g.bindingOf(t, acc).AssetID
		g.place(t, assets[i], nodes[i])
	}
	return credID, assets, accounts
}

func (g *rtFixture) rotationAndCandidateCounts(t *testing.T) (int64, int64) {
	t.Helper()
	var rots, cands int64
	require.NoError(t, g.db.Model(&model.CredentialRotation{}).Count(&rots).Error)
	require.NoError(t, g.db.Model(&model.ChangeSecretCandidate{}).Count(&cands).Error)
	return rots, cands
}

// 來源共用憑證為全域歸屬、掛 4 台（範圍內 2、範圍外 2）：範圍化發起者的批次只以選定資產判定，
// 範圍內 2 台拆分成功；範圍外 2 台遠端零觸碰、仍掛在來源憑證上、來源現行版本不變。
func testGlobalOwnedSourceSplitBySelectedAssets(t *testing.T) {
	g := newRtFixture(t)
	grantRtSplit(g)
	hosts := []string{"10.3.11.1", "10.3.11.2", "10.3.11.3", "10.3.11.4"}
	credID, _, accounts := g.globalSharedOn(t, "rt-global-4", hosts, []uint{g.in, g.in, g.out, g.out})
	before := g.credentialOf(t, credID).CurrentVersionID
	// 本夾具未接範圍投影，明列範圍內的 2 個掛載（「全部」只展開範圍內由 TestScopedBatchRotationScope 驗）
	batch, assetIDs, err := g.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, false, accounts[0], accounts[1]),
		rtScopedUser, "rt-scoped")
	require.NoError(t, err)
	require.Len(t, assetIDs, 2)
	records := g.runner.RunBatch(batch, assetIDs)
	require.Len(t, records, 2)
	for _, r := range records {
		assert.Equal(t, model.ChangeSecretSuccess, r.Status, r.Error)
	}
	assert.Equal(t, 1, g.rotateCalls(hosts[0]))
	assert.Equal(t, 1, g.rotateCalls(hosts[1]))
	assert.Equal(t, 0, g.rotateCalls(hosts[2]), "範圍外遠端零觸碰")
	assert.Equal(t, 0, g.rotateCalls(hosts[3]), "範圍外遠端零觸碰")
	for _, acc := range accounts[2:] {
		assert.Equal(t, credID, g.bindingOf(t, acc).CredentialID, "未選中的掛載不動")
	}
	assert.Equal(t, before, g.credentialOf(t, credID).CurrentVersionID, "來源憑證就位版本不變")
}

// 非批次直接呼叫拆分入口（帶批次上界）：指定範圍內 1＋範圍外 1 整筆拒絕，輪替與候選筆數不變、遠端零呼叫。
func testBoundedSplitDirectCallMixedScopeRejected(t *testing.T) {
	g := newRtFixture(t)
	grantRtSplit(g)
	hosts := []string{"10.3.12.1", "10.3.12.2"}
	credID, _, accounts := g.globalSharedOn(t, "rt-direct-mixed", hosts, []uint{g.in, g.out})
	rots0, cands0 := g.rotationAndCandidateCounts(t)
	ctx := contextWithInitiator(context.Background(), rtScopedUser, "rt-scoped")
	_, err := g.rotations.startSplitForBatch(ctx, credID, accounts, StartRotationRequest{},
		&splitAssetBound{caps: []string{CredCapAccountRotate}})
	require.Error(t, err)
	reason, ok := batchStopReason(err)
	require.True(t, ok, "範圍拒絕回批次授權停止")
	assert.Equal(t, model.ChangeSecretReasonAuthzRevoked, reason)
	rots, cands := g.rotationAndCandidateCounts(t)
	assert.Equal(t, rots0, rots, "不建立輪替")
	assert.Equal(t, cands0, cands, "不建立候選")
	assert.Equal(t, 0, g.rotateCalls(hosts[0])+g.rotateCalls(hosts[1]), "遠端零呼叫")

	// 不屬於來源的掛載識別同樣整筆拒絕
	_, other := g.addHost(t, "rt-direct-other", "10.3.12.3", "ops")
	_, err = g.rotations.startSplitForBatch(ctx, credID, []uint{accounts[0], other}, StartRotationRequest{},
		&splitAssetBound{caps: []string{CredCapAccountRotate}})
	assert.ErrorIs(t, err, ErrCredentialRotationNoBinding)
	rots, cands = g.rotationAndCandidateCounts(t)
	assert.Equal(t, rots0, rots)
	assert.Equal(t, cands0, cands)
}

// 批次觸發的拆分被拒：該憑證的 2 筆目標記 skipped 帶撤權碼，批次中其他（專用）目標照常。
func testBoundedSplitBatchRejectionOthersProceed(t *testing.T) {
	g := newRtFixture(t)
	grantRtSplit(g)
	hosts := []string{"10.3.13.1", "10.3.13.2"}
	_, assets, _ := g.globalSharedOn(t, "rt-batch-reject", hosts, []uint{g.in, g.in})
	soloAsset, _ := g.addHost(t, "rt-solo", "10.3.13.9", "ops")
	g.place(t, soloAsset, g.in)
	batch, assetIDs, err := g.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, true), rtScopedUser, "rt-scoped")
	require.NoError(t, err)
	require.Len(t, assetIDs, 3)
	g.place(t, assets[0], g.out)
	records := g.runner.RunBatch(batch, assetIDs)
	require.Len(t, records, 3)
	byAsset := map[uint]model.ChangeSecretRecord{}
	for _, r := range records {
		byAsset[r.AssetID] = r
	}
	for _, a := range assets {
		assert.Equal(t, model.ChangeSecretSkipped, byAsset[a].Status)
		assert.Equal(t, model.ChangeSecretReasonAuthzRevoked, byAsset[a].Error)
	}
	assert.Equal(t, model.ChangeSecretSuccess, byAsset[soloAsset].Status, byAsset[soloAsset].Error)
	assert.Equal(t, 0, g.rotateCalls(hosts[0])+g.rotateCalls(hosts[1]), "被拒的一組遠端零觸碰")
	assert.Equal(t, 1, g.rotateCalls("10.3.13.9"), "其他目標照常")
}

// 帶上界的拆分在能力欄空白、null、無效 JSON、空陣列時 fail closed；能力陣列缺脫離時仍以拆分模式下限要求脫離。
func testBoundedSplitCapabilitiesFailClose(t *testing.T) {
	start := func(t *testing.T, host string) (*rtFixture, *model.CredentialRotation) {
		g := newRtFixture(t)
		grantRtSplit(g)
		credID, _, accounts := g.globalSharedOn(t, "rt-caps-"+host, []string{host}, []uint{g.in})
		ctx := contextWithInitiator(context.Background(), rtScopedUser, "rt-scoped")
		rot, err := g.rotations.startSplitForBatch(ctx, credID, accounts, StartRotationRequest{},
			&splitAssetBound{caps: []string{CredCapAccountRotate}})
		require.NoError(t, err)
		require.NotNil(t, rot.AuthorizationID)
		return g, rot
	}
	setCaps := func(t *testing.T, g *rtFixture, rot *model.CredentialRotation, raw string) {
		require.NoError(t, g.db.Model(&model.CredentialJobAuthorization{}).Where("id = ?", *rot.AuthorizationID).
			Update("capabilities", raw).Error)
	}
	memberError := func(t *testing.T, g *rtFixture, rot *model.CredentialRotation) string {
		var m model.CredentialRotationMember
		require.NoError(t, g.db.Where("rotation_id = ?", rot.ID).First(&m).Error)
		return m.LastError
	}
	for i, tc := range []struct{ name, raw string }{
		{"empty", ""}, {"null", "null"}, {"invalid_json", "{not json"}, {"empty_array", "[]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := fmt.Sprintf("10.3.14.%d", i+1)
			g, rot := start(t, host)
			setCaps(t, g, rot, tc.raw)
			ctx := contextWithInitiator(context.Background(), rtScopedUser, "rt-scoped")
			_, _ = g.rotations.RunFor(ctx, rot.ID, RotationRecordOrigin{})
			assert.Equal(t, 0, g.rotateCalls(host), "能力欄不完整：遠端零觸碰")
			assert.Equal(t, model.ChangeSecretReasonAuthzContextMissing, memberError(t, g, rot))
		})
	}
	t.Run("missing_detach", func(t *testing.T) {
		host := "10.3.14.9"
		g, rot := start(t, host)
		setCaps(t, g, rot, `["account:rotate","credential:rotate"]`)
		g.az.revoke(CredCapDetach)
		ctx := contextWithInitiator(context.Background(), rtScopedUser, "rt-scoped")
		_, _ = g.rotations.RunFor(ctx, rot.ID, RotationRecordOrigin{})
		assert.Equal(t, 0, g.rotateCalls(host), "撤回脫離：遠端零觸碰")
		assert.Equal(t, model.ChangeSecretReasonAuthzRevoked, memberError(t, g, rot))
	})
}

// 全域主體的批次觸發拆分（帶上界）照常成功，授權脈絡存完整能力（含拆分模式下限）。
func testBoundedSplitGlobalPositive(t *testing.T) {
	f := setupBatchFixture(t)
	rec := newSecretRecorder()
	f.useExecutor(rec)
	f.rotations.executors = func(string) rotationExecutor { return rec }
	_, accounts := f.sharedOn(t, "rt-global-positive", "ops", "old-shared", "10.3.15.1", "10.3.15.2")
	batch, assetIDs, err := f.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, false, accounts...), 1, "admin")
	require.NoError(t, err)
	records := f.runner.RunBatch(batch, assetIDs)
	require.Len(t, records, 2)
	for _, r := range records {
		assert.Equal(t, model.ChangeSecretSuccess, r.Status, r.Error)
	}
	var rot model.CredentialRotation
	require.NoError(t, f.db.First(&rot).Error)
	require.NotNil(t, rot.AuthorizationID)
	var auth model.CredentialJobAuthorization
	require.NoError(t, f.db.First(&auth, *rot.AuthorizationID).Error)
	caps, err := boundedRotationCapabilities(&auth)
	require.NoError(t, err)
	assert.Subset(t, caps, boundedSplitFloor())
	stored, err := strictAuthorizationCapabilities(&auth)
	require.NoError(t, err)
	assert.Subset(t, stored, boundedSplitFloor(), "授權脈絡保存完整的拆分能力")
}

// 背景工作的目標範圍重驗（同名外部測試涵蓋候選投影；本檔涵蓋批次執行器）。
func TestRotationWorkScopeRecheck(t *testing.T) {
	t.Run("batch_revalidates_after_account_lock", testBatchRevalidatesAfterAccountLock)
	t.Run("batch_shared_mode_rechecks_bind", testBatchSharedModeRevalidatesBind)
	t.Run("pre_upgrade_work_completes", testPreUpgradeWorkCompletes)
	t.Run("single_account_revoked_after_candidate", testSingleAccountRevokedAfterCandidate)
	// 判定（與成員領取）短交易的兩種提交順序：SQLite 在交易外同步點注入；PG 另以 pg_locks 證明阻擋
	t.Run("sqlite_orders", testDispatchShortTxSQLite)
	t.Run("pg_move_first", testDispatchShortTxPGMoveFirst)
	t.Run("pg_claim_first", testDispatchShortTxPGClaimFirst)
}

// 單帳號路徑：帳號鎖後的第一次重驗通過、候選落庫之後才撤權，送出舊密碼認證與新密碼之前再重驗，
// 遠端 Rotate 零呼叫、候選丟棄、記撤權碼；全域主體權限未變的對照照常成功。
func testSingleAccountRevokedAfterCandidate(t *testing.T) {
	t.Run("scoped_revoked", func(t *testing.T) {
		g := newRtFixture(t)
		g.az.grant(CredCapAccountRotate, g.in)
		assetID, accountID := g.addHost(t, "rt-cand-h1", "10.3.16.1", "ops")
		g.place(t, assetID, g.in)
		batch, assetIDs, err := g.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, false, accountID),
			rtScopedUser, "rt-scoped")
		require.NoError(t, err)
		var stages []string
		g.runner.dispatchHook = func(stage string, acc uint) {
			stages = append(stages, stage)
			if stage == dispatchStageCandidate && acc == accountID {
				var n int64
				require.NoError(t, g.db.Model(&model.ChangeSecretCandidate{}).Where("account_id = ?", acc).Count(&n).Error)
				require.EqualValues(t, 1, n, "掛點時候選已落庫")
				g.az.revoke(CredCapAccountRotate)
			}
		}
		records := g.runner.RunBatch(batch, assetIDs)
		assert.Equal(t, []string{dispatchStageCandidate}, stages, "走到候選落庫後的重驗點")
		assert.Equal(t, 0, g.rotateCalls("10.3.16.1"), "撤權在派送前生效：遠端零呼叫")
		require.Len(t, records, 1)
		assert.Equal(t, model.ChangeSecretSkipped, records[0].Status)
		assert.Equal(t, model.ChangeSecretReasonAuthzRevoked, records[0].Error)
		var cands int64
		require.NoError(t, g.db.Model(&model.ChangeSecretCandidate{}).Count(&cands).Error)
		assert.EqualValues(t, 0, cands, "尚未派送：候選丟棄")
	})
	t.Run("global_unchanged_succeeds", func(t *testing.T) {
		f := setupBatchFixture(t)
		rec := newSecretRecorder()
		f.useExecutor(rec)
		_, accountID := f.addHost(t, "rt-cand-h2", "10.3.16.2", "ops")
		batch, assetIDs, err := f.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, false, accountID), 1, "admin")
		require.NoError(t, err)
		hits := 0
		f.runner.dispatchHook = func(stage string, _ uint) {
			if stage == dispatchStageCandidate {
				hits++
			}
		}
		records := f.runner.RunBatch(batch, assetIDs)
		assert.Equal(t, 1, hits)
		require.Len(t, records, 1)
		assert.Equal(t, model.ChangeSecretSuccess, records[0].Status, records[0].Error)
		_, rc, _ := rec.snapshotCalls()
		assert.Equal(t, 1, rc["10.3.16.2"])
	})
}

// 升級前在途工作（全域發起者建立的計畫、批次與一筆待驗候選；新欄取預設值）照常執行與收斂，
// 不出現上界暫停原因碼。
func testPreUpgradeWorkCompletes(t *testing.T) {
	f := setupBatchFixture(t)
	rec := newSecretRecorder()
	f.useExecutor(rec)
	a1, _ := f.addHost(t, "pre-plan-h", "10.3.8.1", "ops")
	_, acc2 := f.addHost(t, "pre-batch-h", "10.3.8.2", "ops")
	_, acc3 := f.addHost(t, "pre-cand-h", "10.3.8.3", "ops")

	plan, err := f.plans.Create(adminCtx(), planRequest("pre-upgrade plan", []uint{a1}, "ops"))
	require.NoError(t, err)
	precs := f.runner.RunPlan(plan)
	require.Len(t, precs, 1)
	assert.Equal(t, model.ChangeSecretSuccess, precs[0].Status, precs[0].Error)

	batch, ids, err := f.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, false, acc2), 1, "admin")
	require.NoError(t, err)
	assert.Equal(t, model.CredentialOwnerGlobal, f.reload(t, batch.ID).SharedCredentialOwnerKind, "歸屬欄取預設值")
	brecs := f.runner.RunBatch(batch, ids)
	require.Len(t, brecs, 1)
	assert.Equal(t, model.ChangeSecretSuccess, brecs[0].Status, brecs[0].Error)

	// 待驗候選：首次驗證失敗留下候選，之後的重試收斂
	rec.mu.Lock()
	rec.verifyErr["10.3.8.3"] = errors.New("verify transport lost")
	rec.mu.Unlock()
	cb, cids, err := f.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, false, acc3), 1, "admin")
	require.NoError(t, err)
	crecs := f.runner.RunBatch(cb, cids)
	require.Len(t, crecs, 1)
	require.Equal(t, model.ChangeSecretUnverified, crecs[0].Status, crecs[0].Error)
	var cand model.ChangeSecretCandidate
	require.NoError(t, f.db.Where("account_id = ?", acc3).First(&cand).Error)
	rec.mu.Lock()
	delete(rec.verifyErr, "10.3.8.3")
	rec.mu.Unlock()
	f.retry.RetryOne(&cand)
	var left int64
	require.NoError(t, f.db.Model(&model.ChangeSecretCandidate{}).Where("account_id = ?", acc3).Count(&left).Error)
	assert.EqualValues(t, 0, left, "待驗候選經重試收斂")

	var bound int64
	require.NoError(t, f.db.Model(&model.ChangeSecretRecord{}).
		Where("error = ?", "CHANGE_SECRET_SCOPE_BOUND_EXCEEDED").Count(&bound).Error)
	assert.EqualValues(t, 0, bound, "無上界暫停記錄")
}

// 一般逐帳號路徑：重驗在取得帳號互斥鎖之後。另一個工作持有帳號鎖期間資產移出範圍，鎖釋放後遠端零觸碰。
func testBatchRevalidatesAfterAccountLock(t *testing.T) {
	g := newRtFixture(t)
	g.az.grant(CredCapAccountRotate, g.in)
	assetID, accountID := g.addHost(t, "rt-lock-h1", "10.3.4.1", "ops")
	g.place(t, assetID, g.in)
	batch, assetIDs, err := g.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, true), rtScopedUser, "rt-scoped")
	require.NoError(t, err)
	askedBefore := g.az.askedCount()

	unlock := lockRotationAccount(accountID)
	done := make(chan []model.ChangeSecretRecord, 1)
	go func() { done <- g.runner.RunBatch(batch, assetIDs) }()
	// 給執行器走到帳號鎖：鎖前若有重驗，判定次數會在此期間增加
	deadline := time.Now().Add(700 * time.Millisecond)
	for time.Now().Before(deadline) && g.az.askedCount() == askedBefore {
		time.Sleep(10 * time.Millisecond)
	}
	g.place(t, assetID, g.out)
	unlock()
	var records []model.ChangeSecretRecord
	select {
	case records = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("批次未結束")
	}
	assert.Equal(t, 0, g.rotateCalls("10.3.4.1"), "等鎖期間移出範圍：遠端零觸碰")
	require.Len(t, records, 1)
	assert.Equal(t, model.ChangeSecretSkipped, records[0].Status)
	assert.Equal(t, model.ChangeSecretReasonAuthzRevoked, records[0].Error)
	var cands int64
	require.NoError(t, g.db.Model(&model.ChangeSecretCandidate{}).Count(&cands).Error)
	assert.EqualValues(t, 0, cands, "不建立候選")
}

// 整批同一組：執行時依批次授權脈絡重驗模式能力，並對本批次新建的共用憑證與目標資產檢查掛入範圍。
func testBatchSharedModeRevalidatesBind(t *testing.T) {
	// setup 兩台放在 in；帳號改密在 in、建立在 in 與 out；新憑證歸屬由 ownerOut 決定（out 或 in）
	setup := func(t *testing.T, ownerOut bool, host string) (*rtFixture, *model.ChangeSecretBatch, []uint, [2]uint, [2]uint) {
		g := newRtFixture(t)
		g.az.grant(CredCapAccountRotate, g.in)
		g.az.grant(CredCapCreate, g.in, g.out)
		g.az.grant(CredCapBind, g.in)
		var accounts [2]uint
		for i, suffix := range []string{"1", "2"} {
			assetID, accountID := g.addHost(t, "rt-shared-"+host+suffix, host+suffix, "ops")
			g.place(t, assetID, g.in)
			accounts[i] = accountID
		}
		req := sharedBatchRequest("ops", "rt 同一組 "+host)
		owner := g.in
		if ownerOut {
			owner = g.out
		}
		req.SharedCredentialOwnership = &CredentialOwnershipInput{Kind: model.CredentialOwnerNode, NodeID: &owner}
		batch, assetIDs, err := g.batches.Create(req, rtScopedUser, "rt-scoped")
		require.NoError(t, err)
		require.Len(t, assetIDs, 2)
		before := [2]uint{g.bindingOf(t, accounts[0]).CredentialID, g.bindingOf(t, accounts[1]).CredentialID}
		return g, batch, assetIDs, accounts, before
	}
	assertUntouched := func(t *testing.T, g *rtFixture, host string, records []model.ChangeSecretRecord,
		accounts, before [2]uint) {
		t.Helper()
		assert.Equal(t, 0, g.rotateCalls(host+"1"), "遠端零觸碰")
		assert.Equal(t, 0, g.rotateCalls(host+"2"), "遠端零觸碰")
		require.NotEmpty(t, records)
		assert.Equal(t, model.ChangeSecretSkipped, records[0].Status)
		assert.Equal(t, model.ChangeSecretReasonAuthzRevoked, records[0].Error)
		for i, acc := range accounts {
			assert.Equal(t, before[i], g.bindingOf(t, acc).CredentialID, "不改綁")
		}
		var cands int64
		require.NoError(t, g.db.Model(&model.ChangeSecretCandidate{}).Count(&cands).Error)
		assert.EqualValues(t, 0, cands, "不建立候選")
	}

	t.Run("bind_revoked_after_create", func(t *testing.T) {
		g, batch, assetIDs, accounts, before := setup(t, false, "10.3.5.")
		g.az.revoke(CredCapBind)
		records := g.runner.RunBatch(batch, assetIDs)
		assertUntouched(t, g, "10.3.5.", records, accounts, before)
	})

	t.Run("new_credential_outside_bind_scope", func(t *testing.T) {
		// 目標資產都在掛入範圍內，但新共用憑證歸屬在掛入範圍外：仍不得派送與改綁
		g, batch, assetIDs, accounts, before := setup(t, true, "10.3.6.")
		records := g.runner.RunBatch(batch, assetIDs)
		assertUntouched(t, g, "10.3.6.", records, accounts, before)
	})

	t.Run("in_scope_succeeds", func(t *testing.T) {
		g, batch, assetIDs, accounts, _ := setup(t, false, "10.3.7.")
		records := g.runner.RunBatch(batch, assetIDs)
		require.Len(t, records, 2)
		for _, r := range records {
			assert.Equal(t, model.ChangeSecretSuccess, r.Status, r.Error)
		}
		assert.Equal(t, 1, g.rotateCalls("10.3.7.1"))
		assert.Equal(t, 1, g.rotateCalls("10.3.7.2"))
		for _, acc := range accounts {
			assert.Equal(t, batch.SharedCredentialID, g.bindingOf(t, acc).CredentialID, "成功目標改綁到新共用憑證")
		}
	})
}
