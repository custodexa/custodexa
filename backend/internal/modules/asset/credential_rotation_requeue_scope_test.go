package asset

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
)

// ownershipOutOfScopeForTest 範圍拒絕值的替身（範圍化主體對歸屬範圍外的憑證），與正式範圍拒絕值
// 同樣帶目標種類。
type ownershipOutOfScopeForTest struct{}

func (ownershipOutOfScopeForTest) Error() string                 { return "credential ownership out of scope" }
func (ownershipOutOfScopeForTest) ScopeDeniedTargetKind() string { return "credential" }

var errOwnershipOutOfScopeForTest error = ownershipOutOfScopeForTest{}

// ownershipScopedAuthorizer 對 user 以判定當下讀到的憑證歸屬判定：歸屬節點不是 node 即範圍拒絕；
// 其他主體交給 inner。與正式轉接頭同一口徑（以呼叫方連線讀現況，不沿用重排當下的結果）。
type ownershipScopedAuthorizer struct {
	inner *fakeCredentialAuthorizer
	user  uint
	node  uint
}

func (a *ownershipScopedAuthorizer) AuthorizeCredentialManagement(ctx context.Context, db *gorm.DB,
	actor CredentialManagementActor, req CredentialManagementRequest) (CredentialManagementDecision, error) {
	if actor.UserID == a.user {
		q := db
		if q == nil {
			q = database.DB
		}
		for _, id := range req.CredentialIDs {
			var c model.Credential
			if err := q.Select("id", "owner_node_id").First(&c, id).Error; err != nil {
				return CredentialManagementDecision{}, err
			}
			if c.OwnerNodeID == nil || *c.OwnerNodeID != a.node {
				return CredentialManagementDecision{ScopeDenial: errOwnershipOutOfScopeForTest}, nil
			}
		}
	}
	return a.inner.AuthorizeCredentialManagement(ctx, db, actor, req)
}

func (a *ownershipScopedAuthorizer) RestoreGeneration(db *gorm.DB) (string, error) {
	return a.inner.RestoreGeneration(db)
}

// 範圍化主體重排一台最終失敗成員後，該憑證改歸其範圍外：背景派送前重驗重排者不通過，成員停止並留下原因，
// 不以仍具權的發起者脈絡送出。對照：歸屬仍在範圍內時背景照常派送。
func TestBackgroundRevalidatesRequeuerAfterOwnershipLeavesScope(t *testing.T) {
	const inNode, outNode uint = 501, 502
	setOwner := func(t *testing.T, f *requeueFixture, node uint) uint {
		t.Helper()
		credID := f.member(t).CredentialID
		require.NoError(t, f.db.Model(&model.Credential{}).Where("id = ?", credID).
			Updates(map[string]any{"owner_kind": model.CredentialOwnerNode, "owner_node_id": node}).Error)
		return credID
	}

	f := newRequeueFixture(t, "10.9.9.61", "10.9.9.62")
	setOwner(t, f, inNode)
	f.rotations.mgmt = credentialManagementGate{authorizer: &ownershipScopedAuthorizer{inner: f.authz, user: 9, node: inNode}}
	_, before, _ := f.rec.snapshotCalls()

	require.NoError(t, f.rotations.requeueMember(userCtx(9, "scoped-clicker"), f.rot, f.memberID))
	require.Equal(t, model.CredentialMemberQueued, f.member(t).State, "歸屬在範圍內時重排成功")
	assert.Equal(t, uint(9), f.member(t).RequeuedBy)

	// 重排之後、背景派送之前，憑證改歸到重排者範圍外；本輪發起者（7）仍具權
	setOwner(t, f, outNode)
	advanced, err := f.rotations.AdvanceMemberInBackground(context.Background(), f.rot.ID, f.memberID)
	require.NoError(t, err)
	assert.True(t, advanced, "背景確實接手了這個成員")
	m := f.member(t)
	assert.Equal(t, model.CredentialMemberAbandoned, m.State, "重排者重驗不通過：成員停止，不派送")
	assert.Equal(t, model.ChangeSecretReasonAuthzRevoked, m.LastError, "範圍拒絕＝撤權，停止原因留在成員列")
	_, after, _ := f.rec.snapshotCalls()
	assert.Equal(t, before, after, "遠端零觸碰：不以發起者脈絡送出")

	// 對照：歸屬仍在範圍內，背景以發起者與重排者雙重重驗通過後派送
	g := newRequeueFixture(t, "10.9.9.63", "10.9.9.64")
	setOwner(t, g, inNode)
	g.rotations.mgmt = credentialManagementGate{authorizer: &ownershipScopedAuthorizer{inner: g.authz, user: 9, node: inNode}}
	require.NoError(t, g.rotations.requeueMember(userCtx(9, "scoped-clicker"), g.rot, g.memberID))
	advanced, err = g.rotations.AdvanceMemberInBackground(context.Background(), g.rot.ID, g.memberID)
	require.NoError(t, err)
	assert.True(t, advanced)
	assert.Equal(t, model.CredentialMemberApplied, g.member(t).State)
}

// 背景重驗的原因碼：能力不足與範圍拒絕都是撤權，判定器失效才是無法判定。
func TestRevalidationReasonMapsScopeDenialToRevoked(t *testing.T) {
	assert.Equal(t, model.ChangeSecretReasonAuthzRevoked,
		revalidationReason(capabilityDenied(ErrCredentialBindForbidden, CredCapRotate)))
	assert.Equal(t, model.ChangeSecretReasonAuthzRevoked, revalidationReason(errOwnershipOutOfScopeForTest))
	assert.Equal(t, model.ChangeSecretReasonAuthzRevoked,
		revalidationReason(fmt.Errorf("wrapped: %w", errOwnershipOutOfScopeForTest)))
	assert.Equal(t, model.ChangeSecretReasonAuthzUnavailable, revalidationReason(ErrCredentialAuthzUnavailable))
}
