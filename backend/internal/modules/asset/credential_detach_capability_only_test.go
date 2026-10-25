package asset

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// detachOnlyDeniedCaps 除脫離以外的全部憑證與帳號語義能力。
var detachOnlyDeniedCaps = []string{
	CredCapView, CredCapCreate, CredCapUpdate, CredCapSetSecret, CredCapRotate,
	CredCapConvertScope, CredCapDelete, CredCapBind, CredCapAccountRotate, CredCapAccountEdit,
}

// 全域主體只持脫離能力（不持掛載）即可完成單台脫離：脫離流程內部的改綁與建專用憑證不得替
// 操作者追加任何能力要求。對照：連脫離能力也沒有時以能力拒絕，掛載與遠端皆不變。
func TestGlobalDetachOnlyCapabilityDetaches(t *testing.T) {
	const detacher uint = 9
	f := setupRotationFixture(t)
	credID, accounts := f.sharedOn(t, "只持脫離", "ops", "old-shared", "10.13.9.1", "10.13.9.2")
	accA, accB := accounts[0], accounts[1]
	f.perms.denyFor(detacher, detachOnlyDeniedCaps...)

	rot, err := f.rotations.Detach(userCtx(detacher, "detach-only"), credID, accB,
		DetachCredentialRequest{Source: DetachSourceRandom})
	require.NoError(t, err, "只持脫離能力的全域主體脫離成功")
	require.NotNil(t, rot)

	moved := f.binding(t, accB)
	assert.NotEqual(t, credID, moved.CredentialID, "該台改掛新的專用憑證")
	assert.Equal(t, model.CredentialScopeDedicated, f.credential(t, moved.CredentialID).Scope)
	assert.Equal(t, credID, f.binding(t, accA).CredentialID, "其餘掛載不受影響")

	// 本主體被問到的每一次判定都只要求脫離能力（流程內沒有追加掛載或其他能力）
	f.perms.mu.Lock()
	var askedForDetacher int
	for i, req := range f.perms.asked {
		if f.perms.askedActors[i] != detacher {
			continue
		}
		askedForDetacher++
		assert.Equal(t, []string{CredCapDetach}, req.Capabilities, "第 %d 次判定（%s）", i, req.Operation)
	}
	f.perms.mu.Unlock()
	assert.Positive(t, askedForDetacher, "脫離確實經過管理授權判定")

	// 對照：連脫離能力也沒有
	g := setupRotationFixture(t)
	credG, accountsG := g.sharedOn(t, "不持脫離", "ops", "old-shared", "10.13.9.3", "10.13.9.4")
	g.perms.denyFor(detacher, append([]string{CredCapDetach}, detachOnlyDeniedCaps...)...)
	_, err = g.rotations.Detach(userCtx(detacher, "no-detach"), credG, accountsG[1],
		DetachCredentialRequest{Source: DetachSourceRandom})
	require.ErrorIs(t, err, ErrCredentialBindForbidden, "缺脫離能力以能力拒絕")
	assert.Equal(t, credG, g.binding(t, accountsG[1]).CredentialID, "掛載不變")
	_, rotateCalls, _ := g.remote.snapshot()
	assert.Zero(t, rotateCalls["10.13.9.4"], "遠端零觸碰")
}
