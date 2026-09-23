package authz

import (
	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestAccessRequestItemViews(t *testing.T) {
	s, db, req, agent := twoPendingItems(t)
	// Only the second asset is assigned to this reviewer.
	require.NoError(t, db.Where("approver_id=?", 2).Delete(&model.ApproverScope{}).Error)
	actor, assetID := uint(2), uint(2)
	require.NoError(t, db.Create(&model.ApproverScope{ApproverID: &actor, AssetID: &assetID, GrantedBy: 3}).Error)
	mine, err := s.ListMine(agent)
	require.NoError(t, err)
	require.Len(t, mine, 1)
	require.Len(t, mine[0].Items, 2)
	pending, err := s.ListPending(2, false, time.Now())
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.Len(t, pending[0].Items, 2)
	count, err := s.PendingCount(2, false, time.Now())
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
	_, err = s.Approve(2, true, req.ID, DecideInput{})
	require.NoError(t, err)
	history, total, err := s.ListHistory(2, false, 1, 20)
	require.NoError(t, err)
	require.EqualValues(t, 1, total)
	require.Len(t, history[0].Items, 2)
	tickets, err := s.MyActiveTickets(agent, time.Now())
	require.NoError(t, err)
	require.Len(t, tickets, 2)
	for _, ticket := range tickets {
		require.NotNil(t, ticket.RequestID)
		require.Equal(t, req.ID, *ticket.RequestID)
	}
}

// 審核者要知道自己在核准哪一台機器。名稱隨項目一起投影，因為「決定一個項目」
// 不等於「讀得到那個資產」——審核者對非主資產通常沒有讀取權，逼前端回頭打
// GET /assets/:id 只會落到「資產名稱無法讀取」的裸 id。
func TestPendingItemsProjectAssetName(t *testing.T) {
	s, db, _, _ := twoPendingItems(t)
	// 這位審核者的範圍只涵蓋資產 2，且名下沒有任何資產授權（授權只發給 agent）。
	require.NoError(t, db.Where("approver_id=?", 2).Delete(&model.ApproverScope{}).Error)
	actor, assetID := uint(2), uint(2)
	require.NoError(t, db.Create(&model.ApproverScope{ApproverID: &actor, AssetID: &assetID, GrantedBy: 3}).Error)
	var grants int64
	require.NoError(t, db.Model(&model.AssetAuthorization{}).Where("user_id = ?", actor).Count(&grants).Error)
	require.Zero(t, grants, "前提：審核者對這些資產沒有讀取權")
	// 資產 1 已軟刪：名稱仍要讀得到，而且要說得出目標已不存在。
	require.NoError(t, db.Delete(&model.Asset{}, 1).Error)

	pending, err := s.ListPending(2, false, time.Now())
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.Len(t, pending[0].Items, 2)
	byAsset := map[uint]model.AccessRequestItem{}
	for _, item := range pending[0].Items {
		byAsset[item.AssetID] = item
	}
	require.Equal(t, "a-approval", byAsset[1].AssetName)
	require.True(t, byAsset[1].AssetDeleted, "軟刪資產要標示出來")
	require.Equal(t, "a-reason", byAsset[2].AssetName)
	require.False(t, byAsset[2].AssetDeleted)
}
