package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

type approvalsCard struct {
	Value       int64 `json:"value"`
	Count       int64 `json:"count"`
	ReviewCount int64 `json:"review_count"`
}

type approvalsSpec struct {
	requester uint
	executor  *uint
	// items：每項的資產與最終狀態（建立時一律 pending，之後改成要的狀態）
	items   []approvalsItem
	expired bool
}

type approvalsItem struct {
	asset   uint
	decided bool
}

func (e *parityEnv) addUser(name string, kind string, owner *uint) *model.User {
	e.t.Helper()
	u := &model.User{Username: name, Password: "x", Active: true, Email: emailPtr(name + "@x"), Kind: kind, OwnerUserID: owner}
	require.NoError(e.t, e.db.Create(u).Error)
	e.users[name] = u
	e.who[name] = e.who["user-b"]
	return u
}

func (e *parityEnv) addRequest(sp approvalsSpec) *model.AccessRequest {
	e.t.Helper()
	expiry := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	if sp.expired {
		expiry = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	r := &model.AccessRequest{RequesterID: sp.requester, ExecutorUserID: sp.executor, AssetID: sp.items[0].asset, Reason: "r",
		RequestedDurationMinutes: 30, Status: model.AccessRequestPending, PendingExpiresAt: expiry}
	require.NoError(e.t, e.db.Create(r).Error)
	for _, it := range sp.items {
		item := &model.AccessRequestItem{RequestID: r.ID, RequesterID: sp.requester, AssetID: it.asset, Status: model.AccessRequestPending}
		require.NoError(e.t, e.db.Create(item).Error)
		if it.decided {
			require.NoError(e.t, e.db.Model(item).Update("status", model.AccessRequestApproved).Error)
		}
	}
	return r
}

// addBreakGlass 建一張已即時核准、等待補審的破窗單（短窗 pending_expires_at 視需要已過）。
func (e *parityEnv) addBreakGlass(requester, asset uint, windowPassed bool, created time.Time) *model.AccessRequest {
	e.t.Helper()
	expiry := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	if windowPassed {
		expiry = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	r := &model.AccessRequest{RequesterID: requester, AssetID: asset, Reason: "r", RequestedDurationMinutes: 30,
		Status: model.AccessRequestPending, PendingExpiresAt: expiry, Kind: model.AccessRequestKindBreakGlass,
		ReviewStatus: model.BreakGlassReviewPending, CreatedAt: created}
	require.NoError(e.t, e.db.Create(r).Error)
	item := &model.AccessRequestItem{RequestID: r.ID, RequesterID: requester, AssetID: asset, Status: model.AccessRequestPending}
	require.NoError(e.t, e.db.Create(item).Error)
	require.NoError(e.t, e.db.Model(item).Update("status", model.AccessRequestApproved).Error)
	require.NoError(e.t, e.db.Model(r).Update("status", model.AccessRequestApproved).Error)
	return r
}

func (e *parityEnv) approvalsCard(who string) approvalsCard {
	e.t.Helper()
	w, _ := e.call(who, "/api/v1/dashboard/cards/pending-approvals")
	require.Equal(e.t, http.StatusOK, w.Code, w.Body.String())
	var c approvalsCard
	require.NoError(e.t, json.Unmarshal(w.Body.Bytes(), &c))
	return c
}

// views 回傳審核中心兩視圖與導航 badge 的完整數：待審列表載入數、badge 的待審數與待補審數、待補審列表載入數。
func (e *parityEnv) views(who string) (pendingLoaded, badgeCount, badgeReview, reviewLoaded int64) {
	e.t.Helper()
	pendingLoaded = e.total(who, "/api/v1/access-requests/pending")
	reviewLoaded = e.total(who, "/api/v1/access-requests/reviews/pending")
	w, m := e.call(who, "/api/v1/access-requests/pending/count")
	require.Equal(e.t, http.StatusOK, w.Code)
	require.NoError(e.t, json.Unmarshal(m["count"], &badgeCount))
	require.NoError(e.t, json.Unmarshal(m["review_count"], &badgeReview))
	return
}

func testApprovalsParity(t *testing.T) {
	e := newParityEnv(t)
	alpha, beta := e.alpha, e.beta

	a := e.addUser("approver-a", "", nil)
	gm := e.addUser("approver-gm", "", nil)
	idle := e.addUser("approver-idle", "", nil)
	stranger := e.addUser("stranger", "", nil)
	r1 := e.addUser("req-1", "", nil)
	r2 := e.addUser("req-2", "", nil)
	bulk := e.addUser("req-bulk", "", nil)
	agent := e.addUser("agent-of-a", model.KindAgent, &a.ID)
	_ = stranger

	// 資格：a 經審核方群組取得 alpha；gm 經審核方群組取得 beta；idle 有資格但範圍只涵蓋無任何申請的申請人
	g := &model.UserGroup{Name: "approvers-beta"}
	require.NoError(t, e.db.Create(g).Error)
	require.NoError(t, e.db.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: gm.ID}).Error)
	ig := &model.UserGroup{Name: "approvers-idle"}
	require.NoError(t, e.db.Create(ig).Error)
	require.NoError(t, e.db.Create(&model.UserGroupMember{UserGroupID: ig.ID, UserID: idle.ID}).Error)
	unrelated := e.addUser("unrelated", "", nil)
	ag := &model.UserGroup{Name: "approvers-alpha"}
	require.NoError(t, e.db.Create(ag).Error)
	require.NoError(t, e.db.Create(&model.UserGroupMember{UserGroupID: ag.ID, UserID: a.ID}).Error)
	require.NoError(t, e.db.Create(&model.ApproverScope{ApproverGroupID: &ag.ID, AssetID: &alpha, GrantedBy: 1}).Error)
	require.NoError(t, e.db.Create(&model.ApproverScope{ApproverGroupID: &g.ID, AssetID: &beta, GrantedBy: 1}).Error)
	require.NoError(t, e.db.Create(&model.ApproverScope{ApproverGroupID: &ig.ID, SubjectUserID: &unrelated.ID, GrantedBy: 1}).Error)

	// 納入 a 的待審：r1 的 alpha 一張，bulk 的 alpha 205 張（超過列表 200 筆上限）
	counted := e.addRequest(approvalsSpec{requester: r1.ID, items: []approvalsItem{{asset: alpha}}})
	for i := 0; i < 205; i++ {
		e.addRequest(approvalsSpec{requester: bulk.ID, items: []approvalsItem{{asset: alpha}}})
	}
	// 單內兩項都在範圍內時只算一張申請
	both := e.addRequest(approvalsSpec{requester: r2.ID, items: []approvalsItem{{asset: beta}, {asset: beta}}})

	// 排除案例：每個都同時要求單筆核決對 a 回拒絕
	outOfScope := e.addRequest(approvalsSpec{requester: r2.ID, items: []approvalsItem{{asset: beta}}})
	own := e.addRequest(approvalsSpec{requester: a.ID, items: []approvalsItem{{asset: alpha}}})
	ownAgent := e.addRequest(approvalsSpec{requester: agent.ID, items: []approvalsItem{{asset: alpha}}})
	byExecutor := e.addRequest(approvalsSpec{requester: r2.ID, executor: &a.ID, items: []approvalsItem{{asset: alpha}}})
	onlyOutOfScopeLeft := e.addRequest(approvalsSpec{requester: r1.ID, items: []approvalsItem{{asset: alpha, decided: true}, {asset: beta}}})
	expired := e.addRequest(approvalsSpec{requester: r2.ID, expired: true, items: []approvalsItem{{asset: alpha}}})

	// 破窗：短窗已過與超過補審逾期時限的都照計；自己的、範圍外的、已補審的不計
	bg1 := e.addBreakGlass(r1.ID, alpha, true, time.Now())
	bg2 := e.addBreakGlass(r2.ID, alpha, false, time.Now().Add(-100*time.Hour))
	bgOwn := e.addBreakGlass(a.ID, alpha, false, time.Now())
	bgOut := e.addBreakGlass(r1.ID, beta, false, time.Now())
	bgDone := e.addBreakGlass(r2.ID, alpha, false, time.Now())
	require.NoError(t, e.db.Model(bgDone).Update("review_status", model.BreakGlassReviewReviewed).Error)

	id := func(r *model.AccessRequest) uint { return r.ID }
	decide := func(r *model.AccessRequest) error {
		_, err := e.requests.Approve(a.ID, false, id(r), authz.DecideInput{})
		return err
	}

	t.Run("資格與命中", func(t *testing.T) {
		// 命中：a 見 1＋205 張 alpha 與 2 張破窗；card 的 value＝count＋review_count
		c := e.approvalsCard("approver-a")
		assert.EqualValues(t, 206, c.Count)
		assert.EqualValues(t, 2, c.ReviewCount)
		assert.EqualValues(t, 208, c.Value)
		// 群組審核者正向：beta 範圍內 both、outOfScope、onlyOutOfScopeLeft 三張，破窗一張
		g := e.approvalsCard("approver-gm")
		assert.EqualValues(t, 3, g.Count)
		assert.EqualValues(t, 1, g.ReviewCount)
		// 有效資格但無命中為 0
		z := e.approvalsCard("approver-idle")
		assert.Zero(t, z.Value)
		assert.Zero(t, z.Count)
		assert.Zero(t, z.ReviewCount)
		// 無資格者拒絕，admin 不兜底，且拒絕回應不帶數字
		for _, who := range []string{"admin", "stranger", "user-a"} {
			w, _ := e.call(who, "/api/v1/dashboard/cards/pending-approvals")
			assert.Equal(t, http.StatusForbidden, w.Code, who)
			assert.NotContains(t, w.Body.String(), `"value"`, who)
		}
	})

	t.Run("兩視圖與badge同源", func(t *testing.T) {
		c := e.approvalsCard("approver-a")
		pendingLoaded, badgeCount, badgeReview, reviewLoaded := e.views("approver-a")
		assert.EqualValues(t, 200, pendingLoaded, "列表仍是載入數，形狀不變")
		assert.EqualValues(t, 2, reviewLoaded)
		assert.EqualValues(t, 206, badgeCount, "badge 是完整數，不受 200 筆上限影響")
		assert.EqualValues(t, 2, badgeReview)
		assert.Equal(t, c.Count, badgeCount)
		assert.Equal(t, c.ReviewCount, badgeReview)
		assert.Equal(t, c.Value, badgeCount+badgeReview)
		assert.Greater(t, badgeCount, pendingLoaded)

		gc := e.approvalsCard("approver-gm")
		gl, gb, gr, grl := e.views("approver-gm")
		assert.EqualValues(t, gc.Count, gl, "未超過上限時載入數等於完整數")
		assert.Equal(t, gc.Count, gb)
		assert.Equal(t, gc.ReviewCount, gr)
		assert.Equal(t, gr, grl)
	})

	t.Run("排除項不計且單筆核決拒絕", func(t *testing.T) {
		// 排除的申請不出現在 a 的待審列表（只取該申請單的 id 比對）
		_, m := e.call("approver-a", "/api/v1/access-requests/pending")
		var rows []struct{ ID uint }
		require.NoError(t, json.Unmarshal(m["data"], &rows))
		seen := map[uint]bool{}
		for _, r := range rows {
			seen[r.ID] = true
		}
		for name, r := range map[string]*model.AccessRequest{
			"範圍外": outOfScope, "申請人": own, "本人agent": ownAgent, "執行者": byExecutor,
			"範圍內已決只剩範圍外": onlyOutOfScopeLeft, "逾期": expired, "多項": both,
		} {
			assert.False(t, seen[r.ID], name)
		}

		assert.ErrorIs(t, decide(outOfScope), authz.ErrNotEligibleApprover, "範圍外")
		assert.ErrorIs(t, decide(own), authz.ErrSelfApproval, "申請人")
		assert.ErrorIs(t, decide(ownAgent), authz.ErrSelfApproval, "本人 agent")
		assert.ErrorIs(t, decide(byExecutor), authz.ErrSelfApproval, "執行者")
		assert.ErrorIs(t, decide(onlyOutOfScopeLeft), authz.ErrNotEligibleApprover, "範圍內已決只剩範圍外 pending")
		assert.ErrorIs(t, decide(expired), authz.ErrAccessRequestConflict, "逾期")

		// 仍計入的對照：onlyOutOfScopeLeft 與多項單對在範圍內的群組審核者可核決
		_, m = e.call("approver-gm", "/api/v1/access-requests/pending")
		require.NoError(t, json.Unmarshal(m["data"], &rows))
		gseen := map[uint]bool{}
		for _, r := range rows {
			gseen[r.ID] = true
		}
		assert.True(t, gseen[onlyOutOfScopeLeft.ID])
		assert.True(t, gseen[both.ID])
		assert.True(t, gseen[outOfScope.ID])
		assert.False(t, gseen[counted.ID])
	})

	t.Run("待補審排除與單筆補審相同", func(t *testing.T) {
		_, m := e.call("approver-a", "/api/v1/access-requests/reviews/pending")
		var rows []struct{ ID uint }
		require.NoError(t, json.Unmarshal(m["data"], &rows))
		got := map[uint]bool{}
		for _, r := range rows {
			got[r.ID] = true
		}
		assert.True(t, got[bg1.ID] && got[bg2.ID] && len(got) == 2)

		review := func(r *model.AccessRequest) error {
			_, err := e.requests.Review(a.ID, false, id(r), model.BreakGlassDispositionConfirmed, "n")
			return err
		}
		assert.ErrorIs(t, review(bgOwn), authz.ErrSelfReview)
		assert.ErrorIs(t, review(bgOut), authz.ErrNotEligibleApprover)
		assert.ErrorIs(t, review(bgDone), authz.ErrAlreadyReviewed)
		// 短窗已過、與超過補審逾期時限仍未補審的兩張：照計，且同一操作者 Review 成功
		require.NoError(t, review(bg1))
		require.NoError(t, review(bg2))
		assert.Zero(t, e.approvalsCard("approver-a").ReviewCount)
		assert.EqualValues(t, 206, e.approvalsCard("approver-a").Count, "補審不影響待審數")
	})

	t.Run("原列表回應形狀不變", func(t *testing.T) {
		for _, p := range []string{"/api/v1/access-requests/pending", "/api/v1/access-requests/reviews/pending"} {
			w, m := e.call("approver-a", p)
			require.Equal(t, http.StatusOK, w.Code, p)
			assert.Contains(t, m, "data", p)
			assert.Contains(t, m, "total", p)
		}
	})
}
