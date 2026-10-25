package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 授權列表的列級可操作旗標：以真實的授權服務、範圍判定與撤銷資格計算。
// 節點、資產名稱以 zz-ra- 起頭。

type raAction struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
	Limit   string `json:"limit"`
}

type raRow struct {
	ID      uint `json:"id"`
	Actions *struct {
		UpdateAccounts raAction  `json:"update_accounts"`
		Delete         raAction  `json:"delete"`
		Revoke         *raAction `json:"revoke"`
	} `json:"actions"`
}

func (e *trEnv) listRows(uid uint) ([]raRow, string) {
	e.t.Helper()
	svc := authz.NewAssetAuthorizationService(e.db)
	aeval := authz.NewAuthorizationScopeEvaluator(e.cat, asset.NewScopeTopologyReader())
	svc.SetWriteScope(authz.NewAuthorizationWriteScope(aeval))
	h := api.NewAuthorizationHandler(svc, authz.NewEffectiveAccessResolver(e.db).WithScope(aeval))
	h.EnableScopedWrites(authz.NewAuthorizationRowActions(e.db, e.svc), nil)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		p, err := authz.ResolveUserOnWithCatalogue(e.db, e.cat, uid, authz.TokenFacts{})
		require.NoError(e.t, err)
		middleware.SetPrincipal(c, p)
		c.Set("userID", uid)
		c.Set("username", fmt.Sprintf("u%d", uid))
		c.Next()
	})
	r.GET("/api/v1/authorizations", h.List)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/authorizations?page_size=100", nil))
	require.Equal(e.t, http.StatusOK, w.Code, w.Body.String())
	var out struct {
		Data []raRow `json:"data"`
	}
	require.NoError(e.t, json.Unmarshal(w.Body.Bytes(), &out), w.Body.String())
	return out.Data, w.Body.String()
}

func raFind(rows []raRow, id uint) *raRow {
	for i := range rows {
		if rows[i].ID == id {
			return &rows[i]
		}
	}
	return nil
}

func (e *trEnv) rule(subjectUser, subjectGroup *uint, assetID, grantedBy uint) uint {
	e.t.Helper()
	a := model.AssetAuthorization{UserID: subjectUser, UserGroupID: subjectGroup, AssetID: &assetID,
		Permission: model.PermissionConnect, GrantedBy: grantedBy, Accounts: model.AccountScope{model.AccountScopeAll}}
	require.NoError(e.t, e.db.Create(&a).Error)
	return a.ID
}

// 把任務的第一張票證接回申請單（列表據此回填所屬申請單）。
func (e *trEnv) linkTicket(tk trTask) {
	e.t.Helper()
	require.NoError(e.t, e.db.Model(&model.AccessRequest{}).Where("id = ?", tk.reqID).
		Update("authorization_id", tk.authIDs[0]).Error)
}

func TestAuthorizationRowActions(t *testing.T) {
	e := newTREnv(t)
	e.node("zz-ra-a", "")
	e.node("zz-ra-b", "zz-ra-a")
	e.node("zz-ra-c", "")
	x := e.asset("zz-ra-x", "zz-ra-b")
	y := e.asset("zz-ra-y", "zz-ra-c")
	op := e.user("zz-ra-op")
	e.grantNodes(op, e.role(authz.PermAuthorizationManage), "zz-ra-a")
	sub := e.user("zz-ra-sub")
	requester := e.user("zz-ra-requester")

	group := model.UserGroup{Name: "zz-ra-group"}
	require.NoError(t, e.db.Create(&group).Error)
	require.NoError(t, e.db.Create(&model.UserGroupMember{UserGroupID: group.ID, UserID: op}).Error)

	byOther := e.rule(&sub, nil, x, e.super)
	// 另立主體：同主體同客體同權限的手動規則受唯一索引約束
	sub2 := e.user("zz-ra-sub2")
	byOp := e.rule(&sub2, nil, x, op)
	selfRule := e.rule(&op, nil, x, e.super)
	groupRule := e.rule(nil, &group.ID, x, e.super)

	// 臨時授權：範圍內單項、橫跨範圍外資產、已過期
	inScope := e.task(requester, 0, trItem{assetID: x})
	e.linkTicket(inScope)
	mixed := e.task(requester, 0, trItem{assetID: x}, trItem{assetID: y})
	e.linkTicket(mixed)
	expired := e.task(requester, 0, trItem{assetID: x})
	e.linkTicket(expired)
	require.NoError(t, e.db.Model(&model.AssetAuthorization{}).Where("id = ?", expired.authIDs[0]).
		Update("date_expired", time.Now().Add(-time.Minute)).Error)

	rows, body := e.listRows(op)

	t.Run("manual rules follow the same decisions as the write endpoints", func(t *testing.T) {
		r := raFind(rows, byOther)
		require.NotNil(t, r, body)
		require.NotNil(t, r.Actions, body)
		require.Equal(t, raAction{Allowed: true, Limit: "narrow_only"}, r.Actions.UpdateAccounts, "非建立者只能縮小")
		require.Equal(t, raAction{Allowed: true}, r.Actions.Delete)
		require.Nil(t, r.Actions.Revoke, "手動規則不帶 revoke")

		r = raFind(rows, byOp)
		require.NotNil(t, r, body)
		require.Equal(t, raAction{Allowed: true}, r.Actions.UpdateAccounts, "建立者不帶限制")
	})
	t.Run("self subject and own group block account scope changes but not deletion", func(t *testing.T) {
		for _, id := range []uint{selfRule, groupRule} {
			r := raFind(rows, id)
			require.NotNil(t, r, body)
			require.Equal(t, raAction{Reason: "self_subject"}, r.Actions.UpdateAccounts)
			require.Equal(t, raAction{Allowed: true}, r.Actions.Delete)
		}
	})
	t.Run("ticket rule is bound to its request", func(t *testing.T) {
		r := raFind(rows, inScope.authIDs[0])
		require.NotNil(t, r, body)
		require.Equal(t, raAction{Reason: "ticket_bound"}, r.Actions.UpdateAccounts)
		require.Equal(t, raAction{Reason: "ticket_bound"}, r.Actions.Delete)
		require.NotNil(t, r.Actions.Revoke)
		require.Equal(t, raAction{Allowed: true}, *r.Actions.Revoke, "範圍涵蓋整張申請單的資產")
	})
	t.Run("revoke is judged on the whole request", func(t *testing.T) {
		r := raFind(rows, mixed.authIDs[0])
		require.NotNil(t, r, body)
		require.NotNil(t, r.Actions.Revoke)
		require.Equal(t, raAction{Reason: "revoke_not_eligible"}, *r.Actions.Revoke, "同單另有範圍外資產")
		require.Nil(t, raFind(rows, mixed.authIDs[1]), "範圍外資產的票證不在列表")
	})
	t.Run("expired ticket cannot be revoked", func(t *testing.T) {
		r := raFind(rows, expired.authIDs[0])
		require.NotNil(t, r, body)
		require.Equal(t, raAction{Reason: "not_revocable"}, *r.Actions.Revoke)
	})
	t.Run("flags agree with the endpoints", func(t *testing.T) {
		// 旗標說可撤銷的，撤銷端點照做；說不可撤銷的，端點拒絕
		code, rb := e.revoke(op, mixed.reqID, 0)
		require.Equal(t, http.StatusForbidden, code, rb)
		code, rb = e.revoke(op, inScope.reqID, 0)
		require.Equal(t, http.StatusOK, code, rb)
	})
	t.Run("super administrator gets no flags", func(t *testing.T) {
		all, sbody := e.listRows(e.super)
		require.NotEmpty(t, all, sbody)
		for _, r := range all {
			require.Nil(t, r.Actions, sbody)
		}
		require.NotContains(t, sbody, `"actions"`)
	})
}
