package agentmcp

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/sensitivescan"
	"github.com/gin-gonic/gin"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

func (f *fixture) owner(t *testing.T) sessionOwner {
	t.Helper()
	var token model.AgentToken
	require.NoError(t, f.db.First(&token).Error)
	return sessionOwner{MCP: "test", User: f.agent, Token: token.ID}
}
func (f *fixture) invoke(t *testing.T, name string, args any) *mcp.CallToolResult {
	t.Helper()
	raw, err := json.Marshal(args)
	require.NoError(t, err)
	var r *mcp.CallToolResult
	f.authenticated(t, "192.0.2.8", func(c *gin.Context) {
		var err error
		r, err = f.h.execute(c.Request.Context(), c, f.owner(t), name, raw)
		require.NoError(t, err)
	})
	return r
}
func object(t *testing.T, r *mcp.CallToolResult) map[string]any {
	t.Helper()
	var v map[string]any
	require.NoError(t, json.Unmarshal([]byte(resultText(r)), &v))
	return v
}
func (f *fixture) open(t *testing.T) (string, *ownedSession) {
	t.Helper()
	r := f.invoke(t, "open_session", map[string]any{"asset_id": f.asset, "account_id": f.account, "request_id": f.task})
	require.False(t, r.IsError, resultText(r))
	handle := object(t, r)["session_handle"].(string)
	e := f.h.owned(f.owner(t), handle)
	require.NotNil(t, e)
	t.Cleanup(func() { e.connection.Transport.Close(); <-e.connection.Done })
	return handle, e
}
func TestToolListAssetsExposure(t *testing.T) {
	f := newFixture(t)
	r := f.invoke(t, "list_assets", map[string]any{})
	require.False(t, r.IsError, resultText(r))
	assets := object(t, r)["assets"].([]any)
	require.Len(t, assets, 1)
	a := assets[0].(map[string]any)
	require.EqualValues(t, f.asset, a["asset_id"])
	require.Equal(t, true, a["connectable"])
	require.NotEmpty(t, a["accounts"])
	var exposures []model.AgentVisibilityExposure
	require.NoError(t, f.db.Find(&exposures).Error)
	require.Len(t, exposures, 1)
	require.Equal(t, f.agent, exposures[0].UserID)
	require.Equal(t, f.asset, exposures[0].AssetID)
	f.invoke(t, "list_assets", map[string]any{})
	var n int64
	f.db.Model(&model.AgentVisibilityExposure{}).Count(&n)
	require.EqualValues(t, 1, n)
}
func TestToolRequestAccess(t *testing.T) {
	for _, mode := range []string{"already_connectable", "open_without_item", "missing_accounts", "invisible"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			in := map[string]any{"items": []any{map[string]any{"asset_id": f.asset, "accounts": []string{"testuser"}}}, "reason": "maintenance", "duration_minutes": 10}
			var before int64
			f.db.Model(&model.AccessRequest{}).Count(&before)
			switch mode {
			case "open_without_item":
				require.NoError(t, f.db.Model(&model.AccessRequest{}).Where("id=?", f.task).Update("closed_at", time.Now()).Error)
			case "missing_accounts":
				in["items"] = []any{map[string]any{"asset_id": f.asset}}
			case "invisible":
				in["items"] = []any{map[string]any{"asset_id": 999, "accounts": []string{"x"}}}
				f.h.ssh.AuthorizationService.SetAgentProbeRecorder(func(context.Context, uint, uint, uint, string) error { return nil })
			}
			r := f.invoke(t, "request_access", in)
			v := object(t, r)
			var after int64
			f.db.Model(&model.AccessRequest{}).Count(&after)
			switch mode {
			case "already_connectable":
				require.False(t, r.IsError, resultText(r))
				require.Equal(t, "already_connectable", v["status"])
				require.EqualValues(t, f.task, v["request_id"])
				require.Equal(t, before, after)
			case "open_without_item":
				require.False(t, r.IsError, resultText(r))
				require.Equal(t, "approved", v["status"])
				require.Equal(t, before+1, after)
				var items []model.AccessRequestItem
				f.db.Where("request_id=?", v["request_id"]).Find(&items)
				require.Len(t, items, 1)
				require.Equal(t, model.AccessRequestApproved, items[0].Status)
			case "missing_accounts":
				require.Equal(t, "VALIDATION_AGENT_ACCOUNTS_REQUIRED", v["code"])
				require.Equal(t, before, after)
			case "invisible":
				require.Equal(t, "NOTFOUND_ASSET", v["code"])
				require.Equal(t, before, after)
			}
		})
	}
}
func TestToolCheckRequestWaitingInfo(t *testing.T) {
	f := newFixture(t)
	require.NoError(t, f.db.Model(&model.AccessRequest{}).Where("id=?", f.task).Update("status", model.AccessRequestPending).Error)
	require.NoError(t, f.db.Create(&model.SecurityPolicy{Key: "access_request_min_approvals", Value: "2"}).Error)
	require.NoError(t, f.db.Create(&model.AccessRequestApproval{RequestID: f.task, ItemID: &f.item, ApproverID: 1, Note: "first approval"}).Error)
	r := f.invoke(t, "check_request", map[string]any{"request_id": f.task})
	require.False(t, r.IsError, resultText(r))
	v := object(t, r)
	var task model.AccessRequest
	require.NoError(t, f.db.First(&task, f.task).Error)
	for _, k := range []string{"created_at", "status", "approvals_received", "approvals_required", "expires_at"} {
		require.Contains(t, v, k)
	}
	at, err := time.Parse(time.RFC3339Nano, v["created_at"].(string))
	require.NoError(t, err)
	require.True(t, at.Equal(task.CreatedAt))
	exp, err := time.Parse(time.RFC3339Nano, v["expires_at"].(string))
	require.NoError(t, err)
	require.True(t, exp.Equal(task.PendingExpiresAt))
	require.EqualValues(t, 1, v["approvals_received"])
	require.EqualValues(t, 2, v["approvals_required"])
	require.Equal(t, "pending", v["status"])

	// 項目快照為準：需人核的項目回快照值；自動核准（0）的單不再回全域下限
	require.NoError(t, f.db.Model(&model.AccessRequestItem{}).Where("id=?", f.item).Update("policy_snapshot", `{"required_approvals":3}`).Error)
	require.EqualValues(t, 3, object(t, f.invoke(t, "check_request", map[string]any{"request_id": f.task}))["approvals_required"])
	require.NoError(t, f.db.Model(&model.AccessRequestItem{}).Where("id=?", f.item).Update("policy_snapshot", `{"required_approvals":0,"auto_basis":"open"}`).Error)
	require.EqualValues(t, 0, object(t, f.invoke(t, "check_request", map[string]any{"request_id": f.task}))["approvals_required"])
	for _, text := range []string{"繼續等", "改做別的事", "判定不會過"} {
		require.Contains(t, descriptions["check_request"], text)
	}
}
func TestToolOpenSessionExplicitTask(t *testing.T) {
	f := newFixture(t)
	r := f.invoke(t, "open_session", map[string]any{"asset_id": f.asset})
	require.True(t, r.IsError)
	other := model.AccessRequest{RequesterID: f.agent, AssetID: f.asset, Status: model.AccessRequestPending, Reason: "second", RequestedDurationMinutes: 10, PendingExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, f.db.Create(&other).Error)
	// A second valid task must not change the selected task.
	var first model.AccessRequestItem
	require.NoError(t, f.db.First(&first, f.item).Error)
	var grant model.AssetAuthorization
	require.NoError(t, f.db.First(&grant, *first.AuthorizationID).Error)
	grant.ID = 0
	require.NoError(t, f.db.Create(&grant).Error)
	second := first
	second.ID = 0
	second.RequestID = other.ID
	second.AuthorizationID = &grant.ID
	second.Status = model.AccessRequestPending
	require.NoError(t, f.db.Create(&second).Error)
	require.NoError(t, f.db.Model(&second).Update("status", model.AccessRequestApproved).Error)
	r = f.invoke(t, "open_session", map[string]any{"asset_id": f.asset, "account_id": f.account})
	require.True(t, r.IsError)
	handle, e := f.open(t)
	require.Equal(t, f.task, *e.connection.Session.AccessRequestID)
	r = f.invoke(t, "close_session", map[string]any{"session_handle": handle})
	require.False(t, r.IsError)
}
func TestSessionHandleScoping(t *testing.T) {
	f := newFixture(t)
	handle, _ := f.open(t)
	owner := f.owner(t)
	raw := json.RawMessage(fmt.Sprintf(`{"session_handle":%q}`, handle))
	for _, o := range []sessionOwner{{MCP: "other", User: owner.User, Token: owner.Token}, {MCP: owner.MCP, User: owner.User, Token: owner.Token + 1}, {MCP: owner.MCP, User: owner.User + 1, Token: owner.Token}} {
		_, _, code := f.h.attribution(o, "read_screen", raw)
		require.Equal(t, "NOTFOUND_SESSION", code)
	}
}
func TestToolCloseTask(t *testing.T) {
	f := newFixture(t)
	handle, e := f.open(t)
	r := f.invoke(t, "close_task", map[string]any{"request_id": f.task, "report": "first"})
	require.False(t, r.IsError, resultText(r))
	require.EqualValues(t, 1, object(t, r)["version"])
	select {
	case <-e.connection.Done:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream not closed")
	}
	r = f.invoke(t, "run_command", map[string]any{"session_handle": handle, "command": "echo never"})
	require.Equal(t, "terminated", object(t, r)["status"])
	var task model.AccessRequest
	require.NoError(t, f.db.First(&task, f.task).Error)
	require.NotNil(t, task.ClosedAt)
	closed := *task.ClosedAt
	r = f.invoke(t, "close_task", map[string]any{"request_id": f.task, "report": "revision"})
	require.False(t, r.IsError, resultText(r))
	require.EqualValues(t, 2, object(t, r)["version"])
	f.db.First(&task, f.task)
	require.True(t, closed.Equal(*task.ClosedAt))
	require.NoError(t, f.db.Model(&model.AccessRequest{}).Where("id=?", f.task).Update("closed_at", time.Now().Add(-25*time.Hour)).Error)
	r = f.invoke(t, "close_task", map[string]any{"request_id": f.task, "report": "too late"})
	require.Equal(t, "CONFLICT_ACCESS_REQUEST_STATE", object(t, r)["code"])
	var reports []model.AgentTaskReport
	require.NoError(t, f.db.Order("version").Find(&reports).Error)
	require.Len(t, reports, 2)
	require.Equal(t, "first", reports[0].Body)
	other := model.AccessRequest{RequesterID: 1, AssetID: f.asset, Status: model.AccessRequestPending, Reason: "other", RequestedDurationMinutes: 10, PendingExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, f.db.Create(&other).Error)
	r = f.invoke(t, "close_task", map[string]any{"request_id": other.ID, "report": "no"})
	require.Equal(t, "NOTFOUND_ACCESS_REQUEST", object(t, r)["code"])
	f.db.First(&other, other.ID)
	require.Nil(t, other.ClosedAt)
}
func TestTaskClosedByItemExpiry(t *testing.T) {
	f := newFixture(t)
	handle, e := f.open(t)
	require.NoError(t, f.db.Model(&model.AccessRequestItem{}).Where("id=?", f.item).Update("approved_date_start", time.Now().Add(-2*time.Hour)).Error)
	select {
	case <-e.connection.Done:
	case <-time.After(3 * time.Second):
		t.Fatal("expiry orphan")
	}
	var task model.AccessRequest
	require.NoError(t, f.db.First(&task, f.task).Error)
	require.NotNil(t, task.ClosedAt)
	r := f.invoke(t, "check_request", map[string]any{"request_id": f.task})
	require.Equal(t, true, object(t, r)["missing_report_at_close"])
	r = f.invoke(t, "read_screen", map[string]any{"session_handle": handle})
	require.Equal(t, "terminated", object(t, r)["status"])
}
func addMaskRule(t *testing.T, f *fixture) {
	t.Helper()
	require.NoError(t, f.db.Create(&model.AlertRule{Name: "card", Pattern: sensitivescan.CardPattern, Direction: model.DirectionOutput, Action: "alert", Enabled: true}).Error)
	require.NoError(t, audit.GetAlertMatcher().LoadRules())
}
