package api

import (
	"fmt"
	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestTaskDetailAndSessionQuery(t *testing.T) {
	e := newAgentReadEnv(t)
	request := e.request(t, 1)
	path := fmt.Sprintf("/agent-tasks/%d", request.ID)
	for _, url := range []string{path, fmt.Sprintf("/sessions?access_request_id=%d", request.ID)} {
		require.Equal(t, 401, e.get(url, "").Code)
		for _, token := range []string{e.token, e.jwt["other"], e.jwt[model.RoleUser]} {
			require.Equal(t, 403, e.get(url, token).Code)
		}
	}
	empty := agentReadJSON(t, e.get(path, e.jwt[model.RoleAuditor]))
	require.Empty(t, empty["session_ids"])
	require.Empty(t, empty["reports"].(map[string]any)["versions"])
	require.Equal(t, 404, e.get("/agent-tasks/999", e.jwt[model.RoleAuditor]).Code)
	require.Equal(t, 400, e.get("/agent-tasks/bad", e.jwt[model.RoleAuditor]).Code)
	require.Equal(t, 400, e.get("/sessions?access_request_id=bad", e.jwt[model.RoleAuditor]).Code)
	other := e.request(t, 2)
	for i := 0; i < 103; i++ {
		row := model.Session{SessionID: fmt.Sprint(i), UserID: e.agent.ID, AccessRequestID: &request.ID, StartTime: time.Now(), Status: model.SessionStatusClosed, Protocol: model.ProtocolSSH}
		require.NoError(t, e.db.Create(&row).Error)
	}
	require.NoError(t, e.db.Create(&model.Session{SessionID: "other-task", UserID: e.agent.ID, AccessRequestID: &other.ID, StartTime: time.Now(), Status: model.SessionStatusClosed, Protocol: model.ProtocolSSH}).Error)
	closed := time.Now().Add(-time.Hour)
	require.NoError(t, e.db.Model(request).Update("closed_at", closed).Error)
	require.NoError(t, e.db.Create(&model.AgentTaskReport{AccessRequestID: request.ID, UserID: e.agent.ID, Version: 1, Body: "late report", SubmittedAt: time.Now()}).Error)
	require.NoError(t, e.db.Create(&model.AccessRequestApproval{RequestID: request.ID, ApproverID: e.owner.ID, Note: "original approval note"}).Error)
	w := e.get(path+"?limit=9999", e.jwt[model.RoleAuditor])
	require.Equal(t, 200, w.Code, w.Body.String())
	out := agentReadJSON(t, w)
	require.Len(t, out["session_ids"], 100)
	require.EqualValues(t, 103, out["session_total"])
	require.Contains(t, w.Body.String(), "original approval note")
	reports := out["reports"].(map[string]any)
	require.Equal(t, true, reports["missing_report_at_close"])
	require.Len(t, reports["versions"], 1)
	rows := agentReadJSON(t, e.get(fmt.Sprintf("/sessions?access_request_id=%d&page=1&page_size=1", request.ID), e.jwt[model.RoleAuditor]))
	require.EqualValues(t, 103, rows["total"])
	require.Len(t, rows["data"], 1)
	bounded := agentReadJSON(t, e.get(fmt.Sprintf("/sessions?access_request_id=%d&page_size=99999", request.ID), e.jwt[model.RoleAuditor]))
	require.Len(t, bounded["data"], 100)
	require.EqualValues(t, 103, bounded["total"])
	require.EqualValues(t, 1, out["approval_total"])
	require.NoError(t, e.db.Create(&model.AccessRequestApproval{RequestID: request.ID, ApproverID: e.other.ID, Note: "second approval"}).Error)
	approvalPage := agentReadJSON(t, e.get(path+"?limit=1&approval_offset=1", e.jwt[model.RoleAuditor]))
	require.EqualValues(t, 2, approvalPage["approval_total"])
	require.Len(t, approvalPage["request"].(map[string]any)["approvals"], 1)
	require.Equal(t, "second approval", approvalPage["request"].(map[string]any)["approvals"].([]any)[0].(map[string]any)["note"])
	// 核准票要指得出「誰核准的」，不能只留 approver_id 的裸 id
	require.Equal(t, e.other.Username, approvalPage["request"].(map[string]any)["approvals"].([]any)[0].(map[string]any)["approver_username"])
	require.Equal(t, e.owner.Username, out["request"].(map[string]any)["approvals"].([]any)[0].(map[string]any)["approver_username"])
	require.EqualValues(t, request.ID, rows["data"].([]any)[0].(map[string]any)["access_request_id"])
	require.Empty(t, agentReadJSON(t, e.get("/sessions?access_request_id=999", e.jwt[model.RoleAuditor]))["data"])
	var logs []model.AuditLog
	require.NoError(t, e.db.Where("resource IN ?", []model.AuditResource{model.ResourceAccessRequest, model.ResourceSession}).Find(&logs).Error)
	for _, resource := range []model.AuditResource{model.ResourceAccessRequest, model.ResourceSession} {
		found := false
		for _, row := range logs {
			if row.Resource == resource && row.Details != "" {
				require.Contains(t, row.Details, "access_request_id")
				found = true
			}
		}
		require.True(t, found, "read audit for %s", resource)
	}
}

// 詳情頁的每個項目都要能指出「誰核准的」與「當初申請的帳號範圍」，
// 不能只留 decided_by 的裸 id，也不能因為核准縮限就讓申請範圍消失。
func TestTaskDetailItemProjections(t *testing.T) {
	e := newAgentReadEnv(t)
	request := e.request(t, 1)
	decided := model.AccessRequestItem{RequestID: request.ID, RequesterID: e.owner.ID, AssetID: 1, Accounts: model.AccountScope{"app"}, Status: model.AccessRequestPending}
	require.NoError(t, e.db.Create(&decided).Error)
	at := time.Now()
	require.NoError(t, e.db.Model(&decided).Updates(map[string]any{"status": model.AccessRequestApproved, "decided_by": e.other.ID, "decided_at": at,
		"policy_snapshot": `{"segment":"approval","required_approvals":1,"requested_accounts":["app","root"]}`}).Error)
	legacy := model.AccessRequestItem{RequestID: request.ID, RequesterID: e.owner.ID, AssetID: 2, Status: model.AccessRequestPending}
	require.NoError(t, e.db.Create(&legacy).Error)
	w := e.get(fmt.Sprintf("/agent-tasks/%d", request.ID), e.jwt[model.RoleAuditor])
	require.Equal(t, 200, w.Code, w.Body.String())
	items := agentReadJSON(t, w)["request"].(map[string]any)["items"].([]any)
	require.Len(t, items, 2)
	first := items[0].(map[string]any)
	require.Equal(t, e.other.Username, first["decided_by_username"])
	require.Equal(t, []any{"app", "root"}, first["requested_accounts"])
	require.Equal(t, []any{"app"}, first["accounts"])
	second := items[1].(map[string]any)
	// 未決定的項目沒有決定者；舊快照沒有這個鍵，回 null 而不是假裝申請了空範圍
	require.Empty(t, second["decided_by_username"])
	require.Contains(t, second, "requested_accounts")
	require.Nil(t, second["requested_accounts"])
}

// agent 自己開的單沒有 executor_user_id 欄位值（執行者就是申請人），但讀取面
// 不該要求讀者自己知道「null 代表申請人」——詳情頁據此決定要不要給「看鑰匙」
// 的入口，欄位缺席等於入口消失。同時：每個項目都要帶得出資產名稱。
func TestTaskDetailProjectsExecutorAndAssetName(t *testing.T) {
	e := newAgentReadEnv(t)
	require.NoError(t, e.db.Create(&model.Asset{Name: "web-01", Protocol: model.ProtocolSSH, Host: "h", Port: 22, CreatedBy: e.owner.ID}).Error)
	require.NoError(t, e.db.Create(&model.Asset{Name: "db-01", Protocol: model.ProtocolSSH, Host: "h", Port: 22, CreatedBy: e.owner.ID}).Error)
	// 自主執行：申請人就是 agent，executor_user_id 未寫入。
	self := &model.AccessRequest{RequesterID: e.agent.ID, AssetID: 1, Reason: "self-opened", RequestedDurationMinutes: 30, Status: model.AccessRequestPending, PendingExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, e.db.Create(self).Error)
	var stored model.AccessRequest
	require.NoError(t, e.db.Unscoped().Select("executor_user_id").First(&stored, self.ID).Error)
	require.Nil(t, stored.ExecutorUserID, "前提：欄位在 DB 仍為 null")
	require.NoError(t, e.db.Create(&model.AccessRequestItem{RequestID: self.ID, RequesterID: e.agent.ID, AssetID: 1, Accounts: model.AccountScope{"app"}, Status: model.AccessRequestPending}).Error)
	require.NoError(t, e.db.Create(&model.AccessRequestItem{RequestID: self.ID, RequesterID: e.agent.ID, AssetID: 2, Accounts: model.AccountScope{"app"}, Status: model.AccessRequestPending}).Error)
	require.NoError(t, e.db.Delete(&model.Asset{}, 2).Error)

	w := e.get(fmt.Sprintf("/agent-tasks/%d", self.ID), e.jwt[model.RoleAuditor])
	require.Equal(t, 200, w.Code, w.Body.String())
	request := agentReadJSON(t, w)["request"].(map[string]any)
	require.EqualValues(t, e.agent.ID, request["executor_user_id"])
	require.EqualValues(t, e.agent.ID, request["executor"].(map[string]any)["id"])
	items := request["items"].([]any)
	require.Len(t, items, 2)
	require.Equal(t, "web-01", items[0].(map[string]any)["asset_name"])
	require.Equal(t, false, items[0].(map[string]any)["asset_deleted"])
	require.Equal(t, "db-01", items[1].(map[string]any)["asset_name"])
	require.Equal(t, true, items[1].(map[string]any)["asset_deleted"])
}
