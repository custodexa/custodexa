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
