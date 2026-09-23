package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestExportAgentToolCallsArgumentsRetained(t *testing.T) {
	svc, db := setupExportEnv(t)
	at := time.Now().UTC().Truncate(time.Second)
	sid, asset := uint(1), uint(7)
	require.NoError(t, db.Create(&model.Session{ID: sid, SessionID: "export-ledger", UserID: 9, AssetID: &asset, Protocol: model.ProtocolSSH, Status: model.SessionStatusClosed}).Error)
	for id := uint(1); id <= 3; id++ {
		row := model.AgentToolCall{ID: id, Seq: id, UserID: 9, AgentTokenID: 1, OwnerUserID: 8, Tool: "list_assets", ArgsRedacted: `{"search":"retained evidence"}`, ArgsRetained: id == 1, ArgsSealed: []byte("sealed-never-export-4111111111111111"), Decision: model.ToolCallAllowed, CreatedAt: at, SessionID: &sid}
		if id == 3 {
			row.SessionID = nil
		}
		require.NoError(t, db.Session(&gorm.Session{SkipHooks: true}).Create(&row).Error)
	}
	var buf bytes.Buffer
	m, err := svc.Export(&buf, &ExportFilter{SessionID: &sid, Types: []TimelineEventType{TimelineTypeAuditLog}}, 9, "auditor")
	require.NoError(t, err)
	files := unzip(t, buf.Bytes())
	raw := files["agent_tool_calls.json"]
	var entries []map[string]any
	require.NoError(t, json.Unmarshal(raw, &entries))
	require.Len(t, entries, 2)
	require.Equal(t, true, entries[0]["args_retained"])
	require.Equal(t, false, entries[1]["args_retained"])
	require.Equal(t, map[string]any{"search": "retained evidence"}, entries[0]["args_redacted"])
	for name, data := range files {
		require.NotContains(t, string(data), "args_sealed", name)
		require.NotContains(t, string(data), "4111111111111111", name)
	}
	require.Equal(t, 2, m.Counts["agent_tool_calls"])
	require.EqualValues(t, 2, m.Totals["agent_tool_calls"])
	require.False(t, m.Truncated["agent_tool_calls"])
	found := false
	for _, f := range m.Files {
		if f.Name == "agent_tool_calls.json" {
			found = true
			require.Equal(t, fmt.Sprintf("%x", sha256.Sum256(raw)), f.SHA256)
		}
	}
	require.True(t, found)
}

func TestExportAgentToolCallsScope(t *testing.T) {
	svc, db := setupExportEnv(t)
	at := time.Now().UTC().Truncate(time.Second)
	older := at.Add(-time.Hour)
	asset, sid := uint(7), uint(1)
	require.NoError(t, db.Create(&model.Session{ID: sid, SessionID: "scope", UserID: 9, AssetID: &asset, Protocol: model.ProtocolSSH, Status: model.SessionStatusClosed}).Error)
	for id := uint(1); id <= 3; id++ {
		row := model.AgentToolCall{ID: id, Seq: id, UserID: 9, AgentTokenID: 1, OwnerUserID: 8, Tool: "list_assets", ArgsRedacted: `{}`, ArgsRetained: true, Decision: model.ToolCallAllowed, CreatedAt: at}
		if id == 1 {
			row.SessionID = &sid
		}
		if id == 3 {
			row.CreatedAt = older
		}
		require.NoError(t, db.Session(&gorm.Session{SkipHooks: true}).Create(&row).Error)
	}
	user, other := uint(9), uint(99)
	for _, tc := range []struct {
		name   string
		filter ExportFilter
		want   int
	}{
		{"user and time", ExportFilter{UserID: &user, StartTime: &at}, 2},
		{"asset", ExportFilter{AssetID: &asset}, 1},
		{"other user", ExportFilter{UserID: &other}, 0},
		{"session overrides time", ExportFilter{SessionID: &sid, EndTime: &older}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.filter.Types = []TimelineEventType{TimelineTypeAuditLog}
			var buf bytes.Buffer
			m, err := svc.Export(&buf, &tc.filter, 9, "auditor")
			require.NoError(t, err)
			require.Equal(t, tc.want, m.Counts["agent_tool_calls"])
			require.EqualValues(t, tc.want, m.Totals["agent_tool_calls"])
		})
	}
	var buf bytes.Buffer
	m, err := svc.Export(&buf, &ExportFilter{SessionID: &sid, Types: []TimelineEventType{TimelineTypeCommand}}, 9, "auditor")
	require.NoError(t, err)
	require.NotContains(t, unzip(t, buf.Bytes()), "agent_tool_calls.json")
	require.NotContains(t, m.Counts, "agent_tool_calls")
}
