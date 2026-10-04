package sshproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestTextSessionTransferSnapshot(t *testing.T) {
	for _, tc := range []struct {
		protocol model.ProtocolType
		console  bool
	}{{model.ProtocolSSH, false}, {model.ProtocolMySQL, false}, {model.ProtocolPostgres, false},
		{model.ProtocolRedis, false}, {model.ProtocolMSSQL, false}, {model.ProtocolMySQL, true},
		{model.ProtocolPostgres, true}, {model.ProtocolMSSQL, true}} {
		t.Run(fmt.Sprintf("%s/console=%v", tc.protocol, tc.console), func(t *testing.T) {
			e := setupConsoleEnv(t, string(tc.protocol))
			policies := policy.NewSecurityPolicyService(e.db)
			e.h.DataTransfer = policy.NewDataTransferService(policies)
			keys := []string{policy.PolicyClipboardSendEnabled, policy.PolicyClipboardRecvEnabled,
				policy.PolicyFileUploadEnabled, policy.PolicyFileDownloadEnabled, policy.PolicyFileDeleteEnabled}
			set := func(values []bool) {
				for i, key := range keys {
					_, err := policies.Update(key, fmt.Sprint(values[i]), "fixture")
					require.NoError(t, err)
				}
			}
			create := func() *model.Session {
				return e.h.createSession(1, 1, tc.protocol, "192.0.2.17", nil, accountSnapshot{}, authProvenance{}, tc.console)
			}
			rows := func() []model.AuditLog {
				var result []model.AuditLog
				require.NoError(t, e.db.Where("action=? AND resource=? AND status=?", model.ActionCreate, model.ResourceSession, model.StatusSuccess).Order("id").Find(&result).Error)
				return result
			}
			verify := func(sess *model.Session, want map[string]any, resolved bool) string {
				t.Helper()
				require.NotNil(t, sess, "session creation must succeed before testing its snapshot")
				var result []model.AuditLog
				require.NoError(t, e.db.Where("action=? AND resource=? AND resource_id=?", model.ActionCreate, model.ResourceSession, sess.ID).Find(&result).Error)
				require.Len(t, result, 1, "successful text session must have exactly one transfer snapshot")
				row := result[0]
				require.Equal(t, model.StatusSuccess, row.Status)
				require.Equal(t, sess.UserID, row.UserID)
				require.Equal(t, sess.AssetID, row.AssetID)
				require.Equal(t, sess.ClientIP, row.ClientIP)
				var detail map[string]any
				require.NoError(t, json.Unmarshal([]byte(row.Details), &detail))
				require.Equal(t, map[string]any{"session_id": float64(sess.ID), "asset_id": float64(1),
					"protocol": string(tc.protocol), "db_console": tc.console, "transfer_capabilities": want,
					"clipboard_enforced": false, "transfer_capabilities_resolved": resolved}, detail)
				return row.Details
			}
			set([]bool{false, true, true, false, true})
			first := create()
			original := verify(first, map[string]any{"clipboard_send": false, "clipboard_recv": true, "file_upload": true, "file_download": false, "file_delete": true}, true)
			set([]bool{true, false, false, true, false})
			second := create()
			verify(second, map[string]any{"clipboard_send": true, "clipboard_recv": false, "file_upload": false, "file_download": true, "file_delete": false}, true)
			require.Len(t, rows(), 2)
			require.Equal(t, original, rows()[0].Details, "policy updates cannot rewrite history")
			// No injected resolver is an unresolved snapshot, never known all-allowed policy.
			e.h.DataTransfer = nil
			verify(create(), map[string]any{"clipboard_send": false, "clipboard_recv": false, "file_upload": false, "file_download": false, "file_delete": false}, false)
			before := len(rows())
			require.NotNil(t, e.h.createSession(1, 1, model.ProtocolK8s, "192.0.2.17", nil, accountSnapshot{}, authProvenance{}, false))
			require.Len(t, rows(), before, "K8s is outside this snapshot scope")
			require.NoError(t, e.db.Callback().Create().Before("gorm:create").Register("reject_snapshot_session", func(tx *gorm.DB) {
				if tx.Statement.Table == "sessions" {
					tx.AddError(errors.New("session insert unavailable"))
				}
			}))
			require.Nil(t, create())
			require.Len(t, rows(), before, "failed session insert cannot write success snapshot")
			require.NoError(t, e.db.Callback().Create().Remove("reject_snapshot_session"))
			e.h.AuditService = nil
			require.NotNil(t, create(), "missing audit service retains the existing connection outcome")
			require.Len(t, rows(), before)
		})
	}
}
