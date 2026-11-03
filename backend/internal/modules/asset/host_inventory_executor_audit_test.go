package asset

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/custodexa/backend/internal/model"
)

const invExecSecretMarker = "CXEXECSECRET-9b1e"

func TestInventoryExecutorAuditAndAlert(t *testing.T) {
	run := func(t *testing.T, withExecutor bool, escalation string) (*execInvEnv, *invAlertSink, model.HostAccountScan) {
		t.Helper()
		e := newExecInvEnv(t, false)
		sink := &invAlertSink{}
		e.svc.alerts = sink
		if withExecutor {
			e.srv.addAccount(delegExecutorUser, invExecSecretMarker, fakeSudoNopasswd)
			e.setExecutor(t, delegExecutorUser, invExecSecretMarker, "")
		}
		e.svc.collect = func(context.Context, uint, string, *AssetCredentials, ssh.HostKeyCallback, string) (*invScanResult, *inventoryError) {
			return &invScanResult{
				Status:     model.HostAccountScanSucceeded,
				Escalation: escalation,
				Coverage:   []invCoverageItem{{Check: invCheckAccounts, State: invStateChecked, Count: 2}},
				Findings: []invFindingResult{
					{Username: "rogue", UID: "1001", LoginCapable: true, Privileged: true, Reasons: []string{"sudo_direct"}},
				},
			}, nil
		}
		_, err := e.svc.Initiate(e.assetID, invAdmin)
		require.NoError(t, err)
		e.svc.Wait()
		var s model.HostAccountScan
		require.NoError(t, e.db.Where("asset_id = ?", e.assetID).Order("id DESC").First(&s).Error)
		return e, sink, s
	}
	audits := func(t *testing.T, e *execInvEnv, action model.AuditAction) map[string]any {
		t.Helper()
		var l model.AuditLog
		require.NoError(t, e.db.Where("action = ? AND asset_id = ?", action, e.assetID).Order("id DESC").First(&l).Error)
		out := map[string]any{}
		require.NoError(t, json.Unmarshal([]byte(l.Details), &out))
		return out
	}

	t.Run("專用帳號盤點的兩筆審計與告警", func(t *testing.T) {
		e, sink, scan := run(t, true, invEscalationUsed)
		assert.Equal(t, model.HostAccountIdentityExecutor, scan.IdentityMode)
		start := audits(t, e, model.ActionInventoryScan)
		assert.Equal(t, model.HostAccountIdentityExecutor, start["identity_mode"])
		assert.Equal(t, delegExecutorUser, start["identity_username"])
		done := audits(t, e, model.ActionInventoryScanDone)
		assert.Equal(t, "used", done["escalation"])
		require.Equal(t, 1, sink.count())
		assert.Equal(t, "executor", sink.events[0].Params["identity_mode"])

		var all []model.AuditLog
		require.NoError(t, e.db.Where("asset_id = ?", e.assetID).Find(&all).Error)
		for _, l := range all {
			assert.NotContains(t, l.Details, invExecSecretMarker)
		}
		for k, v := range sink.events[0].Params {
			assert.False(t, strings.Contains(k+v, invExecSecretMarker))
		}
	})
	t.Run("預設帳號盤點不帶 escalation", func(t *testing.T) {
		e, _, _ := run(t, false, "")
		done := audits(t, e, model.ActionInventoryScanDone)
		_, has := done["escalation"]
		assert.False(t, has)
		start := audits(t, e, model.ActionInventoryScan)
		assert.Equal(t, "", start["identity_username"])
	})
	t.Run("三種提權結果都入結束審計", func(t *testing.T) {
		for _, want := range []string{invEscalationNotNeeded, invEscalationDenied} {
			e, _, _ := run(t, true, want)
			assert.Equal(t, want, audits(t, e, model.ActionInventoryScanDone)["escalation"])
		}
	})
}
