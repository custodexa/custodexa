package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

const toolArgsPlain = `{"command":"echo 4111111111111111","session_handle":"fp:ba7816bf8f01"}`

type toolArgsCodec struct {
	crypto.ColumnCodec
	db       *gorm.DB
	decrypts int
	fail     bool
}

func (c *toolArgsCodec) DecryptFor(ctx context.Context, ref crypto.CipherRef, sealed string) (string, error) {
	c.decrypts++
	var n int64
	if err := c.db.Model(&model.AuditLog{}).Where("action = ?", model.ActionAgentToolCallArgsViewed).Count(&n).Error; err != nil {
		return "", err
	}
	if n == 0 {
		return "", errors.New("decrypt before committed audit")
	}
	if c.fail {
		return "", errors.New("private decryption failure")
	}
	return c.ColumnCodec.DecryptFor(ctx, ref, sealed)
}

type toolArgsEnv struct {
	*agentReadEnv
	codec    *toolArgsCodec
	failures *revealTestFailures
	handler  *AuditIntegrityHandler
}

func newToolArgsEnv(t *testing.T, enabled bool) *toolArgsEnv {
	t.Helper()
	e := newAgentReadEnv(t)
	require.NoError(t, e.db.AutoMigrate(&model.DataKey{}, &model.CommandAlert{}))
	kek, err := crypto.NewEnvKEKProvider(make([]byte, 32))
	require.NoError(t, err)
	km, err := keyvault.InitKeyManager(e.db, kek)
	require.NoError(t, err)
	t.Cleanup(km.ZeroizeForRelease)
	sealed, err := km.EncryptFor(context.Background(), keyvault.RefAgentToolCallArgs, toolArgsPlain)
	require.NoError(t, err)
	sid, task, asset := uint(73), uint(91), uint(42)
	require.NoError(t, e.db.Create(&model.Session{ID: sid, SessionID: "ledger-reveal", UserID: e.agent.ID, Protocol: model.ProtocolSSH, Status: model.SessionStatusClosed, AssetID: &asset, AccessRequestID: &task}).Error)
	for id := uint(1); id <= 2; id++ {
		row := model.AgentToolCall{ID: id, Seq: id, UserID: e.agent.ID, AgentTokenID: 1, OwnerUserID: e.owner.ID, Tool: "run_command", AccessRequestID: &task, SessionID: &sid, ArgsRedacted: `{"command":"echo [REDACTED]"}`, ArgsRetained: true, Decision: model.ToolCallAllowed, CreatedAt: time.Now()}
		if id == 1 {
			row.ArgsSealed = []byte(sealed)
		}
		require.NoError(t, e.db.Session(&gorm.Session{SkipHooks: true}).Create(&row).Error)
	}
	if enabled {
		_, err = e.policies.Update(policy.PolicyAlertOnSensitiveReveal, "true", "admin")
		require.NoError(t, err)
	}
	codec := &toolArgsCodec{ColumnCodec: km, db: e.db}
	failures := &revealTestFailures{}
	h := NewAuditIntegrityHandler(e.db, nil)
	h.SetToolCallArguments(audit.NewToolCallArgumentsService(e.db, codec, audit.NewTxSink(), failures), audit.NewSensitiveRevealService(e.policies, audit.NewAlertRecorder(e.db), failures))
	auth := identity.NewAuthService("agent-read-test-key", time.Hour)
	auth.SetEpochGateDB(e.db)
	e.router = gin.New()
	e.router.Use(middleware.AgentRouteAllowlist(auth))
	h.RegisterRoutes(e.router.Group("/api/v1"), auth)
	return &toolArgsEnv{e, codec, failures, h}
}
func (e *toolArgsEnv) countAudit(t *testing.T) int64 {
	var n int64
	require.NoError(t, e.db.Model(&model.AuditLog{}).Where("action = ?", model.ActionAgentToolCallArgsViewed).Count(&n).Error)
	return n
}

const argsURL = "/agent-tool-calls/1/arguments?reason=investigation"

func TestAgentToolCallArgumentsPermissions(t *testing.T) {
	e := newToolArgsEnv(t, false)
	for _, tc := range []struct {
		token  string
		status int
	}{{"", 401}, {e.token, 403}, {e.jwt[model.RoleUser], 403}, {e.jwt[model.RoleAuditor], 200}, {e.jwt[model.RoleAdmin], 200}} {
		w := e.get(argsURL, tc.token)
		require.Equal(t, tc.status, w.Code, w.Body.String())
		if tc.status != 200 {
			require.NotContains(t, w.Body.String(), "4111111111111111")
		}
	}
	require.EqualValues(t, 2, e.countAudit(t))
	require.Equal(t, 2, e.codec.decrypts)
}
func TestAgentToolCallArgumentsAuditBeforeDecrypt(t *testing.T) {
	e := newToolArgsEnv(t, false)
	w := e.get(argsURL, e.jwt[model.RoleAuditor])
	require.Equal(t, 200, w.Code, w.Body.String())
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	require.JSONEq(t, toolArgsPlain, string(mustArguments(t, w.Body.Bytes())))
	require.EqualValues(t, 1, e.countAudit(t))
	require.Equal(t, 1, e.codec.decrypts)
	var row model.AuditLog
	require.NoError(t, e.db.Where("action = ?", model.ActionAgentToolCallArgsViewed).First(&row).Error)
	require.Equal(t, model.ResourceAgentToolCall, row.Resource)
	require.EqualValues(t, 1, *row.ResourceID)
	require.Equal(t, e.owner.ID, row.UserID)
	var details map[string]any
	require.NoError(t, json.Unmarshal([]byte(row.Details), &details))
	require.Equal(t, map[string]any{"tool_call_id": float64(1), "session_id": float64(73), "access_request_id": float64(91), "reason": "investigation"}, details)
	require.NotContains(t, row.Details, "4111111111111111")
}
func mustArguments(t *testing.T, raw []byte) json.RawMessage {
	var body struct {
		Data struct {
			Arguments json.RawMessage `json:"arguments"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(raw, &body))
	return body.Data.Arguments
}
func TestAgentToolCallArgumentsFailClose(t *testing.T) {
	e := newToolArgsEnv(t, true)
	require.NoError(t, e.db.Migrator().DropTable(&model.AuditLog{}))
	w := e.get(argsURL, e.jwt[model.RoleAuditor])
	require.Equal(t, 500, w.Code, w.Body.String())
	require.NotContains(t, w.Body.String(), "4111111111111111")
	require.Equal(t, 0, e.codec.decrypts)
	require.EqualValues(t, 0, revealRowCount(t, e.db, "command_alerts"))
	require.Contains(t, e.failures.causes, model.CauseAuditWriteSyncRefused)
}
func TestAgentToolCallArgumentsUniformNotFound(t *testing.T) {
	e := newToolArgsEnv(t, true)
	var body string
	for _, id := range []string{"2", "999", "0", "invalid"} {
		w := e.get("/agent-tool-calls/"+id+"/arguments?reason=investigation", e.jwt[model.RoleAuditor])
		require.Equal(t, 404, w.Code)
		require.Contains(t, w.Body.String(), "NOTFOUND_TOOL_CALL_ARGUMENTS")
		if body != "" {
			require.Equal(t, body, w.Body.String())
		}
		body = w.Body.String()
	}
	require.Zero(t, e.codec.decrypts)
	require.Zero(t, e.countAudit(t))
}
func TestAgentToolCallArgumentsReason(t *testing.T) {
	e := newToolArgsEnv(t, false)
	for _, reason := range []string{"", " \t\n", strings.Repeat("a", 1001), strings.Repeat("字", 334), strings.Repeat(" ", 1000) + "x"} {
		w := e.get("/agent-tool-calls/1/arguments?reason="+url.QueryEscape(reason), e.jwt[model.RoleAuditor])
		require.Equal(t, 400, w.Code)
		require.Contains(t, w.Body.String(), "VALIDATION_BAD_PARAMS")
	}
	require.Zero(t, e.codec.decrypts)
	require.Zero(t, e.countAudit(t))
	w := e.get("/agent-tool-calls/1/arguments?reason="+strings.Repeat("a", 1000), e.jwt[model.RoleAuditor])
	require.Equal(t, 200, w.Code, w.Body.String())
}
func TestAgentToolCallArgumentsDecryptFailure(t *testing.T) {
	e := newToolArgsEnv(t, true)
	e.codec.fail = true
	w := e.get(argsURL, e.jwt[model.RoleAuditor])
	require.Equal(t, 500, w.Code)
	require.NotContains(t, w.Body.String(), "private decryption failure")
	require.EqualValues(t, 1, e.countAudit(t))
	require.EqualValues(t, 0, revealRowCount(t, e.db, "command_alerts"))
}
func TestSensitiveRevealAgentToolCallEnabled(t *testing.T) {
	e := newToolArgsEnv(t, true)
	w := e.get(argsURL, e.jwt[model.RoleAuditor])
	require.Equal(t, 200, w.Code, w.Body.String())
	require.EqualValues(t, 1, revealRowCount(t, e.db, "command_alerts"))
	var row model.CommandAlert
	require.NoError(t, e.db.Select("id,kind,rule_id,rule_name,reason_code,severity,command,session_id,user_id,asset_id,disposition,note").First(&row).Error)
	require.Equal(t, model.AlertKindSensitiveReveal, row.Kind)
	require.Nil(t, row.RuleID)
	require.Equal(t, "medium", row.Severity)
	require.Empty(t, row.Command)
	require.EqualValues(t, 73, row.SessionID)
	require.Equal(t, e.owner.ID, row.UserID)
	require.EqualValues(t, 42, *row.AssetID)
	var meta map[string]any
	require.NoError(t, json.Unmarshal([]byte(row.Note), &meta))
	require.Equal(t, "agent_tool_call", meta["source_type"])
	require.EqualValues(t, 1, meta["source_id"])
	require.EqualValues(t, 91, meta["access_request_id"])
	require.Equal(t, "investigation", meta["reason"])
}
func TestSensitiveRevealAgentToolCallDisabled(t *testing.T) {
	e := newToolArgsEnv(t, false)
	w := e.get(argsURL, e.jwt[model.RoleAuditor])
	require.Equal(t, 200, w.Code, w.Body.String())
	require.EqualValues(t, 0, revealRowCount(t, e.db, "command_alerts"))
	require.EqualValues(t, 1, e.countAudit(t))
}
func TestSensitiveRevealAgentToolCallNoPlaintext(t *testing.T) {
	e := newToolArgsEnv(t, true)
	w := e.get(argsURL, e.jwt[model.RoleAuditor])
	require.Equal(t, 200, w.Code, w.Body.String())
	var rows []map[string]any
	require.NoError(t, e.db.Table("command_alerts").Find(&rows).Error)
	require.Len(t, rows, 1)
	raw, err := json.Marshal(rows)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "4111111111111111")
	require.NotContains(t, string(raw), "fp:ba7816bf8f01")
}
func TestSensitiveRevealAgentToolCallFailureStillDelivers(t *testing.T) {
	e := newToolArgsEnv(t, true)
	require.NoError(t, e.db.Migrator().DropTable(&model.CommandAlert{}))
	w := e.get(argsURL, e.jwt[model.RoleAuditor])
	require.Equal(t, 200, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "4111111111111111")
	require.EqualValues(t, 1, e.countAudit(t))
	require.Contains(t, e.failures.causes, model.CauseSensitiveRevealAlertWriteFailed)
}

func TestAgentToolCallArgumentsMissingDependencies(t *testing.T) {
	for _, name := range []string{"reader", "audit sink", "codec"} {
		t.Run(name, func(t *testing.T) {
			e := newToolArgsEnv(t, true)
			switch name {
			case "reader":
				e.handler.SetToolCallArguments(nil, nil)
			case "audit sink":
				e.handler.SetToolCallArguments(audit.NewToolCallArgumentsService(e.db, e.codec, nil, e.failures), nil)
			case "codec":
				e.handler.SetToolCallArguments(audit.NewToolCallArgumentsService(e.db, nil, audit.NewTxSink(), e.failures), nil)
			}
			w := e.get(argsURL, e.jwt[model.RoleAuditor])
			require.Equal(t, 500, w.Code)
			require.NotContains(t, w.Body.String(), "4111111111111111")
			require.Zero(t, e.codec.decrypts)
			require.Zero(t, revealRowCount(t, e.db, "command_alerts"))
			if name != "codec" {
				require.Zero(t, e.countAudit(t))
			}
		})
	}
}
