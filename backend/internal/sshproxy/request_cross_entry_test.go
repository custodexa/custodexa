package sshproxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/testgate"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
)

func TestConsoleTokenCannotRedeemAgainViaSSH(t *testing.T) {
	target := consoleTargetOf(t, testgate.EnvDBConsolePostgres)
	env := setupConsoleEnv(t, "postgres")
	require.NoError(t, env.db.Model(&model.Asset{}).Where("id=1").Updates(map[string]any{
		"host": target.host, "port": target.port, "db_name": target.database,
	}).Error)
	enc, err := aesColumnCodec(t, make([]byte, 32)).EncryptFor(context.Background(), crypto.CipherRef{Table: "credential_secret_versions", Column: "password_enc"}, target.password)
	require.NoError(t, err)
	credential := model.Credential{Scope: model.CredentialScopeDedicated, Username: target.user, SecretType: model.ChangeSecretTypePassword, AuthMethod: "sql", ProtocolFamily: model.ProtocolFamilyDatabase}
	require.NoError(t, env.db.Create(&credential).Error)
	version := model.CredentialSecretVersion{CredentialID: credential.ID, VersionNo: 1, SecretType: model.ChangeSecretTypePassword, PasswordEnc: enc, CreatedReason: model.CredentialVersionReasonManual}
	require.NoError(t, env.db.Create(&version).Error)
	require.NoError(t, env.db.Create(&model.AssetAccount{AssetID: 1, Username: target.user, IsDefault: true, AuthMethod: "sql", CredentialID: credential.ID, EffectiveVersionID: &version.ID}).Error)
	matcher := audit.InitAlertMatcher(env.db, nil)
	require.NoError(t, matcher.LoadRules())
	t.Cleanup(func() { audit.InitAlertMatcher(nil, nil) })
	t.Cleanup(func() { env.h.AuditService.Shutdown(context.Background()) })
	router := gin.New()
	router.GET("/api/v1/db-console", env.h.HandleDBConsole)
	router.GET("/api/v1/ssh", env.h.HandleSSH)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	t.Cleanup(func() {
		deadline := time.Now().Add(5 * time.Second)
		for env.h.Registry.Count() > 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		time.Sleep(100 * time.Millisecond)
	})
	token := env.issueTicket(t)
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/api/v1/db-console?connect_token="+url.QueryEscape(token), nil)
	require.NoError(t, err)
	t.Cleanup(func() { ws.Close() })
	client := &consoleClient{t: t, ws: ws}
	client.awaitReady()
	t.Log("PASS same ticket redeemed successfully by the PostgreSQL console")
	response, err := http.Get(server.URL + "/api/v1/ssh?connect_token=" + url.QueryEscape(token))
	require.NoError(t, err)
	defer response.Body.Close()
	var body map[string]any
	require.NoError(t, json.NewDecoder(response.Body).Decode(&body))
	require.Equal(t, http.StatusUnauthorized, response.StatusCode)
	require.Equal(t, "AUTH_CONNECT_TOKEN_INVALID", body["code"])
	t.Log("PASS replay of the same ticket at the SSH entry rejected with HTTP 401")
}
