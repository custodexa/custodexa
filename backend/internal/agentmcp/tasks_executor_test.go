package agentmcp

import (
	"fmt"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/require"
)

// 自動化帳號的資產清單只列登入帳號：執行身分不列、也不為它嘗試簽發連線授權。
func TestToolListAssetsOmitsExecutorAccount(t *testing.T) {
	f := newFixture(t)
	var base model.AssetAccount
	require.NoError(t, f.db.First(&base, f.account).Error)
	cred := model.Credential{Scope: model.CredentialScopeDedicated, Username: "cx-exec", SecretType: model.ChangeSecretTypePassword, AuthMethod: "password", ProtocolFamily: model.ProtocolFamilySSH}
	require.NoError(t, f.db.Create(&cred).Error)
	exec := model.AssetAccount{AssetID: f.asset, Username: "cx-exec", CredentialID: cred.ID, EffectiveVersionID: base.EffectiveVersionID, Privileged: true, Purpose: model.AccountPurposeExecutor}
	require.NoError(t, f.db.Create(&exec).Error)
	// 授權範圍明列 cx-exec：排除只能來自用途，不是授權範圍
	require.NoError(t, f.db.Model(&model.AssetAuthorization{}).Where("user_id = ?", f.agent).
		Update("accounts", model.AccountScope{"testuser", "cx-exec"}).Error)
	r := f.invoke(t, "list_assets", map[string]any{})
	require.False(t, r.IsError, resultText(r))
	assets := object(t, r)["assets"].([]any)
	require.Len(t, assets, 1)
	accounts := assets[0].(map[string]any)["accounts"].([]any)
	require.Len(t, accounts, 1, fmt.Sprint(accounts))
	require.NotContains(t, fmt.Sprint(accounts), "cx-exec")
}
