package sshproxy

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
)

// TestCreateAssetWithoutCredentialSourceHasNoMount 擋「放寬 username 必填後建出 username 空白的
// 掛載列，連線時以空帳號嘗試匿名或免密登入」：五種以帳號名登入的協定各建一台不帶任何憑證來源的
// 資產，斷言零掛載，且連線一律被零帳號閘以 RULE_ACCOUNT_NONE_USABLE 拒絕。
//
// SSH／MySQL／Postgres／MSSQL 走本包真實的簽發＋兌換閘（G-S11）；RDP 走圖形入口（proxy 包的
// G-G11），該閘的判定式是「解析出的帳號 AccountID == 0」，本測試斷言同一個判定輸入，閘本身由
// proxy/zero_account_gate_test.go 釘住。帶密碼卻無帳號名的 SSH 仍以 ErrUsernameRequired 拒絕
func TestCreateAssetWithoutCredentialSourceHasNoMount(t *testing.T) {
	h, db, _ := setupPolicyGateTest(t)
	seedGateFixture(t, db)
	svc, err := asset.NewAssetService(aesColumnCodec(t, make([]byte, 32)), "localhost", 4822, audit.NewTxSink())
	require.NoError(t, err)
	ctx := context.WithValue(context.Background(), "userID", uint(2)) //nolint:staticcheck // 沿用既有審計 context 慣例
	ctx = context.WithValue(ctx, "username", "u-admin")               //nolint:staticcheck // 同上

	for _, tc := range []struct {
		protocol model.ProtocolType
		port     int
	}{
		{model.ProtocolSSH, 22}, {model.ProtocolRDP, 3389}, {model.ProtocolMySQL, 3306},
		{model.ProtocolPostgres, 5432}, {model.ProtocolMSSQL, 1433},
	} {
		created, err := svc.Create(ctx, &asset.CreateAssetRequest{
			Name: "pending-" + string(tc.protocol), Protocol: tc.protocol, Host: "10.0.0.1", Port: tc.port,
			CreatedBy: 2, CreatedByName: "u-admin",
		})
		require.NoError(t, err, "%s：不帶任何憑證來源應可建立", tc.protocol)
		require.True(t, created.CredentialPending, "%s：建立回應標示待配憑證", tc.protocol)

		var mounts int64
		require.NoError(t, db.Unscoped().Model(&model.AssetAccount{}).
			Where("asset_id = ?", created.ID).Count(&mounts).Error)
		require.Zero(t, mounts, "%s：不得建出任何掛載列（含 username 空白者）", tc.protocol)

		uid, aid := uint(1), created.ID
		require.NoError(t, db.Create(&model.AssetAuthorization{
			UserID: &uid, AssetID: &aid, Permission: model.PermissionConnect, GrantedBy: 2,
		}).Error)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)

		if tc.protocol == model.ProtocolRDP {
			creds, cerr := svc.GetWithCredentialsForAccount(created.ID, 0)
			require.NoError(t, cerr)
			require.Zero(t, creds.AccountID, "rdp：圖形入口零帳號閘的判定輸入須為 AccountID 0")
			require.Empty(t, creds.Username)
			continue
		}
		code, resp, _ := issueToken(h, 1, model.RoleUser, created.ID)
		require.Equal(t, http.StatusOK, code, "%s：簽發不擋零帳號（由兌換點擋）: %v", tc.protocol, resp)
		token, _ := resp["connect_token"].(string)
		require.NotEmpty(t, token)
		code, redeemResp := redeemSSH(h, token)
		require.NotEqual(t, http.StatusSwitchingProtocols, code, "%s：零帳號資產不得建線", tc.protocol)
		require.Equal(t, "RULE_ACCOUNT_NONE_USABLE", redeemResp["code"], "%s: code=%d resp=%v", tc.protocol, code, redeemResp)
	}

	_, err = svc.Create(ctx, &asset.CreateAssetRequest{
		Name: "secret-without-username", Protocol: model.ProtocolSSH, Host: "10.0.0.2", Port: 22,
		Password: "pw-only", CreatedBy: 2,
	})
	require.ErrorIs(t, err, asset.ErrUsernameRequired, "有秘密卻無帳號名是填寫錯誤，不是稍後再配")
}
