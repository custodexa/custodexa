package api

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/pkg/crypto"
)

// 放棄一輪已動過主機的輪替後，憑證的進行中識別即清空；詳情與輪替回應仍要指得出那一輪，
// 否則逐台補跑在畫面上沒有入口。
func TestCredentialDetailCarriesUnsettledRotationAfterAbandon(t *testing.T) {
	f := setupCredentialAPIEnv(t)
	r, mgr := credentialTestRouter(t, f)
	adminToken, err := mgr.GenerateToken(1, "admin", "a@example.com", model.RoleAdmin, crypto.AuthContext{})
	require.NoError(t, err)

	rot, err := f.rotations.Start(credAdminCtx(), f.sharedID, asset.StartRotationRequest{})
	require.NoError(t, err)
	// 模擬已送出未驗證（遠端可能已換）：放棄後憑證進入不同步而不是回到閒置
	require.NoError(t, f.db.Model(&model.CredentialRotationMember{}).Where("rotation_id = ?", rot.ID).
		Update("state", model.CredentialMemberChangedUnverified).Error)

	before := credentialDetailBody(t, r, adminToken, f.sharedID)
	_, present := before["unsettled_rotation_id"]
	assert.False(t, present, "進行中時以 active_rotation_id 為準，不出現未收束那一欄")

	require.NoError(t, f.rotations.Abandon(credAdminCtx(), rot.ID))

	detail := credentialDetailBody(t, r, adminToken, f.sharedID)
	assert.EqualValues(t, 0, detail["active_rotation_id"], "前置條件：放棄後進行中識別已清空")
	assert.EqualValues(t, rot.ID, detail["unsettled_rotation_id"], "詳情指得出放棄後仍未收束的那一輪")

	var body struct {
		Data map[string]any `json:"data"`
	}
	raw := credentialGet(t, r, "/api/v1/credentials/"+uintToStr(f.sharedID)+"/rotations/"+uintToStr(rot.ID), adminToken)
	require.NoError(t, json.Unmarshal([]byte(raw), &body))
	assert.Equal(t, "abandoned", body.Data["status"])
	assert.Equal(t, true, body.Data["unsettled"], "輪替回應標明它仍是要逐台補跑的那一輪")

	// 成員帶出候選是否仍在（拆分模式已收束的成員據此給補跑）：只有候選還在的那一台帶 true
	members, err := f.rotations.Members(rot.ID)
	require.NoError(t, err)
	require.NotEmpty(t, members)
	require.NoError(t, f.db.Create(&model.ChangeSecretCandidate{
		AssetID: members[0].AssetID, AccountID: members[0].AccountID, AccountUsername: members[0].Username,
		SecretType: model.ChangeSecretTypePassword,
	}).Error)
	var withMembers struct {
		Data struct {
			Members []map[string]any `json:"members"`
		} `json:"data"`
	}
	raw = credentialGet(t, r, "/api/v1/credentials/"+uintToStr(f.sharedID)+"/rotations/"+uintToStr(rot.ID), adminToken)
	require.NoError(t, json.Unmarshal([]byte(raw), &withMembers))
	kept := map[float64]bool{}
	for _, m := range withMembers.Data.Members {
		if v, ok := m["candidate_kept"]; ok {
			kept[m["id"].(float64)] = v.(bool)
		}
	}
	assert.Equal(t, map[float64]bool{float64(members[0].ID): true}, kept)
}

// 本輪一台都沒動過就放棄：這一輪等於沒發生過，不得留下未收束的入口。
func TestCredentialDetailOmitsUnsettledRotationAfterFreshAbandon(t *testing.T) {
	f := setupCredentialAPIEnv(t)
	r, mgr := credentialTestRouter(t, f)
	adminToken, err := mgr.GenerateToken(1, "admin", "a@example.com", model.RoleAdmin, crypto.AuthContext{})
	require.NoError(t, err)

	rot, err := f.rotations.Start(credAdminCtx(), f.sharedID, asset.StartRotationRequest{})
	require.NoError(t, err)
	require.NoError(t, f.rotations.Abandon(credAdminCtx(), rot.ID))

	detail := credentialDetailBody(t, r, adminToken, f.sharedID)
	_, present := detail["unsettled_rotation_id"]
	assert.False(t, present)

	var body struct {
		Data map[string]any `json:"data"`
	}
	raw := credentialGet(t, r, "/api/v1/credentials/"+uintToStr(f.sharedID)+"/rotations/"+uintToStr(rot.ID), adminToken)
	require.NoError(t, json.Unmarshal([]byte(raw), &body))
	_, flagged := body.Data["unsettled"]
	assert.False(t, flagged)
}
