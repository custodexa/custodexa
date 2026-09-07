package asset

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
)

// markCredentialOutOfSync 把憑證推成「上一輪未收斂」的形狀：
// 有待生效版本、卻已無進行中的那一輪。
func markCredentialOutOfSync(t *testing.T, credentialID uint) {
	t.Helper()
	var version model.CredentialSecretVersion
	require.NoError(t, database.DB.Where("credential_id = ?", credentialID).
		Order("id DESC").First(&version).Error)
	require.NoError(t, database.DB.Model(&model.Credential{}).
		Where("id = ?", credentialID).
		UpdateColumns(map[string]any{
			"pending_version_id": version.ID,
			"active_rotation_id": nil,
		}).Error)
}

// 建立資產時掛既有共用憑證，須與掛載（Bind）走同一道收斂閘。
//
// 未收斂＝上一輪改密停在半途，部分主機已換、部分還沒。此時把一台新機器掛上去，
// 它會拿到「現行版本」，而現行版本正是那組沒換成功的舊秘密——於是新機器一開始
// 就落在錯誤的一邊，且不在任何一輪的成員清單裡，補跑補不到它。
func TestCreateAssetWithSharedCredentialRequiresConverged(t *testing.T) {
	_ = setupCredentialDB(t)
	assets, _, creds := newCredentialServices(t)

	shared := newSharedCredential(t, creds, "ops-unconverged", "ops", "pw-1")
	markCredentialOutOfSync(t, shared.ID)

	_, err := assets.Create(&CreateAssetRequest{
		Name: "new-host", Protocol: model.ProtocolSSH, Host: "10.8.1.1", Port: 22,
		CredentialID: shared.ID, CreatedBy: 1, CreatedByName: "admin",
	})
	assert.ErrorIs(t, err, ErrCredentialOutOfSync,
		"未收斂的共用憑證不得在建資產時被掛上（同 Bind 的判準）")

	var count int64
	require.NoError(t, database.DB.Model(&model.Asset{}).
		Where("name = ?", "new-host").Count(&count).Error)
	assert.Zero(t, count, "被拒的建立不得留下半成品資產")
}

// 收斂之後同一條路徑必須放行——閘門不得寬到誤傷正常建立。
func TestCreateAssetWithConvergedSharedCredentialSucceeds(t *testing.T) {
	db := setupCredentialDB(t)
	assets, _, creds := newCredentialServices(t)

	shared := newSharedCredential(t, creds, "ops-converged", "ops", "pw-1")
	a, err := assets.Create(&CreateAssetRequest{
		Name: "ok-host", Protocol: model.ProtocolSSH, Host: "10.8.1.2", Port: 22,
		CredentialID: shared.ID, CreatedBy: 1, CreatedByName: "admin",
	})
	require.NoError(t, err)

	var account model.AssetAccount
	require.NoError(t, db.Where("asset_id = ?", a.ID).First(&account).Error)
	assert.Equal(t, shared.ID, account.CredentialID)
}

// promoteToCredential 同時動舊憑證與目標憑證兩列，取鎖必須依憑證識別定序。
//
// 兩條方向相反的改綁（A→B 與 B→A）若各按自己的語義順序取鎖，會各持對方要的
// 那一列。定序這件事沒有執行期訊號——死鎖只在並行下出現，單測永遠看不到——
// 故以原始碼守衛釘住：本函式只准經 lockCredentialRowsOrdered 取憑證列鎖。
func TestPromoteToCredentialLocksCredentialsOrdered(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "change_secret_candidate_service.go", nil, 0)
	require.NoError(t, err)

	var found bool
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Name.Name != "promoteToCredential" {
			continue
		}
		found = true
		var bare, ordered int
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			ident, ok := call.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			switch ident.Name {
			case "lockCredentialRow":
				bare++
			case "lockCredentialRowsOrdered":
				ordered++
			}
			return true
		})
		assert.Zero(t, bare,
			"promoteToCredential 直接呼叫 lockCredentialRow：兩筆憑證未依識別定序取鎖")
		assert.Equal(t, 1, ordered,
			"promoteToCredential 須以 lockCredentialRowsOrdered 一次取齊兩筆憑證列鎖")
	}
	require.True(t, found, "找不到 promoteToCredential，守衛已失效")
}
