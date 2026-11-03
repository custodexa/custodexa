package asset_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
)

// 範圍化存檔路徑：涵蓋某台的全帳號計劃，不因該台的執行身分引用共用憑證而被拒。
func TestScopedPlanSaveIgnoresSharedExecutor(t *testing.T) {
	p := newPsEnv(t)
	in2 := p.asset("bs-in-exec", "bs-in")
	cred := p.credential("bs-exec-cred", "bs-in")
	p.account(in2, "pc", cred)
	req := func(name string) *asset.ChangeSecretPlanRequest {
		return &asset.ChangeSecretPlanRequest{Name: name, AssetIDs: []uint{in2}}
	}
	code, body := p.create("scoped", req("before"))
	require.Equal(t, http.StatusBadRequest, code, "共用憑證掛成登入帳號時照既有規則拒絕")
	require.Contains(t, string(body), "VALIDATION_PLAN_SHARED_CREDENTIAL_TARGET")

	require.NoError(t, p.db.Model(&model.AssetAccount{}).Where("asset_id = ? AND credential_id = ?", in2, cred).
		Update("purpose", model.AccountPurposeExecutor).Error)
	code, body = p.create("scoped", req("after"))
	require.Equal(t, http.StatusCreated, code, string(body))
}
