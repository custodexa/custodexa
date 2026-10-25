package asset_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
)

// 整批同一組模式新共用憑證的歸屬：建立批次時以判定器驗一次並持久化於批次列。
// 本檔以正式判定器驗建立面；runner 以持久值重驗並寫入憑證見同名內部測試。

func bsSharedReq(name string, owner *asset.CredentialOwnershipInput) *asset.ChangeSecretBatchRequest {
	req := bsReq("postgres")
	req.PasswordMode = model.BatchPasswordShared
	req.CredentialName = name
	req.SharedCredentialOwnership = owner
	return req
}

func TestScopedBatchSharedOwnership(t *testing.T) {
	gin.SetMode(gin.TestMode)
	e := newBsEnv(t)
	scoped, global := e.users["scoped"], e.users["global"]
	node := func(id uint) *asset.CredentialOwnershipInput {
		return &asset.CredentialOwnershipInput{Kind: model.CredentialOwnerNode, NodeID: &id}
	}

	t.Run("scoped_in_scope_node_persisted", func(t *testing.T) {
		batch, _, err := e.svc.Create(bsSharedReq("bs-own-in", node(e.nodes["bs-in"])), scoped, "bs-scoped")
		require.NoError(t, err)
		var row model.ChangeSecretBatch
		require.NoError(t, e.db.First(&row, batch.ID).Error)
		require.Equal(t, model.CredentialOwnerNode, row.SharedCredentialOwnerKind)
		require.NotNil(t, row.SharedCredentialOwnerNodeID)
		require.Equal(t, e.nodes["bs-in"], *row.SharedCredentialOwnerNodeID)
	})

	t.Run("scoped_rejections", func(t *testing.T) {
		var before int64
		require.NoError(t, e.db.Model(&model.ChangeSecretBatch{}).Count(&before).Error)
		code, body := e.post("scoped", bsSharedReq("bs-own-none", nil))
		require.Equal(t, http.StatusBadRequest, code, string(body))
		require.Contains(t, string(body), string(apierror.CodeCredentialOwnershipInvalid))

		code, body = e.post("scoped", bsSharedReq("bs-own-global", &asset.CredentialOwnershipInput{Kind: model.CredentialOwnerGlobal}))
		require.Equal(t, http.StatusForbidden, code, string(body))

		c1, b1 := e.post("scoped", bsSharedReq("bs-own-out", node(e.nodes["bs-out"])))
		c2, b2 := e.post("scoped", bsSharedReq("bs-own-missing", node(987660)))
		require.Equal(t, http.StatusNotFound, c1, string(b1))
		require.Equal(t, c1, c2)
		require.JSONEq(t, string(b1), string(b2), "範圍外與不存在節點同形")
		var resp map[string]any
		require.NoError(t, json.Unmarshal(b1, &resp))
		require.Equal(t, string(apierror.CodeAssetNodeNotFound), resp["code"])

		var after int64
		require.NoError(t, e.db.Model(&model.ChangeSecretBatch{}).Count(&after).Error)
		require.Equal(t, before, after, "四次拒絕皆不寫批次列")
	})

	t.Run("global_unspecified_is_global", func(t *testing.T) {
		batch, _, err := e.svc.Create(bsSharedReq("bs-own-g", nil), global, "bs-global")
		require.NoError(t, err)
		var row model.ChangeSecretBatch
		require.NoError(t, e.db.First(&row, batch.ID).Error)
		require.Equal(t, model.CredentialOwnerGlobal, row.SharedCredentialOwnerKind)
		require.Nil(t, row.SharedCredentialOwnerNodeID)
	})
}
