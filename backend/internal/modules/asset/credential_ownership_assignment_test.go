package asset_test

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/testgate"
)

// TestCredentialOwnershipAssignment 新憑證的管理歸屬：建立、範圍轉換、脫離、批次整組建立，
// 與歸屬節點刪除時的承接（含與建立的兩種提交順序）。
func TestCredentialOwnershipAssignment(t *testing.T) {
	e := newCoEnv(t)
	if e.dsn != "" {
		require.Equal(t, "postgres", e.db.Dialector.Name())
	}

	t.Run("全域主體未帶歸屬預設全域", func(t *testing.T) {
		e.port.advances.Store(0)
		dto, err := e.create(e.super, nil)
		require.NoError(t, err)
		kind, node := e.ownerOf(dto.ID)
		assert.Equal(t, model.CredentialOwnerGlobal, kind)
		assert.Nil(t, node)
		assert.EqualValues(t, 1, e.port.advances.Load())
	})

	t.Run("範圍化主體四種拒絕皆不建立、範圍外與不存在同形", func(t *testing.T) {
		before := e.credentialCount()
		e.port.advances.Store(0)

		_, err := e.create(e.manager, nil)
		assert.ErrorIs(t, err, asset.ErrCredentialOwnershipInvalid, "未帶歸屬")

		_, err = e.create(e.manager, onGlobal())
		var capDenied *authz.CredentialOwnershipCapabilityError
		assert.True(t, errors.As(err, &capDenied), "要求全域為能力拒絕，實得 %v", err)

		_, errOut := e.create(e.manager, onNode(e.nodes["co-out"]))
		_, errMissing := e.create(e.manager, onNode(coMissingNode))
		codeOut, bodyOut := deny(t, errOut)
		codeMissing, bodyMissing := deny(t, errMissing)
		assert.Equal(t, codeMissing, codeOut)
		assert.Equal(t, bodyMissing, bodyOut, "範圍外與不存在節點的回應逐欄相同")

		assert.Equal(t, before, e.credentialCount(), "四次失敗皆不建立憑證")
		assert.EqualValues(t, 0, e.port.advances.Load(), "失敗不推進權限版本")
	})

	t.Run("範圍化主體帶範圍內節點成功", func(t *testing.T) {
		e.port.advances.Store(0)
		kid := e.nodes["co-in/kid"]
		dto, err := e.create(e.manager, onNode(kid))
		require.NoError(t, err)
		kind, node := e.ownerOf(dto.ID)
		assert.Equal(t, model.CredentialOwnerNode, kind)
		require.NotNil(t, node)
		assert.Equal(t, kid, *node)
		audits := e.ownershipAudits(dto.ID)
		require.Len(t, audits, 1)
		assert.Contains(t, audits[0], fmt.Sprintf(`"ownership":{"kind":"node","node_id":%d}`, kid))
		assert.EqualValues(t, 1, e.port.advances.Load(), "權限版本推進點恰一次")
	})

	t.Run("歸屬欄形狀不合法", func(t *testing.T) {
		before := e.credentialCount()
		_, err := e.create(e.super, &asset.CredentialOwnershipInput{Kind: "asset"})
		assert.ErrorIs(t, err, asset.ErrCredentialOwnershipInvalid, "kind 值域外（asset 不可由請求指定）")
		_, err = e.create(e.super, &asset.CredentialOwnershipInput{Kind: "team"})
		assert.ErrorIs(t, err, asset.ErrCredentialOwnershipInvalid, "kind 值域外")
		_, err = e.create(e.super, &asset.CredentialOwnershipInput{Kind: model.CredentialOwnerNode})
		assert.ErrorIs(t, err, asset.ErrCredentialOwnershipInvalid, "node 缺 node_id")
		assert.Equal(t, before, e.credentialCount())
	})

	t.Run("專用轉共用依建立規則、轉專用改隨資產", func(t *testing.T) {
		id := e.dedicated()
		kind, _ := e.ownerOf(id)
		require.Equal(t, model.CredentialOwnerAsset, kind, "轉專用後歸屬隨資產")
		require.Nil(t, e.row(id).OwnerNodeID)

		convert := func(o *asset.CredentialOwnershipInput) error {
			_, err := e.creds.ConvertScope(e.ctx(e.manager), id, &asset.ConvertCredentialScopeRequest{
				Scope: model.CredentialScopeShared, Name: fmt.Sprintf("co-convert-%d", id), Ownership: o})
			return err
		}
		e.port.advances.Store(0)
		codeOut, bodyOut := deny(t, convert(onNode(e.nodes["co-out"])))
		codeMissing, bodyMissing := deny(t, convert(onNode(coMissingNode)))
		assert.Equal(t, codeMissing, codeOut)
		assert.Equal(t, bodyMissing, bodyOut, "轉共用帶範圍外與不存在節點的回應相同")
		assert.Equal(t, model.CredentialScopeDedicated, e.row(id).Scope, "失敗維持專用")
		assert.EqualValues(t, 0, e.port.advances.Load(), "失敗的兩次未推進")

		in := e.nodes["co-in"]
		require.NoError(t, convert(onNode(in)))
		kind, node := e.ownerOf(id)
		assert.Equal(t, model.CredentialOwnerNode, kind)
		require.NotNil(t, node)
		assert.Equal(t, in, *node)
		assert.EqualValues(t, 1, e.port.advances.Load(), "轉共用的交易只推進一次")

		e.port.advances.Store(0)
		_, err := e.creds.ConvertScope(e.ctx(e.super), id,
			&asset.ConvertCredentialScopeRequest{Scope: model.CredentialScopeDedicated})
		require.NoError(t, err)
		kind, node = e.ownerOf(id)
		assert.Equal(t, model.CredentialOwnerAsset, kind)
		assert.Nil(t, node)
		assert.EqualValues(t, 1, e.port.advances.Load(), "轉專用同樣改變誰能管理，推進一次")

		_, err = e.creds.ConvertScope(e.ctx(e.super), id,
			&asset.ConvertCredentialScopeRequest{Scope: model.CredentialScopeDedicated, Ownership: onGlobal()})
		assert.ErrorIs(t, err, asset.ErrCredentialOwnershipInvalid, "對專用指定歸屬")
	})

	t.Run("脫離與批次整組建立", asset.OwnershipDetachAndBatchPathsForTest)

	t.Run("節點刪除承接", func(t *testing.T) {
		parent, child := e.nodes["co-parent"], e.nodes["co-child"]
		a, err := e.create(e.super, onNode(child))
		require.NoError(t, err)
		b, err := e.create(e.super, onNode(child))
		require.NoError(t, err)
		top, err := e.create(e.super, onNode(e.nodes["co-top"]))
		require.NoError(t, err)

		e.failCascade.Store(true)
		_, err = e.groups.Delete(e.ctx(e.super), child, e.super, "co-super", "127.0.0.1")
		e.failCascade.Store(false)
		require.ErrorIs(t, err, errCoCascadeInjected)
		var alive int64
		require.NoError(t, e.db.Model(&model.AssetGroup{}).Where("id = ?", child).Count(&alive).Error)
		assert.EqualValues(t, 1, alive, "承接寫入失敗時節點刪除整筆回滾")
		_, node := e.ownerOf(a.ID)
		require.NotNil(t, node)
		assert.Equal(t, child, *node)

		e.port.advances.Store(0)
		_, err = e.groups.Delete(e.ctx(e.super), child, e.super, "co-super", "127.0.0.1")
		require.NoError(t, err, "承接不阻擋節點刪除")
		for _, id := range []uint{a.ID, b.ID} {
			kind, node := e.ownerOf(id)
			assert.Equal(t, model.CredentialOwnerNode, kind)
			require.NotNil(t, node)
			assert.Equal(t, parent, *node, "子節點刪除後改歸父節點")
			audits := e.ownershipAudits(id)
			require.Len(t, audits, 2, "建立一列＋承接一列")
			assert.Contains(t, audits[1], fmt.Sprintf(`"ownership_before":{"kind":"node","node_id":%d}`, child))
		}
		assert.EqualValues(t, 1, e.port.advances.Load(), "承接兩筆仍由節點刪除交易推進一次")

		_, err = e.groups.Delete(e.ctx(e.super), e.nodes["co-top"], e.super, "co-super", "127.0.0.1")
		require.NoError(t, err)
		kind, node := e.ownerOf(top.ID)
		assert.Equal(t, model.CredentialOwnerGlobal, kind, "頂層節點刪除後改為全域")
		assert.Nil(t, node)
		assert.Len(t, e.ownershipAudits(top.ID), 2)
	})

	t.Run("建立與節點刪除的兩種提交順序", func(t *testing.T) {
		coOwnershipCommitOrders(t, e)
	})

	if !t.Failed() && os.Getenv(testgate.EnvPGDSN) != "" {
		fmt.Println("EVIDENCE dialect=postgres")
		t.Log("EVIDENCE dialect=postgres")
	}
}

// coOwnershipCommitOrders 「建立共用憑證指定節點 N」與「刪除空節點 N」兩種提交順序。
//
// PostgreSQL：以拓撲窄 port 的「取序列化鎖之前」hook，在一個交易已開始、尚未取鎖時讓另一個交易
// 整筆提交，兩者真的交錯。SQLite（單一連線）無法在交易內再開交易，依序執行兩者以固定提交順序。
func coOwnershipCommitOrders(t *testing.T, e *coEnv) {
	pg := e.dsn != ""
	deleteNode := func(id uint) error {
		_, err := e.groups.Delete(e.ctx(e.super), id, e.super, "co-super", "127.0.0.1")
		return err
	}

	t.Run("刪除先提交", func(t *testing.T) {
		n := e.node("co-order-del", "co-in")
		before := e.credentialCount()
		var delErr, createErr error
		if pg {
			e.port.onceBeforeLock(func() { delErr = deleteNode(n) })
			_, createErr = e.create(e.manager, onNode(n))
		} else {
			delErr = deleteNode(n)
			_, createErr = e.create(e.manager, onNode(n))
		}
		require.NoError(t, delErr)
		_, missingErr := e.create(e.manager, onNode(coMissingNode))
		codeGone, bodyGone := deny(t, createErr)
		codeMissing, bodyMissing := deny(t, missingErr)
		assert.Equal(t, codeMissing, codeGone)
		assert.Equal(t, bodyMissing, bodyGone, "建立回與不存在節點同形")
		assert.Equal(t, before, e.credentialCount(), "憑證表筆數不變")
		coAssertNoDanglingOwner(t, e)
	})

	t.Run("建立先提交", func(t *testing.T) {
		parent := e.nodes["co-in"]
		n := e.node("co-order-create", "co-in")
		var created *asset.CredentialDTO
		var createErr, delErr error
		if pg {
			e.port.onceBeforeLock(func() { created, createErr = e.create(e.manager, onNode(n)) })
			delErr = deleteNode(n)
		} else {
			created, createErr = e.create(e.manager, onNode(n))
			delErr = deleteNode(n)
		}
		require.NoError(t, createErr)
		require.NoError(t, delErr, "刪除照常成功")
		kind, node := e.ownerOf(created.ID)
		assert.Equal(t, model.CredentialOwnerNode, kind)
		require.NotNil(t, node)
		assert.Equal(t, parent, *node, "新憑證被承接到 N 的父節點")
		coAssertNoDanglingOwner(t, e)
	})
}

// coAssertNoDanglingOwner 任何憑證列（含軟刪）都不指向已刪或不存在的節點。
func coAssertNoDanglingOwner(t *testing.T, e *coEnv) {
	t.Helper()
	var dangling int64
	require.NoError(t, e.db.Raw(`SELECT COUNT(*) FROM credentials c WHERE c.owner_kind = ? AND NOT EXISTS (
		SELECT 1 FROM asset_groups g WHERE g.id = c.owner_node_id AND g.deleted_at IS NULL)`,
		model.CredentialOwnerNode).Scan(&dangling).Error)
	assert.Zero(t, dangling, "不得出現 owner_node_id 指向已刪節點的憑證")
}
