package asset_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
)

// coGate 憑證管理關卡替身：預設放行；可指定「對某筆憑證不放行」與「判定器本身出錯」。
type coGate struct {
	mu      sync.Mutex
	denied  map[uint]bool
	failErr error
}

// denyCredential 關卡對這筆憑證判為無權（範圍外掛載不構成拒絕理由，改以憑證本身當拒絕鍵）。
func (g *coGate) denyCredential(id uint) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.denied == nil {
		g.denied = map[uint]bool{}
	}
	g.denied[id] = true
}

func (g *coGate) reset() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.denied, g.failErr = nil, nil
}

func (g *coGate) fail(err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.failErr = err
}

func (g *coGate) AuthorizeCredentialManagement(_ context.Context, _ *gorm.DB,
	_ asset.CredentialManagementActor, req asset.CredentialManagementRequest) (asset.CredentialManagementDecision, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failErr != nil {
		return asset.CredentialManagementDecision{}, g.failErr
	}
	for _, id := range req.CredentialIDs {
		if g.denied[id] {
			return asset.CredentialManagementDecision{Allowed: false, Missing: string(authz.PermCredentialUpdate)}, nil
		}
	}
	return asset.CredentialManagementDecision{Allowed: true, AuthzVersion: 1}, nil
}

// updater 在 co-in 節點範圍持 credential:view／update 的主體。
func (e *coEnv) updater() uint {
	e.t.Helper()
	id := e.user("co-updater")
	role := model.Role{Name: "co-credential-updater", DefinitionVersion: 1}
	require.NoError(e.t, e.db.Create(&role).Error)
	for _, p := range []authz.Permission{authz.PermCredentialView, authz.PermCredentialUpdate} {
		require.NoError(e.t, e.db.Create(&model.RolePermission{RoleID: role.ID, PermissionKey: string(p)}).Error)
	}
	require.NoError(e.t, e.db.Create(&model.UserRole{UserID: id, RoleID: role.ID,
		Source: model.RoleSourceManual, ScopeKind: model.ScopeKindNodes}).Error)
	require.NoError(e.t, e.db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser,
		SubjectID: id, RoleID: role.ID, NodeID: e.nodes["co-in"]}).Error)
	return id
}

// shared 建一筆共用憑證（由超管建立）；mount 為真時掛到一台新資產，回傳資產識別。
func (e *coEnv) shared(owner *asset.CredentialOwnershipInput, mount bool) (*asset.CredentialDTO, uint) {
	e.t.Helper()
	dto, err := e.create(e.super, owner)
	require.NoError(e.t, err)
	if !mount {
		return dto, 0
	}
	e.seq++
	a := model.Asset{Name: fmt.Sprintf("co-asset-%d", e.seq), Protocol: model.ProtocolSSH,
		Host: fmt.Sprintf("10.68.%d.%d", e.seq/250, e.seq%250+1), Port: 22, CreatedBy: e.super, Active: true}
	require.NoError(e.t, e.db.Create(&a).Error)
	require.NoError(e.t, e.db.Create(&model.AssetAccount{AssetID: a.ID, CredentialID: dto.ID, Username: "ops"}).Error)
	return dto, a.ID
}

func (e *coEnv) accountRows(credID uint) []model.AssetAccount {
	e.t.Helper()
	var rows []model.AssetAccount
	require.NoError(e.t, e.db.Where("credential_id = ?", credID).Order("id").Find(&rows).Error)
	return rows
}

func (e *coEnv) reassign(actor uint, ids []uint, to *asset.CredentialOwnershipInput) (*asset.ReassignCredentialOwnershipResult, error) {
	return e.creds.ReassignOwnership(e.ctx(actor), &asset.ReassignCredentialOwnershipRequest{CredentialIDs: ids, Ownership: to})
}

// batchUnavailable 取出批次不可操作的筆數與經共用出口寫出的回應原文。
func batchUnavailable(t *testing.T, err error) (int, int, string) {
	t.Helper()
	var u *asset.CredentialBatchUnavailableError
	require.True(t, errors.As(err, &u), "應為批次不可操作值，實得 %v", err)
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/api/v1/credentials/ownership", nil)
	middleware.RespondBatchUnavailable(c, u.Count)
	return u.Count, w.Code, w.Body.String()
}

// TestCredentialOwnershipReassign 共用憑證改歸：單筆（PUT 的 ownership）與批次共用同一組逐筆關卡。
func TestCredentialOwnershipReassign(t *testing.T) {
	e := newCoEnv(t)
	upd := e.updater()
	in, kid, out := e.nodes["co-in"], e.nodes["co-in/kid"], e.nodes["co-out"]

	t.Run("超管把全域憑證改歸節點", func(t *testing.T) {
		e.gate.reset()
		dto, assetID := e.shared(onGlobal(), true)
		before := e.accountRows(dto.ID)
		verBefore := e.row(dto.ID).CurrentVersionID
		e.port.advances.Store(0)

		res, err := e.reassign(e.super, []uint{dto.ID}, onNode(in))
		require.NoError(t, err)
		assert.Equal(t, 1, res.Changed)
		kind, node := e.ownerOf(dto.ID)
		assert.Equal(t, model.CredentialOwnerNode, kind)
		require.NotNil(t, node)
		assert.Equal(t, in, *node)
		assert.Equal(t, before, e.accountRows(dto.ID), "掛載列（含就位版本）不變")
		assert.Equal(t, verBefore, e.row(dto.ID).CurrentVersionID, "密文版本不變")
		audits := e.ownershipAudits(dto.ID)
		require.Len(t, audits, 2, "建立一列、改歸一列")
		assert.Contains(t, audits[1], `"ownership_before":{"kind":"global"}`)
		assert.Contains(t, audits[1], fmt.Sprintf(`"ownership":{"kind":"node","node_id":%d}`, in))
		assert.EqualValues(t, 1, e.port.advances.Load(), "權限版本推進一次")
		_ = assetID
	})

	t.Run("範圍化主體範圍內改歸成功、改全域被拒、範圍外與不存在同形", func(t *testing.T) {
		e.gate.reset()
		dto, _ := e.shared(onNode(in), false)

		res, err := e.reassign(upd, []uint{dto.ID}, onNode(kid))
		require.NoError(t, err)
		assert.Equal(t, 1, res.Changed)
		_, node := e.ownerOf(dto.ID)
		require.NotNil(t, node)
		assert.Equal(t, kid, *node)

		e.port.advances.Store(0)
		_, err = e.reassign(upd, []uint{dto.ID}, onGlobal())
		var capDenied *authz.CredentialOwnershipCapabilityError
		assert.True(t, errors.As(err, &capDenied), "改全域為能力拒絕，實得 %v", err)

		_, errOut := e.reassign(upd, []uint{dto.ID}, onNode(out))
		_, errMissing := e.reassign(upd, []uint{dto.ID}, onNode(coMissingNode))
		codeOut, bodyOut := deny(t, errOut)
		codeMissing, bodyMissing := deny(t, errMissing)
		assert.Equal(t, codeMissing, codeOut)
		assert.Equal(t, bodyMissing, bodyOut, "範圍外與不存在節點的回應逐欄相同")
		_, node = e.ownerOf(dto.ID)
		assert.Equal(t, kid, *node, "三次失敗皆不改歸屬")
		assert.EqualValues(t, 0, e.port.advances.Load())
	})

	t.Run("批次三筆含一筆範圍外整批拒且只回筆數", func(t *testing.T) {
		e.gate.reset()
		a, _ := e.shared(onNode(in), false)
		b, _ := e.shared(onNode(in), false)
		c, _ := e.shared(onNode(out), false)
		e.port.advances.Store(0)

		_, err := e.reassign(upd, []uint{a.ID, b.ID, c.ID}, onNode(kid))
		count, code, body := batchUnavailable(t, err)
		assert.Equal(t, 1, count)
		assert.Equal(t, http.StatusNotFound, code)
		assert.Contains(t, body, "NOTFOUND_BATCH_ITEMS_UNAVAILABLE")
		for _, d := range []*asset.CredentialDTO{a, b, c} {
			assert.NotContains(t, body, d.Name)
		}
		for _, id := range []uint{a.ID, b.ID} {
			_, node := e.ownerOf(id)
			assert.Equal(t, in, *node)
		}
		_, node := e.ownerOf(c.ID)
		assert.Equal(t, out, *node)
		assert.EqualValues(t, 0, e.port.advances.Load())
	})

	t.Run("超管批次三筆全成功、三筆審計、權限版本只推進一次", func(t *testing.T) {
		e.gate.reset()
		var ids []uint
		for i := 0; i < 3; i++ {
			d, _ := e.shared(onGlobal(), false)
			ids = append(ids, d.ID)
		}
		e.port.advances.Store(0)
		res, err := e.reassign(e.super, ids, onNode(out))
		require.NoError(t, err)
		assert.Equal(t, 3, res.Changed)
		for _, id := range ids {
			assert.Len(t, e.ownershipAudits(id), 2)
		}
		assert.EqualValues(t, 1, e.port.advances.Load())
	})

	t.Run("歸屬未變不寫審計不推進版本", func(t *testing.T) {
		e.gate.reset()
		d, _ := e.shared(onNode(in), false)
		e.port.advances.Store(0)
		res, err := e.reassign(e.super, []uint{d.ID}, onNode(in))
		require.NoError(t, err)
		assert.Equal(t, 0, res.Changed)
		assert.Len(t, e.ownershipAudits(d.ID), 1, "只有建立那一列")
		assert.EqualValues(t, 0, e.port.advances.Load())
	})

	t.Run("第三筆寫入失敗時前兩筆回滾", func(t *testing.T) {
		e.gate.reset()
		var ids []uint
		for i := 0; i < 3; i++ {
			d, _ := e.shared(onGlobal(), false)
			ids = append(ids, d.ID)
		}
		e.port.advances.Store(0)
		e.seen.Store(0)
		e.failAt.Store(3)
		defer e.failAt.Store(0)
		_, err := e.reassign(e.super, ids, onNode(in))
		require.Error(t, err)
		assert.ErrorIs(t, err, errCoCascadeInjected)
		for _, id := range ids {
			kind, _ := e.ownerOf(id)
			assert.Equal(t, model.CredentialOwnerGlobal, kind)
			assert.Len(t, e.ownershipAudits(id), 1)
		}
		assert.EqualValues(t, 0, e.port.advances.Load())
	})

	t.Run("批次含關卡判為無權的憑證整批拒且零寫入", func(t *testing.T) {
		e.gate.reset()
		ok, _ := e.shared(onNode(in), true)
		bad, _ := e.shared(onNode(in), true)
		e.gate.denyCredential(bad.ID)
		e.port.advances.Store(0)

		_, err := e.reassign(upd, []uint{ok.ID, bad.ID}, onNode(kid))
		count, _, _ := batchUnavailable(t, err)
		assert.Equal(t, 1, count)
		for _, id := range []uint{ok.ID, bad.ID} {
			_, node := e.ownerOf(id)
			assert.Equal(t, in, *node, "整批不寫")
			assert.Len(t, e.ownershipAudits(id), 1, "零新增審計")
		}
		assert.EqualValues(t, 0, e.port.advances.Load(), "權限版本不推進")
	})

	t.Run("批次含輪替中憑證整批拒", func(t *testing.T) {
		e.gate.reset()
		ok, _ := e.shared(onNode(in), true)
		busy, _ := e.shared(onNode(in), true)
		require.NoError(t, e.db.Model(&model.Credential{}).Where("id = ?", busy.ID).
			Update("active_rotation_id", 1).Error)
		e.port.advances.Store(0)

		_, err := e.reassign(upd, []uint{ok.ID, busy.ID}, onNode(kid))
		count, _, _ := batchUnavailable(t, err)
		assert.Equal(t, 1, count)
		for _, id := range []uint{ok.ID, busy.ID} {
			_, node := e.ownerOf(id)
			assert.Equal(t, in, *node)
			assert.Len(t, e.ownershipAudits(id), 1)
		}
		assert.EqualValues(t, 0, e.port.advances.Load())
	})

	t.Run("關卡的非拒絕類錯誤原樣回傳不當成可操作", func(t *testing.T) {
		e.gate.reset()
		d, _ := e.shared(onNode(in), true)
		e.gate.fail(errors.New("authorizer backend down"))
		defer e.gate.reset()
		_, err := e.reassign(upd, []uint{d.ID}, onNode(kid))
		require.Error(t, err)
		var u *asset.CredentialBatchUnavailableError
		assert.False(t, errors.As(err, &u), "判定器故障不得計入不可操作筆數")
		assert.ErrorIs(t, err, asset.ErrCredentialAuthzUnavailable)
		_, node := e.ownerOf(d.ID)
		assert.Equal(t, in, *node)
	})

	t.Run("同一組輸入單筆與批次結論一致", func(t *testing.T) {
		type tc struct {
			name  string
			setup func() uint
			ok    bool
		}
		cases := []tc{
			{"關卡判為無權", func() uint {
				d, _ := e.shared(onNode(in), true)
				e.gate.denyCredential(d.ID)
				return d.ID
			}, false},
			{"輪替中", func() uint {
				d, _ := e.shared(onNode(in), true)
				require.NoError(t, e.db.Model(&model.Credential{}).Where("id = ?", d.ID).
					Update("active_rotation_id", 1).Error)
				return d.ID
			}, false},
			{"可操作", func() uint {
				d, _ := e.shared(onNode(in), true)
				return d.ID
			}, true},
		}
		for _, c := range cases {
			e.gate.reset()
			single := c.setup()
			_, serr := e.creds.Update(e.ctx(upd), single, &asset.UpdateCredentialRequest{Ownership: onNode(kid)})
			e.gate.reset()
			batchID := c.setup()
			_, berr := e.reassign(upd, []uint{batchID}, onNode(kid))
			assert.Equal(t, c.ok, serr == nil, "%s 單筆結論 %v", c.name, serr)
			assert.Equal(t, c.ok, berr == nil, "%s 批次結論 %v", c.name, berr)
		}
	})
}
