package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 帶狀態檢查的憑證入口（自憑證側卸載、整組輪替起始、逐台補跑、放棄）：範圍化主體對範圍外憑證，
// 不論其掛載、輪替進行中、未收斂、零掛載、輪替歸屬或輪次是否已結束，回應都與不存在逐位元相同且零寫入；
// 範圍內的狀態拒絕照舊（正向對照）。

// scRotationRouter 遠端輪替三入口：輪替引擎為真實作（遠端依賴不注入：被拒的請求不得走到遠端）。
func (e *scEnv) scRotationRouter(uid uint, rot *asset.CredentialRotationService) *gin.Engine {
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(newCoverageAuditService()))
	r.Use(e.scPrincipal(uid))
	h := api.NewCredentialHandler(e.creds, rot, scStatus{})
	reg := middleware.EnforceRegistry()
	r.POST("/api/v1/credentials/:id/rotations", reg, h.StartRotation)
	r.POST("/api/v1/credentials/:id/rotations/:rid/members/:mid/retry", reg, h.RetryMember)
	r.POST("/api/v1/credentials/:id/rotations/:rid/abandon", reg, h.AbandonRotation)
	return r
}

// scCode 回應本文的錯誤碼（逐字比對，避免前綴相同的兩個碼互相滿足包含判斷）。
func scCode(t *testing.T, body string) string {
	t.Helper()
	var parsed struct {
		Code string `json:"code"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &parsed), body)
	return parsed.Code
}

// scRotationRow 直接寫一筆輪替與一個成員（不經引擎：只為讓識別與狀態存在）。
func (m *scMount) scRotationRow(credID, accountID uint, status, memberState string) (rid, mid uint) {
	m.t.Helper()
	rot := model.CredentialRotation{CredentialID: credID, Epoch: 1, Mode: model.CredentialRotationModeGroup,
		Status: status, RequestedBy: m.holder, StartedAt: time.Now()}
	require.NoError(m.t, m.db.Create(&rot).Error)
	var acc model.AssetAccount
	require.NoError(m.t, m.db.First(&acc, accountID).Error)
	mem := model.CredentialRotationMember{RotationID: rot.ID, AccountID: accountID, CredentialID: credID,
		Username: acc.Username, AssetID: acc.AssetID, State: memberState}
	require.NoError(m.t, m.db.Create(&mem).Error)
	if status == model.CredentialRotationRunning {
		require.NoError(m.t, m.db.Model(&model.Credential{}).Where("id = ?", credID).
			Update("active_rotation_id", rot.ID).Error)
	}
	return rot.ID, mem.ID
}

// scCredSnapshot 憑證的輪替狀態欄與掛載數、輪替與成員的狀態（零寫入的比對基準）。
func (m *scMount) scCredSnapshot(credID uint) string {
	m.t.Helper()
	var c model.Credential
	require.NoError(m.t, m.db.First(&c, credID).Error)
	ptr := func(p *uint) string {
		if p == nil {
			return "-"
		}
		return fmt.Sprint(*p)
	}
	var rots []model.CredentialRotation
	require.NoError(m.t, m.db.Where("credential_id = ?", credID).Order("id").Find(&rots).Error)
	var mems []model.CredentialRotationMember
	require.NoError(m.t, m.db.Where("credential_id = ?", credID).Order("id").Find(&mems).Error)
	out := fmt.Sprintf("active=%s pending=%s epoch=%d mounts=%d", ptr(c.ActiveRotationID), ptr(c.PendingVersionID),
		c.RotationEpoch, m.mountCount(credID))
	for _, r := range rots {
		out += fmt.Sprintf(" rot%d=%s", r.ID, r.Status)
	}
	for _, x := range mems {
		out += fmt.Sprintf(" mem%d=%s", x.ID, x.State)
	}
	return out
}

func runUnbindOutOfScopeSameShape(t *testing.T, m *scMount) {
	mgr := m.user("zz-sc-unbinder")
	m.grant(mgr, []string{"zz-sc-in"}, authz.PermCredentialView, authz.PermCredentialBind,
		authz.PermCredentialUpdate)
	out := m.cred("zz-sc-unbind-out", m.nodeID("zz-sc-out"))
	accOut := m.mount(out, m.aOut)
	busy := m.cred("zz-sc-unbind-out-busy", m.nodeID("zz-sc-out"))
	accBusy := m.mount(busy, m.aOut)
	require.NoError(t, m.db.Model(&model.Credential{}).Where("id = ?", busy).
		Update("active_rotation_id", 424242).Error)
	other := m.cred("zz-sc-unbind-out-other", m.nodeID("zz-sc-out"))
	unbind := func(credID, accountID uint) (int, string) {
		return m.call(mgr, "DELETE", fmt.Sprintf("%s/bindings/%d", credPath(credID), accountID), "")
	}
	before := []string{m.scCredSnapshot(out), m.scCredSnapshot(busy), m.scCredSnapshot(other)}
	accounts := m.accountCount()

	wantCode, wantBody := unbind(m.ghost, accOut)
	require.Equal(t, http.StatusNotFound, wantCode, wantBody)
	require.Equal(t, string(apierror.CodeCredentialNotFound), scCode(t, wantBody), "不存在的憑證回憑證不存在")
	for _, c := range []struct {
		label       string
		cred, accID uint
	}{
		{"範圍外憑證＋其真掛載", out, accOut},
		{"範圍外憑證＋不存在掛載", out, 999990},
		{"範圍外且輪替進行中＋其真掛載", busy, accBusy},
		// 以範圍外憑證的帳號識別逐一試憑證識別：真憑證、另一筆範圍外憑證、不存在三者不可分
		{"帳號識別探測：另一筆範圍外憑證", other, accOut},
		{"帳號識別探測：不存在憑證＋另一掛載", m.ghost, accBusy},
		{"帳號識別探測：範圍外憑證＋別筆的掛載", busy, accOut},
	} {
		code, body := unbind(c.cred, c.accID)
		require.Equal(t, wantCode, code, c.label+"：%s", body)
		require.JSONEq(t, wantBody, body, c.label)
		require.Equal(t, wantBody, body, c.label+"：逐位元相同")
	}
	require.Equal(t, before, []string{m.scCredSnapshot(out), m.scCredSnapshot(busy), m.scCredSnapshot(other)}, "零寫入")
	require.Equal(t, accounts, m.accountCount(), "帳號表筆數不變")

	// 正向對照：範圍內憑證的範圍內掛載在輪替進行中仍回進行中衝突，卸載的狀態檢查沒有因順序調整而消失
	in := m.cred("zz-sc-unbind-in-busy", m.nodeID("zz-sc-in"))
	accIn := m.mount(in, m.aIn)
	require.NoError(t, m.db.Model(&model.Credential{}).Where("id = ?", in).
		Update("active_rotation_id", 424243).Error)
	code, body := unbind(in, accIn)
	require.Equal(t, http.StatusConflict, code, body)
	require.Equal(t, string(apierror.CodeCredentialRotationActive), scCode(t, body))
	require.EqualValues(t, 1, m.mountCount(in))
}

func runRotationStartOutOfScopeSameShape(t *testing.T, m *scMount) {
	mgr := m.user("zz-sc-rotator")
	m.grant(mgr, []string{"zz-sc-in"}, authz.PermCredentialView, authz.PermCredentialRotate)
	rot := asset.NewCredentialRotationService(m.db, m.assets, nil, nil, m.codec, audit.NewTxSink(), m.adapter).
		WithScopeSource(authz.NewCredentialScopeReader(m.eval, m.db))
	r := m.scRotationRouter(mgr, rot)
	start := func(credID uint) (int, string) {
		return scServe(r, "POST", credPath(credID)+"/rotations", `{"mode":"group"}`)
	}
	normal := m.cred("zz-sc-start-out", m.nodeID("zz-sc-out"))
	m.mount(normal, m.aOut)
	zero := m.cred("zz-sc-start-out-zero", m.nodeID("zz-sc-out"))
	busy := m.cred("zz-sc-start-out-busy", m.nodeID("zz-sc-out"))
	m.mount(busy, m.aOut)
	require.NoError(t, m.db.Model(&model.Credential{}).Where("id = ?", busy).
		Update("active_rotation_id", 424244).Error)
	unsynced := m.cred("zz-sc-start-out-unsynced", m.nodeID("zz-sc-out"))
	m.mount(unsynced, m.aOut)
	require.NoError(t, m.db.Model(&model.Credential{}).Where("id = ?", unsynced).
		Update("pending_version_id", 424245).Error)
	ids := []uint{normal, zero, busy, unsynced}
	snap := func() []string {
		var s []string
		for _, id := range ids {
			s = append(s, m.scCredSnapshot(id))
		}
		return s
	}
	before := snap()
	rotations := m.rotationCount()

	wantCode, wantBody := start(m.ghost)
	require.Equal(t, http.StatusNotFound, wantCode, wantBody)
	require.Equal(t, string(apierror.CodeCredentialNotFound), scCode(t, wantBody), "範圍化主體眼中不存在的憑證走範圍拒絕出口")
	for _, c := range []struct {
		label string
		id    uint
	}{{"範圍外一般", normal}, {"範圍外零掛載", zero}, {"範圍外輪替進行中", busy}, {"範圍外未收斂", unsynced}} {
		code, body := start(c.id)
		require.Equal(t, wantCode, code, c.label+"：%s", body)
		require.JSONEq(t, wantBody, body, c.label)
		require.Equal(t, wantBody, body, c.label+"：逐位元相同")
	}
	require.Equal(t, before, snap(), "零寫入")
	require.Equal(t, rotations, m.rotationCount(), "輪替列為 0")

	// 正向對照：範圍內的進行中與零掛載仍回各自的狀態拒絕
	inBusy := m.cred("zz-sc-start-in-busy", m.nodeID("zz-sc-in"))
	m.mount(inBusy, m.aIn)
	require.NoError(t, m.db.Model(&model.Credential{}).Where("id = ?", inBusy).
		Update("active_rotation_id", 424246).Error)
	code, body := start(inBusy)
	require.Equal(t, http.StatusConflict, code, body)
	require.Equal(t, string(apierror.CodeCredentialRotationActive), scCode(t, body))
	inZero := m.cred("zz-sc-start-in-zero", m.nodeID("zz-sc-in"))
	code, body = start(inZero)
	require.Equal(t, http.StatusConflict, code, body)
	require.Equal(t, string(apierror.CodeCredentialRotationNoBinding), scCode(t, body))
	require.Equal(t, rotations, m.rotationCount(), "正向對照同樣零輪替列")
}

func runRetryAbandonOutOfScopeSameShape(t *testing.T, m *scMount) {
	mgr := m.user("zz-sc-retrier")
	m.grant(mgr, []string{"zz-sc-in"}, authz.PermCredentialView, authz.PermCredentialRotate)
	rot := asset.NewCredentialRotationService(m.db, m.assets, nil, nil, m.codec, audit.NewTxSink(), m.adapter).
		WithScopeSource(authz.NewCredentialScopeReader(m.eval, m.db))
	r := m.scRotationRouter(mgr, rot)
	retry := func(credID, rid, mid uint) (int, string) {
		return scServe(r, "POST", fmt.Sprintf("%s/rotations/%d/members/%d/retry", credPath(credID), rid, mid), "")
	}
	abandon := func(credID, rid uint) (int, string) {
		return scServe(r, "POST", fmt.Sprintf("%s/rotations/%d/abandon", credPath(credID), rid), "")
	}

	out := m.cred("zz-sc-retry-out", m.nodeID("zz-sc-out"))
	accOut := m.mount(out, m.aOut)
	ridDone, midDone := m.scRotationRow(out, accOut, model.CredentialRotationCompleted, model.CredentialMemberApplied)
	ridRun, midRun := m.scRotationRow(out, accOut, model.CredentialRotationRunning, model.CredentialMemberQueued)
	other := m.cred("zz-sc-retry-out-other", m.nodeID("zz-sc-out"))
	accOther := m.mount(other, m.aOut)
	ridOther, midOther := m.scRotationRow(other, accOther, model.CredentialRotationRunning, model.CredentialMemberQueued)
	before := []string{m.scCredSnapshot(out), m.scCredSnapshot(other)}

	t.Run("逐台補跑", func(t *testing.T) {
		wantCode, wantBody := retry(m.ghost, ridRun, midRun)
		require.Equal(t, http.StatusNotFound, wantCode, wantBody)
		require.Equal(t, string(apierror.CodeCredentialNotFound), scCode(t, wantBody), "範圍化主體眼中不存在的憑證走範圍拒絕出口")
		for _, c := range []struct {
			label         string
			cred, rid, id uint
		}{
			{"範圍外憑證＋其進行中輪替與成員", out, ridRun, midRun},
			{"範圍外憑證＋其已結束輪替", out, ridDone, midDone},
			{"範圍外憑證＋不屬於它的輪替", out, ridOther, midOther},
			{"範圍外憑證＋不存在輪替", out, 999991, midRun},
			{"範圍外憑證＋不存在成員", out, ridRun, 999992},
		} {
			code, body := retry(c.cred, c.rid, c.id)
			require.Equal(t, wantCode, code, c.label+"：%s", body)
			require.JSONEq(t, wantBody, body, c.label)
			require.Equal(t, wantBody, body, c.label+"：逐位元相同")
		}
		require.Equal(t, before, []string{m.scCredSnapshot(out), m.scCredSnapshot(other)}, "零寫入")
	})

	t.Run("放棄", func(t *testing.T) {
		wantCode, wantBody := abandon(m.ghost, ridRun)
		require.Equal(t, http.StatusNotFound, wantCode, wantBody)
		require.Equal(t, string(apierror.CodeCredentialNotFound), scCode(t, wantBody), "範圍化主體眼中不存在的憑證走範圍拒絕出口")
		for _, c := range []struct {
			label     string
			cred, rid uint
		}{
			{"範圍外憑證＋其進行中輪替", out, ridRun},
			{"範圍外憑證＋其已結束輪替", out, ridDone},
			{"範圍外憑證＋不屬於它的輪替", out, ridOther},
			{"範圍外憑證＋不存在輪替", out, 999991},
		} {
			code, body := abandon(c.cred, c.rid)
			require.Equal(t, wantCode, code, c.label+"：%s", body)
			require.JSONEq(t, wantBody, body, c.label)
			require.Equal(t, wantBody, body, c.label+"：逐位元相同")
		}
		require.Equal(t, before, []string{m.scCredSnapshot(out), m.scCredSnapshot(other)}, "零寫入")
	})

	t.Run("正向對照：範圍內的輪替歸屬與已結束照舊", func(t *testing.T) {
		in := m.cred("zz-sc-retry-in", m.nodeID("zz-sc-in"))
		accIn := m.mount(in, m.aIn)
		ridIn, midIn := m.scRotationRow(in, accIn, model.CredentialRotationCompleted, model.CredentialMemberApplied)
		code, body := abandon(in, ridIn)
		require.Equal(t, http.StatusConflict, code, body)
		require.Equal(t, string(apierror.CodeCredentialRotationNotRunning), scCode(t, body))
		code, body = retry(in, ridIn, midIn)
		require.Equal(t, http.StatusConflict, code, body)
		require.Equal(t, string(apierror.CodeCredentialRotationNotRunning), scCode(t, body))
		code, body = abandon(in, ridOther)
		require.Equal(t, http.StatusNotFound, code, body)
		require.Equal(t, string(apierror.CodeCredentialRotationNotFound), scCode(t, body), "範圍內憑證＋別筆的輪替回輪替不存在")
		require.Equal(t, before, []string{m.scCredSnapshot(out), m.scCredSnapshot(other)}, "範圍外的輪替仍未被動到")
	})
}
