package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 能力判定先於範圍與存在性：路由層只要求任一寫入能力，缺本次動作能力的範圍化主體走得到服務層，
// 服務層必須在查任何一筆憑證之前就以能力拒絕。對範圍內、範圍外、歸屬全域與不存在的識別，
// 回應逐位元相同且零寫入；持有該能力者範圍內成功，範圍外與不存在同為不存在回應。
func TestScopedCredentialCapabilityFirstSameShape(t *testing.T) {
	t.Run("SQLite", func(t *testing.T) {
		runCapabilityFirstCases(t, func(t *testing.T) *scMount { return newSCMount(t) })
	})
	t.Run("PostgreSQL", func(t *testing.T) {
		runCapabilityFirstCases(t, func(t *testing.T) *scMount {
			return newSCMountOn(t, newSCEnvPG(t, "sc_capability_first"))
		})
	})
}

// capFirstEntry 一個在查表之前先判能力的入口；perm 是本次動作要求的能力，okCode 是持有者在範圍內的成功碼，
// bareIn 為真時範圍內的憑證不掛載（刪除仍有掛載時拒刪）。
type capFirstEntry struct {
	name, method, suffix, body string
	perm                       authz.Permission
	okCode                     int
	bareIn                     bool
}

var capFirstEntries = []capFirstEntry{
	{"修改", "PUT", "", `{"note":"zz-cf-note"}`, authz.PermCredentialUpdate, http.StatusOK, false},
	{"刪除", "DELETE", "", "", authz.PermCredentialDelete, http.StatusNoContent, true},
	{"轉換", "POST", "/scope", `{"scope":"dedicated"}`, authz.PermCredentialConvertScope, http.StatusOK, false},
	{"宣告新秘密", "POST", "/secret", `{"password":"zz-cf-secret"}`, authz.PermCredentialSetSecret, http.StatusOK, false},
	{"影響確認宣告", "POST", "/impact-confirmations", `{"operation":"set_secret"}`, authz.PermCredentialSetSecret, http.StatusOK, false},
	{"影響確認輪替", "POST", "/impact-confirmations", `{"operation":"rotate"}`, authz.PermCredentialRotate, http.StatusOK, false},
}

func runCapabilityFirstCases(t *testing.T, open func(t *testing.T) *scMount) {
	for i, e := range capFirstEntries {
		i, e := i, e
		t.Run(e.name+"：缺該能力時範圍內、範圍外、全域與不存在同形且零寫入", func(t *testing.T) {
			runCapabilityAbsentCase(t, open(t), i, e)
		})
		t.Run(e.name+"：持有該能力時範圍內成功、範圍外與不存在同形", func(t *testing.T) {
			runCapabilityHeldCase(t, open(t), i, e)
		})
	}
}

// capFirstTargets 每個案例各自的憑證：範圍內與範圍外各掛一台（轉專用需要唯一掛載），全域不掛。
func capFirstTargets(m *scMount, i int, e capFirstEntry) (in, out, global uint) {
	in = m.cred(fmt.Sprintf("zz-cf-in-%d", i), m.nodeID("zz-sc-in"))
	if !e.bareIn {
		m.mount(in, m.aIn)
	}
	out = m.cred(fmt.Sprintf("zz-sc-out-cf-%d", i), m.nodeID("zz-sc-out"))
	m.mount(out, m.aOut)
	global = m.cred(fmt.Sprintf("zz-cf-global-%d", i), nil)
	return in, out, global
}

func runCapabilityAbsentCase(t *testing.T, m *scMount, i int, e capFirstEntry) {
	// 持有其餘全部憑證能力（含路由層任一寫入能力），只缺本次動作要求的那一項
	perms := []authz.Permission{}
	for _, p := range scCredentialPerms {
		if p != e.perm {
			perms = append(perms, p)
		}
	}
	u := m.user(fmt.Sprintf("zz-cf-absent-%d", i))
	m.grant(u, []string{"zz-sc-in"}, perms...)
	in, out, global := capFirstTargets(m, i, e)
	before := m.capFirstSnapshot()

	wantCode, wantBody := m.call(u, e.method, credPath(m.ghost)+e.suffix, e.body)
	require.Equal(t, http.StatusForbidden, wantCode, "不存在：%s", wantBody)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(wantBody), &parsed), wantBody)
	require.Equal(t, string(apierror.CodePermissionDenied), parsed["code"], wantBody)
	for _, x := range []struct {
		label string
		id    uint
	}{{"範圍內", in}, {"範圍外", out}, {"歸屬全域", global}} {
		code, body := m.call(u, e.method, credPath(x.id)+e.suffix, e.body)
		require.Equal(t, wantCode, code, x.label+"：%s", body)
		require.JSONEq(t, wantBody, body, x.label)
		require.Equal(t, wantBody, body, x.label+"：逐位元相同")
	}
	require.Equal(t, before, m.capFirstSnapshot(), "能力拒絕零寫入")
}

func runCapabilityHeldCase(t *testing.T, m *scMount, i int, e capFirstEntry) {
	u := m.user(fmt.Sprintf("zz-cf-held-%d", i))
	m.grant(u, []string{"zz-sc-in"}, authz.PermCredentialView, e.perm)
	in, out, global := capFirstTargets(m, i, e)
	before := m.capFirstSnapshot()

	wantCode, wantBody := m.call(u, e.method, credPath(m.ghost)+e.suffix, e.body)
	require.Equal(t, http.StatusNotFound, wantCode, "不存在：%s", wantBody)
	require.Contains(t, wantBody, string(apierror.CodeCredentialNotFound), wantBody)
	for _, x := range []struct {
		label string
		id    uint
	}{{"範圍外", out}, {"歸屬全域", global}} {
		code, body := m.call(u, e.method, credPath(x.id)+e.suffix, e.body)
		require.Equal(t, wantCode, code, x.label+"：%s", body)
		require.JSONEq(t, wantBody, body, x.label)
		require.Equal(t, wantBody, body, x.label+"：逐位元相同")
	}
	require.Equal(t, before, m.capFirstSnapshot(), "範圍外與不存在零寫入")

	// 正向對照：範圍內成功，證明前置判定沒有把持有者一併擋下
	code, body := m.call(u, e.method, credPath(in)+e.suffix, e.body)
	require.Equal(t, e.okCode, code, body)
}

// capFirstSnapshot 寫入面快照：全部憑證列（含已軟刪）、密文版本、掛載與影響確認筆數。
func (m *scMount) capFirstSnapshot() string {
	m.t.Helper()
	var creds []model.Credential
	require.NoError(m.t, m.db.Unscoped().Order("id").Find(&creds).Error)
	raw, err := json.Marshal(creds)
	require.NoError(m.t, err)
	count := func(v any) int64 {
		var n int64
		require.NoError(m.t, m.db.Model(v).Count(&n).Error)
		return n
	}
	return fmt.Sprintf("%s|versions=%d|accounts=%d|confirmations=%d", raw,
		count(&model.CredentialSecretVersion{}), count(&model.AssetAccount{}),
		count(&model.CredentialImpactConfirmation{}))
}
