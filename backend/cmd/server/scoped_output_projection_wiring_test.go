package main

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
)

// TestScopedOutputProjectionWiring 注入自檢：完整時通過，逐項未注入各回指出該項的錯誤；
// 執行期缺投影時輪替進度查詢回內部錯誤且不出站任何成員。
func TestScopedOutputProjectionWiring(t *testing.T) {
	e := newOutEnv(t, soWithRotation(), soWithAccounts())
	reader := authz.NewCredentialScopeReader(e.eval, e.db)
	svc := asset.NewAssetAccountService(e.assets, e.codec, nil)
	judge := asset.NewAccountRowActionJudge(e.creds, svc)

	build := func(accountScope, projector, rotation, outputScope bool, csOpts ...bool) scopedOutputWiring {
		csOutput, csPlanScope := true, true
		if len(csOpts) == 2 {
			csOutput, csPlanScope = csOpts[0], csOpts[1]
		}
		accounts := api.NewAssetAccountHandler(svc, e.authzSvc)
		if accountScope {
			accounts.SetAccountCredentialScope(reader)
		}
		rot := e.rot.CredentialRotationService
		if !outputScope {
			rot = asset.NewCredentialRotationService(e.db, e.assets, nil, nil, e.codec, nil, e.adapter)
		}
		ch := api.NewCredentialHandler(e.creds, e.rot, scStatus{})
		if projector {
			ch.SetAccountRowProjector(reader, judge)
		}
		if rotation {
			ch.SetRotationMemberProjection(rot)
		}
		cands, err := asset.NewChangeSecretCandidateService(e.db, e.codec, e.assets, nil)
		require.NoError(t, err)
		if csPlanScope {
			cands.WithScope(authz.NewChangeSecretScope(e.eval))
		}
		cs := api.NewChangeSecretHandler(nil, nil, cands, nil, nil, nil)
		if csOutput {
			cs.SetCredentialOutputScope(reader)
		}
		return collectScopedOutputWiring(accounts, ch, cs)
	}

	t.Run("complete", func(t *testing.T) {
		require.NoError(t, build(true, true, true, true).require())
	})
	missing := []struct {
		name string
		w    scopedOutputWiring
		want string
	}{
		{"帳號 handler 的憑證投影來源", build(false, true, true, true), "帳號 handler 的憑證投影來源未注入"},
		{"憑證 handler 的帳號列投影器", build(true, false, true, true), "憑證 handler 的帳號列投影器未注入"},
		{"憑證 handler 的輪替成員投影", build(true, true, false, true), "憑證 handler 的輪替成員投影未注入"},
		{"輪替投影已注入但其輸出判定未注入", build(true, true, true, false), "輪替成員投影的輸出判定未注入"},
		{"改密 handler 的輸出判定", build(true, true, true, true, false, true), "改密 handler 的輸出判定未注入"},
		{"候選服務的計畫範圍判定", build(true, true, true, true, true, false), "候選服務的計畫範圍判定未注入"},
	}
	for _, m := range missing {
		t.Run(m.name, func(t *testing.T) {
			err := m.w.require()
			require.Error(t, err)
			t.Logf("WIRING-ERROR %s: %v", m.name, err)
			assert.Contains(t, err.Error(), m.want)
		})
	}

	t.Run("runtime_projection_missing", func(t *testing.T) {
		// 有投影的路由先起跑一輪，再以沒有注入投影的組裝查進度
		e.soBumpRotationIDs()
		wired := e.soRotationRouter(e.mgr)
		credBase := credPath(e.rotCred)
		code, raw := soServe(wired, http.MethodPost, credBase+"/impact-confirmations", `{"operation":"rotate"}`)
		require.Equal(t, http.StatusOK, code, raw)
		confirmID, _ := soDecode(t, raw)["confirmation_id"].(string)
		code, raw = soServe(wired, http.MethodPost, credBase+"/rotations",
			fmt.Sprintf(`{"mode":"group","impact_confirmation_id":%q}`, confirmID))
		require.Equal(t, http.StatusAccepted, code, raw)
		rid := uint(soDecode(t, raw)["data"].(map[string]any)["id"].(float64))

		r := gin.New()
		r.Use(middleware.AuditLogMiddleware(newCoverageAuditService()))
		r.Use(e.scPrincipal(e.mgr))
		h := api.NewCredentialHandler(e.creds, e.rot, scStatus{})
		r.GET("/api/v1/credentials/:id/rotations/:rid", middleware.EnforceRegistry(), h.GetRotation)
		code, raw = soServe(r, http.MethodGet, fmt.Sprintf("%s/rotations/%d", credBase, rid), "")
		assert.Equal(t, http.StatusInternalServerError, code, raw)
		assert.NotContains(t, raw, `"members"`)
		assert.NotContains(t, raw, "zz-so-asset-in-0")
		assert.False(t, strings.Contains(raw, "zz-so-out"), raw)
	})
}
