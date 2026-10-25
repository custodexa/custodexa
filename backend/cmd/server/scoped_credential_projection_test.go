package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// scProjection 範圍化投影的資料集：範圍內三十筆、範圍外三十筆、全域一筆，
// 另有專用憑證、掛載跨範圍的共用憑證與數個角色不同的主體。
type scProjection struct {
	*scEnv
	inIDs, outIDs map[uint]bool
	globalID      uint
	dedIn, dedOut uint
	mixID         uint // 歸屬範圍內，掛範圍內 2 台、範圍外 3 台
	wideID        uint // 歸屬範圍內，掛 a-in 與 a-out
	aIn, aOut     uint
	viewer        uint // 範圍內：檢視、改中繼資料、改密、輪替、掛載、卸載、轉換（無刪除）
	deleter       uint // 範圍內：檢視、刪除、改中繼資料
	wide          uint // 檢視涵蓋兩個節點，操作能力只在範圍內節點
	super         uint
}

func newSCProjection(t *testing.T) *scProjection {
	t.Helper()
	e := newSCEnv(t)
	p := &scProjection{scEnv: e, inIDs: map[uint]bool{}, outIDs: map[uint]bool{}}
	e.node("zz-sc-in", "")
	e.node("zz-sc-in/kid", "zz-sc-in")
	e.node("zz-sc-out", "")
	p.aIn = e.asset("zz-sc-asset-in-1", "zz-sc-in/kid")
	a2 := e.asset("zz-sc-asset-in-2", "zz-sc-in")
	p.aOut = e.asset("zz-sc-asset-out-1", "zz-sc-out")
	o2 := e.asset("zz-sc-asset-out-2", "zz-sc-out")
	o3 := e.asset("zz-sc-asset-out-3", "zz-sc-out")
	for i := 0; i < 30; i++ {
		p.inIDs[e.cred(fmt.Sprintf("zz-sc-n%02d-in", i), e.nodeID("zz-sc-in"))] = true
		p.outIDs[e.cred(fmt.Sprintf("zz-sc-n%02d-out", i), e.nodeID("zz-sc-out"))] = true
	}
	p.globalID = e.cred("zz-sc-global", nil)
	p.dedIn = e.dedicated(p.aIn)
	p.dedOut = e.dedicated(p.aOut)
	p.mixID = e.cred("zz-sc-mix", e.nodeID("zz-sc-in"))
	for _, a := range []uint{p.aIn, a2, p.aOut, o2, o3} {
		e.mount(p.mixID, a)
	}
	p.wideID = e.cred("zz-sc-wide", e.nodeID("zz-sc-in"))
	e.mount(p.wideID, p.aIn)
	e.mount(p.wideID, p.aOut)

	p.viewer = e.user("zz-sc-viewer")
	e.grant(p.viewer, []string{"zz-sc-in"}, authz.PermCredentialView, authz.PermCredentialUpdate,
		authz.PermCredentialSetSecret, authz.PermCredentialRotate, authz.PermCredentialBind,
		authz.PermCredentialDetach, authz.PermCredentialConvertScope)
	p.deleter = e.user("zz-sc-deleter")
	e.grant(p.deleter, []string{"zz-sc-in"}, authz.PermCredentialView, authz.PermCredentialDelete,
		authz.PermCredentialUpdate)
	p.wide = e.user("zz-sc-wide-user")
	e.grant(p.wide, []string{"zz-sc-in", "zz-sc-out"}, authz.PermCredentialView)
	e.grant(p.wide, []string{"zz-sc-in"}, authz.PermCredentialUpdate, authz.PermCredentialBind,
		authz.PermCredentialDetach)
	p.super = e.super
	return p
}

func TestScopedCredentialProjection(t *testing.T) {
	p := newSCProjection(t)

	t.Run("列表先套範圍再搜尋篩選與切頁", func(t *testing.T) {
		// 範圍內三十筆（命名 zz-sc-nXX-in）加兩筆專用憑證中範圍內的一筆、mix、wide 都在範圍內
		all := p.list(p.viewer, "page_size=200")
		for id := range all.ids() {
			require.False(t, p.outIDs[id], "範圍外憑證 %d 不得出現", id)
			require.NotEqual(t, p.globalID, id)
			require.NotEqual(t, p.dedOut, id)
		}
		for id := range p.inIDs {
			require.True(t, all.ids()[id], "範圍內憑證 %d 應出現", id)
		}
		require.True(t, all.ids()[p.dedIn])
		require.Equal(t, 30+3, all.Total, "範圍內三十筆加專用一筆加 mix 與 wide")
		require.Equal(t, all.Total, len(all.Data))

		// 搜尋 zz-sc-n1：範圍內外各十筆符合，只回範圍內十筆；第二頁與 total 只含範圍內
		hit := p.list(p.viewer, "search=zz-sc-n1&page_size=200")
		require.Equal(t, 10, hit.Total)
		page2 := p.list(p.viewer, "search=zz-sc-n1&page=2&page_size=4")
		require.Equal(t, 10, page2.Total)
		require.Len(t, page2.Data, 4)
		for id := range page2.ids() {
			require.True(t, p.inIDs[id])
		}
		page3 := p.list(p.viewer, "search=zz-sc-n1&page=3&page_size=4")
		require.Len(t, page3.Data, 2)

		// rotation_state 在範圍之後：偶數識別為逾期，只算範圍內者
		over := p.list(p.viewer, "rotation_state=overdue&page_size=200")
		for id := range over.ids() {
			require.True(t, id%2 == 0 && !p.outIDs[id])
		}
		wantOver := 0
		for id := range all.ids() {
			if id%2 == 0 {
				wantOver++
			}
		}
		require.Equal(t, wantOver, over.Total)
	})

	t.Run("歸屬與節點篩選", func(t *testing.T) {
		require.Equal(t, 0, p.list(p.viewer, "ownership=global").Total, "全域歸屬在範圍外")
		require.Equal(t, 0, p.list(p.viewer, fmt.Sprintf("owner_node_id=%d", p.nodes["zz-sc-out"])).Total)
		in := p.list(p.viewer, fmt.Sprintf("ownership=node&owner_node_id=%d&page_size=200", p.nodes["zz-sc-in"]))
		require.Equal(t, 32, in.Total, "範圍內節點歸屬：三十筆加 mix 與 wide")
		ded := p.list(p.viewer, "ownership=asset&page_size=200")
		require.Equal(t, map[uint]bool{p.dedIn: true}, ded.ids(), "範圍內與範圍外資產的專用憑證只出現前者")
	})

	t.Run("範圍外與不存在憑證同形", func(t *testing.T) {
		missing := uint(999991)
		for _, id := range []uint{p.globalID, idsFirst(p.outIDs), p.dedOut, missing} {
			for _, rq := range [][2]string{
				{"GET", credPath(id)},
				{"GET", credPath(id) + "/rotations/1"},
				{"PUT", credPath(id)},
				{"POST", credPath(id) + "/secret"},
				{"POST", credPath(id) + "/scope"},
				{"POST", credPath(id) + "/bindings"},
			} {
				body := ""
				switch {
				case rq[0] == "PUT":
					body = `{"note":"x"}`
				case strings.HasSuffix(rq[1], "/secret"):
					body = `{"password":"zz-new-pw"}`
				case strings.HasSuffix(rq[1], "/scope"):
					body = `{"scope":"dedicated"}`
				case strings.HasSuffix(rq[1], "/bindings"):
					body = fmt.Sprintf(`{"asset_id":%d}`, p.aIn)
				}
				wantCode, wantBody := p.call(p.viewer, rq[0], strings.Replace(rq[1], fmt.Sprint(id), fmt.Sprint(missing), 1), body)
				code, raw := p.call(p.viewer, rq[0], rq[1], body)
				require.Equal(t, wantCode, code, "%s %s", rq[0], rq[1])
				require.Equal(t, wantBody, raw, "%s %s", rq[0], rq[1])
				require.NotEqual(t, http.StatusOK, code)
			}
		}
		// 刪除走另一個主體（viewer 無刪除能力）
		for _, id := range []uint{p.globalID, idsFirst(p.outIDs)} {
			wantCode, wantBody := p.call(p.deleter, "DELETE", credPath(missing), "")
			code, raw := p.call(p.deleter, "DELETE", credPath(id), "")
			require.Equal(t, wantCode, code)
			require.Equal(t, wantBody, raw)
		}
		var n int64
		require.NoError(t, p.db.Model(&model.Credential{}).Where("id = ?", p.globalID).Count(&n).Error)
		require.EqualValues(t, 1, n, "範圍外刪除不得動到資料")
	})

	t.Run("在集合內等於單筆放行", func(t *testing.T) {
		for _, uid := range []uint{p.viewer, p.wide} {
			listed := p.list(uid, "page_size=200").ids()
			var creds []model.Credential
			require.NoError(t, p.db.Select("id").Find(&creds).Error)
			for _, c := range creds {
				code, _ := p.call(uid, "GET", credPath(c.ID), "")
				require.Equal(t, listed[c.ID], code == http.StatusOK, "主體 %d 憑證 %d", uid, c.ID)
			}
		}
	})

	t.Run("讀取審計列數與全域主體相同且全域回應不含範圍化欄位", func(t *testing.T) {
		count := func() int64 { return countAuditRows(t, p.db) }
		b := count()
		p.list(p.viewer, "")
		scoped := count() - b
		b = count()
		sup := p.list(p.super, "page_size=200")
		require.Equal(t, scoped, count()-b, "讀取審計列數與主體種類無關")
		for _, r := range sup.Data {
			_, hasActions := r["actions"]
			require.False(t, hasActions, "全域主體無 actions 鍵")
			require.Empty(t, outCountOf(r), "全域主體無範圍外台數鍵")
			require.Contains(t, r, "ownership")
		}
		var dbTotal int64
		require.NoError(t, p.db.Model(&model.Credential{}).Count(&dbTotal).Error)
		require.EqualValues(t, dbTotal, sup.Total, "全域主體看到全部")
	})

	t.Run("掛載數與清單只計範圍內並給範圍外台數", func(t *testing.T) {
		l := p.list(p.viewer, "page_size=200")
		row := l.row(p.mixID)
		require.EqualValues(t, 2, row["binding_count"])
		require.Equal(t, scOutCountJSON(3), outCountOf(row))

		code, raw := p.call(p.viewer, "GET", credPath(p.mixID), "")
		require.Equal(t, http.StatusOK, code, raw)
		var detail struct {
			Data map[string]any `json:"data"`
		}
		require.NoError(t, json.Unmarshal([]byte(raw), &detail))
		bindings, _ := detail.Data["bindings"].([]any)
		require.Len(t, bindings, 2)
		require.Equal(t, scOutCountJSON(3), outCountOf(detail.Data))

		// 刪除被拒：名單兩筆、範圍外台數 3
		code, raw = p.call(p.deleter, "DELETE", credPath(p.mixID), "")
		require.Equal(t, http.StatusConflict, code, raw)
		var inUse map[string]any
		require.NoError(t, json.Unmarshal([]byte(raw), &inUse))
		require.Len(t, inUse["assets"], 2)
		require.Equal(t, scOutCountJSON(3), outCountOf(inUse))

		for _, body := range []string{l.raw, raw} {
			require.NotContains(t, body, "zz-sc-out")
			require.NotContains(t, body, "zz-sc-asset-out")
		}
		require.NotContains(t, string(mustJSON(detail.Data)), "zz-sc-out")

		// 全域主體回應無範圍外台數鍵
		code, raw = p.call(p.super, "GET", credPath(p.mixID), "")
		require.Equal(t, http.StatusOK, code)
		require.NotContains(t, raw, disclosureFieldName())
	})

	t.Run("列級旗標", func(t *testing.T) {
		l := p.list(p.viewer, "page_size=200")
		acts := l.row(p.mixID)["actions"].(map[string]any)
		require.Equal(t, true, acts["edit"].(map[string]any)["allowed"])
		del := acts["delete"].(map[string]any)
		require.Equal(t, false, del["allowed"])
		require.Equal(t, "no_capability", del["reason"])
		require.NotContains(t, string(mustJSON(acts)), "zz-sc-")

		// 旗標不可操作的刪除直接送出仍被伺服器拒絕
		code, _ := p.call(p.viewer, "DELETE", credPath(p.wideID), "")
		require.NotEqual(t, http.StatusNoContent, code)
		var n int64
		require.NoError(t, p.db.Model(&model.Credential{}).Where("id = ?", p.wideID).Count(&n).Error)
		require.EqualValues(t, 1, n)

		// 掛載列：範圍內資產可操作，檢視涵蓋但操作範圍之外的資產 unbind／detach 為 out_of_scope
		code, raw := p.call(p.wide, "GET", credPath(p.wideID), "")
		require.Equal(t, http.StatusOK, code, raw)
		var detail struct {
			Data struct {
				Bindings []struct {
					AssetID uint                      `json:"asset_id"`
					Actions map[string]map[string]any `json:"actions"`
				} `json:"bindings"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal([]byte(raw), &detail))
		require.Len(t, detail.Data.Bindings, 2)
		for _, b := range detail.Data.Bindings {
			for _, k := range []string{"unbind", "detach"} {
				a := b.Actions[k]
				if b.AssetID == p.aOut {
					require.Equal(t, false, a["allowed"], k)
					require.Equal(t, "out_of_scope", a["reason"], k)
				} else {
					require.Equal(t, true, a["allowed"], k)
				}
			}
		}
		// 該主體的檢視範圍涵蓋兩個節點：掛載列的所屬節點照實帶出，不因操作能力較窄而遮蔽
		require.Contains(t, raw, `"node_paths":["zz-sc-out"]`)
	})

	t.Run("多掛載專用憑證以最早一筆掛載判定", func(t *testing.T) {
		t.Run("SQLite", func(t *testing.T) {
			assertDedicatedFirstMountProjection(t, newSCEnv(t))
		})
		t.Run("PostgreSQL", func(t *testing.T) {
			assertDedicatedFirstMountProjection(t, newSCEnvPG(t, "sc_first_mount"))
		})
	})

	t.Run("四種邊界例", func(t *testing.T) {
		// (a) 全域檢視加節點更新：列表含全部憑證，範圍外歸屬列 edit 為 out_of_scope
		a := p.user("zz-sc-edge-a")
		p.grantGlobal(a, p.role(authz.PermCredentialView))
		p.grant(a, []string{"zz-sc-in"}, authz.PermCredentialUpdate)
		la := p.list(a, "page_size=200")
		require.Equal(t, p.list(p.super, "page_size=200").Total, la.Total)
		out := la.row(idsFirst(p.outIDs))["actions"].(map[string]any)["edit"].(map[string]any)
		require.Equal(t, false, out["allowed"])
		require.Equal(t, "out_of_scope", out["reason"])
		in := la.row(idsFirst(p.inIDs))["actions"].(map[string]any)["edit"].(map[string]any)
		require.Equal(t, true, in["allowed"])

		// (b) 只持節點更新、無檢視：列表被拒
		b := p.user("zz-sc-edge-b")
		p.grant(b, []string{"zz-sc-in"}, authz.PermCredentialUpdate)
		codeB, rawB := p.call(b, "GET", "/api/v1/credentials", "")
		require.Equal(t, http.StatusForbidden, codeB, rawB)

		// (c) 唯一檢視指派已失效（綁定的節點已不存在）：同一個拒絕、本文與 (b) 逐欄相同
		c := p.user("zz-sc-edge-c")
		p.node("zz-sc-gone", "")
		p.grant(c, []string{"zz-sc-gone"}, authz.PermCredentialView)
		require.NoError(t, p.db.Delete(&model.AssetGroup{}, p.nodes["zz-sc-gone"]).Error)
		codeC, rawC := p.call(c, "GET", "/api/v1/credentials", "")
		require.Equal(t, codeB, codeC)
		require.Equal(t, rawB, rawC)

		// (d) 另持一筆仍有效的節點檢視：只計該範圍內，不含全域與失效範圍
		d := p.user("zz-sc-edge-d")
		p.node("zz-sc-gone2", "")
		p.grant(d, []string{"zz-sc-gone2"}, authz.PermCredentialView)
		p.grant(d, []string{"zz-sc-in"}, authz.PermCredentialView)
		require.NoError(t, p.db.Delete(&model.AssetGroup{}, p.nodes["zz-sc-gone2"]).Error)
		ld := p.list(d, "page_size=200")
		require.Equal(t, 33, ld.Total)
		require.False(t, ld.ids()[p.globalID])
		for id := range p.outIDs {
			require.False(t, ld.ids()[id])
		}
	})
}

func idsFirst(m map[uint]bool) uint {
	var best uint
	for id := range m {
		if best == 0 || id < best {
			best = id
		}
	}
	return best
}

func mustJSON(v any) []byte {
	raw, _ := json.Marshal(v)
	return raw
}
