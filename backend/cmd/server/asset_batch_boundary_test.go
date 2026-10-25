package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 資產批次操作（搬移、加標籤、刪除）的共用邊界，經正式 handler、審計中介層與真判定器。
//
//	go test ./cmd/server/ -run '^TestAssetBatchBoundary$' -count=1 -v

// sbTopo 計次的拓撲窄 port：記 begin 與推進權限版本的呼叫次數。
type sbTopo struct{ begins, advances atomic.Int32 }

func (p *sbTopo) LockTopology(*gorm.DB) error           { return nil }
func (p *sbTopo) BeginPermissionChange(*gorm.DB) error  { p.begins.Add(1); return nil }
func (p *sbTopo) AdvanceVersion(*gorm.DB) error         { p.advances.Add(1); return nil }
func (p *sbTopo) SettlePermissionChange(*gorm.DB) error { return nil }

type sbEnv struct {
	*saEnv
	topo *sbTopo
}

func newSBEnv(t *testing.T) *sbEnv {
	t.Helper()
	e := newSAEnv(t)
	saTree(e)
	topo := &sbTopo{}
	e.assets.SetTopologyPermissionPort(topo)
	// 刪除的級聯撤銷面與組裝根相同（未注入時資產刪除 fail-close）
	e.assets.SetAuthorizationRevoker(e.authzSvc)
	return &sbEnv{saEnv: e, topo: topo}
}

const sbMissingNode uint = 999917

var sbActions = []string{"move", "tags", "delete"}

// sbPost 送出一次批次請求；move 的目的節點由 target 指定。
func sbPost(e *sbEnv, uid uint, action string, ids []uint, target uint) (int, string) {
	idsJSON, _ := json.Marshal(ids)
	var body string
	switch action {
	case "move":
		body = fmt.Sprintf(`{"asset_ids":%s,"target_node_id":%d}`, idsJSON, target)
	case "tags":
		body = fmt.Sprintf(`{"asset_ids":%s,"tags":["sb-new-tag"]}`, idsJSON)
	default:
		body = fmt.Sprintf(`{"asset_ids":%s}`, idsJSON)
	}
	return e.do(uid, true, "POST", "/api/v1/assets/batch/"+action, body)
}

// sbState 一組資產的可觀測狀態：歸屬、標籤、是否仍存在，以及全庫授權列數。
type sbState struct {
	Mounts map[uint][]string
	Tags   map[uint]string
	Live   map[uint]bool
	Grants int64
}

func sbSnap(t *testing.T, e *sbEnv, ids ...uint) sbState {
	t.Helper()
	s := sbState{Mounts: map[uint][]string{}, Tags: map[uint]string{}, Live: map[uint]bool{}}
	for _, id := range ids {
		s.Mounts[id] = saMounted(t, e.saEnv, id)
		var a model.Asset
		require.NoError(t, e.db.Where("id = ?", id).Limit(1).Find(&a).Error)
		s.Live[id] = a.ID == id
		s.Tags[id] = a.Tags
	}
	require.NoError(t, e.db.Model(&model.AssetAuthorization{}).Count(&s.Grants).Error)
	return s
}

func sbLastAudit(t *testing.T, e *sbEnv) model.AuditLog {
	t.Helper()
	var row model.AuditLog
	require.NoError(t, e.db.Unscoped().Order("id desc").First(&row).Error)
	return row
}

// sbRequireSingleRow 該請求恰多一列審計，回傳該列與拆開的拒絕細節。
func sbRequireSingleRow(t *testing.T, e *sbEnv, before int64, msg string) (model.AuditLog, map[string]string) {
	t.Helper()
	require.Equal(t, before+1, countAuditRows(t, e.db), "%s：只有一列請求審計，沒有逐列資產變更列", msg)
	row := sbLastAudit(t, e)
	denial, _ := splitDenialDetails(t, row.Details)
	return row, denial
}

// sbMgr 只在 zz-sa-a 持檢視、編輯、刪除的範圍化管理者。
func sbMgr(e *sbEnv, name string, nodes ...string) uint {
	u := e.user(name)
	if len(nodes) == 0 {
		nodes = []string{"zz-sa-a"}
	}
	e.grantNodes(u, e.role(authz.PermAssetView, authz.PermAssetUpdate, authz.PermAssetDelete), nodes...)
	return u
}

// sbPartial 檢視範圍 A、B，但編輯與刪除只在 B：A 內資產「看得到、沒有該權限點」。
func sbPartial(e *sbEnv) uint {
	u := e.user("zz-sa-partial")
	e.grantNodes(u, e.role(authz.PermAssetView), "zz-sa-a", "zz-sa-b")
	e.grantNodes(u, e.role(authz.PermAssetUpdate, authz.PermAssetDelete), "zz-sa-b")
	return u
}

func sbAffected(t *testing.T, raw string) (affected, unchanged int) {
	t.Helper()
	var out struct {
		Data struct {
			Affected  int `json:"affected"`
			Unchanged int `json:"unchanged"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(raw), &out), raw)
	return out.Data.Affected, out.Data.Unchanged
}

func TestAssetBatchBoundary(t *testing.T) {
	// 混入一筆範圍外、一筆不存在、一筆無權（指派不含該權限點）的整批拒絕：三種原因逐位元相同。
	t.Run("unavailable_items_indistinguishable", func(t *testing.T) {
		for _, act := range sbActions {
			t.Run(act, func(t *testing.T) {
				e := newSBEnv(t)
				u := sbPartial(e)
				okB := e.asset("zz-sa-okb", "zz-sa-b")
				noPerm := e.asset("zz-sa-noperm", "zz-sa-a")
				out := e.asset("zz-sa-out", "zz-sa-c")
				target := e.nodes["zz-sa-b"]
				state0 := sbSnap(t, e, okB, noPerm, out)

				var bodies []string
				for _, bad := range []struct {
					name string
					id   uint
				}{{"no_perm", noPerm}, {"out_of_scope", out}, {"missing", 999907}} {
					before := countAuditRows(t, e.db)
					code, raw := sbPost(e, u, act, []uint{okB, bad.id}, target)
					require.Equal(t, http.StatusNotFound, code, "%s：%s", bad.name, raw)
					assert.Equal(t, string(apierror.CodeBatchItemsUnavailable), saErrorCode(t, raw), bad.name)
					assert.Contains(t, raw, `"count":1`, "%s：參數只有筆數", bad.name)
					assert.NotContains(t, raw, "zz-sa-", "%s：不含 fixture 名稱", bad.name)
					for _, id := range []uint{noPerm, out} {
						assert.False(t, regexp.MustCompile(fmt.Sprintf(`\b%d\b`, id)).MatchString(raw), "%s：不含資產 ID %d", bad.name, id)
					}
					bodies = append(bodies, raw)
					row, d := sbRequireSingleRow(t, e, before, bad.name)
					assert.Equal(t, model.StatusDenied, row.Status, bad.name)
					assert.Equal(t, "scope", d["denial"], bad.name)
					assert.Equal(t, "1", d["count"], "%s：count 等於無法操作的筆數", bad.name)
					assert.NotContains(t, row.Details, "zz-sa-", bad.name)
					assert.Equal(t, state0, sbSnap(t, e, okB, noPerm, out), "%s：被拒後資產、歸屬、標籤、授權皆不變", bad.name)
				}
				assert.JSONEq(t, bodies[0], bodies[1], "無權與範圍外逐位元相同")
				assert.JSONEq(t, bodies[0], bodies[2], "無權與不存在逐位元相同")
			})
		}
	})

	// 沒有任何含該權限點的指派：路由閘單一 forbidden；撤銷發生在批次交易之前或鎖之後，同樣單一 forbidden。
	t.Run("capability_denial_single_forbidden", func(t *testing.T) {
		for _, act := range sbActions {
			t.Run(act, func(t *testing.T) {
				e := newSBEnv(t)
				viewer := e.user("zz-sa-viewer")
				e.grantNodes(viewer, e.role(authz.PermAssetView), "zz-sa-a")
				x := e.asset("zz-sa-cap-x", "zz-sa-a")
				state0 := sbSnap(t, e, x)
				target := e.nodes["zz-sa-a"]

				before := countAuditRows(t, e.db)
				code, gateBody := sbPost(e, viewer, act, []uint{x}, target)
				require.Equal(t, http.StatusForbidden, code, gateBody)
				assert.NotContains(t, gateBody, "count")
				row, d := sbRequireSingleRow(t, e, before, "路由閘")
				assert.Equal(t, model.StatusDenied, row.Status)
				assert.Equal(t, "capability", d["denial"])
				assert.NotContains(t, d, "count")
				assert.Equal(t, state0, sbSnap(t, e, x))

				for _, when := range []string{"before_tx_other_commit", "after_lock_same_tx"} {
					e := newSBEnv(t)
					u := sbMgr(e, "zz-sa-revoked")
					y := e.asset("zz-sa-cap-y", "zz-sa-a")
					state1 := sbSnap(t, e, y)
					revoke := func(db *gorm.DB) error {
						return db.Where("user_id = ?", u).Delete(&model.UserRole{}).Error
					}
					hooks := &asset.AssetBatchTestHooks{}
					if when == "before_tx_other_commit" {
						// 批次交易取得序列化鎖之前，已另行提交撤銷
						hooks.BeforeTx = func() { require.NoError(t, revoke(e.db)) }
					} else {
						// 取得序列化鎖之後、重讀主體之前，於同一交易內移除指派
						hooks.AfterLock = func(tx *gorm.DB) error { return revoke(tx) }
					}
					e.batchHooks = hooks
					before := countAuditRows(t, e.db)
					code, raw := sbPost(e, u, act, []uint{y}, e.nodes["zz-sa-a"])
					require.Equal(t, http.StatusForbidden, code, "%s：%s", when, raw)
					assert.JSONEq(t, gateBody, raw, "%s：與路由閘同為單一 forbidden，不是批次 404", when)
					assert.NotContains(t, raw, "count", when)
					row, d := sbRequireSingleRow(t, e, before, when)
					assert.Equal(t, model.StatusDenied, row.Status, when)
					assert.Equal(t, "capability", d["denial"], when)
					assert.NotContains(t, d, "count", when)
					assert.NotContains(t, row.Details, "zz-sa-", when)
					assert.Equal(t, state1, sbSnap(t, e, y), "%s：零變更", when)
				}
			})
		}
	})

	t.Run("bad_params_400", func(t *testing.T) {
		e := newSBEnv(t)
		x := e.asset("zz-sa-bp", "zz-sa-a")
		state0 := sbSnap(t, e, x)
		for _, c := range []struct{ name, path, body string }{
			{"move_empty_ids", "move", `{"asset_ids":[],"target_node_id":1}`},
			{"move_zero_target", "move", fmt.Sprintf(`{"asset_ids":[%d],"target_node_id":0}`, x)},
			{"tags_empty_ids", "tags", `{"asset_ids":[],"tags":["a"]}`},
			{"tags_empty_tags", "tags", fmt.Sprintf(`{"asset_ids":[%d],"tags":[]}`, x)},
			{"delete_empty_ids", "delete", `{"asset_ids":[]}`},
		} {
			code, raw := e.do(e.super, true, "POST", "/api/v1/assets/batch/"+c.path, c.body)
			assert.Equal(t, http.StatusBadRequest, code, "%s：%s", c.name, raw)
			assert.Equal(t, string(apierror.CodeBadParams), saErrorCode(t, raw), c.name)
		}
		assert.Equal(t, state0, sbSnap(t, e, x), "資產不變")
	})

	// 不設筆數上限；重複 ID 只計一次。
	t.Run("no_size_limit_and_dedupe", func(t *testing.T) {
		e := newSBEnv(t)
		ids := make([]uint, 0, 1001)
		for i := 0; i < 1001; i++ {
			ids = append(ids, e.asset(fmt.Sprintf("zz-sa-bulk-%d", i), "zz-sa-a"))
		}
		code, raw := sbPost(e, e.super, "tags", ids, 0)
		require.Equal(t, http.StatusOK, code, raw)
		affected, unchanged := sbAffected(t, raw)
		assert.Equal(t, 1001, affected)
		assert.Zero(t, unchanged)

		code, raw = sbPost(e, e.super, "tags", []uint{ids[0], ids[0], ids[1]}, 0)
		require.Equal(t, http.StatusOK, code, raw)
		affected, unchanged = sbAffected(t, raw)
		assert.Zero(t, affected)
		assert.Equal(t, 2, unchanged, "重複 ID 去重後只計兩台")
	})

	// 範圍化主體的批次含一台範圍外資產：整批拒絕、只回筆數、零寫入、零逐列審計、零版本推進。
	t.Run("scoped_batch_with_out_of_scope_rejected_whole", func(t *testing.T) {
		for _, act := range sbActions {
			t.Run(act, func(t *testing.T) {
				e := newSBEnv(t)
				mgr := sbMgr(e, "zz-sa-mgr", "zz-sa-a", "zz-sa-b")
				in1 := e.asset("zz-sa-in1", "zz-sa-a")
				in2 := e.asset("zz-sa-in2", "zz-sa-a")
				out := e.asset("zz-sa-out", "zz-sa-c")
				state0 := sbSnap(t, e, in1, in2, out)
				before := countAuditRows(t, e.db)
				code, raw := sbPost(e, mgr, act, []uint{in1, in2, out}, e.nodes["zz-sa-b"])
				require.Equal(t, http.StatusNotFound, code, raw)
				assert.Contains(t, raw, `"count":1`)
				assert.NotContains(t, raw, "zz-sa-")
				sbRequireSingleRow(t, e, before, act)
				assert.Equal(t, state0, sbSnap(t, e, in1, in2, out), "零寫入")
				assert.Zero(t, e.topo.begins.Load(), "未開始任何權限相關寫入")
				assert.Zero(t, e.topo.advances.Load(), "權限版本零推進")
			})
		}
	})

	// 全域主體成功時，權限版本在該交易只推進一次（不論筆數）。
	t.Run("global_success_advances_version_once", func(t *testing.T) {
		for _, act := range []string{"move", "delete"} {
			t.Run(act, func(t *testing.T) {
				e := newSBEnv(t)
				ids := []uint{e.asset("zz-sa-g1", "zz-sa-a"), e.asset("zz-sa-g2", "zz-sa-a"), e.asset("zz-sa-g3", "zz-sa-a")}
				code, raw := sbPost(e, e.super, act, ids, e.nodes["zz-sa-b"])
				require.Equal(t, http.StatusOK, code, raw)
				affected, _ := sbAffected(t, raw)
				assert.Equal(t, 3, affected)
				assert.EqualValues(t, 1, e.topo.begins.Load(), "begin 只呼叫一次")
				assert.EqualValues(t, 1, e.topo.advances.Load(), "版本只推進一次")
			})
		}
	})

	// 同一組輸入：逐台單筆與批次的允許／拒絕結論一致，成功時結果狀態一致（比對不含 updated_at）。
	t.Run("batch_agrees_with_single", func(t *testing.T) {
		for _, act := range []string{"tags", "delete"} {
			t.Run(act, func(t *testing.T) {
				e := newSBEnv(t)
				mgr := sbMgr(e, "zz-sa-agree")
				for _, c := range []struct {
					name   string
					mounts []string
				}{
					{"in_scope", []string{"zz-sa-a"}},
					{"out_of_scope", []string{"zz-sa-c"}},
					{"mixed_attribution", []string{"zz-sa-a", "zz-sa-c"}},
					{"ungrouped", nil},
					{"missing", nil},
				} {
					bID, sID := uint(999907), uint(999908)
					if c.name != "missing" {
						bID = e.asset("zz-sa-b-"+c.name, c.mounts...)
						sID = e.asset("zz-sa-s-"+c.name, c.mounts...)
					}
					bCode, bRaw := sbPost(e, mgr, act, []uint{bID}, 0)
					var sCode int
					var sRaw string
					if act == "tags" {
						sCode, sRaw = e.do(mgr, true, "PUT", idPath(sID), `{"tags":"sb-new-tag"}`)
					} else {
						sCode, sRaw = e.do(mgr, true, "DELETE", idPath(sID), "")
					}
					bAllowed, sAllowed := bCode == http.StatusOK, sCode >= 200 && sCode < 300
					assert.Equal(t, sAllowed, bAllowed, "%s：單筆 %d %s／批次 %d %s", c.name, sCode, sRaw, bCode, bRaw)
					if !bAllowed && !sAllowed {
						assert.Equal(t, sCode, bCode, "%s：拒絕時狀態碼一致", c.name)
					}
					if bAllowed && sAllowed && c.name != "missing" {
						bs, ss := sbSnap(t, e, bID), sbSnap(t, e, sID)
						assert.Equal(t, ss.Live[sID], bs.Live[bID], c.name)
						assert.Equal(t, ss.Tags[sID], bs.Tags[bID], c.name)
						assert.Equal(t, ss.Mounts[sID], bs.Mounts[bID], c.name)
					}
				}
			})
		}
	})

	// 搬移目的節點在範圍外與不存在：回應逐位元相同，歸屬不變。
	t.Run("move_target_out_of_scope_equals_missing", func(t *testing.T) {
		e := newSBEnv(t)
		mgr := sbMgr(e, "zz-sa-mv", "zz-sa-a", "zz-sa-b")
		ac := e.asset("zz-sa-mv-ac", "zz-sa-a", "zz-sa-c")
		state0 := sbSnap(t, e, ac)
		cOut, rOut := sbPost(e, mgr, "move", []uint{ac}, e.nodes["zz-sa-c"])
		cMiss, rMiss := sbPost(e, mgr, "move", []uint{ac}, sbMissingNode)
		assert.GreaterOrEqual(t, cOut, 400, rOut)
		assert.Equal(t, cOut, cMiss)
		assert.JSONEq(t, rMiss, rOut)
		assert.Equal(t, state0, sbSnap(t, e, ac), "被拒後歸屬不變")

		code, raw := sbPost(e, mgr, "move", []uint{ac}, e.nodes["zz-sa-b"])
		require.Equal(t, http.StatusOK, code, raw)
		assert.Equal(t, []string{"zz-sa-b", "zz-sa-c"}, saMounted(t, e.saEnv, ac), "A 換成 B，範圍外的 C 保留")
	})

	// 加標籤任一台超過上限：整批回 400，請求審計一列、狀態 failure、不帶 denial。
	t.Run("tags_over_limit_single_failure_row", func(t *testing.T) {
		e := newSBEnv(t)
		full := e.asset("zz-sa-tag-full", "zz-sa-a")
		small := e.asset("zz-sa-tag-small", "zz-sa-a")
		tags := make([]string, 20)
		for i := range tags {
			tags[i] = fmt.Sprintf("t%02d", i)
		}
		require.NoError(t, e.db.Model(&model.Asset{}).Where("id = ?", full).UpdateColumn("tags", strings.Join(tags, ",")).Error)
		state0 := sbSnap(t, e, full, small)
		before := countAuditRows(t, e.db)
		code, raw := sbPost(e, e.super, "tags", []uint{small, full}, 0)
		require.Equal(t, http.StatusBadRequest, code, raw)
		row, d := sbRequireSingleRow(t, e, before, "超限")
		assert.Equal(t, model.StatusFailure, row.Status)
		assert.NotContains(t, d, "denial")
		assert.Equal(t, state0, sbSnap(t, e, full, small), "所有資產標籤不變")
	})

	// 刪除被範圍外歸屬擋下：409、只帶台數，請求審計一列 failure、不帶 denial。
	t.Run("delete_blocked_shape_and_audit", func(t *testing.T) {
		e := newSBEnv(t)
		mgr := sbMgr(e, "zz-sa-blk")
		x := e.asset("zz-sa-blk-x", "zz-sa-a", "zz-sa-c")
		y := e.asset("zz-sa-blk-y", "zz-sa-a")
		state0 := sbSnap(t, e, x, y)
		before := countAuditRows(t, e.db)
		code, raw := sbPost(e, mgr, "delete", []uint{x, y}, 0)
		require.Equal(t, http.StatusConflict, code, raw)
		assert.Equal(t, string(apierror.CodeAssetBatchHasOutOfScopeNodes), saErrorCode(t, raw))
		assert.Contains(t, raw, `"count":1`)
		assert.NotContains(t, raw, "zz-sa-")
		row, d := sbRequireSingleRow(t, e, before, "受阻")
		assert.Equal(t, model.StatusFailure, row.Status)
		assert.NotContains(t, d, "denial")
		assert.Equal(t, state0, sbSnap(t, e, x, y), "兩台資產、歸屬、授權不變")
	})
}
