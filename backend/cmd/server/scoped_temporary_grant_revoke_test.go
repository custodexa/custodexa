package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/policy"
)

// 臨時授權撤銷的範圍化 HTTP 夾具：請求經撤銷路由的粗閘中介層與 handler，到真實服務與真實範圍判定。
// 節點、資產名稱以 zz-tr- 起頭。

type trEnv struct {
	*saEnv
	svc *authz.AccessRequestService
}

func newTREnv(t *testing.T) *trEnv {
	t.Helper()
	base := newSAEnv(t)
	require.NoError(t, base.db.AutoMigrate(&model.AccessRequest{}, &model.AccessRequestItem{},
		&model.AccessRequestApproval{}, &model.SecurityPolicy{}, &model.AuditLog{}))
	// 授權規則管理能力需標為範圍生效，節點範圍指派才會被物化
	cat, err := authz.CatalogueWithScopedEnforcedForTest(append(append([]authz.Permission{}, saPerms...), authz.PermAuthorizationManage)...)
	require.NoError(t, err)
	base.cat = cat
	base.eval = authz.NewScopeEvaluator(cat, asset.NewScopeTopologyReader())
	e := &trEnv{saEnv: base}
	e.svc = e.service(audit.NewTxSink())
	return e
}

func (e *trEnv) service(sink port.TxSink) *authz.AccessRequestService {
	svc := authz.NewAccessRequestService(e.db, policy.NewSecurityPolicyService(e.db), nil, nil, nil)
	svc.SetRevokeScope(authz.NewAuthorizationWriteScope(authz.NewAuthorizationScopeEvaluator(e.cat, asset.NewScopeTopologyReader())))
	svc.SetAuditTxSink(sink)
	return svc
}

func (e *trEnv) revokeVia(svc *authz.AccessRequestService, uid, requestID, itemID uint) (int, string) {
	e.t.Helper()
	return e.serveRevoke(svc, false, uid, requestID, itemID)
}

// revokeAudited 同 revoke，但最外層掛真的審計中介層（同步寫入），供讀回該請求的審計列。
func (e *trEnv) revokeAudited(uid, requestID uint) (int, string) {
	e.t.Helper()
	return e.serveRevoke(e.svc, true, uid, requestID, 0)
}

func (e *trEnv) serveRevoke(svc *authz.AccessRequestService, audited bool, uid, requestID, itemID uint) (int, string) {
	e.t.Helper()
	r := gin.New()
	if audited {
		r.Use(middleware.AuditLogMiddleware(newCoverageAuditService()))
	}
	r.Use(func(c *gin.Context) {
		c.Set("userID", uid)
		c.Set("username", fmt.Sprintf("u%d", uid))
		c.Next()
	})
	h := api.NewAccessRequestHandler(svc, nil, e.db)
	r.POST("/api/v1/access-requests/:id/revoke", middleware.RequireRevokeEligibilityOn(e.db, e.cat), h.Revoke)
	body := `{"note":"zz-tr-note"}`
	if itemID != 0 {
		body = fmt.Sprintf(`{"note":"zz-tr-note","item_id":%d}`, itemID)
	}
	req := httptest.NewRequest("POST", fmt.Sprintf("/api/v1/access-requests/%d/revoke", requestID), strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

func (e *trEnv) revoke(uid, requestID, itemID uint) (int, string) {
	return e.revokeVia(e.svc, uid, requestID, itemID)
}

// trTask 一張申請單的種子：items 為 (資產, 狀態) 序列；approvedBy 為原核准人（0＝自動核准）。
type trItem struct {
	assetID uint
	pending bool
}

type trTask struct {
	reqID   uint
	itemIDs []uint
	authIDs []uint // 與 itemIDs 對齊；待審項為 0
}

func (e *trEnv) task(requester, approvedBy uint, items ...trItem) trTask {
	e.t.Helper()
	now := time.Now()
	dur := 60
	start := now.Add(-time.Minute)
	expire := now.Add(time.Hour)
	req := model.AccessRequest{RequesterID: requester, AssetID: items[0].assetID, Reason: "zz-tr", Kind: "normal",
		RequestedDurationMinutes: dur, Status: model.AccessRequestPending, PendingExpiresAt: now.Add(time.Hour)}
	if approvedBy != 0 {
		req.ApproverID = &approvedBy
	}
	require.NoError(e.t, e.db.Create(&req).Error)
	require.NoError(e.t, e.db.Model(&req).Update("status", model.AccessRequestApproved).Error)
	out := trTask{reqID: req.ID}
	for _, it := range items {
		item := model.AccessRequestItem{RequestID: req.ID, RequesterID: requester, AssetID: it.assetID,
			Accounts: model.AccountScope{model.AccountScopeAll}, Status: model.AccessRequestPending, PolicySnapshot: "{}"}
		authID := uint(0)
		if !it.pending {
			a := model.AssetAuthorization{UserID: &requester, AssetID: ptr(it.assetID), Permission: model.PermissionConnect,
				GrantedBy: e.super, Source: model.AuthorizationSourceTicket, DateStart: &start, DateExpired: &expire,
				Accounts: model.AccountScope{model.AccountScopeAll}}
			require.NoError(e.t, e.db.Create(&a).Error)
			authID = a.ID
			item.AuthorizationID = &a.ID
			item.ApprovedDurationMinutes = &dur
			item.ApprovedDateStart = &start
			if approvedBy != 0 {
				item.DecidedBy = &approvedBy
			}
		}
		// 項目只能以待審建立（模型建立前檢查），核准狀態於建立後再轉
		approved := item.AuthorizationID != nil
		require.NoError(e.t, e.db.Create(&item).Error)
		if approved {
			require.NoError(e.t, e.db.Model(&item).Update("status", model.AccessRequestApproved).Error)
		}
		out.itemIDs = append(out.itemIDs, item.ID)
		out.authIDs = append(out.authIDs, authID)
	}
	return out
}

func ptr[T any](v T) *T { return &v }

func (e *trEnv) ticketAlive(authID uint) bool {
	var n int64
	require.NoError(e.t, e.db.Model(&model.AssetAuthorization{}).Where("id = ?", authID).Count(&n).Error)
	return n == 1
}

func (e *trEnv) itemStatus(itemID uint) model.AccessRequestStatus {
	var it model.AccessRequestItem
	require.NoError(e.t, e.db.First(&it, itemID).Error)
	return it.Status
}

func (e *trEnv) revokeAuditRows(reqID uint) []model.AuditLog {
	var rows []model.AuditLog
	require.NoError(e.t, e.db.Where("resource = ? AND resource_id = ? AND action = ?",
		model.ResourceAccessRequest, reqID, model.ActionRevoke).Find(&rows).Error)
	return rows
}

// unchanged 票證與任務項皆未變。
func (e *trEnv) unchanged(tk trTask) {
	e.t.Helper()
	for i, id := range tk.itemIDs {
		if tk.authIDs[i] != 0 {
			require.True(e.t, e.ticketAlive(tk.authIDs[i]))
			require.Equal(e.t, model.AccessRequestApproved, e.itemStatus(id))
		} else {
			require.Equal(e.t, model.AccessRequestPending, e.itemStatus(id))
		}
	}
	require.Empty(e.t, e.revokeAuditRows(tk.reqID))
}

// trFrozenRevokeDenial 撤銷路由能力拒絕的凍結形狀（取自基準的核可差異檔）：
// 回應的錯誤碼、鍵集與訊息，以及審計 details 新增的鍵值。
type trFrozenRevokeDenial struct {
	code, message string
	keys          []string
	details       map[string]string
}

func loadFrozenRevokeDenial(t *testing.T) trFrozenRevokeDenial {
	t.Helper()
	const route = "POST /api/v1/access-requests/:id/revoke"
	raw, err := os.ReadFile(filepath.Join(authzBaselineDir, "approved-diffs.json"))
	require.NoError(t, err)
	var doc struct {
		Entries []struct {
			Status   string `json:"status"`
			Selector struct {
				Keys       []string `json:"keys"`
				FromStatus []int    `json:"from_status"`
				Fields     []string `json:"fields"`
			} `json:"selector"`
			Expect struct {
				Status int `json:"status"`
				Error  *struct {
					Code    string   `json:"code"`
					Keys    []string `json:"keys"`
					Message string   `json:"message"`
				} `json:"error"`
				AuditEdit *struct {
					DetailsAddedKeys []struct {
						Count int `json:"count"`
						// 其他路由的項目可能有數值，撤銷路由的值在下方逐一斷言為字串
						Match map[string]any `json:"match"`
						Keys  []string       `json:"keys"`
					} `json:"details_added_keys"`
				} `json:"audit_edit"`
			} `json:"expect"`
		} `json:"entries"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))
	var out trFrozenRevokeDenial
	errorHits, auditHits := 0, 0
	for _, en := range doc.Entries {
		if en.Status != "active" || !slices.Contains(en.Selector.Keys, route) || !slices.Contains(en.Selector.FromStatus, http.StatusForbidden) {
			continue
		}
		// 能力拒絕的回應形狀：同時改狀態與錯誤欄的那一筆（另一筆只改資格拒絕的訊息）
		if en.Expect.Error != nil && slices.Contains(en.Selector.Fields, "status") {
			require.Equal(t, http.StatusForbidden, en.Expect.Status)
			out.code, out.message = en.Expect.Error.Code, en.Expect.Error.Message
			out.keys = append([]string{}, en.Expect.Error.Keys...)
			sort.Strings(out.keys)
			errorHits++
		}
		if en.Expect.AuditEdit != nil {
			require.Len(t, en.Expect.AuditEdit.DetailsAddedKeys, 1)
			add := en.Expect.AuditEdit.DetailsAddedKeys[0]
			require.Equal(t, 1, add.Count)
			out.details = map[string]string{}
			for k, v := range add.Match {
				sv, ok := v.(string)
				require.True(t, ok, "撤銷路由凍結的 details 值須為字串：%s=%v", k, v)
				out.details[strings.TrimPrefix(k, "details.")] = sv
			}
			require.ElementsMatch(t, add.Keys, denialKeysOf(out.details))
			auditHits++
		}
	}
	require.Equal(t, 1, errorHits, "凍結的能力拒絕回應形狀須恰一筆")
	require.Equal(t, 1, auditHits, "凍結的能力拒絕審計形狀須恰一筆")
	return out
}

type failingTxSink struct{}

func (failingTxSink) WriteInTx(*gorm.DB, port.AuditEvent) error { return errors.New("audit sink down") }

func TestScopedTemporaryGrantRevoke(t *testing.T) {
	e := newTREnv(t)
	e.node("zz-tr-a", "")
	e.node("zz-tr-b", "zz-tr-a")
	e.node("zz-tr-c", "")
	x := e.asset("zz-tr-x", "zz-tr-b")
	x2 := e.asset("zz-tr-x2", "zz-tr-b")
	y := e.asset("zz-tr-y", "zz-tr-c")
	requester := e.user("zz-tr-requester")
	approver := e.user("zz-tr-approver")
	e.builtin(approver, model.RoleApprover)
	op := e.user("zz-tr-op")
	e.grantNodes(op, e.role(authz.PermAuthorizationManage), "zz-tr-a")
	other := e.user("zz-tr-other-cap")
	e.grantGlobal(other, e.role(authz.PermAssetView))
	globalHolder := e.user("zz-tr-global-holder")
	e.grantGlobal(globalHolder, e.role(authz.PermAuthorizationManage))
	const forbiddenBody = "AUTH_PERMISSION_DENIED"
	const notEligible = "RULE_ACCESS_TICKET_NOT_REVOKE_ELIGIBLE"

	t.Run("in scope capability holder revokes another approvers ticket", func(t *testing.T) {
		tk := e.task(requester, approver, trItem{assetID: x})
		code, body := e.revoke(op, tk.reqID, 0)
		require.Equal(t, http.StatusOK, code, body)
		require.False(t, e.ticketAlive(tk.authIDs[0]))
		var it model.AccessRequestItem
		require.NoError(t, e.db.First(&it, tk.itemIDs[0]).Error)
		require.Equal(t, model.AccessRequestItemRevoked, it.Status)
		require.NotNil(t, it.RevokedBy)
		require.Equal(t, op, *it.RevokedBy)
		rows := e.revokeAuditRows(tk.reqID)
		require.Len(t, rows, 1)
		require.Equal(t, op, rows[0].UserID)
		require.Contains(t, rows[0].Details, fmt.Sprintf(`"authorization_id":%d`, tk.authIDs[0]))
		require.Contains(t, rows[0].Details, fmt.Sprintf(`"revoked_item_ids":[%d]`, tk.itemIDs[0]))
	})
	t.Run("out of scope asset is not eligible and nothing changes", func(t *testing.T) {
		tk := e.task(requester, approver, trItem{assetID: y})
		code, body := e.revoke(op, tk.reqID, 0)
		require.Equal(t, http.StatusForbidden, code, body)
		require.Contains(t, body, notEligible)
		e.unchanged(tk)
	})
	t.Run("whole request with an out of scope item is refused then single in scope item succeeds", func(t *testing.T) {
		tk := e.task(requester, approver, trItem{assetID: x2}, trItem{assetID: y})
		code, body := e.revoke(op, tk.reqID, 0)
		require.Equal(t, http.StatusForbidden, code, body)
		require.Contains(t, body, notEligible)
		e.unchanged(tk)
		code, body = e.revoke(op, tk.reqID, tk.itemIDs[0])
		require.Equal(t, http.StatusOK, code, body)
		require.False(t, e.ticketAlive(tk.authIDs[0]))
		require.True(t, e.ticketAlive(tk.authIDs[1]))
		require.Equal(t, model.AccessRequestApproved, e.itemStatus(tk.itemIDs[1]))
	})
	t.Run("pending sibling outside scope blocks whole request revoke", func(t *testing.T) {
		tk := e.task(requester, approver, trItem{assetID: x}, trItem{assetID: y, pending: true})
		code, body := e.revoke(op, tk.reqID, 0)
		require.Equal(t, http.StatusForbidden, code, body)
		require.Contains(t, body, notEligible)
		e.unchanged(tk)
	})
	t.Run("pending sibling inside scope is retired with the whole request", func(t *testing.T) {
		tk := e.task(requester, approver, trItem{assetID: x}, trItem{assetID: x2, pending: true})
		code, body := e.revoke(op, tk.reqID, 0)
		require.Equal(t, http.StatusOK, code, body)
		require.False(t, e.ticketAlive(tk.authIDs[0]))
		require.Equal(t, model.AccessRequestItemRevoked, e.itemStatus(tk.itemIDs[1]))
	})
	t.Run("only another capability is refused at the coarse gate", func(t *testing.T) {
		tk := e.task(requester, approver, trItem{assetID: x})
		code, body := e.revoke(other, tk.reqID, 0)
		require.Equal(t, http.StatusForbidden, code, body)
		require.Contains(t, body, forbiddenBody)
		require.NotContains(t, body, notEligible)
		e.unchanged(tk)
	})
	t.Run("coarse gate refusal matches the frozen shape field by field", func(t *testing.T) {
		frozen := loadFrozenRevokeDenial(t)
		require.Equal(t, forbiddenBody, frozen.code)
		ensureDenialAuditTable(t, e.db)
		tk := e.task(requester, approver, trItem{assetID: x})
		before := countAuditRows(t, e.db)
		code, body := e.revokeAudited(other, tk.reqID)
		require.Equal(t, http.StatusForbidden, code, body)
		var resp map[string]any
		require.NoError(t, json.Unmarshal([]byte(body), &resp), body)
		keys := make([]string, 0, len(resp))
		for k := range resp {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		require.Equal(t, frozen.keys, keys, "回應只有凍結的鍵（無 params）：%s", body)
		require.Equal(t, frozen.code, resp["code"])
		require.Equal(t, frozen.message, resp["error"])
		require.Equal(t, before+1, countAuditRows(t, e.db))
		var row model.AuditLog
		require.NoError(t, e.db.Unscoped().Order("id desc").First(&row).Error)
		require.Equal(t, model.StatusDenied, row.Status)
		require.Equal(t, http.StatusForbidden, row.StatusCode)
		require.Equal(t, other, row.UserID)
		gotNew, gotExisting := splitDenialDetails(t, row.Details)
		require.Equal(t, frozen.details, gotNew, row.Details)
		require.Empty(t, gotExisting, row.Details)
		// 票證與任務項不變；此處的審計列是中介層記下的拒絕列，不是撤銷列
		require.True(t, e.ticketAlive(tk.authIDs[0]))
		require.Equal(t, model.AccessRequestApproved, e.itemStatus(tk.itemIDs[0]))
		rows := e.revokeAuditRows(tk.reqID)
		require.Len(t, rows, 1)
		require.Equal(t, row.ID, rows[0].ID)
	})
	t.Run("asset moved out of scope before revoke is judged by the new scope", func(t *testing.T) {
		moved := e.asset("zz-tr-moved", "zz-tr-b")
		tk := e.task(requester, approver, trItem{assetID: moved})
		require.NoError(t, e.db.Model(&model.AssetNode{}).Where("asset_id = ?", moved).Update("node_id", e.nodes["zz-tr-c"]).Error)
		code, body := e.revoke(op, tk.reqID, 0)
		require.Equal(t, http.StatusForbidden, code, body)
		require.Contains(t, body, notEligible)
		e.unchanged(tk)
	})
	t.Run("existing holders keep their eligibility", func(t *testing.T) {
		own := e.task(requester, approver, trItem{assetID: y})
		code, body := e.revoke(approver, own.reqID, 0)
		require.Equal(t, http.StatusOK, code, body)
		require.False(t, e.ticketAlive(own.authIDs[0]))

		sup := e.task(requester, approver, trItem{assetID: y})
		code, body = e.revoke(e.super, sup.reqID, 0)
		require.Equal(t, http.StatusOK, code, body)

		notOwn := e.task(requester, e.user("zz-tr-other-approver"), trItem{assetID: y})
		code, body = e.revoke(approver, notOwn.reqID, 0)
		require.Equal(t, http.StatusForbidden, code, body)
		require.Contains(t, body, notEligible)
		e.unchanged(notOwn)
	})
	t.Run("global capability holder revokes any asset", func(t *testing.T) {
		tk := e.task(requester, approver, trItem{assetID: y})
		code, body := e.revoke(globalHolder, tk.reqID, 0)
		require.Equal(t, http.StatusOK, code, body)
		require.False(t, e.ticketAlive(tk.authIDs[0]))
	})
	t.Run("audit write failure rolls the whole revoke back", func(t *testing.T) {
		tk := e.task(requester, approver, trItem{assetID: x}, trItem{assetID: x2})
		code, body := e.revokeVia(e.service(failingTxSink{}), op, tk.reqID, 0)
		require.GreaterOrEqual(t, code, http.StatusInternalServerError, body)
		e.unchanged(tk)
		var req model.AccessRequest
		require.NoError(t, e.db.First(&req, tk.reqID).Error)
		require.Nil(t, req.RevokedAt)
	})
	t.Run("typed nil or absent sink is refused by the assembly gate", func(t *testing.T) {
		svc := authz.NewAccessRequestService(e.db, nil, nil, nil, nil)
		require.Error(t, svc.RequireRevokeWiring())
	})
}
