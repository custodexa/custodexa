package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/testgate"
)

// TestAuthorizationScopeLockOrder 授權規則寫入與臨時授權撤銷的鎖序（PostgreSQL，不在 SQLite 跑）：
//   - 方向 A（與拓撲、節點範圍指派變更互斥）：另一連線持有拓撲序列化鎖時，五種交易各自在該鎖上等待，
//     此時等待者尚未完成任何寫入、也沒有取任何其他列鎖（建立、批次與調整帳號範圍只取主體 users 列鎖，
//     它排在拓撲鎖之前）；申請單、票證、規則與資產列仍可被第三條連線鎖走。
//   - 交錯：持鎖方是真的資產搬移或節點範圍指派撤除，後行寫入依新狀態裁決（見 runAuthorizationScopeInterleave）。
//   - 方向 B（主體 users 列鎖先於拓撲鎖）：另一連線持有主體 users 列鎖時，建立、批次與調整帳號範圍
//     在該列鎖上等待，且尚未持有拓撲鎖。
//
// 等待一律以 pg_locks 單列 count 與 pg_blocking_pids 證明（pwloProveWait），不以逾時代替。

type alsWriter struct {
	name string
	// subject 取主體 users 列鎖者（建立、批次、調整帳號範圍）；刪除與撤銷不鎖主體列
	subject uint
	// free 等待當下仍須可被第三條連線鎖走的列
	free []pwloRowRef
	run  func() error
}

func TestAuthorizationScopeLockOrder(t *testing.T) {
	if os.Getenv(testgate.EnvPGDSN) == "" && !testgate.RequireIntegration() {
		t.Skipf("%s 未設：本測試只在 PostgreSQL 跑", testgate.EnvPGDSN)
	}
	testgate.Value(t, testgate.EnvPGDSN)

	e := newPWLOEnv(t, "authorization_scope_lock_order", true, "writer", "mover")
	w := e.actor("writer")
	rec := &pwloRecorder{}
	rec.install(t, w.db)
	raw := e.selfCheckPool(t)

	principal, err := authz.ResolveUserOn(e.fix, e.root, authz.TokenFacts{})
	require.NoError(t, err)
	ctx := authz.ContextWithPrincipal(context.Background(), principal)
	scope := authz.NewAuthorizationWriteScope(authz.NewAuthorizationScopeEvaluator(authz.ProductCatalogue(), asset.NewScopeTopologyReader()))
	authSvc := authz.NewAssetAuthorizationService(w.db)
	authSvc.SetWriteScope(scope)
	reqSvc := authz.NewAccessRequestService(w.db, policy.NewSecurityPolicyService(w.db), nil, nil, nil)
	reqSvc.SetRevokeScope(scope)
	reqSvc.SetAuditTxSink(audit.NewTxSink())
	require.NoError(t, reqSvc.RequireRevokeWiring())

	node := e.newNode(t, "als")
	seq := 0
	newAsset := func() uint {
		seq++
		a := model.Asset{Name: fmt.Sprintf("als-asset-%d", seq), Host: fmt.Sprintf("10.9.8.%d", seq), Port: 22, Protocol: model.ProtocolSSH, Active: true, CreatedBy: e.root}
		require.NoError(t, e.fix.Create(&a).Error)
		require.NoError(t, e.fix.Create(&model.AssetNode{AssetID: a.ID, NodeID: node}).Error)
		return a.ID
	}
	newRule := func(subject, assetID uint) uint {
		r := model.AssetAuthorization{UserID: &subject, AssetID: &assetID, Permission: model.PermissionConnect,
			GrantedBy: e.root, Accounts: model.AccountScope{model.AccountScopeAll}}
		require.NoError(t, e.fix.Create(&r).Error)
		return r.ID
	}
	// 撤銷：原核准人（非 admin）撤銷自己核准的單，走既有資格；範圍判定因無能力為假，不影響鎖序
	newTicket := func(requester, approver, assetID uint) (reqID, itemID, authID uint) {
		now := time.Now()
		dur := 60
		start, expire := now.Add(-time.Minute), now.Add(time.Hour)
		a := model.AssetAuthorization{UserID: &requester, AssetID: &assetID, Permission: model.PermissionConnect, GrantedBy: e.root,
			Source: model.AuthorizationSourceTicket, DateStart: &start, DateExpired: &expire, Accounts: model.AccountScope{model.AccountScopeAll}}
		require.NoError(t, e.fix.Create(&a).Error)
		req := model.AccessRequest{RequesterID: requester, AssetID: assetID, Reason: "als", Kind: "normal", RequestedDurationMinutes: dur,
			Status: model.AccessRequestPending, ApproverID: &approver, PendingExpiresAt: now.Add(time.Hour)}
		require.NoError(t, e.fix.Create(&req).Error)
		require.NoError(t, e.fix.Model(&req).Update("status", model.AccessRequestApproved).Error)
		item := model.AccessRequestItem{RequestID: req.ID, RequesterID: requester, AssetID: assetID, Accounts: model.AccountScope{model.AccountScopeAll},
			Status: model.AccessRequestPending, ApprovedDurationMinutes: &dur, ApprovedDateStart: &start, DecidedBy: &approver,
			AuthorizationID: &a.ID, PolicySnapshot: "{}"}
		// 項目只能以待審建立（模型建立前檢查），核准狀態於建立後再轉
		require.NoError(t, e.fix.Create(&item).Error)
		require.NoError(t, e.fix.Model(&item).Update("status", model.AccessRequestApproved).Error)
		return req.ID, item.ID, a.ID
	}

	build := func(kind string) alsWriter {
		subject := e.human(t, fmt.Sprintf("als-subject-%s-%d", kind, seq))
		assetID := newAsset()
		switch kind {
		case "grant":
			return alsWriter{name: kind, subject: subject, free: []pwloRowRef{{"assets", assetID}}, run: func() error {
				_, err := authSvc.Grant(ctx, authz.GrantSpec{UserID: &subject, AssetID: &assetID, Permission: model.PermissionView, GrantedBy: e.root})
				return err
			}}
		case "grant_batch":
			return alsWriter{name: kind, subject: subject, free: []pwloRowRef{{"assets", assetID}}, run: func() error {
				_, err := authSvc.GrantBatch(ctx, []uint{subject}, nil, []uint{assetID}, nil, model.PermissionConnect, e.root, nil)
				return err
			}}
		case "update_accounts":
			rule := newRule(subject, assetID)
			return alsWriter{name: kind, subject: subject, free: []pwloRowRef{{"asset_authorizations", rule}, {"assets", assetID}}, run: func() error {
				_, err := authSvc.UpdateAccountScope(ctx, rule, &[]string{"root"})
				return err
			}}
		case "delete":
			rule := newRule(subject, assetID)
			return alsWriter{name: kind, free: []pwloRowRef{{"asset_authorizations", rule}, {"assets", assetID}, {"users", subject}}, run: func() error {
				return authSvc.RevokePermission(ctx, rule)
			}}
		default: // revoke
			approver := e.human(t, fmt.Sprintf("als-approver-%d", seq))
			reqID, itemID, authID := newTicket(subject, approver, assetID)
			return alsWriter{name: kind, free: []pwloRowRef{{"access_requests", reqID}, {"access_request_items", itemID}, {"asset_authorizations", authID}, {"users", subject}},
				run: func() error {
					_, err := reqSvc.RevokeItem(approver, false, "als-approver", reqID, 0, "als-note")
					return err
				}}
		}
	}

	// onlyUserRowLocks 等待當下已完成的寫入或列鎖只允許主體 users 列鎖（排在拓撲鎖之前）
	onlyUserRowLocks := func(stmts []string) []string {
		var bad []string
		for _, s := range stmts {
			l := strings.ToLower(s)
			if strings.Contains(l, `from "users"`) && strings.Contains(l, "for no key update") {
				continue
			}
			bad = append(bad, s)
		}
		return bad
	}

	kinds := []string{"grant", "grant_batch", "update_accounts", "delete", "revoke"}
	for i, kind := range kinds {
		kind := kind
		t.Run("topology_lock_holder_blocks_"+kind, func(t *testing.T) {
			wr := build(kind)
			holder := pwloBeginConn(t, raw)
			pwloReleaseConns(t, holder)
			holder.exec(t, "SELECT pg_advisory_xact_lock($1, $2)", authz.TopologySerializationLockClass, int32(1))
			require.EqualValues(t, 1, pwloAdvisoryHeld(t, e.obs, holder.pid, authz.TopologySerializationLockClass, 1))
			w.pool.reset()
			rec.reset()
			run := pwloGo(wr.run)
			pid := e.awaitBegin(t, w, run, wr.name, i)
			proof, ok, why := pwloProveWait(t, e.obs, pid, holder.pid, pwloAdvisory(authz.TopologySerializationLockClass, 1), pwloProofBound, run)
			require.True(t, ok, "%s 未被證明停在拓撲鎖上：%s", wr.name, why)
			require.Zero(t, pwloAdvisoryHeld(t, e.obs, pid, authz.TopologySerializationLockClass, 1), "%s 等待時不得已持有拓撲鎖", wr.name)
			require.Empty(t, onlyUserRowLocks(rec.writesOrRowLocks()), "%s 在拓撲鎖上等待時，除主體 users 列鎖外不得已有寫入或列鎖", wr.name)
			if wr.subject != 0 {
				require.Error(t, e.rowFree(t, "users", wr.subject), "%s 應已持有主體 users 列鎖（排在拓撲鎖之前）", wr.name)
			}
			e.requireRowsFree(t, wr.name+" 等拓撲鎖", wr.free...)
			require.False(t, run.finished(), "%s 在持鎖者放行前就已完成", wr.name)
			holder.exec(t, "COMMIT")
			requirePWLOClean(t, wr.name, run.wait(t, wr.name))
			fmt.Printf("ALS direction=A writer=%s holder_pid=%d writer_pid=%d proof=%s\n", wr.name, holder.pid, pid, proof)
			// 方言取自寫入端實際連線，證明本子案例確在 PostgreSQL 上跑出等待證明
			fmt.Printf("EVIDENCE dialect=%s subcase=authorization_scope_A_%s pids=holder:%d;writer:%d\n", w.db.Dialector.Name(), wr.name, holder.pid, pid)
		})
	}
	for i, kind := range []string{"grant", "grant_batch", "update_accounts"} {
		kind := kind
		t.Run("subject_row_lock_holder_blocks_before_topology_"+kind, func(t *testing.T) {
			wr := build(kind)
			holder := pwloBeginConn(t, raw)
			pwloReleaseConns(t, holder)
			holder.exec(t, "SELECT id FROM users WHERE id = $1 FOR NO KEY UPDATE", wr.subject)
			w.pool.reset()
			rec.reset()
			run := pwloGo(wr.run)
			pid := e.awaitBegin(t, w, run, wr.name, 100+i)
			proof, ok, why := pwloProveWait(t, e.obs, pid, holder.pid, pwloRowLock(), pwloProofBound, run)
			require.True(t, ok, "%s 未被證明停在主體 users 列鎖上：%s", wr.name, why)
			require.Zero(t, pwloAdvisoryHeld(t, e.obs, pid, authz.TopologySerializationLockClass, 1), "%s 等主體列鎖時不得已持有拓撲鎖（列鎖先於拓撲鎖）", wr.name)
			require.False(t, run.finished(), "%s 在持鎖者放行前就已完成", wr.name)
			holder.exec(t, "COMMIT")
			requirePWLOClean(t, wr.name, run.wait(t, wr.name))
			fmt.Printf("ALS direction=B writer=%s holder_pid=%d writer_pid=%d proof=%s\n", wr.name, holder.pid, pid, proof)
			// 方言取自寫入端實際連線，證明本子案例確在 PostgreSQL 上跑出等待證明
			fmt.Printf("EVIDENCE dialect=%s subcase=authorization_scope_B_%s pids=holder:%d;writer:%d\n", w.db.Dialector.Name(), wr.name, holder.pid, pid)
		})
	}
	// 持鎖方改為真的拓撲變更（搬移、撤除指派）的兩種先後（authorization_scope_interleave_pg_test.go）
	runAuthorizationScopeInterleave(t, e)
}
