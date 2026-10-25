package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 掛載的交易內重判：Bind 交易第一個動作取拓撲序列化鎖，憑證列鎖之後以交易外同一道關卡重判。
// 交易外判定之後才提交的改歸或撤權，在鎖後重判生效；掛載先提交時其後的合法改歸照常成功並保留該掛載。
// PostgreSQL 另以 pg_locks 證明：持序列化鎖的 Bind 交易讓後到的改歸在同一把鎖上等待，且此時
// 尚未取資產列與憑證列鎖。

const (
	scAuditScopeDenial      = `%"denial":"scope"%`
	scAuditCapabilityDenial = `%"denial":"capability"%`
)

// newBinder 新主體：在範圍內節點有唯一一筆含 bind 的指派。
func (m *scMount) newBinder(name string) uint {
	m.t.Helper()
	uid := m.user(name)
	m.grant(uid, []string{"zz-sc-in"}, authz.PermCredentialView, authz.PermCredentialBind, authz.PermCredentialUpdate)
	return uid
}

func (m *scMount) bindAs(uid, credID, assetID uint) (int, string) {
	m.t.Helper()
	return m.call(uid, "POST", credPath(credID)+"/bindings", fmt.Sprintf(`{"asset_id":%d}`, assetID))
}

func scReassignBody(credID, nodeID uint) string {
	return fmt.Sprintf(`{"credential_ids":[%d],"ownership":{"kind":"node","node_id":%d}}`, credID, nodeID)
}

// reassignAs 經批次改歸路由把一筆憑證改歸到指定節點。
func (m *scMount) reassignAs(uid, credID, nodeID uint) (int, string) {
	m.t.Helper()
	return m.call(uid, "POST", "/api/v1/credentials/ownership", scReassignBody(credID, nodeID))
}

func (m *scMount) auditCount(pattern string) int64 {
	m.t.Helper()
	var n int64
	require.NoError(m.t, m.db.Model(&model.AuditLog{}).Where("details LIKE ?", pattern).Count(&n).Error)
	return n
}

func (m *scMount) nodeAssignmentCount(uid uint) int64 {
	m.t.Helper()
	var n int64
	require.NoError(m.t, m.db.Model(&model.RoleBindingNode{}).
		Where("subject_kind = ? AND subject_id = ?", model.BindingSubjectUser, uid).Count(&n).Error)
	return n
}

// scOwnerNode 經 db（可為呼叫端交易）讀憑證目前的歸屬節點。
func scOwnerNode(t *testing.T, db *gorm.DB, credID uint) *uint {
	t.Helper()
	var c model.Credential
	require.NoError(t, db.Select("id", "owner_node_id").First(&c, credID).Error)
	return c.OwnerNodeID
}

// clearBindHooks 測試結束前還原掛載的測試掛點。
func (m *scMount) clearBindHooks() { m.creds.SetBindHooksForTest(nil, nil) }

func runBindRecheckCases(t *testing.T, m *scMount, pg bool) {
	inNode, outNode := *m.nodeID("zz-sc-in"), *m.nodeID("zz-sc-out")

	t.Run("改歸先提交時其後的 Bind 與不存在同形拒絕", func(t *testing.T) {
		defer m.clearBindHooks()
		binder := m.newBinder("zz-sc-race-a")
		src := m.cred("zz-sc-race-a-src", &inNode)
		wantCode, wantBody := m.bindAs(binder, m.ghost, m.aIn)
		require.Equal(t, http.StatusNotFound, wantCode, wantBody)
		scopeBefore, accountsBefore := m.auditCount(scAuditScopeDenial), m.accountCount()

		var reassignCode int
		var reassignBody string
		var seen *uint
		seenSet := false
		m.creds.SetBindHooksForTest(func() {
			// 交易外判定已放行之後、Bind 交易開始之前，超管把來源改歸到範圍外並提交
			reassignCode, reassignBody = m.reassignAs(m.holder, src, outNode)
		}, func(tx *gorm.DB) error {
			seen, seenSet = scOwnerNode(t, tx, src), true
			return nil
		})
		code, body := m.bindAs(binder, src, m.aIn)
		m.clearBindHooks()

		require.Equal(t, http.StatusOK, reassignCode, "改歸不因掛載而被拒：%s", reassignBody)
		require.True(t, seenSet, "鎖後掛點必須被走到")
		require.NotNil(t, seen)
		require.Equal(t, outNode, *seen, "裁決當下來源已在範圍外")
		require.Equal(t, wantCode, code, "與不存在同形")
		require.Equal(t, wantBody, body, "與不存在逐位元相同")
		require.Zero(t, m.mountCount(src), "零掛載")
		require.Equal(t, accountsBefore, m.accountCount(), "掛載數不變")
		require.Equal(t, scopeBefore+1, m.auditCount(scAuditScopeDenial), "審計為範圍拒絕")
	})

	t.Run("Bind 先提交時其後的合法改歸成功且保留該掛載", func(t *testing.T) {
		defer m.clearBindHooks()
		binder := m.newBinder("zz-sc-race-b")
		src := m.cred("zz-sc-race-b-src", &inNode)
		var seen *uint
		var waitRun *pwloRun
		var waited *scReassignResult
		m.creds.SetBindHooksForTest(nil, func(tx *gorm.DB) error {
			seen = scOwnerNode(t, tx, src)
			if pg {
				waitRun, waited = m.proveReassignWaitsOnBind(t, tx, src, outNode)
			}
			return nil
		})
		code, body := m.bindAs(binder, src, m.aIn)
		m.clearBindHooks()

		require.NotNil(t, seen, "鎖後掛點必須被走到")
		require.Equal(t, inNode, *seen, "裁決當下來源在範圍內")
		require.Equal(t, http.StatusCreated, code, body)
		if pg {
			require.NoError(t, waitRun.wait(t, "等在序列化鎖上的改歸"))
			require.Equal(t, http.StatusOK, waited.code, "Bind 提交後改歸照常成功：%s", waited.body)
		} else {
			rc, rb := m.reassignAs(m.holder, src, outNode)
			require.Equal(t, http.StatusOK, rc, rb)
		}
		require.Equal(t, outNode, *scOwnerNode(t, m.db, src), "改歸已生效")
		require.EqualValues(t, 1, m.mountCount(src), "改歸不改掛載：該掛載保留")
	})

	t.Run("Bind 與 Rebind 只取序列化鎖、不推進權限版本", func(t *testing.T) {
		binder := m.newBinder("zz-sc-lock-count")
		src := m.cred("zz-sc-lock-count-src", &inNode)
		versionBefore, err := authz.CurrentVersion(m.db)
		require.NoError(t, err)

		before := m.topo.counts()
		code, body := m.bindAs(binder, src, m.aIn)
		require.Equal(t, http.StatusCreated, code, body)
		after := m.topo.counts()
		require.Equal(t, scTopologyCounts{locks: 1}, scTopologyCounts{locks: after.locks - before.locks,
			begins: after.begins - before.begins, advances: after.advances - before.advances}, "Bind：一次序列化鎖、零 Begin、零推進")

		target := m.cred("zz-sc-lock-count-target", &inNode)
		acc := m.mount(m.globalCred, m.aIn2)
		before = m.topo.counts()
		code, body = m.call(binder, "PUT", fmt.Sprintf("/api/v1/assets/%d/accounts/%d/credential", m.aIn2, acc),
			fmt.Sprintf(`{"credential_id":%d}`, target))
		require.Equal(t, http.StatusOK, code, body)
		after = m.topo.counts()
		require.Equal(t, scTopologyCounts{locks: 1}, scTopologyCounts{locks: after.locks - before.locks,
			begins: after.begins - before.begins, advances: after.advances - before.advances}, "Rebind：一次序列化鎖、零 Begin、零推進")

		versionAfter, err := authz.CurrentVersion(m.db)
		require.NoError(t, err)
		require.Equal(t, versionBefore, versionAfter, "掛載與改綁不推進權限版本")
	})

	t.Run("撤權在交易外判定之後、取序列化鎖之前由另一連線提交：Bind 回 403 能力拒絕", func(t *testing.T) {
		defer m.clearBindHooks()
		binder := m.newBinder("zz-sc-revoke-i")
		src := m.cred("zz-sc-revoke-i-src", &inNode)
		capBefore, accountsBefore := m.auditCount(scAuditCapabilityDenial), m.accountCount()
		m.creds.SetBindHooksForTest(func() { m.dropNodeAssignments(binder) }, nil)
		code, body := m.bindAs(binder, src, m.aIn)
		m.clearBindHooks()

		require.Equal(t, http.StatusForbidden, code, "單一 forbidden，不是 404：%s", body)
		require.Equal(t, capBefore+1, m.auditCount(scAuditCapabilityDenial), "審計 denial=capability")
		require.Zero(t, m.mountCount(src))
		require.Equal(t, accountsBefore, m.accountCount(), "掛載數不變")
	})

	t.Run("撤權在取序列化鎖之後、憑證列鎖之前於同一交易內移除：Bind 回 403 能力拒絕", func(t *testing.T) {
		defer m.clearBindHooks()
		binder := m.newBinder("zz-sc-revoke-ii")
		src := m.cred("zz-sc-revoke-ii-src", &inNode)
		capBefore, accountsBefore := m.auditCount(scAuditCapabilityDenial), m.accountCount()
		hit := false
		m.creds.SetBindHooksForTest(nil, func(tx *gorm.DB) error {
			hit = true
			if err := tx.Where("user_id = ? AND scope_kind = ?", binder, model.ScopeKindNodes).
				Delete(&model.UserRole{}).Error; err != nil {
				return err
			}
			return tx.Where("subject_kind = ? AND subject_id = ?", model.BindingSubjectUser, binder).
				Delete(&model.RoleBindingNode{}).Error
		})
		code, body := m.bindAs(binder, src, m.aIn)
		m.clearBindHooks()

		require.True(t, hit, "鎖後掛點必須被走到")
		require.Equal(t, http.StatusForbidden, code, "單一 forbidden，不是 404：%s", body)
		require.Equal(t, capBefore+1, m.auditCount(scAuditCapabilityDenial), "審計 denial=capability")
		require.Zero(t, m.mountCount(src))
		require.Equal(t, accountsBefore, m.accountCount(), "掛載數不變")
		require.EqualValues(t, 1, m.nodeAssignmentCount(binder), "同交易的移除隨 Bind 回滾：證明重判讀的是本交易")
	})

	if !pg {
		return
	}

	t.Run("取得序列化鎖之後由另一連線提交撤權：不被擋，Bind 依鎖後重讀的主體回 403", func(t *testing.T) {
		defer m.clearBindHooks()
		binder := m.newBinder("zz-sc-revoke-iii")
		src := m.cred("zz-sc-revoke-iii-src", &inNode)
		capBefore, accountsBefore := m.auditCount(scAuditCapabilityDenial), m.accountCount()
		revoked := false
		m.creds.SetBindHooksForTest(nil, func(*gorm.DB) error {
			// 撤權不取序列化鎖：在 Bind 交易持鎖期間，另一連線的撤權直接提交
			m.dropNodeAssignments(binder)
			revoked = true
			return nil
		})
		code, body := m.bindAs(binder, src, m.aIn)
		m.clearBindHooks()

		require.True(t, revoked, "撤權在 Bind 持鎖期間完成提交")
		require.Zero(t, m.nodeAssignmentCount(binder), "撤權已提交")
		require.Equal(t, http.StatusForbidden, code, "單一 forbidden，不是 404：%s", body)
		require.Equal(t, capBefore+1, m.auditCount(scAuditCapabilityDenial), "審計 denial=capability")
		require.Zero(t, m.mountCount(src))
		require.Equal(t, accountsBefore, m.accountCount(), "掛載數不變")
	})
}

// scReassignResult 背景改歸請求的結果（run 結束後才可讀）。
type scReassignResult struct {
	code int
	body string
}

// proveReassignWaitsOnBind 在 Bind 交易持有序列化鎖時送出改歸，以 pg_locks 證明改歸在同一把鎖上等待
// （後行 pid 一列 NOT granted、Bind 的 pid granted 恰一列、且在 pg_blocking_pids 之內），並證明此刻
// 資產列與憑證列都未被鎖（列鎖在序列化鎖之後）。回傳背景執行與其結果。
func (m *scMount) proveReassignWaitsOnBind(t *testing.T, tx *gorm.DB, credID, nodeID uint) (*pwloRun, *scReassignResult) {
	t.Helper()
	var holder int64
	require.NoError(t, tx.Raw("SELECT pg_backend_pid()").Scan(&holder).Error)
	eng := m.scRouter(m.holder)
	res := &scReassignResult{}
	run := pwloGo(func() error {
		req := httptest.NewRequest("POST", "/api/v1/credentials/ownership", strings.NewReader(scReassignBody(credID, nodeID)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		eng.ServeHTTP(w, req)
		res.code, res.body = w.Code, w.Body.String()
		return nil
	})
	waiter := m.topologyWaiter(t, holder, run)
	proof, ok, why := pwloProveWait(t, m.db, waiter, holder,
		pwloAdvisory(authz.TopologySerializationLockClass, 1), pwloProofBound, run)
	require.True(t, ok, why)
	t.Logf("EVIDENCE bind_holds_topology_lock waiter=%d holder=%d %s", waiter, holder, proof)
	for _, r := range []struct {
		table string
		id    uint
	}{{"credentials", credID}, {"assets", m.aIn}} {
		require.NoError(t, m.rowFreeNow(r.table, r.id), "%s id=%d 不得已被鎖（列鎖必須在序列化鎖之後）", r.table, r.id)
	}
	return run, res
}

// topologyWaiter 等到 holder 以外有一條連線在拓撲序列化鎖上排隊，回其 pid。
func (m *scMount) topologyWaiter(t *testing.T, holder int64, run *pwloRun) int64 {
	t.Helper()
	deadline := time.Now().Add(pwloProofBound)
	for time.Now().Before(deadline) {
		var pids []int64
		require.NoError(t, m.db.Raw(`SELECT pid FROM pg_locks
 WHERE locktype = 'advisory' AND NOT granted AND pid <> ?
   AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
   AND classid::bigint = ? AND objid::bigint = 1 AND objsubid = 2`,
			holder, int64(authz.TopologySerializationLockClass)).Scan(&pids).Error)
		if len(pids) == 1 {
			return pids[0]
		}
		require.False(t, run.finished(), "改歸在 Bind 持鎖期間就結束，沒有在序列化鎖上等待")
		time.Sleep(pwloProofInterval)
	}
	t.Fatalf("%s 內沒有連線在拓撲序列化鎖上等待", pwloProofBound)
	return 0
}

// rowFreeNow 另開交易以 FOR UPDATE NOWAIT 鎖指定列後回滾：成功表示當下沒有交易持有該列的列鎖。
func (m *scMount) rowFreeNow(table string, id uint) error {
	return m.db.Transaction(func(tx *gorm.DB) error {
		var n int64
		if err := tx.Raw("SELECT count(*) FROM (SELECT id FROM "+table+" WHERE id = ? FOR UPDATE NOWAIT) s", id).
			Scan(&n).Error; err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("%s id=%d 不存在", table, id)
		}
		return nil
	})
}
