package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/pkg/crypto"
)

// TestPermissionWriteLockOrder 子案例 (f) asset_create_vs_credential_rotate 與
// (g) serialization_point_blocks_before_first_write：拓撲序列化鎖是拓撲寫入交易的第一個動作，
// 早於憑證列鎖（lockCredentialRowsOrdered／lockImportCredentials）、資產列鎖與任何寫入。

// pwloSiteTopology 拓撲鎖取得後的停點名（authz.SetTopologyLockAcquiredHookForTest）。
const pwloSiteTopology = "topology_acquired"

// installTopologyStop 武裝 pwloSiteTopology 時，第一個取得拓撲鎖的交易停在「已取拓撲鎖、尚未執行下一個語句」。
// 掛點是全域的：其他交易之後再取拓撲鎖時，同一個停點已觸發過，不會再停。
func (e *pwloEnv) installTopologyStop(t *testing.T) {
	t.Helper()
	restore := authz.SetTopologyLockAcquiredHookForTest(func(tx *gorm.DB) { e.stops.hit(pwloSiteTopology, tx) })
	t.Cleanup(restore)
}

// pwloRecorder 某參與者連線池上已完成的 GORM 語句（寫入回呼）：用來證明等鎖當下該交易還沒有任何寫入與列鎖。
type pwloRecorder struct {
	mu    sync.Mutex
	stmts []string
}

func (r *pwloRecorder) install(t *testing.T, db *gorm.DB) {
	t.Helper()
	rec := func(d *gorm.DB) {
		if d.Statement == nil {
			return
		}
		if s := d.Statement.SQL.String(); s != "" {
			r.mu.Lock()
			r.stmts = append(r.stmts, s)
			r.mu.Unlock()
		}
	}
	cb := db.Callback()
	require.NoError(t, cb.Create().After("gorm:create").Register("pwlo:rec_create", rec))
	require.NoError(t, cb.Query().After("gorm:query").Register("pwlo:rec_query", rec))
	require.NoError(t, cb.Update().After("gorm:update").Register("pwlo:rec_update", rec))
	require.NoError(t, cb.Delete().After("gorm:delete").Register("pwlo:rec_delete", rec))
	require.NoError(t, cb.Row().After("gorm:row").Register("pwlo:rec_row", rec))
	require.NoError(t, cb.Raw().After("gorm:raw").Register("pwlo:rec_raw", rec))
}

func (r *pwloRecorder) reset() {
	r.mu.Lock()
	r.stmts = nil
	r.mu.Unlock()
}

// writesOrRowLocks 已完成語句中的寫入（INSERT／UPDATE／DELETE）與列鎖（FOR UPDATE／NO KEY UPDATE／SHARE／KEY SHARE）。
func (r *pwloRecorder) writesOrRowLocks() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, s := range r.stmts {
		u := strings.ToUpper(strings.TrimSpace(s))
		if strings.HasPrefix(u, "INSERT") || strings.HasPrefix(u, "UPDATE") || strings.HasPrefix(u, "DELETE") ||
			strings.Contains(u, " FOR UPDATE") || strings.Contains(u, " FOR NO KEY UPDATE") ||
			strings.Contains(u, " FOR SHARE") || strings.Contains(u, " FOR KEY SHARE") {
			out = append(out, s)
		}
	}
	return out
}

// rowFree 觀測以外的第三條連線以 FOR UPDATE NOWAIT 鎖指定列後立即回滾：成功表示當下沒有交易持有該列的任何列鎖
// （FOR UPDATE 與四種列鎖都衝突，NOWAIT 遇鎖即回 55P03，不等待）。
func (e *pwloEnv) rowFree(t *testing.T, table string, id uint) error {
	t.Helper()
	tx := e.fix.Begin()
	require.NoError(t, tx.Error)
	defer tx.Rollback()
	var n int64
	err := tx.Raw("SELECT count(*) FROM (SELECT id FROM "+table+" WHERE id = ? FOR UPDATE NOWAIT) s", id).Scan(&n).Error
	if err == nil && n != 1 {
		err = fmt.Errorf("%s id=%d 不存在", table, id)
	}
	return err
}

type pwloRowRef struct {
	table string
	id    uint
}

func (e *pwloEnv) requireRowsFree(t *testing.T, what string, rows ...pwloRowRef) {
	t.Helper()
	for _, r := range rows {
		require.NoError(t, e.rowFree(t, r.table, r.id), "%s：%s id=%d 不得已被鎖（列鎖必須在拓撲鎖之後）", what, r.table, r.id)
	}
}

// pwloAssetKit 同一參與者連線池上的資產、節點、憑證真服務。AssetService／CredentialService 經 database.DB 開交易，
// 呼叫端把 database.DB 指向該參與者的連線池。
type pwloAssetKit struct {
	assets *asset.AssetService
	groups *asset.AssetGroupService
	creds  *asset.CredentialService
}

func (e *pwloEnv) assetKit(t *testing.T, actor string) pwloAssetKit {
	t.Helper()
	aes, err := crypto.NewAESCrypto(make([]byte, 32))
	require.NoError(t, err)
	codec := fieldCapTestCodec{c: aes}
	svc, err := asset.NewAssetService(codec, "localhost", 4822, audit.NewTxSink())
	require.NoError(t, err)
	svc.SetAuthorizationRevoker(e.revoker(actor))
	svc.SetTopologyPermissionPort(authz.TopologyPermissionAdapter{})
	svc.SetSecurityChangeAlertSink(noopAlertSink{})
	svc.WithManagementAuthorizer(fieldCapSeedAuthorizer{}).WithSystemAlertSink(noopAlertSink{})
	groups := newWiredAssetGroupService(e.actor(actor).db, e.revoker(actor))
	creds := asset.NewCredentialService(svc, codec, audit.NewTxSink()).WithOwnershipScope(globalOwnershipScopeForTest{}).
		WithManagementAuthorizer(fieldCapSeedAuthorizer{}).WithSystemAlertSink(noopAlertSink{})
	database.DB = e.actor(actor).db
	return pwloAssetKit{assets: svc, groups: groups, creds: creds}
}

func (e *pwloEnv) rootCtx() context.Context {
	ctx := context.WithValue(context.Background(), "userID", e.root) //nolint:staticcheck // 沿用審計 context 慣例
	return context.WithValue(ctx, "username", "pwlo-root")           //nolint:staticcheck
}

// nodeCtx 節點寫入用：服務交易內以 context 主體重解範圍判定，須帶操作者主體（root 為超級管理者）。
func (e *pwloEnv) nodeCtx() context.Context {
	return authz.ContextWithPrincipal(e.rootCtx(), &authz.Principal{UserID: e.root})
}

func (e *pwloEnv) sharedCredential(t *testing.T, k pwloAssetKit, tag string) uint {
	t.Helper()
	dto, err := k.creds.Create(e.rootCtx(), &asset.CreateCredentialRequest{
		Name: "pwlo-cred-" + tag, Username: "ops", Password: "pw-" + tag, ProtocolFamily: model.ProtocolFamilySSH,
	})
	require.NoError(t, err)
	return dto.ID
}

func (e *pwloEnv) createAsset(k pwloAssetKit, name, host string, cred uint, nodes ...uint) (*model.Asset, error) {
	return k.assets.Create(asset.WithSystemCaller(e.rootCtx()), &asset.CreateAssetRequest{
		Name: name, Protocol: model.ProtocolSSH, Host: host, Port: 22, CredentialID: cred, NodeIDs: nodes,
		CreatedBy: e.root, CreatedByName: "pwlo-root",
	})
}

// pwloBuildCreateVsRotate (f)：建立資產並掛共用憑證 C × 憑證輪替的最小替身（交易第一個動作取拓撲鎖，
// 再以 FOR UPDATE 鎖 C 列並寫入；credentials 不是外鍵父表）。兩種先後的共用資源都是拓撲鎖：
// 資產建立先行時停在拓撲鎖取得後，此時 C 列必須仍可被第三條連線鎖走；替身先行時資產建立必須在拓撲鎖上等，
// 且尚未執行任何寫入或列鎖（序列化點在 lockCredentialRowsOrdered 之前）。
func pwloBuildCreateVsRotate(t *testing.T, name string) (*pwloEnv, pwloCase) {
	t.Helper()
	e := newPWLOEnv(t, name, true, "create", "rotate")
	e.installTopologyStop(t)
	kit := e.assetKit(t, "create")
	rec := &pwloRecorder{}
	rec.install(t, e.actor("create").db)
	create := pwloParty{name: "asset_create", actor: "create", stopSite: pwloSiteTopology, run: func(fx *pwloFixture) error {
		_, err := e.createAsset(kit, "pwlo-f-"+fx.channel, "10.9.6.1", fx.cred, fx.node)
		return err
	}}
	rotate := pwloParty{name: "credential_rotate", actor: "rotate", stopSite: "rotate_after_write", run: func(fx *pwloFixture) error {
		return e.actor("rotate").db.Transaction(func(tx *gorm.DB) error {
			if err := authz.LockScopeTopologyTx(tx); err != nil {
				return err
			}
			var n int64
			if err := tx.Raw("SELECT count(*) FROM (SELECT id FROM credentials WHERE id = ? FOR UPDATE) s", fx.cred).Scan(&n).Error; err != nil {
				return err
			}
			if n != 1 {
				return fmt.Errorf("憑證 %d 不存在", fx.cred)
			}
			if err := tx.Exec("UPDATE credentials SET note = ? WHERE id = ?", "rotated", fx.cred).Error; err != nil {
				return err
			}
			e.stops.hit("rotate_after_write", tx)
			return nil
		})
	}}
	return e, pwloCase{
		parties: [2]pwloParty{create, rotate},
		target:  func(*pwloFixture) pwloTarget { return pwloAdvisory(authz.TopologySerializationLockClass, 1) },
		setup: func(t *testing.T, tag string) *pwloFixture {
			fx := &pwloFixture{node: e.newNode(t, "f-"+tag), channel: tag}
			fx.cred = e.sharedCredential(t, kit, "f-"+tag)
			fx.version = e.version(t)
			rec.reset()
			return fx
		},
		atStop: func(t *testing.T, fx *pwloFixture, lead pwloParty, leadPID int64) {
			require.EqualValues(t, 1, pwloAdvisoryHeld(t, e.obs, leadPID, authz.TopologySerializationLockClass, 1),
				"%s 停在停點時應已持有拓撲鎖", lead.name)
			if lead.name != "asset_create" {
				return
			}
			require.Empty(t, rec.writesOrRowLocks(), "資產建立停在拓撲鎖取得後，不得已有寫入或列鎖")
			e.requireRowsFree(t, "資產建立已取拓撲鎖、尚未取憑證列鎖", pwloRowRef{"credentials", fx.cred})
		},
		onWait: func(t *testing.T, fx *pwloFixture, follow pwloParty, followPID int64) {
			require.Zero(t, pwloAdvisoryHeld(t, e.obs, followPID, authz.TopologySerializationLockClass, 1),
				"%s 在拓撲鎖上等待時不得已持有它", follow.name)
			if follow.name == "asset_create" {
				require.Empty(t, rec.writesOrRowLocks(), "資產建立在拓撲鎖上等待時，不得已有寫入或列鎖（含 lockCredentialRowsOrdered）")
			}
		},
		snap: func(t *testing.T, fx *pwloFixture) map[string]int64 {
			name := "pwlo-f-" + fx.channel
			return map[string]int64{
				"asset_live":    e.scalar(t, "SELECT count(*) FROM assets WHERE name = ? AND deleted_at IS NULL", name),
				"asset_nodes":   e.scalar(t, "SELECT count(*) FROM asset_nodes n JOIN assets a ON a.id = n.asset_id WHERE a.name = ? AND n.node_id = ?", name, fx.node),
				"cred_bound":    e.scalar(t, "SELECT count(*) FROM asset_accounts c JOIN assets a ON a.id = c.asset_id WHERE a.name = ? AND c.credential_id = ? AND c.deleted_at IS NULL", name, fx.cred),
				"cred_rotated":  e.scalar(t, "SELECT count(*) FROM credentials WHERE id = ? AND note = 'rotated'", fx.cred),
				"version_delta": e.version(t) - fx.version,
			}
		},
	}
}

// pwloWriter (g) 一種拓撲寫入：run 走正式服務入口；rows 是等鎖當下必須仍未被鎖的列；after 斷言放行後的寫入結果。
type pwloWriter struct {
	name  string
	rows  []pwloRowRef
	run   func() error
	after func(t *testing.T)
	// noAdvance 該寫入只取拓撲鎖、不推進權限版本（節點建立）。
	noAdvance bool
}

// runSerializationPointCase (g)：另一連線持有拓撲鎖時，六種拓撲寫入加節點建立共七種各自停在取鎖處。
// 等待以限定 database、classid、objid=1、objsubid=2、pid 的 pg_locks 單列 count 與 pg_blocking_pids 證明
// （pwloProveWait 的 advisory 種類，含持鎖者 granted 恰 1 列）；同時該寫入方的連線尚未完成任何寫入或列鎖、
// 憑證列與資產列（節點寫入另含節點列）仍可被第三條連線以 NOWAIT 鎖走；放行後各自完成；除節點建立（只取鎖、不推進）外推進版本恰一次。
func runSerializationPointCase(t *testing.T) {
	const name = "serialization_point_blocks_before_first_write"
	e := newPWLOEnv(t, name, true, "writer")
	e.attested = e.checkAttestation(t)
	kit := e.assetKit(t, "writer")
	w := e.actor("writer")
	rec := &pwloRecorder{}
	rec.install(t, w.db)
	raw := e.selfCheckPool(t)

	cred := e.sharedCredential(t, kit, "g")
	n1, n2 := e.newNode(t, "g-n1"), e.newNode(t, "g-n2")
	parent, mover, leaf := e.newNode(t, "g-parent"), e.newNode(t, "g-mover"), e.newNode(t, "g-leaf")
	seed, err := e.createAsset(kit, "pwlo-g-seed", "10.9.7.1", cred, n1)
	require.NoError(t, err)
	victim, err := e.createAsset(kit, "pwlo-g-victim", "10.9.7.2", cred, n1)
	require.NoError(t, err)
	require.EqualValues(t, 1, e.scalar(t, "SELECT count(*) FROM asset_nodes WHERE asset_id = ?", victim.ID), "被刪資產須有掛載")
	cid := int64(cred)
	common := []pwloRowRef{{"credentials", cred}, {"assets", seed.ID}, {"assets", victim.ID}}
	liveByName := func(t *testing.T, name string) int64 {
		return e.scalar(t, "SELECT count(*) FROM assets WHERE name = ? AND deleted_at IS NULL", name)
	}

	writers := []pwloWriter{
		{name: "create", rows: common, run: func() error {
			_, err := e.createAsset(kit, "pwlo-g-create", "10.9.7.3", cred, n1)
			return err
		}, after: func(t *testing.T) { require.EqualValues(t, 1, liveByName(t, "pwlo-g-create")) }},
		{name: "import_commit", rows: common, run: func() error {
			_, err := kit.assets.ImportAssets(asset.WithSystemCaller(e.rootCtx()), &asset.ImportBatch{Source: asset.ImportSourceForm, Rows: []asset.ImportRow{
				{Name: "pwlo-g-imp-1", Protocol: "ssh", Host: "10.9.7.4", CredentialID: &cid, NodeIDs: []uint{n1}},
				{Name: "pwlo-g-imp-2", Protocol: "ssh", Host: "10.9.7.5", CredentialID: &cid, NodeIDs: []uint{n1}},
			}}, e.root, "pwlo-root")
			return err
		}, after: func(t *testing.T) {
			require.EqualValues(t, 1, liveByName(t, "pwlo-g-imp-1"))
			require.EqualValues(t, 1, liveByName(t, "pwlo-g-imp-2"))
		}},
		{name: "mount_change", rows: common, run: func() error {
			ids := []uint{n2}
			_, err := kit.assets.Update(asset.WithSystemCaller(e.rootCtx()), seed.ID, &asset.UpdateAssetRequest{NodeIDs: &ids})
			return err
		}, after: func(t *testing.T) {
			require.EqualValues(t, 1, e.scalar(t, "SELECT count(*) FROM asset_nodes WHERE asset_id = ? AND node_id = ?", seed.ID, n2))
			require.EqualValues(t, 1, e.scalar(t, "SELECT count(*) FROM asset_nodes WHERE asset_id = ?", seed.ID))
		}},
		{name: "delete_mounted_asset", rows: common, run: func() error {
			return kit.assets.Delete(asset.WithSystemCaller(context.Background()), victim.ID)
		}, after: func(t *testing.T) { require.EqualValues(t, 1, e.deleted(t, "assets", victim.ID)) }},
		{name: "node_create", rows: append(append([]pwloRowRef{}, common...), pwloRowRef{"asset_groups", parent}), noAdvance: true, run: func() error {
			p := parent
			_, err := kit.groups.Create(e.nodeCtx(), &asset.AssetGroupRequest{Name: "pwlo-g-created", ParentID: &p}, e.root, "pwlo-root", pwloClientIP)
			return err
		}, after: func(t *testing.T) {
			require.EqualValues(t, 1, e.scalar(t, "SELECT count(*) FROM asset_groups WHERE name = ? AND parent_id = ? AND deleted_at IS NULL", "pwlo-g-created", parent))
		}},
		{name: "node_move", rows: append(append([]pwloRowRef{}, common...), pwloRowRef{"asset_groups", mover}, pwloRowRef{"asset_groups", parent}), run: func() error {
			p := parent
			_, err := kit.groups.Move(e.nodeCtx(), mover, &p, e.root, "pwlo-root", pwloClientIP)
			return err
		}, after: func(t *testing.T) {
			require.EqualValues(t, 1, e.scalar(t, "SELECT count(*) FROM asset_groups WHERE id = ? AND parent_id = ?", mover, parent))
		}},
		{name: "node_delete", rows: append(append([]pwloRowRef{}, common...), pwloRowRef{"asset_groups", leaf}), run: func() error {
			_, err := kit.groups.Delete(e.nodeCtx(), leaf, e.root, "pwlo-root", pwloClientIP)
			return err
		}, after: func(t *testing.T) { require.EqualValues(t, 1, e.deleted(t, "asset_groups", leaf)) }},
	}

	for i, wr := range writers {
		before := e.version(t)
		holder := pwloBeginConn(t, raw)
		pwloReleaseConns(t, holder)
		holder.exec(t, "SELECT pg_advisory_xact_lock($1, $2)", authz.TopologySerializationLockClass, int32(1))
		require.EqualValues(t, 1, pwloAdvisoryHeld(t, e.obs, holder.pid, authz.TopologySerializationLockClass, 1), "持鎖連線應持有拓撲鎖")

		w.pool.reset()
		rec.reset()
		run := pwloGo(wr.run)
		pid := e.awaitBegin(t, w, run, wr.name, i)
		proof, ok, why := pwloProveWait(t, e.obs, pid, holder.pid, pwloAdvisory(authz.TopologySerializationLockClass, 1), pwloProofBound, run)
		pending := rec.writesOrRowLocks()
		var rowErr error
		for _, r := range wr.rows {
			if rowErr = e.rowFree(t, r.table, r.id); rowErr != nil {
				rowErr = fmt.Errorf("%s id=%d: %w", r.table, r.id, rowErr)
				break
			}
		}
		finishedEarly := run.finished()
		holder.exec(t, "COMMIT")
		err := run.wait(t, wr.name)
		e.notePIDs("holder", holder.pid)
		e.notePIDs(wr.name, pid)
		fmt.Printf("WRITER subcase=%s writer=%s holder_pid=%d writer_pid=%d confirmed=%v proof=%s writes_or_row_locks_before_release=%d rows_free=%v finished_before_release=%v sqlstate=%s err=%q reason=%q\n",
			name, wr.name, holder.pid, pid, ok, proof, len(pending), rowErr == nil, finishedEarly, pwloStateLabel(err), pwloErrText(err), why)
		require.True(t, ok, "%s 未被證明停在拓撲鎖上：%s", wr.name, why)
		require.Empty(t, pending, "%s 等拓撲鎖時已完成寫入或列鎖", wr.name)
		require.NoError(t, rowErr, "%s 等拓撲鎖時憑證列、資產列或節點列已被鎖", wr.name)
		require.False(t, finishedEarly, "%s 在持鎖者放行前就已完成", wr.name)
		requirePWLOClean(t, wr.name, err)
		wr.after(t)
		wantDelta := int64(1)
		if wr.noAdvance {
			wantDelta = 0
		}
		require.EqualValues(t, wantDelta, e.version(t)-before, "%s 權限版本推進次數", wr.name)
	}
	fmt.Printf("EVIDENCE dialect=%s subcase=%s pids=%s attested=%v\n", e.fix.Dialector.Name(), name, e.pidSummary(), e.attested)
}
