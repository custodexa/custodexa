package asset_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/testgate"
)

// 批次新增資產的逐列範圍：正式寫入範圍判定（資產建立標為 scoped-enforced）、正式憑證歸屬判定，
// 掛載判定以與組裝根相同的口徑接上（不帶目標只認全域來源；帶目標由判定器依歸屬判定）。
//
// 樹：ri-in、ri-in2（範圍化主體的兩個指派節點）、ri-hidden（範圍外）。

var riPerms = []authz.Permission{authz.PermAssetView, authz.PermAssetCreate,
	authz.PermCredentialView, authz.PermCredentialBind}

// riAuthorizer 掛載判定：與組裝根的轉接頭同一口徑（不帶目標只認全域來源）。
type riAuthorizer struct {
	res  *authz.Resolver
	eval *authz.ScopeEvaluator
	db   *gorm.DB
}

func (a riAuthorizer) AuthorizeCredentialManagement(ctx context.Context, db *gorm.DB,
	actor asset.CredentialManagementActor, req asset.CredentialManagementRequest) (asset.CredentialManagementDecision, error) {
	if db == nil {
		db = a.db
	}
	d, err := a.res.HasAllCapabilities(db, actor.UserID, req.Capabilities)
	if err != nil {
		return asset.CredentialManagementDecision{}, err
	}
	out := asset.CredentialManagementDecision{Allowed: d.Allowed, Missing: d.Missing}
	if len(req.CredentialIDs) == 0 && len(req.AssetIDs) == 0 {
		return out, nil
	}
	missing, denied, err := a.eval.DecideCredentialManagement(ctx, db, actor.UserID, req.Capabilities,
		req.CredentialIDs, req.AssetIDs)
	if err != nil {
		return asset.CredentialManagementDecision{}, err
	}
	switch {
	case denied != nil:
		out.Allowed, out.Missing, out.ScopeDenial = false, "", denied
	case missing != "":
		out.Allowed, out.Missing = false, missing
	default:
		out.Allowed, out.Missing = true, ""
	}
	return out, nil
}

// riAllowAllWriteScope 寫入範圍判定替身：全放行（範圍判定出現前的口徑）。
type riAllowAllWriteScope struct{}

func (riAllowAllWriteScope) AuthorizeAssetCreate(context.Context, *gorm.DB, []uint) error { return nil }

func (riAllowAllWriteScope) AuthorizeAssetWrite(context.Context, *gorm.DB, asset.AssetWriteOp, uint, []uint) error {
	return nil
}

func (riAllowAllWriteScope) MergeAssetNodes(_ context.Context, _ *gorm.DB, _ uint, _, requested []uint) ([]uint, error) {
	return requested, nil
}

// AccessPolicyCoversNodes 全放行替身：每組目的節點皆在存取政策範圍內。
func (riAllowAllWriteScope) AccessPolicyCoversNodes(_ context.Context, _ *gorm.DB, nodeSets [][]uint) ([]bool, error) {
	out := make([]bool, len(nodeSets))
	for i := range out {
		out[i] = true
	}
	return out, nil
}

type riEnv struct {
	t       *testing.T
	db      *gorm.DB
	port    *coPort
	svc     *asset.AssetService
	legacy  *asset.AssetService // 範圍判定出現前的口徑（寫入範圍與掛載恆放行），供全域主體比對
	newSvc  func() *asset.AssetService
	creds   *asset.CredentialService
	nodes   map[string]uint
	paths   map[string]string
	scoped  uint
	global  uint
	super   uint
	cred    map[string]uint
	credRow map[string]string // 鍵 → 憑證名稱
	seq     int
}

func newRiEnv(t *testing.T) *riEnv {
	t.Helper()
	db, _ := openRaceDB(t)
	first, tail := raceModels()
	require.NoError(t, db.AutoMigrate(first...))
	require.NoError(t, db.AutoMigrate(tail...))
	require.NoError(t, db.AutoMigrate(&model.AssetAccount{}, &model.CredentialSecretVersion{},
		&model.ChangeSecretCandidate{}, &model.AssetHostKey{}))
	require.NoError(t, db.Exec("INSERT INTO authz_state (id, version) VALUES (1, 0)").Error)
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })

	e := &riEnv{t: t, db: db, port: &coPort{}, nodes: map[string]uint{}, cred: map[string]uint{},
		credRow: map[string]string{}}
	for _, n := range []string{"ri-in", "ri-in2", "ri-hidden"} {
		g := model.AssetGroup{Name: n}
		require.NoError(t, db.Create(&g).Error)
		e.nodes[n] = g.ID
	}
	pathByID, err := asset.NodePathMap(db)
	require.NoError(t, err)
	e.paths = map[string]string{}
	for n, id := range e.nodes {
		e.paths[n] = pathByID[id]
	}

	cat, err := authz.CatalogueWithScopedEnforcedForTest(riPerms...)
	require.NoError(t, err)
	topo := asset.NewScopeTopologyReader()
	eval := authz.NewScopeEvaluator(cat, topo, authz.CredentialScopeResolver())

	sink := audit.NewTxSink()
	newSvc := func() *asset.AssetService {
		svc, err := asset.NewAssetService(asset.ColumnCodecForExternalTest(t), "localhost", 4822, sink)
		require.NoError(t, err)
		svc.SetTopologyPermissionPort(e.port)
		svc.SetSecurityChangeAlertSink(swNoopAlerts{})
		return svc
	}
	e.svc = newSvc()
	e.svc.SetAssetWriteScopePort(authz.NewAssetWriteScope(eval))
	e.svc.SetCoverageSnapshotPort(authz.NewTopologyCoverageReader(topo))
	e.svc.WithManagementAuthorizer(riAuthorizer{res: authz.NewResolver(db), eval: eval, db: db}).
		WithSystemAlertSink(swNoopAlerts{})
	e.newSvc = newSvc
	e.legacy = newSvc()
	e.legacy.SetAssetWriteScopePort(riAllowAllWriteScope{})
	e.legacy.WithManagementAuthorizer(swAllowCredentials{}).WithSystemAlertSink(swNoopAlerts{})
	e.creds = asset.NewCredentialService(e.svc, asset.ColumnCodecForExternalTest(t), sink).
		WithOwnershipScope(authz.NewCredentialOwnershipScope(eval)).
		WithManagementAuthorizer(swAllowCredentials{}).WithSystemAlertSink(swNoopAlerts{})

	e.super = e.user("ri-super")
	adminRole := model.Role{Name: model.RoleAdmin}
	require.NoError(t, db.Create(&adminRole).Error)
	require.NoError(t, db.Create(&model.UserRole{UserID: e.super, RoleID: adminRole.ID,
		Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)

	role := model.Role{Name: "ri-importer", DefinitionVersion: 1}
	require.NoError(t, db.Create(&role).Error)
	for _, p := range riPerms {
		require.NoError(t, db.Create(&model.RolePermission{RoleID: role.ID, PermissionKey: string(p)}).Error)
	}
	e.scoped = e.user("ri-scoped")
	require.NoError(t, db.Create(&model.UserRole{UserID: e.scoped, RoleID: role.ID,
		Source: model.RoleSourceManual, ScopeKind: model.ScopeKindNodes}).Error)
	for _, n := range []string{"ri-in", "ri-in2"} {
		require.NoError(t, db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser,
			SubjectID: e.scoped, RoleID: role.ID, NodeID: e.nodes[n]}).Error)
	}
	e.global = e.user("ri-global")
	require.NoError(t, db.Create(&model.UserRole{UserID: e.global, RoleID: role.ID,
		Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)

	e.newCred("in", onNode(e.nodes["ri-in"]))
	e.newCred("hidden", onNode(e.nodes["ri-hidden"]))
	e.newCred("global", onGlobal())
	e.newCred("hidden-rotating", onNode(e.nodes["ri-hidden"]))
	require.NoError(t, db.Model(&model.Credential{}).Where("id = ?", e.cred["hidden-rotating"]).
		Update("active_rotation_id", 9999).Error)
	e.newCred("hidden-dedicated", onNode(e.nodes["ri-hidden"]))
	hostAsset := e.existingAsset("ri-hidden-host", "ri-hidden")
	require.NoError(t, db.Create(&model.AssetAccount{AssetID: hostAsset, CredentialID: e.cred["hidden-dedicated"],
		Username: "ops"}).Error)
	_, err = e.creds.ConvertScope(e.ctx(e.super), e.cred["hidden-dedicated"],
		&asset.ConvertCredentialScopeRequest{Scope: model.CredentialScopeDedicated})
	require.NoError(t, err)
	e.existingAsset("ri-dup-hidden", "ri-hidden")
	e.existingAsset("ri-dup-in", "ri-in")
	return e
}

func (e *riEnv) user(name string) uint {
	e.t.Helper()
	u := model.User{Username: name, Password: "x", Active: true}
	require.NoError(e.t, e.db.Create(&u).Error)
	return u.ID
}

func (e *riEnv) ctx(userID uint) context.Context {
	ctx := authz.ContextWithPrincipal(context.Background(), &authz.Principal{UserID: userID})
	ctx = context.WithValue(ctx, "userID", userID)    //nolint:staticcheck // 沿用審計 context 慣例
	ctx = context.WithValue(ctx, "username", "ri-op") //nolint:staticcheck
	return asset.WithFieldCapability(ctx, func(string) asset.FieldCapGrant { return asset.FieldCapViaCompat })
}

func (e *riEnv) newCred(key string, ownership *asset.CredentialOwnershipInput) {
	e.t.Helper()
	e.seq++
	name := fmt.Sprintf("ri-cred-%s-%d", key, e.seq)
	dto, err := e.creds.Create(e.ctx(e.super), &asset.CreateCredentialRequest{
		Name: name, Username: "ops", ProtocolFamily: model.ProtocolFamilySSH,
		Password: fmt.Sprintf("ri-fixture-%d", e.seq), Ownership: ownership,
	})
	require.NoError(e.t, err)
	e.cred[key], e.credRow[key] = dto.ID, name
}

func (e *riEnv) existingAsset(name, node string) uint {
	e.t.Helper()
	e.seq++
	a := model.Asset{Name: name, Protocol: model.ProtocolSSH, Host: fmt.Sprintf("10.71.0.%d", e.seq),
		Port: 22, CreatedBy: e.super, Active: true}
	require.NoError(e.t, e.db.Create(&a).Error)
	require.NoError(e.t, e.db.Create(&model.AssetNode{AssetID: a.ID, NodeID: e.nodes[node]}).Error)
	return a.ID
}

func (e *riEnv) count(m any) int64 {
	e.t.Helper()
	var n int64
	require.NoError(e.t, e.db.Model(m).Count(&n).Error)
	return n
}

func (e *riEnv) row(name string, nodes []uint, credKey string) asset.ImportRow {
	r := asset.ImportRow{Name: name, Protocol: "ssh", Host: "10.72.0.1", NodeIDs: nodes}
	if credKey != "" {
		id := int64(e.cred[credKey])
		r.CredentialID = &id
	}
	return r
}

func credRef(id int64) *int64 { return &id }

func errsJSON(t *testing.T, rep asset.ImportRowReport) string {
	t.Helper()
	b, err := json.Marshal(rep.Errors)
	require.NoError(t, err)
	return string(b)
}

func TestScopedImportRowScope(t *testing.T) {
	e := newRiEnv(t)
	if os.Getenv(testgate.EnvPGDSN) != "" {
		require.Equal(t, "postgres", e.db.Dialector.Name())
		fmt.Println("EVIDENCE dialect=postgres")
	}
	in, in2, hidden := e.nodes["ri-in"], e.nodes["ri-in2"], e.nodes["ri-hidden"]

	t.Run("preview_rows", func(t *testing.T) {
		assetsBefore := e.count(&model.Asset{})
		rows := []asset.ImportRow{
			e.row("ri-p0", []uint{in}, ""),
			e.row("ri-p1", []uint{hidden}, ""),
			e.row("ri-p2", []uint{987654}, ""),
			{Name: "ri-p3", Protocol: "ssh", Host: "10.72.0.3", NodePaths: []string{e.paths["ri-hidden"]}},
			{Name: "ri-p4", Protocol: "ssh", Host: "10.72.0.4", NodePaths: []string{"ri-no-such-node"}},
			e.row("ri-p5", []uint{in}, "hidden-dedicated"),
			e.row("ri-p6", []uint{in}, "hidden-rotating"),
			{Name: "ri-p7", Protocol: "ssh", Host: "10.72.0.7", NodeIDs: []uint{in}, CredentialID: credRef(876543)},
			e.row("ri-p8", []uint{in}, "global"),
			e.row("ri-p9", nil, ""),
			e.row("ri-p10", []uint{in2}, "in"),
		}
		pv, err := e.svc.PreviewImport(e.ctx(e.scoped), &asset.ImportBatch{Rows: rows})
		require.NoError(t, err)
		r := pv.Rows
		require.Empty(t, r[0].Errors)
		require.Equal(t, errsJSON(t, r[2]), errsJSON(t, r[1]), "範圍外節點與不存在節點同形")
		require.Len(t, r[1].Errors, 1)
		for i, p := range map[int]string{3: e.paths["ri-hidden"], 4: "ri-no-such-node"} {
			require.Len(t, r[i].Errors, 1, "列 %d", i)
			require.Equal(t, apierror.CodeAssetImportNodePath, r[i].Errors[0].Code)
			require.Equal(t, map[string]any{"path": p}, r[i].Errors[0].Params, "只帶使用者填的路徑")
		}
		want := errsJSON(t, r[7])
		require.Len(t, r[7].Errors, 1)
		require.Equal(t, apierror.CodeCredentialNotFound, r[7].Errors[0].Code)
		for _, i := range []int{5, 6, 8} {
			require.Equal(t, want, errsJSON(t, r[i]), "列 %d 與不存在憑證同形", i)
			require.Nil(t, r[i].Resolved.Credential)
		}
		require.Len(t, r[9].Errors, 1)
		require.Equal(t, apierror.CodeAssetNodeRequired, r[9].Errors[0].Code)
		require.Empty(t, r[10].Errors)
		require.NotNil(t, r[10].Resolved.Credential)
		require.Equal(t, e.credRow["in"], r[10].Resolved.Credential.Name)

		// 以識別碼指向範圍外的列：回應原文不含範圍外節點與憑證的名稱
		idRows := []asset.ImportRow{rows[1], rows[5], rows[6], rows[8]}
		pv2, err := e.svc.PreviewImport(e.ctx(e.scoped), &asset.ImportBatch{Rows: idRows})
		require.NoError(t, err)
		raw, err := json.Marshal(pv2)
		require.NoError(t, err)
		for _, leak := range []string{"ri-hidden", e.credRow["hidden-dedicated"], e.credRow["hidden-rotating"],
			e.credRow["global"]} {
			require.NotContains(t, string(raw), leak)
		}

		// 全域主體：全域歸屬憑證與留空節點皆通過
		g, err := e.svc.PreviewImport(e.ctx(e.global), &asset.ImportBatch{Rows: []asset.ImportRow{rows[8], rows[9]}})
		require.NoError(t, err)
		require.True(t, g.OK, "%+v", g.Rows)
		require.Equal(t, assetsBefore, e.count(&model.Asset{}), "預檢不寫入")
	})

	t.Run("global_preview_unchanged", func(t *testing.T) {
		var rows []asset.ImportRow
		keys := []string{"", "in", "hidden", "global", "hidden-rotating", "hidden-dedicated"}
		nodeSets := [][]uint{{in}, {hidden}, nil, {in, hidden}, {987654}}
		for i := 0; i < 40; i++ {
			r := e.row(fmt.Sprintf("ri-g%02d", i), nodeSets[i%len(nodeSets)], keys[i%len(keys)])
			if i%7 == 3 {
				r.NodeIDs, r.NodePaths = nil, []string{e.paths["ri-hidden"]}
			}
			if i == 11 {
				r.Name = "ri-dup-hidden"
			}
			rows = append(rows, r)
		}
		got, err := e.svc.PreviewImport(e.ctx(e.global), &asset.ImportBatch{Rows: rows})
		require.NoError(t, err)
		base, err := e.legacy.PreviewImport(e.ctx(e.global), &asset.ImportBatch{Rows: rows})
		require.NoError(t, err)
		gb, _ := json.Marshal(got)
		bb, _ := json.Marshal(base)
		require.JSONEq(t, string(bb), string(gb), "全域主體的預檢與範圍判定出現前逐欄相同")
	})

	t.Run("commit_rechecks_in_tx", func(t *testing.T) {
		rows := []asset.ImportRow{
			e.row("ri-c0", []uint{in}, ""),
			e.row("ri-c1", []uint{in2}, ""),
			e.row("ri-c2", []uint{in}, "in"),
		}
		counts := func() [3]int64 {
			return [3]int64{e.count(&model.Asset{}), e.count(&model.AssetNode{}), e.count(&model.AuditLog{})}
		}
		expectRowErr := func(hook func(), undo func(), wantIndex int, wantCode apierror.ErrCode) {
			t.Helper()
			before := counts()
			e.svc.SetImportPreTxHookForTest(hook)
			_, err := e.svc.ImportAssets(e.ctx(e.scoped), &asset.ImportBatch{Rows: rows}, e.scoped, "ri-scoped")
			e.svc.SetImportPreTxHookForTest(nil)
			undo()
			var changed *asset.ImportStateChangedError
			require.True(t, errors.As(err, &changed), "應整批拒絕：%v", err)
			require.Len(t, changed.Rows, 1)
			require.Equal(t, wantIndex, changed.Rows[0].Index)
			require.Len(t, changed.Rows[0].Errors, 1)
			require.Equal(t, wantCode, changed.Rows[0].Errors[0].Code)
			require.Nil(t, changed.Rows[0].Resolved.Credential)
			require.Empty(t, changed.Rows[0].Resolved.NodePaths)
			require.Equal(t, before, counts(), "資產、掛載與審計筆數不變")
		}

		var binding model.RoleBindingNode
		require.NoError(t, e.db.Where("subject_id = ? AND node_id = ?", e.scoped, in2).First(&binding).Error)
		expectRowErr(func() {
			require.NoError(t, e.db.Where("subject_id = ? AND node_id = ?", e.scoped, in2).
				Delete(&model.RoleBindingNode{}).Error)
		}, func() {
			require.NoError(t, e.db.Create(&binding).Error)
		}, 1, apierror.CodeAssetNodeNotFound)

		credID := e.cred["in"]
		expectRowErr(func() {
			require.NoError(t, e.db.Model(&model.Credential{}).Where("id = ?", credID).
				Update("owner_node_id", hidden).Error)
		}, func() {
			require.NoError(t, e.db.Model(&model.Credential{}).Where("id = ?", credID).
				Update("owner_node_id", in).Error)
		}, 2, apierror.CodeCredentialNotFound)

		// 只以路徑指定節點的列被撤權：回顯值只有使用者填的路徑，不帶由路徑解析出的節點識別
		rows[1].NodeIDs, rows[1].NodePaths = nil, []string{e.paths["ri-in2"]}
		expectRowErr(func() {
			require.NoError(t, e.db.Where("subject_id = ? AND node_id = ?", e.scoped, in2).
				Delete(&model.RoleBindingNode{}).Error)
		}, func() {
			require.NoError(t, e.db.Create(&binding).Error)
		}, 1, apierror.CodeAssetImportNodePath)
		e.svc.SetImportPreTxHookForTest(func() {
			require.NoError(t, e.db.Where("subject_id = ? AND node_id = ?", e.scoped, in2).
				Delete(&model.RoleBindingNode{}).Error)
		})
		_, err := e.svc.ImportAssets(e.ctx(e.scoped), &asset.ImportBatch{Rows: rows}, e.scoped, "ri-scoped")
		e.svc.SetImportPreTxHookForTest(nil)
		require.NoError(t, e.db.Create(&binding).Error)
		var changed *asset.ImportStateChangedError
		require.True(t, errors.As(err, &changed), "%v", err)
		require.Empty(t, changed.Rows[0].Values.NodeIDs, "不回由路徑解析出的節點識別")
		require.Equal(t, []string{e.paths["ri-in2"]}, changed.Rows[0].Values.NodePaths)
		raw, merr := json.Marshal(changed.Rows[0])
		require.NoError(t, merr)
		require.NotContains(t, string(raw), fmt.Sprintf(`"node_ids":[%d]`, in2))
		rows[1].NodeIDs, rows[1].NodePaths = []uint{in2}, nil

		advances := e.port.advances.Load()
		res, err := e.svc.ImportAssets(e.ctx(e.scoped), &asset.ImportBatch{Rows: rows}, e.scoped, "ri-scoped")
		require.NoError(t, err)
		require.Equal(t, 3, res.Created)
		require.Equal(t, advances+1, e.port.advances.Load(), "整批只推進一次")
		for _, id := range res.AssetIDs {
			var logs []model.AuditLog
			require.NoError(t, e.db.Where("resource = ? AND resource_id = ? AND details LIKE ?",
				string(model.ResourceAsset), id, "%node_ids%").Find(&logs).Error)
			require.Len(t, logs, 1, "資產 %d 一筆初始掛載審計", id)
			require.Contains(t, logs[0].Details, "topology_coverage")
		}
	})

	t.Run("node_required_both_phases", func(t *testing.T) {
		before := e.count(&model.Asset{})
		_, err := e.svc.ImportAssets(e.ctx(e.scoped), &asset.ImportBatch{Rows: []asset.ImportRow{
			e.row("ri-n0", nil, "")}}, e.scoped, "ri-scoped")
		var invalid *asset.ImportRowsInvalidError
		require.True(t, errors.As(err, &invalid), "%v", err)
		require.Equal(t, apierror.CodeAssetNodeRequired, invalid.Preview.Rows[0].Errors[0].Code)

		// 預檢時仍有全系統來源、提交前改為只經節點範圍持有：交易內以發起者當下的指派重算
		flip := e.user("ri-flip")
		var role model.UserRole
		require.NoError(t, e.db.Where("user_id = ?", e.global).First(&role).Error)
		require.NoError(t, e.db.Create(&model.UserRole{UserID: flip, RoleID: role.RoleID,
			Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
		e.svc.SetImportPreTxHookForTest(func() {
			require.NoError(t, e.db.Model(&model.UserRole{}).Where("user_id = ?", flip).
				Update("scope_kind", model.ScopeKindNodes).Error)
			require.NoError(t, e.db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser,
				SubjectID: flip, RoleID: role.RoleID, NodeID: in}).Error)
		})
		_, err = e.svc.ImportAssets(e.ctx(flip), &asset.ImportBatch{Rows: []asset.ImportRow{
			e.row("ri-n1", nil, "")}}, flip, "ri-flip")
		e.svc.SetImportPreTxHookForTest(nil)
		var changed *asset.ImportStateChangedError
		require.True(t, errors.As(err, &changed), "%v", err)
		require.Equal(t, apierror.CodeAssetNodeRequired, changed.Rows[0].Errors[0].Code)
		require.Equal(t, before, e.count(&model.Asset{}), "未落到根或預設節點")
	})

	t.Run("name_conflict_same_shape", func(t *testing.T) {
		pv, err := e.svc.PreviewImport(e.ctx(e.scoped), &asset.ImportBatch{Rows: []asset.ImportRow{
			e.row("ri-dup-hidden", []uint{in}, ""), e.row("ri-dup-in", []uint{in}, ""),
		}})
		require.NoError(t, err)
		require.NotEmpty(t, pv.Rows[0].Errors)
		require.Equal(t, errsJSON(t, pv.Rows[1]), errsJSON(t, pv.Rows[0]))
		require.False(t, strings.Contains(errsJSON(t, pv.Rows[0]), "ri-hidden"))
	})
	t.Run("write_scope_missing_fails_closed", func(t *testing.T) {
		svc := e.newSvc()
		svc.WithManagementAuthorizer(swAllowCredentials{}).WithSystemAlertSink(swNoopAlerts{})
		before := e.count(&model.Asset{})
		batch := &asset.ImportBatch{Rows: []asset.ImportRow{e.row("ri-w0", []uint{in}, "")}}
		for _, uid := range []uint{e.scoped, e.global} {
			_, err := svc.PreviewImport(e.ctx(uid), batch)
			require.ErrorIs(t, err, asset.ErrAssetWriteScopePortMissing, "預檢：寫入範圍判定未注入即拒絕")
			_, err = svc.ImportAssets(e.ctx(uid), batch, uid, "ri-op")
			require.ErrorIs(t, err, asset.ErrAssetWriteScopePortMissing, "提交：寫入範圍判定未注入即拒絕")
		}
		_, err := svc.ImportAssets(asset.WithSystemCaller(e.ctx(e.super)), batch, e.super, "ri-op")
		require.NoError(t, err, "系統呼叫者不經範圍判定")
		require.Equal(t, before+1, e.count(&model.Asset{}))
	})

	t.Run("lock_before_row_locks", func(t *testing.T) {
		if e.db.Dialector.Name() != "postgres" {
			t.Skip("SQLite 無 advisory 鎖與列鎖；此子案例只在 PostgreSQL 跑法計入")
		}
		const sameKey = ` AND locktype = 'advisory' AND classid::bigint = ? AND objid::bigint = 1 AND objsubid = 2
   AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`
		holder := e.db.Begin()
		require.NoError(t, holder.Error)
		defer holder.Rollback() // 在 release 之後執行：已提交時為 no-op
		released := false
		release := func() {
			if !released {
				released = true
				_ = holder.Commit().Error
			}
		}
		defer release()
		var holderPID int64
		require.NoError(t, holder.Raw("SELECT pg_backend_pid()").Scan(&holderPID).Error)
		require.NoError(t, holder.Exec("SELECT pg_advisory_xact_lock(?, ?)",
			authz.TopologySerializationLockClass, int32(1)).Error)

		pidc := make(chan int64, 1)
		e.svc.SetImportTxStartHookForTest(func(tx *gorm.DB) {
			var pid int64
			_ = tx.Raw("SELECT pg_backend_pid()").Scan(&pid).Error
			pidc <- pid
		})
		defer e.svc.SetImportTxStartHookForTest(nil)
		before := e.count(&model.Asset{})
		credID := e.cred["in"]
		errc := make(chan error, 1)
		go func() {
			_, err := e.svc.ImportAssets(e.ctx(e.scoped), &asset.ImportBatch{Rows: []asset.ImportRow{
				e.row("ri-l0", []uint{in}, "in")}}, e.scoped, "ri-scoped")
			errc <- err
		}()
		defer func() {
			release()
			select {
			case <-errc:
			case <-time.After(10 * time.Second):
			}
		}()
		var importPID int64
		select {
		case importPID = <-pidc:
		case <-time.After(5 * time.Second):
			t.Fatal("提交交易開始掛點未觸發")
		}
		require.NotZero(t, importPID)
		require.NotEqual(t, holderPID, importPID)

		waiting := false
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			var n int64
			require.NoError(t, e.db.Raw(`SELECT count(*) FROM pg_locks WHERE pid = ? AND NOT granted`+sameKey,
				importPID, authz.TopologySerializationLockClass).Scan(&n).Error)
			if n == 1 {
				waiting = true
				break
			}
		}
		require.True(t, waiting, "提交交易須在拓撲序列化鎖上排隊（5 秒內）")
		var blocked bool
		require.NoError(t, e.db.Raw("SELECT ?::int = ANY(pg_blocking_pids(?::int))", holderPID, importPID).
			Scan(&blocked).Error)
		require.True(t, blocked, "擋住提交交易的正是持鎖連線")
		var held int64
		require.NoError(t, e.db.Raw(`SELECT count(*) FROM pg_locks WHERE pid = ? AND granted`+sameKey,
			holderPID, authz.TopologySerializationLockClass).Scan(&held).Error)
		require.Equal(t, int64(1), held)
		t.Logf("EVIDENCE holder_pid=%d import_pid=%d class=%d objid=1 objsubid=2 waiting=true blocked_by_holder=true",
			holderPID, importPID, authz.TopologySerializationLockClass)
		require.Equal(t, before, e.count(&model.Asset{}), "等鎖期間尚未寫入任何列")

		probe := e.db.Begin()
		require.NoError(t, probe.Error)
		probeErr := probe.Exec("SELECT id FROM credentials WHERE id = ? FOR UPDATE NOWAIT", credID).Error
		require.NoError(t, probe.Rollback().Error)
		require.NoError(t, probeErr, "等鎖期間共用憑證列尚未被鎖（憑證列鎖在序列化鎖之後）")
		select {
		case err := <-errc:
			t.Fatalf("持鎖者未放行，提交不得完成：%v", err)
		case <-time.After(200 * time.Millisecond):
		}

		release()
		select {
		case err := <-errc:
			require.NoError(t, err)
			errc <- nil
		case <-time.After(10 * time.Second):
			t.Fatal("放行後提交未完成")
		}
		require.Equal(t, before+1, e.count(&model.Asset{}), "放行後匯入照常完成")
	})
}
