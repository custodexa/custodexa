package asset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/branding"
	"github.com/custodexa/backend/internal/model"
)

// 執行身分的公鑰揭露、共用台數確認與審計。

// fakeExecutorVisibility 共用憑證可見集合的替身。
type fakeExecutorVisibility struct{ visible map[uint]bool }

func (f *fakeExecutorVisibility) SharedCredentialVisible(_ context.Context, id uint) (bool, error) {
	return f.visible[id], nil
}

// onlyAssetsExecutorScope 範圍化主體替身：只有列出的資產在範圍內，其餘回不存在。
type onlyAssetsExecutorScope struct{ ids map[uint]bool }

func (s onlyAssetsExecutorScope) AuthorizeExecutorManage(_ context.Context, _ *gorm.DB, assetID uint) error {
	if s.ids[assetID] {
		return nil
	}
	return ErrAssetNotFound
}

// sharedKeyCredential 共用金鑰憑證，就位版本帶公鑰（type＋base64）。
func (f *executorFixture) sharedKeyCredential(t *testing.T, name, username string) *model.Credential {
	t.Helper()
	private, line, err := GenerateSSHKeyPair("test")
	require.NoError(t, err)
	cred, err := f.creds.Create(adminCtx(), &CreateCredentialRequest{Name: name, Username: username,
		ProtocolFamily: model.ProtocolFamilySSH, PrivateKey: private})
	require.NoError(t, err)
	fields := strings.Fields(line)
	var row model.Credential
	require.NoError(t, f.db.First(&row, cred.ID).Error)
	require.NotNil(t, row.CurrentVersionID)
	require.NoError(t, f.db.Model(&model.CredentialSecretVersion{}).Where("id = ?", *row.CurrentVersionID).
		Update("public_key", fields[0]+" "+fields[1]).Error)
	return &row
}

// jsonKeys 回應序列化後的頂層鍵集。
func jsonKeys(t *testing.T, v any) map[string]bool {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	out := map[string]bool{}
	for k := range m {
		out[k] = true
	}
	return out
}

func TestAssetExecutorPublicKeyExport(t *testing.T) {
	db := setupCredentialDB(t)
	f := newExecutorFixture(t, db)
	vis := &fakeExecutorVisibility{visible: map[uint]bool{}}
	f.exec.WithCredentialVisibility(vis)
	ctx := adminCtx()

	t.Run("generated_key_line", func(t *testing.T) {
		a := f.host(t, "pk-gen-1", model.ProtocolSSH)
		got, err := f.exec.Set(ctx, a.ID, &SetExecutorRequest{Source: ExecutorSourceGenerate, Username: "cx-exec", ExpectedAccountID: uptr(0)})
		require.NoError(t, err)
		line, err := f.exec.ExportPublicKey(ctx, a.ID)
		require.NoError(t, err)
		pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		require.NoError(t, err)

		var m model.AssetAccount
		require.NoError(t, db.First(&m, got.AccountID).Error)
		var v model.CredentialSecretVersion
		require.NoError(t, db.First(&v, *m.EffectiveVersionID).Error)
		// 公鑰隨 v1 一起建立（版本列只准新增、不得事後覆寫）：該憑證只有這一列，且公鑰已在其中
		var versions int64
		require.NoError(t, db.Model(&model.CredentialSecretVersion{}).Where("credential_id = ?", m.CredentialID).Count(&versions).Error)
		assert.EqualValues(t, 1, versions)
		assert.Equal(t, 1, v.VersionNo)
		require.NotEmpty(t, v.PublicKey, "公鑰須與密文同列建立")
		assert.Equal(t, v.PublicKey, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), "金鑰部分與版本列相同")
		assert.Equal(t, fmt.Sprintf("%s-credential-%d", branding.Slug, m.CredentialID), comment)
		assert.NotContains(t, comment, a.Name)
		assert.NotContains(t, comment, "asset")

		read, err := f.exec.Get(ctx, a.ID)
		require.NoError(t, err)
		require.NotNil(t, read.HasPublicKey)
		assert.True(t, *read.HasPublicKey)
		assert.Equal(t, ssh.FingerprintSHA256(pub), read.Fingerprint, "指紋等於讀取回應")
		assertNoKeyMaterial(t, read)
		findAccountAudit(t, db, a.ID, model.AccountOpExecutorPublicKeyExport)
	})

	t.Run("password_type_sentinel", func(t *testing.T) {
		a := f.host(t, "pk-pw-1", model.ProtocolSSH)
		_, err := f.exec.Set(ctx, a.ID, &SetExecutorRequest{Source: ExecutorSourceInline, Username: "cx-exec", Password: "pw", ExpectedAccountID: uptr(0)})
		require.NoError(t, err)
		_, err = f.exec.ExportPublicKey(ctx, a.ID)
		require.ErrorIs(t, err, ErrAssetExecutorPublicKeyNotFound)
		read, err := f.exec.Get(ctx, a.ID)
		require.NoError(t, err)
		keys := jsonKeys(t, read)
		assert.False(t, keys["has_public_key"])
		assert.False(t, keys["fingerprint"])
	})

	t.Run("out_of_scope_shared_key_hidden", func(t *testing.T) {
		cred := f.sharedKeyCredential(t, "pk-shared", "svc-key")
		hosts := []*model.Asset{f.host(t, "pk-sh-1", model.ProtocolSSH), f.host(t, "pk-sh-2", model.ProtocolSSH)}
		for i, a := range hosts {
			_, err := f.exec.Set(ctx, a.ID, &SetExecutorRequest{Source: ExecutorSourceShared, CredentialID: cred.ID,
				AcknowledgedHostCount: iptr(i + 1), ExpectedAccountID: uptr(0)})
			require.NoError(t, err)
		}
		vis.visible[cred.ID] = false
		var exportErrs []error
		for _, a := range hosts {
			read, err := f.exec.Get(ctx, a.ID)
			require.NoError(t, err)
			keys := jsonKeys(t, read)
			assert.False(t, keys["has_public_key"], "範圍外共用金鑰不帶 has_public_key")
			assert.False(t, keys["fingerprint"], "範圍外共用金鑰不帶指紋")
			_, err = f.exec.ExportPublicKey(ctx, a.ID)
			require.True(t, errors.Is(err, ErrAssetExecutorPublicKeyNotFound), "範圍外共用金鑰匯出回同一哨兵：%v", err)
			exportErrs = append(exportErrs, err)
		}
		assert.Equal(t, exportErrs[0].Error(), exportErrs[1].Error())

		// 對照：可見時兩欄出現（證明上面確實走到可見性判定）
		vis.visible[cred.ID] = true
		read, err := f.exec.Get(ctx, hosts[0].ID)
		require.NoError(t, err)
		assert.NotEmpty(t, read.Fingerprint)
	})
}

func TestAssetExecutorSharedHostCount(t *testing.T) {
	db := setupCredentialDB(t)
	f := newExecutorFixture(t, db)
	ctx := adminCtx()
	cred, err := f.creds.Create(ctx, &CreateCredentialRequest{Name: "hc-shared", Username: "svc-hc",
		ProtocolFamily: model.ProtocolFamilySSH, Password: "pw"})
	require.NoError(t, err)
	setShared := func(svc *AssetExecutorService, assetID uint, ack *int) error {
		_, err := svc.Set(ctx, assetID, &SetExecutorRequest{Source: ExecutorSourceShared, CredentialID: cred.ID,
			AcknowledgedHostCount: ack, ExpectedAccountID: uptr(0)})
		return err
	}
	for i := 1; i <= 6; i++ {
		a := f.host(t, fmt.Sprintf("hc-%d", i), model.ProtocolSSH)
		require.NoError(t, setShared(f.exec, a.ID, iptr(i)))
	}
	target := f.host(t, "hc-target", model.ProtocolSSH)
	// 範圍化主體：只有目標這台在範圍內，已掛的六台都在範圍外
	scoped := NewAssetExecutorService(f.accounts, onlyAssetsExecutorScope{ids: map[uint]bool{target.ID: true}})

	countOf := func(t *testing.T, err error) int {
		t.Helper()
		var hc *ExecutorSharedHostCountError
		require.True(t, errors.As(err, &hc), "應為台數確認錯誤：%v", err)
		raw, merr := json.Marshal(hc)
		require.NoError(t, merr)
		assert.JSONEq(t, fmt.Sprintf(`{"Count":%d}`, hc.Count), string(raw), "錯誤值只帶台數")
		for i := 1; i <= 6; i++ {
			assert.NotContains(t, err.Error(), fmt.Sprintf("hc-%d", i))
		}
		assert.NotContains(t, err.Error(), "hc-target")
		return hc.Count
	}
	rejectedBoth := func(t *testing.T, ack *int) int {
		t.Helper()
		before := f.state(t)
		global := countOf(t, setShared(f.exec, target.ID, ack))
		scopedCount := countOf(t, setShared(scoped, target.ID, ack))
		assert.Equal(t, global, scopedCount, "全域主體與範圍化主體結果相同")
		assert.Equal(t, before, f.state(t), "掛載不變")
		return global
	}

	t.Run("missing", func(t *testing.T) {
		assert.Equal(t, 7, rejectedBoth(t, nil))
	})
	t.Run("stale", func(t *testing.T) {
		assert.Equal(t, 7, rejectedBoth(t, iptr(6)))
	})
	t.Run("another_host_mounted_after_confirm", func(t *testing.T) {
		extra := f.host(t, "hc-7", model.ProtocolSSH)
		require.NoError(t, setShared(f.exec, extra.ID, iptr(7)))
		assert.Equal(t, 8, rejectedBoth(t, iptr(7)))
	})
	t.Run("match", func(t *testing.T) {
		require.NoError(t, setShared(scoped, target.ID, iptr(8)))
		d := findAccountAudit(t, db, target.ID, model.AccountOpExecutorSet)
		assert.Equal(t, 8, d.HostCount)
	})
}

// auditRowsFor 某資產的帳號類審計列（動作與原始 details）。
func executorAuditRows(t *testing.T, db *gorm.DB, assetID uint) map[string]model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	require.NoError(t, db.Where("resource = ? AND resource_id = ?", string(model.ResourceAsset), assetID).
		Order("id ASC").Find(&rows).Error)
	out := map[string]model.AuditLog{}
	for _, row := range rows {
		var d model.AssetAccountAuditDetails
		if json.Unmarshal([]byte(row.Details), &d) == nil && d.Resource == "asset_account" {
			out[d.Operation] = row
		}
	}
	return out
}

func TestAssetExecutorAudit(t *testing.T) {
	db := setupCredentialDB(t)
	f := newExecutorFixture(t, db)
	f.exec.WithCredentialVisibility(&fakeExecutorVisibility{visible: map[uint]bool{}})
	ctx := adminCtx()

	t.Run("four_operations", func(t *testing.T) {
		a := f.host(t, "audit-1", model.ProtocolSSH)
		first, err := f.exec.Set(ctx, a.ID, &SetExecutorRequest{Source: ExecutorSourceGenerate, Username: "cx-exec", ExpectedAccountID: uptr(0)})
		require.NoError(t, err)
		_, err = f.exec.ExportPublicKey(ctx, a.ID)
		require.NoError(t, err)
		second, err := f.exec.Set(ctx, a.ID, &SetExecutorRequest{Source: ExecutorSourceInline, Username: "cx-exec",
			PrivateKey: executorTestKey(t), ExpectedAccountID: uptr(first.AccountID)})
		require.NoError(t, err)
		require.NoError(t, f.exec.Clear(ctx, a.ID, uptr(second.AccountID)))

		rows := executorAuditRows(t, db, a.ID)
		want := map[string]model.AuditAction{
			model.AccountOpExecutorSet:             model.ActionCreate,
			model.AccountOpExecutorReplace:         model.ActionUpdate,
			model.AccountOpExecutorClear:           model.ActionDelete,
			model.AccountOpExecutorPublicKeyExport: model.ActionRead,
		}
		for op, action := range want {
			row, ok := rows[op]
			require.True(t, ok, "缺 %s 審計", op)
			assert.Equal(t, action, row.Action, op)
			assert.NotContains(t, row.Details, "ssh-ed25519", op)
			assert.NotContains(t, row.Details, "-----BEGIN", op)
		}
		var set model.AssetAccountAuditDetails
		require.NoError(t, json.Unmarshal([]byte(rows[model.AccountOpExecutorSet].Details), &set))
		assert.Equal(t, ExecutorSourceGenerate, set.Source)
	})

	t.Run("audit_failure_rolls_back", func(t *testing.T) {
		a := f.host(t, "audit-fail-1", model.ProtocolSSH)
		failing := NewAssetAccountService(f.assets, f.codec, failingTxSink{err: errors.New("audit down")}).
			WithManagementAuthorizer(f.auth).WithSystemAlertSink(newFakeAlertSink()).WithAccountWriteScope(allowAllAccountWriteScope{})
		svc := NewAssetExecutorService(failing, allowAllExecutorScope{})
		before := f.state(t)
		_, err := svc.Set(ctx, a.ID, &SetExecutorRequest{Source: ExecutorSourceGenerate, Username: "cx-exec", ExpectedAccountID: uptr(0)})
		require.Error(t, err)
		assert.Equal(t, before, f.state(t), "審計寫入失敗：無執行身分掛載也無新憑證")
		var execs int64
		require.NoError(t, db.Model(&model.AssetAccount{}).Where("asset_id = ? AND purpose = ?", a.ID, model.AccountPurposeExecutor).Count(&execs).Error)
		assert.Zero(t, execs)
	})
}

// fakeBindingScopeView 憑證檢視替身：只有 in 內的資產在檢視範圍，動作能力全部可用。
type fakeBindingScopeView struct{ in map[uint]bool }

func (v fakeBindingScopeView) ApplyVisible(q *gorm.DB) (*gorm.DB, error) { return q, nil }
func (v fakeBindingScopeView) AssetsInView(ids []uint) (map[uint]bool, error) {
	out := map[uint]bool{}
	for _, id := range ids {
		out[id] = v.in[id]
	}
	return out, nil
}
func (v fakeBindingScopeView) AssetsInCapability(_ string, ids []uint) (map[uint]bool, error) {
	return v.AssetsInView(ids)
}
func (v fakeBindingScopeView) Allows(string, []uint) (bool, string) { return true, "" }
func (v fakeBindingScopeView) MaskNodes(ids []uint) ([]uint, int)   { return ids, 0 }

func TestCredentialBindingPurposeProjection(t *testing.T) {
	db := setupCredentialDB(t)
	f := newExecutorFixture(t, db)
	ctx := adminCtx()
	execCred, err := f.creds.Create(ctx, &CreateCredentialRequest{Name: "proj-exec", Username: "svc-proj",
		ProtocolFamily: model.ProtocolFamilySSH, Password: "pw"})
	require.NoError(t, err)
	loginCred, err := f.creds.Create(ctx, &CreateCredentialRequest{Name: "proj-login", Username: "ops-proj",
		ProtocolFamily: model.ProtocolFamilySSH, Password: "pw"})
	require.NoError(t, err)
	hosts := []*model.Asset{f.host(t, "proj-1", model.ProtocolSSH), f.host(t, "proj-2", model.ProtocolSSH),
		f.host(t, "proj-out-zz", model.ProtocolSSH)}
	for i, a := range hosts {
		_, err := f.exec.Set(ctx, a.ID, &SetExecutorRequest{Source: ExecutorSourceShared, CredentialID: execCred.ID,
			AcknowledgedHostCount: iptr(i + 1), ExpectedAccountID: uptr(0)})
		require.NoError(t, err)
	}
	_, err = f.creds.Bind(ctx, loginCred.ID, &BindCredentialRequest{AssetID: hosts[0].ID})
	require.NoError(t, err)

	load := func(id uint) []*CredentialBindingDTO {
		var c model.Credential
		require.NoError(t, db.First(&c, id).Error)
		rows, err := credentialBindingDTOs(db, &c)
		require.NoError(t, err)
		return rows
	}
	execRows := load(execCred.ID)
	require.Len(t, execRows, 3)
	for _, r := range execRows {
		assert.Equal(t, model.AccountPurposeExecutor, r.Purpose)
	}

	view := fakeBindingScopeView{in: map[uint]bool{hosts[0].ID: true, hosts[1].ID: true}}
	scoped, outside, err := filterBindingsInView(db, view, execRows)
	require.NoError(t, err)
	require.Len(t, scoped, 2)
	assert.Equal(t, 1, outside)
	for _, r := range scoped {
		assert.Equal(t, CredentialAction{Allowed: false, Reason: CredentialActionExecutorManaged}, r.Actions["unbind"])
		assert.True(t, r.Actions["detach"].Allowed, "脫離照既有判定")
		assert.NotEqual(t, hosts[2].ID, r.AssetID)
	}
	raw, err := json.Marshal(scoped)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "proj-out-zz", "範圍外掛載不帶可識別欄位")

	loginRows, _, err := filterBindingsInView(db, view, load(loginCred.ID))
	require.NoError(t, err)
	require.Len(t, loginRows, 1)
	assert.Equal(t, model.AccountPurposeLogin, loginRows[0].Purpose)
	assert.True(t, loginRows[0].Actions["unbind"].Allowed, "登入列照舊可用")
}
