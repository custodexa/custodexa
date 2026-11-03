package asset

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// 執行身分讀取帶設定來源：來源落在掛載列，不由審計反查。

func TestExecutorSource(t *testing.T) {
	db := setupCredentialDB(t)
	f := newExecutorFixture(t, db)
	ctx := adminCtx()

	sharedCred := func(name, user string) uint {
		c, err := f.creds.Create(ctx, &CreateCredentialRequest{Name: name, Username: user,
			ProtocolFamily: model.ProtocolFamilySSH, Password: "pw"})
		require.NoError(t, err)
		return c.ID
	}

	t.Run("each_source_is_read_back", func(t *testing.T) {
		gen := f.host(t, "src-gen", model.ProtocolSSH)
		inl := f.host(t, "src-inl", model.ProtocolSSH)
		shr := f.host(t, "src-shr", model.ProtocolSSH)
		cnv := f.host(t, "src-cnv", model.ProtocolSSH)
		_, err := f.exec.Set(ctx, gen.ID, &SetExecutorRequest{Source: ExecutorSourceGenerate, Username: "cx-exec", ExpectedAccountID: uptr(0)})
		require.NoError(t, err)
		_, err = f.exec.Set(ctx, inl.ID, &SetExecutorRequest{Source: ExecutorSourceInline, Username: "cx-exec", Password: "exec-pw", ExpectedAccountID: uptr(0)})
		require.NoError(t, err)
		_, err = f.exec.Set(ctx, shr.ID, &SetExecutorRequest{Source: ExecutorSourceShared, CredentialID: sharedCred("src-shared", "svc-src"),
			AcknowledgedHostCount: iptr(1), ExpectedAccountID: uptr(0)})
		require.NoError(t, err)
		ops, err := f.accounts.Create(WithSystemCaller(ctx), cnv.ID, &CreateAssetAccountRequest{Username: "ops", Password: "ops-pw"})
		require.NoError(t, err)
		_, err = f.exec.Set(ctx, cnv.ID, &SetExecutorRequest{Source: ExecutorSourceConvert, AccountID: ops.ID, ExpectedAccountID: uptr(0)})
		require.NoError(t, err)

		for id, want := range map[uint]string{gen.ID: ExecutorSourceGenerate, inl.ID: ExecutorSourceInline,
			shr.ID: ExecutorSourceShared, cnv.ID: ExecutorSourceConvert} {
			got, err := f.exec.Get(ctx, id)
			require.NoError(t, err)
			assert.Equal(t, want, got.Source)
		}
	})

	t.Run("replace_changes_source", func(t *testing.T) {
		a := f.host(t, "src-replace", model.ProtocolSSH)
		first, err := f.exec.Set(ctx, a.ID, &SetExecutorRequest{Source: ExecutorSourceGenerate, Username: "cx-exec", ExpectedAccountID: uptr(0)})
		require.NoError(t, err)
		assert.Equal(t, ExecutorSourceGenerate, first.Source)
		second, err := f.exec.Set(ctx, a.ID, &SetExecutorRequest{Source: ExecutorSourceShared, CredentialID: sharedCred("src-replace-shared", "svc-rep"),
			AcknowledgedHostCount: iptr(1), ExpectedAccountID: uptr(first.AccountID)})
		require.NoError(t, err)
		assert.Equal(t, ExecutorSourceShared, second.Source, "PUT 回應與 GET 同形")
		got, err := f.exec.Get(ctx, a.ID)
		require.NoError(t, err)
		assert.Equal(t, ExecutorSourceShared, got.Source)
	})

	t.Run("convert_survives_audit_purge", func(t *testing.T) {
		a := f.host(t, "src-purge", model.ProtocolSSH)
		ops, err := f.accounts.Create(WithSystemCaller(ctx), a.ID, &CreateAssetAccountRequest{Username: "ops", Password: "ops-pw"})
		require.NoError(t, err)
		_, err = f.exec.Set(ctx, a.ID, &SetExecutorRequest{Source: ExecutorSourceConvert, AccountID: ops.ID, ExpectedAccountID: uptr(0)})
		require.NoError(t, err)
		require.NoError(t, db.Exec("DELETE FROM audit_logs").Error)
		got, err := f.exec.Get(ctx, a.ID)
		require.NoError(t, err)
		assert.Equal(t, ExecutorSourceConvert, got.Source, "來源不依賴審計表")
	})

	t.Run("empty_source_omits_key", func(t *testing.T) {
		a := f.host(t, "src-empty", model.ProtocolSSH)
		set, err := f.exec.Set(ctx, a.ID, &SetExecutorRequest{Source: ExecutorSourceGenerate, Username: "cx-exec", ExpectedAccountID: uptr(0)})
		require.NoError(t, err)
		require.NoError(t, db.Exec("UPDATE asset_accounts SET executor_source = '' WHERE id = ?", set.AccountID).Error)
		got, err := f.exec.Get(ctx, a.ID)
		require.NoError(t, err)
		raw, err := json.Marshal(got)
		require.NoError(t, err)
		m := map[string]json.RawMessage{}
		require.NoError(t, json.Unmarshal(raw, &m))
		assert.NotContains(t, m, "source")
		assert.True(t, got.Configured)
	})

	t.Run("response_and_audit_carry_no_secret", func(t *testing.T) {
		a := f.host(t, "src-secret", model.ProtocolSSH)
		set, err := f.exec.Set(ctx, a.ID, &SetExecutorRequest{Source: ExecutorSourceGenerate, Username: "cx-exec", ExpectedAccountID: uptr(0)})
		require.NoError(t, err)
		got, err := f.exec.Get(ctx, a.ID)
		require.NoError(t, err)
		assertNoKeyMaterial(t, set)
		assertNoKeyMaterial(t, got)
		var rows []model.AuditLog
		require.NoError(t, db.Where("resource = ? AND resource_id = ?", string(model.ResourceAsset), a.ID).Find(&rows).Error)
		require.NotEmpty(t, rows)
		for _, r := range rows {
			assert.NotContains(t, r.Details, "-----BEGIN")
			assert.NotContains(t, r.Details, "ssh-ed25519")
		}
	})
}
