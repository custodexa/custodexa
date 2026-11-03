package asset

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 憑證列表與詳情的掛載用途：同一憑證的未刪除掛載用途一致，憑證層帶單值。

func dtoKeys(t *testing.T, v any) []string {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	m := map[string]json.RawMessage{}
	require.NoError(t, json.Unmarshal(raw, &m))
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func without(keys []string, drop string) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if k != drop {
			out = append(out, k)
		}
	}
	return out
}

func TestCredentialDTOPurpose(t *testing.T) {
	db := setupCredentialDB(t)
	f := newExecutorFixture(t, db)
	ctx := adminCtx()

	newShared := func(name, user string) *CredentialDTO {
		c, err := f.creds.Create(ctx, &CreateCredentialRequest{Name: name, Username: user,
			ProtocolFamily: model.ProtocolFamilySSH, Password: "pw"})
		require.NoError(t, err)
		return c
	}
	detailPurpose := func(id uint) string {
		var c model.Credential
		require.NoError(t, db.First(&c, id).Error)
		dto, err := f.creds.credentialDTO(db, &c)
		require.NoError(t, err)
		return dto.Purpose
	}

	t.Run("login_and_executor", func(t *testing.T) {
		login := newShared("purpose-login", "ops-p")
		exec := newShared("purpose-exec", "svc-p")
		h1 := f.host(t, "purpose-h1", model.ProtocolSSH)
		h2 := f.host(t, "purpose-h2", model.ProtocolSSH)
		_, err := f.creds.Bind(ctx, login.ID, &BindCredentialRequest{AssetID: h1.ID})
		require.NoError(t, err)
		_, err = f.exec.Set(ctx, h1.ID, &SetExecutorRequest{Source: ExecutorSourceShared, CredentialID: exec.ID,
			AcknowledgedHostCount: iptr(1), ExpectedAccountID: uptr(0)})
		require.NoError(t, err)
		_, err = f.exec.Set(ctx, h2.ID, &SetExecutorRequest{Source: ExecutorSourceShared, CredentialID: exec.ID,
			AcknowledgedHostCount: iptr(2), ExpectedAccountID: uptr(0)})
		require.NoError(t, err)
		assert.Equal(t, model.AccountPurposeLogin, detailPurpose(login.ID))
		assert.Equal(t, model.AccountPurposeExecutor, detailPurpose(exec.ID))

		list, err := f.creds.List(ctx, CredentialFilter{})
		require.NoError(t, err)
		got := map[uint]string{}
		for _, d := range list {
			got[d.ID] = d.Purpose
		}
		assert.Equal(t, model.AccountPurposeLogin, got[login.ID])
		assert.Equal(t, model.AccountPurposeExecutor, got[exec.ID])
	})

	t.Run("no_live_binding_omits_key", func(t *testing.T) {
		lone := newShared("purpose-lone", "svc-lone")
		var c model.Credential
		require.NoError(t, db.First(&c, lone.ID).Error)
		dto, err := f.creds.credentialDTO(db, &c)
		require.NoError(t, err)
		assert.NotContains(t, dtoKeys(t, dto), "purpose", "沒有掛載時不出現")

		// 掛載軟刪後同樣不出現
		h := f.host(t, "purpose-soft", model.ProtocolSSH)
		_, err = f.exec.Set(ctx, h.ID, &SetExecutorRequest{Source: ExecutorSourceShared, CredentialID: lone.ID,
			AcknowledgedHostCount: iptr(1), ExpectedAccountID: uptr(0)})
		require.NoError(t, err)
		assert.Equal(t, model.AccountPurposeExecutor, detailPurpose(lone.ID))
		require.NoError(t, db.Where("credential_id = ?", lone.ID).Delete(&model.AssetAccount{}).Error)
		assert.NotContains(t, dtoKeys(t, mustDTO(t, f, db, lone.ID)), "purpose", "掛載已軟刪不出現")
	})

	t.Run("scoped_viewer_all_bindings_out_of_scope", func(t *testing.T) {
		exec := newShared("purpose-scoped", "svc-scoped")
		h := f.host(t, "purpose-out-1", model.ProtocolSSH)
		_, err := f.exec.Set(ctx, h.ID, &SetExecutorRequest{Source: ExecutorSourceShared, CredentialID: exec.ID,
			AcknowledgedHostCount: iptr(1), ExpectedAccountID: uptr(0)})
		require.NoError(t, err)

		var c model.Credential
		require.NoError(t, db.First(&c, exec.ID).Error)
		dto, err := f.creds.credentialDTO(db, &c)
		require.NoError(t, err)
		purposes, err := credentialPurposes(db, []uint{c.ID})
		require.NoError(t, err)
		dto.Purpose = purposes[c.ID]
		require.NoError(t, f.creds.decorateScoped(db, fakeBindingScopeView{in: map[uint]bool{}},
			[]model.Credential{c}, []*CredentialDTO{dto}))
		assert.Equal(t, model.AccountPurposeExecutor, dto.Purpose, "範圍外掛載不影響用途")
		require.NotNil(t, dto.OutOfScopeAssets)
		assert.Equal(t, 1, *dto.OutOfScopeAssets)

		// BASE：沒有任何掛載的共用憑證，同樣經範圍化修飾後的對外鍵集（不含 purpose）
		base := newShared("purpose-base", "svc-base")
		var bc model.Credential
		require.NoError(t, db.First(&bc, base.ID).Error)
		baseDTO, err := f.creds.credentialDTO(db, &bc)
		require.NoError(t, err)
		require.NoError(t, f.creds.decorateScoped(db, fakeBindingScopeView{in: map[uint]bool{}},
			[]model.Credential{bc}, []*CredentialDTO{baseDTO}))
		assert.Equal(t, dtoKeys(t, baseDTO), without(dtoKeys(t, dto), "purpose"),
			"除 purpose 外鍵集與 BASE 相同，不多出範圍外資產識別或名稱")
		raw, err := json.Marshal(dto)
		require.NoError(t, err)
		assert.False(t, strings.Contains(string(raw), "purpose-out-1"))
	})

	t.Run("list_purpose_query_independent_of_n", func(t *testing.T) {
		count := func(n int) int {
			// 為 n 筆憑證各掛一台，量列表過程中查詢掛載用途的語句數
			for i := 0; i < n; i++ {
				cred := newShared("n-cnt-"+numStr(n)+"-"+numStr(i), "svc-cnt-"+numStr(n)+"-"+numStr(i))
				h := f.host(t, "cnt-"+numStr(n)+"-"+numStr(i), model.ProtocolSSH)
				_, err := f.exec.Set(ctx, h.ID, &SetExecutorRequest{Source: ExecutorSourceShared, CredentialID: cred.ID,
					AcknowledgedHostCount: iptr(1), ExpectedAccountID: uptr(0)})
				require.NoError(t, err)
			}
			var purposeQueries int
			name := "count_purpose_" + numStr(n)
			// SQL 在 gorm:query 內才組好，於其後計數
			require.NoError(t, db.Callback().Row().After("gorm:row").Register(name+"_after", func(tx *gorm.DB) {
				if tx.Statement.Table == "asset_accounts" && strings.Contains(tx.Statement.SQL.String(), "MIN(purpose)") {
					purposeQueries++
				}
			}))
			defer db.Callback().Row().Remove(name + "_after")
			_, err := f.creds.List(ctx, CredentialFilter{})
			require.NoError(t, err)
			return purposeQueries
		}
		small := count(3)
		large := count(30)
		assert.Equal(t, small, large, "用途查詢次數不隨筆數增加")
		assert.Equal(t, 1, large)
	})
}

func mustDTO(t *testing.T, f *executorFixture, db *gorm.DB, id uint) *CredentialDTO {
	t.Helper()
	var c model.Credential
	require.NoError(t, db.First(&c, id).Error)
	dto, err := f.creds.credentialDTO(db, &c)
	require.NoError(t, err)
	return dto
}

func numStr(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
