package keyvault

import (
	"context"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func checkLedgerArgsCipher(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.AutoMigrate(&model.DataKey{}, &model.AgentToolCall{}))
	kek, err := crypto.NewEnvKEKProvider(make([]byte, 32))
	require.NoError(t, err)
	km, err := InitKeyManager(db, kek)
	require.NoError(t, err)
	var target envelopeMigrationColumn
	for _, v := range envelopeMigrationTargets {
		if v.cipherRef() == RefAgentToolCallArgs {
			target = v
		}
	}
	require.True(t, target.binary)
	original, err := km.EncryptFor(context.Background(), RefAgentToolCallArgs, `{"command":"echo 4111111111111111"}`)
	require.NoError(t, err)
	row := model.AgentToolCall{Seq: 1, UserID: 1, AgentTokenID: 1, OwnerUserID: 1, Tool: "list_assets", ArgsRedacted: `{}`, ArgsSealed: []byte(original), ArgsRetained: true, Decision: model.ToolCallPending, IntegrityHMAC: "must-not-change"}
	require.NoError(t, db.Session(&gorm.Session{SkipHooks: true}).Create(&row).Error)
	count, err := countPendingColumnValues(db, target, func(string) bool { return false })
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
	var malformed int64
	require.NoError(t, db.Table(target.table).Where(target.valueSQL(db)+" NOT LIKE ?", "enc:a1:%").Count(&malformed).Error)
	require.Zero(t, malformed)
	// The exact rotation primitive handles bytea scans and CAS writes without
	// modifying the signed columns. Re-encryption gets a fresh AEAD nonce.
	result := &EnvelopeMigrationResult{}
	reencryptEnvelopeColumn(db, km, target, func(string) bool { return false }, result)
	require.Zero(t, result.Failed)
	require.EqualValues(t, 1, result.Migrated)
	var saved model.AgentToolCall
	require.NoError(t, db.First(&saved, row.ID).Error)
	require.NotEqual(t, original, string(saved.ArgsSealed))
	require.Equal(t, "must-not-change", saved.IntegrityHMAC)
	plain, err := km.DecryptFor(context.Background(), RefAgentToolCallArgs, string(saved.ArgsSealed))
	require.NoError(t, err)
	require.Contains(t, plain, "4111111111111111")
}
func TestLedgerArgsCipherRotation(t *testing.T) { checkLedgerArgsCipher(t, newKeyManagerDB(t)) }
func TestLedgerArgsCipherRotationPostgres(t *testing.T) {
	base := pgLockTestDSN(t)
	admin := openPGLockDB(t, base)
	const name = "ledger_cipher_test"
	require.NoError(t, admin.Exec("DROP SCHEMA IF EXISTS "+name+" CASCADE").Error)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+name).Error)
	t.Cleanup(func() { require.NoError(t, admin.Exec("DROP SCHEMA "+name+" CASCADE").Error) })
	checkLedgerArgsCipher(t, openPGLockDB(t, base+" search_path="+name))
}
