package keyvault

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"hash/crc32"
	"reflect"
	"strings"
	"testing"
	"time"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/crypto/gcpkms"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"gorm.io/gorm"
)

const gcpSourceRef = "projects/transaction-project/locations/global/keyRings/fixture/cryptoKeys/source"
const gcpTargetRef = "projects/transaction-project/locations/global/keyRings/fixture/cryptoKeys/target"

var errGCPInjected = errors.New("injected transaction failure")

type gcpTxAPI struct {
	keys  map[string]*crypto.AESCrypto
	hook  func(context.Context, string, []byte) error
	calls []string
}

func newGCPTxAPI(t *testing.T) *gcpTxAPI {
	t.Helper()
	f := &gcpTxAPI{keys: map[string]*crypto.AESCrypto{}}
	for i, key := range []string{gcpSourceRef, gcpTargetRef} {
		a, err := crypto.NewAESCrypto(bytes.Repeat([]byte{byte(i + 1)}, 32))
		if err != nil {
			t.Fatal(err)
		}
		f.keys[key] = a
	}
	return f
}
func txCRC(b []byte) *wrapperspb.Int64Value {
	return wrapperspb.Int64(int64(crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli))))
}
func (f *gcpTxAPI) before(ctx context.Context, method string, aad []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.calls = append(f.calls, method)
	if f.hook != nil {
		return f.hook(ctx, method, aad)
	}
	return nil
}
func (f *gcpTxAPI) GetCryptoKey(ctx context.Context, r *kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	if err := f.before(ctx, "metadata", nil); err != nil {
		return nil, err
	}
	return &kmspb.CryptoKey{Name: r.Name, Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT, Primary: &kmspb.CryptoKeyVersion{Name: r.Name + "/cryptoKeyVersions/1", State: kmspb.CryptoKeyVersion_ENABLED, Algorithm: kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION}}, nil
}
func (f *gcpTxAPI) Encrypt(ctx context.Context, r *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
	if err := f.before(ctx, "encrypt", r.AdditionalAuthenticatedData); err != nil {
		return nil, err
	}
	if r.PlaintextCrc32C == nil || r.PlaintextCrc32C.Value != txCRC(r.Plaintext).Value || r.AdditionalAuthenticatedDataCrc32C == nil || r.AdditionalAuthenticatedDataCrc32C.Value != txCRC(r.AdditionalAuthenticatedData).Value {
		return nil, errGCPInjected
	}
	a := f.keys[r.Name]
	if a == nil {
		return nil, errGCPInjected
	}
	blob, err := a.EncryptBytesAAD(r.Plaintext, r.AdditionalAuthenticatedData)
	if err != nil {
		return nil, err
	}
	return &kmspb.EncryptResponse{Name: r.Name + "/cryptoKeyVersions/1", Ciphertext: blob, CiphertextCrc32C: txCRC(blob), VerifiedPlaintextCrc32C: true, VerifiedAdditionalAuthenticatedDataCrc32C: true}, nil
}
func (f *gcpTxAPI) Decrypt(ctx context.Context, r *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
	if err := f.before(ctx, "decrypt", r.AdditionalAuthenticatedData); err != nil {
		return nil, err
	}
	if r.CiphertextCrc32C == nil || r.CiphertextCrc32C.Value != txCRC(r.Ciphertext).Value || r.AdditionalAuthenticatedDataCrc32C == nil || r.AdditionalAuthenticatedDataCrc32C.Value != txCRC(r.AdditionalAuthenticatedData).Value {
		return nil, errGCPInjected
	}
	a := f.keys[r.Name]
	if a == nil {
		return nil, errGCPInjected
	}
	raw, err := a.DecryptBytesAAD(r.Ciphertext, r.AdditionalAuthenticatedData)
	if err != nil {
		return nil, err
	}
	return &kmspb.DecryptResponse{Plaintext: raw, PlaintextCrc32C: txCRC(raw)}, nil
}

// This pool issues real BEGIN/COMMIT/ROLLBACK on one pinned SQL connection.
// Deferred constraints generate a database COMMIT error, not a helper-only error.
type gcpTxPool struct {
	*sql.DB
	conn         *sql.Conn
	active       bool
	creates      int
	fault        string
	events       []string
	lockSeen     bool
	commitFailed bool
	rolledBack   bool
	afterCreate  func()
}
type gcpTxConn struct {
	conn  *sql.Conn
	owner *gcpTxPool
}

func (p *gcpTxPool) BeginTx(ctx context.Context, _ *sql.TxOptions) (gorm.ConnPool, error) {
	if p.active {
		return nil, errGCPInjected
	}
	conn, err := p.DB.Conn(ctx)
	if err != nil {
		return nil, err
	}
	if _, err = conn.ExecContext(ctx, "BEGIN"); err != nil {
		conn.Close()
		return nil, err
	}
	p.conn = conn
	p.active = true
	p.events = append(p.events, "begin")
	return &gcpTxConn{conn: conn, owner: p}, nil
}
func (c *gcpTxConn) before(query string) error {
	p := c.owner
	if strings.Contains(query, "pg_try_advisory_xact_lock") {
		p.lockSeen = true
	}
	if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(query)), "INSERT INTO") && strings.Contains(query, "data_keys") {
		p.creates++
		p.events = append(p.events, "create")
		if p.fault == "create" && p.creates == 2 {
			return errGCPInjected
		}
	}
	return nil
}
func (c *gcpTxConn) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	if err := c.before(q); err != nil {
		return nil, err
	}
	out, err := c.conn.ExecContext(ctx, q, args...)
	return out, err
}
func (c *gcpTxConn) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	if err := c.before(q); err != nil {
		return nil, err
	}
	return c.conn.QueryContext(ctx, q, args...)
}
func (c *gcpTxConn) Commit() error {
	p := c.owner
	p.events = append(p.events, "commit")
	if p.fault == "commit" {
		if _, err := c.conn.ExecContext(context.Background(), "INSERT INTO gcp_commit_child (parent_id) VALUES (99)"); err != nil {
			return err
		}
	}
	_, err := c.conn.ExecContext(context.Background(), "COMMIT")
	if err != nil {
		p.commitFailed = true
		return err
	}
	p.active = false
	return c.conn.Close()
}
func (c *gcpTxConn) Rollback() error {
	p := c.owner
	p.events = append(p.events, "rollback")
	_, err := c.conn.ExecContext(context.Background(), "ROLLBACK")
	p.rolledBack = true
	p.active = false
	closeErr := c.conn.Close()
	if err != nil {
		return err
	}
	return closeErr
}
func installGCPTxPool(t *testing.T, db *gorm.DB) *gcpTxPool {
	t.Helper()
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	pool := &gcpTxPool{DB: sqlDB}
	db.ConnPool = pool
	db.Statement.ConnPool = pool
	return pool
}

type gcpMemorySnapshot struct {
	keys       map[string]map[int][]byte
	active     map[string]int
	ciphers    map[int]*crypto.AESCrypto
	pending    bool
	lastSwitch *KEKSwitchResult
	lastError  error
}

func snapshotGCPMemory(s *KeyManagerService) gcpMemorySnapshot {
	out := gcpMemorySnapshot{keys: map[string]map[int][]byte{}, active: map[string]int{}, ciphers: map[int]*crypto.AESCrypto{}, pending: s.rewrapPending, lastSwitch: s.lastSwitch, lastError: s.lastFinalizeErr}
	for purpose, versions := range s.keys {
		out.keys[purpose] = map[int][]byte{}
		for v, b := range versions {
			out.keys[purpose][v] = bytes.Clone(b)
		}
	}
	for p, v := range s.active {
		out.active[p] = v
	}
	for v, c := range s.ciphers {
		out.ciphers[v] = c
	}
	return out
}
func gcpRows(t *testing.T, db *gorm.DB) []model.DataKey {
	t.Helper()
	var rows []model.DataKey
	if err := db.Order("id").Find(&rows).Error; err != nil {
		t.Fatal("cannot read fixture rows")
	}
	return rows
}
func assertGCPRollback(t *testing.T, s *KeyManagerService, before []model.DataKey, memory gcpMemorySnapshot) {
	t.Helper()
	after := gcpRows(t, s.db)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("live rows changed or pending rows were added")
	}
	if !reflect.DeepEqual(memory, snapshotGCPMemory(s)) {
		t.Fatal("memory state changed")
	}
	for _, row := range after {
		if row.KEKPending {
			t.Fatal("pending row survived")
		}
	}
}
func gcpServiceFixture(t *testing.T, db *gorm.DB) (*KeyManagerService, *gcpkms.Provider, *gcpTxAPI) {
	t.Helper()
	f := newGCPTxAPI(t)
	scope, err := gcpkms.ResolveProjectScope(gcpSourceRef)
	if err != nil {
		t.Fatal(err)
	}
	source, err := gcpkms.NewProvider(context.Background(), gcpkms.Settings{KeyID: gcpSourceRef, Scope: scope}, f)
	if err != nil {
		t.Fatal(err)
	}
	target, err := gcpkms.NewProvider(context.Background(), gcpkms.Settings{KeyID: gcpTargetRef, Scope: scope}, f)
	if err != nil {
		t.Fatal(err)
	}
	s := &KeyManagerService{db: db, kek: source, keys: map[string]map[int][]byte{}, ciphers: map[int]*crypto.AESCrypto{}, active: map[string]int{}}
	for i, purpose := range []string{model.DataKeyPurposeData, model.DataKeyPurposeAuditIntegrity} {
		raw := bytes.Repeat([]byte{byte(i + 11)}, 32)
		column, err := wrapMaterial(source, purpose, 1, raw)
		if err != nil {
			t.Fatal(err)
		}
		row := model.DataKey{Purpose: purpose, Version: 1, WrappedKey: column, KEKID: gcpSourceRef, Status: model.DataKeyStatusActive, CreatedAt: time.Now()}
		if err := db.Create(&row).Error; err != nil {
			t.Fatal(err)
		}
		s.putKey(purpose, 1, raw)
		s.active[purpose] = 1
	}
	f.calls = nil
	return s, target, f
}
func gcpTarget(t *testing.T, p crypto.KEKProvider) *RewrapTarget {
	t.Helper()
	target, err := NewDelegatedRewrapTarget(context.Background(), RewrapTargetModeGCP, p.KeyRef().KeyID, func(context.Context, string, string) (crypto.KEKProvider, error) { return p, nil })
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func (c *gcpTxConn) PrepareContext(ctx context.Context, q string) (*sql.Stmt, error) {
	return c.conn.PrepareContext(ctx, q)
}
func (c *gcpTxConn) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	return c.conn.QueryRowContext(ctx, q, args...)
}
