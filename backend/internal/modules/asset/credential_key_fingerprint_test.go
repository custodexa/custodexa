package asset

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"log"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 寫入私鑰的每條路徑在建立版本時保存對應的公鑰、沿用與更換的公鑰來源、讀取回應的指紋與揭露判定。
//
// 測試用的鑰一律於執行期產生。「預期公鑰」由產生當下的 ed25519 公鑰位元組以線路格式手工組出，
// 不經被測的解析函式；另以版本密文解出的私鑰簽、以保存的公鑰驗，證明兩者是同一把鑰。

// fpKey 測試當下產生的一把 Ed25519 私鑰與其預期的公鑰行、指紋。
type fpKey struct {
	pem  string
	line string
	fp   string
}

func newFPKey(t *testing.T) fpKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(priv, "fp-test")
	require.NoError(t, err)
	var wire []byte
	for _, part := range [][]byte{[]byte("ssh-ed25519"), pub} {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(part)))
		wire = append(append(wire, l[:]...), part...)
	}
	return fpKey{
		pem:  string(pem.EncodeToMemory(block)),
		line: "ssh-ed25519 " + base64.StdEncoding.EncodeToString(wire),
		fp:   ed25519WireFingerprint(pub),
	}
}

// fpFixture 帳號、憑證、資產與專用帳號四個服務共用一個判定樁與一個告警落地面。
type fpFixture struct {
	db       *gorm.DB
	assets   *AssetService
	accounts *AssetAccountService
	creds    *CredentialService
	exec     *AssetExecutorService
	auth     *fakeCredentialAuthorizer
	alerts   *fakeAlertSink
}

func newFPFixture(t *testing.T) *fpFixture {
	t.Helper()
	db := setupCredentialDB(t)
	require.NoError(t, db.AutoMigrate(&model.CredentialJobAuthorization{}))
	codec := aesColumnCodec(t, make([]byte, 32))
	assets, err := NewAssetService(codec, "localhost", 4822, audit.NewTxSink())
	require.NoError(t, err)
	assets.SetTopologyPermissionPort(noopTopologyPort{})
	assets.SetAssetWriteScopePort(allowAllAssetWriteScope{})
	auth := newAllowAllAuthorizer()
	alerts := newFakeAlertSink()
	assets.WithManagementAuthorizer(auth).WithSystemAlertSink(alerts)
	accounts := NewAssetAccountService(assets, codec, audit.NewTxSink()).
		WithManagementAuthorizer(auth).WithSystemAlertSink(alerts).WithAccountWriteScope(allowAllAccountWriteScope{})
	creds := NewCredentialService(assets, codec, audit.NewTxSink()).WithOwnershipScope(globalOwnershipScopeForTest{}).
		WithManagementAuthorizer(auth).WithSystemAlertSink(alerts)
	return &fpFixture{db: db, assets: assets, accounts: accounts, creds: creds,
		exec: NewAssetExecutorService(accounts, allowAllExecutorScope{}), auth: auth, alerts: alerts}
}

func (f *fpFixture) version(t *testing.T, id uint) model.CredentialSecretVersion {
	t.Helper()
	var v model.CredentialSecretVersion
	require.NoError(t, f.db.First(&v, id).Error)
	return v
}

func (f *fpFixture) currentVersion(t *testing.T, credentialID uint) model.CredentialSecretVersion {
	t.Helper()
	var c model.Credential
	require.NoError(t, f.db.First(&c, credentialID).Error)
	require.NotNil(t, c.CurrentVersionID)
	return f.version(t, *c.CurrentVersionID)
}

func (f *fpFixture) effectiveVersion(t *testing.T, accountID uint) model.CredentialSecretVersion {
	t.Helper()
	return effectiveVersionRow(t, f.db, accountID)
}

// assertVersionKey 版本保存的公鑰等於預期，且與版本密文中的私鑰是同一把（以私鑰簽、以保存的公鑰驗）。
func assertVersionKey(t *testing.T, assets *AssetService, v model.CredentialSecretVersion, wantLine string) {
	t.Helper()
	require.NotEmpty(t, v.PrivateKeyEnc, "版本應帶私鑰")
	require.NotEmpty(t, v.PublicKey, "版本 #%d 應保存公鑰", v.ID)
	if wantLine != "" {
		assert.Equal(t, wantLine, v.PublicKey, "保存的公鑰等於輸入私鑰的公鑰")
	}
	assert.Len(t, strings.Fields(v.PublicKey), 2, "公鑰只含型別與 base64 兩段")
	resolved, err := assets.resolver.ResolveVersion(context.Background(), v.CredentialID, v.ID)
	require.NoError(t, err)
	signer, err := ssh.ParsePrivateKey([]byte(secretText(t, resolved.PrivateKey)))
	require.NoError(t, err)
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(v.PublicKey))
	require.NoError(t, err)
	challenge := make([]byte, 32)
	_, err = rand.Read(challenge)
	require.NoError(t, err)
	sig, err := signer.Sign(rand.Reader, challenge)
	require.NoError(t, err)
	require.NoError(t, pub.Verify(challenge, sig), "版本 #%d 的公鑰與其私鑰不相符", v.ID)
}

// --- 1.1 人工輸入的每條路徑 ---

func TestFingerprintWritePathAssetCreate(t *testing.T) {
	f := newFPFixture(t)
	for _, form := range []string{"TopLevel", "Inline"} {
		t.Run(form, func(t *testing.T) {
			k := newFPKey(t)
			req := &CreateAssetRequest{Name: "fp-asset-" + form, Protocol: model.ProtocolSSH,
				Host: "10.41.0.1", Port: 22, Username: "root", PrivateKey: k.pem, CreatedBy: 1}
			if form == "Inline" {
				req = &CreateAssetRequest{Name: "fp-asset-" + form, Protocol: model.ProtocolSSH,
					Host: "10.41.0.2", Port: 22, Credential: &InlineCredential{Username: "root", PrivateKey: k.pem}, CreatedBy: 1}
			}
			a, err := f.assets.Create(WithSystemCaller(context.Background()), req)
			require.NoError(t, err)
			acc := defaultAccountOf(t, f.db, a.ID)
			assertVersionKey(t, f.assets, f.effectiveVersion(t, acc.ID), k.line)
		})
	}
}

func TestFingerprintWritePathAssetUpdate(t *testing.T) {
	f := newFPFixture(t)
	t.Run("ExistingDefaultAccount", func(t *testing.T) {
		a := newSSHAsset(t, f.assets, "fp-asset-upd", "10.41.1.1")
		acc := defaultAccountOf(t, f.db, a.ID)
		k := newFPKey(t)
		_, err := f.assets.Update(WithSystemCaller(adminCtx()), a.ID, &UpdateAssetRequest{PrivateKey: pkStrPtr(k.pem)})
		require.NoError(t, err)
		assertVersionKey(t, f.assets, f.effectiveVersion(t, acc.ID), k.line)
	})
	t.Run("ZeroAccountAsset", func(t *testing.T) {
		a, err := f.assets.Create(WithSystemCaller(context.Background()), &CreateAssetRequest{
			Name: "fp-asset-zero", Protocol: model.ProtocolSSH, Host: "10.41.1.2", Port: 22, CreatedBy: 1})
		require.NoError(t, err)
		var n int64
		require.NoError(t, f.db.Model(&model.AssetAccount{}).Where("asset_id = ?", a.ID).Count(&n).Error)
		require.Zero(t, n, "PRECONDITION: 零掛載資產")
		k := newFPKey(t)
		_, err = f.assets.Update(WithSystemCaller(adminCtx()), a.ID, &UpdateAssetRequest{
			Username: pkStrPtr("root"), PrivateKey: pkStrPtr(k.pem)})
		require.NoError(t, err)
		acc := defaultAccountOf(t, f.db, a.ID)
		assertVersionKey(t, f.assets, f.effectiveVersion(t, acc.ID), k.line)
	})
}

func TestFingerprintWritePathAccountCreateAndUpdate(t *testing.T) {
	f := newFPFixture(t)
	a := newSSHAsset(t, f.assets, "fp-acct", "10.41.2.1")
	for _, form := range []string{"TopLevel", "Inline"} {
		t.Run("Create/"+form, func(t *testing.T) {
			k := newFPKey(t)
			req := &CreateAssetAccountRequest{Username: "deploy-" + strings.ToLower(form), PrivateKey: k.pem}
			if form == "Inline" {
				req = &CreateAssetAccountRequest{Credential: &InlineCredential{Username: "deploy-inline", PrivateKey: k.pem}}
			}
			dto, err := f.accounts.Create(WithSystemCaller(adminCtx()), a.ID, req)
			require.NoError(t, err)
			assertVersionKey(t, f.assets, f.effectiveVersion(t, dto.ID), k.line)
			assert.Equal(t, k.fp, dto.PrivateKeyFingerprint, "寫入回應（完整形狀）帶指紋")
		})
	}
	t.Run("Update", func(t *testing.T) {
		dto, err := f.accounts.Create(WithSystemCaller(adminCtx()), a.ID, &CreateAssetAccountRequest{Username: "deploy-upd", Password: "pw"})
		require.NoError(t, err)
		k := newFPKey(t)
		_, err = f.accounts.Update(adminCtx(), a.ID, dto.ID, &UpdateAssetAccountRequest{PrivateKey: pkStrPtr(k.pem)})
		require.NoError(t, err)
		assertVersionKey(t, f.assets, f.effectiveVersion(t, dto.ID), k.line)
	})
}

func TestFingerprintWritePathCredentialCreateAndSetSecret(t *testing.T) {
	f := newFPFixture(t)
	k := newFPKey(t)
	cred, err := f.creds.Create(adminCtx(), &CreateCredentialRequest{Name: "fp-shared", Username: "ops",
		ProtocolFamily: model.ProtocolFamilySSH, PrivateKey: k.pem})
	require.NoError(t, err)
	assertVersionKey(t, f.assets, f.currentVersion(t, cred.ID), k.line)
	assert.Equal(t, k.fp, cred.PrivateKeyFingerprint, "看得到這筆憑證的建立者，寫入回應帶指紋")

	host := newSSHAsset(t, f.assets, "fp-shared-host", "10.41.3.1")
	binding, err := f.creds.Bind(adminCtx(), cred.ID, &BindCredentialRequest{AssetID: host.ID})
	require.NoError(t, err)

	k2 := newFPKey(t)
	out, err := f.creds.SetSecret(adminCtx(), cred.ID, &SetCredentialSecretRequest{PrivateKey: k2.pem})
	require.NoError(t, err)
	assertVersionKey(t, f.assets, f.currentVersion(t, cred.ID), k2.line)
	assertVersionKey(t, f.assets, f.effectiveVersion(t, binding.ID), k2.line)
	assert.Equal(t, k2.fp, out.PrivateKeyFingerprint)
}

func TestFingerprintWritePathExecutorInline(t *testing.T) {
	f := newFPFixture(t)
	a := f.assetForExecutor(t, "fp-exec-inline")
	k := newFPKey(t)
	got, err := f.exec.Set(adminCtx(), a.ID, &SetExecutorRequest{Source: ExecutorSourceInline, Username: "cx-exec",
		PrivateKey: k.pem, ExpectedAccountID: uptr(0)})
	require.NoError(t, err)
	assertVersionKey(t, f.assets, f.effectiveVersion(t, got.AccountID), k.line)
	// 直填的專用帳號依既有規則讀得到頂層指紋、可匯出公鑰
	read, err := f.exec.Get(adminCtx(), a.ID)
	require.NoError(t, err)
	assert.Equal(t, k.fp, read.Fingerprint)
	line, err := f.exec.ExportPublicKey(adminCtx(), a.ID)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(line, k.line+" "), "匯出的公鑰行即輸入私鑰的公鑰：%q", line)
}

func (f *fpFixture) assetForExecutor(t *testing.T, name string) *model.Asset {
	t.Helper()
	a, err := f.assets.Create(WithSystemCaller(context.Background()), &CreateAssetRequest{
		Name: name, Protocol: model.ProtocolSSH, Host: name + ".internal", Port: 22,
		Username: "seed", Password: "seed-pw", CreatedBy: 1,
	})
	require.NoError(t, err)
	return a
}

// 系統路徑 UpdatePrivateKey（目前沒有正式呼叫者，仍不得留下沒有公鑰的私鑰版本）
func TestFingerprintWritePathSystemUpdatePrivateKey(t *testing.T) {
	f := newFPFixture(t)
	a := newSSHAsset(t, f.assets, "fp-sys", "10.41.4.1")
	acc := defaultAccountOf(t, f.db, a.ID)
	k := newFPKey(t)
	require.NoError(t, f.assets.UpdatePrivateKey(a.ID, acc.ID, acc.Username, k.pem))
	assertVersionKey(t, f.assets, f.effectiveVersion(t, acc.ID), k.line)
	// 只改密碼：私鑰與公鑰都跟著同一版搬
	require.NoError(t, f.assets.UpdatePassword(a.ID, acc.ID, acc.Username, "rotated-pw"))
	assertVersionKey(t, f.assets, f.effectiveVersion(t, acc.ID), k.line)
}

// --- 1.3 沿用與更換 ---

// 設私鑰、只改密碼、換私鑰：三步逐步比對公鑰（共用憑證的更正秘密與帳號修改兩個寫入面）
func TestFingerprintCarryOverThreeSteps(t *testing.T) {
	f := newFPFixture(t)
	t.Run("CredentialSetSecret", func(t *testing.T) {
		kA, kB := newFPKey(t), newFPKey(t)
		cred, err := f.creds.Create(adminCtx(), &CreateCredentialRequest{Name: "fp-three", Username: "ops",
			ProtocolFamily: model.ProtocolFamilySSH, Password: "pw-0", PrivateKey: kA.pem})
		require.NoError(t, err)
		v1 := f.currentVersion(t, cred.ID)
		assertVersionKey(t, f.assets, v1, kA.line)

		_, err = f.creds.SetSecret(adminCtx(), cred.ID, &SetCredentialSecretRequest{Password: "pw-1"})
		require.NoError(t, err)
		v2 := f.currentVersion(t, cred.ID)
		require.NotEqual(t, v1.ID, v2.ID)
		assert.Equal(t, v1.PrivateKeyEnc, v2.PrivateKeyEnc, "只改密碼時私鑰密文原樣搬")
		assertVersionKey(t, f.assets, v2, kA.line)

		_, err = f.creds.SetSecret(adminCtx(), cred.ID, &SetCredentialSecretRequest{PrivateKey: kB.pem})
		require.NoError(t, err)
		v3 := f.currentVersion(t, cred.ID)
		assertVersionKey(t, f.assets, v3, kB.line)
		assert.NotEqual(t, v2.PublicKey, v3.PublicKey, "換私鑰後不得沿用舊公鑰")
	})
	t.Run("AccountUpdate", func(t *testing.T) {
		kA, kB := newFPKey(t), newFPKey(t)
		a := newSSHAsset(t, f.assets, "fp-three-acct", "10.41.5.1")
		dto, err := f.accounts.Create(WithSystemCaller(adminCtx()), a.ID, &CreateAssetAccountRequest{
			Username: "deploy", Password: "pw-0", PrivateKey: kA.pem})
		require.NoError(t, err)
		assertVersionKey(t, f.assets, f.effectiveVersion(t, dto.ID), kA.line)
		_, err = f.accounts.Update(adminCtx(), a.ID, dto.ID, &UpdateAssetAccountRequest{Password: pkStrPtr("pw-1")})
		require.NoError(t, err)
		assertVersionKey(t, f.assets, f.effectiveVersion(t, dto.ID), kA.line)
		_, err = f.accounts.Update(adminCtx(), a.ID, dto.ID, &UpdateAssetAccountRequest{PrivateKey: pkStrPtr(kB.pem)})
		require.NoError(t, err)
		assertVersionKey(t, f.assets, f.effectiveVersion(t, dto.ID), kB.line)
	})
	t.Run("AssetUpdateDefaultAccount", func(t *testing.T) {
		kA, kB := newFPKey(t), newFPKey(t)
		a, err := f.assets.Create(WithSystemCaller(context.Background()), &CreateAssetRequest{
			Name: "fp-three-asset", Protocol: model.ProtocolSSH, Host: "10.41.5.2", Port: 22,
			Username: "root", Password: "pw-0", PrivateKey: kA.pem, CreatedBy: 1})
		require.NoError(t, err)
		acc := defaultAccountOf(t, f.db, a.ID)
		assertVersionKey(t, f.assets, f.effectiveVersion(t, acc.ID), kA.line)
		_, err = f.assets.Update(WithSystemCaller(adminCtx()), a.ID, &UpdateAssetRequest{Password: pkStrPtr("pw-1")})
		require.NoError(t, err)
		assertVersionKey(t, f.assets, f.effectiveVersion(t, acc.ID), kA.line)
		_, err = f.assets.Update(WithSystemCaller(adminCtx()), a.ID, &UpdateAssetRequest{PrivateKey: pkStrPtr(kB.pem)})
		require.NoError(t, err)
		assertVersionKey(t, f.assets, f.effectiveVersion(t, acc.ID), kB.line)
	})
}

// 沿用只認原樣搬的私鑰：公鑰未知的舊版本只改密碼，新版本的公鑰同樣未知，不憑空補上
func TestFingerprintCarryOverUnknownStaysUnknown(t *testing.T) {
	f := newFPFixture(t)
	k := newFPKey(t)
	cred, err := f.creds.Create(adminCtx(), &CreateCredentialRequest{Name: "fp-legacy", Username: "ops",
		ProtocolFamily: model.ProtocolFamilySSH, Password: "pw-0", PrivateKey: k.pem})
	require.NoError(t, err)
	// 模擬升級前寫入：另建一版公鑰為空、私鑰密文相同的版本並設為現行
	v1 := f.currentVersion(t, cred.ID)
	legacy := model.CredentialSecretVersion{CredentialID: cred.ID, VersionNo: v1.VersionNo + 1, SecretType: v1.SecretType,
		PasswordEnc: v1.PasswordEnc, PrivateKeyEnc: v1.PrivateKeyEnc, CreatedReason: model.CredentialVersionReasonManual}
	require.NoError(t, f.db.Create(&legacy).Error)
	require.NoError(t, f.db.Model(&model.Credential{}).Where("id = ?", cred.ID).Update("current_version_id", legacy.ID).Error)

	detail, err := f.creds.Get(adminCtx(), cred.ID)
	require.NoError(t, err)
	assert.True(t, detail.HasPrivateKey)
	assert.Empty(t, detail.PrivateKeyFingerprint, "公鑰未知：有私鑰、沒有指紋")

	_, err = f.creds.SetSecret(adminCtx(), cred.ID, &SetCredentialSecretRequest{Password: "pw-1"})
	require.NoError(t, err)
	v3 := f.currentVersion(t, cred.ID)
	assert.Equal(t, v1.PrivateKeyEnc, v3.PrivateKeyEnc)
	assert.Empty(t, v3.PublicKey, "來源版本公鑰未知，沿用後仍未知（不以其他版本的公鑰代替）")

	// 重新設定同一把私鑰後取得指紋
	out, err := f.creds.SetSecret(adminCtx(), cred.ID, &SetCredentialSecretRequest{PrivateKey: k.pem})
	require.NoError(t, err)
	assert.Equal(t, k.fp, out.PrivateKeyFingerprint)
}

// 版本建立的最後一道：沒有私鑰的版本不帶公鑰（呼叫端誤帶也清掉）
func TestFingerprintAppendVersionDropsPublicKeyWithoutPrivateKey(t *testing.T) {
	f := newFPFixture(t)
	cred, err := f.creds.Create(adminCtx(), &CreateCredentialRequest{Name: "fp-pw-only", Username: "ops",
		ProtocolFamily: model.ProtocolFamilySSH, Password: "pw"})
	require.NoError(t, err)
	k := newFPKey(t)
	var v *model.CredentialSecretVersion
	require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error {
		var e error
		v, e = appendCredentialVersion(tx, cred.ID, model.ChangeSecretTypePassword, "enc-pw", "",
			model.CredentialVersionReasonManual, withVersionPublicKey(k.line))
		return e
	}))
	assert.Empty(t, f.version(t, v.ID).PublicKey)
}

// --- 2.1 讀取回報指紋 ---

func TestFingerprintReadAccountRowsThreeStates(t *testing.T) {
	f := newFPFixture(t)
	a := newSSHAsset(t, f.assets, "fp-read", "10.41.6.1")
	k := newFPKey(t)
	withKey, err := f.accounts.Create(WithSystemCaller(adminCtx()), a.ID, &CreateAssetAccountRequest{Username: "with-key", PrivateKey: k.pem})
	require.NoError(t, err)
	unknown, err := f.accounts.Create(WithSystemCaller(adminCtx()), a.ID, &CreateAssetAccountRequest{Username: "unknown-key", PrivateKey: newFPKey(t).pem})
	require.NoError(t, err)
	// 公鑰未知：模擬升級前的版本（直寫空公鑰的新版本並就位）
	uv := f.effectiveVersion(t, unknown.ID)
	legacy := model.CredentialSecretVersion{CredentialID: uv.CredentialID, VersionNo: uv.VersionNo + 1, SecretType: uv.SecretType,
		PrivateKeyEnc: uv.PrivateKeyEnc, CreatedReason: model.CredentialVersionReasonManual}
	require.NoError(t, f.db.Create(&legacy).Error)
	require.NoError(t, f.db.Model(&model.AssetAccount{}).Where("id = ?", unknown.ID).Update("effective_version_id", legacy.ID).Error)

	list, err := f.accounts.List(a.ID)
	require.NoError(t, err)
	byName := map[string]*AssetAccountDTO{}
	for _, d := range list {
		byName[d.Username] = d
	}
	keysOf := func(d *AssetAccountDTO) map[string]bool { return jsonKeys(t, d) }

	pw := byName["seed"]
	require.NotNil(t, pw)
	assert.False(t, pw.HasPrivateKey)
	assert.False(t, keysOf(pw)["private_key_fingerprint"], "沒有私鑰：欄位不出現")

	got := byName["with-key"]
	require.NotNil(t, got)
	assert.True(t, got.HasPrivateKey)
	assert.Equal(t, k.fp, got.PrivateKeyFingerprint, "有指紋：與私鑰的公鑰以 SHA-256 計算的結果相同")

	unk := byName["unknown-key"]
	require.NotNil(t, unk)
	assert.True(t, unk.HasPrivateKey, "公鑰未知仍回報已設定私鑰")
	assert.False(t, keysOf(unk)["private_key_fingerprint"], "公鑰未知：欄位不出現")

	one, err := f.accounts.Get(a.ID, withKey.ID)
	require.NoError(t, err)
	assert.Equal(t, k.fp, one.PrivateKeyFingerprint, "單筆與列表同一列相同")
}

func TestFingerprintReadCredentialListAndDetail(t *testing.T) {
	f := newFPFixture(t)
	k := newFPKey(t)
	withKey, err := f.creds.Create(adminCtx(), &CreateCredentialRequest{Name: "fp-list-key", Username: "ops",
		ProtocolFamily: model.ProtocolFamilySSH, PrivateKey: k.pem})
	require.NoError(t, err)
	pwOnly, err := f.creds.Create(adminCtx(), &CreateCredentialRequest{Name: "fp-list-pw", Username: "ops",
		ProtocolFamily: model.ProtocolFamilySSH, Password: "pw"})
	require.NoError(t, err)

	list, err := f.creds.List(adminCtx(), CredentialFilter{})
	require.NoError(t, err)
	rows := map[uint]*CredentialDTO{}
	for _, r := range list {
		rows[r.ID] = r
	}
	require.NotNil(t, rows[withKey.ID])
	assert.Equal(t, k.fp, rows[withKey.ID].PrivateKeyFingerprint)
	assert.False(t, jsonKeys(t, rows[pwOnly.ID])["private_key_fingerprint"], "沒有私鑰：欄位不出現")

	detail, err := f.creds.Get(adminCtx(), withKey.ID)
	require.NoError(t, err)
	assert.Equal(t, rows[withKey.ID].PrivateKeyFingerprint, detail.PrivateKeyFingerprint, "列表與詳情回報相同的指紋")
}

// --- 2.2 精簡形狀與範圍外收窄的帳號列 ---

func TestFingerprintNotInSlimOrOutOfScopeRows(t *testing.T) {
	full := &AssetAccountDTO{ID: 1, Username: "u", HasPrivateKey: true, PrivateKeyFingerprint: "SHA256:zz-fp-sentinel"}
	require.True(t, jsonKeys(t, full)["private_key_fingerprint"], "PRECONDITION: 完整版帶指紋")
	for name, v := range map[string]any{
		"slim":         SlimAssetAccountDTO(full),
		"out_of_scope": OutOfScopeAssetAccountDTO(full),
	} {
		raw, err := json.Marshal(v)
		require.NoError(t, err)
		assert.NotContains(t, string(raw), "private_key_fingerprint", name)
		assert.NotContains(t, string(raw), "zz-fp-sentinel", name)
	}
}

// --- 2.5 寫入回應套用檢視判定（服務層） ---

func TestFingerprintCredentialWriteResponsesNeedView(t *testing.T) {
	f := newFPFixture(t)
	k := newFPKey(t)
	cred, err := f.creds.Create(adminCtx(), &CreateCredentialRequest{Name: "fp-w", Username: "ops",
		ProtocolFamily: model.ProtocolFamilySSH, Password: "pw", PrivateKey: k.pem})
	require.NoError(t, err)
	host := newSSHAsset(t, f.assets, "fp-w-host", "10.41.7.1")
	_, err = f.creds.Bind(adminCtx(), cred.ID, &BindCredentialRequest{AssetID: host.ID})
	require.NoError(t, err)

	// 主體 2：具修改、更正秘密、建立與範圍轉換能力，沒有檢視能力
	const noView uint = 2
	f.auth.denyFor(noView, CredCapView)
	ctxNoView := context.WithValue(context.WithValue(context.Background(), "userID", noView), "username", "noview") //nolint:staticcheck

	note := "zz-note"
	writes := map[string]func(ctx context.Context) (*CredentialDTO, error){
		"update": func(ctx context.Context) (*CredentialDTO, error) {
			return f.creds.Update(ctx, cred.ID, &UpdateCredentialRequest{Note: &note})
		},
		"set_secret_password_only": func(ctx context.Context) (*CredentialDTO, error) {
			return f.creds.SetSecret(ctx, cred.ID, &SetCredentialSecretRequest{Password: "pw-next"})
		},
	}
	for name, call := range writes {
		t.Run(name+"/no_view", func(t *testing.T) {
			dto, err := call(ctxNoView)
			require.NoError(t, err, "寫入本身成功")
			assert.True(t, dto.HasPrivateKey)
			assert.False(t, jsonKeys(t, dto)["private_key_fingerprint"], "沒有檢視能力：寫入回應不帶指紋")
		})
		t.Run(name+"/with_view", func(t *testing.T) {
			dto, err := call(adminCtx())
			require.NoError(t, err)
			assert.Equal(t, k.fp, dto.PrivateKeyFingerprint, "檢視與修改皆具：寫入回應帶指紋")
		})
	}

	t.Run("set_secret_new_key/no_view", func(t *testing.T) {
		k2 := newFPKey(t)
		dto, err := f.creds.SetSecret(ctxNoView, cred.ID, &SetCredentialSecretRequest{PrivateKey: k2.pem})
		require.NoError(t, err)
		assert.False(t, jsonKeys(t, dto)["private_key_fingerprint"])
		assert.Equal(t, k2.line, f.currentVersion(t, cred.ID).PublicKey, "不給指紋不影響保存公鑰")
	})

	t.Run("create/no_view", func(t *testing.T) {
		dto, err := f.creds.Create(ctxNoView, &CreateCredentialRequest{Name: "fp-w-create", Username: "ops",
			ProtocolFamily: model.ProtocolFamilySSH, PrivateKey: newFPKey(t).pem})
		require.NoError(t, err)
		assert.False(t, jsonKeys(t, dto)["private_key_fingerprint"])
	})

	t.Run("convert_scope", func(t *testing.T) {
		single, err := f.creds.Create(adminCtx(), &CreateCredentialRequest{Name: "fp-w-conv", Username: "ops2",
			ProtocolFamily: model.ProtocolFamilySSH, PrivateKey: newFPKey(t).pem})
		require.NoError(t, err)
		h := newSSHAsset(t, f.assets, "fp-w-conv-host", "10.41.7.2")
		_, err = f.creds.Bind(adminCtx(), single.ID, &BindCredentialRequest{AssetID: h.ID})
		require.NoError(t, err)
		dto, err := f.creds.ConvertScope(ctxNoView, single.ID, &ConvertCredentialScopeRequest{Scope: model.CredentialScopeDedicated})
		require.NoError(t, err)
		assert.False(t, jsonKeys(t, dto)["private_key_fingerprint"], "沒有檢視能力：範圍轉換回應不帶指紋")
		back, err := f.creds.ConvertScope(adminCtx(), single.ID, &ConvertCredentialScopeRequest{Scope: model.CredentialScopeShared, Name: "fp-w-conv-2"})
		require.NoError(t, err)
		assert.NotEmpty(t, back.PrivateKeyFingerprint, "具檢視能力：範圍轉換回應帶指紋")
	})

	t.Run("judge_error_fails_closed", func(t *testing.T) {
		const broken uint = 3
		f.auth.failFor(broken, assert.AnError)
		ctx := context.WithValue(context.WithValue(context.Background(), "userID", broken), "username", "broken") //nolint:staticcheck
		dto := &CredentialDTO{ID: cred.ID, fingerprint: k.fp}
		f.creds.discloseFingerprintIfViewable(ctx, dto)
		assert.Empty(t, dto.PrivateKeyFingerprint, "判定失敗不給指紋")
		dto2 := &CredentialDTO{ID: cred.ID, fingerprint: k.fp}
		f.creds.discloseFingerprintIfViewable(context.Background(), dto2)
		assert.Empty(t, dto2.PrivateKeyFingerprint, "無主體不給指紋")
	})
}

// --- 2.6 指紋不進稽核、告警與日誌 ---

func TestFingerprintNotInAuditAlertsOrLogs(t *testing.T) {
	f := newFPFixture(t)
	var logBuf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(prev) })
	// 資料庫日誌用正式模式的組裝，寫進可觀察的緩衝（夾具預設丟棄資料庫日誌）
	var dbLogBuf bytes.Buffer
	prevDBLogger := f.db.Logger
	f.db.Logger = database.NewGormLogger(true, &dbLogBuf)
	t.Cleanup(func() { f.db.Logger = prevDBLogger })

	k1, k2, k3 := newFPKey(t), newFPKey(t), newFPKey(t)
	cred, err := f.creds.Create(adminCtx(), &CreateCredentialRequest{Name: "fp-audit", Username: "ops",
		ProtocolFamily: model.ProtocolFamilySSH, PrivateKey: k1.pem})
	require.NoError(t, err)
	host := newSSHAsset(t, f.assets, "fp-audit-host", "10.41.8.1")
	_, err = f.creds.Bind(adminCtx(), cred.ID, &BindCredentialRequest{AssetID: host.ID})
	require.NoError(t, err)
	_, err = f.creds.SetSecret(adminCtx(), cred.ID, &SetCredentialSecretRequest{PrivateKey: k2.pem})
	require.NoError(t, err)
	acc, err := f.accounts.Create(WithSystemCaller(adminCtx()), host.ID, &CreateAssetAccountRequest{Username: "deploy", Password: "pw"})
	require.NoError(t, err)
	_, err = f.accounts.Update(adminCtx(), host.ID, acc.ID, &UpdateAssetAccountRequest{PrivateKey: pkStrPtr(k3.pem)})
	require.NoError(t, err)

	var logs []model.AuditLog
	require.NoError(t, f.db.Find(&logs).Error)
	require.NotEmpty(t, logs, "PRECONDITION: 更換私鑰有審計列")
	auditRaw, err := json.Marshal(logs)
	require.NoError(t, err)
	events := f.alerts.snapshot()
	require.NotEmpty(t, events, "PRECONDITION: 宣告秘密有告警")
	alertRaw, err := json.Marshal(events)
	require.NoError(t, err)

	// 正式模式的資料庫日誌只在語句失敗時輸出：刻意讓下一次版本寫入失敗，確認錯誤日誌確實出現、但不帶公鑰
	require.NoError(t, f.db.Exec(`CREATE TRIGGER zz_reject_version BEFORE INSERT ON credential_secret_versions
		BEGIN SELECT RAISE(ABORT, 'zz rejected by test'); END`).Error)
	k4 := newFPKey(t)
	_, err = f.creds.SetSecret(adminCtx(), cred.ID, &SetCredentialSecretRequest{PrivateKey: k4.pem})
	require.Error(t, err, "PRECONDITION: 版本寫入被拒")
	require.Contains(t, dbLogBuf.String(), "credential_secret_versions", "PRECONDITION: 失敗的版本寫入留下資料庫錯誤日誌")

	// 對照：非正式模式的資料庫日誌帶參數值，證明這裡觀察得到語句的參數
	var devLogBuf bytes.Buffer
	f.db.Logger = database.NewGormLogger(false, &devLogBuf)
	k5 := newFPKey(t)
	_, err = f.creds.SetSecret(adminCtx(), cred.ID, &SetCredentialSecretRequest{PrivateKey: k5.pem})
	require.Error(t, err)
	require.Contains(t, devLogBuf.String(), strings.Fields(k5.line)[1], "對照組：非正式模式的資料庫日誌帶公鑰參數")
	f.db.Logger = database.NewGormLogger(true, &dbLogBuf)

	for _, k := range []fpKey{k1, k2, k3, k4} {
		b64 := strings.Fields(k.line)[1]
		for name, raw := range map[string]string{"audit": string(auditRaw), "alerts": string(alertRaw), "log": logBuf.String(),
			"db_log": dbLogBuf.String()} {
			assert.NotContains(t, raw, k.fp, "%s 不含指紋", name)
			assert.NotContains(t, raw, strings.TrimPrefix(k.fp, "SHA256:"), "%s 不含指紋本體", name)
			assert.NotContains(t, raw, b64, "%s 不含公鑰", name)
		}
	}
	assert.NotContains(t, string(auditRaw), "SHA256:", "審計不含任何 SHA256 指紋")
}
