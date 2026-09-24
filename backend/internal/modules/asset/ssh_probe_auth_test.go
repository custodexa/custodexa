package asset

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// SSH 撥測的認證組裝：以行程內 SSH 靶機實跑真連線，驗證撥測與正式終端連線
// 採同一套規則（私鑰先、密碼後、同一次交握），以及「無秘密」「私鑰無法解析」
// 兩種情形在撥號前就回報正確原因、不對目標產生任何連線。

type sshProbeFixture struct {
	*csFixture
	host string
	port int
}

func setupSSHProbeFixture(t *testing.T) *sshProbeFixture {
	t.Helper()
	f := setupChangeSecretFixture(t, "root", "probe-pass-123")
	f.assets.SetHostKeyService(f.hostKeys)
	host, portStr, err := net.SplitHostPort(f.server.addr())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return &sshProbeFixture{csFixture: f, host: host, port: port}
}

// sshAsset 建一台指向靶機（或指定位址）的 SSH 資產，秘密依參數決定
func (f *sshProbeFixture) sshAsset(t *testing.T, name, host string, port int, password, privateKey string) uint {
	t.Helper()
	a, err := f.assets.Create(&CreateAssetRequest{
		Name: name, Protocol: model.ProtocolSSH, Host: host, Port: port,
		Username: "root", Password: password, PrivateKey: privateKey, CreatedBy: 1,
	})
	require.NoError(t, err)
	return a.ID
}

func (f *sshProbeFixture) run(t *testing.T, assetID uint) *ConnectionTestResult {
	t.Helper()
	res, err := f.assets.TestConnection(context.Background(), assetID, 5)
	require.NoError(t, err)
	require.NotNil(t, res)
	return res
}

// countingListener 只計數被接受的連線、立即關閉：用來證明撥測「沒有撥號」
func countingListener(t *testing.T) (string, int, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	var n atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			c.Close()
		}
	}()
	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return host, port, &n
}

func TestSSHConnectionTestPrivateKeyOnlySucceeds(t *testing.T) {
	f := setupSSHProbeFixture(t)
	privPEM, authLine := testKeyPair(t, "probe-key")
	f.server.seedAuthorizedKeys(authLine + "\n")

	id := f.sshAsset(t, "key-only", f.host, f.port, "", privPEM)
	res := f.run(t, id)

	assert.True(t, res.Success, "只有私鑰的帳號應以金鑰完成登入，實得 code=%s error_code=%s", res.Code, res.ErrorCode)
	assert.Empty(t, res.Code)
	assert.Equal(t, int32(1), f.server.publicKeyAuthOK.Load(), "靶機應恰好接受一次公鑰認證")
	assert.Equal(t, int32(0), f.server.passwordAuthCalls.Load(), "沒有密碼時不得送出密碼認證")
}

func TestSSHConnectionTestPasswordOnlySucceeds(t *testing.T) {
	f := setupSSHProbeFixture(t)

	res := f.run(t, f.assetID) // fixture 預設資產：只有密碼

	assert.True(t, res.Success, "只有密碼的帳號應以密碼完成登入，實得 code=%s", res.Code)
	assert.Equal(t, int32(1), f.server.passwordAuthCalls.Load())
	assert.Equal(t, int32(0), f.server.publicKeyAuthOK.Load())
}

func TestSSHConnectionTestKeyAndPasswordPrefersKey(t *testing.T) {
	f := setupSSHProbeFixture(t)
	privPEM, authLine := testKeyPair(t, "probe-both")
	f.server.seedAuthorizedKeys(authLine + "\n")

	id := f.sshAsset(t, "key-and-pw", f.host, f.port, "probe-pass-123", privPEM)
	res := f.run(t, id)

	assert.True(t, res.Success, "code=%s", res.Code)
	assert.Equal(t, int32(1), f.server.publicKeyAuthOK.Load(), "兩者皆有時私鑰優先")
	assert.Equal(t, int32(0), f.server.passwordAuthCalls.Load(), "私鑰已被接受，不應再送密碼")
}

// 金鑰被拒後在同一次交握內改用密碼：與正式終端連線相同的行為
func TestSSHConnectionTestRejectedKeyFallsBackToPasswordInSameHandshake(t *testing.T) {
	f := setupSSHProbeFixture(t)
	privPEM, _ := testKeyPair(t, "probe-unauthorized") // 不寫入 authorized_keys

	id := f.sshAsset(t, "key-rejected-pw-ok", f.host, f.port, "probe-pass-123", privPEM)
	res := f.run(t, id)

	assert.True(t, res.Success, "code=%s", res.Code)
	assert.Equal(t, int32(0), f.server.publicKeyAuthOK.Load())
	assert.Equal(t, int32(1), f.server.passwordAuthCalls.Load())
}

func TestSSHConnectionTestUnauthorizedKeyIsAuthFailure(t *testing.T) {
	f := setupSSHProbeFixture(t)
	privPEM, _ := testKeyPair(t, "probe-unauthorized")

	id := f.sshAsset(t, "key-rejected", f.host, f.port, "", privPEM)
	res := f.run(t, id)

	assert.False(t, res.Success)
	assert.Equal(t, apierror.CodeSSHAuthFailed, res.Code, "金鑰被目標拒絕應歸認證失敗")
	assert.NotEqual(t, ErrorCodeNoUsableAccount, res.ErrorCode)
}

func TestSSHConnectionTestNoSecretDoesNotDial(t *testing.T) {
	f := setupSSHProbeFixture(t)
	host, port, accepted := countingListener(t)

	id := f.sshAsset(t, "no-secret", host, port, "", "")
	res := f.run(t, id)

	assert.False(t, res.Success)
	assert.Equal(t, apierror.CodeAssetTestNoAccount, res.Code)
	assert.Equal(t, ErrorCodeNoUsableAccount, res.ErrorCode)
	assert.Equal(t, int32(0), accepted.Load(), "無秘密時不得撥號")
}

func TestSSHConnectionTestInvalidPrivateKeyReportsReason(t *testing.T) {
	_, rawPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(rawPriv, "protected", []byte("secret-phrase"))
	require.NoError(t, err)
	encryptedPEM := string(pem.EncodeToMemory(block))
	// 格式錯誤：執行期產生的合法私鑰截掉後半（常見的複製貼上不完整）
	validPEM, _ := testKeyPair(t, "probe-truncated")
	truncatedPEM := validPEM[:len(validPEM)/2]

	cases := map[string]struct{ key, password string }{
		"malformed":            {key: truncatedPEM},
		"passphrase_protected": {key: encryptedPEM},
		// 另有密碼也一樣判失敗：正式連線在私鑰無法解析時同樣無法建立
		"malformed_with_password": {key: "garbage", password: "probe-pass-123"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := setupSSHProbeFixture(t)
			host, port, accepted := countingListener(t)

			id := f.sshAsset(t, "bad-key-"+name, host, port, tc.password, tc.key)
			res := f.run(t, id)

			assert.False(t, res.Success)
			assert.Equal(t, apierror.CodeAssetTestPrivateKeyInvalid, res.Code)
			assert.Equal(t, ErrorCodePrivateKeyInvalid, res.ErrorCode)
			assert.NotEmpty(t, res.Message, "過渡 message 應取同碼的 zh fallback")
			assert.NotContains(t, res.Message, "ssh:", "原始解析錯誤不得出現在回應")
			assert.Equal(t, int32(0), accepted.Load(), "私鑰無法解析時不得撥號")
		})
	}
}

// 金鑰憑證的資產遇到目標不可達：原因必須是連線失敗，不能被誤報成「無可用帳號」。
// 憑證正確而主機網路不通，是管理者最需要被正確指出方向的情形
func TestSSHConnectionTestPrivateKeyOnlyUnreachableIsConnectionFailure(t *testing.T) {
	f := setupSSHProbeFixture(t)
	privPEM, _ := testKeyPair(t, "probe-unreachable")

	// 取一個剛釋放的埠：保證此刻無人監聽，撥號必被拒
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	require.NoError(t, ln.Close())

	id := f.sshAsset(t, "key-only-unreachable", host, port, "", privPEM)
	res := f.run(t, id)

	assert.False(t, res.Success)
	assert.Equal(t, apierror.CodeAssetTestConnectionFailed, res.Code)
	assert.Equal(t, ErrorCodeConnectionFailed, res.ErrorCode)
	assert.NotEqual(t, apierror.CodeAssetTestNoAccount, res.Code)
}
