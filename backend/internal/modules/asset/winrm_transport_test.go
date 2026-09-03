package asset

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// WinRM 傳輸不變式：目標拿不出訊息層加密就拒連（不降級明文）、TLS 三模式、
// HTTP 層守衛擋明文載荷。前兩組以正式的 NTLM 交握實跑（交握在伺服端密碼學之前就結束）。

// TestWinRMClientRefusesUnencryptedTarget 目標只接受明文（不提供 Negotiate、或未認證即
// 接受）→ 拒連帶 WINRM_ENCRYPTION_UNAVAILABLE；端點自始至終收不到任何帶載荷的請求。
func TestWinRMClientRefusesUnencryptedTarget(t *testing.T) {
	for _, mode := range []string{fakeWinRMModeBasicOnly, fakeWinRMModeAnonymous} {
		t.Run(mode, func(t *testing.T) {
			f := newFakeWinRMServer(t, "old")
			f.set(func(f *fakeWinRMServer) { f.mode = mode })

			e := newWindowsWinRMExecutor() // 正式組態：真 NTLM 交握
			e.dialTimeout, e.commandTimeout = 5*time.Second, 5*time.Second
			target := rotationTarget{asset: f.asset(), channel: model.RotationChannelWindowsWinRM, username: "Administrator"}

			err := e.Rotate(context.Background(), target, "old", "NewP@ss1")
			require.Error(t, err)
			var rejected *remoteRejectedError
			require.True(t, errors.As(err, &rejected), "須為遠端確定未變更的分流型別: %v", err)
			assert.Equal(t, model.ChangeSecretReasonWinRMEncryptionUnavailable, rejected.reason)
			require.ErrorIs(t, err, errWinRMEncryptionUnavailable)

			snap := f.snapshot()
			assert.Equal(t, 0, snap.bodyRequests, "拒連後不得有任何帶載荷的請求抵達端點（明文降級）")
			assert.Empty(t, snap.commands, "遠端未被觸碰")
		})
	}

	t.Run("runner 記為 failed 且候選清除", func(t *testing.T) {
		f := newFakeWinRMServer(t, "winoldpass")
		f.set(func(f *fakeWinRMServer) { f.mode = fakeWinRMModeBasicOnly })
		host, port := f.hostPort()

		fx := setupChangeSecretFixture(t, "root", "oldpass123")
		winrmID := fx.addRotationAsset(t, &CreateAssetRequest{
			Name: "win-plaintext", Protocol: model.ProtocolRDP, Host: host, Port: 3389,
			Username: "Administrator", Password: "winoldpass",
			RotationChannel: model.RotationChannelWindowsWinRM, WinrmScheme: model.WinrmSchemeHTTP, WinrmPort: port,
		})
		fx.runner.executors = func(string) rotationExecutor {
			e := newWindowsWinRMExecutor()
			e.dialTimeout, e.commandTimeout = 5*time.Second, 5*time.Second
			return e
		}
		records := fx.runner.RunPlan(fx.planForAssets(t, []uint{winrmID}, nil))
		require.Len(t, records, 1)
		assert.Equal(t, model.ChangeSecretFailed, records[0].Status)
		assert.Equal(t, model.ChangeSecretReasonWinRMEncryptionUnavailable, records[0].Error)
		assert.EqualValues(t, 0, fx.candidateCount(t), "遠端確定未變更 ⇒ 候選清除")
		assert.Equal(t, 0, f.snapshot().bodyRequests)
	})

	t.Run("傳輸守衛擋下明文載荷", func(t *testing.T) {
		f := newFakeWinRMServer(t, "old")
		f.set(func(f *fakeWinRMServer) { f.mode = fakeWinRMModeAnonymous }) // 端點什麼都收
		hc := newWinRMHTTPClient(nil, time.Second)

		req, err := http.NewRequest(http.MethodPost, f.srv.URL+"/wsman", strings.NewReader("<s:Envelope>plain</s:Envelope>"))
		require.NoError(t, err)
		req.Header.Set("Content-Type", winrmSOAPContentType)
		_, err = hc.Do(req)
		require.Error(t, err)
		assert.ErrorIs(t, err, errWinRMEncryptionUnavailable, "明文載荷須在送出前被拒")

		basic, err := http.NewRequest(http.MethodPost, f.srv.URL+"/wsman", nil)
		require.NoError(t, err)
		basic.SetBasicAuth("u", "p")
		_, err = hc.Do(basic)
		assert.ErrorIs(t, err, errWinRMEncryptionUnavailable, "Basic 認證標頭須被拒")

		assert.Equal(t, 0, f.snapshot().bodyRequests, "端點不得收到明文載荷")
	})
}

// TestWinRMClientTLSModes https 三模式對自簽憑證：system 拒、ca（上傳該憑證）接受、insecure 接受；
// ca 配錯的 CA 拒。
func TestWinRMClientTLSModes(t *testing.T) {
	f := newFakeWinRMTLSServer(t, "old")
	otherCA := unrelatedCertPEM(t)
	require.NotNil(t, parseCertPool(t, f.certPEM()))
	require.NotEqual(t, f.certPEM(), otherCA)

	cases := []struct {
		name   string
		mode   string
		ca     string
		accept bool
	}{
		{"system 不信任自簽", model.WinrmTLSModeSystem, "", false},
		{"ca 信任上傳憑證", model.WinrmTLSModeCA, f.certPEM(), true},
		{"ca 配錯憑證", model.WinrmTLSModeCA, otherCA, false},
		{"insecure 接受", model.WinrmTLSModeInsecure, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := f.snapshot().handshakes
			asset := f.asset()
			asset.WinrmTLSMode = c.mode
			asset.WinrmCACert = c.ca
			session, err := newWinRMSession(context.Background(), asset, "Administrator", "old", f.security, 5*time.Second)
			require.NoError(t, err)
			out := session.run(buildWindowsCommand(windowsVerifyScript), "", 5*time.Second, 5*time.Second)
			if c.accept {
				require.NoError(t, out.err)
				assert.Equal(t, 0, out.exitCode)
				assert.Greater(t, f.snapshot().handshakes, before, "應真的連上端點")
				return
			}
			require.Error(t, out.err)
			var dialErr *winrmDialError
			assert.True(t, errors.As(out.err, &dialErr), "TLS 失敗發生在建立 shell 之前")
			assert.NotErrorIs(t, out.err, errWinRMEncryptionUnavailable)
			assert.NotErrorIs(t, out.err, errWinRMAuthFailed)
			assert.Equal(t, before, f.snapshot().handshakes, "憑證不受信任時不得有任何請求抵達端點（不自動降級 insecure）")
		})
	}
}

// TestWinRMTransportNTLMHandshakeShape 正式 NTLM 交握對假端點的行為：端點提供 Negotiate 但
// 挑戰不合法時，交握失敗且沒有載荷送出；空載荷請求本身不含 Authorization: Basic。
func TestWinRMTransportNTLMHandshakeShape(t *testing.T) {
	f := newFakeWinRMServer(t, "old")
	sec := newWinRMNTLMSecurity("Administrator", "old")
	hc := newWinRMHTTPClient(nil, time.Second)
	err := sec.handshake(context.Background(), hc, f.srv.URL+"/wsman")
	require.Error(t, err)
	// 假端點不會回 NTLM 挑戰：第二輪拿到裸 Negotiate 再送 Negotiate 訊息，最後 401 ⇒ 憑證被拒語義
	assert.True(t, errors.Is(err, errWinRMAuthFailed) || errors.Is(err, errWinRMEncryptionUnavailable), "err=%v", err)
	snap := f.snapshot()
	assert.Equal(t, 0, snap.bodyRequests, "交握全程空載荷")
	assert.GreaterOrEqual(t, snap.handshakes, 2, "交握至少兩段（401 挑戰、Negotiate）")
}

// TestWinRMFramingRoundTrip 框架與 NTLM 封裝格式的自洽：unframe(frame(x)) == x。
func TestWinRMFramingRoundTrip(t *testing.T) {
	sealed := []byte{0x10, 0, 0, 0, '-', '-', 'E', '\r', '\n', 0xff, 0x00, 0x7f}
	framed := frameEncrypted(sealed, 42)
	assert.True(t, strings.HasPrefix(string(framed), winrmMIMEBoundary+"\r\n\tContent-Type: "+winrmEncryptedProtocol+"\r\n"))
	assert.Contains(t, string(framed), "OriginalContent: type="+winrmSOAPContentType+";Length=42\r\n")
	assert.True(t, strings.HasSuffix(string(framed), winrmMIMEBoundary+"--\r\n"))

	got, n, err := unframeEncrypted(framed)
	require.NoError(t, err)
	assert.Equal(t, 42, n)
	assert.Equal(t, sealed, got)

	_, _, err = unframeEncrypted([]byte("not a frame"))
	assert.Error(t, err)
}
