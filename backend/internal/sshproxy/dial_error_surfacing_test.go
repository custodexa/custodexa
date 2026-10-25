package sshproxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/k8sproxy"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

// TestK8sDialCode k8sproxy 分類（K8sError.Kind）→ apierror code 映射
// 六類各配一碼、彼此相異且都已註冊；
// Kind 值變動或漏配時本測試紅（散文降級為 Data fallback 後，碼是唯一分辨依據）。
func TestK8sDialCode(t *testing.T) {
	kinds := []string{
		k8sproxy.KindUnauthorized, k8sproxy.KindForbidden, k8sproxy.KindNotFound,
		k8sproxy.KindTLS, k8sproxy.KindUnreachable, k8sproxy.KindUnknown,
	}
	seen := map[apierror.ErrCode]string{}
	for _, kind := range kinds {
		code := k8sDialCode(&k8sproxy.K8sError{Kind: kind, Message: "x"})
		if code == apierror.CodeK8sPodUnavailable {
			t.Errorf("kind %q 落回泛碼（未配專屬碼）", kind)
		}
		if !apierror.IsRegistered(code) {
			t.Errorf("kind %q 映到未註冊的碼 %q", kind, code)
		}
		if prev, dup := seen[code]; dup {
			t.Errorf("kind %q 與 %q 共用碼 %q（六類必須可分辨）", kind, prev, code)
		}
		seen[code] = kind
	}
	// 非 K8sError 與未知 Kind 退回泛碼（不 panic、不誤用他類碼）
	if got := k8sDialCode(errors.New("boom")); got != apierror.CodeK8sPodUnavailable {
		t.Errorf("非 K8sError 應退回泛碼，got %q", got)
	}
	if got := k8sDialCode(&k8sproxy.K8sError{Kind: "brand-new"}); got != apierror.CodeK8sPodUnavailable {
		t.Errorf("未知 Kind 應退回泛碼，got %q", got)
	}
}

// TestDialErrorCode sentinel → apierror code 映射
func TestDialErrorCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want apierror.ErrCode
	}{
		// 不符被拒（不放行路徑）用拒絕碼，不用陳述「已送出憑證」的警示碼
		{name: "host key 不符被拒", err: asset.ErrHostKeyChanged, want: apierror.CodeSSHHostKeyMismatchRefused},
		{name: "包裹後的 host key 不符被拒仍命中", err: fmt.Errorf("wrap: %w", asset.ErrHostKeyChanged), want: apierror.CodeSSHHostKeyMismatchRefused},
		{name: "認證失敗", err: ErrAuthFailed, want: apierror.CodeSSHAuthFailed},
		{name: "逾時", err: ErrDialTimeout, want: apierror.CodeSSHDialTimeout},
		{name: "不可達", err: ErrUnreachable, want: apierror.CodeSSHUnreachable},
		{name: "未分類錯誤落不可達", err: errors.New("boom"), want: apierror.CodeSSHUnreachable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dialErrorCode(tt.err); got != tt.want {
				t.Errorf("dialErrorCode(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

// TestWriteDialErrorWS 瀏覽器 WS 客戶端收到升級後的 MsgError（code＋zh fallback）
// 後連線正常關閉
func TestWriteDialErrorWS(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/ssh", func(c *gin.Context) {
		writeDialError(c, apierror.CodeSSHHostKeyMismatchRefused, "主機身分與記錄不符：這次連線已拒絕")
	})
	srv := httptest.NewServer(r)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ssh"
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("WS 升級應成功: err=%v resp=%v", err, resp)
	}
	defer conn.Close()

	_, raw, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("讀取 error 訊息失敗: %v", err)
	}
	var msg Message
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatalf("error 訊息非合法 JSON: %v (%s)", err, raw)
	}
	if msg.Type != MsgError {
		t.Errorf("Type = %q, want %q", msg.Type, MsgError)
	}
	if msg.Code != "RULE_SSH_HOST_KEY_MISMATCH_REFUSED" {
		t.Errorf("Code = %q, want RULE_SSH_HOST_KEY_MISMATCH_REFUSED", msg.Code)
	}
	if !strings.Contains(msg.Data, "這次連線已拒絕") {
		t.Errorf("Data = %q, want 含「這次連線已拒絕」", msg.Data)
	}

	// error 訊息後應收到正常關閉
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("error 訊息後應關閉連線")
	} else if !websocket.IsCloseError(err, websocket.CloseNormalClosure) {
		t.Errorf("關閉語義非 NormalClosure: %v", err)
	}
}

// TestWriteDialErrorHTTP 非 WS 升級請求維持既有 HTTP 502 JSON 語義
func TestWriteDialErrorHTTP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/ssh", func(c *gin.Context) {
		writeDialError(c, apierror.CodeSSHAuthFailed, "SSH 認證失敗，請確認資產憑證")
	})
	req := httptest.NewRequest("GET", "/ssh", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("狀態碼 = %d, want 502", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("回應非 JSON: %v (%s)", err, w.Body.String())
	}
	if resp["error"] != "SSH 認證失敗，請確認資產憑證" {
		t.Errorf("error = %v, want SSH 認證失敗文案", resp["error"])
	}
}

// rejectingSSHTarget 行程內 SSH 靶機：接受交握、拒絕任何公鑰認證。
// accepted 計數 TCP 連線、keyAttempts 計數收到的公鑰認證嘗試。
func rejectingSSHTarget(t *testing.T) (string, int, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	var accepted, keyAttempts atomic.Int32
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			keyAttempts.Add(1)
			return nil, errors.New("public key not authorized")
		},
	}
	cfg.AddHostKey(hostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer nc.Close()
				_ = nc.SetDeadline(time.Now().Add(10 * time.Second))
				_, _, _, _ = ssh.NewServerConn(nc, cfg)
			}()
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return host, port, &accepted, &keyAttempts
}

// dialTerminalWithPrivateKey 走實際建連流程：資產指向靶機、預設帳號的就位版本放入
// 指定私鑰（直寫密文，模擬寫入驗證上線前已在庫的私鑰），簽發 connect token 後以
// 瀏覽器 WebSocket 兌換，回傳第一個 WS 訊息。
func dialTerminalWithPrivateKey(t *testing.T, privateKey string) (Message, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	h, db, _ := setupPolicyGateTest(t)
	seedGateFixture(t, db)
	setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
	if err := db.AutoMigrate(&model.AssetHostKey{}, &model.Role{}, &model.UserGroup{}); err != nil {
		t.Fatalf("migrate host keys: %v", err)
	}
	if err := db.AutoMigrate(&model.UserRole{}, &model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{}); err != nil {
		t.Fatalf("migrate host keys: %v", err)
	}
	h.HostKeys = asset.NewHostKeyService(db)

	host, port, accepted, keyAttempts := rejectingSSHTarget(t)
	if err := db.Model(&model.Asset{}).Where("id = ?", 1).
		Updates(map[string]any{"host": host, "port": port}).Error; err != nil {
		t.Fatalf("point asset at target: %v", err)
	}
	enc, err := aesColumnCodec(t, make([]byte, 32)).EncryptFor(context.Background(),
		keyvault.RefCredentialVersionPrivateKey, privateKey)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	cred := model.Credential{Scope: model.CredentialScopeDedicated, Username: "root",
		SecretType: model.ChangeSecretTypeSSHKey, ProtocolFamily: model.ProtocolFamilySSH}
	if err := db.Create(&cred).Error; err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	ver := model.CredentialSecretVersion{CredentialID: cred.ID, VersionNo: 1,
		SecretType: model.ChangeSecretTypeSSHKey, PrivateKeyEnc: enc,
		CreatedReason: model.CredentialVersionReasonManual}
	if err := db.Create(&ver).Error; err != nil {
		t.Fatalf("seed version: %v", err)
	}
	if err := db.Create(&model.AssetAccount{AssetID: 1, Username: "root", IsDefault: true,
		CredentialID: cred.ID, EffectiveVersionID: &ver.ID}).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}

	code, resp, _ := issueToken(h, 1, model.RoleUser, 1)
	if code != http.StatusOK {
		t.Fatalf("簽發應成功: code=%d resp=%v", code, resp)
	}
	token, _ := resp["connect_token"].(string)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/ssh", h.HandleSSH)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ssh?cols=80&rows=24&connect_token=" + url.QueryEscape(token)
	conn, wsResp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		status := 0
		if wsResp != nil {
			status = wsResp.StatusCode
		}
		t.Fatalf("WS 升級應成功: err=%v status=%d", err, status)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	_, raw, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("讀取 error 訊息失敗: %v", err)
	}
	var msg Message
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatalf("error 訊息非合法 JSON: %v (%s)", err, raw)
	}
	return msg, accepted, keyAttempts
}

// TestDialPrivateKeyInvalidSurfacesOverWS 私鑰無法解析（格式錯誤、受 passphrase 保護）
// 經實際建連流程送達：碼為 RULE_SSH_PRIVATE_KEY_INVALID、data 與該碼的 zh fallback
// 完全相等，且靶機沒收到任何連線。
func TestDialPrivateKeyInvalidSurfacesOverWS(t *testing.T) {
	desc, ok := apierror.DescriptorOf(apierror.CodeSSHPrivateKeyInvalid)
	if !ok || desc.ZhFallback == "" {
		t.Fatal("RULE_SSH_PRIVATE_KEY_INVALID 須已登記且有 zh fallback")
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	encBlock, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "dial", []byte("secret-phrase"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	cases := map[string]string{
		"Malformed":  "-----BEGIN OPENSSH PRIVATE KEY-----\nbroken\n",
		"Passphrase": string(pem.EncodeToMemory(encBlock)),
	}
	for name, key := range cases {
		t.Run(name, func(t *testing.T) {
			msg, accepted, _ := dialTerminalWithPrivateKey(t, key)
			if msg.Type != MsgError {
				t.Fatalf("Type = %q, want %q", msg.Type, MsgError)
			}
			if msg.Code != string(apierror.CodeSSHPrivateKeyInvalid) {
				t.Fatalf("Code = %q, want %s", msg.Code, apierror.CodeSSHPrivateKeyInvalid)
			}
			if msg.Data != desc.ZhFallback {
				t.Fatalf("Data = %q, want registry zh fallback %q", msg.Data, desc.ZhFallback)
			}
			if msg.Data == "解析私鑰失敗" {
				t.Fatalf("Data 不得是截斷後的舊訊息")
			}
			if n := accepted.Load(); n != 0 {
				t.Fatalf("私鑰無法解析時不得撥號，靶機收到 %d 條連線", n)
			}
		})
	}
}

// TestDialRejectedPublicKeyStaysAuthFailed 可解析但被目標拒絕的私鑰仍歸認證失敗，
// 與私鑰無法解析明確區分。
func TestDialRejectedPublicKeyStaysAuthFailed(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "dial-rejected")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	msg, _, keyAttempts := dialTerminalWithPrivateKey(t, string(pem.EncodeToMemory(block)))
	if msg.Code != string(apierror.CodeSSHAuthFailed) {
		t.Fatalf("Code = %q, want %s (data=%q)", msg.Code, apierror.CodeSSHAuthFailed, msg.Data)
	}
	if keyAttempts.Load() == 0 {
		t.Fatal("前提：靶機應收到公鑰認證嘗試")
	}
}
