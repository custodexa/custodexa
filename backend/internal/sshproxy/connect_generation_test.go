package sshproxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/custodexa/backend/internal/modules/identity"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/pkg/crypto"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

// 憑證世代閘於 connect_token 兌換點的複查，與會話的認證溯源快照
// 與 guacd 路徑（internal/proxy）語義對稱：
// 簽發後、兌換前 provider 或使用者世代推進者，一律 401＋AUTH_CONNECT_TOKEN_INVALID。
//
// 閘本體（session.VerifyCredentialGenerationByUserID）直查 database.DB，
// 測試一律接真 sqlite、不 mock 掉閘——mock 掉就只驗到了呼叫點存在，
// 驗不到「零值本地 grant 不受影響」這條關鍵相容語義。

// setupGenerationTest 於既有政策閘 harness 上補 OIDC provider／host key 兩張表，
// 並把 asset 1 置於 open 段位（世代閘的判定不受政策段位影響）
func setupGenerationTest(t *testing.T) (*Handler, *gorm.DB) {
	t.Helper()
	h, db, _ := setupPolicyGateTest(t)
	if err := db.AutoMigrate(&model.OIDCProvider{}, &model.AssetHostKey{}); err != nil {
		t.Fatalf("migrate oidc/hostkey: %v", err)
	}
	seedGateFixture(t, db)
	setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
	return h, db
}

// seedProvider 建一個 OIDC provider 並回傳其 ID
func seedProvider(t *testing.T, db *gorm.DB, epoch int, enabled bool) uint {
	t.Helper()
	p := model.OIDCProvider{
		Name: "idp", Issuer: "https://idp.example", ClientID: "cid",
		AuthEpoch: epoch, Enabled: enabled,
	}
	if err := db.Create(&p).Error; err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	// Enabled 帶 not null default:false，GORM 對零值欄位交由 DB default 填，
	// 顯式 true 才會寫入；此處回寫確保兩種取值都精確落庫
	if err := db.Model(&model.OIDCProvider{}).Where("id = ?", p.ID).
		Update("enabled", enabled).Error; err != nil {
		t.Fatalf("set provider enabled: %v", err)
	}
	return p.ID
}

// issueTokenWithAuth 以帶認證脈絡的身分簽發 connect_token——脈絡經
// middleware.GetAuthContext 讀取，故測試以 context key 注入，與生產路徑同源
func issueTokenWithAuth(h *Handler, userID uint, role string, assetID uint, authCtx crypto.AuthContext) (int, map[string]interface{}) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/connect-tokens", func(c *gin.Context) {
		c.Set("userID", userID)
		c.Set("role", role)
		c.Set("authContext", authCtx)
		h.HandleCreateConnectToken(c)
	})
	body, _ := json.Marshal(map[string]interface{}{"asset_id": assetID})
	req := httptest.NewRequest("POST", "/connect-tokens", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp
}

// mustIssueWithAuth 簽發並回傳 token，前置失敗即中止
func mustIssueWithAuth(t *testing.T, h *Handler, authCtx crypto.AuthContext) string {
	t.Helper()
	code, resp := issueTokenWithAuth(h, 1, model.RoleUser, 1, authCtx)
	if code != http.StatusOK || resp["connect_token"] == nil {
		t.Fatalf("前置簽發應成功: code=%d resp=%v", code, resp)
	}
	token, _ := resp["connect_token"].(string)
	return token
}

// TestConnectRedeemGenerationRecheck 兌換點憑證世代複查（1.9）
func TestConnectRedeemGenerationRecheck(t *testing.T) {
	t.Run("簽發後 provider 世代推進，兌換被拒", func(t *testing.T) {
		h, db := setupGenerationTest(t)
		pid := seedProvider(t, db, 0, true)
		seedAccount(t, db, 1, "root", true)

		token := mustIssueWithAuth(t, h, crypto.AuthContext{
			AuthMethod: crypto.AuthMethodOIDC, ProviderID: pid,
		})

		// 停用／secret 輪替會推進 provider 世代（重新啟用不回退）
		if err := db.Model(&model.OIDCProvider{}).Where("id = ?", pid).
			Update("auth_epoch", 1).Error; err != nil {
			t.Fatalf("bump provider epoch: %v", err)
		}

		code, resp := redeemSSH(h, token)
		if code != http.StatusUnauthorized || resp["code"] != "AUTH_CONNECT_TOKEN_INVALID" {
			t.Fatalf("provider 世代推進後兌換應 401+AUTH_CONNECT_TOKEN_INVALID: code=%d resp=%v", code, resp)
		}
	})

	t.Run("簽發後 provider 停用，兌換被拒", func(t *testing.T) {
		h, db := setupGenerationTest(t)
		pid := seedProvider(t, db, 0, true)
		seedAccount(t, db, 1, "root", true)

		token := mustIssueWithAuth(t, h, crypto.AuthContext{
			AuthMethod: crypto.AuthMethodOIDC, ProviderID: pid,
		})

		if err := db.Model(&model.OIDCProvider{}).Where("id = ?", pid).
			Update("enabled", false).Error; err != nil {
			t.Fatalf("disable provider: %v", err)
		}

		code, resp := redeemSSH(h, token)
		if code != http.StatusUnauthorized || resp["code"] != "AUTH_CONNECT_TOKEN_INVALID" {
			t.Fatalf("provider 停用後兌換應 401+AUTH_CONNECT_TOKEN_INVALID: code=%d resp=%v", code, resp)
		}
	})

	t.Run("簽發後使用者憑證世代推進，兌換被拒", func(t *testing.T) {
		h, db := setupGenerationTest(t)
		pid := seedProvider(t, db, 0, true)
		seedAccount(t, db, 1, "root", true)

		token := mustIssueWithAuth(t, h, crypto.AuthContext{
			AuthMethod: crypto.AuthMethodOIDC, ProviderID: pid,
		})

		// 解除外部身分綁定／改密／改為僅外部登入皆推進使用者世代；
		// 帳號仍啟用、角色未變，角色現查閘完全擋不到這一類
		if err := identity.BumpCredentialEpoch(db, 1, "test_unbind"); err != nil {
			t.Fatalf("bump credential epoch: %v", err)
		}

		code, resp := redeemSSH(h, token)
		if code != http.StatusUnauthorized || resp["code"] != "AUTH_CONNECT_TOKEN_INVALID" {
			t.Fatalf("使用者世代推進後兌換應 401+AUTH_CONNECT_TOKEN_INVALID: code=%d resp=%v", code, resp)
		}
	})

	t.Run("本地 grant（四欄零值）不受世代閘影響", func(t *testing.T) {
		// 升級期相容的關鍵語義：ProviderID 0＝本地／LDAP 登入，且世代 0 與 DB
		// default 一致。即使系統中存在已推進世代的 provider，本地 grant 也不得被牽連
		h, db := setupGenerationTest(t)
		seedProvider(t, db, 7, false) // 已停用且世代已推進的 provider
		seedAccount(t, db, 1, "root", true)

		code, resp, _ := issueToken(h, 1, model.RoleUser, 1)
		if code != http.StatusOK || resp["connect_token"] == nil {
			t.Fatalf("前置簽發應成功: code=%d resp=%v", code, resp)
		}
		token, _ := resp["connect_token"].(string)

		rcode, rresp := redeemSSH(h, token)
		if rcode == http.StatusUnauthorized || rresp["code"] == "AUTH_CONNECT_TOKEN_INVALID" {
			t.Fatalf("本地 grant 不得被世代閘攔下: code=%d resp=%v", rcode, rresp)
		}
		// 排除假通過：正向案應落到後續建線階段失敗（資產 host 不可達），非 200/101
		if rcode == http.StatusOK || rcode == http.StatusSwitchingProtocols {
			t.Fatalf("正向案應落建線階段失敗、非假通過/升級: code=%d resp=%v", rcode, rresp)
		}
	})
}

// serveTestSSHConn 最小 SSH 伺服端：接 session channel、對 pty-req/shell 回 OK 並回聲，
// 足以讓 sshproxy.Dial 完成握手＋PTY＋shell
func serveTestSSHConn(nConn net.Conn, cfg *ssh.ServerConfig) {
	sconn, chans, reqs, err := ssh.NewServerConn(nConn, cfg)
	if err != nil {
		nConn.Close()
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			return
		}
		go func(reqs <-chan *ssh.Request) {
			for req := range reqs {
				switch req.Type {
				case "pty-req", "shell", "window-change":
					if req.WantReply {
						req.Reply(true, nil)
					}
				default:
					if req.WantReply {
						req.Reply(false, nil)
					}
				}
			}
		}(chReqs)
		go func(ch ssh.Channel) {
			io.Copy(ch, ch)
			ch.Close()
		}(ch)
	}
}

// startTestSSHServer 起一個行程內 SSH 伺服器（127.0.0.1 隨機埠），回傳埠號。
// 用行程內伺服器而非測試靶機容器：溯源斷言必須真的走完建線 → createSession，
// 不能因容器不可達／密碼漂移而跳過
func startTestSSHServer(t *testing.T, user, password string) int {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == user && string(pass) == password {
				return nil, nil
			}
			return nil, fmt.Errorf("認證失敗")
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			nc, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go serveTestSSHConn(nc, cfg)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// prepareRedeemableAsset 讓 asset 1 指向行程內 SSH 伺服器，並補上可用帳號憑證，
// 使兌換能真的建線並走到 createSession
func prepareRedeemableAsset(t *testing.T, h *Handler, db *gorm.DB) {
	t.Helper()
	port := startTestSSHServer(t, "testuser", "testpass123")
	if err := db.Model(&model.Asset{}).Where("id = ?", 1).
		Updates(map[string]interface{}{"host": "127.0.0.1", "port": port}).Error; err != nil {
		t.Fatalf("point asset at test server: %v", err)
	}
	// 帳號密碼須以與 AssetService 同一把測試金鑰＋同一 AAD 欄位身分加密
	enc, err := aesColumnCodec(t, make([]byte, 32)).EncryptFor(context.Background(),
		crypto.CipherRef{Table: "asset_accounts", Column: "password_enc"}, "testpass123")
	if err != nil {
		t.Fatalf("encrypt account password: %v", err)
	}
	acct := model.AssetAccount{AssetID: 1, Username: "testuser", PasswordEnc: enc, IsDefault: true}
	if err := db.Create(&acct).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}
	h.SessionService = session.NewSessionService(nil)
	h.HostKeys = asset.NewHostKeyService(db)
}

// latestSession 取最近建立的一筆會話列
func latestSession(t *testing.T, db *gorm.DB) model.Session {
	t.Helper()
	var s model.Session
	if err := db.Order("id DESC").First(&s).Error; err != nil {
		t.Fatalf("未建立 session 列（兌換未走到 createSession）: %v", err)
	}
	return s
}

// TestSessionAuthProvenance 會話認證溯源快照（1.9）：OIDC 兌換寫入 provider 與世代，
// 本地兌換寫 NULL。NULL 與 0 的區分是「停用 provider 時要砍哪些連線」的判定基礎——
// 混為一談會把本地登入建立的會話一併砍掉
func TestSessionAuthProvenance(t *testing.T) {
	t.Run("OIDC grant 兌換後 session 帶 provider 與世代", func(t *testing.T) {
		h, db := setupGenerationTest(t)
		prepareRedeemableAsset(t, h, db)
		pid := seedProvider(t, db, 3, true)

		token := mustIssueWithAuth(t, h, crypto.AuthContext{
			AuthMethod: crypto.AuthMethodOIDC, ProviderID: pid, AuthEpoch: 3,
		})
		// WS 升級在 httptest recorder 上必失敗（不可 hijack），但 session 列已於
		// 升級前寫入——溯源欄位正是本測試的斷言對象
		redeemSSH(h, token)

		s := latestSession(t, db)
		if s.AuthProviderID == nil || *s.AuthProviderID != pid {
			t.Fatalf("session.auth_provider_id 應為 %d: got=%v", pid, s.AuthProviderID)
		}
		if s.AuthEpoch != 3 {
			t.Fatalf("session.auth_epoch 應為 3: got=%d", s.AuthEpoch)
		}
	})

	t.Run("本地 grant 兌換後 auth_provider_id 為 NULL", func(t *testing.T) {
		h, db := setupGenerationTest(t)
		prepareRedeemableAsset(t, h, db)

		code, resp, _ := issueToken(h, 1, model.RoleUser, 1)
		if code != http.StatusOK || resp["connect_token"] == nil {
			t.Fatalf("前置簽發應成功: code=%d resp=%v", code, resp)
		}
		token, _ := resp["connect_token"].(string)
		redeemSSH(h, token)

		s := latestSession(t, db)
		if s.AuthProviderID != nil {
			t.Fatalf("本地登入的 session 須寫 NULL 以與 OIDC 區分: got=%v", *s.AuthProviderID)
		}
		if s.AuthEpoch != 0 {
			t.Fatalf("本地登入的 session auth_epoch 應為 0: got=%d", s.AuthEpoch)
		}
		// 溯源絕不可由外部身分表反推：此使用者無任何外部身分，欄位就該是空的
		var count int64
		if err := db.Model(&model.Session{}).Where("auth_provider_id IS NOT NULL").
			Count(&count).Error; err != nil {
			t.Fatalf("count: %v", err)
		}
		if count != 0 {
			t.Fatalf("本地兌換不得寫入任何 provider 溯源: count=%d", count)
		}
	})
}
