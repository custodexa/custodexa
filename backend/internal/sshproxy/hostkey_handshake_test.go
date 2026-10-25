package sshproxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/custodexa/backend/pkg/crypto"
)

// handshakeAlertSink 記錄型系統告警落地面
type handshakeAlertSink struct {
	events []port.SystemAlertEvent
}

func (s *handshakeAlertSink) RaiseInTx(_ *gorm.DB, ev port.SystemAlertEvent) (port.SystemAlertReceipt, error) {
	s.events = append(s.events, ev)
	return port.SystemAlertReceipt{}, nil
}

type handshakeFailingTxSink struct{ err error }

func (f handshakeFailingTxSink) WriteInTx(*gorm.DB, port.AuditEvent) error { return f.err }

// handshakeTarget 能完成交握與密碼認證的行程內 SSH 靶機；onAuth 在認證回呼內執行（斷言留痕已存在）。
type handshakeTarget struct {
	hostKey      ssh.PublicKey
	authAttempts atomic.Int32
	onAuth       func()
	// rejectSessionMsg 非空時：認證成功後對 session channel 開啟回 Reject，訊息即此字串
	//（模擬冒充主機把收到的密碼塞回錯誤訊息）
	rejectSessionMsg string
}

func startHandshakeTarget(t *testing.T, user, password string) (*handshakeTarget, string, int) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	tg := &handshakeTarget{hostKey: signer.PublicKey()}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			tg.authAttempts.Add(1)
			if tg.onAuth != nil {
				tg.onAuth()
			}
			if c.User() == user && string(pass) == password {
				return nil, nil
			}
			return nil, fmt.Errorf("認證失敗")
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			nc, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			if tg.rejectSessionMsg != "" {
				go serveRejectingSSHConn(nc, cfg, tg.rejectSessionMsg)
				continue
			}
			go serveTestSSHConn(nc, cfg)
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return tg, host, port
}

// serveRejectingSSHConn 完成交握與認證後，對每個 channel 開啟都以伺服器可控的訊息拒絕
func serveRejectingSSHConn(nConn net.Conn, cfg *ssh.ServerConfig, msg string) {
	sconn, chans, reqs, err := ssh.NewServerConn(nConn, cfg)
	if err != nil {
		nConn.Close()
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	for newCh := range chans {
		_ = newCh.Reject(ssh.Prohibited, msg)
	}
}

// captureHostKeyLog 攔截標準 log 輸出（測試結束還原）
func captureHostKeyLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

// redeemWSGrant 直接以票證管理器簽發指定 grant 後兌換（供 agent 主體的票）
func (e *handshakeEnv) redeemWSGrant(t *testing.T, grant proxy.ConnectGrant, n int) []Message {
	t.Helper()
	token, err := e.h.ConnectTokens.IssueConnectToken(context.Background(), grant)
	if err != nil {
		t.Fatal(err)
	}
	return e.redeemToken(t, token, n)
}

func (e *handshakeEnv) redeemToken(t *testing.T, token string, n int) []Message {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/ssh", e.h.HandleSSH)
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
	t.Cleanup(func() { conn.Close() })
	var msgs []Message
	for i := 0; i < n; i++ {
		_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		_, raw, err := conn.ReadMessage()
		if err != nil {
			break
		}
		var msg Message
		if err := json.Unmarshal(raw, &msg); err != nil {
			t.Fatalf("訊息非合法 JSON: %v (%s)", err, raw)
		}
		msgs = append(msgs, msg)
		if msg.Type == MsgError {
			break
		}
	}
	return msgs
}

func (e *handshakeEnv) auditsOf(t *testing.T, action model.AuditAction) []model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	if err := e.db.Where("action = ?", string(action)).Order("id").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}

type handshakeEnv struct {
	h        *Handler
	db       *gorm.DB
	target   *handshakeTarget
	hostKeys *asset.HostKeyService
	alerts   *handshakeAlertSink
}

// newHandshakeEnv 資產 1 指向靶機、預設帳號帶密碼憑證；主機金鑰服務帶真審計落地面與記錄型告警落地面。
func newHandshakeEnv(t *testing.T) *handshakeEnv {
	t.Helper()
	h, db, _ := setupPolicyGateTest(t)
	seedGateFixture(t, db)
	setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
	if err := db.AutoMigrate(&model.AssetHostKey{}, &model.AssetHostKeyMismatch{}); err != nil {
		t.Fatal(err)
	}
	target, host, port := startHandshakeTarget(t, "testuser", "testpass123")
	if err := db.Model(&model.Asset{}).Where("id = ?", 1).
		Updates(map[string]any{"host": host, "port": port}).Error; err != nil {
		t.Fatal(err)
	}
	enc, err := aesColumnCodec(t, make([]byte, 32)).EncryptFor(context.Background(),
		crypto.CipherRef{Table: "credential_secret_versions", Column: "password_enc"}, "testpass123")
	if err != nil {
		t.Fatal(err)
	}
	cred := model.Credential{Scope: model.CredentialScopeDedicated, Username: "testuser",
		SecretType: model.ChangeSecretTypePassword, AuthMethod: "sql", ProtocolFamily: model.ProtocolFamilySSH}
	if err := db.Create(&cred).Error; err != nil {
		t.Fatal(err)
	}
	ver := model.CredentialSecretVersion{CredentialID: cred.ID, VersionNo: 1,
		SecretType: model.ChangeSecretTypePassword, PasswordEnc: enc, CreatedReason: model.CredentialVersionReasonManual}
	if err := db.Create(&ver).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.AssetAccount{AssetID: 1, Username: "testuser", IsDefault: true,
		CredentialID: cred.ID, EffectiveVersionID: &ver.ID}).Error; err != nil {
		t.Fatal(err)
	}
	h.SessionService = session.NewSessionService(nil)
	h.Registry = proxy.NewConnectionRegistry()
	hostKeys := asset.NewHostKeyService(db)
	alerts := &handshakeAlertSink{}
	hostKeys.SetAuditTxSink(audit.NewTxSink())
	hostKeys.SetSystemAlertSink(alerts)
	h.HostKeys = hostKeys
	return &handshakeEnv{h: h, db: db, target: target, hostKeys: hostKeys, alerts: alerts}
}

// seedForeignRecord 為資產 1 寫入與靶機不同的記錄，讓兌換撥號判為不符
func (e *handshakeEnv) seedForeignRecord(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	var a model.Asset
	if err := e.db.First(&a, 1).Error; err != nil {
		t.Fatal(err)
	}
	host, port, _ := a.HostKeyAddress()
	if err := e.db.Create(&model.AssetHostKey{AssetID: 1, Algorithm: foreign.Type(), Fingerprint: ssh.FingerprintSHA256(foreign),
		PublicKey: base64.StdEncoding.EncodeToString(foreign.Marshal()), Host: host, Port: port}).Error; err != nil {
		t.Fatal(err)
	}
	return foreign
}

// redeemWS 簽發 connect token 並以瀏覽器 WebSocket 兌換，回傳依序讀到的前 n 個訊息（或讀到 error／關閉為止）
func (e *handshakeEnv) redeemWS(t *testing.T, n int) []Message {
	t.Helper()
	code, resp, _ := issueToken(e.h, 1, model.RoleUser, 1)
	if code != http.StatusOK {
		t.Fatalf("簽發應成功: code=%d resp=%v", code, resp)
	}
	token, _ := resp["connect_token"].(string)
	return e.redeemToken(t, token, n)
}

func (e *handshakeEnv) mismatchAudits(t *testing.T) []model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	if err := e.db.Where("action = ?", string(model.ActionHostKeyMismatch)).Order("id").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}

// TestHostKeyMismatchHandshake 終端：不符時 WS 依序收到 connected 與 RULE_SSH_HOST_KEY_CHANGED 的 notice、無 error；
// agent 主體遇不符收到 RULE_SSH_HOST_KEY_MISMATCH_REFUSED 的 error（文案明示未送出憑證）；
// 靶機收到認證時審計與告警已存在；審計的連線識別等於會話列的 session_id；留痕失敗時收到
// RULE_SSH_HOST_KEY_CHECK_FAILED 且靶機認證嘗試 0；記錄讀取失敗不再映射為不可達。
func TestHostKeyMismatchHandshake(t *testing.T) {
	t.Run("不符放行：connected 後 notice，留痕早於認證，連線識別等於會話識別", func(t *testing.T) {
		e := newHandshakeEnv(t)
		foreign := e.seedForeignRecord(t)
		var auditsAtAuth, alertsAtAuth int32 = -1, -1
		e.target.onAuth = func() {
			var n int64
			e.db.Model(&model.AuditLog{}).Where("action = ?", string(model.ActionHostKeyMismatch)).Count(&n)
			auditsAtAuth = int32(n)
			alertsAtAuth = int32(len(e.alerts.events))
		}
		msgs := e.redeemWS(t, 2)
		if len(msgs) < 2 || msgs[0].Type != MsgConnected {
			t.Fatalf("第一個訊息應為 connected: %+v", msgs)
		}
		if msgs[1].Type != MsgNotice || msgs[1].Code != string(apierror.CodeSSHHostKeyChanged) {
			t.Fatalf("第二個訊息應為 RULE_SSH_HOST_KEY_CHANGED 的 notice: %+v", msgs[1])
		}
		// 互動放行：憑證確實送出，警示文案維持「已送出登入憑證」的說法
		if !strings.Contains(msgs[1].Data, "已送出登入憑證") {
			t.Fatalf("互動放行的警示應陳述已送出登入憑證: %q", msgs[1].Data)
		}
		for _, m := range msgs {
			if m.Type == MsgError {
				t.Fatalf("不得收到 error: %+v", m)
			}
		}
		if e.target.authAttempts.Load() == 0 {
			t.Fatal("互動路徑放行後靶機應收到認證嘗試")
		}
		if auditsAtAuth != 1 || alertsAtAuth != 1 {
			t.Fatalf("靶機收到認證時審計與告警應已存在（審計 %d、告警 %d）", auditsAtAuth, alertsAtAuth)
		}
		audits := e.mismatchAudits(t)
		if len(audits) != 1 {
			t.Fatalf("審計應 1 筆，實有 %d", len(audits))
		}
		var details map[string]any
		_ = json.Unmarshal([]byte(audits[0].Details), &details)
		var sess model.Session
		if err := e.db.Order("id DESC").First(&sess).Error; err != nil {
			t.Fatalf("會話列應已建立: %v", err)
		}
		if details["connection_ref"] != sess.SessionID || sess.SessionID == "" {
			t.Fatalf("審計的連線識別 %v 應等於會話列的 session_id %q", details["connection_ref"], sess.SessionID)
		}
		if details["path"] != "terminal" || details["outcome"] != "allowed" || details["recorded_fingerprint"] != ssh.FingerprintSHA256(foreign) ||
			details["observed_fingerprint"] != ssh.FingerprintSHA256(e.target.hostKey) {
			t.Fatalf("審計 details 不符: %v", details)
		}
		if audits[0].UserID != 1 || audits[0].Username != "u-user" {
			t.Fatalf("連線使用者應為兌換者（依 ID 現查名稱）: %+v", audits[0])
		}
		ev := e.alerts.events[0]
		if ev.Type != port.SystemAlertHostKeyMismatch || ev.Params["outcome"] != "allowed" || ev.Params["path"] != "terminal" ||
			ev.Params["connection_ref"] != sess.SessionID || ev.Actor.Username != "u-user" {
			t.Fatalf("告警事件不符: %+v", ev)
		}
		if details["credentials"] != "about_to_be_sent" {
			t.Fatalf("放行的不符審計應明示憑證即將送出: %v", details)
		}
		// 憑證實際已送出：認證完成後補記一筆，同一 correlation_id
		sent := e.auditsOf(t, model.ActionHostKeyCredSent)
		if len(sent) != 1 {
			t.Fatalf("認證完成後應補記 host_key_cred_sent 1 筆，實有 %d", len(sent))
		}
		var sd map[string]any
		_ = json.Unmarshal([]byte(sent[0].Details), &sd)
		if sd["correlation_id"] != details["correlation_id"] || sd["auth_result"] != "succeeded" || sd["path"] != "terminal" {
			t.Fatalf("host_key_cred_sent details 不符: %v", sd)
		}
	})

	t.Run("agent 主體建線遇不符：拒絕、靶機認證嘗試 0、留痕為 refused（agent_terminal）", func(t *testing.T) {
		e := newHandshakeEnv(t)
		e.seedForeignRecord(t)
		msgs := e.redeemWSGrant(t, proxy.ConnectGrant{
			UserID: 1, AssetID: 1, PrincipalKind: model.KindAgent, AgentTokenID: 77,
		}, 2)
		if len(msgs) != 1 || msgs[0].Type != MsgError || msgs[0].Code != string(apierror.CodeSSHHostKeyMismatchRefused) {
			t.Fatalf("agent 遇不符應收到 RULE_SSH_HOST_KEY_MISMATCH_REFUSED 的 error 後關閉: %+v", msgs)
		}
		// 拒絕：憑證未送出，回應文案不得聲稱已送出，且要明示未送出
		if strings.Contains(msgs[0].Data, "已送出") || !strings.Contains(msgs[0].Data, "未送出任何登入憑證") {
			t.Fatalf("拒絕情境的文案應明示未送出登入憑證、不含已送出的說法: %q", msgs[0].Data)
		}
		if n := e.target.authAttempts.Load(); n != 0 {
			t.Fatalf("agent 背景路徑遇不符不得送出憑證，靶機收到 %d 次認證", n)
		}
		audits := e.mismatchAudits(t)
		if len(audits) != 1 {
			t.Fatalf("審計應 1 筆，實有 %d", len(audits))
		}
		var details map[string]any
		_ = json.Unmarshal([]byte(audits[0].Details), &details)
		if details["outcome"] != "refused" || details["path"] != "agent_terminal" || details["credentials"] != "not_sent" {
			t.Fatalf("agent 的不符審計應為 refused／agent_terminal／not_sent: %v", details)
		}
		if len(e.alerts.events) != 1 || e.alerts.events[0].Params["outcome"] != "refused" || e.alerts.events[0].Params["path"] != "agent_terminal" {
			t.Fatalf("agent 的告警應為 refused／agent_terminal: %+v", e.alerts.events)
		}
		if len(e.auditsOf(t, model.ActionHostKeyCredSent)) != 0 {
			t.Fatal("拒絕後不得補記憑證已送出")
		}
	})

	t.Run("人類終端放行後目標拒絕認證：error 幀帶不符參數，補記憑證已送出但認證失敗", func(t *testing.T) {
		e := newHandshakeEnv(t)
		e.seedForeignRecord(t)
		// 資產帳號密碼改成錯的：目標在不符放行後拒絕認證
		var acct model.AssetAccount
		if err := e.db.Where("asset_id = ?", 1).First(&acct).Error; err != nil {
			t.Fatal(err)
		}
		enc, _ := aesColumnCodec(t, make([]byte, 32)).EncryptFor(context.Background(),
			crypto.CipherRef{Table: "credential_secret_versions", Column: "password_enc"}, "wrong-pass")
		if err := e.db.Model(&model.CredentialSecretVersion{}).Where("id = ?", *acct.EffectiveVersionID).Update("password_enc", enc).Error; err != nil {
			t.Fatal(err)
		}
		msgs := e.redeemWS(t, 2)
		if len(msgs) != 1 || msgs[0].Type != MsgError || msgs[0].Code != string(apierror.CodeSSHAuthFailed) {
			t.Fatalf("應收到 RULE_SSH_AUTH_FAILED: %+v", msgs)
		}
		if msgs[0].Params["host_key_mismatch"] != "1" {
			t.Fatalf("認證失敗的 error 幀應帶 host_key_mismatch 參數（憑證可能已送出）: %+v", msgs[0])
		}
		if e.target.authAttempts.Load() == 0 {
			t.Fatal("前提：靶機應收到認證嘗試")
		}
		sent := e.auditsOf(t, model.ActionHostKeyCredSent)
		if len(sent) != 1 {
			t.Fatalf("認證失敗仍應補記憑證已送出 1 筆，實有 %d", len(sent))
		}
		var sd map[string]any
		_ = json.Unmarshal([]byte(sent[0].Details), &sd)
		if sd["auth_result"] != "failed" {
			t.Fatalf("auth_result 應為 failed: %v", sd)
		}
	})

	t.Run("冒充主機把密碼塞進 channel reject：日誌、WS 回應與審計都不含密碼", func(t *testing.T) {
		e := newHandshakeEnv(t)
		e.seedForeignRecord(t)
		const sentinel = "testpass123"
		e.target.rejectSessionMsg = "pam: " + sentinel + " rejected"
		logs := captureHostKeyLog(t)
		msgs := e.redeemWS(t, 2)
		if len(msgs) != 1 || msgs[0].Type != MsgError {
			t.Fatalf("session channel 被拒應收到 error: %+v", msgs)
		}
		for _, m := range msgs {
			if strings.Contains(m.Data, sentinel) || strings.Contains(m.Code, sentinel) {
				t.Fatalf("WS 回應洩漏密碼: %+v", m)
			}
		}
		if strings.Contains(logs.String(), sentinel) {
			t.Fatalf("後端日誌洩漏密碼:\n%s", logs.String())
		}
		var all []model.AuditLog
		e.db.Find(&all)
		for _, a := range all {
			if strings.Contains(a.Details, sentinel) || strings.Contains(a.ErrorMsg, sentinel) {
				t.Fatalf("審計列洩漏密碼: %+v", a)
			}
		}
	})

	t.Run("留痕失敗：RULE_SSH_HOST_KEY_CHECK_FAILED 且靶機認證嘗試 0", func(t *testing.T) {
		e := newHandshakeEnv(t)
		e.seedForeignRecord(t)
		e.hostKeys.SetAuditTxSink(handshakeFailingTxSink{err: errors.New("audit down")})
		msgs := e.redeemWS(t, 2)
		if len(msgs) != 1 || msgs[0].Type != MsgError || msgs[0].Code != string(apierror.CodeSSHHostKeyCheckFailed) {
			t.Fatalf("應收到 RULE_SSH_HOST_KEY_CHECK_FAILED 的 error 後關閉: %+v", msgs)
		}
		if n := e.target.authAttempts.Load(); n != 0 {
			t.Fatalf("留痕失敗時憑證不得送出，靶機收到 %d 次認證", n)
		}
		if len(e.alerts.events) != 0 || len(e.mismatchAudits(t)) != 0 {
			t.Fatal("留痕失敗時審計與告警皆應回滾")
		}
	})

	t.Run("記錄讀取失敗映射為查核失敗而非不可達", func(t *testing.T) {
		e := newHandshakeEnv(t)
		if err := e.db.Migrator().DropTable(&model.AssetHostKey{}); err != nil {
			t.Fatal(err)
		}
		msgs := e.redeemWS(t, 2)
		if len(msgs) != 1 || msgs[0].Type != MsgError {
			t.Fatalf("應收到 error: %+v", msgs)
		}
		if msgs[0].Code == string(apierror.CodeSSHUnreachable) {
			t.Fatal("記錄讀取失敗不得映射為 RULE_SSH_UNREACHABLE")
		}
		if msgs[0].Code != string(apierror.CodeSSHHostKeyCheckFailed) {
			t.Fatalf("應為 RULE_SSH_HOST_KEY_CHECK_FAILED，實得 %s", msgs[0].Code)
		}
		if n := e.target.authAttempts.Load(); n != 0 {
			t.Fatalf("查核失敗時憑證不得送出，靶機收到 %d 次認證", n)
		}
	})
}
