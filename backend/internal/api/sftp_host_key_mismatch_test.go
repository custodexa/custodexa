package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/modules/session"
)

// sftpTarget 行程內 SSH 靶機：密碼認證＋ sftp 子系統，記錄認證嘗試次數
type sftpTarget struct {
	host      string
	port      int
	hostKey   ssh.PublicKey
	authCalls atomic.Int32
	// rejectSessionMsg 非空時：認證後對 session channel 開啟以此訊息拒絕（模擬冒充主機回填密碼）
	rejectSessionMsg string
}

func startSFTPTarget(t *testing.T, username, password string) *sftpTarget {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	tg := &sftpTarget{hostKey: signer.PublicKey()}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			tg.authCalls.Add(1)
			if c.User() == username && string(pass) == password {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("bad password")
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	home := t.TempDir()
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sconn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
				if err != nil {
					nc.Close()
					return
				}
				defer sconn.Close()
				go ssh.DiscardRequests(reqs)
				for newCh := range chans {
					if tg.rejectSessionMsg != "" {
						_ = newCh.Reject(ssh.Prohibited, tg.rejectSessionMsg)
						continue
					}
					if newCh.ChannelType() != "session" {
						_ = newCh.Reject(ssh.UnknownChannelType, "only session")
						continue
					}
					ch, chReqs, err := newCh.Accept()
					if err != nil {
						return
					}
					go func() {
						for req := range chReqs {
							if req.Type == "subsystem" && len(req.Payload) >= 4 && string(req.Payload[4:]) == "sftp" {
								_ = req.Reply(true, nil)
								srv, err := sftp.NewServer(ch, sftp.WithServerWorkingDirectory(home))
								if err == nil {
									_ = srv.Serve()
								}
								ch.Close()
								return
							}
							_ = req.Reply(false, nil)
						}
					}()
				}
			}()
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	tg.host = host
	tg.port, _ = strconv.Atoi(portStr)
	return tg
}

type sftpHostKeyEnv struct {
	db       *gorm.DB
	handler  *SFTPHandler
	svc      *session.SFTPService
	hostKeys *asset.HostKeyService
	alerts   *hkAlertSink
	target   *sftpTarget
	assetID  uint
	homeDir  string
}

// setupSFTPHostKeyEnv 真 sqlite、真資產服務、真 SFTP service 與 handler；user 1 持 asset 的常設 connect
func setupSFTPHostKeyEnv(t *testing.T) *sftpHostKeyEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := migrateWithAuthz(db, &model.User{}, &model.UserGroup{}, &model.Asset{}, &model.AssetGroup{}, &model.AssetNode{},
		&model.AssetAccount{}, &model.Credential{}, &model.CredentialSecretVersion{}, &model.AssetAuthorization{}, &model.ApproverScope{},
		&model.Session{}, &model.AuditLog{}, &model.AssetHostKey{}, &model.AssetHostKeyMismatch{}, &model.Role{}, &model.UserRole{},
		&model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{}); err != nil {
		t.Fatal(err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	target := startSFTPTarget(t, "root", "pw-123")
	db.Create(&model.User{Username: "u1", Email: emailPtr("u@x"), Active: true})
	row := model.Asset{Name: "a1", Protocol: model.ProtocolSSH, Host: target.host, Port: target.port, CreatedBy: 1, Active: true}
	if err := db.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	codec := aesColumnCodec(t, make([]byte, 32))
	enc, err := codec.EncryptFor(context.Background(), keyvault.RefCredentialVersionPassword, "pw-123")
	if err != nil {
		t.Fatal(err)
	}
	cred := model.Credential{Scope: model.CredentialScopeDedicated, Username: "root",
		SecretType: model.ChangeSecretTypePassword, ProtocolFamily: model.ProtocolFamilySSH}
	if err := db.Create(&cred).Error; err != nil {
		t.Fatal(err)
	}
	ver := model.CredentialSecretVersion{CredentialID: cred.ID, VersionNo: 1, SecretType: model.ChangeSecretTypePassword,
		PasswordEnc: enc, CreatedReason: model.CredentialVersionReasonManual}
	if err := db.Create(&ver).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.AssetAccount{AssetID: row.ID, Username: "root", IsDefault: true,
		CredentialID: cred.ID, EffectiveVersionID: &ver.ID}).Error; err != nil {
		t.Fatal(err)
	}
	uid, aid := uint(1), row.ID
	if err := db.Create(&model.AssetAuthorization{UserID: &uid, AssetID: &aid, Permission: model.PermissionConnect, GrantedBy: 1}).Error; err != nil {
		t.Fatal(err)
	}
	assetSvc, err := asset.NewAssetService(codec, "localhost", 4822, audit.NewTxSink())
	assetSvc.SetTopologyPermissionPort(noopTopologyPort{})
	if err != nil {
		t.Fatal(err)
	}
	hostKeys := asset.NewHostKeyService(db)
	alerts := &hkAlertSink{}
	hostKeys.SetAuditTxSink(audit.NewTxSink())
	hostKeys.SetSystemAlertSink(alerts)
	svc := session.NewSFTPService(assetSvc, hostKeys)
	auditSvc := audit.NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false})
	handler := NewSFTPHandler(svc, authz.NewAssetAuthorizationService(db), auditSvc, newSFTPTestAuthService(t, db))
	return &sftpHostKeyEnv{db: db, handler: handler, svc: svc, hostKeys: hostKeys, alerts: alerts, target: target, assetID: row.ID}
}

// seedForeignHostKey 為資產寫入一筆與靶機不同的記錄（同撥號位址），使下一次 SFTP 撥號判為不符
func (e *sftpHostKeyEnv) seedForeignHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	foreign := hkKey(t)
	if err := e.db.Create(&model.AssetHostKey{
		AssetID: e.assetID, Algorithm: foreign.Type(), Fingerprint: ssh.FingerprintSHA256(foreign),
		PublicKey: base64.StdEncoding.EncodeToString(foreign.Marshal()), Host: e.target.host, Port: e.target.port,
	}).Error; err != nil {
		t.Fatal(err)
	}
	return foreign
}

func (e *sftpHostKeyEnv) call(method, path, query string, body ...string) *httptest.ResponseRecorder {
	r := gin.New()
	handle := func(c *gin.Context) {
		c.Set("userID", uint(1))
		c.Set("username", "u1")
		middleware.SetPrincipal(c, legacyPrincipal(model.RoleUser))
		switch method {
		case "GET":
			e.handler.List(c)
		case "POST":
			e.handler.Mkdir(c)
		}
	}
	r.GET("/assets/:id/files", handle)
	r.POST("/assets/:id/files/mkdir", handle)
	var payload io.Reader
	if len(body) > 0 {
		payload = strings.NewReader(body[0])
	}
	req := httptest.NewRequest(method, path+query, payload)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func (e *sftpHostKeyEnv) mismatchAudits(t *testing.T) []map[string]any {
	t.Helper()
	var rows []model.AuditLog
	if err := e.db.Where("action = ?", string(model.ActionHostKeyMismatch)).Order("id").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		var d map[string]any
		_ = json.Unmarshal([]byte(r.Details), &d)
		d["_user_id"] = r.UserID
		d["_username"] = r.Username
		out = append(out, d)
	}
	return out
}

// TestSFTPHostKeyMismatch 檔案傳輸屬互動路徑：不符時列目錄 200 且帶 host_key_mismatch 旗標、上傳類操作不帶旗標但各寫審計
// （處置為放行）；帶 session_id 時審計連線識別為該會話主鍵、不帶時為空；查核失敗回 502 與 RULE_SSH_HOST_KEY_CHECK_FAILED。
func TestSFTPHostKeyMismatch(t *testing.T) {
	t.Run("列目錄帶旗標、審計與告警同流程留下", func(t *testing.T) {
		e := setupSFTPHostKeyEnv(t)
		foreign := e.seedForeignHostKey(t)
		w := e.call("GET", fmt.Sprintf("/assets/%d/files", e.assetID), "?path=/")
		if w.Code != http.StatusOK {
			t.Fatalf("列目錄應 200: %d %s", w.Code, w.Body.String())
		}
		var body map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if body["host_key_mismatch"] != true {
			t.Fatalf("不符時列目錄回應應帶 host_key_mismatch: true，實得 %s", w.Body.String())
		}
		if e.target.authCalls.Load() == 0 {
			t.Fatal("互動路徑放行後應已送出憑證（靶機收到認證）")
		}
		audits := e.mismatchAudits(t)
		if len(audits) != 1 {
			t.Fatalf("不符審計應 1 筆，實有 %d", len(audits))
		}
		d := audits[0]
		if d["path"] != "file_transfer" || d["outcome"] != "allowed" || d["recorded_fingerprint"] != ssh.FingerprintSHA256(foreign) ||
			d["observed_fingerprint"] != ssh.FingerprintSHA256(e.target.hostKey) || d["_user_id"] != uint(1) || d["_username"] != "u1" {
			t.Fatalf("審計 details 不符: %v", d)
		}
		if _, has := d["connection_ref"]; has {
			t.Fatalf("獨立入口（不帶 session_id）的連線識別應為空: %v", d)
		}
		if len(e.alerts.events) != 1 || e.alerts.events[0].Type != port.SystemAlertHostKeyMismatch ||
			e.alerts.events[0].Params["path"] != "file_transfer" || e.alerts.events[0].Params["outcome"] != "allowed" {
			t.Fatalf("應有一則 host_key_mismatch（file_transfer／allowed）告警: %+v", e.alerts.events)
		}
		if d["credentials"] != "about_to_be_sent" {
			t.Fatalf("放行審計應明示憑證即將送出: %v", d)
		}
		var sent []model.AuditLog
		e.db.Where("action = ?", string(model.ActionHostKeyCredSent)).Find(&sent)
		if len(sent) != 1 {
			t.Fatalf("認證完成後應補記憑證已送出 1 筆，實有 %d", len(sent))
		}
		var sd map[string]any
		_ = json.Unmarshal([]byte(sent[0].Details), &sd)
		if sd["auth_result"] != "succeeded" || sd["correlation_id"] != d["correlation_id"] || sd["path"] != "file_transfer" {
			t.Fatalf("host_key_cred_sent details 不符: %v", sd)
		}
		// 相符時不帶旗標：採用靶機金鑰後再列目錄
		if _, err := e.hostKeys.Adopt(e.assetID, ssh.FingerprintSHA256(e.target.hostKey), asset.HostKeyActor{UserID: 1, Username: "u1"}); err != nil {
			t.Fatal(err)
		}
		w = e.call("GET", fmt.Sprintf("/assets/%d/files", e.assetID), "?path=/")
		if w.Code != http.StatusOK {
			t.Fatalf("採用後列目錄應 200: %d %s", w.Code, w.Body.String())
		}
		body = nil
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if _, has := body["host_key_mismatch"]; has {
			t.Fatalf("相符時不得帶旗標: %s", w.Body.String())
		}
	})

	t.Run("帶 session_id 時連線識別為會話主鍵；建目錄不帶旗標但寫審計", func(t *testing.T) {
		e := setupSFTPHostKeyEnv(t)
		e.seedForeignHostKey(t)
		aid := e.assetID
		sess := model.Session{UserID: 1, AssetID: &aid, AccountID: 1, AccountUsername: "root", Protocol: model.ProtocolSSH, Status: model.SessionStatusClosed}
		if err := e.db.Create(&sess).Error; err != nil {
			t.Fatal(err)
		}
		// 會話的帳號主鍵須指向預設帳號（AccountForSession 現查）
		var acct model.AssetAccount
		e.db.Where("asset_id = ?", e.assetID).First(&acct)
		e.db.Model(&sess).Update("account_id", acct.ID)
		w := e.call("POST", fmt.Sprintf("/assets/%d/files/mkdir", e.assetID), fmt.Sprintf("?session_id=%d", sess.ID),
			fmt.Sprintf(`{"path":"/tmp/hk-%d-%d"}`, sess.ID, time.Now().UnixNano()))
		if w.Code != http.StatusOK {
			t.Fatalf("建目錄應 200: %d %s", w.Code, w.Body.String())
		}
		var body map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if _, has := body["host_key_mismatch"]; has {
			t.Fatalf("非列目錄操作不帶旗標: %s", w.Body.String())
		}
		audits := e.mismatchAudits(t)
		if len(audits) != 1 || audits[0]["connection_ref"] != strconv.FormatUint(uint64(sess.ID), 10) || audits[0]["outcome"] != "allowed" {
			t.Fatalf("帶 session_id 的審計連線識別應為會話主鍵: %v", audits)
		}
	})

	t.Run("查核失敗：502 與 RULE_SSH_HOST_KEY_CHECK_FAILED，憑證未送出", func(t *testing.T) {
		e := setupSFTPHostKeyEnv(t)
		e.seedForeignHostKey(t)
		e.hostKeys.SetAuditTxSink(hkFailingTxSink{err: errors.New("audit down")})
		w := e.call("GET", fmt.Sprintf("/assets/%d/files", e.assetID), "?path=/")
		if w.Code != http.StatusBadGateway {
			t.Fatalf("查核失敗應 502: %d %s", w.Code, w.Body.String())
		}
		var body map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if body["code"] != "RULE_SSH_HOST_KEY_CHECK_FAILED" {
			t.Fatalf("code 應為 RULE_SSH_HOST_KEY_CHECK_FAILED: %s", w.Body.String())
		}
		if e.target.authCalls.Load() != 0 {
			t.Fatal("查核失敗時不得送出憑證")
		}
		if len(e.alerts.events) != 0 || len(e.mismatchAudits(t)) != 0 {
			t.Fatal("查核失敗時審計與告警皆不得留下")
		}
	})

	t.Run("冒充主機把密碼塞進 channel reject：日誌、回應與審計都不含密碼", func(t *testing.T) {
		e := setupSFTPHostKeyEnv(t)
		e.seedForeignHostKey(t)
		const sentinel = "pw-123"
		e.target.rejectSessionMsg = "pam: " + sentinel + " rejected"
		var logs bytes.Buffer
		prev := log.Writer()
		log.SetOutput(&logs)
		t.Cleanup(func() { log.SetOutput(prev) })
		w := e.call("GET", fmt.Sprintf("/assets/%d/files", e.assetID), "?path=/")
		if w.Code != http.StatusBadGateway {
			t.Fatalf("channel 被拒應 502: %d %s", w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), sentinel) {
			t.Fatalf("回應洩漏密碼: %s", w.Body.String())
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
		if e.target.authCalls.Load() == 0 {
			t.Fatal("前提：靶機應收到認證（密碼已送出）")
		}
	})
}
