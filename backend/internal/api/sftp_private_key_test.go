package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupSFTPPrivateKeyEnv 真 sqlite、真資產服務與 SFTP service：資產帳號的就位版本
// 放入指定的私鑰明文（直寫密文，模擬寫入驗證上線前已在庫的壞私鑰）。
// 目標位址指向一個剛釋放的埠：若解析失敗沒被攔下而真的撥號，會得到連線被拒
// 並落入動作失敗碼，測試因此能分辨。
func setupSFTPPrivateKeyEnv(t *testing.T, privateKey string) (*session.SFTPService, uint) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql db: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.Asset{}, &model.AssetGroup{}, &model.AssetNode{}, &model.AssetAccount{},
		&model.Credential{}, &model.CredentialSecretVersion{}, &model.AssetHostKey{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	ln.Close()

	codec := aesColumnCodec(t, make([]byte, 32))
	assetSvc, err := asset.NewAssetService(codec, "localhost", 4822, audit.NewTxSink())
	if err != nil {
		t.Fatalf("asset service: %v", err)
	}

	row := model.Asset{Name: "sftp-pk", Protocol: model.ProtocolSSH, Host: "127.0.0.1", Port: port, CreatedBy: 1, Active: true}
	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	enc, err := codec.EncryptFor(context.Background(), keyvault.RefCredentialVersionPrivateKey, privateKey)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	cred := model.Credential{Scope: model.CredentialScopeDedicated, Username: "root",
		SecretType: model.ChangeSecretTypeSSHKey, ProtocolFamily: model.ProtocolFamilySSH}
	if err := db.Create(&cred).Error; err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	ver := model.CredentialSecretVersion{CredentialID: cred.ID, VersionNo: 1, SecretType: model.ChangeSecretTypeSSHKey,
		PrivateKeyEnc: enc, CreatedReason: model.CredentialVersionReasonManual}
	if err := db.Create(&ver).Error; err != nil {
		t.Fatalf("seed version: %v", err)
	}
	if err := db.Model(&cred).Update("current_version_id", ver.ID).Error; err != nil {
		t.Fatalf("seed current version: %v", err)
	}
	if err := db.Create(&model.AssetAccount{AssetID: row.ID, Username: "root", IsDefault: true,
		CredentialID: cred.ID, EffectiveVersionID: &ver.ID}).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}
	return session.NewSFTPService(assetSvc, asset.NewHostKeyService(db)), row.ID
}

// TestSFTPUnparsablePrivateKeyReturnsDedicatedCode 經 SFTP service 真路徑（dialSFTP）
// 到 respondSFTPError 出口：格式錯誤與受 passphrase 保護的私鑰皆回 400 與
// RULE_SSH_PRIVATE_KEY_INVALID，回應不帶解析原文。
func TestSFTPUnparsablePrivateKeyReturnsDedicatedCode(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "sftp", []byte("secret-phrase"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	cases := map[string]string{
		"Malformed":  "-----BEGIN OPENSSH PRIVATE KEY-----\nbroken\n",
		"Passphrase": string(pem.EncodeToMemory(block)),
	}
	for name, key := range cases {
		t.Run(name, func(t *testing.T) {
			svc, assetID := setupSFTPPrivateKeyEnv(t, key)
			_, listErr := svc.List(assetID, 0, "/tmp")
			if listErr == nil {
				t.Fatal("壞私鑰不得列目錄成功")
			}

			gin.SetMode(gin.TestMode)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", "/assets/1/files", nil)
			respondSFTPError(c, listErr, apierror.CodeInternalSFTPListFailed)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("狀態碼 = %d，預期 400；body=%s", w.Code, w.Body.String())
			}
			var resp map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("回應非 JSON: %v", err)
			}
			if resp["code"] != string(apierror.CodeSSHPrivateKeyInvalid) {
				t.Fatalf("code = %v，預期 %s", resp["code"], apierror.CodeSSHPrivateKeyInvalid)
			}
			if body := w.Body.String(); strings.Contains(body, "ssh:") {
				t.Fatalf("回應洩漏解析原文: %s", body)
			}
		})
	}
}
