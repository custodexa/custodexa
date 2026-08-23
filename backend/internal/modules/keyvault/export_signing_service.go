package keyvault

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// ExportSigningService 匯出 manifest 的 Ed25519 簽章（
// PCI 10.3.4）。選 Ed25519 而非 HMAC：
// 驗證者（QSA）在組織外，公鑰可分發離線驗證，共享密鑰不可行
type ExportSigningService struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// NewExportSigningService 載入或首次生成簽章金鑰：
// DB 無列 → 生成 Ed25519 金鑰對，私鑰加密落 DB；有列 → 解密載入。
// codec 為信封 key manager。
//
// **ColumnCodec**：新生成的
// 私鑰一律以 RefExportSigningPrivateKey 綁定 AAD 寫出 `enc:a1`——介面上沒有
// Encrypt(plaintext)，建構上不可能寫出無 AAD 密文；既有 enc:v／legacy 密文
// 由 DecryptFor 依前綴分派解密（strict 未啟用時）
func NewExportSigningService(db *gorm.DB, codec crypto.ColumnCodec) (*ExportSigningService, error) {
	ctx := context.Background()
	var row model.ExportSigningKey
	switch err := db.First(&row, 1).Error; {
	case err == nil:
		privRaw, err := codec.DecryptFor(ctx, RefExportSigningPrivateKey, row.PrivateKeyEnc)
		if err != nil {
			return nil, fmt.Errorf("解密簽章私鑰失敗（加密金鑰變更後既有金鑰不可用）: %w", err)
		}
		priv, err := base64.StdEncoding.DecodeString(privRaw)
		if err != nil || len(priv) != ed25519.PrivateKeySize {
			return nil, errors.New("簽章私鑰格式損毀")
		}
		key := ed25519.PrivateKey(priv)
		return &ExportSigningService{priv: key, pub: key.Public().(ed25519.PublicKey)}, nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		// 首啟生成
	default:
		return nil, fmt.Errorf("讀取簽章金鑰失敗: %w", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成簽章金鑰失敗: %w", err)
	}
	privEnc, err := codec.EncryptFor(ctx, RefExportSigningPrivateKey,
		base64.StdEncoding.EncodeToString(priv))
	if err != nil {
		return nil, fmt.Errorf("加密簽章私鑰失敗: %w", err)
	}
	row = model.ExportSigningKey{
		ID: 1, PrivateKeyEnc: privEnc,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
	if err := db.Create(&row).Error; err != nil {
		return nil, fmt.Errorf("寫入簽章金鑰失敗: %w", err)
	}
	log.Printf("[ExportSigning] 已生成匯出簽章金鑰（Ed25519，公鑰 %s...）", row.PublicKey[:12])
	return &ExportSigningService{priv: priv, pub: pub}, nil
}

// Sign 簽 manifest bytes，回 base64 簽章
func (s *ExportSigningService) Sign(data []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, data))
}

// PublicKeyBase64 公鑰（base64，供下載端點與離線驗證）
func (s *ExportSigningService) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(s.pub)
}

// VerifySignature 驗證（測試與文檔範例用；實務驗證者以公鑰離線驗）
func (s *ExportSigningService) VerifySignature(data []byte, sigBase64 string) bool {
	sig, err := base64.StdEncoding.DecodeString(sigBase64)
	if err != nil {
		return false
	}
	return ed25519.Verify(s.pub, data, sig)
}
