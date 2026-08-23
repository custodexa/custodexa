package keyvault

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// ErrCheckpointSigningKeyVersionUnknown 取用不存在的鑰版本。
//
// **必須是明確錯誤而非靜默略過**：驗證端遇到「檢查點宣稱以 v2 簽章但庫內無 v2」
// 時，唯一誠實的結論是 signature_invalid——回一個「驗不了所以算過」等於為
// 「改版本號使簽章免驗」開後門
var ErrCheckpointSigningKeyVersionUnknown = errors.New("檢查點簽章鑰版本不存在：以該版本簽的檢查點不可驗")

// CheckpointSigningService 檢查點鏈的 Ed25519 簽章鑰服務（audit-checkpoint-chain）。
//
// 與 ExportSigningService 的差異（刻意）：
//   - **自始帶版本**：多版本並存於記憶體，依 version 取鑰；檢查點記錄其簽章版本，
//     使日後新增輪替不需資料遷移，也使歷史檢查點在輪替後仍可驗。
//   - **私鑰無任何出口**：本型別不提供匯出私鑰的方法，資料表無刪除路徑，
//     model 掛 BeforeUpdate／BeforeDelete 全拒守衛。
//
// 載入或生成失敗一律回錯（呼叫端 fail-close 拒絕啟動）：帶病啟動會產生一批
// 無法驗證的檢查點，而檢查點的全部價值就在「可驗」。
type CheckpointSigningService struct {
	// keys 版本→私鑰（公鑰由私鑰導出）
	keys map[int]ed25519.PrivateKey
	// activeVersion 現行簽章版本
	activeVersion int
}

// NewCheckpointSigningService 載入全部版本的簽章鑰；庫內無列時生成 v1（active）。
//
// codec 為信封 ColumnCodec：私鑰以 RefCheckpointSigningPrivateKey 綁定 AAD 寫出
// `enc:a1`——介面上沒有 Encrypt(plaintext)，建構上不可能寫出無 AAD 密文。
func NewCheckpointSigningService(db *gorm.DB, codec crypto.ColumnCodec) (*CheckpointSigningService, error) {
	ctx := context.Background()

	var rows []model.CheckpointSigningKey
	if err := db.Order("version ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("讀取檢查點簽章鑰失敗: %w", err)
	}

	if len(rows) == 0 {
		return generateCheckpointSigningKey(ctx, db, codec)
	}

	svc := &CheckpointSigningService{keys: map[int]ed25519.PrivateKey{}}
	for _, row := range rows {
		privRaw, err := codec.DecryptFor(ctx, RefCheckpointSigningPrivateKey, row.PrivateKeyEnc)
		if err != nil {
			return nil, fmt.Errorf("解密檢查點簽章私鑰 v%d 失敗（KEK 變更或密文損毀；"+
				"以此鑰簽的歷史檢查點將不可驗，拒絕帶病啟動）: %w", row.Version, err)
		}
		priv, err := base64.StdEncoding.DecodeString(privRaw)
		if err != nil || len(priv) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("檢查點簽章私鑰 v%d 格式損毀", row.Version)
		}
		key := ed25519.PrivateKey(priv)
		// 公鑰欄與私鑰必須自洽：不符表示有人單改公鑰欄想讓偽造簽章驗過
		if want := base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)); want != row.PublicKey {
			return nil, fmt.Errorf("檢查點簽章鑰 v%d 的公鑰欄與私鑰不符（疑遭竄改）", row.Version)
		}
		svc.keys[row.Version] = key
		if row.Active {
			svc.activeVersion = row.Version
		}
	}
	if svc.activeVersion == 0 {
		return nil, errors.New("檢查點簽章鑰無 active 版本：無從決定以哪把鑰封章，拒絕啟動")
	}
	log.Printf("[CheckpointSigning] 已載入檢查點簽章鑰 %d 個版本（active v%d）",
		len(svc.keys), svc.activeVersion)
	return svc, nil
}

// generateCheckpointSigningKey 首啟生成 v1（active）
func generateCheckpointSigningKey(ctx context.Context, db *gorm.DB, codec crypto.ColumnCodec) (*CheckpointSigningService, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成檢查點簽章鑰失敗: %w", err)
	}
	privEnc, err := codec.EncryptFor(ctx, RefCheckpointSigningPrivateKey,
		base64.StdEncoding.EncodeToString(priv))
	if err != nil {
		return nil, fmt.Errorf("加密檢查點簽章私鑰失敗: %w", err)
	}
	row := model.CheckpointSigningKey{
		Version:       1,
		Active:        true,
		PublicKey:     base64.StdEncoding.EncodeToString(pub),
		PrivateKeyEnc: privEnc,
	}
	if err := db.Create(&row).Error; err != nil {
		return nil, fmt.Errorf("寫入檢查點簽章鑰失敗: %w", err)
	}
	log.Printf("[CheckpointSigning] 已生成檢查點簽章鑰 v1（Ed25519，公鑰 %s...）", row.PublicKey[:12])
	return &CheckpointSigningService{
		keys:          map[int]ed25519.PrivateKey{1: priv},
		activeVersion: 1,
	}, nil
}

// ActiveVersion 現行簽章鑰版本（封章時記入檢查點）
func (s *CheckpointSigningService) ActiveVersion() int { return s.activeVersion }

// Sign 以現行鑰簽，回 (版本, base64 簽章)
func (s *CheckpointSigningService) Sign(data []byte) (int, string) {
	priv := s.keys[s.activeVersion]
	return s.activeVersion, base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data))
}

// PublicKeyBase64 指定版本的公鑰（base64）；版本不存在回錯，不回空值
func (s *CheckpointSigningService) PublicKeyBase64(version int) (string, error) {
	priv, ok := s.keys[version]
	if !ok {
		return "", fmt.Errorf("%w: v%d", ErrCheckpointSigningKeyVersionUnknown, version)
	}
	return base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)), nil
}

// ActivePublicKeyBase64 現行鑰公鑰（公鑰端點與金鑰清冊的同源出口）
func (s *CheckpointSigningService) ActivePublicKeyBase64() string {
	pub, _ := s.PublicKeyBase64(s.activeVersion)
	return pub
}

// PublicKeyFingerprint 公鑰指紋 hex(SHA-256(公鑰原始位元組)[:8])，沿金鑰清冊既有演算法
func (s *CheckpointSigningService) PublicKeyFingerprint(version int) (string, error) {
	pubB64, err := s.PublicKeyBase64(version)
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:8]), nil
}

// Verify 以指定版本的公鑰驗章；版本不存在回錯（呼叫端計為 signature_invalid）
func (s *CheckpointSigningService) Verify(version int, data []byte, sigBase64 string) (bool, error) {
	pubB64, err := s.PublicKeyBase64(version)
	if err != nil {
		return false, err
	}
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		return false, err
	}
	sig, err := base64.StdEncoding.DecodeString(sigBase64)
	if err != nil {
		return false, nil
	}
	return ed25519.Verify(ed25519.PublicKey(pub), data, sig), nil
}
