package asset

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/branding"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
)

// 堡壘機專用帳號的公鑰：讀取回應只帶 has_public_key／fingerprint，公鑰本體只能經匯出取得，
// 每次匯出留一筆讀取審計。
//
// 可見性：專用憑證隨資產範圍可見；共用憑證依主體的憑證可見集合判定。範圍外的共用憑證不給指紋也不給匯出：
// 同一把共用金鑰在每台的指紋相同，範圍化主體拿多台一比就能推出哪些資產共用同一把範圍外的金鑰。
// 非金鑰型、沒有公鑰、不可見三者對外同形。

// ExecutorCredentialVisibility 共用憑證是否在主體的憑證可見集合內（消費者側窄介面）。
type ExecutorCredentialVisibility interface {
	SharedCredentialVisible(ctx context.Context, credentialID uint) (bool, error)
}

// WithCredentialVisibility 注入共用憑證可見性判定（組裝時）。未注入時共用憑證一律視為不可見（fail-close）。
func (s *AssetExecutorService) WithCredentialVisibility(v ExecutorCredentialVisibility) *AssetExecutorService {
	s.credVisibility = v
	return s
}

// executorPublicKey 執行身分可對該主體揭露的公鑰（type＋base64）；不可揭露回 ("", nil)。
func (s *AssetExecutorService) executorPublicKey(ctx context.Context, db *gorm.DB, exec *model.AssetAccount) (string, error) {
	if exec == nil || exec.EffectiveVersionID == nil {
		return "", nil
	}
	var cred model.Credential
	if err := db.Select("id", "scope", "secret_type").Where("id = ?", exec.CredentialID).First(&cred).Error; err != nil {
		return "", fmt.Errorf("查詢執行身分憑證失敗: %w", err)
	}
	if cred.SecretType != model.ChangeSecretTypeSSHKey {
		return "", nil
	}
	if cred.Scope == model.CredentialScopeShared && !isSystemCaller(ctx) {
		if s.credVisibility == nil {
			return "", nil
		}
		visible, err := s.credVisibility.SharedCredentialVisible(ctx, cred.ID)
		if err != nil {
			return "", err
		}
		if !visible {
			return "", nil
		}
	}
	var version model.CredentialSecretVersion
	if err := db.Select("id", "public_key").Where("id = ?", *exec.EffectiveVersionID).First(&version).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", nil
		}
		return "", fmt.Errorf("查詢執行身分版本失敗: %w", err)
	}
	fields := strings.Fields(version.PublicKey)
	if len(fields) < 2 {
		return "", nil
	}
	return fields[0] + " " + fields[1], nil
}

// fillPublicKeyView 讀取回應補上 has_public_key 與 fingerprint（只在可揭露時出現）。
func (s *AssetExecutorService) fillPublicKeyView(ctx context.Context, dto *AssetExecutorDTO, exec *model.AssetAccount) error {
	key, err := s.executorPublicKey(ctx, database.DB, exec)
	if err != nil || key == "" {
		return err
	}
	pub, _, _, _, perr := ssh.ParseAuthorizedKey([]byte(key))
	if perr != nil {
		return nil
	}
	has := true
	dto.HasPublicKey = &has
	dto.Fingerprint = ssh.FingerprintSHA256(pub)
	return nil
}

// ExportPublicKey 匯出 authorized_keys 單行（comment＝<slug>-credential-<id>，不帶資產識別），同交易寫讀取審計。
func (s *AssetExecutorService) ExportPublicKey(ctx context.Context, assetID uint) (string, error) {
	if _, err := s.accounts.assets.GetByID(assetID); err != nil {
		return "", err
	}
	if err := s.authorize(ctx, database.DB, assetID); err != nil {
		return "", err
	}
	userID, operator := model.UserFromContext(ctx)
	var line string
	err := database.DB.Transaction(func(tx *gorm.DB) error {
		exec, err := findExecutor(tx, assetID)
		if err != nil {
			return err
		}
		key, err := s.executorPublicKey(ctx, tx, exec)
		if err != nil {
			return err
		}
		if key == "" {
			return ErrAssetExecutorPublicKeyNotFound
		}
		line = fmt.Sprintf("%s %s-credential-%d", key, branding.Slug, exec.CredentialID)
		credID, credScope := credentialAuditRef(tx, exec.CredentialID)
		return writeAssetAccountAudit(s.accounts.auditTx, tx, model.AssetAccountAudit{
			AssetID:         assetID,
			AccountID:       exec.ID,
			Username:        exec.Username,
			Operation:       model.AccountOpExecutorPublicKeyExport,
			CredentialID:    credID,
			CredentialScope: credScope,
		}, userID, operator)
	})
	if err != nil {
		return "", err
	}
	return line, nil
}
