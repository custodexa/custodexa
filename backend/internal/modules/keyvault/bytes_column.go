package keyvault

import (
	"context"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
)

var _ material.BytesColumnCodec = (*KeyManagerService)(nil)

// EncryptBytesFor borrows plaintext without making an immutable secret copy.
func (s *KeyManagerService) EncryptBytesFor(_ context.Context, ref crypto.CipherRef, plaintext []byte) (string, error) {
	return vaultUse(&s.materialGate, func() (string, error) { return s.encryptBytes(ref, plaintext) }, nil)
}
func (s *KeyManagerService) encryptBytes(ref crypto.CipherRef, plaintext []byte) (string, error) {
	if len(plaintext) == 0 {
		return "", nil
	}
	if !ref.Valid() {
		return "", fmt.Errorf("%w（table=%q column=%q）", ErrCipherRefIncomplete, ref.Table, ref.Column)
	}
	// **版本先鎖定，材料後取得**：鎖定之後不論走快取或到期重解，都只認這個版本。
	// 重解回來若發現 active 已被輪替，該次操作仍以已鎖定的版本完成——半途改綁
	// 會讓同一批寫入落成兩種版本的密文
	s.mu.RLock()
	ver := s.active[model.DataKeyPurposeData]
	s.mu.RUnlock()
	c, release, err := s.acquireDataCipher(ver)
	if err != nil {
		return "", err
	}
	if c == nil {
		return "", errors.New("data DEK 未初始化")
	}
	defer release()
	raw, err := c.EncryptBytesAAD(plaintext, ref.AAD())
	if err != nil {
		return "", err
	}
	return crypto.EncodeEnvelopeAAD(crypto.AADSchemeA1, ver, raw)
}

// DecryptBytesFor transfers plaintext ownership without using the string adapter.
func (s *KeyManagerService) DecryptBytesFor(_ context.Context, ref crypto.CipherRef, ciphertext string) (*material.Secret, error) {
	return vaultUse(&s.materialGate, func() (*material.Secret, error) { return material.AdoptResult(s.decryptBytesWith(ciphertext, ref)) }, func(p *material.Secret) { p.Destroy() })
}

// decryptBytesWith is the shared format, AAD, and cipher-selection core.
func (s *KeyManagerService) decryptBytesWith(ciphertext string, ref crypto.CipherRef) ([]byte, error) {
	return vaultUse(&s.materialGate, func() ([]byte, error) { return s.decryptBytes(ciphertext, ref) }, wipePlain)
}
func (s *KeyManagerService) decryptBytes(ciphertext string, ref crypto.CipherRef) ([]byte, error) {
	if ciphertext == "" {
		return nil, nil
	}
	scheme, ver, raw, ok, err := crypto.ParseEnvelopeFull(ciphertext)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w（無前綴值）", ErrNonFinalCiphertext)
	}
	if scheme == crypto.AADSchemeNone {
		return nil, fmt.Errorf("%w（無 AAD 綁定的 enc:v 值）", ErrNonFinalCiphertext)
	}
	if scheme == crypto.AADSchemeA1 && !ref.Valid() {
		return nil, fmt.Errorf("%w（帶 AAD 密文須經 DecryptFor 解密）", ErrCipherRefIncomplete)
	}
	// 解密路徑的版本來自密文自身：要解的可能是歷史版本，快取以版本為鍵逐版計時
	c, release, err := s.acquireDataCipher(ver)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, fmt.Errorf("密文引用不存在的 data DEK v%d", ver)
	}
	defer release()
	var aad []byte
	if scheme == crypto.AADSchemeA1 {
		aad = ref.AAD()
	}
	plain, err := c.DecryptBytesAAD(raw, aad)
	if err != nil {
		material.Wipe(plain)
		return nil, err
	}
	return plain, nil
}
