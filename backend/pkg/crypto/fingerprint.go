package crypto

import (
	"crypto/sha256"
	"encoding/hex"
)

// Fingerprint 通用金鑰指紋：對原始位元組取 SHA-256 前 8 bytes 的小寫 hex（64-bit）。
// KEK / JWT_SECRET / Ed25519 公鑰共用同一演算法，避免各處自行實作導致漂移
// （key-inventory-transparency）。單向摘要，僅供人眼辨識——不可反推金鑰、
// 不作授權或業務唯一性判斷依據（KEK 重包時作指紋碰撞保守拒絕之用不在此限）。
func Fingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:8])
}
