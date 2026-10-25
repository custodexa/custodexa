package asset

import (
	"testing"

	"github.com/custodexa/backend/pkg/crypto"
)

// ColumnCodecForExternalTest 外部測試套件（asset_test）建構資產服務用的欄位加解密（零值金鑰）。
func ColumnCodecForExternalTest(t *testing.T) crypto.ColumnCodec {
	t.Helper()
	return aesColumnCodec(t, make([]byte, 32))
}
