package crypto

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// 信封密文格式：enc:v<version>:<base64(nonce+ct)>。
// legacy 密文為純 base64（不含 ':'），與前綴無歧義；ParseEnvelope 以此分派
// 新舊解密路徑。
//
// AAD 方案：enc:a<scheme>:v<version>:<base64>。
// 目前唯一方案為 a1（資料層 AAD 綁 table|column；**不綁 pk**，
// 編碼與理由見 codec.go 的 CipherRef 與 canonicalAAD）。未知 scheme MUST 回
// 格式錯，SHALL NOT 落入 legacy 純 base64 路徑——否則外部塞入的 `enc:x:` 值會被
// 當成 legacy 密文送進單鑰解密器。
const envelopeAnyPrefix = "enc:"

// AAD 方案標記值域（方案版本＝AAD 組成規則的版本）
const (
	// AADSchemeNone 無 AAD（既有 enc:v<N> 格式）
	AADSchemeNone = ""
	// AADSchemeA1 方案 1：DEK 層綁 purpose|version、資料層綁 table|column
	// （**pk 不參與**——理由見 codec.go 的 CipherRef）
	AADSchemeA1 = "a1"
)

// EncodeEnvelopeAAD 將密文位元組編為帶 AAD 方案標記的信封格式
// （**全專案唯一的資料密文編碼入口**）。
//
// **無 AAD 編碼能力已移除**：原
// `EncodeEnvelope(version, raw)` 與本函式的「scheme 為空即退回無 AAD 格式」分支
// 一併刪除。無 AAD 寫出因此在**建構上**不可能——不再是靠守衛測試自律的承諾。
// 未知或空 scheme 一律回錯，SHALL NOT 猜測、SHALL NOT 退回任何無 AAD 形式。
func EncodeEnvelopeAAD(scheme string, version int, raw []byte) (string, error) {
	if scheme != AADSchemeA1 {
		return "", fmt.Errorf("%w（未知 AAD 方案 %q：系統不具備無 AAD 寫出能力）",
			ErrInvalidCiphertext, scheme)
	}
	return fmt.Sprintf("%s%s:v%d:%s", envelopeAnyPrefix, scheme, version,
		base64.StdEncoding.EncodeToString(raw)), nil
}

// IsEnvelope 密文是否為任一版本化信封格式（含帶 AAD 方案者）
func IsEnvelope(s string) bool {
	return strings.HasPrefix(s, envelopeAnyPrefix)
}

// ParseEnvelope 解析版本化密文（無 AAD 相容入口）。
// 非信封格式（legacy 純 base64）回 ok=false 且 err=nil；帶前綴但格式損毀回 err。
// 帶 AAD 方案的密文由本函式回 err（呼叫端須改用 ParseEnvelopeFull）——
// 舊呼叫端不會誤把帶 AAD 密文當無 AAD 解。
func ParseEnvelope(s string) (version int, raw []byte, ok bool, err error) {
	scheme, version, raw, ok, err := ParseEnvelopeFull(s)
	if err != nil || !ok {
		return 0, nil, ok, err
	}
	if scheme != AADSchemeNone {
		return 0, nil, false, ErrInvalidCiphertext
	}
	return version, raw, true, nil
}

// ParseEnvelopeFull 解析版本化密文並回傳 AAD 方案標記。
// 非信封格式（legacy 純 base64）回 ok=false 且 err=nil；
// 帶 `enc:` 前綴但方案未知或格式損毀一律回 err（不回落 legacy 路徑）。
func ParseEnvelopeFull(s string) (scheme string, version int, raw []byte, ok bool, err error) {
	if !IsEnvelope(s) {
		return AADSchemeNone, 0, nil, false, nil
	}
	rest := s[len(envelopeAnyPrefix):]
	scheme = AADSchemeNone
	if !strings.HasPrefix(rest, "v") {
		// enc:<scheme>:v<N>:<b64>
		sep := strings.IndexByte(rest, ':')
		if sep <= 0 {
			return AADSchemeNone, 0, nil, false, ErrInvalidCiphertext
		}
		scheme = rest[:sep]
		if scheme != AADSchemeA1 {
			return AADSchemeNone, 0, nil, false, ErrInvalidCiphertext
		}
		rest = rest[sep+1:]
		if !strings.HasPrefix(rest, "v") {
			return AADSchemeNone, 0, nil, false, ErrInvalidCiphertext
		}
	}
	rest = rest[1:] // 去 "v"
	sep := strings.IndexByte(rest, ':')
	if sep <= 0 {
		return AADSchemeNone, 0, nil, false, ErrInvalidCiphertext
	}
	version, err = strconv.Atoi(rest[:sep])
	if err != nil || version < 0 {
		return AADSchemeNone, 0, nil, false, ErrInvalidCiphertext
	}
	raw, err = base64.StdEncoding.DecodeString(rest[sep+1:])
	if err != nil {
		return AADSchemeNone, 0, nil, false, ErrInvalidCiphertext
	}
	return scheme, version, raw, true, nil
}
