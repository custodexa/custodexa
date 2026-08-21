package crypto

import (
	"context"
	"errors"
	"fmt"
)

// KEK 執行期模式（KEK_PROVIDER 的值域，kek-provider-modularization D1）：
// 描述「材料從哪裡來／由誰保管」，僅供清冊顯示與稽核對照（D10）。
// **不進 KeyRef、不進 kek_id、不進 wrapped 格式標記**——否則同一材料在
// env 與 ui 下寫出的列不相同，「同鑰互換零語義差異」（D9）當場破功。
const (
	KEKModeEnv = "env"
	KEKModeUI  = "ui"
	KEKModeKMS = "kms"
	KEKModeHSM = "hsm"
)

// KeyRef.Provider 值域（三值，非四值；D4）：描述「這串引用要用哪種解包途徑
// 解讀」。env 與 ui 皆映射 local。
const (
	KeyRefProviderLocal = "local"
	KeyRefProviderKMS   = "kms"
	KeyRefProviderHSM   = "hsm"
)

// ErrKEKFormatMismatch 包裹值格式標記與本 provider 不符（D4）：
// 於 Unwrap 之前判定，取代「籠統 GCM 驗證失敗」的無診斷路徑
var ErrKEKFormatMismatch = errors.New("包裹材料格式標記與現行 KEK provider 不符")

// KeyRef 金鑰引用（kek-provider-modularization D4）：
// 本地模式為材料指紋（可由材料重算），委託模式為外部金鑰識別（不可重算）。
// **相等性 SHALL 僅由 (Provider, KeyID) 決定，不含執行期組態模式**。
type KeyRef struct {
	// Provider local | kms | hsm（三值）
	Provider string
	// KeyID local: hex(SHA-256(material)[:8])；kms: 正規 key ARN；hsm: token:label（跳脫後）
	KeyID string
}

// Equal 金鑰引用相等性：僅比 (Provider, KeyID)。
// 誠實界定：本地模式的 KeyID 為 64-bit 截斷摘要，相等**不能證明同材料**
// （D9）——上線判準為「金鑰引用一致且現行代表列全數實際解包成功」。
func (r KeyRef) Equal(o KeyRef) bool {
	return r.Provider == o.Provider && r.KeyID == o.KeyID
}

func (r KeyRef) String() string {
	return r.Provider + ":" + r.KeyID
}

// KEKProvider 金鑰加密鑰（KEK）提供者（kek-provider-modularization D4）：
// 負責包裹／解包 DEK 等金鑰材料。KEK 明文不落庫、不經 API、不落日誌。
//
// 核心不變式：KEK 來源模式的差異 SHALL 完全封裝於本介面之下，
// KeyManagerService 以上零語義差異。
type KEKProvider interface {
	// Wrap 包裹明文金鑰材料。
	//
	// **nil／空 aad 一律拒絕——三 provider 的共同契約**
	// （release-transitional-cleanup P2 M1）：
	//   - 本地 provider：底層 AESCrypto.EncryptBytesAAD 回 ErrAADRequired；
	//   - 委託 provider（kms／hsm）：回 kms.ErrAADRequired——EncodeWrappedKey 對
	//     委託格式一律要求 AAD，送出空綁定會產出無綁定的委託 blob。
	//
	// 原「本地 nil＝不綁定」的 per-provider 差異（kek-provider-modularization
	// D11.1 裁決 2）已隨無 AAD 寫出能力的原語層刪除而收斂：本地 provider 亦不再
	// 可能寫出無綁定的包裹值，故 A/B/C 共用的契約測試 SHALL 把「空 AAD 被拒」
	// 列為**共同期望**。
	Wrap(ctx context.Context, plaintext, aad []byte) ([]byte, error)
	// Unwrap 解包；aad 須與包裹時逐位元相同。
	// nil／空 aad 同樣一律拒絕（同 Wrap）。
	Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error)
	// KeyRef 金鑰引用（落 kek_id 的值即 KeyRef().KeyID）
	KeyRef() KeyRef
	// Mode 執行期組態模式（env／ui／kms／hsm）。D10 雙軌互證：清冊 provider 欄
	// SHALL 由此導出，SHALL NOT 重讀 os.Getenv、亦 SHALL NOT 由 KeyRef().Provider
	// 推導（後者三值，無法區分 env 與 ui）
	Mode() string
	// FormatTag 本 provider 寫出的 wrapped 格式標記（local／kms／hsm）
	FormatTag() string
	// ReEncrypt 由舊 wrapped 直接產出本 provider 的 wrapped。
	// 預設實作＝from.Unwrap 後本 provider Wrap；KMS 可覆寫為原生 ReEncrypt 原語
	ReEncrypt(ctx context.Context, wrapped, aad []byte, from KEKProvider) ([]byte, error)
}

// KeyIDSyntaxValidator 選用介面：委託型 provider 可宣告「何謂本 provider 的正規
// KeyID 語法」（kek-provider-modularization D11.1 裁決 1「收窄三」）。
//
// **為何是選用介面而非介面方法**：本地 provider 的 KeyID 是材料指紋，
// 「正規語法」對它沒有意義；把它塞進 KEKProvider 會逼本地實作寫一個恆真的
// 方法，而那正是 no-op 檢查最容易被誤刪的地方。
//
// **判語法、不判歸屬**：實作 SHALL 只回答「這串是不是本 provider 的識別形式」，
// SHALL NOT 以「等不等於當前金鑰」作答——後者會把退役／過渡期的其他合法識別
// 一律誤殺（D11.1 明列的失敗判準）。
type KeyIDSyntaxValidator interface {
	ValidateKeyIDSyntax(keyID string) error
}

// LocalAESKEKProvider 本地 AES-256-GCM KEK provider（A env 與 B ui **共用同一實作**，
// D1）：差別僅在材料注入時機（啟動期 env vs 解封期 API）。此共用即
// 「A↔B 同鑰互換免遷移」（D9）的實作根據——同材料下 KeyRef 相同、格式標記相同、
// 互相可解。
type LocalAESKEKProvider struct {
	aes   *AESCrypto
	keyID string
	mode  string
}

// NewLocalAESKEKProvider 建立本地 KEK provider；material 必須為 32 bytes。
// mode 僅供 D10 稽核對照，**不影響任何落庫值**（KeyRef／格式標記皆與 mode 無關）
func NewLocalAESKEKProvider(material []byte, mode string) (*LocalAESKEKProvider, error) {
	if mode != KEKModeEnv && mode != KEKModeUI {
		return nil, fmt.Errorf("本地 KEK provider 的執行期模式僅可為 env／ui，得 %q", mode)
	}
	a, err := NewAESCrypto(material)
	if err != nil {
		return nil, err
	}
	return &LocalAESKEKProvider{aes: a, keyID: Fingerprint(material), mode: mode}, nil
}

// NewEnvKEKProvider 建立 env 模式的本地 KEK provider（相容入口）
func NewEnvKEKProvider(key []byte) (*LocalAESKEKProvider, error) {
	return NewLocalAESKEKProvider(key, KEKModeEnv)
}

// Wrap 包裹金鑰材料
func (p *LocalAESKEKProvider) Wrap(_ context.Context, plaintext, aad []byte) ([]byte, error) {
	return p.aes.EncryptBytesAAD(plaintext, aad)
}

// Unwrap 解包金鑰材料
func (p *LocalAESKEKProvider) Unwrap(_ context.Context, wrapped, aad []byte) ([]byte, error) {
	return p.aes.DecryptBytesAAD(wrapped, aad)
}

// KeyRef 金鑰引用（Provider 恆為 local——env 與 ui 不區分）
func (p *LocalAESKEKProvider) KeyRef() KeyRef {
	return KeyRef{Provider: KeyRefProviderLocal, KeyID: p.keyID}
}

// KeyID KEK 指紋（相容存取器；等同 KeyRef().KeyID）
func (p *LocalAESKEKProvider) KeyID() string { return p.keyID }

// Mode 執行期模式（env／ui）
func (p *LocalAESKEKProvider) Mode() string { return p.mode }

// FormatTag 本地格式標記（env／ui 共用同一標記）
func (p *LocalAESKEKProvider) FormatTag() string { return WrappedFormatLocal }

// ReEncrypt 預設實作：以來源 provider 解包後由本 provider 重新包裹
func (p *LocalAESKEKProvider) ReEncrypt(ctx context.Context, wrapped, aad []byte, from KEKProvider) ([]byte, error) {
	return DefaultReEncrypt(ctx, p, wrapped, aad, from)
}

// DefaultReEncrypt KEKProvider.ReEncrypt 的預設實作（解包後重新包裹）。
// 委託型 provider 具原生 ReEncrypt 原語者可不用此函式。
func DefaultReEncrypt(ctx context.Context, to KEKProvider, wrapped, aad []byte, from KEKProvider) ([]byte, error) {
	raw, err := from.Unwrap(ctx, wrapped, aad)
	if err != nil {
		return nil, fmt.Errorf("以來源 KEK 解包失敗: %w", err)
	}
	return to.Wrap(ctx, raw, aad)
}
