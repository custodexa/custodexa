package crypto

import (
	"context"
	"strconv"
	"strings"
)

// 【已移除】Codec 介面（`Encrypt(plaintext)`＋`Decrypt(ciphertext)`）於
// kek-provider-modularization D5 cutover（tasks 1.7）**自本套件刪除**，不留過渡別名。
//
// 理由：該介面**不帶欄位身分**，寫出的是無 AAD 的 `enc:v<N>` 密文。cutover 的
// 驗收判準是「寫入端在**建構上**不可能產出無 AAD 密文」——只要仍存在一個
// 帶 `Encrypt(plaintext)` 的介面可供服務層持有，該保證就退化為「靠自律」，
// 且「現查殘餘為 0」淪為瞬時快照（tasks 1.7 失敗判準第 4 條）。
//
// 服務層一律持 ColumnCodec（見下）。
//
// **無 AAD 寫出能力已於 release-transitional-cleanup 整組刪除**：原先僅存的
// 退版反向回寫路徑（未匯出方法＋無 AAD 信封編碼）連同其守衛一併移除，
// 「寫入端不可能產出無 AAD 密文」自此是建構事實而非靠守衛維持的承諾。
// 讀取端亦無相容語義——非 `enc:a1` 之值於 DecryptFor 一律 fail-close。

// CipherRef 資料密文的邏輯位置（kek-provider-modularization D5 資料層 AAD）：
// 登記表名與欄名。
//
// **主鍵不參與 AAD（定案 A2，fable 仲裁＋codex 第二意見獨立同結論）**：
// pk 綁定所防的「同表同欄跨列搬移」以具 DB 寫權為前提，而該層級已明載為信任邊界，
// 且該攻擊者另有嚴格更強的等價手段（直接改同列的 host／username 等非加密欄位、
// 刪列重建同 pk 貼回舊密文——後者 D5 自承不擋）。反之 pk 綁定有三處主動傷害：
// (1) 還原至 pk 不同的環境使密文不可解；(2) sqlite 自增 pk 重用使保證本就打折；
// (3) 破壞 asset-multi-account 的密文原樣複製契約。
// 移除 pk 後，create 路徑於 insert 前即可完成加密，**不需兩階段寫入**。
type CipherRef struct {
	Table  string
	Column string
}

// ColumnCodec 帶欄位身分的加解密介面（cutover 後服務層持有的型別）。
// **刻意不含 Encrypt(plaintext)**——持有本介面者在建構上不可能寫出無 AAD 密文。
type ColumnCodec interface {
	EncryptFor(ctx context.Context, ref CipherRef, plaintext string) (string, error)
	DecryptFor(ctx context.Context, ref CipherRef, ciphertext string) (string, error)
}

// AAD 命名空間與方案版本。
//
// **編碼規則**：固定欄位順序＋**長度前綴**，SHALL NOT 以未逸出的字串裸串接
// ——`("ab","c")` 與 `("a","bc")` 裸串接會得到同一份 AAD（碰撞），
// 使「跨欄搬移」的防護在特定命名下靜默失效。
// **為何不引用 internal/branding.Slug**：本包位於 pkg/ 之下，外部可 import；
// 依賴 internal/ 會使外部 import 編譯失敗。品牌識別字在此以字面量表達，
// 與 branding.Slug 同值（brand-residual-cleanup）。
const (
	aadNamespace = "custodexa"
	// aadDomainWrappedDEK DEK 包裹層
	aadDomainWrappedDEK = "wrapped-dek"
	// aadDomainDataField 資料密文層
	aadDomainDataField = "data-field"
	// aadSchemeVersion AAD 組成規則的版本（與密文前綴的方案標記 a1 同步演進）
	aadSchemeVersion = "v1"
)

// canonicalAAD 無歧義 AAD 編碼：`custodexa|<domain>|<version>` 後接
// 各欄位的 `|<len>:<value>`。長度前綴使編碼為單射（injective）。
func canonicalAAD(domain string, parts ...string) []byte {
	var b strings.Builder
	b.WriteString(aadNamespace)
	b.WriteByte('|')
	b.WriteString(domain)
	b.WriteByte('|')
	b.WriteString(aadSchemeVersion)
	for _, p := range parts {
		b.WriteByte('|')
		b.WriteString(strconv.Itoa(len(p)))
		b.WriteByte(':')
		b.WriteString(p)
	}
	return []byte(b.String())
}

// DEKAAD DEK 包裹層 AAD（D5）：綁定用途與版本。
//
// **不含 kek_id 等可變識別符**（design.md D5 round-2，codex 批 A high）：
// 委託模式的 `kek_id` 正規化改寫（D11／tasks 3.1a）明訂「純識別欄改寫、不重包」，
// AAD 一旦含 kek_id，該改寫必然使既有列解包失敗——tasks 3.1a 的
// 「kek_id 改寫後既有列仍可解包」驗收與本項互為前提。包裹材料本就只能由當初
// 包裹它的 KEK 解開，把該 KEK 的**名字**再寫進 AAD 是冗餘的。
//
// **完備性依賴（SHALL 明載，否則放寬時靜默失效）**：`purpose|version` 之所以是
// 完備的 slot 判別式，依賴兩項既有不變式——
// (1) data_keys 的 (purpose, version, kek_id) partial 唯一索引；
// (2) 重包守衛拒絕任何曾出現過的 kek_id。
func DEKAAD(purpose string, version int) []byte {
	return canonicalAAD(aadDomainWrappedDEK, purpose, strconv.Itoa(version))
}

// AAD 資料密文層 AAD（D5）：綁定登記表名與欄名。
func (r CipherRef) AAD() []byte {
	return canonicalAAD(aadDomainDataField, r.Table, r.Column)
}

// Valid 兩維度皆非空才可用於 AAD 綁定
func (r CipherRef) Valid() bool {
	return r.Table != "" && r.Column != ""
}

// String 診斷用（不含任何密文或金鑰材料）
func (r CipherRef) String() string { return r.Table + "." + r.Column }
