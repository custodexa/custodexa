package crypto

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// wrapped_key 值自描述格式（kek-provider-modularization D4／D5 定案 B2；
// 相容窗於 release-transitional-cleanup D5 拆除）：
//
//	wk:2:<格式標記>:<base64>   ＝ 以 DEKAAD(purpose, version) **帶 AAD** 包裹（唯一合法形式）
//	wk:1:<格式標記>:<base64>   ＝ 無 AAD 包裹（發佈前過渡格式，**讀端於解包前拒收**）
//	<裸 base64>                ＝ 發佈前過渡格式（**讀端於解包前拒收**）
//
// **前綴恆為強制語義**：寫入端一律寫出 `wk:2:`；判別子 `1` 的產出器
// （AddLocalWrappedPrefix／RelabelAsAADBound／StripLocalWrappedPrefix）與
// 階段狀態（WrappedPrefixStage／持久化標記）整組刪除，故系統在建構上不具備
// 任何寫出無前綴或 `wk:1` 值的能力，亦不存在控制該行為的相容窗。
//
// **AAD 的在場性由格式版本承載，SHALL NOT 由讀端試錯判定**（定案 B2）。
// 先前的「先試 AAD、失敗退回無 AAD」沒有任何關閉條件——任何無 AAD 的舊 blob
// （含備份中的）都能被貼進任一 slot 而被讀端永遠收下。拒收判別子 `1` 的建構
// 前提正是「其合法產出路徑已不存在」。
//
// 誠實界定：前綴本身可被具 DB 寫權者改寫，故它**不是可信認證資料**；
// 其價值在於格式分流與可盤點殘量。改寫前綴只能造成解包失敗（DoS，該層級
// 攻擊者本就能做）——**不能**把帶 AAD 的 blob 變成可用空 AAD 通過驗證的 blob
// （GCM tag 綁死包裹當下的 AAD）。
const (
	wrappedKeyPrefixV1 = "wk:1:"
	wrappedKeyPrefixV2 = "wk:2:"
)

// wrapped 格式標記（描述位元組以哪種途徑解包；與 KeyRef.Provider 脫鉤、
// 與執行期模式 env／ui 無關）
const (
	WrappedFormatLocal = "local"
	WrappedFormatKMS   = "kms"
	WrappedFormatHSM   = "hsm"
)

// ErrWrappedKeyFormat wrapped_key 值格式錯（未知標記／未知版本／損毀／
// 發佈前過渡格式）
var ErrWrappedKeyFormat = errors.New("wrapped_key 格式無效")

// ErrWrappedKeyPreRelease wrapped_key 為發佈前過渡格式（無前綴或判別子 `1`）。
// 錯誤訊息指明須重建資料庫——拆除前建立的庫其本地 wrapped_key 恆為無前綴裸
// base64，改碼後首啟即於金鑰載入 fail-close，使「舊庫不可誤用」有機械保證。
var ErrWrappedKeyPreRelease = fmt.Errorf(
	"%w：資料庫含發佈前過渡格式的 wrapped_key，請重建資料庫", ErrWrappedKeyFormat)

// 註：原 `HasWrappedPrefix`（任一版本皆算「帶前綴」）已隨相容窗刪除——
// 終態下「帶前綴」與「合法」不再等價（`wk:1` 帶前綴卻必被拒收），保留它只會
// 讓呼叫端以為前綴在場即可用。判定一律走 `IsAADBoundWrapped` 或 `ParseWrappedKey`。

// IsAADBoundWrapped 值是否宣告為帶 AAD 包裹（wk:2）
func IsAADBoundWrapped(s string) bool { return strings.HasPrefix(s, wrappedKeyPrefixV2) }

// AADBoundWrappedPrefix 指定格式標記的「帶 AAD」前綴（如 `wk:2:kms:`）。
//
// 存在理由（D11.1 裁決 1「收窄一」）：委託模式的非正規 kek_id 偵測 SHALL **只**
// 檢查可證明為該委託格式的列，故呼叫端需要一個由**本檔的單一事實源**導出的
// 前綴字面——手寫 "wk:2:kms:" 會與 wrappedKeyPrefixV2 各自漂移。
func AADBoundWrappedPrefix(tag string) string { return wrappedKeyPrefixV2 + tag + ":" }

// EncodeWrappedKey 編碼 wrapped_key 欄位值：**一律** `wk:2:<格式標記>:<base64>`。
//
// **無前綴與判別子 `1` 的寫出分支已於 release-transitional-cleanup 刪除**，
// AAD 在場性參數（恆真）與收斂階段參數（恆強制）一併移除——「寫入端不可能
// 產出非終態 wrapped 值」自此是**建構事實**，不是靠呼叫端自律的承諾。
func EncodeWrappedKey(tag string, raw []byte) (string, error) {
	switch tag {
	case WrappedFormatLocal, WrappedFormatKMS, WrappedFormatHSM:
	default:
		return "", fmt.Errorf("%w（未知格式標記 %q）", ErrWrappedKeyFormat, tag)
	}
	return wrappedKeyPrefixV2 + tag + ":" + base64.StdEncoding.EncodeToString(raw), nil
}

// ParseWrappedKey 解析 wrapped_key 欄位值；回傳格式標記與包裹材料位元組。
//
// **兩類發佈前過渡格式一律於解包前 fail-close**（ErrWrappedKeyPreRelease）：
//   - 無前綴裸 base64——拆除前建立之資料庫的本地形式；
//   - 判別子 `1`（無 AAD 包裹）——其合法產出路徑已不存在，接受它等同永久
//     接受任何無 AAD 的舊包裹材料（含備份）被貼入金鑰槽。
//
// 兩者皆回可辨識格式錯，SHALL NOT 落入籠統的解包失敗、SHALL NOT 以任何
// 相容語義解包。
func ParseWrappedKey(s string) (tag string, raw []byte, err error) {
	switch {
	case strings.HasPrefix(s, wrappedKeyPrefixV2):
	case strings.HasPrefix(s, wrappedKeyPrefixV1):
		return "", nil, fmt.Errorf("%w（判別子 1＝無 AAD 包裹）", ErrWrappedKeyPreRelease)
	case strings.HasPrefix(s, "wk:"):
		// 未知版本（wk:3 等）：SHALL NOT 猜測，於解包前即回格式錯
		return "", nil, fmt.Errorf("%w（未知 wrapped 格式版本）", ErrWrappedKeyFormat)
	default:
		return "", nil, fmt.Errorf("%w（無前綴裸 base64）", ErrWrappedKeyPreRelease)
	}
	rest := s[len(wrappedKeyPrefixV2):]
	sep := strings.IndexByte(rest, ':')
	if sep <= 0 {
		return "", nil, fmt.Errorf("%w（前綴後缺格式標記分隔）", ErrWrappedKeyFormat)
	}
	tag = rest[:sep]
	switch tag {
	case WrappedFormatLocal, WrappedFormatKMS, WrappedFormatHSM:
	default:
		return "", nil, fmt.Errorf("%w（未知格式標記 %q）", ErrWrappedKeyFormat, tag)
	}
	raw, err = base64.StdEncoding.DecodeString(rest[sep+1:])
	if err != nil {
		return "", nil, fmt.Errorf("%w（base64 損毀）", ErrWrappedKeyFormat)
	}
	return tag, raw, nil
}
