package keyvault

import (
	"fmt"
	"strings"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
)

// 委託模式的 kek_id 形式守衛（kek-provider-modularization D11／D11.1 裁決 1）。
//
// **這裡刻意「只偵測、不改寫」**。round-1 曾規劃一次性存量正規化 migration，
// round-2 雙審獨立同判其整項取消，理由有二：
//
//  1. **目標族群為空**：data_keys.kek_id 的唯一寫入來源是
//     `s.kek.KeyRef().KeyID`（三個寫入點全部經 kekKeyID()），而 KMS provider 的
//     KeyRef().KeyID 自建構起就是正規 ARN；KMS 支援是首次釋出，故庫內不可能存在
//     需要被正規化的歷史資料。
//  2. **天真述詞會製造不可逆污染**：以「kek_id != 當前 KeyID 即改寫」判定，
//     在 alias 被重指向時會把 ARN-A 包裹的列改標成 ARN-B——材料未動而標籤已錯，
//     把原本正確的 ErrKEKMismatch fail-close 換成不可逆的標籤污染。
//
// 故本檔的不變式是：**不存在任何改寫既有 kek_id 的程式碼路徑**
// （由 TestNoKEKIDRewritePath 的 AST 守衛釘住）；偵測到異常即 fail-close 並給
// 可執行指引，處置留給人並要求逐列實際驗證材料歸屬。

// ErrDelegatedKEKIDNotCanonical 委託模式下偵測到非正規 kek_id（資料異常）。
//
// 理論上不可能發生（見本檔頂端），出現即代表有人以 DB 寫權直接改過該欄，
// 或存在本設計未預期的寫入路徑。無論何者，自動修復都比 fail-close 危險。
var ErrDelegatedKEKIDNotCanonical = fmt.Errorf("委託 KEK 模式偵測到非正規 kek_id")

// guardDelegatedKEKIDCanonical 檢查委託模式下既有列的 kek_id 是否為正規形式。
//
// **三道收窄，缺一即會誤殺正常部署**：
//
//   - 收窄零（本地 no-op）：以 KeyRef().Provider == local 閘住。InitKeyManager
//     屬 B 模式段 2，本地 provider 也會走到這裡；本地 KeyID 是材料指紋，
//     「正規語法」對它沒有意義。
//   - 收窄一（資料集合）：**僅檢查 wrapped_key 前綴可證明為本 provider 委託格式
//     的列**（`wk:2:<tag>:`），SHALL NOT 掃全表——A/B→C 重包留下的**退役 local
//     列**其 kek_id 是本地指紋，掃全表必誤判為非正規而使正常遷移後的部署開不了機。
//   - 收窄三（判定式）：「非正規」＝**不符該 provider 的 KeyID 語法**，
//     SHALL NOT 以「不等於當前 KeyRef().KeyID」判定——後者會把其他合法 ARN
//     （退役 KEK、重包過渡期的舊列）一律誤殺。語法合格但非當前金鑰者屬正常存量，
//     由代表列篩選處理。
//
// provider 未實作 KeyIDSyntaxValidator 時本檢查亦為 no-op：沒有語法可判就不該
// 憑空判定（HSM 於 P4 接上自己的實作）。
func guardDelegatedKEKIDCanonical(rows []model.DataKey, kek crypto.KEKProvider) error {
	if kek == nil || kek.KeyRef().Provider == crypto.KeyRefProviderLocal {
		return nil
	}
	validator, ok := kek.(crypto.KeyIDSyntaxValidator)
	if !ok {
		return nil
	}
	prefix := crypto.AADBoundWrappedPrefix(kek.FormatTag())
	var offenders []string
	seen := map[string]bool{}
	for _, r := range rows {
		if !strings.HasPrefix(r.WrappedKey, prefix) {
			continue
		}
		if seen[r.KEKID] {
			continue
		}
		seen[r.KEKID] = true
		if err := validator.ValidateKeyIDSyntax(r.KEKID); err != nil {
			offenders = append(offenders, fmt.Sprintf("%s v%d（kek_id=%s）", r.Purpose, r.Version, r.KEKID))
		}
	}
	if len(offenders) == 0 {
		return nil
	}
	// **指引不得是裸 UPDATE**（D11.1 裁決 1「收窄二」）：一次性全表 UPDATE 只是
	// 把 alias 重指向的同款不可逆污染從程式碼搬到人手上。要求逐列以明確 KeyId＋AAD
	// 實際試解包成功後才改標。
	return fmt.Errorf("%w：拒絕啟動。受影響列：%s。"+
		"SHALL NOT 以單條 UPDATE 全表改標——請逐列以明確 KeyId 與該列的 DEK AAD 實際試解包，"+
		"確認材料確由該金鑰包裹後才改標；無法解包者屬材料歸屬不明，須依 runbook 處置",
		ErrDelegatedKEKIDNotCanonical, strings.Join(offenders, "、"))
}
