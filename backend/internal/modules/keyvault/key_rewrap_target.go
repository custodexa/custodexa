package keyvault

import (
	"context"
	"errors"
	"fmt"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/pkg/crypto"
)

// 重包目標（kek-provider-modularization D7）：換鑰精靈的 discriminated union
// 在服務層的表述。
//
// **為何不是裸 crypto.KEKProvider**：本地目標的材料格式驗證（D8 路 2）若只落在
// handler，任何繞過 handler 的呼叫端（含日後新增的內部流程）都能以不合格材料
// 重包。改為「**唯一公開建構入口即驗證入口＋sink 端重驗**」。
//
// **誠實界定（原「建構上不可能」的措辭過強）**：欄位不導出只擋得住**套件外**的
// 呼叫端；同一個 service 套件內任何人都能寫 `RewrapTarget{mode: "local",
// provider: anything}` 而完全不經驗證。故不變式改由兩道各自成立的防線承擔：
//
//  1. 套件外：欄位不可寫，只能經 NewLocalRewrapTarget／NewDelegatedRewrapTarget；
//  2. 套件內外皆適用：RewrapKEK 於入口呼叫 Validate() 重驗完整不變式，
//     且該重驗涵蓋「provider 確實由這份通過格式驗證的材料建出」——手寫的
//     struct literal 若不附上合格材料就過不了 sink，附了就等於通過同一組驗證。
//
// **委託分支（kms／hsm）自 Phase C 3.1／3.3 起接上實際 provider**：
// 目標 provider 由組裝根注入的 DelegatedProviderFactory 建構，建構本身即完成
// 連通性預檢（KMS：DescribeKey 正規化＋金鑰可用性＋一次真實 Encrypt／Decrypt
// 往返）。未注入 factory 或該模式尚未交付（hsm）時仍回 ErrRewrapTargetUnsupported。

// 重包目標的判別子值域，逐字沿用 crypto.KeyRef.Provider 的三值——
// union 的判別子與落庫的金鑰引用同源，避免兩套字面各自漂移
const (
	RewrapTargetModeLocal = crypto.KeyRefProviderLocal
	RewrapTargetModeKMS   = crypto.KeyRefProviderKMS
	RewrapTargetModeHSM   = crypto.KeyRefProviderHSM
)

// ErrRewrapMaterialFormat 本地目標材料未通過伺服端格式驗證（D8 路 2：長度、
// 字元集、非出廠預設值）。**不得只靠前端**——前端驗證只是即時回饋。
var ErrRewrapMaterialFormat = errors.New("新 KEK 材料不合格式要求")

// ErrRewrapTargetModeInvalid 判別子不在白名單
var ErrRewrapTargetModeInvalid = errors.New("重包目標模式無效")

// ErrRewrapTargetUnsupported 委託目標尚未交付（Phase C 3.1／3.3）
var ErrRewrapTargetUnsupported = errors.New("委託 KEK 目標的重包尚未提供")

// ErrRewrapTargetSameAsCurrent 目標金鑰引用等於現行 KEK
var ErrRewrapTargetSameAsCurrent = errors.New("重包目標與現行 KEK 相同")

// ErrRewrapTargetSeen 目標金鑰引用與金鑰表衝突。
//
// **本地與委託的判定範圍不同（D11.1 裁決 6）**：
//   - 本地目標：曾出現過即拒（含退役列）——KEK 隨機生成，碰撞就換一把即可；
//   - 委託目標：僅「存在使用該 kek_id 的**未退役**列」才拒——ARN 不可重生，
//     沿用嚴格語義等於一次 abandon 就永久燒毀該 CMK。
var ErrRewrapTargetSeen = errors.New("重包目標的金鑰引用曾出現於金鑰表")

// ErrRewrapTargetUnavailable 委託目標的連通性預檢失敗（不可達／無權限／金鑰不合用）
var ErrRewrapTargetUnavailable = errors.New("委託重包目標的連通性預檢失敗")

// DelegatedProviderFactory 委託目標 provider 的建構器（由組裝根注入）。
//
// **為何是注入而非在 service 內直接建構**：目標的 region／服務商來自本行程的
// 部署組態，而「讀部署組態」是組裝根的職責；service 層直接讀 env 會讓這條路徑
// 繞過 config 的三值語義與判定矩陣，也讓測試無法在不污染行程 env 的前提下覆蓋。
//
// 實作 SHALL 於回傳前完成連通性預檢（D7 的 C 模式重包前置：確認目標金鑰已存在
// 且本服務具備所需權限），使「預檢通過」與「拿得到 provider」是同一件事——
// 分成兩步會留下「拿到 provider 但沒預檢」的呼叫路徑。
type DelegatedProviderFactory func(ctx context.Context, mode, keyRef string) (crypto.KEKProvider, error)

// ErrRewrapTargetInvariant 重包目標未通過 sink 端的不變式重驗
var ErrRewrapTargetInvariant = errors.New("重包目標未通過不變式檢查")

// RewrapTarget 重包目標（union）。
//
// 欄位不導出使**套件外**只能經構造函式取得實例；套件內的 struct literal 由
// RewrapKEK 入口的 Validate() 擋下（見本檔頂端的誠實界定）。
type RewrapTarget struct {
	mode     string
	provider crypto.KEKProvider
	// material 為本地目標的**解碼後金鑰**（32 bytes），只為 sink 端重驗而保留。
	//
	// **為何持有一份而不是只留 provider**：不持有金鑰時，sink 能檢查的只有
	// 「mode 合法、provider 非 nil」，那擋不住「以任意 provider 造一個 local
	// 目標」——而那正是 R2 指出的繞道。持有之後，重驗可以同時證明
	// 「金鑰形狀合格且非出廠預設值」與「provider 確實由這把金鑰建出」（指紋比對）。
	//
	// **存的是金鑰而非輸入字串**（kek-encoding-and-unseal-entry 決策 11）：
	// 材料可為原字元／十六進位／base64 三種寫法，指紋比對的對象只能是解碼結果；
	// 存輸入字串會讓 hex 形態的目標永遠對不上自己的 provider。
	// 生命週期以 Destroy 結束，且 RewrapKEK 用畢即銷毀。
	material []byte
}

// NewLocalRewrapTarget 由使用者輸入的材料建構本地目標。
//
// **伺服端格式驗證的唯一落點**（D8 路 2）：可解碼為 32 位元組金鑰、原字元形態的
// 字元集限 crypto.KEKAlphabet、非出廠預設值——三者與啟動判定（config 列 3b）共用
// 同一驗證器，兩端不會各自漂移。
//
// **三種輸入寫法**（kek-encoding-and-unseal-entry）：原字元 32 位元組、
// 64 個十六進位字元、解碼後恰 32 位元組的 base64。三者解出同一把金鑰時，
// 其 KeyRef（指紋）相同，故「以哪種寫法輸入」不影響任何落庫值。
//
// **誠實界定**：格式驗證是降低常見弱值風險的務實手段，系統 SHALL NOT 宣稱能由
// 單一值驗證其熵。
//
// provider 的執行期模式取 ui：本目標是**只用於包裹的過渡物件**，永不成為本行程
// 的 runtime provider，而 mode 不影響任何落庫值（KeyRef 與格式標記皆與 mode 無關，
// D1）——即材料日後被放進 ENCRYPTION_KEY 以 env 模式啟動，仍解得開本次寫出的列。
func NewLocalRewrapTarget(material string) (*RewrapTarget, error) {
	if reason := config.ValidateKEKMaterial(material); reason != "" {
		return nil, fmt.Errorf("%w：%s", ErrRewrapMaterialFormat, reason)
	}
	key, reason := config.DecodeKEKMaterialKey(material)
	if reason != "" {
		return nil, fmt.Errorf("%w：%s", ErrRewrapMaterialFormat, reason)
	}
	provider, err := crypto.NewLocalAESKEKProvider(key, crypto.KEKModeUI)
	if err != nil {
		return nil, fmt.Errorf("%w：%v", ErrRewrapMaterialFormat, err)
	}
	// provider 內部持有 key 作為 AES 金鑰，本結構另留一份副本供 sink 端重驗；
	// 兩份的生命週期不同（provider 隨包裹作業、副本隨 Destroy），故不共用切片
	own := make([]byte, len(key))
	copy(own, key)
	return &RewrapTarget{
		mode:     RewrapTargetModeLocal,
		provider: provider,
		material: own,
	}, nil
}

// Validate 於 sink 端重驗完整不變式。
//
// **重驗而非信任建構**：同一套件內的 struct literal 不經任何構造函式即可產生
// 實例，故「唯一構造入口」只在套件邊界上成立。三項檢查缺一不可：
//
//   - mode 在白名單內；
//   - provider 非 nil；
//   - 本地目標的**金鑰**通過 config.ValidateKEKKey（長度恰 32、非出廠預設值），
//     且 provider 的 KeyID 等於該金鑰的指紋——後者證明 provider 真的由這把金鑰
//     建出，否則「合格金鑰 ＋ 不相干 provider」的組合仍可通過。
//
// **sink 端驗的是金鑰、不是材料**（kek-encoding-and-unseal-entry 決策 11）：
// 字元集是**輸入編碼**的性質，解碼之後該資訊已不存在，宣稱在此重驗了字元集
// 是不誠實的。真正撐住不變式的兩項（金鑰形狀合格、provider 由它建出）原樣保留。
func (t *RewrapTarget) Validate() error {
	if t == nil {
		return fmt.Errorf("%w：目標為 nil", ErrRewrapTargetInvariant)
	}
	switch t.mode {
	case RewrapTargetModeLocal, RewrapTargetModeKMS, RewrapTargetModeHSM:
	default:
		return fmt.Errorf("%w：%q", ErrRewrapTargetModeInvalid, t.mode)
	}
	if t.mode != RewrapTargetModeLocal {
		// 委託目標沒有材料可驗（材料不在本系統內），能驗的是「provider 存在」
		// 與「provider 的金鑰引用種類與判別子一致」——後者擋下「以 kms 判別子
		// 夾帶一個本地 provider」的套件內 struct literal 繞道，
		// 那正是本地分支要用指紋比對擋下的同一類問題。
		if t.provider == nil {
			return fmt.Errorf("%w：委託目標未持有 KEK provider", ErrRewrapTargetInvariant)
		}
		ref := t.provider.KeyRef()
		if ref.Provider != t.mode {
			return fmt.Errorf("%w：委託目標判別子 %q 與 provider 金鑰引用種類 %q 不符",
				ErrRewrapTargetInvariant, t.mode, ref.Provider)
		}
		if ref.KeyID == "" {
			return fmt.Errorf("%w：委託目標的金鑰引用為空", ErrRewrapTargetInvariant)
		}
		return nil
	}
	if t.provider == nil {
		return fmt.Errorf("%w：目標未持有 KEK provider", ErrRewrapTargetInvariant)
	}
	if reason := config.ValidateKEKKey(t.material); reason != "" {
		return fmt.Errorf("%w：%s", ErrRewrapMaterialFormat, reason)
	}
	ref := t.provider.KeyRef()
	if ref.Provider != crypto.KeyRefProviderLocal || ref.KeyID != crypto.Fingerprint(t.material) {
		return fmt.Errorf("%w：本地目標的 provider 並非由其金鑰建出（引用 %s/%s）",
			ErrRewrapTargetInvariant, ref.Provider, ref.KeyID)
	}
	return nil
}

// Destroy 覆寫本目標持有的材料副本。
//
// **誠實界定**：本方法覆寫的是 RewrapTarget 自己配置的那份 byte buffer。
// 呼叫端經 string 傳入的原始材料、以及 provider 內部由該材料展開的 AES 金鑰表
// （pkg/crypto 未提供銷毀入口）都不在覆寫範圍內；string 的 backing array 在 Go
// 語義下不可覆寫，其回收時點由 GC 決定。SHALL NOT 宣稱材料已自行程記憶體抹除。
func (t *RewrapTarget) Destroy() {
	if t == nil {
		return
	}
	for i := range t.material {
		t.material[i] = 0
	}
	t.material = nil
}

// NewDelegatedRewrapTarget 委託目標（kms／hsm）。
//
// 三種失敗刻意分開，因為處置完全不同：
//   - 白名單外的 mode → ErrRewrapTargetModeInvalid（打錯字）；
//   - factory 未注入或該模式尚未交付 → ErrRewrapTargetUnsupported（版本不支援）；
//   - factory 建構／預檢失敗 → ErrRewrapTargetUnavailable（組態或權限問題）。
//
// **SHALL NOT 靜默退化為本地目標**：任一失敗都不得產生任何 data_keys 寫入。
//
// 連通性預檢（D7 的 C 模式重包前置）由 factory 實作承擔——KMS 為
// DescribeKey（金鑰存在＋正規化＋可用性）＋一次真實 Encrypt／Decrypt 往返；
// 所需 IAM action 為 kms:DescribeKey／kms:Encrypt／kms:Decrypt，
// C1↔C1 原生 ReEncrypt 另需 **kms:ReEncryptFrom 與 kms:ReEncryptTo 兩個**
// （非單一 kms:ReEncrypt，D11.1 裁決 5 的 opus L2）。
func NewDelegatedRewrapTarget(ctx context.Context, mode, keyRef string, factory DelegatedProviderFactory) (*RewrapTarget, error) {
	switch mode {
	case RewrapTargetModeKMS, RewrapTargetModeHSM:
	default:
		return nil, fmt.Errorf("%w：%q", ErrRewrapTargetModeInvalid, mode)
	}
	if keyRef == "" {
		return nil, fmt.Errorf("%w：委託目標須指定 key_ref", ErrRewrapTargetModeInvalid)
	}
	if factory == nil {
		return nil, fmt.Errorf("%w（目標模式 %s）", ErrRewrapTargetUnsupported, mode)
	}
	provider, err := factory(ctx, mode, keyRef)
	if err != nil {
		if errors.Is(err, ErrRewrapTargetUnsupported) {
			return nil, err
		}
		return nil, fmt.Errorf("%w（目標模式 %s）: %v", ErrRewrapTargetUnavailable, mode, err)
	}
	if provider == nil {
		return nil, fmt.Errorf("%w（目標模式 %s）", ErrRewrapTargetUnsupported, mode)
	}
	target := &RewrapTarget{mode: mode, provider: provider}
	// 建構入口即驗不變式：判別子與 provider 的金鑰引用種類必須一致，
	// 否則 factory 的實作錯誤會拖到 sink 端才被發現
	if err := target.Validate(); err != nil {
		return nil, err
	}
	return target, nil
}

// Mode 目標判別子（local／kms／hsm）
func (t *RewrapTarget) Mode() string { return t.mode }

// IsLocal 本地目標（材料在使用者手上，適用 paste-back 與保存確認語義）
func (t *RewrapTarget) IsLocal() bool { return t.mode == RewrapTargetModeLocal }

// Provider 包裹用的 KEK provider
func (t *RewrapTarget) Provider() crypto.KEKProvider { return t.provider }

// KeyRef 目標金鑰引用（落 kek_id 的值即 KeyRef().KeyID）
func (t *RewrapTarget) KeyRef() crypto.KeyRef { return t.provider.KeyRef() }
