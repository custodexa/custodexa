// Package kms 提供 AWS KMS 委託型 KEK provider（kek-provider-modularization D11／D11.1）。
//
// 本套件是 crypto.KEKProvider 的委託實作，與本地 AES provider 完全可互換：
// 上層（KeyManagerService 以上）看不到任何模式差異，差別全部封裝於此。
//
// **供應鏈立場（D11.1 裁決 3）**：一律採 AWS 官方 SDK v2，
// SHALL NOT 自建 SigV4 簽章與 KMS JSON 呼叫——自建簽章屬密碼學相鄰程式碼，
// 其維護成本與出錯後果遠高於一個官方維護的相依。
package kms

import (
	"fmt"
	"regexp"
	"strings"
)

// maxKeyARNLength key ARN 的長度上限。
//
// 實際的 KMS key ARN 最長約 90 字元（`arn:aws-us-gov:kms:<region>:<12>:key/<uuid>`）。
// 設 256 是留餘裕而非貼合——它的職責只是**在正規表示式之前先擋掉病態長字串**，
// 使「餵一段超長輸入進語法檢查」不會成為一條可探索的路徑。
const maxKeyARNLength = 256

// 語法零件（各段皆為封閉值域，D11.1 裁決 1「收窄三」＋round-4 codex med #3）。
//
// **為何逐段收窄**：原式的 partition／region 段都寫成 `[a-z0-9-]+`，
// 使 `arn:x:kms:-:000000000000:key/A` 這種**無意義但語法合格**的字串通過檢查。
// 「非正規偵測」的價值在於它是資料異常的最後一道判別，值域越寬、能混過去的
// 假 kek_id 就越多，故三段一律改為封閉列舉／固定形狀：
//
//	partition：AWS 目前公告的三個商用／主權雲分割（aws／aws-cn／aws-us-gov）；
//	region   ：`<2 字母>-<字母段>+-<1~2 位數>`（涵蓋 us-east-1、ap-northeast-1、
//	           cn-north-1、us-gov-west-1、ap-southeast-3 等實際形狀）；
//	資源     ：小寫 hex UUID 或多區域金鑰 `mrk-<32 位小寫 hex>`——KMS 的 key-id
//	           **只有**這兩種形狀，`key/A` 之類短字串一律非法。
//
// **收窄的誤殺風險已逐項確認為零**：合法的他把 ARN（退役 KEK、重包過渡期舊列）
// 必然由 KMS 自身產生，其三段必然落在上述值域內；
// TestValidateKeyIDSyntaxUsesARNGrammar 的正向格即釘住此點。
const (
	arnPartitionPattern = `(?:aws|aws-cn|aws-us-gov)`
	arnRegionPattern    = `[a-z]{2}(?:-[a-z]+)+-[0-9]{1,2}`
	arnAccountPattern   = `[0-9]{12}`
	arnKeyIDPattern     = `(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})`
)

// canonicalKeyARN KMS **key ARN** 的語法形式（D11.1 裁決 1「收窄三」）：
//
//	arn:<partition>:kms:<region>:<account>:key/<key-id>
//
// 刻意只認 `key/` 段：alias ARN（`…:alias/<name>`）與裸 key-id 皆非正規形式。
// key-id 段同時涵蓋一般金鑰（UUID）與多區域金鑰（`mrk-<32 hex>`）。
var canonicalKeyARN = regexp.MustCompile(
	`^arn:(` + arnPartitionPattern + `):kms:(` + arnRegionPattern + `):(` + arnAccountPattern + `):key/(` + arnKeyIDPattern + `)$`)

// KeyARNParts 正規 key ARN 的解析結果（各段皆已通過語法檢查）
type KeyARNParts struct {
	Partition string
	Region    string
	Account   string
	KeyID     string
}

// IsMultiRegion 該 key-id 是否為多區域金鑰（MRK）。
//
// **僅供診斷與已知限制的釘住之用，SHALL NOT 用於身分等價判定**——
// 見 provider.go「MRK 的已知限制」段：本版把 replica 視為另一把鑰。
func (p KeyARNParts) IsMultiRegion() bool { return strings.HasPrefix(p.KeyID, "mrk-") }

// ParseKeyARN 解析正規 key ARN；非正規形式回 ok=false。
//
// 這是本套件內**唯一**的 ARN 拆解入口：帳號信任範圍檢查（AccountScope）與
// 非正規偵測共用同一份語法，兩者不可能對「什麼算正規」有不同理解。
func ParseKeyARN(s string) (KeyARNParts, bool) {
	if len(s) > maxKeyARNLength {
		return KeyARNParts{}, false
	}
	m := canonicalKeyARN.FindStringSubmatch(s)
	if m == nil {
		return KeyARNParts{}, false
	}
	return KeyARNParts{Partition: m[1], Region: m[2], Account: m[3], KeyID: m[4]}, true
}

// IsCanonicalKeyARN 判定字串是否符合 KMS key ARN 語法。
//
// **這是「非正規」偵測的唯一判定式（D11.1 裁決 1 收窄三）**：
// SHALL NOT 以「不等於當前 KeyRef().KeyID」判定——後者會把**其他合法 KMS ARN**
// （退役 KEK、重包過渡期的舊列）一律誤殺。語法合格但非當前金鑰者屬正常存量，
// 由既有代表列篩選（key_manager_service.go 的 kek_id == env 過濾）處理，
// 不歸本檢查。
func IsCanonicalKeyARN(s string) bool {
	_, ok := ParseKeyARN(s)
	return ok
}

// AccountScope 部署端宣告的**信任帳號範圍**（round-4 codex high #1）。
//
// **要解的問題**：委託重包精靈的請求體只帶 `key_ref`，region／provider 沿用本行程
// 組態——但完整 ARN 仍可指定**同 region 的任意 AWS 帳號**。只要對方的 key policy
// 或 grant 放行，一次 API 呼叫就把全部 DEK 材料重包進外部信任域，而「不讓請求體
// 決定重包到哪個雲端帳號」正是原裁決 6 要防的事。region 沿用擋不住這件事。
//
// **信任範圍的來源＝部署組態，不是請求**：由 KEK_KMS_KEY_ID 所屬帳號推導
// （見 cmd/server/kek_provider.go 的 resolveTrustedAccountScope）。零值 Scope
// 代表「未宣告範圍」，此時 New 不做帳號檢查——啟動期建構的目標就是組態自身，
// 拿組態去驗組態沒有意義；檢查只施加於**請求可指定目標**的重包路徑。
type AccountScope struct {
	Partition string
	Account   string
}

// declared 是否已宣告信任範圍
func (s AccountScope) declared() bool { return s.Account != "" && s.Partition != "" }

// permits 目標 ARN 是否落在信任範圍內
func (s AccountScope) permits(p KeyARNParts) bool {
	return p.Partition == s.Partition && p.Account == s.Account
}

// String 人可讀形式（帳號 ID 非機密，可入錯誤訊息與稽核）
func (s AccountScope) String() string { return s.Partition + ":" + s.Account }

// ValidateKeyIDSyntax 實作 crypto.KeyIDSyntaxValidator：判定既有 kek_id 是否為
// 本 provider 認可的正規形式。
//
// **本方法只判語法、不判歸屬**：回 nil 不代表該 kek_id 指向本 provider 的金鑰，
// 只代表它是一個語法合格的 KMS key ARN。歸屬由代表列篩選與實際解包成功承擔
// （D4／1.5 的判準優先序）。
func (p *Provider) ValidateKeyIDSyntax(keyID string) error {
	if IsCanonicalKeyARN(keyID) {
		return nil
	}
	return fmt.Errorf("%w（值 %q 不符 arn:<partition>:kms:<region>:<account>:key/<key-id> 語法；"+
		"partition 限 aws／aws-cn／aws-us-gov，key-id 限 UUID 或 mrk-<32 hex>）",
		ErrKeyIDNotCanonical, keyID)
}
