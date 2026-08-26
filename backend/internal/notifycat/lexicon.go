package notifycat

import (
	"embed"
	"encoding/json"
	"fmt"
	"path"
	"sort"

	"github.com/custodexa/backend/internal/model"
)

// 短語詞庫。
//
// 與 event 目錄的分工：event 目錄渲染「一則通知」的 title/text；詞庫渲染
// 「一個機器碼的三語短語」——cause code、告警等級、阻斷標示這類值層枚舉。
// 兩者共用語系檔慣例（三語、embed、完備性守衛），但鍵空間互不重疊。
//
// 用法二選一：
//   - 直接呼叫 Phrase（buildSlackText 這類非 event 的組字點）。
//   - 在 ParamSpec 宣告 Lexicon，Render 插值時自動把值換成該語系短語
//     （cause_code 走此路，故模板寫 {cause_code} 而使用者看到的是短語）。
//
// 未知鍵一律回吐鍵本身（機器碼）而非空字串：通知寧可露出機器碼，不可缺字。

// Lexicon 詞庫識別字。
type Lexicon string

const (
	// LexiconCause 審計失效原因碼（值域＝model.Cause* 常數，守衛比對）
	LexiconCause Lexicon = "cause"
	// LexiconSeverity 告警等級（值域＝model.AlertSeverity* 常數，守衛比對）
	LexiconSeverity Lexicon = "severity"
	// LexiconAlertState 告警狀態標示（目前僅阻斷標示；無 model 對應常數）
	LexiconAlertState Lexicon = "alert_state"
	// LexiconDegraded 降級投遞的 generic 文案（RenderDegraded 用）。
	//
	// 為何走詞庫而非 locales 事件目錄：降級文案不是「某個
	// 事件」的模板，它必須在 event 未註冊時仍可用；而 checkCatalog 的鍵集
	// 雙向相等檢查（vExtraInLang ＋ 事件數比對）要求 locales 的鍵集恰等於
	// registry，塞一個 registry 沒有的 `_degraded` 進去即紅。詞庫的鍵空間
	// 與事件目錄互不重疊，且同樣受三語完備性守衛（checkLexicons）保護
	LexiconDegraded Lexicon = "degraded"
	// LexiconEntity 告警脈絡行的實體標籤（會話／使用者／資產）。
	//
	// 這三個標籤原為 alert_notifier.go 內的英文硬編碼，與該檔檔頭自述的
	// 「系統文案一律走 notifycat 的通道語系渲染」矛盾——收件人語系設為日文時，
	// 仍會讀到英文的 session／user／asset。改走詞庫後自動納入三語完備性守衛。
	//
	// **只收標籤，不收主體名稱**：使用者名與資產名是使用者資料，翻譯目錄不碰
	// （既有慣例，見 buildSlackText 檔頭）。
	LexiconEntity Lexicon = "entity"
)

// 實體標籤的詞庫鍵（值域即 lexicons/*.json 的 entity 區塊鍵集，受守衛比對）。
const (
	EntitySession = "session"
	EntityUser    = "user"
	EntityAsset   = "asset"
)

// AlertStateBlocked 阻斷型告警標示鍵（command_alert Slack 呈現用）。
const AlertStateBlocked = "blocked"

// 降級文案的詞庫鍵。text 帶 {event} 佔位符（唯一允許的插值），由
// RenderDegraded 以 interpolate 展開——降級路徑不吃 params 值。
const (
	DegradedKeyTitle = "title"
	DegradedKeyText  = "text"
)

// causeEnum 失效原因碼允許清單。與 mechanismEnum 同策略：引用 model 常數
// （改名即編譯失敗），新增未同步則由 TestCauseEnumMatchesModel 攔截。
var causeEnum = []string{
	model.CauseRecordingProbeFailed,
	model.CauseRecordingStartFailed,
	model.CauseRecordingFlushFailed,
	model.CauseRecordingWriteFailed,
	model.CauseRecordingResizeWriteFailed,
	model.CauseRecordingStopFailed,
	model.CauseRecordingFileStatFailed,
	model.CauseRecordingRenameFailed,
	model.CauseRecordingMetadataUpdateFailed,
	model.CauseRecordingFileMissing,
	model.CauseSessionRecordCreateFailed,
	model.CauseAuditWriteFallbackFile,
	model.CauseAuditWriteBatchDropped,
	model.CauseAuditWriteSyncRefused,
	model.CauseSyslogConnectFailed,
	model.CauseSyslogBufferOverflow,
	model.CauseKEKRetirementBacklog,
	model.CauseAADResidueImpossibleState,
	model.CauseCheckpointAnchorDropped,
	model.CauseAuditChainStructureInvalid,
	model.CauseAuditChainContentMismatch,
	model.CauseAuditChainContentExtraRows,
	model.CauseAuditChainVerifyFailed,
	model.CauseSourcePolicyUnreadable,
	model.CauseSourcePolicyCorrupt,
}

//go:embed lexicons/*.json
var lexiconFS embed.FS

// lexiconCat[lang][lexicon][key] → 短語。啟動時 init 載入並固化。
var lexiconCat = map[string]map[Lexicon]map[string]string{}

func init() {
	for _, lang := range SupportedLangs {
		raw, err := lexiconFS.ReadFile(path.Join("lexicons", lang+".json"))
		if err != nil {
			panic(fmt.Sprintf("notifycat: 載入詞庫 %s 失敗: %v", lang, err))
		}
		var parsed map[Lexicon]map[string]string
		if err := json.Unmarshal(raw, &parsed); err != nil {
			panic(fmt.Sprintf("notifycat: 解析詞庫 %s 失敗: %v", lang, err))
		}
		lexiconCat[lang] = parsed
	}
}

// Phrase 取短語；語系未支援即 fallback DefaultLang，詞庫或鍵缺失即回吐 key。
func Phrase(lang string, lex Lexicon, key string) string {
	if key == "" {
		return ""
	}
	byLex, ok := lexiconCat[resolveLang(lang)]
	if !ok {
		return key
	}
	if phrase := byLex[lex][key]; phrase != "" {
		return phrase
	}
	return key
}

// Lexicons 已宣告的詞庫清單（守衛與診斷用）。
func Lexicons() []Lexicon {
	return []Lexicon{LexiconCause, LexiconSeverity, LexiconAlertState, LexiconDegraded, LexiconEntity}
}

// CauseCodes 全部失效原因碼（順序穩定；守衛與診斷用）。
func CauseCodes() []string {
	out := append([]string(nil), causeEnum...)
	sort.Strings(out)
	return out
}
