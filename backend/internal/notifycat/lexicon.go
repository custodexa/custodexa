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
	// LexiconCause 稽核失效原因碼（值域＝model.Cause* 常數，守衛比對）
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
	// LexiconRotationReport 資產帳號輪替證據報告的版面文案（標題、表頭、狀態桶名、
	// 口徑說明）。
	//
	// 為何走詞庫而非事件目錄：這些字不屬於任何一則通知，它們印在會離開系統的
	// 產物上——報告的語言由排程或請求指定，而三語齊備由既有守衛保證。
	// 後端零散文出站的原則在此同樣適用：Go 檔內不得出現這些字面。
	LexiconRotationReport Lexicon = "rotation_report"
	// LexiconComplianceReport 合規對照報告的版面文案（封面、範圍聲明、摘要、
	// 表頭、結果與條文型別的說法、口徑）。理由同 LexiconRotationReport：印在會
	// 離開系統的產物上，語言由請求指定，三語齊備由既有守衛保證。
	LexiconComplianceReport Lexicon = "compliance_report"
	// LexiconAlertKind 非規則類告警的白話標題（值域＝model 中 rule 以外的 AlertKind* 常數）。
	//
	// 這些類別沒有規則名可顯示：rule_name 存的是機器碼、指令欄刻意為空。
	// 通知若照規則類版型組字，收件人會看到機器碼標題與空的指令區塊。
	LexiconAlertKind Lexicon = "alert_kind"
	// LexiconAlertKindText 非規則類告警的說明句：發生了什麼、去哪裡看（值域同上）。
	LexiconAlertKindText Lexicon = "alert_kind_text"
	// LexiconDegradeReason 指令降級原因碼的白話情境句（值域＝model.Degrade* 常數）。
	//
	// 只描述事實，不斷言成因（例如「沒有回顯」不等於「對端關閉了回顯」）。
	LexiconDegradeReason Lexicon = "degrade_reason"
	// LexiconDateList 日期清單參數的附註（清單只帶最早的若干個時，「另有 N 天」）。
	// 短語內的 {n} 由渲染端代入，不經事件模板的插值
	LexiconDateList Lexicon = "date_list"
	// LexiconHostKeyOutcome 主機金鑰不符的處置（allowed＝已放行且平台已代為送出登入憑證；refused＝已拒絕未送出）
	LexiconHostKeyOutcome Lexicon = "host_key_outcome"
	// LexiconHostKeyPath 主機金鑰不符發生的撥號路徑
	LexiconHostKeyPath Lexicon = "host_key_path"
	// LexiconCredentialAttachEntry 以 API token 掛載既有憑證的掛載方式（入口）
	LexiconCredentialAttachEntry Lexicon = "credential_attach_entry"
	// LexiconAPITokenLevel API token 授權角色的層級短語（read、read_write），與 ParamSpec.Levels 的
	// 渲染格式：item 為一項的寫法（{role}、{level} 由渲染端代入），sep 為項與項之間的分隔符
	LexiconAPITokenLevel Lexicon = "api_token_level"
	// LexiconMechanism 稽核機制名稱（鍵＝mechanismEnum）
	LexiconMechanism Lexicon = "mechanism"
	// LexiconDeliveryReason 投遞失敗與放棄的原因語句（鍵＝deliveryReasonEnum；已遮蔽、不含網址與秘密）
	LexiconDeliveryReason Lexicon = "delivery_reason"
	// LexiconNotifyFooter Slack 文字最後一行的固定詞：發生時間、前往處理、前往查看
	LexiconNotifyFooter Lexicon = "notify_footer"
	// LexiconRotationAlertKind 改密工作提醒的種類（鍵＝rotationAlertKindEnum）
	LexiconRotationAlertKind Lexicon = "rotation_alert_kind"
	// 系統安全告警中原樣進句子的列舉參數（各自一個詞庫，鍵集＝該參數的允許清單）
	LexiconPolicyRelaxType     Lexicon = "policy_relax_type"
	LexiconCustomSecretEntry   Lexicon = "custom_secret_entry"
	LexiconIdentitySourceKind  Lexicon = "identity_source_kind"
	LexiconYesNo               Lexicon = "yes_no"
	LexiconSecurityAdminAction Lexicon = "security_admin_action"
	LexiconRetentionDataClass  Lexicon = "retention_data_class"
	LexiconOffsiteSubject      Lexicon = "offsite_subject"
	LexiconOffsiteChange       Lexicon = "offsite_change"
	LexiconHostKeyRecordSource Lexicon = "host_key_record_source"
	LexiconHostKeyRecordChange Lexicon = "host_key_record_change"
	LexiconChannelChange       Lexicon = "channel_change"
	LexiconPeersQuery          Lexicon = "peers_query"
	LexiconConfirmSource       Lexicon = "confirm_source"
	LexiconIdentityMode        Lexicon = "identity_mode"
	// LexiconAccessTier 存取政策的段位（open、reason、approval）
	LexiconAccessTier Lexicon = "access_tier"
	// LexiconAssetField 資產的位址與傳輸設定欄位（位址變更與傳輸驗證放寬的欄位清單，ParamSpec.List）
	LexiconAssetField Lexicon = "asset_field"
	// LexiconChannelField 通知通道的欄位（通道變更的欄位清單，ParamSpec.List）
	LexiconChannelField Lexicon = "channel_field"
	// LexiconIdentitySourceField 身分來源（目錄服務、OIDC）的欄位（身分來源變更的欄位清單，ParamSpec.List）
	LexiconIdentitySourceField Lexicon = "identity_source_field"
	// LexiconListFormat 清單渲染的版面詞：sep 為項與項之間的分隔符
	LexiconListFormat Lexicon = "list_format"
	// LexiconDuration 時長的寫法（ParamSpec.Duration）：hour／hours 含 {h}、minute／minutes 含 {m}，
	// combined 是小時加分鐘的寫法（{hours}、{minutes} 代入前兩者）
	LexiconDuration Lexicon = "duration"
	// LexiconDMTitle 個人訊息第一行的定向標題（鍵＝TargetedEventKinds 的標題種類：access_request、break_glass、
	// daily_review），接在原標題之前
	LexiconDMTitle Lexicon = "dm_title"
	// LexiconDMUndeliveredReason 個人訊息未能送達的原因句（鍵＝TargetedUndeliveredReasons）
	LexiconDMUndeliveredReason Lexicon = "dm_undelivered_reason"
	// LexiconDMEventKind 個人訊息未能送達時的事件種類（鍵＝TargetedEventKinds）
	LexiconDMEventKind Lexicon = "dm_event_kind"
	// LexiconDMAutoOff 對個人派送被自動關閉的原因句（通道變更告警的 dm_auto_off 參數）
	LexiconDMAutoOff Lexicon = "dm_auto_off"
)

// 個人訊息未能送達的原因（targeted_notification_undelivered 的 reason 參數）。
const (
	TargetedReasonNoEmail           = "no_email"
	TargetedReasonEmailAmbiguous    = "email_ambiguous"
	TargetedReasonRecipientNotFound = "recipient_not_found"
	TargetedReasonMaxAttempts       = "max_attempts"
	TargetedReasonRateLimited       = "rate_limited"
	TargetedReasonNoRecipient       = "no_recipient"
	TargetedReasonResolveFailed     = "resolve_failed"
)

// TargetedUndeliveredReasons 個人訊息未能送達的原因代碼（順序穩定）。
func TargetedUndeliveredReasons() []string {
	return []string{TargetedReasonNoEmail, TargetedReasonEmailAmbiguous, TargetedReasonRecipientNotFound,
		TargetedReasonMaxAttempts, TargetedReasonRateLimited, TargetedReasonNoRecipient, TargetedReasonResolveFailed}
}

// 送個人訊息的事件種類（未能送達事件的 event_kind 參數）。
const (
	TargetedKindAccessRequest     = "access_request"
	TargetedKindBreakGlass        = "break_glass"
	TargetedKindBreakGlassOverdue = "break_glass_overdue"
	TargetedKindDailyReview       = "daily_review"
)

// TargetedEventKinds 送個人訊息的事件種類（順序穩定）。
func TargetedEventKinds() []string {
	return []string{TargetedKindAccessRequest, TargetedKindBreakGlass, TargetedKindBreakGlassOverdue, TargetedKindDailyReview}
}

// 對個人派送被自動關閉的原因（通道變更告警的 dm_auto_off 參數）。
const (
	DMAutoOffHost = "host"
	DMAutoOffType = "type"
)

// LexiconListFormat 的鍵。
const ListFormatKeySep = "sep"

// LexiconDuration 的鍵。
const (
	DurationKeyHour     = "hour"
	DurationKeyHours    = "hours"
	DurationKeyMinute   = "minute"
	DurationKeyMinutes  = "minutes"
	DurationKeyCombined = "combined"
)

// LexiconNotifyFooter 的鍵。
const (
	NotifyFooterKeyOccurred = "occurred"
	NotifyFooterKeyAction   = "action"
	NotifyFooterKeyView     = "view"
)

// deliveryReasonEnum 投遞失敗與放棄的原因代碼（通知投遞已放棄的 reason 參數；畫面以同一組代碼查譯）。
var deliveryReasonEnum = []string{
	"http_404", "http_401", "http_5xx", "http_other", "timeout", "connect",
	"slack_channel", "slack_not_in", "slack_auth", "slack_scope", "slack_rate", "slack_other",
	"snapshot_unreadable", "channel_unreadable", "policy",
	"redirect_not_followed", "redirect_policy", "redirect_too_many",
	"rate_limited", "type_unregistered", "render_failed",
}

// DeliveryReasonCodes 回傳投遞原因代碼的副本（投遞層與守衛用）。
func DeliveryReasonCodes() []string {
	return append([]string(nil), deliveryReasonEnum...)
}

// API token 層級詞庫的版面鍵（層級值本身即 read、read_write 兩鍵）
const (
	APITokenLevelKeyItem = "item"
	APITokenLevelKeySep  = "sep"
)

// DateListKeyMore 「另有 N 天」的詞庫鍵
const DateListKeyMore = "more"

// 實體標籤的詞庫鍵（值域即 lexicons/*.json 的 entity 區塊鍵集，受守衛比對）。
const (
	EntitySession = "session"
	EntityUser    = "user"
	EntityAsset   = "asset"
	// EntitySourceIP 來源位址標籤（新來源位址告警的說明行用）
	EntitySourceIP = "source_ip"
)

// AlertStateBlocked 阻斷型告警標示鍵（command_alert Slack 呈現用）。
const AlertStateBlocked = "blocked"

// AlertStatePossibleSensitive is deliberately heuristic, never a certainty claim.
const AlertStatePossibleSensitive = "possible_sensitive_output"

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
	model.CauseHostKeyMismatchRecordFailed,
	model.CauseAuditWriteFallbackFile,
	model.CauseAuditWriteBatchDropped,
	model.CauseAuditWriteSyncRefused,
	model.CauseSensitiveRevealAlertWriteFailed,
	model.CauseCommandAuditWriteRefused,
	model.CauseCommandBlockerUnavailable,
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
	model.CauseOffsiteUploadFailed,
	model.CauseOffsiteUploadStalled,
	model.CauseOffsiteIntegrityMismatch,
	model.CauseRoleStateMismatch,
	model.CausePrincipalStateMismatch,
	model.CauseDEKUnwrapFailed,
	model.CauseRestoreSealDeferred,
	model.CauseRestoreSealStateUnreadable,
	model.CauseKeystrokeDirUnwritable,
	model.CauseKeystrokeKeySealFailed,
	model.CauseKeystrokeFileCreateFailed,
	model.CauseKeystrokeWriteFailed,
	model.CauseKeystrokeWriterStalled,
	model.CauseNotificationEnqueueFailed,
	model.CauseNotificationDispatchFailed,
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

// LexiconEntries 某語系某詞庫的全部詞條（複本；語系未支援即 DefaultLang）。
//
// 供產物層的措辭守衛逐條掃描（例如報告不得出現某類說法）；呼叫端改動回傳值
// 不影響詞庫本身。
func LexiconEntries(lang string, lex Lexicon) map[string]string {
	out := map[string]string{}
	for k, v := range lexiconCat[resolveLang(lang)][lex] {
		out[k] = v
	}
	return out
}

// Lexicons 已宣告的詞庫清單（守衛與診斷用）。
func Lexicons() []Lexicon {
	return []Lexicon{LexiconCause, LexiconSeverity, LexiconAlertState, LexiconDegraded,
		LexiconEntity, LexiconRotationReport, LexiconComplianceReport, LexiconAlertKind,
		LexiconAlertKindText, LexiconDegradeReason, LexiconDateList, LexiconHostKeyOutcome, LexiconHostKeyPath,
		LexiconCredentialAttachEntry, LexiconAPITokenLevel, LexiconMechanism, LexiconDeliveryReason,
		LexiconNotifyFooter, LexiconPolicyRelaxType, LexiconCustomSecretEntry, LexiconIdentitySourceKind,
		LexiconYesNo, LexiconSecurityAdminAction, LexiconRetentionDataClass, LexiconOffsiteSubject,
		LexiconOffsiteChange, LexiconHostKeyRecordSource, LexiconHostKeyRecordChange, LexiconChannelChange,
		LexiconPeersQuery, LexiconConfirmSource, LexiconIdentityMode, LexiconRotationAlertKind,
		LexiconAccessTier, LexiconAssetField, LexiconChannelField, LexiconIdentitySourceField,
		LexiconListFormat, LexiconDuration, LexiconDMTitle, LexiconDMUndeliveredReason, LexiconDMEventKind,
		LexiconDMAutoOff}
}

// CauseCodes 全部失效原因碼（順序穩定；守衛與診斷用）。
func CauseCodes() []string {
	out := append([]string(nil), causeEnum...)
	sort.Strings(out)
	return out
}
