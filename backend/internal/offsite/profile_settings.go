package offsite

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/custodexa/backend/internal/model"
)

// 離機儲存設定的**單一驗證核心**與其拒因值域。
//
// 獨立成檔的理由：`Save` 與 `ConfirmGenerationSwitch` 兩條寫入路徑必須呼叫**同一個**
// 函式。若 confirm 有自己的簡化路徑，「先 Save 被拒、再直接打 confirm 端點」
// 就是一條真正的繞過路徑——那不是理論風險，confirm 收的是完整的新設定。
// AST 守衛 TestOffsiteConfirmUsesSharedValidationCore 釘住這件事。

// 靜態拒因（恆為常數，不回填使用者輸入；供 apierror 對照表與 i18n）。
const (
	// ReasonCredentialConflict 同時提供新憑證與清除旗標——兩個互斥意圖同時出現，
	// 服務層無從裁決哪個是使用者真意
	ReasonCredentialConflict = "offsite.credential_conflict"
	// ReasonProviderInvalid provider 不在枚舉內
	ReasonProviderInvalid = "offsite.provider_invalid"
	// ReasonBucketRequired bucket 為空
	ReasonBucketRequired = "offsite.bucket_required"
	// ReasonEndpointInvalid 端點不是合法 http(s) URL、或缺主機名
	ReasonEndpointInvalid = "offsite.endpoint_invalid"
	// ReasonEndpointHasSecrets 端點含 userinfo／query／fragment。
	// **訊息與審計皆不回顯值**：被拒的三種成分正是秘密唯一可能的藏身之處
	ReasonEndpointHasSecrets = "offsite.endpoint_has_secrets"
	// ReasonRegionOrEndpointRequired s3 且端點與 region 皆空
	// （SDK 無 region 解析不出 AWS 預設端點）
	ReasonRegionOrEndpointRequired = "offsite.region_or_endpoint_required"
	// ReasonCredentialHalfSet s3 靜態憑證只給一半（兩鍵須同設，或兩鍵皆空走預設鏈）
	ReasonCredentialHalfSet = "offsite.credential_half_set"
	// ReasonCredentialReuseOnMove 落點（provider／端點／bucket）變更而憑證欄留空。
	//
	// **為何不能讓「空＝沿用」跨落點生效**：被劫持的 admin session 可先把 bucket
	// 改成自控位址並沿用既存憑證，再由上傳路徑把既存憑證送往新位址。
	// 既存世代無憑證時不套此規則——那時根本沒有憑證可被沿用
	ReasonCredentialReuseOnMove = "offsite.credential_reuse_on_move"
	// ReasonStaleConfirmation 確認請求所依據的現行世代已被其他操作變更。
	// **訊息不回顯現況細節**（不說現在是哪個 bucket／端點）
	ReasonStaleConfirmation = "offsite.settings_stale_confirmation"
	// ReasonDigestMismatch 攜回的設定摘要與請求體不符（確認畫面顯示 A、送出卻是 B）
	ReasonDigestMismatch = "offsite.settings_digest_mismatch"
	// ReasonNoCurrentGeneration 目前無現行世代（停止離機時已無可退役的世代）
	ReasonNoCurrentGeneration = "offsite.no_current_generation"
	// ReasonGenerationNotFound 指定的世代不存在
	ReasonGenerationNotFound = "offsite.generation_not_found"
	// ReasonCredentialsAlreadyRevoked 該世代的憑證已撤銷（冪等提示，非錯誤語義）
	ReasonCredentialsAlreadyRevoked = "offsite.credentials_already_revoked"
	// ReasonEncryptFailed 憑證加密失敗（金鑰事故）。**靜態哨兵**：codec 的底層錯誤
	// 可能夾帶明文片段，不得 %w 包裝進錯誤鏈
	ReasonEncryptFailed = "offsite.credential_encrypt_failed"
	// ReasonDecryptFailed 憑證解密失敗（金鑰事故，非設定錯誤）。同上不 %w
	ReasonDecryptFailed = "offsite.credential_decrypt_failed"
	// ReasonGCSCredentialInvalid gcs 憑證不是可用的服務帳號金鑰 JSON
	// （type、必要欄位或 token_uri 不符）。Detail 只帶欄位名，**不回顯值**
	ReasonGCSCredentialInvalid = "offsite.gcs_credential_invalid"
	// ReasonGCSEndpointNeedsCredential gcs 本次結果不帶顯式服務帳號憑證，
	// 而端點不是空值或 Google 官方網域。**訊息不回顯端點值**
	ReasonGCSEndpointNeedsCredential = "offsite.gcs_endpoint_needs_credential"
)

// AllSettingsReasons 全部靜態拒因（供 apierror 對照表的雙向 Exhaustive 守衛）。
func AllSettingsReasons() []string {
	return []string{
		ReasonCredentialConflict, ReasonProviderInvalid, ReasonBucketRequired,
		ReasonEndpointInvalid, ReasonEndpointHasSecrets, ReasonRegionOrEndpointRequired,
		ReasonCredentialHalfSet, ReasonCredentialReuseOnMove, ReasonStaleConfirmation,
		ReasonDigestMismatch, ReasonNoCurrentGeneration, ReasonGenerationNotFound,
		ReasonCredentialsAlreadyRevoked, ReasonEncryptFailed, ReasonDecryptFailed,
		ReasonGCSCredentialInvalid, ReasonGCSEndpointNeedsCredential,
	}
}

// SettingsError 帶靜態拒因的設定錯誤。
//
// `Error()` 只印**靜態句**：任何使用者輸入（端點值、bucket 名、憑證）一律不進
// 錯誤鏈——錯誤鏈會順著 log.Printf("%v") 流進 operational log。
type SettingsError struct {
	Reason string
	// Detail 次級靜態原因（如端點被拒的成分種類），恆取自常數，**不含值**
	Detail string
}

func (e *SettingsError) Error() string {
	if e.Detail != "" {
		return "離機儲存設定被拒：" + e.Reason + "（" + e.Detail + "）"
	}
	return "離機儲存設定被拒：" + e.Reason
}

func reject(reason string) error { return &SettingsError{Reason: reason} }

func rejectWith(reason, detail string) error { return &SettingsError{Reason: reason, Detail: detail} }

// ReasonOf 取錯誤的靜態拒因；非設定錯誤回空字串。
func ReasonOf(err error) string {
	var se *SettingsError
	if errors.As(err, &se) {
		return se.Reason
	}
	return ""
}

// DetailOf 取錯誤的次級靜態原因（如被拒的欄位名）；非設定錯誤或無次級原因回空字串。
func DetailOf(err error) string {
	var se *SettingsError
	if errors.As(err, &se) {
		return se.Detail
	}
	return ""
}

// SettingsInput 設定寫入的請求形狀（write-only 憑證欄）。
//
// **憑證欄的三種意圖**：填值＝設定新憑證；`ClearCredentials`＝改走 SDK 預設鏈；
// 兩者皆無＝沿用既存（僅在落點未變時成立）。讀取 DTO 恆不回填憑證，
// 故前端無從把既存值送回來。
type SettingsInput struct {
	Provider  string
	Endpoint  string
	Bucket    string
	Prefix    string
	Region    string
	PathStyle bool

	// AccessKeyID／SecretAccessKey s3 靜態憑證（兩者須同設或同空）
	AccessKeyID     string
	SecretAccessKey string
	// ServiceAccountJSON gcs service account JSON **原文**
	ServiceAccountJSON string
	// ClearCredentials 顯式改走 SDK 預設鏈／ADC；與非空憑證併用即拒
	ClearCredentials bool
}

// normalizedSettings 驗證核心的產物（**唯一**可用於寫列與算指紋的形狀）。
type normalizedSettings struct {
	Provider string
	// EndpointFull 正規化完整端點（含 path）；空＝未指定
	EndpointFull string
	// EndpointOrigin 顯示與審計用（不含 path）
	EndpointOrigin string
	Bucket         string
	Prefix         string
	Region         string
	PathStyle      bool

	// credentialIntent new／clear／reuse
	credentialIntent string
	// credentialPlain 待加密的憑證明文（intent=new 時非空）
	credentialPlain string
}

const (
	credIntentNew   = "new"
	credIntentClear = "clear"
	credIntentReuse = "reuse"
)

// existingCredentialState 驗證核心需要的既存現行世代資訊：只帶「是否存在、provider、
// 憑證來源模式」，**不帶憑證明文**。
//
// 表單的「憑證欄留空」有三種意義（沿用保存型憑證、沿用預設憑證鏈、首次設定），
// 光看表單值分不出來；「本次結果是否帶顯式服務帳號憑證」要靠這份狀態判定。
// 呼叫端在鎖內讀到現行列後以 existingStateOf 轉出；seed 傳零值＝無既存世代。
type existingCredentialState struct {
	// exists 現行世代是否存在
	exists bool
	// provider 現行世代的 provider
	provider string
	// mode 現行世代的憑證來源模式（model.OffsiteCredential*）
	mode string
}

// existingStateOf 由現行世代列取出驗證核心需要的狀態（row 為 nil＝無現行世代）。
func existingStateOf(row *model.OffsiteProfile) existingCredentialState {
	if row == nil {
		return existingCredentialState{}
	}
	return existingCredentialState{exists: true, provider: row.Provider, mode: row.CredentialMode}
}

// carriesExplicitCredential 本次結果是否會帶顯式憑證。
//
// 新填入憑證＝是；清除旗標＝否；留空沿用時，只有既存現行世代為保存型才有憑證可沿用
// （同落點由 checkCredentialReuse 另行保證），其餘（預設憑證鏈、已撤銷、無世代）
// 沿用到的都不是顯式憑證。
func (e existingCredentialState) carriesExplicitCredential(intent string) bool {
	switch intent {
	case credIntentNew:
		return true
	case credIntentReuse:
		return e.exists && e.mode == model.OffsiteCredentialStored
	default:
		return false
	}
}

// validateAndNormalizeOffsiteSettings 設定的**單一驗證與正規化核心**。
//
// `Save` 與 `ConfirmGenerationSwitch` 兩條路徑都呼叫本函式，confirm **不得**有
// 簡化路徑（AST 守衛釘住）。落點變更拒沿用憑證的判定不在此處——它需要既存列，
// 屬鎖內步驟 (3)。existing 為既存現行世代的憑證狀態（見 existingCredentialState）。
func validateAndNormalizeOffsiteSettings(in SettingsInput, existing existingCredentialState) (normalizedSettings, error) {
	var out normalizedSettings

	// (1) 憑證輸入衝突：兩個互斥意圖同時出現
	hasNewCred := in.AccessKeyID != "" || in.SecretAccessKey != "" || in.ServiceAccountJSON != ""
	if hasNewCred && in.ClearCredentials {
		return out, reject(ReasonCredentialConflict)
	}

	// (2) provider 枚舉
	provider := strings.TrimSpace(in.Provider)
	if provider == "" {
		provider = ProviderS3
	}
	if provider != ProviderS3 && provider != ProviderGCS {
		return out, reject(ReasonProviderInvalid)
	}
	out.Provider = provider

	// (3) bucket 非空
	out.Bucket = strings.TrimSpace(in.Bucket)
	if out.Bucket == "" {
		return out, reject(ReasonBucketRequired)
	}
	out.Prefix = strings.Trim(strings.TrimSpace(in.Prefix), "/")
	out.PathStyle = in.PathStyle

	// (4) 端點淨化——訊息與拒因**不回顯值**
	endpoint := strings.TrimSpace(in.Endpoint)
	if endpoint != "" {
		reason, ok := ValidateEndpoint(endpoint)
		if !ok {
			switch reason {
			case EndpointRejectUserinfo, EndpointRejectQuery, EndpointRejectFragment:
				return out, rejectWith(ReasonEndpointHasSecrets, string(reason))
			default:
				return out, rejectWith(ReasonEndpointInvalid, string(reason))
			}
		}
		full, _ := NormalizeEndpointFull(endpoint)
		out.EndpointFull = full
		out.EndpointOrigin = NormalizeEndpointOrigin(endpoint)
	}

	// (5) provider 專屬約束
	switch provider {
	case ProviderS3:
		out.Region = strings.TrimSpace(in.Region)
		if (in.AccessKeyID == "") != (in.SecretAccessKey == "") {
			return out, reject(ReasonCredentialHalfSet)
		}
		if out.EndpointFull == "" && out.Region == "" {
			return out, reject(ReasonRegionOrEndpointRequired)
		}
	case ProviderGCS:
		// region 於 gcs 恆空（指紋成分固定；填了也不會被使用，正規化即抹除，
		// 否則同一組設定會因表單殘值算出不同指紋而誤觸世代切換）
		out.Region = ""
	}

	// (6) 憑證意圖與明文
	switch {
	case in.ClearCredentials:
		out.credentialIntent = credIntentClear
	case hasNewCred:
		out.credentialIntent = credIntentNew
		plain, err := marshalCredentials(provider, in)
		if err != nil {
			return out, err
		}
		out.credentialPlain = plain
	default:
		out.credentialIntent = credIntentReuse
	}

	// (7) gcs 憑證內容與端點邊界：受管憑證與平台自身的雲端身分只用在設定所指的目標上
	if provider == ProviderGCS {
		if out.credentialIntent == credIntentNew {
			if err := validateGCSServiceAccountJSON(out.credentialPlain); err != nil {
				return out, err
			}
		}
		if !existing.carriesExplicitCredential(out.credentialIntent) &&
			!gcsEndpointIsEmptyOrOfficial(out.EndpointFull) {
			return out, reject(ReasonGCSEndpointNeedsCredential)
		}
	}
	return out, nil
}

// gcsOfficialTokenURI 服務帳號金鑰 JSON 允許的權杖端點（唯一值）。
const gcsOfficialTokenURI = "https://oauth2.googleapis.com/token"

// validateGCSServiceAccountJSON gcs 憑證內容檢查（驗證核心與客戶端建構共用）。
//
// 只接受 Google 服務帳號金鑰：`type` 為 service_account，`client_email`、
// `private_key`、`token_uri` 皆存在，且 `token_uri` 等於官方權杖端點。
// 其他型別的憑證一律拒絕。
// **回傳的錯誤只帶欄位名，不含任何值。**
func validateGCSServiceAccountJSON(plain string) error {
	var doc map[string]any
	if err := json.Unmarshal([]byte(plain), &doc); err != nil {
		return rejectWith(ReasonGCSCredentialInvalid, "json")
	}
	str := func(k string) string {
		v, _ := doc[k].(string)
		return strings.TrimSpace(v)
	}
	if str("type") != "service_account" {
		return rejectWith(ReasonGCSCredentialInvalid, "type")
	}
	for _, k := range []string{"client_email", "private_key", "token_uri"} {
		if str(k) == "" {
			return rejectWith(ReasonGCSCredentialInvalid, k)
		}
	}
	if str("token_uri") != gcsOfficialTokenURI {
		return rejectWith(ReasonGCSCredentialInvalid, "token_uri")
	}
	return nil
}

// gcsEndpointIsEmptyOrOfficial 端點為空，或主機屬 googleapis.com 及其子網域。
func gcsEndpointIsEmptyOrOfficial(endpoint string) bool {
	if endpoint == "" {
		return true
	}
	return gcsHostIsOfficial(endpoint)
}

// gcsHostIsOfficial 端點的主機是否屬 googleapis.com 及其子網域（解析失敗視為否）。
func gcsHostIsOfficial(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return host == "googleapis.com" || strings.HasSuffix(host, ".googleapis.com")
}

// storedCredentials s3 憑證的密文內容形狀（gcs 直接存 SA JSON 原文，不套本結構）。
type storedCredentials struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
}

// marshalCredentials 依 provider 產出待加密的明文。
func marshalCredentials(provider string, in SettingsInput) (string, error) {
	if provider == ProviderGCS {
		// gcs＝service account JSON **原文**（SDK 的 WithCredentialsJSON 直接吃它）
		return in.ServiceAccountJSON, nil
	}
	b, err := json.Marshal(storedCredentials{
		AccessKeyID: in.AccessKeyID, SecretAccessKey: in.SecretAccessKey,
	})
	if err != nil {
		// 不 %w：序列化錯誤的訊息會含被序列化的值
		return "", reject(ReasonEncryptFailed)
	}
	return string(b), nil
}

// unmarshalCredentials 依 provider 由明文取出 driver 需要的欄位。
// **不回傳錯誤細節**：解析失敗只可能是密文內容損壞，訊息不得含明文片段。
func unmarshalCredentials(provider, plain string) (storedCredentials, string, bool) {
	if provider == ProviderGCS {
		return storedCredentials{}, plain, plain != ""
	}
	var sc storedCredentials
	if err := json.Unmarshal([]byte(plain), &sc); err != nil {
		return storedCredentials{}, "", false
	}
	return sc, "", sc.AccessKeyID != "" && sc.SecretAccessKey != ""
}

// fingerprintOf 由正規化設定算指紋（指紋成分）。
func (n normalizedSettings) fingerprintOf() string {
	return ComputeProfileID(n.Provider, FingerprintEndpointToken(n.Provider, n.EndpointFull),
		n.Bucket, n.Prefix, n.Region)
}

// settingsDigest 世代切換確認的綁定摘要（防過期確認與 TOCTOU）。
//
// 涵蓋**正規化後**的六個連線參數與憑證意圖——後者不可省：同一組連線參數配
// 「帶新憑證」與「沿用」是兩個不同的請求，確認畫面顯示的是其中一個。
// **不含憑證值本身**（摘要會被原樣攜回前端，值進去就等於把憑證帶出門）。
func (n normalizedSettings) settingsDigest() string {
	payload := strings.Join([]string{
		n.Provider, n.EndpointFull, n.Bucket, n.Prefix, n.Region,
		fmt.Sprintf("%t", n.PathStyle), n.credentialIntent,
	}, "\n")
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}
