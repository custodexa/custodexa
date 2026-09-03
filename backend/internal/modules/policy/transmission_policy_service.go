package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/custodexa/backend/internal/model"
)

// 傳輸通道識別：政策鍵、清冊與 API 共用
const (
	TransportChannelRDP    = "rdp"
	TransportChannelVNC    = "vnc"
	TransportChannelDB     = "db"
	TransportChannelLDAP   = "ldap"
	TransportChannelSyslog = "syslog"
	TransportChannelNotify = "notify"
	// TransportChannelWinRM 改密通道（系統路徑，不經使用者連線）：資產改密通道設為
	// WinRM 時，該資產同時受其連線協議通道與本通道管轄，清冊分列。無政策鍵——
	// 改密不走 connect-token 閘，等級對它沒有可作用的攔截點
	TransportChannelWinRM = "winrm"
)

// 風險項鍵（穩定識別，供 fingerprint 與前端呈現；label 變動不影響既有同意）
const (
	RiskRDPIgnoreCert       = "rdp_ignore_cert"
	RiskRDPSecurityBelowNLA = "rdp_security_below_nla"
	RiskVNCUnencrypted      = "vnc_unencrypted"
	RiskDBTLSDisabled       = "db_tls_disabled"
	RiskLDAPPlaintext       = "ldap_plaintext"
	RiskLDAPSkipVerify      = "ldap_skip_verify"
	RiskSyslogNonTLS        = "syslog_non_tls"
	RiskNotifyHTTP          = "notify_http"
	// RiskWinRMHTTPNTLM WinRM 改密通道走 http：載荷有 NTLM 訊息層加密，但沒有 TLS
	RiskWinRMHTTPNTLM = "winrm_http_ntlm"
	// RiskWinRMTLSInsecure WinRM 改密通道走 https 但不驗證伺服器憑證
	RiskWinRMTLSInsecure = "winrm_tls_insecure"
)

// RiskItem 一項傳輸風險（型別定義在 model.TransmissionRisk——資產列表
// transient 欄位與判定核心共用同一型別，避免兩處結構漂移）
type RiskItem = model.TransmissionRisk

// ── 後端顯示字串 i18n 共用基建──────────────────────
// 三類後端顯示字串（risk label、inventory note/preflight）皆錨定穩定機器碼、
// 保留 zh 為 fallback；前端以碼查譯。此處為 risk 與 inventory 共用的 template
// 驗證與內插——registry 註冊時雙向驗證 {placeholder} 集合恰等於 RequiredParams。

// displayPlaceholderRe 比對 zh template 的 {name} 插值槽
var displayPlaceholderRe = regexp.MustCompile(`\{([a-zA-Z_][a-zA-Z0-9_]*)\}`)

// templatePlaceholders 取 template 的 {name} 集合
func templatePlaceholders(tmpl string) map[string]bool {
	set := map[string]bool{}
	for _, m := range displayPlaceholderRe.FindAllStringSubmatch(tmpl, -1) {
		set[m[1]] = true
	}
	return set
}

// validateTemplateParams 註冊時雙向驗證：template 的 {placeholder} 集合恰等於
// required；required 無空/重複。共用於 risk 與 inventory registry。
func validateTemplateParams(kind, code, tmpl string, required []string) error {
	reqSet := map[string]bool{}
	for _, p := range required {
		if p == "" {
			return fmt.Errorf("%s %q: required param 名為空", kind, code)
		}
		if reqSet[p] {
			return fmt.Errorf("%s %q: required param %q 重複", kind, code, p)
		}
		reqSet[p] = true
	}
	phSet := templatePlaceholders(tmpl)
	for p := range reqSet {
		if !phSet[p] {
			return fmt.Errorf("%s %q: required param %q 不在 template", kind, code, p)
		}
	}
	for p := range phSet {
		if !reqSet[p] {
			return fmt.Errorf("%s %q: template placeholder %q 未宣告 required", kind, code, p)
		}
	}
	return nil
}

// interpolateTemplate 以 params 替換 template 的 {name}（假設已驗齊全）
func interpolateTemplate(tmpl string, params map[string]any) string {
	return displayPlaceholderRe.ReplaceAllStringFunc(tmpl, func(m string) string {
		name := m[1 : len(m)-1]
		if v, ok := params[name]; ok {
			return fmt.Sprintf("%v", v)
		}
		return m
	})
}

// RiskDescriptor 風險項描述：zh template（wire fallback／稽核快照來源）＋必要參數
type RiskDescriptor struct {
	ZhTemplate     string
	RequiredParams []string
}

// riskDefs 風險 registry（唯一事實源）；經 registerRisk 註冊、init 填充
var riskDefs = map[string]RiskDescriptor{}

// registerRisk 註冊風險描述，重複／template↔params 不符即 panic（startup fail-fast）
func registerRisk(key string, d RiskDescriptor) {
	if _, dup := riskDefs[key]; dup {
		panic(fmt.Sprintf("risk %q 重複註冊", key))
	}
	if err := validateTemplateParams("risk", key, d.ZhTemplate, d.RequiredParams); err != nil {
		panic(err)
	}
	riskDefs[key] = d
}

func init() {
	registerRisk(RiskRDPIgnoreCert, RiskDescriptor{ZhTemplate: "RDP 未驗證伺服器憑證"})
	registerRisk(RiskRDPSecurityBelowNLA, RiskDescriptor{ZhTemplate: "RDP 安全模式未達 NLA"})
	registerRisk(RiskVNCUnencrypted, RiskDescriptor{ZhTemplate: "VNC 協議未加密"})
	registerRisk(RiskDBTLSDisabled, RiskDescriptor{ZhTemplate: "資料庫連線未啟用 TLS"})
	registerRisk(RiskLDAPPlaintext, RiskDescriptor{ZhTemplate: "目錄連線未加密（非 ldaps）"})
	registerRisk(RiskLDAPSkipVerify, RiskDescriptor{ZhTemplate: "目錄連線跳過憑證驗證"})
	registerRisk(RiskSyslogNonTLS, RiskDescriptor{ZhTemplate: "syslog 轉發未加密（{protocol}）", RequiredParams: []string{"protocol"}})
	registerRisk(RiskNotifyHTTP, RiskDescriptor{ZhTemplate: "通知投遞使用 http 明文"})
	registerRisk(RiskWinRMHTTPNTLM, RiskDescriptor{ZhTemplate: "WinRM 改密通道走 http（僅 NTLM 訊息層加密，無 TLS）"})
	registerRisk(RiskWinRMTLSInsecure, RiskDescriptor{ZhTemplate: "WinRM 改密通道未驗證伺服器憑證"})
}

// AllRiskDescriptors 回傳 registry 副本（完備性測試枚舉用）
func AllRiskDescriptors() map[string]RiskDescriptor {
	out := make(map[string]RiskDescriptor, len(riskDefs))
	for k, v := range riskDefs {
		out[k] = v
	}
	return out
}

// newRisk 由 registry 產生風險項（唯一 sanctioned 建構子）：驗 required params 齊全（缺則
// fail-fast panic）、以 zh template 內插產生 Label，回傳既有 wire 結構 {Key, Label}——
// 不加 Params 欄位，保持 consent／審計 JSON 形狀不變。
// 全域 AST 守衛禁止 registry 外設 Label 的裸 RiskItem 字面量繞過本建構子。
func newRisk(key string, params map[string]any) RiskItem {
	d, ok := riskDefs[key]
	if !ok {
		panic(fmt.Sprintf("risk %q 未註冊", key))
	}
	for _, p := range d.RequiredParams {
		if _, ok := params[p]; !ok {
			panic(fmt.Sprintf("risk %q 缺 required param %q", key, p))
		}
	}
	return RiskItem{Key: key, Label: interpolateTemplate(d.ZhTemplate, params)}
}

// channelPolicyKeys 通道 → 政策鍵
var channelPolicyKeys = map[string]string{
	TransportChannelRDP:    PolicyTransportRDPLevel,
	TransportChannelVNC:    PolicyTransportVNCLevel,
	TransportChannelDB:     PolicyTransportDBLevel,
	TransportChannelLDAP:   PolicyTransportLDAPLevel,
	TransportChannelSyslog: PolicyTransportSyslogLevel,
	TransportChannelNotify: PolicyTransportNotifyLevel,
}

// TransmissionPolicyService 傳輸安全政策判定核心：
// 風險判定規則唯一所在，供 connect-token 簽發閘、設定存檔閘、LDAP 登入閘、
// 資產徽章與通道清冊共用——判定散落各 handler 會漂移，清冊與閘門對同一
// 資產給出不同答案即誠實性破產
type TransmissionPolicyService struct {
	policy *SecurityPolicyService
	// ldapRiskView LDAP 設定的**執行期**風險視圖 provider。
	// 改自原本的 config.LDAPConfig 快照：設定遷入 DB 後可隨時變更，啟動時
	// 拷貝一份 config 會使清冊與徽章永遠停在啟動當下的值。
	//
	// **provider 回三態不回 nil**：DEK 事故下若清冊顯示「LDAP 未啟用」而設定頁
	// 顯示「已啟用」，兩個管理面互相打臉且把排錯指向錯誤方向。
	//
	// **不含 bind 密碼**（兩型分離）：本服務為清冊、資產徽章等多處共用，撥號
	// 用的明文密碼不得被帶進這些呼叫棧。
	//
	// nil-safe：nil＝未接目錄服務（既有測試與不需 LDAP 的組裝），視為未設定態
	ldapRiskView func() LDAPRiskResult
}

// NewTransmissionPolicyService 建立傳輸政策判定服務。
//
// ldapRiskView 可為 nil（未接目錄服務時視為未設定）。組裝序見 stage2：
// 先建 LDAPDirectoryService → 以其 RiskViewProvider() 建本服務 →
// 回頭 SetTransmissionPolicy 打環
func NewTransmissionPolicyService(
	policy *SecurityPolicyService, ldapRiskView func() LDAPRiskResult,
) *TransmissionPolicyService {
	return &TransmissionPolicyService{policy: policy, ldapRiskView: ldapRiskView}
}

// ChannelLevel 取通道強制等級（off/warn/strict）；未知通道回 off（不擋）
func (s *TransmissionPolicyService) ChannelLevel(channel string) string {
	key, ok := channelPolicyKeys[channel]
	if !ok {
		return TransportLevelOff
	}
	switch level := s.policy.Get(key); level {
	case TransportLevelWarn, TransportLevelStrict:
		return level
	default:
		return TransportLevelOff
	}
}

// AssetChannel 資產所屬的連線類傳輸通道；SSH（協議即加密）與 K8s
// （control plane TLS 另有 k8s_insecure_skip_tls 治理）不在本政策範疇，回空
func (s *TransmissionPolicyService) AssetChannel(asset *model.Asset) string {
	switch {
	case asset.Protocol == model.ProtocolRDP:
		return TransportChannelRDP
	case asset.Protocol == model.ProtocolVNC:
		return TransportChannelVNC
	case asset.Protocol.IsDatabase():
		return TransportChannelDB
	default:
		return ""
	}
}

// AssetRisks 連線類通道風險判定。RDP 基於最終 guacd 參數
// （EffectiveRDPParams 單一事實源，與 proxy 注入必然一致）
func (s *TransmissionPolicyService) AssetRisks(asset *model.Asset) []RiskItem {
	switch s.AssetChannel(asset) {
	case TransportChannelRDP:
		var risks []RiskItem
		security, ignoreCert := asset.EffectiveRDPParams()
		if ignoreCert {
			risks = append(risks, newRisk(RiskRDPIgnoreCert, nil))
		}
		if security != model.RDPSecurityNLA {
			risks = append(risks, newRisk(RiskRDPSecurityBelowNLA, nil))
		}
		return risks
	case TransportChannelVNC:
		// RFB 協議本身無加密，恆命中
		return []RiskItem{newRisk(RiskVNCUnencrypted, nil)}
	case TransportChannelDB:
		// fail-closed：僅明確啟用 TLS 的檔位視為安全；未知值在 dbproxy
		// 不會加 TLS 旗標（存量髒資料仍可能存在），一律計為風險
		switch asset.DBTLSMode {
		case "require", "verify-ca", "verify-full":
			return nil
		default:
			return []RiskItem{newRisk(RiskDBTLSDisabled, nil)}
		}
	default:
		return nil
	}
}

// AssetRotationChannel 資產的改密通道在傳輸階梯上的通道名；非 WinRM 回空。
//
// 與 AssetChannel 分開：AssetChannel 是 connect-token 閘的依據，改密屬系統路徑，
// 不得觸發連線前的風險同意閘；合併會讓 rdp 資產因改密設定而在使用者連線時被攔。
func (s *TransmissionPolicyService) AssetRotationChannel(asset *model.Asset) string {
	if asset.EffectiveRotationChannel() == model.RotationChannelWindowsWinRM {
		return TransportChannelWinRM
	}
	return ""
}

// AssetRotationRisks 改密通道的風險判定：http → 僅訊息層加密；https＋insecure → 未驗證憑證；
// https 配 system／ca 無風險。scheme 為空或未知一律計為 http 檔（fail-closed）。
func (s *TransmissionPolicyService) AssetRotationRisks(asset *model.Asset) []RiskItem {
	if s.AssetRotationChannel(asset) != TransportChannelWinRM {
		return nil
	}
	if asset.WinrmScheme != model.WinrmSchemeHTTPS {
		return []RiskItem{newRisk(RiskWinRMHTTPNTLM, nil)}
	}
	if asset.WinrmTLSMode == model.WinrmTLSModeInsecure {
		return []RiskItem{newRisk(RiskWinRMTLSInsecure, nil)}
	}
	return nil
}

// ldapView 取現行 LDAP 設定視圖（nil-safe）。
//
// provider 未注入＝本組裝不接目錄服務，視為未設定——不是「故障」：把
// 「沒接」記成故障會讓每個不需 LDAP 的部署在清冊上看到紅字
func (s *TransmissionPolicyService) ldapView() LDAPRiskResult {
	if s.ldapRiskView == nil {
		return LDAPRiskResult{State: LDAPResolveUnconfigured}
	}
	return s.ldapRiskView()
}

// LDAPRisks 認證通道風險判定：檢查撥號當下實際參數，
// 與設定存放位置無關。LDAP 未設定/未啟用＝通道不存在，無風險項。
//
// **判準本體在 LDAPRisksOf 純函式**：登入路徑
// 的閘改為對「該次登入解析出的 snapshot」直接呼叫該純函式，本方法則是清冊
// 等消費端的入口。兩者共用同一函式，判準不會因來源不同而漂移。
//
// 故障態不回報風險項：無從得知現行 URL 是否加密，捏造風險項與捏造「無風險」
// 一樣不誠實。故障的可見性由清冊的專屬 note 碼承擔（見 buildLDAP）
func (s *TransmissionPolicyService) LDAPRisks() []RiskItem {
	result := s.ldapView()
	if result.State != LDAPResolveOK {
		return nil
	}
	return LDAPRisksOf(result.View)
}

// SyslogRisks 設定類通道風險判定：非 TLS 傳輸即命中
func (s *TransmissionPolicyService) SyslogRisks(protocol string) []RiskItem {
	if protocol == model.SyslogProtocolTCPTLS {
		return nil
	}
	return []RiskItem{newRisk(RiskSyslogNonTLS, map[string]any{"protocol": protocol})}
}

// NotifyRisks 設定類通道風險判定：http 明文即命中
func (s *TransmissionPolicyService) NotifyRisks(url string) []RiskItem {
	if strings.HasPrefix(strings.ToLower(url), "http://") {
		return []RiskItem{newRisk(RiskNotifyHTTP, nil)}
	}
	return nil
}

// ConsentTTLDays 同意效期天數（0=永不過期）；讀時動態取值，政策改動立即生效
func (s *TransmissionPolicyService) ConsentTTLDays() int {
	return s.policy.GetInt(PolicyTransportConsentTTLDays)
}

// 設定類閘結果碼
const (
	TransmissionGateAckRequired  = "ack_required"
	TransmissionGateStrictReject = "strict_reject"
)

// TransmissionGateError 設定類存檔閘拒絕（typed error：呼叫端以 errors.As
// 取風險項映射 HTTP 語義——warn 未確認回 400＋風險項，strict 回 400＋原因）
type TransmissionGateError struct {
	Code    string     `json:"code"`
	Channel string     `json:"channel"`
	Risks   []RiskItem `json:"risks"`
}

// Error 實作 error 介面
func (e *TransmissionGateError) Error() string {
	if e.Code == TransmissionGateStrictReject {
		return "傳輸安全政策（嚴格）拒絕存檔：設定含不安全傳輸"
	}
	return "設定含不安全傳輸，需附風險確認聲明（risk_acknowledged）"
}

// CheckSettingSave 設定類通道存檔閘（與既有驗證同處 service 層）：
// off 或無風險＝nil；warn＋已確認＝nil（呼叫端負責聲明入審計）；
// warn＋未確認＝ack_required；strict＝無條件拒絕。
// 存量設定不回溯——本閘只攔「存檔」動作，運行中設定不中斷（spec 已鎖定）
func (s *TransmissionPolicyService) CheckSettingSave(channel string, risks []RiskItem, acknowledged bool) error {
	if len(risks) == 0 {
		return nil
	}
	switch s.ChannelLevel(channel) {
	case TransportLevelStrict:
		return &TransmissionGateError{Code: TransmissionGateStrictReject, Channel: channel, Risks: risks}
	case TransportLevelWarn:
		if acknowledged {
			return nil
		}
		return &TransmissionGateError{Code: TransmissionGateAckRequired, Channel: channel, Risks: risks}
	default:
		return nil
	}
}

// TransmissionRiskFingerprint 風險項集合的確定性雜湊：
// 僅取 key、排序後雜湊——順序無關；集合變更（資產傳輸屬性改動）即不符，
// 令既有同意自然失效，無需在資產寫路徑掛 hook
func TransmissionRiskFingerprint(risks []RiskItem) string {
	keys := make([]string, 0, len(risks))
	for _, r := range risks {
		keys = append(keys, r.Key)
	}
	sort.Strings(keys)
	sum := sha256.Sum256([]byte(strings.Join(keys, "\n")))
	return hex.EncodeToString(sum[:])
}
