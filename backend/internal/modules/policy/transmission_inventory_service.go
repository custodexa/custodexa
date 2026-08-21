package policy

import (
	"errors"
	"fmt"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// ChannelInventoryProvider 通知通道清冊來源（**policy 自宣告的窄介面**，audit 側實作）。
//
// **存在理由是 4.11 環拆解**（Phase B W1 1.12／R3.1 §3.1）：清冊服務原本直接持有
// `*NotificationChannelService`，使 policy→audit 成為真出向邊，而 audit→policy
// 又因讀 `failure_alert_enabled` 等政策而必然存在（`audit_failure_service.go`），
// 兩者合成環。介面由消費方（policy）宣告、實作留在 audit、注入在 `cmd/server/stage2.go`，
// 方向即翻轉為 audit→policy 單向（R3.1 §3.2 矩陣：policy 列全 ✗）。
//
// 回傳型別是 `model.NotificationChannel`：`internal/model` 為共用包（R3 §1.3 裁決
// 不拆），policy 與 audit 皆合法依賴它，故用它承載清冊列不會把邊加回來。
// **偏離旗標 `TransmissionDeviation` 由 audit 於 `toDisplay` 填妥**——本波不搬動
// 該判定，清冊端只做計數，行為與拆環前逐位相同。
type ChannelInventoryProvider interface {
	// List 全部通知通道（url/secret 已解密為顯示值，並已填妥 TransmissionDeviation）
	List() ([]model.NotificationChannel, error)
}

// TransmissionInventoryService 通道加密清冊（transmission-security-policy D5）：
// 讀時彙整不落表。資產類以 SQL group by 聚合（不逐列），每個欄位組合以
// 代表資產映射回 TransmissionPolicyService 判定——count 在 SQL、規則在 D1
// 單一所在，聚合不會與閘門漂移
type TransmissionInventoryService struct {
	db     *gorm.DB
	policy *TransmissionPolicyService
	// channels 通道清冊來源：型別是 policy 自宣告的窄介面，非 audit 的具體型別（4.11 拆環）
	channels ChannelInventoryProvider
}

// NewTransmissionInventoryService 建立清冊服務。
// channels 為窄介面（4.11 拆環）：呼叫端 SHALL 傳入非 nil 實作
func NewTransmissionInventoryService(db *gorm.DB, policy *TransmissionPolicyService, channels ChannelInventoryProvider) *TransmissionInventoryService {
	return &TransmissionInventoryService{db: db, policy: policy, channels: channels}
}

// InventoryChannel 清冊單一通道狀態
type InventoryChannel struct {
	Channel string `json:"channel"`
	// Deployment true＝部署層設定（標「部署方管理」，無設定開關）
	Deployment bool `json:"deployment"`
	// Level 政策等級（政策通道；SSH/nginx 無）
	Level string `json:"level,omitempty"`
	// TotalCount 通道下資產/設定總數
	TotalCount int64 `json:"total_count"`
	// AtRiskCount 命中風險判定數（偏離）
	AtRiskCount int64 `json:"at_risk_count"`
	// Detail 分布明細（group by 組合 → 數量）；中文 `(未設定)` 保留供舊前端／export
	// fallback（i18n-backend-labels：新前端改讀 DetailCodes）
	Detail map[string]int64 `json:"detail,omitempty"`
	// DetailCodes 完整 machine-keyed 明細（技術複合鍵原樣、`(未設定)`→`unset`）：
	// 新前端整份採用取代 Detail、不合併（rr-I4）
	DetailCodes map[string]int64 `json:"detail_codes,omitempty"`
	// Risks 單例通道（LDAP/syslog）的風險項
	Risks []RiskItem `json:"risks,omitempty"`
	// StrictPreflight 「若切 strict」預檢描述（zh fallback；前端優先 PreflightCode 查譯）
	StrictPreflight string `json:"strict_preflight,omitempty"`
	// PreflightCode/PreflightParams 前端 i18n（rr-I3；count 為整數）
	PreflightCode   string         `json:"preflight_code,omitempty"`
	PreflightParams map[string]any `json:"preflight_params,omitempty"`
	// Note 誠實記載（協議即加密／部署方管理等；zh fallback，前端優先 NoteCode 查譯）
	Note string `json:"note,omitempty"`
	// NoteCode/NoteParams 前端 i18n（rr-I3）
	NoteCode   string         `json:"note_code,omitempty"`
	NoteParams map[string]any `json:"note_params,omitempty"`
	// DisplayParams 通道級顯示參數（供清冊 risk label 查譯，如 syslog {protocol}——rr-I2）
	DisplayParams map[string]any `json:"display_params,omitempty"`
}

// TransmissionInventory 清冊快照
type TransmissionInventory struct {
	GeneratedAt time.Time          `json:"generated_at"`
	GeneratedBy string             `json:"generated_by,omitempty"`
	Channels    []InventoryChannel `json:"channels"`
}

// Build 彙整全通道加密狀態
func (s *TransmissionInventoryService) Build() (*TransmissionInventory, error) {
	inv := &TransmissionInventory{GeneratedAt: time.Now()}

	ssh, err := s.buildSSH()
	if err != nil {
		return nil, err
	}
	rdp, err := s.buildRDP()
	if err != nil {
		return nil, err
	}
	vnc, err := s.buildVNC()
	if err != nil {
		return nil, err
	}
	db, err := s.buildDB()
	if err != nil {
		return nil, err
	}
	syslog, err := s.buildSyslog()
	if err != nil {
		return nil, err
	}
	notify, err := s.buildNotify()
	if err != nil {
		return nil, err
	}
	inv.Channels = []InventoryChannel{ssh, rdp, vnc, db, s.buildLDAP(), syslog, notify, buildNginx()}
	return inv, nil
}

// ── inventory note/preflight registry（i18n-backend-labels rr-I3/rr3）─────────
// note/preflight 顯示字串錨定穩定碼；descriptor 帶 Kind 決定 locale namespace
//（note→transportNote、preflight→transportPreflight）。與 risk 共用 template validator。

type inventoryKind string

const (
	invKindNote      inventoryKind = "note"
	invKindPreflight inventoryKind = "preflight"
)

// detailUnsetCode DB 明細「未設定」的機器鍵（取代中文 `(未設定)`）
const detailUnsetCode = "unset"
const detailUnsetZh = "(未設定)"

// InventoryDescriptor 清冊顯示字串描述
type InventoryDescriptor struct {
	Kind           inventoryKind
	ZhTemplate     string
	RequiredParams []string
}

// inventoryDefs 清冊顯示字串 registry（唯一事實源）
var inventoryDefs = map[string]InventoryDescriptor{}

// registerInventory 註冊 note/preflight 描述；kind 不合法／重複／template↔params 不符即 panic
func registerInventory(kind inventoryKind, code, tmpl string, required ...string) {
	if kind != invKindNote && kind != invKindPreflight {
		panic(fmt.Sprintf("inventory %q 非法 kind %q", code, kind))
	}
	if _, dup := inventoryDefs[code]; dup {
		panic(fmt.Sprintf("inventory %q 重複註冊", code))
	}
	if err := validateTemplateParams("inventory", code, tmpl, required); err != nil {
		panic(err)
	}
	inventoryDefs[code] = InventoryDescriptor{Kind: kind, ZhTemplate: tmpl, RequiredParams: required}
}

func init() {
	// note（9）：LDAP 三完整碼（啟用／未啟用／讀取失敗），不用中文前綴組合（rr-I1）
	registerInventory(invKindNote, "ssh_encrypted", "SSH 協議本身加密，不在政策範疇")
	registerInventory(invKindNote, "vnc_no_encryption", "VNC/RFB 協議無加密選項，全部資產恆為明文通道")
	// LDAP 三碼（ldap-settings-migration D6/N3）：設定自 env 遷入 DB 後由
	// 身分管理 UI 維護，「部署方管理」語義退場（該徽章自此僅剩 nginx）。
	// 故障態必須有專屬碼——顯示為「未啟用」會與設定頁的「已啟用」互相打臉，
	// 並把排錯方向指向「誰把 LDAP 關掉了」而非真因（金鑰或資料庫）
	registerInventory(invKindNote, "ldap_ui_managed", "設定於身分管理的目錄設定頁維護")
	registerInventory(invKindNote, "ldap_disabled_ui_managed", "LDAP 未啟用；設定於身分管理的目錄設定頁維護")
	registerInventory(invKindNote, "ldap_resolve_failed", "LDAP 設定讀取失敗（資料庫或金鑰問題），現行加密狀態無法判定；請檢查伺服器日誌")
	registerInventory(invKindNote, "syslog_unset", "syslog 轉發未設定")
	registerInventory(invKindNote, "syslog_disabled", "syslog 轉發未啟用")
	registerInventory(invKindNote, "syslog_protocol", "轉發協議：{protocol}", "protocol")
	registerInventory(invKindNote, "nginx_deploy_managed", "前端對外 HTTPS 屬部署層：本服務不自帶 TLS，須由前置的 TLS-terminating 反向代理/ingress 提供 443 ssl＋80→443 redirect＋HSTS＋wss（範例見 docker/reverse-proxy/）；容器內 nginx 僅 listen 80；部署方管理")
	// preflight（4）：rdp/vnc/db 帶 {n}（vue-i18n 隱式 plural 參數，對齊 codebase 慣例
	// 如 riskCount "{n} risk | {n} risks"）、ldap 無參
	registerInventory(invKindPreflight, "rdp_reject", "若切 strict 將拒絕 {n} 台 RDP 資產連線", "n")
	registerInventory(invKindPreflight, "vnc_reject", "若切 strict 將拒絕全部 {n} 台 VNC 資產連線", "n")
	registerInventory(invKindPreflight, "db_reject", "若切 strict 將拒絕 {n} 台未啟 TLS 的資料庫資產連線", "n")
	registerInventory(invKindPreflight, "ldap_reject", "若切 strict 將拒絕全部 LDAP 登入（本地帳號不受影響）")
}

// AllInventoryDescriptors 回傳 registry 副本（完備性測試枚舉用）
func AllInventoryDescriptors() map[string]InventoryDescriptor {
	out := make(map[string]InventoryDescriptor, len(inventoryDefs))
	for k, v := range inventoryDefs {
		out[k] = v
	}
	return out
}

// inventoryDescriptorOrPanic 取指定 kind 的描述；kind 不符或未註冊即 panic
func inventoryDescriptorOrPanic(kind inventoryKind, code string) InventoryDescriptor {
	d, ok := inventoryDefs[code]
	if !ok {
		panic(fmt.Sprintf("inventory %q 未註冊", code))
	}
	if d.Kind != kind {
		panic(fmt.Sprintf("inventory %q kind 為 %q，非 %q", code, d.Kind, kind))
	}
	return d
}

// requireInventoryParams 驗 required params 齊全（缺則 fail-fast）
func requireInventoryParams(code string, d InventoryDescriptor, params map[string]any) {
	for _, p := range d.RequiredParams {
		if _, ok := params[p]; !ok {
			panic(fmt.Sprintf("inventory %q 缺 required param %q", code, p))
		}
	}
}

// setNote 由 registry 設定通道 note（唯一 sanctioned 設 .Note 的處；全域 AST 守衛
// 禁止 registry 外對 .Note 賦值或 InventoryChannel{Note:…} 字面量繞過本函式）
func setNote(ch *InventoryChannel, code string, params map[string]any) {
	d := inventoryDescriptorOrPanic(invKindNote, code)
	requireInventoryParams(code, d, params)
	ch.NoteCode = code
	if len(params) > 0 {
		ch.NoteParams = params
	}
	ch.Note = interpolateTemplate(d.ZhTemplate, params)
}

// setPreflight 由 registry 設定 strict 預檢（唯一 sanctioned 設 .StrictPreflight 的處）
func setPreflight(ch *InventoryChannel, code string, params map[string]any) {
	d := inventoryDescriptorOrPanic(invKindPreflight, code)
	requireInventoryParams(code, d, params)
	ch.PreflightCode = code
	if len(params) > 0 {
		ch.PreflightParams = params
	}
	ch.StrictPreflight = interpolateTemplate(d.ZhTemplate, params)
}

// legacyDetailFromCodes 由完整 machine-keyed 明細衍生 zh fallback Detail（`unset`→`(未設定)`，
// 技術鍵原樣）——供舊前端／export（rr-I4）
func legacyDetailFromCodes(codes map[string]int64) map[string]int64 {
	if len(codes) == 0 {
		return nil
	}
	out := make(map[string]int64, len(codes))
	for k, v := range codes {
		// 累加而非覆蓋：髒資料若使 unset 與字面 "(未設定)" 同時存在，兩者映到同一
		// 顯示鍵時 count 守恆不遺失（codex impl-review I2）
		if k == detailUnsetCode {
			out[detailUnsetZh] += v
		} else {
			out[k] += v
		}
	}
	return out
}

func (s *TransmissionInventoryService) countAssets(where string, args ...interface{}) (int64, error) {
	var n int64
	err := s.db.Model(&model.Asset{}).Where(where, args...).Count(&n).Error
	return n, err
}

func (s *TransmissionInventoryService) buildSSH() (InventoryChannel, error) {
	total, err := s.countAssets("protocol = ?", model.ProtocolSSH)
	ch := InventoryChannel{Channel: "ssh", TotalCount: total}
	setNote(&ch, "ssh_encrypted", nil)
	return ch, err
}

func (s *TransmissionInventoryService) buildRDP() (InventoryChannel, error) {
	ch := InventoryChannel{
		Channel:     TransportChannelRDP,
		Level:       s.policy.ChannelLevel(TransportChannelRDP),
		DetailCodes: map[string]int64{},
	}
	var rows []struct {
		RDPSecurity   string
		RDPVerifyCert bool
		N             int64
	}
	err := s.db.Model(&model.Asset{}).
		Select("rdp_security, rdp_verify_cert, COUNT(*) AS n").
		Where("protocol = ?", model.ProtocolRDP).
		Group("rdp_security, rdp_verify_cert").Scan(&rows).Error
	if err != nil {
		return ch, err
	}
	for _, r := range rows {
		rep := model.Asset{Protocol: model.ProtocolRDP, RDPSecurity: r.RDPSecurity, RDPVerifyCert: r.RDPVerifyCert}
		security, ignoreCert := rep.EffectiveRDPParams()
		// 技術複合鍵（語言中性，不譯）
		key := fmt.Sprintf("security=%s,verify_cert=%t", security, !ignoreCert)
		ch.DetailCodes[key] += r.N
		ch.TotalCount += r.N
		if len(s.policy.AssetRisks(&rep)) > 0 {
			ch.AtRiskCount += r.N
		}
	}
	ch.Detail = legacyDetailFromCodes(ch.DetailCodes)
	if ch.AtRiskCount > 0 {
		setPreflight(&ch, "rdp_reject", map[string]any{"n": ch.AtRiskCount})
	}
	return ch, nil
}

func (s *TransmissionInventoryService) buildVNC() (InventoryChannel, error) {
	total, err := s.countAssets("protocol = ?", model.ProtocolVNC)
	ch := InventoryChannel{
		Channel: TransportChannelVNC,
		Level:   s.policy.ChannelLevel(TransportChannelVNC),
		// RFB 協議無加密，恆命中
		TotalCount: total, AtRiskCount: total,
	}
	setNote(&ch, "vnc_no_encryption", nil)
	if total > 0 {
		setPreflight(&ch, "vnc_reject", map[string]any{"n": total})
	}
	return ch, err
}

func (s *TransmissionInventoryService) buildDB() (InventoryChannel, error) {
	ch := InventoryChannel{
		Channel:     TransportChannelDB,
		Level:       s.policy.ChannelLevel(TransportChannelDB),
		DetailCodes: map[string]int64{},
	}
	var rows []struct {
		Protocol  model.ProtocolType
		DBTLSMode string
		N         int64
	}
	err := s.db.Model(&model.Asset{}).
		Select("protocol, db_tls_mode, COUNT(*) AS n").
		Where("protocol IN ?", []model.ProtocolType{model.ProtocolMySQL, model.ProtocolPostgres, model.ProtocolRedis, model.ProtocolMSSQL}).
		Group("protocol, db_tls_mode").Scan(&rows).Error
	if err != nil {
		return ch, err
	}
	for _, r := range rows {
		// tls mode enum 為語言中性技術鍵；未設定改機器鍵 unset（rr-I4）
		mode := r.DBTLSMode
		if mode == "" {
			mode = detailUnsetCode
		}
		ch.DetailCodes[mode] += r.N
		ch.TotalCount += r.N
		rep := model.Asset{Protocol: r.Protocol, DBTLSMode: r.DBTLSMode}
		if len(s.policy.AssetRisks(&rep)) > 0 {
			ch.AtRiskCount += r.N
		}
	}
	ch.Detail = legacyDetailFromCodes(ch.DetailCodes)
	if ch.AtRiskCount > 0 {
		setPreflight(&ch, "db_reject", map[string]any{"n": ch.AtRiskCount})
	}
	return ch, nil
}

// buildLDAP LDAP 通道清冊列（ldap-settings-migration D6/N3）。
//
// **Deployment 為 false**：設定自 env 遷入 DB 後由身分管理 UI 維護，「部署方
// 管理」（無設定開關）語義不再成立——保留 true 會使清冊指引 admin 去改一個
// 已經不生效的 env。該徽章自此僅剩 nginx。
//
// **三態各有出口**：故障不得落入「未啟用」分支（見 note 碼註解）。取值只呼叫
// provider 一次，避免同一頁的狀態與風險項出自兩次解析
func (s *TransmissionInventoryService) buildLDAP() InventoryChannel {
	ch := InventoryChannel{
		Channel:    TransportChannelLDAP,
		Deployment: false,
		Level:      s.policy.ChannelLevel(TransportChannelLDAP),
	}
	result := s.policy.ldapView()
	if result.State == LDAPResolveFailed {
		setNote(&ch, "ldap_resolve_failed", nil)
		return ch
	}
	// 未設定（無列）與已設定但停用兩者對清冊等價：都不會撥號、無通道風險
	if result.State != LDAPResolveOK || !result.View.Enabled {
		setNote(&ch, "ldap_disabled_ui_managed", nil)
		return ch
	}
	setNote(&ch, "ldap_ui_managed", nil)
	ch.TotalCount = 1
	ch.Risks = LDAPRisksOf(result.View)
	if len(ch.Risks) > 0 {
		ch.AtRiskCount = 1
		setPreflight(&ch, "ldap_reject", nil)
	}
	return ch
}

func (s *TransmissionInventoryService) buildSyslog() (InventoryChannel, error) {
	ch := InventoryChannel{
		Channel: TransportChannelSyslog,
		Level:   s.policy.ChannelLevel(TransportChannelSyslog),
	}
	var setting model.SyslogSetting
	if err := s.db.First(&setting, 1).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			setNote(&ch, "syslog_unset", nil)
			return ch, nil
		}
		return ch, err
	}
	if !setting.Enabled {
		setNote(&ch, "syslog_disabled", nil)
		return ch, nil
	}
	ch.TotalCount = 1
	setNote(&ch, "syslog_protocol", map[string]any{"protocol": setting.Protocol})
	ch.Risks = s.policy.SyslogRisks(setting.Protocol)
	if len(ch.Risks) > 0 {
		ch.AtRiskCount = 1
		// 供清冊頁 riskLabel 查譯 syslog_non_tls 的 {protocol}（rr-I2）
		ch.DisplayParams = map[string]any{"protocol": setting.Protocol}
	}
	return ch, nil
}

func (s *TransmissionInventoryService) buildNotify() (InventoryChannel, error) {
	ch := InventoryChannel{
		Channel: TransportChannelNotify,
		Level:   s.policy.ChannelLevel(TransportChannelNotify),
	}
	// 通知通道量級個位數到數十且 URL 信封加密落庫，走 List 逐列解密評估
	//（偏離判定已在 toDisplay 填 TransmissionDeviation）；資產類才走 SQL 聚合
	channels, err := s.channels.List()
	if err != nil {
		return ch, err
	}
	ch.TotalCount = int64(len(channels))
	for _, c := range channels {
		if c.TransmissionDeviation {
			ch.AtRiskCount++
		}
	}
	return ch, nil
}

func buildNginx() InventoryChannel {
	ch := InventoryChannel{Channel: "nginx", Deployment: true}
	setNote(&ch, "nginx_deploy_managed", nil)
	return ch
}
