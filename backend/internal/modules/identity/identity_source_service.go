package identity

import (
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
)

// 身分來源的管理面：目錄與身分提供者的合併視圖、映射規則 CRUD、檢核面板的狀態彙總。
//
// # 為什麼是一支彙總端點而不是前端拼多支
//
// 檢核面板的燈號要回答的是同一個時刻的狀態。分散成多支請求時，燈號之間會出現
// 不同時點的混合——「憑證已設定」取自 5 秒前、「最近登入帶到群組」取自現在，
// 而管理者據以判斷的是這兩件事的組合。
//
// # 狀態彙總不對外撥號
//
// 本服務的狀態端點只回報**系統已經觀測到的事實**（設定值、規則數、映射事實、
// 登入時的群組觀測快照、探索文件的快取新鮮度），一律不發起對外連線。
// 頁面載入即撥號會把一支唯讀的狀態查詢變成可被反覆觸發的出站探測，
// 也會與連線測試的資源上限互相干擾。**主動測試是介面上的獨立動作**
// （重新探索、測試連線），由操作者按下去才發生。
// 無從觀測的燈號回 null（介面呈現為「尚無資料」）——**不知道不得畫成綠色**。

// IdentitySourceService 身分來源管理面服務
type IdentitySourceService struct {
	db      *gorm.DB
	auditTx port.TxSink

	// discovery 供狀態彙總讀取探索文件的快取新鮮度（只讀快取、不撥號）。
	// 未注入時探索燈號一律回 null
	discovery *OIDCDiscoveryService
}

// NewIdentitySourceService 建立身分來源管理面服務
func NewIdentitySourceService(db *gorm.DB, auditTx port.TxSink) *IdentitySourceService {
	return &IdentitySourceService{db: db, auditTx: auditTx}
}

// SetDiscovery 注入 discovery 服務（狀態彙總的探索燈號來源）
func (s *IdentitySourceService) SetDiscovery(d *OIDCDiscoveryService) {
	s.discovery = d
}

// IdentitySourceRow 合併列表的一列
type IdentitySourceRow struct {
	// Type 對外型別：ldap 或 oidc
	Type string `json:"type"`
	ID   uint   `json:"id"`
	Name string `json:"name"`
	// Address 目錄的位址或提供者的 issuer
	Address string `json:"address"`
	Enabled bool   `json:"enabled"`
	// LastLoginAt 此來源最近一次成功登入的時間（無登入即 null）
	LastLoginAt *time.Time `json:"last_login_at"`
	// MappingRuleCount 此來源的映射規則條數
	MappingRuleCount int64 `json:"mapping_rule_count"`
}

// ListSources 合併列表：目錄（單例，至多一列）與全部提供者。
func (s *IdentitySourceService) ListSources() ([]IdentitySourceRow, error) {
	if s == nil || s.db == nil {
		return nil, ErrMappingServiceUnavailable
	}
	out := []IdentitySourceRow{}

	dir, err := ldapDirectoryLiveRow(s.db)
	if err != nil {
		return nil, fmt.Errorf("讀取目錄設定失敗: %w", err)
	}
	if dir != nil {
		total, _, err := CountMappings(s.db, model.RoleMappingChannelKindDirectory, dir.ID)
		if err != nil {
			return nil, err
		}
		lastLogin, err := s.directoryLastLogin()
		if err != nil {
			return nil, err
		}
		out = append(out, IdentitySourceRow{
			Type: "ldap", ID: dir.ID, Name: dir.Name, Address: dir.URL,
			Enabled: dir.Enabled, LastLoginAt: lastLogin, MappingRuleCount: total,
		})
	}

	var providers []model.OIDCProvider
	if err := s.db.Order("id").Find(&providers).Error; err != nil {
		return nil, fmt.Errorf("讀取身分提供者失敗: %w", err)
	}
	for i := range providers {
		p := &providers[i]
		total, _, err := CountMappings(s.db, model.RoleMappingChannelKindProvider, p.ID)
		if err != nil {
			return nil, err
		}
		lastLogin, err := s.providerLastLogin(p.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, IdentitySourceRow{
			Type: "oidc", ID: p.ID, Name: p.Name, Address: p.Issuer,
			Enabled: p.Enabled, LastLoginAt: lastLogin, MappingRuleCount: total,
		})
	}
	return out, nil
}

// directoryLastLogin 目錄供應帳號的最近登入時間
func (s *IdentitySourceService) directoryLastLogin() (*time.Time, error) {
	var out []time.Time
	if err := s.db.Model(&model.User{}).
		Where("is_ldap = ? AND last_login_at IS NOT NULL", true).
		Order("last_login_at DESC").Limit(1).Pluck("last_login_at", &out).Error; err != nil {
		return nil, fmt.Errorf("讀取目錄最近登入時間失敗: %w", err)
	}
	if len(out) == 0 {
		return nil, nil
	}
	t := out[0]
	return &t, nil
}

// providerLastLogin 綁定此提供者的帳號的最近登入時間
func (s *IdentitySourceService) providerLastLogin(providerID uint) (*time.Time, error) {
	var out []time.Time
	if err := s.db.Model(&model.User{}).
		Joins("JOIN user_external_identities uei ON uei.user_id = users.id").
		Where("uei.provider_id = ? AND uei.deleted_at IS NULL AND users.last_login_at IS NOT NULL",
			providerID).
		Order("users.last_login_at DESC").Limit(1).
		Pluck("users.last_login_at", &out).Error; err != nil {
		return nil, fmt.Errorf("讀取提供者最近登入時間失敗: %w", err)
	}
	if len(out) == 0 {
		return nil, nil
	}
	t := out[0]
	return &t, nil
}

// SourceStatusWarning 狀態彙總的一項警告（機器碼，文案由用戶端依碼決定）
type SourceStatusWarning struct {
	Code string `json:"code"`
}

// SourceStatus 檢核面板第二塊的全部燈號。
//
// 三態欄位一律用指標：null 是「尚未觀測到」，與 false（觀測到且不通過）是
// 兩件事。壓成布林的話「還沒測過」會呈現為「測過但失敗」。
type SourceStatus struct {
	// DiscoveryReachable 提供者型別：探索文件是否可達（取自快取新鮮度）
	DiscoveryReachable *bool `json:"discovery_reachable"`
	// ConnectionOK 目錄型別：連線與 bind 是否通過
	ConnectionOK *bool `json:"connection_ok"`
	// GroupAttrReadable 目錄型別：抽樣使用者是否可讀群組屬性
	GroupAttrReadable *bool `json:"group_attr_readable"`

	CredentialSet bool       `json:"credential_set"`
	LastLoginAt   *time.Time `json:"last_login_at"`
	// LastLoginGroupsSeen 最近一次登入是否帶到群組資料（尚無登入觀測即 null）
	LastLoginGroupsSeen  *bool                 `json:"last_login_groups_seen"`
	LastLoginGroupsCount int                   `json:"last_login_groups_count"`
	RuleCount            int64                 `json:"rule_count"`
	EnabledRuleCount     int64                 `json:"enabled_rule_count"`
	LastRecomputeMatched int64                 `json:"last_recompute_matched_users"`
	Warnings             []SourceStatusWarning `json:"warnings"`
}

// DirectoryStatus 目錄（單例）的狀態彙總
func (s *IdentitySourceService) DirectoryStatus() (*SourceStatus, error) {
	if s == nil || s.db == nil {
		return nil, ErrMappingServiceUnavailable
	}
	dir, err := ldapDirectoryLiveRow(s.db)
	if err != nil {
		return nil, fmt.Errorf("讀取目錄設定失敗: %w", err)
	}
	if dir == nil {
		return nil, ErrMappingSourceNotFound
	}
	out := &SourceStatus{
		CredentialSet: dir.BindPasswordEnc != "",
		Warnings:      []SourceStatusWarning{},
	}
	// 連線與群組屬性抽樣兩盞燈取自連線測試，而狀態彙總不撥號（見檔頭），
	// 故未觀測即 null，由介面上的「測試連線」動作填補
	if err := s.fillCommon(out, model.RoleMappingChannelKindDirectory, dir.ID,
		dir.AttrGroup != ""); err != nil {
		return nil, err
	}
	out.LastLoginAt, err = s.directoryLastLogin()
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ProviderStatus 某提供者的狀態彙總
func (s *IdentitySourceService) ProviderStatus(providerID uint) (*SourceStatus, error) {
	if s == nil || s.db == nil {
		return nil, ErrMappingServiceUnavailable
	}
	var rows []model.OIDCProvider
	if err := s.db.Where("id = ?", providerID).Limit(1).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("讀取身分提供者失敗: %w", err)
	}
	if len(rows) == 0 {
		return nil, ErrMappingSourceNotFound
	}
	p := &rows[0]
	out := &SourceStatus{
		CredentialSet: p.ClientSecretEnc != "",
		Warnings:      []SourceStatusWarning{},
	}
	if s.discovery != nil {
		reachable := s.discovery.CachedReachable(p)
		if reachable != nil {
			out.DiscoveryReachable = reachable
		}
	}
	if err := s.fillCommon(out, model.RoleMappingChannelKindProvider, p.ID,
		p.GroupsClaim != ""); err != nil {
		return nil, err
	}
	var err error
	out.LastLoginAt, err = s.providerLastLogin(p.ID)
	if err != nil {
		return nil, err
	}
	// 設了群組宣告名卻沒帶 groups 授權範圍：多數提供者因此不發群組宣告，
	// 鍵缺席依既有判準視為空集合，症狀是全體映射角色被撤且無訊號。
	// 這一格沒有登入側的跳過事件可依靠（那一格是「宣告名沒設」），故在此亮黃燈
	if p.GroupsClaim != "" && !scopesContainGroups(p.Scopes) {
		out.Warnings = append(out.Warnings,
			SourceStatusWarning{Code: mappingWarningGroupsScopeMissing})
	}
	return out, nil
}

// fillCommon 兩型別共通的四項：規則數、命中人數、群組觀測、屬性未設警告
func (s *IdentitySourceService) fillCommon(out *SourceStatus, kind string,
	sourceID uint, attrSet bool) error {
	total, enabled, err := CountMappings(s.db, kind, sourceID)
	if err != nil {
		return err
	}
	out.RuleCount = total
	out.EnabledRuleCount = enabled

	channel := model.RoleMappingChannel(kind, sourceID)
	var matched int64
	if err := s.db.Model(&model.UserRoleMapping{}).
		Where("channel = ?", channel).
		Distinct("user_id").Count(&matched).Error; err != nil {
		return fmt.Errorf("計算映射命中人數失敗: %w", err)
	}
	out.LastRecomputeMatched = matched

	seen, count, err := s.groupObservation(channel)
	if err != nil {
		return err
	}
	out.LastLoginGroupsSeen = seen
	out.LastLoginGroupsCount = count

	// 有啟用中的規則卻沒設群組屬性名／宣告名：規則永遠不命中。
	// 與登入側的跳過事件是同一件事的兩層訊號
	if !attrSet && enabled > 0 {
		out.Warnings = append(out.Warnings,
			SourceStatusWarning{Code: mappingWarningSourceAttrUnsetWithRules})
	}
	return nil
}

// groupObservation 這條途徑最近一次登入的群組觀測快照。
//
// 快照只在已知態寫入（未知態覆蓋會抹掉「上次成功讀到什麼」這個唯一的診斷線索），
// 故查無快照即回 null——那是「尚無登入觀測」，不是「登入了但沒帶到群組」。
func (s *IdentitySourceService) groupObservation(channel string) (*bool, int, error) {
	type snapshot struct {
		GroupSnapshotGroups string
	}
	var rows []snapshot
	if err := s.db.Model(&model.User{}).
		Select("group_snapshot_groups").
		Where("group_snapshot_channel = ? AND group_snapshot_at IS NOT NULL", channel).
		Order("group_snapshot_at DESC").Limit(1).Scan(&rows).Error; err != nil {
		return nil, 0, fmt.Errorf("讀取群組觀測快照失敗: %w", err)
	}
	if len(rows) == 0 {
		return nil, 0, nil
	}
	var groups []string
	if rows[0].GroupSnapshotGroups != "" {
		if err := json.Unmarshal([]byte(rows[0].GroupSnapshotGroups), &groups); err != nil {
			// 快照是診斷用的自報值，解不開時不讓它擋住整支狀態查詢
			seen := false
			return &seen, 0, nil
		}
	}
	seen := len(groups) > 0
	return &seen, len(groups), nil
}

// mappingWarningSourceAttrUnsetWithRules／mappingWarningGroupsScopeMissing
// 狀態彙總專用的兩支警告碼（與 internal/apierror 的常數同值）
const (
	mappingWarningSourceAttrUnsetWithRules = "MAPPING_SOURCE_ATTR_UNSET_WITH_RULES"
	mappingWarningGroupsScopeMissing       = "MAPPING_GROUPS_SCOPE_MISSING"
)
