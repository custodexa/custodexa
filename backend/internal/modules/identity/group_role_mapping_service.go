package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 映射規則的管理面（CRUD 與交易內審計）。
//
// # 為什麼規則掛在來源之下而不是自成一頁
//
// 一條規則是「某一個外部來源的某個群組給哪個角色」。脫離來源之後每一列都要
// 重述自己屬於誰，而管理者的實際動線是「設好這個來源 → 決定它的群組怎麼給角色」。
// 服務層因此一律以（來源種類，來源識別）定址，識別不對即查無規則，
// 不做「以規則 id 直接定址」的旁路——那條旁路會讓一次筆誤改到另一個來源的規則。
//
// # 警告與確認，不阻擋
//
// 兩種情形要求操作者顯式確認：規則指向管理員角色，以及來源尚未設定群組屬性名
// 或群組宣告名。兩者都**不阻擋**——管理者可能正打算先建規則再回頭補設定，
// 阻擋只會逼人繞路，而繞路之後就沒有任何記錄了。要防的是不知情，不是不發生。
// 確認的事實與規則內容一併入審計。

var (
	// ErrMappingSourceNotFound 指定的外部來源不存在（或已刪除）
	ErrMappingSourceNotFound = errors.New("指定的身分來源不存在")
	// ErrMappingRuleNotFound 指定的映射規則不存在，或不屬於這個來源
	ErrMappingRuleNotFound = errors.New("映射規則不存在")
	// ErrMappingRoleUnknown 指定的角色名不存在
	ErrMappingRoleUnknown = errors.New("指定的角色不存在")
	// ErrMappingMatchValueEmpty 比對值為空
	ErrMappingMatchValueEmpty = errors.New("群組比對值不得為空")
	// ErrMappingMatchValueDN 目錄側的比對值不是可解析的辨識名稱
	ErrMappingMatchValueDN = errors.New("群組比對值必須是可解析的辨識名稱")
	// ErrMappingSourceKind 未知的來源種類
	ErrMappingSourceKind = errors.New("未知的身分來源種類")
	// ErrMappingServiceUnavailable 服務未接線（nil DB）
	ErrMappingServiceUnavailable = errors.New("身分來源管理服務未接線")
)

// mappingMatchValueMaxLen 比對值長度上限（與欄位寬度一致）
const mappingMatchValueMaxLen = 500

// MappingAckRequiredError 命中風險情形且未帶確認。
//
// 帶著命中的警告碼上拋，HTTP 層據以組出 422 與 Meta.warnings——
// 服務層不知道也不該知道對外文案，警告碼是兩層之間唯一的約定。
type MappingAckRequiredError struct {
	Warnings []string
}

func (e *MappingAckRequiredError) Error() string {
	return "映射規則需要風險確認: " + strings.Join(e.Warnings, ",")
}

// GroupRoleMappingActor 操作者（handler 自已認證脈絡填入，不接受請求端指定）
type GroupRoleMappingActor struct {
	ID   uint
	Name string
	IP   string
}

// GroupRoleMappingInput 建立與更新的請求形狀。
//
// Enabled 用指標：省略即沿用（更新）或預設啟用（建立）。值型別的話
// 「沒送這一欄」與「停用」同形，一次部分更新就會把規則靜默關掉。
type GroupRoleMappingInput struct {
	MatchValue       string `json:"match_value"`
	Role             string `json:"role"`
	Enabled          *bool  `json:"enabled"`
	RiskAcknowledged bool   `json:"risk_acknowledged"`

	// Actor 由 handler 填入
	Actor GroupRoleMappingActor `json:"-"`
}

// GroupRoleMappingView 對外呈現一條規則
type GroupRoleMappingView struct {
	ID         uint      `json:"id"`
	MatchValue string    `json:"match_value"`
	Role       string    `json:"role"`
	Enabled    bool      `json:"enabled"`
	CreatedBy  string    `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// 映射規則的審計事件碼（Details.event）
const (
	MappingAuditEventCreate = "group_role_mapping_create"
	MappingAuditEventUpdate = "group_role_mapping_update"
	MappingAuditEventDelete = "group_role_mapping_delete"
)

// MappingSourceKind 由對外的來源型別字串取通道種類。
//
// 對外型別（ldap／oidc）與通道種類（directory／provider）刻意是兩套字面值：
// 前者是介面與路由的詞彙，後者是映射事實表主鍵的一部分。在此一處轉換，
// 其餘各處只用通道種類——兩套字面值在別處混用時，錯的那次會表現為
// 「規則設了卻永遠不命中」而沒有任何錯誤。
func MappingSourceKind(sourceType string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(sourceType)) {
	case "ldap":
		return model.RoleMappingChannelKindDirectory, nil
	case "oidc":
		return model.RoleMappingChannelKindProvider, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrMappingSourceKind, sourceType)
	}
}

// sourceAttrState 一個來源的群組讀取設定現況
type sourceAttrState struct {
	// exists 來源列是否存在
	exists bool
	// attrSet 群組屬性名（目錄）或群組宣告名（提供者）是否已設定
	attrSet bool
	// name 來源顯示名（審計用）
	name string
}

// resolveSource 讀取來源列的現況。查不到即 ErrMappingSourceNotFound。
func resolveSource(tx *gorm.DB, kind string, sourceID uint) (sourceAttrState, error) {
	switch kind {
	case model.RoleMappingChannelKindDirectory:
		var rows []model.LDAPDirectory
		if err := tx.Where("id = ?", sourceID).Limit(1).Find(&rows).Error; err != nil {
			return sourceAttrState{}, fmt.Errorf("讀取目錄設定失敗: %w", err)
		}
		if len(rows) == 0 {
			return sourceAttrState{}, ErrMappingSourceNotFound
		}
		return sourceAttrState{exists: true, attrSet: rows[0].AttrGroup != "", name: rows[0].Name}, nil
	case model.RoleMappingChannelKindProvider:
		var rows []model.OIDCProvider
		if err := tx.Where("id = ?", sourceID).Limit(1).Find(&rows).Error; err != nil {
			return sourceAttrState{}, fmt.Errorf("讀取身分提供者失敗: %w", err)
		}
		if len(rows) == 0 {
			return sourceAttrState{}, ErrMappingSourceNotFound
		}
		return sourceAttrState{exists: true, attrSet: rows[0].GroupsClaim != "", name: rows[0].Name}, nil
	default:
		return sourceAttrState{}, fmt.Errorf("%w: %q", ErrMappingSourceKind, kind)
	}
}

// validateMatchValue 依來源種類驗證比對值。
//
// 目錄側必須可解析為辨識名稱：解析不了的規則永遠不命中，而症狀是
// 「規則列在頁上、狀態是啟用、沒有一個人拿到角色」。存檔期是唯一有訊號的時刻。
// 提供者側各家宣告值的形態由提供者決定，非空即可。
func validateMatchValue(kind, raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", ErrMappingMatchValueEmpty
	}
	if len(v) > mappingMatchValueMaxLen {
		return "", fmt.Errorf("%w: 長度上限 %d", ErrMappingMatchValueEmpty, mappingMatchValueMaxLen)
	}
	if kind == model.RoleMappingChannelKindDirectory {
		if _, err := ldap.ParseDN(v); err != nil {
			return "", ErrMappingMatchValueDN
		}
	}
	return v, nil
}

// mappingWarningsOf 這條規則命中哪些需要確認的情形（順序固定，供比對穩定）
func mappingWarningsOf(roleName string, attrSet bool) []string {
	var out []string
	if roleName == model.RoleAdmin {
		out = append(out, mappingWarningTargetsAdminRole)
	}
	if !attrSet {
		out = append(out, mappingWarningSourceAttrUnset)
	}
	return out
}

// 警告機器碼（與 internal/apierror 的常數同值；服務層不 import HTTP 層）
const (
	mappingWarningTargetsAdminRole = "MAPPING_TARGETS_ADMIN_ROLE"
	mappingWarningSourceAttrUnset  = "MAPPING_SOURCE_ATTR_UNSET"
)

// ListMappings 某來源的全部規則（含停用者；管理端要看得到自己停掉的那條）
func (s *IdentitySourceService) ListMappings(kind string, sourceID uint) ([]GroupRoleMappingView, error) {
	if s == nil || s.db == nil {
		return nil, ErrMappingServiceUnavailable
	}
	if _, err := resolveSource(s.db, kind, sourceID); err != nil {
		return nil, err
	}
	rows, err := mappingRowsOf(s.db, kind, sourceID)
	if err != nil {
		return nil, err
	}
	return s.viewsOf(rows)
}

// mappingRowsOf 讀某來源的規則列（含角色關聯）
func mappingRowsOf(tx *gorm.DB, kind string, sourceID uint) ([]model.GroupRoleMapping, error) {
	column, err := roleMappingSourceColumn(kind)
	if err != nil {
		return nil, err
	}
	var rows []model.GroupRoleMapping
	if err := tx.Preload("Role").Where(column+" = ?", sourceID).
		Order("id").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("讀取群組映射規則失敗: %w", err)
	}
	return rows, nil
}

// viewsOf 組出對外形狀（建立者以帳號名呈現，查不到即留空）
func (s *IdentitySourceService) viewsOf(rows []model.GroupRoleMapping) ([]GroupRoleMappingView, error) {
	names, err := s.creatorNames(rows)
	if err != nil {
		return nil, err
	}
	out := make([]GroupRoleMappingView, 0, len(rows))
	for i := range rows {
		out = append(out, mappingViewOf(&rows[i], names[rows[i].CreatedBy]))
	}
	return out, nil
}

func (s *IdentitySourceService) creatorNames(rows []model.GroupRoleMapping) (map[uint]string, error) {
	ids := make([]uint, 0, len(rows))
	for i := range rows {
		ids = append(ids, rows[i].CreatedBy)
	}
	names := map[uint]string{}
	if len(ids) == 0 {
		return names, nil
	}
	type row struct {
		ID       uint
		Username string
	}
	var found []row
	if err := s.db.Model(&model.User{}).Select("id, username").
		Where("id IN ?", ids).Scan(&found).Error; err != nil {
		return nil, fmt.Errorf("讀取規則建立者失敗: %w", err)
	}
	for _, r := range found {
		names[r.ID] = r.Username
	}
	return names, nil
}

func mappingViewOf(row *model.GroupRoleMapping, creator string) GroupRoleMappingView {
	roleName := ""
	if row.Role != nil {
		roleName = row.Role.Name
	}
	return GroupRoleMappingView{
		ID:         row.ID,
		MatchValue: row.MatchValue,
		Role:       roleName,
		Enabled:    row.Enabled,
		CreatedBy:  creator,
		CreatedAt:  row.CreatedAt,
		UpdatedAt:  row.UpdatedAt,
	}
}

// CreateMapping 建立一條規則（驗證 → 確認 → 交易內建列與審計）
func (s *IdentitySourceService) CreateMapping(kind string, sourceID uint,
	in GroupRoleMappingInput) (*GroupRoleMappingView, error) {
	if s == nil || s.db == nil {
		return nil, ErrMappingServiceUnavailable
	}
	source, err := resolveSource(s.db, kind, sourceID)
	if err != nil {
		return nil, err
	}
	matchValue, err := validateMatchValue(kind, in.MatchValue)
	if err != nil {
		return nil, err
	}
	role, err := roleByName(s.db, in.Role)
	if err != nil {
		return nil, err
	}
	if warnings := mappingWarningsOf(role.Name, source.attrSet); len(warnings) > 0 && !in.RiskAcknowledged {
		return nil, &MappingAckRequiredError{Warnings: warnings}
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	row := &model.GroupRoleMapping{
		MatchValue: matchValue,
		RoleID:     role.ID,
		Enabled:    enabled,
		CreatedBy:  in.Actor.ID,
	}
	switch kind {
	case model.RoleMappingChannelKindDirectory:
		id := sourceID
		row.LDAPDirectoryID = &id
	case model.RoleMappingChannelKindProvider:
		id := sourceID
		row.OIDCProviderID = &id
	}
	// 建列與審計同交易：外部群組被授予角色的規則被建立卻無審計紀錄，
	// 不是可接受的終局（沿目錄設定服務的同一裁決）
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(row).Error; err != nil {
			return fmt.Errorf("建立群組映射規則失敗: %w", err)
		}
		return s.auditMapping(tx, in.Actor, model.ActionCreate, MappingAuditEventCreate,
			kind, sourceID, row, role.Name, in.RiskAcknowledged, source)
	}); err != nil {
		return nil, err
	}
	row.Role = role
	view := mappingViewOf(row, in.Actor.Name)
	return &view, nil
}

// UpdateMapping 更新一條規則（比對值、角色、啟用旗標）
func (s *IdentitySourceService) UpdateMapping(kind string, sourceID, ruleID uint,
	in GroupRoleMappingInput) (*GroupRoleMappingView, error) {
	if s == nil || s.db == nil {
		return nil, ErrMappingServiceUnavailable
	}
	source, err := resolveSource(s.db, kind, sourceID)
	if err != nil {
		return nil, err
	}
	row, err := mappingRowOf(s.db, kind, sourceID, ruleID)
	if err != nil {
		return nil, err
	}
	matchValue, err := validateMatchValue(kind, in.MatchValue)
	if err != nil {
		return nil, err
	}
	role, err := roleByName(s.db, in.Role)
	if err != nil {
		return nil, err
	}
	if warnings := mappingWarningsOf(role.Name, source.attrSet); len(warnings) > 0 && !in.RiskAcknowledged {
		return nil, &MappingAckRequiredError{Warnings: warnings}
	}
	row.MatchValue = matchValue
	row.RoleID = role.ID
	if in.Enabled != nil {
		row.Enabled = *in.Enabled
	}
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.GroupRoleMapping{}).Where("id = ?", row.ID).
			Updates(map[string]any{
				"match_value": row.MatchValue,
				"role_id":     row.RoleID,
				"enabled":     row.Enabled,
			}).Error; err != nil {
			return fmt.Errorf("更新群組映射規則失敗: %w", err)
		}
		return s.auditMapping(tx, in.Actor, model.ActionUpdate, MappingAuditEventUpdate,
			kind, sourceID, row, role.Name, in.RiskAcknowledged, source)
	}); err != nil {
		return nil, err
	}
	row.Role = role
	names, err := s.creatorNames([]model.GroupRoleMapping{*row})
	if err != nil {
		return nil, err
	}
	view := mappingViewOf(row, names[row.CreatedBy])
	return &view, nil
}

// DeleteMapping 刪除一條規則（軟刪；規則列的軟刪不影響已賦予的角色，
// 那些角色在該來源的下一次登入重算時才被收回——時效見營運文件）
func (s *IdentitySourceService) DeleteMapping(kind string, sourceID, ruleID uint,
	actor GroupRoleMappingActor) error {
	if s == nil || s.db == nil {
		return ErrMappingServiceUnavailable
	}
	source, err := resolveSource(s.db, kind, sourceID)
	if err != nil {
		return err
	}
	row, err := mappingRowOf(s.db, kind, sourceID, ruleID)
	if err != nil {
		return err
	}
	roleName := ""
	if row.Role != nil {
		roleName = row.Role.Name
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Delete(&model.GroupRoleMapping{}, row.ID).Error; err != nil {
			return fmt.Errorf("刪除群組映射規則失敗: %w", err)
		}
		return s.auditMapping(tx, actor, model.ActionDelete, MappingAuditEventDelete,
			kind, sourceID, row, roleName, false, source)
	})
}

// mappingRowOf 以（來源，規則識別）定址單條規則
func mappingRowOf(tx *gorm.DB, kind string, sourceID, ruleID uint) (*model.GroupRoleMapping, error) {
	column, err := roleMappingSourceColumn(kind)
	if err != nil {
		return nil, err
	}
	var rows []model.GroupRoleMapping
	if err := tx.Preload("Role").Where("id = ? AND "+column+" = ?", ruleID, sourceID).
		Limit(1).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("讀取群組映射規則失敗: %w", err)
	}
	if len(rows) == 0 {
		return nil, ErrMappingRuleNotFound
	}
	return &rows[0], nil
}

// roleByName 以角色名取角色列
func roleByName(tx *gorm.DB, name string) (*model.Role, error) {
	v := strings.TrimSpace(name)
	if v == "" {
		return nil, ErrMappingRoleUnknown
	}
	var rows []model.Role
	if err := tx.Where("name = ?", v).Limit(1).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("查詢角色失敗: %w", err)
	}
	if len(rows) == 0 {
		return nil, ErrMappingRoleUnknown
	}
	return &rows[0], nil
}

// auditMapping 寫一筆映射規則的審計列。
//
// resource 沿用既有的 model.ResourceAuth（同目錄設定服務）——不新增 resource
// 常數，前端審計頁的枚舉查譯即無新增無譯文機器碼的風險。
//
// **以角色名進 roles 欄**：審計列要答得出「升到哪個角色」，只送角色識別數字
// 的話稽核得自己去翻另一張表，而角色列可能已被改名或刪除。
func (s *IdentitySourceService) auditMapping(tx *gorm.DB, actor GroupRoleMappingActor,
	action model.AuditAction, event, kind string, sourceID uint,
	row *model.GroupRoleMapping, roleName string, acknowledged bool, source sourceAttrState) error {
	details := map[string]any{
		"event":             event,
		"source_kind":       kind,
		"source_id":         sourceID,
		"rule_id":           row.ID,
		"match_value":       row.MatchValue,
		"roles":             roleName,
		"enabled":           row.Enabled,
		"risk_acknowledged": acknowledged,
		"source_attr_set":   source.attrSet,
	}
	payload, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("序列化群組映射規則審計內容失敗: %w", err)
	}
	id := row.ID
	if err := port.WriteInTx(s.auditTx, tx, port.AuditEvent{
		Action:     string(action),
		Resource:   string(model.ResourceAuth),
		ResourceID: &id,
		Status:     string(model.StatusSuccess),
		Actor:      gatewayapi.Actor{UserID: actor.ID, Username: actor.Name},
		Request:    gatewayapi.RequestMeta{ClientIP: actor.IP},
		Details:    string(payload),
	}); err != nil {
		return fmt.Errorf("寫入群組映射規則審計失敗: %w", err)
	}
	return nil
}

// CountMappings 某來源的規則條數（全部與啟用中）。
//
// 「本來源有沒有啟用中的規則」在登入路徑上另有 hasActiveGroupRoleMappings，
// 兩者讀同一張表同一個條件——管理端要的是數字，登入端要的是存在性，
// 各自取自己需要的那一種，不共用一個回傳兩用的函式。
func CountMappings(tx *gorm.DB, kind string, sourceID uint) (total, enabled int64, err error) {
	column, cerr := roleMappingSourceColumn(kind)
	if cerr != nil {
		return 0, 0, cerr
	}
	if err := tx.Model(&model.GroupRoleMapping{}).Where(column+" = ?", sourceID).
		Count(&total).Error; err != nil {
		return 0, 0, fmt.Errorf("計算群組映射規則數失敗: %w", err)
	}
	if err := tx.Model(&model.GroupRoleMapping{}).
		Where(column+" = ? AND enabled = ?", sourceID, true).
		Count(&enabled).Error; err != nil {
		return 0, 0, fmt.Errorf("計算啟用中的群組映射規則數失敗: %w", err)
	}
	return total, enabled, nil
}
