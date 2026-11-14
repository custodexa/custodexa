package asset

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 盤點結果的讀取（納管於讀取時計算）與處置（忽略、重新開啟）。

var (
	// ErrInventoryFindingNotFound 結果不存在或不屬於路徑上的資產（兩者回應相同）。
	ErrInventoryFindingNotFound = errors.New("inventory: finding not found")
	// ErrInventoryIgnoreReason 忽略理由不合格。
	ErrInventoryIgnoreReason = errors.New("inventory: invalid ignore reason")
)

const (
	inventoryIgnoreReasonMax = 500
	inventoryPageSizeMax     = 200
	inventoryPageSizeDefault = 50
)

// InventoryFindingView 一筆結果（含讀取時計算的納管狀態）。
type InventoryFindingView struct {
	model.HostAccountFinding
	Managed           bool     `json:"managed"`
	PrivilegedReasons []string `json:"privileged_reasons"`
	IgnoredReasons    []string `json:"ignored_reasons"`
}

// InventoryFindingQuery 單資產結果的篩選與分頁。nil 欄位不篩。
type InventoryFindingQuery struct {
	Privileged *bool
	Managed    *bool
	Present    *bool
	Status     string
	// Actionable 為 true 時排除系統預設帳號（不可登入且唯一特權理由為主要群組 root），即「需要處理」。
	Actionable bool
	Page       int
	PageSize   int
}

// InventoryScanView 一次盤點的讀取形狀：盤點列加登入身分名稱。
// 預設帳號模式回該帳號名（含已軟刪除者，查不到為空字串）；專用帳號模式一律為空字串，
// 專用帳號名只經專用帳號自己的讀取端點呈現。
type InventoryScanView struct {
	model.HostAccountScan
	IdentityUsername string `json:"identity_username"`
}

// InventoryNextIdentity 現在發起盤點會用誰登入。專用帳號模式的 Username 一律為空字串。
type InventoryNextIdentity struct {
	Mode     string `json:"mode"`
	Username string `json:"username"`
}

// AssetInventoryView 單資產的最近一次盤點與結果。
type AssetInventoryView struct {
	Scan         *InventoryScanView     `json:"scan"`
	NextIdentity *InventoryNextIdentity `json:"next_identity"`
	Coverage     []invCoverageItem      `json:"coverage"`
	FixedNotes   []string               `json:"fixed_notes"`
	Findings     []InventoryFindingView `json:"findings"`
	Total        int64                  `json:"total"`
	Page         int                    `json:"page"`
	PageSize     int                    `json:"page_size"`
}

// InventoryGlobalQuery 全域清單。AllowedAssetIDs 為 nil 時不限資產（呼叫端已判定可檢視全部）。
type InventoryGlobalQuery struct {
	AllowedAssetIDs []uint
	Page            int
	PageSize        int
}

type findingRow struct {
	model.HostAccountFinding
	Managed bool
}

func normalizePage(page, size int) (int, int) {
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = inventoryPageSizeDefault
	}
	if size > inventoryPageSizeMax {
		size = inventoryPageSizeMax
	}
	return page, size
}

func findingsBase(db *gorm.DB) *gorm.DB {
	return db.Table("host_account_findings AS f").
		Select("f.*, (aa.id IS NOT NULL) AS managed").
		Joins("LEFT JOIN asset_accounts aa ON aa.asset_id = f.asset_id AND aa.username = f.username AND aa.deleted_at IS NULL")
}

// excludeRoutineSystemAccounts 排除系統預設帳號（判準同 inventoryRoutineSystemAccount）。
func excludeRoutineSystemAccounts(db *gorm.DB) *gorm.DB {
	return db.Where("NOT (NOT f.login_capable AND f.privileged_reasons IN ?)", inventoryRoutineReasonSets)
}

func toViews(rows []findingRow) []InventoryFindingView {
	out := make([]InventoryFindingView, 0, len(rows))
	for _, r := range rows {
		v := InventoryFindingView{HostAccountFinding: r.HostAccountFinding, Managed: r.Managed,
			PrivilegedReasons: parseReasons(r.HostAccountFinding.PrivilegedReasons), IgnoredReasons: parseReasons(r.HostAccountFinding.IgnoredReasons)}
		if v.PrivilegedReasons == nil {
			v.PrivilegedReasons = []string{}
		}
		if v.IgnoredReasons == nil {
			v.IgnoredReasons = []string{}
		}
		out = append(out, v)
	}
	return out
}

// GetAssetInventory 單資產：最近一次盤點與結果。
func (s *HostAccountInventoryService) GetAssetInventory(assetID uint, q InventoryFindingQuery) (*AssetInventoryView, error) {
	var a model.Asset
	if err := s.db.First(&a, assetID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInventoryAssetNotFound
		}
		return nil, err
	}
	next, err := s.nextIdentity(&a)
	if err != nil {
		return nil, err
	}
	page, size := normalizePage(q.Page, q.PageSize)
	view := &AssetInventoryView{FixedNotes: inventoryFixedNotes, Coverage: []invCoverageItem{}, Page: page, PageSize: size, NextIdentity: next}
	var scan model.HostAccountScan
	err = s.db.Where("asset_id = ?", assetID).Order("id DESC").Limit(1).Take(&scan).Error
	switch {
	case err == nil:
		sv := &InventoryScanView{HostAccountScan: scan}
		if scan.IdentityMode == model.HostAccountIdentityDefault {
			sv.IdentityUsername = s.defaultIdentityName(scan.IdentityAccountID)
		}
		view.Scan = sv
		_ = json.Unmarshal([]byte(scan.Coverage), &view.Coverage)
	case !errors.Is(err, gorm.ErrRecordNotFound):
		return nil, err
	}
	base := findingsBase(s.db).Where("f.asset_id = ?", assetID)
	if q.Privileged != nil {
		base = base.Where("f.privileged = ?", *q.Privileged)
	}
	if q.Present != nil {
		base = base.Where("f.present = ?", *q.Present)
	}
	if q.Status != "" {
		base = base.Where("f.status = ?", q.Status)
	}
	if q.Actionable {
		base = excludeRoutineSystemAccounts(base)
	}
	if q.Managed != nil {
		if *q.Managed {
			base = base.Where("aa.id IS NOT NULL")
		} else {
			base = base.Where("aa.id IS NULL")
		}
	}
	if err := base.Session(&gorm.Session{}).Count(&view.Total).Error; err != nil {
		return nil, err
	}
	var rows []findingRow
	if err := base.Order("f.privileged DESC, f.username ASC").Offset((page - 1) * size).Limit(size).Scan(&rows).Error; err != nil {
		return nil, err
	}
	view.Findings = toViews(rows)
	return view, nil
}

// defaultIdentityName 預設帳號模式的盤點列登入帳號名；含已軟刪除的列，查不到為空字串。
func (s *HostAccountInventoryService) defaultIdentityName(accountID uint) string {
	var acc model.AssetAccount
	if err := s.db.Unscoped().Select("username").Where("id = ?", accountID).Limit(1).Find(&acc).Error; err != nil {
		return ""
	}
	return acc.Username
}

// nextIdentity 唯讀計算現在發起會用誰登入：有專用帳號掛載為 executor（不看能不能用），
// 否則有預設帳號為 default_account，兩者皆無或平台不支援為 nil。不解封、不取密。
// 讀專用帳號掛載出錯時回錯，不以 default_account 代答。
func (s *HostAccountInventoryService) nextIdentity(a *model.Asset) (*InventoryNextIdentity, error) {
	if !inventoryPlatformSupported(a) {
		return nil, nil
	}
	_, found, err := readInventoryExecutorMount(s.db, a.ID)
	if err != nil {
		return nil, err
	}
	if found {
		return &InventoryNextIdentity{Mode: model.HostAccountIdentityExecutor}, nil
	}
	var accs []model.AssetAccount
	if err := s.db.Where("asset_id = ? AND is_default = ?", a.ID, true).Limit(1).Find(&accs).Error; err != nil {
		return nil, err
	}
	if len(accs) == 0 {
		return nil, nil
	}
	return &InventoryNextIdentity{Mode: model.HostAccountIdentityDefault, Username: accs[0].Username}, nil
}

// InventoryGlobalView 全域清單。
type InventoryGlobalView struct {
	Findings []InventoryFindingView `json:"findings"`
	Total    int64                  `json:"total"`
	Page     int                    `json:"page"`
	PageSize int                    `json:"page_size"`
}

// globalFindingsQuery 全域清單的預設篩選：開啟、特權、仍存在、未納管、不是系統預設帳號、資產未刪除。
func globalFindingsQuery(db *gorm.DB, q InventoryGlobalQuery) *gorm.DB {
	base := excludeRoutineSystemAccounts(findingsBase(db).
		Joins("JOIN assets a ON a.id = f.asset_id AND a.deleted_at IS NULL").
		Where("f.status = ? AND f.privileged AND f.present AND aa.id IS NULL", model.HostAccountFindingOpen))
	if q.AllowedAssetIDs != nil {
		base = base.Where("f.asset_id IN ?", append([]uint{0}, q.AllowedAssetIDs...))
	}
	return base
}

// ListGlobalFindings 全域清單（依呼叫者可檢視的資產投影）。
func (s *HostAccountInventoryService) ListGlobalFindings(q InventoryGlobalQuery) (*InventoryGlobalView, error) {
	page, size := normalizePage(q.Page, q.PageSize)
	view := &InventoryGlobalView{Page: page, PageSize: size}
	base := globalFindingsQuery(s.db, q)
	if err := base.Session(&gorm.Session{}).Count(&view.Total).Error; err != nil {
		return nil, err
	}
	var rows []findingRow
	if err := base.Order("f.asset_id ASC, f.username ASC").Offset((page - 1) * size).Limit(size).Scan(&rows).Error; err != nil {
		return nil, err
	}
	view.Findings = toViews(rows)
	return view, nil
}

// validateIgnoreReason 去除首尾空白後 1 至 500 字元、不含控制字元。
func validateIgnoreReason(reason string) (string, error) {
	r := strings.TrimSpace(reason)
	n := utf8.RuneCountInString(r)
	if n < 1 || n > inventoryIgnoreReasonMax || !utf8.ValidString(r) {
		return "", ErrInventoryIgnoreReason
	}
	for _, c := range r {
		if unicode.IsControl(c) {
			return "", ErrInventoryIgnoreReason
		}
	}
	return r, nil
}

func (s *HostAccountInventoryService) loadFinding(tx *gorm.DB, assetID, findingID uint) (*model.HostAccountFinding, error) {
	var f model.HostAccountFinding
	err := tx.Where("id = ? AND asset_id = ?", findingID, assetID).Take(&f).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrInventoryFindingNotFound
	}
	return &f, err
}

func (s *HostAccountInventoryService) writeFindingAudit(tx *gorm.DB, action model.AuditAction, f *model.HostAccountFinding, actor InventoryActor, details map[string]any) error {
	b, err := json.Marshal(details)
	if err != nil {
		return err
	}
	assetID, id := f.AssetID, f.ID
	return port.WriteInTx(s.auditTx, tx, port.AuditEvent{
		OccurredAt: time.Now(),
		Actor:      gatewayapi.Actor{UserID: actor.UserID, Username: actor.Username},
		Action:     string(action),
		Resource:   model.AuditResourceHostAccountFinding,
		ResourceID: &id,
		AssetID:    &assetID,
		Status:     string(model.StatusSuccess),
		Request:    actor.requestMeta(),
		Details:    string(b),
	})
}

// IgnoreFinding 以理由忽略一筆結果，記下當下的特權理由快照；審計同交易。
func (s *HostAccountInventoryService) IgnoreFinding(assetID, findingID uint, reason string, actor InventoryActor) (*model.HostAccountFinding, error) {
	r, err := validateIgnoreReason(reason)
	if err != nil {
		return nil, err
	}
	var out *model.HostAccountFinding
	err = s.db.Transaction(func(tx *gorm.DB) error {
		f, err := s.loadFinding(tx, assetID, findingID)
		if err != nil {
			return err
		}
		now := time.Now()
		f.Status, f.IgnoreReason, f.IgnoredBy, f.IgnoredByName, f.IgnoredAt, f.IgnoredReasons =
			model.HostAccountFindingIgnored, r, actor.UserID, actor.Username, &now, f.PrivilegedReasons
		if err := tx.Model(&model.HostAccountFinding{}).Where("id = ?", f.ID).Updates(map[string]any{
			"status": f.Status, "ignore_reason": r, "ignored_by": actor.UserID, "ignored_by_name": actor.Username,
			"ignored_at": now, "ignored_reasons": f.IgnoredReasons,
		}).Error; err != nil {
			return err
		}
		out = f
		return s.writeFindingAudit(tx, model.ActionInventoryIgnore, f, actor, map[string]any{
			"asset_id": assetID, "username": f.Username, "reason": r, "reasons": parseReasons(f.IgnoredReasons),
		})
	})
	return out, err
}

// ReopenFinding 手動重新開啟一筆結果；審計同交易。
func (s *HostAccountInventoryService) ReopenFinding(assetID, findingID uint, actor InventoryActor) (*model.HostAccountFinding, error) {
	var out *model.HostAccountFinding
	err := s.db.Transaction(func(tx *gorm.DB) error {
		f, err := s.loadFinding(tx, assetID, findingID)
		if err != nil {
			return err
		}
		f.Status = model.HostAccountFindingOpen
		if err := tx.Model(&model.HostAccountFinding{}).Where("id = ?", f.ID).
			Update("status", model.HostAccountFindingOpen).Error; err != nil {
			return err
		}
		out = f
		return s.writeFindingAudit(tx, model.ActionInventoryReopen, f, actor, map[string]any{
			"asset_id": assetID, "username": f.Username,
		})
	})
	return out, err
}
