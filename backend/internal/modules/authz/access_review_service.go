package authz

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// ErrReviewNotFound 複審紀錄不存在
var ErrReviewNotFound = errors.New("複審紀錄不存在")

// AccessMatrixEntry 存取矩陣單列（audit-workflows）：一筆授權的可讀展開。
// 主體分 user 或 user_group（二選一）、客體分 asset 或 asset_group（二選一），
// 與 asset_authorization 的 XOR 約束一致（主體側 nullable）
type AccessMatrixEntry struct {
	AuthorizationID uint      `json:"authorization_id"`
	UserID          *uint     `json:"user_id,omitempty"`
	Username        string    `json:"username,omitempty"`
	UserGroupID     *uint     `json:"user_group_id,omitempty"`
	UserGroupName   string    `json:"user_group_name,omitempty"`
	AssetID         *uint     `json:"asset_id,omitempty"`
	AssetName       string    `json:"asset_name,omitempty"`
	AssetGroupID    *uint     `json:"asset_group_id,omitempty"`
	GroupName       string    `json:"group_name,omitempty"`
	Permission      string    `json:"permission"`
	GrantedBy       uint      `json:"granted_by"`
	GrantedAt       time.Time `json:"granted_at"`
}

// AccessReviewView 複審紀錄視圖（含距今天數，不含大型 snapshot）
type AccessReviewView struct {
	model.AccessReview
	DaysAgo int `json:"days_ago"`
}

// AccessReviewService 週期性存取複審（audit-workflows v1，PCI 7.2.4）
type AccessReviewService struct {
	db *gorm.DB
}

// NewAccessReviewService 建立存取複審服務
func NewAccessReviewService(db *gorm.DB) *AccessReviewService {
	return &AccessReviewService{db: db}
}

// GetMatrix 產出當下完整存取矩陣（所有授權，join 用戶/資產/群組名稱）。
// 現有 authorization service 的 List 強制帶 user_id/asset_id，無法列全表，故此處直查
func (s *AccessReviewService) GetMatrix() ([]AccessMatrixEntry, error) {
	var entries []AccessMatrixEntry
	err := s.db.Model(&model.AssetAuthorization{}).
		Select(`asset_authorizations.id AS authorization_id,
			asset_authorizations.user_id AS user_id,
			users.username AS username,
			asset_authorizations.user_group_id AS user_group_id,
			user_groups.name AS user_group_name,
			asset_authorizations.asset_id AS asset_id,
			assets.name AS asset_name,
			asset_authorizations.asset_group_id AS asset_group_id,
			asset_groups.name AS group_name,
			asset_authorizations.permission AS permission,
			asset_authorizations.granted_by AS granted_by,
			asset_authorizations.created_at AS granted_at`).
		Joins("LEFT JOIN users ON users.id = asset_authorizations.user_id").
		Joins("LEFT JOIN user_groups ON user_groups.id = asset_authorizations.user_group_id").
		Joins("LEFT JOIN assets ON assets.id = asset_authorizations.asset_id").
		Joins("LEFT JOIN asset_groups ON asset_groups.id = asset_authorizations.asset_group_id").
		Where("asset_authorizations.deleted_at IS NULL").
		Order("asset_authorizations.id").
		Scan(&entries).Error
	if err != nil {
		return nil, fmt.Errorf("查詢存取矩陣失敗: %w", err)
	}
	return entries, nil
}

// CreateReview 提交一筆複審簽核（快照當下矩陣為不可變證據）。
// 回傳建立的紀錄（不含 snapshot，避免回應肥大）
func (s *AccessReviewService) CreateReview(reviewerID uint, reviewerName, note string) (*model.AccessReview, error) {
	matrix, err := s.GetMatrix()
	if err != nil {
		return nil, err
	}
	snapshot, err := json.Marshal(matrix)
	if err != nil {
		return nil, fmt.Errorf("序列化矩陣快照失敗: %w", err)
	}

	review := &model.AccessReview{
		ReviewedBy:         reviewerID,
		ReviewerName:       reviewerName,
		ReviewedAt:         time.Now(),
		Scope:              "全部使用者存取權（user × asset/group × permission）",
		Note:               note,
		AuthorizationCount: len(matrix),
		MatrixSnapshot:     string(snapshot),
	}
	if err := s.db.Create(review).Error; err != nil {
		return nil, fmt.Errorf("建立複審紀錄失敗: %w", err)
	}
	review.MatrixSnapshot = "" // 回應不帶大型快照
	return review, nil
}

// ListReviews 複審歷史（近→遠），附距今天數；不含 snapshot
func (s *AccessReviewService) ListReviews(limit int) ([]AccessReviewView, error) {
	if limit < 1 {
		limit = 50
	}
	var reviews []model.AccessReview
	if err := s.db.Order("reviewed_at DESC").Limit(limit).Find(&reviews).Error; err != nil {
		return nil, fmt.Errorf("查詢複審歷史失敗: %w", err)
	}
	views := make([]AccessReviewView, len(reviews))
	now := time.Now()
	for i := range reviews {
		reviews[i].MatrixSnapshot = "" // 列表不帶快照
		views[i] = AccessReviewView{
			AccessReview: reviews[i],
			DaysAgo:      int(math.Floor(now.Sub(reviews[i].ReviewedAt).Hours() / 24)),
		}
	}
	return views, nil
}

// LastReviewDaysAgo 距上次複審天數（-1 表示從未複審）。供儀表板「上次複審 N 天前」與逾期提示
func (s *AccessReviewService) LastReviewDaysAgo() (int, error) {
	var last model.AccessReview
	err := s.db.Order("reviewed_at DESC").First(&last).Error
	if err == gorm.ErrRecordNotFound {
		return -1, nil
	}
	if err != nil {
		return 0, fmt.Errorf("查詢上次複審失敗: %w", err)
	}
	return int(math.Floor(time.Now().Sub(last.ReviewedAt).Hours() / 24)), nil
}

// GetReviewSnapshot 取單筆複審的矩陣快照（供證據匯出/檢視）
func (s *AccessReviewService) GetReviewSnapshot(reviewID uint) (string, error) {
	var review model.AccessReview
	if err := s.db.First(&review, reviewID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return "", ErrReviewNotFound
		}
		return "", err
	}
	return review.MatrixSnapshot, nil
}

// ReviewPeriodDays 複審建議週期（v1 固定 180 天，
// 週期值與逾期判定由伺服端回傳，前端不硬編碼；政策鍵化登 backlog）
const ReviewPeriodDays = 180

// ErrReviewSnapshotCorrupted 快照損壞（不可解析），回明確錯誤而非空內容
var ErrReviewSnapshotCorrupted = errors.New("複審快照損壞，無法解析")

// AccessReviewDetail 單筆複審檢視 DTO：
// 中繼資料＋解析後的矩陣陣列（型別化，前端抽屜契約固定）
type AccessReviewDetail struct {
	ID                 uint                `json:"id"`
	ReviewedBy         uint                `json:"reviewed_by"`
	ReviewerName       string              `json:"reviewer_name"`
	ReviewedAt         time.Time           `json:"reviewed_at"`
	Scope              string              `json:"scope"`
	Note               string              `json:"note"`
	AuthorizationCount int                 `json:"authorization_count"`
	Matrix             []AccessMatrixEntry `json:"matrix"`
}

// GetReviewDetail 取單筆複審完整內容：快照 json.Unmarshal 為矩陣陣列，
// 損壞快照回 ErrReviewSnapshotCorrupted（明確 500，不回空內容謊稱正常）
func (s *AccessReviewService) GetReviewDetail(reviewID uint) (*AccessReviewDetail, error) {
	var review model.AccessReview
	if err := s.db.First(&review, reviewID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrReviewNotFound
		}
		return nil, fmt.Errorf("查詢複審紀錄失敗: %w", err)
	}
	var matrix []AccessMatrixEntry
	if err := json.Unmarshal([]byte(review.MatrixSnapshot), &matrix); err != nil {
		return nil, ErrReviewSnapshotCorrupted
	}
	return &AccessReviewDetail{
		ID:                 review.ID,
		ReviewedBy:         review.ReviewedBy,
		ReviewerName:       review.ReviewerName,
		ReviewedAt:         review.ReviewedAt,
		Scope:              review.Scope,
		Note:               review.Note,
		AuthorizationCount: review.AuthorizationCount,
		Matrix:             matrix,
	}, nil
}
