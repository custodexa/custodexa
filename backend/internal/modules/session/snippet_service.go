package session

import (
	"errors"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 片段錯誤：handler 以 errors.Is 區分 400/404 與 500
var (
	ErrSnippetNotFound  = errors.New("片段不存在")
	ErrSnippetTooLong   = errors.New("片段內容超過 4096 字元上限")
	ErrSnippetNameEmpty = errors.New("片段名稱不可為空")
)

const snippetContentMaxLen = 4096

// SnippetRequest 片段建立/更新請求
type SnippetRequest struct {
	Name    string `json:"name" binding:"required"`
	Content string `json:"content" binding:"required"`
}

// SnippetService 使用者命令片段 CRUD：
// 全部查詢帶 user_id 條件，他人資源一律視為不存在（404）
type SnippetService struct {
	db *gorm.DB
}

// NewSnippetService 創建片段服務
func NewSnippetService(db *gorm.DB) *SnippetService {
	return &SnippetService{db: db}
}

func validateSnippet(req *SnippetRequest) error {
	if req.Name == "" {
		return ErrSnippetNameEmpty
	}
	if len(req.Content) > snippetContentMaxLen {
		return ErrSnippetTooLong
	}
	return nil
}

// List 列出指定使用者的全部片段
func (s *SnippetService) List(userID uint) ([]model.Snippet, error) {
	var snippets []model.Snippet
	if err := s.db.Where("user_id = ?", userID).Order("id").Find(&snippets).Error; err != nil {
		return nil, err
	}
	return snippets, nil
}

// Create 建立片段
func (s *SnippetService) Create(userID uint, req *SnippetRequest) (*model.Snippet, error) {
	if err := validateSnippet(req); err != nil {
		return nil, err
	}
	snippet := &model.Snippet{UserID: userID, Name: req.Name, Content: req.Content}
	if err := s.db.Create(snippet).Error; err != nil {
		return nil, err
	}
	return snippet, nil
}

// Update 更新片段（僅限本人）
func (s *SnippetService) Update(userID, id uint, req *SnippetRequest) (*model.Snippet, error) {
	if err := validateSnippet(req); err != nil {
		return nil, err
	}
	var snippet model.Snippet
	if err := s.db.Where("id = ? AND user_id = ?", id, userID).First(&snippet).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrSnippetNotFound
		}
		return nil, err
	}
	snippet.Name = req.Name
	snippet.Content = req.Content
	if err := s.db.Save(&snippet).Error; err != nil {
		return nil, err
	}
	return &snippet, nil
}

// Delete 刪除片段（僅限本人；他人資源回 NotFound 防越權探測）
func (s *SnippetService) Delete(userID, id uint) error {
	result := s.db.Where("id = ? AND user_id = ?", id, userID).Delete(&model.Snippet{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrSnippetNotFound
	}
	return nil
}
