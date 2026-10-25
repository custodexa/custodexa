package asset

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"golang.org/x/text/unicode/norm"
	"gorm.io/gorm"
)

// 標籤文法上限：寫入與查詢兩端皆驗證
const (
	maxTagRunes      = 64  // 單一標籤字元數上限
	maxTagsPerAsset  = 20  // 每資產標籤數上限
	maxTagsSerialize = 500 // 序列化總長上限（對齊 assets.tags varchar(500)）
	maxTagsPerQuery  = 20  // 查詢參數標籤數上限
)

var (
	ErrTagTooLong       = errors.New("標籤長度超過上限（單項至多 64 字元）")
	ErrTooManyTags      = errors.New("標籤數量超過上限（至多 20 項）")
	ErrTagsTotalTooLong = errors.New("標籤總長度超過上限（合計至多 500 字元）")
	ErrTagEmpty         = errors.New("標籤不得為空")
	ErrTagContainsComma = errors.New("標籤不得含逗號")
)

// canonicalTag 標籤 canonical 相等鍵：NFC 正規化＋小寫折疊。
// 去重、清單 distinct、比對三處共用同一鍵，避免「Web/web」在清單成兩項
// 而篩選又視為同一項的三角不一致。
func canonicalTag(s string) string {
	return strings.ToLower(norm.NFC.String(s))
}

// normalizeTagList 逗號字串 → 正規化標籤序列：切分、NFC、trim、去空、
// canonical 去重（保留首見書寫形）。冪等：套兩次結果不變。
func normalizeTagList(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]bool, len(parts))
	for _, p := range parts {
		tag := strings.TrimSpace(norm.NFC.String(p))
		if tag == "" {
			continue
		}
		key := canonicalTag(tag)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, tag)
	}
	return out
}

// validateTagList 文法上限檢查（違規由 handler 映射為 400）
func validateTagList(tags []string) error {
	if len(tags) > maxTagsPerAsset {
		return ErrTooManyTags
	}
	total := 0
	for i, tag := range tags {
		if utf8.RuneCountInString(tag) > maxTagRunes {
			return ErrTagTooLong
		}
		total += len(tag)
		if i > 0 {
			total++ // 逗號分隔符
		}
	}
	if total > maxTagsSerialize {
		return ErrTagsTotalTooLong
	}
	return nil
}

// escapeLikeTag 跳脫 LIKE 萬用字元：`%`/`_`/`\` 三字元。SQL 端必須
// 搭配 ESCAPE '\' 使用——SQLite 的 LIKE 預設無跳脫字元，缺 ESCAPE 會造成
// 「測試綠、生產誤中」分岔（db_prod 誤中 dbxprod）。
var likeTagReplacer = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

func escapeLikeTag(s string) string {
	return likeTagReplacer.Replace(s)
}

// tagWholeWordCondition 整詞比對條件（前後補逗號式）；pattern 由
// tagWholeWordPattern 產生
const tagWholeWordCondition = `(',' || LOWER(tags) || ',') LIKE ? ESCAPE '\'`

func tagWholeWordPattern(tag string) string {
	return "%," + escapeLikeTag(canonicalTag(tag)) + ",%"
}

// TagCount 標籤與使用數（清單端點與治理介面共用）
type TagCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// ListTags 全表彙整既有標籤：canonical 去重（保首見書寫形，以資產 id
// 序為準）、附使用數、升冪排序。不建獨立 tag 表——本規模全表掃為毫秒級
// （postgres 實測 500 列 <1ms）。
func (s *AssetService) ListTags() ([]TagCount, error) {
	return listTagsOn(database.DB, nil, false)
}

// NormalizeTagsForWrite 以全表為參照的寫入正規化（系統呼叫者口徑）。
// 請求路徑一律改用 NormalizeTagsForWriteTx，依主體建參照。
func (s *AssetService) NormalizeTagsForWrite(raw string) (string, error) {
	return s.NormalizeTagsForWriteTx(WithSystemCaller(context.Background()), database.DB, raw)
}

// ParseTagsQuery 查詢參數解析（handler 用）：切分、trim、去空；超上限報錯。
func ParseTagsQuery(raw string) ([]string, error) {
	tags := normalizeTagList(raw)
	if len(tags) > maxTagsPerQuery {
		return nil, ErrTooManyTags
	}
	return tags, nil
}

// validateGovernanceTag 治理操作的單一標籤驗證（rename 的 to／delete 的 name）
func validateGovernanceTag(name string) error {
	if strings.TrimSpace(name) == "" {
		return ErrTagEmpty
	}
	if strings.Contains(name, ",") {
		return ErrTagContainsComma
	}
	if utf8.RuneCountInString(name) > maxTagRunes {
		return ErrTagTooLong
	}
	return nil
}

// rewriteAssetTags 治理共用迴圈：對含 matchTag（canonical 相等）的所有資產
// 以 mapFn 重寫標籤序列，單一交易內逐筆 GORM 更新（AfterUpdate hook 以
// ctx 操作者身分落審計——治理是操作者行為須留痕，與 migration 的無主
// 清洗不同）。回傳受影響資產數。
func rewriteAssetTags(ctx context.Context, matchTag string, mapFn func([]string) []string) (int64, error) {
	matchKey := canonicalTag(matchTag)
	var affected int64

	err := database.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var assets []model.Asset
		if err := tx.Where(tagWholeWordCondition, tagWholeWordPattern(matchTag)).
			Order("id ASC").Find(&assets).Error; err != nil {
			return fmt.Errorf("查詢受影響資產失敗: %w", err)
		}
		for i := range assets {
			tags := normalizeTagList(assets[i].Tags)
			has := false
			for _, t := range tags {
				if canonicalTag(t) == matchKey {
					has = true
					break
				}
			}
			if !has {
				continue // LIKE 已整詞比對，此為保險絲
			}
			newTags := mapFn(tags)
			if err := validateTagList(newTags); err != nil {
				return fmt.Errorf("資產 %d 重寫後標籤違規: %w", assets[i].ID, err)
			}
			joined := strings.Join(newTags, ",")
			if joined == assets[i].Tags {
				continue
			}
			if err := tx.Model(&assets[i]).Update("tags", joined).Error; err != nil {
				return fmt.Errorf("更新資產 %d 標籤失敗: %w", assets[i].ID, err)
			}
			affected++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return affected, nil
}

// RenameTag 全面改名：from→to 套用至所有含 from 的資產；to 與既有
// 標籤 canonical 相等時即為合併（歸一至既有書寫形），逐資產 canonical 去重。
func (s *AssetService) RenameTag(ctx context.Context, from, to string) (int64, error) {
	if strings.TrimSpace(from) == "" {
		return 0, ErrTagEmpty
	}
	if err := validateGovernanceTag(to); err != nil {
		return 0, err
	}
	to = strings.TrimSpace(norm.NFC.String(to))

	// 目標若 canonical 等於既有標籤，歸一至既有書寫形（合併語義一致性）
	existing, err := s.ListTags()
	if err != nil {
		return 0, err
	}
	toKey := canonicalTag(to)
	fromKey := canonicalTag(from)
	for _, tc := range existing {
		if canonicalTag(tc.Name) == toKey && canonicalTag(tc.Name) != fromKey {
			to = tc.Name
			break
		}
	}

	return rewriteAssetTags(ctx, from, func(tags []string) []string {
		mapped := make([]string, 0, len(tags))
		for _, t := range tags {
			if canonicalTag(t) == fromKey {
				mapped = append(mapped, to)
			} else {
				mapped = append(mapped, t)
			}
		}
		// canonical 去重（合併時同資產同時含 from 與 to 不留重複）
		return normalizeTagList(strings.Join(mapped, ","))
	})
}

// DeleteTag 刪除標籤：自所有含該標籤的資產移除，其餘標籤不動。
func (s *AssetService) DeleteTag(ctx context.Context, name string) (int64, error) {
	if strings.TrimSpace(name) == "" {
		return 0, ErrTagEmpty
	}
	key := canonicalTag(name)
	return rewriteAssetTags(ctx, name, func(tags []string) []string {
		kept := make([]string, 0, len(tags))
		for _, t := range tags {
			if canonicalTag(t) == key {
				continue
			}
			kept = append(kept, t)
		}
		return kept
	})
}
