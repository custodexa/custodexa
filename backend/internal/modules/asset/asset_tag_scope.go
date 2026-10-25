package asset

import (
	"fmt"
	"sort"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
)

// 標籤字典與書寫歸一的範圍化投影。
//
// 範圍化檢視者的字典、篩選與歸一都以「同一主體不帶篩選的資產列表集合」為準（由呼叫方算好傳入，
// 本模組不判定可視範圍）；其他主體沿全表彙整（ListTags）。只出現在集合外資產上的標籤不出現，
// 使用數只計集合內資產。

// ListTagsForAssetIDs 只彙整 ids 內未刪除資產的標籤：canonical 去重（保首見書寫形，以資產 id 序為準）、
// 只計這些資產的使用數、升冪排序。ids 為空回空清單（不是全表）。
func (s *AssetService) ListTagsForAssetIDs(ids []uint) ([]TagCount, error) {
	return listTagsOn(database.DB, ids, true)
}

// listTagsOn 標籤彙整的共用實作；restricted 為假時彙整全表（ListTags 的口徑）。
func listTagsOn(db *gorm.DB, ids []uint, restricted bool) ([]TagCount, error) {
	if restricted && len(ids) == 0 {
		return []TagCount{}, nil
	}
	q := db.Model(&model.Asset{}).Where("tags IS NOT NULL AND tags <> ''")
	if restricted {
		q = q.Where("id IN ?", ids)
	}
	var rawTags []string
	if err := q.Order("id ASC").Pluck("tags", &rawTags).Error; err != nil {
		return nil, fmt.Errorf("查詢標籤失敗: %w", err)
	}
	return aggregateTags(rawTags), nil
}

// aggregateTags rawTags 須已依資產 id 升冪。
func aggregateTags(rawTags []string) []TagCount {
	spelling := make(map[string]string) // canonical → 首見書寫形
	counts := make(map[string]int)      // canonical → 使用資產數
	for _, raw := range rawTags {
		for _, tag := range normalizeTagList(raw) {
			key := canonicalTag(tag)
			if _, ok := spelling[key]; !ok {
				spelling[key] = tag
			}
			counts[key]++
		}
	}
	out := make([]TagCount, 0, len(spelling))
	for key, name := range spelling {
		out = append(out, TagCount{Name: name, Count: counts[key]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
