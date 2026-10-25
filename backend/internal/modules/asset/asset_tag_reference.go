package asset

import (
	"context"
	"strings"

	"gorm.io/gorm"
)

// 書寫歸一的參照：寫入標籤時「改存既有寫法」所比對的字典。
//
// 範圍化檢視者的參照是其可視資產上的標籤（與同一主體不帶篩選的資產列表同一集合），
// 其他主體是全表（現行）。範圍化主體寫入只在範圍外出現過的寫法時不被歸一，
// 回應與寫入全新標籤同形，不揭露範圍外是否存在同名標籤。

// TagReferencePort 歸一參照的可視集合來源（消費者側窄介面，由組裝根注入）。
//
// scoped 為假表示呼叫者不是範圍化檢視者，參照取全表；為真時以 ids 內的資產建參照（ids 可為空）。
type TagReferencePort interface {
	VisibleAssetIDsTx(ctx context.Context, tx *gorm.DB) (ids []uint, scoped bool, err error)
}

// SetTagReferencePort 注入歸一參照的可視集合來源（組裝時）。未注入時參照取全表（現行行為）。
func (s *AssetService) SetTagReferencePort(p TagReferencePort) { s.tagReference = p }

// tagSpellingRefTx 歸一參照：canonical → 參照內的首見寫法。系統呼叫者與未注入者取全表。
func (s *AssetService) tagSpellingRefTx(ctx context.Context, tx *gorm.DB) (map[string]string, error) {
	ids, scoped := []uint(nil), false
	if s.tagReference != nil && !isSystemCaller(ctx) {
		var err error
		if ids, scoped, err = s.tagReference.VisibleAssetIDsTx(ctx, tx); err != nil {
			return nil, err
		}
	}
	existing, err := listTagsOn(tx, ids, scoped)
	if err != nil {
		return nil, err
	}
	ref := make(map[string]string, len(existing))
	for _, tc := range existing {
		ref[canonicalTag(tc.Name)] = tc.Name
	}
	return ref, nil
}

// NormalizeTagsForWriteTx 寫入路徑正規化：切分、trim、canonical 去重，歸一至參照內的既有寫法
// （參照有「DBA」時存「Dba」改存「DBA」），再驗文法上限。參照沒有的寫法以請求內首見為準。
func (s *AssetService) NormalizeTagsForWriteTx(ctx context.Context, tx *gorm.DB, raw string) (string, error) {
	tags := normalizeTagList(raw)
	if len(tags) == 0 {
		return "", nil
	}
	ref, err := s.tagSpellingRefTx(ctx, tx)
	if err != nil {
		return "", err
	}
	return applyTagSpellingRef(tags, ref)
}

// applyTagSpellingRef tags 須已正規化（canonical 不重複）；就地歸一後驗上限並序列化。
func applyTagSpellingRef(tags []string, ref map[string]string) (string, error) {
	for i, tag := range tags {
		if known, ok := ref[canonicalTag(tag)]; ok {
			tags[i] = known
		}
	}
	if err := validateTagList(tags); err != nil {
		return "", err
	}
	return strings.Join(tags, ","), nil
}
