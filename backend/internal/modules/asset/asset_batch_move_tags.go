package asset

import (
	"context"
	"fmt"
	"strings"
	"time"

	"golang.org/x/text/unicode/norm"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 批次搬移與批次加標籤（共用邊界見 asset_batch_service.go）。

// batchMovePlan 一台資產的歸屬變更。
type batchMovePlan struct {
	id       uint
	old, new []uint
}

// BatchMove 批次搬移：每台的新歸屬＝{目的節點} ∪ 該資產在操作者範圍外的既有歸屬（等同對該台送單筆
// node_ids=[目的節點]）；已是新歸屬者計入 Unchanged、不寫審計。涵蓋差異整批前後各取一次快照，
// 依資產拆到各自的掛載審計列；有變更時權限版本推進一次。
func (s *AssetService) BatchMove(ctx context.Context, ids []uint, targetNodeID uint) (BatchResult, error) {
	ids = DedupeBatchIDs(ids)
	if len(ids) == 0 {
		return BatchResult{}, ErrBatchEmpty
	}
	tag, err := newAssetBatchTag(len(ids))
	if err != nil {
		return BatchResult{}, err
	}
	userID, username := model.UserFromContext(ctx)
	hooks := assetBatchHooks(ctx)
	var res BatchResult
	err = s.runAssetBatchTx(ctx, true, func(tx *gorm.DB) error {
		items, err := s.precheckBatchTx(ctx, tx, AssetWriteUpdate, ids)
		if err != nil {
			return err
		}
		// 目的節點：不存在與已刪除回 ErrNodeNotFound；範圍外由合併判定回節點種類的範圍拒絕（同形寫出）
		if err := validateNodeIDsTx(tx, []uint{targetNodeID}); err != nil {
			return err
		}
		plans := make([]batchMovePlan, 0, len(items))
		for _, it := range items {
			merged, err := s.mergeNodesScopeTx(ctx, tx, it.id, it.current, []uint{targetNodeID})
			if err != nil {
				return err
			}
			if uintSetEqual(it.current, merged) {
				res.Unchanged++
				continue
			}
			plans = append(plans, batchMovePlan{id: it.id, old: it.current, new: merged})
		}
		if len(plans) == 0 {
			return nil
		}
		if err := s.beginTopologyChangeTx(tx); err != nil {
			return err
		}
		changedIDs := make([]uint, len(plans))
		for i, p := range plans {
			changedIDs[i] = p.id
		}
		cov, err := s.beginBatchCoverageTx(ctx, tx, changedIDs)
		if err != nil {
			return err
		}
		for i, p := range plans {
			if err := hooks.beforeItemWrite(tx, i); err != nil {
				return err
			}
			if err := replaceAssetNodes(tx, p.id, p.new); err != nil {
				return err
			}
		}
		perAsset, err := cov.finishTx(s, tx, changedIDs)
		if err != nil {
			return err
		}
		if userID != 0 {
			for _, p := range plans {
				if err := writeAssetNodeChangeAudit(s.auditTx, tx, p.id, p.old, p.new, perAsset[p.id], userID, username, tag); err != nil {
					return fmt.Errorf("記錄節點掛載變更失敗: %w", err)
				}
			}
		}
		res.Affected = len(plans)
		return s.advanceTopologyVersionTx(tx)
	})
	if err != nil {
		return BatchResult{}, err
	}
	return res, nil
}

// batchCoverage 批次掛載變更的前快照；skip 為真時（系統呼叫者且未注入）不取、審計列不帶涵蓋。
type batchCoverage struct {
	skip   bool
	before CoverageSnapshot
}

// beginBatchCoverageTx 寫掛載之前對整批取一次前快照；未注入時非系統呼叫者回 ErrCoverageSnapshotPortMissing。
func (s *AssetService) beginBatchCoverageTx(ctx context.Context, tx *gorm.DB, ids []uint) (*batchCoverage, error) {
	if s.coverage == nil {
		if isSystemCaller(ctx) {
			return &batchCoverage{skip: true}, nil
		}
		return nil, ErrCoverageSnapshotPortMissing
	}
	before, err := s.coverage.CoverageSnapshot(tx, ids)
	if err != nil {
		return nil, fmt.Errorf("取得變更前涵蓋失敗: %w", err)
	}
	return &batchCoverage{before: before}, nil
}

// finishTx 寫掛載之後對整批取一次後快照，依資產拆成單台快照後產出各自的差集；skip 時回空表。
func (b *batchCoverage) finishTx(s *AssetService, tx *gorm.DB, ids []uint) (map[uint]*TopologyCoverage, error) {
	out := make(map[uint]*TopologyCoverage, len(ids))
	if b == nil || b.skip {
		return out, nil
	}
	after, err := s.coverage.CoverageSnapshot(tx, ids)
	if err != nil {
		return nil, fmt.Errorf("取得變更後涵蓋失敗: %w", err)
	}
	for _, id := range ids {
		cov := BuildTopologyCoverage(coverageOfAsset(b.before, id), coverageOfAsset(after, id))
		out[id] = &cov
	}
	return out, nil
}

// coverageOfAsset 整批快照中單台資產的部分（與對該台單獨取快照同形）。
func coverageOfAsset(snap CoverageSnapshot, id uint) CoverageSnapshot {
	one := CoverageSnapshot{Assets: map[uint]AssetCoverage{}}
	if c, ok := snap.Assets[id]; ok {
		one.Assets[id] = c
	}
	return one
}

// normalizeBatchRequestTags 請求標籤：逐項先過文法驗證（空、逗號、單項長度），再 NFC、trim、canonical 去重（保首見）。
func normalizeBatchRequestTags(tags []string) ([]string, error) {
	out := make([]string, 0, len(tags))
	seen := make(map[string]bool, len(tags))
	for _, raw := range tags {
		if err := validateGovernanceTag(raw); err != nil {
			return nil, err
		}
		t := strings.TrimSpace(norm.NFC.String(raw))
		key := canonicalTag(t)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil, ErrBatchTagsEmpty
	}
	return out, nil
}

// BatchAddTags 批次加標籤：每台的新標籤＝現有 ∪ 請求。歸一只套在請求標籤上（參照為操作者可視字典，
// 批次交易內建一次），資產既有標籤的寫法不動。已含全部請求標籤者計入 Unchanged；任一台超過上限整批回
// 既有標籤驗證錯誤。寫入只改 tags 與 updated_at、不經更新 hook（該 hook 只寫一列無 diff 的更新審計），
// 改由本函式逐台寫一列帶 diff 與批次鍵的資產變更審計。
func (s *AssetService) BatchAddTags(ctx context.Context, ids []uint, tags []string) (BatchResult, error) {
	ids = DedupeBatchIDs(ids)
	if len(ids) == 0 {
		return BatchResult{}, ErrBatchEmpty
	}
	req, err := normalizeBatchRequestTags(tags)
	if err != nil {
		return BatchResult{}, err
	}
	tag, err := newAssetBatchTag(len(ids))
	if err != nil {
		return BatchResult{}, err
	}
	userID, username := model.UserFromContext(ctx)
	hooks := assetBatchHooks(ctx)
	var res BatchResult
	err = s.runAssetBatchTx(ctx, false, func(tx *gorm.DB) error {
		items, err := s.precheckBatchTx(ctx, tx, AssetWriteUpdate, ids)
		if err != nil {
			return err
		}
		ref, err := s.tagSpellingRefTx(ctx, tx)
		if err != nil {
			return err
		}
		spelled := make([]string, len(req))
		for i, t := range req {
			spelled[i] = t
			if known, ok := ref[canonicalTag(t)]; ok {
				spelled[i] = known
			}
		}
		for i, it := range items {
			row, err := lockAssetForUpdateTx(tx, it.id)
			if err != nil {
				return err
			}
			next, added := unionTags(normalizeTagList(row.Tags), spelled)
			if !added {
				res.Unchanged++
				continue
			}
			if err := validateTagList(next); err != nil {
				return err
			}
			if err := hooks.beforeItemWrite(tx, i); err != nil {
				return err
			}
			updated := *row
			updated.Tags = strings.Join(next, ",")
			updated.UpdatedAt = time.Now()
			if err := tx.Model(&model.Asset{}).Where("id = ?", it.id).
				UpdateColumns(map[string]any{"tags": updated.Tags, "updated_at": updated.UpdatedAt}).Error; err != nil {
				return fmt.Errorf("更新資產標籤失敗: %w", err)
			}
			if userID != 0 {
				if err := writeAssetChangeAudit(s.auditTx, tx, row, &updated, userID, username, model.ActionUpdate, "", tag); err != nil {
					return fmt.Errorf("記錄資產變更失敗: %w", err)
				}
			}
			res.Affected++
		}
		return nil
	})
	if err != nil {
		return BatchResult{}, err
	}
	return res, nil
}

// unionTags existing 之後依序補上 add 中 canonical 尚未出現者；added 表示有新增。
func unionTags(existing, add []string) ([]string, bool) {
	have := make(map[string]bool, len(existing)+len(add))
	for _, t := range existing {
		have[canonicalTag(t)] = true
	}
	out := append([]string(nil), existing...)
	added := false
	for _, t := range add {
		key := canonicalTag(t)
		if have[key] {
			continue
		}
		have[key] = true
		out = append(out, t)
		added = true
	}
	return out, added
}
