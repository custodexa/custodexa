package asset

// 批次新增資產的逐列範圍判定（預檢與提交共用；提交在交易內、拓撲序列化鎖之後以 tx 重算）。
//
// 兩個能力各自判定是否範圍化，不為主體快取單一旗標：
//   - 節點依資產建立能力：經寫入範圍判定（AuthorizeAssetCreate）。不帶節點的判定放行＝不限（全域），
//     回「歸屬不得為空」＝只經節點範圍持有；之後逐節點判定，範圍外與不存在同為該列的節點錯誤。
//   - 憑證依掛載能力：不帶目標的判定放行＝有全系統來源，照現行以整批目標判一次；否則逐張帶目標判定，
//     範圍拒絕（範圍外、全域歸屬、不存在）同為該列的「憑證不存在」，排在專用、協定、改密中、未收斂之前。
//
// 全域主體與系統呼叫者照現行（判定恆放行目標），回應不變。寫入範圍判定未注入時，非系統呼叫者的
// 預檢與提交回 ErrAssetWriteScopePortMissing（與單筆建立同一 fail-close，不在沒有判定的情況下放行）。

import (
	"context"
	"errors"
	"strings"

	"gorm.io/gorm"
)

// importScope 一次判定的結果；零值＝不限。
type importScope struct {
	// nodesLimited 資產建立能力只經節點範圍持有
	nodesLimited bool
	// nodeOut 範圍外的既有節點
	nodeOut map[uint]bool
	// credOut 掛載判定為範圍拒絕的憑證（只在掛載能力無全系統來源時逐張判）
	credOut map[uint]bool
}

// outOfScope 既有節點 id 是否在資產建立範圍外；nil 接收者＝不限。
func (sc *importScope) outOfScope(id uint) bool {
	return sc != nil && sc.nodeOut[id]
}

// scopeDeniedKindNode 節點種類的範圍拒絕（目標種類的機器字串）。
const scopeDeniedKindNode = "node"

var (
	// errImportCredentialUnavailable 提交時重算：該列的憑證已不在掛載判定範圍內（與不存在同形）。
	errImportCredentialUnavailable = errors.New("asset: import credential unavailable")
	// errImportNodeUnavailable 提交時重算：該列的節點已不在資產建立範圍內（與不存在同形）。
	errImportNodeUnavailable = errors.New("asset: import node unavailable")
	// errImportNodeRequired 提交時重算：主體只經節點範圍持有資產建立能力而該列未指定節點。
	errImportNodeRequired = errors.New("asset: import node required")
)

// importCredentialScope 掛既有憑證的列的掛載判定，先於任何憑證載入（db 為 nil＝交易外）。
// 有全系統來源者照現行以整批目標判一次；其餘逐張判定，範圍拒絕記入 credOut，能力拒絕整批回錯。
func (s *AssetService) importCredentialScope(ctx context.Context, db *gorm.DB, sc *importScope, credentialIDs []uint) error {
	if isSystemCaller(ctx) || len(credentialIDs) == 0 {
		return nil
	}
	_, err := s.mgmt.require(ctx, db, CredentialManagementRequest{
		Operation: CredOpBind, Capabilities: []string{CredCapBind},
	})
	if err == nil {
		return requireCreateCredentialCaps(s.mgmt, ctx, db, credentialIDs, 0, false, false, s.writeScope != nil)
	}
	var capErr *CapabilityDeniedError
	if !errors.As(err, &capErr) {
		return err
	}
	for _, id := range credentialIDs {
		d, err := s.mgmt.require(ctx, db, CredentialManagementRequest{
			Operation: CredOpBind, Capabilities: []string{CredCapBind}, CredentialIDs: []uint{id},
		})
		switch {
		case err == nil:
		case d.ScopeDenial != nil && errors.Is(err, d.ScopeDenial):
			if sc.credOut == nil {
				sc.credOut = map[uint]bool{}
			}
			sc.credOut[id] = true
		default:
			return err
		}
	}
	return nil
}

// importNodeScope 資產建立能力對 nodeIDs（皆為既有節點）的判定。
func (s *AssetService) importNodeScope(ctx context.Context, db *gorm.DB, sc *importScope, nodeIDs []uint) error {
	if isSystemCaller(ctx) {
		return nil
	}
	if s.writeScope == nil {
		return ErrAssetWriteScopePortMissing
	}
	err := s.writeScope.AuthorizeAssetCreate(ctx, db, nil)
	switch {
	case err == nil:
		return nil
	case !errors.Is(err, ErrAssetNodeRequired):
		return err
	}
	sc.nodesLimited = true
	for _, id := range nodeIDs {
		err := s.writeScope.AuthorizeAssetCreate(ctx, db, []uint{id})
		var denied scopeDeniedTarget
		switch {
		case err == nil:
		case errors.As(err, &denied) && denied.ScopeDeniedTargetKind() == scopeDeniedKindNode:
			if sc.nodeOut == nil {
				sc.nodeOut = map[uint]bool{}
			}
			sc.nodeOut[id] = true
		default:
			return err
		}
	}
	return nil
}

// importAccessPolicyScope 存取政策覆寫的逐列範圍（預檢與提交的交易外驗證共用）：節點欄已解析成功、
// 且帶非空覆寫的列，目的節點至少一個須在存取政策權限點的範圍內。任一列不符即整批拒絕，
// 回應與不持該權限點者的匯入相同，不逐列標示。
func (s *AssetService) importAccessPolicyScope(ctx context.Context, db *gorm.DB, rows []ImportRow,
	reports []ImportRowReport, nodeIDs [][]uint) error {
	var sets [][]uint
	for i := range rows {
		if rows[i].AccessPolicy == "" || rowHasFieldError(reports[i], importFieldNodes) {
			continue
		}
		sets = append(sets, nodeIDs[i])
	}
	return s.requireAccessPolicyCoverage(ctx, db, sets)
}

// requireAccessPolicyCoverage 每組目的節點都須至少一個在存取政策範圍內；空集合不判定。
func (s *AssetService) requireAccessPolicyCoverage(ctx context.Context, db *gorm.DB, sets [][]uint) error {
	if len(sets) == 0 {
		return nil
	}
	covered, err := s.accessPolicyCoversTx(ctx, db, sets)
	if err != nil {
		return err
	}
	for _, ok := range covered {
		if !ok {
			return accessPolicyScopeDenied(ctx)
		}
	}
	return nil
}

// rowHasFieldError 該列是否已有指定欄位的錯誤。
func rowHasFieldError(rep ImportRowReport, field string) bool {
	for _, e := range rep.Errors {
		if e.Field == field {
			return true
		}
	}
	return false
}

// isImportScopeRowError 交易內範圍重算的列錯誤。
func isImportScopeRowError(err error) bool {
	return errors.Is(err, errImportNodeUnavailable) || errors.Is(err, errImportCredentialUnavailable) ||
		errors.Is(err, errImportNodeRequired)
}

// importReferencedNodeIDs 各列引用的既有節點（路徑唯一比中者與存在的 node_ids），去重、序穩定。
func importReferencedNodeIDs(rows []ImportRow, lk *importLookups) []uint {
	var out []uint
	seen := map[uint]bool{}
	add := func(id uint) {
		if _, ok := lk.nodePaths[id]; ok && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for i := range rows {
		for _, p := range rows[i].NodePaths {
			if m := lk.pathToIDs[p]; len(m) == 1 {
				add(m[0])
			}
		}
		for _, id := range rows[i].NodeIDs {
			add(id)
		}
	}
	return out
}

// recheckImportScopeTx 提交交易內（拓撲序列化鎖之後、憑證列鎖之前）以交易內視圖重算逐列範圍。
// 任一列不過回該列的 importTxRowError（整批回滾）；全部通過時範圍化主體的每台補涵蓋審計。
func (s *AssetService) recheckImportScopeTx(ctx context.Context, tx *gorm.DB, prepared []*preparedAsset, rows []ImportRowReport) error {
	sc := &importScope{}
	if err := s.importCredentialScope(ctx, tx, sc, preparedCredentialIDs(prepared)); err != nil {
		return err
	}
	var nodeIDs []uint
	seen := map[uint]bool{}
	for _, p := range prepared {
		for _, id := range p.nodeIDs {
			if !seen[id] {
				seen[id] = true
				nodeIDs = append(nodeIDs, id)
			}
		}
	}
	if err := s.importNodeScope(ctx, tx, sc, nodeIDs); err != nil {
		return err
	}
	// 存取政策覆寫的範圍以交易內視圖重算（先於逐列錯誤；不符整批拒絕）
	var policySets [][]uint
	for _, p := range prepared {
		if p != nil && p.asset.AccessPolicy != nil && *p.asset.AccessPolicy != "" {
			policySets = append(policySets, p.nodeIDs)
		}
	}
	if err := s.requireAccessPolicyCoverage(ctx, tx, policySets); err != nil {
		return err
	}
	var currentPaths map[uint]string
	for i, p := range prepared {
		if sc.nodesLimited && len(p.nodeIDs) == 0 {
			return &importTxRowError{index: i, err: errImportNodeRequired}
		}
		for _, id := range p.nodeIDs {
			if !sc.nodeOut[id] {
				continue
			}
			paths := rows[i].Values.NodePaths
			if len(paths) > 0 && currentPaths == nil {
				var err error
				if currentPaths, err = NodePathMap(tx); err != nil {
					return err
				}
			}
			return &importTxRowError{index: i, err: errImportNodeUnavailable, path: importUserNodePath(paths, currentPaths[id])}
		}
		if p.sharedCredentialID != 0 && sc.credOut[p.sharedCredentialID] {
			return &importTxRowError{index: i, err: errImportCredentialUnavailable}
		}
	}
	if sc.nodesLimited {
		for _, p := range prepared {
			p.coverageAudit = true
		}
	}
	return nil
}

// importUserNodePath 該列以路徑指定節點時，回使用者填的那一段路徑（current 為該節點當下的全路徑；
// 已改名則回整列路徑，與「路徑不再相符」同形）；以 id 指定時回空字串。
func importUserNodePath(paths []string, current string) string {
	if len(paths) == 0 {
		return ""
	}
	for _, p := range paths {
		if p == current {
			return p
		}
	}
	return strings.Join(paths, ";")
}
