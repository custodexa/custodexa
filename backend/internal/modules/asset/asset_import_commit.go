package asset

// 資產批次匯入的寫入：整批單一交易、全有或全無。
//
// 流程（與單筆建立同一組交易內步驟，見 createPreparedTx）：
//  1. 交易外以 validateImportBatch 逐列完整驗證（與預檢同一函式）；任一列有錯即
//     回 ImportRowsInvalidError，不開交易。
//  2. 固定鎖序取鎖：名稱鎖 → treeStructMu → 交易內憑證列鎖（依憑證 id 遞增）。
//  3. 單一交易內逐列：以路徑提交的列重算節點全路徑比對、再查名稱、以鎖住的憑證列
//     完整重驗，再寫資產、預設掛載、帳號稽核、節點掛載與節點稽核。
//  4. 交易內任一列重驗失敗即整筆回滾，回 ImportStateChangedError 標出該列與原因；
//     非重驗性錯誤（查詢失敗、稽核寫不進去）同樣整筆回滾，由呼叫端以內部錯誤處理。

import (
	"context"
	"errors"
	"sort"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// importTxRowError 交易內某一列失敗（帶列索引，供回報與回滾判定）
type importTxRowError struct {
	index int
	err   error
	// path 節點路徑比對失敗時的那一段路徑
	path string
}

func (e *importTxRowError) Error() string { return e.err.Error() }
func (e *importTxRowError) Unwrap() error { return e.err }

// errImportNodePathChanged 以路徑提交的列，其節點的當下全路徑與提交值不符
var errImportNodePathChanged = errors.New("節點路徑已變更")

// SetImportPreTxHookForTest 測試用：在交易外驗證通過之後、開交易之前呼叫 fn，
// 用以模擬「預檢後狀態被他人改變」。正式組裝不呼叫
func (s *AssetService) SetImportPreTxHookForTest(fn func()) {
	s.importPreTxHook = fn
}

// ImportAssets 整批寫入。ctx 須帶已驗證的操作者；createdBy／createdByName 為同一操作者，
// 寫入每台資產的建立者與帳號、節點稽核列
func (s *AssetService) ImportAssets(ctx context.Context, batch *ImportBatch,
	createdBy uint, createdByName string) (*ImportResult, error) {

	if err := checkBatchSize(batch); err != nil {
		return nil, err
	}
	ctx = operatorContext(ctx, createdBy, createdByName)
	preview, prepared, err := s.validateImportBatch(ctx, batch, createdBy, createdByName)
	if err != nil {
		return nil, err
	}
	if !preview.OK {
		return nil, &ImportRowsInvalidError{Preview: preview}
	}
	if s.importPreTxHook != nil {
		s.importPreTxHook()
	}

	// 固定鎖序：名稱鎖 → treeStructMu → 交易內憑證列鎖
	assetNameMu.Lock()
	defer assetNameMu.Unlock()
	treeStructMu.Lock()
	defer treeStructMu.Unlock()

	result := &ImportResult{AssetIDs: make([]uint, 0, len(prepared))}
	err = database.DB.Transaction(func(tx *gorm.DB) error {
		creds, lerr := lockImportCredentials(tx, prepared)
		if lerr != nil {
			return lerr
		}
		var currentPaths map[uint]string
		for i, p := range prepared {
			if paths := preview.Rows[i].Values.NodePaths; len(paths) > 0 {
				if currentPaths == nil {
					if currentPaths, lerr = NodePathMap(tx); lerr != nil {
						return lerr
					}
				}
				if bad, ok := nodePathsStillMatch(paths, p.nodeIDs, currentPaths); !ok {
					return &importTxRowError{index: i, err: errImportNodePathChanged, path: bad}
				}
			}
			created, cerr := s.createPreparedTx(ctx, tx, p, creds)
			if cerr != nil {
				return &importTxRowError{index: i, err: cerr}
			}
			result.AssetIDs = append(result.AssetIDs, p.asset.ID)
			if !created {
				result.CredentialPending++
			}
		}
		return nil
	})
	if err != nil {
		var rowErr *importTxRowError
		if errors.As(err, &rowErr) {
			if fe, ok := importTxFieldError(rowErr); ok {
				rep := preview.Rows[rowErr.index]
				rep.Errors = []ImportFieldError{fe}
				return nil, &ImportStateChangedError{Rows: []ImportRowReport{rep}}
			}
			return nil, rowErr.err
		}
		return nil, err
	}
	result.Created = len(result.AssetIDs)
	return result, nil
}

// lockImportCredentials 依憑證 id 遞增取全部所指憑證的列鎖。已不存在的憑證不在
// 結果內，交給該列的重驗回報「憑證不存在」（而不是讓整批以無列號的錯誤失敗）
func lockImportCredentials(tx *gorm.DB, prepared []*preparedAsset) (map[uint]*model.Credential, error) {
	seen := map[uint]bool{}
	ids := make([]uint, 0, len(prepared))
	for _, p := range prepared {
		if p.sharedCredentialID != 0 && !seen[p.sharedCredentialID] {
			seen[p.sharedCredentialID] = true
			ids = append(ids, p.sharedCredentialID)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	out := make(map[uint]*model.Credential, len(ids))
	for _, id := range ids {
		cred, err := lockCredentialRow(tx, id)
		if errors.Is(err, ErrCredentialNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out[id] = cred
	}
	return out, nil
}

// nodePathsStillMatch 以路徑提交的列：每段路徑在當下仍須唯一對應到預檢解析出的節點，
// 且每個節點的當下全路徑仍在提交的路徑中（節點被改名或搬移即不符）。回傳第一段對不上的路徑
func nodePathsStillMatch(paths []string, nodeIDs []uint, current map[uint]string) (string, bool) {
	want := make(map[uint]bool, len(nodeIDs))
	for _, id := range nodeIDs {
		want[id] = true
	}
	submitted := make(map[string]bool, len(paths))
	for _, p := range paths {
		submitted[p] = true
		var match []uint
		for id, cp := range current {
			if cp == p {
				match = append(match, id)
			}
		}
		if len(match) != 1 || !want[match[0]] {
			return p, false
		}
	}
	for _, id := range nodeIDs {
		if !submitted[current[id]] {
			return current[id], false
		}
	}
	return "", true
}

// importTxFieldError 交易內重驗失敗 → 列錯誤。只有「預檢後狀態被改變」這一類可對應到
// 某一欄；其餘（查詢失敗、稽核寫入失敗）回 false，由呼叫端以內部錯誤處理
func importTxFieldError(e *importTxRowError) (ImportFieldError, bool) {
	if errors.Is(e.err, errImportNodePathChanged) {
		return fieldErrP(importFieldNodes, apierror.CodeAssetImportNodePath, map[string]any{"path": e.path}), true
	}
	if _, isTag := tagValidationCodeOf(e.err); isTag {
		return ImportFieldError{}, false
	}
	return importFieldErrorFor(e.err)
}
