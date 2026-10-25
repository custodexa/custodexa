package api

import (
	"encoding/json"

	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz/disclosure"
)

// 範圍化檢視者的憑證回應：範圍外台數只在本層由純整數轉出（揭露登錄固定欄名與函式）。
// 非範圍化檢視者的回應鍵集不變（無範圍外台數欄、無 actions 欄）。

// withOutOfScopeCount 以既有序列化結果為底加上範圍外台數欄。
func withOutOfScopeCount(base any, n int) (map[string]any, error) {
	raw, err := json.Marshal(base)
	if err != nil {
		return nil, err
	}
	row := map[string]any{}
	if err := json.Unmarshal(raw, &row); err != nil {
		return nil, err
	}
	row[disclosure.FieldOutOfScopeAssetCount] = disclosure.Count(disclosure.OutOfScopeAssetCount, n)
	return row, nil
}

// credentialRowsJSON 列表資料列；範圍化檢視者的列另帶範圍外台數。
func credentialRowsJSON(items []*asset.CredentialDTO) ([]any, error) {
	out := make([]any, 0, len(items))
	for _, it := range items {
		if it.OutOfScopeAssets == nil {
			out = append(out, it)
			continue
		}
		row, err := withOutOfScopeCount(it, *it.OutOfScopeAssets)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, nil
}

// credentialDetailJSON 詳情；範圍化檢視者另帶範圍外台數，掛載列另帶範圍外歸屬節點數。
func credentialDetailJSON(d *asset.CredentialDetailDTO) (any, error) {
	if d.OutOfScopeAssets == nil {
		return d, nil
	}
	row, err := withOutOfScopeCount(d, *d.OutOfScopeAssets)
	if err != nil {
		return nil, err
	}
	bindings, err := credentialBindingRowsJSON(d.Bindings)
	if err != nil {
		return nil, err
	}
	row["bindings"] = bindings
	return row, nil
}

// credentialBindingRowsJSON 範圍化檢視者的掛載列：以既有序列化結果為底加上範圍外歸屬節點數。
func credentialBindingRowsJSON(items []*asset.CredentialBindingDTO) ([]any, error) {
	out := make([]any, 0, len(items))
	for _, it := range items {
		if it.OutOfScopeNodes == nil {
			out = append(out, it)
			continue
		}
		raw, err := json.Marshal(it)
		if err != nil {
			return nil, err
		}
		row := map[string]any{}
		if err := json.Unmarshal(raw, &row); err != nil {
			return nil, err
		}
		row[disclosure.FieldOutOfScopeNodeCount] = disclosure.Count(disclosure.OutOfScopeNodeCount, *it.OutOfScopeNodes)
		out = append(out, row)
	}
	return out, nil
}
