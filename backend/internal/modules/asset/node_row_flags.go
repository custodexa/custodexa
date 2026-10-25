package asset

import "errors"

// 節點樹與平面節點列表的範圍化讀取：列級旗標與可選節點標記。
//
// 旗標由 authz 依節點寫入的同一動作規則算出，asset 只負責把旗標放到回應列上；
// 非範圍化檢視者不帶任何旗標，回應鍵集與序列化結果維持不變（嵌入指標為 nil 時不輸出）。

// errNodeTreeFlagsMissing 範圍化檢視者的樹讀取缺旗標來源（組裝錯誤）。
var errNodeTreeFlagsMissing = errors.New("asset: node tree scope without flag source")

// NodeRowFlags 範圍化檢視者每個節點的列級旗標。旗標只代表授權層可嘗試：
// 引用阻擋、非空、同層同名、環路、深度與並發改變拓撲都不反映在旗標上。
// Manageable、LocatorOnly 只決定呈現樣式；操作是否可用只看各 Can*。
type NodeRowFlags struct {
	Manageable     bool `json:"manageable"`
	LocatorOnly    bool `json:"locator_only"`
	ScopeRoot      bool `json:"scope_root"`
	CanCreateChild bool `json:"can_create_child"`
	CanRename      bool `json:"can_rename"`
	CanMove        bool `json:"can_move"`
	CanDelete      bool `json:"can_delete"`
}

// NodeTreeScope 範圍化檢視者的樹讀取附加資訊（由 authz 算好交給 Tree）。
// ConnAssetIDs 為連線可視資產，用來判定 LocatorOnly（不在管理可視內、本身也沒有連線可視的直掛資產）；
// Flags 依節點識別碼回旗標（Manageable、ScopeRoot 與各 Can*），LocatorOnly 由 Tree 補上。
type NodeTreeScope struct {
	ConnAssetIDs map[uint]bool
	Flags        func(nodeIDs []uint) (map[uint]NodeRowFlags, error)
}

// WithLocator 依「是否有連線可視的直掛資產」補上 LocatorOnly，回傳新值（不改傳入值）。
func (f NodeRowFlags) WithLocator(hasConnDirect bool) NodeRowFlags {
	f.LocatorOnly = !f.Manageable && !hasConnDirect
	return f
}
