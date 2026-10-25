package main

import (
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
)

// newMappingAssignmentGuard 組出映射規則、釘住與直接指派共用的指派關卡。
//
// 可接受的目標集合是組裝時決定的：完整集合（升級前存量角色、新範本與自訂角色），
// 新範本與自訂角色因此可經直接、群組、映射與釘住指派，並照常經過保護角色、指派能力、
// 範圍欄位與 agent 等既有規則。這個函式刻意沒有參數：集合不是設定值，也不是請求可切換的開關；
// 要改變集合時改這一處，連同整條放行條件一起審。
func newMappingAssignmentGuard() *identity.AssignmentGuard {
	return identity.NewAssignmentGuard(identity.FullCatalog())
}

// wireScopedBindingReaders 把節點範圍指派用的唯讀讀取接到共用的指派關卡與授權變更分類器：
// 關卡的節點存在讀取（asset 提供，接受呼叫端交易）、關卡與分類器的節點涵蓋讀取共用同一個拓撲讀取器。
// 未接時帶節點範圍的寫入一律拒絕（關卡 fail-close），分類器的範圍比較退回只含節點自身。
func wireScopedBindingReaders(guard *identity.AssignmentGuard, topo *asset.ScopeTopologyReader) {
	guard.SetNodeExistenceReader(asset.NewNodeExistenceReader())
	guard.SetNodeCoverageReader(topo)
	authz.SetGrantNodeCoverReader(topo)
}
