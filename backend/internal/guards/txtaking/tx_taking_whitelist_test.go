package txtaking

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"golang.org/x/tools/go/packages"
)

// tx-taking 跨模組寫入白名單。
//
// **這個守衛存在的唯一理由**：把 `*gorm.DB` 交給別的模組之後，
// **編譯器與資料邊界閘門（6.0b ratchet）都看不見對方寫了哪張表**——
// 寫入發生在 authz 的方法體內、對象是 authz 自有的表，掃描器判為「自己寫自己」，
// 而真正的事實是「asset／identity 的交易在寫 authz 的表」。ratchet 因此會顯示
// 「乾淨」，這正是「跨模組存取只經對外介面（編譯器可證）」這條規則
// 在此類路徑上名存實亡的具體形狀。
//
// 本守衛以三個彼此獨立的軸維持可審計性：
//
//	A. **呼叫點必登記**——非 authz 的非測試檔呼叫任何 tx-taking 方法，未登記即紅。
//	B. **登記必存在＋必附理由**——登記項在現實中消失即紅（防白名單越留越寬）；
//	   理由空白即紅（防「先加一列再說」）。
//	C. **偵測器健康**——authz 對外的 tx-taking 匯出方法集合必須與登記的被呼叫方
//	   集合逐字相同。新增一個 tx-taking 匯出方法卻沒登記，A 軸抓不到
//	   （沒人呼叫就沒有呼叫點），C 軸抓得到。
//
// **本守衛擋不住的事（誠實界定，不得省略）**：有 commit 權者可以刪掉本檔；
// 也可以在 authz 的方法體內對任何一張表下手——白名單只保證「哪些呼叫點把交易交出去」
// 這件事是被登記且被審視過的，**不保證交出去之後發生了什麼**。

// txTakingEntry 一筆 tx-taking 跨模組寫入登記。
type txTakingEntry struct {
	// CallerFile 呼叫點所在檔（相對 module 根）
	CallerFile string
	// Callee authz 對外的 tx-taking 方法名
	Callee string
	// OriginalSites 具名白名單所列的原始寫入點（收口前的 file:line）。
	// 收口把多個 Delete 併進一個方法，這一欄使「五處」與現況呼叫點的對應不失聯。
	OriginalSites []string
	// Reason 為何非得把交易交出去（空白即紅）
	Reason string
}

// txTakingWhitelist 交易級聯類的原始寫入點收口後的呼叫點。
// 原為五處寫入點／三個呼叫點；資產刪除新增一處；
// 離機排隊點兩處（session.UpdateRecording、audit.completeJob）。
var txTakingWhitelist = []txTakingEntry{
	{
		CallerFile: "internal/api/authorization_handler.go",
		Callee:     "SelfSubjects",
		OriginalSites: []string{
			"（新增）本人範圍查詢端點讀取操作者自己、所屬群組與擁有的 agent",
		},
		Reason: "本人範圍與建立授權規則時的防自我授權判定共用同一個查詢函式，" +
			"畫面停用的對象與服務端拒絕的對象才不會分歧；函式簽名因此收交易句柄。" +
			"本呼叫點傳入的是一般連線、不在任何交易內，方法只讀使用者、群組成員與 agent 擁有者，" +
			"不寫任何表。",
	},
	{
		CallerFile: "internal/modules/identity/user_service.go",
		Callee:     "CheckOwnerTransfer",
		OriginalSites: []string{
			"（新增）agent 擁有者轉移在變更擁有者的交易內檢查新擁有者的既有授權足跡",
		},
		Reason: "擁有者轉移必須與「新擁有者建立以該 agent 為主體的規則、對該 agent 的申請投票」" +
			"以同一把鎖序列化：呼叫端先鎖 agent 的使用者列，再在同一交易內查新擁有者建立的有效規則、" +
			"申請人型審核範圍與有效核准票，命中即整筆回滾。交易外判定會留下「判定通過後、" +
			"轉移寫入前」新建規則的窗口。方法只讀（含列鎖），不寫任何 authz 表。",
	},
	{
		CallerFile: "cmd/server/credential_management_adapter.go",
		Callee:     "HasAllCapabilities",
		OriginalSites: []string{
			"（新增）憑證管理授權 adapter 在呼叫端交易內重驗能力",
		},
		Reason: "憑證管理的授權判定必須在呼叫端的交易內進行：與影響集合、鎖序在同一個一致讀取點，" +
			"避免「判定通過後、寫入前」權限被撤銷的窗口。該方法只讀（使用者、角色、權限世代），" +
			"不寫任何 authz 表；交易句柄只用來讓讀取落在同一個交易快照。",
	},
	{
		CallerFile: "internal/modules/asset/asset_group_service.go",
		Callee:     "RevokeByAssetGroup",
		OriginalSites: []string{
			"internal/service/asset_group_service.go:512（Delete AssetAuthorization）",
			"internal/service/asset_group_service.go:519（Delete ApproverScope）",
		},
		Reason: "刪除資產節點必須與「撤銷掛在該節點上的授權與審核範圍」原子成立：" +
			"節點刪了而授權留著＝幽靈授權（授權列表顯示已不存在的客體），" +
			"授權撤了而節點刪除回滾＝無故失權。asset 不得 import authz（禁止邊），" +
			"authz 也不能反過來驅動 asset 的刪除交易，故只能由 asset 交出交易句柄。",
	},
	{
		// 呼叫點隨資產刪除的交易內層（DeleteTx，可接收外部交易）移到 asset_write_scope_tx.go；
		// 撤銷語意與同交易原子性不變
		CallerFile: "internal/modules/asset/asset_write_scope_tx.go",
		Callee:     "RevokeByAsset",
		OriginalSites: []string{
			"internal/modules/asset/asset_service.go:1092（Delete AssetAuthorization，" +
				"初版直接寫 authz 的表，撞資料邊界閘門後收口）",
		},
		Reason: "刪除資產必須與「撤銷該資產的授權與審核範圍」原子成立：" +
			"權限查詢只查 asset_authorizations、不 join assets，資產刪了而授權留著" +
			"＝已刪資產的授權在權限判定中仍然命中（本 change 要修的缺陷本體）；" +
			"授權撤了而資產刪除回滾＝無故失權。ApproverScope.AssetID 同理——" +
			"資產消失後留下的是懸掛範圍。" +
			"asset 不得 import authz（禁止邊），authz 也不能反過來驅動 asset 的" +
			"刪除交易，故只能由 asset 交出交易句柄。與 RevokeByAssetGroup 是同一類" +
			"問題的兩個粒度（節點／單一資產）。",
	},
	{
		CallerFile: "internal/modules/asset/topology_permission.go",
		Callee:     "AdvanceVersion",
		OriginalSites: []string{
			"（新增）拓撲寫入交易（單筆建立、批次匯入、掛載集合改變的更新）經 asset 端窄介面呼叫 authz 的拓撲鎖與權限版本動作",
		},
		Reason: "拓撲（資產掛載集合）改變必須與權限版本推進原子成立，否則舊快取在拓撲改變後繼續放行；asset 不得 import authz（禁止邊）。",
	},
	{
		CallerFile: "internal/modules/asset/topology_permission.go",
		Callee:     "BeginPermissionChange",
		OriginalSites: []string{
			"（新增）拓撲寫入交易（單筆建立、批次匯入、掛載集合改變的更新）經 asset 端窄介面呼叫 authz 的拓撲鎖與權限版本動作",
		},
		Reason: "權限事件鏈的寫入前校準，須與拓撲寫入同一交易；不取鎖。",
	},
	{
		CallerFile: "internal/modules/asset/topology_permission.go",
		Callee:     "LockTopology",
		OriginalSites: []string{
			"（新增）拓撲寫入交易（單筆建立、批次匯入、掛載集合改變的更新）經 asset 端窄介面呼叫 authz 的拓撲鎖與權限版本動作",
		},
		Reason: "拓撲序列化鎖必須在拓撲寫入交易內取得並持有到交易結束，且是交易第一個動作，所以只能由 asset 交出交易句柄；鎖本身不寫任何表。",
	},
	{
		CallerFile: "internal/modules/asset/asset_group_scope_port.go",
		Callee:     "AuthorizeNodeCreate",
		OriginalSites: []string{
			"（新增）節點寫入交易（建立、改名、改描述、搬移、刪除）在取得拓撲序列化鎖之後經 asset 端窄介面呼叫 authz",
		},
		Reason: "建立節點的範圍判定必須在取得拓撲序列化鎖之後、於同一交易重讀主體與拓撲，判定與寫入之間不得有指派或拓撲變動；只讀、不取鎖、不寫表。",
	},
	{
		CallerFile: "internal/modules/asset/asset_group_scope_port.go",
		Callee:     "AuthorizeNodeEdit",
		OriginalSites: []string{
			"（新增）節點寫入交易（建立、改名、改描述、搬移、刪除）在取得拓撲序列化鎖之後經 asset 端窄介面呼叫 authz",
		},
		Reason: "改名、改描述與刪除節點的範圍判定（嚴格子孫規則）必須在取鎖後同交易重讀主體與拓撲；只讀、不取鎖、不寫表。",
	},
	{
		CallerFile: "internal/modules/asset/asset_group_scope_port.go",
		Callee:     "AuthorizeNodeMove",
		OriginalSites: []string{
			"（新增）節點寫入交易（建立、改名、改描述、搬移、刪除）在取得拓撲序列化鎖之後經 asset 端窄介面呼叫 authz",
		},
		Reason: "搬移節點的來源、目的與「子樹含範圍節點」判定必須在取鎖後同交易讀取；只讀、不取鎖、不寫表。",
	},
	{
		CallerFile: "internal/modules/asset/asset_group_scope_port.go",
		Callee:     "NodeScopeReferences",
		OriginalSites: []string{
			"（新增）節點寫入交易（建立、改名、改描述、搬移、刪除）在取得拓撲序列化鎖之後經 asset 端窄介面呼叫 authz",
		},
		Reason: "節點刪除前的範圍引用查詢必須與刪除同交易：查詢後、刪除前若有新指派引用該節點，刪除不得完成；只讀、不取鎖、不寫表。",
	},
	{
		CallerFile: "internal/modules/asset/asset_write_scope_tx.go",
		Callee:     "AuthorizeAssetCreate",
		OriginalSites: []string{
			"（新增）資產寫入交易（建立、更新、停用、刪除）在取得拓撲序列化鎖之後經 asset 端窄介面呼叫 authz",
		},
		Reason: "建立資產的初始歸屬判定必須在取得拓撲序列化鎖之後、於同一交易重讀主體與拓撲，判定與寫入之間不得有指派或拓撲變動；只讀、不取鎖、不寫表。",
	},
	{
		CallerFile: "internal/modules/asset/asset_write_scope_tx.go",
		Callee:     "AuthorizeAssetWrite",
		OriginalSites: []string{
			"（新增）資產寫入交易（建立、更新、停用、刪除）在取得拓撲序列化鎖之後經 asset 端窄介面呼叫 authz",
		},
		Reason: "更新、停用與刪除的範圍與刪停歸屬判定必須在取鎖後同交易重讀主體與資產歸屬，每筆依自己裁決當下的歸屬判定；只讀、不取鎖、不寫表。",
	},
	{
		CallerFile: "internal/modules/asset/asset_write_scope_tx.go",
		Callee:     "MergeAssetNodes",
		OriginalSites: []string{
			"（新增）資產寫入交易（建立、更新、停用、刪除）在取得拓撲序列化鎖之後經 asset 端窄介面呼叫 authz",
		},
		Reason: "節點合併要以同交易內的現行歸屬與重讀的主體計算可替換部分，與掛載寫入之間不得有歸屬變動；只讀、不取鎖、不寫表。",
	},
	{
		CallerFile: "internal/modules/asset/asset_account_write_scope.go",
		Callee:     "AuthorizeAccountWrite",
		OriginalSites: []string{
			"（新增）資產帳號寫入交易（建立、更新、刪除、設預設）在取得拓撲序列化鎖之後經 asset 端窄介面呼叫 authz",
		},
		Reason: "帳號寫入隨所屬資產判定，須在取鎖後同交易重讀主體與資產歸屬，早於資產列鎖與憑證列鎖；只讀、不取鎖、不寫表。",
	},
	{
		CallerFile: "internal/modules/asset/asset_write_scope_tx.go",
		Callee:     "CoverageSnapshot",
		OriginalSites: []string{
			"（新增）資產初始掛載與掛載變更在寫入前後各取一次涵蓋快照，經 asset 端窄介面呼叫 authz",
		},
		Reason: "涵蓋差異要附在同一交易的掛載審計列，前後兩次快照須讀同一交易內的狀態；只讀、不取鎖、不寫表。",
	},
	{
		CallerFile: "internal/modules/asset/asset_batch_move_tags.go",
		Callee:     "CoverageSnapshot",
		OriginalSites: []string{
			"（新增）資產批次搬移交易在寫入掛載前後對整批各取一次涵蓋快照，經 asset 端窄介面呼叫 authz",
		},
		Reason: "整批一次前後快照要拆到同一交易的各資產掛載審計列，前後兩次須讀同一交易內的狀態（寫入後的快照要看得到本交易的寫入）；只讀、不取鎖、不寫表。",
	},
	{
		CallerFile: "internal/modules/asset/topology_coverage.go",
		Callee:     "CoverageSnapshot",
		OriginalSites: []string{
			"（新增）節點搬移交易在寫入前後各取一次涵蓋快照，經 asset 端窄介面呼叫 authz",
		},
		Reason: "涵蓋差異要附在同一交易的搬移審計列，前後兩次快照須讀同一交易內的狀態（寫入後的快照要看得到本交易的寫入）；只讀、不取鎖、不寫表。",
	},
	{
		CallerFile: "internal/modules/identity/auth_service.go",
		Callee:     "AdvanceVersion",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/auth_service.go",
		Callee:     "BeginPermissionChange",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/external_identity_service.go",
		Callee:     "AdvanceVersion",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/external_identity_service.go",
		Callee:     "BeginPermissionChange",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/external_identity_service.go",
		Callee:     "SettlePermissionChange",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/group_role_mapping_service.go",
		Callee:     "AdvanceVersion",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/group_role_mapping_service.go",
		Callee:     "BeginPermissionChange",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/ldap_directory_service.go",
		Callee:     "BeginPermissionChange",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/mapping_revocation.go",
		Callee:     "AdvanceVersion",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/mapping_revocation.go",
		Callee:     "SettlePermissionChange",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/mapping_supports.go",
		Callee:     "AdvanceVersion",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/oidc_login_service.go",
		Callee:     "AdvanceVersion",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/oidc_login_service.go",
		Callee:     "BeginPermissionChange",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/oidc_provider_service.go",
		Callee:     "BeginPermissionChange",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/role_definition_service.go",
		Callee:     "AdvanceVersion",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/role_definition_service.go",
		Callee:     "BeginPermissionChange",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/role_definition_service.go",
		Callee:     "SettlePermissionChange",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/role_mapping_recompute.go",
		Callee:     "BeginPermissionChange",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/role_mapping_recompute.go",
		Callee:     "SettlePermissionChange",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/role_binding_scope.go",
		Callee:     "AdvanceVersion",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/role_source_transitions.go",
		Callee:     "AdvanceVersion",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/role_source_transitions.go",
		Callee:     "SettlePermissionChange",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/user_group_mapping_service.go",
		Callee:     "AdvanceVersion",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/user_group_mapping_service.go",
		Callee:     "BeginPermissionChange",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/user_group_role_bindings.go",
		Callee:     "AdvanceVersion",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/user_group_role_bindings.go",
		Callee:     "BeginPermissionChange",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/user_group_role_bindings.go",
		Callee:     "SettlePermissionChange",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/user_group_service.go",
		Callee:     "AdvanceVersion",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/user_group_service.go",
		Callee:     "BeginPermissionChange",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/user_group_service.go",
		Callee:     "SettlePermissionChange",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/user_role_pin.go",
		Callee:     "BeginPermissionChange",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/user_service.go",
		Callee:     "AdvanceVersion",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/user_service.go",
		Callee:     "BeginPermissionChange",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/user_service.go",
		Callee:     "SettlePermissionChange",
		OriginalSites: []string{
			"（新增登記）權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "權限相關寫入與版本推進（或事件鏈校準、補記）必須在同一個交易內原子成立；identity 在自己的權限寫入交易內呼叫 authz 的包級函式，呼叫形態與既有行為不變。",
	},
	{
		CallerFile: "internal/modules/identity/user_group_service.go",
		Callee:     "RevokeByUserGroup",
		OriginalSites: []string{
			"internal/modules/identity/user_group_service.go:104（Delete AssetAuthorization）",
			"internal/modules/identity/user_group_service.go:115（Delete ApproverScope）",
		},
		Reason: "刪群組即失權（spec）與「群組審核範圍一併失效」必須與群組軟刪同交易：" +
			"殘留 approver_group=null 的幽靈範圍會讓殘留成員列回復審核資格。" +
			"撤銷筆數還要進同交易的審計 Details，" +
			"分兩個交易寫會出現「審計說撤了 N 筆、實際回滾了」的不一致。",
	},
	{
		CallerFile: "internal/modules/identity/user_service.go",
		Callee:     "RevokeByUser",
		OriginalSites: []string{
			"internal/modules/identity/user_service.go:513（Delete ApproverScope）",
		},
		Reason: "帳號軟刪與其審核範圍失效必須原子成立，且整段被「本地 admin 不變式」" +
			"的系統級鎖與使用者憑證鎖包住（取鎖順序 system → user）。" +
			"authz 無法另開交易——那會落在鎖外，且帳號刪除回滾時範圍已被撤。",
	},
	{
		CallerFile: "internal/modules/session/session_service.go",
		Callee:     "EnqueueTx",
		OriginalSites: []string{
			"internal/modules/session/session_service.go:UpdateRecording（錄影欄位落地" +
				"與排入離機佇列同一筆交易；**非收口前的舊寫入點**，" +
				"evidence-offsite-storage 新增的排隊點）",
		},
		Reason: "「錄影檔已落地」與「已排入離機佇列」必須原子成立：分兩個交易寫會留下" +
			"「落地了但沒排隊」的窗口，而那個窗口內的錄影只有本機唯一副本、" +
			"且沒有任何佇列指標會顯示它缺席——回填掃描要到下一輪才可能補上，" +
			"期間磁碟故障即證據永久遺失。反向（排了隊而錄影欄位回滾）則會讓 worker " +
			"對著一個不存在的路徑重試到上限。session 不得擁有 offsite_objects" +
			"（表所有權歸 internal/offsite，資料邊界閘門擋著），故只能交出交易句柄。",
	},
	{
		CallerFile: "internal/modules/audit/audit_export_job_worker.go",
		Callee:     "EnqueueTx",
		OriginalSites: []string{
			"internal/modules/audit/audit_export_job_worker.go:completeJob（產物落定" +
				"與排入離機佇列同一筆交易；**非收口前的舊寫入點**，" +
				"evidence-offsite-storage 新增的排隊點）",
		},
		Reason: "與 session 的排隊點同型、同理由，差別在證據包的本機副本更脆弱：" +
			"產物目錄不在備份範圍內，主機遺失即消失（離機動機本身）。" +
			"「job 已 done 而沒排隊」的窗口內，那份證據包只有一個隨時會蒸發的副本，" +
			"且下載窗口只有 24 小時、過後本機檔被清掃刪除——回填掃描補得回帳冊列，" +
			"補不回已經不存在的檔案。audit 不得擁有 offsite_objects，故只能交出交易句柄。",
	},
	{
		CallerFile: "internal/middleware/scope_gate.go",
		Callee:     "DecideWithDenial",
		OriginalSites: []string{
			"（新增）登錄閘對宣告了目標解析的登錄項做範圍判定，範圍拒絕時取種類與層次交共用出口",
		},
		Reason: "判定器在給定的資料庫句柄上重解主體、讀目標與拓撲，簽名因此收交易句柄。" +
			"登錄閘在 handler 之前判定，傳入的是一般連線（帶請求脈絡）、不在任何交易內；" +
			"判定只讀、不取鎖、不寫任何表。範圍拒絕的層次（資產層或帳號層）只能經本方法取得，" +
			"依種類推定會把「資產在範圍內、帳號不屬於它」錯標為資產層。",
	},
	{
		CallerFile: "internal/middleware/scope_tx_recheck.go",
		Callee:     "DecideWithDenial",
		OriginalSites: []string{
			"（新增）服務在寫入交易內重判登錄閘通過的範圍判定（資產更新改掛載後），範圍拒絕時取種類與層次交回 handler",
		},
		Reason: "重判必須讀到本交易已寫入、尚未提交的掛載，才能判出「改動後目標已在範圍外」，所以收呼叫方的交易句柄。" +
			"判定只讀、不取鎖、不寫任何表；拒絕時呼叫方整筆回滾。拒絕值（含帳號目標的層次）只經本方法取得，" +
			"本檔與 handler 都不建構或改寫拒絕值。",
	},
	{
		CallerFile: "internal/modules/identity/approver_scope_management_key.go",
		Callee:     "AdvanceVersion",
		OriginalSites: []string{
			"（新增登記）啟動期補鍵資料步驟在每個角色的權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "補鍵沿角色定義寫入鏈的次序：權限寫入、定義版本、權限版本、系統身分審計與狀態事件必須在同一個交易內原子成立，任一步失敗整筆回滾；呼叫形態與角色定義服務相同。",
	},
	{
		CallerFile: "internal/modules/identity/approver_scope_management_key.go",
		Callee:     "BeginPermissionChange",
		OriginalSites: []string{
			"（新增登記）啟動期補鍵資料步驟在每個角色的權限寫入交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "補鍵沿角色定義寫入鏈的次序：權限寫入、定義版本、權限版本、系統身分審計與狀態事件必須在同一個交易內原子成立，任一步失敗整筆回滾；呼叫形態與角色定義服務相同。",
	},
	{
		CallerFile: "internal/modules/identity/scoped_template_seed.go",
		Callee:     "AdvanceVersion",
		OriginalSites: []string{
			"（新增登記）啟動期範本種入資料步驟在單一交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "種入沿角色定義寫入鏈的次序：權限狀態比對、寫入兩列範本、權限版本與狀態事件必須在同一個交易內原子成立，任一步失敗整筆回滾；呼叫形態與審核範圍管理鍵補鍵相同。",
	},
	{
		CallerFile: "internal/modules/identity/scoped_template_seed.go",
		Callee:     "BeginPermissionChange",
		OriginalSites: []string{
			"（新增登記）啟動期範本種入資料步驟在單一交易內呼叫 authz 的包級函式；與拓撲介面的同名方法同名，掃描器以名稱比對而列入",
		},
		Reason: "種入沿角色定義寫入鏈的次序：權限狀態比對、寫入兩列範本、權限版本與狀態事件必須在同一個交易內原子成立，任一步失敗整筆回滾；呼叫形態與審核範圍管理鍵補鍵相同。",
	},
	{
		CallerFile: "internal/modules/asset/credential_impact.go",
		Callee:     "CredentialImpactScopeIn",
		OriginalSites: []string{
			"（新增）共用憑證修改的範圍外影響集合在持有憑證列鎖的交易內計算",
		},
		Reason: "影響集合（範圍內清單、範圍外集合）必須與掛載集合在同一個交易讀取點計算，" +
			"另開連線會讀不到本交易的狀態，單連線環境下還會與持鎖交易互等。" +
			"方法只重解主體並讀節點與資產範圍，不取鎖、不寫任何表。",
	},
	{
		CallerFile: "cmd/server/credential_management_adapter.go",
		Callee:     "CredentialCapabilityMissing",
		OriginalSites: []string{
			"（新增）不帶目標的憑證管理檢核在呼叫端交易內改認任一有效來源（含節點範圍來源）",
		},
		Reason: "與同檔 HasAllCapabilities 同一個讀取點：能力重驗在呼叫端交易內進行，" +
			"另開連線會與持有憑證列鎖的交易讀到不同的指派狀態，單連線環境下還會互等。" +
			"方法只重解主體並讀指派與角色，不取鎖、不寫任何表。",
	},
	{
		CallerFile: "cmd/server/credential_management_adapter.go",
		Callee:     "DecideCredentialManagement",
		OriginalSites: []string{
			"（新增）帶目標的憑證管理檢核在呼叫端交易內以憑證歸屬與明確目標資產判定能力與範圍",
		},
		Reason: "歸屬與掛載目標須在持有憑證列鎖的同一交易讀取點判定，判定與寫入之間才不會出現" +
			"歸屬被改、資產被搬的窗口。方法只重解主體並讀憑證歸屬、節點與資產範圍，不取鎖、不寫任何表。",
	},
	{
		CallerFile: "cmd/server/credential_management_adapter.go",
		Callee:     "DecideCredentialOnNodes",
		OriginalSites: []string{
			"（新增）新增資產建立專用憑證時，在已取拓撲序列化鎖的建立交易內以送出的節點判定建立憑證能力",
		},
		Reason: "送出節點的範圍判定須與節點刪除、搬移落在同一個拓撲序列化點：交易外判定會留下" +
			"「判定通過後、寫入前節點被刪或搬出範圍」的窗口。方法只重解主體並讀節點範圍，不取鎖、不寫任何表。",
	},
	{
		CallerFile: "internal/modules/asset/credential_ownership.go",
		Callee:     "AuthorizeSharedOwnership",
		OriginalSites: []string{
			"（新增）建立共用憑證與轉共用時，在已取拓撲序列化鎖的交易內判定新歸屬",
		},
		Reason: "歸屬節點的範圍判定必須與節點刪除、搬移落在同一個拓撲序列化點：交易外判定會留下" +
			"「判定通過後、寫入前節點被刪或搬出範圍」的窗口。方法只重解主體並讀節點範圍，" +
			"不取鎖、不寫任何表、不推進權限版本；節點存在性由呼叫端在同一交易內驗。",
	},
	{
		CallerFile: "internal/modules/asset/credential_ownership_reassign.go",
		Callee:     "AuthorizeOwnershipChange",
		OriginalSites: []string{
			"（新增）共用憑證改歸（單筆與批次）在已取拓撲序列化鎖與憑證列鎖的交易內判定新舊歸屬",
		},
		Reason: "與建立時的歸屬判定同理：目的節點與各筆現行歸屬的範圍判定須與拓撲鎖、憑證列鎖同一讀取點，" +
			"否則判定結果可能在寫入前失效。方法只重解主體並讀節點範圍，不取鎖、不寫任何表、不推進權限版本。",
	},
	{
		CallerFile: "internal/modules/asset/asset_import_scope.go",
		Callee:     "AuthorizeAssetCreate",
		OriginalSites: []string{
			"（新增）批次新增資產的逐列節點範圍判定，預檢與提交共用（asset_import_scope.go:91、:100）",
		},
		Reason: "提交時在拓撲序列化鎖之後、於同一交易以交易內視圖重算逐列範圍（asset_import_scope.go:162），判定與寫入之間不得有指派或拓撲變動；預檢（asset_import_validate.go:137）傳入的是一般連線、不在任何交易內。與單筆建立同一個判定方法，只讀、不取鎖、不寫表。",
	},
	{
		CallerFile: "internal/modules/asset/asset_write_scope_tx.go",
		Callee:     "AccessPolicyCoversNodes",
		OriginalSites: []string{
			"（新增）資產建立交易與批次新增（預檢與提交交易內重算）判定帶非空存取政策覆寫的目的節點是否在存取政策範圍內（asset_write_scope_tx.go:168 accessPolicyCoversTx；呼叫方 asset_write_scope_tx.go:184、asset_import_scope.go:136）",
		},
		Reason: "建立與提交時須在拓撲序列化鎖之後、於同一交易重讀主體與節點範圍，判定與寫入之間不得有指派或拓撲變動；" +
			"預檢傳入的是一般連線、不在任何交易內。方法只重解主體並物化存取政策權限點的範圍，不取鎖、不寫表。",
	},
	{
		CallerFile: "internal/modules/asset/asset_access_policy_overrides.go",
		Callee:     "AccessPolicyProjection",
		OriginalSites: []string{
			"（新增）單台覆寫清單以請求連線取存取政策權限點的範圍投影（asset_access_policy_overrides.go:106 ListAccessPolicyOverrides）",
		},
		Reason: "投影要在與清單查詢同一個連線上重解主體並物化範圍，列表、計數與節點遮蔽才出自同一份集合；" +
			"唯讀端點，傳入的是一般連線、不在任何交易內。方法只讀指派與節點樹，不取鎖、不寫表。",
	},
	{
		CallerFile: "internal/modules/asset/asset_access_policy_overrides.go",
		Callee:     "ApplyAssets",
		OriginalSites: []string{
			"（新增）單台覆寫清單把存取政策權限點的集合套到以 assets 為主表的查詢（asset_access_policy_overrides.go:115 ListAccessPolicyOverrides）",
		},
		Reason: "集合述詞以子查詢加在呼叫方的查詢上，必須在覆寫條件、搜尋、計數與分頁之前套用，所以收查詢句柄；" +
			"回傳的是加了條件的同一查詢，不執行任何語句、不寫表。",
	},
	{
		CallerFile: "internal/modules/asset/change_secret_batch_service.go",
		Callee:     "LockTopology",
		OriginalSites: []string{
			"（新增）批次改密建立交易的第一個動作取拓撲序列化鎖（change_secret_batch_service.go:293）",
		},
		Reason: "鎖必須在建立交易內取得並持有到交易結束，之後的能力重判與範圍交集才看到同一份節點樹，所以只能由 asset 交出交易句柄；鎖本身不寫任何表。",
	},
	{
		CallerFile: "internal/modules/asset/change_secret_batch_service.go",
		Callee:     "CapabilityMissing",
		OriginalSites: []string{
			"（新增）批次改密不帶目標的關卡被拒後，以任一有效來源（含節點範圍）再檢核模式所需能力（change_secret_batch_service.go:378）",
		},
		Reason: "建立交易內的重判（change_secret_batch_service.go:296）必須與拓撲鎖、範圍交集同一讀取點，交易外判定會留下「判定通過後、寫入前」撤權的窗口；交易外的預判（:269）傳入一般連線。方法只重解主體並讀指派、角色與拓撲，不取鎖、不寫任何表。",
	},
	{
		CallerFile: "internal/modules/asset/change_secret_batch_service.go",
		Callee:     "AssetScope",
		OriginalSites: []string{
			"（新增）批次改密建立交易內解析目標時取發起者帳號改密的資產範圍（change_secret_batch_service.go:397）",
		},
		Reason: "回傳的資產範圍是以傳入句柄建立的子查詢，由呼叫端嵌進自己的查詢執行，必須與呼叫端查詢同一句柄、同一讀取點。目標解析與寫入同一交易、在拓撲序列化鎖之後，範圍與目標之間不得有指派或拓撲變動。方法只重解主體並讀指派、角色與拓撲，不取鎖、不寫任何表。",
	},
	{
		CallerFile: "internal/modules/asset/change_secret_batch_view.go",
		Callee:     "ViewScope",
		OriginalSites: []string{
			"（新增）批次改密讀取投影取檢視者的資產範圍（change_secret_batch_view.go:29）",
		},
		Reason: "回傳的資產範圍是以傳入句柄建立的子查詢，由呼叫端嵌進自己的查詢執行，必須與呼叫端查詢同一句柄、同一讀取點。本呼叫點傳入的是一般連線、不在任何交易內。方法只重解主體並讀指派、角色與拓撲，不取鎖、不寫任何表。",
	},
	{
		CallerFile: "internal/modules/asset/change_secret_candidate_view.go",
		Callee:     "ViewScope",
		OriginalSites: []string{
			"（新增）改密候選列表取檢視者的資產範圍（change_secret_candidate_view.go:27）",
		},
		Reason: "回傳的資產範圍是以傳入句柄建立的子查詢，由呼叫端嵌進自己的查詢執行，必須與呼叫端查詢同一句柄、同一讀取點。本呼叫點傳入的是一般連線、不在任何交易內。方法只重解主體並讀指派、角色與拓撲，不取鎖、不寫任何表。",
	},
	{
		CallerFile: "internal/modules/asset/change_secret_candidate_view.go",
		Callee:     "CandidateDenial",
		OriginalSites: []string{
			"（新增）改密候選單筆讀取與顯式清除的範圍判定（change_secret_candidate_view.go:46、:64）",
		},
		Reason: "清除時在取拓撲序列化鎖之後於同一交易判定候選所屬資產在範圍內，判定與刪除之間不得有指派或拓撲變動；單筆讀取傳入一般連線。範圍拒絕值只經本方法取得，不在 asset 端建構。方法只重解主體並讀指派、角色與拓撲，不取鎖、不寫任何表。",
	},
	{
		CallerFile: "internal/modules/asset/change_secret_candidate_view.go",
		Callee:     "LockTopology",
		OriginalSites: []string{
			"（新增）改密候選顯式清除交易的第一個動作取拓撲序列化鎖（change_secret_candidate_view.go:61）",
		},
		Reason: "鎖必須在清除交易內取得並持有到交易結束，範圍判定與刪除才落在同一個拓撲序列化點，所以只能由 asset 交出交易句柄；鎖本身不寫任何表。",
	},
	{
		CallerFile: "internal/modules/asset/change_secret_plan_scope.go",
		Callee:     "LockTopology",
		OriginalSites: []string{
			"（新增）改密計畫儲存、刪除與執行交易的第一個動作取拓撲序列化鎖（change_secret_plan_scope.go:36、:177）",
		},
		Reason: "鎖必須在計畫寫入交易內取得並持有到交易結束，目標範圍判定與掛載上界寫入才看到同一份節點樹，所以只能由 asset 交出交易句柄；鎖本身不寫任何表。",
	},
	{
		CallerFile: "internal/modules/asset/change_secret_plan_scope.go",
		Callee:     "ViewScope",
		OriginalSites: []string{
			"（新增）改密計畫的記錄讀取與儲存交易內的目標判定取檢視者範圍（change_secret_plan_scope.go:151、:194、:217）",
		},
		Reason: "回傳的資產範圍是以傳入句柄建立的子查詢，由呼叫端嵌進自己的查詢執行，必須與呼叫端查詢同一句柄、同一讀取點。儲存時在拓撲序列化鎖之後於同一交易判定明列目標，判定與寫入之間不得有指派或拓撲變動；記錄讀取傳入一般連線。方法只重解主體並讀指派、角色與拓撲，不取鎖、不寫任何表。",
	},
	{
		CallerFile: "internal/modules/asset/change_secret_plan_scope.go",
		Callee:     "CredentialsVisible",
		OriginalSites: []string{
			"（新增）以憑證為目標的計畫儲存時，在持有憑證列鎖的交易內判定目標憑證歸屬在範圍內（change_secret_plan_scope.go:231）",
		},
		Reason: "歸屬判定須與憑證列鎖、影響確認與掛載上界寫入同一交易讀取點，否則判定後、寫入前歸屬可能被改。方法只重解主體並讀指派、角色與拓撲，不取鎖、不寫任何表。",
	},
	{
		CallerFile: "internal/modules/asset/change_secret_plan_visibility.go",
		Callee:     "ViewScope",
		OriginalSites: []string{
			"（新增）改密計畫可見性投影取檢視者帳號改密的資產範圍（change_secret_plan_visibility.go:26）",
		},
		Reason: "回傳的資產範圍是以傳入句柄建立的子查詢，由呼叫端嵌進自己的查詢執行，必須與呼叫端查詢同一句柄、同一讀取點。讀取面與在交易內重判可見性的呼叫端共用本函式，句柄由呼叫端決定。方法只重解主體並讀指派、角色與拓撲，不取鎖、不寫任何表。",
	},
	{
		CallerFile: "internal/modules/asset/change_secret_plan_visibility.go",
		Callee:     "CredentialsVisible",
		OriginalSites: []string{
			"（新增）改密計畫可見性投影判定憑證目標的歸屬在檢視者範圍內（change_secret_plan_visibility.go:36）",
		},
		Reason: "與同檔 ViewScope 同一個句柄、同一讀取點，帳號目標與憑證目標的可見性才不會分歧。方法只重解主體並讀指派、角色與拓撲，不取鎖、不寫任何表。",
	},
	{
		CallerFile: "internal/modules/identity/assignment_guard.go",
		Callee:     "LiveNodesTx",
		OriginalSites: []string{
			"（新增）節點範圍指派寫入在取得拓撲序列化鎖之後，於同一交易檢查範圍內的節點都存在且未刪除（assignment_guard.go:205）",
		},
		Reason: "節點是否存在必須與指派寫入同一個讀取點：檢查與寫入之間節點不得被刪除，所以只能用呼叫端的交易讀 asset 擁有的節點表；identity 不得直接碰該表，經窄介面由 asset 實作。方法只讀、不取鎖、不寫任何表；未注入讀取時帶節點範圍的寫入一律拒絕。",
	},
}

// txTakingReasonViolations 比對純函式（抽出來才能對「無理由登記」做突變自檢）：
// 回傳理由空白或欄位殘缺的登記項描述。
func txTakingReasonViolations(entries []txTakingEntry) []string {
	var out []string
	for _, e := range entries {
		switch {
		case strings.TrimSpace(e.Reason) == "":
			out = append(out, e.CallerFile+" → "+e.Callee+"：理由欄空白")
		case strings.TrimSpace(e.CallerFile) == "" || strings.TrimSpace(e.Callee) == "":
			out = append(out, "登記項欄位殘缺："+e.CallerFile+" → "+e.Callee)
		case len(e.OriginalSites) == 0:
			out = append(out, e.CallerFile+" → "+e.Callee+"：未指名收口前的原始寫入點")
		}
	}
	sort.Strings(out)
	return out
}

// authzPkgPath authz 模組的 import path（tx-taking 方法的擁有者之一）。
const authzPkgPath = "github.com/custodexa/backend/internal/modules/authz"

// authzModuleDir authz 模組相對 module 根的目錄（判「是不是 authz 自己」用）。
const authzModuleDir = "internal/modules/authz/"

// offsitePkgPath／offsiteModuleDir 離機儲存基礎設施包
// （evidence-offsite-storage）。`Ledger.EnqueueTx` 收 `*gorm.DB`，使
// 「錄影落地」與「排入離機佇列」同一交易——沒有「落地了但沒排隊」的窗口。
//
// **納入被呼叫方集合的理由與 authz 完全相同**：交易句柄一旦交出去，編譯器與
// 資料邊界閘門都看不見對方寫了哪張表。offsite 擁有 offsite_objects 與
// offsite_profiles 兩張表，session／audit 對 EnqueueTx 的呼叫因此必須被登記。
const (
	offsitePkgPath   = "github.com/custodexa/backend/internal/offsite"
	offsiteModuleDir = "internal/offsite/"
)

// txTakingCalleePkgs 被呼叫方（tx-taking 方法的擁有者）：import path → 顯示標籤。
var txTakingCalleePkgs = map[string]string{
	authzPkgPath:   "authz",
	offsitePkgPath: "offsite",
	assetPkgPath:   "asset",
}

// assetPkgPath asset 套件。只有 txTakingCalleeTypes 列出的型別進入被呼叫方集合：
// identity 在取得拓撲序列化鎖之後，經窄介面用自己的交易檢查節點是否存在，該讀取由 asset 擁有；
// asset 其餘的 tx-taking 匯出方法與既有呼叫點不屬這條通道，整包納入會連帶要求無關的登記。
const assetPkgPath = "github.com/custodexa/backend/internal/modules/asset"

// txTakingCalleeTypes 套件內只納入的型別（套件不在此表＝納入全部匯出型別）。
var txTakingCalleeTypes = map[string]map[string]bool{
	assetPkgPath: {"NodeExistenceReader": true},
}

// txTakingTypeAllowed 判被呼叫方套件內的型別是否在納入範圍。
func txTakingTypeAllowed(pkgPath, typeName string) bool {
	only, filtered := txTakingCalleeTypes[pkgPath]
	return !filtered || only[typeName]
}

// txTakingCalleeDirs 被呼叫方自己的目錄（自己寫自己的表不算跨界）。
var txTakingCalleeDirs = []string{authzModuleDir, offsiteModuleDir}

// txTakingMethodsWithoutCallers **已宣告但目前無外部呼叫點**的 tx-taking 匯出方法。
//
// C 軸（偵測器健康）要求「被呼叫方的 tx-taking 匯出方法集合＝登記的被呼叫方集合」。
// 呼叫點登記（txTakingWhitelist）只有在真的有人呼叫時才存在，故「方法已存在、
// 呼叫點尚未落地」這一格需要另一張表——否則 C 軸會逼人為了讓測試綠而先寫一個假的
// 呼叫點登記，那正好是 B 軸要擋的東西。
//
// **本表不是豁免**：登記在此的方法一旦真的被呼叫，A 軸仍要求該呼叫點進
// txTakingWhitelist。本表只回答「這個方法為什麼可以把交易收進來」。
var txTakingMethodsWithoutCallers = map[string]string{
	"Decide": "節點範圍授權判定，須在呼叫方的寫入交易內現查指派與目標，與寫入同一交易，" +
		"判定與寫入之間不得有指派或拓撲變動。判定本身不取鎖、不寫表（只讀）；現況為契約骨架，無外部呼叫點。",
	"ScopeSetFor": "範圍集合述詞（不限／空／條件），須與 Decide 在同一交易內重解主體，" +
		"列表在分頁與計數前以它過濾，集合與單筆判定才同源。只讀、不取鎖、不寫表；現況無外部呼叫點。",
	"NodeScopeOnlySetFor": "「只取節點範圍指派」變體，與 ScopeSetFor 同一交易、同一來源過濾重解主體（管理可視）。" +
		"只讀、不取鎖、不寫表；現況無外部呼叫點。",
	"NodeScopeProjection": "主體對某權限點的節點投影（可選節點與定位祖先），在呼叫方交易內重解主體與讀拓撲，" +
		"供後段在寫入交易內取得與判定同源的節點集合。只讀、不取鎖、不寫表；現況無外部呼叫點（authz 包內的節點樹範圍化讀取直接用同一投影的內部函式）。",
	"ApplyScopeSet": "把範圍集合以子樹子查詢加到呼叫方查詢上，子查詢須以同一交易句柄建立，" +
		"與集合判定讀同一份拓撲。只組查詢、不執行寫入、不取鎖；現況無外部呼叫點。",
	"ManagementScopeNodeCountsFor": "管理範圍節點計數投影（仍存在／已刪除），在呼叫方交易內重解主體並讀指派綁定節點，" +
		"與同一請求的集合判定一致。只讀、不取鎖、不寫表；現況無外部呼叫點。",
	"ManagementVisibleScopeFor": "資產管理可視（檢視捷徑主體為全部、其餘為資產檢視的只取節點範圍變體），在呼叫方交易內重解主體，" +
		"與同一請求的列表過濾與計數同源。只讀、不取鎖、不寫表；現況無外部呼叫點（資產頁讀取器在 authz 包內用同一內部函式）。",
	"ManagementVisibleScopeForAssignments": "以指派集合為輸入的資產管理可視（預覽台數），檢視捷徑判定與正式判定同一實作，" +
		"角色定義與節點存活在呼叫方交易內讀。只讀、不取鎖、不寫表；現況無外部呼叫點。",
	"ApplyManagementVisible": "把資產管理可視加到呼叫方的資產查詢上，子查詢須以同一交易句柄建立。" +
		"只組查詢、不執行寫入、不取鎖；現況無外部呼叫點。",
	"CountManagementVisible": "資產管理可視的去重台數，與列表同一集合述詞、同一交易。只讀、不取鎖、不寫表；現況無外部呼叫點。",
	"DecideForAssignments": "以指派集合為輸入的單筆判定（模擬指派預覽），角色定義、節點存活與目標拓撲須在呼叫方交易內讀，" +
		"與同一請求的其他判定讀同一份狀態。只讀、不取鎖、不寫表；現況無外部呼叫點。",
	"ScopeSetForAssignments": "以指派集合為輸入的一般三態集合，與 DecideForAssignments 同一交易、同一套規則。" +
		"只讀、不取鎖、不寫表；現況無外部呼叫點。",
	"NodeScopeOnlySetForAssignments": "以指派集合為輸入的「只取節點範圍指派」變體，與 DecideForAssignments 同一交易。" +
		"只讀、不取鎖、不寫表；現況無外部呼叫點。",
	"ViewShortcutForAssignments": "以指派集合為輸入的檢視類全量視圖資格，角色定義在呼叫方交易內讀，" +
		"與同一請求的集合判定一致。只讀、不取鎖、不寫表；現況無外部呼叫點。",
	"CheckRuleSubjects": "建立與調整授權規則時的防自我授權判定，須與規則寫入同一交易：" +
		"agent 主體以帳號列鎖讀取擁有者，與擁有者轉移同鎖序，否則並發的轉移可讓判定失效。" +
		"現況呼叫者都在 authz 包內（授權規則服務），故無外部呼叫點。只讀（含列鎖）。",
	"CheckApproverScope": "建立申請人型審核範圍時檢查審核方與申請人不相交，與範圍寫入同一交易，" +
		"避免判定後、寫入前成員變動。現況呼叫者在 authz 包內。只讀。",
	"IsOwnAgentRequest": "申請決定時現查申請人是否為操作者擁有的 agent，須與計票、狀態寫入同一交易，" +
		"才與擁有者轉移以同一把鎖序列化。現況呼叫者在 authz 包內。只讀。",
	"DecideObject": "建立授權規則時判定客體（資產或節點其一）是否在操作者的授權規則管理範圍內，" +
		"須與規則寫入同一交易、在拓撲序列化鎖之後，判定與寫入之間不得有指派或拓撲變動。" +
		"只讀、不取鎖、不寫表；現況呼叫者在 authz 包內（授權規則服務），故無外部呼叫點。",
	"DecideRule": "調整帳號範圍與刪除既有授權規則時以規則的客體為目標判定，與 DecideObject 同一交易、同一套規則。" +
		"只讀、不取鎖、不寫表；現況呼叫者在 authz 包內（授權規則服務），故無外部呼叫點。",
	"CountUnavailableObjects": "批次建立授權規則時逐一判定客體、回無法操作（範圍外或不存在）的件數，" +
		"與批次寫入同一交易，整批的判定才與寫入讀同一份指派與拓撲。" +
		"只讀、不取鎖、不寫表；現況呼叫者在 authz 包內（授權規則服務），故無外部呼叫點。",
	"AllAssetsInScope": "臨時授權撤銷資格的範圍判定：撤銷交易在拓撲序列化鎖之後於同一交易內重解主體，" +
		"逐項判定所涉資產皆在授權規則管理範圍內，判定與撤銷寫入之間不得有指派或拓撲變動。" +
		"只讀、不取鎖、不寫表；現況呼叫者在 authz 包內（申請單服務），故無外部呼叫點。",
	"ApplyAuthorizationRuleScope": "把授權規則列表的範圍集合以子樹子查詢加到呼叫方的授權規則查詢上（篩選、計數與分頁之前），" +
		"子查詢須以同一連線句柄建立，與集合判定讀同一份拓撲。" +
		"只組查詢、不執行寫入、不取鎖；現況呼叫者在 authz 包內（授權列表與有效權限檢視），故無外部呼叫點。",
	"MarkForeign": "世代切換／停止離機時把舊世代的存量物件整批轉為 foreign。" +
		"必須與「退役舊世代列、建立新世代列、寫審計」同一交易——" +
		"否則會留下「世代已切換而舊物件仍宣稱屬現行世代」的中間態。" +
		"現況呼叫者在 offsite 包內（設定服務），故無外部呼叫點。",
	"CountByGeneration": "鎖內重數某世代的存量物件（世代切換確認的判定依據）。" +
		"與 MarkForeign 同交易同理由；現況呼叫者在包內。",
	"CurrentGeneration": "以呼叫方的 tx **重讀**現行設定世代（GenerationSource 契約）。" +
		"帶 tx 是必要的：EnqueueTx 在呼叫方的交易內執行，世代若以交易外的預讀取得，" +
		"兩者之間的世代切換會讓帳冊記到一個已退役的世代 id。**唯讀**——" +
		"本方法不寫任何表，交易句柄只用於讀一致性。",
	"DecideCreate": "建立審核範圍前判定客體（資產或節點）或申請人型的管理資格，須與範圍寫入同一交易、在拓撲序列化鎖之後，" +
		"判定與寫入之間不得有指派或拓撲變動。只讀、不取鎖、不寫表；現況呼叫者在 authz 包內（審核範圍服務），故無外部呼叫點。",
	"DecideRow": "移除既有審核範圍前以該列為目標判定審核範圍管理資格，與 DecideCreate 同一交易、同一套規則。" +
		"只讀、不取鎖、不寫表；現況呼叫者在 authz 包內（審核範圍服務），故無外部呼叫點。",
	"DecideApplicantRow": "移除申請人型審核範圍時的第二步判定（申請人型管理資格），與 DecideRow 同一交易。" +
		"只讀、不取鎖、不寫表；現況呼叫者在 authz 包內（審核範圍服務），故無外部呼叫點。",
}

// minTxTakingScanPackages `packages.Load("./...")` 的載入下限（現況 32，取 24 為保守下界）。
const minTxTakingScanPackages = 24

// txTakingScan 一次掃描的產物
type txTakingScan struct {
	// Methods 被呼叫方對外的 tx-taking 匯出方法名集合（跨全部被呼叫方包的聯集；
	// 方法名在兩個包內重名時仍只是一個鍵——A 軸的登記以 `pkgLabel.method` 表述，
	// 故不會混淆歸屬）
	Methods map[string]bool
	// Calls 非 authz 非測試檔對這些方法的呼叫點：method → []file:line
	Calls map[string][]string
	// CallerFiles 呼叫點所在檔（相對 module 根）→ 呼叫的方法集合
	CallerFiles map[string]map[string]bool
	Packages    int
	Files       int
	// Err 掃描失敗的原因（載入錯誤、包數低於下限、pkg.Errors 非空）。
	//
	// 失敗不在掃描函式內就地 t.Fatalf：結果由兩軸共用單次載入，sync.Once 內的 `t`
	// 屬於第一個進入的測試，在其中 Fatal 只會讓那一軸紅，另一軸拿到零值結構
	// （nil map、Packages 為 0）並在空集合上通過。故由每個呼叫者各自 Fatal。
	Err error
}

var (
	txTakingScanOnce  sync.Once
	txTakingScanCache txTakingScan
)

// scanTxTaking 取（並快取）掃描結果，本檔兩支守衛（A／B 軸）共用。
//
// 兩軸看的是同一棵樹的同一份事實且都不改動它，而帶完整型別資訊的全 module
// packages.Load 單次約 30 秒（基準量測：本包 65s／2 次）。
//
// root 由呼叫點傳入而非在此取得，故 modroot 定位的失敗仍各自 Fatal，
// 不會落進 Once 內造成零值快取。失敗處理見 txTakingScan.Err。
func scanTxTaking(t *testing.T, root string) txTakingScan {
	t.Helper()
	txTakingScanOnce.Do(func() { txTakingScanCache = runTxTakingScan(root) })
	if txTakingScanCache.Err != nil {
		t.Fatalf("%v", txTakingScanCache.Err)
	}
	return txTakingScanCache
}

// runTxTakingScan 以型別資訊掃出 (a) authz 的 tx-taking 匯出方法、(b) 外部呼叫點。
//
// 不接 *testing.T：本函式在 sync.Once 內執行，任何 t 都只屬於第一個進入者。
// 載入下限與 pkg.Errors 兩道防假綠管線**判準值與時機不變**，只是改為寫入 Err。
func runTxTakingScan(root string) txTakingScan {
	fail := func(format string, args ...any) txTakingScan {
		return txTakingScan{Err: fmt.Errorf(format, args...)}
	}
	fset := token.NewFileSet()
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo |
			packages.NeedImports | packages.NeedDeps,
		Dir:   root,
		Fset:  fset,
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return fail("packages.Load 失敗（守衛無法在無視野下宣稱通過）: %v", err)
	}
	if len(pkgs) < minTxTakingScanPackages {
		return fail("只載入 %d 個包（下限 %d）：掃描範圍已失真", len(pkgs), minTxTakingScanPackages)
	}
	for _, p := range pkgs {
		if len(p.Errors) > 0 {
			return fail("包 %s 有 %d 個載入／型別錯誤（首個：%v）：守衛拒絕在殘缺的 AST 上作判定",
				p.PkgPath, len(p.Errors), p.Errors[0])
		}
	}

	scan := txTakingScan{
		Methods:     map[string]bool{},
		Calls:       map[string][]string{},
		CallerFiles: map[string]map[string]bool{},
		Packages:    len(pkgs),
	}
	rel := func(abs string) string {
		r, err := filepath.Rel(root, abs)
		if err != nil {
			return abs
		}
		return filepath.ToSlash(r)
	}

	// (a) 被呼叫方的 tx-taking 匯出方法：接收者在被呼叫方包、任一參數為 *gorm.DB
	for _, p := range pkgs {
		if _, ok := txTakingCalleePkgs[p.PkgPath]; !ok || p.Types == nil {
			continue
		}
		sc := p.Types.Scope()
		for _, name := range sc.Names() {
			obj := sc.Lookup(name)
			// 只看**匯出型別**的匯出方法：未匯出型別（如內化後的
			// assetAuthorizationRepository）的方法外部根本取不到，
			// 不構成跨模組通道，列進來只會逼人為內部細節登記白名單
			if !obj.Exported() {
				continue
			}
			named, ok := obj.Type().(*types.Named)
			if !ok || !txTakingTypeAllowed(p.PkgPath, obj.Name()) {
				continue
			}
			for i := 0; i < named.NumMethods(); i++ {
				m := named.Method(i)
				if !m.Exported() {
					continue
				}
				sig, ok := m.Type().(*types.Signature)
				if !ok || sig.Params().Len() == 0 {
					continue
				}
				if signatureTakesGormDB(sig) {
					scan.Methods[m.Name()] = true
				}
			}
		}
	}
	if len(scan.Methods) == 0 {
		return fail("在被呼叫方集合中找不到任何 tx-taking 匯出方法：偵測器已失明，" +
			"「零未登記呼叫」不構成證據（比對本檔的 txTakingCalleePkgs 是否仍正確）")
	}

	// (b) 外部呼叫點
	for _, p := range pkgs {
		if p.TypesInfo == nil {
			continue
		}
		for _, f := range p.Syntax {
			path := fset.Position(f.Pos()).Filename
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			rf := rel(path)
			if isTxTakingCalleeFile(rf) {
				continue // 被呼叫方自己在自己的表上寫，不是跨模組
			}
			scan.Files++
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || !scan.Methods[sel.Sel.Name] {
					return true
				}
				// 以型別資訊確認被呼叫的真的是 authz 的方法：同名方法在別的型別上
				// 很常見（例：api.RecordingTokenManager.RevokeByUser），
				// 純名稱比對會誤報，而誤報會逼人把不相干的呼叫點寫進白名單
				if !isTxTakingCalleeMethodCall(p.TypesInfo, sel) {
					return true
				}
				site := rf + ":" + itoa(fset.Position(call.Pos()).Line)
				scan.Calls[sel.Sel.Name] = append(scan.Calls[sel.Sel.Name], site)
				if scan.CallerFiles[rf] == nil {
					scan.CallerFiles[rf] = map[string]bool{}
				}
				scan.CallerFiles[rf][sel.Sel.Name] = true
				return true
			})
		}
	}
	return scan
}

// isTxTakingCalleeFile 判檔案是否屬於某個被呼叫方包自己。
func isTxTakingCalleeFile(rf string) bool {
	for _, dir := range txTakingCalleeDirs {
		if strings.HasPrefix(rf, dir) {
			return true
		}
	}
	return false
}

// isTxTakingCalleeMethodCall 判 selector 指向的是否為被呼叫方包內宣告的方法
// （消費者側窄介面的呼叫同樣成立——介面方法的宣告包是消費者，
// 故另判「介面方法收 *gorm.DB 且接收者是介面」）。
func isTxTakingCalleeMethodCall(info *types.Info, sel *ast.SelectorExpr) bool {
	obj := info.Uses[sel.Sel]
	fn, ok := obj.(*types.Func)
	if !ok {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || !signatureTakesGormDB(sig) {
		return false
	}
	if fn.Pkg() != nil {
		if _, ok := txTakingCalleePkgs[fn.Pkg().Path()]; ok &&
			txTakingTypeAllowed(fn.Pkg().Path(), recvTypeName(sig)) {
			return true
		}
	}
	// 消費者側窄介面：方法宣告在呼叫方的包，但簽名收 *gorm.DB 且名字落在
	// 被呼叫方的 tx-taking 集合內——那正是窄 port 的形狀
	recv := sig.Recv()
	return recv != nil && recv.Type() != nil && types.IsInterface(recv.Type())
}

// recvTypeName 方法接收者的具名型別名（包級函式或匿名接收者回空字串）。
func recvTypeName(sig *types.Signature) string {
	recv := sig.Recv()
	if recv == nil {
		return ""
	}
	t := recv.Type()
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	if named, ok := t.(*types.Named); ok && named.Obj() != nil {
		return named.Obj().Name()
	}
	return ""
}

// signatureTakesGormDB 判簽名是否在「任一參數位置」收 *gorm.DB。
//
// 刻意掃全部位置而非只看 At(0)：本庫自己的慣例就有 tx 不在首位的形式
// （`port.WriteInTx(sink, tx, event)`），故 `RevokeByAsset(assetID uint, tx *gorm.DB)`
// 是純風格選擇而非繞過。原本的位置式判定會讓這種寫法**靜默失明**——
// 方法集合軸與呼叫點軸同源，兩軸會一起瞎，而誠實邊界已明列
// 交易級聯只剩「窄化／白名單／code review」三道防線，白名單這道不能被參數順序關掉。
// （2026-08-10 對抗輪實證：tx 放第二位時三支守衛全 PASS。）
func signatureTakesGormDB(sig *types.Signature) bool {
	for i := 0; i < sig.Params().Len(); i++ {
		if isGormDBPointer(sig.Params().At(i).Type()) {
			return true
		}
	}
	return false
}

// isGormDBPointer 判型別是否為 *gorm.DB（以型別資訊判，不看識別字拼法）。
func isGormDBPointer(t types.Type) bool {
	ptr, ok := t.(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := ptr.Elem().(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj != nil && obj.Name() == "DB" && obj.Pkg() != nil && obj.Pkg().Path() == "gorm.io/gorm"
}

// TestTxTakingCrossModuleWritesAreWhitelisted A 軸＋B 軸。
func TestTxTakingCrossModuleWritesAreWhitelisted(t *testing.T) {
	root := lifecycleModuleRoot(t)
	scan := scanTxTaking(t, root)

	registered := map[string]map[string]bool{}
	for _, e := range txTakingWhitelist {
		if registered[e.CallerFile] == nil {
			registered[e.CallerFile] = map[string]bool{}
		}
		registered[e.CallerFile][e.Callee] = true
	}

	// A 軸：呼叫點必登記
	var unregistered []string
	for file, methods := range scan.CallerFiles {
		for m := range methods {
			if !registered[file][m] {
				unregistered = append(unregistered, file+" → "+m)
			}
		}
	}
	sort.Strings(unregistered)
	if len(unregistered) > 0 {
		t.Errorf("以下呼叫點把交易句柄交給了他包卻未登記於 txTakingWhitelist：\n  %s\n"+
			"tx-taking 不受編譯器保護，未登記＝無人審視過它寫了什麼",
			strings.Join(unregistered, "\n  "))
	}

	// B 軸之一：登記項在現實中必須仍存在（防白名單越留越寬）
	var stale []string
	for _, e := range txTakingWhitelist {
		if !scan.CallerFiles[e.CallerFile][e.Callee] {
			stale = append(stale, e.CallerFile+" → "+e.Callee)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("以下登記項在現實中已不存在（移除須顯式更新白名單，否則下一次新增會被舊列默許）：\n  %s",
			strings.Join(stale, "\n  "))
	}

	// B 軸之二：理由欄
	if v := txTakingReasonViolations(txTakingWhitelist); len(v) > 0 {
		t.Errorf("白名單登記缺理由或欄位殘缺：\n  %s", strings.Join(v, "\n  "))
	}

	// 具名白名單的每一處都必須有歸屬。
	//
	// **數量是契約**：原定五處（收口的既有寫入點）；
	// 資產刪除新增一處＝六處；離機排隊點兩處（session／audit）＝八處；
	// 憑證管理授權 adapter 的交易內能力重驗（只讀）＝九處；本人範圍查詢與
	// agent 擁有者轉移的防自我授權判定（皆只讀）＝十一處；拓撲鎖與權限版本介面進入
	// 掃描集合後，asset 三處（LockTopology、BeginPermissionChange、AdvanceVersion）與
	// identity 既有的權限版本呼叫三十三處（包級函式與介面方法同名）＝四十七處；登錄閘的範圍判定
	// （DecideWithDenial，只讀）＝四十八處；服務寫入交易內的範圍重判（同一方法，只讀）＝四十九處；節點寫入交易在取拓撲鎖後經 asset 端窄介面
	// 呼叫的建立、編輯、搬移範圍判定與刪除前範圍引用查詢四處、搬移交易的涵蓋快照一處（皆只讀）＝五十四處；資產寫入交易在取拓撲鎖後經 asset 端窄介面
	// 呼叫的建立、更新／停用／刪除、節點合併範圍判定三處、帳號寫入隨所屬資產的範圍判定一處、
	// 資產掛載變更的涵蓋快照一處（皆只讀）＝五十九處；憑證管理檢核在呼叫端交易內的範圍影響集合、
	// 不帶目標與帶目標的範圍化能力判定、共用憑證建立與改歸的歸屬判定五處（皆只讀）＝六十四處；
	// 資產批次搬移交易的整批涵蓋快照一處（只讀）＝六十五處；啟動期補鍵資料步驟在每個角色的權限寫入交易內
	// 呼叫的權限版本推進與事件鏈校準兩處＝六十七處；批次新增資產的逐列節點範圍判定一處（只讀）、
	// 批次改密建立交易的拓撲鎖與兩道範圍化判定三處、改密讀取投影（批次、候選、計畫記錄與可見性）
	// 的資產範圍與憑證歸屬判定、候選清除與計畫寫入的拓撲鎖與範圍判定共九處（鎖不寫表、判定皆只讀）
	// ＝八十處；新增資產在建立交易內以送出節點判定建立憑證能力一處（只讀）、存取政策覆寫的建立與批次新增
	// 範圍判定一處、單台覆寫清單的範圍投影與集合套用兩處（皆只讀）＝八十四處；角色指派的節點範圍寫入在同交易內推進權限版本一處＝八十五處；節點範圍指派寫入在同交易內檢查節點存在（asset 的節點存在讀取，只讀）一處＝八十六處；範圍化管理範本種入資料步驟在單一交易內的權限狀態比對與權限版本推進兩處＝八十八處。調整此數字必須連同
	// 上方 txTakingWhitelist 的登記與其理由一起改——這正是「新增 tx-taking 呼叫點
	// 要被看見」的機制，不是可以隨手放寬的門檻。
	const expectedTxTakingSites = 88
	total := 0
	for _, e := range txTakingWhitelist {
		total += len(e.OriginalSites)
	}
	if total != expectedTxTakingSites {
		t.Errorf("交易級聯白名單應為 %d 處，現登記 %d 處："+
			"新增／移除都必須同步本檔的具名清單與本常數",
			expectedTxTakingSites, total)
	}
	if scan.Files < 250 {
		t.Errorf("只掃了 %d 個非測試檔（下限 250）：掃描面已失真", scan.Files)
	}
	t.Logf("tx-taking 掃描：%d 包／%d 非測試檔／被呼叫方 tx-taking 匯出方法 %d 個／外部呼叫點 %d 個",
		scan.Packages, scan.Files, len(scan.Methods), len(scan.CallerFiles))
}

// TestTxTakingMethodSetMatchesWhitelist C 軸（偵測器健康）：
// 被呼叫方的 tx-taking 匯出方法集合必須與登記的方法集合逐字相同
// （＝呼叫點白名單的 Callee ∪ 尚無呼叫點的方法登記）。
// 新增一個 tx-taking 匯出方法而無人呼叫時，A 軸抓不到，本軸抓得到。
func TestTxTakingMethodSetMatchesWhitelist(t *testing.T) {
	root := lifecycleModuleRoot(t)
	scan := scanTxTaking(t, root)

	declared := map[string]bool{}
	for _, e := range txTakingWhitelist {
		declared[e.Callee] = true
	}
	for m, reason := range txTakingMethodsWithoutCallers {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("txTakingMethodsWithoutCallers 的 %s 缺理由：無理由的登記等於沒有審過", m)
		}
		declared[m] = true
	}
	var missing, extra []string
	for m := range scan.Methods {
		if !declared[m] {
			extra = append(extra, m)
		}
	}
	for m := range declared {
		if !scan.Methods[m] {
			missing = append(missing, m)
		}
	}
	sort.Strings(extra)
	sort.Strings(missing)
	if len(extra) > 0 {
		t.Errorf("被呼叫方有未登記的 tx-taking 匯出方法：%s\n"+
			"每一個把 *gorm.DB 收進來的匯出方法都是一條編譯器看不見的跨模組寫入通道，"+
			"必須登記於 txTakingWhitelist（有呼叫點時）或 txTakingMethodsWithoutCallers（尚無呼叫點時）並附理由", strings.Join(extra, ", "))
	}
	if len(missing) > 0 {
		t.Errorf("登記了被呼叫方並不存在的 tx-taking 方法：%s（登記已過期）",
			strings.Join(missing, ", "))
	}
}

// TestTxTakingReasonMutation 判定純函式的突變自檢：
// 餵合成的登記表，證明「無理由」「欄位殘缺」「未指名原始寫入點」三種形態都會被挑出，
// 且乾淨輸入零誤判。（`packages.Load` 需要完整 module，無法以 TempDir 造樣本樹）
func TestTxTakingReasonMutation(t *testing.T) {
	clean := []txTakingEntry{
		{CallerFile: "a.go", Callee: "M", OriginalSites: []string{"x:1"}, Reason: "有理由"},
	}
	if v := txTakingReasonViolations(clean); len(v) != 0 {
		t.Errorf("乾淨輸入不得誤判: %v", v)
	}
	cases := []struct {
		name  string
		entry txTakingEntry
	}{
		{"理由空白", txTakingEntry{CallerFile: "a.go", Callee: "M", OriginalSites: []string{"x:1"}}},
		{"理由僅空白字元", txTakingEntry{CallerFile: "a.go", Callee: "M", OriginalSites: []string{"x:1"}, Reason: "   "}},
		{"欄位殘缺", txTakingEntry{CallerFile: "", Callee: "M", OriginalSites: []string{"x:1"}, Reason: "有理由"}},
		{"未指名原始寫入點", txTakingEntry{CallerFile: "a.go", Callee: "M", Reason: "有理由"}},
	}
	for _, c := range cases {
		if v := txTakingReasonViolations([]txTakingEntry{c.entry}); len(v) != 1 {
			t.Errorf("%s：應恰好挑出 1 筆違規, got %v", c.name, v)
		}
	}
}
