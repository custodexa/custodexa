package asset

import (
	"encoding/json"
	"log"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// asset 模組的交易內審計產生點（T-2 的 11 處）。
//
// **收口前的形態**：11 個呼叫點都呼叫 `model.RecordAssetAccountChange`／
// `model.RecordAssetChange`／`model.RecordAssetNodeChange`，由 `internal/model`
// 直接 `tx.Create(&AuditLog{})` 落地（manifest 的 AP-22／AP-26／AP-27）。
// 那使 **audit 的落地面在 model 層又開了三個入口**，且 asset 模組的審計寫入
// 對 audit 模組完全不可見。
//
// **收口後**：事件的**建構**留在 asset（欄位語義是 asset 的），**落地**一律經
// `port.WriteInTx`（audit 的唯一交易內落地面）。三個函式的簽名刻意與收口前的
// `model.Record*Change` 逐位相同、只多一個 sink 參數——使 diff 只有「誰去寫」，
// 沒有「寫什麼」。
//
// **fail-close 逐點保存**：本檔三個函式一律把 error 原樣回傳、不吞不包裝；
// 呼叫端的 `return`／`log.Printf` 二分逐點維持收口前的現況（AP-39／41／42 是
// 刻意的 fail-open，manifest 已標 `fail-close?＝否`，收口時不得順手改判——
// 那是行為變更）。

// auditActionForAccountOp 帳號操作 → 審計動作。
// 自 `internal/model/asset_account_audit.go` 隨 T-2 收口一併遷入（未匯出，零 export budget）。
func auditActionForAccountOp(op string) model.AuditAction {
	switch op {
	case model.AccountOpCreate:
		return model.ActionCreate
	case model.AccountOpDelete:
		return model.ActionDelete
	default:
		return model.ActionUpdate
	}
}

// writeAssetAccountAudit 記錄帳號操作審計（原 model.RecordAssetAccountChange）。
//
// Resource 用 asset＋ResourceID＝assetID：帳號無獨立的審計查詢入口，掛在資產下
// 才能在「這台資產發生過什麼」的既有時間線上被看見；帳號自身以 Details 的
// account_id/account_username 辨識。
func writeAssetAccountAudit(sink port.TxSink, tx *gorm.DB, a model.AssetAccountAudit, userID uint, operator string) error {
	details := model.AssetAccountAuditDetails{
		Resource:        "asset_account",
		AccountID:       a.AccountID,
		Username:        a.Username,
		Operation:       a.Operation,
		Fields:          a.Fields,
		CopyFromAssetID: a.CopyFromAssetID,
		CopyFromAccount: a.CopyFromAccount,
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		log.Printf("序列化帳號變更詳情失敗: %v", err)
		detailsJSON = []byte("{}")
	}

	assetID := a.AssetID
	return port.WriteInTx(sink, tx, port.AuditEvent{
		OccurredAt: time.Now(),
		Actor:      gatewayapi.Actor{UserID: userID, Username: operator},
		Action:     string(auditActionForAccountOp(a.Operation)),
		Resource:   string(model.ResourceAsset),
		ResourceID: &assetID,
		// 帳號事件的主體是它所屬的那台資產（auditor-workbench）：帳號無獨立樞紐，
		// 不釘主體鍵就只能靠 (resource, resource_id) 反推，而那條路會撈到同號的別種實體
		AssetID: &assetID,
		Status:  string(model.StatusSuccess),
		Details: string(detailsJSON),
	})
}

// writeAssetChangeAudit 記錄資產變更（原 model.RecordAssetChange）。
//
// **「無變更即不記錄」的語義逐字保留**：`ActionUpdate` 且 diff 為空時回 nil 且
// 不產生任何審計列——收口前如此，收口後亦然。這一條若被順手改成「總是寫一列」，
// 既有的審計列數斷言會整批漂移。
func writeAssetChangeAudit(sink port.TxSink, tx *gorm.DB, old, new *model.Asset,
	userID uint, username string, action model.AuditAction) error {

	changes := model.DiffAsset(old, new)
	if len(changes) == 0 && action == model.ActionUpdate {
		// 沒有變更，不記錄
		return nil
	}

	details := model.AssetChangeDetails{Changes: changes}
	// 伺服端自動清空允許資料庫清單的留痕。
	//
	// **判定自 old／new 推得而非由呼叫端傳入**：Update 的驗證保證了「非主控台協議
	// 的清單一律不得為非空」，故「新協議不支援主控台、舊清單非空、新清單空」
	// 這個形狀只可能來自伺服端的自動清空——顯式送非空的請求在更早就被擋掉了。
	// 讓判定與被判定的事實同源，勝過在服務層多傳一個會與實際行為漂移的旗標。
	if !new.Protocol.SupportsQueryConsole() &&
		len(old.AllowedDatabases) > 0 && len(new.AllowedDatabases) == 0 {
		details.AllowedDatabasesCleared = true
		details.PreviousAllowedDatabaseCount = len(old.AllowedDatabases)
	}
	// 伺服端自動清空改密通道的留痕。判定同樣自 old／new 推得：Update 的驗證保證了
	// 「顯式送來的不相容組合一律被拒」，故「舊通道與新協定不相容、新通道為空」
	// 這個形狀只可能來自伺服端的自動清空
	if old.RotationChannel != "" && new.RotationChannel == "" &&
		!model.RotationChannelCompatibleWith(new.Protocol, old.RotationChannel) {
		details.RotationChannelCleared = true
		details.PreviousRotationChannel = old.RotationChannel
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		log.Printf("序列化變更詳情失敗: %v", err)
		detailsJSON = []byte("{}")
	}

	resourceID := &new.ID
	if action == model.ActionDelete {
		resourceID = &old.ID
	}

	return port.WriteInTx(sink, tx, port.AuditEvent{
		OccurredAt: time.Now(),
		Actor:      gatewayapi.Actor{UserID: userID, Username: username},
		Action:     string(action),
		Resource:   string(model.ResourceAsset),
		ResourceID: resourceID,
		// 與 ResourceID 同源而非取 new.ID：刪除事件的資產已不存在於 new，
		// 兩欄取值分家會讓同一列自陳兩台不同的機器
		AssetID: resourceID,
		Status:  string(model.StatusSuccess),
		Details: string(detailsJSON),
	})
}

// writeAssetNodeChangeAudit 節點掛載變更審計（原 model.RecordAssetNodeChange）。
// M2M 成員不經 hook diff，由 service 節點同步邏輯顯式呼叫，記 node_ids 舊→新。
func writeAssetNodeChangeAudit(sink port.TxSink, tx *gorm.DB, assetID uint,
	oldNodeIDs, newNodeIDs []uint, userID uint, username string) error {

	details := model.AssetChangeDetails{Changes: []model.AssetChange{
		{Field: "node_ids", Old: oldNodeIDs, New: newNodeIDs},
	}}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		log.Printf("序列化節點變更詳情失敗: %v", err)
		detailsJSON = []byte("{}")
	}

	return port.WriteInTx(sink, tx, port.AuditEvent{
		OccurredAt: time.Now(),
		Actor:      gatewayapi.Actor{UserID: userID, Username: username},
		Action:     string(model.ActionUpdate),
		Resource:   string(model.ResourceAsset),
		ResourceID: &assetID,
		// 節點搬移改的是這台資產的掛載位置，主體仍是資產本身而非被掛的節點
		AssetID: &assetID,
		Status:  string(model.StatusSuccess),
		Details: string(detailsJSON),
	})
}
