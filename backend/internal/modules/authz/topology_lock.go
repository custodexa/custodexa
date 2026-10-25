package authz

import (
	"errors"
	"fmt"

	"gorm.io/gorm"
)

// 拓撲序列化鎖：改動資產拓撲（資產掛在哪些節點、節點樹形狀）的寫入交易，與以拓撲為輸入的
// 範圍判定交易，經同一把交易級鎖排成單一序列，判定因此不會讀到半套拓撲，
// 也不會漏掉一次尚未提交的拓撲變更。鎖只負責序列化，不含任何判定。
//
// 取鎖位置是交易的第一個動作，早於任何業務列鎖（憑證列、資產列等）；
// 使用者層與群組層的鎖若同交易需要，先於本鎖（鎖的全序見範圍判定契約）。

// TopologySerializationLockClass 兩參數 advisory 鎖的 classid（objid 恆為 1）。
// 登記於 keyvault 的 key_manager_lock.go 兩參數清單。
const TopologySerializationLockClass int32 = 0x6F74_6B04

const topologySerializationLockObjID int32 = 1

// ErrTopologyLockOutsideTx 拓撲鎖必須在交易內取得：交易外取得的 xact 鎖在語句結束就釋放，
// 等於沒有鎖。
var ErrTopologyLockOutsideTx = errors.New("authz: topology lock requires a transaction")

// LockScopeTopologyTx 於呼叫端交易 tx 內取得拓撲序列化鎖，持有到交易結束。
//
// PostgreSQL 取 pg_advisory_xact_lock(class, 1)。SQLite 沒有 advisory 鎖，改以不改值的
// 寫入取得整庫寫鎖（與命中列數無關）；SQLite 只服務測試，序列化強度與 PostgreSQL
// 不等價：競爭時是等待 busy timeout 還是立刻回錯，取決於取鎖前交易是否已讀過資料，
// 回錯原樣上拋、由呼叫端整筆回滾，不重試，也不依交易內是否已有讀取而分支。
//
// 取鎖交易維持 Read Committed：鎖之後的拓撲與主體必須以新語句重讀。
func LockScopeTopologyTx(tx *gorm.DB) error {
	if tx == nil || tx.Statement == nil {
		return ErrTopologyLockOutsideTx
	}
	if _, ok := tx.Statement.ConnPool.(gorm.TxCommitter); !ok {
		return ErrTopologyLockOutsideTx
	}
	switch tx.Dialector.Name() {
	case "postgres":
		if err := tx.Exec("SELECT pg_advisory_xact_lock(?, ?)",
			TopologySerializationLockClass, topologySerializationLockObjID).Error; err != nil {
			return fmt.Errorf("取得拓撲序列化鎖失敗: %w", err)
		}
	case "sqlite":
		if err := tx.Exec("UPDATE role_binding_nodes SET node_id = node_id WHERE 1 = 0").Error; err != nil {
			return fmt.Errorf("取得拓撲序列化鎖失敗: %w", err)
		}
	default:
		return fmt.Errorf("不支援的資料庫 dialect %q：無拓撲序列化鎖實作", tx.Dialector.Name())
	}
	// 測試期掛點（生產恆為 nil）：把本交易登記為已持拓撲鎖，供鎖序守衛判定其後的使用者層鎖；
	// 停點讓測試把交易停在「已取拓撲鎖、尚未執行下一個語句」。
	if probe := LockOrderProbeHook(); probe != nil {
		probe(tx, LockLayerTopology)
	}
	if h := loadTopologyLockAcquiredHook(); h != nil {
		h(tx)
	}
	return nil
}
