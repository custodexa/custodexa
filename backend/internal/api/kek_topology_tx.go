package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/sourceip"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 金鑰拓撲的交易內寫入：拓撲端點與重包流程兩條成功路徑共用。
//
// 單一交易內依序：取拓撲序列化鎖 → 寫拓撲（鎖內讀出 before）→ 交易內成功審計
// （前後摘要、correlation_id、來源）→ 前後不同時產生金鑰拓撲變更系統告警。
// 摘要與分類只用鎖內讀到的 before。任一步失敗整筆回滾、拓撲維持原值。
// 系統告警取代舊的非持久通知，同一次變更只發一次。

// 拓撲寫入的來源（審計 details 的 source）。
const (
	topologySourceEndpoint = "topology_endpoint"
	topologySourceRewrap   = "rewrap"
)

// errTopologyAlertRaise 拓撲變更告警寫入失敗（整筆已回滾）。
var errTopologyAlertRaise = errors.New("金鑰拓撲變更告警寫入失敗")

// kekTopologyHooks 測試同步點（生產為 nil）：取鎖之後、讀舊值之前
var kekTopologyHooks struct {
	afterLock func(address string)
}

// SetEvidenceSinks 注入拓撲變更的交易內審計與系統告警落地面（組裝根呼叫）。
func (h *KeyManagementHandler) SetEvidenceSinks(txSink port.TxSink, alerts port.SystemAlertSink) {
	h.txSink, h.alerts = txSink, alerts
}

// EvidenceSinksReady 組裝根啟動自檢：兩個落地面都已注入。
func (h *KeyManagementHandler) EvidenceSinksReady() error {
	if h.txSink == nil {
		return fmt.Errorf("金鑰拓撲: %w", port.ErrTxSinkMissing)
	}
	if h.alerts == nil {
		return fmt.Errorf("金鑰拓撲: %w", port.ErrSystemAlertSinkMissing)
	}
	return nil
}

// topologyChangeKinds 前後拓撲不同的欄位類別（升冪、去重）；不含任何位址或秘密。
func topologyChangeKinds(before, after *model.KEKTopology) []string {
	var b model.KEKTopology
	if before != nil {
		b = *before
	}
	var kinds []string
	if b.Provider != after.Provider {
		kinds = append(kinds, "provider")
	}
	if b.Address != after.Address {
		kinds = append(kinds, "address")
	}
	if b.TransitKeyName != after.TransitKeyName {
		kinds = append(kinds, "transit_key_name")
	}
	if b.RoleID != after.RoleID {
		kinds = append(kinds, "role_id")
	}
	if b.Region != after.Region {
		kinds = append(kinds, "region")
	}
	sort.Strings(kinds)
	return kinds
}

// saveTopologyInTx 在單一交易內寫拓撲、成功審計與（有變更時）系統告警。
// 回傳鎖內讀到的 before 與寫入後的 after，以及兩者的摘要。
func (h *KeyManagementHandler) saveTopologyInTx(c *gin.Context, in keyvault.KEKTopologyInput, source string) (after *model.KEKTopology, beforeSummary, afterSummary string, err error) {
	if err := h.EvidenceSinksReady(); err != nil {
		return nil, "", "", err
	}
	actorID, actorName := topologyActorID(c), currentActorName(c)
	clientIP := sourceip.Of(c)
	err = h.db.Transaction(func(tx *gorm.DB) error {
		if err := keyvault.LockKEKTopologyTx(tx); err != nil {
			return err
		}
		if hook := kekTopologyHooks.afterLock; hook != nil {
			hook(in.Address)
		}
		before, saved, err := keyvault.SaveKEKTopologyTx(tx, in)
		if err != nil {
			return err
		}
		after = saved
		beforeSummary, afterSummary = topologySummary(before), topologySummary(saved)
		changed := beforeSummary != afterSummary || (before != nil && before.Provider != saved.Provider)
		correlationID := ""
		if changed {
			if correlationID, err = newEvidenceCorrelationID(); err != nil {
				return err
			}
		}
		details := map[string]any{
			"event":    "kek_topology_update",
			"provider": in.Provider,
			"before":   beforeSummary,
			"after":    afterSummary,
			"source":   source,
		}
		if correlationID != "" {
			details["correlation_id"] = correlationID
		}
		body, err := json.Marshal(details)
		if err != nil {
			return fmt.Errorf("編碼拓撲變更審計失敗: %w", err)
		}
		if err := port.WriteInTx(h.txSink, tx, port.AuditEvent{
			Actor:    gatewayapi.Actor{UserID: actorID, Username: actorName},
			Action:   string(model.ActionUpdate),
			Resource: string(model.ResourceKeyManagement),
			Status:   string(model.StatusSuccess),
			Request: gatewayapi.RequestMeta{Method: c.Request.Method, Path: c.Request.URL.Path,
				ClientIP: clientIP, StatusCode: http.StatusOK, Body: string(body)},
			Details: string(body),
		}); err != nil {
			return fmt.Errorf("寫入拓撲變更審計失敗: %w", err)
		}
		if !changed {
			return nil
		}
		kinds := topologyChangeKinds(before, saved)
		if len(kinds) == 0 {
			kinds = []string{"provider"}
		}
		if _, err := port.RaiseInTx(h.alerts, tx, port.SystemAlertEvent{
			Type:          port.SystemAlertKeyTopologyChanged,
			Actor:         port.SystemAlertActor{UserID: actorID, Username: actorName},
			ClientIP:      clientIP,
			Target:        port.SystemAlertTarget{Kind: port.SystemAlertTargetSystemSetting, ID: "kek_topology"},
			CorrelationID: correlationID,
			Params:        map[string]string{"change_kind": strings.Join(kinds, ",")},
		}); err != nil {
			return fmt.Errorf("%w: %w", errTopologyAlertRaise, err)
		}
		return nil
	})
	if err != nil {
		return nil, "", "", err
	}
	if h.auditTopologyHook != nil {
		h.auditTopologyHook(topologyAuditRecord{provider: in.Provider, before: beforeSummary, after: afterSummary, ok: true})
	}
	return after, beforeSummary, afterSummary, nil
}
