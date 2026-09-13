package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/notifycat"
	"github.com/custodexa/backend/internal/sourceip"
)

// 委託拓撲的設定端點（`/keys` 群組，admin 限定）。
//
// # 這一組欄位為什麼算安全變更
//
// 拓撲承載「上鎖的資料金鑰送去哪裡解、重包時明文金鑰送去哪裡」。改掉位址就等於
// 改掉目的地，故：只能經已認證且具管理角色的端點；成功與被拒**都**留痕且審計本文
// 查得到前後值；成功另發安全類告警。
//
// # 三者都不阻止具資料庫寫入權者直接改表
//
// 認證端點、審計、告警、以及解封頁與換鑰精靈的兩處人工核對，共同承擔課責。
// 那條路的防線是資料庫存取控管與離機的審計副本，不在本端點射程；
// 本檔的任何說明 SHALL NOT 把核對勾選寫成安全保證。

// kekTopologyRequest 拓撲更新的請求本文。
//
// **json tag 是遮罩清單的對照基準**（auditmask 的綁定點掃描器讀它），故四個欄位
// 全部具名；未出現在該服務商鍵集內的欄位由 handler 拒絕，不靠 tag 缺席擋。
type kekTopologyRequest struct {
	Address        string `json:"address"`
	TransitKeyName string `json:"transit_key_name"`
	RoleID         string `json:"role_id"`
	Region         string `json:"region"`
}

// kekTopologyResponse 拓撲的對外形狀（GET 與 PUT 共用）。
type kekTopologyResponse struct {
	Provider       string   `json:"provider"`
	Configured     bool     `json:"configured"`
	Address        string   `json:"address"`
	TransitKeyName string   `json:"transit_key_name"`
	RoleID         string   `json:"role_id"`
	Region         string   `json:"region"`
	KeyRef         string   `json:"key_ref"`
	EditableFields []string `json:"editable_fields"`
	Digest         string   `json:"digest"`
	UpdatedBy      string   `json:"updated_by"`
	UpdatedAt      string   `json:"updated_at"`
}

// DeploymentKMSProvider 回報部署檔宣告的委託服務商（非委託模式為空字串）。
//
// 以閉包注入而非讓 handler 讀環境：讀部署組態是組裝根的職責，且注入使測試能在
// 不污染行程 env 的前提下覆蓋三家分支。
type DeploymentKMSProvider func() string

// SetDeploymentKMSProvider 注入部署宣告的服務商（組裝根呼叫）。
func (h *KeyManagementHandler) SetDeploymentKMSProvider(fn DeploymentKMSProvider) {
	h.kmsProvider = fn
}

// deploymentProvider 取得部署宣告的服務商。
func (h *KeyManagementHandler) deploymentProvider() string {
	if h.kmsProvider == nil {
		return ""
	}
	return h.kmsProvider()
}

// GetKEKTopology 讀取本部署的委託拓撲。
func (h *KeyManagementHandler) GetKEKTopology(c *gin.Context) {
	provider := h.deploymentProvider()
	row, err := keyvault.LoadKEKTopology(h.db)
	if err != nil && !errors.Is(err, keyvault.ErrKEKTopologyNotConfigured) {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalKeyInventoryQuery, err)
		return
	}
	keyRef, err := keyvault.CurrentKEKID(h.db)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalKeyInventoryQuery, err)
		return
	}
	c.JSON(http.StatusOK, topologyResponse(provider, row, keyRef))
}

// UpdateKEKTopology 更新委託拓撲（單筆原子更新）。
func (h *KeyManagementHandler) UpdateKEKTopology(c *gin.Context) {
	provider := h.deploymentProvider()
	editable := keyvault.EditableTopologyFields(provider)
	if len(editable) == 0 {
		// GCP 與非委託模式：沒有可編輯的欄位。**被拒也留痕**——
		// 「有人試圖改這個部署的目的地」本身就是要留下的事實。
		h.auditTopologyChange(c, provider, "", "", false, apierror.CodeKeyTopologyNotEditable)
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeKeyTopologyNotEditable, nil)
		return
	}

	var req kekTopologyRequest
	raw, err := decodeTopologyBody(c, editable, &req)
	if err != nil {
		h.auditTopologyChange(c, provider, "", raw, false, apierror.CodeKeyTopologyInvalid)
		// 鍵集本身不成立時無「哪一欄壞了」可言，回該服務商的完整可編輯欄位集：
		// 呼叫端據此知道正確的鍵集，前端則把整組標紅。
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeKeyTopologyInvalid,
			map[string]any{"fields": strings.Join(editable, ", ")})
		return
	}

	before, _ := keyvault.LoadKEKTopology(h.db)
	in := keyvault.KEKTopologyInput{
		Provider: provider, Address: req.Address, TransitKeyName: req.TransitKeyName,
		RoleID: req.RoleID, Region: req.Region, UpdatedBy: currentActorName(c),
	}
	beforeSummary := topologySummary(before)
	afterSummary := topologySummary(&model.KEKTopology{Provider: provider, Address: req.Address,
		TransitKeyName: req.TransitKeyName, RoleID: req.RoleID, Region: req.Region})

	savedBefore, after, err := keyvault.SaveKEKTopology(h.db, in)
	if err != nil {
		var verr *keyvault.KEKTopologyValidationError
		code := apierror.CodeKeyTopologyInvalid
		status := http.StatusBadRequest
		if errors.Is(err, keyvault.ErrKEKTopologyNotEditable) {
			code = apierror.CodeKeyTopologyNotEditable
		} else if !errors.As(err, &verr) {
			code = apierror.CodeInternalKeyInventoryQuery
			status = http.StatusInternalServerError
		}
		// 被拒的變更同樣留痕，且審計本文查得到**企圖改成什麼**。
		h.auditTopologyChange(c, provider, beforeSummary, afterSummary, false, code)
		if status == http.StatusInternalServerError {
			apierror.RespondInternal(c, status, code, err)
			return
		}
		// fields 為已宣告的 ParamOpaque：以 ", " 相接後既進訊息，也讓前端切開
		// 逐欄標紅。型別必須是字串——切片會在 validateParams 被整組丟掉。
		payload := map[string]any{}
		if code == apierror.CodeKeyTopologyInvalid {
			names := editable
			if errors.As(err, &verr) && len(verr.Fields) > 0 {
				names = verr.Fields
			}
			payload["fields"] = strings.Join(names, ", ")
		}
		apierror.Respond(c, status, code, payload)
		return
	}
	_ = savedBefore

	h.auditTopologyChange(c, provider, beforeSummary, afterSummary, true, "")
	h.notifyTopologyChange(currentActorName(c), provider, beforeSummary, afterSummary)

	keyRef, _ := keyvault.CurrentKEKID(h.db)
	c.JSON(http.StatusOK, topologyResponse(provider, after, keyRef))
}

// decodeTopologyBody 以**該服務商的精確鍵集**解析請求本文。
//
// 多一鍵、少一鍵、未知鍵、重複鍵一律拒絕：union 不允許選填欄位，否則「缺漏」與
// 「刻意不帶」無從區分。回傳去識別的鍵名摘要供留痕（不含值）。
func decodeTopologyBody(c *gin.Context, editable []string, req *kekTopologyRequest) (string, error) {
	var raw map[string]json.RawMessage
	dec := json.NewDecoder(c.Request.Body)
	if err := dec.Decode(&raw); err != nil {
		return "", err
	}
	if len(raw) != len(editable) {
		return keyNames(raw), fmt.Errorf("欄位組合不符")
	}
	for _, k := range editable {
		if _, ok := raw[k]; !ok {
			return keyNames(raw), fmt.Errorf("缺少欄位 %s", k)
		}
	}
	for k, v := range raw {
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return keyNames(raw), err
		}
		switch k {
		case "address":
			req.Address = s
		case "transit_key_name":
			req.TransitKeyName = s
		case "role_id":
			req.RoleID = s
		case "region":
			req.Region = s
		}
	}
	return keyNames(raw), nil
}

func keyNames(raw map[string]json.RawMessage) string {
	names := make([]string, 0, len(raw))
	for k := range raw {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// topologyResponse 組出對外形狀。
func topologyResponse(provider string, row *model.KEKTopology, keyRef string) kekTopologyResponse {
	out := kekTopologyResponse{
		Provider:       provider,
		Configured:     row != nil,
		KeyRef:         keyRef,
		EditableFields: keyvault.EditableTopologyFields(provider),
	}
	if out.EditableFields == nil {
		out.EditableFields = []string{}
	}
	if row != nil {
		out.Address, out.TransitKeyName, out.RoleID, out.Region = row.Address, row.TransitKeyName, row.RoleID, row.Region
		out.UpdatedBy = row.UpdatedBy
		out.UpdatedAt = row.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	if row != nil || keyRef != "" {
		out.Digest = keyvault.TopologyDigest(row, keyRef)
	}
	return out
}

// topologySummary 前後值的可讀摘要（**非秘密欄位**）。
//
// 未設定時為固定字面而非空字串：「首次設定」與「摘要組不出來」在通知與審計上
// 必須分得開。
func topologySummary(row *model.KEKTopology) string {
	if row == nil {
		return "(unset)"
	}
	var parts []string
	if row.Address != "" {
		parts = append(parts, "address="+row.Address)
	}
	if row.TransitKeyName != "" {
		parts = append(parts, "transit_key_name="+row.TransitKeyName)
	}
	if row.RoleID != "" {
		parts = append(parts, "role_id="+row.RoleID)
	}
	if row.Region != "" {
		parts = append(parts, "region="+row.Region)
	}
	if len(parts) == 0 {
		return "(unset)"
	}
	return strings.Join(parts, " ")
}

// topologyAuditRecord 一次拓撲變更留痕的可觀察形狀。
//
// **存在的理由是可驗證性**：「成功與被拒都留痕、且本文查得到前後值」是本端點的
// 硬性要求，而它只有在能被讀回來的時候才是一條可檢查的性質。審計服務的寫入面
// 需要整條檢查點鏈才建得起來，在端點層的測試裡把它架起來只會讓測試在驗別的東西。
type topologyAuditRecord struct {
	provider string
	before   string
	after    string
	ok       bool
	code     string
}

// auditTopologyChange 寫入拓撲變更的專屬審計列。
//
// **前後值進本文**：只記「拓撲已變更」不成立——稽核要回答的是「送去哪裡解」變成
// 了什麼。四個欄位皆為非秘密，另於審計遮罩的拓撲端點專屬集登記為可追蹤。
func (h *KeyManagementHandler) auditTopologyChange(c *gin.Context, provider, before, after string, ok bool, code apierror.ErrCode) {
	if h.auditTopologyHook != nil {
		h.auditTopologyHook(topologyAuditRecord{provider: provider, before: before, after: after, ok: ok, code: string(code)})
	}
	if h.auditService == nil {
		return
	}
	details := map[string]any{
		"event":    "kek_topology_update",
		"provider": provider,
		"before":   before,
		"after":    after,
	}
	if !ok {
		details["rejected_code"] = string(code)
	}
	body, err := json.Marshal(details)
	if err != nil {
		return
	}
	status := model.StatusSuccess
	statusCode := http.StatusOK
	if !ok {
		status = model.StatusFailure
		statusCode = http.StatusBadRequest
	}
	h.auditService.Log(&audit.AuditLogEntry{
		UserID: topologyActorID(c), Username: currentActorName(c),
		Action: model.ActionUpdate, Resource: model.ResourceKeyManagement,
		Status: status, Method: c.Request.Method, Path: c.Request.URL.Path,
		ClientIP: sourceip.Of(c), StatusCode: statusCode, RequestBody: string(body),
	})
}

// notifyTopologyChange 發出安全類告警。
//
// **不走 alert_rules**：該表是危險指令的正則規則，拓撲變更不是指令事件。
// 通知通道未設定或不可達時只有審計——介面 SHALL NOT 宣稱已通知。
func (h *KeyManagementHandler) notifyTopologyChange(actor, provider, before, after string) {
	notifier := audit.GetAlertNotifier()
	if notifier == nil {
		return
	}
	if actor == "" {
		actor = "unknown"
	}
	notifier.NotifyEvent(notifycat.EventKEKTopologyChanged, map[string]string{
		"actor": actor, "provider": provider, "before": before, "after": after,
	})
}

// currentActorName／topologyActorID 取本次請求的操作者（課責欄）。
//
// 端點在 AuthMiddleware 之後，兩者必然有值；取不到時留空而非以固定值頂替
// ——「不知道是誰」與「是某個人」在稽核上不是同一件事。
func currentActorName(c *gin.Context) string {
	name, _ := middleware.GetCurrentUsername(c)
	return name
}

func topologyActorID(c *gin.Context) uint {
	id, _ := middleware.GetCurrentUserID(c)
	return id
}
