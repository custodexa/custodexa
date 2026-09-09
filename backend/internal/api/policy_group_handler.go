package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/sourceip"
)

// 政策組管理端點：規範條文與安全設定的對照，全部寫入收在這一組路由上。
//
// **寫入只有這一個入口**：合規對照頁是唯讀的，設定頁也不得改對照——同一份對照
// 有兩個寫入面時，「這條要求是誰改的」會分裂成兩套記錄。讀取開放給稽核人員
// （他們要看得到對照的內容才判讀得了結果），寫入限管理員。

// 組代號的路徑參數。路徑字串逐字不變，抽成常數使參數名只有一個改點——
// 路由與 handler 取參數的名字對不上時，症狀是參數靜默地讀成空字串。
const policyGroupCodePath = "/:code"

// PolicyGroupHandler 政策組、條文、機構備註與人工確認的管理端。
type PolicyGroupHandler struct {
	groups     *policy.PolicyGroupRepository
	compliance *policy.ComplianceService
	audit      *audit.AuditLogService
}

// NewPolicyGroupHandler 建立政策組管理 handler（auditService 可為 nil，表示停用審計）。
func NewPolicyGroupHandler(groups *policy.PolicyGroupRepository,
	compliance *policy.ComplianceService, auditService *audit.AuditLogService) *PolicyGroupHandler {
	return &PolicyGroupHandler{groups: groups, compliance: compliance, audit: auditService}
}

// clauseView 條文加上它的要求與機構備註（管理頁與合規對照頁共用的呈現形狀）。
//
// 條文、要求、備註分屬三張表是因為生命週期不同，但畫面上它們是一張卡片；
// 讓前端自己做三次對照，等於把「哪一條備註掛在哪一條條文上」再實作一遍。
type clauseView struct {
	model.PolicyClause
	Controls   []model.PolicyClauseControl   `json:"controls"`
	Annotation *model.PolicyClauseAnnotation `json:"annotation,omitempty"`
}

// buildClauseViews 把三張表併成條文卡片；groupCode 為空＝全部組。
func buildClauseViews(clauses []model.PolicyClause, controls []model.PolicyClauseControl,
	annotations []model.PolicyClauseAnnotation) []clauseView {

	byClause := map[string][]model.PolicyClauseControl{}
	for _, c := range controls {
		key := c.GroupCode + "\x00" + c.ClauseNo
		byClause[key] = append(byClause[key], c)
	}
	annotationBy := map[string]*model.PolicyClauseAnnotation{}
	for i := range annotations {
		a := annotations[i]
		annotationBy[a.GroupCode+"\x00"+a.ClauseNo] = &a
	}

	out := make([]clauseView, 0, len(clauses))
	for _, clause := range clauses {
		key := clause.GroupCode + "\x00" + clause.ClauseNo
		view := clauseView{PolicyClause: clause, Controls: byClause[key]}
		if view.Controls == nil {
			view.Controls = []model.PolicyClauseControl{}
		}
		view.Annotation = annotationBy[key]
		out = append(out, view)
	}
	return out
}

// List 政策組清單（admin 與 auditor）。
func (h *PolicyGroupHandler) List(c *gin.Context) {
	groups, err := h.groups.ListGroups()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError,
			apierror.CodeInternalPolicyGroupRead, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": groups})
}

// Get 單一政策組的條文、要求與機構備註（admin 與 auditor）。
func (h *PolicyGroupHandler) Get(c *gin.Context) {
	code := c.Param("code")
	group, err := h.groups.GetGroup(code)
	if err != nil {
		respondPolicyGroupError(c, err, apierror.CodeInternalPolicyGroupRead)
		return
	}
	clauses, controls, annotations, err := h.readGroupContent(code)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError,
			apierror.CodeInternalPolicyGroupRead, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": gin.H{
		"group":   group,
		"clauses": buildClauseViews(clauses, controls, annotations),
	}})
}

// readGroupContent 取某組的條文、要求與備註三張表。
func (h *PolicyGroupHandler) readGroupContent(code string) ([]model.PolicyClause,
	[]model.PolicyClauseControl, []model.PolicyClauseAnnotation, error) {

	clauses, err := h.groups.ListClauses(code)
	if err != nil {
		return nil, nil, nil, err
	}
	controls, err := h.groups.ListControls(code)
	if err != nil {
		return nil, nil, nil, err
	}
	annotations, err := h.groups.ListAnnotations(code)
	if err != nil {
		return nil, nil, nil, err
	}
	return clauses, controls, annotations, nil
}

// policyGroupCreateRequest 建立自建組
type policyGroupCreateRequest struct {
	Code string `json:"code" binding:"required"`
	Name string `json:"name" binding:"required"`
	// Locale 機構原文的語言標示：自建組的條文原樣儲存與顯示，不機器翻譯，
	// 介面據此標示「機構原文」
	Locale string `json:"locale"`
}

// Create 建立機構自建政策組。
func (h *PolicyGroupHandler) Create(c *gin.Context) {
	var req policyGroupCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	if err := h.groups.CreateCustomGroup(req.Code, req.Name, req.Locale); err != nil {
		respondPolicyGroupError(c, err, apierror.CodeInternalPolicyGroupWrite)
		return
	}
	// **審計緊接著寫入，不等回應用的那次讀取**：資料已經變了，而讀取失敗會讓
	// 這次寫入完全沒有留痕——回應可以是 500，稽核軌跡不能是空的
	h.writeAudit(c, model.ActionCreate, req.Code, "", "group_create",
		[]policyChangeDetail{{Field: "name", Old: "", New: req.Name}})
	group, err := h.groups.GetGroup(req.Code)
	if err != nil {
		respondPolicyGroupError(c, err, apierror.CodeInternalPolicyGroupRead)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": group})
}

// policyGroupRenameRequest 更名
type policyGroupRenameRequest struct {
	Name string `json:"name" binding:"required"`
}

// Rename 自建組更名。
func (h *PolicyGroupHandler) Rename(c *gin.Context) {
	code := c.Param("code")
	var req policyGroupRenameRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	before, err := h.groups.GetGroup(code)
	if err != nil {
		respondPolicyGroupError(c, err, apierror.CodeInternalPolicyGroupRead)
		return
	}
	if err := h.groups.RenameCustomGroup(code, req.Name); err != nil {
		respondPolicyGroupError(c, err, apierror.CodeInternalPolicyGroupWrite)
		return
	}
	h.writeAudit(c, model.ActionUpdate, code, "", "group_rename",
		[]policyChangeDetail{{Field: "name", Old: before.Name, New: req.Name}})
	after, err := h.groups.GetGroup(code)
	if err != nil {
		respondPolicyGroupError(c, err, apierror.CodeInternalPolicyGroupRead)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": after})
}

// policyGroupEnabledRequest 生效開關。
//
// 指標而非裸布林：缺欄位與明確送 false 必須分得出來，否則漏帶欄位會被讀成
// 「請把這一組停用」，而停用一整組的後果是它的偏離全部消失在畫面上。
type policyGroupEnabledRequest struct {
	Enabled *bool `json:"enabled" binding:"required"`
}

// SetEnabled 切換政策組生效（內建組亦可，生效與否由機構決定）。
func (h *PolicyGroupHandler) SetEnabled(c *gin.Context) {
	code := c.Param("code")
	var req policyGroupEnabledRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Enabled == nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	before, err := h.groups.GetGroup(code)
	if err != nil {
		respondPolicyGroupError(c, err, apierror.CodeInternalPolicyGroupRead)
		return
	}
	if err := h.groups.SetGroupEnabled(code, *req.Enabled); err != nil {
		respondPolicyGroupError(c, err, apierror.CodeInternalPolicyGroupWrite)
		return
	}
	h.writeAudit(c, model.ActionUpdate, code, "", "group_enabled",
		[]policyChangeDetail{{
			Field: "enabled",
			Old:   fmt.Sprintf("%t", before.Enabled),
			New:   fmt.Sprintf("%t", *req.Enabled),
		}})
	after, err := h.groups.GetGroup(code)
	if err != nil {
		respondPolicyGroupError(c, err, apierror.CodeInternalPolicyGroupRead)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": after})
}

// Delete 刪除自建組（連帶清除其條文、要求與備註）。
func (h *PolicyGroupHandler) Delete(c *gin.Context) {
	code := c.Param("code")
	before, err := h.groups.GetGroup(code)
	if err != nil {
		respondPolicyGroupError(c, err, apierror.CodeInternalPolicyGroupRead)
		return
	}
	if err := h.groups.DeleteCustomGroup(code); err != nil {
		respondPolicyGroupError(c, err, apierror.CodeInternalPolicyGroupWrite)
		return
	}
	h.writeAudit(c, model.ActionDelete, code, "", "group_delete",
		[]policyChangeDetail{{Field: "name", Old: before.Name, New: ""}})
	c.JSON(http.StatusOK, gin.H{"data": gin.H{"code": code}})
}

// policyClauseControlRequest 條文對單一設定鍵的要求。
//
// 未定值（由稽核判讀）以 comparator=review、expected_value 留空表達；
// 它不是漏填，而是條文本身沒有給出可比較的值
type policyClauseControlRequest struct {
	PolicyKey     string `json:"policy_key"`
	Comparator    string `json:"comparator"`
	ExpectedValue string `json:"expected_value"`
	ReferenceOnly bool   `json:"reference_only"`
}

// policyClauseUpsertRequest 新增或編輯條文（要求為整批取代）
type policyClauseUpsertRequest struct {
	Title    string                       `json:"title"`
	Summary  string                       `json:"summary"`
	Kind     string                       `json:"kind"`
	Controls []policyClauseControlRequest `json:"controls"`
}

// UpsertClause 新增或編輯自建組的條文。
func (h *PolicyGroupHandler) UpsertClause(c *gin.Context) {
	code, clauseNo := c.Param("code"), c.Param("clause_no")
	var req policyClauseUpsertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	old, err := h.clauseDigest(code, clauseNo)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError,
			apierror.CodeInternalPolicyGroupRead, err)
		return
	}

	clause := model.PolicyClause{
		GroupCode: code, ClauseNo: clauseNo,
		Title: req.Title, Summary: req.Summary, Kind: req.Kind,
	}
	controls := make([]model.PolicyClauseControl, 0, len(req.Controls))
	for _, ctrl := range req.Controls {
		controls = append(controls, model.PolicyClauseControl{
			PolicyKey:     ctrl.PolicyKey,
			Comparator:    ctrl.Comparator,
			ExpectedValue: ctrl.ExpectedValue,
			ReferenceOnly: ctrl.ReferenceOnly,
		})
	}
	written, writtenControls, err := h.groups.UpsertCustomClause(clause, controls)
	if err != nil {
		respondPolicyGroupError(c, err, apierror.CodeInternalPolicyGroupWrite)
		return
	}
	// 新值取自寫入端回傳的那一份，不再讀一次資料庫：提交後的讀取失敗只該影響
	// 回應，不該讓一次已經生效的對照變更沒有留痕
	h.writeAudit(c, model.ActionUpdate, code, clauseNo, "clause_upsert",
		[]policyChangeDetail{{
			Field: "clause", Old: old, New: formatClauseDigest(written, writtenControls),
		}})

	view, err := h.singleClauseView(code, clauseNo)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError,
			apierror.CodeInternalPolicyGroupRead, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": view})
}

// DeleteClause 刪除自建組的條文（機構備註不動：升級與編輯都不得清掉機構寫的東西）。
func (h *PolicyGroupHandler) DeleteClause(c *gin.Context) {
	code, clauseNo := c.Param("code"), c.Param("clause_no")
	old, err := h.clauseDigest(code, clauseNo)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError,
			apierror.CodeInternalPolicyGroupRead, err)
		return
	}
	if err := h.groups.DeleteCustomClause(code, clauseNo); err != nil {
		respondPolicyGroupError(c, err, apierror.CodeInternalPolicyGroupWrite)
		return
	}
	h.writeAudit(c, model.ActionDelete, code, clauseNo, "clause_delete",
		[]policyChangeDetail{{Field: "clause", Old: old, New: ""}})
	c.JSON(http.StatusOK, gin.H{"data": gin.H{"code": code, "clause_no": clauseNo}})
}

// policyClauseNoteRequest 機構備註與人工確認共用的一句說明
type policyClauseNoteRequest struct {
	Note string `json:"note"`
}

// UpsertAnnotation 寫機構備註（不影響判定）。
func (h *PolicyGroupHandler) UpsertAnnotation(c *gin.Context) {
	code, clauseNo := c.Param("code"), c.Param("clause_no")
	var req policyClauseNoteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	before := h.annotationOf(code, clauseNo)
	oldNote := ""
	if before != nil {
		oldNote = before.Note
	}
	if err := h.groups.UpsertAnnotation(code, clauseNo, req.Note); err != nil {
		respondPolicyGroupError(c, err, apierror.CodeInternalPolicyGroupWrite)
		return
	}
	h.writeAudit(c, model.ActionUpdate, code, clauseNo, "annotation_upsert",
		[]policyChangeDetail{{Field: "note", Old: oldNote, New: req.Note}})
	c.JSON(http.StatusOK, gin.H{"data": h.annotationOf(code, clauseNo)})
}

// ConfirmClause 人工確認一條待確認的條文（再次確認覆蓋前次，歷史留在操作日誌）。
func (h *PolicyGroupHandler) ConfirmClause(c *gin.Context) {
	code, clauseNo := c.Param("code"), c.Param("clause_no")
	var req policyClauseNoteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	username, _ := middleware.GetCurrentUsername(c)
	before := h.annotationOf(code, clauseNo)
	oldConfirm, oldNote := "", ""
	if before != nil && before.ConfirmedBy != "" {
		oldConfirm = before.ConfirmedBy
		if before.ConfirmedAt != nil {
			oldConfirm += " @ " + before.ConfirmedAt.UTC().Format(time.RFC3339)
		}
	}
	if before != nil {
		oldNote = before.ConfirmationNote
	}
	now := time.Now().UTC()
	if err := h.groups.ConfirmClause(code, clauseNo, username, req.Note, now); err != nil {
		respondPolicyGroupError(c, err, apierror.CodeInternalPolicyGroupWrite)
		return
	}
	// 說明的舊值→新值一併入列：再次確認會覆蓋上一句說明，只記操作者與時間的話，
	// 「上次是憑什麼確認的」在覆蓋之後就沒有任何地方答得出來
	h.writeAudit(c, model.ActionUpdate, code, clauseNo, "clause_confirm",
		[]policyChangeDetail{
			{
				Field: "confirmation",
				Old:   oldConfirm,
				New:   username + " @ " + now.Format(time.RFC3339),
			},
			{Field: "confirmation_note", Old: oldNote, New: req.Note},
		})
	c.JSON(http.StatusOK, gin.H{"data": h.annotationOf(code, clauseNo)})
}

// ---- 讀取助手 ----

// annotationOf 取一條條文的機構備註；讀不到回 nil（備註是選配的）。
func (h *PolicyGroupHandler) annotationOf(code, clauseNo string) *model.PolicyClauseAnnotation {
	annotations, err := h.groups.ListAnnotations(code)
	if err != nil {
		return nil
	}
	for i := range annotations {
		if annotations[i].ClauseNo == clauseNo {
			return &annotations[i]
		}
	}
	return nil
}

// singleClauseView 取單一條文的卡片。
func (h *PolicyGroupHandler) singleClauseView(code, clauseNo string) (*clauseView, error) {
	clauses, controls, annotations, err := h.readGroupContent(code)
	if err != nil {
		return nil, err
	}
	for _, view := range buildClauseViews(clauses, controls, annotations) {
		if view.ClauseNo == clauseNo {
			v := view
			return &v, nil
		}
	}
	return nil, nil
}

// clauseDigest 既有條文的可讀摘要；不存在時回空字串（＝新增）。
func (h *PolicyGroupHandler) clauseDigest(code, clauseNo string) (string, error) {
	clauses, err := h.groups.ListClauses(code)
	if err != nil {
		return "", err
	}
	var found *model.PolicyClause
	for i := range clauses {
		if clauses[i].ClauseNo == clauseNo {
			found = &clauses[i]
			break
		}
	}
	if found == nil {
		return "", nil
	}
	controls, err := h.groups.ListControls(code)
	if err != nil {
		return "", err
	}
	mine := make([]model.PolicyClauseControl, 0, len(controls))
	for _, ctrl := range controls {
		if ctrl.ClauseNo == clauseNo {
			mine = append(mine, ctrl)
		}
	}
	return formatClauseDigest(*found, mine), nil
}

// formatClauseDigest 條文的可讀摘要，供審計列答出「從什麼改成什麼」。
//
// 用摘要而不是整份 JSON：審計列的變更詳情要讓人在列表上一眼看得出差別，
// 而條文的實質內容就是標題、摘要、型別與那幾條要求。
//
// **摘要與參考值標記都在內**：只改摘要會改變條文對機構的意思，把固定要求改成
// 參考值更會把一個偏離的結果變成待人工確認——兩者若不進摘要，審計列的舊值與
// 新值會逐字相同，而稽核人員看到的是一次沒有內容的變更。
func formatClauseDigest(clause model.PolicyClause,
	controls []model.PolicyClauseControl) string {

	parts := make([]string, 0, len(controls))
	for _, ctrl := range controls {
		expected := ctrl.ExpectedValue
		if expected == "" {
			expected = "-"
		}
		mark := ""
		if ctrl.ReferenceOnly {
			mark = " reference"
		}
		parts = append(parts,
			fmt.Sprintf("%s %s %s%s", ctrl.PolicyKey, ctrl.Comparator, expected, mark))
	}
	sort.Strings(parts)
	digest := fmt.Sprintf("%s/%s summary=%q", clause.Kind, clause.Title, clause.Summary)
	if len(parts) > 0 {
		digest += " [" + strings.Join(parts, "; ") + "]"
	}
	return digest
}

// ---- 審計 ----

// policyGroupAuditDetails 審計詳情的形狀（沿既有 changes[] 慣例，另帶對照座標）。
type policyGroupAuditDetails struct {
	GroupCode string               `json:"group_code"`
	ClauseNo  string               `json:"clause_no,omitempty"`
	Op        string               `json:"op"`
	Changes   []policyChangeDetail `json:"changes"`
}

// writeAudit 政策組寫入的唯一審計出口。
//
// **一個字面量承載全部寫入**：拆成八份會讓欄位集各自演化，而稽核比對的是同一
// 組欄位。details 只帶組代號、條號、操作與舊值→新值，不含任何憑證材料。
func (h *PolicyGroupHandler) writeAudit(c *gin.Context, action model.AuditAction,
	groupCode, clauseNo, op string, changes []policyChangeDetail) {

	if h.audit == nil {
		return
	}
	userID, _ := middleware.GetCurrentUserID(c)
	username, _ := middleware.GetCurrentUsername(c)
	details, err := json.Marshal(policyGroupAuditDetails{
		GroupCode: groupCode, ClauseNo: clauseNo, Op: op, Changes: changes,
	})
	if err != nil {
		// 編碼不可能失敗（全是字串欄）。真的失敗時寧可少一份詳情也不能少一列審計
		details = nil
	}
	h.audit.Log(&audit.AuditLogEntry{
		UserID:     userID,
		Username:   username,
		Action:     action,
		Resource:   model.ResourcePolicyGroup,
		Status:     model.StatusSuccess,
		Method:     c.Request.Method,
		Path:       c.Request.URL.Path,
		ClientIP:   sourceip.Of(c),
		StatusCode: http.StatusOK,
		ErrorMsg:   fmt.Sprintf("policy_group=%s clause=%s op=%s", groupCode, clauseNo, op),
		Details:    string(details),
	})
}

// ---- 錯誤對應 ----

// policyGroupErrorMapping 資料存取層的拒絕碼 → 對外碼與狀態碼。
//
// 逐碼對應而不是一律 400：內建組唯讀是權限題（403）、代號重複是衝突（409）、
// 組不存在是找不到（404），三者的下一步各不相同
var policyGroupErrorMapping = map[string]struct {
	Status int
	Code   apierror.ErrCode
}{
	policy.ErrCodePolicyGroupBuiltinReadOnly: {http.StatusForbidden, apierror.CodePolicyGroupBuiltinReadOnly},
	policy.ErrCodePolicyGroupNotFound:        {http.StatusNotFound, apierror.CodePolicyGroupNotFound},
	policy.ErrCodePolicyGroupDuplicateCode:   {http.StatusConflict, apierror.CodePolicyGroupDuplicateCode},
	policy.ErrCodePolicyGroupCode:            {http.StatusBadRequest, apierror.CodeValidationPolicyGroupCode},
	policy.ErrCodePolicyGroupClauseNo:        {http.StatusBadRequest, apierror.CodeValidationPolicyGroupClauseNo},
	policy.ErrCodePolicyGroupClauseKind:      {http.StatusBadRequest, apierror.CodeValidationPolicyGroupClauseKind},
	policy.ErrCodePolicyGroupUnknownKey:      {http.StatusBadRequest, apierror.CodeValidationPolicyGroupUnknownKey},
	policy.ErrCodePolicyGroupKeyType:         {http.StatusBadRequest, apierror.CodeValidationPolicyGroupKeyType},
	policy.ErrCodePolicyGroupComparator:      {http.StatusBadRequest, apierror.CodeValidationPolicyGroupComparator},
	policy.ErrCodePolicyGroupExpectedValue:   {http.StatusBadRequest, apierror.CodeValidationPolicyGroupExpectedValue},
	policy.ErrCodePolicyGroupDuplicateKey:    {http.StatusBadRequest, apierror.CodeValidationPolicyGroupDuplicateKey},
	policy.ErrCodeApplyPreviewMode:           {http.StatusBadRequest, apierror.CodeValidationApplyPreviewMode},
}

// respondPolicyGroupError 把資料存取層的具名拒絕原樣出到 HTTP；
// 不具名的錯誤（資料庫故障）落 fallback 的 500 碼。
func respondPolicyGroupError(c *gin.Context, err error, fallback apierror.ErrCode) {
	var groupErr *policy.PolicyGroupError
	if errors.As(err, &groupErr) {
		if mapped, ok := policyGroupErrorMapping[groupErr.Code]; ok {
			apierror.Respond(c, mapped.Status, mapped.Code, nil)
			return
		}
	}
	apierror.RespondInternal(c, http.StatusInternalServerError, fallback, err)
}

// RegisterRoutes 註冊政策組路由。
//
// 讀取開放 auditor：稽核人員看不到對照的內容就判讀不了結果，而讀取不擴大寫入面。
// 寫入一律 admin，且**角色閘掛在中介層鏈上**而非 handler 函式體內——寫在鏈上時
// 「這條路由由誰守」才是路由 golden 觀察得到的事實
func (h *PolicyGroupHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	groups := r.Group("/policy-groups")
	groups.Use(middleware.AuthMiddleware(authService))

	read := groups.Group("")
	read.Use(middleware.RequireAnyRole(model.RoleAdmin, model.RoleAuditor))
	{
		read.GET("", h.List)
		read.GET(policyGroupCodePath, h.Get)
	}

	write := groups.Group("")
	write.Use(middleware.RequireRole(model.RoleAdmin))
	{
		write.POST("", h.Create)
		write.PUT(policyGroupCodePath, h.Rename)
		write.PUT("/:code/enabled", h.SetEnabled)
		write.DELETE(policyGroupCodePath, h.Delete)
		write.PUT("/:code/clauses/:clause_no", h.UpsertClause)
		write.DELETE("/:code/clauses/:clause_no", h.DeleteClause)
		write.PUT("/:code/clauses/:clause_no/annotation", h.UpsertAnnotation)
		write.POST("/:code/clauses/:clause_no/confirm", h.ConfirmClause)
	}
}
