package asset

// 資產批次新增的逐列驗證（預檢與寫入共用同一個 validateImportBatch）。
// 必填、格式、適用性、節點、憑證逐欄檢查、不短路；同批重名與標籤歸一以整批為單位；
// 最後每列交給單筆建立的 prepareCreate 再走一次，匯入不另立建立規則。

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// importLookups 整批驗證共用的一次性查詢結果
type importLookups struct {
	existingNames map[string]bool
	tagSpelling   map[string]string // canonical → 全庫既有寫法
	nodePaths     map[uint]string   // 節點 id → 全路徑
	pathToIDs     map[string][]uint // 全路徑 → 節點 id（不唯一時多筆）
	credentials   map[uint]*model.Credential
}

func (s *AssetService) loadImportLookups(db *gorm.DB, rows []ImportRow) (*importLookups, error) {
	lk := &importLookups{existingNames: map[string]bool{}, tagSpelling: map[string]string{},
		credentials: map[uint]*model.Credential{}}

	names := make([]string, 0, len(rows))
	credIDs := make([]uint, 0, len(rows))
	for i := range rows {
		if rows[i].Name != "" {
			names = append(names, rows[i].Name)
		}
		if rows[i].CredentialID != nil && *rows[i].CredentialID > 0 && *rows[i].CredentialID <= int64(^uint32(0)) {
			credIDs = append(credIDs, uint(*rows[i].CredentialID))
		}
	}
	if len(names) > 0 {
		var existing []string
		if err := db.Model(&model.Asset{}).Where("name IN ?", names).Pluck("name", &existing).Error; err != nil {
			return nil, fmt.Errorf("查詢既有資產名稱失敗: %w", err)
		}
		for _, n := range existing {
			lk.existingNames[n] = true
		}
	}
	tags, err := s.ListTags()
	if err != nil {
		return nil, err
	}
	for _, tc := range tags {
		lk.tagSpelling[canonicalTag(tc.Name)] = tc.Name
	}
	if lk.nodePaths, err = NodePathMap(db); err != nil {
		return nil, err
	}
	lk.pathToIDs = make(map[string][]uint, len(lk.nodePaths))
	for id, p := range lk.nodePaths {
		lk.pathToIDs[p] = append(lk.pathToIDs[p], id)
	}
	if len(credIDs) > 0 {
		var creds []model.Credential
		if err := db.Where("id IN ?", credIDs).Find(&creds).Error; err != nil {
			return nil, fmt.Errorf("查詢憑證失敗: %w", err)
		}
		for i := range creds {
			lk.credentials[creds[i].ID] = &creds[i]
		}
	}
	return lk, nil
}

// normalizeImportRow 去前後空白、協定轉小寫、節點路徑去空。不改動其餘值
func normalizeImportRow(r ImportRow) ImportRow {
	r.Name = strings.TrimSpace(r.Name)
	r.Protocol = strings.ToLower(strings.TrimSpace(r.Protocol))
	r.Host = strings.TrimSpace(r.Host)
	r.Tags = strings.TrimSpace(r.Tags)
	r.Description = strings.TrimSpace(r.Description)
	r.AccessPolicy = strings.TrimSpace(r.AccessPolicy)
	r.DBName = strings.TrimSpace(r.DBName)
	r.K8sNamespace = strings.TrimSpace(r.K8sNamespace)
	r.RDPSecurity = strings.TrimSpace(r.RDPSecurity)
	r.DBTLSMode = strings.TrimSpace(r.DBTLSMode)
	if len(r.NodePaths) > 0 {
		paths := make([]string, 0, len(r.NodePaths))
		for _, p := range r.NodePaths {
			if p = strings.TrimSpace(p); p != "" {
				paths = append(paths, p)
			}
		}
		r.NodePaths = paths
	}
	return r
}

// hasControlChar 是否含控制字元（U+0000–U+001F、U+007F 等）
func hasControlChar(v string) bool {
	for _, r := range v {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// displayLine 列在畫面上的列號：CSV 為檔案列號，線上填寫為陣列序（自 1 起）
func displayLine(r ImportRow, index int) int {
	if r.Line != nil {
		return *r.Line
	}
	return index + 1
}

// validateImportBatch 逐列完整驗證（預檢與寫入共用）。回傳逐列報告，以及每一列
// 通過時的寫入準備（未通過的列為 nil）。非驗證性錯誤（查詢失敗）以 error 回傳
func (s *AssetService) validateImportBatch(ctx context.Context, batch *ImportBatch,
	createdBy uint, createdByName string) (*ImportPreview, []*preparedAsset, error) {

	rows := make([]ImportRow, len(batch.Rows))
	for i := range batch.Rows {
		rows[i] = normalizeImportRow(batch.Rows[i])
	}
	lk, err := s.loadImportLookups(database.DB, rows)
	if err != nil {
		return nil, nil, err
	}

	reports := make([]ImportRowReport, len(rows))
	nodeIDs := make([][]uint, len(rows))
	for i := range rows {
		rep := &reports[i]
		rep.Index = i
		rep.Line = rows[i].Line
		rep.Errors = []ImportFieldError{}
		if i < len(batch.parseErrs) {
			rep.Errors = append(rep.Errors, batch.parseErrs[i]...)
		}
		if i < len(batch.raw) && len(batch.raw[i]) > 0 {
			rep.Raw = batch.raw[i]
		}
		nodeIDs[i] = validateImportRowFields(&rows[i], rep, lk)
		rep.Values = rows[i]
		rep.Values.NodeIDs = nodeIDs[i]
	}

	markBatchDuplicateNames(rows, reports, lk)
	normalizeBatchTags(rows, reports, lk)

	prepared := make([]*preparedAsset, len(rows))
	for i := range rows {
		if len(reports[i].Errors) > 0 {
			continue
		}
		req := importCreateRequest(rows[i], nodeIDs[i], reports[i].Resolved.Tags, createdBy, createdByName)
		// 單筆建立的同一套規則最後再走一次：匯入不另立建立規則
		p, perr := s.prepareCreate(ctx, req, prepareOptions{skipNameCheck: true, tagsNormalized: true})
		if perr != nil {
			fe, ok := importFieldErrorFor(perr)
			if !ok {
				return nil, nil, perr
			}
			reports[i].Errors = append(reports[i].Errors, fe)
			continue
		}
		prepared[i] = p
	}

	preview := &ImportPreview{Rows: reports}
	preview.Summary.Total = len(rows)
	for i := range reports {
		if len(reports[i].Errors) == 0 {
			preview.Summary.Valid++
		} else {
			preview.Summary.Invalid++
		}
		if rows[i].CredentialID == nil {
			preview.Summary.CredentialPending++
		}
	}
	preview.OK = preview.Summary.Invalid == 0
	return preview, prepared, nil
}

// validateImportRowFields 單列的欄位檢查（必填、格式、適用性、節點、憑證），
// 不短路、同列多錯全列出。回傳該列最終的節點 id 集
func validateImportRowFields(r *ImportRow, rep *ImportRowReport, lk *importLookups) []uint {
	add := func(e ImportFieldError) { rep.Errors = append(rep.Errors, e) }
	hasErr := func(field string) bool {
		for _, e := range rep.Errors {
			if e.Field == field {
				return true
			}
		}
		return false
	}

	checkText := func(field, v string, max int, required, noControl bool) {
		switch {
		case v == "":
			if required {
				add(fieldErr(field, apierror.CodeAssetImportFieldRequired))
			}
		case utf8.RuneCountInString(v) > max:
			add(fieldErrP(field, apierror.CodeAssetImportFieldTooLong, map[string]any{"max": max}))
		case noControl && hasControlChar(v):
			add(fieldErr(field, apierror.CodeAssetImportFieldFormat))
		}
	}
	checkText(importFieldName, r.Name, importMaxNameRunes, true, true)
	checkText(importFieldHost, r.Host, importMaxHostRunes, true, true)
	checkText(importFieldDescription, r.Description, importMaxDescriptionRunes, false, false)

	protocol := model.ProtocolType(r.Protocol)
	protocolOK := IsAssetProtocol(protocol)
	switch {
	case r.Protocol == "":
		add(fieldErr(importFieldProtocol, apierror.CodeAssetImportFieldRequired))
	case !protocolOK:
		add(fieldErr(importFieldProtocol, apierror.CodeInvalidProtocol))
	}
	if protocolOK && !hasErr(importFieldHost) && validateMSSQLHost(protocol, r.Host) != nil {
		add(fieldErr(importFieldHost, apierror.CodeMSSQLHostComma))
	}

	// 埠：留空＝協定預設埠
	if r.Port == nil {
		if protocolOK && !hasErr(importFieldPort) {
			p := importDefaultPorts[protocol]
			r.Port = &p
			rep.Resolved.PortDefaulted = true
		}
	} else if *r.Port < 1 || *r.Port > 65535 {
		add(fieldErr(importFieldPort, apierror.CodeAssetImportPort))
	}

	if validateAccessPolicy(r.AccessPolicy) != nil {
		add(fieldErr(importFieldAccessPolicy, apierror.CodeInvalidAccessPolicy))
	}

	// 適用性：不適用該協定卻有值即列錯誤（靜默忽略會讓使用者以為設了其實沒生效）。
	// 協定本身不合法時無從判定適用性，只驗值域
	notApplicable := func(field, v string, applies bool) bool {
		if v != "" && protocolOK && !applies {
			add(fieldErr(field, apierror.CodeAssetImportNotApplicable))
			return true
		}
		return false
	}
	if !notApplicable(importFieldDBName, r.DBName, protocol.IsDatabase()) {
		checkText(importFieldDBName, r.DBName, importMaxDBNameRunes, false, true)
	}
	if !notApplicable(importFieldK8sNamespace, r.K8sNamespace, protocol == model.ProtocolK8s) {
		if protocol == model.ProtocolK8s && r.K8sNamespace == "" {
			add(fieldErr(importFieldK8sNamespace, apierror.CodeAssetK8sNamespaceRequired))
		} else {
			checkText(importFieldK8sNamespace, r.K8sNamespace, importMaxK8sNamespaceRunes, false, true)
		}
	}
	if !notApplicable(importFieldRDPSecurity, r.RDPSecurity, protocol == model.ProtocolRDP) &&
		validateRDPSecurity(r.RDPSecurity) != nil {
		add(fieldErr(importFieldRDPSecurity, apierror.CodeInvalidRDPSecurity))
	}
	if !notApplicable(importFieldDBTLSMode, r.DBTLSMode, protocol.IsDatabase()) &&
		validateDBTLSMode(r.DBTLSMode) != nil {
		add(fieldErr(importFieldDBTLSMode, apierror.CodeInvalidDBTLSMode))
	}

	ids := validateImportNodes(r, rep, lk, add)
	validateImportCredential(r, rep, lk, protocol, protocolOK, add, hasErr(importFieldCredentialID))
	return ids
}

// validateImportNodes 節點：node_ids 須存在；node_paths 須完全比對唯一的既有節點全路徑。
// 兩者都帶時（CSV 預檢後回送）以路徑為準，且解析結果須與 node_ids 一致
func validateImportNodes(r *ImportRow, rep *ImportRowReport, lk *importLookups,
	add func(ImportFieldError)) []uint {

	ids := make([]uint, 0, len(r.NodeIDs)+len(r.NodePaths))
	seen := map[uint]bool{}
	if len(r.NodePaths) > 0 {
		for _, p := range r.NodePaths {
			matches := lk.pathToIDs[p]
			if len(matches) != 1 {
				add(fieldErrP(importFieldNodes, apierror.CodeAssetImportNodePath, map[string]any{"path": p}))
				continue
			}
			if !seen[matches[0]] {
				seen[matches[0]] = true
				ids = append(ids, matches[0])
			}
		}
		if len(r.NodeIDs) > 0 && len(ids) == len(r.NodePaths) && !uintSetEqual(dedupe(r.NodeIDs), ids) {
			add(fieldErrP(importFieldNodes, apierror.CodeAssetImportNodePath,
				map[string]any{"path": strings.Join(r.NodePaths, ";")}))
		}
	} else {
		for _, id := range r.NodeIDs {
			if _, ok := lk.nodePaths[id]; !ok {
				add(fieldErr(importFieldNodes, apierror.CodeAssetNodeNotFound))
				break
			}
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	rep.Resolved.NodePaths = make([]string, 0, len(ids))
	for _, id := range ids {
		rep.Resolved.NodePaths = append(rep.Resolved.NodePaths, lk.nodePaths[id])
	}
	return ids
}

func dedupe(ids []uint) []uint {
	out := make([]uint, 0, len(ids))
	seen := map[uint]bool{}
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// validateImportCredential 憑證：存在、共用、協定族相容、未在改密、上一輪已收斂。
// 各條件獨立回報；憑證存在即回顯名稱與帳號名
func validateImportCredential(r *ImportRow, rep *ImportRowReport, lk *importLookups,
	protocol model.ProtocolType, protocolOK bool, add func(ImportFieldError), parseFailed bool) {

	if r.CredentialID == nil || parseFailed {
		return
	}
	if *r.CredentialID <= 0 || *r.CredentialID > int64(^uint32(0)) {
		add(fieldErr(importFieldCredentialID, apierror.CodeAssetImportFieldFormat))
		return
	}
	cred := lk.credentials[uint(*r.CredentialID)]
	if cred == nil {
		add(fieldErr(importFieldCredentialID, apierror.CodeCredentialNotFound))
		return
	}
	ref := &ImportCredentialRef{ID: cred.ID, Username: cred.Username}
	if cred.Name != nil {
		ref.Name = *cred.Name
	}
	rep.Resolved.Credential = ref
	if cred.Scope != model.CredentialScopeShared {
		add(fieldErr(importFieldCredentialID, apierror.CodeCredentialDedicatedSingle))
	}
	if protocolOK && assertProtocolFamilyMatch(cred, &model.Asset{Protocol: protocol}) != nil {
		add(fieldErr(importFieldCredentialID, apierror.CodeCredentialProtocolMismatch))
	}
	if assertNoActiveRotation(cred) != nil {
		add(fieldErr(importFieldCredentialID, apierror.CodeCredentialRotationActive))
	}
	if assertCredentialConverged(nil, cred) != nil {
		add(fieldErr(importFieldCredentialID, apierror.CodeCredentialOutOfSync))
	}
}

// markBatchDuplicateNames 同批重名：兩列都標並指向對方列號；與既有資產重名另標
func markBatchDuplicateNames(rows []ImportRow, reports []ImportRowReport, lk *importLookups) {
	byName := map[string][]int{}
	for i := range rows {
		if rows[i].Name != "" {
			byName[rows[i].Name] = append(byName[rows[i].Name], i)
		}
	}
	for i := range rows {
		if rows[i].Name != "" && lk.existingNames[rows[i].Name] {
			reports[i].Errors = append(reports[i].Errors, fieldErr(importFieldName, apierror.CodeAssetNameExists))
		}
		group := byName[rows[i].Name]
		if len(group) < 2 {
			continue
		}
		other := group[0]
		if other == i {
			other = group[1]
		}
		reports[i].Errors = append(reports[i].Errors, fieldErrP(importFieldName,
			apierror.CodeAssetImportNameInBatch, map[string]any{"other_line": displayLine(rows[other], other)}))
	}
}

// normalizeBatchTags 標籤：先對全庫既有寫法歸一，再對同批歸一（同批新標籤以第一次
// 出現的寫法為準），最後套上限。結果即實際落庫的寫法
func normalizeBatchTags(rows []ImportRow, reports []ImportRowReport, lk *importLookups) {
	batchSpelling := map[string]string{}
	for i := range rows {
		tags := normalizeTagList(rows[i].Tags)
		for j, tag := range tags {
			key := canonicalTag(tag)
			if known, ok := lk.tagSpelling[key]; ok {
				tags[j] = known
				continue
			}
			if first, ok := batchSpelling[key]; ok {
				tags[j] = first
				continue
			}
			batchSpelling[key] = tag
		}
		if err := validateTagList(tags); err != nil {
			if fe, ok := importFieldErrorFor(err); ok {
				reports[i].Errors = append(reports[i].Errors, fe)
			}
		}
		reports[i].Resolved.Tags = strings.Join(tags, ",")
	}
}

// importCreateRequest 列 → 單筆建立請求（帳號名與秘密一律為空：登入身分只來自共用憑證）
func importCreateRequest(r ImportRow, nodeIDs []uint, tags string, createdBy uint, createdByName string) *CreateAssetRequest {
	req := &CreateAssetRequest{
		Name:          r.Name,
		Protocol:      model.ProtocolType(r.Protocol),
		Host:          r.Host,
		Description:   r.Description,
		Tags:          tags,
		NodeIDs:       nodeIDs,
		AccessPolicy:  r.AccessPolicy,
		RDPSecurity:   r.RDPSecurity,
		DBName:        r.DBName,
		DBTLSMode:     r.DBTLSMode,
		K8sNamespace:  r.K8sNamespace,
		CreatedBy:     createdBy,
		CreatedByName: createdByName,
	}
	if r.Port != nil {
		req.Port = *r.Port
	}
	if r.CredentialID != nil && *r.CredentialID > 0 {
		req.CredentialID = uint(*r.CredentialID)
	}
	return req
}

// importFieldErrorFor 建立規則的 sentinel → 列錯誤（欄位＋碼）。
// 第二回傳值 false＝不是可歸到某一欄的驗證錯誤（查詢失敗等），由呼叫端以內部錯誤處理
func importFieldErrorFor(err error) (ImportFieldError, bool) {
	if code, ok := tagValidationCodeOf(err); ok {
		return fieldErr(importFieldTags, code), true
	}
	table := []struct {
		target error
		field  string
		code   apierror.ErrCode
	}{
		{ErrAssetNameExists, importFieldName, apierror.CodeAssetNameExists},
		{ErrInvalidProtocol, importFieldProtocol, apierror.CodeInvalidProtocol},
		{ErrMSSQLHostComma, importFieldHost, apierror.CodeMSSQLHostComma},
		{ErrInvalidAccessPolicy, importFieldAccessPolicy, apierror.CodeInvalidAccessPolicy},
		{ErrInvalidRDPSecurity, importFieldRDPSecurity, apierror.CodeInvalidRDPSecurity},
		{ErrInvalidDBTLSMode, importFieldDBTLSMode, apierror.CodeInvalidDBTLSMode},
		{ErrK8sTargetRequired, importFieldK8sNamespace, apierror.CodeAssetK8sNamespaceRequired},
		{ErrUsernameRequired, importFieldCredentialID, apierror.CodeAssetUsernameRequired},
		{ErrNodeNotFound, importFieldNodes, apierror.CodeAssetNodeNotFound},
		{ErrCredentialNotFound, importFieldCredentialID, apierror.CodeCredentialNotFound},
		{ErrCredentialDedicatedSingleBinding, importFieldCredentialID, apierror.CodeCredentialDedicatedSingle},
		{ErrCredentialProtocolMismatch, importFieldCredentialID, apierror.CodeCredentialProtocolMismatch},
		{ErrCredentialRotationActive, importFieldCredentialID, apierror.CodeCredentialRotationActive},
		{ErrCredentialOutOfSync, importFieldCredentialID, apierror.CodeCredentialOutOfSync},
	}
	for _, t := range table {
		if errors.Is(err, t.target) {
			return fieldErr(t.field, t.code), true
		}
	}
	return ImportFieldError{}, false
}

// tagValidationCodeOf 標籤文法 sentinel → 機器碼（與 handler 的映射同一組碼）
func tagValidationCodeOf(err error) (apierror.ErrCode, bool) {
	switch {
	case errors.Is(err, ErrTagEmpty):
		return apierror.CodeTagEmpty, true
	case errors.Is(err, ErrTagContainsComma):
		return apierror.CodeTagContainsComma, true
	case errors.Is(err, ErrTagTooLong):
		return apierror.CodeTagTooLong, true
	case errors.Is(err, ErrTooManyTags):
		return apierror.CodeTooManyTags, true
	case errors.Is(err, ErrTagsTotalTooLong):
		return apierror.CodeTagsTotalTooLong, true
	}
	return "", false
}
