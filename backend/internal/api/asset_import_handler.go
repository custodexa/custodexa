package api

// 資產批次新增的兩個端點：預檢（唯讀）與整批寫入。
//
// 本文自行讀取而不經 gin binding：JSON 列須 DisallowUnknownFields（夾帶秘密或帳號名欄
// 即整批拒收），CSV 是原文。兩者皆以 MaxBytesReader 限 1 MiB。審計中介層記的請求列
// 依既有遮罩規則處理本文；課責由逐台建立稽核列與本 handler 補的 import_source／
// import_count 承擔（見 auditmask 的 rawRequestBodyReaders 登記）。

import (
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/gin-gonic/gin"
)

// readImportBody 讀取請求本文（上限 1 MiB）；超限回 TOO_LARGE
func readImportBody(c *gin.Context) ([]byte, bool) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, asset.ImportMaxBytes)
	data, err := io.ReadAll(c.Request.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeAssetImportTooLarge, nil)
			return nil, false
		}
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return nil, false
	}
	return data, true
}

// respondImportError 匯入錯誤出口：檔案層 400、有列錯誤 400（附逐列報告）、
// 交易內重驗失敗 409（已整筆回滾），其餘為內部錯誤
func respondImportError(c *gin.Context, err error) {
	var fileErr *asset.ImportFileError
	var rowsErr *asset.ImportRowsInvalidError
	var stateErr *asset.ImportStateChangedError
	switch {
	case errors.As(err, &fileErr):
		apierror.Write(c, http.StatusBadRequest, apierror.ErrorResponse{
			Code: fileErr.Code, Params: fileErr.Params, Meta: fileErr.Meta})
	case errors.As(err, &rowsErr):
		apierror.Write(c, http.StatusBadRequest, apierror.ErrorResponse{
			Code: apierror.CodeAssetImportRowsInvalid,
			Meta: map[string]any{"summary": rowsErr.Preview.Summary, "rows": rowsErr.Preview.Rows}})
	case errors.As(err, &stateErr):
		apierror.Write(c, http.StatusConflict, apierror.ErrorResponse{
			Code: apierror.CodeAssetImportStateChanged,
			Meta: map[string]any{"rows": stateErr.Rows}})
	default:
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetCreate, err)
	}
}

// PreviewImport POST /assets/import/preview：接受 text/csv（原文）與 application/json
// （列陣列），回逐列檢查結果。唯讀，不寫任何資料
func (h *AssetHandler) PreviewImport(c *gin.Context) {
	data, ok := readImportBody(c)
	if !ok {
		return
	}
	var batch *asset.ImportBatch
	var err error
	switch c.ContentType() {
	case "text/csv":
		batch, err = asset.ParseImportCSV(data)
	case "application/json":
		batch, err = asset.DecodeImportJSON(data)
	default:
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	if err != nil {
		respondImportError(c, err)
		return
	}
	preview, err := h.assetService.PreviewImport(c.Request.Context(), batch)
	if err != nil {
		respondImportError(c, err)
		return
	}
	c.JSON(http.StatusOK, preview)
}

// Import POST /assets/import：只收 application/json（列陣列）。全部列通過才於單一交易
// 寫入；交易內重驗失敗整筆回滾回 409。成功 201
func (h *AssetHandler) Import(c *gin.Context) {
	if c.ContentType() != "application/json" {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	data, ok := readImportBody(c)
	if !ok {
		return
	}
	batch, err := asset.DecodeImportJSON(data)
	if err != nil {
		respondImportError(c, err)
		return
	}
	userID, exists := middleware.GetCurrentUserID(c)
	if !exists {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return
	}
	username, _ := middleware.GetCurrentUsername(c)

	result, err := h.assetService.ImportAssets(operatorRequestContext(c), batch, userID, username)
	created := 0
	if result != nil {
		created = result.Created
	}
	// 整批請求列的補充標記：來源入口與建立台數（失敗時為 0）。逐台建立列由交易內寫入
	c.Set("audit_details", map[string]string{
		"import_source": batch.Source,
		"import_count":  strconv.Itoa(created),
	})
	if err != nil {
		respondImportError(c, err)
		return
	}
	c.JSON(http.StatusCreated, result)
}
