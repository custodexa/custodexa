package sshproxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/csvsafe"
	"github.com/custodexa/backend/internal/dbconsole"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/sourceip"
)

// 匯出被拒的真實原因。**只進審計**——對外六態一律收斂為同一則 404，
// 因為它們每一個都具「找不到這個結果」的形狀，分述即開出會話存在性的探測面
const (
	consoleDenyIdentifierInvalid = "identifier_invalid"
	consoleDenySessionNotFound   = "session_not_found"
	consoleDenyNotOwner          = "not_owner"
	consoleDenySessionNotActive  = "session_not_active"
	consoleDenyEventNotCurrent   = "event_not_current"
	consoleDenySetOutOfRange     = "set_out_of_range"
)

// 串流中止的原因（受控值域，無 driver 原文）
const (
	consoleAbortClientOrEncode = "write_error"
)

// HandleDBConsoleExport 結果匯出
// （`GET /api/v1/db-console/sessions/:id/results/:event_id/export`）。
//
// 判定序列：身分 → 六態存在性 → 傳輸政策 → 串流。
// **政策判定放在身分之後**：對本人的政策拒絕回 403 是有資訊的（他該去找管理者），
// 而對非本人回同一則 403 就等於確認了「這個結果存在」
func (h *Handler) HandleDBConsoleExport(c *gin.Context) {
	userID, ok := middleware.GetCurrentUserID(c)
	if !ok {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return
	}

	req, reason := h.resolveExportTarget(c, userID)
	if reason != "" {
		h.auditConsoleExport(c, userID, req.assetID, model.StatusDenied, http.StatusNotFound,
			map[string]any{"kind": consoleKindResultExport, "reason": reason})
		h.writeConsoleResultNotFound(c)
		return
	}

	if !h.consoleExportAllowed(c, userID, req.assetID) {
		h.auditConsoleExport(c, userID, req.assetID, model.StatusDenied, http.StatusForbidden,
			map[string]any{"kind": consoleKindResultExport, "reason": "global_policy",
				"event_id": req.eventID, "set_index": req.setIndex})
		apierror.Respond(c, http.StatusForbidden, apierror.CodeTransferDenied, map[string]any{
			"action": policy.TransferActionFileDownload,
			"reason": "global_policy",
		})
		return
	}

	h.streamConsoleCSV(c, userID, req)
}

// consoleExportRequest 一次匯出所指的結果
type consoleExportRequest struct {
	sessionID uint
	assetID   uint
	eventID   string
	setIndex  int
	seq       int
	assetName string
	set       dbconsole.ResultSet
}

// resolveExportTarget 六態判定。回傳非空的 reason 即不成立——
// **回應對六者逐位元組相同**，差異只寫進審計
func (h *Handler) resolveExportTarget(c *gin.Context, userID uint) (consoleExportRequest, string) {
	var req consoleExportRequest

	sessionID64, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil || sessionID64 == 0 {
		return req, consoleDenyIdentifierInvalid
	}
	req.sessionID = uint(sessionID64)

	req.eventID = c.Param("event_id")
	if !isConsoleEventID(req.eventID) {
		return req, consoleDenyIdentifierInvalid
	}
	setIndex := 0
	if raw := c.Query("set"); raw != "" {
		n, cerr := strconv.Atoi(raw)
		if cerr != nil || n < 0 {
			return req, consoleDenyIdentifierInvalid
		}
		setIndex = n
	}
	req.setIndex = setIndex
	if format := c.Query("format"); format != "" && format != "csv" {
		return req, consoleDenyIdentifierInvalid
	}

	sess, err := h.SessionService.GetByID(req.sessionID)
	if err != nil || sess == nil {
		return req, consoleDenySessionNotFound
	}
	if sess.AssetID != nil {
		req.assetID = *sess.AssetID
	}
	if sess.UserID != userID {
		return req, consoleDenyNotOwner
	}
	if sess.Status != model.SessionStatusActive {
		return req, consoleDenySessionNotActive
	}

	live, ok := h.consoleSessionsRef().Load(req.sessionID)
	if !ok {
		return req, consoleDenySessionNotActive
	}
	cs, ok := live.(*consoleSession)
	if !ok {
		return req, consoleDenySessionNotActive
	}
	unit, ok := cs.cache.get(req.eventID)
	if !ok {
		return req, consoleDenyEventNotCurrent
	}
	if setIndex >= len(unit.Sets) {
		return req, consoleDenySetOutOfRange
	}
	req.set = unit.Sets[setIndex]
	req.seq = unit.Seq
	req.assetName = h.consoleAssetName(req.assetID)
	return req, ""
}

// isConsoleEventID 事件識別的形狀檢查（26 字元 Crockford base32）。
// 形狀不對就不必去查快取——那是一個畸形請求，不是一次查不到
func isConsoleEventID(s string) bool {
	if len(s) != 26 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'A' && r <= 'Z' && r != 'I' && r != 'L' && r != 'O' && r != 'U':
		default:
			return false
		}
	}
	return true
}

func (h *Handler) consoleAssetName(assetID uint) string {
	if assetID == 0 || h.AssetService == nil {
		return "result"
	}
	assetRow, err := h.AssetService.GetByID(assetID)
	if err != nil || assetRow == nil {
		return "result"
	}
	return assetRow.Name
}

// writeConsoleResultNotFound 六態共用的唯一回應。
// 任何一態多帶一個欄位，收斂就破了
func (h *Handler) writeConsoleResultNotFound(c *gin.Context) {
	apierror.Respond(c, http.StatusNotFound, apierror.CodeDBConsoleResultNotFound, nil)
}

// consoleExportAllowed 傳輸政策的第四個強制點（fail-close）
func (h *Handler) consoleExportAllowed(c *gin.Context, userID, assetID uint) bool {
	if h.DataTransfer == nil {
		return true
	}
	allowed, err := h.DataTransfer.AllowsAction(c.Request.Context(), userID, assetID,
		policy.TransferChannelWeb, policy.TransferActionFileDownload)
	if err != nil {
		log.Printf("[DBConsole] 傳輸能力解析失敗（fail-close 拒絕）: userID=%d assetID=%d err=%v",
			userID, assetID, err)
		return false
	}
	return allowed
}

// streamConsoleCSV 串流輸出並於同一次寫入算出摘要。
//
// **匯出的是快取裡的結果，不重新執行語句**：重跑會讓非冪等語句生效兩次，
// 而且在審計上那是一次新的執行。因此匯出內容＝畫面所見（受上限截斷）
func (h *Handler) streamConsoleCSV(c *gin.Context, userID uint, req consoleExportRequest) {
	filename := consoleExportFilename(req.assetName, req.seq, time.Now().UTC())
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, filename))
	// UTF-8 無 BOM：BOM 會讓非試算表的消費端多讀到三個位元組
	c.Header("Content-Type", "text/csv; charset=utf-8")

	counter := &consoleCountingWriter{w: c.Writer, hash: sha256.New()}
	// 預設形態（無 BOM、LF）：與此端點原本的輸出逐位元組相同；
	// BOM 留給以試算表為讀者的匯出開啟
	writer, werr := csvsafe.NewWriter(counter, csvsafe.Options{})
	if werr != nil {
		log.Printf("[DBConsole] CSV 寫入器建立失敗: %v", werr)
		return
	}

	err := writeConsoleCSV(writer, req.set)
	writer.Flush()
	if err == nil {
		err = writer.Error()
	}
	if err != nil {
		// 中止的痕跡與成功的痕跡一樣重要：它記的是**我方寫進 socket 的**
		// 位元組與其摘要，不是客戶端實收的量
		log.Printf("[DBConsole] 結果匯出串流中斷: eventID=%s err=%v", req.eventID, err)
		h.auditConsoleExport(c, userID, req.assetID, model.StatusFailure, http.StatusOK,
			map[string]any{
				"kind": consoleKindResultExport, "event_id": req.eventID,
				"set_index": req.setIndex, "bytes_sent": counter.n,
				"sha256_sent": counter.sum(), "reason": consoleAbortClientOrEncode,
			})
		return
	}

	h.auditConsoleExport(c, userID, req.assetID, model.StatusSuccess, http.StatusOK,
		map[string]any{
			"kind": consoleKindResultExport, "session_id": req.sessionID, "seq": req.seq,
			"event_id": req.eventID, "set_index": req.setIndex,
			"rows": req.set.RowCount, "size": counter.n, "sha256": counter.sum(),
			"filename": filename,
		})
}

// writeConsoleCSV RFC 4180 形態：首列欄名，NULL 為空欄，二進位佔位原樣
func writeConsoleCSV(w *csvsafe.Writer, set dbconsole.ResultSet) error {
	header := make([]string, len(set.Columns))
	for i, col := range set.Columns {
		header[i] = consoleCSVCell(col.Name)
	}
	if err := w.Write(header); err != nil {
		return err
	}
	row := make([]string, len(set.Columns))
	for _, values := range set.Rows {
		for i := range row {
			row[i] = ""
			if i < len(values) && values[i] != nil {
				row[i] = consoleCSVCell(*values[i])
			}
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return nil
}

// consoleCSVCell 防公式注入：規則與轉義的豁免由共用的 CSV 寫入層定義
// （internal/csvsafe），本處只是取用點——同一條規則散在各匯出點即會漂移
func consoleCSVCell(v string) string {
	return csvsafe.Cell(v)
}

// consoleExportFilename 檔名以資產名、單位序號與 UTC 時戳組成。
// 資產名可能含路徑分隔符或引號，逐字元過濾成安全集合
func consoleExportFilename(assetName string, seq int, at time.Time) string {
	safe := make([]rune, 0, len(assetName))
	for _, r := range assetName {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			safe = append(safe, r)
		default:
			safe = append(safe, '_')
		}
	}
	name := strings.Trim(string(safe), "_")
	if name == "" {
		name = "result"
	}
	return fmt.Sprintf("%s-%d-%s.csv", name, seq, at.Format("20060102T150405Z"))
}

// consoleCountingWriter 邊寫邊計數與算摘要（零額外 IO）
type consoleCountingWriter struct {
	w    io.Writer
	hash hash.Hash
	n    int64
}

func (c *consoleCountingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if n > 0 {
		c.n += int64(n)
		_, _ = c.hash.Write(p[:n])
	}
	return n, err
}

func (c *consoleCountingWriter) sum() string {
	return hex.EncodeToString(c.hash.Sum(nil))
}

// auditConsoleExport 匯出成敗與中止的留痕（action=file_download、resource=file）
func (h *Handler) auditConsoleExport(c *gin.Context, userID, assetID uint,
	status model.AuditStatus, statusCode int, body map[string]any) {
	if h.AuditService == nil {
		log.Printf("[DBConsole] 審計服務未注入，匯出事件未留痕（status=%s）", status)
		return
	}
	raw, err := json.Marshal(body)
	if err != nil {
		raw = []byte(`{}`)
	}
	username, _ := middleware.GetCurrentUsername(c)
	// 資產主體鍵直接進字面量：資產樞紐只讀 asset_id，這一欄的處置必須看得見。
	// 資產未知時寫 NULL 而非 0——0 會被讀成「編號 0 的資產」
	var assetRef *uint
	if assetID != 0 {
		aid := assetID
		assetRef = &aid
	}
	entry := &audit.AuditLogEntry{
		UserID:      userID,
		Username:    username,
		Action:      model.ActionFileDownload,
		Resource:    model.ResourceFile,
		AssetID:     assetRef,
		Status:      status,
		Method:      c.Request.Method,
		Path:        c.FullPath(),
		ClientIP:    sourceip.Of(c),
		StatusCode:  statusCode,
		RequestID:   c.GetString("request_id"),
		RequestBody: string(raw),
	}
	if assetRef != nil {
		entry.ResourceID = assetRef
	}
	h.AuditService.Log(entry)
}
