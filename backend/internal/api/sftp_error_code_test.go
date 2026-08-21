package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/modules/session"
)

// errBoom 代表底層 ssh/sftp 庫的原文（不得外洩至回應）
var errBoom = errors.New("boom: connection reset by peer")

// TestRespondSFTPErrorCodes respondSFTPError 的分流（V2 對抗驗收 H3）。
//
// 修正前所有遠端失敗共用 INTERNAL_SFTP_OPERATION_FAILED「檔案操作失敗」：
// 按下「下載」失敗只看得到「檔案操作失敗」，比遷移前的「下載失敗」還模糊，
// 而「須為空目錄」這句唯一可行動的指引也被吞掉。現依動作分碼、指引獨立成碼。
// 狀態碼不動：路徑驗證 400、其餘 502。
func TestRespondSFTPErrorCodes(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		actionCode apierror.ErrCode
		wantStatus int
		wantCode   apierror.ErrCode
	}{
		{"路徑驗證失敗仍 400", session.ErrInvalidRemotePath,
			apierror.CodeInternalSFTPListFailed, http.StatusBadRequest, apierror.CodeSFTPInvalidPath},
		{"列目錄失敗", fmt.Errorf("讀取目錄失敗: %w", errBoom),
			apierror.CodeInternalSFTPListFailed, http.StatusBadGateway, apierror.CodeInternalSFTPListFailed},
		{"下載失敗", fmt.Errorf("開啟遠端檔案失敗: %w", errBoom),
			apierror.CodeInternalSFTPDownloadFailed, http.StatusBadGateway, apierror.CodeInternalSFTPDownloadFailed},
		{"上傳失敗", fmt.Errorf("上傳失敗: %w", errBoom),
			apierror.CodeInternalSFTPUploadFailed, http.StatusBadGateway, apierror.CodeInternalSFTPUploadFailed},
		{"建目錄失敗", fmt.Errorf("建立目錄失敗: %w", errBoom),
			apierror.CodeInternalSFTPMkdirFailed, http.StatusBadGateway, apierror.CodeInternalSFTPMkdirFailed},
		{"刪除失敗", fmt.Errorf("刪除檔案失敗: %w", errBoom),
			apierror.CodeInternalSFTPDeleteFailed, http.StatusBadGateway, apierror.CodeInternalSFTPDeleteFailed},
		// 可行動指引優先於動作碼：即使呼叫點傳的是 Delete 動作碼，
		// 「須為空目錄」也必須以自己的碼出去（否則使用者無從知道怎麼補救）
		{"目錄非空的可行動指引", fmt.Errorf("%w: %w", session.ErrRemoveDirNotEmpty, errBoom),
			apierror.CodeInternalSFTPDeleteFailed, http.StatusBadGateway, apierror.CodeSFTPDirNotEmpty},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", "/assets/1/files", nil)

			respondSFTPError(c, tc.err, tc.actionCode)

			if w.Code != tc.wantStatus {
				t.Fatalf("狀態碼 = %d，預期 %d", w.Code, tc.wantStatus)
			}
			var resp map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("回應非 JSON: %v", err)
			}
			if resp["code"] != string(tc.wantCode) {
				t.Fatalf("code = %v，預期 %s", resp["code"], tc.wantCode)
			}
			// 底層原文（ssh/sftp 庫訊息）不得外洩
			if body := w.Body.String(); strings.Contains(body, "boom") {
				t.Fatalf("回應洩漏底層錯誤原文: %s", body)
			}
		})
	}
}

// TestSFTPHandlersUseDistinctActionCodes 五個 handler 各自傳入不同的動作碼
// （H3 的重點是「錯在哪個動作」可辨；複製貼上時漏改就會退回同一碼）。
//
// 以 AST 讀 sftp_handler.go：每個 respondSFTPError 呼叫點的第三引數必須是
// apierror.Code* 選擇器，且五個呼叫點兩兩相異。
func TestSFTPHandlersUseDistinctActionCodes(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "sftp_handler.go", nil, 0)
	if err != nil {
		t.Fatalf("parse sftp_handler.go: %v", err)
	}

	byFunc := map[string]string{}
	var currentFunc string
	ast.Inspect(file, func(n ast.Node) bool {
		if fn, ok := n.(*ast.FuncDecl); ok {
			currentFunc = fn.Name.Name
			return true
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok || ident.Name != "respondSFTPError" {
			return true
		}
		if len(call.Args) != 3 {
			t.Fatalf("%s: respondSFTPError 應帶 3 個引數（含動作碼），實得 %d", currentFunc, len(call.Args))
		}
		sel, ok := call.Args[2].(*ast.SelectorExpr)
		if !ok {
			t.Fatalf("%s: 動作碼引數必須是 apierror.Code*，實得 %T", currentFunc, call.Args[2])
		}
		byFunc[currentFunc] = sel.Sel.Name
		return true
	})

	want := []string{"List", "Download", "Upload", "Mkdir", "Delete"}
	seen := map[string]string{}
	for _, fn := range want {
		code, ok := byFunc[fn]
		if !ok {
			t.Fatalf("handler %s 未經 respondSFTPError 回覆（或已改名，映射須同步）", fn)
		}
		if prev, dup := seen[code]; dup {
			t.Fatalf("handler %s 與 %s 共用動作碼 %s（動作將不可分辨）", fn, prev, code)
		}
		seen[code] = fn
	}
	if len(byFunc) != len(want) {
		t.Fatalf("respondSFTPError 呼叫點 %v 超出已知的五個動作 handler", byFunc)
	}
}
