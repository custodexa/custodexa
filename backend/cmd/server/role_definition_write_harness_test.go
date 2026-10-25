package main

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
)

// 角色定義寫入接線的共用測試夾具：把 handler 的四個寫入方法掛在測試專用的 gin 引擎上
// （正式路由表不含寫入路由），操作者以標頭帶入，繞過登入中介層但保留 handler 讀到的 userID。

const writeHarnessUserHeader = "X-Test-User"

type roleWriteHarness struct {
	t      *testing.T
	engine *gin.Engine
}

func newRoleWriteHarness(t *testing.T, h *api.RoleDefinitionHandler) *roleWriteHarness {
	t.Helper()
	prev := gin.Mode()
	gin.SetMode(gin.TestMode)
	t.Cleanup(func() { gin.SetMode(prev) })
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if v := c.GetHeader(writeHarnessUserHeader); v != "" {
			id, err := strconv.ParseUint(v, 10, 32)
			if err == nil {
				c.Set("userID", uint(id))
			}
		}
		c.Next()
	})
	r.POST("/defs", h.Create)
	r.POST("/defs/:id/copy", h.Copy)
	r.PUT("/defs/:id", h.Update)
	r.DELETE("/defs/:id", h.Delete)
	return &roleWriteHarness{t: t, engine: r}
}

// doUnknownLength 送出本文長度未知（ContentLength=-1，如 chunked）的請求。
func (h *roleWriteHarness) doUnknownLength(actor uint, method, path, body string) (int, map[string]any, string) {
	h.t.Helper()
	req := httptest.NewRequest(method, path, io.NopCloser(strings.NewReader(body)))
	req.ContentLength = -1
	req.Header.Set(writeHarnessUserHeader, strconv.FormatUint(uint64(actor), 10))
	rec := httptest.NewRecorder()
	h.engine.ServeHTTP(rec, req)
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out, rec.Body.String()
}

// do 送出一個請求；body 以原樣字串送出，使「未列鍵」「尾端多餘內容」這類 map 表達不了的輸入可測。
func (h *roleWriteHarness) do(actor uint, method, path, body string) (int, map[string]any, string) {
	h.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(writeHarnessUserHeader, strconv.FormatUint(uint64(actor), 10))
	rec := httptest.NewRecorder()
	h.engine.ServeHTTP(rec, req)
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out, rec.Body.String()
}

// newRoleDefinitionServiceForTest 依需要缺哪個依賴建立角色定義服務（共用於各 fail-close 案例）。
func newRoleDefinitionServiceForTest(env *baselineEnv, withGrader, withEvents bool) *identity.RoleDefinitionService {
	var grader *identity.GrantGrader
	if withGrader {
		grader = identity.NewGrantGrader(audit.NewTxSink(), audit.NewSystemAlertSink(nil))
	}
	var events identity.RoleStateEventWriter
	if withEvents {
		events = identity.NewPermissionChainEventWriter()
	}
	return identity.NewRoleDefinitionService(env.db, audit.NewTxSink(), events, grader)
}
