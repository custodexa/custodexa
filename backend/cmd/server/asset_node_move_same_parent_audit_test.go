package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// TestAssetNodeMoveSameParentRequestAudit 原地搬移雖不寫節點審計，
// 請求層審計中介層仍為這次請求留一列（誰在何時送了什麼）。
func TestAssetNodeMoveSameParentRequestAudit(t *testing.T) {
	e := newTcaEnv(t, true)
	old := database.DB
	database.DB = e.db // 請求層審計中介層寫入本測試庫
	t.Cleanup(func() { database.DB = old })

	parent := e.node("same-parent-p", nil)
	child := e.node("same-parent-c", &parent)

	h := api.NewAssetGroupHandler(e.svc, nil, nil)
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(newCoverageAuditService()))
	r.Use(func(c *gin.Context) {
		p, err := authz.ResolveUserOnWithCatalogue(e.db, authz.ProductCatalogue(), e.super, authz.TokenFacts{})
		require.NoError(t, err)
		middleware.SetPrincipal(c, p)
		c.Set("userID", e.super)
		c.Set("username", "tca-super")
		c.Next()
	})
	r.PUT("/asset-groups/:id/move", h.Move)

	path := fmt.Sprintf("/asset-groups/%d/move", child)
	requestRows := func() int64 {
		var n int64
		require.NoError(t, e.db.Model(&model.AuditLog{}).
			Where("method = ? AND path = ?", http.MethodPut, path).Count(&n).Error)
		return n
	}
	nodeRows := func() int64 {
		var n int64
		require.NoError(t, e.db.Model(&model.AuditLog{}).Where("details LIKE ?", "%asset_node_move%").Count(&n).Error)
		return n
	}
	req0, node0 := requestRows(), nodeRows()

	body, _ := json.Marshal(map[string]any{"parent_id": parent})
	req := httptest.NewRequest(http.MethodPut, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, req0+1, requestRows(), "原地搬移的請求層審計列應增加一列")
	require.Equal(t, node0, nodeRows(), "原地搬移不得寫 asset_node_move 節點審計")
}
