package api

import (
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/gin-gonic/gin"
)

// 測試裝配的路由註冊。
//
// 生產路徑的 `RegisterRoutes` 掛的是真的 AuthMiddleware（要簽章有效的 token），
// 而這裡要驗的是**角色邊界之後**的行為，故沿既有 handler 測試的作法自行掛角色
// 中介層、以測試 header 注入身分。角色閘用的是與生產同一支中介層，
// 「admin 專屬」不是靠測試自己判斷。

func registerPolicyGroupTestRoutes(v1 *gin.RouterGroup, h *PolicyGroupHandler) {
	g := v1.Group("/policy-groups")
	read := g.Group("")
	read.Use(middleware.RequireAnyRole(model.RoleAdmin, model.RoleAuditor))
	read.GET("", h.List)
	read.GET("/:code", h.Get)

	write := g.Group("")
	write.Use(middleware.RequireRole(model.RoleAdmin))
	write.POST("", h.Create)
	write.PUT("/:code", h.Rename)
	write.PUT("/:code/enabled", h.SetEnabled)
	write.DELETE("/:code", h.Delete)
	write.PUT("/:code/clauses/:clause_no", h.UpsertClause)
	write.DELETE("/:code/clauses/:clause_no", h.DeleteClause)
	write.PUT("/:code/clauses/:clause_no/annotation", h.UpsertAnnotation)
	write.POST("/:code/clauses/:clause_no/confirm", h.ConfirmClause)
}

func registerComplianceTestRoutes(v1 *gin.RouterGroup, h *ComplianceHandler) {
	g := v1.Group("/compliance")
	g.Use(middleware.RequireAnyRole(model.RoleAdmin, model.RoleAuditor))
	g.GET("/snapshot", h.Snapshot)
}

func registerSecurityPolicyTestRoutes(v1 *gin.RouterGroup, h *SecurityPolicyHandler) {
	g := v1.Group("/security-policies")
	g.Use(middleware.RequireRole(model.RoleAdmin))
	g.GET("", h.List)
	g.GET("/defs/:key", h.Def)
	g.POST("/compliance/preview", h.CompliancePreview)
	g.POST("/apply-preview", h.ApplyPreview)
}

func registerScheduleTestRoutes(v1 *gin.RouterGroup, h *ScheduleHandler) {
	g := v1.Group("/schedules")
	g.Use(middleware.RequireRole(model.RoleAdmin))
	g.POST("/next-runs", h.NextRuns)
}
