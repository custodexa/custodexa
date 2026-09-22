package audit

import (
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// AgentTaskReportRequestIDs is an unexecuted, single-column read projection.
// The report owner constructs it; callers compose it as a server-side subquery,
// never load an unbounded list or directly name another module's table.
func AgentTaskReportRequestIDs(db *gorm.DB) *gorm.DB {
	return db.Model(&model.AgentTaskReport{}).Select("access_request_id")
}
