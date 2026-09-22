package database

import (
	"fmt"
	"github.com/custodexa/backend/internal/model"

	"github.com/custodexa/backend/internal/testgate"

	"testing"
	"time"
)

func TestAgentVisibilityExposuresPostgres(t *testing.T) {
	db := freshSchema(t, testgate.Value(t, testgate.EnvPGDSN), fmt.Sprintf("w32_exposures_%d", time.Now().UnixNano()))
	for _, m := range migrations {
		if err := m.Up(db); err != nil {
			t.Fatal(m.Version, err)
		}
	}
	now := time.Now().UTC()
	row := model.AgentVisibilityExposure{UserID: 1, AssetID: 20, FirstSeenAt: now, LastSeenAt: now}
	if err := db.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&row).Error; err == nil {
		t.Fatal("duplicate disclosure key accepted")
	}
	var rows []model.AgentVisibilityExposure
	if err := rollbackAgentVisibilityExposures(db); err == nil {
		t.Fatal("Down destroyed exposure evidence")
	}
	if err := db.Find(&rows).Error; err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	t.Log("composite key enforced; rollback retains evidence")
}
