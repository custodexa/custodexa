package authz

import (
	"context"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/testgate"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"sync"
	"testing"
	"time"
)

func TestAgentVisibilityExposureDisclosureAndClassification(t *testing.T) {
	_, _, db, agent := setupItemRequestEnv(t)
	svc := NewAssetAuthorizationService(db)
	if err := svc.RecordAgentVisibilityExposures(context.Background(), 1, []uint{1}); err != nil {
		t.Fatal(err)
	}
	var n int64
	db.Model(&model.AgentVisibilityExposure{}).Count(&n)
	if n != 0 {
		t.Fatal("human exposure", n)
	}
	if err := svc.RecordAgentVisibilityExposures(context.Background(), agent, []uint{1, 1}); err != nil {
		t.Fatal(err)
	}
	var first, second model.AgentVisibilityExposure
	if err := db.First(&first).Error; err != nil {
		t.Fatal(err)
	}
	if err := svc.RecordAgentVisibilityExposures(context.Background(), agent, []uint{1}); err != nil {
		t.Fatal(err)
	}
	db.First(&second)
	db.Model(&model.AgentVisibilityExposure{}).Count(&n)
	if n != 1 || !first.FirstSeenAt.Equal(second.FirstSeenAt) || second.LastSeenAt.Before(first.LastSeenAt) {
		t.Fatal(first, second, n)
	}
	// Existing but inactive targets are not retired: deletion, not active, is the boundary.
	db.Model(&model.Asset{}).Where("id=2").Update("active", false)
	for _, tc := range []struct {
		user, asset uint
		want        string
	}{{agent, 1, model.ProbeRevoked}, {agent, 2, model.ProbeNeverVisible}, {1, 1, model.ProbeNeverVisible}, {agent, 999, model.ProbeRetired}} {
		got, err := ClassifyAgentProbe(db, tc.user, tc.asset)
		if err != nil || got != tc.want {
			t.Fatal(tc, got, err)
		}
	}
	if err := db.Session(&gorm.Session{SkipHooks: true}).Model(&model.Asset{}).Where("id=1").Update("deleted_at", time.Now()).Error; err != nil {
		t.Fatal(err)
	}
	if got, err := ClassifyAgentProbe(db, agent, 1); err != nil || got != model.ProbeRetired {
		t.Fatal(got, err)
	}
	if err := db.Transaction(func(tx *gorm.DB) error {
		if err := recordAgentVisibilityExposures(tx, agent, []uint{2}); err != nil {
			return err
		}
		return errors.New("rollback")
	}); err == nil {
		t.Fatal("expected rollback")
	}
	if got, err := ClassifyAgentProbe(db, agent, 2); err != nil || got != model.ProbeNeverVisible {
		t.Fatal(got, err)
	}
}

func TestAgentVisibilityExposureItemApproval(t *testing.T) {
	s, _, db, agent := setupItemRequestEnv(t)
	req, err := s.Submit(agent, "agent", model.RoleUser, itemInput(1))
	if err != nil {
		t.Fatal(err)
	}
	var n int64
	db.Model(&model.AgentVisibilityExposure{}).Count(&n)
	if n != 0 {
		t.Fatal("pending disclosure", n)
	}
	if _, err := s.Approve(2, true, req.ID, DecideInput{ItemID: req.Items[0].ID}); err != nil {
		t.Fatal(err)
	}
	if got, err := ClassifyAgentProbe(db, agent, 1); err != nil || got != model.ProbeRevoked {
		t.Fatal(got, err)
	}
	if _, err := s.Submit(agent, "agent", model.RoleUser, itemInput(3)); err != nil {
		t.Fatal(err)
	}
	if got, err := ClassifyAgentProbe(db, agent, 3); err != nil || got != model.ProbeRevoked {
		t.Fatal("automatic approval", got, err)
	}
	// Human item approval must not add disclosures.
	human, err := s.Submit(1, "human", model.RoleUser, itemInput(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(2, true, human.ID, DecideInput{ItemID: human.Items[0].ID}); err != nil {
		t.Fatal(err)
	}
	db.Model(&model.AgentVisibilityExposure{}).Where("user_id=1").Count(&n)
	if n != 0 {
		t.Fatal("human approval", n)
	}
}

func TestAgentVisibilityExposureApprovalRollback(t *testing.T) {
	s, db, req, _ := twoPendingItems(t)
	if err := db.Migrator().DropTable(&model.AgentVisibilityExposure{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(2, true, req.ID, DecideInput{ItemID: req.Items[0].ID}); err == nil {
		t.Fatal("approval without exposure committed")
	}
	var item model.AccessRequestItem
	db.First(&item, req.Items[0].ID)
	if item.Status != model.AccessRequestPending || item.AuthorizationID != nil {
		t.Fatal(item)
	}
	var n int64
	db.Model(&model.AssetAuthorization{}).Where("source=?", model.AuthorizationSourceTicket).Count(&n)
	if n != 0 {
		t.Fatal("orphan approval grant", n)
	}
}

func TestAgentVisibilityExposuresConcurrentPostgres(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	sql, _ := db.DB()
	t.Cleanup(func() { sql.Close() })
	schema := fmt.Sprintf("w32_exposure_upsert_%d", time.Now().UnixNano())
	if err := db.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Exec("DROP SCHEMA " + schema + " CASCADE") })
	scoped, err := gorm.Open(postgres.Open(dsn+" search_path="+schema), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	pool, _ := scoped.DB()
	t.Cleanup(func() { pool.Close() })
	if err := scoped.AutoMigrate(&model.User{}, &model.AgentVisibilityExposure{}); err != nil {
		t.Fatal(err)
	}
	if err := scoped.Create(&model.User{ID: 1, Username: "agent", Kind: model.KindAgent}).Error; err != nil {
		t.Fatal(err)
	}
	svc := NewAssetAuthorizationService(scoped)
	errs := make(chan error, 16)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- svc.RecordAgentVisibilityExposures(context.Background(), 1, []uint{20, 20})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var rows []model.AgentVisibilityExposure
	if err := scoped.Find(&rows).Error; err != nil || len(rows) != 1 || rows[0].FirstSeenAt.After(rows[0].LastSeenAt) {
		t.Fatal(rows, err)
	}
	t.Log("16 concurrent upserts: one exposure; first/last timestamps ordered")
}
