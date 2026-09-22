package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/notifycat"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
)

var ErrAgentReportForbidden = errors.New("agent report forbidden")
var ErrAgentReportWindow = errors.New("agent report revision window closed")
var ErrAgentReportBody = errors.New("agent report body required or too long")

type AgentTaskFacts struct {
	ID, RequesterID, ExecutorID uint
	ClosedAt                    *time.Time
}
type AgentPrincipalFacts struct {
	Kind    string
	OwnerID uint
}
type AgentTaskSource func(*gorm.DB, uint) (AgentTaskFacts, error)
type AgentPrincipalSource func(*gorm.DB, uint) (AgentPrincipalFacts, error)

// OwnerEventWriter publishes through existing channels after commit, with owner_id.
type OwnerEventWriter func(uint, notifycat.Event, map[string]string)

type AgentTaskReports struct {
	db        *gorm.DB
	sink      port.TxSink
	task      AgentTaskSource
	principal AgentPrincipalSource
	notify    OwnerEventWriter
	now       func() time.Time
}

func NewAgentTaskReports(db *gorm.DB, sink port.TxSink, task AgentTaskSource, principal AgentPrincipalSource, notify OwnerEventWriter) *AgentTaskReports {
	return &AgentTaskReports{db: db, sink: sink, task: task, principal: principal, notify: notify, now: time.Now}
}
func (s *AgentTaskReports) Submit(ctx context.Context, requestID uint, actor gatewayapi.Actor, body string) (*model.AgentTaskReport, error) {
	return s.submit(ctx, requestID, actor, body, nil)
}

// SubmitAndClose stores the report and the first persisted closing instant in one
// transaction. The task owner supplies the closure writer; no reverse module dependency.
func (s *AgentTaskReports) SubmitAndClose(ctx context.Context, requestID uint, actor gatewayapi.Actor, body string, closeTask func(*gorm.DB, uint, time.Time) error) (*model.AgentTaskReport, error) {
	return s.submit(ctx, requestID, actor, body, closeTask)
}
func (s *AgentTaskReports) submit(ctx context.Context, requestID uint, actor gatewayapi.Actor, body string, closeTask func(*gorm.DB, uint, time.Time) error) (*model.AgentTaskReport, error) {
	if strings.TrimSpace(body) == "" || len(body) > 65536 {
		return nil, ErrAgentReportBody
	}
	var result model.AgentTaskReport
	var ownerID uint
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if s.task == nil || s.principal == nil || s.notify == nil {
			return errors.New("agent report dependencies unavailable")
		}
		task, err := s.task(tx, requestID)
		if err != nil {
			return err
		}
		principal, err := s.principal(tx, actor.UserID)
		if err != nil {
			return err
		}
		if principal.Kind != model.KindAgent || principal.OwnerID == 0 || task.ExecutorID != actor.UserID {
			return ErrAgentReportForbidden
		}
		var rows []model.AgentTaskReport
		if err := tx.Where("access_request_id=?", requestID).Order("version").Find(&rows).Error; err != nil {
			return err
		}
		now := s.now().UTC().Truncate(time.Microsecond)
		if task.ClosedAt != nil && (now.Before(*task.ClosedAt) || !now.Before(task.ClosedAt.Add(24*time.Hour))) {
			return ErrAgentReportWindow
		}
		version := uint(1)
		if len(rows) > 0 {
			if rows[0].UserID != actor.UserID {
				return ErrAgentReportForbidden
			}
			if task.ClosedAt == nil {
				return ErrAgentReportWindow
			}
			version = rows[len(rows)-1].Version + 1
		}
		result = model.AgentTaskReport{AccessRequestID: requestID, UserID: actor.UserID, Version: version, Body: body, SubmittedAt: now}
		if err := tx.Create(&result).Error; err != nil {
			return err
		}
		digest := sha256.Sum256([]byte(body))
		details, err := json.Marshal(map[string]any{"event": "agent_task_report_submitted", "report_id": result.ID, "access_request_id": requestID, "version": version, "body_sha256": hex.EncodeToString(digest[:]), "owner_user_id": principal.OwnerID})
		if err != nil {
			return err
		}
		if err := port.WriteInTx(s.sink, tx, port.AuditEvent{Actor: actor, Action: string(model.ActionCreate), Resource: string(model.ResourceAccessRequest), ResourceID: &requestID, Status: string(model.StatusSuccess), Details: string(details)}); err != nil {
			return err
		}
		if closeTask != nil {
			if err := closeTask(tx, requestID, now); err != nil {
				return err
			}
		}
		ownerID = principal.OwnerID
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.notify(ownerID, notifycat.EventAgentTaskReport, map[string]string{"owner_id": fmt.Sprint(ownerID), "request_id": fmt.Sprint(requestID), "report_id": fmt.Sprint(result.ID), "version": fmt.Sprint(result.Version), "user_id": fmt.Sprint(actor.UserID)})
	return &result, nil
}

type AgentTaskReportVersions struct {
	AccessRequestID uint                    `json:"access_request_id"`
	ClosedAt        *time.Time              `json:"closed_at"`
	MissingAtClose  *bool                   `json:"missing_report_at_close"`
	Latest          *model.AgentTaskReport  `json:"latest"`
	Versions        []model.AgentTaskReport `json:"versions"`
}

func (s *AgentTaskReports) Versions(ctx context.Context, requestID, userID uint, role string) (*AgentTaskReportVersions, error) {
	var result AgentTaskReportVersions
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		task, err := s.task(tx, requestID)
		if err != nil {
			return err
		}
		principal, err := s.principal(tx, task.ExecutorID)
		if err != nil {
			return err
		}
		if role != model.RoleAdmin && role != model.RoleAuditor && userID != task.ExecutorID && userID != task.RequesterID && userID != principal.OwnerID {
			return ErrAgentReportForbidden
		}
		result = AgentTaskReportVersions{AccessRequestID: requestID, ClosedAt: task.ClosedAt, Versions: []model.AgentTaskReport{}}
		if err := tx.Where("access_request_id=?", requestID).Order("version DESC").Find(&result.Versions).Error; err != nil {
			return err
		}
		if len(result.Versions) > 0 {
			result.Latest = &result.Versions[0]
		}
		if task.ClosedAt != nil {
			missing := true
			for _, r := range result.Versions {
				if !r.SubmittedAt.After(*task.ClosedAt) {
					missing = false
					break
				}
			}
			result.MissingAtClose = &missing
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}
