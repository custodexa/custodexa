package audit

import (
	"context"
	"errors"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sensitivescan"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// OutputAlertWindow bounds notification delay and groups a burst into one row.
const OutputAlertWindow = 5 * time.Second

type outputAlertBucket struct {
	first time.Time
	meta  OutputAlertMetadata
}

// OutputAlerts belongs to one session's scanner worker. Only rule identity,
// timestamps and counts survive scanning; it never receives matching text.
type OutputAlerts struct {
	session model.Session
	sink    gatewayapi.AlertSink
	rules   map[uint]model.AlertRule
	pending map[uint]outputAlertBucket
}

func NewOutputAlerts(sess model.Session, rules []model.AlertRule, sink gatewayapi.AlertSink) *OutputAlerts {
	a := &OutputAlerts{session: sess, sink: sink, rules: map[uint]model.AlertRule{}, pending: map[uint]outputAlertBucket{}}
	for _, r := range rules {
		a.rules[r.ID] = r
	}
	return a
}

func (a *OutputAlerts) Add(hits []sensitivescan.Match, now time.Time) error {
	err := a.Flush(now, false)
	for _, hit := range hits {
		if _, ok := a.rules[hit.RuleID]; !ok {
			continue
		}
		b, ok := a.pending[hit.RuleID]
		if !ok {
			b = outputAlertBucket{first: now}
		}
		b.meta.Count++
		a.pending[hit.RuleID] = b
	}
	return err
}

// Flush emits expired windows, or every pending window on session close.
// Writes go through the same AlertSink as input alerts (including notify/syslog).
func (a *OutputAlerts) Flush(now time.Time, all bool) error {
	var errs []error
	for id, b := range a.pending {
		if !all && now.Sub(b.first) < OutputAlertWindow {
			continue
		}
		r := a.rules[id]
		ruleID := id
		alert := gatewayapi.CommandAlert{Kind: model.AlertKindRule, ReasonCode: b.meta.ReasonCode(), RuleID: &ruleID,
			RuleName: r.Name, SessionID: a.session.ID, Actor: gatewayapi.Actor{UserID: a.session.UserID},
			AssetID: a.session.AssetID, Level: r.Severity, OccurredAt: b.first, Disposition: model.AlertDispositionPending}
		// Delete after the attempt: a downstream failure must not replay/duplicate an
		// alert whose database commit may have succeeded. The caller logs failures.
		if err := gatewayapi.RecordAlert(context.Background(), a.sink, alert); err != nil {
			errs = append(errs, err)
		}
		delete(a.pending, id)
	}
	return errors.Join(errs...)
}
