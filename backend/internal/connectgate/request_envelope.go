package connectgate

import (
	"errors"
	"net/http"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

type RequestEnvelopeMatcher interface {
	MatchRequestItem(requestID, userID, assetID uint, username string, at time.Time) (*model.AccessRequestItem, error)
	RequestEnvelopeRequired(userID uint) (bool, error)
}

// RequestEnvelope evaluates both mandatory agent linkage and a supplied human task.
// Internal failures also fail closed, without exposing database details.
func RequestEnvelope(m RequestEnvelopeMatcher, requestID, userID, assetID uint, username string) *Outcome {
	required, err := m.RequestEnvelopeRequired(userID)
	dimension := "asset"
	if err == nil && !required && requestID == 0 {
		return nil
	}
	if err == nil && requestID != 0 {
		_, err = m.MatchRequestItem(requestID, userID, assetID, username, time.Now())
		if err == nil {
			return nil
		}
		if errors.Is(err, authz.ErrRequestItemScope) {
			dimension = "scope"
		} else if errors.Is(err, authz.ErrRequestItemWindow) {
			dimension = "window"
		}
	}
	return Deny(http.StatusForbidden, string(apierror.CodeAuthRequestItemMismatch), map[string]any{"dimension": dimension, "access_request_id": requestID, "asset_id": assetID})
}
func NeedsRequestEnvelope(m RequestEnvelopeMatcher, requestID, userID uint) bool {
	if userID == 0 {
		return requestID != 0
	} // No authenticated subject: an earlier identity gate owns rejection.
	if requestID != 0 {
		return true
	}
	required, err := m.RequestEnvelopeRequired(userID)
	return required || err != nil
}
func RequestItemDimension(out *Outcome) string {
	if out == nil || out.Meta == nil {
		return ""
	}
	v, _ := out.Meta["dimension"].(string)
	return v
}
