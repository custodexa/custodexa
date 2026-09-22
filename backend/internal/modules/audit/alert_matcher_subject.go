package audit

import (
	"errors"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// SubjectAlertMatcher binds authenticated provenance once per connection. It
// shares the live rule cache; it never infers identity from command content.
type SubjectAlertMatcher struct {
	matcher *AlertMatcher
	kind    string
}

// kind is required; session callers supply ConnectGrant.PrincipalKind.
// Invalid legacy provenance remains explicitly unknown, never human.
func (m *AlertMatcher) ForSubject(kind string) *SubjectAlertMatcher {
	if kind != model.KindHuman && kind != model.KindAgent {
		kind = gatewayapi.PrincipalKindUnknown
	}
	return &SubjectAlertMatcher{matcher: m, kind: kind}
}
func ruleAppliesToSubject(ruleKind, subject string) bool {
	if ruleKind == "" || ruleKind == model.AlertSubjectAll {
		return true
	}
	return (subject == model.KindHuman || subject == model.KindAgent) && ruleKind == subject
}
func (s *SubjectAlertMatcher) Match(command, protocol string) []*model.AlertRule {
	if s == nil || s.matcher == nil {
		return nil
	}
	return s.matcher.matchSubject(command, protocol, s.kind)
}
func (s *SubjectAlertMatcher) MatchBlock(command, protocol string) (*model.AlertRule, bool) {
	for _, r := range s.Match(command, protocol) {
		if r.Action == "block" {
			return r, true
		}
	}
	return nil, false
}
func (s *SubjectAlertMatcher) MatchAndStore(cmds []model.SessionCommand, protocol string) {
	if s != nil && s.matcher != nil {
		s.matcher.matchAndStoreSubject(cmds, protocol, s.kind)
	}
}
func (s *SubjectAlertMatcher) BlockerHealth() error {
	if s == nil || s.matcher == nil {
		return errors.New("alert matcher unavailable")
	}
	return s.matcher.BlockerHealth()
}
