package model

import (
	"context"
	"encoding/json"
	"fmt"
	"gorm.io/gorm/schema"
	"reflect"
)

// Keep the established Go/numeric JSON shape for session alerts while storing
// absence as SQL NULL. A database CHECK restricts that absence to breaker alerts.
type nullableAlertSessionID struct{}

func init() { schema.RegisterSerializer("nullable_alert_session", nullableAlertSessionID{}) }
func (nullableAlertSessionID) Scan(ctx context.Context, field *schema.Field, dst reflect.Value, value interface{}) error {
	if value == nil {
		return field.Set(ctx, dst, uint(0))
	}
	return field.Set(ctx, dst, value)
}
func (nullableAlertSessionID) Value(ctx context.Context, field *schema.Field, dst reflect.Value, value interface{}) (interface{}, error) {
	id, ok := value.(uint)
	if !ok {
		return nil, fmt.Errorf("invalid alert session id type")
	}
	if id == 0 {
		return nil, nil
	}
	return int64(id), nil
}
func (a CommandAlert) MarshalJSON() ([]byte, error) {
	type plain CommandAlert
	if a.Kind == AlertKindAgentBreaker && a.SessionID == 0 {
		return json.Marshal(struct {
			plain
			SessionID *uint `json:"session_id"`
		}{plain: plain(a)})
	}
	return json.Marshal(plain(a))
}
