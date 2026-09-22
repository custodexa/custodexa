package audit

import "testing"

func TestMaskSensitiveAccessRequestFields(t *testing.T) {
	for _, endpoint := range []string{"POST /api/v1/access-requests", "POST /api/v1/access-requests/break-glass", "POST /api/v1/access-requests/:id/approve", "POST /api/v1/access-requests/:id/reject", "POST /api/v1/access-requests/:id/revoke", "POST /api/v1/access-requests/:id/review"} {
		key := "note"
		if endpoint == "POST /api/v1/access-requests" || endpoint == "POST /api/v1/access-requests/break-glass" {
			key = "reason"
		}
		out := MaskSensitiveFields(endpoint, map[string]interface{}{key: "maintenance rationale", "password": "private", "token": "private", "secret": "private"})
		if out[key] != "maintenance rationale" {
			t.Fatal(endpoint, out)
		}
		for _, secret := range []string{"password", "token", "secret"} {
			if out[secret] == "private" {
				t.Fatal("credential exposed", endpoint, secret)
			}
		}
		if out := MaskSensitiveFields("POST /api/v1/unknown", map[string]interface{}{key: "private"}); out[key] == "private" {
			t.Fatal("global exception", key)
		}
	}
}
