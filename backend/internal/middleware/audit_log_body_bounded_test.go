package middleware

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/gin-gonic/gin"
)

type auditFaultBody struct {
	data   *bytes.Reader
	closed bool
	fail   bool
}

func (b *auditFaultBody) Read(p []byte) (int, error) {
	if b.fail && b.data.Len() == 0 {
		return 0, errors.New("read failed")
	}
	return b.data.Read(p)
}
func (b *auditFaultBody) Close() error { b.closed = true; return nil }

func TestAuditBodyBoundedReplayAndMask(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name, contentType, body, wantBody string
		fail, overLimit                   bool
	}{
		{"complete JSON", "application/json", `{"password":"secret-complete","name":"safe"}`, "", false, false},
		{"huge JSON", "application/json", `{"password":"secret-large","pad":"` + strings.Repeat("x", 100000) + `"}`, "[TRUNCATED: audit capture limit 65536 bytes]", false, false},
		{"huge multipart", "multipart/form-data; boundary=test", "--test\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\n" + strings.Repeat("x", 100000) + "\r\n--test--\r\n", "[TRUNCATED: audit capture limit 65536 bytes]", false, false},
		{"endpoint cap", "application/json", strings.Repeat("x", (1<<20)+1), "[TRUNCATED: audit capture limit 65536 bytes]", false, true},
		{"read error", "application/json", `{"password":"secret-error"}`, "[AUDIT CAPTURE READ ERROR]", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := installClipboardAuditDB(t)
			svc := audit.NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true, AsyncAuditEnabled: false})
			r := gin.New()
			r.Use(AuditLogMiddleware(svc), func(c *gin.Context) { c.Set("userID", uint(7)); c.Set("username", "tester"); c.Next() })
			var got []byte
			var handlerErr error
			r.POST("/api/v1/assets/import", func(c *gin.Context) {
				// MaxBytesReader must still see the full stream after middleware capture.
				c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20)
				got, handlerErr = io.ReadAll(c.Request.Body)
				_ = c.Request.Body.Close()
				if tc.overLimit {
					c.Status(http.StatusRequestEntityTooLarge)
					return
				}
				c.Status(http.StatusOK)
			})
			body := &auditFaultBody{data: bytes.NewReader([]byte(tc.body)), fail: tc.fail}
			req := httptest.NewRequest("POST", "/api/v1/assets/import", nil)
			req.Body = body
			req.ContentLength = int64(len(tc.body))
			req.Header.Set("Content-Type", tc.contentType)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if tc.overLimit {
				var maxErr *http.MaxBytesError
				if !errors.As(handlerErr, &maxErr) || w.Code != http.StatusRequestEntityTooLarge || string(got) != tc.body[:1<<20] {
					t.Fatalf("downstream limit failed: code=%d len=%d err=%v", w.Code, len(got), handlerErr)
				}
			} else if string(got) != tc.body {
				t.Fatalf("handler body changed: got %d, want %d", len(got), len(tc.body))
			}
			if !body.closed {
				t.Fatal("original body not closed")
			}
			row := latestAuditRow(t, db)
			if tc.wantBody != "" {
				if row.RequestBody != tc.wantBody {
					t.Fatalf("request_body=%q", row.RequestBody)
				}
				if strings.Contains(row.Details, "secret-") {
					t.Fatal("details leaked original")
				}
			} else if strings.Contains(row.RequestBody, "secret-complete") || !strings.Contains(row.RequestBody, "MASKED") {
				t.Fatalf("unmasked JSON: %s", row.RequestBody)
			}
		})
	}
}
