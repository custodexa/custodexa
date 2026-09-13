package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/custodexa/backend/internal/seal"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

type retainedBody struct {
	raw  []byte
	read bool
	fail bool
}

func (b *retainedBody) Read(dst []byte) (int, error) {
	if b.read {
		return 0, io.EOF
	}
	b.read = true
	b.raw = dst
	n := copy(dst, `{"kek":"owned-fixture"}`)
	if b.fail {
		return n, errors.New("partial body read failed")
	}
	return n, io.EOF
}
func TestUnsealBodyAllExitZeroize(t *testing.T) {
	for _, which := range []string{"read-error", "admission", "acquire"} {
		t.Run(which, func(t *testing.T) {
			body := &retainedBody{fail: which == "read-error"}
			h := NewSealHandler(seal.NewUnsealed(nil), nil)
			// 解封端點自本版起於**所有模式**要求解封授權脈絡，且脈絡驗證早於
			// 讀取請求體——沒有它，本測試要守的那條「讀進來的 body 在所有離開
			// 路徑上都被歸零」根本不會被走到。故先備一個有效脈絡。
			grants := NewSealGrantStore(0)
			h.SetSealAuthorization(grants, func(string, []byte) (uint, error) { return 1, nil })
			grant, _, err := grants.Issue(1, "admin")
			if err != nil {
				t.Fatalf("issue grant: %v", err)
			}
			if which == "admission" {
				h.SetAdmitter(func(context.Context) (func(bool), error) { return nil, errors.New("admission unavailable") })
			}
			r := sourceTestRouter(t, h)
			w := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/api/v1/seal/unseal", body)
			req.Header.Set("Authorization", "SealGrant "+grant)
			r.ServeHTTP(w, req)
			if len(body.raw) == 0 || !bytes.Equal(body.raw, make([]byte, len(body.raw))) {
				t.Fatal("owned HTTP buffer retained")
			}
			t.Logf("%s: HTTP %d original body allocation zero", which, w.Code)
		})
	}
}
func TestSealPayloadPartialCleanup(t *testing.T) {
	p := &SealUnsealPayload{}
	dec := json.NewDecoder(strings.NewReader(`{"kek":"first","password":"second","unknown":1}`))
	if err := decodeSealObject(dec, p); err == nil {
		t.Fatal("malformed object accepted")
	}
	originals := [][]byte{p.KEK, p.Password}
	p.Zeroize()
	for _, raw := range originals {
		if len(raw) == 0 || !bytes.Equal(raw, make([]byte, len(raw))) {
			t.Fatal("partial payload retained")
		}
	}
	t.Log("partial payload fields zero; decoder internal storage is outside the erasure claim")
}
