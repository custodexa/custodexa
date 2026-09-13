package guard

import (
	"errors"
	"testing"
)

func TestCheckPlainText(t *testing.T) {
	cases := []struct {
		name    string
		base    string
		wantErr bool
	}{
		{"ws loopback name", "ws://localhost:8080", false},
		{"http loopback name", "http://localhost:8080", false},
		{"http loopback ipv4", "http://127.0.0.1:8080", false},
		{"http loopback ipv4 alternate", "http://127.9.9.9:8080", false},
		{"http loopback ipv6", "http://[::1]:8080", false},
		{"ws non-loopback name", "ws://backend.example.com:8080", true},
		{"http non-loopback name", "http://backend.example.com", true},
		{"http non-loopback ip", "http://10.0.0.5:8080", true},
		{"http name merely containing localhost", "http://localhost.evil.example.com", true},
		{"wss non-loopback allowed", "wss://backend.example.com", false},
		{"https non-loopback allowed", "https://backend.example.com", false},
		{"unsupported scheme", "ftp://localhost", true},
		{"missing scheme", "localhost:8080", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckPlainText(tc.base)
			if tc.wantErr && err == nil {
				t.Fatalf("CheckPlainText(%q) = nil, want error", tc.base)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("CheckPlainText(%q) = %v, want nil", tc.base, err)
			}
		})
	}
}

func TestCheckPlainTextErrorIsSentinel(t *testing.T) {
	err := CheckPlainText("ws://backend.example.com:8080")
	if !errors.Is(err, ErrPlainTextTransport) {
		t.Fatalf("error %v does not wrap ErrPlainTextTransport", err)
	}
}
