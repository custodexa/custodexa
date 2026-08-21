package sshproxy

import (
	"testing"
	"time"
)

func TestShareManagerCreateResolve(t *testing.T) {
	m := NewShareManager()
	code, expires, err := m.Create(7, 1, 10*time.Minute)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(code) != 32 {
		t.Errorf("code length = %d", len(code))
	}
	if time.Until(expires) < 9*time.Minute {
		t.Errorf("expires too soon: %v", expires)
	}

	sid, ok := m.Resolve(code)
	if !ok || sid != 7 {
		t.Errorf("Resolve = %d, %v", sid, ok)
	}
}

func TestShareManagerRecreateInvalidatesOld(t *testing.T) {
	m := NewShareManager()
	oldCode, _, _ := m.Create(7, 1, time.Minute)
	newCode, _, _ := m.Create(7, 1, time.Minute)

	if _, ok := m.Resolve(oldCode); ok {
		t.Error("old code should be invalid after recreate")
	}
	if sid, ok := m.Resolve(newCode); !ok || sid != 7 {
		t.Error("new code should resolve")
	}
}

func TestShareManagerExpiry(t *testing.T) {
	m := NewShareManager()
	code, _, _ := m.Create(7, 1, -time.Second) // 已過期
	if _, ok := m.Resolve(code); ok {
		t.Error("expired code should not resolve")
	}
}

func TestShareManagerRevoke(t *testing.T) {
	m := NewShareManager()
	code, _, _ := m.Create(7, 1, time.Minute)

	if !m.Revoke(7) {
		t.Error("Revoke should report existing share")
	}
	if _, ok := m.Resolve(code); ok {
		t.Error("revoked code should not resolve")
	}
	if m.Revoke(7) {
		t.Error("second Revoke should report missing")
	}
}
