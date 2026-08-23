package model

import "testing"

// TestUserDisplayNameResolver 顯示名 resolver 三段優先序：
// local_display_name || full_name || username，取第一個 trim 後非空者。
func TestUserDisplayNameResolver(t *testing.T) {
	sp := func(s string) *string { return &s }
	cases := []struct {
		name string
		user User
		want string
	}{
		{"override wins", User{Username: "alice", FullName: "Alice Wang", LocalDisplayName: sp("小王")}, "小王"},
		{"blank override falls back to full_name", User{Username: "alice", FullName: "Alice Wang", LocalDisplayName: sp("   ")}, "Alice Wang"},
		{"nil override falls back to full_name", User{Username: "alice", FullName: "Alice Wang"}, "Alice Wang"},
		{"both empty falls back to username", User{Username: "alice", FullName: "  ", LocalDisplayName: sp("")}, "alice"},
		{"only username", User{Username: "alice"}, "alice"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.user.DisplayName(); got != c.want {
				t.Fatalf("DisplayName() = %q, want %q", got, c.want)
			}
		})
	}
}

// TestUserEmailString email NULL（未知）以空字串回傳
func TestUserEmailString(t *testing.T) {
	e := "a@x"
	if got := (&User{Email: &e}).EmailString(); got != "a@x" {
		t.Fatalf("EmailString() = %q, want a@x", got)
	}
	if got := (&User{Email: nil}).EmailString(); got != "" {
		t.Fatalf("nil EmailString() = %q, want empty", got)
	}
}
