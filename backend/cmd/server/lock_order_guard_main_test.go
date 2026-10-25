package main

import (
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/custodexa/backend/internal/modules/authz"
)

// TestMain 安裝測試期動態鎖序守衛：整個套件的測試跑完後，任一交易違反使用者層與拓撲鎖的全序
// （已知例外只在登記處放行）即列出違規與取鎖位置，並以非零結束。
func TestMain(m *testing.M) {
	var mu sync.Mutex
	var violations []authz.LockOrderViolation
	restore := authz.SetLockOrderGuardForTest(func(v authz.LockOrderViolation) {
		mu.Lock()
		defer mu.Unlock()
		violations = append(violations, v)
	})
	fmt.Println("EVIDENCE lockorder-probe=installed")
	code := m.Run()
	restore()
	mu.Lock()
	defer mu.Unlock()
	if len(violations) > 0 {
		fmt.Fprintf(os.Stderr, "lock order guard: %d violation(s)\n", len(violations))
		for i, v := range violations {
			fmt.Fprintf(os.Stderr, "violation %d: %s\n", i+1, v)
		}
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}
