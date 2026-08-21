//go:build ignore
// +build ignore

// E2E 測試輔助工具：依 base32 secret 產生當前時間窗的 TOTP 驗證碼。
// 在容器內執行（與後端共用時鐘，避免 host 時間偏移造成驗證失敗）：
//
//	docker compose exec -T backend go run scripts/totp_code.go <secret>
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/pquerna/otp/totp"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: go run totp_code.go <base32-secret>")
		os.Exit(1)
	}

	code, err := totp.GenerateCode(os.Args[1], time.Now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate code failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(code)
}
