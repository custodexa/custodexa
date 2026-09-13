//go:build !linux

package prochardening

import "fmt"

func Harden() error {
	return fmt.Errorf("process hardening: unsupported platform")
}
