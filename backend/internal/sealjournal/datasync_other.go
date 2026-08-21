//go:build !linux

package sealjournal

import "os"

// datasync 在非 Linux 平台退回 fsync（語義較強，不影響正確性）。
// 產品執行環境為 Linux 容器；此實作僅供本機開發編譯。
func datasync(f *os.File) error {
	return f.Sync()
}
