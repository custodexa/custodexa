//go:build linux

package prochardening

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func Harden() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_SET_DUMPABLE failed (check security_opt and ulimits.core deployment settings): %w", err)
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("RLIMIT_CORE failed (check ulimits.core): %w", err)
	}
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE | unix.MCL_ONFAULT); err != nil {
		return fmt.Errorf("mlockall failed (check cap_add IPC_LOCK and ulimits.memlock): %w", err)
	}
	return nil
}
