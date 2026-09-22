package sshproxy

import (
	"context"
	"github.com/custodexa/backend/internal/dbconsole"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

type timeoutDialect struct {
	*stubDialect
	remaining time.Duration
}

func (d *timeoutDialect) Exec(ctx context.Context, _ string) (*dbconsole.ExecOutcome, error) {
	at, ok := ctx.Deadline()
	if ok {
		d.remaining = time.Until(at)
	}
	return okOutcome(1), nil
}
func TestMCPQueryTimeoutReachesDialect(t *testing.T) {
	for _, timeout := range []time.Duration{time.Second, dbconsole.StatementTimeout} {
		t.Run(timeout.String(), func(t *testing.T) {
			base := &stubDialect{currentDB: "app"}
			f := newConsoleFixture(t, base)
			d := &timeoutDialect{stubDialect: base}
			f.s.dialect = d
			_, err := f.s.execUnitTimeout("select 1", nil, timeout)
			require.NoError(t, err)
			require.InDelta(t, timeout.Seconds(), d.remaining.Seconds(), 0.2)
		})
	}
}
