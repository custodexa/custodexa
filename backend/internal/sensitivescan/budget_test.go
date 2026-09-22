package sensitivescan

import (
	"github.com/custodexa/backend/internal/model"
	"strings"
	"testing"
	"time"
)

// Measurement: docker-compose.dev.yml backend, linux/arm64, Go 1.26.6;
// 8 visible CPUs, 15970 MiB VM memory; cpu.max="max 100000", memory.max="max".
// One scanner at a time, two builtin enabled rules, 100 KiB per operation,
// 4096-byte frames plus EOF Flush; regex compilation is outside the timed region.
// No parallel full suite or protocol targets during calibration (2026-09-21).
const outputScanBudget = 40 * time.Millisecond // 7.59ms measured; >5x headroom for shared dev-host noise

var outputScanHits int

func outputScanFixture(tb testing.TB) (*Rules, []byte) {
	tb.Helper()
	r, err := Compile([]model.AlertRule{
		{ID: 1, Pattern: CardPattern, Direction: model.DirectionOutput, Enabled: true},
		{ID: 2, Pattern: PrivateKeyPattern, Direction: model.DirectionOutput, Enabled: true},
	}, "ssh")
	if err != nil {
		tb.Fatal(err)
	}
	line := "row card=4111-1111-1111-1111 invalid=4111111111111112 header=-----BEGIN RSA PRIVATE KEY-----\n"
	return r, []byte(strings.Repeat(line, (100*1024/len(line))+1)[:100*1024])
}

func scanOutputUnit(r *Rules, payload []byte) int {
	s := NewStreamScanner(r)
	hits := 0
	for pos := 0; pos < len(payload); pos += 4096 {
		end := pos + 4096
		if end > len(payload) {
			end = len(payload)
		}
		hits += len(s.Write(payload[pos:end]))
	}
	return hits + len(s.Flush())
}

func BenchmarkOutputScan(b *testing.B) {
	r, payload := outputScanFixture(b)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		outputScanHits = scanOutputUnit(r, payload)
	}
}

func TestOutputScanBudget(t *testing.T) {
	r, payload := outputScanFixture(t)
	scanOutputUnit(r, payload) // warm caches
	start := time.Now()
	for i := 0; i < 20; i++ {
		outputScanHits = scanOutputUnit(r, payload)
	}
	elapsed := time.Since(start) / 20
	t.Logf("100KiB serial average=%s budget=%s", elapsed, outputScanBudget)
	if elapsed > outputScanBudget {
		t.Fatalf("output scan budget exceeded: %s > %s", elapsed, outputScanBudget)
	}
}

func TestOutputScanBudgetDisabled(t *testing.T) {
	r, err := Compile([]model.AlertRule{{ID: 1, Pattern: CardPattern, Direction: model.DirectionOutput, Enabled: false}}, "ssh")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(strings.Repeat("4111111111111111\n", 6400))[:100*1024]
	s := NewStreamScanner(r)
	allocs := testing.AllocsPerRun(100, func() { outputScanHits = len(s.Write(payload)) + len(s.Flush()) })
	// Zero scanning work means no compiled rules, no allocations, no retained
	// bytes and no offset advance; elapsed wall time cannot be literally zero.
	if len(r.rules) != 0 || allocs != 0 || s.offset != 0 || s.tail != "" || outputScanHits != 0 {
		t.Fatalf("disabled scan work: rules=%d allocs=%g offset=%d tail=%d hits=%d", len(r.rules), allocs, s.offset, len(s.tail), outputScanHits)
	}
	t.Log("disabled output rules: no regex, zero allocations, zero retained bytes, zero offset advance")
}
