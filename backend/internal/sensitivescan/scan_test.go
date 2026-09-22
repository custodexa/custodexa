package sensitivescan

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
)

func builtinRules(t *testing.T) *Rules {
	t.Helper()
	r, err := Compile([]model.AlertRule{
		{ID: 1, Pattern: CardPattern, Direction: model.DirectionOutput, Enabled: true},
		{ID: 2, Pattern: PrivateKeyPattern, Direction: model.DirectionOutput, Enabled: true},
	}, "ssh")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestLuhn(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		valid      bool
	}{
		{"13", "4222222222222", true},
		{"14", "30569309025904", true},
		{"15", "378282246310005", true},
		{"16", "4111111111111111", true},
		{"17", "40000000000000006", true},
		{"18", "400000000000000002", true},
		{"19", "4000000000000000006", true},
		{"spaces", "4111 1111 1111 1111", true},
		{"hyphens", "4111-1111-1111-1111", true},
		{"invalid_checksum", "4111111111111112", false},
		{"12", "400000000002", false},
		{"20", "40000000000000000002", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Luhn(tc.text); got != tc.valid {
				t.Fatalf("valid=%v want %v", got, tc.valid)
			}
		})
	}
}

func TestCardCandidate(t *testing.T) {
	r := builtinRules(t)
	for _, tc := range []struct {
		name, text string
		count      int
	}{
		{"13", "4222222222222", 1}, {"14", "30569309025904", 1},
		{"15", "378282246310005", 1}, {"16", "4111111111111111", 1},
		{"17", "40000000000000006", 1}, {"18", "400000000000000002", 1},
		{"19", "4000000000000000006", 1},
		{"spaces", "card: 4111 1111 1111 1111\n", 1},
		{"hyphens", "card: 4111-1111-1111-1111\n", 1},
		{"invalid_checksum", "4111111111111112", 0},
		{"12", "400000000002", 0}, {"20", "40000000000000000002", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := len(r.Scan(tc.text)); got != tc.count {
				t.Fatalf("matches=%d want %d", got, tc.count)
			}
		})
	}
}

func TestFalsePositiveCorpus(t *testing.T) {
	f, err := os.Open("testdata/non_cards.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r := builtinRules(t)
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			t.Fatal("malformed corpus row")
		}
		count++
		if hits := r.Scan(parts[1]); len(hits) != 0 {
			t.Errorf("corpus row %d (%s): %d hits", count, parts[0], len(hits))
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	t.Logf("corpus entries=%d", count)
	if count < 200 {
		t.Fatalf("corpus entries=%d want >=200", count)
	}
}

func TestPrivateKeyHeader(t *testing.T) {
	r := builtinRules(t)
	for _, label := range []string{"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY", "PGP PRIVATE KEY BLOCK", "PGP PRIVATE KEY", "DSA PRIVATE KEY", "ENCRYPTED PRIVATE KEY"} {
		t.Run(label, func(t *testing.T) {
			if got := len(r.Scan("-----BEGIN " + label + "-----\n")); got != 1 {
				t.Fatalf("matches=%d want 1", got)
			}
		})
	}
}

func TestOutOfScopeEncoded(t *testing.T) {
	if got := len(builtinRules(t).Scan(base64.StdEncoding.EncodeToString([]byte("4111111111111111")))); got != 0 {
		t.Fatalf("encoded card matched: %d", got)
	}
}

func TestFrameBoundary(t *testing.T) {
	const card = "4111111111111111"
	r := builtinRules(t)
	cuts := 0
	for cut := 1; cut < len(card); cut++ {
		cuts++
		t.Run(fmt.Sprint(cut), func(t *testing.T) {
			s := NewStreamScanner(r)
			hits := s.Write([]byte(card[:cut]))
			hits = append(hits, s.Write([]byte(card[cut:]))...)
			hits = append(hits, s.Flush()...)
			if len(hits) != 1 {
				t.Fatalf("matches=%d want 1", len(hits))
			}
			if hits[0].Start != 0 || hits[0].End != int64(len(card)) {
				t.Fatalf("wrong absolute positions: %+v", hits[0])
			}
		})
	}
	t.Logf("frame boundary cuts=%d card length=%d expected=%d", cuts, len(card), len(card)-1)
	if cuts != len(card)-1 {
		t.Fatal("missing cut")
	}
}

func TestStreamScanner(t *testing.T) {
	t.Run("bounded_overlap_and_absolute_dedup", func(t *testing.T) {
		s := NewStreamScanner(builtinRules(t))
		prefix := strings.Repeat("x", OverlapBytes*2) + "\n"
		if len(s.Write([]byte(prefix))) != 0 {
			t.Fatal("prefix matched")
		}
		var hits []Match
		for i := 0; i < 100; i++ {
			hits = append(hits, s.Write([]byte("4111 1111 1111 1111\n"))...)
			if len(s.tail) > OverlapBytes {
				t.Fatalf("retained=%d", len(s.tail))
			}
		}
		hits = append(hits, s.Flush()...)
		hits = append(hits, s.Flush()...)
		if len(hits) != 100 {
			t.Fatalf("matches=%d want 100", len(hits))
		}
		for i, hit := range hits {
			if hit.Start != int64(len(prefix)+i*20) {
				t.Fatalf("wrong offset: %+v", hit)
			}
		}
	})
	t.Run("disabled_output_rules_skip_all_work", func(t *testing.T) {
		r, err := Compile([]model.AlertRule{
			{Pattern: "[", Direction: model.DirectionOutput, Enabled: false},
			{Pattern: ".*", Direction: model.DirectionInput, Enabled: true},
		}, "ssh")
		if err != nil {
			t.Fatal(err)
		}
		s := NewStreamScanner(r)
		if len(s.Write([]byte("4111111111111111"))) != 0 || len(s.Flush()) != 0 {
			t.Fatal("disabled scanner emitted matches")
		}
		if s.offset != 0 || s.tail != "" || len(s.lastEnd) != 0 {
			t.Fatal("disabled scanner retained scanning state")
		}
	})
}
