package sealjournal

import (
	"bytes"
	"context"
	"os"
	"testing"
)

func TestSealOperationJournal(t *testing.T) {
	j, p := openProbedJournal(t, t.TempDir())
	ctx := context.Background()
	seq, err := j.WriteSealReceived(ctx, 2, `{"actor":1,"mode":"ui","source":"digest"}`)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.WriteSealOutcome(ctx, 2, seq, "seal_completed"); err != nil {
		t.Fatal(err)
	}
	sink := newSink()
	if _, err = j.Replay(ctx, sink); err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for _, b := range sink.batches {
		for _, e := range b.Events {
			kinds[e.Kind] = true
			if e.Kind == KindSealOutcome && e.Outcome != "seal_completed" {
				t.Fatal(e.Outcome)
			}
		}
	}
	if !kinds[KindSealReceived] || !kinds[KindSealOutcome] {
		t.Fatalf("kinds=%v", kinds)
	}
	p.mu.Lock()
	n := len(p.writeGIDs)
	p.mu.Unlock()
	if n != 1 {
		t.Fatalf("writers=%d", n)
	}
	t.Log("seal received and completed replayed by the single writer")
}
func TestSealJournalCompatibility(t *testing.T) {
	dir := t.TempDir()
	j := openTestJournal(t, dir)
	ctx := context.Background()
	seq, err := j.WriteReceived(ctx, 1, "abcd")
	if err != nil {
		t.Fatal(err)
	}
	if err = j.WriteOutcome(ctx, 1, seq, "success"); err != nil {
		t.Fatal(err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(j.path)
	if err != nil {
		t.Fatal(err)
	}
	reopened := openTestJournal(t, dir)
	after, err := os.ReadFile(j.path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("old fixture modified at open")
	}
	sink := newSink()
	if _, err = reopened.Replay(ctx, sink); err != nil {
		t.Fatal(err)
	}
	if len(sink.batches) == 0 {
		t.Fatal("old fixture missing")
	}
	t.Log("old unseal fixture readable; original bytes unchanged at open")
}
