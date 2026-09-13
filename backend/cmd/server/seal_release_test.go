package main

import (
	"bytes"
	"context"
	"errors"
	"github.com/custodexa/backend/internal/seal"
	"testing"
	"time"
)

func TestLocalKEKOwnerRelease(t *testing.T) {
	env := newSealIntegrationEnv(t)
	provider, owner, err := buildOwnedUIKEKProvider([]byte(testInitialKEK))
	if err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err = owner.Borrow(func(b []byte) error { raw = b; return nil }); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	graph, err := runStage2(ctx, env.s1, provider, nil, nil, owner)
	if err == nil || graph == nil {
		t.Fatal("cancelled graph missing")
	}
	if err = graph.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, make([]byte, len(raw))) || len(raw) == 0 {
		t.Fatal("local KEK original retained")
	}
	t.Log("cancelled stage2 graph releases original local KEK allocation")
}
func TestSealGraphRelease(t *testing.T) {
	for _, which := range []string{"error", "timeout"} {
		t.Run(which, func(t *testing.T) {
			bag := &seal.ResourceBag{}
			if which == "error" {
				bag.AddFunc("worker", func(context.Context) error { return errors.New("worker release failed") })
			} else {
				bag.AddFunc("worker", func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() })
			}
			g := &appGraph{bag: bag}
			ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
			defer cancel()
			first := g.Release(ctx)
			second := g.Release(context.Background())
			if first == nil || second == nil {
				t.Fatalf("release failure lost: first=%v second=%v", first, second)
			}
			t.Logf("%s: first=%v repeated=%v", which, first, second)
		})
	}
}
