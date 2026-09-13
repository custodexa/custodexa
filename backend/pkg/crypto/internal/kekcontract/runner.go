// Package kekcontract supplies one provider-neutral assertion set to driver tests.
package kekcontract

import (
	"bytes"
	"context"
	"testing"

	"github.com/custodexa/backend/pkg/crypto"
)

type Case struct {
	Name          string
	Build         func(*testing.T) crypto.KEKProvider
	Other         func(*testing.T) crypto.KEKProvider
	WantFormatTag string
	WantRefKind   string
}

func LocalCases() []Case {
	return []Case{
		{
			Name: "local-env",
			Build: func(t *testing.T) crypto.KEKProvider {
				p, err := crypto.NewLocalAESKEKProvider(bytes.Repeat([]byte{1}, 32), crypto.KEKModeEnv)
				if err != nil {
					t.Fatalf("local env provider: %v", err)
				}
				return p
			},
			Other: func(t *testing.T) crypto.KEKProvider {
				p, err := crypto.NewLocalAESKEKProvider(bytes.Repeat([]byte{2}, 32), crypto.KEKModeEnv)
				if err != nil {
					t.Fatalf("local env provider: %v", err)
				}
				return p
			},
			WantFormatTag: crypto.WrappedFormatLocal,
			WantRefKind:   crypto.KeyRefProviderLocal,
		},
		{
			Name: "local-ui",
			Build: func(t *testing.T) crypto.KEKProvider {
				p, err := crypto.NewLocalAESKEKProvider(bytes.Repeat([]byte{1}, 32), crypto.KEKModeUI)
				if err != nil {
					t.Fatalf("local ui provider: %v", err)
				}
				return p
			},
			Other: func(t *testing.T) crypto.KEKProvider {
				p, err := crypto.NewLocalAESKEKProvider(bytes.Repeat([]byte{2}, 32), crypto.KEKModeUI)
				if err != nil {
					t.Fatalf("local ui provider: %v", err)
				}
				return p
			},
			WantFormatTag: crypto.WrappedFormatLocal,
			WantRefKind:   crypto.KeyRefProviderLocal,
		},
	}
}

// Run preserves all assertions from the original three-provider contract.
func Run(t *testing.T, cases []Case) {
	ctx := context.Background()
	dek := bytes.Repeat([]byte{9}, 32)
	aad := crypto.DEKAAD("data", 1)

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			p := c.Build(t)

			wrapped, err := p.Wrap(ctx, dek, aad)
			if err != nil {
				t.Fatalf("Wrap: %v", err)
			}
			if bytes.Contains(wrapped, dek) {
				t.Fatal("包裹結果內含明文材料")
			}
			got, err := p.Unwrap(ctx, wrapped, aad)
			if err != nil {
				t.Fatalf("Unwrap: %v", err)
			}
			if !bytes.Equal(got, dek) {
				t.Fatal("往返材料不符")
			}

			if _, err := p.Unwrap(ctx, wrapped, crypto.DEKAAD("data", 2)); err == nil {
				t.Fatal("AAD 不符 MUST 解包失敗")
			}

			if _, err := c.Other(t).Unwrap(ctx, wrapped, aad); err == nil {
				t.Fatal("他鑰 MUST 解包失敗")
			}

			if p.FormatTag() != c.WantFormatTag {
				t.Fatalf("FormatTag want %q got %q", c.WantFormatTag, p.FormatTag())
			}
			if p.KeyRef().Provider != c.WantRefKind {
				t.Fatalf("KeyRef().Provider want %q got %q", c.WantRefKind, p.KeyRef().Provider)
			}
			if p.KeyRef().KeyID == "" {
				t.Fatal("KeyRef().KeyID 不得為空")
			}
			if p.Mode() == "" {
				t.Fatal("Mode() 不得為空")
			}

			re, err := p.ReEncrypt(ctx, wrapped, aad, p)
			if err != nil {
				t.Fatalf("ReEncrypt: %v", err)
			}
			if again, err := p.Unwrap(ctx, re, aad); err != nil || !bytes.Equal(again, dek) {
				t.Fatalf("ReEncrypt 結果不可解或材料不符: %v", err)
			}

			for _, empty := range [][]byte{nil, {}} {
				out, err := p.Wrap(ctx, dek, empty)
				if err == nil {
					t.Fatalf("空 AAD 的 Wrap MUST 被拒（否則寫得出無綁定的包裹值），竟得 %x", out)
				}
				if out != nil {
					t.Fatalf("空 AAD 的 Wrap MUST NOT 產出包裹值，得 %x", out)
				}
				if _, err := p.Unwrap(ctx, wrapped, empty); err == nil {
					t.Fatal("空 AAD 的 Unwrap MUST 被拒（否則保留了以空 AAD 試錯的讀取路徑）")
				}
			}
		})
	}
}

// Interchange checks both directions for every pair supplied by a driver entry.
func Interchange(t *testing.T, cases []Case) {
	for _, source := range cases {
		for _, target := range cases {
			if source.Name == target.Name {
				continue
			}
			t.Run(source.Name+"-to-"+target.Name, func(t *testing.T) {
				ctx := context.Background()
				dek := bytes.Repeat([]byte{5}, 32)
				aad := crypto.DEKAAD("data", 3)
				from, to := source.Build(t), target.Build(t)
				wrapped, err := from.Wrap(ctx, dek, aad)
				if err != nil {
					t.Fatalf("source Wrap: %v", err)
				}
				moved, err := to.ReEncrypt(ctx, wrapped, aad, from)
				if err != nil {
					t.Fatalf("cross ReEncrypt: %v", err)
				}
				got, err := to.Unwrap(ctx, moved, aad)
				if err != nil || !bytes.Equal(got, dek) {
					t.Fatal("target cannot recover material")
				}
				back, err := from.ReEncrypt(ctx, moved, aad, to)
				if err != nil {
					t.Fatalf("reverse ReEncrypt: %v", err)
				}
				got, err = from.Unwrap(ctx, back, aad)
				if err != nil || !bytes.Equal(got, dek) {
					t.Fatal("source cannot recover returned material")
				}
			})
		}
	}
}
