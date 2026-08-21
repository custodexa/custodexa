package kms

import (
	"bytes"
	"context"
	"testing"

	"github.com/custodexa/backend/pkg/crypto"
)

// A／B／C 三 provider 的**共用契約測試**（D11.1 裁決 2「介面契約須同步」）。
//
// **存在理由＝互換性證明**：D1 的核心不變式是「KEK 來源模式的差異完全封裝於
// KEKProvider 之下，KeyManagerService 以上零語義差異」。要證明這件事，就得有一組
// **同一份**斷言跑過每個 provider——各寫各的測試只能證明各自沒壞，證明不了可互換。
//
// **nil／空 AAD 已收斂為共同期望**（release-transitional-cleanup P2 M1）：
// 原先是 per-provider 差異（本地 nil＝不綁定、委託 nil＝拒絕，round-2 codex
// medium），但無 AAD 的寫出能力自 AESCrypto 原語層刪除後，本地 provider 亦回
// crypto.ErrAADRequired——兩者不再互斥，故 nilAADRejected 旗標一併移除，
// 「空 AAD 一律被拒」改為三 provider 共用斷言。

type providerCase struct {
	name string
	// build 每次呼叫回傳一個**全新**的 provider（避免測試間共用捕獲狀態）
	build func(t *testing.T) crypto.KEKProvider
	// other 另一把不同金鑰的同型 provider（用於「他鑰解不開」斷言）
	other         func(t *testing.T) crypto.KEKProvider
	wantFormatTag string
	wantRefKind   string
}

func contractCases() []providerCase {
	return []providerCase{
		{
			name: "local-env",
			build: func(t *testing.T) crypto.KEKProvider {
				p, err := crypto.NewLocalAESKEKProvider(bytes.Repeat([]byte{1}, 32), crypto.KEKModeEnv)
				if err != nil {
					t.Fatalf("local env provider: %v", err)
				}
				return p
			},
			other: func(t *testing.T) crypto.KEKProvider {
				p, err := crypto.NewLocalAESKEKProvider(bytes.Repeat([]byte{2}, 32), crypto.KEKModeEnv)
				if err != nil {
					t.Fatalf("local env provider: %v", err)
				}
				return p
			},
			wantFormatTag: crypto.WrappedFormatLocal,
			wantRefKind:   crypto.KeyRefProviderLocal,
		},
		{
			name: "local-ui",
			build: func(t *testing.T) crypto.KEKProvider {
				p, err := crypto.NewLocalAESKEKProvider(bytes.Repeat([]byte{1}, 32), crypto.KEKModeUI)
				if err != nil {
					t.Fatalf("local ui provider: %v", err)
				}
				return p
			},
			other: func(t *testing.T) crypto.KEKProvider {
				p, err := crypto.NewLocalAESKEKProvider(bytes.Repeat([]byte{2}, 32), crypto.KEKModeUI)
				if err != nil {
					t.Fatalf("local ui provider: %v", err)
				}
				return p
			},
			wantFormatTag: crypto.WrappedFormatLocal,
			wantRefKind:   crypto.KeyRefProviderLocal,
		},
		{
			name: "kms",
			build: func(t *testing.T) crypto.KEKProvider {
				f := newFakeKMS()
				f.addKey(testKeyAlias, testKeyID, testKeyARN)
				return newTestProvider(t, f, testKeyAlias)
			},
			other: func(t *testing.T) crypto.KEKProvider {
				f := newFakeKMS()
				f.addKey(otherKeyAlias, otherKeyID, otherKeyARN)
				return newTestProvider(t, f, otherKeyAlias)
			},
			wantFormatTag: crypto.WrappedFormatKMS,
			wantRefKind:   crypto.KeyRefProviderKMS,
		},
	}
}

// TestKEKProviderContract 三 provider 共用的行為契約
func TestKEKProviderContract(t *testing.T) {
	ctx := context.Background()
	dek := bytes.Repeat([]byte{9}, 32)
	aad := crypto.DEKAAD("data", 1)

	for _, c := range contractCases() {
		t.Run(c.name, func(t *testing.T) {
			p := c.build(t)

			// 1. 帶 AAD 的往返（三模式共同期望）
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

			// 2. AAD 不符即失敗
			if _, err := p.Unwrap(ctx, wrapped, crypto.DEKAAD("data", 2)); err == nil {
				t.Fatal("AAD 不符 MUST 解包失敗")
			}

			// 3. 他鑰解不開
			if _, err := c.other(t).Unwrap(ctx, wrapped, aad); err == nil {
				t.Fatal("他鑰 MUST 解包失敗")
			}

			// 4. 身分面：格式標記與金鑰引用種類
			if p.FormatTag() != c.wantFormatTag {
				t.Fatalf("FormatTag want %q got %q", c.wantFormatTag, p.FormatTag())
			}
			if p.KeyRef().Provider != c.wantRefKind {
				t.Fatalf("KeyRef().Provider want %q got %q", c.wantRefKind, p.KeyRef().Provider)
			}
			if p.KeyRef().KeyID == "" {
				t.Fatal("KeyRef().KeyID 不得為空")
			}
			if p.Mode() == "" {
				t.Fatal("Mode() 不得為空")
			}

			// 5. ReEncrypt：由自身重包（同 provider）恆可解
			re, err := p.ReEncrypt(ctx, wrapped, aad, p)
			if err != nil {
				t.Fatalf("ReEncrypt: %v", err)
			}
			if again, err := p.Unwrap(ctx, re, aad); err != nil || !bytes.Equal(again, dek) {
				t.Fatalf("ReEncrypt 結果不可解或材料不符: %v", err)
			}

			// 6. **共同期望**：nil／空 AAD 於包裹與解包兩端一律被拒，且不產出任何值
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

// TestCrossProviderReEncryptInterchange 互換性的另一面：委託 provider 能接手
// 本地 provider 包裹的材料（A/B→C 重包的核心能力），且結果可由委託端解回。
func TestCrossProviderReEncryptInterchange(t *testing.T) {
	ctx := context.Background()
	dek := bytes.Repeat([]byte{5}, 32)
	aad := crypto.DEKAAD("data", 3)

	local, err := crypto.NewLocalAESKEKProvider(bytes.Repeat([]byte{1}, 32), crypto.KEKModeEnv)
	if err != nil {
		t.Fatalf("local: %v", err)
	}
	f := newFakeKMS()
	f.addKey(testKeyAlias, testKeyID, testKeyARN)
	kmsProvider := newTestProvider(t, f, testKeyAlias)

	localWrapped, err := local.Wrap(ctx, dek, aad)
	if err != nil {
		t.Fatalf("local Wrap: %v", err)
	}
	kmsWrapped, err := kmsProvider.ReEncrypt(ctx, localWrapped, aad, local)
	if err != nil {
		t.Fatalf("cross ReEncrypt: %v", err)
	}
	got, err := kmsProvider.Unwrap(ctx, kmsWrapped, aad)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("委託端解不回原材料: %v", err)
	}
	// 反向：本地 provider 亦能接手委託材料（C→A/B 的反向重包能力）
	backWrapped, err := local.ReEncrypt(ctx, kmsWrapped, aad, kmsProvider)
	if err != nil {
		t.Fatalf("reverse ReEncrypt: %v", err)
	}
	if back, err := local.Unwrap(ctx, backWrapped, aad); err != nil || !bytes.Equal(back, dek) {
		t.Fatalf("本地端解不回原材料: %v", err)
	}
}
