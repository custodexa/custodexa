package crypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// KeyRef 與本地 provider 的釘子（kek-provider-modularization D4／D9）。

// D9 免遷移三條釘子（opus H5 修正版）：AES-GCM 隨機 nonce 使「位元相同」
// 物理上不可滿足，故驗收改為 (a) KeyRef 完全相同、(b) 互解、(c) 格式標記相同。
func TestLocalProviderEnvUIEquivalence(t *testing.T) {
	material := testKey(5)
	envP, err := NewLocalAESKEKProvider(material, KEKModeEnv)
	if err != nil {
		t.Fatalf("env provider: %v", err)
	}
	uiP, err := NewLocalAESKEKProvider(material, KEKModeUI)
	if err != nil {
		t.Fatalf("ui provider: %v", err)
	}
	ctx := context.Background()
	dek := testKey(9)

	// (a) 同材料下兩模式的 KeyRef **完全相同**（逐欄）
	if envP.KeyRef() != uiP.KeyRef() {
		t.Fatalf("KeyRef 不相同：env=%+v ui=%+v", envP.KeyRef(), uiP.KeyRef())
	}
	if envP.KeyRef().Provider != KeyRefProviderLocal {
		t.Fatalf("KeyRef.Provider = %q，env／ui MUST 皆映射為 local", envP.KeyRef().Provider)
	}
	if !envP.KeyRef().Equal(uiP.KeyRef()) {
		t.Fatal("KeyRef.Equal 應為真（相等性不含執行期模式）")
	}

	// (b) 互解：A 包裹之值 B 可解、B 包裹之值 A 可解
	aad := DEKAAD("data", 1)
	wEnv, err := envP.Wrap(ctx, dek, aad)
	if err != nil {
		t.Fatalf("env Wrap: %v", err)
	}
	wUI, err := uiP.Wrap(ctx, dek, aad)
	if err != nil {
		t.Fatalf("ui Wrap: %v", err)
	}
	got, err := uiP.Unwrap(ctx, wEnv, aad)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("ui 解不開 env 包裹之值: err=%v", err)
	}
	got, err = envP.Unwrap(ctx, wUI, aad)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("env 解不開 ui 包裹之值: err=%v", err)
	}

	// (c) 格式標記相同（皆為本地形式）
	if envP.FormatTag() != uiP.FormatTag() || envP.FormatTag() != WrappedFormatLocal {
		t.Fatalf("格式標記不一致：env=%q ui=%q", envP.FormatTag(), uiP.FormatTag())
	}

	// 執行期模式的差異僅出現在模式存取器（供清冊呈現與稽核對照）
	if envP.Mode() != KEKModeEnv || uiP.Mode() != KEKModeUI {
		t.Fatal("模式存取器應各自回報執行期模式")
	}
}

// KeyRef.Provider 為三值，SHALL NOT 取 env／ui
func TestKeyRefProviderIsThreeValued(t *testing.T) {
	for _, mode := range []string{KEKModeEnv, KEKModeUI} {
		p, err := NewLocalAESKEKProvider(testKey(1), mode)
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		switch p.KeyRef().Provider {
		case KeyRefProviderLocal, KeyRefProviderKMS, KeyRefProviderHSM:
		default:
			t.Fatalf("KeyRef.Provider %q 不在三值域內", p.KeyRef().Provider)
		}
		if p.KeyRef().Provider == mode {
			t.Fatalf("KeyRef.Provider 取到執行期模式 %q：env／ui 的 KeyRef 將不可能相同", mode)
		}
	}
}

// AAD 綁定：不同 aad 解包必失敗（DEK 層跨 slot 搬移的防線）
func TestLocalProviderAADBinding(t *testing.T) {
	p, _ := NewLocalAESKEKProvider(testKey(3), KEKModeEnv)
	ctx := context.Background()
	wrapped, err := p.Wrap(ctx, testKey(9), DEKAAD("data", 3))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if _, err := p.Unwrap(ctx, wrapped, DEKAAD("audit_integrity", 1)); err == nil {
		t.Fatal("以不同 slot 的 AAD 解包應失敗（跨 slot 搬移防線）")
	}
	// 空 AAD 於原語層即被拒（ErrAADRequired，P2 M1）——連 GCM 驗證都不會走到
	if _, err := p.Unwrap(ctx, wrapped, nil); !errors.Is(err, ErrAADRequired) {
		t.Fatalf("不帶 AAD 解包 MUST 回 ErrAADRequired，得 %v", err)
	}
	if _, err := p.Unwrap(ctx, wrapped, DEKAAD("data", 3)); err != nil {
		t.Fatalf("同 AAD 應可解: %v", err)
	}
}

// ReEncrypt 預設實作：由來源 provider 解包後以本 provider 重新包裹
func TestReEncryptDefault(t *testing.T) {
	from, _ := NewLocalAESKEKProvider(testKey(1), KEKModeEnv)
	to, _ := NewLocalAESKEKProvider(testKey(2), KEKModeUI)
	ctx := context.Background()
	dek := testKey(9)
	aad := DEKAAD("data", 1)

	w1, _ := from.Wrap(ctx, dek, aad)
	w2, err := to.ReEncrypt(ctx, w1, aad, from)
	if err != nil {
		t.Fatalf("ReEncrypt: %v", err)
	}
	got, err := to.Unwrap(ctx, w2, aad)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("重加密後材料不符: err=%v", err)
	}
	if _, err := from.Unwrap(ctx, w2, aad); err == nil {
		t.Fatal("重加密後不應仍可由來源 KEK 解開")
	}
}

// wrapped_key 前綴恆強制（release-transitional-cleanup D5）：
// 寫端一律 `wk:2:`、讀端於解包前拒收無前綴與判別子 `1`。
func TestWrappedKeyPrefixAlwaysEnforced(t *testing.T) {
	raw := []byte("wrapped-material-bytes")

	t.Run("全部格式標記一律編為帶 AAD 的 wk:2", func(t *testing.T) {
		for _, tag := range []string{WrappedFormatLocal, WrappedFormatKMS, WrappedFormatHSM} {
			v, err := EncodeWrappedKey(tag, raw)
			if err != nil {
				t.Fatalf("%s: %v", tag, err)
			}
			if !strings.HasPrefix(v, "wk:2:"+tag+":") || !IsAADBoundWrapped(v) {
				t.Fatalf("格式 %s 未編為帶 AAD 的 wk:2：%q", tag, v)
			}
			gotTag, got, err := ParseWrappedKey(v)
			if err != nil || gotTag != tag || !bytes.Equal(got, raw) {
				t.Fatalf("%s roundtrip 失敗: tag=%q err=%v", tag, gotTag, err)
			}
		}
	})

	t.Run("無前綴裸 base64 於解包前 fail-close 且指明重建", func(t *testing.T) {
		bare := base64.StdEncoding.EncodeToString(raw)
		_, _, err := ParseWrappedKey(bare)
		if err == nil {
			t.Fatal("無前綴值 MUST 被拒收（發佈前過渡格式）")
		}
		if !errors.Is(err, ErrWrappedKeyPreRelease) || !errors.Is(err, ErrWrappedKeyFormat) {
			t.Fatalf("錯誤未可辨識為發佈前過渡格式：%v", err)
		}
		if !strings.Contains(err.Error(), "重建") {
			t.Fatalf("錯誤訊息 MUST 指明須重建資料庫：%v", err)
		}
	})

	t.Run("判別子 1 於解包前 fail-close", func(t *testing.T) {
		v1 := "wk:1:" + WrappedFormatLocal + ":" + base64.StdEncoding.EncodeToString(raw)
		_, _, err := ParseWrappedKey(v1)
		if err == nil {
			t.Fatal("判別子 1（無 AAD 包裹）MUST 被拒收")
		}
		if !errors.Is(err, ErrWrappedKeyPreRelease) {
			t.Fatalf("錯誤未可辨識為發佈前過渡格式：%v", err)
		}
	})

	t.Run("未知格式標記與未知版本於解包前即判定不符", func(t *testing.T) {
		if _, _, err := ParseWrappedKey("wk:2:vault:aGk="); err == nil {
			t.Fatal("未知格式標記應回格式錯，而非落入籠統 GCM 失敗")
		}
		if _, _, err := ParseWrappedKey("wk:3:local:aGk="); err == nil {
			t.Fatal("未知 wrapped 格式版本應於解包前即回格式錯")
		}
		if _, err := EncodeWrappedKey("vault", raw); err == nil {
			t.Fatal("未知格式標記不得可編碼")
		}
	})
}

// TestWrappedKeyNoAADFallback AAD 在場性由格式版本承載、SHALL NOT 由讀端試錯判定
// （D5 定案 B2）：`wk:2:` 列以**無 AAD** 解包 MUST 失敗且 MUST NOT 回退。
//
// 這是「無 fallback」的核心回歸釘子。判別子 `1` 的產出器（AddLocalWrappedPrefix／
// RelabelAsAADBound）已刪除，故此處以手工字面構造該類值，證明**即使有人以
// DB 直寫塞入**，讀端仍於解包前拒收。
func TestWrappedKeyNoAADFallback(t *testing.T) {
	kek, err := NewLocalAESKEKProvider(testKey(1), KEKModeEnv)
	if err != nil {
		t.Fatalf("kek: %v", err)
	}
	ctx := context.Background()
	dek := testKey(7)
	aad := DEKAAD("data", 1)

	rawV2, err := kek.Wrap(ctx, dek, aad)
	if err != nil {
		t.Fatalf("wrap aad: %v", err)
	}
	v2, err := EncodeWrappedKey(kek.FormatTag(), rawV2)
	if err != nil {
		t.Fatalf("encode v2: %v", err)
	}
	_, parsed, err := ParseWrappedKey(v2)
	if err != nil {
		t.Fatalf("parse v2: %v", err)
	}
	if got, err := kek.Unwrap(ctx, parsed, aad); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("wk:2 以宣告的 AAD 解包應成功: err=%v", err)
	}
	if _, err := kek.Unwrap(ctx, parsed, nil); err == nil {
		t.Fatal("wk:2 列以無 AAD 解包竟成功：AAD 在場性被試錯繞過（無 fallback 立約失效）")
	}

	// DB 直寫塞入的無 AAD 包裹（判別子 1）：讀端於解包前即拒，材料永無機會被解。
	// 無 AAD 的包裹能力已於 P2 M1 自原語層刪除，故此材料由測試層 stdlib 助手封出
	rawV1 := sealNoAAD(t, testKey(1), dek)
	forged := "wk:1:" + kek.FormatTag() + ":" + base64.StdEncoding.EncodeToString(rawV1)
	if _, _, err := ParseWrappedKey(forged); !errors.Is(err, ErrWrappedKeyPreRelease) {
		t.Fatalf("手工塞入的 wk:1 MUST 於解包前被拒：err=%v", err)
	}
	// 改標為 wk:2 只能造成解包失敗（DoS），MUST NOT 讓無 AAD blob 通過 AAD 驗證
	relabelled := "wk:2:" + kek.FormatTag() + ":" + base64.StdEncoding.EncodeToString(rawV1)
	_, relabelledRaw, err := ParseWrappedKey(relabelled)
	if err != nil {
		t.Fatalf("parse relabelled: %v", err)
	}
	if _, err := kek.Unwrap(ctx, relabelledRaw, aad); err == nil {
		t.Fatal("把無 AAD 材料改標為 wk:2 後竟可解：前綴被當成可信認證資料")
	}
}

// enc:a1 密文格式與未知 scheme 的處置（D5）
func TestEnvelopeAADScheme(t *testing.T) {
	raw := []byte("nonce-and-ct")
	s, err := EncodeEnvelopeAAD(AADSchemeA1, 2, raw)
	if err != nil {
		t.Fatalf("EncodeEnvelopeAAD: %v", err)
	}
	if !strings.HasPrefix(s, "enc:a1:v2:") {
		t.Fatalf("格式不符: %s", s)
	}
	scheme, ver, got, ok, err := ParseEnvelopeFull(s)
	if err != nil || !ok || scheme != AADSchemeA1 || ver != 2 || !bytes.Equal(got, raw) {
		t.Fatalf("roundtrip 失敗: scheme=%q ver=%d ok=%v err=%v", scheme, ver, ok, err)
	}

	// 未知 enc:* scheme MUST 報格式錯而非落入 legacy 路徑（codex info）
	for _, bad := range []string{"enc:a2:v1:aGk=", "enc:x:v1:aGk=", "enc:zz:v1:aGk="} {
		if _, _, _, ok, err := ParseEnvelopeFull(bad); err == nil || ok {
			t.Fatalf("未知 scheme %q 應回格式錯（ok=%v err=%v）", bad, ok, err)
		}
	}

	// 舊入口 ParseEnvelope 不得把帶 AAD 密文當無 AAD 解
	if _, _, ok, err := ParseEnvelope(s); ok || err == nil {
		t.Fatal("ParseEnvelope 應拒絕帶 AAD 方案的密文")
	}

	// **無 AAD 編碼能力已刪除**（release-transitional-cleanup D1）：
	// 空 scheme MUST 回錯，SHALL NOT 退回 `enc:v<N>` 形式
	if out, err := EncodeEnvelopeAAD(AADSchemeNone, 3, raw); err == nil {
		t.Fatalf("空 scheme 竟編碼成功（無 AAD 寫出能力應已在建構上消失）：%q", out)
	}
	for _, bad := range []string{"a2", "x"} {
		if _, err := EncodeEnvelopeAAD(bad, 3, raw); err == nil {
			t.Fatalf("未知 scheme %q 不得可編碼", bad)
		}
	}
	// 解析能力仍在（殘值盤點與引用掃描的判定基礎）
	if _, ver, _, ok, err := ParseEnvelopeFull("enc:v3:bm9uY2UtYW5kLWN0"); !ok || err != nil || ver != 3 {
		t.Fatalf("enc:v 解析能力 MUST 保留: ok=%v ver=%d err=%v", ok, ver, err)
	}
}

// AAD 組成不含任何可變識別符（kek_id 已剔除）
func TestDEKAADHasNoMutableIdentifier(t *testing.T) {
	a := string(DEKAAD("data", 3))
	if a != "custodexa|wrapped-dek|v1|4:data|1:3" {
		t.Fatalf("DEK 層 AAD 組成漂移: %q", a)
	}
	if strings.Contains(a, "kek") {
		t.Fatal("DEK 層 AAD MUST NOT 含 KEK 識別（與 kek_id 正規化改寫互斥）")
	}
	ref := CipherRef{Table: "assets", Column: "password_enc"}
	if string(ref.AAD()) != "custodexa|data-field|v1|6:assets|12:password_enc" {
		t.Fatalf("資料層 AAD 組成漂移: %q", ref.AAD())
	}
	// AAD 裁決 A2：資料層 AAD **不綁主鍵**——同表同欄的兩列共用同一份 AAD。
	// 這是明載的信任邊界（見 CipherRef 文件註），不是缺陷；此處釘住該事實，
	// 使日後若改回綁 pk 必須連同本測試與 create 路徑一併重新裁決。
	if string((CipherRef{Table: "assets", Column: "password_enc"}).AAD()) !=
		string(ref.AAD()) {
		t.Fatal("同表同欄的 AAD 不應因列而異（A2 定案：不綁主鍵）")
	}
}

// TestCanonicalAADIsInjective AAD 編碼 SHALL NOT 以未逸出的字串裸串接：
// `("ab","c")` 與 `("a","bc")` 裸串接會得到同一份 AAD，使「跨欄搬移」的防護
// 在特定命名下靜默失效。長度前綴使編碼為單射。
func TestCanonicalAADIsInjective(t *testing.T) {
	a := (CipherRef{Table: "ab", Column: "c"}).AAD()
	b := (CipherRef{Table: "a", Column: "bc"}).AAD()
	if bytes.Equal(a, b) {
		t.Fatalf("AAD 編碼發生維度串接碰撞: %q == %q", a, b)
	}
	// DEK 層同理（purpose 與 version 之間）
	if bytes.Equal(DEKAAD("data1", 1), DEKAAD("data", 11)) {
		t.Fatal("DEK 層 AAD 編碼發生維度串接碰撞")
	}
	// 兩層命名空間互不重疊：資料層密文的 AAD 不可能等於任何 DEK 層 AAD
	if bytes.Equal((CipherRef{Table: "data", Column: "1"}).AAD(), DEKAAD("data", 1)) {
		t.Fatal("資料層與 DEK 層 AAD 命名空間重疊")
	}
}

// TestEncodeWrappedKeyHasNoUnboundBranch 「寫入端不可能產出非終態 wrapped 值」
// 的**建構事實**（release-transitional-cleanup D5）：EncodeWrappedKey 的簽章
// 不再有 AAD 在場性與階段參數，故不存在任何可產出裸 base64 或 `wk:1` 的呼叫形式。
//
// 缺陷史：原本第三參數是裸 `bool`、第四是階段，本地＋相容窗＋false 即產出
// 無前綴無 AAD 的裸值——「終態格式」只存在於註解裡。
func TestEncodeWrappedKeyHasNoUnboundBranch(t *testing.T) {
	raw := []byte("wrapped-material-bytes")
	for _, tag := range []string{WrappedFormatLocal, WrappedFormatKMS, WrappedFormatHSM} {
		v, err := EncodeWrappedKey(tag, raw)
		if err != nil {
			t.Fatalf("格式 %s 應可編碼: %v", tag, err)
		}
		if !IsAADBoundWrapped(v) {
			t.Fatalf("格式 %s MUST 編為帶 AAD 的 wk:2，得 %q", tag, v)
		}
	}
}
