package main

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

// 離線驗證器的 canonical 重建測試。
//
// **本檔的價值在於它是獨立的第二條路徑**：這些 golden 字串必須與產品端
// `TestCheckpointCanonicalGolden`／`TestCheckpointCanonicalGoldenV2` 的字串
// 逐位元組相同，而兩邊的程式碼完全沒有共用。任一邊改了編碼，這裡就會紅。

const (
	goldenV1 = `{"seq":7,"id_from":4023,"id_to":5000,"row_count":978,` +
		`"agg_hash":"1111111111111111111111111111111111111111111111111111111111111111",` +
		`"agg_scheme":"cp-agg-v1",` +
		`"prev_checkpoint_hash":"2222222222222222222222222222222222222222222222222222222222222222",` +
		`"min_created_at_us":1786496523456789,"max_created_at_us":1786500184567890,` +
		`"sealed_at_us":1786500300000000,"signing_key_version":1}`

	// v2 的 state 摘要＝SHA-256( 大端 8 bytes 長度 ‖ `[[1,1],[2,3]]` )
	goldenV2 = `{"seq":7,"id_from":4023,"id_to":5000,"row_count":978,` +
		`"agg_hash":"1111111111111111111111111111111111111111111111111111111111111111",` +
		`"agg_scheme":"cp-agg-v2",` +
		`"prev_checkpoint_hash":"2222222222222222222222222222222222222222222222222222222222222222",` +
		`"min_created_at_us":1786496523456789,` +
		`"state":[{"table":"user_roles","hash":"%HASH%","count":2}],` +
		`"role_state_reconciled":null,` +
		`"max_created_at_us":1786500184567890,` +
		`"sealed_at_us":1786500300000000,"signing_key_version":1}`
)

func strPtr(s string) *string { return &s }
func i64Ptr(v int64) *int64   { return &v }

func baseCheckpoint() checkpoint {
	minAt := "2026-08-12T01:02:03.456789Z"
	maxAt := "2026-08-12T02:03:04.567890Z"
	return checkpoint{
		Seq: 7, IDFrom: 4023, IDTo: 5000, RowCount: 978,
		AggHash:            "1111111111111111111111111111111111111111111111111111111111111111",
		AggScheme:          schemeV1,
		PrevCheckpointHash: "2222222222222222222222222222222222222222222222222222222222222222",
		MinCreatedAt:       &minAt,
		MaxCreatedAt:       &maxAt,
		SealedAt:           "2026-08-12T02:05:00Z",
		SigningKeyVersion:  1,
	}
}

func TestSignBytesV1Golden(t *testing.T) {
	got, err := signBytes(baseCheckpoint())
	if err != nil {
		t.Fatalf("signBytes: %v", err)
	}
	if string(got) != goldenV1 {
		t.Fatalf("v1 位元組不符\n got: %s\nwant: %s", got, goldenV1)
	}
}

func TestSignBytesV2Golden(t *testing.T) {
	cp := baseCheckpoint()
	cp.AggScheme = schemeV2
	cp.RoleStateSnapshot = strPtr(`{"user_roles":[[1,1],[2,3]]}`)
	cp.RoleStateHash = strPtr("這一欄刻意與快照不符：載荷取的是由快照本體現算的摘要")
	cp.RoleStateCount = i64Ptr(999)

	got, err := signBytes(cp)
	if err != nil {
		t.Fatalf("signBytes: %v", err)
	}
	want := strings.Replace(goldenV2, "%HASH%", stateHash([]byte(`[[1,1],[2,3]]`)), 1)
	if string(got) != want {
		t.Fatalf("v2 位元組不符\n got: %s\nwant: %s", got, want)
	}
	if strings.Contains(string(got), "999") {
		t.Error("載荷取了 role_state_count 欄而非由快照本體現算")
	}
}

// TestSignBytesV2ReconciledTriState 對帳結果三態各自的寫法
func TestSignBytesV2ReconciledTriState(t *testing.T) {
	yes, no := true, false
	for _, c := range []struct {
		name string
		val  *bool
		want string
	}{
		{"未對帳", nil, `"role_state_reconciled":null`},
		{"相符", &yes, `"role_state_reconciled":true`},
		{"不符", &no, `"role_state_reconciled":false`},
	} {
		t.Run(c.name, func(t *testing.T) {
			cp := baseCheckpoint()
			cp.AggScheme = schemeV2
			cp.RoleStateSnapshot = strPtr(`{"user_roles":[]}`)
			cp.RoleStateReconciled = c.val
			got, err := signBytes(cp)
			if err != nil {
				t.Fatalf("signBytes: %v", err)
			}
			if !strings.Contains(string(got), c.want) {
				t.Fatalf("載荷未含 %s\n%s", c.want, got)
			}
		})
	}
}

// TestSignBytesRejectsUnknownScheme 未知載荷版本不猜形狀
func TestSignBytesRejectsUnknownScheme(t *testing.T) {
	cp := baseCheckpoint()
	cp.AggScheme = "cp-agg-v99"
	if _, err := signBytes(cp); err == nil {
		t.Fatal("未知 agg_scheme 應拒驗：猜一個形狀去驗會把版本問題偽裝成竄改")
	}
}

// TestSignBytesV2FallsBackToHashColumn 快照本體不可得時退回摘要欄
func TestSignBytesV2FallsBackToHashColumn(t *testing.T) {
	cp := baseCheckpoint()
	cp.AggScheme = schemeV2
	cp.RoleStateHash = strPtr("abcd")
	cp.RoleStateCount = i64Ptr(2)

	entries, fellBack, err := stateEntries(cp)
	if err != nil {
		t.Fatalf("stateEntries: %v", err)
	}
	if !fellBack {
		t.Fatal("未標記退回摘要欄：報表必須說清楚驗的是摘要未被改、不是快照未被改")
	}
	if len(entries) != 1 || entries[0].hash != "abcd" || entries[0].count != 2 {
		t.Fatalf("退回結果 = %+v", entries)
	}

	// 兩欄皆缺＝無從重建，必須報錯而非以空 state 放行
	cp.RoleStateHash = nil
	if _, _, err := stateEntries(cp); err == nil {
		t.Fatal("v2 缺快照與摘要欄時應報錯")
	}
}

// TestVerifyRoundTrip 以真的 Ed25519 金鑰簽 v2 載荷並驗回來，
// 再改一個位元證明會失敗（驗證器真的會拒絕）
func TestVerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	cp := baseCheckpoint()
	cp.AggScheme = schemeV2
	cp.RoleStateSnapshot = strPtr(`{"user_roles":[[1,1],[2,3]]}`)

	signed, err := signBytes(cp)
	if err != nil {
		t.Fatalf("signBytes: %v", err)
	}
	sig := ed25519.Sign(priv, signed)
	if !ed25519.Verify(pub, signed, sig) {
		t.Fatal("自簽自驗失敗")
	}

	// 改快照本體一個位元組（把 2 號帳號的角色由 3 改成 1）＝簽章必然驗不過
	cp.RoleStateSnapshot = strPtr(`{"user_roles":[[1,1],[2,1]]}`)
	tampered, err := signBytes(cp)
	if err != nil {
		t.Fatalf("signBytes: %v", err)
	}
	if ed25519.Verify(pub, tampered, sig) {
		t.Fatal("改了快照本體仍驗過：快照未落在簽章涵蓋範圍內")
	}
}

// TestLinkHashUnaffectedByEncoding 鏈接雜湊沿用同一份重建位元組
func TestLinkHashUnaffectedByEncoding(t *testing.T) {
	cp := baseCheckpoint()
	signed, err := signBytes(cp)
	if err != nil {
		t.Fatalf("signBytes: %v", err)
	}
	h1, err := linkHash(signed, "c2ln")
	if err != nil {
		t.Fatalf("linkHash: %v", err)
	}
	h2, err := linkHash(signed, "c2ln")
	if err != nil {
		t.Fatalf("linkHash: %v", err)
	}
	if h1 != h2 || len(h1) != 64 {
		t.Fatalf("鏈接雜湊 = %s / %s", h1, h2)
	}
}
