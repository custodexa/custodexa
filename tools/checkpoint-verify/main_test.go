package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
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

// ── 第三版、第四版（帳本區間四欄、perm 鍵）──────────────────────────────

// 與產品端 TestCheckpointCanonicalGoldenV4 第一串逐位元組相同（兩邊程式碼不共用）
const goldenV4 = `{"seq":1,"id_from":1,"id_to":0,"row_count":0,"agg_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","agg_scheme":"cp-agg-v4","prev_checkpoint_hash":"anchor","min_created_at_us":null,"state":[{"table":"user_roles","hash":"04041a39e9767c77f7fc63538c94ad54c941e29bd62a274dfd5f8d26ddecbc95","count":0}],"role_state_reconciled":null,"max_created_at_us":null,"sealed_at_us":0,"signing_key_version":1,"tool_call_id_from":1,"tool_call_id_to":0,"tool_call_row_count":0,"tool_call_agg_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","perm":{"format":2,"model":1,"catalog":"cccccccccccccccccccccccccccccccc","snapshot_digest":"e9b09ee485bf6583fa9f866aae228c908aa2bd2ae1c28fb2db6abb689f48399e","event_seq":1,"event_head":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","reconciled":null,"origin":true}}`

func u64Ptr(v uint64) *uint64 { return &v }

func v4Checkpoint() checkpoint {
	empty := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	return checkpoint{Seq: 1, IDFrom: 1, IDTo: 0, AggHash: empty, AggScheme: schemeV4, PrevCheckpointHash: "anchor",
		SealedAt: "1970-01-01T00:00:00Z", SigningKeyVersion: 1, RoleStateSnapshot: strPtr(`{"user_roles":[]}`),
		ToolCallIDFrom: u64Ptr(1), ToolCallIDTo: u64Ptr(0), ToolCallRowCount: i64Ptr(0), ToolCallAggHash: strPtr(empty),
		permPresent: true,
		// wire 上的鍵序與規格不同：重建依固定鍵序，不依 wire 順序
		permRaw: []byte(`{"origin":true,"reconciled":null,"format":2,"model":1,"catalog":"cccccccccccccccccccccccccccccccc","snapshot_digest":"e9b09ee485bf6583fa9f866aae228c908aa2bd2ae1c28fb2db6abb689f48399e","event_seq":1,"event_head":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}`)}
}

func TestSignBytesV4Golden(t *testing.T) {
	got, err := signBytes(v4Checkpoint())
	if err != nil {
		t.Fatalf("signBytes: %v", err)
	}
	if string(got) != goldenV4 {
		t.Fatalf("v4 位元組不符\n got: %s\nwant: %s", got, goldenV4)
	}
	cp := v4Checkpoint()
	cp.permRaw = []byte("null")
	got, err = signBytes(cp)
	if err != nil || !strings.HasSuffix(string(got), `"perm":null}`) {
		t.Fatalf("perm:null 重建：%s %v", got, err)
	}
	// v3：同一份欄位去掉 perm、版本改 v3，帳本四欄照寫
	cp = v4Checkpoint()
	cp.AggScheme, cp.permPresent, cp.permRaw = schemeV3, false, nil
	got, err = signBytes(cp)
	if err != nil || !strings.HasSuffix(string(got), `"tool_call_agg_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}`) || strings.Contains(string(got), "perm") {
		t.Fatalf("v3 重建：%s %v", got, err)
	}
}

func TestPermWireRejects(t *testing.T) {
	ok := `{"format":2,"model":1,"catalog":"cccccccccccccccccccccccccccccccc","snapshot_digest":"` + strings.Repeat("a", 64) + `","event_seq":7,"event_head":"` + strings.Repeat("b", 64) + `","reconciled":false,"origin":false}`
	if _, err := parsePermWire([]byte(ok)); err != nil {
		t.Fatalf("合法物件被拒：%v", err)
	}
	for name, body := range map[string]string{
		"重複鍵":            strings.Replace(ok, `"model":1,`, `"model":1,"model":1,`, 1),
		"未知鍵":            strings.Replace(ok, `"model":1,`, `"model":1,"extra":1,`, 1),
		"缺鍵":             strings.Replace(ok, `"model":1,`, ``, 1),
		"前導零":            strings.Replace(ok, `"event_seq":7`, `"event_seq":07`, 1),
		"小數":             strings.Replace(ok, `"event_seq":7`, `"event_seq":7.0`, 1),
		"指數":             strings.Replace(ok, `"event_seq":7`, `"event_seq":7e0`, 1),
		"負號":             strings.Replace(ok, `"event_seq":7`, `"event_seq":-7`, 1),
		"超出 int64":       strings.Replace(ok, `"event_seq":7`, `"event_seq":9223372036854775808`, 1),
		"大寫 hex":         strings.Replace(ok, strings.Repeat("a", 64), strings.Repeat("A", 64), 1),
		"空字串":            strings.Replace(ok, strings.Repeat("b", 64), "", 1),
		"origin 帶非 1 序號": strings.Replace(ok, `"origin":false`, `"origin":true`, 1),
		"reconciled 非布林": strings.Replace(ok, `"reconciled":false`, `"reconciled":"no"`, 1),
		"非物件":            `[1]`,
	} {
		if _, err := parsePermWire([]byte(body)); err == nil {
			t.Errorf("%s：應拒絕", name)
		}
	}
	// format 值域＝已支援的快照格式集合（與產品端同一集合），不是「任意正整數」
	for _, f := range []string{"1", "2"} {
		p, err := parsePermWire([]byte(strings.Replace(ok, `"format":2`, `"format":`+f, 1)))
		if err != nil || p.format != f {
			t.Errorf("已支援格式 %s 應接受：%v", f, err)
		}
	}
	for _, f := range []string{"0", "3", "999", "18446744073709551616"} {
		_, err := parsePermWire([]byte(strings.Replace(ok, `"format":2`, `"format":`+f, 1)))
		if err == nil {
			t.Errorf("format %s：應拒絕", f)
			continue
		}
		if f != "0" && !strings.Contains(err.Error(), "不是本工具支援的權限快照格式版本") {
			t.Errorf("format %s 的拒絕原因應指向格式集合：%v", f, err)
		}
	}
	if p, err := parsePermWire([]byte("null")); err != nil || p != nil {
		t.Fatalf("null：%v %v", p, err)
	}
	if _, err := parsePermWire([]byte(strings.Replace(ok, `"event_seq":7`, `"event_seq":9223372036854775807`, 1))); err != nil {
		t.Fatalf("int64 上界應接受：%v", err)
	}
}

// ── 直接餵產品 API 的實際輸出（testdata 由 backend 的 TestCheckpointListPermWire 匯出）──

func fixtureKey(t *testing.T) string {
	raw, err := os.ReadFile("testdata/api-public-key.json")
	if err != nil {
		t.Fatal(err)
	}
	var ke keyEnvelope
	if err := json.Unmarshal(raw, &ke); err != nil {
		t.Fatal(err)
	}
	return ke.Data.PublicKey
}

func runTool(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String() + errb.String()
}

// editFixture 以通用 JSON 改寫 API 輸出中指定 seq 的一列，寫成暫存檔
func editFixture(t *testing.T, seq float64, edit func(item map[string]json.RawMessage)) string {
	t.Helper()
	raw, err := os.ReadFile("testdata/api-list-v3-v4.json")
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Data struct {
			Items []map[string]json.RawMessage `json:"items"`
			Total int64                        `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	for _, it := range env.Data.Items {
		var s float64
		_ = json.Unmarshal(it["seq"], &s)
		if s == seq {
			edit(it)
		}
	}
	b, _ := json.Marshal(env)
	p := filepath.Join(t.TempDir(), "edited.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAPIFixtureV3V4(t *testing.T) {
	key := fixtureKey(t)
	in := "testdata/api-list-v3-v4.json"
	code, out := runTool(t, "-input", in, "-pubkey", key)
	if code != 0 || !strings.Contains(out, "結果：全數通過") {
		t.Fatalf("產品 API 實際輸出應全數通過（code=%d）\n%s", code, out)
	}
	if !strings.Contains(out, "cp-agg-v4 3 筆") || !strings.Contains(out, "cp-agg-v3 1 筆") {
		t.Fatalf("版本計數不符：\n%s", out)
	}
	for _, tamper := range []string{"payload-bit", "row-count", "signature-bit", "perm-origin", "scheme-downgrade"} {
		code, out := runTool(t, "-input", in, "-pubkey", key, "-tamper", tamper)
		if code != 1 || !strings.Contains(out, "FAIL") {
			t.Errorf("-tamper %s 應 FAIL（code=%d）\n%s", tamper, code, out)
		}
	}
	t.Run("第四版列缺 perm 鍵：載荷無法重建，不自行補 null", func(t *testing.T) {
		p := editFixture(t, 2, func(it map[string]json.RawMessage) { delete(it, "perm") })
		code, out := runTool(t, "-input", p, "-pubkey", key)
		if code != 1 || !strings.Contains(out, "載荷無法重建") {
			t.Fatalf("code=%d\n%s", code, out)
		}
	})
	t.Run("第三版列帶 perm 鍵：載荷無法重建", func(t *testing.T) {
		p := editFixture(t, 1, func(it map[string]json.RawMessage) { it["perm"] = json.RawMessage("null") })
		code, out := runTool(t, "-input", p, "-pubkey", key)
		if code != 1 || !strings.Contains(out, "載荷無法重建") {
			t.Fatalf("code=%d\n%s", code, out)
		}
	})
	t.Run("改 perm 的對帳結果：簽章 FAIL", func(t *testing.T) {
		p := editFixture(t, 4, func(it map[string]json.RawMessage) {
			it["perm"] = json.RawMessage(strings.Replace(string(it["perm"]), `"reconciled":true`, `"reconciled":false`, 1))
		})
		code, out := runTool(t, "-input", p, "-pubkey", key)
		if code != 1 || !strings.Contains(out, "簽章=FAIL") {
			t.Fatalf("code=%d\n%s", code, out)
		}
	})
	t.Run("perm.format 改成未支援的 999：載荷無法重建，不誤報成簽章 FAIL", func(t *testing.T) {
		p := editFixture(t, 4, func(it map[string]json.RawMessage) {
			it["perm"] = json.RawMessage(strings.Replace(string(it["perm"]), `"format":2`, `"format":999`, 1))
		})
		code, out := runTool(t, "-input", p, "-pubkey", key)
		if code != 1 || !strings.Contains(out, "載荷無法重建") || !strings.Contains(out, "format 999") || strings.Contains(out, "簽章=FAIL") {
			t.Fatalf("code=%d\n%s", code, out)
		}
	})
	t.Run("perm.format 改成已支援的舊格式 1：照常重建，簽章 FAIL", func(t *testing.T) {
		p := editFixture(t, 4, func(it map[string]json.RawMessage) {
			it["perm"] = json.RawMessage(strings.Replace(string(it["perm"]), `"format":2`, `"format":1`, 1))
		})
		code, out := runTool(t, "-input", p, "-pubkey", key)
		if code != 1 || !strings.Contains(out, "簽章=FAIL") || strings.Contains(out, "載荷無法重建") {
			t.Fatalf("code=%d\n%s", code, out)
		}
	})
	t.Run("未知版本：停止並回報（離開碼 2）", func(t *testing.T) {
		p := editFixture(t, 3, func(it map[string]json.RawMessage) { it["agg_scheme"] = json.RawMessage(`"cp-agg-v99"`) })
		code, out := runTool(t, "-input", p, "-pubkey", key)
		if code != 2 || !strings.Contains(out, "非本工具已知的載荷版本") {
			t.Fatalf("code=%d\n%s", code, out)
		}
	})
}
