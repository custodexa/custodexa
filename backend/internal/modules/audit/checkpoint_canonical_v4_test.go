package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// 第四版載荷的位元組與重建規則。
//
// 本檔釘三件事：v4 載荷的位元組（帶 perm 物件、perm 為 null、對帳結果為 false 三種）、
// 以手寫字串重建同一串位元組（不經 payload struct 與 stateHash），以及由欄位重建 perm 的
// 唯一規則在每一種清空／改壞之下的去向（簽章驗不過 vs 載荷建不出）。

const v4TestSnapshot = `{"format":"permission_state","v":2,"meta":{"model":1,"catalog":"cccccccccccccccccccccccccccccccc","version":3,"generation_fp":"","restore_op_id":""},"sets":{"roles":[],"user_roles":[[2,1,"global","manual"]],"group_roles":[],"binding_nodes":[],"nodes":[],"role_maps":[],"group_maps":[],"members":[],"groups":[],"principals":[],"role_defs":[],"role_perms":[]}}`

// v4 帶附證的檢查點（起點：event_seq=1、origin=true、reconciled=null）。
func v4CanonicalFixture() *model.AuditCheckpoint {
	cp := v3CanonicalFixture()
	cp.AggScheme = model.AggSchemeV4
	snap, format, seq, head, origin := v4TestSnapshot, 2, int64(1), strings.Repeat("e", 64), true
	cp.PermStateSnapshot, cp.PermFormat, cp.PermEventSeq, cp.PermEventHead, cp.PermOrigin = &snap, &format, &seq, &head, &origin
	return cp
}

const v4GoldenPrefix = `{"seq":1,"id_from":1,"id_to":0,"row_count":0,"agg_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","agg_scheme":"cp-agg-v4","prev_checkpoint_hash":"anchor","min_created_at_us":null,"state":[{"table":"user_roles","hash":"04041a39e9767c77f7fc63538c94ad54c941e29bd62a274dfd5f8d26ddecbc95","count":0}],"role_state_reconciled":null,"max_created_at_us":null,"sealed_at_us":0,"signing_key_version":1,"tool_call_id_from":1,"tool_call_id_to":0,"tool_call_row_count":0,"tool_call_agg_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",`

func TestCheckpointCanonicalGoldenV4(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(cp *model.AuditCheckpoint)
		want   string
	}{
		{"帶 perm 物件（起點）", func(*model.AuditCheckpoint) {},
			v4GoldenPrefix + `"perm":{"format":2,"model":1,"catalog":"cccccccccccccccccccccccccccccccc","snapshot_digest":"e9b09ee485bf6583fa9f866aae228c908aa2bd2ae1c28fb2db6abb689f48399e","event_seq":1,"event_head":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","reconciled":null,"origin":true}}`},
		{"perm 為 null", func(cp *model.AuditCheckpoint) {
			cp.PermStateSnapshot, cp.PermFormat, cp.PermEventSeq, cp.PermEventHead, cp.PermOrigin = nil, nil, nil, nil, nil
		}, v4GoldenPrefix + `"perm":null}`},
		{"reconciled 為 false", func(cp *model.AuditCheckpoint) {
			f, seq, origin := false, int64(9), false
			cp.PermReconciled, cp.PermEventSeq, cp.PermOrigin = &f, &seq, &origin
		}, v4GoldenPrefix + `"perm":{"format":2,"model":1,"catalog":"cccccccccccccccccccccccccccccccc","snapshot_digest":"e9b09ee485bf6583fa9f866aae228c908aa2bd2ae1c28fb2db6abb689f48399e","event_seq":9,"event_head":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","reconciled":false,"origin":false}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cp := v4CanonicalFixture()
			tc.mutate(cp)
			got, err := CheckpointSignBytes(cp)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Fatalf("v4 簽章 payload 位元組不符 golden\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

// TestCheckpointOfflineRebuildV4 以手寫字串與手算長度前綴摘要重建 v4 位元組（不用 payload struct、
// 不用 stateHash），證明離線驗證者照規格即可逐位元組重建。
func TestCheckpointOfflineRebuildV4(t *testing.T) {
	digest := func(body string) string {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(body)))
		sum := sha256.Sum256(append(n[:], []byte(body)...))
		return hex.EncodeToString(sum[:])
	}
	empty := hex.EncodeToString(func() []byte { s := sha256.Sum256(nil); return s[:] }())
	want := `{"seq":1,"id_from":1,"id_to":0,"row_count":0,"agg_hash":"` + empty + `","agg_scheme":"cp-agg-v4",` +
		`"prev_checkpoint_hash":"anchor","min_created_at_us":null,` +
		`"state":[{"table":"user_roles","hash":"` + digest("[]") + `","count":0}],"role_state_reconciled":null,` +
		`"max_created_at_us":null,"sealed_at_us":0,"signing_key_version":1,` +
		`"tool_call_id_from":1,"tool_call_id_to":0,"tool_call_row_count":0,"tool_call_agg_hash":"` + empty + `",` +
		`"perm":{"format":2,"model":1,"catalog":"` + strings.Repeat("c", 32) + `","snapshot_digest":"` + digest(v4TestSnapshot) +
		`","event_seq":1,"event_head":"` + strings.Repeat("e", 64) + `","reconciled":null,"origin":true}}`
	got, err := CheckpointSignBytes(v4CanonicalFixture())
	if err != nil || string(got) != want {
		t.Fatalf("offline mismatch: %s\nwant: %s\n%v", got, want, err)
	}
	// 公開規格所載的第四版向量與雜湊必須與產品編碼相同
	doc, err := os.ReadFile("../../../cmd/server/testdata/docs/security/audit-checkpoint-offline-verification.md")
	if err != nil {
		t.Fatal("documentation mount unavailable: " + err.Error())
	}
	sum := sha256.Sum256(got)
	if !strings.Contains(string(doc), want) || !strings.Contains(string(doc), hex.EncodeToString(sum[:])) {
		t.Fatal("規格文件的第四版向量或其 sha256 與產品編碼不同")
	}
	// 鏈接雜湊：所有版本同一條規則（被簽章位元組原樣內嵌＋signature），無附證分支
	cp := v4CanonicalFixture()
	cp.Signature = "c2ln"
	link, err := CheckpointLinkHash(cp)
	if err != nil {
		t.Fatal(err)
	}
	manual := sha256.Sum256([]byte(`{"signed":` + want + `,"signature":"c2ln"}`))
	if link != hex.EncodeToString(manual[:]) {
		t.Fatal("v4 鏈接雜湊不是「signed＋signature」單一規則")
	}
}

type v4TestSigner struct{ priv ed25519.PrivateKey }

func newV4TestSigner(t *testing.T) *v4TestSigner {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &v4TestSigner{priv: priv}
}
func (s *v4TestSigner) ActiveVersion() int { return 1 }
func (s *v4TestSigner) Sign(data []byte) (int, string) {
	return 1, base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, data))
}
func (s *v4TestSigner) Verify(v int, data []byte, sig string) (bool, error) {
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return false, nil
	}
	return v == 1 && ed25519.Verify(s.priv.Public().(ed25519.PublicKey), data, raw), nil
}

// 每一種改動的結構層去向：簽章驗不過（載荷建得出但不是被簽的那一串）或載荷建不出。
func TestCheckpointV4PermRebuildRules(t *testing.T) {
	signer := newV4TestSigner(t)
	signed := func(t *testing.T) *model.AuditCheckpoint {
		cp := v4CanonicalFixture()
		payload, err := CheckpointSignBytes(cp)
		if err != nil {
			t.Fatal(err)
		}
		_, cp.Signature = signer.Sign(payload)
		return cp
	}
	verify := func(cp *model.AuditCheckpoint) (bool, error) {
		payload, err := CheckpointSignBytes(cp)
		if err != nil {
			return false, err
		}
		return signer.Verify(cp.SigningKeyVersion, payload, cp.Signature)
	}
	mustInvalidSig := func(t *testing.T, cp *model.AuditCheckpoint) {
		t.Helper()
		ok, err := verify(cp)
		if err != nil || ok {
			t.Fatalf("應為簽章驗不過（載荷建得出），got ok=%v err=%v", ok, err)
		}
	}
	mustPayloadInvalid := func(t *testing.T, cp *model.AuditCheckpoint) {
		t.Helper()
		if _, err := CheckpointSignBytes(cp); !errors.Is(err, ErrCheckpointPayloadInvalid) {
			t.Fatalf("應為載荷建不出（ErrCheckpointPayloadInvalid），got %v", err)
		}
	}

	t.Run("原樣驗過", func(t *testing.T) {
		if ok, err := verify(signed(t)); err != nil || !ok {
			t.Fatal(ok, err)
		}
	})
	t.Run("整組清空六欄：重建為 null，簽章驗不過", func(t *testing.T) {
		cp := signed(t)
		cp.PermStateSnapshot, cp.PermFormat, cp.PermEventSeq, cp.PermEventHead, cp.PermReconciled, cp.PermOrigin = nil, nil, nil, nil, nil, nil
		perm, err := checkpointPermFromColumns(cp)
		if err != nil || perm != nil {
			t.Fatalf("整組清空應重建為 null，got %v %v", perm, err)
		}
		mustInvalidSig(t, cp)
	})
	for name, clear := range map[string]func(cp *model.AuditCheckpoint){
		"清快照本體": func(cp *model.AuditCheckpoint) { cp.PermStateSnapshot = nil },
		"清起點旗標": func(cp *model.AuditCheckpoint) { cp.PermOrigin = nil },
		"清事件鏈頭": func(cp *model.AuditCheckpoint) { cp.PermEventHead = nil },
		"只留對帳結果": func(cp *model.AuditCheckpoint) {
			cp.PermStateSnapshot, cp.PermFormat, cp.PermEventSeq, cp.PermEventHead, cp.PermOrigin = nil, nil, nil, nil, nil
			f := true
			cp.PermReconciled = &f
		},
		"快照為空字串":     func(cp *model.AuditCheckpoint) { s := ""; cp.PermStateSnapshot = &s },
		"快照為字面 null": func(cp *model.AuditCheckpoint) { s := "null"; cp.PermStateSnapshot = &s },
		"事件鏈頭非 hex":  func(cp *model.AuditCheckpoint) { s := strings.Repeat("Z", 64); cp.PermEventHead = &s },
		"事件序號為 0":    func(cp *model.AuditCheckpoint) { n := int64(0); cp.PermEventSeq = &n },
	} {
		t.Run("部分清空或出值域："+name+"→載荷建不出", func(t *testing.T) {
			cp := signed(t)
			clear(cp)
			mustPayloadInvalid(t, cp)
		})
	}
	t.Run("改起點旗標：驗不過", func(t *testing.T) {
		cp := signed(t)
		f, seq := false, int64(1)
		cp.PermOrigin, cp.PermEventSeq = &f, &seq
		mustInvalidSig(t, cp)
	})
	t.Run("改對帳結果：驗不過", func(t *testing.T) {
		cp := signed(t)
		yes := true
		cp.PermReconciled = &yes
		mustInvalidSig(t, cp)
	})
	t.Run("改快照本體（摘要隨之改變）：驗不過", func(t *testing.T) {
		cp := signed(t)
		body := strings.Replace(v4TestSnapshot, `"version":3`, `"version":4`, 1)
		cp.PermStateSnapshot = &body
		mustInvalidSig(t, cp)
	})
	t.Run("agg_scheme 改成 v3：以 v3 形狀重建，驗不過", func(t *testing.T) {
		cp := signed(t)
		cp.AggScheme = model.AggSchemeV3
		mustInvalidSig(t, cp)
	})
	t.Run("agg_scheme 改成 v3 並清空附證：驗不過", func(t *testing.T) {
		cp := signed(t)
		cp.AggScheme = model.AggSchemeV3
		cp.PermStateSnapshot, cp.PermFormat, cp.PermEventSeq, cp.PermEventHead, cp.PermReconciled, cp.PermOrigin = nil, nil, nil, nil, nil, nil
		mustInvalidSig(t, cp)
	})
	t.Run("origin=true 且 event_seq=2：載荷建不出", func(t *testing.T) {
		cp := signed(t)
		n := int64(2)
		cp.PermEventSeq = &n
		mustPayloadInvalid(t, cp)
	})
	t.Run("format 與本體 v 不等：載荷建不出", func(t *testing.T) {
		cp := signed(t)
		v1 := 1
		cp.PermFormat = &v1
		mustPayloadInvalid(t, cp)
	})
	t.Run("未知 format：載荷建不出", func(t *testing.T) {
		cp := signed(t)
		v9 := 9
		cp.PermFormat = &v9
		mustPayloadInvalid(t, cp)
	})
	t.Run("非 canonical 快照（多一個空白）：載荷建不出", func(t *testing.T) {
		cp := signed(t)
		body := v4TestSnapshot + " "
		cp.PermStateSnapshot = &body
		mustPayloadInvalid(t, cp)
	})
}
