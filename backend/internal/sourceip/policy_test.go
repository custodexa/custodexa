package sourceip

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// policyVector 共用測試向量（testdata/policy_vectors.json）的一條。
//
// 同一份檔由前端測試經唯讀掛載讀取，斷言前端的格式提示不拒絕任何 valid=true 的向量；
// 後端在此逐條斷言四個函式。兩側讀同一檔，行為分歧才會被抓到。
type policyVector struct {
	Name       string   `json:"name"`
	List       []string `json:"list"`
	Address    string   `json:"address"`
	Valid      bool     `json:"valid"`
	Normalized []string `json:"normalized"`
	Allowed    bool     `json:"allowed"`
	Status     string   `json:"status"`
	Families   []string `json:"families"`
}

const minPolicyVectors = 25

func loadPolicyVectors(t *testing.T) []policyVector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "policy_vectors.json"))
	if err != nil {
		t.Fatalf("讀取共用向量失敗: %v", err)
	}
	var vs []policyVector
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatalf("解析共用向量失敗: %v", err)
	}
	if len(vs) < minPolicyVectors {
		t.Fatalf("共用向量只有 %d 條（下限 %d）：向量檔被清空時守衛仍須轉紅", len(vs), minPolicyVectors)
	}
	return vs
}

// TestPolicyVectors 逐條向量斷言 Inspect／ParsePrefixes／Allowed／CoverageStatus。
func TestPolicyVectors(t *testing.T) {
	for _, v := range loadPolicyVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			prefixes, normalized, items, valid := Inspect(v.List)
			if valid != v.Valid {
				t.Fatalf("valid = %v, want %v（items=%+v）", valid, v.Valid, items)
			}
			if len(items) != len(v.List) {
				t.Fatalf("items 數 = %d, want %d（逐項回報不得漏項）", len(items), len(v.List))
			}
			wantNorm := v.Normalized
			if wantNorm == nil {
				wantNorm = []string{}
			}
			if !reflect.DeepEqual(normalized, wantNorm) {
				t.Fatalf("normalized = %v, want %v", normalized, wantNorm)
			}

			parsed, err := ParsePrefixes(v.List)
			if v.Valid {
				if err != nil {
					t.Fatalf("ParsePrefixes 對合法清單回錯: %v", err)
				}
				if len(parsed) != len(prefixes) {
					t.Fatalf("ParsePrefixes 回 %d 條，Inspect 回 %d 條", len(parsed), len(prefixes))
				}
				if got := Allowed(v.Address, parsed); got != v.Allowed {
					t.Fatalf("Allowed(%q) = %v, want %v", v.Address, got, v.Allowed)
				}
				status, families := CoverageStatus(parsed)
				if status != v.Status {
					t.Fatalf("status = %q, want %q", status, v.Status)
				}
				wantFam := v.Families
				if wantFam == nil {
					wantFam = []string{}
				}
				if families == nil {
					families = []string{}
				}
				if !reflect.DeepEqual(families, wantFam) {
					t.Fatalf("families = %v, want %v", families, wantFam)
				}
				// Evaluate 與強制點同一路徑：以儲存字串重走一次必須得到同一答案
				verdict := Evaluate(JoinStored(normalized), nil, v.Address)
				if verdict.Allowed != v.Allowed {
					t.Fatalf("Evaluate.Allowed = %v, want %v（reason=%s）", verdict.Allowed, v.Allowed, verdict.Reason)
				}
				if !verdict.Allowed && verdict.Reason != ReasonSourceNotAllowed {
					t.Fatalf("合法清單的拒絕原因 = %q, want %q", verdict.Reason, ReasonSourceNotAllowed)
				}
			} else {
				if err == nil {
					t.Fatal("ParsePrefixes 對不合法清單未回錯（部分寫入＝靜默丟棄不合法項目）")
				}
				if !errors.Is(err, ErrPrefixInvalid) && !errors.Is(err, ErrTooManyPrefixes) {
					t.Fatalf("錯誤未包裝為具名 sentinel: %v", err)
				}
				// 至少一項帶錯誤碼，且錯誤碼在閉集合內
				flagged := 0
				for _, it := range items {
					switch it.ErrorCode {
					case "":
					case ItemInvalid, ItemTooMany:
						flagged++
					default:
						t.Fatalf("未知的項目錯誤碼 %q", it.ErrorCode)
					}
				}
				if flagged == 0 {
					t.Fatal("valid=false 卻沒有任何項目帶錯誤碼：介面無從就近提示")
				}
			}
		})
	}
}

// TestCanonical 位址正規化：zone 去除、IPv4-mapped 還原、非法回 false。
func TestCanonical(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"203.0.113.5", "203.0.113.5", true},
		{" 203.0.113.5 ", "203.0.113.5", true},
		{"::ffff:203.0.113.5", "203.0.113.5", true},
		{"2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1", true},
		{"fe80::1%eth0", "fe80::1", true},
		{"unknown", "", false},
		{"", "", false},
		{"10.0.0.0/8", "", false},
		{"256.1.1.1", "", false},
	}
	for _, c := range cases {
		got, ok := Canonical(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("Canonical(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

// TestEvaluateFailClose 政策不可用時一律拒絕，且原因碼與來源拒絕區分。
func TestEvaluateFailClose(t *testing.T) {
	if v := Evaluate("", errors.New("db down"), "10.1.2.3"); v.Allowed || v.Reason != ReasonPolicyUnreadable || v.Cause != CauseReadError {
		t.Fatalf("讀取失敗應拒絕且標 read_error，實得 %+v", v)
	}
	if v := Evaluate("10.0.0.0/8,garbage", nil, "10.1.2.3"); v.Allowed || v.Reason != ReasonPolicyUnreadable || v.Cause != CauseParseError {
		t.Fatalf("字串損壞應拒絕且標 parse_error，實得 %+v", v)
	}
	if v := Evaluate("", nil, ""); !v.Allowed {
		t.Fatalf("空清單應放行（含來源不可解析者），實得 %+v", v)
	}
	if v := Evaluate("10.0.0.0/8", nil, "203.0.113.5"); v.Allowed || v.Reason != ReasonSourceNotAllowed || len(v.Policy) != 1 {
		t.Fatalf("清單外應拒絕並帶清單快照，實得 %+v", v)
	}
	if v := Evaluate("10.0.0.0/8", nil, "10.1.2.3"); !v.Allowed || v.Reason != "" {
		t.Fatalf("清單內應放行，實得 %+v", v)
	}
}

// TestSplitJoinStored 儲存字串往返。
func TestSplitJoinStored(t *testing.T) {
	if got := SplitStored(""); len(got) != 0 || got == nil {
		t.Fatalf("空字串應回非 nil 空清單，實得 %#v", got)
	}
	if got := SplitStored(" 10.0.0.0/8, ,2001:db8::/32 "); !reflect.DeepEqual(got, []string{"10.0.0.0/8", "2001:db8::/32"}) {
		t.Fatalf("SplitStored = %v", got)
	}
	if got := JoinStored([]string{"10.0.0.0/8", "2001:db8::/32"}); got != "10.0.0.0/8,2001:db8::/32" {
		t.Fatalf("JoinStored = %q", got)
	}
}
