package api

import (
	"net/http"
	"testing"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/seal"
)

// 封印機器碼的雙向對照守衛。
//
// 狀態機只生成機器碼、不生成文字；apierror registry 才有三語文案。兩邊若各自
// 維護一份碼表，同一失敗就會有兩個名字——監控依 API 回應歸類、稽核依狀態機
// 日誌歸類，兩者從此對不起來。本守衛把「碼值逐字相同」與「每個碼都有映射」
// 變成可執行契約。

// sealMachineCodes 是 internal/seal 對外可能回傳的全部機器碼。
//
// 手列而非反射：碼是常數不是變數，反射列舉不到；手列的代價由下方的
// 「每一個都必須有映射且已註冊」斷言承擔——漏列一個，它就會在
// SealErrorResponse 的預設分支被靜默吞掉，而那正是本守衛要防的事。
var sealMachineCodes = []string{
	seal.CodeUnsealInProgress,
	seal.CodeCleanupPending,
	seal.CodeAlreadyUnsealed,
	seal.CodeCooldownActive,
	seal.CodeBackoffActive,
	seal.CodeMaterialInvalid,
	seal.CodeAborted,
	seal.CodeJournalIOFailure,
	seal.CodeInitFailed,
	seal.CodeStage2Timeout,
	seal.CodePublishUnconfirmed,
}

// TestSealCodesMapToRegisteredAPIErrors 每個狀態機碼都有對應且已註冊的 apierror 碼。
func TestSealCodesMapToRegisteredAPIErrors(t *testing.T) {
	for _, code := range sealMachineCodes {
		m, ok := sealErrorStatus[code]
		if !ok {
			t.Errorf("狀態機碼 %s 未登記映射——它會落入預設分支而被當成材料失敗回覆", code)
			continue
		}
		if string(m.code) != code {
			t.Errorf("狀態機碼 %s 對應到不同名的 apierror 碼 %s——同一失敗會有兩個名字", code, m.code)
		}
		if !apierror.IsRegistered(m.code) {
			t.Errorf("apierror 碼 %s 未註冊，回應會退化為通用 500", m.code)
		}
		if m.status < 400 || m.status > 599 {
			t.Errorf("狀態機碼 %s 映射到非錯誤狀態碼 %d", code, m.status)
		}
	}
}

// TestSealGateCodeRegistered 封印閘的 503 機器碼必須已註冊。
func TestSealGateCodeRegistered(t *testing.T) {
	for _, code := range []apierror.ErrCode{
		apierror.CodeSealServiceSealed,
		apierror.CodeSealSourceNotAllowed,
		apierror.CodeSealStatusUnavailable,
	} {
		if !apierror.IsRegistered(code) {
			t.Errorf("%s 未註冊", code)
		}
	}
}

// TestSealErrorResponseFallsBackToMaterialInvalid 未知錯誤不得產生可區分的回應形狀。
func TestSealErrorResponseFallsBackToMaterialInvalid(t *testing.T) {
	code, status := SealErrorResponse(errUnknownForTest{})
	if code != apierror.CodeSealMaterialInvalid || status != http.StatusBadRequest {
		t.Fatalf("未知錯誤映射為 %s/%d，期望 SEAL_MATERIAL_INVALID/400", code, status)
	}
}

type errUnknownForTest struct{}

func (errUnknownForTest) Error() string { return "測試：非 seal 套件的錯誤" }

// TestSealPayloadDecodeRejectsUnknownFields 未知欄位一律拒絕。
//
// 在「輸錯即固化為部署主金鑰」的初始化路徑上，靜默忽略未知欄位是不可接受的
// 失敗模式：呼叫端會以為某個新增的確認欄位已生效。
func TestSealPayloadDecodeRejectsUnknownFields(t *testing.T) {
	if _, err := DecodeSealMaterial([]byte(`{"kek":"x","surprise":1}`)); err == nil {
		t.Fatal("含未知欄位的請求體竟被接受")
	}
	if _, err := DecodeSealMaterial([]byte(`{"kek":"x"}`)); err != nil {
		t.Fatalf("合法請求體被拒: %v", err)
	}
	if _, err := DecodeSealMaterial(make([]byte, MaxSealUnsealBodyBytes+1)); err == nil {
		t.Fatal("超過大小上限的請求體竟被接受")
	}
}

// TestSealPayloadZeroize 歸零後不得殘留任何材料欄位。
//
// **斷言覆寫而非只斷言參考已放掉**：秘密欄位改為 []byte 的全部理由就是
// 「承載明文的那一份可以被覆寫」；若只檢查欄位為 nil，把 `p.KEK = nil`
// 寫成一行就能讓測試變綠，而原本的 backing array 仍完整躺在記憶體裡。
func TestSealPayloadZeroize(t *testing.T) {
	p := &SealUnsealPayload{
		KEK: []byte("aaaa"), KEKConfirm: []byte("aaaa"),
		ConfirmSaved: true, Username: "u", Password: []byte("secret"),
	}
	// 另存 backing array 的視圖：Zeroize 之後這些視圖必須全為 0。
	views := [][]byte{p.KEK[:], p.KEKConfirm[:], p.Password[:]}
	p.Zeroize()
	if p.KEK != nil || p.KEKConfirm != nil || p.Password != nil || p.Username != "" || p.ConfirmSaved {
		t.Fatalf("歸零後仍殘留欄位參考：%+v", p)
	}
	for i, v := range views {
		for j, b := range v {
			if b != 0 {
				t.Fatalf("第 %d 個秘密欄位的 backing array 第 %d 個位元組為 %#x，未被覆寫", i, j, b)
			}
		}
	}
}

// TestSealPayloadDecodeIntoZeroableBuffers 解析結果必須落在可覆寫的 buffer。
//
// 這是正向驗收：`encoding/json` 解出的 string 是獨立且不可覆寫的副本，
// 歸零原始 body 與清空欄位都碰不到它。改為自訂解析後，Zeroize 覆寫的就是
// 承載明文的那一份。
func TestSealPayloadDecodeIntoZeroableBuffers(t *testing.T) {
	body := []byte(`{"kek":"AAAABBBBCCCCDDDD","kek_confirm":"AAAABBBBCCCCDDDD","confirm_saved":true,"username":"admin","password":"pw-secret"}`)
	p, err := DecodeSealMaterial(body)
	if err != nil {
		t.Fatalf("合法請求體被拒: %v", err)
	}
	if string(p.KEK) != "AAAABBBBCCCCDDDD" || string(p.Password) != "pw-secret" ||
		p.Username != "admin" || !p.ConfirmSaved {
		t.Fatalf("解析結果不符：%+v", p)
	}
	kekView, pwView := p.KEK[:], p.Password[:]
	p.Zeroize()
	for _, v := range [][]byte{kekView, pwView} {
		for _, b := range v {
			if b != 0 {
				t.Fatal("解析結果的 backing array 未被 Zeroize 覆寫——秘密仍以不可覆寫的副本存在")
			}
		}
	}
}

// TestSealPayloadRejectsTrailingAndDuplicate 尾隨值與重複鍵一律拒絕。
//
// 只 Decode 一次時，`{...}{...}` 的第二個值完全不被檢視；而重複鍵在
// last-wins 語義下使「送出的內容」與「被驗證的內容」可以不同——後者是
// paste-back 的直接繞道（送兩個 kek，驗的是後者、人以為送的是前者）。
func TestSealPayloadRejectsTrailingAndDuplicate(t *testing.T) {
	cases := map[string]string{
		"尾隨第二個物件":   `{"kek":"x"}{"kek":"y"}`,
		"尾隨陣列":      `{"kek":"x"}[1]`,
		"尾隨純量":      `{"kek":"x"}1`,
		"尾隨右括號":     `{"kek":"x"}]`,
		"尾隨右大括號":    `{"kek":"x"}}`,
		"重複 kek":    `{"kek":"x","kek":"y"}`,
		"重複 用於繞過確認": `{"kek":"x","kek_confirm":"x","kek":"y"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeSealMaterial([]byte(body)); err == nil {
				t.Fatalf("%s 竟被接受：嚴格驗證可被無聲繞過", name)
			}
		})
	}
	// 尾隨空白仍應接受——否則任何加了換行的客戶端都會被拒。
	if _, err := DecodeSealMaterial([]byte("{\"kek\":\"x\"}\n \t")); err != nil {
		t.Fatalf("尾隨空白的請求體被拒: %v", err)
	}
}

// TestSealPayloadUnescapesJSONStrings 自訂解析必須與 JSON 轉義語義一致。
//
// 自己寫解析器的代價就是這條測試：轉義處理錯誤會讓「使用者輸入的材料」與
// 「伺服端驗證的材料」不同，而該差異在初始化路徑上會被固化成部署主 KEK。
func TestSealPayloadUnescapesJSONStrings(t *testing.T) {
	cases := []struct{ body, want string }{
		{`{"kek":"a\"b"}`, `a"b`},
		{`{"kek":"a\\b"}`, `a\b`},
		{`{"kek":"a\/b"}`, `a/b`},
		{`{"kek":"a\nb\tc"}`, "a\nb\tc"},
		{`{"kek":"中文"}`, "中文"},
		{`{"kek":"😀"}`, "\U0001F600"},
	}
	for _, c := range cases {
		p, err := DecodeSealMaterial([]byte(c.body))
		if err != nil {
			t.Fatalf("%s 被拒: %v", c.body, err)
		}
		if string(p.KEK) != c.want {
			t.Fatalf("%s 解出 %q，期望 %q", c.body, string(p.KEK), c.want)
		}
		p.Zeroize()
	}
	for _, bad := range []string{`{"kek":"a\qb"}`, `{"kek":"a\u12"}`, `{"kek":123}`, `{"kek":"a`} {
		if _, err := DecodeSealMaterial([]byte(bad)); err == nil {
			t.Fatalf("不合法的字串字面量 %s 竟被接受", bad)
		}
	}
}
