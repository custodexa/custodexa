package api

import (
	"fmt"
	"strings"
	"testing"
)

// 解封請求本文擴張的守衛（任務 4.3）。
//
// 三項嚴格性沿既有理由（未知鍵、重複鍵、尾隨內容一律拒絕），本檔另守三件新的：
//
//	(1) 委託分支的秘密欄解進**可覆寫的位元組**（不是 string）；
//	(2) 服務帳號金鑰檔有**欄位級**上限，超限即拒且不回顯片段；
//	(3) 本文上限上調後仍有界。

// TestDecodeSealMaterialDelegatedFields 委託分支的欄位各自解得出且可覆寫。
func TestDecodeSealMaterialDelegatedFields(t *testing.T) {
	body := `{"access_key_id":"AKIAFIXTURE","secret_access_key":"fixture-secret",` +
		`"service_account_json":"{\"type\":\"service_account\"}",` +
		`"vault_secret_id":"sid","vault_token":"tok","topology_digest":"deadbeef",` +
		`"region":"ap-northeast-1","key_ref":"arn:aws:kms:x:1:key/a",` +
		`"address":"https://vault.example:8200","transit_key_name":"kek","role_id":"r1"}`
	p, err := DecodeSealMaterial([]byte(body))
	if err != nil {
		t.Fatalf("合法欄位應解得出: %v", err)
	}
	// 非秘密欄位：留 string（要進審計、要比對）。
	if p.TopologyDigest != "deadbeef" || p.Region != "ap-northeast-1" ||
		p.KeyRef != "arn:aws:kms:x:1:key/a" || p.Address != "https://vault.example:8200" ||
		p.TransitKeyName != "kek" || p.RoleID != "r1" {
		t.Fatalf("非秘密欄位解析不符: %+v", p)
	}
	// 鍵集記錄下來了（分支判定在呼叫端，解析層只記事實）。
	present := p.Present()
	for _, k := range []string{"access_key_id", "secret_access_key", "service_account_json",
		"vault_secret_id", "vault_token", "topology_digest"} {
		if !present[k] {
			t.Fatalf("鍵集未記錄 %q", k)
		}
	}
	// 秘密欄位：可覆寫的位元組，Zeroize 之後原位元組全零。
	originals := [][]byte{p.AccessKeyID, p.SecretAccessKey, p.ServiceAccountJSON, p.VaultSecretID, p.VaultToken}
	for i, raw := range originals {
		if len(raw) == 0 {
			t.Fatalf("第 %d 個秘密欄位為空", i)
		}
	}
	p.Zeroize()
	for i, raw := range originals {
		for _, b := range raw {
			if b != 0 {
				t.Fatalf("第 %d 個秘密欄位未歸零: %q", i, raw)
			}
		}
	}
}

// TestDecodeSealMaterialStillRejectsMalformed 三項既有嚴格性未被擴張稀釋。
func TestDecodeSealMaterialStillRejectsMalformed(t *testing.T) {
	for name, body := range map[string]string{
		"未知欄位": `{"access_key_id":"a","not_a_field":"x"}`,
		"重複欄位": `{"vault_token":"a","vault_token":"b"}`,
		"尾隨內容": `{"vault_token":"a"}{"vault_token":"b"}`,
		"非物件":  `["vault_token"]`,
		"空本文":  ``,
	} {
		if _, err := DecodeSealMaterial([]byte(body)); err == nil {
			t.Errorf("%s 應被拒", name)
		}
	}
}

// TestUnsealPayloadServiceAccountFieldLimit 服務帳號金鑰檔的欄位級上限。
//
// 與本文上限分開訂：本文上限管的是單次驗證成本，欄位上限管的是「這個欄位收到的
// 是不是一份服務帳號金鑰檔」。超限即拒且**不回顯內容片段**。
func TestUnsealPayloadServiceAccountFieldLimit(t *testing.T) {
	const marker = "SENTINEL-MUST-NOT-APPEAR"
	oversize := marker + strings.Repeat("A", MaxServiceAccountJSONBytes)
	body := fmt.Sprintf(`{"service_account_json":%q}`, oversize)
	if len(body) >= MaxSealUnsealBodyBytes {
		t.Fatalf("夾具超出本文上限，會被前一道擋下而測不到欄位上限（body=%d, 上限=%d）",
			len(body), MaxSealUnsealBodyBytes)
	}
	p, err := DecodeSealMaterial([]byte(body))
	if err == nil {
		p.Zeroize()
		t.Fatal("超出欄位上限的服務帳號金鑰檔應被拒")
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("錯誤訊息回顯了內容片段: %v", err)
	}

	// 正向控制：上限之內的內容可被接受，否則「一律拒絕」也會讓上面全綠。
	ok := fmt.Sprintf(`{"service_account_json":%q}`, strings.Repeat("A", 1024))
	if p2, err := DecodeSealMaterial([]byte(ok)); err != nil {
		t.Fatalf("上限之內的內容應被接受: %v", err)
	} else {
		p2.Zeroize()
	}
}

// TestUnsealPayloadBodyLimitStillBounded 本文上限上調後仍有界。
func TestUnsealPayloadBodyLimitStillBounded(t *testing.T) {
	if MaxSealUnsealBodyBytes <= MaxServiceAccountJSONBytes {
		t.Fatal("本文上限須大於欄位上限，否則欄位上限永遠測不到")
	}
	over := fmt.Sprintf(`{"kek":%q}`, strings.Repeat("A", MaxSealUnsealBodyBytes))
	if _, err := DecodeSealMaterial([]byte(over)); err == nil {
		t.Fatal("超出本文上限應被拒")
	}
}
