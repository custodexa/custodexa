package audit

import (
	"testing"
)

// 端點感知遮罩的行為守衛。
//
// 改前遮罩只看鍵名，於是同一個鍵名在任一端點上可能是憑證就一律不登記——
// `url` 即因此長期不登記，代價是目錄服務的伺服器位址變更不可稽核。
// 本檔守的是那條代價確實被解掉了，而且**只解掉那一條**：
//
//	(1) 同名鍵在兩個端點上結果不同（這是端點感知的全部意義）；
//	(2) 端點未知時只套全域集（安全側的退化，不是放行）；
//	(3) 端點是伺服端註冊事實，請求宣告的任何值都不構成端點；
//	(4) 全域 default-deny 未被放寬：未登記的鍵在任一端點仍被遮。

const maskedMarker = "***MASKED***"

// TestMaskSensitiveFieldsIsEndpointAware 同名鍵在兩個端點上結果不同。
func TestMaskSensitiveFieldsIsEndpointAware(t *testing.T) {
	body := map[string]interface{}{"url": "ldaps://dc.example:636"}

	ldap := MaskSensitiveFields("PUT /api/v1/ldap-directory", body)
	if ldap["url"] != "ldaps://dc.example:636" {
		t.Fatalf("目錄服務端點的 url 應原樣入庫（認證來源被改導到哪裡的唯一課責欄），得 %v", ldap["url"])
	}

	notify := MaskSensitiveFields("PUT /api/v1/notification-channels/:id", body)
	if notify["url"] != maskedMarker {
		t.Fatalf("通知管道端點的 url 應維持遮罩（webhook URL 本身即持有型權杖），得 %v", notify["url"])
	}
}

// TestMaskSensitiveFieldsUnknownEndpointUsesGlobalSetOnly 端點未知時只套全域集。
//
// 未匹配任何路由（或呼叫端沒給端點）時退化為改前的行為：不多放行任何鍵。
func TestMaskSensitiveFieldsUnknownEndpointUsesGlobalSetOnly(t *testing.T) {
	body := map[string]interface{}{"url": "ldaps://dc.example:636", "name": "primary"}
	for _, endpoint := range []string{"", "GET /api/v1/unknown", "PUT /api/v1/ldap-directory/../notification-channels"} {
		out := MaskSensitiveFields(endpoint, body)
		if out["url"] != maskedMarker {
			t.Errorf("端點 %q 不應放行 url，得 %v", endpoint, out["url"])
		}
		if out["name"] != "primary" {
			t.Errorf("端點 %q 的全域放行鍵應原樣入庫，得 %v", endpoint, out["name"])
		}
	}
}

// TestMaskSensitiveFieldsKeepsGlobalDefaultDeny 端點專屬集不放寬全域 default-deny。
func TestMaskSensitiveFieldsKeepsGlobalDefaultDeny(t *testing.T) {
	body := map[string]interface{}{
		"url":               "https://vault.example:8200",
		"bind_password_enc": "should-never-appear",
		"secret_access_key": "should-never-appear",
		"unknown_field":     "x",
	}
	for _, endpoint := range append(AuditMaskEndpoints(), "", "PUT /api/v1/notification-channels/:id") {
		out := MaskSensitiveFields(endpoint, body)
		for _, key := range []string{"bind_password_enc", "secret_access_key", "unknown_field"} {
			if out[key] != maskedMarker {
				t.Errorf("端點 %q 放行了未登記的鍵 %q——端點感知放寬的是鍵名的全域語義，"+
					"不是 default-deny 本身", endpoint, key)
			}
		}
	}
}

// TestTopologyEndpointRegistersDestinationFields 拓撲端點放行的是目的地欄位。
//
// 這三個欄位承載「上鎖的資料金鑰送去哪裡解」；少了它們，審計列只答得出
// 「拓撲被改了」而答不出改成什麼。
func TestTopologyEndpointRegistersDestinationFields(t *testing.T) {
	const endpoint = "PUT /api/v1/keys/topology"
	out := MaskSensitiveFields(endpoint, map[string]interface{}{
		"address":          "https://vault.example:8200",
		"region":           "ap-northeast-1",
		"role_id":          "role-fixture",
		"transit_key_name": "custodexa-kek",
	})
	for _, key := range []string{"address", "region", "role_id"} {
		if out[key] == maskedMarker {
			t.Errorf("拓撲端點應放行 %q（目的地欄位）", key)
		}
	}
	// transit_key_name 的鍵名命中機密語義片段，刻意不放行；其課責由 handler
	// 自寫的 kek_topology_update 審計列承擔（帶完整前後值摘要）。
	if out["transit_key_name"] != maskedMarker {
		t.Error("transit_key_name 不應放行——G3 的過度攔截是刻意的安全側，不為個案開名稱例外")
	}
}

// TestEndpointAuditFieldNamesMatchesMask 列舉出的鍵與實際放行的一致。
//
// 兩者分歧時守衛會拿著一份與現實不同的清單去判定，而分歧的方向恰好是
// 「有人加了一條放行但沒有人在檢查它」。
func TestEndpointAuditFieldNamesMatchesMask(t *testing.T) {
	for _, endpoint := range AuditMaskEndpoints() {
		names := EndpointAuditFieldNames(endpoint)
		if len(names) == 0 {
			t.Errorf("端點 %q 被列舉卻沒有任何專屬放行", endpoint)
			continue
		}
		body := map[string]interface{}{}
		for _, n := range names {
			body[n] = "value-" + n
		}
		out := MaskSensitiveFields(endpoint, body)
		for _, n := range names {
			if out[n] == maskedMarker {
				t.Errorf("端點 %q 列舉了 %q 卻仍被遮——列舉與實作已分歧", endpoint, n)
			}
		}
	}
}

// TestLDAPURLAuditable 目錄服務的伺服器位址變更自此可稽核。
//
// 這是本產品長期的課責空白：改前 `url` 因「鍵名的全域語義」不登記，於是
// 「認證來源被改導到哪裡」只能靠 `base_dn`／`user_filter`／`skip_tls_verify`／
// `enabled` 間接推斷。端點感知遮罩把判定改為「這個鍵名**在這個端點上**是不是機密」。
func TestLDAPURLAuditable(t *testing.T) {
	const endpoint = "PUT /api/v1/ldap-directory"
	out := MaskSensitiveFields(endpoint, map[string]interface{}{
		"url":               "ldaps://new-dc.attacker.example:636",
		"base_dn":           "dc=example,dc=com",
		"bind_password_enc": "should-never-appear",
	})
	if out["url"] != "ldaps://new-dc.attacker.example:636" {
		t.Fatalf("目錄服務端點的 url 應原樣入庫，得 %v", out["url"])
	}
	// 同一列上的憑證欄仍維持遮罩——放寬的是鍵名的全域語義，不是 default-deny。
	if out["bind_password_enc"] != maskedMarker {
		t.Fatalf("同端點的憑證欄不得因此放行，得 %v", out["bind_password_enc"])
	}
}

// TestNotificationChannelURLMasked 通知管道的 `url` 維持遮罩。
//
// Slack／Teams／釘釘形態的 webhook URL **本身就是持有型權杖**：放行它等於把憑證
// 逐字寫進受檢查點鏈保護、刪不掉的審計列。
func TestNotificationChannelURLMasked(t *testing.T) {
	for _, endpoint := range []string{
		"POST /api/v1/notification-channels",
		"PUT /api/v1/notification-channels/:id",
	} {
		out := MaskSensitiveFields(endpoint, map[string]interface{}{
			"url":  "https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXX",
			"name": "ops-alerts",
		})
		if out["url"] != maskedMarker {
			t.Errorf("端點 %q 的 url 應維持遮罩，得 %v", endpoint, out["url"])
		}
		if out["name"] != "ops-alerts" {
			t.Errorf("端點 %q 的識別欄應原樣入庫，得 %v", endpoint, out["name"])
		}
	}
}
