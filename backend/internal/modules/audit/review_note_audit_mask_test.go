package audit

import "testing"

// TestAlertReviewNoteReachesAuditLog 審閱與核決端點的理由與批次關聯碼要原樣進稽核列。
//
// 擋的威脅：理由被遮成遮罩字串後，稽核列只剩「某人把告警標為無害」，答不出依據；
// 同一批送出的多筆也無從在稽核面辨認是同一次操作。
func TestAlertReviewNoteReachesAuditLog(t *testing.T) {
	const batch = "6f1c2a0e-8a4b-4c1d-9e2f-0a1b2c3d4e5f"
	cases := map[string]map[string]interface{}{
		"POST /api/v1/command-alerts/:id/review":   {"disposition": "benign", "note": "維運人員換筆電", "batch_id": batch},
		"POST /api/v1/access-requests/:id/approve": {"note": "", "batch_id": batch},
		"POST /api/v1/access-requests/:id/reject":  {"note": "本週凍結變更", "batch_id": batch},
		"POST /api/v1/access-requests/:id/review":  {"disposition": "confirmed", "note": "事後確認", "batch_id": batch},
	}
	for endpoint, body := range cases {
		got := MaskSensitiveFields(endpoint, body)
		for _, key := range []string{"note", "batch_id"} {
			if got[key] != body[key] {
				t.Errorf("%s 的 %s 應原樣入稽核，得到 %v", endpoint, key, got[key])
			}
		}
	}
	// 未登記的端點不因此多放行
	if got := MaskSensitiveFields("POST /api/v1/access-requests/:id/revoke", map[string]interface{}{"batch_id": batch}); got["batch_id"] == batch {
		t.Errorf("撤銷端點不收批次關聯碼，不應放行")
	}
}
