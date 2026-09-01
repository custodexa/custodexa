package api

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/custodexa/backend/internal/offsite"
)

// 離機儲存管理 API 的**憑證不外流**守衛：帶憑證的三條寫入路徑，四個斷言面
// （回應體、中介層審計列、operational log、錯誤鏈全文）皆不得出現憑證與其
// base64 形態。裝配見 offsite_storage_fixture_test.go。

// ── C. 禁 request-body logging ───────────────────────────────────────────

// TestOffsiteSettingsHandlersDoNotLogRequestBody 帶憑證的三條寫入路徑，
// **四個斷言面**皆不得出現憑證與其 base64 形態。
//
// 斷言面：
//
//	回應體            handler 的出站投影
//	審計列            **中介層**產出的 audit_logs 逐欄（request_body／details／error_msg）
//	operational log   `log` 套件輸出（RespondInternal 會把原始 cause 印進去）
//	錯誤鏈全文        走一條會失敗的路徑，把 err.Error() 與 %+v 納入斷言面
//
// **不得只驗服務層 DTO**：憑證進得去、出不來這條紅線的實際破口在中介層——
// 審計中介層會把 request body 遮罩後整串寫進 `audit_logs.request_body`，
// 而該表受檢查點鏈保護，寫進去就刪不掉。
func TestOffsiteSettingsHandlersDoNotLogRequestBody(t *testing.T) {
	needles := offsiteSecretNeedles()

	// 帶滿三種憑證欄的請求體（provider=s3 只會用到前兩者，第三者仍在 body 內
	// ——中介層的遮罩以鍵名為單位，漏一個鍵就是一次永久封存的洩漏）
	credPayload := func(env *offsiteAPIEnv, bucket string) map[string]any {
		p := env.s3Payload(bucket)
		p["service_account_json"] = offsiteFakeSAJSON()
		return p
	}

	t.Run("PUT /settings", func(t *testing.T) {
		env := newOffsiteAPIEnv(t)
		token := env.adminToken(t, 331)
		getLog := captureOperationalLog(t)

		w := env.do(t, http.MethodPut, "/api/v1/offsite-storage/settings", token,
			credPayload(env, "evidence-bucket-one"))
		if w.Code != http.StatusOK {
			t.Fatalf("前提不成立：PUT 應 200，實得 %d (%s)", w.Code, w.Body.String())
		}
		assertAuditCarriesMaskedBody(t, env, http.MethodPut, "/api/v1/offsite-storage/settings")
		assertLogCaptureIsLive(t, getLog())
		assertNoSecret(t, "PUT 回應體", w.Body.String(), needles)
		assertNoSecret(t, "PUT 審計列", env.auditRowsJSON(t), needles)
		assertNoSecret(t, "PUT operational log", getLog(), needles)

		// 錯誤鏈全文：codec 的錯誤刻意夾帶明文，服務層必須淨化為靜態拒因
		env.codec.setEncFail(true)
		errChain := offsiteErrorChain(t, func() error {
			_, err := env.svc.Save(context.Background(),
				offsite.SettingsInput{
					Provider: "s3", Endpoint: "https://" + offsiteEndpointHost,
					Bucket: "evidence-bucket-one", Region: "us-east-1",
					AccessKeyID: offsiteFakeAccessKey, SecretAccessKey: offsiteFakeSecret,
				}, offsite.OffsiteActor{ID: 331, Name: "offsiteadmin331"})
			return err
		})
		assertNoSecret(t, "PUT 錯誤鏈全文", errChain, needles)
		env.codec.setEncFail(false)

		// 同一條失敗路徑走 HTTP：500 的原始 cause 由 RespondInternal 印進 log
		env.codec.setEncFail(true)
		w = env.do(t, http.MethodPut, "/api/v1/offsite-storage/settings", token,
			credPayload(env, "evidence-bucket-three"))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("加密失敗應 500（金鑰事故），實得 %d (%s)", w.Code, w.Body.String())
		}
		assertNoSecret(t, "PUT 失敗回應體", w.Body.String(), needles)
		assertNoSecret(t, "PUT 失敗 operational log", getLog(), needles)
		assertNoSecret(t, "PUT 失敗審計列", env.auditRowsJSON(t), needles)
	})

	t.Run("POST /settings/confirm", func(t *testing.T) {
		env := newOffsiteAPIEnv(t)
		token := env.adminToken(t, 332)
		getLog := captureOperationalLog(t)

		w := env.do(t, http.MethodPut, "/api/v1/offsite-storage/settings", token,
			credPayload(env, "evidence-bucket-one"))
		if w.Code != http.StatusOK {
			t.Fatalf("前置設定失敗: %d (%s)", w.Code, w.Body.String())
		}
		gen1 := uint(offsiteBody(t, w)["generation_id"].(float64))
		env.seedObject(t, gen1, 9301, offsite.StateUploaded)

		w = env.do(t, http.MethodPut, "/api/v1/offsite-storage/settings", token,
			credPayload(env, "evidence-bucket-two"))
		hint := offsiteBody(t, w)
		if hint["needs_confirmation"] != true {
			t.Fatalf("前置：改落點應回需確認: %s", w.Body.String())
		}

		confirmReq := credPayload(env, "evidence-bucket-two")
		confirmReq["expected_current_generation_id"] = gen1
		confirmReq["settings_digest"] = hint["settings_digest"]
		w = env.do(t, http.MethodPost, "/api/v1/offsite-storage/settings/confirm", token, confirmReq)
		if w.Code != http.StatusOK {
			t.Fatalf("前提不成立：confirm 應 200，實得 %d (%s)", w.Code, w.Body.String())
		}
		assertAuditCarriesMaskedBody(t, env, http.MethodPost, "/api/v1/offsite-storage/settings/confirm")
		assertLogCaptureIsLive(t, getLog())
		assertNoSecret(t, "confirm 回應體", w.Body.String(), needles)
		assertNoSecret(t, "confirm 審計列", env.auditRowsJSON(t), needles)
		assertNoSecret(t, "confirm operational log", getLog(), needles)

		// 錯誤鏈全文：confirm 的加密失敗路徑
		env.codec.setEncFail(true)
		errChain := offsiteErrorChain(t, func() error {
			_, err := env.svc.ConfirmGenerationSwitch(context.Background(), offsite.ConfirmRequest{
				Settings: offsite.SettingsInput{
					Provider: "s3", Endpoint: "https://" + offsiteEndpointHost,
					Bucket: "evidence-bucket-four", Region: "us-east-1",
					AccessKeyID: offsiteFakeAccessKey, SecretAccessKey: offsiteFakeSecret,
				},
				ExpectedCurrentGenerationID: 0, SettingsDigest: "irrelevant",
			}, offsite.OffsiteActor{ID: 332, Name: "offsiteadmin332"})
			return err
		})
		assertNoSecret(t, "confirm 錯誤鏈全文", errChain, needles)
		env.codec.setEncFail(false)
	})

	t.Run("POST /test", func(t *testing.T) {
		env := newOffsiteAPIEnv(t)
		token := env.adminToken(t, 333)
		env.factory.set(offsite.NewFakeClient("evidence-bucket-one"))
		getLog := captureOperationalLog(t)

		w := env.do(t, http.MethodPost, "/api/v1/offsite-storage/test", token,
			credPayload(env, "evidence-bucket-one"))
		if w.Code != http.StatusOK {
			t.Fatalf("前提不成立：test 應 200，實得 %d (%s)", w.Code, w.Body.String())
		}
		assertAuditCarriesMaskedBody(t, env, http.MethodPost, "/api/v1/offsite-storage/test")
		assertLogCaptureIsLive(t, getLog())
		assertNoSecret(t, "test 回應體", w.Body.String(), needles)
		assertNoSecret(t, "test 審計列", env.auditRowsJSON(t), needles)
		assertNoSecret(t, "test operational log", getLog(), needles)

		// 錯誤鏈全文：沿用既存憑證（同落點）而解密失敗——codec 的錯誤刻意夾帶
		// **密文**，故本格同時證明 base64 形態也被淨化掉了
		if w := env.do(t, http.MethodPut, "/api/v1/offsite-storage/settings", token,
			credPayload(env, "evidence-bucket-one")); w.Code != http.StatusOK {
			t.Fatalf("前置設定失敗: %d (%s)", w.Code, w.Body.String())
		}
		env.codec.setDecFail(true)
		reuse := map[string]any{
			"provider": "s3", "endpoint": "https://" + offsiteEndpointHost + "/" + offsiteEndpointPathToken,
			"bucket": "evidence-bucket-one", "prefix": "custodexa", "region": "us-east-1",
			"path_style": true,
		}
		w = env.do(t, http.MethodPost, "/api/v1/offsite-storage/test", token, reuse)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("解密失敗應 500（金鑰事故），實得 %d (%s)", w.Code, w.Body.String())
		}
		errChain := offsiteErrorChain(t, func() error {
			_, err := env.svc.TestSettings(context.Background(), offsite.SettingsInput{
				Provider: "s3", Endpoint: "https://" + offsiteEndpointHost + "/" + offsiteEndpointPathToken,
				Bucket: "evidence-bucket-one", Prefix: "custodexa", Region: "us-east-1", PathStyle: true,
			}, offsite.OffsiteActor{ID: 9999, Name: "chain"})
			return err
		})
		assertNoSecret(t, "test 錯誤鏈全文", errChain, needles)
		assertNoSecret(t, "test 失敗回應體", w.Body.String(), needles)
		assertNoSecret(t, "test 失敗 operational log", getLog(), needles)
		assertNoSecret(t, "test 失敗審計列", env.auditRowsJSON(t), needles)
		env.codec.setDecFail(false)
	})
}

// offsiteErrorChain 取一條失敗路徑的錯誤鏈全文（`Error()` ＋ `%+v`）。
//
// 兩種渲染都要：`%+v` 會展開部分實作的額外欄位，只驗 `Error()` 會漏掉那一面。
func offsiteErrorChain(t *testing.T, run func() error) string {
	t.Helper()
	err := run()
	if err == nil {
		t.Fatal("預期的失敗路徑沒有失敗——錯誤鏈斷言失去觀測對象")
	}
	return err.Error() + "\n" + fmt.Sprintf("%+v", err)
}
