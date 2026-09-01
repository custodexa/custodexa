package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/offsite"
)

// 離機儲存管理 API 的**運維面**守衛：失敗清單的分頁與排序、重試端點的 404 收斂、
// 連線測試的兩種失敗語義分立。裝配見 offsite_storage_fixture_test.go。

// TestOffsiteFailuresPaginationAndOrdering 失敗清單的分頁與排序。
//
// 排序的界定在 handler 註解裡寫得很清楚：**頁內成立**（到期日不在帳冊裡，
// 跨頁全域排序需要一次 O(全表) 的點查詢風暴）。本測試釘的正是那個界定。
func TestOffsiteFailuresPaginationAndOrdering(t *testing.T) {
	env := newOffsiteAPIEnv(t)
	token := env.adminToken(t, 304)

	now := time.Now()
	// 到期日刻意與 id 遞減序不同，否則「沒有重排」也會過
	deadlines := map[uint]*time.Time{
		9101: offsiteAt(now, 24*time.Hour+time.Hour),    // 1 天
		9102: offsiteAt(now, 5*24*time.Hour+time.Hour),  // 5 天
		9103: nil,                                       // 無到期日（永久保留）
		9104: offsiteAt(now, 2*24*time.Hour+time.Hour),  // 2 天
		9105: offsiteAt(now, 30*24*time.Hour+time.Hour), // 30 天
	}
	ids := map[uint]uint{}
	for _, owner := range []uint{9101, 9102, 9103, 9104, 9105} {
		row := env.seedObject(t, 1, owner, offsite.StateFailed)
		ids[owner] = row.ID
		env.describer.descs[owner] = offsite.OwnerDescription{
			Label:   "session-" + strconv.FormatUint(uint64(owner), 10),
			EndedAt: now.Add(-time.Hour), RetentionDeadline: deadlines[owner],
		}
	}

	// 第一頁：帳冊以 id DESC 取 9105／9104／9103，本層重排為到期近者在前
	w := env.do(t, http.MethodGet, "/api/v1/offsite-storage/failures?page=1&size=3", token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("失敗清單應 200，實得 %d (%s)", w.Code, w.Body.String())
	}
	page1 := offsiteBody(t, w)
	if int(page1["total"].(float64)) != 5 || int(page1["page"].(float64)) != 1 ||
		int(page1["page_size"].(float64)) != 3 {
		t.Fatalf("分頁中繼資料不符: %s", w.Body.String())
	}
	items1 := page1["data"].([]any)
	if len(items1) != 3 {
		t.Fatalf("第一頁應 3 筆，實得 %d: %s", len(items1), w.Body.String())
	}
	wantOrder := []uint{ids[9104], ids[9105], ids[9103]} // 2 天 → 30 天 → 無到期日殿後
	for i, it := range items1 {
		m := it.(map[string]any)
		if uint(m["object_id"].(float64)) != wantOrder[i] {
			t.Fatalf("第一頁第 %d 筆應為 object_id=%d，實得 %v（排序未依「到期近者在前、無到期日殿後」）",
				i+1, wantOrder[i], m["object_id"])
		}
	}
	// days_to_deadline 存在且合理
	first := items1[0].(map[string]any)
	if _, ok := first["days_to_deadline"]; !ok {
		t.Fatalf("到期在即的件必須帶 days_to_deadline: %v", first)
	}
	if d := int(first["days_to_deadline"].(float64)); d != 2 {
		t.Fatalf("days_to_deadline 應為 2，實得 %d", d)
	}
	if last := items1[2].(map[string]any); last["days_to_deadline"] != nil {
		if _, ok := last["days_to_deadline"]; ok {
			t.Fatalf("無到期日者不得帶 days_to_deadline: %v", last)
		}
	}

	// 第二頁：不與第一頁重疊
	w = env.do(t, http.MethodGet, "/api/v1/offsite-storage/failures?page=2&size=3", token, nil)
	page2 := offsiteBody(t, w)
	items2 := page2["data"].([]any)
	if len(items2) != 2 {
		t.Fatalf("第二頁應 2 筆，實得 %d: %s", len(items2), w.Body.String())
	}
	seen := map[float64]bool{}
	for _, it := range items1 {
		seen[it.(map[string]any)["object_id"].(float64)] = true
	}
	for _, it := range items2 {
		id := it.(map[string]any)["object_id"].(float64)
		if seen[id] {
			t.Fatalf("第二頁與第一頁重疊於 object_id=%v", id)
		}
	}
	// 頁內排序同樣成立：9101（1 天）在 9102（5 天）之前
	if uint(items2[0].(map[string]any)["object_id"].(float64)) != ids[9101] {
		t.Fatalf("第二頁排序不符（1 天者應在 5 天者之前）: %s", w.Body.String())
	}
}

func offsiteAt(base time.Time, d time.Duration) *time.Time {
	v := base.Add(d)
	return &v
}

// TestOffsiteRetryEndpointsConvergeNotFound 批次重試回筆數；單筆重試的兩種
// 「不可重試」**收斂同一個 404**。
//
// **逐位元組比對兩個回應**：可分辨即是資訊洩漏——「這個 id 存在但不是 failed」
// 與「這個 id 不存在」的差異只對攻擊者有意義（帳冊列的存在性），對管理員則是
// 同一個修正動作。
func TestOffsiteRetryEndpointsConvergeNotFound(t *testing.T) {
	env := newOffsiteAPIEnv(t)
	token := env.adminToken(t, 305)

	for _, owner := range []uint{9201, 9202, 9203} {
		env.seedObject(t, 1, owner, offsite.StateFailed)
	}
	uploaded := env.seedObject(t, 1, 9204, offsite.StateUploaded)

	w := env.do(t, http.MethodPost, "/api/v1/offsite-storage/retry-failed", token, map[string]any{})
	if w.Code != http.StatusOK {
		t.Fatalf("批次重試應 200，實得 %d (%s)", w.Code, w.Body.String())
	}
	if n := int(offsiteBody(t, w)["retried"].(float64)); n != 3 {
		t.Fatalf("批次重試應回 3 筆，實得 %d (%s)", n, w.Body.String())
	}
	var stillFailed int64
	if err := env.db.Model(&model.OffsiteObject{}).
		Where("state = ?", offsite.StateFailed).Count(&stillFailed).Error; err != nil {
		t.Fatalf("計數 failed: %v", err)
	}
	if stillFailed != 0 {
		t.Fatalf("批次重試後不應再有 failed 件，實得 %d", stillFailed)
	}

	missing := env.do(t, http.MethodPost, "/api/v1/offsite-storage/objects/987654/retry", token, map[string]any{})
	notFailed := env.do(t, http.MethodPost,
		fmt.Sprintf("/api/v1/offsite-storage/objects/%d/retry", uploaded.ID), token, map[string]any{})
	if missing.Code != http.StatusNotFound || notFailed.Code != http.StatusNotFound {
		t.Fatalf("兩種不可重試皆應 404，實得 %d／%d", missing.Code, notFailed.Code)
	}
	if !bytes.Equal(missing.Body.Bytes(), notFailed.Body.Bytes()) {
		t.Fatalf("「不存在」與「非 failed 態」的回應可分辨＝洩漏帳冊列存在性：\n  不存在：%s\n  非failed：%s",
			missing.Body.String(), notFailed.Body.String())
	}
	if code := offsiteErrCode(t, missing); code != string(apierror.CodeNotFoundOffsiteObject) {
		t.Fatalf("404 機器碼應為 %s，實得 %s", apierror.CodeNotFoundOffsiteObject, code)
	}
}

// TestOffsiteConnectionTestSemantics 連線測試的**兩種失敗語義分立**。
//
//	測試未能執行（欄位驗證、限流） → 4xx，走 apierror 信封、無 stages
//	測試已執行含失敗           → HTTP 200 ＋ stages[]（每階段 step／outcome／code）
//
// 把「bucket 不可達」回成 4xx 會使前端無從呈現「探測跑完但某一步失敗」的階梯結果，
// 而分階段定位正是這個端點存在的理由。
func TestOffsiteConnectionTestSemantics(t *testing.T) {
	env := newOffsiteAPIEnv(t)

	t.Run("未能執行：欄位驗證失敗走 apierror 信封", func(t *testing.T) {
		token := env.adminToken(t, 311)
		payload := env.s3Payload("")
		w := env.do(t, http.MethodPost, "/api/v1/offsite-storage/test", token, payload)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("驗證失敗應 4xx，實得 %d (%s)", w.Code, w.Body.String())
		}
		if code := offsiteErrCode(t, w); code != string(apierror.CodeValidationOffsiteBucketRequired) {
			t.Fatalf("機器碼應為 %s，實得 %s", apierror.CodeValidationOffsiteBucketRequired, code)
		}
		if strings.Contains(w.Body.String(), "stages") {
			t.Fatalf("測試未能執行時不得回 stages（那會讓前端誤以為探測跑過）: %s", w.Body.String())
		}
	})

	t.Run("未能執行：限流走 apierror 信封", func(t *testing.T) {
		token := env.adminToken(t, 312)
		env.factory.set(offsite.NewFakeClient("evidence-bucket-one"))
		payload := env.s3Payload("evidence-bucket-one")
		limited := false
		for i := 0; i < 8; i++ {
			w := env.do(t, http.MethodPost, "/api/v1/offsite-storage/test", token, payload)
			if w.Code == http.StatusTooManyRequests {
				if code := offsiteErrCode(t, w); code != string(apierror.CodeRuleOffsiteTestRateLimited) {
					t.Fatalf("429 機器碼應為 %s，實得 %s", apierror.CodeRuleOffsiteTestRateLimited, code)
				}
				if w.Header().Get("Retry-After") != "" {
					t.Fatal("限流回應不得附 Retry-After（會洩漏界線參數）")
				}
				limited = true
				break
			}
			if w.Code != http.StatusOK {
				t.Fatalf("第 %d 次測試應為 200 或 429，實得 %d (%s)", i+1, w.Code, w.Body.String())
			}
		}
		if !limited {
			t.Fatal("連續測試未觸發限流——per-actor 界線未生效")
		}
	})

	ladders := []struct {
		name    string
		build   func() *offsite.FakeClient
		passed  bool
		stages  int
		wantOne map[string]string // step → 期望 outcome
	}{
		{
			name: "全綠：六階皆 ok",
			build: func() *offsite.FakeClient {
				return offsite.NewFakeClient("evidence-bucket-one")
			},
			passed: true, stages: 6,
			wantOne: map[string]string{"probe_bucket": "ok", "write": "ok", "read": "ok", "delete": "ok"},
		},
		{
			name: "warn：治理讀不到＋刪除被拒，整體仍 passed",
			build: func() *offsite.FakeClient {
				c := offsite.NewFakeClient("evidence-bucket-one")
				c.SetGovernance(offsite.BucketGovernance{
					Versioning: offsite.VersioningUnknown, Retention: offsite.RetentionUnknown,
				})
				c.Inject(&offsite.FaultSlot{Op: "delete", Err: errors.New("access denied")})
				return c
			},
			passed: true, stages: 6,
			wantOne: map[string]string{"versioning": "warn", "retention": "warn", "delete": "warn"},
		},
		{
			name: "fail：bucket 不可達，停在第 0 段",
			build: func() *offsite.FakeClient {
				c := offsite.NewFakeClient("evidence-bucket-one")
				c.SetProbeError(errors.New("no such bucket"))
				return c
			},
			passed: false, stages: 1,
			wantOne: map[string]string{"probe_bucket": "fail"},
		},
	}
	for i, lc := range ladders {
		t.Run(lc.name, func(t *testing.T) {
			token := env.adminToken(t, uint(320+i))
			env.factory.set(lc.build())
			w := env.do(t, http.MethodPost, "/api/v1/offsite-storage/test", token,
				env.s3Payload("evidence-bucket-one"))
			if w.Code != http.StatusOK {
				t.Fatalf("測試已執行一律 200（含失敗），實得 %d (%s)", w.Code, w.Body.String())
			}
			var result struct {
				Passed bool `json:"passed"`
				Stages []struct {
					Step    string `json:"step"`
					Outcome string `json:"outcome"`
					Code    string `json:"code"`
				} `json:"stages"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatalf("測試結果無法解析: %v (%s)", err, w.Body.String())
			}
			if result.Passed != lc.passed {
				t.Fatalf("passed 應為 %v，實得 %v (%s)", lc.passed, result.Passed, w.Body.String())
			}
			if len(result.Stages) != lc.stages {
				t.Fatalf("stages 應 %d 階，實得 %d (%s)", lc.stages, len(result.Stages), w.Body.String())
			}
			got := map[string]string{}
			for _, s := range result.Stages {
				if s.Step == "" || s.Outcome == "" {
					t.Fatalf("每一階段皆須有 step 與 outcome: %s", w.Body.String())
				}
				if s.Outcome != "ok" && s.Code == "" {
					t.Fatalf("非 ok 的階段必須帶機器碼: %s", w.Body.String())
				}
				got[s.Step] = s.Outcome
			}
			for step, outcome := range lc.wantOne {
				if got[step] != outcome {
					t.Fatalf("階段 %s 應為 %s，實得 %q (%s)", step, outcome, got[step], w.Body.String())
				}
			}
		})
	}
}
