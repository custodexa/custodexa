package offsite

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"
)

// 測試連線（責任邊界裁定後的中立化版本）：
// 第 0 段＝ProbeBucket 治理現況揭露（只回報、不判好壞）；
// 第 1 段＝無任何保留欄位的寫→讀→刪實測。
// 步驟以 driver 介面中立化，機器碼跨 driver 同碼。

// 逐步結果的 outcome 值域。
const (
	StepOK   = "ok"
	StepWarn = "warn"
	StepFail = "fail"
)

// 步驟名（回應的 step 欄；i18n 查譯鍵於 API 波（1.9）落地）。
const (
	StepProbeBucket = "probe_bucket"
	StepVersioning  = "versioning"
	StepRetention   = "retention"
	StepWrite       = "write"
	StepRead        = "read"
	StepDelete      = "delete"
)

// 測試連線的機器碼（offsite.*；apierror 三語登記屬 1.9）。
const (
	// CodeTestBucketUnreachable 第 0 段：bucket 不存在或不可達
	CodeTestBucketUnreachable = "offsite.test_bucket_unreachable"
	// CodeTestGovernanceUnknown 治理現況讀不到（權限不足等）；
	// warn——無法確認、不影響上傳
	CodeTestGovernanceUnknown = "offsite.test_governance_unknown"
	// CodeTestWriteFailed 探測物寫入失敗
	CodeTestWriteFailed = "offsite.test_write_failed"
	// CodeTestReadFailed 探測物讀回失敗
	CodeTestReadFailed = "offsite.test_read_failed"
	// CodeTestReadMismatch 讀回內容與寫入不符
	CodeTestReadMismatch = "offsite.test_read_mismatch"
	// CodeTestDeleteDenied 探測物刪除被拒——**收斂單一 warn、不細分**
	// （bucket 保留擋下或憑證缺刪除權限，兩者都只是 warn，
	// 產品正式路徑對遠端零刪除，不依賴刪除能力）
	CodeTestDeleteDenied = "offsite.test_delete_denied"
)

// StepResult 測試連線的一步結果。**不含端點 origin 以外的任何憑證資訊**；
// Detail 為機器可讀的現況描述，不回顯任何鍵值。
type StepResult struct {
	Step    string `json:"step"`
	Outcome string `json:"outcome"` // ok|warn|fail
	// ErrorCode outcome 非 ok 時的機器碼（offsite.*）；ok 恆空
	ErrorCode string `json:"error_code,omitempty"`
	// Detail 現況描述（治理揭露的內容、warn 的並列可能）
	Detail string `json:"detail,omitempty"`
}

// RunConnectionTest 執行兩段式測試連線，回逐步結果陣列。
//
// 遇 fail 即停在該步（後續步驟必然無意義）；warn 不中斷。
// prefix＝部署設定的 key 前綴；now 注入時刻來源（探測物命名）。
func RunConnectionTest(ctx context.Context, c Client, prefix string, now func() time.Time) []StepResult {
	var steps []StepResult

	// ── 第 0 段：ProbeBucket 治理現況揭露（只讀） ──
	gov, err := c.ProbeBucket(ctx)
	if err != nil {
		return append(steps, StepResult{
			Step: StepProbeBucket, Outcome: StepFail, ErrorCode: CodeTestBucketUnreachable,
			Detail: "bucket 不存在或不可達",
		})
	}
	steps = append(steps, StepResult{Step: StepProbeBucket, Outcome: StepOK, Detail: "bucket 可達"})
	steps = append(steps, disclosureStep(StepVersioning, string(gov.Versioning),
		gov.Versioning == VersioningUnknown))
	retentionDetail := string(gov.Retention)
	if gov.RetentionDetail != "" {
		retentionDetail += "（" + gov.RetentionDetail + "）"
	}
	steps = append(steps, disclosureStep(StepRetention, retentionDetail,
		gov.Retention == RetentionUnknown))

	// ── 第 1 段：寫讀刪實測（無任何保留欄位） ──
	key := ConnectionTestObjectKey(prefix, now().UnixNano())
	payload := []byte(fmt.Sprintf("custodexa-connection-test %d", now().Unix()))

	if _, err := c.Put(ctx, key, bytes.NewReader(payload), PutOpts{
		ContentLength: int64(len(payload)),
	}); err != nil {
		return append(steps, StepResult{
			Step: StepWrite, Outcome: StepFail, ErrorCode: CodeTestWriteFailed,
			Detail: "探測物寫入失敗",
		})
	}
	steps = append(steps, StepResult{Step: StepWrite, Outcome: StepOK})

	rd, err := c.Fetch(ctx, ObjectRef{Key: key}, int64(len(payload)))
	if err != nil {
		return append(steps, StepResult{
			Step: StepRead, Outcome: StepFail, ErrorCode: CodeTestReadFailed,
			Detail: "探測物讀回失敗",
		})
	}
	got, readErr := io.ReadAll(rd)
	_ = rd.Close()
	switch {
	case readErr != nil:
		return append(steps, StepResult{
			Step: StepRead, Outcome: StepFail, ErrorCode: CodeTestReadFailed,
			Detail: "探測物讀回中斷",
		})
	case !bytes.Equal(got, payload):
		return append(steps, StepResult{
			Step: StepRead, Outcome: StepFail, ErrorCode: CodeTestReadMismatch,
			Detail: "讀回內容與寫入不符",
		})
	}
	steps = append(steps, StepResult{Step: StepRead, Outcome: StepOK})

	// 刪除探測物：**本呼叫是全產品非測試碼中 Client.Delete 的唯一合法呼叫點**
	// （防誤接雙層之 (b)，internal/guards/offsitedelete 靜態守衛釘住）。
	// 被拒收斂單一 warn、不細分。
	if err := c.Delete(ctx, ObjectRef{Key: key}); err != nil {
		return append(steps, StepResult{
			Step: StepDelete, Outcome: StepWarn, ErrorCode: CodeTestDeleteDenied,
			Detail: "探測物刪除被拒。兩種可能並存：bucket 保留設定擋下（若你依部署指引設了保留，" +
				"這是預期行為）或憑證缺刪除權限；測試物件將由 bucket lifecycle 或人工清除，" +
				"不計入產品追蹤",
		})
	}
	return append(steps, StepResult{Step: StepDelete, Outcome: StepOK})
}

// disclosureStep 治理揭露步：值可讀＝ok＋現況描述；讀不到＝warn（不影響上傳）。
func disclosureStep(step, detail string, unknown bool) StepResult {
	if unknown {
		return StepResult{
			Step: step, Outcome: StepWarn, ErrorCode: CodeTestGovernanceUnknown,
			Detail: "無法確認（探測讀取失敗或儲存端不提供），不影響上傳",
		}
	}
	return StepResult{Step: step, Outcome: StepOK, Detail: detail}
}

// HasFailure 逐步結果中是否有 fail（API 波聚合整體結果用）。
func HasFailure(steps []StepResult) bool {
	for _, s := range steps {
		if s.Outcome == StepFail {
			return true
		}
	}
	return false
}
