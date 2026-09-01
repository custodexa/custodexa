// Package offsite 承載錄影與證據包的離機儲存基礎設施（evidence-offsite-storage）。
//
// 定位比照 internal/recorder、pkg/crypto/kms：**基礎設施包，不是第八個業務模組**。
// 對業務模組零 import；帳冊（offsite_objects）與 worker 於後續波次落於本包。
//
// 本檔定義 driver 契約：意圖導向的六個語義——上傳、核對、取回、
// 刪除、探測——而非任何特定後端的 API 鏡像。方法集刻意**放不進**逐物件保留與
// 版本綁定讀取：產品對遠端物件只做上傳、記帳、取回時驗證，
// 儲存端治理（不可覆寫、版本歷史、到期清理）由部署方以 bucket 設定承擔。
package offsite

import (
	"context"
	"errors"
	"io"
	"time"
)

// Provider 值域（driver 選擇；帳冊 provider 欄同值域）。
const (
	// ProviderS3 AWS S3 與 S3 相容端點（MinIO 等）
	ProviderS3 = "s3"
	// ProviderGCS Google Cloud Storage 原生 driver（JSON API）
	ProviderGCS = "gcs"
)

// ErrObjectNotFound 目標物件不存在（Head／Fetch／Delete 的跨 driver 收斂哨兵）。
//
// 各 driver 把自家的 not-found 形狀（s3 NoSuchKey／404、gcs ErrObjectNotExist）
// 一律包成本哨兵，消費端以 errors.Is 判定——契約測試對三個實作逐一釘住這件事。
var ErrObjectNotFound = errors.New("offsite: 目標物件不存在")

// ErrBucketNotFound 現行設定的 bucket 不存在（ProbeBucket 的收斂哨兵）。
var ErrBucketNotFound = errors.New("offsite: bucket 不存在")

// ObjectRef 中立位置引用。Bucket 空字串＝現行設定的 bucket；
// foreign 取回帶帳冊列上的舊 bucket——同 provider 同端點換 bucket
// 的情境可成功，換 provider 或端點必不可達。
type ObjectRef struct {
	Bucket string
	Key    string
}

// PutOpts 上傳選項。
//
// **無任何保留／鎖定／hold 欄位**：本結構的形狀就是責任邊界的
// 機械表達——遠端不可覆寫由部署方的 bucket 設定承擔，產品不代發保留請求。
type PutOpts struct {
	// Metadata 物件自訂 metadata（sha256／custodexa-object-id／custodexa-profile）
	Metadata map[string]string
	// ContentLength 內容長度（bytes）；驅動傳輸 deadline 的推導
	ContentLength int64
}

// PutResult 上傳結果。
type PutResult struct {
	// Version 儲存端回的版本識別（s3=versionId、gcs=generation 十進位）。
	// **參考性記錄**：有帶就記、任何路徑不依賴；
	// 非版本化 bucket 為空字串。
	Version string
}

// ObjectInfo Head 的結果（對 key 的**目前內容**，無版本綁定）。
type ObjectInfo struct {
	Size     int64
	Metadata map[string]string
	// Version 參考性記錄，同 PutResult.Version
	Version string
}

// VersioningState bucket 版本化現況的資訊性揭露（只回報、不判好壞）。
type VersioningState string

const (
	VersioningEnabled  VersioningState = "enabled"
	VersioningDisabled VersioningState = "disabled"
	// VersioningUnknown 讀不到（權限不足等）；warn「無法確認，不影響上傳」
	VersioningUnknown VersioningState = "unknown"
)

// RetentionSupport bucket 保留設定現況的資訊性揭露。
type RetentionSupport string

const (
	// RetentionNone 未偵測到任何 bucket 級或逐物件保留設定
	RetentionNone RetentionSupport = "none"
	// RetentionBucketPolicy bucket 級保留（s3=Object Lock default retention rule；
	// gcs=bucket retention policy）
	RetentionBucketPolicy RetentionSupport = "bucket_policy"
	// RetentionPerObject 逐物件保留能力已啟用（gcs ObjectRetentionMode=Enabled；
	// s3 Object Lock 啟用而無 default rule）。**只是能力啟用**：本產品不設定
	// 每物件保留期，單獨啟用不保護本產品上傳的物件（指引警示）
	RetentionPerObject RetentionSupport = "per_object"
	// RetentionUnknown 讀不到（權限不足／模擬器不支援）；降級為 warn
	RetentionUnknown RetentionSupport = "unknown"
)

// BucketGovernance 現行 bucket 的治理現況揭露（第 0 段）。
//
// 全部欄位皆**資訊性**：versioning 與 retention 開不開是部署方的決定，
// 產品只探測與揭露，供部署方對照指引確認設定有生效。
type BucketGovernance struct {
	Versioning VersioningState
	Retention  RetentionSupport
	// RetentionDetail 現況描述（模式／天數等，人讀），無則空；不含判斷語
	RetentionDetail string
}

// Client 儲存 driver 契約。
//
// 實作：s3Client（AWS／MinIO／S3 相容端點）、gcsClient（GCS 原生 JSON API）、
// FakeClient（測試）。三者共用同一套 contract test（contract_test.go），
// 防語義漂移；worker／Ledger／Fetcher／保管鏈／指標一律只面向本介面。
//
// 契約範圍＝object-store driver：ProbeBucket／bucket 語彙以物件儲存為前提；
// 非物件儲存（NFS 等）若日後要接，另立能力協商層，不在本契約射程。
type Client interface {
	// Put 一律寫**現行**設定的 bucket。無任何保留欄位；
	// 重試＝重傳同 key，內容相同故覆寫無害。
	Put(ctx context.Context, key string, r io.Reader, opts PutOpts) (PutResult, error)

	// Head 對 ref 的目前內容核對大小與 metadata（無版本綁定）。
	// 物件不存在回 ErrObjectNotFound。
	Head(ctx context.Context, ref ObjectRef) (ObjectInfo, error)

	// Fetch 取 ref 的目前內容；正確性由呼叫端以 SHA-256 驗證承擔。
	// expectedSize 為呼叫端已知的預期大小（帳冊 size），用於推導傳輸 deadline；
	// ≤0 時取保守下限。回傳的 ReadCloser 由呼叫端負責 Close（Close 一併釋放
	// deadline 資源）。物件不存在回 ErrObjectNotFound。
	Fetch(ctx context.Context, ref ObjectRef, expectedSize int64) (io.ReadCloser, error)

	// Delete 刪除 ref 指向的物件。
	//
	// **正式產品路徑（含保留清理）不呼叫本方法**——遠端到期清理由部署方的
	// bucket lifecycle 承擔；本方法存在為未來擴充點
	// （屆時只接線、不改 driver），現階段唯一合法呼叫者＝TestConnection
	// 清理自己的探測物。此不變式由靜態守衛
	// internal/guards/offsitedelete 斷言（誤接即紅）。
	Delete(ctx context.Context, ref ObjectRef) error

	// ProbeBucket 現行 bucket 的存在性與治理現況揭露（第 0 段）。
	// bucket 不存在回 ErrBucketNotFound；治理欄讀不到時以 Unknown 值降級、
	// 不回錯誤（探測失敗不影響上傳）。
	ProbeBucket(ctx context.Context) (BucketGovernance, error)
}

// 逐呼叫 deadline 常數（gcs 沿同表）。
const (
	// opTimeoutShort Head／Delete／ProbeBucket（組態讀取）的 deadline
	opTimeoutShort = 30 * time.Second
	// transferTimeoutFloor Put／Fetch 的 deadline 下限（守衛防調得更緊，見
	// TestTransferTimeoutFloorNotLowered）
	transferTimeoutFloor = 2 * time.Minute
	// transferRateBytesPerSec deadline 推導的保守傳輸速率基準（1 MiB/s，design §9）
	transferRateBytesPerSec = 1 << 20
)

// transferTimeout Put／Fetch 的 deadline：max(2 分鐘, size ÷ 1 MiB/s × 2)。
// size ≤ 0（未知）取下限。
func transferTimeout(size int64) time.Duration {
	if size <= 0 {
		return transferTimeoutFloor
	}
	d := time.Duration(size/transferRateBytesPerSec) * time.Second * 2
	if d < transferTimeoutFloor {
		return transferTimeoutFloor
	}
	return d
}

// deadlineReadCloser 把 Fetch 的 deadline cancel 綁到 ReadCloser.Close：
// 資料串流在 Fetch 返回後才發生，deadline 的生命週期必須跟著串流走。
type deadlineReadCloser struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (d *deadlineReadCloser) Close() error {
	err := d.ReadCloser.Close()
	d.cancel()
	return err
}
