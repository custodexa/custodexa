package offsite

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strconv"
	"sync"
	"sync/atomic"
)

// FakeClient Client 介面的記憶體測試替身（docs/dev/testing.md §7 三件套）。
//
//   - 故障注入格只對「命中本格 op＋key」的呼叫注入，回本格哨兵 error，
//     fired 計數供 t.Cleanup 斷言 >0（證明測試真的走到注入點）；
//   - 阻塞格（BlockUntilCtx）阻塞至 ctx 結束才回，供 deadline 觸發實證；
//   - metadata 模擬：Put 存入、Head 讀回，與真 driver 同語義；
//   - DeleteCalls 總計數：保留清理「對遠端零 Delete 呼叫」的行為層斷言
//     （防誤接雙層之 (a)）。
//
// **面向 Client 介面**，不模擬任何特定後端的 API 形狀。
type FakeClient struct {
	mu      sync.Mutex
	bucket  string
	objects map[string]*fakeObject // bucket + "\x00" + key
	genSeq  int64
	// versioned true 時 Put 回遞增 generation 作 Version（版本識別為參考性
	// 記錄——contract test 斷言「缺席不影響行為」，兩態都要能擺出來）
	versioned bool

	gov      BucketGovernance
	probeErr error

	faults []*FaultSlot

	deleteCalls atomic.Int64
	fetchCalls  atomic.Int64
}

type fakeObject struct {
	data     []byte
	metadata map[string]string
	version  string
}

// FaultSlot 一格故障注入。零值欄位＝不啟用該行為。
type FaultSlot struct {
	// Op 命中的操作：put／head／fetch／delete／probe
	Op string
	// Key 命中的 key；空字串＝該操作的所有 key（probe 無 key，恆以空匹配）
	Key string
	// Err 本格哨兵 error（呼叫端以 errors.Is 判定）
	Err error
	// BlockUntilCtx true＝阻塞至 ctx 結束、回 ctx.Err()（deadline 實證格）
	BlockUntilCtx bool
	// Content 非空且 Op=fetch 時，回本值取代實際內容（「遠端內容被竄改」格）
	Content []byte

	fired atomic.Int64
}

// Fired 本格被命中的次數（testing.md §7：t.Cleanup 斷言 >0）。
func (s *FaultSlot) Fired() int64 { return s.fired.Load() }

// NewFakeClient 以指定的現行 bucket 建立替身。
func NewFakeClient(bucket string) *FakeClient {
	return &FakeClient{
		bucket:  bucket,
		objects: map[string]*fakeObject{},
		gov:     BucketGovernance{Versioning: VersioningDisabled, Retention: RetentionNone},
	}
}

// Inject 掛入一格故障注入，回傳同一格供 fired 斷言。
func (f *FakeClient) Inject(slot *FaultSlot) *FaultSlot {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.faults = append(f.faults, slot)
	return slot
}

// SetGovernance 設定 ProbeBucket 的揭露內容。
func (f *FakeClient) SetGovernance(gov BucketGovernance) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gov = gov
}

// SetProbeError 設定 ProbeBucket 整體失敗（bucket 不可達等）。
func (f *FakeClient) SetProbeError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.probeErr = err
}

// SetVersioned 控制 Put 是否回版本識別（模擬版本化／非版本化 bucket 兩態）。
func (f *FakeClient) SetVersioned(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.versioned = v
}

// FetchCalls Fetch 被呼叫的總次數。取回的 singleflight 合併只能以計數器證明
// ——「兩個呼叫端都拿到內容」在未合併時同樣成立。
func (f *FakeClient) FetchCalls() int64 { return f.fetchCalls.Load() }

// DeleteCalls Delete 被呼叫的總次數（含被注入拒絕的呼叫）。
func (f *FakeClient) DeleteCalls() int64 { return f.deleteCalls.Load() }

// ObjectData 讀出物件現存內容與 metadata（測試檢視面；bucket 空＝現行）。
func (f *FakeClient) ObjectData(ref ObjectRef) ([]byte, map[string]string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.objects[f.objKey(ref)]
	if !ok {
		return nil, nil, false
	}
	return append([]byte(nil), o.data...), o.metadata, true
}

// ObjectCount 現存物件數。
func (f *FakeClient) ObjectCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.objects)
}

func (f *FakeClient) objKey(ref ObjectRef) string {
	b := ref.Bucket
	if b == "" {
		b = f.bucket
	}
	return b + "\x00" + ref.Key
}

// hitFault 找出第一個命中 op＋key 的注入格並執行其行為。
// 回 (err, true)＝本次呼叫由注入格接管。
func (f *FakeClient) hitFault(ctx context.Context, op, key string) (error, bool) {
	f.mu.Lock()
	var slot *FaultSlot
	for _, s := range f.faults {
		if s.Op == op && (s.Key == "" || s.Key == key) {
			slot = s
			break
		}
	}
	f.mu.Unlock()
	if slot == nil {
		return nil, false
	}
	slot.fired.Add(1)
	if slot.BlockUntilCtx {
		<-ctx.Done()
		if slot.Err != nil {
			return slot.Err, true
		}
		return ctx.Err(), true
	}
	if slot.Err != nil {
		return slot.Err, true
	}
	return nil, false // 純內容替換格（Content）：不回錯、由呼叫處取 Content
}

func (f *FakeClient) contentOverride(op, key string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.faults {
		if s.Op == op && (s.Key == "" || s.Key == key) && len(s.Content) > 0 {
			return append([]byte(nil), s.Content...)
		}
	}
	return nil
}

func (f *FakeClient) Put(ctx context.Context, key string, r io.Reader, opts PutOpts) (PutResult, error) {
	ctx, cancel := context.WithTimeout(ctx, transferTimeout(opts.ContentLength))
	defer cancel()
	if err, taken := f.hitFault(ctx, "put", key); taken {
		return PutResult{}, err
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return PutResult{}, fmt.Errorf("offsite: fake 讀取上傳內容失敗: %w", err)
	}
	meta := map[string]string{}
	for k, v := range opts.Metadata {
		meta[k] = v
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.genSeq++
	ver := ""
	if f.versioned {
		ver = strconv.FormatInt(f.genSeq, 10)
	}
	f.objects[f.objKey(ObjectRef{Key: key})] = &fakeObject{data: data, metadata: meta, version: ver}
	return PutResult{Version: ver}, nil
}

func (f *FakeClient) Head(ctx context.Context, ref ObjectRef) (ObjectInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeoutShort)
	defer cancel()
	if err, taken := f.hitFault(ctx, "head", ref.Key); taken {
		return ObjectInfo{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.objects[f.objKey(ref)]
	if !ok {
		return ObjectInfo{}, fmt.Errorf("offsite: fake head（key %s）: %w", ref.Key, ErrObjectNotFound)
	}
	return ObjectInfo{Size: int64(len(o.data)), Metadata: o.metadata, Version: o.version}, nil
}

func (f *FakeClient) Fetch(ctx context.Context, ref ObjectRef, expectedSize int64) (io.ReadCloser, error) {
	f.fetchCalls.Add(1)
	ctx, cancel := context.WithTimeout(ctx, transferTimeout(expectedSize))
	if err, taken := f.hitFault(ctx, "fetch", ref.Key); taken {
		cancel()
		return nil, err
	}
	if data := f.contentOverride("fetch", ref.Key); data != nil {
		return &deadlineReadCloser{ReadCloser: io.NopCloser(bytes.NewReader(data)), cancel: cancel}, nil
	}
	f.mu.Lock()
	o, ok := f.objects[f.objKey(ref)]
	f.mu.Unlock()
	if !ok {
		cancel()
		return nil, fmt.Errorf("offsite: fake fetch（key %s）: %w", ref.Key, ErrObjectNotFound)
	}
	return &deadlineReadCloser{
		ReadCloser: io.NopCloser(bytes.NewReader(append([]byte(nil), o.data...))),
		cancel:     cancel,
	}, nil
}

func (f *FakeClient) Delete(ctx context.Context, ref ObjectRef) error {
	f.deleteCalls.Add(1)
	ctx, cancel := context.WithTimeout(ctx, opTimeoutShort)
	defer cancel()
	if err, taken := f.hitFault(ctx, "delete", ref.Key); taken {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.objects, f.objKey(ref))
	return nil
}

func (f *FakeClient) ProbeBucket(ctx context.Context) (BucketGovernance, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeoutShort)
	defer cancel()
	if err, taken := f.hitFault(ctx, "probe", ""); taken {
		return BucketGovernance{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.probeErr != nil {
		return BucketGovernance{}, f.probeErr
	}
	return f.gov, nil
}
