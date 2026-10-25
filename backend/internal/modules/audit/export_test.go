package audit

// UntracedSeqHooks 無來源變動事件寫入流程的測試掛點集合，未設定的欄位維持 nil。
type UntracedSeqHooks struct {
	AfterCompare  func(attempt int, headSeq int64)
	AfterInsert   func(attempt int)
	AfterConflict func(attempt int)
	SavepointStep func(step string) error
}

// SetUntracedSeqHooksForTest 設定掛點並回傳還原函式；須在啟動並發寫入之前呼叫。
func SetUntracedSeqHooksForTest(h UntracedSeqHooks) func() {
	prev := UntracedSeqHooks{untracedAfterCompare, untracedAfterInsert, untracedAfterConflict, untracedSavepointStep}
	untracedAfterCompare, untracedAfterInsert, untracedAfterConflict, untracedSavepointStep =
		h.AfterCompare, h.AfterInsert, h.AfterConflict, h.SavepointStep
	return func() {
		untracedAfterCompare, untracedAfterInsert, untracedAfterConflict, untracedSavepointStep =
			prev.AfterCompare, prev.AfterInsert, prev.AfterConflict, prev.SavepointStep
	}
}
