package apierror

// 整批中有項目無法操作（無權、範圍外或不存在）的單一碼。
//
// 唯一寫出函式為 middleware.RespondBatchUnavailable；回應只帶筆數，不帶任何 ID 或名稱，
// 三種原因不可區分。選 404 與單筆「範圍外等於不存在」同一語義。
var CodeBatchItemsUnavailable = register("NOTFOUND_BATCH_ITEMS_UNAVAILABLE", Descriptor{
	ZhFallback: "{count} 筆項目無法操作",
	Params:     []ParamSpec{{Key: "count", Kind: ParamInt}},
})
