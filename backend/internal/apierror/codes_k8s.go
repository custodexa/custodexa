package apierror

// K8s 連線錯誤分類碼。
//
// 對應 `k8sproxy.classifyErr` 的六類（K8sError.Kind：unauthorized / forbidden /
// notfound / tls / unreachable / unknown）。原本這六類只以 `Message` 散文經
// WS 幀 Data 傳遞、共用 RULE_K8S_POD_UNAVAILABLE 一碼，前端無從分辨；此處
// 一類一碼，前端可依碼查譯並給出對應處置指引。
//
// 與 k8sproxy 的分工：分類邏輯與其 zh 文案留在 k8sproxy（含 namespace 等
// 具體脈絡），映射（Kind → 本檔的碼）在 sshproxy 側；WS 幀的 Data 仍帶
// k8sproxy 的原文案當 fallback，故本檔的 ZhFallback 是**不含 namespace 的
// 泛化版**（碼的 ZhFallback 不接受 opaque 值內嵌，見 ParamOpaque 契約）。
var (
	CodeK8sUnauthorized = register("RULE_K8S_UNAUTHORIZED", Descriptor{
		ZhFallback: "Token 認證失敗（401）：請確認 Bearer Token 有效"})
	CodeK8sForbidden = register("RULE_K8S_FORBIDDEN", Descriptor{
		ZhFallback: "無權限（403）：Token 缺少該 namespace 的 list pods 權限"})
	CodeK8sNamespaceNotFound = register("RULE_K8S_NAMESPACE_NOT_FOUND", Descriptor{
		ZhFallback: "namespace 不存在（404）"})
	CodeK8sTLSFailed = register("RULE_K8S_TLS_FAILED", Descriptor{
		ZhFallback: "TLS 憑證驗證失敗：請設定正確的 CA 憑證，或（不建議）開啟略過驗證"})
	CodeK8sUnreachable = register("RULE_K8S_UNREACHABLE", Descriptor{
		ZhFallback: "無法連到 API server：請確認位址/連接埠與網路可達性"})
	CodeK8sUnknown = register("RULE_K8S_UNKNOWN", Descriptor{
		ZhFallback: "連線 K8s 失敗，請確認叢集位址、認證與網路"})
)
