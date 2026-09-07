import request from './request'

// 單實例守衛的完整快照（管理者限定；single-instance-guard）。
//
// 與 seal/status 的 `instance_guard` 粗狀態分兩層：粗狀態不寫審計列、供橫幅每 60 秒輪詢；
// 本端點每次呼叫經審計中介層留一列讀取，**只在橫幅出現時由管理者取一次**（與手動重新整理），
// 呼叫端 SHALL NOT 對它輪詢。
// 回應：state／since／reason／instance{hostname,pid,started_at}／db_session_pid／
// holder{application_name,pid,backend_start,code,fingerprint_source}（無持鎖者時 null）／
// ack／lost_total／peers。
export function getInstanceGuard(config = {}) {
  return request({
    url: '/instance-guard',
    method: 'get',
    ...config,
  })
}

// —— 攔下模式的兩條未認證端點（preservice-pages）——
//
// 服務尚未上線時可達：段 2 未起、JWT 不可能存在，故兩者都不帶身分，
// 可達性由與解封端點同一份來源網段組態承擔。與上方的管理者端點分屬不同
// 生命週期階段（攔下期／服務中），共置於本模組只因主題相同。

// 取得攔下狀態。回應：
// `{ state: "halted"|"running", since, holder{application_name,pid,backend_start,code,
//    fingerprint_source}|null, retry_interval_seconds }`。
// 唯讀、無副作用；攔下頁據 `retry_interval_seconds` 決定輪詢週期。
export function getInstanceGuardHalt(config = {}) {
  return request({
    url: '/instance-guard/halt',
    method: 'get',
    ...config,
  })
}

// 送出三要件確認。payload：`{ confirmed_primary_down, code, username, password }`。
// **失敗一律以機器碼分流，不看 HTTP 狀態碼**：退避回應是 429（行程內計數，
// 不是帳號鎖定閘），帳密錯是 401，持鎖者變更是 409 且 body 頂層另帶
// `holder`／`state`／`retry_interval_seconds`（後端以 apierror 的 Meta 平鋪）。
// 帳密錯的 401 帶自己的機器碼，故不會被請求層當成 access token 失效而觸發續期。
export function ackInstanceGuardHalt(payload, config = {}) {
  return request({
    url: '/instance-guard/ack',
    method: 'post',
    data: payload,
    ...config,
  })
}
