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
