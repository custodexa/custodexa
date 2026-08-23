import request from './request'

// 封印狀態與解封。
//
// **兩條端點都不要求 JWT**：要求 JWT 會在「admin 已開 MFA」時死鎖——TOTP secret
// 是信封加密欄，封印期解不開，管理員無法登入來解封。授權改由「知道 KEK」承擔
//（一般解封）；空金鑰表的初始化解封另要求初始管理員憑證（見 unseal 的 payload）。
// 故本模組的呼叫端不需要也不應該預設已登入；請求攔截器帶不帶 token 皆不影響。

// 取得封印狀態：state（sealed／unsealing／unsealed／sealed-faulted）、generation、
// cleanup_pending（待收束）、cooldown_until（冷卻到期）、fault_code（故障機器碼）、
// journal_faulted、timeout_total 與 timeout_retry_hint_code（逾時重試指引）、
// initialization_required（空金鑰表＝初始化解封路徑；未解封時才出現）
export function getSealStatus(config = {}) {
  return request({
    url: '/seal/status',
    method: 'get',
    ...config,
  })
}

// 送出一次解封嘗試。payload：
//   一般解封（既有部署）：{ kek }
//   初始化解封（空金鑰表）：{ kek, kek_confirm, confirm_saved, username, password }
// 後端以未知欄位拒絕（DisallowUnknownFields），故不得夾帶額外鍵。
// **材料類失敗（格式／解包／憑證／paste-back／保存確認）回應刻意不可區分**——
// 呼叫端 SHALL 直接呈現 resolveApiError 的結果，SHALL NOT 自行推測失敗成因。
export function unseal(payload, config = {}) {
  return request({
    url: '/seal/unseal',
    method: 'post',
    data: payload,
    ...config,
  })
}
