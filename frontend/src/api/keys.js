import request from './request'

// 金鑰清冊與換鑰精靈（admin only）

// 取得金鑰清冊：DB 側版本鏈＋env 側存在性＋遷移/重包狀態
export function getKeyInventory() {
  return request({
    url: '/keys',
    method: 'get',
  })
}

// 輪替金鑰：purpose = 'data'（批次重加密）| 'audit_integrity'（僅新章換鑰）
export function rotateKey(purpose) {
  return request({
    url: '/keys/rotate',
    method: 'post',
    data: { purpose },
  })
}

// KEK 重包（明文流向反轉後）。
//
// payload 為 **discriminated union**，由 mode 判別，變體互斥且鍵集精確
//（多鍵／少鍵／未知鍵／mode 與欄位不符一律 400 VALIDATION_KEY_REWRAP_*）：
//   本地 { mode: 'local', new_kek, new_kek_confirm, confirm_saved }
//   委託 { mode: 'kms' | 'hsm', key_ref }（本版後端回 501，UI 標示為本版未提供）
// 回應恰三鍵 { target_mode, new_kek_id, rewrapped_keys }——**不含任何 KEK 明文**：
// 材料由呼叫端提供，伺服端不生成、不回傳、不落庫、不落日誌。
// config 可傳 { skipErrorToast: true } 讓呼叫端自行呈現錯誤（如 409 衝突合併恢復指引）
export function rewrapKEK(payload, config = {}) {
  return request({
    url: '/keys/rewrap',
    method: 'post',
    data: payload,
    ...config,
  })
}

// 放棄未切換的 KEK 重包：軟退役未切換的新 KEK 包裹列、清待切換狀態，回現行 KEK 狀態
export function abandonRewrap() {
  return request({
    url: '/keys/rewrap',
    method: 'delete',
  })
}

// 清理退役金鑰資料：唯一的材料銷毀點。
// 回 { purged: [{purpose,version,kek_id}], skipped: [{purpose,version,kek_id,refs,reason}] }；
// 未收斂或鎖忙時 409（apierror 碼 CONFLICT_KEY_CLEANUP_NOT_CONVERGED／CONFLICT_KEY_OP_BUSY）。
// config 可傳 { skipErrorToast: true } 讓呼叫端自行呈現錯誤
export function cleanupRetiredMaterial(config = {}) {
  return request({
    url: '/keys/retired-material',
    method: 'delete',
    ...config,
  })
}
