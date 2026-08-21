import request from './request'

/** 通道加密清冊（admin；transmission-security-policy 4.1，讀取入審計） */
export function getTransmissionInventory() {
  return request({
    url: '/transmission-inventory',
    method: 'get',
  })
}

/** 匯出清冊快照（admin；4.2，回 JSON＋時間戳＋產生者，匯出入審計） */
export function exportTransmissionInventory() {
  return request({
    url: '/transmission-inventory/export',
    method: 'post',
  })
}
