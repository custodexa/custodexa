import request from './request'

/**
 * 取得 syslog 轉發設定與轉發狀態
 * @returns {Promise} 回傳 { data: { dropped: number, setting: SyslogSetting } }
 */
export function getSyslogSettings() {
  return request({
    url: '/syslog-settings',
    method: 'get',
  })
}

/**
 * 更新 syslog 轉發設定（後端寫入審計；啟用時 host 必填由後端驗證）
 * @param {Object} data - { enabled, host, port, protocol: 'udp'|'tcp'|'tcp+tls', tls_ca }
 * @returns {Promise} 回傳 { data: SyslogSetting }
 */
export function updateSyslogSettings(data, options = {}) {
  return request({
    url: '/syslog-settings',
    method: 'put',
    data,
    skipErrorToast: options.skipErrorToast === true,
  })
}

/**
 * 以目前表單值發送測試訊息（不落庫；測試即實送，受傳輸政策閘管——
 * warn 檔對非 TLS 端點測試須帶 risk_acknowledged）
 * 成敗由 HTTP 狀態碼表達（asset-syslog-debt-cleanup D1）：送達成功 resolve
 * 為 { data: { success: true } }；送達失敗 reject，回應為 502 且 body 為
 * { error, code: 'INTERNAL_SYSLOG_TEST_FAILED' }（以 resolveApiError 查譯）；
 * 傳輸政策閘未確認則 reject 於 400＋code='VALIDATION_TRANSMISSION_ACK_REQUIRED'
 * @param {Object} data - 同 updateSyslogSettings 的 body
 * @returns {Promise} 成功時回傳 { data: { success: true } }
 */
export function testSyslogSettings(data, options = {}) {
  return request({
    url: '/syslog-settings/test',
    method: 'post',
    data,
    skipErrorToast: options.skipErrorToast === true,
  })
}
