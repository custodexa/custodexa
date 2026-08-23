// 連線結束原因唯一事實源（值域硬拷後端 model/session.go:20-26＋
// sshproxy/bridge.go、proxy/tunnel.go；完備性由 end-reason.spec.js 釘住）。
// 譯文住 locale 檔 enum.endReason.*，getter 回 t()

import { t } from '@/i18n'

export const END_REASON_VALUES = [
  'normal',
  'idle_timeout',
  'max_duration',
  'admin_terminate',
  'user_terminate',
  'backend_restart',
  'orphaned',
  'revoked',
  'block_clear_failed',
]

const END_REASON_TAG_TYPE = {
  normal: 'info',
  idle_timeout: 'warning',
  max_duration: 'warning',
  admin_terminate: 'danger',
  user_terminate: 'info',
  backend_restart: 'warning',
  orphaned: 'warning',
  revoked: 'danger',
  block_clear_failed: 'danger',
}

export const END_REASON_TEXT = {}
for (const value of END_REASON_VALUES) {
  Object.defineProperty(END_REASON_TEXT, value, {
    enumerable: true,
    get: () => t(`enum.endReason.${value}`),
  })
}

// 顯示文字：未知值原樣顯示（向前相容新值域），空值顯示 '-'
export const getEndReasonText = (reason) =>
  END_REASON_TEXT[reason] || reason || '-'

export const getEndReasonTagType = (reason) =>
  END_REASON_TAG_TYPE[reason] || 'info'
