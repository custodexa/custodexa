// 連線測試成功但主機身分與記錄不符：以不自動消失的通知卡呈現（duration 0）。
// 一般 toast 數秒後消失，使用者可能沒讀到「憑證已送出、可能有人冒充」就錯過，
// 故改為需手動關閉的通知卡。同一資產重測時先關掉前一張，避免卡片堆疊。
import { h } from 'vue'
import { ElNotification } from 'element-plus'
import { t } from '@/i18n'
import HostKeyMismatchTestCard from '@/components/asset/HostKeyMismatchTestCard.vue'

const openCards = new Map()

/**
 * @param {Object} opts
 * @param {number|string} opts.assetId 被測資產
 * @param {number} [opts.latencyMs] 撥測延遲（標題列沿用一般成功文案）
 * @param {Function} [opts.onGo] 超管點「前往資產設定採用或重置主機金鑰」：卡片先關再交呼叫端開抽屜
 * @returns {{close: Function}} ElNotification handle
 */
export function notifyHostKeyMismatchTest({ assetId, latencyMs, onGo }) {
  openCards.get(assetId)?.close()
  let handle = null
  const go = () => {
    handle?.close()
    onGo?.(assetId)
  }
  handle = ElNotification({
    type: 'success',
    title: t('assets.testSuccess', { ms: latencyMs }),
    duration: 0,
    position: 'bottom-right',
    customClass: 'host-key-test-notification',
    message: h(HostKeyMismatchTestCard, { onGo: go }),
    onClose: () => {
      if (openCards.get(assetId) === handle) {
        openCards.delete(assetId)
      }
    },
  })
  openCards.set(assetId, handle)
  return handle
}
