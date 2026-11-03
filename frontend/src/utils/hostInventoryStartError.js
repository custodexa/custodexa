import { t } from '@/i18n'
import { resolveApiError } from '@/api/error'

// 專用帳號相關的三個發起錯誤：文案走 apiError，畫面不顯示任何數值
const EXECUTOR_START_ERRORS = [
  'RULE_INVENTORY_EXECUTOR_UNAVAILABLE',
  'CONFLICT_INVENTORY_EXECUTOR_BUSY',
  'RULE_INVENTORY_EXECUTOR_RATE_LIMITED',
]

/**
 * 發起盤點被拒時，狀態卡內就地顯示的句子與下一步。
 * @param {Object} err - axios 錯誤
 * @returns {{message: string, goAccounts: boolean, goExecutor: boolean, reload: boolean}}
 *   reload＝已有一筆在進行，呼叫端要重讀；goExecutor 只有「專用帳號沒有可用秘密」才有，
 *   且要持專用帳號管理權的人才顯示（由呼叫端判斷）。
 */
export function startErrorView(err) {
  const code = err?.response?.data?.code
  const status = err?.response?.status
  const view = { message: '', goAccounts: false, goExecutor: false, reload: false }
  if (code === 'CONFLICT_INVENTORY_SCAN_RUNNING') {
    view.message = t('hostInventory.err.running')
    view.reload = true
  } else if (code === 'RULE_INVENTORY_PLATFORM_UNSUPPORTED') {
    view.message = t('hostInventory.err.platform')
  } else if (code === 'RULE_INVENTORY_NO_ACCOUNT') {
    view.message = t('hostInventory.err.noAccount')
    view.goAccounts = true
  } else if (code === 'RULE_INVENTORY_NO_SECRET') {
    view.message = t('hostInventory.err.noSecret')
    view.goAccounts = true
  } else if (EXECUTOR_START_ERRORS.includes(code)) {
    view.message = resolveApiError(err.response.data, status)
    view.goExecutor = code === 'RULE_INVENTORY_EXECUTOR_UNAVAILABLE'
  } else if (status === 403 || status === 404) {
    view.message = t('hostInventory.err.notInScope')
  } else {
    view.message = t('hostInventory.err.generic')
  }
  return view
}
