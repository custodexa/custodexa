import { findExecutorError } from '@/constants/assetExecutor'
import { resolveApiError } from '@/api/error'

function errorParam(data, key) {
  return data?.params?.[key] ?? data?.details?.[key]
}

/**
 * 把設定對話框送出的錯誤回應轉成就地錯誤列：落點、一句原因、修正鈕。
 * 落點與文案鍵查 EXECUTOR_ERROR_TABLE；表外或標 apiError 的碼以 resolveApiError 為原因句。
 *
 * @param {Object} ctx
 * @param {string} ctx.code - 錯誤碼
 * @param {Object} ctx.data - 回應本文（帶 params）
 * @param {number} ctx.status - HTTP 狀態
 * @param {'set'|'replace'|'convert'} ctx.context - 對話框當下的情境
 * @param {Function} ctx.t - i18n
 * @param {boolean} ctx.windowsFamily - Windows 族沒有平台產生金鑰，修正改為直接輸入密碼
 * @param {string} ctx.submittedName - 送出的帳號名稱
 * @param {Object|null} ctx.convertAccount - 轉換時選定的帳號列
 * @param {number} ctx.confirmedFrom - 送出時確認的台數（對話框自己保留，不取自伺服器）
 * @param {number} ctx.shownCount - 畫面上顯示的台數（伺服器沒回 count 時沿用）
 * @param {string} ctx.secretWord - 「密碼」或「金鑰」
 * @returns {{ placement: string, text: string, fixAction: string|null, fixLabel?: string, recheck?: string, count?: number, credentialId?: number }}
 */
export function buildExecutorError(ctx) {
  const { code, data, status, context, t } = ctx
  const row = findExecutorError(code, context) || findExecutorError(code, 'set')
  const fallback = resolveApiError(data, status, t('assetExecutor.dialog.createFailed'))
  if (!row || row.messageKey === 'apiError') {
    const placement = row?.placement && row.placement !== 'reload' ? row.placement : 'button'
    return { placement, text: fallback, fixAction: null }
  }
  switch (row.fixAction) {
    case 'useConvert':
      return {
        placement: 'field-username',
        text: t(row.messageKey, { account: ctx.submittedName }),
        fixAction: 'useConvert',
        fixLabel: t('assetExecutor.error.useConvert'),
      }
    case 'confirmCount': {
      const to = Number(errorParam(data, 'count')) || ctx.shownCount
      return {
        placement: 'confirm-count',
        text: t(row.messageKey, { from: ctx.confirmedFrom, to, secret: ctx.secretWord }),
        fixAction: 'confirmCount',
        fixLabel: t('assetExecutor.error.confirmCount', { count: to }),
        count: to,
      }
    }
    case 'useGenerate':
      // Windows 族沒有平台產生金鑰：句尾與修正鈕都改為直接輸入密碼
      return {
        placement: 'field-credential',
        text: t(ctx.windowsFamily ? 'assetExecutor.error.purposeMismatchWindows' : row.messageKey),
        fixAction: 'useGenerate',
        fixLabel: ctx.windowsFamily ? t('assetExecutor.error.useInlinePassword') : t('assetExecutor.error.useGenerate'),
      }
    case 'openPlans':
    case 'openRotation':
    case 'openCredentials': {
      const accountName = ctx.convertAccount?.username || ''
      return {
        placement: 'field-account',
        text: t(row.messageKey, { account: accountName }),
        fixAction: row.fixAction,
        fixLabel: t(`assetExecutor.error.${row.fixAction}`),
        recheck: t('assetExecutor.error.recheckConvert'),
        credentialId: ctx.convertAccount?.credential_id || 0,
      }
    }
    default:
      return { placement: 'button', text: fallback, fixAction: null }
  }
}
