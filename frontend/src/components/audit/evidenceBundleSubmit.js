// 操作日誌頁「匯出稽核證據包」的送出邏輯（audit-workflows「證據包的非同步交付」）。
//
// 證據包只經非同步 job 交付：送出後在背景打包，產物到下載中心取件。
// 這一按沒有檔案落下來，所以提示必須說清楚「去哪裡拿」並附連結。
import { h } from 'vue'
import { ElMessage, ElNotification } from 'element-plus'
import { createAuditExportJob } from '@/api/auditExport'
import { resolveApiError } from '@/api/error'
import { t } from '@/i18n'

export const DOWNLOAD_CENTER_PATH = '/audit/exports'

/**
 * 由對話框欄位組出範圍條件；三項皆空時回 null（後端要求至少一項）。
 * @param {Array} timeRange [start, end]
 * @param {{user_id?:number|null, asset_id?:number|null}} form
 * @returns {Object|null}
 */
export function buildBundleScope(timeRange, form) {
  const scope = {}
  if (Array.isArray(timeRange) && timeRange.length === 2) {
    scope.start_time = timeRange[0]
    scope.end_time = timeRange[1]
  }
  if (form?.user_id) scope.user_id = form.user_id
  if (form?.asset_id) scope.asset_id = form.asset_id
  return Object.keys(scope).length > 0 ? scope : null
}

function notifyQueued(deduplicated, router) {
  const title = deduplicated ? t('auditLogs.exportDeduplicated') : t('auditLogs.exportSuccess')
  const hint = deduplicated
    ? t('auditLogs.exportDeduplicatedHint')
    : t('auditLogs.exportSuccessHint')
  let handle = null
  const goDownloads = (event) => {
    event.preventDefault()
    handle?.close()
    router.push(DOWNLOAD_CENTER_PATH)
  }
  handle = ElNotification({
    type: deduplicated ? 'info' : 'success',
    title,
    duration: 8000,
    message: h('div', { 'data-test': 'export-queued-notice' }, [
      h('div', hint),
      h(
        'a',
        {
          href: DOWNLOAD_CENTER_PATH,
          style: 'color: var(--el-color-primary)',
          'data-test': 'export-go-downloads',
          onClick: goDownloads,
        },
        t('auditLogs.exportGoDownloads')
      ),
    ]),
  })
}

/**
 * 送出證據包打包。成功（含同範圍去重）回 true；失敗以後端文案提示並回 false。
 *
 * 錯誤由這裡呈現而非全域攔截器：關閉全域 toast，避免同一錯誤出現兩次，
 * 也讓本頁的錯誤文案與後端回傳一致（code 譯文 → 後端 error → 通用語）。
 * @param {Object} scope buildBundleScope 的結果
 * @param {{push: Function}} router
 * @returns {Promise<boolean>}
 */
export async function submitEvidenceBundle(scope, router) {
  try {
    const res = await createAuditExportJob(
      { ...scope, pack: 'evidence_bundle' },
      { skipErrorToast: true }
    )
    notifyQueued(Boolean(res?.deduplicated), router)
    return true
  } catch (error) {
    const resp = error?.response
    ElMessage.error(resp ? resolveApiError(resp.data, resp.status) : t('api.networkError'))
    return false
  }
}
