import { h } from 'vue'
import { confirmDestructive } from '@/utils/confirm'
import { accessPolicyEnumLabels } from '@/utils/policyFormat'
import { t } from '@/i18n'

/**
 * 單台連線政策降級的確認對話框（覆寫表與資產表單共用）。
 * 取消 reject（與 ElMessageBox.confirm 一致），呼叫端據此不送出並把顯示值還原。
 *
 * @param {{ assetName: string, nodePath?: string, change: { from: string|null, to: string|null, unknownDefault: boolean } }} opts
 */
export function confirmAccessPolicyDowngrade({ assetName, nodePath = '', change }) {
  const label = (v) => accessPolicyEnumLabels[v] || v
  const target = nodePath ? `${assetName}（${nodePath}）` : assetName
  const lines = []
  if (change.unknownDefault || change.to === null) {
    lines.push(t('accessPolicyDowngrade.unknownDefault', { asset: target }))
  } else {
    lines.push(
      t('accessPolicyDowngrade.change', { asset: target, from: label(change.from), to: label(change.to) })
    )
    lines.push(
      change.to === 'open'
        ? t('accessPolicyDowngrade.consequenceOpen')
        : t('accessPolicyDowngrade.consequenceReason')
    )
  }
  lines.push(t('accessPolicyDowngrade.notice'))
  return confirmDestructive(
    h('div', { style: 'white-space: pre-line' }, lines.join('\n')),
    t('accessPolicyDowngrade.title'),
    { confirmButtonText: t('accessPolicyDowngrade.confirm') }
  )
}
