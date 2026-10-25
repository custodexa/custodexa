import { ref } from 'vue'
import { t } from '@/i18n'
import { useAssignmentPreview } from '@/composables/useAssignmentPreview'
import { needsDangerConfirm } from '@/utils/dangerCombo'

/**
 * 映射規則變更的儲存前預覽與確認。預覽是建議性的：失敗或無權（403）一律標示暫時無法取得，
 * 仍交由使用者決定是否儲存。gate(body, ctx) 回傳 true 才繼續送出寫入；
 * 沒有需要確認的內容時直接放行。ctx：{ newTarget, managementRoles, oldTarget }。
 */
export function useRuleChangeGate(busy) {
  const preview = useAssignmentPreview()
  const confirmOpen = ref(false)
  const confirmPreview = ref(null)
  const confirmUnavailable = ref(false)
  const confirmNotify = ref('')
  const confirmFootnote = ref('')
  let decide = null

  const notifyFor = (data, ctx) => {
    const op = data?.operation || {}
    if (['increase', 'decrease'].includes(op.self_direction) || (data?.subjects || []).some(item => item.self)) return t('dangerConfirm.notify.selfChange')
    if ((op.marks || []).length && ctx.managementRoles?.length) return t('dangerConfirm.notify.mappingRule', { target: ctx.newTarget, role: ctx.managementRoles.join('、') })
    return ''
  }

  const gate = async (body, ctx = {}) => {
    busy.value = true
    let outcome
    try { outcome = await preview.run(body) } finally { busy.value = false }
    if (outcome.ok && !needsDangerConfirm(outcome.data)) return true
    confirmPreview.value = outcome.ok ? outcome.data : null
    confirmUnavailable.value = !outcome.ok
    confirmNotify.value = outcome.ok ? notifyFor(outcome.data, ctx) : ''
    confirmFootnote.value = ctx.oldTarget ? t('dangerConfirm.oldTargetRevoked', { target: ctx.oldTarget }) : ''
    confirmOpen.value = true
    return new Promise(resolve => { decide = resolve })
  }
  const settle = (value) => {
    confirmOpen.value = false
    const done = decide
    decide = null
    done?.(value)
  }
  return {
    confirmOpen, confirmPreview, confirmUnavailable, confirmNotify, confirmFootnote,
    gate, proceedConfirm: () => settle(true), cancelConfirm: () => settle(false),
  }
}
