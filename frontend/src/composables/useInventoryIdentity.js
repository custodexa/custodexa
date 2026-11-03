import { computed, ref, watch } from 'vue'
import { t } from '@/i18n'
import { getAssetExecutor } from '@/api/assetExecutor'
import { visibleText } from '@/utils/visibleName'

/**
 * 盤點抽屜的「用誰登入」：依讀取回應的 next_identity 決定確認氣泡、從未盤點說明卡與發起條件的寫法。
 *
 * next_identity：{ mode: 'executor'|'default_account', username }，不支援或兩種身分都沒有時為 null；
 * 欄位缺席（undefined）時退回只看預設帳號。專用帳號名不在 next_identity 內：只有持
 * asset:executor-manage 者才呼叫專用帳號讀取端點取得，其他人一律用代稱，也不呼叫該端點。
 *
 * @param {Object} options
 * @param {import('vue').Ref<number|string>} options.assetId
 * @param {import('vue').Ref<boolean>} options.open - 抽屜是否開著（重新開啟時重讀專用帳號名）
 * @param {import('vue').Ref<Object|null|undefined>} options.nextIdentity
 * @param {import('vue').Ref<string>} options.defaultName - 帳號表的預設帳號名（next_identity 缺席時的退路）
 * @param {() => boolean} options.canManageExecutor - 是否持有 asset:executor-manage
 */
export function useInventoryIdentity({ assetId, open, nextIdentity, defaultName, canManageExecutor }) {
  const executorName = ref('')

  const mode = computed(() => {
    const n = nextIdentity.value
    if (n === undefined) return defaultName.value ? 'default_account' : null
    return n?.mode || null
  })
  const identityKnown = computed(() => nextIdentity.value !== undefined)
  const canExecutor = computed(() => !!canManageExecutor())

  // 持專用帳號管理權限者：為了在氣泡寫出帳號名，讀一次專用帳號；失敗或 404 退回代稱
  let seq = 0
  watch(
    () => [open.value, assetId.value, mode.value, canExecutor.value],
    async ([isOpen, id, m, can]) => {
      const mine = ++seq
      if (!isOpen || !id || m !== 'executor' || !can) {
        executorName.value = ''
        return
      }
      try {
        const res = await getAssetExecutor(id)
        if (mine === seq) executorName.value = res?.configured ? String(res.username || '').trim() : ''
      } catch {
        if (mine === seq) executorName.value = ''
      }
    },
    { immediate: true }
  )

  // 預設帳號名：next_identity 有給就用它，缺席時用帳號表
  const defaultAccountName = computed(() => {
    const n = nextIdentity.value
    if (n && n.mode === 'default_account') return String(n.username || '').trim()
    return n === undefined ? defaultName.value : ''
  })

  const confirmTitle = computed(() => {
    if (mode.value === 'executor') {
      return executorName.value
        ? t('hostInventory.confirm.titleExecutor', { account: visibleText(executorName.value) })
        : t('hostInventory.confirm.titleExecutorNoName')
    }
    return defaultAccountName.value
      ? t('hostInventory.confirm.title', { name: visibleText(defaultAccountName.value) })
      : t('hostInventory.confirm.titleNoName')
  })
  // 沒有專用帳號、改用預設帳號時多一句提醒（結果可能不完整）
  const confirmNoExecutor = computed(() => mode.value === 'default_account')
  const neverCardKey = computed(() => (mode.value === 'executor' ? 'hostInventory.never.cardExecutor' : 'hostInventory.never.card'))

  return { executorName, mode, identityKnown, canExecutor, defaultAccountName, confirmTitle, confirmNoExecutor, neverCardKey }
}
