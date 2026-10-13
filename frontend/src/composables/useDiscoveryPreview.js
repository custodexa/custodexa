// 探索預覽：呼叫、結果、錯誤種類與時間，詳情頁左欄與接通前確認面板共用。
//
// 結果綁定送出當下的 issuer：
// - 每次送出記下受測 issuer 與遞增序號；回覆不是最新一次送出的就丟棄，
//   較舊的請求晚到不得蓋掉較新的結果。
// - 表單目前的 issuer 與受測值不同＝stale（結果已過期）。
// - 未過期且受測值與已儲存值不同＝unsaved（結果對應的是還沒存的網址）。
// - 換到另一個來源時清空結果並作廢進行中的請求。
import { ref, computed, watch } from 'vue'
import { t } from '@/i18n'
import { resolveApiError } from '@/api/error'
import { previewOIDCDiscovery, isNotImplemented } from '@/api/identitySources'

const errorKindOf = (error) => {
  if (isNotImplemented(error)) return 'error'
  const status = error?.response?.status
  if (status === 400) return 'invalid'
  if (status === 502) return 'unreachable'
  return 'error'
}

const errorTextOf = (error) =>
  isNotImplemented(error)
    ? t('identitySources.oidc.discoveryPending')
    : resolveApiError(
      error?.response?.data,
      error?.response?.status,
      t('identitySources.oidc.discoveryFailed')
    )

/**
 * @param {object} opts
 * @param {() => string} opts.currentIssuer 表單目前的 issuer
 * @param {() => string} opts.savedIssuer 已儲存的 issuer（新增頁為空字串）
 * @param {() => unknown} opts.sourceKey 來源識別（路由 id），改變即清空
 * @param {(error: unknown) => void} [opts.onError] 失敗時的記錄回呼
 */
export function useDiscoveryPreview({ currentIssuer, savedIssuer, sourceKey, onError }) {
  const record = ref(null)
  const running = ref(false)
  let seq = 0

  const norm = (v) => String(v || '').trim()

  const run = async () => {
    const issuer = norm(currentIssuer())
    if (!issuer) return
    const mine = ++seq
    running.value = true
    try {
      const result = await previewOIDCDiscovery(issuer)
      if (mine !== seq) return
      record.value = { result, errorKind: null, errorText: '', at: new Date().toISOString(), issuer }
    } catch (error) {
      if (mine !== seq) return
      record.value = {
        result: null,
        errorKind: errorKindOf(error),
        errorText: errorTextOf(error),
        at: new Date().toISOString(),
        issuer,
      }
      onError?.(error)
    } finally {
      if (mine === seq) running.value = false
    }
  }

  const clear = () => {
    seq += 1
    record.value = null
    running.value = false
  }

  const stale = computed(() => Boolean(record.value) && norm(currentIssuer()) !== record.value.issuer)
  const unsaved = computed(
    () => Boolean(record.value) && !stale.value && record.value.issuer !== norm(savedIssuer())
  )

  watch(sourceKey, clear)

  return {
    record,
    running,
    run,
    clear,
    stale,
    unsaved,
    // 左欄沿用的兩個呈現值：成功結果與錯誤訊息
    result: computed(() => record.value?.result || null),
    errorText: computed(() => record.value?.errorText || ''),
    // 給面板的單一輸入
    panelInput: computed(() => ({ record: record.value, stale: stale.value, unsaved: unsaved.value })),
  }
}
