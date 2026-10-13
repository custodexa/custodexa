// 登入頁的 `?source=` 登入測試標示。
//
// 只接受 `oidc:<編號>` 或 `ldap:<編號>`，其餘一律忽略（看到的就是一般登入頁）。
// 未登入時：要測的單一登入方式排到第一個並加標示，不自動按下；不在登入方法清單中時
// 說明可能已停用或設定不完整；目錄測試在帳密表單上方說明，目錄不在公開清單（停用、
// 已刪除或不存在，三者對外不可區分）時同樣說明不在登入頁。
// 已登入時：不掛載帳密表單與任何單一登入按鈕，只說明要用無痕視窗或另一個瀏覽器開啟，
// 避免在同一個瀏覽器登入而換掉目前的工作階段。
import { computed, ref, watch } from 'vue'
import { getAccessToken } from '@/utils/session'

export const LOGIN_TEST_SOURCE_RE = /^(oidc|ldap):[0-9]{1,10}$/

/** 解析 source 參數；格式不符回 null */
export function parseLoginTestSource(raw) {
  if (typeof raw !== 'string' || !LOGIN_TEST_SOURCE_RE.test(raw)) return null
  const [type, id] = raw.split(':')
  return { type, id }
}

/**
 * @param {import('vue').Ref<Array<{id: number|string}>>} providers 登入方法清單（單一登入）
 * @param {object} [opts]
 * @param {import('vue').Ref<Array<{id: number|string}>>} [opts.directories] 登入方法清單中的目錄（與 providers 同一次載入）
 * @param {() => string} [opts.search] 網址查詢字串（預設取目前網址）
 * @param {() => boolean} [opts.authed] 目前是否已登入（預設看記憶體中的存取權杖）
 */
export function useLoginTestSource(providers, opts = {}) {
  const search = opts.search || (() => window.location.search)
  const authed = opts.authed || (() => Boolean(getAccessToken()))
  const source = parseLoginTestSource(new URLSearchParams(search()).get('source'))
  // 清單每次載入（含失敗降級為空）都會整個換掉，換過一次即視為已載入
  const loaded = ref(false)
  watch(providers, () => {
    loaded.value = true
  })

  const isTarget = (p) => source?.type === 'oidc' && String(p?.id) === source.id
  const listed = computed(() => (providers.value || []).some(isTarget))
  const directoryListed = computed(() =>
    (opts.directories?.value || []).some((d) => source?.type === 'ldap' && String(d?.id) === source.id)
  )
  const blocked = computed(() => Boolean(source) && authed())

  const ordered = computed(() => {
    const list = providers.value || []
    return listed.value ? [...list.filter(isTarget), ...list.filter((p) => !isTarget(p))] : list
  })

  const notice = computed(() => {
    if (!source) return null
    if (blocked.value) return 'authed'
    if (!loaded.value) return null
    if (source.type === 'ldap') return directoryListed.value ? 'ldap' : 'notListed'
    return listed.value ? null : 'notListed'
  })

  // 目錄帳號欄的提示只在目錄確實在登入頁時換成「目錄帳號」
  const isLdap = computed(() => notice.value === 'ldap')
  return { source, blocked, ordered, notice, isTarget, isLdap }
}
