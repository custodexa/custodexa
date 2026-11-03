import { computed, ref, watch } from 'vue'
import { isRoleSetApproverOnly } from '@/api/approverOnly'

/**
 * 直接指派被判定為「只有審核者角色」時的就近說明。
 * 角色與範圍分頁與建立帳號表單共用：伺服器回這個碼時記下該用哪一組文案，
 * 修正鈕的動作（以原集合加上全系統的一般使用者重送）由呼叫端執行。
 * 不按修正鈕就不送出任何寫入；草稿變動時說明收起。
 *
 * draft（選填，角色與範圍分頁用）：
 *   roles        角色名稱清單的 ref（草稿）
 *   sources      草稿變動要收起說明的來源（watch 來源陣列）
 *   isNodeScoped (name) => 該角色草稿是否限定節點
 *   setGlobal    (name) => 把該角色草稿改回全系統
 */
export const GENERAL_USER_ROLE = 'user'

const COPY = {
  // 原集合沒有一般使用者：加上全系統的一般使用者
  add: { title: 'users.approverOnlyPrompt.title', body: 'users.approverOnlyPrompt.body', fix: 'users.approverOnlyPrompt.fix' },
  // 原集合的一般使用者限定在節點：改成全系統
  widen: { title: 'users.approverOnlyPrompt.nodeTitle', body: 'users.approverOnlyPrompt.nodeBody', fix: 'users.approverOnlyPrompt.nodeFix' },
  // 建立帳號只有全系統，直接勾上一般使用者
  create: { title: 'users.approverOnlyPrompt.createTitle', body: 'users.approverOnlyPrompt.createBody', fix: 'users.approverOnlyPrompt.createFix' },
}

/** 角色名稱清單加上一般使用者（已有則原樣），不改動傳入的陣列 */
export const withGeneralUser = (roles) =>
  roles.includes(GENERAL_USER_ROLE) ? [...roles] : [...roles, GENERAL_USER_ROLE]

export function useApproverOnlyPrompt(draft = null) {
  const variant = ref('')
  const visible = computed(() => variant.value !== '')
  const copy = computed(() => COPY[variant.value] || null)

  /** 是這個碼就顯示對應文案並回 true；其他錯誤回 false 交還呼叫端 */
  const capture = (error, kind = 'add') => {
    if (!isRoleSetApproverOnly(error)) return false
    variant.value = COPY[kind] ? kind : 'add'
    return true
  }
  const dismiss = () => {
    variant.value = ''
  }
  // 同步收起：修正鈕改草稿後立即重送，延遲的收起不會蓋掉重送後的新說明
  if (draft?.sources) watch(draft.sources, dismiss, { deep: true, flush: 'sync' })

  // 一般使用者限定在節點時不給能力，修正時改成全系統而不是多一筆
  const userNodeScoped = () =>
    !!draft?.roles && draft.roles.value.includes(GENERAL_USER_ROLE) && draft.isNodeScoped(GENERAL_USER_ROLE)
  /** 依目前草稿決定文案後顯示；不是這個碼回 false */
  const captureDraft = (error) => capture(error, userNodeScoped() ? 'widen' : 'add')
  /**
   * 草稿加上全系統的一般使用者；回傳寫入要額外帶的範圍（限定節點改全系統時為 { user: null }），
   * 不能指派角色者的範圍變動不會進草稿差異，所以由這裡明確帶出。
   */
  const toGlobalUser = () => {
    const widen = userNodeScoped()
    draft.roles.value = withGeneralUser(draft.roles.value)
    if (widen) draft.setGlobal(GENERAL_USER_ROLE)
    return widen ? { [GENERAL_USER_ROLE]: null } : {}
  }
  return { variant, visible, copy, capture, captureDraft, dismiss, toGlobalUser }
}
