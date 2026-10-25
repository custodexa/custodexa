import { computed, ref, shallowRef, watch } from 'vue'
import { can, useCapabilities } from '@/composables/useCapabilities'
import { canEnter, entryRuleFor } from '@/router/entryRules'
import { onSessionEnded } from '@/utils/session'
import {
  dismissReleaseGuidance,
  getReleaseGuidanceState,
  getRetentionAdjustments,
} from '@/api/releaseGuidance'

/**
 * 新版說明的狀態提供者。
 *
 * 說明版本固定為 1.18.0，與產品 patch 版號分開；關閉狀態以伺服器為準（缺列＝尚未關閉），
 * 不用 localStorage 判斷是否首次登入。段落只依目前能力與入口規則決定「適用與否」、連結
 * 一律以目的入口的規則經 `canEnter` 判定，與側欄、路由守衛同一函式。
 *
 * 登出或換帳號清空全部狀態，並以世代丟棄舊會話仍在途的回應。
 */

export const GUIDANCE_VERSION = '1.18.0'

// 保留區塊的讀取能力：以 GET /security-policies 的登錄裁決為準
const RETENTION_CAPABILITY = 'securitypolicy:manage'

const { loadedUserId } = useCapabilities()

const status = ref('idle') // idle | loading | ready | error
const dismissed = ref(false)
const forced = ref(false) // 由「新版說明」重開：本次強制展開，不改伺服器狀態
const saving = ref(false)
const saveFailed = ref(false)
const focusTick = ref(0)

const retention = shallowRef({ status: 'idle', items: [], uncovered: [] })

let generation = 0
// 保留紀錄讀取的世代：同一帳號失去讀取能力時單獨作廢，不牽動關閉狀態的讀寫
let retentionGeneration = 0
// 關閉成功後遞增：較早發出的狀態讀取晚到時不得把已關閉改回未關閉
let stateEpoch = 0

function resetGuidance() {
  generation += 1
  retentionGeneration += 1
  stateEpoch += 1
  status.value = 'idle'
  dismissed.value = false
  forced.value = false
  saving.value = false
  saveFailed.value = false
  focusTick.value = 0
  retention.value = { status: 'idle', items: [], uncovered: [] }
}

onSessionEnded(resetGuidance)

// 同一帳號已載入後失去讀取能力：清空保留區塊並作廢在途讀取，舊內容不得留在畫面上
watch(
  () => can(RETENTION_CAPABILITY),
  (allowed) => {
    if (allowed) return
    retentionGeneration += 1
    retention.value = { status: 'idle', items: [], uncovered: [] }
  },
  { flush: 'sync' },
)

const unwrap = (res) => (res?.data && typeof res.data === 'object' && !Array.isArray(res.data) ? res.data : res)

/** 載入本人關閉狀態；已載入或載入中不重複送出。 */
async function load({ force = false } = {}) {
  if (!force && (status.value === 'loading' || status.value === 'ready')) return
  const gen = generation
  const epoch = stateEpoch
  status.value = 'loading'
  try {
    const body = unwrap(await getReleaseGuidanceState(GUIDANCE_VERSION))
    if (gen !== generation || epoch !== stateEpoch) return
    if (!body || typeof body.dismissed !== 'boolean') {
      status.value = 'error'
      return
    }
    dismissed.value = body.dismissed
    status.value = 'ready'
  } catch {
    if (gen !== generation || epoch !== stateEpoch) return
    status.value = 'error'
  }
}

/** 關閉：成功才收起；失敗保留卡片並可重試。 */
async function dismiss() {
  if (saving.value) return false
  const gen = generation
  saving.value = true
  saveFailed.value = false
  try {
    await dismissReleaseGuidance(GUIDANCE_VERSION)
    if (gen !== generation) return false
    stateEpoch += 1
    dismissed.value = true
    forced.value = false
    status.value = 'ready'
    return true
  } catch {
    if (gen === generation) saveFailed.value = true
    return false
  } finally {
    if (gen === generation) saving.value = false
  }
}

/** 由使用者選單重開：本次強制展開並移焦，不重設伺服器狀態；保留紀錄重新讀取。 */
function reopen() {
  forced.value = true
  focusTick.value += 1
  retention.value = { status: 'idle', items: [], uncovered: [] }
  if (status.value === 'idle' || status.value === 'error') void load({ force: true })
}

/** 讀取保留調整告知；沒有安全政策讀取能力時不請求。 */
async function loadRetention() {
  if (!can(RETENTION_CAPABILITY)) return
  if (retention.value.status === 'loading' || retention.value.status === 'ready') return
  const gen = retentionGeneration
  retention.value = { status: 'loading', items: [], uncovered: [] }
  try {
    const body = unwrap(await getRetentionAdjustments())
    if (gen !== retentionGeneration) return
    if (!body || !Array.isArray(body.items) || !Array.isArray(body.uncovered)) {
      retention.value = { status: 'error', items: [], uncovered: [] }
      return
    }
    retention.value = { status: 'ready', items: body.items, uncovered: body.uncovered }
  } catch {
    if (gen !== retentionGeneration) return
    retention.value = { status: 'error', items: [], uncovered: [] }
  }
}

/** 目的入口對目前使用者是否成立；入口規則未登記一律為否（fail-closed）。 */
function entryOpen(path) {
  const rule = entryRuleFor(path)
  return rule ? canEnter(rule) : false
}

// 告警頁保留的三個頁籤能力：告警記錄、規則管理、系統告警目錄（通知通道已移到系統設定）
const ALERT_TAB_CAPABILITIES = ['audit:view', 'alertrule:manage', 'systemalert:manage']

// 段落與連結：段落適用條件與連結可進分開判定。連結一律以目的入口規則判定。
// 每段只有一份，不因多角色重複。
const SECTION_DEFS = [
  {
    id: 'basic', column: 'changes', textKey: 'upgradeGuidance.basic',
    applies: () => true, links: [],
  },
  {
    id: 'superAdminMigration', column: 'changes', textKey: 'upgradeGuidance.superAdminMigration',
    applies: () => can('ui:connect-bypass'), links: [],
  },
  {
    // 登入即可的 /assets 入口不能當段落條件，否則一般使用者會收到資產管理說明
    id: 'assets', column: 'changes', textKey: 'upgradeGuidance.assets',
    applies: () => can('ui:assets-global'),
    links: [{ to: '/assets', labelKey: 'menu.assets' }],
  },
  {
    // 變更欄只說事實；「改歸到節點」放在建議步驟欄，入口連結也在那裡。
    // 顯示條件與連結都沿 /credentials 的入口規則，不查任何憑證計數
    id: 'credentialOwnership', column: 'changes', textKey: 'upgradeGuidance.credentialOwnership',
    step: {
      titleKey: 'upgradeGuidance.credentialOwnershipStepTitle',
      textKey: 'upgradeGuidance.credentialOwnershipStepText',
    },
    applies: () => entryOpen('/credentials'),
    links: [{ to: '/credentials', labelKey: 'menu.credentials' }],
  },
  {
    id: 'authorization', column: 'changes', textKey: 'upgradeGuidance.authorization',
    applies: () => entryOpen('/authorizations'),
    links: [{ to: '/authorizations', labelKey: 'menu.authorizations' }],
  },
  {
    id: 'audit', column: 'changes', textKey: 'upgradeGuidance.audit',
    // 段落條件取告警頁剩餘頁籤的能力任一；連結仍以 /alerts 的入口規則判定
    applies: () => ALERT_TAB_CAPABILITIES.some((p) => can(p)),
    links: [{ to: '/alerts', labelKey: 'menu.alerts' }],
  },
  {
    id: 'roles', column: 'nextSteps', textKey: 'upgradeGuidance.roles',
    applies: () => entryOpen('/roles') || entryOpen('/user-groups'),
    links: [
      { to: '/roles', labelKey: 'menu.roles' },
      { to: '/user-groups', labelKey: 'menu.userGroups' },
    ],
  },
  {
    id: 'approvals', column: 'nextSteps', textKey: 'upgradeGuidance.approvals',
    applies: () => entryOpen('/approvals'),
    links: [{ to: '/approvals', labelKey: 'menu.approvals' }],
  },
  {
    // 通道頁入口登記後以該入口規則判定；登記之前判準只用通道管理能力
    id: 'notifications', column: 'nextSteps', textKey: 'upgradeGuidance.notifications',
    applies: () =>
      entryRuleFor('/notification-channels') ? entryOpen('/notification-channels') : can('notification_channel:manage'),
    links: [{ to: '/notification-channels', labelKey: 'alerts.tabChannels' }],
  },
  {
    // 不查現有帳號是否符合，也不附連結
    id: 'localAdmin', column: 'nextSteps', textKey: 'upgradeGuidance.localAdmin',
    applies: () => entryOpen('/security-policies'), links: [],
  },
]

const sections = computed(() =>
  SECTION_DEFS.filter((def) => def.applies()).map((def) => ({
    id: def.id,
    column: def.column,
    textKey: def.textKey,
    step: def.step || null,
    links: def.links.filter((l) => entryOpen(l.to)),
  })),
)

const visible = computed(() => forced.value || status.value === 'error' || (status.value === 'ready' && !dismissed.value))

/** 保留區塊是否可見：載入中、失敗（重試）或有內容；兩者皆空不顯示。 */
const retentionAllowed = computed(() => can(RETENTION_CAPABILITY))

export function useUpgradeGuidance() {
  return {
    version: GUIDANCE_VERSION,
    status,
    dismissed,
    forced,
    saving,
    saveFailed,
    focusTick,
    retention,
    retentionAllowed,
    visible,
    sections,
    loadedUserId,
    load,
    dismiss,
    reopen,
    loadRetention,
    reset: resetGuidance,
  }
}
