<template>
  <section
    v-if="guidance.visible.value"
    class="upgrade-guidance"
    data-test="upgrade-guidance"
    :aria-labelledby="titleId"
  >
    <header class="ug-head">
      <div class="ug-head-main">
        <el-icon
          class="ug-info-icon"
          data-test="ug-info-icon"
          aria-hidden="true"
        >
          <Info />
        </el-icon>
        <h2
          :id="titleId"
          ref="titleRef"
          class="ug-title"
          tabindex="-1"
          data-test="ug-title"
        >
          {{ t('upgradeGuidance.title') }}
        </h2>
      </div>
      <el-button
        v-if="guidance.status.value === 'ready' || guidance.forced.value"
        class="ug-close"
        link
        :aria-label="t('common.close')"
        :disabled="guidance.saving.value"
        data-test="ug-close"
        @click="onDismiss"
      >
        <el-icon><X /></el-icon>
      </el-button>
    </header>

    <div
      v-if="guidance.status.value === 'error'"
      class="ug-error"
      role="alert"
      data-test="ug-load-failed"
    >
      <el-icon class="ug-error-icon">
        <TriangleAlert />
      </el-icon>
      <span class="ug-error-text">{{ t('upgradeGuidance.loadFailed') }}</span>
      <el-button
        size="small"
        data-test="ug-load-retry"
        @click="guidance.load({ force: true })"
      >
        <el-icon><RefreshCw /></el-icon>
        {{ t('common.retry') }}
      </el-button>
    </div>

    <template v-else>
      <div class="ug-columns">
        <div
          class="ug-column"
          data-test="ug-col-changes"
        >
          <h3 class="ug-subtitle">
            {{ t('upgradeGuidance.changes') }}
          </h3>
          <ul class="ug-list">
            <li
              v-for="s in changeSections"
              :key="s.id"
              :data-section="s.id"
            >
              <span>{{ t(s.textKey) }}</span>
              <!-- 有建議步驟的段落，入口連結放在步驟裡，這裡不重複 -->
              <router-link
                v-for="l in (s.step ? [] : s.links)"
                :key="l.to"
                class="ug-link"
                :to="l.to"
                :data-link="l.to"
              >
                {{ t('upgradeGuidance.goTo', { name: t(l.labelKey) }) }}
              </router-link>
            </li>
          </ul>
        </div>
        <div
          v-if="nextItems.length"
          class="ug-column"
          data-test="ug-col-next"
        >
          <h3 class="ug-subtitle">
            {{ t('upgradeGuidance.nextSteps') }}
          </h3>
          <ol class="ug-list ug-steps">
            <li
              v-for="item in nextItems"
              :key="item.key"
              :data-section="item.step ? undefined : item.section.id"
              :data-step="item.step ? item.section.id : undefined"
            >
              <span
                class="ug-step-no"
                aria-hidden="true"
              />
              <span
                v-if="item.step"
                class="ug-step-text"
              ><strong>{{ t(item.section.step.titleKey) }}</strong>
                {{ t(item.section.step.textKey) }}</span>
              <span
                v-else
                class="ug-step-text"
              >{{ t(item.section.textKey) }}</span>
              <router-link
                v-for="l in item.section.links"
                :key="l.to"
                class="ug-link ug-link-right"
                :to="l.to"
                :data-link="l.to"
              >
                {{ t('upgradeGuidance.goTo', { name: t(l.labelKey) }) }}
              </router-link>
            </li>
          </ol>
        </div>
      </div>

      <div
        v-if="showRetentionLoading"
        class="ug-retention"
        data-test="ug-retention-loading"
      >
        <div
          class="ug-skeleton"
          role="status"
        >
          <span class="ug-skeleton-label">
            <el-icon class="is-loading"><Loader /></el-icon>
            {{ t('common.loading') }}
          </span>
          <el-skeleton
            animated
            :rows="2"
          />
        </div>
      </div>
      <div
        v-else-if="retentionState.status === 'error'"
        class="ug-retention ug-error"
        role="alert"
        data-test="ug-retention-failed"
      >
        <el-icon class="ug-error-icon">
          <TriangleAlert />
        </el-icon>
        <span class="ug-error-text">{{ t('upgradeGuidance.retentionFailed') }}</span>
        <el-button
          size="small"
          data-test="ug-retention-retry"
          @click="onRetentionRetry"
        >
          <el-icon><RefreshCw /></el-icon>
          {{ t('common.retry') }}
        </el-button>
      </div>
      <div
        v-else-if="hasRetentionContent"
        class="ug-retention"
        data-test="ug-retention"
      >
        <div
          v-if="retentionState.items.length"
          class="ug-retention-block"
          data-test="ug-retention-items"
        >
          <h3 class="ug-subtitle">
            {{ t('upgradeGuidance.retentionTitle') }}
          </h3>
          <p class="ug-note">
            {{ t('upgradeGuidance.retentionHint') }}
          </p>
          <ul class="ug-list">
            <li
              v-for="it in retentionState.items"
              :key="it.key"
              :data-retention-key="it.key"
            >
              <span class="ug-item-text">{{ retentionLine(it) }}</span>
              <time
                class="ug-time"
                :datetime="it.raised_at"
              >{{ formatDateTime(it.raised_at) }}</time>
              <span
                v-if="it.reason === 'cross_key_follow'"
                class="ug-note"
              >{{ t('upgradeGuidance.retentionFollow') }}</span>
            </li>
          </ul>
        </div>
        <div
          v-if="retentionState.uncovered.length"
          class="ug-retention-block ug-uncovered"
          data-test="ug-retention-uncovered"
        >
          <h3 class="ug-subtitle ug-uncovered-title">
            <el-icon class="ug-warn-icon">
              <TriangleAlert />
            </el-icon>
            {{ t('upgradeGuidance.uncoveredTitle') }}
            <span
              class="ug-badge"
              data-test="ug-current-setting"
            >{{ t('upgradeGuidance.currentSetting') }}</span>
          </h3>
          <ul class="ug-list">
            <li
              v-for="u in retentionState.uncovered"
              :key="u.data_key"
              :data-uncovered-key="u.data_key"
            >
              {{ uncoveredLine(u) }}
            </li>
          </ul>
          <p class="ug-note">
            {{ t('upgradeGuidance.uncoveredHint') }}
            <router-link
              v-if="securityPoliciesOpen"
              class="ug-link"
              to="/security-policies"
              data-link="/security-policies"
            >
              {{ t('upgradeGuidance.goTo', { name: t('menu.securityPolicies') }) }}
            </router-link>
          </p>
        </div>
      </div>

      <div
        v-if="guidance.saveFailed.value"
        class="ug-error"
        role="alert"
        data-test="ug-save-failed"
      >
        <el-icon class="ug-error-icon">
          <TriangleAlert />
        </el-icon>
        <span class="ug-error-text">{{ t('upgradeGuidance.saveFailed') }}</span>
        <el-button
          size="small"
          :loading="guidance.saving.value"
          data-test="ug-save-retry"
          @click="onDismiss"
        >
          <el-icon><RefreshCw /></el-icon>
          {{ t('common.retry') }}
        </el-button>
      </div>

      <footer class="ug-foot">
        <span class="ug-note">{{ t('upgradeGuidance.reopenHint') }}</span>
        <el-button
          size="small"
          :loading="guidance.saving.value"
          data-test="ug-dismiss"
          @click="onDismiss"
        >
          {{ t('upgradeGuidance.dismiss') }}
        </el-button>
      </footer>
    </template>
  </section>
</template>

<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, ref, useId, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { X, Info, TriangleAlert, RefreshCw, Loader } from 'lucide-vue-next'
import { te, t } from '@/i18n'
import { formatDateTime } from '@/utils/format'
import { canEnter, entryRuleFor } from '@/router/entryRules'
import { useCapabilities } from '@/composables/useCapabilities'
import { useUpgradeGuidance } from '@/composables/useUpgradeGuidance'

// 非阻擋的升級說明卡：無遮罩、不鎖焦點，載入與關閉都不影響頁面其他元件。
// 內容只有靜態段落與入口連結，不查任何帳號、資產、節點或憑證的清單與計數。

const guidance = useUpgradeGuidance()
const { loadedUserId, ready: capabilitiesReady } = useCapabilities()
const route = useRoute()
const router = useRouter()

const titleId = `ug-title-${useId()}`
const titleRef = ref(null)

const changeSections = computed(() => guidance.sections.value.filter((s) => s.column === 'changes'))
const nextSections = computed(() => guidance.sections.value.filter((s) => s.column === 'nextSteps'))
// 建議步驟欄：一般段落加上「變更欄段落自帶的步驟」（接在角色段落之後，沒有角色段落則排在最後）
const nextItems = computed(() => {
  const stepItems = guidance.sections.value
    .filter((s) => s.step)
    .map((s) => ({ key: `step-${s.id}`, step: true, section: s }))
  const items = []
  let placed = false
  for (const s of nextSections.value) {
    items.push({ key: s.id, step: false, section: s })
    if (s.id === 'roles') {
      items.push(...stepItems)
      placed = true
    }
  }
  if (!placed) items.push(...stepItems)
  return items
})

const retentionState = computed(() => guidance.retention.value)
const showRetentionLoading = computed(
  () => guidance.retentionAllowed.value && retentionState.value.status === 'loading',
)
const hasRetentionContent = computed(
  () =>
    retentionState.value.status === 'ready' &&
    (retentionState.value.items.length > 0 || retentionState.value.uncovered.length > 0),
)
const securityPoliciesOpen = computed(() => {
  const rule = entryRuleFor('/security-policies')
  return rule ? canEnter(rule) : false
})

const keyLabel = (key) => (te(`policyLabel.${key}`) ? t(`policyLabel.${key}`) : key)
const daysText = (n) => (n === 0 ? t('policyZero.retention') : `${n} ${t('policyUnit.days')}`)

const retentionLine = (it) =>
  t('upgradeGuidance.retentionItem', { item: keyLabel(it.key), before: it.old_days, after: it.new_days })
const uncoveredLine = (u) =>
  t('upgradeGuidance.uncoveredItem', {
    item: keyLabel(u.data_key),
    days: daysText(u.data_days),
    checkpoint: daysText(u.checkpoint_days),
  })

const onDismiss = () => guidance.dismiss()
const onRetentionRetry = () => {
  guidance.retention.value = { status: 'idle', items: [], uncovered: [] }
  guidance.loadRetention()
}

// 保留區塊：卡片可見、能力就緒且持有安全政策讀取能力時才取數；讀取失敗只影響該區塊
watch(
  [() => guidance.visible.value, capabilitiesReady, guidance.retentionAllowed, () => guidance.retention.value.status],
  ([visible, ready, allowed, st]) => {
    if (visible && ready && allowed && st === 'idle') guidance.loadRetention()
  },
  { immediate: true },
)

// 換帳號：清空舊狀態並重新讀取，舊會話仍在途的回應由 provider 的世代丟棄
watch(loadedUserId, (next, prev) => {
  if (prev != null && next !== prev) {
    guidance.reset()
    guidance.load()
  }
})

// 使用者選單的「新版說明」導向 ?guidance=<版本>：本次強制展開並移焦，
// 消費後以 replace 移除 query，不改伺服器狀態
function consumeGuidanceQuery() {
  if (route.query.guidance !== guidance.version) return
  guidance.reopen()
  const rest = { ...route.query }
  delete rest.guidance
  router.replace({ path: route.path, query: rest, hash: route.hash })
}
watch(() => route.query.guidance, consumeGuidanceQuery)

// 焦點守衛：使用者選單（Element Plus 下拉）收起時會把焦點還給選單本體或 BODY，
// 發生時間取決於選單開了多久與收合動畫，無法用固定毫秒蓋過。
// 移焦後掛一個 focusout 守衛：只要焦點是從下拉彈層（.el-popper）離開、且沒有落在標題上，
// 就把焦點收回標題。鍵盤選取時順序相反：焦點已在標題，下拉才把焦點還給觸發鈕，
// 此時 focusout 的來源就是標題本身，同樣收回。使用者自己按鍵或點擊後立即解除，不與後續操作搶焦點。
let releaseFocusGuard = null

function guardTitleFocus() {
  releaseFocusGuard?.()
  const onFocusOut = (e) => {
    const from = e.target
    if (!(from instanceof Element)) return
    const title = titleRef.value
    const fromTitle = !!title && (from === title || title.contains(from))
    if (!fromTitle && !from.closest('.el-popper')) return
    const to = e.relatedTarget
    if (to && titleRef.value && (to === titleRef.value || titleRef.value.contains(to))) return
    titleRef.value?.focus?.()
    // focusout 期間的 focus() 可能被緊接著的焦點轉移蓋掉（焦點直接給觸發鈕時），
    // 待轉移完成後若守衛仍在且焦點不在標題，再收回一次
    queueMicrotask(() => {
      if (!releaseFocusGuard) return
      const el = titleRef.value
      if (el && document.activeElement !== el) el.focus?.()
    })
  }
  const stop = () => releaseFocusGuard?.()
  document.addEventListener('focusout', onFocusOut, true)
  document.addEventListener('pointerdown', stop, true)
  document.addEventListener('keydown', stop, true)
  releaseFocusGuard = () => {
    document.removeEventListener('focusout', onFocusOut, true)
    document.removeEventListener('pointerdown', stop, true)
    document.removeEventListener('keydown', stop, true)
    releaseFocusGuard = null
  }
}

watch(
  () => guidance.focusTick.value,
  async (tick) => {
    if (!tick) return
    await nextTick()
    titleRef.value?.focus?.()
    guardTitleFocus()
  },
)

onBeforeUnmount(() => releaseFocusGuard?.())

onMounted(() => {
  guidance.load()
  consumeGuidanceQuery()
})
</script>

<style scoped>
.upgrade-guidance {
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  padding: var(--ot-space-lg);
  margin-bottom: var(--ot-space-md);
}

.ug-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--ot-space-md);
}

.ug-head-main {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  min-width: 0;
}

.ug-info-icon {
  flex: none;
  color: var(--ot-primary);
  font-size: 18px;
}

.ug-title {
  margin: 0;
  font-size: var(--ot-font-size-lg);
  color: var(--ot-text-primary);
}

.ug-title:focus-visible {
  outline: 2px solid var(--ot-primary);
  outline-offset: 2px;
}

.ug-columns {
  display: flex;
  flex-wrap: wrap;
  gap: var(--ot-space-lg);
  margin-top: var(--ot-space-md);
}

.ug-column {
  flex: 1 1 280px;
  min-width: 0;
}

.ug-subtitle {
  margin: 0 0 var(--ot-space-sm, 8px);
  font-size: var(--ot-font-size-md);
  color: var(--ot-text-primary);
}

.ug-list {
  margin: 0;
  padding-left: 1.25em;
  display: flex;
  flex-direction: column;
  gap: 6px;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.ug-link {
  margin-left: 8px;
  color: var(--ot-primary);
  white-space: nowrap;
}

/* 建議欄：序號圓圈、連結靠右、列間分隔線 */
.ug-steps {
  list-style: none;
  padding-left: 0;
  gap: 0;
  counter-reset: ug-step;
}

.ug-steps > li {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  padding: var(--ot-space-sm) 0;
  border-bottom: 1px solid var(--ot-border-subtle);
  counter-increment: ug-step;
}

.ug-steps > li:last-child {
  border-bottom: 0;
}

.ug-step-no {
  flex: none;
  width: 20px;
  height: 20px;
  border: 1px solid var(--ot-border);
  border-radius: 50%;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: var(--ot-font-size-xs, 12px);
  color: var(--ot-text-secondary);
}

.ug-step-no::before {
  content: counter(ug-step);
}

.ug-step-text {
  flex: 1 1 auto;
  min-width: 0;
}

.ug-link-right {
  margin-left: auto;
}

/* 升級時調整紀錄：時間靠右 */
.ug-retention-block li {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
}

.ug-retention-block li .ug-time {
  margin-left: auto;
}

/* 目前未涵蓋區塊：警示框底色 */
.ug-uncovered {
  padding: var(--ot-space-md);
  border: 1px solid color-mix(in srgb, var(--ot-warning) 45%, transparent);
  border-radius: var(--ot-radius-md);
  background-color: color-mix(in srgb, var(--ot-warning) 10%, transparent);
}

.ug-uncovered-title {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
}

.ug-warn-icon {
  color: var(--ot-warning);
}

.ug-badge {
  padding: 0 var(--ot-space-sm);
  border: 1px solid var(--ot-warning);
  border-radius: var(--ot-radius-sm);
  color: var(--ot-warning);
  font-size: var(--ot-font-size-xs, 12px);
  font-weight: normal;
}

/* 載入中骨架 */
.ug-skeleton {
  width: 100%;
  padding: var(--ot-space-md);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}

.ug-skeleton-label {
  display: inline-flex;
  align-items: center;
  gap: var(--ot-space-sm);
  margin-bottom: var(--ot-space-sm);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.ug-time,
.ug-note {
  margin-left: 8px;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.ug-retention {
  margin-top: var(--ot-space-md);
  padding-top: var(--ot-space-md);
  border-top: 1px solid var(--ot-border-subtle);
  display: flex;
  flex-wrap: wrap;
  gap: var(--ot-space-lg);
}

.ug-retention-block {
  flex: 1 1 280px;
  min-width: 0;
}

.ug-error {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  margin-top: var(--ot-space-md);
  padding: var(--ot-space-sm) var(--ot-space-md);
  border: 1px solid color-mix(in srgb, var(--ot-warning) 45%, transparent);
  border-radius: var(--ot-radius-md);
  background-color: color-mix(in srgb, var(--ot-warning) 10%, transparent);
  color: var(--ot-text-primary);
  font-size: var(--ot-font-size-sm);
}

.ug-error-icon {
  flex: none;
  color: var(--ot-warning);
}

.ug-error-text {
  flex: 1 1 auto;
}

.ug-error .el-button {
  margin-left: auto;
}

.ug-foot {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--ot-space-md);
  margin-top: var(--ot-space-md);
}

.ug-foot .ug-note {
  margin-left: 0;
}

@media (max-width: 640px) {
  .ug-foot {
    flex-direction: column;
    align-items: flex-start;
  }
}
</style>
