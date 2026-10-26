<template>
  <nav
    v-if="sections.length > 0"
    ref="navRef"
    class="policy-section-nav"
    :aria-label="$t('securityPolicies.sectionNavLabel')"
    data-test="policy-section-nav"
    @keydown.up.prevent="moveFocus(-1)"
    @keydown.down.prevent="moveFocus(1)"
  >
    <ul class="nav-list">
      <li
        v-for="section in sections"
        :key="section.id"
      >
        <button
          type="button"
          class="nav-item"
          :class="{ 'is-current': current === section.id }"
          :aria-current="current === section.id ? 'location' : undefined"
          :data-nav-id="section.id"
          :data-test="`section-nav-${section.id}`"
          @click="select(section.id)"
          @keydown.enter.prevent="select(section.id)"
          @keydown.space.prevent="select(section.id)"
        >
          {{ section.title }}
        </button>
      </li>
    </ul>
  </nav>
</template>

<script setup>
import { nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'

/**
 * 安全政策頁的分區導覽。項目只取父層傳入的 sections（頁面分區卡片用的同一份
 * visibleSections），不看權限、不看角色、不發請求。卡片以 data-section-id 定位。
 */
const props = defineProps({
  // visibleSections：[{ id, title, ... }]，順序即頁面順序
  sections: { type: Array, required: true },
})

const navRef = ref(null)
const current = ref('')
const visibleIds = new Set()
let observer = null

const cardOf = (id) => document.querySelector(`[data-section-id="${id}"]`)

const select = (id) => {
  current.value = id
  const card = cardOf(id)
  if (!card) return
  card.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
  // 把焦點移到卡片（鍵盤與讀屏使用者接著從該區讀起）；不再捲一次
  if (!card.hasAttribute('tabindex')) card.setAttribute('tabindex', '-1')
  card.focus?.({ preventScroll: true })
}

// 目前位置＝畫面中最上方的分區
const refreshCurrent = () => {
  const first = props.sections.find((s) => visibleIds.has(s.id))
  if (first) current.value = first.id
}

const onIntersect = (entries) => {
  entries.forEach((entry) => {
    const id = entry.target?.getAttribute?.('data-section-id')
    if (!id) return
    if (entry.isIntersecting) visibleIds.add(id)
    else visibleIds.delete(id)
  })
  refreshCurrent()
}

const observeCards = async () => {
  if (typeof IntersectionObserver === 'undefined') return
  await nextTick()
  if (observer) observer.disconnect()
  visibleIds.clear()
  // 視窗上緣往下 40% 的帶狀區域內有露出的最上方分區算目前位置
  observer = new IntersectionObserver(onIntersect, { rootMargin: '0px 0px -60% 0px' })
  props.sections.forEach((s) => {
    const card = cardOf(s.id)
    if (card) observer.observe(card)
  })
}

const moveFocus = (step) => {
  const buttons = Array.from(navRef.value?.querySelectorAll('button.nav-item') || [])
  if (buttons.length === 0) return
  const index = buttons.indexOf(document.activeElement)
  const next = index === -1 ? 0 : Math.min(buttons.length - 1, Math.max(0, index + step))
  buttons[next].focus()
}

watch(
  () => props.sections.map((s) => s.id).join('|'),
  () => {
    if (!props.sections.some((s) => s.id === current.value)) current.value = props.sections[0]?.id || ''
    observeCards()
  },
  { immediate: true }
)

onMounted(observeCards)
onBeforeUnmount(() => {
  if (observer) observer.disconnect()
  observer = null
})
</script>

<style scoped>
.policy-section-nav {
  position: sticky;
  top: var(--ot-space-md);
  align-self: start;
  max-height: calc(100vh - 2 * var(--ot-space-md));
  overflow-y: auto;
}

.nav-list {
  margin: 0;
  padding: 0;
  list-style: none;
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
}

.nav-item {
  display: block;
  width: 100%;
  padding: var(--ot-space-xs) var(--ot-space-sm);
  font: inherit;
  font-size: var(--ot-font-size-sm);
  text-align: left;
  color: var(--ot-text-secondary);
  background: transparent;
  border: 1px solid transparent;
  border-left: 3px solid transparent;
  border-radius: var(--ot-radius-md);
  cursor: pointer;
}

.nav-item:hover {
  color: var(--ot-text-primary);
  background-color: var(--ot-bg-surface);
}

.nav-item:focus-visible {
  outline: 2px solid var(--el-color-primary);
  outline-offset: 1px;
}

.nav-item.is-current {
  color: var(--ot-text-primary);
  font-weight: 600;
  background-color: var(--ot-bg-surface);
  border-left-color: var(--el-color-primary);
}

/* 窄畫面：導覽改排在分區之上，項目自動換行，不做水平捲動 */
@media (max-width: 900px) {
  .policy-section-nav {
    position: static;
    max-height: none;
    overflow: visible;
  }

  .nav-list {
    flex-direction: row;
    flex-wrap: wrap;
  }

  .nav-item {
    width: auto;
    border: 1px solid var(--ot-border-subtle);
  }

  .nav-item.is-current {
    border-color: var(--el-color-primary);
  }
}
</style>
