<template>
  <!-- 側欄底部的產品版本行：純文字、不可點。
       取不到可顯示的版本時整行不渲染，不留空白。
       收合態只有 64px，比照 logo 列收掉品牌名、只留版號；滑過以 title 看完整字樣 -->
  <div
    v-if="version"
    class="sidebar-version"
    :class="{ collapsed }"
    :title="fullText"
  >
    {{ collapsed ? version : fullText }}
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { BRAND } from '@/brand'
import { displayableVersion } from '@/utils/productVersion'

const props = defineProps({
  // `/auth/me` 的 product_version 原值；顯示與否由 displayableVersion 判定
  raw: { type: String, default: '' },
  collapsed: { type: Boolean, default: false },
})

const version = computed(() => displayableVersion(props.raw))
const fullText = computed(() => `${BRAND.name} ${version.value}`)
</script>

<style scoped>
/* 在選單捲動區之外（側欄是 flex 直欄、選單 flex: 1 自己捲），
   故選單再長也留在視窗底部。字級與色取次要文字，不搶選單的注意力 */
.sidebar-version {
  flex-shrink: 0;
  border-top: 1px solid var(--ot-border-subtle);
  padding: var(--ot-space-sm) var(--ot-space-md);
  font-size: var(--ot-font-size-xs);
  line-height: 16px;
  color: var(--ot-text-secondary);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  cursor: default;
}

.sidebar-version.collapsed {
  padding: var(--ot-space-sm) var(--ot-space-xs);
  text-align: center;
}
</style>
