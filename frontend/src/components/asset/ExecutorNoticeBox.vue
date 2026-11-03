<!--
  ExecutorNoticeBox：堡壘機專用帳號畫面共用的提示框（警示與錯誤）。

  左側圖示、粗體小號標題、其下內文（預設插槽）。tone 決定框色與預設圖示：
  warning＝黃框與三角驚嘆號，danger＝紅框與圓形叉號，success＝細綠框與細勾號；icon 可換成其他圖示（例如重新整理）。
  focusable 時框本身可被程式聚焦（tabindex=-1），供沒有修正鈕的錯誤承接焦點。
-->
<template>
  <div
    class="notice-box"
    :class="`is-${tone}`"
    :tabindex="focusable ? -1 : undefined"
  >
    <component
      :is="iconComponent"
      :size="15"
      aria-hidden="true"
      class="nb-icon"
      data-test="notice-box-icon"
    />
    <div class="nb-main">
      <strong
        v-if="title"
        class="nb-title"
        data-test="notice-box-title"
      >{{ title }}</strong>
      <slot />
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { Check, CircleX, TriangleAlert } from 'lucide-vue-next'

const props = defineProps({
  tone: { type: String, default: 'warning' },
  title: { type: String, default: '' },
  icon: { type: [Object, Function], default: null },
  focusable: { type: Boolean, default: false },
})

const TONE_ICONS = { warning: TriangleAlert, danger: CircleX, success: Check }
const iconComponent = computed(() => props.icon || TONE_ICONS[props.tone] || TriangleAlert)
</script>

<style scoped>
.notice-box {
  display: flex;
  align-items: flex-start;
  gap: var(--ot-space-sm);
  padding: var(--ot-space-sm) var(--ot-space-md) var(--ot-space-sm) var(--ot-space-sm);
  font-size: var(--ot-font-size-sm);
  line-height: 1.6;
  color: var(--ot-text-primary);
  border: 1px solid;
  border-radius: var(--ot-radius-md);
}

.notice-box.is-warning {
  background-color: color-mix(in srgb, var(--ot-warning) 10%, transparent);
  border-color: color-mix(in srgb, var(--ot-warning) 45%, transparent);
}

.notice-box.is-danger {
  background-color: color-mix(in srgb, var(--ot-danger) 18%, transparent);
  border-color: color-mix(in srgb, var(--ot-danger) 70%, transparent);
}

.notice-box.is-success {
  background-color: color-mix(in srgb, var(--ot-success) 12%, transparent);
  border-color: color-mix(in srgb, var(--ot-success) 55%, transparent);
}

.nb-icon {
  flex: none;
  margin-top: 3px;
}

.is-warning .nb-icon {
  color: var(--ot-warning);
}

.is-danger .nb-icon {
  color: var(--ot-danger);
}

.is-success .nb-icon {
  color: var(--ot-success);
}

.nb-main {
  display: flex;
  flex: 1;
  flex-direction: column;
  align-items: flex-start;
  gap: 2px;
  min-width: 0;
}

.nb-title {
  font-size: var(--ot-font-size-sm);
  font-weight: 600;
}

.nb-main :deep(p) {
  margin: 0;
}
</style>
