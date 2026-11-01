<template>
  <!-- 樹欄位內的覆蓋層：零高度的置頂錨點，提示與鎖定條以絕對定位疊在樹上、說明卡以視窗座標固定（可超出樹欄位底部），不佔高度、不推動樹列 -->
  <div
    v-if="hint || tip || rowTip || locked"
    class="tree-overlays"
  >
    <div
      v-if="hint"
      class="drag-root-hint"
      :style="{ position: 'absolute', top: 0, left: 0, right: 0, height: `${coverHeight}px` }"
    >
      {{ $t('nodeTree.drag.rootHint') }}
    </div>
    <div
      v-if="tip"
      class="drag-tip"
      :class="tip.ok ? 'is-ok' : 'is-no'"
      :style="{ position: 'fixed', left: `${tip.left}px`, top: `${tip.top}px` }"
      role="tooltip"
    >
      <div class="drag-tip-title">
        {{ tip.title }}
      </div>
      <div class="drag-tip-body">
        {{ tip.body }}
      </div>
    </div>
    <div
      v-if="rowTip && !tip"
      class="drag-tip row-tip"
      :style="{ position: 'fixed', left: `${rowTip.left}px`, top: `${rowTip.top}px` }"
      role="tooltip"
    >
      <div
        v-if="rowTip.title"
        class="drag-tip-title"
      >
        {{ rowTip.title }}
      </div>
      <div class="drag-tip-body">
        {{ rowTip.body }}
      </div>
    </div>
    <div
      v-if="locked"
      class="drag-lock"
      :style="{ position: 'absolute', top: 0, left: 0, right: 0, height: `${lockHeight}px` }"
    >
      <span
        class="drag-lock-bar"
        :style="{ height: `${coverHeight}px` }"
      >{{ $t('nodeTree.drag.lockBar') }}</span>
    </div>
  </div>
</template>

<script setup>
defineProps({
  hint: { type: Boolean, default: false },
  tip: { type: Object, default: null },
  rowTip: { type: Object, default: null },
  locked: { type: Boolean, default: false },
  lockHeight: { type: Number, default: 0 },
  coverHeight: { type: Number, default: 0 },
})
</script>

<style scoped>
.tree-overlays {
  position: sticky;
  top: 0;
  height: 0;
  z-index: 5;
}

.drag-root-hint {
  box-sizing: border-box;
  display: flex;
  align-items: center;
  padding: 0 8px;
  font-size: 12px;
  color: var(--el-color-primary);
  /* 不透明底：疊在標題列上時，底下的字不得透出 */
  background: var(--ot-bg-surface);
  border-radius: 4px;
  box-shadow: inset 0 0 0 1px var(--el-color-primary-light-5);
}

.drag-tip {
  box-sizing: border-box;
  width: 204px;
  padding: 6px 8px;
  border-radius: 6px;
  font-size: 12px;
  line-height: 1.5;
  background: var(--el-bg-color-overlay, #fff);
  border: 1px solid var(--ot-border-subtle, #e4e7ed);
  box-shadow: var(--el-box-shadow-light);
  pointer-events: none;
}

.drag-tip.is-ok {
  border-color: var(--el-color-primary);
}

.drag-tip-title {
  font-weight: 600;
}

.drag-tip.is-no .drag-tip-title {
  color: var(--el-color-danger);
}

.drag-tip-body {
  color: var(--ot-text-secondary);
}

.drag-lock {
  display: flex;
  justify-content: center;
  background: color-mix(in srgb, var(--el-bg-color, #fff) 70%, transparent);
}

.drag-lock-bar {
  box-sizing: border-box;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 100%;
  padding: 0 10px;
  font-size: 12px;
  border-radius: 4px;
  color: var(--el-color-primary);
  /* 不透明底：完整蓋住標題列 */
  background: var(--ot-bg-surface);
  box-shadow: inset 0 0 0 1px var(--el-color-primary-light-5);
}
</style>
