<template>
  <ul
    class="tab-context-menu"
    role="menu"
    :style="{ left: x + 'px', top: y + 'px' }"
  >
    <template
      v-for="item in ITEMS"
      :key="item.command"
    >
      <li
        role="menuitem"
        tabindex="0"
        @click="emit('select', item.command)"
        @keydown.enter.space.prevent="emit('select', item.command)"
      >
        {{ $t(item.label) }}
      </li>
      <li
        v-if="item.divider"
        class="menu-divider"
      />
    </template>
  </ul>
</template>

<script setup>
defineProps({
  x: { type: Number, default: 0 },
  y: { type: Number, default: 0 },
})

// select：選中的指令名，由外層執行
const emit = defineEmits(['select'])

// 重連／複製一組，分隔線後為各種關閉
const ITEMS = [
  { command: 'reconnect', label: 'workspace.menuReconnect' },
  { command: 'duplicate', label: 'workspace.menuDuplicate', divider: true },
  { command: 'close', label: 'workspace.menuClose' },
  { command: 'closeOthers', label: 'workspace.menuCloseOthers' },
  { command: 'closeLeft', label: 'workspace.menuCloseLeft' },
  { command: 'closeRight', label: 'workspace.menuCloseRight' },
  { command: 'closeAll', label: 'workspace.menuCloseAll' },
]
</script>

<style scoped>
.tab-context-menu {
  position: fixed;
  z-index: 3000;
  min-width: 120px;
  margin: 0;
  padding: 4px 0;
  list-style: none;
  background: var(--el-bg-color-overlay);
  border: 1px solid var(--el-border-color);
  border-radius: 4px;
  box-shadow: var(--el-box-shadow-light);
  font-size: 13px;
}

.tab-context-menu li {
  padding: 6px 16px;
  cursor: pointer;
  color: var(--el-text-color-primary);
}

.tab-context-menu li:hover {
  background: var(--el-fill-color-light);
}

.tab-context-menu .menu-divider {
  height: 1px;
  margin: 4px 0;
  padding: 0;
  background: var(--el-border-color-lighter);
  cursor: default;
}
</style>
