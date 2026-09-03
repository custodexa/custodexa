<template>
  <div class="share-view">
    <div class="share-header">
      <span>{{ $t('shareView.header') }}</span>
    </div>
    <MonitorTerminal
      :session-id="0"
      :share-code="code"
    />
    <TerminalWatermark />
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import MonitorTerminal from '@/components/MonitorTerminal.vue'
import TerminalWatermark from '@/components/TerminalWatermark.vue'

const route = useRoute()
const code = computed(() => route.params.code)
</script>

<style scoped>
.share-view {
  height: 100vh;
  display: flex;
  flex-direction: column;
  background: #1e1e1e;
}

.share-header {
  height: 36px;
  display: flex;
  align-items: center;
  padding: 0 16px;
  color: #ccc;
  font-size: 13px;
  background: #252526;
}

.share-view :deep(.monitor-terminal) {
  flex: 1;
}
</style>
