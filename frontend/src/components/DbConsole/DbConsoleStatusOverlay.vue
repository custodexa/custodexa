<template>
  <div class="status-overlay">
    <template v-if="status === 'connecting'">
      <el-icon
        class="is-loading"
        :size="32"
      >
        <LoaderCircle />
      </el-icon>
      <p>{{ t('dbConsole.connecting') }}</p>
    </template>
    <el-result
      v-else
      :icon="status === 'error' ? 'error' : 'info'"
      :title="status === 'error'
        ? t('dbConsole.errorTitle')
        : t('dbConsole.disconnectedTitle')"
      :sub-title="detail"
    >
      <template #extra>
        <el-button
          type="primary"
          @click="emit('reconnect')"
        >
          {{ t('dbConsole.reconnect') }}
        </el-button>
      </template>
    </el-result>
  </div>
</template>

<script setup>
import { LoaderCircle } from 'lucide-vue-next'
import { t } from '@/i18n'

defineProps({
  status: { type: String, default: '' },
  detail: { type: String, default: '' },
})

const emit = defineEmits(['reconnect'])
</script>

<style scoped>
.status-overlay {
  position: absolute;
  inset: 0;
  z-index: 10;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: var(--ot-space-sm);
  background: var(--el-bg-color);
}
</style>
