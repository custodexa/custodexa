<template>
  <el-popover
    placement="bottom-end"
    :width="200"
    trigger="click"
  >
    <template #reference>
      <el-button
        class="column-gear"
        :title="$t('columnSettings.gearTooltip')"
      >
        <el-icon><Setting /></el-icon>
        {{ $t('columnSettings.button') }}
      </el-button>
    </template>
    <div class="column-settings">
      <p class="settings-hint">
        {{ $t('columnSettings.hint') }}
      </p>
      <el-checkbox
        v-for="col in pool"
        :key="col.key"
        :model-value="modelValue.includes(col.key)"
        :label="col.label"
        @change="(checked) => toggle(col.key, checked)"
      />
      <div class="settings-footer">
        <el-button
          size="small"
          text
          @click="$emit('reset')"
        >
          {{ $t('columnSettings.resetDefault') }}
        </el-button>
      </div>
    </div>
  </el-popover>
</template>

<script setup>
import { Setting } from '@element-plus/icons-vue'

// 欄位自訂齒輪（asset-list-info-layering D4）：池按角色由父層給定；
// 持久化（localStorage 角色分域 key）由父層負責，本元件純呈現
const props = defineProps({
  // 已勾選的池欄 key 陣列
  modelValue: { type: Array, default: () => [] },
  // 可選欄池 [{ key, label }]
  pool: { type: Array, default: () => [] },
})
const emit = defineEmits(['update:modelValue', 'reset'])

// 僅供本元件 template 的 checkbox 使用；不對外 expose（父層透過 v-model
// 與 @reset 互動，無 ref 呼叫端）
const toggle = (key, checked) => {
  const next = props.modelValue.filter((k) => k !== key)
  if (checked) next.push(key)
  emit('update:modelValue', next)
}
</script>

<style scoped>
.settings-hint {
  margin: 0 0 8px;
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.column-settings :deep(.el-checkbox) {
  display: flex;
  margin-right: 0;
}

.settings-footer {
  margin-top: 8px;
  text-align: right;
  border-top: 1px solid var(--el-border-color-lighter);
  padding-top: 6px;
}
</style>
