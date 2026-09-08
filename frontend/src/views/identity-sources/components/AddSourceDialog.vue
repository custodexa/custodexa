<template>
  <el-dialog
    :model-value="modelValue"
    :title="$t('identitySources.addDialog.title')"
    width="520px"
    :close-on-click-modal="false"
    @update:model-value="$emit('update:modelValue', $event)"
  >
    <p class="picker-hint">
      {{ $t('identitySources.addDialog.hint') }}
    </p>

    <!-- 只問型別，不在此收任何欄位：選定即進詳情頁，儲存前不建立任何資料 -->
    <el-radio-group
      v-model="picked"
      class="picker-group"
    >
      <el-radio
        class="picker-item"
        value="oidc"
      >
        <span class="picker-title">{{ $t('identitySources.addDialog.oidcTitle') }}</span>
        <span class="picker-desc">{{ $t('identitySources.addDialog.oidcDesc') }}</span>
      </el-radio>
      <!-- 目錄為單例資源：已有一個時本選項停用，並就地說明原因——
           停用而不說明只會讓人以為是壞掉的選項 -->
      <el-radio
        class="picker-item"
        value="ldap"
        :disabled="directoryExists"
      >
        <span class="picker-title">{{ $t('identitySources.addDialog.ldapTitle') }}</span>
        <span class="picker-desc">{{ $t('identitySources.addDialog.ldapDesc') }}</span>
        <span
          v-if="directoryExists"
          class="picker-disabled"
        >{{ $t('identitySources.addDialog.ldapDisabled') }}</span>
      </el-radio>
    </el-radio-group>

    <template #footer>
      <el-button @click="$emit('update:modelValue', false)">
        {{ $t('common.cancel') }}
      </el-button>
      <el-button
        type="primary"
        :disabled="!picked"
        @click="$emit('picked', picked)"
      >
        {{ $t('identitySources.addDialog.next') }}
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { ref, watch } from 'vue'

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  directoryExists: { type: Boolean, default: false },
})

defineEmits(['update:modelValue', 'picked'])

const picked = ref('oidc')

// 每次開啟都回到預設選項：留著上一次的選擇會讓「已停用的目錄」仍是選中狀態
watch(
  () => props.modelValue,
  (open) => {
    if (open) picked.value = 'oidc'
  }
)
</script>

<style scoped>
.picker-hint {
  margin: 0 0 var(--ot-space-md);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.picker-group {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm);
  width: 100%;
}

/* el-radio 預設是單行內聯，這裡要的是可讀說明的選項卡 */
.picker-item {
  display: flex;
  align-items: flex-start;
  width: 100%;
  height: auto;
  margin: 0;
  padding: var(--ot-space-md);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md, 6px);
}

.picker-item :deep(.el-radio__label) {
  display: flex;
  flex-direction: column;
  gap: 4px;
  white-space: normal;
  line-height: 1.6;
}

.picker-title {
  font-weight: 600;
  color: var(--ot-text-primary);
}

.picker-desc {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
}

.picker-disabled {
  color: var(--ot-warning, #e6a23c);
  font-size: var(--ot-font-size-xs);
}
</style>
