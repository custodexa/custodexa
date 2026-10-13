<template>
  <div
    class="entra-assist"
    data-test="entra-issuer-assist"
  >
    <label
      class="entra-assist__label"
      :for="inputId"
    >{{ $t('identitySources.oidc.entraAssist.label') }}</label>
    <el-input
      :id="inputId"
      v-model="tenantId"
      class="entra-assist__input"
      data-test="entra-tenant-input"
      placeholder="00000000-0000-0000-0000-000000000000"
      @input="onInput"
      @change="submit"
    />
    <div
      v-if="status"
      class="entra-assist__done"
      data-test="entra-assist-status"
    >
      {{ $t(`identitySources.oidc.entraAssist.${status}`) }}
    </div>
  </div>
</template>

<script setup>
// Entra 的 Issuer 輔助：只拿到目錄（租用戶）識別碼的管理者，貼上即組成完整網址。
// Issuer 欄仍是實際儲存的值、可手動改；這裡只負責代填，不另存任何東西
import { ref } from 'vue'

defineProps({
  // 父頁組好後回報的結果：composed／composedKeptTid；空字串＝尚未組成
  status: { type: String, default: '' },
})

const emit = defineEmits(['compose'])

const inputId = `entra-tenant-${Math.random().toString(36).slice(2, 8)}`
const tenantId = ref('')

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

const submit = () => {
  const id = tenantId.value.trim()
  if (id) emit('compose', id)
}

// 貼上完整的 GUID 即組成，不必再按 Enter 或移開焦點；其他寫法（如網域名稱）於確認時組成
const onInput = (value) => {
  if (GUID.test(String(value).trim())) submit()
}
</script>

<style scoped>
.entra-assist {
  width: 100%;
  margin-top: var(--ot-space-xs);
  padding: var(--ot-space-sm);
  background-color: var(--ot-bg-elevated);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md, 6px);
}

.entra-assist__label {
  display: block;
  margin-bottom: 4px;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
}

.entra-assist__input :deep(input) {
  font-family: var(--ot-font-mono, monospace);
}

.entra-assist__done {
  margin-top: 4px;
  color: var(--ot-success);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
}
</style>
