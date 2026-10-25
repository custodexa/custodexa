<!--
  CredentialReassignDialog：把共用憑證改歸到節點（單筆列操作與批次共用）。

  整批原子：任一筆不可操作，伺服器整批拒絕且只回筆數，不指出是哪一筆。
  改歸只改管理歸屬，已掛載的資產與連線不受影響；節點候選與全域選項由伺服器標示。
-->
<template>
  <el-dialog
    :model-value="modelValue"
    :title="t('credentials.reassign.title', { count: credentials.length })"
    width="520px"
    :close-on-click-modal="false"
    data-test="reassign-dialog"
    @update:model-value="close"
  >
    <p
      class="names"
      data-test="reassign-names"
    >
      {{ names }}
    </p>
    <el-form
      label-position="top"
      @submit.prevent
    >
      <el-form-item :label="t('credentials.reassign.target')">
        <CredentialOwnershipSelect
          v-model="ownership"
          purpose="credential_update"
          :active="modelValue"
          :hint="t('credentials.reassign.hint')"
          @state="state = $event"
        />
      </el-form-item>
    </el-form>
    <template #footer>
      <el-button
        data-test="reassign-cancel"
        @click="close(false)"
      >
        {{ t('common.cancel') }}
      </el-button>
      <el-button
        type="primary"
        :loading="submitting"
        :disabled="!state.ready || !credentials.length"
        data-test="reassign-submit"
        @click="submit"
      >
        {{ t('credentials.reassign.submit', { count: credentials.length }) }}
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { reassignCredentialOwnership } from '@/api/credentials'
import CredentialOwnershipSelect from './CredentialOwnershipSelect.vue'

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  // [{ id, name }]
  credentials: { type: Array, default: () => [] },
})

const emit = defineEmits(['update:modelValue', 'done'])

const { t } = useI18n()

const ownership = ref({ kind: 'node', node_id: null })
const state = ref({ ready: false })
const submitting = ref(false)

const names = computed(() => props.credentials.map((c) => c.name).join('、'))

watch(() => props.modelValue, (open) => {
  if (open) ownership.value = { kind: 'node', node_id: null }
})

function close(visible = false) {
  emit('update:modelValue', visible === true)
}

function body() {
  const { kind, node_id: nodeId } = ownership.value
  return {
    credential_ids: props.credentials.map((c) => c.id),
    ownership: kind === 'node' ? { kind, node_id: nodeId } : { kind },
  }
}

async function submit() {
  submitting.value = true
  try {
    await reassignCredentialOwnership(body())
    ElMessage.success(t('credentials.reassign.done', { count: props.credentials.length }))
    close(false)
    emit('done')
  } catch (err) {
    console.error('[CredentialReassign] 改歸失敗:', err?.response?.status, err?.response?.data?.code)
  } finally {
    submitting.value = false
  }
}

defineExpose({ ownership, submit, body })
</script>

<style scoped>
.names {
  margin: 0 0 var(--ot-space-md);
  color: var(--ot-text-secondary);
  word-break: break-all;
}
</style>
