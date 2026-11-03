<!--
  ExecutorInfoList：已設定時的資訊列（帳號名稱、秘密來源、型別、金鑰指紋）。
  只讀 executor（最近一次 GET 的回應），不含任何秘密。
-->
<template>
  <dl
    class="info"
    data-test="executor-info"
  >
    <dt>{{ t('assetExecutor.fields.account') }}</dt>
    <dd
      class="mono"
      data-test="executor-username"
    >
      {{ executor.username }}
    </dd>
    <dt>{{ t('assetExecutor.fields.secretSource') }}</dt>
    <dd data-test="executor-source">
      {{ sourceText }}
      <el-tag
        v-if="sharedTagText"
        size="small"
        type="warning"
        effect="plain"
        data-test="executor-shared-tag"
      >
        {{ sharedTagText }}
      </el-tag>
    </dd>
    <dt>{{ t('assetExecutor.fields.secretType') }}</dt>
    <dd>{{ t(`enum.credentialSecretType.${executor.secret_type}`) }}</dd>
    <template v-if="executor.fingerprint">
      <dt>{{ t('assetExecutor.fields.fingerprint') }}</dt>
      <dd>
        <code
          class="mono"
          data-test="executor-fingerprint"
        >{{ executor.fingerprint }}</code>
        <el-button
          size="small"
          link
          :title="t('assetExecutor.copyFingerprint')"
          :aria-label="t('assetExecutor.copyFingerprint')"
          data-test="executor-copy-fingerprint"
          @click="copyFingerprint"
        >
          <Copy
            :size="13"
            aria-hidden="true"
          />
        </el-button>
      </dd>
    </template>
  </dl>
</template>

<script setup>
import { computed } from 'vue'
import { ElMessage } from 'element-plus'
import { Copy } from 'lucide-vue-next'
import { useI18n } from 'vue-i18n'
import { executorSourceKey } from '@/constants/assetExecutor'

const props = defineProps({
  executor: { type: Object, required: true },
})

const { t } = useI18n()

const credential = computed(() => props.executor?.credential || {})
const sourceText = computed(() => {
  const key = executorSourceKey(props.executor)
  return t(`assetExecutor.sourceLabel.${key}`, { name: credential.value.credential_name || '' })
})
// 共用台數標籤與帳號表的共用標籤同格式，以琥珀色標示（台數代表同一組秘密的影響範圍）
const sharedTagText = computed(() => {
  if (credential.value.credential_out_of_scope === true) return t('assetExecutor.sharedTagOutOfScope')
  if (credential.value.shared_credential) {
    return t('assetExecutor.sharedTag', { count: credential.value.binding_count || 0 })
  }
  return ''
})

async function copyFingerprint() {
  try {
    await navigator.clipboard.writeText(props.executor.fingerprint)
    ElMessage.success(t('assetExecutor.fingerprintCopied'))
  } catch {
    ElMessage.error(t('common.copyFailed'))
  }
}
</script>

<style scoped>
.info {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: 2px var(--ot-space-md);
  margin: 0;
  font-size: var(--ot-font-size-sm);
}

.info dt {
  color: var(--ot-text-secondary);
}

.info dd {
  margin: 0;
}

.mono {
  font-family: var(--ot-font-mono, monospace);
}
</style>
