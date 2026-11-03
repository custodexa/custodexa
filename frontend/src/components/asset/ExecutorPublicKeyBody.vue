<!--
  ExecutorPublicKeyBody：公鑰面板的內容（對話框結果內嵌與錨定彈出框共用）。

  內嵌（設定結果）：金鑰指紋列＋複製圖示、「公鑰」標籤、公鑰框、複製／下載。
  彈出框（取得公鑰）：標題、公鑰框、複製／下載與日誌句同列、加到登入金鑰清單的一句。
-->
<template>
  <div class="pk-content">
    <template v-if="inline">
      <template v-if="fingerprint">
        <div class="pk-label">
          {{ t('assetExecutor.fields.fingerprint') }}
        </div>
        <div class="pk-fp">
          <code data-test="pk-fingerprint">{{ fingerprint }}</code>
          <el-button
            size="small"
            link
            :title="t('assetExecutor.copyFingerprint')"
            :aria-label="t('assetExecutor.copyFingerprint')"
            data-test="pk-copy-fingerprint"
            @click="emit('copy-fingerprint')"
          >
            <Copy
              :size="13"
              aria-hidden="true"
            />
          </el-button>
        </div>
      </template>
      <div class="pk-label">
        {{ t('assetExecutor.publicKey.label') }}
      </div>
    </template>
    <div
      v-else
      ref="titleRef"
      class="pk-title"
      tabindex="-1"
      data-test="pk-title"
    >
      <KeyRound
        :size="14"
        aria-hidden="true"
      />
      {{ t('assetExecutor.publicKey.title', { account }) }}
    </div>

    <div
      v-if="loading"
      class="pk-muted"
      data-test="pk-loading"
    >
      {{ t('assetExecutor.publicKey.loading') }}
    </div>
    <div
      v-if="error"
      class="pk-error"
      data-test="pk-error"
    >
      {{ error }}
    </div>

    <template v-if="text">
      <div class="pk-box">
        <code data-test="pk-line">{{ text }}</code>
      </div>
      <div class="pk-actions">
        <el-button
          size="small"
          data-test="pk-copy"
          @click="emit('copy')"
        >
          <Copy
            :size="13"
            aria-hidden="true"
            class="btn-icon"
          />
          {{ t('assetExecutor.publicKey.copy') }}
        </el-button>
        <el-button
          size="small"
          data-test="pk-download"
          @click="emit('download')"
        >
          <Download
            :size="13"
            aria-hidden="true"
            class="btn-icon"
          />
          {{ t('assetExecutor.publicKey.download') }}
        </el-button>
        <span
          v-if="!inline"
          class="pk-muted pk-logged"
          data-test="pk-logged"
        >{{ t('assetExecutor.publicKey.logged') }}</span>
      </div>
      <p
        v-if="!inline"
        class="pk-muted pk-hint"
        data-test="pk-add-hint"
      >
        {{ t('assetExecutor.publicKey.addHint', { account }) }}
      </p>
    </template>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { Copy, Download, KeyRound } from 'lucide-vue-next'

defineProps({
  text: { type: String, default: '' },
  loading: { type: Boolean, default: false },
  error: { type: String, default: '' },
  account: { type: String, default: '' },
  fingerprint: { type: String, default: '' },
  inline: { type: Boolean, default: false },
})
const emit = defineEmits(['copy', 'download', 'copy-fingerprint'])

const { t } = useI18n()
const titleRef = ref(null)

defineExpose({ titleRef })
</script>

<style scoped>
.pk-content {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
  font-size: var(--ot-font-size-sm);
}

.pk-label {
  color: var(--ot-text-secondary);
}

.pk-fp {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
}

.pk-fp code,
.pk-box code {
  font-family: var(--ot-font-mono, monospace);
}

.pk-title {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
  font-weight: 600;
  outline: none;
}

.pk-box {
  padding: var(--ot-space-sm);
  background: var(--ot-bg-page);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}

.pk-box code {
  display: block;
  word-break: break-all;
}

.pk-actions {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
}

.pk-actions .el-button + .el-button {
  margin-left: 0;
}

.pk-logged {
  margin-left: auto;
}

.pk-muted {
  color: var(--ot-text-secondary);
}

.pk-hint {
  margin: 0;
}

.pk-error {
  color: var(--ot-danger);
}

.btn-icon {
  margin-right: 4px;
}
</style>
