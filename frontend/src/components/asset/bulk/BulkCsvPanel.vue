<template>
  <div
    class="csv-panel"
    data-test="bulk-csv-panel"
  >
    <section class="block">
      <div class="block-head">
        <span class="block-title">1. {{ t('assets.bulk.stepDownload') }}</span>
        <el-button
          size="small"
          data-test="bulk-download-template"
          @click="downloadTemplate"
        >
          {{ t('assets.bulk.downloadTemplate') }}
        </el-button>
      </div>
      <div class="hints">
        <p>{{ t('assets.bulk.templateHint') }}</p>
        <p>{{ t('assets.bulk.credentialHint') }}</p>
        <div class="hint-row">
          <p>{{ t('assets.bulk.noSecretHint') }}</p>
          <el-button
            link
            type="primary"
            data-test="bulk-toggle-field-help"
            @click="helpOpen = !helpOpen"
          >
            {{ t('assets.bulk.viewFieldHelp') }}
            <el-icon class="caret">
              <ChevronUp v-if="helpOpen" />
              <ChevronDown v-else />
            </el-icon>
          </el-button>
        </div>
        <BulkFieldHelp v-if="helpOpen" />
      </div>
    </section>

    <section class="block">
      <span class="block-title">2. {{ t('assets.bulk.stepUpload') }}</span>
      <el-upload
        drag
        accept=".csv,text/csv"
        :auto-upload="false"
        :show-file-list="false"
        :disabled="loading"
        :on-change="onChange"
        class="dropzone"
        data-test="bulk-dropzone"
      >
        <div
          v-loading="loading"
          class="dropzone-inner"
        >
          <div class="dropzone-text">
            {{ t('assets.bulk.dropzone') }}
          </div>
          <div class="dropzone-limit">
            {{ t('assets.bulk.dropzoneLimit') }}
          </div>
        </div>
      </el-upload>
      <el-alert
        v-if="fileError"
        :title="fileError"
        type="error"
        :closable="false"
        class="file-error"
        data-test="bulk-file-error"
      />
    </section>
  </div>
</template>

<script setup>
/**
 * 上傳 CSV 模式：下載範本、欄位說明、拖放上傳。
 * 解析與驗證全在伺服端（預檢端點收原文）；本元件只把選到的檔案交給上層，
 * 檔案層錯誤由上層取得後回填 fileError，就地顯示在上傳區下方、不載入表格
 */
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { ChevronDown, ChevronUp } from 'lucide-vue-next'
import BulkFieldHelp from './BulkFieldHelp.vue'
import { templateCsv } from '@/utils/assetBulk'
import { downloadBlob } from '@/utils/download'

defineProps({
  loading: { type: Boolean, default: false },
  fileError: { type: String, default: '' },
})

const emit = defineEmits(['file'])

const { t } = useI18n()

const helpOpen = ref(false)

function downloadTemplate() {
  downloadBlob(new Blob([templateCsv()], { type: 'text/csv;charset=utf-8' }), 'assets-template.csv')
}

function onChange(uploadFile) {
  if (uploadFile?.raw) emit('file', uploadFile.raw)
}

defineExpose({ helpOpen })
</script>

<style scoped>
.csv-panel {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-lg);
  padding: var(--ot-space-md) var(--ot-space-lg);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}

.block {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm);
}

.block-head {
  display: flex;
  align-items: center;
  gap: var(--ot-space-md);
}

.block-title {
  font-weight: 600;
}

.hints {
  padding-left: var(--ot-space-lg);
  color: var(--ot-text-primary);
  font-size: var(--ot-font-size-sm);
  line-height: 1.8;
}

.hints p {
  margin: 0;
}

.hint-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: var(--ot-space-sm);
}

.caret {
  margin-left: 2px;
}

.dropzone {
  padding-left: var(--ot-space-lg);
}

.dropzone :deep(.el-upload-dragger) {
  padding: var(--ot-space-lg);
}

.dropzone-text {
  color: var(--ot-text-primary);
}

.dropzone-limit {
  margin-top: var(--ot-space-xs);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
}

.file-error {
  margin-left: var(--ot-space-lg);
  width: auto;
}
</style>
