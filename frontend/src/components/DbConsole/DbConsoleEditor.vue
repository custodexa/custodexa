<template>
  <div class="db-console-editor">
    <div class="editor-actions">
      <el-button
        type="primary"
        size="small"
        :disabled="!canRun"
        @click="runAll"
      >
        {{ t('dbConsole.editor.run') }}
      </el-button>
      <el-button
        size="small"
        :disabled="!canRun || !hasSelection"
        @click="runSelection"
      >
        {{ t('dbConsole.editor.runSelection') }}
      </el-button>
      <el-button
        size="small"
        :disabled="!canRun"
        @click="runCursorStatement"
      >
        {{ t('dbConsole.editor.runCursor') }}
      </el-button>
      <el-button
        v-if="busy"
        size="small"
        type="warning"
        @click="emit('cancel')"
      >
        {{ t('dbConsole.editor.cancel') }}
      </el-button>
      <span class="editor-hint">{{ t('dbConsole.editor.shortcutHint') }}</span>
    </div>

    <!-- 批次終止符說明：同一個編輯器上 mysql/postgres 以分號分段、mssql 需要
         獨立一行的批次終止符，差異無說明時會被誤判為「送出沒反應」。
         關閉後本次分頁不再出現——不落 localStorage，否則共用同一台機器的
         下一個人就再也看不到 -->
    <el-alert
      v-if="showBatchHint"
      class="editor-alert"
      type="info"
      show-icon
      :closable="true"
      :title="t('dbConsole.editor.batchHint')"
      @close="batchHintDismissed = true"
    />

    <textarea
      ref="areaRef"
      class="editor-area"
      :value="modelValue"
      :placeholder="t('dbConsole.editor.placeholder')"
      spellcheck="false"
      @input="onInput"
      @keyup="syncSelection"
      @mouseup="syncSelection"
      @select="syncSelection"
      @keydown.tab.prevent="insertIndent"
      @keydown.enter.ctrl.exact.prevent="runAll"
      @keydown.enter.meta.exact.prevent="runAll"
    />

    <!-- 錯誤就近呈現於編輯器下方，不走全域提示 -->
    <div
      v-if="error"
      class="editor-error"
    >
      <el-alert
        type="error"
        :closable="false"
        show-icon
        :title="error.message"
      >
        <p
          v-if="error.dbError && error.dbError.code"
          class="error-code"
        >
          {{ t('dbConsole.editor.targetCode', { code: error.dbError.code }) }}
        </p>
        <pre
          v-if="error.dbError && error.dbError.message"
          class="error-detail"
        >{{ error.dbError.message }}</pre>
      </el-alert>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { t } from '@/i18n'
import { segmentAtCursor } from './statement-segments'

const props = defineProps({
  modelValue: { type: String, default: '' },
  // 方言：只用於方言專屬的使用者提示，不從結果內容推測
  dialect: { type: String, default: '' },
  // 有單位進行中：單進行中送出
  busy: { type: Boolean, default: false },
  // 連線不可用或目標受限：送出一律被拒，先在畫面上停用
  disabled: { type: Boolean, default: false },
  // 編輯器下方的錯誤面板內容
  error: { type: Object, default: null },
})

const emit = defineEmits(['update:modelValue', 'execute', 'cancel'])

const areaRef = ref(null)
const hasSelection = ref(false)
const batchHintDismissed = ref(false)

const canRun = computed(() => !props.busy && !props.disabled)
const showBatchHint = computed(() => props.dialect === 'mssql' && !batchHintDismissed.value)

function onInput(event) {
  emit('update:modelValue', event.target.value)
  syncSelection()
}

// textarea 沒有自己的 selectionchange 事件，選取範圍只能在可能改變它的互動後同步
function syncSelection() {
  const el = areaRef.value
  hasSelection.value = !!el && el.selectionStart !== el.selectionEnd
}

function insertIndent() {
  const el = areaRef.value
  if (!el) return
  const { selectionStart: start, selectionEnd: end } = el
  const next = `${props.modelValue.slice(0, start)}  ${props.modelValue.slice(end)}`
  emit('update:modelValue', next)
  // 值由父層回寫，游標位置要等回寫落到 DOM 之後才推得回去
  requestAnimationFrame(() => {
    el.selectionStart = start + 2
    el.selectionEnd = start + 2
    syncSelection()
  })
}

function submit(sql) {
  const text = String(sql || '').trim()
  if (!text || !canRun.value) return
  emit('execute', text)
}

function runAll() {
  submit(props.modelValue)
}

function runSelection() {
  const el = areaRef.value
  if (!el) return
  submit(props.modelValue.slice(el.selectionStart, el.selectionEnd))
}

function runCursorStatement() {
  const el = areaRef.value
  submit(segmentAtCursor(props.modelValue, el ? el.selectionStart : 0))
}

defineExpose({ focus: () => areaRef.value?.focus() })
</script>

<style scoped>
.db-console-editor {
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 0;
  gap: var(--ot-space-xs);
  padding: var(--ot-space-sm);
}

.editor-actions {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
  flex-wrap: wrap;
}

.editor-hint {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-disabled);
  margin-left: auto;
}

.editor-alert {
  flex: none;
}

.editor-area {
  flex: 1 1 auto;
  min-height: 96px;
  resize: none;
  width: 100%;
  box-sizing: border-box;
  padding: var(--ot-space-sm);
  border: 1px solid var(--el-border-color);
  border-radius: var(--el-border-radius-base);
  background: var(--el-fill-color-blank);
  color: var(--el-text-color-primary);
  font-family: var(--ot-font-mono);
  font-size: var(--ot-font-size-sm);
  line-height: 1.6;
  tab-size: 2;
}

.editor-area:focus {
  outline: none;
  border-color: var(--el-color-primary);
}

/* 目標端的錯誤原文可以很長；限高內捲避免把編輯器推走，
   但留得夠讀完一般的語法錯誤 */
.editor-error {
  flex: none;
  max-height: 45%;
  overflow: auto;
}

.error-code {
  margin: var(--ot-space-xs) 0 0;
  font-family: var(--ot-font-mono);
  font-size: var(--ot-font-size-sm);
}

.error-detail {
  margin: var(--ot-space-xs) 0 0;
  white-space: pre-wrap;
  word-break: break-word;
  font-family: var(--ot-font-mono);
  font-size: var(--ot-font-size-sm);
}
</style>
