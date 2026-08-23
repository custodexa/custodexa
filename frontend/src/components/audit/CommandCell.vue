<template>
  <!-- 降級列：這一輪**沒有**可信的指令文字。
       絕不留空字串、也不寫成看起來像空指令的符號——空白會被讀成「使用者按了 Enter
       但沒打字」，那是另一種捏造。此處一律渲染成明確的狀態列。 -->
  <div
    v-if="degraded"
    class="cmd-degraded"
    data-test="degraded-command"
  >
    <div class="cmd-degraded__head">
      <el-icon class="cmd-degraded__icon">
        <WarningFilled />
      </el-icon>
      <span class="cmd-degraded__title">{{ $t('commands.degrade.title') }}</span>
    </div>
    <div
      class="cmd-degraded__reason"
      data-test="degraded-reason"
    >
      {{ reasonText }}
    </div>
    <div class="cmd-degraded__next">
      <span data-test="degraded-recording-hint">{{ recordingHint }}</span>
      <el-button
        v-if="showSeek"
        link
        type="primary"
        size="small"
        data-test="degraded-seek"
        @click="emit('seek', row)"
      >
        {{ $t('commands.degrade.seekAction') }}
      </el-button>
    </div>
  </div>

  <!-- 限定列：文字已入庫，但可能不等於實際執行的指令（Qualify*）。
       與降級列不同型，不可共用同一個標記——否則「無降級標記 ⇒ 文字可信」也會變成假話。 -->
  <div
    v-else-if="qualified"
    class="cmd-qualified"
    data-test="qualified-command"
  >
    <span class="command-text">{{ row.command }}</span>
    <el-tooltip
      :content="reasonText"
      placement="top"
    >
      <el-tag
        type="warning"
        size="small"
        data-test="qualified-tag"
      >
        {{ $t('commands.degrade.qualifiedTag') }}
      </el-tag>
    </el-tooltip>
  </div>

  <!-- 一般列：**不加任何「已驗證」字樣**（偵測判準是充分條件
       而非必要條件，沒有標記不等於內容可信） -->
  <span
    v-else
    class="command-text"
  >{{ row.command }}</span>
</template>

<script setup>
import { computed } from 'vue'
import { WarningFilled } from '@element-plus/icons-vue'
import {
  degradeReasonLabel,
  degradeRecordingHint,
  isDegradedRow,
  isQualifiedRow,
} from '@/constants/command-degrade'

const props = defineProps({
  // 一列 session_command（含 degraded／degrade_reason 兩欄）
  row: { type: Object, required: true },
  // 該列所屬會話的錄影狀態：available／unavailable／unknown（跨會話頁尚未查證時）
  recordingState: { type: String, default: 'unknown' },
  // 呼叫端是否提供「跳到該時段」的下一步（無回放能力的情境給 false）
  seekable: { type: Boolean, default: true },
})

const emit = defineEmits(['seek'])

const degraded = computed(() => isDegradedRow(props.row))
const qualified = computed(() => isQualifiedRow(props.row))
const reasonText = computed(() => degradeReasonLabel(props.row?.degrade_reason))
const recordingHint = computed(() =>
  degradeRecordingHint(props.row?.degrade_reason, props.recordingState)
)
// 沒有錄影就沒有這個下一步，不擺一顆點了只會落空的按鈕
const showSeek = computed(() => props.seekable && props.recordingState !== 'unavailable')
</script>

<style scoped>
/* 欄位若開了 show-overflow-tooltip，.cell 會是 nowrap；狀態列自己覆寫回可換行
   （高度隨內容長，不被水平裁切），一般列的截斷行為則原樣不動 */
.cmd-degraded {
  white-space: normal;
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: var(--ot-space-xs) var(--ot-space-sm);
  border-left: 3px solid var(--ot-warning);
  border-radius: var(--ot-radius-sm);
  background-color: rgba(217, 169, 62, 0.12);
}

.cmd-degraded__head {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
}

.cmd-degraded__icon {
  color: var(--ot-warning);
}

.cmd-degraded__title {
  color: var(--ot-warning);
  font-size: var(--ot-font-size-sm);
  font-weight: 600;
}

.cmd-degraded__reason {
  color: var(--ot-text-primary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.5;
}

.cmd-degraded__next {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
}

.cmd-qualified {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
}

.command-text {
  font-family: var(--ot-font-mono);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-primary);
}
</style>
