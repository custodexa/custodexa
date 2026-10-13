<template>
  <!-- 錄影失敗誠實標示：失敗與「本來就無錄製」是兩回事，須帶原因可辨 -->
  <el-tooltip
    v-if="session.recording_error"
    :content="$t('sessions.recordingErrorTooltip', { error: auditCauseLabel(session.recording_error) })"
    placement="top"
  >
    <el-tag type="danger">
      {{ $t('sessionDetail.noRecordingFailed') }}
    </el-tag>
  </el-tooltip>
  <!-- 有錄影紀錄但錄影檔讀不到：說「目前讀不到」，不說「從未錄到」 -->
  <el-tooltip
    v-else-if="blocked"
    :content="$t(`recordingReadability.card.${blocked}.body`)"
    placement="top"
    :trigger="['hover', 'focus']"
  >
    <el-tag
      :type="blocked === 'missing' ? 'danger' : 'warning'"
      tabindex="0"
      data-test="recording-status-tag"
    >
      <el-icon><TriangleAlert /></el-icon>
      {{ $t(`recordingReadability.state.${blocked}`) }}
    </el-tag>
  </el-tooltip>
  <span
    v-else-if="session.has_recording"
    class="recording-status-available"
  >
    <el-tag
      type="success"
      data-test="recording-status-tag"
    >
      <el-icon><CirclePlay /></el-icon>
      {{ $t('sessionDetail.hasRecording') }}
    </el-tag>
    <span
      v-if="offsite"
      class="recording-offsite-hint"
      data-test="recording-offsite-hint"
    >{{ $t('recordingReadability.offsiteHint') }}</span>
  </span>
  <el-tag
    v-else
    type="info"
    data-test="recording-status-tag"
  >
    {{ $t('sessionDetail.noRecording') }}
  </el-tag>
</template>

<script setup>
import { computed } from 'vue'
import { CirclePlay, TriangleAlert } from 'lucide-vue-next'
// recording_error 存機器碼（cause code）；散文僅存量資料才有——
// auditCauseLabel 未知值原樣回傳，兩者共存不需分支
import { auditCauseLabel } from '@/constants/audit-enums'
import { blockedRecordingState, isOffsiteRecording } from '@/utils/recordingReadability'

const props = defineProps({
  session: { type: Object, required: true },
})

const blocked = computed(() => blockedRecordingState(props.session))
const offsite = computed(() => isOffsiteRecording(props.session))
</script>

<style scoped>
.recording-status-available {
  display: inline-flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}

.recording-offsite-hint {
  font-size: 12px;
  line-height: 1.5;
  color: var(--ot-text-secondary);
}
</style>
