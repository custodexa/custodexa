<template>
  <!-- 讀不到時停用並說明原因。停用的按鈕本身收不到滑鼠與焦點事件，
       故由外層可聚焦的容器承接：滑過或鍵盤聚焦都看得到原因，
       螢幕報讀器經 aria-describedby 讀到同一句話 -->
  <span
    v-if="blockedState"
    class="recording-download-blocked"
    tabindex="0"
    :aria-describedby="reasonId"
    data-test="recording-download-blocked"
    @mouseenter="tipVisible = true"
    @mouseleave="tipVisible = false"
    @focus="tipVisible = true"
    @blur="tipVisible = false"
  >
    <el-tooltip
      :visible="tipVisible"
      :content="reason"
      placement="bottom-end"
    >
      <el-button
        disabled
        data-test="recording-download-button"
      >
        <el-icon><Download /></el-icon>
        {{ $t('sessionDetail.downloadRecording') }}
      </el-button>
    </el-tooltip>
    <span
      :id="reasonId"
      class="recording-download-reason"
    >{{ reason }}</span>
  </span>
  <el-button
    v-else
    type="primary"
    :loading="loading"
    data-test="recording-download-button"
    @click="$emit('download')"
  >
    <el-icon><Download /></el-icon>
    {{ $t('sessionDetail.downloadRecording') }}
  </el-button>
</template>

<script setup>
import { computed, ref, useId } from 'vue'
import { Download } from 'lucide-vue-next'
import { t } from '@/i18n'

const props = defineProps({
  // null＝可下載；'unreadable'｜'missing'＝停用並說明原因
  blockedState: { type: String, default: null },
  loading: { type: Boolean, default: false },
})
defineEmits(['download'])

const reasonId = `recording-download-reason-${useId()}`
const tipVisible = ref(false)
const reason = computed(() =>
  props.blockedState ? t(`recordingReadability.downloadDisabled.${props.blockedState}`) : ''
)
</script>

<style scoped>
.recording-download-blocked {
  display: inline-flex;
  border-radius: 6px;
  cursor: not-allowed;
}

/* 停用鈕不攔指標事件，滑過由外層容器承接 */
.recording-download-blocked :deep(.el-button) {
  pointer-events: none;
}

.recording-download-blocked:focus-visible {
  outline: 2px solid var(--ot-primary);
  outline-offset: 2px;
}

/* 視覺上隱藏、報讀器可讀 */
.recording-download-reason {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}
</style>
