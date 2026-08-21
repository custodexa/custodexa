<template>
  <div
    class="span-bars"
    data-test="session-spans"
  >
    <p
      v-if="rows.length === 0"
      class="span-empty"
      data-test="spans-empty"
    >
      {{ $t('auditorWorkbench.spans.empty') }}
    </p>

    <div
      v-for="row in rows"
      :key="row.span.session_id"
      class="span-row"
      data-test="span-row"
    >
      <div
        class="span-meta"
        :style="{ width: `${gutter}px` }"
        :title="metaTitle(row.span)"
      >
        <span class="meta-main">{{ counterpartName(row.span) }}</span>
        <span class="meta-sub">
          {{ row.span.account || '-' }} · {{ row.span.protocol }}
        </span>
      </div>

      <div class="span-track">
        <el-tooltip
          placement="top"
          :show-after="150"
          :content="tooltip(row)"
        >
          <div
            class="span-bar"
            :class="{
              'is-ongoing': row.geo.ongoing,
              'is-clipped-start': row.geo.clippedStart,
              'is-clipped-end': row.geo.clippedEnd,
            }"
            :style="{ left: `${row.geo.left}%`, width: `${row.geo.width}%` }"
            role="button"
            tabindex="0"
            :aria-label="ariaLabel(row)"
            :data-test="`span-bar-${row.span.session_id}`"
            @click="emit('open-session', row.span.session_id)"
            @keyup.enter="emit('open-session', row.span.session_id)"
          />
        </el-tooltip>
        <span
          v-if="row.geo.ongoing"
          class="ongoing-label"
          :style="{ left: `${Math.min(row.geo.left + row.geo.width, 96)}%` }"
        >
          {{ $t('auditorWorkbench.spans.ongoing') }}
        </span>
      </div>

      <div class="span-tail">
        <el-tag
          size="small"
          :type="recordingTagType(row.span.recording_state)"
          :data-test="`recording-${row.span.session_id}`"
          :title="recordingHint(row.span.recording_state)"
        >
          {{ $t(`auditorWorkbench.recording.${row.span.recording_state || 'none'}`) }}
        </el-tag>
        <el-button
          v-if="row.span.recording_state === 'available'"
          link
          type="primary"
          size="small"
          @click="emit('open-session', row.span.session_id)"
        >
          {{ $t('auditorWorkbench.spans.replay') }}
        </el-button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { spanGeometry } from './timelineGeometry'
import { sessionStatusLabel } from './timelineSummary'
import { formatDateTime, formatDurationSeconds } from '@/utils/format'

// 會話跨度條（D6）。**不做泳道**：同時段多人在線由多列在同一刻度上視覺重疊
// 呈現，列依 start 升冪排序使重疊叢集相鄰。進行中會話右端漸層淡出，
// SHALL NOT 畫硬邊——硬邊會被讀成「已結束於此刻」
const props = defineProps({
  spans: { type: Array, default: () => [] },
  from: { type: [String, Number, Date], required: true },
  to: { type: [String, Number, Date], required: true },
  subject: { type: String, default: 'user' },
  gutter: { type: Number, default: 200 },
  now: { type: Number, default: null },
})
const emit = defineEmits(['open-session'])

const { t } = useI18n()

const nowMs = computed(() => props.now ?? Date.now())

const rows = computed(() =>
  [...(props.spans || [])]
    .sort((a, b) => new Date(a.start) - new Date(b.start))
    .map((span) => ({ span, geo: spanGeometry(span, props.from, props.to, nowMs.value) }))
    .filter((row) => row.geo && row.geo.visible)
)

const counterpartName = (span) =>
  props.subject === 'asset'
    ? span.user_name || `#${span.user_id}`
    : span.asset_name || (span.asset_id ? `#${span.asset_id}` : '-')

const metaTitle = (span) =>
  `${counterpartName(span)} · ${span.account || '-'} · ${span.protocol}`

const endText = (row) =>
  row.geo.ongoing
    ? t('auditorWorkbench.spans.ongoing')
    : formatDateTime(row.span.end)

const tooltip = (row) => {
  const parts = [
    t('auditorWorkbench.spans.tooltipRange', {
      start: formatDateTime(row.span.start),
      end: endText(row),
    }),
    t('auditorWorkbench.spans.tooltipDuration', {
      duration: formatDurationSeconds(row.geo.durationSeconds),
    }),
    t('auditorWorkbench.spans.tooltipStatus', {
      status: sessionStatusLabel(row.span.status) || row.span.status || '-',
    }),
  ]
  // 裁切必須說明白：不標的話跨窗會話看起來就是「剛好在窗邊起訖」
  if (row.geo.clippedStart) parts.push(t('auditorWorkbench.spans.clippedStart'))
  if (row.geo.clippedEnd) parts.push(t('auditorWorkbench.spans.clippedEnd'))
  return parts.join('\n')
}

const ariaLabel = (row) =>
  t('auditorWorkbench.spans.ariaLabel', {
    user: row.span.user_name || `#${row.span.user_id}`,
    asset: row.span.asset_name || (row.span.asset_id ? `#${row.span.asset_id}` : '-'),
    start: formatDateTime(row.span.start),
    end: endText(row),
    duration: formatDurationSeconds(row.geo.durationSeconds),
  })

const recordingTagType = (state) => {
  if (state === 'available') return 'success'
  if (state === 'purged') return 'warning'
  return 'info'
}

// 「無錄影檔」分不出「未設定」與「錄影失敗」（後端把兩者壓成同一個 none，
// `timeline_service.go:634-644`），而後者是重大缺失。標籤維持短，分辨方法
// 掛在提示上；其餘兩態沒有可補的資訊，不掛空提示
const recordingHint = (state) =>
  state && state !== 'none' ? undefined : t('auditorWorkbench.recording.noneHint')
</script>

<style scoped>
.span-bars {
  padding: var(--ot-space-xs) 0;
}

.span-empty {
  margin: var(--ot-space-sm) 0;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.span-row {
  display: flex;
  align-items: center;
  height: 28px;
}

.span-row:hover {
  background-color: var(--ot-bg-hover);
}

.span-meta {
  flex: none;
  padding-right: var(--ot-space-sm);
  overflow: hidden;
  white-space: nowrap;
  text-overflow: ellipsis;
  font-size: var(--ot-font-size-xs);
}

.meta-main {
  color: var(--ot-text-primary);
}

.meta-sub {
  margin-left: var(--ot-space-xs);
  color: var(--ot-text-secondary);
}

.span-track {
  position: relative;
  flex: 1;
  height: 100%;
}

.span-bar {
  position: absolute;
  top: 8px;
  height: 12px;
  /* 極短會話（dev 庫大量 0-1 秒）沒有最小寬度就完全看不見 */
  min-width: 3px;
  border-radius: 2px;
  background-color: var(--ot-primary);
  cursor: pointer;
}

.span-bar:focus-visible {
  outline: 2px solid var(--ot-primary-hover);
}

/* 進行中：右端漸層淡出，不畫硬邊 */
.span-bar.is-ongoing {
  background-image: linear-gradient(
    to right,
    var(--ot-primary) 60%,
    rgba(79, 131, 241, 0)
  );
  border-radius: 2px 0 0 2px;
}

/* 裁切標記：窗外延伸的那一端加斜紋邊 */
.span-bar.is-clipped-start {
  border-left: 3px double var(--ot-warning);
  border-radius: 0 2px 2px 0;
}

.span-bar.is-clipped-end {
  border-right: 3px double var(--ot-warning);
  border-radius: 2px 0 0 2px;
}

.ongoing-label {
  position: absolute;
  top: 6px;
  font-size: var(--ot-font-size-xs);
  color: var(--ot-primary-hover);
  white-space: nowrap;
  pointer-events: none;
}

.span-tail {
  flex: none;
  width: 150px;
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: var(--ot-space-xs);
}
</style>
