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

    <template v-else>
      <!-- 總覽的開合列：**永遠看得到全部連線的時段塊**（同一條刻度尺），
           展開才逐資產分列。收合態只佔一列，事件明細因此留在初始視窗內 -->
      <div
        class="span-row is-overview"
        role="button"
        tabindex="0"
        :aria-expanded="overviewOpen ? 'true' : 'false'"
        :aria-label="overviewOpen
          ? $t('auditorWorkbench.spans.collapseOverview')
          : $t('auditorWorkbench.spans.expandOverview')"
        data-test="spans-overview-toggle"
        @click="overviewOpen = !overviewOpen"
        @keyup.enter="overviewOpen = !overviewOpen"
      >
        <div
          class="span-meta"
          :style="{ width: `${gutter}px` }"
          :title="overviewMetaTitle"
        >
          <span class="meta-caret">{{ overviewOpen ? '▾' : '▸' }}</span>
          <span class="meta-main">{{ $t('auditorWorkbench.spans.overviewTitle') }}</span>
          <span
            class="meta-sub"
            data-test="spans-overview-summary"
          >
            {{ overviewSummary }}
          </span>
        </div>

        <div class="span-track">
          <span
            v-for="row in rows"
            :key="`all-${row.span.session_id}`"
            class="span-bar is-block"
            :class="{ 'is-ongoing': row.geo.ongoing }"
            :style="{ left: `${row.geo.left}%`, width: `${row.geo.width}%` }"
            aria-hidden="true"
          />
        </div>

        <div class="span-tail" />
      </div>

      <template v-if="overviewOpen">
        <template
          v-for="group in shownGroups"
          :key="group.key"
        >
          <!-- 總覽層：一台資產一列。時段塊只做定位，逐場細節在展開層 -->
          <div
            class="span-row is-asset"
            role="button"
            tabindex="0"
            :aria-expanded="isAssetOpen(group.key) ? 'true' : 'false'"
            :aria-label="isAssetOpen(group.key)
              ? $t('auditorWorkbench.spans.collapseAsset', { name: group.name })
              : $t('auditorWorkbench.spans.expandAsset', { name: group.name })"
            :data-test="`asset-row-${group.key}`"
            @click="toggleAsset(group.key)"
            @keyup.enter="toggleAsset(group.key)"
          >
            <div
              class="span-meta"
              :style="{ width: `${gutter}px` }"
              :title="group.name"
            >
              <span class="meta-caret">{{ isAssetOpen(group.key) ? '▾' : '▸' }}</span>
              <span class="meta-main">{{ group.name }}</span>
            </div>

            <div class="span-track">
              <span
                v-for="row in group.rows"
                :key="`g-${row.span.session_id}`"
                class="span-bar is-block"
                :class="{ 'is-ongoing': row.geo.ongoing }"
                :style="{ left: `${row.geo.left}%`, width: `${row.geo.width}%` }"
                aria-hidden="true"
              />
            </div>

            <div class="span-tail">
              <el-tag
                size="small"
                type="info"
                :data-test="`asset-count-${group.key}`"
              >
                {{ $t('auditorWorkbench.spans.assetSessions', { n: group.rows.length }) }}
              </el-tag>
            </div>
          </div>

          <!-- 展開層：逐場一列。並發會話 SHALL NOT 合併，同時在線者才辨識得出來 -->
          <div
            v-for="row in (isAssetOpen(group.key) ? group.rows : [])"
            :key="row.span.session_id"
            class="span-row is-session"
            data-test="span-row"
          >
            <div
              class="span-meta is-indented"
              :style="{ width: `${gutter}px` }"
              :title="metaTitle(row.span)"
            >
              <span class="meta-main">{{ sessionName(row.span) }}</span>
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
        </template>

        <!-- 資產數超過上限：其餘的摺成一列，總覽高度因此不隨資產數無限長 -->
        <div
          v-if="restCount > 0"
          class="span-row is-rest"
          role="button"
          tabindex="0"
          :aria-expanded="restOpen ? 'true' : 'false'"
          data-test="spans-rest-toggle"
          @click="restOpen = !restOpen"
          @keyup.enter="restOpen = !restOpen"
        >
          <div
            class="span-meta"
            :style="{ width: `${gutter}px` }"
          >
            <span class="meta-caret">{{ restOpen ? '▾' : '▸' }}</span>
            <span class="meta-main">
              {{ $t('auditorWorkbench.spans.restAssets', { n: restCount }) }}
            </span>
          </div>
          <div class="span-track" />
          <div class="span-tail" />
        </div>
      </template>
    </template>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { spanGeometry } from './timelineGeometry'
import { sessionStatusLabel } from './timelineSummary'
import { formatDateTime, formatDurationSeconds } from '@/utils/format'

// 會話跨度條，**兩層**：
// - 總覽層＝按資產聚合，一台資產一列（時段塊＋場數），列數有上界，
//   高度因此不隨會話數線性增長（67 場單層時是 1884px，把主角壓到摺線下）。
// - 展開層＝點資產列還原逐場一列。**不做泳道**：同時段多人在線由多列在
//   同一刻度上視覺重疊呈現，列依 start 升冪排序使重疊叢集相鄰。
//
// 進行中會話右端漸層淡出，SHALL NOT 畫硬邊——硬邊會被讀成「已結束於此刻」。
// 開放端、裁切、最小寬度、文字等價（aria-label）、錄影三態全數只在展開層
// 呈現，語義逐條保留
const props = defineProps({
  spans: { type: Array, default: () => [] },
  from: { type: [String, Number, Date], required: true },
  to: { type: [String, Number, Date], required: true },
  subject: { type: String, default: 'user' },
  gutter: { type: Number, default: 200 },
  now: { type: Number, default: null },
  // 總覽層的列數上界；超出者摺成「其餘 N 台資產」一列
  maxAssetRows: { type: Number, default: 12 },
})
const emit = defineEmits(['open-session'])

const { t } = useI18n()

// 總覽預設收合＝**版面裁決**（DoD 13 與 DoD 14 的算術衝突）：1440×900 下
// 基準資料集有 10 台資產，逐資產展開即 280px，事件明細的初始可視高度就
// 掉到視窗一半以下。收合態仍畫出全部連線的時段塊（資訊不消失，只是不分列），
// 一次點擊即得逐資產分列。不做 localStorage 記憶：重載一律回到合規版面
const overviewOpen = ref(false)
const restOpen = ref(false)
const openAssets = ref(new Set())

const nowMs = computed(() => props.now ?? Date.now())

const rows = computed(() =>
  [...(props.spans || [])]
    .sort((a, b) => new Date(a.start) - new Date(b.start))
    .map((span) => ({ span, geo: spanGeometry(span, props.from, props.to, nowMs.value) }))
    .filter((row) => row.geo && row.geo.visible)
)

const assetName = (span) =>
  span.asset_name || (span.asset_id ? `#${span.asset_id}` : t('auditorWorkbench.spans.unknownAsset'))

// 依資產聚合。排序＝場數多者在前（超出上限時被摺起來的是最少的那些），
// 同場數則以最早起點排序，讀起來與時間軸方向一致
const groups = computed(() => {
  const byKey = new Map()
  rows.value.forEach((row) => {
    const key = String(row.span.asset_id ?? row.span.asset_name ?? 'unknown')
    if (!byKey.has(key)) {
      byKey.set(key, { key, name: assetName(row.span), rows: [] })
    }
    byKey.get(key).rows.push(row)
  })
  return [...byKey.values()].sort(
    (a, b) =>
      b.rows.length - a.rows.length ||
      new Date(a.rows[0].span.start) - new Date(b.rows[0].span.start)
  )
})

const shownGroups = computed(() =>
  restOpen.value ? groups.value : groups.value.slice(0, props.maxAssetRows)
)

const restCount = computed(() => Math.max(0, groups.value.length - props.maxAssetRows))

const overviewSummary = computed(() =>
  t('auditorWorkbench.spans.overviewSummary', {
    assets: groups.value.length,
    sessions: rows.value.length,
  })
)

// 總覽列的 meta 欄固定 200px，en 的「Session overview 39 assets, 67 sessions」
// 會被截掉場數（讀者看不到自己在看多少場連線）。與資產列同做法：整句掛
// title，截斷時仍可 hover 取得全文
const overviewMetaTitle = computed(
  () => `${t('auditorWorkbench.spans.overviewTitle')} ${overviewSummary.value}`
)

const isAssetOpen = (key) => openAssets.value.has(key)

const toggleAsset = (key) => {
  const next = new Set(openAssets.value)
  if (next.has(key)) next.delete(key)
  else next.add(key)
  openAssets.value = next
}

// 展開層列首：資產已寫在群組列上，這裡給的是**這一場是誰、用哪個帳號**
const sessionName = (span) => span.user_name || (span.user_id ? `#${span.user_id}` : '-')

const metaTitle = (span) =>
  `${span.user_name || `#${span.user_id}`} · ${assetName(span)} · ${span.account || '-'} · ${span.protocol}`

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

// 測試與上層需要知道聚合結果（列數上界是規格條文，不是視覺偏好）
defineExpose({ groups, shownGroups, restCount })
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

.span-row.is-overview,
.span-row.is-asset,
.span-row.is-rest {
  cursor: pointer;
}

.span-row.is-overview {
  border-bottom: 1px solid var(--ot-border-subtle);
}

.span-row:focus-visible {
  outline: 2px solid var(--ot-primary-hover);
}

.span-meta {
  flex: none;
  padding-right: var(--ot-space-sm);
  overflow: hidden;
  white-space: nowrap;
  text-overflow: ellipsis;
  font-size: var(--ot-font-size-xs);
}

.span-meta.is-indented {
  padding-left: var(--ot-space-md);
}

/* caret 是「這一列點得開」的唯一線索。總覽列改為預設收合後它更吃重：
   次要灰在整片灰字裡讀不出是可互動的，提到互動藍（與頁面其他可點元素
   同一語彙），hover 再提一階 */
.meta-caret {
  display: inline-block;
  width: 12px;
  color: var(--ot-primary);
  font-weight: 700;
}

.span-row:hover .meta-caret {
  color: var(--ot-primary-hover);
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

/* 聚合列的時段塊只做定位，點擊由整列承接（展開／收合） */
.span-bar.is-block {
  cursor: pointer;
  opacity: 0.7;
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
