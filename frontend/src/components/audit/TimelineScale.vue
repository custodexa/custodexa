<template>
  <div
    class="timeline-scale"
    data-test="timeline-scale"
  >
    <div
      class="scale-gutter"
      :style="{ width: `${gutter}px` }"
    >
      <slot name="gutter" />
    </div>
    <div class="scale-track">
      <div
        v-for="tick in ticks"
        :key="tick.ts"
        class="scale-tick"
        :style="{ left: `${tick.percent}%` }"
      >
        <span class="tick-label">{{ label(tick) }}</span>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { buildTicks, formatTickLabel } from './timelineGeometry'

// 共用刻度尺：跨度條與事件軸都以同一組 from/to 定位，兩區才對得起來。
// 刻度本身不引入任何圖表相依，純 CSS 絕對定位
const props = defineProps({
  from: { type: [String, Number, Date], required: true },
  to: { type: [String, Number, Date], required: true },
  gutter: { type: Number, default: 200 },
  target: { type: Number, default: 8 },
})

const ticks = computed(() => buildTicks(props.from, props.to, props.target))
const label = (tick) => formatTickLabel(tick.ts, tick.step)
</script>

<style scoped>
.timeline-scale {
  display: flex;
  align-items: flex-end;
  height: 28px;
  border-bottom: 1px solid var(--ot-border-subtle);
}

.scale-gutter {
  flex: none;
  padding-right: var(--ot-space-sm);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  overflow: hidden;
  white-space: nowrap;
}

.scale-track {
  position: relative;
  flex: 1;
  height: 100%;
}

.scale-tick {
  position: absolute;
  bottom: 0;
  height: 100%;
  border-left: 1px solid var(--ot-border-subtle);
}

.tick-label {
  position: absolute;
  bottom: 2px;
  left: 3px;
  white-space: nowrap;
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
  font-variant-numeric: tabular-nums;
}
</style>
