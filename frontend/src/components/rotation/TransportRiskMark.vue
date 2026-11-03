<template>
  <!-- 說明開在下方並限寬換行：開在上方會蓋住同一列的結果標籤，單行則會橫跨整個對話框 -->
  <el-tooltip
    v-if="risk"
    placement="bottom"
    popper-class="transport-risk-mark-popper"
    :content="tooltipText"
  >
    <span
      class="transport-risk-mark"
      :class="{ 'transport-risk-mark--unknown': !known }"
      tabindex="0"
      role="note"
      :aria-label="tooltipText"
      data-test="transport-risk-mark"
    >
      <LockOpen
        v-if="known"
        :size="12"
        aria-hidden="true"
      />
      <span class="transport-risk-mark__text">{{ label }}</span>
    </span>
  </el-tooltip>
</template>

<script setup>
// 改密紀錄的傳輸風險標示：取紀錄本身的 transport_risk（執行當下的判定），
// 不看資產現況。空值不渲染；認得的值顯示短標籤與完整說明；不認得的非空值原樣顯示，不吞成空白。
import { computed } from 'vue'
import { LockOpen } from 'lucide-vue-next'
import { useI18n } from 'vue-i18n'
import { riskLabel } from '@/utils/transportDisplay'
import { DB_ROTATION_RISK_KEY } from '@/constants/rotationChannel'

const props = defineProps({
  risk: { type: String, default: '' },
})

const { t } = useI18n()

const known = computed(() => props.risk === DB_ROTATION_RISK_KEY)
const label = computed(() => (known.value ? t('changeSecretPlans.transportRisk.tag') : props.risk))
const tooltipText = computed(() => {
  const full = riskLabel({ key: props.risk })
  return known.value ? t('changeSecretPlans.transportRisk.tooltip', { risk: full }) : full
})
</script>

<style scoped>
.transport-risk-mark {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 0 6px;
  max-width: 100%;
  line-height: 18px;
  padding-top: 1px;
  padding-bottom: 1px;
  font-size: 12px;
  color: var(--ot-warning);
  border: 1px solid var(--ot-warning);
  border-radius: 4px;
  background: color-mix(in srgb, var(--ot-warning) 12%, transparent);
  cursor: default;
}

/* 窄欄（如英日文）放不下時標籤文字可換行，不被欄寬切掉；圖示不縮 */
.transport-risk-mark :deep(svg) {
  flex: none;
}

.transport-risk-mark__text {
  min-width: 0;
  overflow-wrap: anywhere;
}

.transport-risk-mark:focus-visible {
  outline: 2px solid var(--ot-primary);
  outline-offset: 1px;
}

.transport-risk-mark--unknown {
  color: var(--ot-text-secondary);
  border-color: var(--ot-border);
}
</style>

<style>
/* tooltip 掛在 body 下，scoped 樣式管不到，另以 popper-class 限寬 */
.transport-risk-mark-popper.el-popper {
  max-width: 320px;
  white-space: normal;
  line-height: 1.6;
}
</style>
