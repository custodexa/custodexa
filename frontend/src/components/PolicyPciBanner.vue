<template>
  <!-- 頁首摘要條：本頁偏離摘要＋分域套用＋儲存列（settings-domain-restructure D5） -->
  <div
    v-loading="loading"
    class="summary-bar"
    role="status"
  >
    <div class="summary-status">
      <template v-if="deviationCount === 0">
        <el-icon class="summary-icon is-ok">
          <CircleCheck />
        </el-icon>
        <span>{{ okText || $t('pciBanner.okDefault') }}</span>
      </template>
      <template v-else>
        <el-icon class="summary-icon is-warn">
          <Warning />
        </el-icon>
        <span>{{ deviationText }}</span>
      </template>
      <el-tag
        v-if="isDirty"
        type="info"
        size="small"
        effect="plain"
      >
        {{ $t('pciBanner.unsaved') }}
      </el-tag>
      <!-- 電支基準的偏離摘要（security-backlog-settlement D6）：與 PCI 各自獨立，
           不合計——同一項可能符合其一而偏離另一，合計會使兩者都不可解讀。
           epaymentDeviationCount=null 時不渲染（未接該基準的頁面） -->
      <el-tag
        v-if="epaymentDeviationCount !== null"
        :type="epaymentDeviationCount === 0 ? 'success' : 'warning'"
        size="small"
        effect="plain"
      >
        {{
          epaymentDeviationCount === 0
            ? $t('pciBanner.epaymentOk')
            : $t('pciBanner.epaymentDeviation', { n: epaymentDeviationCount }, epaymentDeviationCount)
        }}
      </el-tag>
      <!-- 域頁回母頁總覽的雙向連結（與母頁分域列表對稱；overviewCount=null 不渲染） -->
      <router-link
        v-if="overviewCount !== null"
        class="overview-link"
        :to="overviewRoute"
      >
        {{ $t('pciBanner.overviewLink', { n: overviewCount }, overviewCount) }}
      </router-link>
    </div>
    <!-- 母頁分域偏離列表等擴充內容（overview 模式） -->
    <slot name="extra" />
    <div class="summary-actions">
      <el-button
        :disabled="loading || saving"
        @click="$emit('apply')"
      >
        {{ applyLabel || $t('pciBanner.applyPage') }}
      </el-button>
      <!-- 套用電支基準：填入的是兩基準取嚴值（後端 strictest_value），
           不是電支值本身——見 usePolicyForm.applyPageEPayment -->
      <el-button
        v-if="epaymentDeviationCount !== null"
        :disabled="loading || saving"
        @click="$emit('apply-epayment')"
      >
        {{ $t('pciBanner.applyEPayment') }}
      </el-button>
      <el-button
        :disabled="!isDirty || saving"
        @click="$emit('reset')"
      >
        {{ $t('pciBanner.revert') }}
      </el-button>
      <el-button
        type="primary"
        :disabled="!isDirty"
        :loading="saving"
        @click="$emit('save')"
      >
        {{ $t('common.save') }}
      </el-button>
    </div>
  </div>
</template>

<script setup>
import { CircleCheck, Warning } from '@element-plus/icons-vue'

defineProps({
  loading: { type: Boolean, default: false },
  saving: { type: Boolean, default: false },
  isDirty: { type: Boolean, default: false },
  deviationCount: { type: Number, default: 0 },
  // 空預設＝套用 locale 內建文案（pciBanner.okDefault / pciBanner.applyPage）；
  // 母頁需覆寫時傳入字串（如 SecurityPolicies 傳全系統版文案）
  okText: { type: String, default: '' },
  deviationText: { type: String, required: true },
  applyLabel: { type: String, default: '' },
  // 域頁傳全系統偏離數即渲染回母頁總覽連結；母頁不傳（null）
  overviewCount: { type: Number, default: null },
  overviewRoute: { type: String, default: '/security-policies' },
  // 電支基準偏離數；null＝該頁不呈現此基準（不渲染標籤與套用鈕）
  epaymentDeviationCount: { type: Number, default: null },
})

defineEmits(['apply', 'apply-epayment', 'reset', 'save'])
</script>

<style scoped>
.summary-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--ot-space-md);
  flex-wrap: wrap;
  padding: var(--ot-space-md);
  margin-bottom: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}

.summary-status {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  color: var(--ot-text-primary);
}

.summary-icon {
  font-size: 18px;
}

.summary-icon.is-ok {
  color: var(--el-color-success);
}

.summary-icon.is-warn {
  color: var(--el-color-warning);
}

.overview-link {
  font-size: var(--ot-font-size-sm);
  color: var(--el-color-primary);
  text-decoration: none;
}
</style>
