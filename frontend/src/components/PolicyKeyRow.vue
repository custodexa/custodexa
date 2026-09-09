<template>
  <!-- 設定列的第一層：標籤、控制項、單位、資訊鈕，沒有別的。
       規範條號、要求值、偏離原因與機制解說一律只在抽屜裡——第一層每多一句話，
       管理者就要多讀一次才知道自己在設什麼 -->
  <div
    class="policy-row"
    :class="{ 'policy-row-text': policy.type === 'text' }"
  >
    <div class="policy-label">
      <!-- 偏離標示不只靠顏色：點是視覺，title 與 aria-label 是文字，
           灰階列印與螢幕報讀各有一條路讀到同一件事 -->
      <span
        v-if="deviating"
        class="policy-deviation-dot"
        :title="$t('policyKeySections.deviationMark')"
        :aria-label="$t('policyKeySections.deviationMark')"
        :data-test="`policy-deviation-${policy.key}`"
      />
      <span class="policy-label-text">{{ label }}</span>
    </div>

    <div class="policy-control">
      <el-input-number
        v-if="policy.type === 'int'"
        :model-value="value"
        :min="policyMin(policy)"
        :max="policy.max || 99999"
        :step="1"
        step-strictly
        :aria-label="label"
        @update:model-value="$emit('update:value', policy.key, $event)"
      />
      <el-switch
        v-else-if="policy.type === 'bool'"
        :model-value="value"
        :aria-label="label"
        @update:model-value="$emit('update:value', policy.key, $event)"
      />
      <el-radio-group
        v-else-if="policy.type === 'enum'"
        :model-value="value"
        @update:model-value="$emit('update:value', policy.key, $event)"
      >
        <el-radio-button
          v-for="option in policy.enum_order"
          :key="option"
          :value="option"
        >
          {{ enumLabel(policy, option) }}
        </el-radio-button>
      </el-radio-group>
      <!-- 文字型：多行鍵給可長高的輸入框，單行鍵給一般輸入框。
           刻意不綁原生 maxlength——它以 UTF-16 單位計，補充平面字元每個算兩格，
           會在後端仍接受的長度就把使用者的輸入截掉。字數改以下方計數呈現 -->
      <div
        v-else-if="policy.type === 'text'"
        class="policy-text"
      >
        <el-input
          v-if="policy.multiline"
          type="textarea"
          :autosize="{ minRows: 5, maxRows: 12 }"
          :model-value="value"
          :aria-label="label"
          @update:model-value="$emit('update:value', policy.key, $event)"
        />
        <el-input
          v-else
          :model-value="value"
          :aria-label="label"
          @update:model-value="$emit('update:value', policy.key, $event)"
        />
        <!-- 超出上限只變色不擋輸入：擋輸入等於在使用者貼上長文時靜默丟字，
             長度的權威判定在後端，這裡只把「會被退回」先講出來 -->
        <span
          class="policy-counter"
          :class="{ 'policy-counter-over': textLength(value) > policy.max_length }"
        >{{ $t('bannerText.counter', {
          count: textLength(value),
          max: policy.max_length,
        }) }}</span>
      </div>
      <span
        v-if="unit"
        class="policy-unit"
      >{{ unit }}</span>
    </div>

    <div class="policy-actions">
      <el-button
        link
        :aria-label="`${$t('policyDrawer.info')}：${label}`"
        :data-test="`policy-info-${policy.key}`"
        @click="$emit('info')"
      >
        <el-icon><Info /></el-icon>
      </el-button>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { Info } from 'lucide-vue-next'
import { enumLabel, policyLabel, policyMin, policyUnit } from '@/utils/policyFormat'

const props = defineProps({
  policy: { type: Object, required: true },
  // 編輯中的值（int→number、bool→boolean、其餘 string）；寫入權在父層
  value: { type: [String, Number, Boolean], default: '' },
  // 對任一生效政策組偏離（同一鍵偏離多組只算一次，父層已收斂）
  deviating: { type: Boolean, default: false },
})

defineEmits(['update:value', 'info'])

const label = computed(() => policyLabel(props.policy))
const unit = computed(() => policyUnit(props.policy))

// 字數以 Unicode code point 計，與後端上限同一口徑；
// String.length 是 UTF-16 單位，補充平面字元會被算成兩個
const textLength = (value) => Array.from(value || '').length
</script>

<style scoped>
.policy-row {
  display: grid;
  grid-template-columns: 260px minmax(220px, 1fr) 40px;
  align-items: center;
  gap: var(--ot-space-md);
  padding: var(--ot-space-sm) 0;
}

/* 文字型鍵的輸入框吃掉整條剩餘寬度——2000 字的內文擠在數值欄寬裡是讀不動的 */
.policy-row-text {
  align-items: start;
}

.policy-label {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
  color: var(--ot-text-primary);
}

.policy-deviation-dot {
  flex: none;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background-color: var(--el-color-warning);
}

.policy-control {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
}

.policy-text {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
  width: 100%;
}

.policy-counter {
  align-self: flex-end;
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}

.policy-counter-over {
  color: var(--ot-danger);
}

.policy-unit {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.policy-actions {
  display: flex;
  justify-content: flex-end;
  color: var(--ot-text-secondary);
}

@media (max-width: 900px) {
  .policy-row {
    grid-template-columns: 1fr 40px;
    align-items: start;
  }
}
</style>
