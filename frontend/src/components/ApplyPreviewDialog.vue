<template>
  <!-- 套用預覽：只列會變動的鍵。已經符合的、不屬於任何政策組的都只給一個數字——
       把它們逐列畫出來，真正要看的那幾行就淹掉了。
       確認只填表單，儲存仍走既有流程與審計 -->
  <el-dialog
    :model-value="modelValue"
    :title="$t('applyPreview.title', { page: pageTitle })"
    width="720px"
    data-test="apply-preview-dialog"
    @update:model-value="$emit('update:modelValue', $event)"
  >
    <div
      v-if="preview"
      class="apply-preview"
    >
      <p class="preview-scope">
        {{ $t('applyPreview.scopeNote', { page: pageTitle }) }}
        {{ basisText }}
      </p>

      <table
        v-if="changes.length > 0"
        class="preview-table"
      >
        <thead>
          <tr>
            <th>{{ $t('applyPreview.colName') }}</th>
            <th>{{ $t('applyPreview.colCurrent') }}</th>
            <th>{{ $t('applyPreview.colProposed') }}</th>
            <th>{{ $t('applyPreview.colSource') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="change in changes"
            :key="change.key"
            :data-test="`preview-change-${change.key}`"
          >
            <td>
              {{ labelOf(change.key) }}
              <!-- 這一項改下去，管理員自己也可能連不進來。警語就近放在該列，
                   不放在對話框底部——底部那一段管理者已經在按「填入表單」了 -->
              <span
                v-if="warnsLockout(change)"
                class="change-warning"
                :data-test="`preview-warning-${change.key}`"
              >{{ $t('applyPreview.mfaAllWarning') }}</span>
            </td>
            <td>{{ valueOf(change.key, change.current) }}</td>
            <td>{{ valueOf(change.key, change.proposed) }}</td>
            <td>{{ groupName(change.source_group) }}</td>
          </tr>
        </tbody>
      </table>
      <!-- 零變動不等於已符合：牴觸的規則是「不能自動改」而不是「都對了」，
           兩者寫成同一句話會讓管理者以為這一頁沒事 -->
      <p
        v-else
        class="preview-empty"
      >
        {{ conflicts.length > 0
          ? $t('applyPreview.emptyConflicts')
          : $t('applyPreview.empty') }}
      </p>

      <section
        v-if="conflicts.length > 0"
        class="preview-conflicts"
      >
        <h4>{{ $t('applyPreview.conflictTitle') }}</h4>
        <p
          v-for="conflict in conflicts"
          :key="conflict.key"
          :data-test="`preview-conflict-${conflict.key}`"
        >
          {{ conflictText(conflict) }}
        </p>
      </section>

      <div class="preview-counts">
        <span data-test="preview-compliant">{{ $t('applyPreview.compliant', { n: compliantCount }) }}</span>
        <span
          v-if="pendingCount > 0"
          data-test="preview-pending"
        >{{ $t('applyPreview.pending', { n: pendingCount }) }}</span>
        <span data-test="preview-unmapped">{{ $t('applyPreview.unmapped', { n: preview.unmapped_count || 0 }) }}</span>
      </div>

      <p class="preview-note">
        {{ $t('applyPreview.notSaved') }}
      </p>
    </div>

    <template #footer>
      <el-button @click="$emit('update:modelValue', false)">
        {{ $t('common.cancel') }}
      </el-button>
      <el-button
        type="primary"
        :disabled="changes.length === 0"
        @click="confirm"
      >
        {{ $t('applyPreview.confirm') }}
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { computed } from 'vue'
import { expectationText, formatValue, policyLabel } from '@/utils/policyFormat'
import { currentLocale, t } from '@/i18n'

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  // 後端算好的預覽：{ mode, group_code, changes, conflicts, unchanged_count, unmapped_count }
  preview: { type: Object, default: null },
  // 本頁的政策項，供顯示名與值的格式化
  policies: { type: Array, default: () => [] },
  // 介面明示套用範圍限本頁
  pageTitle: { type: String, required: true },
  groupNames: { type: Object, default: () => ({}) },
  // 鍵→該鍵對各生效組的判定（後端算的那一份）。底部的「已符合」由它投影，
  // 不用預覽的「不變動數」代替——不變動的裡面混著待稽核判讀與參考值，
  // 那兩種都還沒有人說它符合
  verdictsByKey: { type: Object, default: () => ({}) },
})

const emit = defineEmits(['update:modelValue', 'confirm'])

const byKey = computed(() =>
  Object.fromEntries(props.policies.map((policy) => [policy.key, policy]))
)

const changes = computed(() => props.preview?.changes || [])
const conflicts = computed(() => props.preview?.conflicts || [])

// 一個鍵對多組可能有多份判定；一份偏離就不算符合，一份待判讀就還沒有結論。
// 取最嚴的一個，與條文層的收斂方式一致
const KEY_RESULT_SEVERITY = ['deviating', 'needs_review', 'review', 'compliant']

const keyResult = (key) => {
  const verdicts = (props.verdictsByKey[key] || []).filter(
    (v) => v.result && v.result !== 'unmapped'
  )
  return KEY_RESULT_SEVERITY.find((r) => verdicts.some((v) => v.result === r)) || ''
}

const countByResult = (results) =>
  props.policies.filter((policy) => results.includes(keyResult(policy.key))).length

// 確實符合的鍵數：本頁鍵裡，每一組都說符合的那些
const compliantCount = computed(() => countByResult(['compliant']))

// 待稽核判讀與待人工確認另計：它們既不是符合也不是偏離，併進哪一邊都是誤報
const pendingCount = computed(() => countByResult(['review', 'needs_review']))

const groupName = (code) => props.groupNames[code] || code

const labelOf = (key) => policyLabel(byKey.value[key]) || key

// 把多因子驗證放寬到所有人是唯一會把管理者自己鎖在門外的建議值：套用前尚未綁定
// 的管理員下次登入就進不來。其餘高影響鍵在儲存那一步各有確認，不在此擴張
const warnsLockout = (change) =>
  change.key === 'mfa_required' && change.proposed === 'all'

const valueOf = (key, raw) => {
  const policy = byKey.value[key]
  return policy ? formatValue(policy, raw) : raw
}

const basisText = computed(() => {
  if (props.preview?.mode === 'group') {
    return t('applyPreview.basisGroup', { group: groupName(props.preview.group_code) })
  }
  return t('applyPreview.basisStrictest')
})

// 衝突以人話寫出兩條規則各自的來源與要求；系統不替管理者選一邊
const conflictText = (conflict) => {
  const policy = byKey.value[conflict.key]
  const reasons = (conflict.reasons || []).map((reason) =>
    t('applyPreview.conflictReason', {
      group: groupName(reason.group),
      expectation: expectationText(policy, reason.comparator, reason.expected),
    })
  )
  const joined = new Intl.ListFormat(currentLocale(), {
    style: 'long',
    type: 'conjunction',
  }).format(reasons)
  return t('applyPreview.conflictBody', { name: labelOf(conflict.key), reasons: joined })
}

const confirm = () => {
  emit('confirm', changes.value)
  emit('update:modelValue', false)
}
</script>

<style scoped>
.apply-preview {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-md);
  color: var(--ot-text-primary);
}

.preview-scope,
.preview-empty,
.preview-note {
  margin: 0;
  color: var(--ot-text-secondary);
}

.preview-table {
  width: 100%;
  border-collapse: collapse;
  font-size: var(--ot-font-size-sm);
}

.preview-table th,
.preview-table td {
  padding: var(--ot-space-xs) var(--ot-space-sm);
  text-align: left;
  border-bottom: 1px solid var(--ot-border-subtle);
}

.preview-table th {
  color: var(--ot-text-secondary);
  font-weight: 500;
}

.preview-conflicts {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
  padding: var(--ot-space-sm);
  background-color: var(--ot-bg-elevated);
  border-radius: var(--ot-radius-md);
}

.preview-conflicts h4 {
  margin: 0;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.preview-conflicts p {
  margin: 0;
  line-height: 1.6;
}

.change-warning {
  display: block;
  margin-top: var(--ot-space-xs);
  color: var(--el-color-warning);
  line-height: 1.6;
}

.preview-counts {
  display: flex;
  gap: var(--ot-space-md);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}
</style>
