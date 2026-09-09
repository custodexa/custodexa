<template>
  <!-- 抽屜是設定列唯一的第二層：白話一句、對各生效組的要求與結果、最後變更、
       什麼時候生效、摺疊的更多說明。順序即管理者的閱讀順序——先知道這個值決定
       什麼，再看誰要求什麼，最後才是機制 -->
  <el-drawer
    :model-value="modelValue"
    :title="title"
    size="420px"
    @update:model-value="$emit('update:modelValue', $event)"
  >
    <div
      v-if="policy"
      class="policy-drawer"
    >
      <p
        v-if="plainText"
        class="drawer-plain"
      >
        {{ plainText }}
      </p>

      <section class="drawer-section drawer-requirements">
        <div class="drawer-heading">
          <h4>{{ $t('policyDrawer.requirements') }}</h4>
          <el-tag
            v-if="draft"
            size="small"
            type="info"
            effect="plain"
          >
            {{ $t('policyDrawer.draftNote') }}
          </el-tag>
        </div>
        <div
          v-for="line in requirementLines"
          :key="line.groupCode"
          class="requirement-line"
          :class="`requirement-line--${line.result}`"
          :data-test="`requirement-${line.groupCode}`"
        >
          <div class="requirement-head">
            <el-tag
              :type="line.tagType"
              size="small"
              effect="light"
              class="requirement-result"
              :data-test="`requirement-result-${line.groupCode}`"
            >
              {{ line.resultLabel }}
            </el-tag>
            <strong class="requirement-group">{{ line.group }}</strong>
            <span
              v-if="line.clauseNo"
              class="clause-no"
            >{{ $t('policyDrawer.clauseNo', { no: line.clauseNo }) }}</span>
          </div>
          <span class="requirement-text">
            <template
              v-for="(part, idx) in line.parts"
              :key="idx"
            >
              <strong
                v-if="part.kind === 'value'"
                :class="`requirement-value requirement-value--${line.result}`"
              >{{ part.text }}</strong>
              <template v-else>{{ part.text }}</template>
            </template>
          </span>
        </div>
        <p
          v-if="requirementLines.length === 0"
          class="requirement-empty"
        >
          {{ $t('policyDrawer.none') }}
        </p>
      </section>

      <section class="drawer-section drawer-last-change">
        <h4>{{ $t('policyDrawer.lastChange') }}</h4>
        <p>{{ lastChangeText }}</p>
        <router-link
          class="audit-link"
          :to="auditLink"
        >
          {{ $t('policyDrawer.auditLink') }}
        </router-link>
      </section>

      <section
        v-if="effectText"
        class="drawer-section drawer-effect"
      >
        <h4>{{ $t('policyDrawer.effect') }}</h4>
        <p>{{ effectText }}</p>
      </section>

      <el-collapse v-if="noteText">
        <el-collapse-item :title="$t('policyDrawer.more')">
          <p class="drawer-note">
            {{ noteText }}
          </p>
        </el-collapse-item>
      </el-collapse>
    </div>
  </el-drawer>
</template>

<script setup>
import { computed } from 'vue'
import { formatDateTime } from '@/utils/format'
import { expectationText, formatValue, policyLabel, policyNote } from '@/utils/policyFormat'
import { resultLabel, resultTagType } from '@/utils/policyClauseText'
import { t } from '@/i18n'
import { translated } from '@/utils/i18nDisplay'

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  policy: { type: Object, default: null },
  // 該鍵對各生效組的判定；未對照者（result=unmapped）不列
  verdicts: { type: Array, default: () => [] },
  // 政策組代號→顯示名；查不到時退回代號（判定結果只帶代號）
  groupNames: { type: Object, default: () => ({}) },
  // 判定是以尚未儲存的表單值算的
  draft: { type: Boolean, default: false },
})

defineEmits(['update:modelValue'])

const title = computed(() => (props.policy ? policyLabel(props.policy) : ''))

// 白話一句只給標籤不自明的鍵，且待使用者逐句過目後才入 locale；
// 沒有譯文就不顯示，不自己編一句
const plainText = computed(() => {
  if (!props.policy?.key) return ''
  const key = `policyPlain.${props.policy.key}`
  return translated(key, () => t(key)) || ''
})

const effectText = computed(() => {
  if (!props.policy?.key) return ''
  const key = `policyEffect.${props.policy.key}`
  return translated(key, () => t(key)) || ''
})

const noteText = computed(() => (props.policy ? policyNote(props.policy) : ''))

const groupName = (code) => props.groupNames[code] || code

const expectation = (verdict) =>
  expectationText(props.policy, verdict.comparator, verdict.expected)

// 五種結果各自的句型。未對照不列——「沒有人要求」不是一個要讀的答案。
// 句子切成段渲染：要求值、參考值、目前值粗體，句尾判定詞帶結果顏色，
// 讓稽核人員掃一眼就抓到「要多少、現在多少、過不過」三個字眼。
const MARK = '\u0000'
const mark = (kind) => `${MARK}${kind}${MARK}`

const sentenceSpec = (verdict) => {
  const current = formatValue(props.policy, verdict.current)
  const expected = formatValue(props.policy, verdict.expected)
  switch (verdict.result) {
    case 'compliant':
      return {
        key: 'policyDrawer.compliant',
        values: { expectation: expectation(verdict), current },
        verdictWord: t('policyDrawer.verdictCompliant'),
      }
    case 'deviating':
      return {
        key: 'policyDrawer.deviating',
        values: { expectation: expectation(verdict), current },
        verdictWord: t('policyDrawer.verdictDeviating'),
      }
    case 'needs_review':
      if (verdict.confirmed_by) {
        return {
          key: 'policyDrawer.needsReviewConfirmed',
          values: { expected, who: verdict.confirmed_by, time: formatDateTime(verdict.confirmed_at) },
        }
      }
      return { key: 'policyDrawer.needsReviewUnconfirmed', values: { expected } }
    case 'review':
      return {
        key: 'policyDrawer.auditReview',
        values: { current },
        verdictWord: t('policyDrawer.verdictAuditReview'),
      }
    default:
      return null
  }
}

const VALUE_SLOTS = ['expectation', 'expected', 'current']

// 把翻譯後的句子依佔位切段：值類佔位先換成標記，再照標記拆開
const sentenceParts = (spec) => {
  const placeholders = { ...spec.values }
  for (const slot of VALUE_SLOTS) {
    if (slot in placeholders) placeholders[slot] = mark(slot)
  }
  if (spec.verdictWord !== undefined) placeholders.verdict = mark('verdict')
  const raw = t(spec.key, placeholders)
  if (!raw) return []
  return raw.split(MARK).map((piece, i) => {
    if (i % 2 === 0) return { kind: 'text', text: piece }
    if (piece === 'verdict') return { kind: 'text', text: spec.verdictWord }
    return { kind: 'value', text: spec.values[piece] }
  }).filter((part) => part.text !== '')
}

const requirementLines = computed(() =>
  props.verdicts
    .filter((v) => v.result && v.result !== 'unmapped' && v.group_code)
    .map((v) => {
      const spec = sentenceSpec(v)
      const parts = spec ? sentenceParts(spec) : []
      return {
        groupCode: v.group_code,
        group: groupName(v.group_code),
        clauseNo: v.clause_no || '',
        result: v.result,
        resultLabel: resultLabel(v.result),
        tagType: resultTagType(v.result),
        parts,
        text: [groupName(v.group_code), ...parts.map((p) => p.text)].join(''),
      }
    })
    .filter((line) => line.text)
)

const lastChangeText = computed(() => {
  if (!props.policy?.updated_at) return t('policyDrawer.lastChangeNone')
  return t('policyDrawer.lastChangeBy', {
    time: formatDateTime(props.policy.updated_at),
    who: props.policy.updated_by || '-',
  })
})

// 記錄連結帶資源與鍵的篩選參數：稽核人員從設定名到變更記錄要在三步內
const auditLink = computed(() => ({
  path: '/audit-logs',
  query: {
    tab: 'logs',
    resource: 'security_policy',
    key: props.policy?.key || '',
  },
}))
</script>

<style scoped>
.policy-drawer {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-md);
  color: var(--ot-text-primary);
}

.drawer-plain {
  margin: 0;
  font-size: var(--ot-font-size-md);
}

.drawer-section {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
}

.drawer-section h4 {
  margin: 0;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.drawer-heading {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
}

.drawer-section p {
  margin: 0;
  line-height: 1.6;
}

.requirement-line {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
  padding: var(--ot-space-sm) var(--ot-space-sm);
  margin: 0 0 var(--ot-space-xs);
  border-left: 3px solid var(--ot-border-color);
  border-radius: var(--ot-radius-sm);
  background: var(--ot-fill-color-lighter, transparent);
}

.requirement-line--compliant {
  border-left-color: var(--el-color-success);
}

.requirement-line--deviating {
  border-left-color: var(--el-color-danger);
}

.requirement-line--needs_review,
.requirement-line--review {
  border-left-color: var(--el-color-warning);
}

.requirement-head {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
}

.requirement-result {
  flex-shrink: 0;
}

.requirement-group {
  font-weight: 600;
  color: var(--ot-text-primary);
  line-height: 1.4;
}

.requirement-value {
  font-weight: 600;
  color: var(--ot-text-primary);
}

.requirement-value--compliant {
  color: var(--el-color-success);
}

.requirement-value--deviating {
  color: var(--el-color-danger);
}

.requirement-value--review,
.requirement-value--needs_review {
  color: var(--el-color-warning);
}

.requirement-text {
  display: block;
  color: var(--ot-text-regular, var(--ot-text-primary));
}

.clause-no {
  flex-shrink: 0;
  margin-left: auto;
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
  white-space: nowrap;
}

.requirement-empty,
.drawer-note {
  color: var(--ot-text-secondary);
}

.audit-link {
  font-size: var(--ot-font-size-sm);
  color: var(--el-color-primary);
  text-decoration: none;
}
</style>
