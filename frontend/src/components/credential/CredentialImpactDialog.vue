<!--
  CredentialImpactDialog：共用憑證修改前的範圍外影響確認。

  台數與清單全部取自伺服器：總台數＝範圍內台數＋範圍外台數；清單只列範圍內資產，
  範圍外只給台數並說明「由其他管理者負責，這裡不列出」。勾選知情後才能送出。
  確認只證明操作者知情，不是授權：伺服器每次提交仍自行重驗。
-->
<template>
  <el-dialog
    :model-value="modelValue"
    :title="t('credentials.impact.title')"
    width="620px"
    :close-on-click-modal="false"
    append-to-body
    data-test="impact-dialog"
    @update:model-value="onVisible"
  >
    <div class="subject">
      <span
        class="name"
        data-test="impact-name"
      >{{ credentialName }}</span>
      <el-tag
        size="small"
        type="primary"
      >
        {{ t('enum.credentialScope.shared') }}
      </el-tag>
      <span
        v-if="username"
        class="account"
      >{{ t('credentials.impact.account') }} <span class="mono">{{ username }}</span></span>
    </div>
    <p class="lead">
      <span class="op">{{ operationLabel }}</span>
    </p>
    <p
      class="lead"
      data-test="impact-lead"
    >
      {{ leadText }}
    </p>

    <div class="cells">
      <div
        class="cell"
        data-test="impact-in-cell"
      >
        <div class="cell-label">
          {{ t('credentials.impact.inScope') }}
        </div>
        <div class="cell-num">
          {{ t('credentials.impact.countUnit', { count: inScopeCount }) }}
        </div>
      </div>
      <div
        class="cell out"
        data-test="impact-out-cell"
      >
        <div class="cell-label">
          {{ t('credentials.impact.outScope') }}
        </div>
        <div class="cell-num">
          {{ t('credentials.impact.countUnit', { count: outOfScopeCount }) }}
        </div>
        <div class="cell-note">
          {{ t('credentials.impact.outNote') }}
        </div>
      </div>
    </div>

    <div class="list-title">
      {{ t('credentials.impact.listTitle', { count: inScopeCount }) }}
    </div>
    <el-table
      :data="assets"
      size="small"
      max-height="200"
      data-test="impact-assets"
    >
      <el-table-column
        :label="t('credentials.impact.colAsset')"
        min-width="200"
        show-overflow-tooltip
      >
        <template #default="{ row }">
          <span class="mono">{{ row.asset_name || t('common.assetRef', { id: row.asset_id }) }}</span>
        </template>
      </el-table-column>
      <el-table-column
        v-if="showNodes"
        :label="t('credentials.impact.colNode')"
        min-width="180"
        show-overflow-tooltip
      >
        <template #default="{ row }">
          {{ nodeText(row) }}
        </template>
      </el-table-column>
    </el-table>

    <el-checkbox
      v-model="acknowledged"
      class="ack"
      data-test="impact-ack"
    >
      {{ ackText }}
    </el-checkbox>
    <p
      class="detach-hint"
      data-test="impact-detach-hint"
    >
      {{ t('credentials.impact.detachHint') }}
    </p>

    <template #footer>
      <el-button
        data-test="impact-cancel"
        @click="emit('cancel')"
      >
        {{ t('common.cancel') }}
      </el-button>
      <el-button
        type="primary"
        :disabled="!acknowledged"
        :loading="loading"
        data-test="impact-submit"
        @click="emit('confirm')"
      >
        {{ submitLabel }}
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  // 'set_secret'｜'rotate'
  operation: { type: String, default: 'set_secret' },
  credentialName: { type: String, default: '' },
  username: { type: String, default: '' },
  // 範圍內清單（憑證詳情的掛載列）；範圍外不在其中
  assets: { type: Array, default: () => [] },
  inScopeCount: { type: Number, default: 0 },
  outOfScopeCount: { type: Number, default: 0 },
  // 每次（重）開遞增，清掉上一輪的勾選
  epoch: { type: Number, default: 0 },
  loading: { type: Boolean, default: false },
  // 更正時的物件名詞（密碼／私鑰）
  noun: { type: String, default: '' },
})

const emit = defineEmits(['update:modelValue', 'confirm', 'cancel'])

const { t } = useI18n()

const acknowledged = ref(false)
watch(() => [props.modelValue, props.epoch], () => { acknowledged.value = false })

const total = computed(() => props.inScopeCount + props.outOfScopeCount)
const isRotate = computed(() => props.operation === 'rotate')
const nounText = computed(() => props.noun || t('credentials.secretFix.noun.password'))
const operationLabel = computed(() => (isRotate.value
  ? t('credentials.impact.opRotate')
  : t('credentials.impact.opFix', { noun: nounText.value })))
const leadText = computed(() => (isRotate.value
  ? t('credentials.impact.leadRotate', { total: total.value })
  : t('credentials.impact.leadFix', { total: total.value, noun: nounText.value })))
const ackText = computed(() => (isRotate.value
  ? t('credentials.impact.ackRotate', { count: props.outOfScopeCount })
  : t('credentials.impact.ackFix', { count: props.outOfScopeCount, noun: nounText.value })))
const submitLabel = computed(() => (isRotate.value
  ? t('credentials.impact.submitRotate', { total: total.value })
  : t('credentials.impact.submitFix', { total: total.value })))

// 所屬節點由伺服器隨掛載列帶回（node_paths）；沒有就不畫這一欄，前端不自行推導
const showNodes = computed(() => props.assets.some((a) => Array.isArray(a.node_paths) && a.node_paths.length))
const nodeText = (row) => (Array.isArray(row.node_paths) ? row.node_paths.join('、') : '')

function onVisible(visible) {
  if (!visible) emit('cancel')
  else emit('update:modelValue', true)
}
</script>

<style scoped>
.subject {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  margin-bottom: var(--ot-space-sm);
}

.name {
  font-weight: 600;
}

.account {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.mono {
  font-family: var(--ot-font-mono);
}

.lead {
  margin: 0 0 var(--ot-space-sm);
}

.op {
  font-weight: 500;
}

.cells {
  display: flex;
  gap: var(--ot-space-md);
  margin: var(--ot-space-md) 0;
}

.cell {
  flex: 1;
  padding: var(--ot-space-md);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}

.cell.out {
  border-color: var(--ot-warning);
}

.cell-label,
.cell-note {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.cell-num {
  font-size: var(--ot-font-size-lg);
  font-weight: 600;
}

.list-title {
  margin-bottom: var(--ot-space-xs);
  font-weight: 500;
}

.ack {
  display: flex;
  margin-top: var(--ot-space-md);
  height: auto;
  white-space: normal;
}

.detach-hint {
  margin: var(--ot-space-xs) 0 0;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}
</style>
