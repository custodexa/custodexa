<!--
  CredentialOwnershipSelect：憑證管理歸屬欄（全域或節點）。

  節點選項來自平面節點列表的用途參數（credential_create、credential_update、
  credential_convert_scope），只消費伺服器標示：
    - 回應有 `selectable_all` 才是範圍化判定成立的主體；此時只有 `selectable=true` 的節點可選，
      其餘只作定位祖先、以停用列呈現；`selectable_all=false` 且沒有任何可選節點＝選項為空，
      無法送出（伺服器本來就會拒）。
    - 回應不附 `selectable_all`：沿現行全部節點可選。
  「全域」選項只在回應不是範圍化、或 `selectable_all=true`（可管理全域）時出現。
  前端不走節點樹計算範圍。
-->
<template>
  <div
    class="ownership-select"
    data-test="ownership-select"
  >
    <el-radio-group
      v-if="allowGlobal"
      :model-value="modelValue.kind"
      :disabled="disabled"
      data-test="ownership-kind"
      @update:model-value="onKind"
    >
      <el-radio value="global">
        {{ t('credentials.ownership.global') }}
        <span class="sub">{{ t('credentials.ownership.globalSub') }}</span>
      </el-radio>
      <el-radio value="node">
        {{ t('credentials.ownership.node') }}
      </el-radio>
    </el-radio-group>
    <el-select
      v-if="modelValue.kind === 'node'"
      :model-value="modelValue.node_id ?? undefined"
      :loading="loading"
      :disabled="disabled"
      :empty-values="[null, undefined]"
      :placeholder="t('credentials.ownership.nodePlaceholder')"
      filterable
      class="full"
      data-test="ownership-node"
      @update:model-value="onNode"
    >
      <el-option
        v-for="node in nodes"
        :key="node.id"
        :label="node.path || node.name"
        :value="node.id"
        :disabled="!node.selectable"
        :data-test="`ownership-node-option-${node.id}`"
      >
        {{ node.path || node.name }}
      </el-option>
      <template #empty>
        <div
          class="empty"
          data-test="ownership-node-empty"
        >
          {{ loadFailed ? t('credentials.ownership.loadFailed') : t('credentials.ownership.noSelectable') }}
        </div>
      </template>
    </el-select>
    <p
      v-if="modelValue.kind === 'node' && noSelectable && !loading"
      class="hint warn"
      data-test="ownership-none"
    >
      {{ t('credentials.ownership.noSelectable') }}
    </p>
    <!-- 編輯對話框：逐項說明兩種歸屬各由誰管理；呼叫端給了 hint（例如拒絕原因）時以 hint 為準 -->
    <template v-if="explain && !hint">
      <p
        v-if="allowGlobal"
        class="hint"
        data-test="ownership-explain-global"
      >
        {{ t('credentials.ownership.globalExplain') }}
      </p>
      <p
        class="hint"
        data-test="ownership-explain-node"
      >
        {{ t('credentials.ownership.nodeExplain') }}
      </p>
    </template>
    <p
      v-else
      class="hint"
      data-test="ownership-hint"
    >
      {{ hint || t('credentials.ownership.hint') }}
    </p>
  </div>
</template>

<script setup>
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { getAssetGroups } from '@/api/assets'

const props = defineProps({
  // { kind: 'global'|'node', node_id: number|null }
  modelValue: { type: Object, default: () => ({ kind: 'node', node_id: null }) },
  // 節點用途：credential_create | credential_update | credential_convert_scope
  purpose: { type: String, required: true },
  // 對話框開啟時才載入，關閉再開重新載入
  active: { type: Boolean, default: false },
  hint: { type: String, default: '' },
  // 為真時以「全域：…」「節點：…」兩句說明取代預設的一句提示（編輯對話框）
  explain: { type: Boolean, default: false },
  disabled: { type: Boolean, default: false },
})

const emit = defineEmits(['update:modelValue', 'state'])

const { t } = useI18n()

const nodes = ref([])
const selectableAll = ref(undefined)
const loading = ref(false)
const loadFailed = ref(false)
let seq = 0

const scoped = computed(() => typeof selectableAll.value === 'boolean')
const allowGlobal = computed(() => !scoped.value || selectableAll.value === true)
const noSelectable = computed(() => !loading.value && !nodes.value.some((n) => n.selectable))

function normalize(res) {
  selectableAll.value = typeof res?.selectable_all === 'boolean' ? res.selectable_all : undefined
  return (res?.data || []).map((g) => ({
    id: g.id,
    name: g.name,
    path: g.path,
    // 不帶 selectable 的回應（非範圍化）全部可選
    selectable: g.selectable === undefined ? true : g.selectable === true,
  }))
}

async function load() {
  const current = ++seq
  loading.value = true
  loadFailed.value = false
  try {
    const res = await getAssetGroups({ purpose: props.purpose })
    if (current !== seq) return
    nodes.value = normalize(res)
  } catch (err) {
    if (current !== seq) return
    nodes.value = []
    selectableAll.value = undefined
    loadFailed.value = true
    console.error('[CredentialOwnershipSelect] 載入節點失敗:', err?.response?.status)
  } finally {
    if (current === seq) loading.value = false
  }
}

watch(() => props.active, (open) => { if (open) load() }, { immediate: true })

// 呼叫端靠這個狀態決定能不能送出：節點模式下沒有選到可選節點、或根本沒有可選節點
watch(
  [() => props.modelValue, nodes, loading],
  () => {
    const m = props.modelValue
    // 範圍化主體沒有全域選項：模型停在全域時改回節點，免得送出一個伺服器必拒的值
    if (!loading.value && !allowGlobal.value && m.kind === 'global') {
      emit('update:modelValue', { kind: 'node', node_id: null })
      return
    }
    const picked = m.kind === 'global'
      || (m.kind === 'node' && nodes.value.some((n) => n.id === m.node_id && n.selectable))
    emit('state', { loading: loading.value, ready: !loading.value && picked, allowGlobal: allowGlobal.value, scoped: scoped.value })
  },
  { deep: true, immediate: true },
)

function onKind(kind) {
  emit('update:modelValue', { kind, node_id: kind === 'node' ? props.modelValue.node_id ?? null : null })
}

function onNode(id) {
  emit('update:modelValue', { kind: 'node', node_id: id ?? null })
}

defineExpose({ nodes, allowGlobal, scoped, load })
</script>

<style scoped>
.ownership-select {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm);
  width: 100%;
}

.full {
  width: 100%;
}

.sub {
  margin-left: var(--ot-space-xs);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.hint {
  margin: 0;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.hint.warn {
  color: var(--ot-warning);
}

.empty {
  padding: var(--ot-space-sm);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}
</style>
