<template>
  <div
    class="role-node-picker"
    data-test="role-node-picker"
  >
    <el-radio-group
      :model-value="mode"
      class="rnp-mode"
      data-test="rnp-mode"
      @change="setMode"
    >
      <el-radio-button
        value="all"
        data-test="rnp-mode-all"
      >
        {{ $t('roleNodePicker.modeAll') }}
      </el-radio-button>
      <el-radio-button
        value="nodes"
        data-test="rnp-mode-nodes"
      >
        {{ $t('roleNodePicker.modeNodes') }}
      </el-radio-button>
    </el-radio-group>

    <template v-if="mode === 'nodes'">
      <p
        v-if="noEffectNoteKey"
        class="rnp-note"
        data-test="rnp-no-effect-note"
      >
        {{ $t(noEffectNoteKey) }}
      </p>
      <p class="rnp-hint">
        {{ $t('roleNodePicker.panelHint') }}
      </p>

      <el-alert
        v-if="loadFailed"
        type="warning"
        :closable="false"
        show-icon
        :title="$t('roleNodePicker.treeLoadFailed')"
        data-test="rnp-tree-load-failed"
      />
      <template v-else>
        <el-input
          v-model="query"
          clearable
          size="small"
          class="rnp-search"
          :placeholder="$t('roleNodePicker.searchPlaceholder')"
          data-test="rnp-search"
        />
        <p
          v-if="rows.length === 0"
          class="rnp-empty"
          data-test="rnp-search-empty"
        >
          {{ $t('roleNodePicker.searchEmpty') }}
        </p>
        <ul
          v-else
          class="rnp-tree"
          data-test="rnp-tree"
        >
          <li
            v-for="row in rows"
            :key="row.node.id"
            class="rnp-row"
            :class="`is-${row.state}`"
            :style="{ paddingLeft: `${row.level * 18}px` }"
            :data-test="`rnp-row-${row.node.id}`"
            :data-state="row.state"
          >
            <button
              v-if="row.hasChildren"
              type="button"
              class="rnp-toggle"
              :aria-label="row.expanded ? 'collapse' : 'expand'"
              :data-test="`rnp-toggle-${row.node.id}`"
              @click="toggleExpand(row.node.id)"
            >
              {{ row.expanded ? '▾' : '▸' }}
            </button>
            <span
              v-else
              class="rnp-toggle-gap"
            />
            <el-checkbox
              :model-value="row.state === 'checked' || row.state === 'covered'"
              :indeterminate="row.state === 'partial'"
              :disabled="row.state === 'covered'"
              :data-test="`rnp-check-${row.node.id}`"
              @change="(v) => onToggle(row.node, v)"
            >
              <span class="rnp-name">{{ row.node.name }}</span>
            </el-checkbox>
            <el-tag
              v-if="row.fromGroup"
              size="small"
              effect="plain"
              type="info"
              :data-test="`rnp-from-group-${row.node.id}`"
            >
              {{ $t('roleNodePicker.fromGroup') }}
            </el-tag>
            <span
              v-if="row.state === 'covered' || row.state === 'checked'"
              class="rnp-includes"
              :data-test="`rnp-includes-${row.node.id}`"
            >{{ $t('roleNodePicker.includesChildren') }}</span>
            <span
              class="rnp-count"
              :data-test="`rnp-count-${row.node.id}`"
            >{{ $t('roleNodePicker.assetCount', { n: row.node.subtree_asset_count ?? 0 }) }}</span>
          </li>
        </ul>
      </template>

      <p
        class="rnp-footer"
        data-test="rnp-footer"
      >
        <template v-if="countsUnavailable">
          {{ $t('roleNodePicker.countsUnavailable') }}
        </template>
        <template v-else-if="counts">
          {{ footerText }}
        </template>
      </p>
    </template>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'
import { t } from '@/i18n'

// 角色的節點範圍選擇器（使用者與群組兩個分頁共用）。
// 純 props／events 驅動：不呼叫 API，也不接收角色名稱或權限清單；
// 能不能限定節點、是否提示範圍不會生效，都由呼叫端依伺服器清單決定後以 props 傳入。
const props = defineProps({
  // 草稿：mode 為 'all'（全系統）或 'nodes'（指定節點）；nodeIds 只保留最上層的勾選
  modelValue: {
    type: Object,
    default: () => ({ mode: 'all', nodeIds: [] }),
  },
  // 未刪除節點的扁平清單：{ id, name, parent_id, subtree_asset_count }
  nodes: { type: Array, default: () => [] },
  // 同一角色經使用者群組取得的節點 ID（標「來自群組」，仍可勾為管理者指派）
  groupNodeIds: { type: Array, default: () => [] },
  // 預覽回傳的台數：{ direct, from_groups_extra, total }（群組模式只用 total）；不在此加總
  counts: { type: Object, default: null },
  countsUnavailable: { type: Boolean, default: false },
  // 'user' 或 'group'，決定底部合計句型
  variant: { type: String, default: 'user' },
  // 節點清單讀取失敗
  loadFailed: { type: Boolean, default: false },
  // 範圍不會生效的原因（伺服器給的值）；空字串表示會生效
  noEffectReason: { type: String, default: '' },
})
const emit = defineEmits(['update:modelValue'])

const query = ref('')
const collapsed = ref(new Set())

const mode = computed(() => (props.modelValue?.mode === 'nodes' ? 'nodes' : 'all'))
const draftIds = computed(() => props.modelValue?.nodeIds || [])

const byId = computed(() => new Map(props.nodes.map((n) => [n.id, n])))

// 父節點不在清單內的節點視為根層
const parentOf = (n) => (n.parent_id != null && byId.value.has(n.parent_id) ? n.parent_id : null)

const childrenOf = computed(() => {
  const map = new Map()
  for (const n of props.nodes) {
    const p = parentOf(n)
    if (p == null) continue
    if (!map.has(p)) map.set(p, [])
    map.get(p).push(n.id)
  }
  return map
})

const roots = computed(() => props.nodes.filter((n) => parentOf(n) == null).map((n) => n.id))

function descendantsOf(id) {
  const out = []
  const stack = [...(childrenOf.value.get(id) || [])]
  while (stack.length) {
    const cur = stack.pop()
    out.push(cur)
    stack.push(...(childrenOf.value.get(cur) || []))
  }
  return out
}

function ancestorsOf(id) {
  const out = []
  let cur = byId.value.get(id)
  const seen = new Set()
  while (cur && !seen.has(cur.id)) {
    seen.add(cur.id)
    const p = parentOf(cur)
    if (p == null) break
    out.push(p)
    cur = byId.value.get(p)
  }
  return out
}

const draftSet = computed(() => new Set(draftIds.value))
const groupSet = computed(() => new Set(props.groupNodeIds))

// 節點狀態：checked＝本身被勾、covered＝祖先被勾（已涵蓋，不可另勾）、
// partial＝後代有勾選（半選）、none
const stateMap = computed(() => {
  const map = new Map()
  const covered = new Set()
  for (const id of draftSet.value) {
    for (const d of descendantsOf(id)) covered.add(d)
  }
  const partial = new Set()
  for (const id of draftSet.value) {
    for (const a of ancestorsOf(id)) partial.add(a)
  }
  for (const n of props.nodes) {
    let state = 'none'
    if (draftSet.value.has(n.id)) state = 'checked'
    else if (covered.has(n.id)) state = 'covered'
    else if (partial.has(n.id)) state = 'partial'
    map.set(n.id, state)
  }
  return map
})

// 搜尋：命中的節點連同祖先鏈顯示
const visibleSet = computed(() => {
  const q = query.value.trim().toLowerCase()
  if (!q) return null
  const keep = new Set()
  for (const n of props.nodes) {
    if (String(n.name).toLowerCase().includes(q)) {
      keep.add(n.id)
      for (const a of ancestorsOf(n.id)) keep.add(a)
    }
  }
  return keep
})

const rows = computed(() => {
  const out = []
  const visible = visibleSet.value
  const walk = (id, level) => {
    if (visible && !visible.has(id)) return
    const node = byId.value.get(id)
    const kids = childrenOf.value.get(id) || []
    const shownKids = visible ? kids.filter((k) => visible.has(k)) : kids
    // 搜尋時一律展開，才看得到深層命中
    const expanded = visible ? true : !collapsed.value.has(id)
    out.push({
      node,
      level,
      state: stateMap.value.get(id) || 'none',
      fromGroup: groupSet.value.has(id),
      hasChildren: shownKids.length > 0,
      expanded,
    })
    if (expanded) for (const k of kids) walk(k, level + 1)
  }
  for (const r of roots.value) walk(r, 0)
  return out
})

const noEffectNoteKey = computed(() => {
  if (!props.noEffectReason) return ''
  return props.noEffectReason === 'builtin_global_only'
    ? 'roleNodePicker.builtinGlobalOnlyNote'
    : 'roleNodePicker.rangeNoEffectNote'
})

const footerText = computed(() => {
  const c = props.counts || {}
  const nodes = draftIds.value.length
  if (props.variant === 'group') {
    return t('roleNodePicker.footerGroup', { nodes, total: c.total ?? 0 })
  }
  if (!c.from_groups_extra) {
    return t('roleNodePicker.footerUserNoGroup', { nodes, total: c.total ?? 0 })
  }
  return t('roleNodePicker.footerUser', {
    nodes,
    direct: c.direct ?? 0,
    extra: c.from_groups_extra,
    total: c.total ?? 0,
  })
})

function update(next) {
  emit('update:modelValue', { mode: next.mode, nodeIds: [...next.nodeIds] })
}

function setMode(next) {
  update({ mode: next, nodeIds: draftIds.value })
}

function toggleExpand(id) {
  const next = new Set(collapsed.value)
  if (next.has(id)) next.delete(id)
  else next.add(id)
  collapsed.value = next
}

// 勾選時只保留最上層：移除草稿中已落在該節點子樹內的勾選
function onToggle(node, checked) {
  if (stateMap.value.get(node.id) === 'covered') return
  let ids
  if (checked) {
    const below = new Set(descendantsOf(node.id))
    ids = draftIds.value.filter((id) => !below.has(id) && id !== node.id)
    ids.push(node.id)
  } else {
    ids = draftIds.value.filter((id) => id !== node.id)
  }
  update({ mode: 'nodes', nodeIds: ids })
}
</script>

<style scoped>
.role-node-picker {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm, 8px);
}

.rnp-note {
  margin: 0;
  font-size: 12px;
  color: var(--ot-warning, #e6a23c);
}

.rnp-hint,
.rnp-empty {
  margin: 0;
  font-size: 12px;
  color: var(--ot-text-secondary, #93a4bd);
}

.rnp-tree {
  margin: 0;
  padding: 0;
  list-style: none;
  max-height: 320px;
  overflow: auto;
}

.rnp-row {
  display: flex;
  align-items: center;
  gap: 6px;
  min-height: 30px;
}

.rnp-row.is-covered .rnp-name {
  color: var(--ot-text-secondary, #93a4bd);
}

.rnp-toggle {
  width: 16px;
  padding: 0;
  border: 0;
  background: none;
  color: var(--ot-text-secondary, #93a4bd);
  cursor: pointer;
}

.rnp-toggle-gap {
  display: inline-block;
  width: 16px;
}

.rnp-includes,
.rnp-count {
  font-size: 12px;
  color: var(--ot-text-secondary, #93a4bd);
}

.rnp-count {
  margin-left: auto;
}

.rnp-footer {
  margin: 0;
  font-size: 13px;
}
</style>
