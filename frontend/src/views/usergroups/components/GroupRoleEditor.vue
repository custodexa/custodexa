<template>
  <div
    ref="rootEl"
    class="group-role-editor"
    data-test="group-role-editor"
  >
    <el-select
      v-model="pick"
      class="role-pick"
      :placeholder="pickOpen ? $t('roleNodePicker.filterPlaceholder') : $t('users.assignRoles')"
      filterable
      :filter-method="(q) => (pickQuery = q)"
      data-test="role-pick"
      @visible-change="onPickVisible"
      @change="addPicked"
    >
      <template
        v-for="grp in optionGroups"
        :key="grp.key"
      >
        <el-option-group
          v-if="grp.items.length"
          :label="grp.label"
        >
          <el-option
            v-for="opt in grp.items"
            :key="opt.id"
            :value="opt.id"
            :label="roleLabel(opt.name)"
            :disabled="opt.disabled"
            :data-test="`role-option-${opt.name}`"
          >
            <span class="option-line">
              <span>{{ roleLabel(opt.name) }}</span>
              <span
                v-if="opt.reason"
                class="option-note"
              >{{ opt.reason }}</span>
              <el-tag
                v-if="opt.scopable"
                class="option-scopable"
                size="small"
                effect="plain"
                :data-test="`option-scopable-${opt.name}`"
              >{{ $t('roleNodePicker.tagScopable') }}</el-tag>
            </span>
          </el-option>
        </el-option-group>
      </template>
    </el-select>
    <table
      v-if="selected.length"
      class="role-table"
      data-test="role-table"
    >
      <thead>
        <tr>
          <th>{{ $t('roleNodePicker.roleColumn') }}</th>
          <th>{{ $t('roleNodePicker.scopeColumn') }}</th>
          <th class="col-actions">
            {{ $t('common.actions') }}
          </th>
        </tr>
      </thead>
      <tbody
        v-for="id in selected"
        :key="id"
      >
        <tr
          class="role-row"
          :class="{ 'is-active': activeRole === id }"
          :data-test="`group-role-${nameOf(id)}`"
        >
          <td class="col-role">
            <el-tag
              :type="roleTagType(nameOf(id))"
              size="small"
            >
              {{ roleLabel(nameOf(id)) }}
            </el-tag>
            <el-tag
              v-if="!initial.includes(id)"
              size="small"
              type="success"
              effect="plain"
            >
              {{ $t('userDetail.roles.newlyAdded') }}
            </el-tag>
            <template v-if="stateOf(id) === 'protected'">
              <el-tag
                size="small"
                type="warning"
                data-test="protected-badge"
              >
                {{ $t('userGroups.detail.roles.protectedBadge') }}
              </el-tag>
              <span
                class="option-note"
                data-test="protected-note"
              >{{ $t('userGroups.detail.roles.protectedCannotRemove') }}</span>
            </template>
          </td>
          <td class="col-scope">
            <template v-if="canAssign && optionsReady">
              <template v-if="draftOf(id).mode === 'all'">
                <template v-if="classOf(id) === 'builtin_global_only'">
                  <strong
                    class="not-applicable"
                    :data-test="`scope-not-applicable-${nameOf(id)}`"
                  >{{ $t('roles.list.scopeNotApplicable') }}</strong>
                  <span class="option-note">{{ $t('roleNodePicker.notApplicableNote') }}</span>
                </template>
                <template v-else>
                  <span
                    :data-test="`range-all-${nameOf(id)}`"
                  >{{ $t('roleNodePicker.modeAll') }}</span>
                  <span
                    v-if="classOf(id) === 'effective'"
                    class="option-note"
                    :data-test="`scope-all-note-${nameOf(id)}`"
                  >{{ $t('roleNodePicker.scopeAllNote') }}</span>
                  <span
                    v-else-if="classOf(id) === 'not_scopable'"
                    class="option-note"
                    :data-test="`tag-no-range-${nameOf(id)}`"
                  >{{ $t('roleNodePicker.globalOnlyRowNote') }}</span>
                  <span
                    v-else-if="classOf(id) === 'no_scoped_permission'"
                    class="option-note"
                    :data-test="`range-no-effect-${nameOf(id)}`"
                  >{{ $t('roleNodePicker.rangeNoEffectNote') }}</span>
                </template>
              </template>
              <div
                v-else
                class="range-paths"
                :data-test="`range-paths-${nameOf(id)}`"
              >
                <span
                  v-for="nid in validIdsOf(id)"
                  :key="nid"
                  class="path-line"
                >
                  {{ nodePath(nid) }}
                  <template v-if="nodeById(nid)">{{ $t('roleNodePicker.cardCount', { n: nodeById(nid).subtree_asset_count ?? 0 }) }}</template>
                </span>
                <span
                  v-if="totalOf(id) != null && validIdsOf(id).length > 1"
                  class="option-note"
                  :data-test="`range-total-${nameOf(id)}`"
                >{{ $t('roleNodePicker.footerGroup', { nodes: validIdsOf(id).length, total: totalOf(id) }) }}</span>
              </div>
              <el-tag
                v-if="rangeChanged(id)"
                size="small"
                type="warning"
                effect="plain"
                :data-test="`unsaved-${nameOf(id)}`"
              >
                {{ $t('roleNodePicker.unsaved') }}
              </el-tag>
              <template v-if="missingCountOf(id) > 0">
                <el-tag
                  size="small"
                  type="warning"
                  effect="plain"
                  :data-test="`missing-tag-${nameOf(id)}`"
                >
                  {{ $t('roleNodePicker.nodeMissing') }}
                </el-tag>
                <span
                  class="option-note"
                  :data-test="`missing-note-${nameOf(id)}`"
                >{{ $t('roleNodePicker.nodeMissingNote', { n: missingCountOf(id) }) }}</span>
                <el-button
                  size="small"
                  link
                  :data-test="`remove-missing-${nameOf(id)}`"
                  @click.stop="removeMissing(id)"
                >
                  {{ $t('roleNodePicker.removeMissing') }}
                </el-button>
              </template>
              <span
                v-if="draftOf(id).mode === 'nodes' && draftOf(id).nodeIds.length === 0"
                class="range-error"
                :data-test="`nodes-empty-${nameOf(id)}`"
              >{{ $t('apiError.VALIDATION_ROLE_BINDING_NODES_EMPTY') }}</span>
              <span
                v-if="cardNoEffectKey(id)"
                class="option-note"
                :data-test="`card-no-effect-${nameOf(id)}`"
              >{{ $t(cardNoEffectKey(id)) }}</span>
              <template v-if="isRejected(id) && draftOf(id).mode === 'nodes'">
                <span
                  class="option-note"
                  :data-test="`global-only-note-${nameOf(id)}`"
                >{{ $t('roleNodePicker.globalOnlyNote') }}</span>
                <el-button
                  size="small"
                  link
                  :data-test="`set-all-${nameOf(id)}`"
                  @click.stop="setDraft(id, { mode: 'all', nodeIds: [] })"
                >
                  {{ $t('roleNodePicker.modeAll') }}
                </el-button>
              </template>
              <div
                v-if="moreOpen === id"
                class="more-panel"
                :data-test="`more-panel-${nameOf(id)}`"
              >
                <p class="more-note">
                  {{ $t(classOf(id) === 'builtin_global_only' ? 'roleNodePicker.builtinGlobalOnlyNote' : 'roleNodePicker.rangeNoEffectNote') }}
                </p>
                <el-button
                  size="small"
                  :data-test="`still-limit-${nameOf(id)}`"
                  @click.stop="stillLimit(id)"
                >
                  {{ $t('roleNodePicker.stillLimitNodes') }}
                </el-button>
              </div>
            </template>
            <template v-else>
              <span :data-test="`range-simple-${nameOf(id)}`">{{ simpleScopeText(id) }}</span>
            </template>
          </td>
          <td class="col-actions">
            <el-button
              v-if="canSetRange(id)"
              size="small"
              :data-test="`set-range-${nameOf(id)}`"
              :aria-expanded="activeRole === id"
              @click="togglePanel(id)"
            >
              {{ activeRole === id ? $t('roleNodePicker.collapseRange') : $t('roleNodePicker.setRange') }}
            </el-button>
            <el-button
              v-if="canMore(id)"
              size="small"
              :aria-label="$t('roleNodePicker.moreActions')"
              :data-test="`more-${nameOf(id)}`"
              @click="moreOpen = moreOpen === id ? null : id"
            >
              …
            </el-button>
            <el-button
              v-if="stateOf(id) !== 'protected'"
              type="danger"
              size="small"
              link
              :data-test="`remove-${nameOf(id)}`"
              @click.stop="removeRole(id)"
            >
              {{ $t('users.remove') }}
            </el-button>
          </td>
        </tr>
        <tr
          v-if="activeRole === id && isAssignable(id)"
          class="panel-row"
        >
          <td colspan="3">
            <section
              class="range-panel"
              tabindex="-1"
              data-test="range-panel"
            >
              <h4>{{ $t('roleNodePicker.panelTitleGroup', { role: roleLabel(nameOf(id)) }) }}</h4>
              <RoleNodePicker
                :model-value="draftOf(id)"
                :nodes="options.nodes"
                :counts="countsOf(id)"
                :counts-unavailable="countsUnavailable"
                :load-failed="optionsFailed"
                variant="group"
                @update:model-value="(v) => setDraft(id, v)"
              />
            </section>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script setup>
import { computed, nextTick, onMounted, ref, watch } from 'vue'
import { t } from '@/i18n'
import { getRoleAssignmentOptions } from '@/api/roleDefinitions'
import { roleLabel, roleTagType } from '@/constants/roles'
import { apiErrorSummary } from '@/api/redact'
import RoleNodePicker from '@/components/RoleNodePicker.vue'
import { can } from '@/composables/useCapabilities'
import { classifyRole, isNoEffectClass, SCOPE_CLASS, filterByQuery, splitBuiltinCustom } from '@/utils/roleScopePresentation'

/**
 * 角色與管理範圍編輯器：角色選單、角色列（角色／管理範圍／操作）與範圍設定面板，
 * 以及它們的草稿狀態。不呼叫任何預覽或寫入 API：預覽、確認與儲存由呼叫端負責。
 * bindings 為現有指派（群組頁）；沒有群組可讀時傳空陣列，全部角色視為新加入。
 * 輸出草稿 { roleIds, roleNodes }，roleNodes 只含本次改了範圍的角色（鍵為角色編號字串，
 * 值為節點陣列，null 表示改回全系統）。伺服器是最終裁決：停用與分類只供呈現。
 */
const props = defineProps({
  definitions: { type: Array, default: () => [] },
  bindings: { type: Array, default: () => [] },
  // 初始就選好的角色（不在 bindings 內者視為新加入），可由操作者移除
  preselectIds: { type: Array, default: () => [] },
  // 預覽回傳的各角色涵蓋台數（[{ role_id, total }]）；沒有預覽時為 null
  roleAssets: { type: Array, default: null },
  countsUnavailable: { type: Boolean, default: false },
})
const emit = defineEmits(['update:draft'])

const idsFromBindings = () => props.bindings.map((b) => b.role_id)
const initialSelection = () => {
  const ids = idsFromBindings()
  for (const id of props.preselectIds) if (!ids.includes(id)) ids.push(id)
  return ids
}
const initial = ref(idsFromBindings())
const selected = ref(initialSelection())
const pick = ref(null)
const pickOpen = ref(false)
const pickQuery = ref('')
const onPickVisible = (v) => {
  pickOpen.value = v
  if (!v) pickQuery.value = ''
}
watch(
  () => props.bindings,
  () => {
    initial.value = idsFromBindings()
    selected.value = idsFromBindings()
    ranges.value = {}
  }
)

const defOf = (id) => props.definitions.find((d) => d.id === id)
const nameOf = (id) => defOf(id)?.name || props.bindings.find((b) => b.role_id === id)?.role_name || String(id)
const stateOf = (id) => defOf(id)?.assignment_state || 'open'

// —— 節點範圍：選項、讀回的指派與草稿（鍵為角色編號）——
const canAssign = computed(() => can('role:assign'))
const options = ref({ nodes: [], assignable: new Set(), reasons: {} })
const optionsReady = ref(false)
const optionsFailed = ref(false)
const ranges = ref({})
const activeRole = ref(null)
const ALL = { mode: 'all', nodeIds: [] }
// 群組讀取以 scope 為準判讀節點範圍；節點範圍列即使 node_ids 缺省也不讀成全系統
const origOf = (id) => {
  const b = props.bindings.find((x) => x.role_id === id)
  if (!b) return null
  return b.scope === 'nodes' ? { mode: 'nodes', nodeIds: [...(b.node_ids || [])] } : { mode: 'all', nodeIds: [] }
}
const draftOf = (id) => ranges.value[id] || origOf(id) || ALL
const sameRange = (a, b) => {
  if (a.mode !== b.mode) return false
  if (a.mode === 'all') return true
  const x = [...a.nodeIds].sort((m, n) => m - n)
  const y = [...b.nodeIds].sort((m, n) => m - n)
  return x.length === y.length && x.every((v, i) => v === y[i])
}
const rangeChanged = (id) => !sameRange(draftOf(id), origOf(id) || ALL)
const changedRanges = computed(() => selected.value.filter((id) => canAssign.value && rangeChanged(id)))
const isAssignable = (id) => canAssign.value && options.value.assignable.has(id)
const canCompare = computed(() => canAssign.value && optionsReady.value && !optionsFailed.value)
const isRejected = (id) => canCompare.value && !isAssignable(id)
const isMissingId = (id) => canCompare.value && !options.value.nodes.some((n) => n.id === id)
const nodeById = (id) => options.value.nodes.find((n) => n.id === id)
const nodePath = (id) => nodeById(id)?.path || nodeById(id)?.name || ''
const validIdsOf = (id) => draftOf(id).nodeIds.filter((n) => !isMissingId(n))
const missingCountOf = (id) => (draftOf(id).mode === 'nodes' ? draftOf(id).nodeIds.filter(isMissingId).length : 0)
const setDraft = (id, v) => {
  ranges.value = { ...ranges.value, [id]: { mode: v.mode, nodeIds: [...v.nodeIds] } }
}
// 只改本次編輯的草稿；剩 0 個時仍是指定節點，不改成全系統
const removeMissing = (id) => setDraft(id, { mode: 'nodes', nodeIds: validIdsOf(id) })
const togglePanel = (id) => {
  if (!isAssignable(id)) return
  activeRole.value = activeRole.value === id ? null : id
}
// 角色的範圍分類只取伺服器欄位；能指派角色者另帶不會生效的原因
const classOf = (id) => classifyRole(defOf(id), options.value.reasons[String(id)])
// 會生效的角色（或分類未知時沿用舊行為）有「設定範圍」；已是節點範圍的存量指派也可就地調整
const canSetRange = (id) =>
  canAssign.value &&
  optionsReady.value &&
  isAssignable(id) &&
  (classOf(id) === SCOPE_CLASS.EFFECTIVE || classOf(id) === SCOPE_CLASS.UNKNOWN || draftOf(id).mode === 'nodes')
// 範圍不會生效的角色以全系統持有時，「仍要限定節點」收進「更多」
const canMore = (id) =>
  canAssign.value &&
  optionsReady.value &&
  isAssignable(id) &&
  isNoEffectClass(classOf(id)) &&
  draftOf(id).mode === 'all'
const moreOpen = ref(null)
const rootEl = ref(null)
const stillLimit = async (id) => {
  moreOpen.value = null
  activeRole.value = id
  // 觸發的按鈕隨「更多」面板移除，焦點移到展開的範圍面板
  await nextTick()
  rootEl.value?.querySelector('.range-panel')?.focus({ preventScroll: true })
}
const totalOf = (id) => countsOf(id)?.total ?? null
// 不能指派角色者或選項尚未載入：只呈現讀回的範圍（全系統或節點數），不讀指派選項
const simpleScopeText = (id) => {
  const o = origOf(id)
  return o && o.mode === 'nodes'
    ? t('roleNodePicker.nodeCountOnly', { n: o.nodeIds.length })
    : t('roleNodePicker.modeAll')
}
// 範圍不會生效的提示放在卡片層，面板內不重複
const cardNoEffectKey = (id) => {
  if (!isAssignable(id) || draftOf(id).mode !== 'nodes') return ''
  const reason = options.value.reasons[String(id)]
  if (!reason) return ''
  return reason === 'builtin_global_only' ? 'roleNodePicker.builtinGlobalOnlyNote' : 'roleNodePicker.rangeNoEffectNote'
}
const rangeValue = (id) => {
  const d = draftOf(id)
  return d.mode === 'all' ? null : [...d.nodeIds]
}

const roleOptions = computed(() =>
  props.definitions.map((d) => {
    let reason = ''
    let disabled = false
    if (d.assignment_state === 'protected') {
      disabled = true
      reason = t('roles.assignState.protected')
    } else if (d.assignment_state === 'not_open') {
      disabled = true
      reason = t('roles.assignState.notOpen')
    } else if (d.group_bindable === false) {
      disabled = true
      reason = t('roles.assignState.notGroupBindable')
    } else if (selected.value.includes(d.id)) {
      disabled = true
      reason = t('userDetail.roles.alreadyAdded')
    }
    const scopable =
      canAssign.value && classifyRole(d, options.value.reasons[String(d.id)]) === SCOPE_CLASS.EFFECTIVE
    return { id: d.id, name: d.name, builtin_key: d.builtin_key, disabled, reason, scopable }
  })
)
// 分配角色選單：內建／自訂兩組，組內保留伺服器順序
const optionGroups = computed(() => {
  const { builtin, custom } = splitBuiltinCustom(
    filterByQuery(roleOptions.value, pickQuery.value, (o) => roleLabel(o.name))
  )
  return [
    { key: 'builtin', label: t('roles.list.builtinTitle', { n: builtin.length }), items: builtin },
    { key: 'custom', label: t('roles.list.customTitle', { n: custom.length }), items: custom },
  ]
})

const addPicked = (id) => {
  if (id != null && !selected.value.includes(id)) selected.value = [...selected.value, id]
  pick.value = null
}
const removeRole = (id) => {
  if (stateOf(id) === 'protected') return
  selected.value = selected.value.filter((v) => v !== id)
  if (activeRole.value === id) activeRole.value = null
  if (moreOpen.value === id) moreOpen.value = null
}

const countsOf = (id) => {
  const r = (props.roleAssets || []).find((x) => x.role_id === id)
  return r ? { total: r.total } : null
}
// 以全系統持有可限範圍角色：預覽台數不計全域指派，直接寫「全部資產」，以範圍判定、不看角色名稱
const holdsAllScope = computed(() =>
  selected.value.some((id) => classOf(id) === SCOPE_CLASS.EFFECTIVE && draftOf(id).mode === 'all')
)

const draft = computed(() => {
  const roleNodes = {}
  for (const id of changedRanges.value) roleNodes[String(id)] = rangeValue(id)
  return { roleIds: [...selected.value], roleNodes }
})
watch(draft, (v) => emit('update:draft', v), { flush: 'sync', immediate: true })

// 節點清單只對能指派角色者讀取；其他人不呼叫
let optionsRequested = false
const loadOptions = async () => {
  if (optionsRequested || !canAssign.value) return
  optionsRequested = true
  try {
    const res = await getRoleAssignmentOptions()
    options.value = {
      nodes: res?.nodes || [],
      assignable: new Set(res?.node_assignable_role_ids || []),
      reasons: res?.node_range_no_effect_reasons || {},
    }
    optionsFailed.value = false
  } catch (error) {
    optionsFailed.value = true
    console.error(...apiErrorSummary('role_assignment_options_failed', error))
  } finally {
    optionsReady.value = true
  }
}
watch(canAssign, loadOptions)
onMounted(loadOptions)

defineExpose({ roleOptions, addPicked, draft, holdsAllScope, classOf, draftOf, nodePath })
</script>

<style scoped>
.option-note {
  margin-left: var(--ot-space-sm);
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}
.role-pick {
  width: 280px;
}
.role-table {
  width: 100%;
  border-collapse: collapse;
  margin: var(--ot-space-sm) 0;
}
.role-table th {
  text-align: left;
  font-weight: normal;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
  padding: var(--ot-space-xs) var(--ot-space-sm);
  border-bottom: 1px solid var(--ot-border-subtle);
}
.role-table td {
  padding: var(--ot-space-sm);
  vertical-align: top;
  border-bottom: 1px solid var(--ot-border-subtle);
}
.col-role {
  white-space: nowrap;
}
.col-role > * + * {
  margin-left: var(--ot-space-xs);
}
.col-actions {
  text-align: right;
  white-space: nowrap;
}
.role-row.is-active {
  background: var(--ot-bg-hover);
}
.path-line {
  font-size: var(--ot-font-size-sm);
}
.more-panel {
  margin-top: var(--ot-space-xs);
  padding: var(--ot-space-xs) var(--ot-space-sm);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}
.more-note {
  margin: 0 0 var(--ot-space-xs);
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}
.option-line {
  display: flex;
  align-items: center;
  width: 100%;
}
.option-scopable {
  margin-left: auto;
}
.range-paths {
  display: flex;
  flex-direction: column;
}
.range-error {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-danger);
}
.range-panel {
  margin: var(--ot-space-sm) 0;
  padding: var(--ot-space-sm);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}
.range-panel h4 {
  margin: 0 0 var(--ot-space-xs);
  font-size: var(--ot-font-size-sm);
}
/* 窄畫面（含抽屜滿版）：角色欄與操作欄改為可換行，避免表格撐出水平捲動；寬畫面版面不變 */
@media (max-width: 480px) {
  .col-role,
  .col-actions {
    white-space: normal;
  }
  .col-actions .el-button {
    margin: 0 0 var(--ot-space-xs) var(--ot-space-xs);
  }
  .role-table td,
  .path-line {
    overflow-wrap: anywhere;
  }
}
</style>
