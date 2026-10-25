<template>
  <div
    class="group-roles-tab"
    data-test="group-roles-tab"
  >
    <section class="block">
      <h3>{{ $t('userGroups.detail.roles.title', { n: selected.length }) }}</h3>
      <p class="hint">
        {{ $t('userGroups.detail.roles.help') }}
      </p>
      <el-select
        v-model="pick"
        class="role-pick"
        :placeholder="$t('users.assignRoles')"
        :teleported="false"
        data-test="role-pick"
        @change="addPicked"
      >
        <el-option
          v-for="opt in roleOptions"
          :key="opt.id"
          :value="opt.id"
          :label="roleLabel(opt.name)"
          :disabled="opt.disabled"
          :data-test="`role-option-${opt.name}`"
        >
          <span>{{ roleLabel(opt.name) }}</span>
          <span
            v-if="opt.reason"
            class="option-note"
          >{{ opt.reason }}</span>
        </el-option>
      </el-select>
      <ul class="role-cards">
        <li
          v-for="id in selected"
          :key="id"
          class="role-card"
          :class="{ 'is-openable': isAssignable(id), 'is-active': activeRole === id }"
          :data-test="`group-role-${nameOf(id)}`"
          :tabindex="isAssignable(id) ? 0 : undefined"
          @click="openPanel(id)"
          @keydown.enter.space.self.prevent="openPanel(id)"
        >
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
          <el-button
            v-else
            type="danger"
            size="small"
            link
            :data-test="`remove-${nameOf(id)}`"
            @click.stop="removeRole(id)"
          >
            {{ $t('users.remove') }}
          </el-button>
          <template v-if="canAssign && optionsReady">
            <el-tag
              v-if="isAssignable(id)"
              size="small"
              effect="plain"
              :data-test="`tag-assignable-${nameOf(id)}`"
            >
              {{ $t('roleNodePicker.tagAssignable') }}
            </el-tag>
            <el-tag
              v-else
              size="small"
              effect="plain"
              type="info"
              :data-test="`tag-no-range-${nameOf(id)}`"
            >
              {{ $t('roleNodePicker.tagNoRange') }}
            </el-tag>
            <span
              v-if="draftOf(id).mode === 'all'"
              class="option-note"
              :data-test="`range-all-${nameOf(id)}`"
            >{{ $t('roleNodePicker.modeAll') }}</span>
            <div
              v-else
              class="range-paths"
              :data-test="`range-paths-${nameOf(id)}`"
            >
              <span
                v-for="nid in validIdsOf(id)"
                :key="nid"
                class="option-note"
              >
                {{ nodePath(nid) }}
                <template v-if="nodeById(nid)">{{ $t('roleNodePicker.cardCount', { n: nodeById(nid).subtree_asset_count ?? 0 }) }}</template>
              </span>
            </div>
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
          </template>
        </li>
      </ul>
      <section
        v-if="activeRole != null && isAssignable(activeRole)"
        class="range-panel"
        data-test="range-panel"
      >
        <h4>{{ $t('roleNodePicker.panelTitleGroup', { role: roleLabel(nameOf(activeRole)) }) }}</h4>
        <RoleNodePicker
          :model-value="draftOf(activeRole)"
          :nodes="options.nodes"
          :counts="countsOf(activeRole)"
          :counts-unavailable="preview.status.value === 'unavailable'"
          :load-failed="optionsFailed"
          variant="group"
          @update:model-value="(v) => setDraft(activeRole, v)"
        />
      </section>
      <div class="actions">
        <el-button
          type="primary"
          :disabled="!dirty"
          :loading="saving"
          data-test="roles-save"
          @click="save"
        >
          {{ $t('common.save') }}
        </el-button>
      </div>
    </section>

    <section
      v-if="dirty"
      class="block"
      data-test="impact-panel"
    >
      <h3>{{ $t('userGroups.detail.impact.title') }}</h3>
      <p
        v-if="preview.status.value === 'unavailable'"
        class="hint"
        data-test="impact-unavailable"
      >
        {{ $t('userDetail.change.unavailable') }}
      </p>
      <template v-else-if="preview.result.value">
        <div
          class="row"
          data-test="impact-members"
        >
          {{ $t('userGroups.detail.impact.members', { n: preview.result.value.total ?? 0 }) }}
        </div>
        <div
          class="row"
          data-test="impact-routes"
        >
          <span class="label">{{ $t('userGroups.detail.impact.routesGained') }}</span>
          <span>{{ routeText(preview.result.value.operation?.routes_gained) }}</span>
        </div>
        <div
          v-if="comboMembers > 0"
          class="row"
          data-test="impact-combo"
        >
          {{ $t('userGroups.detail.impact.comboNote', { n: comboMembers }) }}
        </div>
      </template>
      <template v-if="canAssign && groupAssets">
        <div
          class="row"
          data-test="impact-group-assets"
        >
          <span class="label">{{ $t('roleNodePicker.changeManagedAssets') }}</span>
          <span>{{ $t('roleNodePicker.changeAssetsValue', { after: groupAssets.after, before: groupAssets.before }) }}</span>
        </div>
        <p
          class="hint"
          data-test="impact-group-assets-note"
        >
          {{ $t('roleNodePicker.changeGroupAssetsNote') }}
        </p>
      </template>
      <div class="row">
        <span class="label">{{ $t('userDetail.change.connection') }}</span>
        <span data-test="impact-connection">{{ $t('userDetail.change.connectionFixed') }}</span>
      </div>
      <p class="hint">
        {{ $t('userDetail.change.effectiveNow') }}
      </p>
    </section>

    <DangerComboConfirm
      v-model="confirmOpen"
      :preview="confirmPreview"
      :unavailable="confirmUnavailable"
      :notify-message="notifyMessage"
      @confirm="confirmSave"
      @back="confirmOpen = false"
    />
  </div>
</template>

<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { t } from '@/i18n'
import { replaceUserGroupRoleBindings } from '@/api/userGroups'
import { getRoleAssignmentOptions } from '@/api/roleDefinitions'
import { useAssignmentPreview } from '@/composables/useAssignmentPreview'
import { needsDangerConfirm } from '@/utils/dangerCombo'
import { roleLabel, roleTagType } from '@/constants/roles'
import { apiErrorSummary } from '@/api/redact'
import { MENU_GROUPS } from '@/components/sidebarMenu'
import DangerComboConfirm from '@/components/DangerComboConfirm.vue'
import RoleNodePicker from '@/components/RoleNodePicker.vue'
import { can } from '@/composables/useCapabilities'
import { managementRoleNames } from '../groupProtection'

/**
 * 群組詳情的「角色與範圍」分頁：群組角色卡、受保護角色鎖定、依原因停用的下拉、
 * 儲存後的變化與儲存前確認。能指派角色者可為能限定節點的角色選節點範圍，
 * 送出的 role_ids 含仍保留的受保護角色，role_nodes 只為本次改動了範圍的角色而帶。
 * 伺服器是最終裁決：停用與預覽只供呈現。
 */
const props = defineProps({
  group: { type: Object, required: true },
  bindings: { type: Array, default: () => [] },
  definitions: { type: Array, default: () => [] },
})
const emit = defineEmits(['changed'])

const idsFromBindings = () => props.bindings.map((b) => b.role_id)
const initial = ref(idsFromBindings())
const selected = ref(idsFromBindings())
const pick = ref(null)
const saving = ref(false)
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
const openPanel = (id) => {
  if (isAssignable(id)) activeRole.value = id
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
    return { id: d.id, name: d.name, disabled, reason }
  })
)

const rolesDirty = computed(() => {
  const a = [...selected.value].sort((x, y) => x - y)
  const b = [...initial.value].sort((x, y) => x - y)
  return a.length !== b.length || a.some((v, i) => v !== b[i])
})
const dirty = computed(() => rolesDirty.value || changedRanges.value.length > 0)
const addPicked = (id) => {
  if (id != null && !selected.value.includes(id)) selected.value = [...selected.value, id]
  pick.value = null
}
const removeRole = (id) => {
  if (stateOf(id) === 'protected') return
  selected.value = selected.value.filter((v) => v !== id)
  if (activeRole.value === id) activeRole.value = null
}

// —— 預覽（建議性）——
const preview = useAssignmentPreview()
const previewBody = () => {
  const body = {
    kind: 'group_roles',
    group_id: props.group.id,
    role_ids: [...selected.value],
  }
  if (canAssign.value) {
    body.include_managed_asset_counts = true
    const rn = {}
    for (const id of changedRanges.value) rn[String(id)] = rangeValue(id)
    if (Object.keys(rn).length) body.role_nodes = rn
  }
  return body
}
const hasNodeRange = computed(() => selected.value.some((id) => draftOf(id).mode === 'nodes'))
watch([selected, ranges, () => props.bindings, canAssign], () => {
  if (dirty.value || (canAssign.value && hasNodeRange.value)) preview.schedule(previewBody())
  else preview.cancel()
}, { deep: true })

const countsOf = (id) => {
  const r = (preview.result.value?.role_assets || []).find((x) => x.role_id === id)
  return r ? { total: r.total } : null
}
const groupAssets = computed(() => preview.result.value?.group_assets || null)

const ROUTE_TITLES = (() => {
  const map = new Map()
  for (const g of MENU_GROUPS) for (const item of g.items || []) map.set(item.path, item.titleKey)
  return map
})()
const routeName = (path) => (ROUTE_TITLES.has(path) ? t(ROUTE_TITLES.get(path)) : path)
const routeText = (list) =>
  Array.isArray(list) && list.length ? list.map(routeName).join('、') : t('userGroups.detail.impact.none')
const comboMembers = computed(
  () => (preview.result.value?.subjects || []).filter((s) => (s?.new_combos || []).length > 0).length
)

// —— 儲存前確認 ——
const confirmOpen = ref(false)
const confirmPreview = ref(null)
const confirmUnavailable = ref(false)
const notifyMessage = computed(() => {
  const p = confirmPreview.value
  if (!p) return ''
  const op = p.operation || {}
  if (['increase', 'decrease'].includes(op.self_direction) || (p.subjects || []).some((s) => s.self)) {
    return t('dangerConfirm.notify.selfChange')
  }
  if ((op.marks || []).includes('management_grant')) {
    const added = selected.value.filter((id) => !initial.value.includes(id))
    const roles = managementRoleNames(added, props.definitions).map(roleLabel).join('、')
    return (p.total ?? 0) === 0
      ? t('dangerConfirm.notify.groupEmpty', { group: props.group.name, role: roles })
      : t('dangerConfirm.notify.groupRoles', { role: roles })
  }
  return ''
})

const persist = async () => {
  saving.value = true
  try {
    const roleNodes = {}
    for (const id of changedRanges.value) roleNodes[String(id)] = rangeValue(id)
    await replaceUserGroupRoleBindings(props.group.id, [...selected.value], roleNodes)
    ElMessage.success(t('users.rolesAssigned'))
    preview.cancel()
    emit('changed')
  } catch (error) {
    console.error(...apiErrorSummary('user_group_roles_failed', error))
  } finally {
    saving.value = false
  }
}

const save = async () => {
  if (!dirty.value || saving.value) return
  saving.value = true
  let outcome
  try {
    outcome = await preview.run(previewBody())
  } finally {
    saving.value = false
  }
  if (!outcome.ok) {
    confirmPreview.value = null
    confirmUnavailable.value = true
    confirmOpen.value = true
    return
  }
  if (needsDangerConfirm(outcome.data)) {
    confirmPreview.value = outcome.data
    confirmUnavailable.value = false
    confirmOpen.value = true
    return
  }
  await persist()
}
const confirmSave = async () => {
  confirmOpen.value = false
  await persist()
}

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

defineExpose({ roleOptions, addPicked })
</script>

<style scoped>
.group-roles-tab {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-lg);
}
.block {
  padding: var(--ot-space-md);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}
.block h3 {
  margin: 0 0 var(--ot-space-xs);
  font-size: var(--ot-font-size-md);
  color: var(--ot-text-primary);
}
.hint {
  margin: var(--ot-space-xs) 0;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}
.role-pick {
  width: 280px;
}
.option-note {
  margin-left: var(--ot-space-sm);
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}
.role-cards {
  list-style: none;
  padding: 0;
  margin: var(--ot-space-sm) 0;
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
}
.role-card {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  flex-wrap: wrap;
}
.role-card.is-openable {
  cursor: pointer;
}
.role-card.is-active {
  background: var(--ot-bg-hover);
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
.actions {
  display: flex;
  justify-content: flex-end;
}
.row {
  display: flex;
  gap: var(--ot-space-md);
  margin: var(--ot-space-xs) 0;
}
.label {
  min-width: 96px;
  color: var(--ot-text-secondary);
}
</style>
