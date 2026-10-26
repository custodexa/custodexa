<template>
  <div
    class="group-roles-tab"
    data-test="group-roles-tab"
  >
    <div
      class="scope-banner"
      data-test="scope-banner"
    >
      <div class="banner-text">
        <strong>{{ $t('roleScope.bannerTitle') }}</strong>
        {{ $t('roleScope.bannerBody') }}
        {{ $t('userDetail.change.connectionFixed') }}
      </div>
      <a
        v-if="canGoAuthorizations"
        :href="authorizationsHref"
        target="_blank"
        rel="noopener"
        class="banner-link"
        data-test="banner-go-authorizations"
      >{{ $t('roleScope.goAuthorizations') }}</a>
    </div>
    <section class="block">
      <h3>{{ $t('userGroups.detail.roles.title', { n: draft.roleIds.length }) }}</h3>
      <p class="hint">
        {{ $t('userGroups.detail.roles.help') }}
      </p>
      <GroupRoleEditor
        ref="editor"
        :definitions="definitions"
        :bindings="bindings"
        :role-assets="preview.result.value?.role_assets || null"
        :counts-unavailable="preview.status.value === 'unavailable'"
        @update:draft="(v) => (draft = v)"
      />
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
          <span
            v-if="holdsAllScope"
            data-test="impact-group-assets-all"
          >{{ $t('roleNodePicker.changeAssetsAll') }}</span>
          <span v-else>{{ $t('roleNodePicker.changeAssetsValue', { after: groupAssets.after, before: groupAssets.before }) }}</span>
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
        <a
          v-if="canGoAuthorizations"
          :href="authorizationsHref"
          target="_blank"
          rel="noopener"
          class="banner-link"
          data-test="impact-go-authorizations"
        >{{ $t('roleScope.goAuthorizations') }}</a>
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
import { computed, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { t } from '@/i18n'
import { replaceUserGroupRoleBindings } from '@/api/userGroups'
import { useAssignmentPreview } from '@/composables/useAssignmentPreview'
import { needsDangerConfirm } from '@/utils/dangerCombo'
import { roleLabel } from '@/constants/roles'
import { apiErrorSummary } from '@/api/redact'
import { MENU_GROUPS } from '@/components/sidebarMenu'
import DangerComboConfirm from '@/components/DangerComboConfirm.vue'
import GroupRoleEditor from './GroupRoleEditor.vue'
import { can } from '@/composables/useCapabilities'
import { canEnter, entryRuleFor } from '@/router/entryRules'
import { managementRoleNames } from '../groupProtection'

/**
 * 群組詳情的「角色與範圍」分頁：群組角色卡（角色與範圍的選擇由 GroupRoleEditor 承載）、
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
const initial = computed(() => idsFromBindings())
const editor = ref(null)
// 編輯器輸出的草稿：選定的角色與本次改了範圍的角色
const draft = ref({ roleIds: idsFromBindings(), roleNodes: {} })
const saving = ref(false)
const canAssign = computed(() => can('role:assign'))

const roleOptions = computed(() => editor.value?.roleOptions || [])
const addPicked = (id) => editor.value?.addPicked(id)

const canGoAuthorizations = computed(() => canEnter(entryRuleFor('/authorizations')))
const authorizationsHref = computed(() => `/authorizations?user_group_id=${props.group.id}`)

const rolesDirty = computed(() => {
  const a = [...draft.value.roleIds].sort((x, y) => x - y)
  const b = [...initial.value].sort((x, y) => x - y)
  return a.length !== b.length || a.some((v, i) => v !== b[i])
})
const dirty = computed(() => rolesDirty.value || Object.keys(draft.value.roleNodes).length > 0)
// 有任一角色以指定節點持有（本次改的，或讀回的存量指派）
const hasNodeRange = computed(() =>
  draft.value.roleIds.some((id) => {
    const key = String(id)
    if (key in draft.value.roleNodes) return draft.value.roleNodes[key] !== null
    return props.bindings.find((b) => b.role_id === id)?.scope === 'nodes'
  })
)
const holdsAllScope = computed(() => editor.value?.holdsAllScope === true)

// —— 預覽（建議性）——
const preview = useAssignmentPreview()
const previewBody = () => {
  const body = {
    kind: 'group_roles',
    group_id: props.group.id,
    role_ids: [...draft.value.roleIds],
  }
  if (canAssign.value) {
    body.include_managed_asset_counts = true
    if (Object.keys(draft.value.roleNodes).length) body.role_nodes = { ...draft.value.roleNodes }
  }
  return body
}
watch([draft, () => props.bindings, canAssign], () => {
  if (dirty.value || (canAssign.value && hasNodeRange.value)) preview.schedule(previewBody())
  else preview.cancel()
}, { deep: true })

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
    const added = draft.value.roleIds.filter((id) => !initial.value.includes(id))
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
    await replaceUserGroupRoleBindings(props.group.id, [...draft.value.roleIds], { ...draft.value.roleNodes })
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
.scope-banner {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: var(--ot-space-md);
  padding: var(--ot-space-sm) var(--ot-space-md);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  background: var(--ot-bg-hover);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}
.banner-link {
  white-space: nowrap;
  color: var(--ot-primary);
}
@media (max-width: 900px) {
  .scope-banner {
    flex-direction: column;
  }
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
