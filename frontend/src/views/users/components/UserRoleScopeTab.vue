<template>
  <div
    ref="rootEl"
    class="role-scope-tab"
    data-test="role-scope-tab"
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
        href="/authorizations"
        target="_blank"
        rel="noopener"
        class="banner-link"
        data-test="banner-go-authorizations"
      >{{ $t('roleScope.goAuthorizations') }}</a>
    </div>
    <!-- 區一：管理者指派的角色 -->
    <section
      class="block"
      data-test="manual-block"
    >
      <h3>{{ $t('userDetail.roles.manualTitle', { n: selected.length }) }}</h3>
      <p class="hint">
        {{ $t('users.manualRolesHint') }}
      </p>
      <div
        v-if="assignError"
        class="assign-error"
        data-test="assign-error"
      >
        {{ assignError }}
      </div>
      <el-select
        v-model="pick"
        class="role-pick"
        :placeholder="pickOpen ? $t('roleNodePicker.filterPlaceholder') : $t('userDetail.roles.pickRole')"
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
              :key="opt.name"
              :value="opt.name"
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
      <ul class="role-cards">
        <li
          v-for="name in selected"
          :key="name"
          class="role-card"
          :class="{ 'is-openable': canOpen(name), 'is-active': activeRole === name }"
          :data-test="`manual-role-${name}`"
          :tabindex="canOpen(name) ? 0 : undefined"
          @click="openPanel(name)"
          @keydown.enter.space.self.prevent="openPanel(name)"
        >
          <el-tag
            :type="roleTagType(name)"
            size="small"
          >
            {{ roleLabel(name) }}
          </el-tag>
          <el-tag
            v-if="!initial.includes(name)"
            size="small"
            type="success"
            effect="plain"
          >
            {{ $t('userDetail.roles.newlyAdded') }}
          </el-tag>
          <template v-if="canAssign && optionsReady">
            <el-tag
              v-if="isAssignable(name) && !isNoEffect(name)"
              size="small"
              effect="plain"
              :data-test="`tag-assignable-${name}`"
            >
              {{ $t('roleNodePicker.tagAssignable') }}
            </el-tag>
            <el-tag
              v-else-if="!isAssignable(name)"
              size="small"
              effect="plain"
              type="info"
              :data-test="`tag-no-range-${name}`"
            >
              {{ $t('roleNodePicker.tagNoRange') }}
            </el-tag>
            <template v-if="draftOf(name).mode === 'all' && classOf(name) === 'builtin_global_only'">
              <strong
                class="not-applicable"
                :data-test="`scope-not-applicable-${name}`"
              >{{ $t('roles.list.scopeNotApplicable') }}</strong>
              <span class="option-note">{{ $t('roleNodePicker.notApplicableNote') }}</span>
            </template>
            <template v-else-if="draftOf(name).mode === 'all'">
              <span
                class="option-note"
                :data-test="`range-all-${name}`"
              >{{ $t('roleNodePicker.modeAll') }}</span>
              <span
                v-if="classOf(name) === 'no_scoped_permission'"
                class="option-note"
                :data-test="`range-no-effect-${name}`"
              >{{ $t('roleNodePicker.rangeNoEffectNote') }}</span>
            </template>
            <div
              v-else
              class="range-paths"
              :data-test="`range-paths-${name}`"
            >
              <span
                v-for="nid in validIdsOf(name)"
                :key="nid"
                class="option-note"
              >
                {{ nodePath(nid) }}
                <template v-if="nodeById(nid)">{{ $t('roleNodePicker.cardCount', { n: nodeById(nid).subtree_asset_count ?? 0 }) }}</template>
              </span>
            </div>
            <template v-if="missingCountOf(name) > 0">
              <el-tag
                size="small"
                type="warning"
                effect="plain"
                :data-test="`missing-tag-${name}`"
              >
                {{ $t('roleNodePicker.nodeMissing') }}
              </el-tag>
              <span
                class="option-note"
                :data-test="`missing-note-${name}`"
              >{{ $t('roleNodePicker.nodeMissingNote', { n: missingCountOf(name) }) }}</span>
              <el-button
                size="small"
                link
                :data-test="`remove-missing-${name}`"
                @click.stop="removeMissing(name)"
              >
                {{ $t('roleNodePicker.removeMissing') }}
              </el-button>
            </template>
            <span
              v-if="draftOf(name).mode === 'nodes' && draftOf(name).nodeIds.length === 0"
              class="assign-error"
              :data-test="`nodes-empty-${name}`"
            >{{ $t('apiError.VALIDATION_ROLE_BINDING_NODES_EMPTY') }}</span>
            <span
              v-if="cardNoEffectKey(name)"
              class="option-note"
              :data-test="`card-no-effect-${name}`"
            >{{ $t(cardNoEffectKey(name)) }}</span>
            <template v-if="isRejected(name) && draftOf(name).mode === 'nodes'">
              <span
                class="option-note"
                :data-test="`global-only-note-${name}`"
              >{{ $t('roleNodePicker.globalOnlyNote') }}</span>
              <el-button
                size="small"
                link
                :data-test="`set-all-${name}`"
                @click.stop="setDraft(name, { mode: 'all', nodeIds: [] })"
              >
                {{ $t('roleNodePicker.modeAll') }}
              </el-button>
            </template>
            <el-button
              v-if="canMore(name)"
              size="small"
              :aria-label="$t('roleNodePicker.moreActions')"
              :data-test="`more-${name}`"
              @click.stop="moreOpen = moreOpen === name ? '' : name"
            >
              …
            </el-button>
            <div
              v-if="moreOpen === name"
              class="more-panel"
              :data-test="`more-panel-${name}`"
              @click.stop
              @keydown.stop
            >
              <p class="more-note">
                {{ $t(classOf(name) === 'builtin_global_only' ? 'roleNodePicker.builtinGlobalOnlyNote' : 'roleNodePicker.rangeNoEffectNote') }}
              </p>
              <el-button
                size="small"
                :data-test="`still-limit-${name}`"
                @click.stop="stillLimit(name)"
              >
                {{ $t('roleNodePicker.stillLimitNodes') }}
              </el-button>
            </div>
          </template>
          <span
            v-else-if="!canAssign && origNodeCount(name) != null"
            class="option-note"
            :data-test="`range-count-${name}`"
          >{{ $t('roleNodePicker.nodeCountOnly', { n: origNodeCount(name) }) }}</span>
          <el-button
            type="danger"
            size="small"
            link
            :data-test="`remove-${name}`"
            @click.stop="removeRole(name)"
          >
            {{ $t('users.remove') }}
          </el-button>
        </li>
      </ul>
      <section
        v-if="activeRole && isAssignable(activeRole)"
        class="range-panel"
        tabindex="-1"
        data-test="range-panel"
      >
        <h4>{{ $t('roleNodePicker.panelTitleUser', { role: roleLabel(activeRole) }) }}</h4>
        <RoleNodePicker
          :model-value="draftOf(activeRole)"
          :nodes="options.nodes"
          :group-node-ids="groupNodeIdsOf(activeRole)"
          :counts="countsOf(activeRole)"
          :counts-unavailable="preview.status.value === 'unavailable'"
          :load-failed="optionsFailed"
          variant="user"
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

    <!-- 儲存後的變化（建議性預覽；只讀整筆彙總的頁面入口） -->
    <section
      v-if="dirty"
      class="block change-panel"
      data-test="change-panel"
    >
      <h3>{{ $t('userDetail.change.title') }}</h3>
      <p
        v-if="preview.status.value === 'unavailable'"
        class="hint"
        data-test="change-unavailable"
      >
        {{ $t('userDetail.change.unavailable') }}
      </p>
      <template v-else>
        <div
          class="change-row"
          data-test="routes-gained"
        >
          <span class="change-label">{{ $t('userDetail.change.routesGained') }}</span>
          <span>{{ routeText(preview.result.value?.operation?.routes_gained) }}</span>
        </div>
        <div
          class="change-row"
          data-test="routes-lost"
        >
          <span class="change-label">{{ $t('userDetail.change.routesLost') }}</span>
          <span>{{ routeText(preview.result.value?.operation?.routes_lost) }}</span>
        </div>
        <div
          v-if="(preview.result.value?.operation?.marks || []).length"
          class="change-row"
          data-test="change-notify"
        >
          <span class="change-label">{{ $t('userDetail.change.notify') }}</span>
          <span>{{ $t('userDetail.change.notifyValue') }}</span>
        </div>
      </template>
      <div
        v-if="canAssign && managedAssets"
        class="change-row"
        data-test="change-managed-assets"
      >
        <span class="change-label">{{ $t('roleNodePicker.changeManagedAssets') }}</span>
        <span
          v-if="holdsAllScope"
          data-test="change-managed-assets-all"
        >{{ $t('roleNodePicker.changeAssetsAll') }}</span>
        <span v-else>{{ $t('roleNodePicker.changeAssetsValue', { after: managedAssets.after, before: managedAssets.before }) }}</span>
      </div>
      <div class="change-row">
        <span class="change-label">{{ $t('userDetail.change.connection') }}</span>
        <span data-test="change-connection-value">{{ $t('userDetail.change.connectionUnchanged') }}</span>
      </div>
      <p
        class="hint"
        data-test="change-connection"
      >
        {{ $t('userDetail.change.connectionFixed') }}
      </p>
      <p class="hint">
        {{ $t('userDetail.change.effectiveNow') }}
      </p>
    </section>

    <!-- 區二：來自映射的角色 -->
    <section
      class="block"
      data-test="mapped-block"
    >
      <h3>{{ $t('userDetail.roles.mappedTitle', { n: mapped.length }) }}</h3>
      <p
        v-if="!mapped.length"
        class="hint"
      >
        {{ $t('users.mappedRolesEmpty') }}
      </p>
      <template v-else>
        <p class="hint">
          {{ $t('users.mappedRolesHint') }}
        </p>
        <div
          v-for="name in mapped"
          :key="name"
          class="mapped-row"
        >
          <el-checkbox
            :model-value="manualSet.has(name)"
            :disabled="manualSet.has(name) || pinning === name || stateOf(name) === 'protected'"
            :data-test="`pin-${name}`"
            @change="pinRole(name)"
          >
            <el-tag
              :type="roleTagType(name)"
              size="small"
            >
              {{ roleLabel(name) }}
            </el-tag>
            <span class="option-note">{{ $t('userDetail.roles.mappedFromMapping') }}</span>
          </el-checkbox>
          <span
            v-if="removedBothHint(name)"
            class="option-note"
            :data-test="`both-removed-hint-${name}`"
          >{{ removedBothHint(name) }}</span>
          <span class="option-note">
            {{ stateOf(name) === 'protected' && !manualSet.has(name)
              ? $t('userDetail.roles.pinProtected')
              : $t('userDetail.roles.pinLabel') }}
          </span>
        </div>
        <el-alert
          v-if="mapped.includes('approver')"
          type="warning"
          :closable="false"
          show-icon
          :title="$t('users.mappedApproverNeedsScope')"
          data-test="mapped-approver-needs-scope"
        />
      </template>
      <MappingTimingNotice />
      <div
        class="snapshot"
        data-test="group-snapshot"
      >
        <strong>{{ $t('users.groupSnapshotLabel') }}</strong>
        <p
          v-if="!snapshot"
          class="hint"
        >
          {{ $t('users.groupSnapshotEmpty') }}
        </p>
        <template v-else>
          <p class="hint">
            {{ $t('users.groupSnapshotHint') }}
          </p>
          <p class="hint">
            {{ $t('users.groupSnapshotChannel', { channel: snapshot.channel || '-' }) }}
            {{ $t('users.groupSnapshotAt', { time: formatDateTime(snapshot.at) }) }}
          </p>
          <ul v-if="snapshot.groups.length">
            <li
              v-for="(value, index) in snapshot.groups"
              :key="index"
            >
              <code>{{ value }}</code>
            </li>
          </ul>
          <p
            v-else
            class="hint"
          >
            {{ $t('users.groupSnapshotNoGroups') }}
          </p>
        </template>
      </div>
    </section>

    <!-- 區三：來自使用者群組（唯讀） -->
    <section
      class="block"
      data-test="group-block"
    >
      <h3>{{ $t('userDetail.roles.groupTitle', { n: groups.length }) }}</h3>
      <div
        v-if="groupsDenied"
        data-test="group-unavailable"
      >
        <p>{{ $t('userDetail.roles.groupUnavailable') }}</p>
        <p class="hint">
          {{ $t('userDetail.roles.groupUnavailableHint') }}
        </p>
      </div>
      <p
        v-else-if="!groups.length"
        class="hint"
      >
        {{ $t('identityGroupMappings.accountGroupsEmpty') }}
      </p>
      <ul
        v-else
        class="group-list"
      >
        <li
          v-for="g in groups"
          :key="g.id"
          class="group-row"
          :data-test="`group-${g.id}`"
        >
          <strong>{{ g.name }}</strong>
          <el-tag
            v-for="r in g.roles"
            :key="r"
            size="small"
            effect="plain"
          >
            {{ roleLabel(r) }}
          </el-tag>
          <template
            v-for="b in groupNodeBindings(g)"
            :key="`range-${b.role_name}`"
          >
            <span
              v-if="!canCompare"
              class="option-note"
              :data-test="`group-range-count-${g.id}-${b.role_name}`"
            >{{ roleLabel(b.role_name) }}：{{ $t('roleNodePicker.nodeCountOnly', { n: (b.node_ids || []).length }) }}</span>
            <span
              v-else
              class="range-paths"
              :data-test="`group-range-${g.id}-${b.role_name}`"
            >
              <span
                v-for="nid in groupValidIds(b)"
                :key="nid"
                class="option-note"
              >
                {{ roleLabel(b.role_name) }}：{{ nodePath(nid) }}
                <template v-if="groupSourceCount(b.role_name) === 1 && nodeById(nid)">{{ $t('roleNodePicker.cardCount', { n: nodeById(nid).subtree_asset_count ?? 0 }) }}</template>
              </span>
            </span>
          </template>
          <template v-if="groupMissingCount(g) > 0">
            <el-tag
              size="small"
              type="warning"
              effect="plain"
              :data-test="`group-missing-tag-${g.id}`"
            >
              {{ $t('roleNodePicker.nodeMissing') }}
            </el-tag>
            <span
              class="option-note"
              :data-test="`group-missing-note-${g.id}`"
            >{{ $t('roleNodePicker.nodeMissingNote', { n: groupMissingCount(g) }) }}</span>
          </template>
          <a
            class="group-link"
            :href="`/user-groups/${g.id}?tab=roles`"
            :data-test="`group-link-${g.id}`"
            @click.prevent="goGroup(g.id)"
          >{{ $t('userDetail.roles.goGroup') }}</a>
        </li>
      </ul>
    </section>

    <DangerComboConfirm
      v-model="confirmOpen"
      :preview="confirmPreview"
      :unavailable="confirmUnavailable"
      :known-subjects="knownSubjects"
      :notify-message="notifyMessage"
      @confirm="confirmSave"
      @back="confirmOpen = false"
    />
  </div>
</template>

<script setup>
import { computed, nextTick, onMounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { t, te } from '@/i18n'
import {
  assignManualRoles,
  getRoleAssignmentOptions,
  getUserRoleBindings,
  listRoleDefinitions,
  roleErrorCode,
} from '@/api/roleDefinitions'
import { pinUserRole } from '@/api/user'
import { getUserGroups, getUserGroupRoleBindings } from '@/api/userGroups'
import { useAssignmentPreview } from '@/composables/useAssignmentPreview'
import { needsDangerConfirm } from '@/utils/dangerCombo'
import { roleLabel, roleTagType } from '@/constants/roles'
import { formatDateTime } from '@/utils/format'
import { apiErrorSummary } from '@/api/redact'
import { MENU_GROUPS } from '@/components/sidebarMenu'
import DangerComboConfirm from '@/components/DangerComboConfirm.vue'
import MappingTimingNotice from '@/components/MappingTimingNotice.vue'
import RoleNodePicker from '@/components/RoleNodePicker.vue'
import { can } from '@/composables/useCapabilities'
import { canEnter, entryRuleFor } from '@/router/entryRules'
import { classifyRole, isNoEffectClass, SCOPE_CLASS, filterByQuery, splitBuiltinCustom } from '@/utils/roleScopePresentation'

/**
 * 使用者詳情的「角色與範圍」分頁：管理者指派、來自映射、來自群組三區。
 * 送出只帶管理者指派集；映射與群組帶來的角色不併入。能指派角色者可為能限定節點的角色選節點範圍，
 * 送出只為本次改動了範圍的角色帶 role_nodes；只有使用者管理能力者只看到節點數。
 * 伺服器是最終裁決：下拉的停用與預覽只供呈現。
 */
const props = defineProps({
  userId: { type: Number, required: true },
  username: { type: String, default: '' },
  // GET /users/:id 的 role_sets 與觀測快照原始欄位
  roleSets: { type: Object, default: () => ({ manual: [], mapped: [] }) },
  snapshot: { type: Object, default: null },
})
const emit = defineEmits(['changed'])

const router = useRouter()
const logFailure = (event, error) => console.error(...apiErrorSummary(event, error))

const definitions = ref([])
const definitionsLoaded = ref(false)
const initial = ref([...(props.roleSets.manual || [])])
const selected = ref([...(props.roleSets.manual || [])])
const mapped = ref([...(props.roleSets.mapped || [])])
const pick = ref('')
const pickOpen = ref(false)
const pickQuery = ref('')
const onPickVisible = (v) => {
  pickOpen.value = v
  if (!v) pickQuery.value = ''
}
const saving = ref(false)
const pinning = ref('')
const assignError = ref('')

watch(
  () => props.roleSets,
  (sets) => {
    initial.value = [...(sets?.manual || [])]
    selected.value = [...(sets?.manual || [])]
    mapped.value = [...(sets?.mapped || [])]
  }
)

const manualSet = computed(() => new Set(initial.value))
const stateOf = (name) => definitions.value.find((d) => d.name === name)?.assignment_state || 'open'
const idOf = (name) => definitions.value.find((d) => d.name === name)?.id

const roleOptions = computed(() =>
  definitions.value.map((d) => {
    let reason = ''
    let disabled = false
    if (d.assignment_state === 'protected') {
      disabled = true
      reason = t('roles.assignState.protected')
    } else if (d.assignment_state === 'not_open') {
      disabled = true
      reason = t('roles.assignState.notOpen')
    } else if (selected.value.includes(d.name)) {
      disabled = true
      reason = t('userDetail.roles.alreadyAdded')
    }
    const scopable =
      canAssign.value && classifyRole(d, options.value.reasons[String(d.id)]) === SCOPE_CLASS.EFFECTIVE
    return { name: d.name, builtin_key: d.builtin_key, disabled, reason, state: d.assignment_state, scopable }
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

const rolesDirty = computed(() => {
  const a = [...selected.value].sort()
  const b = [...initial.value].sort()
  return a.length !== b.length || a.some((v, i) => v !== b[i])
})

// —— 節點範圍：選項、讀回的指派與草稿 ——
const canAssign = computed(() => can('role:assign'))
const options = ref({ nodes: [], assignable: new Set(), reasons: {} })
const optionsReady = ref(false)
const optionsFailed = ref(false)
const bindings = ref([])
const ranges = ref({}) // 角色名稱 -> { mode, nodeIds }（只存被動過的）
const activeRole = ref('')

const ALL = { mode: 'all', nodeIds: [] }
const bindingOf = (name) => bindings.value.find((b) => b.role_name === name)
// 讀回的範圍原值：以 node_ids 欄位存在判定節點範圍，失效節點 ID 原樣保留
const origOf = (name) => {
  const b = bindingOf(name)
  if (!b) return null
  return Object.prototype.hasOwnProperty.call(b, 'node_ids')
    ? { mode: 'nodes', nodeIds: [...(b.node_ids || [])] }
    : { mode: 'all', nodeIds: [] }
}
const draftOf = (name) => ranges.value[name] || origOf(name) || ALL
const origNodeCount = (name) => {
  const o = origOf(name)
  return o && o.mode === 'nodes' ? o.nodeIds.length : null
}
const sameRange = (a, b) => {
  if (a.mode !== b.mode) return false
  if (a.mode === 'all') return true
  const x = [...a.nodeIds].sort((m, n) => m - n)
  const y = [...b.nodeIds].sort((m, n) => m - n)
  return x.length === y.length && x.every((v, i) => v === y[i])
}
const rangeChanged = (name) => !sameRange(draftOf(name), origOf(name) || ALL)
const changedRanges = computed(() => selected.value.filter((n) => canAssign.value && rangeChanged(n)))
const dirty = computed(() => rolesDirty.value || changedRanges.value.length > 0)

const isAssignable = (name) => {
  const id = idOf(name)
  return canAssign.value && id != null && options.value.assignable.has(id)
}
const noEffectReasonOf = (name) => options.value.reasons[String(idOf(name))] || ''
// 與選項路由的未刪除節點清單比對；清單讀取失敗時無從比對，一律不判失效
const canCompare = computed(() => canAssign.value && optionsReady.value && !optionsFailed.value)
const isMissingId = (id) => canCompare.value && !options.value.nodes.some((n) => n.id === id)
const validIdsOf = (name) => draftOf(name).nodeIds.filter((id) => !isMissingId(id))
const missingCountOf = (name) =>
  draftOf(name).mode === 'nodes' ? draftOf(name).nodeIds.filter(isMissingId).length : 0
// 只改本次編輯的草稿；剩 0 個時仍是指定節點，不改成全系統
const removeMissing = (name) => {
  setDraft(name, { mode: 'nodes', nodeIds: validIdsOf(name) })
}
// 目前不能限定節點：角色以節點範圍持有，但不在伺服器的可限定清單內
const isRejected = (name) => canCompare.value && idOf(name) != null && !isAssignable(name)
// 範圍不會生效的提示放在卡片層，面板內不重複
const cardNoEffectKey = (name) => {
  if (!isAssignable(name) || draftOf(name).mode !== 'nodes') return ''
  const reason = noEffectReasonOf(name)
  if (!reason) return ''
  return reason === 'builtin_global_only'
    ? 'roleNodePicker.builtinGlobalOnlyNote'
    : 'roleNodePicker.rangeNoEffectNote'
}
const nodeById = (id) => options.value.nodes.find((n) => n.id === id)
const nodePath = (id) => nodeById(id)?.path || nodeById(id)?.name || ''
const setDraft = (name, v) => {
  ranges.value = { ...ranges.value, [name]: { mode: v.mode, nodeIds: [...v.nodeIds] } }
}
// 範圍不會生效的角色以全系統持有時，點卡片不開節點選擇；「仍要限定節點」收進「更多」
const classOf = (name) =>
  classifyRole(definitions.value.find((d) => d.name === name), noEffectReasonOf(name))
const isNoEffect = (name) => isNoEffectClass(classOf(name))
const canOpen = (name) => isAssignable(name) && (!isNoEffect(name) || draftOf(name).mode === 'nodes')
const canMore = (name) => canOpen(name) === false && isAssignable(name) && isNoEffect(name)
const moreOpen = ref('')
const openPanel = (name) => {
  if (canOpen(name)) activeRole.value = name
}
const rootEl = ref(null)
const stillLimit = async (name) => {
  moreOpen.value = ''
  activeRole.value = name
  // 觸發的按鈕隨「更多」面板移除，焦點移到展開的範圍面板
  await nextTick()
  rootEl.value?.querySelector('.range-panel')?.focus({ preventScroll: true })
}
const canGoAuthorizations = computed(() => canEnter(entryRuleFor('/authorizations')))

// 同一角色經使用者群組取得的節點（來自群組標記）
const groupNodeIdsOf = (name) => {
  const id = idOf(name)
  const out = new Set()
  for (const g of groups.value) {
    for (const b of g.bindings || []) {
      if (b.role_id === id && b.scope === 'nodes') (b.node_ids || []).forEach((n) => out.add(n))
    }
  }
  return [...out]
}

// 群組以節點範圍持有的角色（全系統持有者不列路徑）
const groupNodeBindings = (g) => (g.bindings || []).filter((b) => b.scope === 'nodes')
const groupValidIds = (b) => (b.node_ids || []).filter((id) => !isMissingId(id))
// 持有同一角色的群組數：只有一個來源時才能把台數歸給該群組
const groupSourceCount = (name) =>
  groups.value.filter((g) => (g.bindings || []).some((b) => b.role_name === name)).length

// 群組給予的節點範圍中已不存在的節點數（只標示，修改要到群組）
const groupMissingCount = (g) => {
  const ids = new Set()
  for (const b of g.bindings || []) {
    if (b.scope === 'nodes') (b.node_ids || []).forEach((n) => isMissingId(n) && ids.add(n))
  }
  return ids.size
}

// 取消勾選來源為並存的角色：外部群組仍會給予，原本限定節點者改為全系統生效
const removedBothHint = (name) => {
  if (selected.value.includes(name) || !initial.value.includes(name)) return ''
  const b = bindingOf(name)
  if (!b || b.source !== 'both') return ''
  return origNodeCount(name) != null
    ? t('roleNodePicker.mappedStillGranted')
    : t('roleNodePicker.mappedStillGrantedGlobal')
}

const addPicked = (name) => {
  if (name && !selected.value.includes(name)) selected.value = [...selected.value, name]
  pick.value = ''
}
const removeRole = (name) => {
  selected.value = selected.value.filter((n) => n !== name)
  if (activeRole.value === name) activeRole.value = ''
  if (moreOpen.value === name) moreOpen.value = ''
}

// —— 預覽（建議性）——
const preview = useAssignmentPreview()
// 本次改動了範圍的角色：null 改回全系統，陣列為節點 ID（預覽與寫入同形，預覽以角色編號為鍵）
const rangeValue = (name) => {
  const d = draftOf(name)
  return d.mode === 'all' ? null : [...d.nodeIds]
}
const previewBody = () => {
  const body = {
    kind: 'direct_roles',
    user_id: props.userId,
    role_ids: selected.value.map(idOf).filter((id) => id != null),
  }
  if (canAssign.value) {
    body.include_managed_asset_counts = true
    const rn = {}
    for (const n of changedRanges.value) if (idOf(n) != null) rn[String(idOf(n))] = rangeValue(n)
    if (Object.keys(rn).length) body.role_nodes = rn
  }
  return body
}
const hasNodeRange = computed(() => selected.value.some((n) => draftOf(n).mode === 'nodes'))
// 角色定義尚未載入時，名稱轉不出編號；此時送出的集合會缺角色，等定義到齊再送
const rolesResolvable = computed(() => definitionsLoaded.value)
watch([selected, ranges, bindings, canAssign, rolesResolvable], () => {
  if (!rolesResolvable.value) preview.cancel()
  else if (dirty.value || (canAssign.value && hasNodeRange.value)) preview.schedule(previewBody())
  else preview.cancel()
}, { deep: true })

const roleAssetRow = (name) =>
  (preview.result.value?.role_assets || []).find((r) => r.role_id === idOf(name))
const countsOf = (name) => {
  const r = roleAssetRow(name)
  return r ? { direct: r.direct, from_groups_extra: r.from_groups_extra, total: r.total } : null
}
const managedAssets = computed(() => preview.result.value?.managed_assets || null)
// 以全系統持有可限範圍角色：預覽台數不計全域指派，直接寫「全部資產」，以範圍判定、不看角色名稱
const holdsAllScope = computed(() =>
  selected.value.some((n) => classOf(n) === SCOPE_CLASS.EFFECTIVE && draftOf(n).mode === 'all')
)

// 頁面入口以導覽列的名稱呈現；對不上的原樣顯示
const ROUTE_TITLES = (() => {
  const map = new Map()
  for (const g of MENU_GROUPS) for (const item of g.items || []) map.set(item.path, item.titleKey)
  return map
})()
const routeName = (path) => (ROUTE_TITLES.has(path) ? t(ROUTE_TITLES.get(path)) : path)
const routeText = (list) =>
  Array.isArray(list) && list.length ? list.map(routeName).join('、') : t('userDetail.change.none')

// —— 儲存前確認 ——
const confirmOpen = ref(false)
const confirmPreview = ref(null)
const confirmUnavailable = ref(false)
const knownSubjects = computed(() => [{ user_id: props.userId, name: props.username }])
const notifyMessage = computed(() => {
  const p = confirmPreview.value
  if (!p) return ''
  const op = p.operation || {}
  if (['increase', 'decrease'].includes(op.self_direction) || (p.subjects || []).some((s) => s.self)) {
    return t('dangerConfirm.notify.selfChange')
  }
  if ((op.marks || []).includes('management_grant')) {
    const added = selected.value.filter((n) => !initial.value.includes(n))
    const roles = added
      .filter((n) => definitions.value.find((d) => d.name === n)?.management_class)
      .map(roleLabel)
      .join('、')
    return t('dangerConfirm.notify.directGrant', {
      roles,
      routes: (op.routes_gained || []).map(routeName).join('、'),
    })
  }
  return ''
})

const SCOPE_ERROR_CODES = new Set([
  'VALIDATION_ROLE_BINDING_NODES_EMPTY',
  'VALIDATION_ROLE_BINDING_NODES_INVALID',
  'VALIDATION_ROLE_NOT_NODE_SCOPABLE',
])

const persist = async () => {
  saving.value = true
  assignError.value = ''
  try {
    // 只送管理者指派集。映射賦予的角色不在這份裡——要固定下來走釘住
    const roleNodes = {}
    for (const n of changedRanges.value) roleNodes[n] = rangeValue(n)
    const res = await assignManualRoles(props.userId, selected.value, roleNodes)
    const ignored = (res?.disclosures || []).find((d) => d.code === 'role.mapped_ignored')
    if (ignored) {
      ElMessage.warning(t('users.mappedRolesIgnored', { roles: ignored.params?.roles || '' }))
    } else {
      ElMessage.success(t('users.rolesAssigned'))
    }
    if (res?.role_sets) {
      initial.value = [...(res.role_sets.manual || [])]
      selected.value = [...initial.value]
      mapped.value = [...(res.role_sets.mapped || [])]
      emit('changed', res.role_sets)
    } else {
      initial.value = [...selected.value]
      emit('changed', null)
    }
    // 儲存成功的草稿即新的原值；隨後以伺服器讀回為準
    if (canAssign.value) {
      bindings.value = bindings.value.filter((b) => !selected.value.includes(b.role_name))
      for (const n of selected.value) {
        const d = draftOf(n)
        bindings.value.push({ role_name: n, role_id: idOf(n), source: bindingOf(n)?.source || 'manual', ...(d.mode === 'nodes' ? { node_ids: [...d.nodeIds] } : {}) })
      }
    }
    ranges.value = {}
    preview.cancel()
    loadBindings()
  } catch (error) {
    const code = roleErrorCode(error)
    if (code && te(`apiError.${code}`)) {
      assignError.value = t(`apiError.${code}`)
      // 範圍相關的錯誤保留草稿；其他已知錯誤角色清單還原
      if (!SCOPE_ERROR_CODES.has(code)) selected.value = [...initial.value]
    } else {
      logFailure('user_role_assign_failed', error)
    }
  } finally {
    saving.value = false
  }
}

const save = async () => {
  if (!dirty.value || saving.value || !definitionsLoaded.value) return
  saving.value = true
  let outcome
  try {
    outcome = await preview.run(previewBody())
  } finally {
    saving.value = false
  }
  if (!outcome.ok) {
    // 預覽只是建議：失敗時不擋儲存，交由使用者決定
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

// 釘住一個映射賦予的角色：走專用端點，不併進替換主體
const pinRole = async (name) => {
  if (manualSet.value.has(name) || pinning.value) return
  pinning.value = name
  try {
    const res = await pinUserRole(props.userId, name)
    if (res?.role_sets) {
      initial.value = [...(res.role_sets.manual || [])]
      if (!dirty.value) selected.value = [...initial.value]
      mapped.value = [...(res.role_sets.mapped || [])]
    } else {
      initial.value = [...initial.value, name]
    }
    ElMessage.success(t('users.rolePinned', { role: roleLabel(name) }))
    emit('changed', res?.role_sets || null)
  } catch (error) {
    logFailure('user_role_pin_failed', error)
  } finally {
    pinning.value = ''
  }
}

// —— 來自群組（唯讀）——
const groups = ref([])
const groupsDenied = ref(false)
const loadGroups = async () => {
  groupsDenied.value = false
  try {
    const res = await getUserGroups({ quiet: true })
    const mine = (res.data || []).filter((g) =>
      (g.member_sources || []).some((m) => m.user_id === props.userId)
    )
    const rows = await Promise.all(
      mine.map(async (g) => {
        const b = await getUserGroupRoleBindings(g.id, { quiet: true })
        return { id: g.id, name: g.name, roles: (b.data || []).map((x) => x.role_name), bindings: b.data || [] }
      })
    )
    groups.value = rows
  } catch (error) {
    groups.value = []
    if (error?.response?.status === 403) {
      groupsDenied.value = true
    } else {
      logFailure('user_group_sources_failed', error)
    }
  }
}
const goGroup = (id) => router?.push({ path: `/user-groups/${id}`, query: { tab: 'roles' } })

const loadDefinitions = async () => {
  try {
    const res = await listRoleDefinitions()
    definitions.value = res?.data || []
  } catch (error) {
    logFailure('role_definitions_failed', error)
  } finally {
    definitionsLoaded.value = true
  }
}

const loadBindings = async () => {
  try {
    const res = await getUserRoleBindings(props.userId)
    bindings.value = res?.data || []
  } catch (error) {
    logFailure('user_role_bindings_failed', error)
  }
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
    logFailure('role_assignment_options_failed', error)
  } finally {
    optionsReady.value = true
  }
}
watch(canAssign, loadOptions)

onMounted(() => {
  loadDefinitions()
  loadGroups()
  loadBindings()
  loadOptions()
})
</script>

<style scoped>
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
.more-panel {
  flex-basis: 100%;
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
@media (max-width: 900px) {
  .scope-banner {
    flex-direction: column;
  }
}
.role-scope-tab {
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
.assign-error {
  margin: var(--ot-space-xs) 0;
  color: var(--ot-danger);
  font-size: var(--ot-font-size-sm);
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
.role-card,
.group-row,
.mapped-row {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  flex-wrap: wrap;
}
.group-list {
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
}
.group-link {
  color: var(--ot-primary);
  font-size: var(--ot-font-size-sm);
}
.actions {
  display: flex;
  justify-content: flex-end;
}
.change-row {
  display: flex;
  gap: var(--ot-space-md);
  margin: var(--ot-space-xs) 0;
}
.change-label {
  min-width: 96px;
  color: var(--ot-text-secondary);
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
.snapshot {
  margin-top: var(--ot-space-md);
}
</style>
