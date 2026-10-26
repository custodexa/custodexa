<template>
  <div class="role-editor">
    <nav class="crumbs">
      <router-link to="/roles">
        {{ $t('menu.roles') }}
      </router-link>
    </nav>

    <PageHeader
      :title="titleText"
      :description="headerDesc"
    >
      <template #actions>
        <el-button
          data-test="editor-cancel"
          @click="goList"
        >
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          v-if="!readonly"
          type="primary"
          :disabled="!canSave"
          :loading="saving"
          data-test="editor-save"
          @click="save"
        >
          {{ $t('common.save') }}
        </el-button>
      </template>
    </PageHeader>

    <el-alert
      v-if="loadFailed"
      type="warning"
      :closable="false"
      :title="$t('roles.list.unavailable')"
      data-test="editor-load-failed"
    />

    <div class="meta-row">
      <el-tag
        v-if="locked"
        type="info"
        data-test="editor-badge-locked"
      >
        {{ $t('roles.editor.badgeBuiltinLocked') }}
      </el-tag>
      <el-tag
        v-else-if="!isNew"
        data-test="editor-badge-custom"
      >
        {{ $t('roles.editor.badgeCustom') }}
      </el-tag>
      <span
        v-if="!locked"
        class="muted"
        data-test="editor-template-line"
      >{{ templateLine }}</span>
      <span
        v-if="holders > 0"
        class="muted"
        data-test="editor-holders"
      >{{ $t('roles.editor.holders', { n: holders }) }}</span>
    </div>

    <div class="name-row">
      <el-input
        v-model="draftName"
        :disabled="readonly"
        maxlength="64"
        :placeholder="$t('roles.create.name')"
        data-test="editor-name"
      />
      <el-input
        v-model="draftDescription"
        :disabled="readonly"
        type="textarea"
        :rows="2"
        :placeholder="$t('roles.create.descriptionPlaceholder')"
        data-test="editor-description"
      />
    </div>

    <el-alert
      v-if="conflict"
      type="error"
      :closable="false"
      :title="$t('roles.editor.conflict.title')"
      data-test="editor-conflict"
    >
      <p>{{ $t('roles.editor.conflict.body') }}</p>
      <div v-if="!conflictStay">
        <el-button
          size="small"
          type="primary"
          data-test="editor-conflict-reload"
          @click="reloadLatest"
        >
          {{ $t('roles.editor.conflict.reload') }}
        </el-button>
        <el-button
          size="small"
          data-test="editor-conflict-stay"
          @click="conflictStay = true"
        >
          {{ $t('roles.editor.conflict.stay') }}
        </el-button>
      </div>
      <p v-else>
        {{ $t('roles.editor.conflict.draftKept') }}
      </p>
    </el-alert>

    <el-alert
      v-if="nodeScopedNotice"
      type="warning"
      :closable="false"
      :title="nodeScopedNotice.text"
      :data-test="nodeScopedNotice.test"
    />

    <div class="editor-grid">
      <section class="panel">
        <h2 class="panel-title">
          {{ $t('roles.editor.systemFeatures') }}
        </h2>
        <p class="muted">
          {{ $t('roles.editor.legend') }}
        </p>

        <div
          v-for="grp in groups"
          :key="grp.key"
          class="group"
          :data-test="`group-${grp.key}`"
        >
          <div class="group-head">
            <strong>{{ $t(`menu.group.${grp.key}`) }}</strong>
            <span class="muted">{{ groupCountText(grp) }}</span>
          </div>
          <div
            v-for="e in grp.entries"
            :key="e.id"
            class="entry"
            :data-test="`entry-${e.id}`"
          >
            <div class="entry-line">
              <span class="entry-title">
                <span class="entry-name">{{ entryLabel(e.id) }}</span>
                <el-tag
                  v-if="stateOf(e) === 'partial'"
                  size="small"
                  type="warning"
                  :data-test="`partial-tag-${e.id}`"
                >
                  {{ $t('roles.summary.partial') }}
                </el-tag>
                <el-tag
                  v-if="placementKind(e) !== 'page'"
                  size="small"
                  type="info"
                  :data-test="`placement-tag-${e.id}`"
                >
                  {{ $t(`roles.editor.placementTag.${placementKind(e)}`) }}
                </el-tag>
                <el-tag
                  v-if="readViaOn(e)"
                  size="small"
                  type="info"
                  :data-test="`read-via-tag-${e.id}`"
                >
                  {{ $t('roles.editor.readViaTag', { via: entryLabel(e.read_via) }) }}
                </el-tag>
                <el-tag
                  v-if="e.scopable === true"
                  size="small"
                  type="success"
                  :data-test="`scopable-entry-${e.id}`"
                >
                  {{ $t('roles.editor.scopable') }}
                </el-tag>
              </span>
              <div
                class="seg"
                role="group"
              >
                <button
                  v-for="s in e.states"
                  :key="s.name"
                  type="button"
                  class="seg-btn"
                  :class="{ active: stateOf(e) === s.name }"
                  :aria-pressed="stateOf(e) === s.name"
                  :disabled="readonly"
                  :data-test="`entry-${e.id}-${s.name}`"
                  @click="setState(e, s.name)"
                >
                  {{ $t(`roles.state.${s.name}`) }}
                </button>
              </div>
            </div>
            <p
              v-if="stateOf(e) === 'partial'"
              class="muted entry-note"
              :data-test="`entry-partial-hint-${e.id}`"
            >
              {{ $t('roles.editor.partialHint') }}
            </p>
            <p
              v-if="placementKind(e) !== 'page'"
              class="muted entry-note"
              :data-test="`placement-note-${e.id}`"
            >
              {{ placementNoteOf(e) }}
            </p>
            <p
              v-if="readViaOn(e)"
              class="muted entry-note"
              :data-test="`read-via-note-${e.id}`"
            >
              {{ $t('roles.editor.readViaNote', { via: entryLabel(e.read_via) }) }}
            </p>
            <p
              v-if="entryNoteFor(e.id)"
              class="muted entry-note"
              :data-test="`entry-note-${e.id}`"
            >
              {{ entryNoteFor(e.id) }}
            </p>
            <p
              v-for="b in blockedFor(e.id)"
              :key="b.id"
              class="warn"
              :data-test="`missing-${e.id}`"
            >
              {{ $t('roles.editor.missing.inline', { items: missingItems(b.missing), screens: entryLabel(e.id) }) }}
            </p>
            <div
              v-if="e.details && e.details.length"
              class="details"
            >
              <button
                type="button"
                class="link"
                :data-test="`detail-toggle-${e.id}`"
                @click="toggleDetail(e.id)"
              >
                {{ $t('roles.editor.detailCount', detailCounts(e)) }}
              </button>
              <div
                v-if="openDetails[e.id]"
                class="detail-list"
              >
                <label
                  v-for="d in e.details"
                  :key="d.id"
                  class="detail-item"
                >
                  <input
                    type="checkbox"
                    :checked="perms.has(d.key)"
                    :disabled="readonly"
                    :data-test="`detail-${d.id}`"
                    @change="toggleKey(d.key)"
                  >
                  {{ detailLabel(d.id) }}
                  <span
                    v-if="sharedWithLabel(e, d)"
                    class="muted detail-shared"
                    :data-test="`detail-shared-${d.id}`"
                  >{{ sharedWithLabel(e, d) }}</span>
                  <el-tag
                    v-if="d.scopable === true"
                    size="small"
                    type="success"
                    :data-test="`scopable-detail-${d.id}`"
                  >
                    {{ $t('roles.editor.scopable') }}
                  </el-tag>
                </label>
                <p
                  v-if="e.id === 'assets'"
                  class="muted"
                >
                  {{ $t('roles.editor.detailNote') }}
                </p>
              </div>
            </div>
          </div>
        </div>

        <div
          v-if="fixedEntries.length"
          class="group"
          data-test="fixed-entries"
        >
          <div class="group-head">
            <strong>{{ $t('menu.group.overview') }}</strong>
            <span class="muted">{{ $t('roles.editor.groupCount.autoShown', { n: fixedEntries.length }) }}</span>
          </div>
          <div
            v-for="f in fixedEntries"
            :key="f"
            class="entry fixed"
            :data-test="`fixed-${f}`"
          >
            <span class="entry-name">{{ fixedLabel(f) }}</span>
            <span class="muted">{{ fixedVisible(f) }}</span>
          </div>
        </div>

        <div
          v-if="capabilities.length"
          class="group"
          data-test="capability-section"
        >
          <div class="group-head">
            <strong>{{ $t('roles.editor.capabilityTitle') }}</strong>
            <span class="muted">{{ $t('roles.editor.capabilityHint') }}</span>
          </div>
          <div
            v-for="c in capabilities"
            :key="c.id"
            class="entry"
          >
            <label class="cap-line">
              <input
                type="checkbox"
                :checked="perms.has(c.key)"
                :disabled="readonly"
                :data-test="`capability-${c.id}`"
                @change="toggleKey(c.key)"
              >
              <span class="entry-name">{{ $t(`roles.editor.capability.${c.id}`) }}</span>
              <el-tag
                v-if="c.scopable === true"
                size="small"
                type="success"
                :data-test="`scopable-capability-${c.id}`"
              >
                {{ $t('roles.editor.scopable') }}
              </el-tag>
            </label>
            <p class="muted">
              {{ $t(`roles.editor.capabilityDesc.${c.id}`) }}
            </p>
            <template v-if="c.trust_hint">
              <p
                class="warn"
                data-test="trust-hint"
              >
                {{ $t('roles.editor.trustHint') }}
              </p>
              <p
                class="muted"
                data-test="no-partial-delegation"
              >
                {{ $t('roles.editor.noPartialDelegation') }}
              </p>
            </template>
            <p
              v-for="b in blockedFor(c.id)"
              :key="b.id"
              class="warn"
              :data-test="`missing-${c.id}`"
            >
              {{ $t('roles.editor.missing.capability', { items: missingItems(b.missing) }) }}
            </p>
          </div>
        </div>
      </section>

      <aside class="panel side">
        <h2 class="panel-title">
          {{ $t('roles.editor.summary.title') }}
        </h2>
        <div
          v-if="summaryFailed"
          data-test="summary-unavailable"
        >
          <p>{{ $t('roles.editor.summary.unavailable') }}</p>
          <p class="muted">
            {{ $t('roles.editor.summary.unavailableHint') }}
          </p>
          <el-button
            size="small"
            data-test="summary-retry"
            @click="refreshSummary"
          >
            {{ $t('common.retry') }}
          </el-button>
        </div>
        <div
          v-else-if="summary"
          data-test="summary-body"
        >
          <p
            v-for="line in summaryLines"
            :key="line.kind"
            class="summary-line"
          >
            <strong>{{ line.label }}</strong>{{ line.text }}
          </p>
        </div>

        <div
          v-if="blocked.length"
          class="side-block"
          data-test="summary-missing"
        >
          <strong>{{ $t('roles.editor.summary.missingTitle') }}</strong>
          <p
            v-for="b in blocked"
            :key="b.id"
            class="muted"
          >
            {{ $t('roles.editor.missing.summary', { entry: blockedLabel(b.id), items: missingItems(b.missing), screens: blockedLabel(b.id) }) }}
          </p>
        </div>

        <div class="side-block">
          <strong>{{ $t('roles.editor.summary.scopeTitle') }}</strong>
          <p
            class="muted"
            data-test="summary-scope"
          >
            {{ scopeText }}
          </p>
        </div>
        <div class="side-block">
          <strong>{{ $t('roles.editor.summary.connectionTitle') }}</strong>
          <p class="muted">
            {{ $t('roles.editor.summary.connectionNote') }}
          </p>
        </div>

        <div
          v-if="canPreview"
          class="side-block"
          data-test="combo-panel"
        >
          <p
            v-if="preview.status.value === 'unavailable'"
            class="muted"
            data-test="preview-inline-unavailable"
          >
            {{ $t('roles.editor.previewInlineUnavailable') }}
          </p>
          <template v-else-if="panelCombos.length">
            <strong>{{ $t('roles.editor.comboPanelTitle', { n: panelCombos.length }) }}</strong>
            <p
              v-for="c in panelCombos"
              :key="c.code"
              class="muted"
            >
              {{ comboText(c.code) }}
            </p>
          </template>
        </div>

        <p class="muted">
          {{ $t('roles.editor.effectiveNow') }}
        </p>
      </aside>
    </div>

    <DangerComboConfirm
      v-model="confirmOpen"
      :preview="confirmPreview"
      :unavailable="confirmUnavailable"
      :known-subjects="knownSubjects"
      :notify-message="notifyMessage"
      @back="confirmOpen = false"
      @confirm="confirmSave"
    />
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import PageHeader from '@/components/PageHeader.vue'
import { clearDetailSubject, setDetailSubject } from '@/utils/detailTitle'
import DangerComboConfirm from '@/components/DangerComboConfirm.vue'
import { t, te } from '@/i18n'
import { roleLabel } from '@/constants/roles'
import { useAssignmentPreview } from '@/composables/useAssignmentPreview'
import { collectNewCombos, needsDangerConfirm } from '@/utils/dangerCombo'
import { entryStateOf, readViaActive, applyEntryState, distinctDetailCount, sharedKeyDetailOf } from '@/views/role-editor/entryState'
import {
  listRoleDefinitions,
  getRoleDescriptors,
  getRoleDefinition,
  summarizeRoleDraft,
  createRoleDefinition,
  updateRoleDefinition,
  roleErrorCode,
  ROLE_ERROR_CONFLICT,
} from '@/api/roleDefinitions'

const route = useRoute()
const router = useRouter()

const roleId = computed(() => (route.params.id ? Number(route.params.id) : 0))
const isNew = computed(() => !roleId.value)

const descriptors = ref({ entries: [], capabilities: [], fixed_entries: [] })
const listRows = ref([])
const canDefine = ref(false)
const detail = ref(null)
const loadFailed = ref(false)

const perms = ref(new Set())
const draftName = ref('')
const draftDescription = ref('')
const loadedReady = ref(false)
const saving = ref(false)
const conflict = ref(false)
const conflictStay = ref(false)
const openDetails = ref({})

const locked = computed(() => !isNew.value && detail.value?.locked === true)
const readonly = computed(() => locked.value || !canDefine.value)
const canSave = computed(() => !readonly.value && !conflict.value && !saving.value && draftName.value.trim() !== '' && loadedReady.value)

const row = computed(() => listRows.value.find((r) => r.id === roleId.value) || null)
const holders = computed(() => (isNew.value ? 0 : row.value?.user_count || 0))
const entries = computed(() => descriptors.value.entries || [])
const capabilities = computed(() => descriptors.value.capabilities || [])
const fixedEntries = computed(() => descriptors.value.fixed_entries || [])

const titleText = computed(() => {
  if (isNew.value) return t('roles.editor.titleNew')
  if (readonly.value) return t('roles.editor.titleView')
  return t('roles.editor.titleEdit')
})
const headerDesc = computed(() => (!isNew.value && detail.value ? displayName(detail.value) : ''))
const displayName = (r) => (r.builtin_key ? roleLabel(r.name) : r.name)

const templateId = computed(() => {
  if (isNew.value) return Number(route.query.template) || 0
  return detail.value?.template_role_id || 0
})
const templateLine = computed(() => {
  const tpl = templateId.value ? listRows.value.find((r) => r.id === templateId.value) : null
  return tpl ? t('roles.list.templateFrom', { name: displayName(tpl) }) : t('roles.list.blankStart')
})

// 入口分組：描述的 Group 為準，同一顯示分組合併
const GROUP_TITLE = { asset: 'assets', authorization: 'identity', identity: 'identity', settings: 'settings', audit: 'audit' }
const groups = computed(() => {
  const order = []
  const map = new Map()
  for (const e of entries.value) {
    const key = GROUP_TITLE[e.group] || e.group
    if (!map.has(key)) {
      map.set(key, { key, entries: [] })
      order.push(key)
    }
    map.get(key).entries.push(e)
  }
  return order.map((k) => map.get(k))
})

const entryLabel = (id) => (te(`roles.editor.entry.${id}`) ? t(`roles.editor.entry.${id}`) : id)
// 入口列下方的補充說明（有該鍵才顯示）：告警與存取複審會一併加上稽核檢視權限
const entryNoteFor = (id) => (te(`roles.editor.entryNote.${id}`) ? t(`roles.editor.entryNote.${id}`) : '')
const detailLabel = (id) => (te(`roles.editor.detail.${id}`) ? t(`roles.editor.detail.${id}`) : id)
const fixedLabel = (id) => (te(`roles.editor.fixed.${id}`) ? t(`roles.editor.fixed.${id}`) : id)
const fixedVisible = (id) => {
  if (id === 'my_agents') return t('roles.editor.fixedVisible.agentOwner')
  if (id === 'approvals') return t('roles.editor.fixedVisible.approver')
  return t('roles.editor.fixedVisible.everyone')
}

// 入口目前的態：集合完整涵蓋的最高態；持有寫入鍵卻未涵蓋管理態為部分管理（伺服器給的 write_keys）
// 隨附檢視（read_via）的入口在來源入口可見時歸為唯讀，這只是呈現，不是可選的態
const stateOf = (e) => entryStateOf(e, perms.value, entries.value)
const readViaOn = (e) => readViaActive(e, perms.value, entries.value)

// 入口所在位置取編輯描述的 placement，不依入口名稱自行推算
const placementKind = (e) => e.placement || 'page'
const placementNoteOf = (e) => {
  const kind = placementKind(e)
  const names = (e.placement_entries || []).map(entryLabel).join(t('common.listSeparator'))
  if (kind === 'embedded') return t('roles.editor.placementNote.embedded', { host: names })
  if (kind === 'helper') return t('roles.editor.placementNote.helper', { entries: names })
  return t(`roles.editor.placementNote.${kind}`)
}

const groupCountText = (grp) => {
  const n = { manage: 0, partial: 0, read: 0, available: 0, hidden: 0 }
  for (const e of grp.entries) n[stateOf(e)] += 1
  if (n.hidden === grp.entries.length) return t('roles.editor.groupCount.allHidden', { n: n.hidden })
  const parts = []
  for (const k of ['manage', 'partial', 'read', 'available', 'hidden']) {
    if (n[k]) parts.push(t(`roles.editor.groupCount.${k}`, { n: n[k] }))
  }
  return parts.join('　')
}

const setPerms = (next) => {
  perms.value = next
}
const setState = (e, name) => {
  if (readonly.value) return
  setPerms(applyEntryState(entries.value, perms.value, e, name, capabilities.value.map((c) => c.key)))
}
const toggleKey = (key) => {
  if (readonly.value) return
  const next = new Set(perms.value)
  if (next.has(key)) next.delete(key)
  else next.add(key)
  setPerms(next)
}
const toggleDetail = (id) => {
  openDetails.value = { ...openDetails.value, [id]: !openDetails.value[id] }
}
const detailCounts = (e) => distinctDetailCount(e, perms.value)
const sharedWithLabel = (e, d) => {
  const other = sharedKeyDetailOf(e, d)
  return other ? t('roles.editor.detailSharedKey', { other: detailLabel(other.id) }) : ''
}

const permsArray = () => [...perms.value].sort()

// 摘要與缺依賴：伺服器產生
const summary = ref(null)
// 草稿的範圍判定：只取伺服器欄位（摘要回應；載入時先用單筆角色的值）
const draftScopable = ref(null)
const draftNoEffect = ref(null)
const summaryFailed = ref(false)
const blocked = ref([])
let summarySeq = 0
const refreshSummary = async () => {
  const mine = ++summarySeq
  try {
    const res = await summarizeRoleDraft(permsArray())
    if (mine !== summarySeq) return
    summary.value = res?.summary || null
    if (typeof res?.scopable === 'boolean') draftScopable.value = res.scopable
    if (typeof res?.node_range_no_effect === 'boolean') draftNoEffect.value = res.node_range_no_effect
    blocked.value = res?.blocked_screens || []
    summaryFailed.value = false
  } catch {
    if (mine !== summarySeq) return
    summaryFailed.value = true
  }
}
let summaryTimer = null
const scheduleSummary = () => {
  clearTimeout(summaryTimer)
  summaryTimer = setTimeout(refreshSummary, 300)
}

const blockedFor = (id) => blocked.value.filter((b) => b.id === id)
const permLabel = (key) => {
  for (const e of entries.value) {
    if (e.states.some((s) => s.keys.includes(key))) return entryLabel(e.id)
  }
  return key
}
const missingItems = (list) => [...new Set((list || []).map(permLabel))].join('、')
const blockedLabel = (id) => (capabilities.value.some((c) => c.id === id) ? t(`roles.editor.capability.${id}`) : entryLabel(id))

const scopeText = computed(() => {
  const s = summary.value || {}
  if (s.scope_node_selectable === true) return t('roles.editor.summary.scopeNodeSelectable')
  if (s.scope_mixed_global_only === true) return t('roles.editor.summary.scopeMixedGlobalOnly')
  return t('roles.editor.summary.scopeAll')
})

// 已有節點範圍指派的角色，草稿改動使範圍不再生效時的提示；只提示，不阻擋儲存
const nodeScopedNotice = computed(() => {
  const n = Number(detail.value?.node_scoped_binding_count) || 0
  if (isNew.value || readonly.value || n <= 0) return null
  if (draftScopable.value === false) return { test: 'scope-notice-reject', text: t('roles.editor.nodeScopedNotice', { n }) }
  if (draftScopable.value === true && draftNoEffect.value === true) {
    return { test: 'scope-notice-no-effect', text: t('roles.editor.nodeScopedNoEffectNotice', { n }) }
  }
  return null
})

const summaryLines = computed(() => {
  const s = summary.value || {}
  const lines = []
  for (const kind of ['manage', 'partial', 'read', 'available']) {
    const ids = s[kind] || []
    if (ids.length) lines.push({ kind, label: `${t(`roles.summary.${kind}`)}：`, text: ids.map(entryLabel).join('、') })
  }
  // 獨立能力不屬於任何頁面，單獨成一段，直接看已勾選的項目
  const caps = capabilities.value.filter((c) => perms.value.has(c.key))
  if (caps.length) {
    lines.push({ kind: 'capabilities', label: `${t('roles.editor.capabilityTitle')}：`, text: caps.map((c) => t(`roles.editor.capability.${c.id}`)).join('、') })
  }
  const hiddenIds = s.hidden || []
  if (hiddenIds.length) {
    lines.push({ kind: 'hidden', label: `${t('roles.editor.summary.hiddenTitle')}：`, text: hiddenIds.map(entryLabel).join('、') })
  }
  if (!lines.length) lines.push({ kind: 'none', label: '', text: t('roles.summary.hidden') })
  return lines
})

// 危險組合：只有修改既有自訂角色才有（新增與複製沒有持有者也沒有引用）
const preview = useAssignmentPreview()
const canPreview = computed(() => !isNew.value && !readonly.value)
const previewBody = () => ({ kind: 'role_definition', role_id: roleId.value, permissions: permsArray() })
const panelCombos = computed(() => collectNewCombos(preview.result.value))
const comboText = (code) => (te(`roles.dangerCombo.${code}`) ? t(`roles.dangerCombo.${code}`) : code)

watch(perms, () => {
  if (!loadedReady.value) return
  scheduleSummary()
  if (canPreview.value) preview.schedule(previewBody())
})

// 儲存前確認
const confirmOpen = ref(false)
const confirmPreview = ref(null)
const confirmUnavailable = ref(false)
const knownSubjects = computed(() => {
  try {
    const u = JSON.parse(localStorage.getItem('user') || 'null')
    if (u && u.id != null) return [{ user_id: u.id, name: u.username || u.full_name || '' }]
  } catch {
    // 沒有本人快取就只以人數表示
  }
  return []
})
const notifyMessage = computed(() => {
  const p = confirmPreview.value
  if (!p) return ''
  const marks = p.operation?.marks || []
  const name = detail.value ? displayName(detail.value) : draftName.value
  if (marks.includes('management_grant')) {
    if (p.total === 0) return t('dangerConfirm.notify.roleDefinitionUnheld', { role: name })
    const routes = (p.operation?.routes_gained || []).join('、')
    if ((p.subjects || []).some((s) => s.self) || p.operation?.self_direction) return t('dangerConfirm.notify.roleDefinitionSelf')
    return routes ? t('dangerConfirm.notify.roleDefinitionHeld', { role: name, routes }) : t('dangerConfirm.notify.roleDefinition')
  }
  return ''
})

const persist = async () => {
  saving.value = true
  try {
    if (isNew.value) {
      const res = await createRoleDefinition({
        name: draftName.value.trim(),
        description: draftDescription.value.trim(),
        permissions: permsArray(),
        templateRoleId: templateId.value || undefined,
      })
      ElMessage.success(t('roles.create.created'))
      const newId = res?.id || res?.data?.id
      router.replace(newId ? `/roles/${newId}` : '/roles')
      return
    }
    await updateRoleDefinition(roleId.value, {
      name: draftName.value.trim(),
      description: draftDescription.value.trim(),
      permissions: permsArray(),
      expectedVersion: detail.value.definition_version,
    })
    ElMessage.success(t('roles.create.updated'))
    await loadAll()
  } catch (error) {
    if (roleErrorCode(error) === ROLE_ERROR_CONFLICT) {
      conflict.value = true
      conflictStay.value = false
    } else {
      console.error('儲存角色失敗:', error)
    }
  } finally {
    saving.value = false
  }
}

const save = async () => {
  if (!canSave.value) return
  if (isNew.value) {
    await persist()
    return
  }
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

const goList = () => router.push('/roles')

// 載入
const applyDetail = (d, { keepName = false } = {}) => {
  perms.value = new Set(d.permissions || [])
  draftScopable.value = typeof d.scopable === 'boolean' ? d.scopable : null
  draftNoEffect.value = typeof d.node_range_no_effect === 'boolean' ? d.node_range_no_effect : null
  if (!keepName) {
    draftName.value = d.name || ''
    draftDescription.value = d.description || ''
  }
}
const loadAll = async () => {
  loadedReady.value = false
  loadFailed.value = false
  try {
    const [desc, list] = await Promise.all([getRoleDescriptors(), listRoleDefinitions()])
    descriptors.value = {
      entries: desc?.entries || [],
      capabilities: desc?.capabilities || [],
      fixed_entries: desc?.fixed_entries || [],
    }
    listRows.value = list?.data || []
    canDefine.value = list?.can_define === true
    if (isNew.value) {
      detail.value = null
      draftName.value = String(route.query.name || '')
      draftDescription.value = String(route.query.description || '')
      if (templateId.value) {
        const tpl = await getRoleDefinition(templateId.value)
        perms.value = new Set(tpl?.permissions || [])
      } else {
        perms.value = new Set()
      }
    } else {
      const d = await getRoleDefinition(roleId.value)
      detail.value = d
      applyDetail(d)
      setDetailSubject(displayName(d))
    }
    conflict.value = false
    conflictStay.value = false
  } catch (error) {
    loadFailed.value = true
    console.error('載入角色失敗:', error)
    return
  }
  loadedReady.value = true
  await refreshSummary()
}
const reloadLatest = () => loadAll()

onMounted(loadAll)
onBeforeUnmount(clearDetailSubject)
</script>

<style scoped>
.crumbs {
  margin-bottom: var(--ot-space-sm);
  font-size: var(--ot-font-size-sm);
}
.meta-row {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  margin-bottom: var(--ot-space-sm);
}
.name-row {
  display: grid;
  grid-template-columns: 1fr 2fr;
  gap: var(--ot-space-sm);
  margin-bottom: var(--ot-space-md);
}
.editor-grid {
  display: grid;
  grid-template-columns: minmax(0, 2fr) minmax(260px, 1fr);
  gap: var(--ot-space-md);
}
.panel {
  padding: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}
.panel-title {
  margin: 0 0 var(--ot-space-sm);
  font-size: var(--ot-font-size-md);
  font-weight: 600;
  color: var(--ot-text-primary);
}
.group {
  margin-top: var(--ot-space-md);
}
.group-head {
  display: flex;
  justify-content: space-between;
  padding-bottom: var(--ot-space-xs);
  border-bottom: 1px solid var(--ot-border-subtle);
}
.entry {
  padding: var(--ot-space-sm) 0;
  border-bottom: 1px solid var(--ot-border-subtle);
}
.entry-line,
.cap-line {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--ot-space-sm);
}
.cap-line {
  justify-content: flex-start;
}
.entry-title {
  display: inline-flex;
  align-items: center;
  gap: var(--ot-space-xs);
}
.entry.fixed {
  display: flex;
  justify-content: space-between;
  color: var(--ot-text-secondary);
}
.seg {
  display: inline-flex;
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  overflow: hidden;
}
.seg-btn {
  padding: 4px 12px;
  border: 0;
  background: transparent;
  color: var(--ot-text-secondary);
  cursor: pointer;
}
.seg-btn + .seg-btn {
  border-left: 1px solid var(--ot-border-subtle);
}
.seg-btn.active {
  background: var(--ot-primary-dim);
  color: var(--ot-primary);
  font-weight: 600;
}
.seg-btn:disabled {
  cursor: default;
  opacity: 0.7;
}
.link {
  border: 0;
  background: transparent;
  padding: 0;
  color: var(--ot-primary);
  cursor: pointer;
  font-size: var(--ot-font-size-sm);
}
.details {
  margin-top: var(--ot-space-xs);
}
.detail-list {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: var(--ot-space-xs);
  margin-top: var(--ot-space-xs);
}
.detail-item {
  font-size: var(--ot-font-size-sm);
}
.detail-shared {
  display: block;
  margin-top: 0;
}
.muted {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
  margin: var(--ot-space-xs) 0 0;
}
.warn {
  color: var(--ot-warning);
  font-size: var(--ot-font-size-sm);
  margin: var(--ot-space-xs) 0 0;
}
.side-block {
  margin-top: var(--ot-space-md);
}
.summary-line {
  margin: 0 0 var(--ot-space-xs);
  font-size: var(--ot-font-size-sm);
}
@media (max-width: 900px) {
  .editor-grid {
    grid-template-columns: 1fr;
  }
}
</style>
