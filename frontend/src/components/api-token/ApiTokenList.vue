<template>
  <div
    class="api-token-list"
    data-test="api-token-list"
  >
    <div class="atl-head">
      <div
        class="atl-summary"
        data-test="api-token-summary"
      >
        <div
          class="atl-stat"
          data-test="summary-usable"
        >
          <span class="atl-stat__value">{{ summary.usable }}</span>
          <span class="atl-stat__label">{{ accountDisabled ? $t('apiTokens.summary.activeWhileDisabled') : $t('apiTokens.summary.active') }}</span>
        </div>
        <div
          class="atl-stat"
          :class="{ 'is-warning': summary.expiringSoon > 0 }"
          data-test="summary-expiring"
        >
          <span class="atl-stat__value">{{ summary.expiringSoon }}</span>
          <span class="atl-stat__label">{{ $t('apiTokens.summary.expiringSoon') }}</span>
        </div>
        <div
          class="atl-stat"
          data-test="summary-inactive"
        >
          <span class="atl-stat__value">{{ summary.inactive }}</span>
          <span class="atl-stat__label">{{ $t('apiTokens.summary.inactive') }}</span>
        </div>
      </div>
      <slot name="actions" />
    </div>

    <div class="atl-table-wrap">
      <table
        class="atl-table"
        data-test="api-token-table"
      >
        <thead>
          <tr>
            <th class="atl-col-name">
              {{ $t('apiTokens.col.name') }}
            </th>
            <th class="atl-col-roles">
              {{ $t('apiTokens.col.grantedRoles') }}
            </th>
            <th class="atl-col-status">
              {{ $t('apiTokens.col.status') }}
            </th>
            <th class="atl-col-expiry">
              {{ $t('apiTokens.col.expiresAt') }}
            </th>
            <th class="atl-col-used">
              {{ $t('apiTokens.col.lastUsed') }}
            </th>
            <th class="atl-col-actions">
              {{ $t('apiTokens.col.actions') }}
            </th>
          </tr>
        </thead>
        <tbody>
          <template
            v-for="row in rows"
            :key="row.key"
          >
            <tr
              v-if="row.kind === 'section'"
              class="atl-section"
              data-test="inactive-section"
            >
              <td colspan="6">
                <button
                  type="button"
                  class="atl-section__toggle"
                  :aria-expanded="inactiveOpen ? 'true' : 'false'"
                  data-test="inactive-toggle"
                  @click="inactiveOpen = !inactiveOpen"
                >
                  <component
                    :is="inactiveOpen ? ChevronDown : ChevronRight"
                    :size="14"
                    aria-hidden="true"
                  />
                  {{ $t('apiTokens.inactiveSection', { n: groups.inactive.length }) }}
                </button>
                <span class="atl-section__hint">{{ $t('apiTokens.inactiveHint') }}</span>
              </td>
            </tr>
            <tr
              v-else
              class="atl-row"
              :class="{ 'is-inactive': row.inactive, 'is-new': !row.inactive && row.token.id === justCreatedId }"
              :data-test="`token-row-${row.token.id}`"
            >
              <td class="atl-col-name">
                <el-tooltip
                  v-if="mode === 'self' && !row.inactive"
                  placement="bottom-start"
                  :show-after="200"
                  popper-class="atl-edit-popper"
                >
                  <template #content>
                    <div
                      class="atl-edit-tip"
                      data-test="how-to-change"
                    >
                      <strong>{{ $t('apiTokens.howToChange.title') }}</strong>
                      <p>{{ $t('apiTokens.howToChange.body') }}</p>
                    </div>
                  </template>
                  <span
                    class="atl-name"
                    tabindex="0"
                    data-test="token-name"
                  >{{ row.token.name }}</span>
                </el-tooltip>
                <span
                  v-else
                  class="atl-name"
                  data-test="token-name"
                >{{ row.token.name }}</span>
                <el-tag
                  v-if="!row.inactive && row.token.id === justCreatedId"
                  size="small"
                  type="success"
                  class="atl-new-tag"
                  data-test="just-created"
                >
                  {{ $t('apiTokens.justCreated') }}
                </el-tag>
                <div class="atl-sub">
                  {{ $t('apiTokens.createdAt', { time: formatDateTime(row.token.created_at) }) }}
                </div>
              </td>
              <td class="atl-col-roles">
                <div
                  v-for="role in row.token.granted_roles || []"
                  :key="role.role_id"
                  class="atl-role"
                  :data-test="`granted-role-${row.token.id}-${role.role_id}`"
                >
                  <el-tag
                    size="small"
                    :type="grantedRoleTagType(role)"
                    :class="[{ 'atl-role--lost': lostRole(row, role) }, grantedRoleTagType(role) === 'info' ? 'ot-tag-neutral' : '']"
                  >
                    {{ grantedRoleLabel(role) }}
                  </el-tag>
                  <span
                    v-if="lostRole(row, role)"
                    class="atl-role__lost"
                    data-test="role-revoked"
                  >{{ $t('apiTokens.roleRevoked') }}</span>
                  <span
                    v-else-if="scopeText(role.scope)"
                    class="atl-role__scope"
                  >{{ scopeText(role.scope) }}</span>
                </div>
              </td>
              <td class="atl-col-status">
                <el-tag
                  size="small"
                  :type="statusTagType(row.token.status)"
                  :class="statusTagClass(row.token.status)"
                  :data-test="`status-${row.token.id}`"
                >
                  {{ statusLabel(row.token) }}
                </el-tag>
                <template v-if="row.token.status === 'revoked' && (row.token.revoked_by || row.token.revoked_at)">
                  <div
                    v-if="row.token.revoked_by?.username"
                    class="atl-sub"
                    data-test="revoked-by"
                  >
                    {{ $t('apiTokens.revokedBy', { user: row.token.revoked_by.username }) }}
                  </div>
                  <div
                    v-if="row.token.revoked_at"
                    class="atl-sub"
                  >
                    {{ formatDateTime(row.token.revoked_at) }}
                  </div>
                </template>
              </td>
              <td class="atl-col-expiry">
                <span
                  v-if="!row.token.expires_at"
                  data-test="never-expires"
                >{{ $t('apiTokens.neverExpires') }}</span>
                <span
                  v-else
                  class="atl-expiry"
                  :class="{
                    'is-warning': row.token.status === 'expiring_soon',
                    'is-danger': row.token.status === 'expired',
                  }"
                >
                  <Clock
                    v-if="row.token.status === 'expiring_soon'"
                    :size="13"
                    aria-hidden="true"
                  />
                  <TriangleAlert
                    v-else-if="row.token.status === 'expired'"
                    :size="13"
                    aria-hidden="true"
                  />
                  {{ formatDateTime(row.token.expires_at) }}
                </span>
              </td>
              <td class="atl-col-used">
                <template v-if="row.token.last_used_at">
                  <div>{{ formatDateTime(row.token.last_used_at) }}</div>
                  <div
                    v-if="row.token.last_used_ip"
                    class="atl-sub"
                  >
                    {{ $t('apiTokens.fromIp', { ip: row.token.last_used_ip }) }}
                  </div>
                </template>
                <span
                  v-else
                  class="atl-muted"
                >{{ $t('apiTokens.neverUsed') }}</span>
              </td>
              <td class="atl-col-actions">
                <el-button
                  v-if="canRevoke && !row.inactive"
                  v-preview-write
                  link
                  type="danger"
                  :data-test="`revoke-${row.token.id}`"
                  @click="emit('revoke', row.token)"
                >
                  {{ $t('apiTokens.revokeAction') }}
                </el-button>
                <span
                  v-else
                  class="atl-muted"
                  :data-test="`no-action-${row.token.id}`"
                >—</span>
              </td>
            </tr>
          </template>
        </tbody>
      </table>
    </div>

    <p
      v-if="showEditHint"
      class="atl-edit-hint"
      data-test="edit-hint"
    >
      <Info
        :size="13"
        aria-hidden="true"
      />
      {{ $t('apiTokens.editHint') }}
    </p>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'
import { ChevronDown, ChevronRight, Clock, Info, TriangleAlert } from 'lucide-vue-next'
import { formatDateTime } from '@/utils/format'
import { previewWrite as vPreviewWrite } from '@/directives/previewWrite'
import {
  grantedRoleLabel,
  grantedRoleTagType,
  scopeText,
  splitTokens,
  statusLabel,
  statusTagClass,
  statusTagType,
  summarize,
} from '@/constants/apiTokens'

/**
 * API token 清單：摘要數字、可用區與可收合的已失效區。
 * 本人區塊與管理者分頁共用；狀態與角色是否有效一律取自後端投影。
 */
const props = defineProps({
  tokens: { type: Array, default: () => [] },
  // self：本人（名稱可看「想改授權」說明、底部常駐說明）；admin：管理者檢視他人
  mode: { type: String, default: 'self' },
  canRevoke: { type: Boolean, default: true },
  justCreatedId: { type: Number, default: null },
  accountDisabled: { type: Boolean, default: false },
  showEditHint: { type: Boolean, default: false },
})
const emit = defineEmits(['revoke'])

const inactiveOpen = ref(true)
const groups = computed(() => splitTokens(props.tokens))
const summary = computed(() => summarize(props.tokens))

const rows = computed(() => {
  const out = groups.value.current.map((token) => ({ kind: 'token', key: `t${token.id}`, token, inactive: false }))
  if (groups.value.inactive.length) {
    out.push({ kind: 'section', key: 'section' })
    if (inactiveOpen.value) {
      for (const token of groups.value.inactive) out.push({ kind: 'token', key: `t${token.id}`, token, inactive: true })
    }
  }
  return out
})

// 角色已不在本人身上：只對仍在清單上方（可用或暫停）的 token 標示；已失效的不再追蹤角色
const lostRole = (row, role) => !row.inactive && role.effective === false
</script>

<style scoped>
.api-token-list {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-md);
}
.atl-head {
  display: flex;
  justify-content: space-between;
  align-items: flex-end;
  gap: var(--ot-space-md);
  flex-wrap: wrap;
}
.atl-summary {
  display: flex;
  gap: var(--ot-space-sm);
  flex-wrap: wrap;
}
.atl-stat {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 120px;
  padding: var(--ot-space-sm) var(--ot-space-md);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}
.atl-stat.is-warning {
  border-color: var(--ot-warning);
}
.atl-stat.is-warning .atl-stat__value {
  color: var(--ot-warning);
}
.atl-stat__value {
  font-size: var(--ot-font-size-xl);
  font-weight: 600;
  line-height: 1.2;
  color: var(--ot-text-primary);
}
.atl-stat__label {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}
.atl-table-wrap {
  overflow-x: auto;
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}
.atl-table {
  width: 100%;
  min-width: 760px;
  border-collapse: collapse;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-primary);
}
.atl-table th {
  padding: var(--ot-space-sm) 12px;
  text-align: left;
  font-weight: 500;
  color: var(--ot-text-secondary);
  background: var(--ot-bg-elevated);
  border-bottom: 1px solid var(--ot-border-subtle);
}
.atl-table td {
  padding: 10px 12px;
  vertical-align: middle;
  border-bottom: 1px solid var(--ot-border-subtle);
  overflow-wrap: anywhere;
}
.atl-table tbody tr:last-child td {
  border-bottom: none;
}
.atl-col-name { width: 22%; }
.atl-col-roles { width: 24%; }
.atl-col-status { width: 15%; }
.atl-col-expiry { width: 15%; }
.atl-col-used { width: 16%; }
.atl-col-actions { width: 8%; }
.atl-row.is-inactive td {
  color: var(--ot-text-secondary);
}
.atl-row.is-new td {
  background: var(--ot-primary-dim);
}
.atl-name {
  font-weight: 600;
  color: var(--ot-text-primary);
}
.atl-row.is-inactive .atl-name {
  color: var(--ot-text-secondary);
}
.atl-name[tabindex] {
  cursor: help;
  border-bottom: 1px dotted transparent;
}
.atl-name[tabindex]:hover,
.atl-name[tabindex]:focus-visible {
  border-bottom-color: var(--ot-text-secondary);
  outline: none;
}
.atl-new-tag {
  margin-left: var(--ot-space-xs);
}
.atl-sub {
  margin-top: 2px;
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}
.atl-muted {
  color: var(--ot-text-secondary);
}
.atl-role {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  flex-wrap: wrap;
}
.atl-role + .atl-role {
  margin-top: 4px;
}
.atl-role__scope {
  color: var(--ot-text-secondary);
}
.atl-role--lost {
  text-decoration: line-through;
  opacity: 0.6;
}
.atl-role__lost {
  color: var(--ot-warning);
}
.atl-expiry {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}
.atl-expiry.is-warning {
  color: var(--ot-warning);
}
.atl-expiry.is-danger {
  color: var(--ot-danger);
}
.atl-section td {
  background: var(--ot-bg-elevated);
  padding: var(--ot-space-sm) 12px;
}
.atl-section__toggle {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 0;
  border: none;
  background: none;
  color: var(--ot-text-primary);
  font: inherit;
  cursor: pointer;
}
.atl-section__toggle:focus-visible {
  outline: 2px solid var(--ot-primary);
  outline-offset: 2px;
}
.atl-section__hint {
  margin-left: var(--ot-space-md);
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}
.atl-edit-hint {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
  margin: 0;
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}
.atl-edit-tip {
  max-width: 320px;
  line-height: 1.5;
}
.atl-edit-tip p {
  margin: 4px 0 0;
}
</style>
