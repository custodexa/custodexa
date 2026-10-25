<template>
  <el-drawer
    :model-value="modelValue"
    :title="$t('systemAlerts.detail.title')"
    size="480px"
    data-test="system-alert-drawer"
    @update:model-value="(v) => emit('update:modelValue', v)"
  >
    <div
      v-loading="loading"
      class="sa-drawer"
    >
      <el-alert
        v-if="failed"
        type="error"
        :closable="false"
        show-icon
        :title="$t('systemAlerts.detail.loadFailed')"
      />
      <template v-if="detail">
        <h3 class="sa-drawer__headline">
          {{ typeName }}
          <el-tag
            size="small"
            :type="TAG_TYPES[detail.severity] || 'info'"
          >
            {{ levelLabel(detail.severity) }}
          </el-tag>
        </h3>
        <p
          class="sa-drawer__time"
          data-test="sa-occurred-at"
        >
          {{ $t('systemAlerts.detail.occurredAt') }} {{ formatDateTime(detail.triggered_at) }}
        </p>

        <!-- 第一層：發生了什麼（型別名稱＋說明＋操作者），技術細節收在下面 -->
        <section>
          <h4>{{ $t('systemAlerts.detail.happened') }}</h4>
          <p data-test="sa-first-layer">
            <template v-if="detail.actor">
              {{ detail.actor }}：
            </template>{{ typeDescription }}
          </p>
          <el-alert
            type="warning"
            :closable="false"
            show-icon
            :title="$t('systemAlerts.detail.notice')"
          />
        </section>

        <!-- 管理類發放：受領對象、新增的角色與範圍（不是操作者自己的權限變化） -->
        <section
          v-if="grant"
          data-test="sa-grant"
        >
          <h4>{{ $t('systemAlerts.detail.grantTitle') }}</h4>
          <dl class="sa-dl">
            <dt>{{ $t('systemAlerts.detail.recipientLabel') }}</dt>
            <dd data-test="sa-grant-recipient">
              {{ grant.recipient }}
            </dd>
            <dt>{{ $t('systemAlerts.detail.grantedRoles') }}</dt>
            <dd data-test="sa-grant-roles">
              {{ grant.roles }}
            </dd>
            <template v-if="grant.scopes.length">
              <dt>{{ $t('systemAlerts.detail.scopeLabel') }}</dt>
              <dd data-test="sa-grant-scope">
                <div
                  v-for="line in grant.scopes"
                  :key="line"
                >
                  {{ line }}
                </div>
              </dd>
            </template>
          </dl>
        </section>

        <!-- 自我授權兩型：操作者自己的前後差異 -->
        <section
          v-if="privilege"
          data-test="sa-privilege"
        >
          <h4>{{ $t('systemAlerts.detail.privilegeTitle', { actor: detail.actor || '' }) }}</h4>
          <table class="sa-table">
            <thead>
              <tr>
                <th />
                <th>{{ $t('systemAlerts.detail.columnBefore') }}</th>
                <th>{{ $t('systemAlerts.detail.columnAfter') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr data-test="sa-priv-roles">
                <th>{{ $t('systemAlerts.detail.roles') }}</th>
                <td>{{ privilege.rolesBefore }}</td>
                <td>{{ privilege.rolesAfter }}</td>
              </tr>
              <tr
                v-if="privilege.manageable"
                data-test="sa-priv-manageable"
              >
                <th>{{ $t('systemAlerts.detail.manageable') }}</th>
                <td>{{ privilege.manageable[0] }}</td>
                <td>{{ privilege.manageable[1] }}</td>
              </tr>
              <tr
                v-if="privilege.connectable"
                data-test="sa-priv-connectable"
              >
                <th>{{ $t('systemAlerts.detail.connectable') }}</th>
                <td>{{ privilege.connectable[0] }}</td>
                <td>{{ privilege.connectable[1] }}</td>
              </tr>
            </tbody>
          </table>
        </section>

        <section data-test="sa-tech">
          <h4>{{ $t('systemAlerts.detail.techTitle') }}</h4>
          <dl class="sa-dl">
            <template v-if="detail.actor">
              <dt>{{ $t('systemAlerts.detail.actorLabel') }}</dt>
              <dd data-test="sa-actor">
                {{ detail.actor }}
              </dd>
            </template>
            <template v-if="detail.client_ip">
              <dt>{{ $t('systemAlerts.detail.sourceAddressLabel') }}</dt>
              <dd data-test="sa-client-ip">
                {{ detail.client_ip }}
              </dd>
            </template>
            <dt>{{ $t('systemAlerts.detail.targetLabel') }}</dt>
            <dd data-test="sa-target">
              {{ targetText }}
            </dd>
            <dt>{{ $t('systemAlerts.detail.paramsLabel') }}</dt>
            <dd data-test="sa-params">
              <div
                v-for="entry in paramEntries"
                :key="entry.key"
                data-test="sa-param"
              >
                <code>{{ entry.key }}</code>: {{ entry.value }}
              </div>
              <div v-if="!paramEntries.length">
                {{ $t('systemAlerts.detail.none') }}
              </div>
            </dd>
            <dt>{{ $t('systemAlerts.detail.typeLabel') }}</dt>
            <dd>{{ typeName }}・{{ $t('systemAlerts.detail.typeLocked') }}</dd>
            <dt>{{ $t('systemAlerts.detail.severityLabel') }}</dt>
            <dd>{{ levelLabel(detail.severity) }}（{{ $t('systemAlerts.detail.severityBasis') }}）</dd>
            <dt>{{ $t('systemAlerts.detail.deliveryLabel') }}</dt>
            <dd data-test="sa-deliveries">
              <div
                v-for="(d, i) in detail.deliveries"
                :key="i"
              >
                {{ d.dest_name }} {{ deliveryLabel(d.state) }}<template v-if="d.attempts > 1">
                  （{{ $t('systemAlerts.detail.attempts', { count: d.attempts }) }}）
                </template>
                <span
                  v-if="deliveryTime(d)"
                  class="sa-delivery-time"
                  data-test="sa-delivery-time"
                >{{ deliveryTime(d) }}</span>
              </div>
              <div v-if="!detail.deliveries.length">
                {{ $t('systemAlerts.delivery.noDestination') }}
              </div>
            </dd>
            <dt>{{ $t('systemAlerts.detail.auditLogLabel') }}</dt>
            <dd data-test="sa-audit-log">
              <router-link
                v-if="detail.audit_log_id && auditLogLink"
                :to="auditLogLink"
                data-test="sa-audit-log-link"
              >
                #{{ detail.audit_log_id }} {{ $t('systemAlerts.detail.auditLogLink') }}
              </router-link>
              <span v-else-if="detail.audit_log_id">#{{ detail.audit_log_id }}</span>
              <span v-else>{{ $t('systemAlerts.detail.auditLogMissing') }}</span>
            </dd>
          </dl>
        </section>
      </template>
    </div>
  </el-drawer>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { getSystemAlertDetail } from '@/api/systemAlerts'
import { formatDateTime } from '@/utils/format'
import { roleLabel } from '@/constants/roles'
import { t } from '@/i18n'

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  alertId: { type: Number, default: null },
})
const emit = defineEmits(['update:modelValue'])

const TAG_TYPES = { high: 'danger', medium: 'warning', low: 'info' }
const LEVELS = ['high', 'medium', 'low']
const DELIVERY_STATES = ['pending', 'retrying', 'delivered', 'abandoned']
// 權限變化區塊只對這三類呈現
const PRIVILEGE_TYPES = ['self_privilege_increased', 'self_privilege_decreased']

const detail = ref(null)
const loading = ref(false)
const failed = ref(false)

const typeName = computed(() => (detail.value ? t(`systemAlerts.types.${detail.value.alert_type}.name`) : ''))
const typeDescription = computed(() => (detail.value ? t(`systemAlerts.types.${detail.value.alert_type}.description`) : ''))
const levelLabel = (level) => (LEVELS.includes(level) ? t(`enum.alertLevel.${level}`) : level)
const deliveryLabel = (state) => (DELIVERY_STATES.includes(state) ? t(`systemAlerts.delivery.${state}`) : state)

// 使用者與群組目標的名稱：管理類發放取受領對象，自我授權的目標就是操作者本人；其餘型別不知道名稱
const targetName = (d) => {
  if (!['user', 'user_group'].includes(d.target_kind)) return ''
  if (d.alert_type === 'management_role_granted') return d.params?.recipient || ''
  if (d.target_kind === 'user' && PRIVILEGE_TYPES.includes(d.alert_type)) return d.actor || ''
  return ''
}

// 目標：種類以文字呈現，識別附在後面；未知種類原樣顯示
const TARGET_KINDS = ['asset', 'credential', 'user', 'user_group', 'role_mapping', 'role', 'identity_source', 'notification_channel', 'session', 'system_setting']
const targetText = computed(() => {
  const d = detail.value
  if (!d || !d.target_kind) return t('systemAlerts.detail.none')
  const kind = TARGET_KINDS.includes(d.target_kind) ? t(`systemAlerts.targetKinds.${d.target_kind}`) : d.target_kind
  const named = targetName(d)
  if (named && d.target_id && d.target_id !== '0') {
    return t('systemAlerts.detail.targetNamed', { name: named, kind, id: d.target_id })
  }
  return d.target_id && d.target_id !== '0' ? `${kind} #${d.target_id}` : kind
})

// 宣告參數：依鍵排序逐列呈現（後端已濾掉保留鍵，且宣告參數不含秘密或完整網址）
const paramEntries = computed(() => {
  const p = (detail.value && detail.value.params) || {}
  return Object.keys(p)
    .sort()
    .map((key) => ({ key, value: p[key] }))
})

// 投遞時間：已送達顯示送達時刻；等待或重送中顯示下一次嘗試時刻；放棄不顯示時間
const deliveryTime = (d) => {
  if (d.state === 'delivered' && d.delivered_at) {
    return t('systemAlerts.detail.deliveredAt', { time: formatDateTime(d.delivered_at) })
  }
  if ((d.state === 'pending' || d.state === 'retrying') && d.next_attempt_at) {
    return t('systemAlerts.detail.nextAttemptAt', { time: formatDateTime(d.next_attempt_at) })
  }
  return ''
}

const roleListText = (csv) =>
  csv
    .split(',')
    .map((name) => roleLabel(name.trim()))
    .join(t('common.listSeparator'))
const listText = (csv) => (csv ? roleListText(csv) : t('systemAlerts.detail.none'))
const countText = (n) => (n === undefined || n === '' ? '' : t('systemAlerts.detail.count', { count: n }))

const privilege = computed(() => {
  const d = detail.value
  if (!d || !PRIVILEGE_TYPES.includes(d.alert_type)) return null
  const p = d.params || {}
  const pair = (before, after) =>
    p[before] === undefined && p[after] === undefined ? null : [countText(p[before]), countText(p[after])]
  return {
    rolesBefore: listText(p.roles_before),
    rolesAfter: listText(p.roles_after),
    manageable: pair('manageable_before', 'manageable_after'),
    connectable: pair('connectable_before', 'connectable_after'),
  }
})

// 範圍行：全系統、節點路徑清單加總數；已刪除的節點只顯示編號。舊告警沒有節點資訊時不猜，整列不顯示
const grantScopes = (d) => {
  const p = d.params || {}
  const lines = []
  const summary = String(p.scope_summary || '').split(',')
  if (summary.includes('global')) lines.push(t('systemAlerts.detail.scopeGlobal'))
  const nodes = Array.isArray(d.scope_nodes) ? d.scope_nodes : []
  if (nodes.length) {
    const names = nodes.map((n) => n.path || t('systemAlerts.detail.scopeNodeDeleted', { id: n.id }))
    lines.push(
      t('systemAlerts.detail.scopeNodes', {
        nodes: names.join(t('common.listSeparator')),
        count: p.scope_node_count || nodes.length,
      }),
    )
  }
  return lines
}

const grant = computed(() => {
  const d = detail.value
  if (!d || d.alert_type !== 'management_role_granted') return null
  const p = d.params || {}
  const name = p.recipient || ''
  return {
    recipient: d.target_kind === 'user_group' ? t('systemAlerts.detail.recipientGroup', { name }) : name,
    roles: p.role_name ? roleListText(p.role_name) : t('systemAlerts.detail.none'),
    scopes: grantScopes(d),
  }
})

// 操作日誌頁沒有以編號查詢的入口，改以告警發生時刻前後各一分鐘的時間窗深連結
const auditLogLink = computed(() => {
  const at = detail.value && Date.parse(detail.value.triggered_at)
  if (!Number.isFinite(at)) return null
  const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z')
  return { path: '/audit-logs', query: { tab: 'logs', start_time: iso(at - 60000), end_before: iso(at + 60000) } }
})

const load = async () => {
  if (!props.modelValue || !props.alertId) return
  loading.value = true
  failed.value = false
  detail.value = null
  try {
    const resp = await getSystemAlertDetail(props.alertId, { skipErrorToast: true })
    const body = resp?.alert_type ? resp : resp?.data
    detail.value = body ? { ...body, deliveries: Array.isArray(body.deliveries) ? body.deliveries : [] } : null
    failed.value = !detail.value
  } catch {
    failed.value = true
  } finally {
    loading.value = false
  }
}

watch(() => [props.modelValue, props.alertId], load, { immediate: true })
</script>

<style scoped>
.sa-drawer__headline {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  margin: 0;
}

.sa-drawer__time {
  margin: var(--ot-space-xs) 0 var(--ot-space-md);
  color: var(--ot-text-secondary);
  font-size: 13px;
}

.sa-table {
  width: 100%;
  border-collapse: collapse;
}

.sa-table th,
.sa-table td {
  padding: var(--ot-space-xs) var(--ot-space-sm);
  text-align: left;
  border-bottom: 1px solid var(--ot-border-subtle);
}

.sa-dl {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: var(--ot-space-xs) var(--ot-space-md);
}

.sa-dl dt {
  color: var(--ot-text-secondary);
}

.sa-dl dd {
  margin: 0;
  overflow-wrap: anywhere;
}

.sa-delivery-time {
  margin-left: var(--ot-space-xs);
  color: var(--ot-text-secondary);
  font-size: 12px;
}
</style>
