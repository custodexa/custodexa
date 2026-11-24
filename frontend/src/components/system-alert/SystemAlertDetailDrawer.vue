<template>
  <el-drawer
    :model-value="modelValue"
    :title="$t('systemAlerts.detail.title')"
    size="480px"
    :append-to-body="appendToBody"
    data-test="system-alert-drawer"
    @update:model-value="(v) => emit('update:modelValue', v)"
  >
    <!-- 從每日簽核的分組開啟：標題列帶這一組的位置與上一筆、下一筆 -->
    <template
      v-if="position"
      #header
    >
      <div class="sa-drawer__header">
        <span class="sa-drawer__header-title">{{ $t('systemAlerts.detail.title') }}</span>
        <span
          class="sa-drawer__pos"
          data-test="sa-position"
        >{{ $t('systemAlerts.detail.position', { i: position.index, n: position.total }) }}</span>
        <el-button
          link
          type="primary"
          size="small"
          data-test="sa-prev"
          :disabled="position.index <= 1"
          @click="emit('prev')"
        >
          <ChevronLeft
            :size="14"
            aria-hidden="true"
          />{{ $t('systemAlerts.detail.prev') }}
        </el-button>
        <el-button
          link
          type="primary"
          size="small"
          data-test="sa-next"
          :disabled="position.index >= position.total"
          @click="emit('next')"
        >
          {{ $t('systemAlerts.detail.next') }}<ChevronRight
            :size="14"
            aria-hidden="true"
          />
        </el-button>
      </div>
    </template>
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
          <p
            v-if="tokenCreated"
            data-test="sa-first-layer"
          >
            {{ tokenCreated.summary }}
          </p>
          <p
            v-else-if="attach"
            data-test="sa-first-layer"
          >
            {{ attach.summary }}
          </p>
          <p
            v-else
            data-test="sa-first-layer"
          >
            <template v-if="detail.actor">
              {{ detail.actor }}：
            </template>{{ typeDescription }}
          </p>
          <el-alert
            v-if="attach"
            type="warning"
            :closable="false"
            show-icon
            :title="attach.warnTitle"
            :description="attach.warnBody"
            data-test="sa-attach-warning"
          />
          <el-alert
            v-else
            type="warning"
            :closable="false"
            show-icon
            :title="$t('systemAlerts.detail.notice')"
          />
        </section>

        <!-- 以 API token 掛載既有憑證：單筆列出 token、憑證、資產與掛載方式；匯入只寫台數與憑證數，逐台到操作日誌看 -->
        <section
          v-if="attach"
          data-test="sa-attach"
        >
          <h4>{{ attach.title }}</h4>
          <dl class="sa-dl">
            <dt>{{ $t('systemAlerts.detail.actorLabel') }}</dt>
            <dd data-test="sa-attach-operator">
              {{ attach.operator }}
            </dd>
            <dt>{{ $t('systemAlerts.detail.attachToken') }}</dt>
            <dd data-test="sa-attach-token">
              {{ attach.token }}
            </dd>
            <template v-if="attach.isImport">
              <dt>{{ $t('systemAlerts.detail.attachAssetCount') }}</dt>
              <dd data-test="sa-attach-asset-count">
                {{ attach.assetCount }}
              </dd>
              <dt>{{ $t('systemAlerts.detail.attachCredentialCount') }}</dt>
              <dd data-test="sa-attach-credential-count">
                {{ attach.credentialCount }}
              </dd>
            </template>
            <template v-else>
              <dt>{{ $t('systemAlerts.detail.attachCredential') }}</dt>
              <dd data-test="sa-attach-credential">
                {{ attach.credential }}<span class="sa-muted">{{ $t('systemAlerts.detail.attachSharedHint') }}</span>
              </dd>
              <dt>{{ $t('systemAlerts.detail.attachAsset') }}</dt>
              <dd data-test="sa-attach-asset">
                {{ attach.asset }}
              </dd>
            </template>
            <dt>{{ $t('systemAlerts.detail.attachEntry') }}</dt>
            <dd data-test="sa-attach-entry">
              {{ attach.entry }}
            </dd>
          </dl>
          <router-link
            v-if="attach.link"
            :to="attach.link.to"
            data-test="sa-attach-link"
          >
            {{ attach.link.text }}
          </router-link>
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

        <!-- 建立高權限 API token：建立者就是 token 的持有者，列出名稱、授權角色與到期 -->
        <section
          v-if="tokenCreated"
          data-test="sa-token-created"
        >
          <h4>{{ $t('systemAlerts.detail.createdTitle') }}</h4>
          <dl class="sa-dl">
            <dt>{{ $t('systemAlerts.detail.createdCreator') }}</dt>
            <dd data-test="sa-token-creator">
              {{ tokenCreated.creator }}
            </dd>
            <dt>{{ $t('systemAlerts.detail.createdPrivRoles') }}</dt>
            <dd data-test="sa-token-priv-roles">
              <template v-if="tokenCreated.privRoles.length">
                <div
                  v-for="(item, i) in tokenCreated.privRoles"
                  :key="`p${i}`"
                  class="sa-token-role"
                >
                  <span>{{ item.label }}</span>
                  <ApiTokenLevelTag
                    v-if="item.level"
                    :level="item.level"
                  />
                </div>
              </template>
              <template v-else>
                {{ $t('systemAlerts.detail.none') }}
              </template>
            </dd>
            <dt>{{ $t('systemAlerts.detail.createdTokenName') }}</dt>
            <dd data-test="sa-token-name">
              {{ tokenCreated.name }}
            </dd>
            <dt>{{ $t('systemAlerts.detail.createdAccess') }}</dt>
            <dd data-test="sa-token-access">
              <ApiTokenAccessBadge :value="tokenCreated.access" />
            </dd>
            <dt>{{ $t('systemAlerts.detail.createdGrantedRoles') }}</dt>
            <dd data-test="sa-token-granted-roles">
              <template v-if="tokenCreated.grantedRoles.length">
                <div
                  v-for="(item, i) in tokenCreated.grantedRoles"
                  :key="`g${i}`"
                  class="sa-token-role"
                >
                  <span>{{ item.label }}</span>
                  <ApiTokenLevelTag
                    v-if="item.level"
                    :level="item.level"
                  />
                </div>
              </template>
              <template v-else>
                {{ $t('systemAlerts.detail.none') }}
              </template>
            </dd>
            <dt>{{ $t('systemAlerts.detail.createdExpiry') }}</dt>
            <dd data-test="sa-token-expiry">
              <template v-if="tokenCreated.expires">
                {{ tokenCreated.expires }}
              </template>
              <template v-else>
                <strong>{{ $t('systemAlerts.detail.createdNeverExpires') }}</strong>
                <span class="sa-muted">（{{ $t('systemAlerts.detail.createdNeverExpiresHint') }}）</span>
              </template>
            </dd>
          </dl>
          <router-link
            v-if="tokenCreated.link"
            :to="tokenCreated.link"
            data-test="sa-view-api-tokens"
          >
            {{ $t('systemAlerts.detail.viewTokens', { user: tokenCreated.actor }) }}
          </router-link>
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

        <!-- 前往被授權對象的權限一覽：只給能進使用者詳情頁者，目標必須是使用者 -->
        <section
          v-if="overviewLink"
          data-test="sa-overview"
        >
          <router-link
            :to="overviewLink.to"
            data-test="sa-view-permission-overview"
          >
            {{ overviewLink.text }}
          </router-link>
        </section>

        <!-- 前往該台的主機帳號盤點：只給目標是資產、識別為正整數、且進得了資產頁者 -->
        <section
          v-if="inventoryLink"
          data-test="sa-inventory"
        >
          <router-link
            :to="inventoryLink.to"
            data-test="sa-view-host-inventory"
          >
            {{ inventoryLink.text }}
          </router-link>
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
                {{ d.dest_name }}<template v-if="d.channel_disabled">
                  {{ $t('systemAlerts.delivery.disabledTag') }}
                </template>
                <span
                  class="sa-delivery-state"
                  :class="`is-${d.state}`"
                >{{ deliveryLabel(d.state) }}</span>
                <span
                  v-if="deliveryBefore(d)"
                  class="sa-delivery-detail"
                  data-test="sa-delivery-detail"
                >{{ deliveryBefore(d) }}</span>
                <span
                  v-if="deliveryTime(d)"
                  class="sa-delivery-time"
                  data-test="sa-delivery-time"
                >{{ deliveryTime(d) }}</span>
                <span
                  v-if="deliveryAfter(d)"
                  class="sa-delivery-detail"
                  data-test="sa-delivery-after"
                >{{ deliveryAfter(d) }}</span>
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
    <!-- 這一筆的處置：單筆審閱（不帶批次關聯碼，處置說明選填）；只給有處置權限者 -->
    <template
      v-if="reviewable && detail"
      #footer
    >
      <div
        class="sa-review"
        data-test="sa-review"
      >
        <div class="sa-review__title">
          {{ $t('systemAlerts.detail.reviewTitle') }}
        </div>
        <el-radio-group
          v-model="reviewForm.disposition"
          data-test="sa-review-disposition"
        >
          <el-radio
            value="benign"
            data-test="sa-review-benign"
          >
            {{ $t('alerts.dispositionBenign') }}
          </el-radio>
          <el-radio
            value="escalated"
            data-test="sa-review-escalated"
          >
            {{ $t('alerts.dispositionEscalated') }}
          </el-radio>
        </el-radio-group>
        <div class="sa-review__label">
          {{ $t('dailyReview.drawer.single.noteLabel') }}
        </div>
        <el-input
          v-model="reviewForm.note"
          type="textarea"
          :rows="2"
          maxlength="500"
          show-word-limit
          data-test="sa-review-note"
        />
        <div class="sa-review__actions">
          <el-button
            data-test="sa-review-close"
            @click="emit('update:modelValue', false)"
          >
            {{ $t('dailyReview.drawer.single.close') }}
          </el-button>
          <el-button
            v-preview-write
            type="primary"
            :loading="reviewSubmitting"
            data-test="sa-review-submit"
            @click="submitReview"
          >
            {{ $t('dailyReview.drawer.single.submit') }}
          </el-button>
        </div>
      </div>
    </template>
  </el-drawer>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { ChevronLeft, ChevronRight } from 'lucide-vue-next'
import { reviewAlert } from '@/api/alerts'
import { previewWrite as vPreviewWrite } from '@/directives/previewWrite'
import { getSystemAlertDetail } from '@/api/systemAlerts'
import { formatDateTime } from '@/utils/format'
import { roleLabel } from '@/constants/roles'
import {
  API_TOKEN_ACCESS_VALUES,
  accessLabel,
  normalizeLevel,
  roleValueLabel,
  SUPER_ROLE_KEY,
} from '@/constants/apiTokens'
import ApiTokenAccessBadge from '@/components/api-token/ApiTokenAccessBadge.vue'
import ApiTokenLevelTag from '@/components/api-token/ApiTokenLevelTag.vue'
import { canEnter, ENTRY_RULES } from '@/router/entryRules'
import { t } from '@/i18n'
import { DELIVERY_MAX_ATTEMPTS } from '@/constants/notification-channels'
import { reasonText, remainingAttempts } from '@/components/alerts/channelDelivery'

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  alertId: { type: Number, default: null },
  appendToBody: { type: Boolean, default: false },
  // 這一組的位置 { index, total }：有值時標題列帶上一筆、下一筆
  position: { type: Object, default: null },
  // 可在明細處置這一筆（呼叫端依處置權限決定）
  reviewable: { type: Boolean, default: false },
})
// prev／next：換上一筆、下一筆；reviewed：這一筆已處置（呼叫端重取並換下一筆）
const emit = defineEmits(['update:modelValue', 'prev', 'next', 'reviewed'])

const reviewForm = ref({ disposition: 'benign', note: '' })
const reviewSubmitting = ref(false)

// 單筆審閱：規則與告警頁的逐筆審閱相同（理由選填，本人觸發者亦同）
const submitReview = async () => {
  if (!props.alertId || reviewSubmitting.value) return
  reviewSubmitting.value = true
  try {
    await reviewAlert(props.alertId, {
      disposition: reviewForm.value.disposition,
      note: reviewForm.value.note.trim(),
    })
    emit('reviewed', props.alertId)
  } catch (error) {
    // 錯誤由全域攔截器提示
    console.error('審閱告警失敗:', error?.response?.status)
  } finally {
    reviewSubmitting.value = false
  }
}

const TAG_TYPES = { high: 'danger', medium: 'warning', low: 'info' }
const LEVELS = ['high', 'medium', 'low']
const DELIVERY_STATES = ['pending', 'retrying', 'delivered', 'abandoned']
// 權限變化區塊只對這三類呈現
const PRIVILEGE_TYPES = ['self_privilege_increased', 'self_privilege_decreased']
// 以 API token 掛載既有憑證：類型鍵與掛載方式（entry）的值域
const ATTACH_TYPE = 'api_token_credential_attached'
const ATTACH_ENTRIES = ['asset_create', 'account_create', 'bind', 'rebind', 'import']

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
  if (d.target_kind === 'user' && d.alert_type === 'privileged_api_token_created') return d.actor || d.params?.actor || ''
  if (d.target_kind === 'user' && d.alert_type === ATTACH_TYPE) return d.actor || d.params?.actor || ''
  return ''
}
// 資產目標的名稱：只有以 API token 掛載既有憑證的單筆告警帶資產名稱
const assetTargetName = (d) =>
  d.target_kind === 'asset' && d.alert_type === ATTACH_TYPE ? d.params?.asset_name || '' : ''

// 目標：種類以文字呈現，識別附在後面；未知種類原樣顯示
const TARGET_KINDS = ['asset', 'credential', 'user', 'user_group', 'role_mapping', 'role', 'identity_source', 'notification_channel', 'session', 'system_setting']
const targetText = computed(() => {
  const d = detail.value
  if (!d || !d.target_kind) return t('systemAlerts.detail.none')
  const kind = TARGET_KINDS.includes(d.target_kind) ? t(`systemAlerts.targetKinds.${d.target_kind}`) : d.target_kind
  const named = targetName(d) || assetTargetName(d)
  if (named && d.target_id && d.target_id !== '0') {
    return t('systemAlerts.detail.targetNamed', { name: named, kind, id: d.target_id })
  }
  return d.target_id && d.target_id !== '0' ? `${kind} #${d.target_id}` : kind
})

// 宣告參數：依鍵排序逐列呈現（後端已濾掉保留鍵，且宣告參數不含秘密或完整網址）
const paramEntries = computed(() => {
  const p = (detail.value && detail.value.params) || {}
  return Object.keys(p)
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
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

// 時間之前的說明：重送中寫已試次數與最近原因；放棄寫原因句子與下一步
const deliveryBefore = (d) => {
  if (d.state === 'retrying' && d.attempts > 0) {
    return d.reason_code
      ? t('systemAlerts.delivery.triedWithReason', { attempts: d.attempts, reason: reasonText(d.reason_code, d.last_error) })
      : t('systemAlerts.delivery.tried', { attempts: d.attempts })
  }
  if (d.state === 'abandoned') {
    switch (d.end_reason) {
      case 'snapshot_unreadable':
        return t('systemAlerts.delivery.abandonedReason.unreadable')
      case 'rate_limited':
        return t('systemAlerts.delivery.abandonedReason.rateLimited')
      case 'type_unregistered':
        return t('systemAlerts.delivery.abandonedReason.type')
      case 'render_failed':
        return t('systemAlerts.delivery.abandonedReason.render')
      case 'max_attempts':
        return t('systemAlerts.delivery.abandonedReason.max', {
          max: DELIVERY_MAX_ATTEMPTS,
          reason: reasonText(d.reason_code, d.last_error),
        })
      default:
        return ''
    }
  }
  return ''
}
// 時間之後的說明：重送中寫最多再試幾次；非第一次送達寫第幾次；停用的通道照送
const deliveryAfter = (d) => {
  const parts = []
  if (d.state === 'retrying' && d.attempts > 0) parts.push(t('systemAlerts.delivery.remaining', { remaining: remainingAttempts(d.attempts) }))
  if (d.state === 'delivered' && d.attempts > 1) parts.push(t('systemAlerts.delivery.deliveredNth', { n: d.attempts }))
  if (d.channel_disabled) parts.push(t('systemAlerts.delivery.disabledStillSent'))
  // 各句自帶前導標點（接在時間或狀態之後）
  return parts.join('')
}

const roleListText = (csv) =>
  csv
    .split(',')
    .map((name) => roleLabel(name.trim()))
    .join(t('common.listSeparator'))
// 超級管理者的內建角色顯示名是「管理員」，不熟角色名稱的人讀不出它就是超級管理者：
// 在告警裡補註一句
const tokenRoleLabel = (value) => {
  const label = roleValueLabel(value)
  return label && String(value).trim() === SUPER_ROLE_KEY
    ? t('systemAlerts.detail.createdSuperRole', { role: label })
    : label
}
// 角色清單與同序的層級清單（皆為逗號分隔）配成「角色＋層級」。
// 兩邊項數不同時不冒配錯角色的風險，只列角色名、不帶層級；沒有層級參數的舊告警同樣只列名稱
const tokenRoleItems = (rolesCsv, levelsCsv) => {
  if (!rolesCsv) return []
  const names = String(rolesCsv).split(',')
  const levels = levelsCsv ? String(levelsCsv).split(',').map((v) => v.trim()) : []
  const paired = levels.length === names.length
  return names
    .map((value, i) => ({ label: tokenRoleLabel(value), level: paired ? normalizeLevel(levels[i]) : '' }))
    .filter((item) => item.label)
}
// 告警參數的權限總結：不認得的值當唯讀；沒有這個參數的告警是本功能之前產生的，當時每個角色都是讀寫
const tokenAlertAccess = (value) => {
  if (value === undefined || value === null || value === '') return 'read_write'
  return API_TOKEN_ACCESS_VALUES.includes(value) ? value : 'read'
}
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

// 建立高權限 API token：參數為 privileged_roles、granted_roles（內建角色為範本識別、自訂角色為名稱，
// 逗號分隔）、token_name、expiry（at＝有到期時刻，另帶 expires_at；never＝永不到期）；
// 較早的告警沒有 expiry 鍵，以有無 expires_at 判斷。建立者取明細的 actor，
// 使用者編號取 target_id。連到該使用者的 API token 分頁需能進使用者管理
const tokenCreated = computed(() => {
  const d = detail.value
  if (!d || d.alert_type !== 'privileged_api_token_created') return null
  const p = d.params || {}
  const actor = d.actor || p.actor || ''
  const privRoles = tokenRoleItems(p.privileged_roles, p.privileged_role_levels)
  const privText = privRoles.length ? privRoles.map((r) => r.label).join(t('common.listSeparator')) : t('systemAlerts.detail.none')
  const access = tokenAlertAccess(p.access)
  const validId = d.target_kind === 'user' && /^[1-9][0-9]*$/.test(String(d.target_id ?? ''))
  const neverExpires = p.expiry === 'never' || (p.expiry !== 'at' && !p.expires_at)
  const expiresAt = !neverExpires && p.expires_at ? formatDateTime(p.expires_at) : ''
  return {
    actor,
    summary: t('systemAlerts.detail.createdSummary', { actor, roles: privText, access: accessLabel(access) }),
    creator: validId ? t('systemAlerts.detail.createdCreatorValue', { name: actor, id: d.target_id }) : actor,
    privRoles,
    access,
    name: p.token_name || '',
    grantedRoles: tokenRoleItems(p.granted_roles, p.granted_role_levels),
    expires: expiresAt,
    link: validId && canEnter(ENTRY_RULES['/users']) ? { path: `/users/${d.target_id}`, query: { tab: 'apiTokens' } } : null,
  }
})

// 以 API token 掛載既有憑證：參數為 token_name、entry（掛載方式）；單筆另帶 credential_name、asset_name，
// 目標為該資產；匯入帶 asset_count、credential_count，目標為操作者（使用者編號取 target_id）。
// 操作者帶使用者編號：匯入取 target_id（目標即操作者），單筆取明細的 actor_user_id。
// 單筆的連結開該資產的編輯框（帳號在其中）；匯入的連結以那一次請求的請求識別篩選操作日誌，
// 恰好列出那一次匯入寫下的每一列（明細沒有請求識別或不能進操作日誌時不呈現）
const attach = computed(() => {
  const d = detail.value
  if (!d || d.alert_type !== ATTACH_TYPE) return null
  const p = d.params || {}
  const actor = d.actor || p.actor || ''
  const validId = /^[1-9][0-9]*$/.test(String(d.target_id ?? ''))
  const entry = ATTACH_ENTRIES.includes(p.entry) ? t(`systemAlerts.detail.attachEntries.${p.entry}`) : p.entry || ''
  const base = { token: p.token_name || '', entry }
  if (p.entry === 'import') {
    return {
      ...base,
      isImport: true,
      title: t('systemAlerts.detail.attachImportTitle'),
      summary: t('systemAlerts.detail.attachImportSummary', {
        actor,
        token_name: p.token_name || '',
        asset_count: p.asset_count ?? '',
        credential_count: p.credential_count ?? '',
      }),
      warnTitle: t('systemAlerts.detail.attachImportWarnTitle'),
      warnBody: t('systemAlerts.detail.attachImportWarnBody'),
      operator:
        d.target_kind === 'user' && validId
          ? t('systemAlerts.detail.createdCreatorValue', { name: actor, id: d.target_id })
          : actor,
      assetCount: t('systemAlerts.detail.count', { count: p.asset_count ?? '' }),
      credentialCount: t('systemAlerts.detail.attachCredentialCountValue', { count: p.credential_count ?? '' }),
      link:
        d.request_id && canEnter(ENTRY_RULES['/audit-logs'])
          ? {
              to: { path: '/audit-logs', query: { tab: 'logs', request_id: d.request_id } },
              text: t('systemAlerts.detail.attachViewImportAudit'),
            }
          : null,
    }
  }
  return {
    ...base,
    isImport: false,
    title: t('systemAlerts.detail.attachTitle'),
    summary: t('systemAlerts.detail.attachSummary', {
      actor,
      token_name: p.token_name || '',
      credential_name: p.credential_name || '',
      asset_name: p.asset_name || '',
    }),
    warnTitle: t('systemAlerts.detail.attachWarnTitle'),
    warnBody: t('systemAlerts.detail.attachWarnBody'),
    operator: /^[1-9][0-9]*$/.test(String(d.actor_user_id ?? ''))
      ? t('systemAlerts.detail.createdCreatorValue', { name: actor, id: d.actor_user_id })
      : actor,
    credential: p.credential_name || '',
    asset: p.asset_name || '',
    link:
      d.target_kind === 'asset' && validId && canEnter(ENTRY_RULES['/assets'])
        ? {
            to: { path: '/assets', query: { edit: String(d.target_id) } },
            text: t('systemAlerts.detail.attachViewAccounts', { asset_name: p.asset_name || '' }),
          }
        : null,
  }
})

// 操作日誌頁沒有以編號查詢的入口，改以告警發生時刻前後各一分鐘的時間窗深連結
const auditLogLink = computed(() => {
  const at = detail.value && Date.parse(detail.value.triggered_at)
  if (!Number.isFinite(at)) return null
  const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z')
  return { path: '/audit-logs', query: { tab: 'logs', start_time: iso(at - 60000), end_before: iso(at + 60000) } }
})

// 「查看 {name} 的權限一覽」：兩個自我授權型取 targetName（操作者本人），
// 對他人發放管理類只在目標是使用者時取受領對象；目標為群組、映射規則、角色者與其他類型都不呈現。
// 對象識別一律取明細的 target_kind／target_id，不從文字反推；檢視者需能進使用者管理。
const OVERVIEW_TYPES = [...PRIVILEGE_TYPES, 'management_role_granted']
const overviewLink = computed(() => {
  const d = detail.value
  if (!d || !OVERVIEW_TYPES.includes(d.alert_type) || d.target_kind !== 'user') return null
  if (!/^[1-9][0-9]*$/.test(String(d.target_id ?? ''))) return null
  if (!canEnter(ENTRY_RULES['/users'])) return null
  const name = targetName(d)
  return {
    to: { path: `/users/${d.target_id}`, query: { tab: 'permissions' } },
    text: t('systemAlerts.detail.viewPermissionOverview', { name }),
  }
})

// 「查看這台的主機帳號盤點」：目標種類與識別一律取明細的 target_kind／target_id，不從文字反推
const inventoryLink = computed(() => {
  const d = detail.value
  if (!d || d.alert_type !== 'unmanaged_privileged_account' || d.target_kind !== 'asset') return null
  if (!/^[1-9][0-9]*$/.test(String(d.target_id ?? ''))) return null
  if (!canEnter(ENTRY_RULES['/assets'])) return null
  return {
    to: { path: '/assets', query: { inventory: String(d.target_id) } },
    text: t('systemAlerts.detail.viewHostInventory'),
  }
})

const load = async () => {
  if (!props.modelValue || !props.alertId) return
  reviewForm.value = { disposition: 'benign', note: '' }
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
.sa-drawer__header {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--ot-space-xs) var(--ot-space-sm);
}

.sa-drawer__header-title {
  flex: 1;
  font-size: var(--ot-font-size-lg);
  font-weight: 600;
  color: var(--ot-text-primary);
}

.sa-drawer__pos {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.sa-drawer__header :deep(.el-button + .el-button) {
  margin-left: 0;
}

.sa-review {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
  padding-top: var(--ot-space-sm);
  border-top: 1px solid var(--ot-border-subtle);
  text-align: left;
}

.sa-review__title {
  font-weight: 600;
  color: var(--ot-text-primary);
}

.sa-review__label {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.sa-review__actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--ot-space-sm);
}

.sa-review__actions :deep(.el-button + .el-button) {
  margin-left: 0;
}

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

.sa-delivery-state {
  margin: 0 4px;
  font-weight: 600;
}

.sa-delivery-state.is-retrying {
  color: var(--ot-warning);
}

.sa-delivery-state.is-abandoned {
  color: var(--ot-danger);
}

.sa-delivery-detail {
  margin-right: 4px;
  color: var(--ot-text-secondary);
}

.sa-delivery-time {
  margin-left: var(--ot-space-xs);
  color: var(--ot-text-secondary);
  font-size: 12px;
}
.sa-token-role {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  flex-wrap: wrap;
}
.sa-token-role + .sa-token-role {
  margin-top: 4px;
}
.sa-muted {
  color: var(--ot-text-secondary);
}
</style>
