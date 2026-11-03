<template>
  <!-- 狀態卡：視線起點；按鈕的回饋留在同一張卡內 -->
  <section
    class="inv-status"
    :class="`tone-${tone}`"
    data-test="inv-status"
  >
    <div class="inv-status-main">
      <div class="inv-status-line">
        <Loader2
          v-if="active"
          :size="16"
          class="spin"
          aria-hidden="true"
        />
        <el-tag
          v-if="scan"
          :type="tagType"
          effect="light"
          size="small"
          data-test="inv-status-tag"
        >
          {{ statusText }}
        </el-tag>
        <span
          class="inv-status-text"
          data-test="inv-status-text"
        >{{ statusLine }}</span>
      </div>
      <p
        v-if="scan && runTime"
        class="inv-lastrun"
        data-test="inv-lastrun"
      >
        {{ lastRunText }}
      </p>
      <p
        v-if="startMessage"
        class="inv-start-error"
        data-test="inv-start-error"
      >
        {{ startMessage }}
        <el-button
          v-if="startMessageGoAccounts && canEditAsset"
          link
          type="primary"
          data-test="inv-go-accounts"
          @click="emit('goto', 'accounts')"
        >
          {{ $t('hostInventory.goAccounts') }}
        </el-button>
        <el-button
          v-if="startMessageGoExecutor"
          link
          type="primary"
          data-test="inv-go-executor"
          @click="emit('goto', 'executor-test-login')"
        >
          {{ $t('hostInventory.goExecutor') }}
        </el-button>
      </p>
      <p
        v-if="pollState === 'timeout'"
        class="inv-poll"
        data-test="inv-poll-timeout"
      >
        {{ $t('hostInventory.line.stillRunning') }}
        <el-button
          link
          type="primary"
          data-test="inv-poll-refresh"
          @click="emit('refresh')"
        >
          {{ $t('hostInventory.btn.refresh') }}
        </el-button>
      </p>
      <p
        v-if="pollState === 'failed'"
        class="inv-poll"
        data-test="inv-poll-failed"
      >
        {{ $t('hostInventory.line.pollFailed') }}
        <el-button
          link
          type="primary"
          data-test="inv-poll-retry"
          @click="emit('refresh')"
        >
          {{ $t('hostInventory.btn.retry') }}
        </el-button>
      </p>
    </div>
    <div class="inv-status-action">
      <slot />
    </div>
    <p
      v-if="blockedReason"
      class="inv-blocked"
      data-test="inv-start-blocked"
    >
      <Info
        :size="14"
        aria-hidden="true"
        class="inv-blocked-icon"
        data-test="inv-blocked-icon"
      />
      <span>{{ blockedReason }}</span>
      <el-button
        v-if="blockedGoAccounts"
        link
        type="primary"
        data-test="inv-blocked-go-accounts"
        @click="emit('goto', 'accounts')"
      >
        <ExternalLink
          :size="12"
          aria-hidden="true"
          class="inv-blocked-link-icon"
          data-test="inv-blocked-link-icon"
        />
        {{ $t('hostInventory.goAccounts') }}
      </el-button>
    </p>
  </section>
</template>

<script setup>
import { computed } from 'vue'
import { ExternalLink, Info, Loader2 } from 'lucide-vue-next'
import { t } from '@/i18n'
import { formatDateTime } from '@/utils/format'
import { visibleText } from '@/utils/visibleName'
import { isActiveStatus, statusKey, statusTone } from '@/utils/hostInventoryPresentation'

// 盤點抽屜的狀態卡：目前狀態、上次由誰以哪個身分執行、發起與輪詢的回饋；發起鈕由預設插槽放入
const props = defineProps({
  scan: { type: Object, default: null },
  defaultName: { type: String, default: '' },
  startMessage: { type: String, default: '' },
  startMessageGoAccounts: { type: Boolean, default: false },
  startMessageGoExecutor: { type: Boolean, default: false },
  canEditAsset: { type: Boolean, default: false },
  pollState: { type: String, default: 'idle' },
  // 發起鈕停用的原因，寫在按鈕正下方；沒有任何登入身分時多一個前往帳號設定的連結
  blockedReason: { type: String, default: '' },
  blockedGoAccounts: { type: Boolean, default: false },
})
const emit = defineEmits(['goto', 'refresh'])

const active = computed(() => !!props.scan && isActiveStatus(props.scan.status))
const tone = computed(() => (props.scan ? statusTone(props.scan.status) : 'info'))
const tagType = computed(() => ({ success: 'success', warning: 'warning', danger: 'danger', primary: 'primary', info: 'info' })[tone.value])

const statusText = computed(() => {
  const k = statusKey(props.scan?.status)
  return k ? t(`hostInventory.status.${k}`) : t('hostInventory.status.unknown', { value: props.scan?.status })
})
const statusLine = computed(() => {
  const s = props.scan
  if (!s) return t('hostInventory.line.never')
  switch (s.status) {
    case 'queued':
      return t('hostInventory.line.queued')
    case 'running':
      return t('hostInventory.line.running')
    case 'succeeded':
      return s.unmanaged_privileged_total > 0
        ? t('hostInventory.line.done', {
            accounts: s.accounts_total,
            privileged: s.privileged_total,
            unmanaged: s.unmanaged_privileged_total,
          })
        : t('hostInventory.line.doneNone')
    case 'partial':
      // 徽章已寫「部分完成：結果可能不完整」，標題改為摘要句
      return t('hostInventory.line.summary', {
        accounts: s.accounts_total ?? 0,
        privileged: s.privileged_total ?? 0,
        unmanaged: s.unmanaged_privileged_total ?? 0,
      })
    case 'failed':
      return t('hostInventory.status.failed')
    case 'interrupted':
      return t('hostInventory.status.interrupted')
    default:
      return statusText.value
  }
})
const identityText = computed(() => {
  const s = props.scan
  if (!s) return ''
  if (s.identity_mode === 'executor') return t('hostInventory.login.executor')
  // 預設帳號模式＝這台沒有堡壘機專用帳號（有專用帳號時盤點改用它登入），括號說明可能讀不到的原因
  // 帳號名取盤點當時的身分（identity_username）；舊回應沒有此欄時退用目前的預設帳號名。
  // 專用帳號只顯示類別，不論權限都不顯示帳號名
  if (s.identity_mode === 'default_account') {
    const name = s.identity_username !== undefined ? String(s.identity_username || '').trim() : props.defaultName
    return name
      ? t('hostInventory.login.defaultNoExecutor', { name: visibleText(name) })
      : t('hostInventory.login.defaultNoNameNoExecutor')
  }
  return t('hostInventory.login.other', { mode: s.identity_mode })
})
// 等待中還沒有開始時間，退用建立時間
const runTime = computed(() => props.scan?.started_at || props.scan?.created_at || '')
// 進行中寫「這次」，其餘寫「上次」
const lastRunText = computed(() =>
  t(active.value ? 'hostInventory.thisRun' : 'hostInventory.lastRun', {
    time: runTime.value ? formatDateTime(runTime.value) : '',
    by: props.scan?.initiated_by_name || '',
    identity: identityText.value,
  })
)
</script>

<style scoped>
.inv-status {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
  padding: 14px 16px;
  margin-bottom: 12px;
  background: var(--ot-bg-elevated);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}

.inv-status.tone-warning {
  border-color: var(--ot-warning);
}

.inv-status.tone-danger {
  border-color: var(--ot-danger);
}

.inv-status-line {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 15px;
}

.inv-lastrun,
.inv-poll,
.inv-start-error {
  margin: 6px 0 0;
  font-size: 13px;
  color: var(--ot-text-secondary);
}

.inv-start-error {
  color: var(--ot-danger);
}

.inv-blocked {
  flex: 0 0 100%;
  margin: -8px 0 0;
  font-size: 13px;
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 6px;
  text-align: right;
  color: var(--ot-warning);
}

.inv-blocked-icon {
  flex: none;
}

.inv-blocked-link-icon {
  margin-right: 4px;
}

.spin {
  animation: inv-spin 1s linear infinite;
}

@keyframes inv-spin {
  to {
    transform: rotate(360deg);
  }
}
</style>
