<template>
  <div
    class="rotation-progress"
    data-test="rotation-progress"
  >
    <div class="progress-head">
      <div class="progress-meta">
        <el-tag
          size="small"
          :type="aggregateTagType"
          data-test="aggregate-state"
        >
          {{ aggregateLabel }}
        </el-tag>
        <span
          class="started-by"
          data-test="rotation-started-by"
        >
          {{ startedByText }}
        </span>
      </div>
      <span
        v-if="pausedByVisibility"
        class="polling-paused"
        data-test="polling-paused"
      >
        {{ t('credentials.rotation.pollingPaused') }}
      </span>
    </div>

    <el-alert
      type="warning"
      :closable="false"
      show-icon
      data-test="rotation-warning"
      :title="t('credentials.rotation.warning')"
    />

    <div class="stat-grid">
      <div
        v-for="stat in stats"
        :key="stat.key"
        class="stat"
        :data-test="`rotation-stat-${stat.key}`"
      >
        <span
          class="stat-number"
          :class="`stat-${stat.key}`"
        >{{ stat.count }}</span>
        <span class="stat-label">{{ stat.label }}</span>
      </div>
    </div>

    <div class="progress-actions">
      <el-button
        v-if="canRotate && retryableMembers.length"
        type="primary"
        :loading="retrying"
        data-test="retry-failed"
        @click="retryFailed"
      >
        {{ t('credentials.rotation.retryFailed', { count: retryableMembers.length }) }}
      </el-button>
      <el-button
        v-if="canRotate && isRunning"
        type="danger"
        plain
        :loading="abandoning"
        data-test="abandon-rotation"
        @click="abandon"
      >
        {{ t('credentials.rotation.abandon') }}
      </el-button>
    </div>
    <p
      v-if="canRotate && isRunning"
      class="hint"
      data-test="abandon-hint"
    >
      {{ abandonHint }}
    </p>
    <p
      v-if="isUnsettled"
      class="hint"
      data-test="unsettled-hint"
    >
      {{ t('credentials.rotation.abandonedUnsettledHint') }}
    </p>

    <div class="members-head">
      <span class="section-title">
        {{ t('credentials.rotation.membersTitle', { count: members.length }) }}
      </span>
      <span
        class="version-summary"
        data-test="version-summary"
      >{{ versionSummary }}</span>
    </div>

    <div
      v-if="members.length"
      class="member-list"
    >
      <div class="member-row member-head">
        <span>{{ t('credentials.rotation.colAsset') }}</span>
        <span>{{ t('credentials.rotation.colVersion') }}</span>
        <span>{{ t('credentials.rotation.colState') }}</span>
        <span />
      </div>
      <div
        v-for="member in members"
        :key="member.id"
        class="member-item"
        :data-test="`member-row-${member.id}`"
      >
        <div class="member-row">
          <span
            class="member-asset"
            :title="assetLabel(member)"
          >{{ assetLabel(member) }}</span>
          <span
            class="mono"
            :class="{ 'version-held': isHeld(member) }"
            :data-test="`member-version-${member.id}`"
          >{{ memberVersionText(member) }}</span>
          <el-tag
            size="small"
            :type="memberStateTagType(member.state)"
            :data-test="`member-state-${member.id}`"
          >
            {{ t(`enum.credentialMemberState.${member.state}`) }}
          </el-tag>
          <span class="member-action">
            <el-button
              v-if="canRotate && canRetry(member)"
              link
              type="primary"
              :data-test="`member-retry-${member.id}`"
              @click="retryMember(member)"
            >
              {{ t('credentials.rotation.retry') }}
            </el-button>
          </span>
        </div>
        <p
          v-if="member.last_error"
          class="member-reason"
          :title="reasonText(member.last_error)"
          :data-test="`member-reason-${member.id}`"
        >
          {{ reasonText(member.last_error) }}
        </p>
      </div>
    </div>
    <p
      v-else
      class="hint"
      data-test="members-empty"
    >
      {{ t('credentials.rotation.membersEmpty') }}
    </p>
    <el-alert
      v-if="skipReport"
      type="warning"
      show-icon
      class="skip-report"
      data-test="host-identity-skip-report"
      :title="t('credentials.rotation.hostIdentitySkipSummary', { done: skipReport.done, skipped: skipReport.items.length })"
      @close="skipReport = null"
    >
      <p
        v-for="(item, idx) in skipReport.items"
        :key="idx"
        class="skip-line"
        data-test="host-identity-skip-line"
      >
        {{ t(`credentials.rotation.${item.key}`, { asset: item.asset }) }}
      </p>
    </el-alert>
    <HostIdentityConfirmDialog
      v-model="hostIdentityDialog.visible"
      :asset="hostIdentityDialog.asset"
      :account="hostIdentityDialog.account"
      :identity="hostIdentityDialog.identity"
      kind="member"
      :submitting="hostIdentityDialog.submitting"
      @confirm="confirmHostIdentity"
    />
  </div>
</template>

<script setup>
/**
 * 整組改密的進行中面板（設計稿 06）。
 *
 * 兩個號碼、不列版本清單：操作者要知道的是「要換到哪一版、現在活的是哪一版」，
 * 逐版清單只會把注意力從「哪幾台還沒就位」引開。
 *
 * 進度以輪詢取得（5 秒），分頁不在前景時暫停——背景分頁的輪詢對操作者沒有價值，
 * 卻會持續在審計上留下讀取記錄。恢復前景時立刻補一次，不等下一個週期。
 *
 * 不顯示預估剩餘時間：整組推進沒有整體上限，沒有可據以估算的來源。
 */
import { computed, ref, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import {
  getCredentialRotation,
  retryCredentialRotationMember,
  abandonCredentialRotation,
} from '@/api/credentials'
import HostIdentityConfirmDialog from '@/components/HostIdentityConfirmDialog.vue'
import { confirmDestructive } from '@/utils/confirm'
import { can } from '@/composables/useCapabilities'
import { formatDateTime } from '@/utils/format'
import {
  MEMBER_STATE_TAG_TYPE,
  AGGREGATE_STATE_TAG_TYPE,
  RETRYABLE_MEMBER_STATES,
  RUNNING_RETRYABLE_MEMBER_STATES,
  RUNNING_RUNNABLE_MEMBER_STATES,
  unsettledMemberRetryable,
} from '@/constants/credentials'

const POLL_INTERVAL_MS = 5000

const props = defineProps({
  credentialId: { type: [Number, String], required: true },
  rotationId: { type: [Number, String], required: true },
  // currentVersionNo 憑證的現行版本序號（0＝尚無密文）
  currentVersionNo: { type: Number, default: 0 },
  // bindings 掛載清單：成員的「連線用版本」來自這裡的 effective_version_no
  bindings: { type: Array, default: () => [] },
})

const emit = defineEmits(['finished', 'changed'])

const { t, te } = useI18n()

const rotation = ref(null)
const retrying = ref(false)
// 依序補跑結束後的跳過清單：常駐到下一次補跑或使用者關閉，不用會自動消失的 toast
const skipReport = ref(null)
const abandoning = ref(false)
const polling = ref(false)
const pausedByVisibility = ref(false)
let pollTimer = null

const members = computed(() => rotation.value?.members || [])
// 補跑與放棄都屬遠端輪替能力（伺服器同樣以此裁決）；無此能力者只看進度，不呈現動作
const canRotate = computed(() => can('credential:rotate'))
const isRunning = computed(() => rotation.value?.status === 'running')
// 已放棄、但仍是憑證要逐台補跑至收斂的那一輪（伺服端判定：整組的目標仍是待生效版本、
// 且還有掛載未就位）。放棄後沒有任何背景程序會再推進它，畫面上的補跑是唯一出口
const isUnsettled = computed(() =>
  rotation.value?.status === 'abandoned' && !!rotation.value?.unsettled)
// 曾看到本輪在執行：只有從執行中轉為結束（或補跑後收斂完成）才通知外層重新載入，
// 打開時就已結束的一輪不必再觸發一次重新載入
const sawRunning = ref(false)

const aggregateState = computed(() => rotation.value?.aggregate_state || '')
const aggregateLabel = computed(() =>
  aggregateState.value
    ? t(`enum.credentialAggregateState.${aggregateState.value}`)
    : t(`enum.credentialRotationStatus.${rotation.value?.status || 'running'}`))
const aggregateTagType = computed(() =>
  AGGREGATE_STATE_TAG_TYPE[aggregateState.value] || 'info')

const startedByText = computed(() => {
  if (!rotation.value) return ''
  return t('credentials.rotation.startedBy', {
    mode: t(`enum.credentialRotationMode.${rotation.value.mode}`),
    user: rotation.value.requested_by_name || '',
    time: formatDateTime(rotation.value.started_at),
  })
})

// 統計依成員狀態分組。已放棄自成一格且只在有值時出現——把它併進「失敗」會讓
// 「這台是被放棄的」與「這台真的改不動」看起來一樣
const stats = computed(() => {
  const count = (states) => members.value.filter((m) => states.includes(m.state)).length
  const rows = [
    { key: 'applied', label: t('enum.credentialMemberState.applied'), count: count(['applied']) },
    {
      key: 'changing',
      label: t('enum.credentialMemberState.changing'),
      count: count(['queued', 'changing', 'retry_wait']),
    },
    {
      key: 'unverified',
      label: t('enum.credentialMemberState.changed_unverified'),
      count: count(['changed_unverified']),
    },
    {
      key: 'failed',
      label: t('enum.credentialMemberState.terminal_failed'),
      count: count(['terminal_failed']),
    },
  ]
  const abandoned = count(['abandoned'])
  if (abandoned > 0) {
    rows.push({
      key: 'abandoned',
      label: t('enum.credentialMemberState.abandoned'),
      count: abandoned,
    })
  }
  return rows
})

const effectiveByAccount = computed(() => {
  const map = {}
  for (const b of props.bindings) map[b.account_id] = b.effective_version_no
  return map
})

// 掛載仍在的成員：卸下的那一台已不由這組秘密登入，不再需要補跑
const isLive = (member) => Object.prototype.hasOwnProperty.call(
  effectiveByAccount.value, member.account_id)

// 整批補跑的對象：失敗、已改未驗證，本輪仍在執行時被授權重驗停止而收束的成員，
// 以及已放棄但未收斂的一輪裡尚未就位的成員
const isRetryable = (member) => RETRYABLE_MEMBER_STATES.includes(member.state)
  || (isRunning.value && RUNNING_RETRYABLE_MEMBER_STATES.includes(member.state))
  || (isUnsettled.value && isLive(member)
    && unsettledMemberRetryable(rotation.value.mode, member.state, member.candidate_kept))

const retryableMembers = computed(() => members.value.filter(isRetryable))

// 目標版本：一輪改密恰建立一個新版本（序號為現有最大值加一），故執行中時
// 目標即現行加一；已結束的輪替以各台實際在用的最高版本為準
const targetVersionNo = computed(() => {
  const inUse = Object.values(effectiveByAccount.value)
  const highest = inUse.length ? Math.max(...inUse) : 0
  // 已放棄但未收斂的整組輪替：待生效版本仍在，目標同執行中
  const pending = isRunning.value || (isUnsettled.value && rotation.value.mode === 'group')
  if (pending) return Math.max(props.currentVersionNo + 1, highest)
  return Math.max(props.currentVersionNo, highest)
})

const versionSummary = computed(() => {
  if (targetVersionNo.value > props.currentVersionNo) {
    return t('credentials.rotation.versionSummary', {
      target: targetVersionNo.value,
      current: props.currentVersionNo,
    })
  }
  return t('credentials.rotation.versionCurrentOnly', { current: props.currentVersionNo })
})

const memberStateTagType = (state) => MEMBER_STATE_TAG_TYPE[state] || 'info'

// 已改未驗證的那一台現在吃哪一組秘密並不確定，故不報版本號
const isHeld = (member) => member.state === 'changed_unverified'

function memberVersionText(member) {
  if (isHeld(member)) return t('credentials.rotation.paused')
  const no = effectiveByAccount.value[member.account_id]
  if (!no) return t('credentials.bindingNoVersion')
  return t('credentials.versionNo', { no })
}

// 逐台補跑另含仍在排隊的成員：服務在推進中途重啟時，沒有任何背景程序會再推進它們
const canRetry = (member) => isRetryable(member)
  || (isRunning.value && RUNNING_RUNNABLE_MEMBER_STATES.includes(member.state))

// 放棄有兩條出口，後果差很多：本輪一台都還沒動過→整輪作廢、憑證回到閒置；
// 已經有主機換到新密碼→不改回、憑證標記不同步、剩餘主機仍要逐台補跑。
// 判準取保守側：只要有任何一個成員離開排隊，就以「已動過」呈現
const rotationTouched = computed(() =>
  members.value.some((member) => member.state !== 'queued'))

const abandonHint = computed(() => (rotationTouched.value
  ? t('credentials.rotation.abandonHint')
  : t('credentials.rotation.abandonHintFresh')))

const abandonMessage = computed(() => (rotationTouched.value
  ? t('credentials.rotation.abandonMessage')
  : t('credentials.rotation.abandonMessageFresh')))

const assetLabel = (member) =>
  member.asset_name || t('common.assetRef', { id: member.asset_id })

// 成員的失敗原因與改密記錄同一組機器碼，走既有的對照表，不另立第二份譯文。
// 查不到的碼原樣顯示——顯示空白會讓「失敗但沒說為什麼」看起來像「沒有原因」
function reasonText(code) {
  if (!code) return ''
  const key = `changeSecretPlans.reason.${code}`
  return te(key) ? t(key) : code
}

function stopPolling() {
  if (pollTimer) {
    clearTimeout(pollTimer)
    pollTimer = null
  }
  polling.value = false
}

const finished = (data) => data?.status && data.status !== 'running'

// 通知外層重新載入：本輪從執行中結束，或補跑後收斂完成
const announceFinish = (data) => finished(data)
  && (sawRunning.value || data.status === 'completed')

function noteStatus(data) {
  if (data?.status === 'running') sawRunning.value = true
}

function schedule() {
  stopPolling()
  if (document.visibilityState === 'hidden') {
    pausedByVisibility.value = true
    return
  }
  polling.value = true
  pollTimer = setTimeout(() => poll(), POLL_INTERVAL_MS)
}

// 單次查詢＋自我排程（沿批次看板慣例）：載入時先查一次，仍在執行才排下一次
async function poll() {
  if (document.visibilityState === 'hidden') {
    stopPolling()
    pausedByVisibility.value = true
    return
  }
  pausedByVisibility.value = false
  try {
    const res = await getCredentialRotation(props.credentialId, props.rotationId)
    rotation.value = res?.data || null
    noteStatus(rotation.value)
  } catch (err) {
    console.error('[CredentialRotation] 查詢改密進度失敗:', err)
    stopPolling()
    return
  }
  if (finished(rotation.value)) {
    stopPolling()
    if (announceFinish(rotation.value)) emit('finished', rotation.value)
    return
  }
  schedule()
}

function onVisibilityChange() {
  if (document.visibilityState === 'hidden') {
    stopPolling()
    pausedByVisibility.value = true
    return
  }
  if (pausedByVisibility.value) {
    pausedByVisibility.value = false
    poll()
  }
}

const HOST_IDENTITY_STOP_CODE = 'CHANGE_SECRET_HOST_IDENTITY_CHANGED'
const TARGET_CHANGED_CODE = 'CHANGE_SECRET_AUTHZ_TARGET_CHANGED'

const hostIdentityDialog = ref({
  visible: false,
  member: null,
  asset: '',
  account: '',
  identity: null,
  submitting: false,
})

function openHostIdentityDialog(member, identity) {
  hostIdentityDialog.value = {
    visible: true,
    member,
    asset: assetLabel(member),
    account: member.username || '',
    identity,
    submitting: false,
  }
}

function closeHostIdentityDialog() {
  hostIdentityDialog.value = { ...hostIdentityDialog.value, visible: false, submitting: false }
}

// 409 的 detail 由後端放在回應本文；對應說明沿用對話框既有文案
const CONFLICT_DETAIL_KEY = {
  not_confirmable: 'hostIdentityConfirm.blocked.contactAdmin',
  different_key_not_accepted: 'hostIdentityConfirm.differentKey.title',
  confirmation_pending: 'hostIdentityConfirm.result.moved',
}

function handleConfirmConflict(err) {
  const detail = err?.response?.data?.detail
  // API 層已關閉此請求的全域錯誤 toast，只由這裡顯示一則（error 等級）
  ElMessage.error(t(CONFLICT_DETAIL_KEY[detail] || 'hostIdentityConfirm.result.moved'))
  closeHostIdentityDialog()
  poll()
}

// quiet：整批補跑時逐台跳成功訊息只是噪音，由呼叫端在結束後報一次
// confirmBody：有值＝帶主機身分確認重送。
// 回傳 false＝請求失敗；'identity'＝回應帶 host_identity（身分變更而停下，尚未改密）；true＝其餘
async function retryMember(member, { quiet = false, confirmBody } = {}) {
  const confirming = !!confirmBody
  retrying.value = true
  try {
    const res = confirming
      ? await retryCredentialRotationMember(
        props.credentialId, props.rotationId, member.id,
        { confirm_host_identity: confirmBody })
      : await retryCredentialRotationMember(
        props.credentialId, props.rotationId, member.id)
    rotation.value = res?.data || rotation.value
    noteStatus(rotation.value)
    const fresh = members.value.find((m) => m.id === member.id)
    const identity = fresh?.host_identity
    if (identity) {
      // 主機身分變更而停下：不當成已補跑，整批補跑時交由呼叫端列入跳過
      if (!quiet) {
        if (confirming) ElMessage.error(t('hostIdentityConfirm.result.moved'))
        openHostIdentityDialog(fresh, identity)
      }
      emit('changed')
      return 'identity'
    }
    if (confirming) {
      closeHostIdentityDialog()
      if (fresh?.last_error === TARGET_CHANGED_CODE) {
        ElMessage.warning(reasonText(fresh.last_error))
      } else if (fresh?.state === 'applied') {
        ElMessage.success(t('hostIdentityConfirm.result.verified'))
      } else {
        // 確認只驗證一次，不會自動再排程
        ElMessage.warning(t('hostIdentityConfirm.result.notVerified'))
      }
    } else if (!quiet) {
      ElMessage.success(t('credentials.rotation.retryDone'))
    }
    emit('changed')
    if (finished(rotation.value)) {
      stopPolling()
      if (announceFinish(rotation.value)) emit('finished', rotation.value)
    }
    return true
  } catch (err) {
    if (confirming && err?.response?.status === 409 &&
        err.response.data?.code === 'CONFLICT_HOST_IDENTITY_MOVED') {
      handleConfirmConflict(err)
      return false
    }
    if (confirming) closeHostIdentityDialog()
    console.error('[CredentialRotation] 補跑失敗:', err)
    return false
  } finally {
    retrying.value = false
  }
}

async function confirmHostIdentity(payload) {
  const member = hostIdentityDialog.value.member
  if (!member) return
  hostIdentityDialog.value = { ...hostIdentityDialog.value, submitting: true }
  await retryMember(member, { confirmBody: payload })
}

// 補跑一次把待補跑的每一台都送完，但**依序**送（await 一台再下一台）：
// 平行送出時任一台卡住會讓其餘結果一起延後，操作者分不出是哪一台在卡。
// 中途失敗即停——剩下的要不要繼續是操作者的判斷，不是這裡替他決定的。
// 因主機身分變更而停下的成員不算失敗：需要逐台確認，不呼叫也不中止，結束時逐台列出
async function retryFailed() {
  const targets = retryableMembers.value.slice()
  skipReport.value = null
  let done = 0
  const skipped = []
  for (const target of targets) {
    const live = members.value.find((m) => m.id === target.id) || target
    if (!canRetry(live)) continue
    if (live.last_error === HOST_IDENTITY_STOP_CODE) {
      skipped.push({ asset: assetLabel(live), key: 'hostIdentitySkipStopped' })
      continue
    }
    const ok = await retryMember(live, { quiet: true })
    if (!ok) return
    if (ok === 'identity') {
      skipped.push({ asset: assetLabel(live), key: 'hostIdentitySkipFoundOnRetry' })
      continue
    }
    done += 1
  }
  if (skipped.length) {
    skipReport.value = { done, items: skipped }
  } else if (done) {
    ElMessage.success(t('credentials.rotation.retryDone'))
  }
}

async function abandon() {
  try {
    await confirmDestructive(
      abandonMessage.value,
      t('credentials.rotation.abandonTitle'),
      { confirmButtonText: t('credentials.rotation.abandonConfirm') },
    )
  } catch {
    return
  }
  abandoning.value = true
  try {
    const res = await abandonCredentialRotation(props.credentialId, props.rotationId)
    rotation.value = res?.data || rotation.value
    stopPolling()
    ElMessage.success(t('credentials.rotation.abandonDone'))
    emit('changed')
    emit('finished', rotation.value)
  } catch (err) {
    console.error('[CredentialRotation] 放棄本輪失敗:', err)
  } finally {
    abandoning.value = false
  }
}

onMounted(() => {
  document.addEventListener('visibilitychange', onVisibilityChange)
  poll()
})

// 卸載後留著的計時器會繼續打 API，而畫面上已經沒有任何東西在等它
onUnmounted(() => {
  document.removeEventListener('visibilitychange', onVisibilityChange)
  stopPolling()
})

defineExpose({
  rotation, poll, stopPolling, polling, pausedByVisibility,
  retryFailed, retryMember, retryableMembers, rotationTouched, isUnsettled,
})
</script>

<style scoped>
.skip-report {
  margin-top: 12px;
}
.skip-line {
  margin: 4px 0 0;
}
.rotation-progress {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-md);
  /* 面板只有 400px 寬：任何子項的最小寬度加起來超過它，整塊就會橫向溢出，
     而溢出的那一側正好是說明文字的結尾 */
  min-width: 0;
}

.progress-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--ot-space-sm);
  flex-wrap: wrap;
}

.progress-meta {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  min-width: 0;
}

.started-by,
.polling-paused {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}

.stat-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(64px, 1fr));
  gap: var(--ot-space-sm);
}

.stat {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--ot-space-xs);
  padding: var(--ot-space-sm);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  background: var(--ot-bg-elevated);
}

.stat-number {
  font-size: var(--ot-font-size-xl);
  font-weight: 600;
  line-height: 1;
}

.stat-applied {
  color: var(--ot-success);
}

.stat-changing {
  color: var(--ot-info);
}

.stat-unverified {
  color: var(--ot-warning);
}

.stat-failed {
  color: var(--ot-danger);
}

.stat-abandoned {
  color: var(--ot-text-disabled);
}

.stat-label {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}

.progress-actions {
  display: flex;
  gap: var(--ot-space-sm);
}

.hint {
  margin: 0;
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-disabled);
  line-height: 1.5;
}

.members-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--ot-space-sm);
}

.section-title {
  font-size: var(--ot-font-size-sm);
  font-weight: 600;
  color: var(--ot-text-primary);
}

.version-summary {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}

.member-list {
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.member-item {
  border-bottom: 1px solid var(--ot-border-subtle);
  padding: var(--ot-space-xs) 0;
}

.member-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 60px auto 40px;
  align-items: center;
  gap: var(--ot-space-sm);
  min-height: 32px;
  font-size: var(--ot-font-size-sm);
}

.member-head {
  min-height: 28px;
  padding-bottom: var(--ot-space-xs);
  border-bottom: 1px solid var(--ot-border-subtle);
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}

.member-asset {
  font-weight: 500;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.mono {
  font-family: var(--ot-font-mono);
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}

.version-held {
  color: var(--ot-warning);
}

.member-reason {
  margin: var(--ot-space-xs) 0 0;
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
  line-height: 1.5;
}

.member-action {
  text-align: right;
}
</style>
