<template>
  <!-- 單實例守衛常駐橫幅（single-instance-guard）。
       顯示條件：守衛狀態非 held、或偵測到其他守衛版實例連線（peers > 0）。
       **沒有關閉鈕**：守衛刻意沒有停用開關，關閉鈕就是那個開關的 UI 版；
       狀態回到 held 且 peers=0 即自然消失。
       粗狀態由 MainLayout 每 60 秒輪詢不寫審計列的 seal/status 傳入；
       管理者細節走會留審計讀取列的 /instance-guard，只在橫幅出現時取一次
       （與手動重新整理），不輪詢。
       守衛防的是「不知情」，不是「不發生」：文案只陳述偵測到什麼與該做什麼，
       不主張系統會阻止並存造成的資料問題 -->
  <div
    v-if="recovered"
    class="instance-guard-banner is-recovered"
    role="status"
    data-test="guard-recovered"
  >
    <div class="banner-main">
      <el-icon class="banner-icon is-success">
        <CircleCheck />
      </el-icon>
      <div class="banner-text">
        <p class="banner-headline">
          {{ t('instanceGuard.recovered') }}
        </p>
      </div>
    </div>
  </div>
  <div
    v-else-if="visible"
    class="instance-guard-banner"
    role="alert"
    :aria-label="t('instanceGuard.ariaLabel')"
  >
    <div class="banner-main">
      <el-icon class="banner-icon">
        <CircleAlert />
      </el-icon>
      <div class="banner-text">
        <p class="banner-headline">
          {{ headline }}
        </p>
        <!-- 次行：起算時間 · 確認者 · 何時消失。三段以中點串成一行，
             讀者掃一眼就知道「什麼時候開始的、誰按的、要等什麼」 -->
        <p
          class="banner-secondary"
          data-test="banner-secondary"
        >
          {{ secondaryLine }}
        </p>
        <!-- 摘要句對**沒有展開區的讀者**（非管理者）內聯呈現。
             管理者的那一份收進「顯示細節」——常駐橫幅的高度是所有人每頁都要付的成本，
             而細節本來就只給管理者。兩邊讀到的事實相同，只是版位不同 -->
        <p
          v-if="!isAdmin"
          class="banner-summary"
          data-test="banner-summary"
        >
          {{ t(summaryKey) }}
        </p>
      </div>
      <div
        v-if="isAdmin"
        class="banner-actions"
      >
        <el-button
          link
          type="warning"
          size="small"
          class="detail-toggle"
          @click="detailOpen = !detailOpen"
        >
          {{ detailOpen ? t('instanceGuard.detail.hide') : t('instanceGuard.detail.show') }}
        </el-button>
        <el-button
          link
          type="warning"
          size="small"
          class="detail-refresh"
          :loading="detailLoading"
          @click="loadDetail"
        >
          {{ t('common.refresh') }}
        </el-button>
      </div>
    </div>

    <!-- 管理者細節，三欄並排以壓低常駐高度：持鎖者指紋（＋本次啟動的確認碼）／本實例識別／處置與風險 -->
    <div
      v-if="isAdmin && detailOpen"
      class="banner-detail"
    >
      <p
        v-if="detailLoading && !detail"
        class="detail-note"
      >
        {{ t('instanceGuard.detail.loading') }}
      </p>
      <p
        v-if="detailError"
        class="detail-note is-error"
      >
        {{ t('instanceGuard.detail.loadFailed') }}
      </p>
      <div
        v-if="detail"
        class="detail-grid"
      >
        <section class="detail-section">
          <h4>{{ t('instanceGuard.detail.holder') }}</h4>
          <dl v-if="detail.holder">
            <div>
              <dt>application_name</dt>
              <dd class="mono">
                {{ detail.holder.application_name || '-' }}
              </dd>
            </div>
            <div>
              <dt>pid</dt>
              <dd class="mono">
                {{ detail.holder.pid }}
              </dd>
            </div>
            <div>
              <dt>backend_start</dt>
              <dd class="mono">
                {{ detail.holder.backend_start || '-' }}
              </dd>
            </div>
            <div>
              <dt>{{ t('instanceGuard.detail.code') }}</dt>
              <dd class="mono">
                {{ detail.holder.code }}
              </dd>
            </div>
          </dl>
          <p
            v-else
            class="detail-note"
          >
            {{ t('instanceGuard.detail.holderNone') }}
          </p>
          <p
            v-if="detail.holder?.fingerprint_source === 'unavailable'"
            class="detail-note"
          >
            {{ t('instanceGuard.detail.fingerprintUnavailable') }}
          </p>
          <template v-if="detail.ack">
            <dl class="ack-row">
              <div>
                <dt>{{ t('instanceGuard.detail.ack') }}</dt>
                <dd class="mono">
                  {{ detail.ack }}
                </dd>
              </div>
            </dl>
            <p class="detail-note">
              {{ actorSource === 'page' ? t('instanceGuard.detail.ackActorPage', { actor: actorName }) : t('instanceGuard.detail.ackActor') }}
            </p>
          </template>
        </section>
        <section class="detail-section">
          <h4>{{ t('instanceGuard.detail.instance') }}</h4>
          <dl>
            <div>
              <dt>{{ t('instanceGuard.detail.hostname') }}</dt>
              <dd class="mono">
                {{ detail.instance?.hostname || '-' }}
              </dd>
            </div>
            <div>
              <dt>{{ t('instanceGuard.detail.pid') }}</dt>
              <dd class="mono">
                {{ detail.instance?.pid ?? '-' }}
              </dd>
            </div>
            <div>
              <dt>{{ t('instanceGuard.detail.startedAt') }}</dt>
              <dd>{{ formatDateTime(detail.instance?.started_at) }}</dd>
            </div>
            <div>
              <dt>{{ t('instanceGuard.detail.dbSessionPid') }}</dt>
              <dd class="mono">
                {{ detail.db_session_pid ?? '-' }}
              </dd>
            </div>
            <div>
              <dt>{{ t('instanceGuard.detail.lostTotal') }}</dt>
              <dd>{{ detail.lost_total ?? 0 }}</dd>
            </div>
            <div>
              <dt>{{ t('instanceGuard.detail.peers') }}</dt>
              <dd>{{ detail.peers ?? 0 }}</dd>
            </div>
          </dl>
        </section>
        <section class="detail-section detail-guidance">
          <p
            class="detail-summary"
            data-test="banner-summary"
          >
            {{ t(summaryKey) }}
          </p>
          <template v-if="nextStepKey">
            <h4>{{ t('instanceGuard.detail.nextStep') }}</h4>
            <p>{{ t(nextStepKey) }}</p>
          </template>
          <h4>{{ t('instanceGuard.detail.risk') }}</h4>
          <p>{{ t('instanceGuard.detail.riskBody') }}</p>
          <p>{{ t('instanceGuard.boundary') }}</p>
        </section>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { CircleAlert, CircleCheck } from 'lucide-vue-next'
import { getInstanceGuard } from '@/api/instanceGuard'
import { formatDateTime } from '@/utils/format'

const props = defineProps({
  // seal/status 的 instance_guard 粗狀態：{ state, since, reason, peers }；null＝尚未取得
  status: { type: Object, default: null },
  // 由 MainLayout 傳入（`isAdmin`）：管理者才取細節端點（每次呼叫留一列審計讀取）
  isAdmin: { type: Boolean, default: false },
})

const { t, te } = useI18n()

// 顯示條件：非 held、或偵測到對等連線（與 seal/status 粗狀態的語義對齊）。
// state 為空字串＝後端尚未建立守衛（只在單測／佔位探針出現）：無事可報就不顯示，
// 避免一個沒有任何資訊的假警示
const visible = computed(() => {
  const s = props.status
  if (!s || !s.state) return false
  return s.state !== 'held' || (s.peers ?? 0) > 0
})

// 取回鎖的一次性成功提示：**只在本次載入中由警示轉為正常時出現**，
// 重新整理即消失（`wasVisible` 是元件狀態，不持久化）。
// 一開始就是 held＋peers=0 的正常情形不顯示任何東西——那是絕大多數的載入，
// 對它們貼一則「已取回」只是噪音。
// 用 `role="status"` 而非 `role="alert"`：狀態回復是報平安，不是需要打斷的警示
const wasVisible = ref(false)
const recovered = ref(false)

// `immediate` 是必要的：橫幅在**掛載當下**就已經是可見的（守衛狀態早於本元件），
// 少了它 `wasVisible` 永遠不會被設起來，鎖取回時就什麼都不顯示
watch(
  visible,
  (now) => {
    if (now) {
      wasVisible.value = true
      recovered.value = false
      return
    }
    if (wasVisible.value) recovered.value = true
  },
  { immediate: true }
)

// 確認者（`actor`／`actor_source` 來自細節端點）。橫幅次行要回答「誰按的」——
// 環境變數路徑本來就識別不了自然人，故顯示「環境變數」而不是捏造一個名字
const actorSource = computed(() => detail.value?.actor_source || '')
const actorName = computed(() => detail.value?.actor || '')
const actorText = computed(() => {
  if (actorSource.value === 'env') return t('instanceGuard.actorEnv')
  return actorName.value
})

// 次行＝起算時間 · 確認者（有才顯示）· 取回鎖後自動消失
const secondaryLine = computed(() => {
  const parts = []
  if (props.status?.since) {
    parts.push(t(sinceKey.value, { time: formatDateTime(props.status.since) }))
  }
  if (actorText.value) parts.push(t('instanceGuard.actorLabel', { actor: actorText.value }))
  parts.push(t('instanceGuard.clearsOnRetake'))
  return parts.join(' · ')
})

// reason 走 locale 查表；後端若送出未知碼則原樣顯示（不吞資訊）
const reasonText = (reason) => {
  const key = `instanceGuard.reason.${reason || 'unknown'}`
  return te(key) ? t(key) : reason
}

// `since` 是「目前狀態的起始時間」：overridden／lost 時就是狀態發生的時刻，「自 … 起」讀得通；
// 但持鎖實例（held＋peers）的 since 是本實例取得鎖的時刻，不是偵測到對等的時刻
//（後端沒有那個欄位，前端不捏造），標籤改說「本實例持鎖自 … 起」以免被讀成偵測時間
const sinceKey = computed(() =>
  props.status?.state === 'held' ? 'instanceGuard.sinceHeld' : 'instanceGuard.since'
)

const headline = computed(() => {
  const s = props.status
  if (!s) return ''
  if (s.state === 'overridden') return t('instanceGuard.headline.overridden')
  if (s.state === 'lost') {
    return t('instanceGuard.headline.lost', { reason: reasonText(s.reason) })
  }
  if (s.state === 'held') {
    return t('instanceGuard.headline.peers', { n: s.peers }, s.peers)
  }
  return t('instanceGuard.headline.other', { state: s.state })
})

// 摘要句依狀態分流。預設句說的是「可能有另一個實例在用同一個資料庫」，
// 但 `lost{db_unreachable}` 態根本沒有另一個實例的跡象——守衛只是連不上資料庫、
// 確認不了鎖的狀態。對這一態沿用預設句會把讀者往「去找另一個實例」的方向送，
// 而該找的是資料庫連線
const summaryKey = computed(() => {
  const s = props.status
  if (s?.state === 'lost' && s?.reason === 'db_unreachable') {
    return 'instanceGuard.summaryUnreachable'
  }
  return 'instanceGuard.summary'
})

// 處置句依狀態分流：他人持鎖（overridden／lost{contention}）→ 確認另一實例已停止；
// 資料庫不可達 → 等連線恢復；永久／未知 → 查權限與日誌；持鎖但有對等 → 確認對方是否該存在
const nextStepKey = computed(() => {
  const s = props.status
  if (!s) return ''
  if (s.state === 'overridden') return 'instanceGuard.detail.nextStepHolder'
  if (s.state === 'lost') {
    if (s.reason === 'contention') return 'instanceGuard.detail.nextStepHolder'
    if (s.reason === 'db_unreachable') return 'instanceGuard.detail.nextStepUnreachable'
    return 'instanceGuard.detail.nextStepPermanent'
  }
  if (s.state === 'held') return 'instanceGuard.detail.nextStepPeers'
  return ''
})

// 管理者細節：只在橫幅出現時取一次（那條端點每次呼叫留一列審計讀取，所以不輪詢）；
// 「重新整理」手動再取。
// 失敗在橫幅內誠實呈現、不走全域 toast（skipErrorToast）——常駐橫幅每次出現就彈一個
// toast 只會把「守衛有事」淹沒在「細節取不到」裡
const detail = ref(null)
const detailLoading = ref(false)
const detailError = ref(false)
// **預設收合**（設計裁決：細節收進展開區）：常駐橫幅的高度是每個人每一頁都要付的
// 成本，而指紋、確認碼、本實例識別是「決定要不要動手時才去讀」的資料，不是每頁都要看的。
// 管理者亦同——預設展開會讓一句標題的橫幅長成半個畫面高。細節仍在橫幅出現時取一次
//（次行的確認者來自同一份資料），只是不攤開
const detailOpen = ref(false)

const loadDetail = async () => {
  detailLoading.value = true
  detailError.value = false
  try {
    detail.value = await getInstanceGuard({ skipErrorToast: true })
  } catch {
    detailError.value = true
  } finally {
    detailLoading.value = false
  }
}

watch(
  () => visible.value && props.isAdmin,
  (shouldLoad) => {
    if (shouldLoad) {
      loadDetail()
    } else {
      // 橫幅消失即丟棄細節：再次出現代表狀態變了，舊指紋不可沿用
      detail.value = null
      detailError.value = false
    }
  },
  { immediate: true }
)
</script>

<style scoped>
.instance-guard-banner {
  flex-shrink: 0;
  padding: var(--ot-space-sm) var(--ot-space-lg);
  /* 警示語意走 --ot-warning 家族（不是品牌色）；底色以 token 混色，不寫死色值。
     不認得 color-mix 的瀏覽器（Chrome 111／Safari 16.2／Firefox 113 之前）會略過
     混色那一行、退回前一行的純 token：底色少了琥珀色調，icon、標題與底線仍是警示色 */
  background-color: var(--ot-bg-elevated);
  background-color: color-mix(in srgb, var(--ot-warning) 14%, var(--ot-bg-surface));
  border-bottom: 1px solid var(--ot-warning);
  border-bottom: 1px solid color-mix(in srgb, var(--ot-warning) 50%, transparent);
  color: var(--ot-text-primary);
  font-size: var(--ot-font-size-md);
}

.banner-main {
  display: flex;
  align-items: flex-start;
  gap: var(--ot-space-sm);
}

.banner-icon {
  flex-shrink: 0;
  margin-top: 2px;
  font-size: 20px;
  color: var(--el-color-warning);
}

.banner-text {
  flex: 1;
  min-width: 0;
}

.banner-headline {
  margin: 0;
  font-weight: 600;
}

/* 取回鎖的一次性提示：正常語意，不套警示色 */
.instance-guard-banner.is-recovered {
  background-color: var(--ot-bg-surface);
  border-bottom: 1px solid var(--ot-border-subtle);
}

.banner-icon.is-success {
  color: var(--el-color-success);
}

.detail-summary {
  margin: 0 0 var(--ot-space-xs);
}

.banner-secondary {
  margin: 2px 0 0;
  font-size: var(--ot-font-size-sm);
  font-weight: 400;
  color: var(--ot-text-secondary);
}

.banner-summary {
  margin: 2px 0 0;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.banner-actions {
  display: flex;
  flex-shrink: 0;
  align-items: center;
  gap: var(--ot-space-xs);
}

.banner-detail {
  margin-top: var(--ot-space-sm);
  padding-top: var(--ot-space-sm);
  border-top: 1px solid var(--ot-border-subtle);
  font-size: var(--ot-font-size-sm);
  line-height: 1.5;
}

.detail-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: var(--ot-space-sm) var(--ot-space-lg);
}

.detail-section {
  min-width: 0;
}

.detail-section h4 {
  margin: 0 0 var(--ot-space-xs);
  font-size: var(--ot-font-size-sm);
  font-weight: 600;
  color: var(--el-color-warning);
}

.detail-guidance h4 + p + h4,
.detail-guidance p + h4 {
  margin-top: var(--ot-space-sm);
}

.detail-section dl {
  display: grid;
  /* 標籤欄最多佔一半：長標籤自己折行，不把值欄擠到連一個日期都放不下 */
  grid-template-columns: fit-content(50%) minmax(0, 1fr);
  gap: 2px var(--ot-space-md);
  margin: 0;
}

.detail-section dl.ack-row {
  margin-top: var(--ot-space-sm);
}

.detail-section dl > div {
  display: contents;
}

.detail-section dt {
  color: var(--ot-text-secondary);
}

.detail-section dd {
  margin: 0;
}

/* 只有指紋類長字串（application_name／確認碼／backend_start／主機名）沒有空白可折，
   才逐字元斷；時間與計數值照一般規則只在空白處折，日期不會被從中間切開 */
.detail-section dd.mono {
  word-break: break-all;
}

.mono {
  font-family: var(--ot-font-mono);
}

.detail-section p {
  margin: 0;
}

.detail-note {
  margin: var(--ot-space-xs) 0 0;
  color: var(--ot-text-secondary);
}

.detail-note.is-error {
  color: var(--el-color-danger);
}
</style>
