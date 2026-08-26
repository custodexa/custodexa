<template>
  <el-dialog
    :model-value="modelValue"
    :title="$t('auditorWorkbench.export.title')"
    width="720px"
    data-test="export-dialog"
    @update:model-value="emit('update:modelValue', $event)"
  >
    <div class="export-body">
      <!-- 0. 要哪一種包。**先選才看得懂下面每一句**：陳述與證物、同步與非同步，
           兩種包的能證明／不能證明各不相同，聲明段隨選擇整組換掉 -->
      <section
        class="ex-block"
        data-test="export-pack"
      >
        <h4>{{ $t('auditorWorkbench.export.pack.label') }}</h4>
        <el-radio-group
          v-model="packType"
          data-test="export-pack-type"
        >
          <el-radio
            value="event_report"
            data-test="export-pack-event_report"
          >
            {{ $t('auditorWorkbench.export.pack.event_report') }}
            <span class="pack-hint">{{ $t('auditorWorkbench.export.pack.eventReportHint') }}</span>
          </el-radio>
          <el-radio
            value="evidence_bundle"
            data-test="export-pack-evidence_bundle"
          >
            {{ $t('auditorWorkbench.export.pack.evidence_bundle') }}
            <span class="pack-hint">{{
              $t('auditorWorkbench.export.pack.evidenceBundleHint')
            }}</span>
          </el-radio>
        </el-radio-group>
        <p
          class="pack-diff"
          data-test="export-pack-diff"
        >
          {{ $t('auditorWorkbench.export.pack.diff') }}
        </p>
      </section>

      <!-- 1. 這一包涵蓋什麼（範圍即畫面上的範圍，逐項攤開讓使用者自己核對） -->
      <section
        class="ex-block"
        data-test="export-scope"
      >
        <h4>{{ sectionTitle('scope') }}</h4>
        <ul>
          <li data-test="export-scope-subject">
            {{ subjectLine }}
          </li>
          <li data-test="export-scope-window">
            {{ windowLine }}
          </li>
          <li data-test="export-scope-types">
            {{ typesLine }}
          </li>
          <li data-test="export-scope-counts">
            {{ countsLine }}
          </li>
          <li
            v-if="ipFiltered"
            class="scope-caveat"
            data-test="export-scope-ip-filter"
          >
            {{ $t('auditorWorkbench.export.ipFilterExcluded') }}
          </li>
        </ul>
      </section>

      <!-- 2. 能證明什麼 —— **必須排在邊界之前**（用語紀律）。
           反過來寫，讀者先讀到一串免責，就讀不出這份報告到底能拿來做什麼 -->
      <section
        class="ex-block"
        data-test="export-proves"
      >
        <h4>{{ sectionTitle('proves') }}</h4>
        <ul>
          <li
            v-for="code in proveCodes"
            :key="code"
            :data-test="`export-proves-${code}`"
          >
            {{ $t(`auditorWorkbench.export.proves.${code}`) }}
          </li>
        </ul>
      </section>

      <!-- 3. 不能證明什麼（每條含情境與由什麼承擔） -->
      <section
        class="ex-block"
        data-test="export-limits"
      >
        <h4>{{ sectionTitle('limits') }}</h4>
        <ul>
          <li
            v-for="code in limitCodes"
            :key="code"
            :data-test="`export-limit-${code}`"
          >
            {{ $t(`auditorWorkbench.export.limit.${code}`) }}
          </li>
        </ul>
      </section>

      <!-- 4. 逐類別的留存狀況：purged 與 not_retained 在此各說各話。
           兩者若被壓成同一句，本功能要消滅的誤讀就原地復活 -->
      <section
        class="ex-block"
        data-test="export-coverage"
      >
        <h4>{{ sectionTitle('coverage') }}</h4>
        <ul>
          <li
            v-for="line in coverageLines"
            :key="line.type"
            :data-test="`export-coverage-${line.state}-${line.type}`"
          >
            <strong>{{ line.category }}</strong>
            <span>{{ line.text }}</span>
          </li>
        </ul>
      </section>

      <!-- 5. 簽章狀態：下載**之前**就要知道拿到的會不會是可獨立驗證的一份 -->
      <el-alert
        v-if="signing === 'off'"
        type="warning"
        :closable="false"
        show-icon
        data-test="export-unsigned"
        :title="$t('auditorWorkbench.export.unsigned.title')"
        :description="$t('auditorWorkbench.export.unsigned.body')"
      />
      <el-alert
        v-else-if="signing === 'unknown'"
        type="info"
        :closable="false"
        show-icon
        data-test="export-signing-unknown"
        :title="$t('auditorWorkbench.export.signingUnknown')"
      />

      <el-alert
        v-if="failed"
        type="error"
        :closable="false"
        show-icon
        data-test="export-failed"
        :title="isBundle
          ? $t('auditorWorkbench.export.bundleFailed')
          : $t('auditorWorkbench.export.failed')"
      />
    </div>

    <template #footer>
      <el-button
        data-test="export-cancel"
        @click="emit('update:modelValue', false)"
      >
        {{ $t('auditorWorkbench.export.cancel') }}
      </el-button>
      <el-button
        type="primary"
        :loading="submitting"
        data-test="export-confirm"
        @click="submit"
      >
        {{ confirmLabel }}
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import {
  createAuditExportJob,
  exportAuditEvidence,
  getExportSigningPublicKey,
} from '@/api/auditExport'
import { typeLabel } from './timelineSummary'
import { formatDateTime } from '@/utils/format'
import { downloadBlob, timestampSuffix } from '@/utils/download'

// 工作台的匯出出口（兩種包型）。
//
// **事件報告＝陳述、證據包＝證物**，兩者連交付形態都不同（同步直下 vs 背景打包
// 後於下載中心限時取件）。以下整段原文寫的是事件報告，那些話對證據包**逐句為假**
// （證據包正是含錄影檔本體與剪貼簿內容的那一種）——故聲明段不共用，隨包型整組換掉。
//
// **兩種包型都套用類別篩選**（後端 4b.1 起：`pack=evidence_bundle` ＋ subject ＋
// types，`parseExportBundleScope`）。發起時**必須明示 `pack`**——證據包也吃樞紐之後，
// 舊的「帶 subject 即事件報告」推斷會把這個請求判成報告並以
// `RULE_EXPORT_JOB_BUNDLE_ONLY` 當場拒絕。過渡期的「證據包不套用類別篩選」
// 文案已隨之退場：那句話現在是假的，留著會讓稽核多篩一輪或改選錯的包型。
//
// **匯出＝報告，不是取證**：以下三段講的是事件報告——包內只有事件事實（誰、何時、對哪個資產、做了什麼），
// 剪貼簿內容、傳輸的檔案本體與錄影檔一律不在其中，且三者的原因並不相同：剪貼簿
// 內容仍留存在系統內，只是不隨報告輸出，**要內容本身有兩條真實途徑**——會話詳情
// 的逐筆解密調閱（`GET /sessions/:id/clipboard-events/:eventID/content`）與證據包
// （收錄解密全文），兩者都自帶調閱紀錄；傳輸的檔案本體本系統從未留存（只記檔名、
// 路徑、大小與內容指紋），任何時候都取不到；錄影檔不隨報告輸出，該連線有沒有錄影檔
// 則由報告的錄影狀態逐筆標明，影像本體同樣走證據包（使用者裁決，2026-08-13）。
//
// 原文曾寫「畫面上沒有取得內容的入口，請向系統管理員提出」——那兩條途徑上線後
// 那句話就成了假話，會把稽核推去走一條不存在的流程（驗收訂正）。
//
// **範圍＝畫面上的範圍**：送出的 params 由父層以與時間軸查詢同一組 ref 算出，
// 對話框自己不另組條件。使用者按下去拿到的，必須就是他正在看的那一段。
//
// **誠實邊界在按下之前呈現**：manifest 要等包產生出來才讀得到，那時使用者
// 已經拿到檔案了。故本對話框在按下匯出前就把同一組聲明講完；聲明的碼與順序
// 對齊後端 `reportDisclosures`（`audit_export_report.go`），文字則是三語 i18n
// 的同一組鍵——包裡與畫面上讀到的是同一句話。
const props = defineProps({
  modelValue: { type: Boolean, default: false },
  // params 送出的查詢參數（父層提供，與時間軸查詢同源）
  params: { type: Object, required: true },
  subject: { type: String, default: 'user' },
  subjectName: { type: String, default: '' },
  from: { type: String, default: '' },
  to: { type: String, default: '' },
  types: { type: Array, default: () => [] },
  // pack 開啟時預選哪一種包型（工具列兩顆按鈕各自帶一個值）。
  // radio 仍可切——預選是省一次點擊，不是把另一種包鎖起來
  pack: { type: String, default: 'event_report' },
  counts: { type: Object, default: () => ({}) },
  coverage: { type: Array, default: () => [] },
  truncated: { type: Boolean, default: false },
  // 畫面上是否套著來源位址篩選。匯出端點沒有這個參數，故範圍是**篩選前**的
  // 全部紀錄——不明說，使用者會以為拿到的是他正在看的那一小段。
  // 同時切換筆數那一行的口徑（counts 是篩選後的數字，見 countsLine）
  ipFiltered: { type: Boolean, default: false },
})
const emit = defineEmits(['update:modelValue'])

const { t } = useI18n()
const router = useRouter()

const submitting = ref(false)
const failed = ref(false)
// on＝已啟用簽章｜off＝確認未啟用｜unknown＝問不到，不得推論
const signing = ref('unknown')

// 包型：event_report（同步直下）｜evidence_bundle（發起 job）。
// 初值取自 props.pack——使用者按的是哪一顆按鈕，開起來就停在哪一種包，
// 不必再點一次 radio；沒有指定時退回事件報告（體積可控、立即拿到手）
const packType = ref(props.pack)
const isBundle = computed(() => packType.value === 'evidence_bundle')

// 能證明什麼：事件報告的碼與順序照抄後端 reportDisclosures 的前半段；
// 證據包另有一組（它承載的是證物，不是陳述）。
// signature 只在確認已啟用簽章時才列——問不到就不講，寧可少一條也不誆
const proveCodes = computed(() => {
  if (isBundle.value) {
    const codes = ['bundle_contents', 'bundle_scope', 'bundle_logged']
    if (signing.value === 'on') codes.push('bundle_signature')
    return codes
  }
  const codes = ['record_ref', 'scope', 'export_logged']
  if (signing.value === 'on') codes.push('signature')
  return codes
})

// 不能證明什麼：後端 reportDisclosures 的後半段，外加兩條**只在介面上有意義**
// 的補充（truncated_differs 講畫面截斷與報告截斷不同源；coverage_states_detail
// 講 not_retained 的空白與 purged 的空白不是同一件事）。
//
// 證據包那組**不是報告那組的子集**：它含明文與錄影本體（保管責任）、走非同步
// （何時才拿得到）、綁申請者本人（別人拿不到）、只收勾選的類別（未勾選者整段
// 不入包）。這四條在報告那組裡一條都沒有，反過來報告的 payload_excluded 對它為假
const limitCodes = computed(() => {
  if (isBundle.value) {
    const codes = [
      'bundle_plaintext',
      'bundle_async',
      'bundle_requester_only',
      'bundle_category_scope',
      'bundle_clipboard_gap',
      'bundle_scope_is_query_range',
    ]
    if (props.truncated) codes.push('bundle_truncated_differs')
    codes.push('bundle_manifest_required', 'bundle_no_offline_tool')
    if (props.subject === 'asset') codes.push('asset_scope')
    return codes
  }
  const codes = ['scope_is_query_range']
  if (props.truncated) codes.push('truncated_differs')
  codes.push(
    'payload_excluded',
    'coverage_states',
    'coverage_states_detail',
    'recording_state',
    'manifest_required',
    'no_offline_tool'
  )
  if (props.subject === 'asset') codes.push('asset_scope')
  return codes
})

// 段落標題也得跟著換：證據包不是「報告」，四段標題留著「這份報告」
// 就是在對取件者描述另一種東西
const sectionTitle = (section) =>
  t(`auditorWorkbench.export.${section}.${isBundle.value ? 'titleBundle' : 'title'}`)

const confirmLabel = computed(() => {
  if (isBundle.value) {
    return submitting.value
      ? t('auditorWorkbench.export.bundleSubmitting')
      : t('auditorWorkbench.export.bundleConfirm')
  }
  return submitting.value
    ? t('auditorWorkbench.export.generating')
    : t('auditorWorkbench.export.confirm')
})

const separator = computed(() => t('auditorWorkbench.export.separator'))

const subjectLine = computed(() =>
  t(
    props.subject === 'asset'
      ? 'auditorWorkbench.export.scope.subjectAsset'
      : 'auditorWorkbench.export.scope.subjectUser',
    { name: props.subjectName }
  )
)

const windowLine = computed(() =>
  t('auditorWorkbench.export.scope.window', {
    from: formatDateTime(props.from),
    to: formatDateTime(props.to),
  })
)

// 類別：預填**照原樣呈現**（使用者剛才篩過什麼，這裡就寫什麼），
// 且兩種包型**都真的照這個範圍收錄**（後端 4b.1 起證據包也套類別），
// 故兩者共用同一句——不再需要「對這個包型不生效」的但書
const typesLine = computed(() =>
  t('auditorWorkbench.export.scope.types', {
    types: props.types.map((type) => typeLabel(type)).join(separator.value),
    n: props.types.length,
  })
)

// 逐類別筆數：counts 是**範圍內的真實總數**（不受單次查詢上限影響），
// 不是畫面上已載入的筆數。報告收錄的也是這個範圍，兩邊對得上。
//
// **例外是位址篩選**：counts 由時間軸查詢帶回，該查詢送了 `client_ip`，
// 所以套著位址篩選時這些數字是**篩選後**的；而匯出端點沒有這個參數
//（`exportParams` 不帶 client_ip），報告收的是篩選前的全部紀錄。
// 兩者放在同一段而不標明口徑，數字與範圍會互相否定——故篩選中改用
// 另一句標題把數字的口徑講死，兩者的關係由下一行的但書收束
const countsLine = computed(() =>
  t(
    props.ipFiltered
      ? 'auditorWorkbench.export.scope.countsIpFiltered'
      : 'auditorWorkbench.export.scope.counts',
    {
      summary: props.types
        .map((type) => `${typeLabel(type)} ${Number(props.counts?.[type]) || 0}`)
        .join(separator.value),
    }
  )
)

const purgedText = (entry) => {
  // 三個佐證值由後端在 state=purged 時一併給出（清除水準線本身就帶著它們）。
  // 缺值時句子會少掉那個數字，但語義不變——不因缺值而改說成別的意思
  const parts = [
    t('auditorWorkbench.export.coverage.purged', {
      policy_days: entry.policy_days ?? '',
      purged_through_at: formatDateTime(entry.purged_through_at),
      last_purge_at: formatDateTime(entry.last_purge_at),
    }),
  ]
  if (entry.checkpoint_seq_range) {
    parts.push(
      t('auditorWorkbench.export.coverage.purgedCheckpoints', {
        archive_unit_from: entry.checkpoint_seq_range.from,
        archive_unit_to: entry.checkpoint_seq_range.to,
      })
    )
  }
  if (entry.partial) parts.push(t('auditorWorkbench.export.coverage.purgedPartial'))
  return parts.join('')
}

// 逐類別留存狀況蓋住**這一包實際收錄的類別**＝勾選中的那幾類。
// 兩種包型同一組（4b.1 起證據包也依類別收錄）：多列未收錄的類別，
// 會讓讀者以為包內有那一類的證物、只是被清掉了
const coverageLines = computed(() =>
  props.types.map((type) => {
    const entry = props.coverage?.find((c) => c.type === type) || {}
    const state = entry.state || 'present'
    const text =
      state === 'purged'
        ? purgedText(entry)
        : t(`auditorWorkbench.export.coverage.${state}`)
    return { type, state, category: typeLabel(type), text }
  })
)

// 簽章狀態的探詢：取得到驗證金鑰＝已啟用；端點不存在（404）＝未啟用。
// 其餘失敗（斷線、逾時、權限）**維持 unknown**——把「問不到」講成「未啟用」
// 是在造一個系統從沒說過的事實
const probeSigning = async () => {
  signing.value = 'unknown'
  try {
    const res = await getExportSigningPublicKey()
    signing.value = res?.data?.public_key ? 'on' : 'off'
  } catch (error) {
    signing.value = error?.response?.status === 404 ? 'off' : 'unknown'
  }
}

watch(
  () => props.modelValue,
  (open) => {
    if (!open) return
    failed.value = false
    // 每次開啟回到**這一次的入口所指定的包型**：上一次在對話框內切過證據包
    // 就一直停在證據包，下一次從「匯出事件報告」進來的「按下即下載」預期會落空
    packType.value = props.pack
    probeSigning()
  },
  { immediate: true }
)

// 證據包的發起參數：**父層那組原樣送出，只多帶一個 `pack`**。
// 樞紐（subject＋user_id／asset_id）、起訖時間與類別全帶，範圍與畫面同一段。
//
// `pack=evidence_bundle` 是必要而非裝飾：證據包也吃樞紐之後，後端缺席 `pack`
// 時的舊推斷（帶 subject＝事件報告）會把這個請求判成報告，job 端點當場以
// `RULE_EXPORT_JOB_BUNDLE_ONLY` 拒絕。
//
// 刻意是**加法**而非白名單：父層日後多帶一個範圍參數時，白名單會靜默把它丟掉
//（範圍與畫面不符，沒人看得出來），原樣送出則是由後端當場拒絕——吵鬧勝過靜默
const bundleParams = computed(() => ({
  ...(props.params || {}),
  pack: 'evidence_bundle',
}))

const submitReport = async () => {
  const blob = await exportAuditEvidence(props.params)
  downloadBlob(blob, `audit-event-report-${timestampSuffix()}.zip`)
}

// 證據包：發起後**導引至下載中心**。留在原地會讓使用者以為什麼都沒發生——
// 這一按沒有檔案落下來，唯一的證據是下載中心多了一列
const submitBundle = async () => {
  const res = await createAuditExportJob(bundleParams.value)
  ElMessage.success(
    res?.deduplicated
      ? t('auditorWorkbench.export.bundleDeduplicated')
      : t('auditorWorkbench.export.bundleQueued')
  )
  await router.push('/audit/exports')
}

const submit = async () => {
  if (submitting.value) return
  submitting.value = true
  failed.value = false
  try {
    if (isBundle.value) {
      await submitBundle()
    } else {
      await submitReport()
    }
    emit('update:modelValue', false)
  } catch (_e) {
    // 全域攔截器已 toast 技術原因；此處講的是後果——事件報告是**沒有拿到任何檔案**，
    // 證據包是**沒有建立任何打包工作**。少了這句，失敗會與「成功但瀏覽器沒提示」同形
    failed.value = true
  } finally {
    submitting.value = false
  }
}
</script>

<style scoped>
/* 範圍段裡的但書：與其他項目同層級，但要看得出它在收窄讀者的預期 */
.scope-caveat {
  color: var(--ot-warning);
}

.export-body {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-md);
  max-height: 60vh;
  overflow-y: auto;
}

.ex-block h4 {
  margin: 0 0 var(--ot-space-xs);
  font-size: var(--ot-font-size-md);
  color: var(--ot-text-primary);
}

.ex-block ul {
  margin: 0;
  padding-left: var(--ot-space-lg);
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
}

.ex-block li {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
  line-height: 1.6;
}

.ex-block strong {
  color: var(--ot-text-primary);
  margin-right: var(--ot-space-xs);
}

/* 包型：兩個選項各自帶一句用途，選之前就看得出差別。
   EP 的 el-radio 預設 nowrap 且橫排，帶說明句時會被裁掉，故直排並解除 nowrap */
.ex-block :deep(.el-radio-group) {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: var(--ot-space-xs);
  width: 100%;
}

.ex-block :deep(.el-radio) {
  height: auto;
  margin-right: 0;
  white-space: normal;
  align-items: flex-start;
}

.pack-hint {
  display: block;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
  font-weight: normal;
  line-height: 1.5;
}

.pack-diff {
  margin: var(--ot-space-xs) 0 0;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
  line-height: 1.6;
}
</style>
