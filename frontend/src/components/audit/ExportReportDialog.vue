<template>
  <el-dialog
    :model-value="modelValue"
    :title="$t('auditorWorkbench.export.title')"
    width="720px"
    data-test="export-dialog"
    @update:model-value="emit('update:modelValue', $event)"
  >
    <div class="export-body">
      <!-- 1. 這份報告涵蓋什麼（範圍即畫面上的範圍，逐項攤開讓使用者自己核對） -->
      <section
        class="ex-block"
        data-test="export-scope"
      >
        <h4>{{ $t('auditorWorkbench.export.scope.title') }}</h4>
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
        </ul>
      </section>

      <!-- 2. 能證明什麼 —— **必須排在邊界之前**（用語紀律）。
           反過來寫，讀者先讀到一串免責，就讀不出這份報告到底能拿來做什麼 -->
      <section
        class="ex-block"
        data-test="export-proves"
      >
        <h4>{{ $t('auditorWorkbench.export.proves.title') }}</h4>
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
        <h4>{{ $t('auditorWorkbench.export.limits.title') }}</h4>
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
        <h4>{{ $t('auditorWorkbench.export.coverage.title') }}</h4>
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
        :title="$t('auditorWorkbench.export.failed')"
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
        {{ submitting
          ? $t('auditorWorkbench.export.generating')
          : $t('auditorWorkbench.export.confirm') }}
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { exportAuditEvidence, getExportSigningPublicKey } from '@/api/auditExport'
import { typeLabel } from './timelineSummary'
import { formatDateTime } from '@/utils/format'
import { downloadBlob, timestampSuffix } from '@/utils/download'

// 工作台的匯出出口。
//
// **匯出＝報告，不是取證**：包內只有事件事實（誰、何時、對哪個資產、做了什麼），
// 剪貼簿內容、傳輸的檔案本體與錄影檔一律不在其中，且三者的原因並不相同：剪貼簿
// 內容仍留存在系統內，只是不隨報告輸出，而畫面上目前也沒有取得內容的入口，需要
// 調閱時走系統管理員；傳輸的檔案本體本系統從未留存（只記檔名、路徑、大小與內容
// 指紋），任何時候都取不到；錄影檔不隨報告輸出，該連線有沒有錄影檔則由報告的錄影
// 狀態逐筆標明（使用者裁決，2026-08-13）。
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
  counts: { type: Object, default: () => ({}) },
  coverage: { type: Array, default: () => [] },
  truncated: { type: Boolean, default: false },
})
const emit = defineEmits(['update:modelValue'])

const { t } = useI18n()

const submitting = ref(false)
const failed = ref(false)
// on＝已啟用簽章｜off＝確認未啟用｜unknown＝問不到，不得推論
const signing = ref('unknown')

// 能證明什麼：碼與順序照抄後端 reportDisclosures 的前半段。
// signature 只在確認已啟用簽章時才列——問不到就不講，寧可少一條也不誆
const proveCodes = computed(() => {
  const codes = ['record_ref', 'scope', 'export_logged']
  if (signing.value === 'on') codes.push('signature')
  return codes
})

// 不能證明什麼：後端 reportDisclosures 的後半段，外加兩條**只在介面上有意義**
// 的補充（truncated_differs 講畫面截斷與報告截斷不同源；coverage_states_detail
// 講 not_retained 的空白與 purged 的空白不是同一件事）
const limitCodes = computed(() => {
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

const typesLine = computed(() =>
  t('auditorWorkbench.export.scope.types', {
    types: props.types.map((type) => typeLabel(type)).join(separator.value),
    n: props.types.length,
  })
)

// 逐類別筆數：counts 是**範圍內的真實總數**（不受單次查詢上限影響），
// 不是畫面上已載入的筆數。報告收錄的也是這個範圍，兩邊對得上
const countsLine = computed(() =>
  t('auditorWorkbench.export.scope.counts', {
    summary: props.types
      .map((type) => `${typeLabel(type)} ${Number(props.counts?.[type]) || 0}`)
      .join(separator.value),
  })
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
    probeSigning()
  },
  { immediate: true }
)

const submit = async () => {
  if (submitting.value) return
  submitting.value = true
  failed.value = false
  try {
    const blob = await exportAuditEvidence(props.params)
    downloadBlob(blob, `audit-event-report-${timestampSuffix()}.zip`)
    emit('update:modelValue', false)
  } catch (_e) {
    // 全域攔截器已 toast 技術原因；此處講的是後果——**沒有拿到任何檔案**。
    // 少了這句，下載沒發生會與「已下載但瀏覽器沒提示」同形
    failed.value = true
  } finally {
    submitting.value = false
  }
}
</script>

<style scoped>
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
</style>
