<template>
  <div
    v-loading="loading"
    class="compliance-map"
  >
    <PageHeader
      :title="$t('menu.complianceMap')"
      :description="$t('complianceMap.headerDesc')"
    >
      <template #actions>
        <!-- 這一頁呈現的是帶時點的判定快照；沒有重新整理，讀者看到過期畫面時
             只能重新導航一次 -->
        <el-button
          :loading="loading"
          data-test="compliance-refresh"
          @click="load()"
        >
          {{ $t('common.refresh') }}
        </el-button>
        <!-- 停用態的入口仍要說得出「為什麼按不下去」：
             title 掛在外層 span，停用的按鈕本身收不到滑鼠事件 -->
        <span
          class="report-slot"
          :title="$t('complianceMap.generateReportDisabled')"
        >
          <el-button disabled>
            {{ $t('complianceMap.generateReport') }}
          </el-button>
        </span>
      </template>
    </PageHeader>

    <div class="chip-row">
      <span class="chip-label">{{ $t('complianceMap.groupsTitle') }}</span>
      <span
        v-for="group in groups"
        :key="group.code"
        class="group-chip"
      >
        <el-button
          size="small"
          round
          :type="group.code === activeGroup ? 'primary' : ''"
          :disabled="!group.enabled"
          @click="activeGroup = group.code"
        >
          {{ group.name }}
          <span
            v-if="!group.enabled"
            class="chip-inactive"
          >{{ $t('complianceMap.groupInactive') }}</span>
        </el-button>
      </span>
      <span class="built-at">
        {{ $t('complianceMap.builtAt') }} {{ formatDateTime(snapshot.built_at) }}
        <span class="built-at-timezone">{{ $t('complianceMap.timezone', { tz: timezone }) }}</span>
      </span>
    </div>

    <div
      v-if="!activeGroup"
      class="panel"
    >
      <EmptyState
        :title="$t('complianceMap.noGroupTitle')"
        :hint="$t('complianceMap.noGroupHint')"
      />
    </div>

    <div
      v-else
      class="layout"
    >
      <div class="main-column">
        <!-- 摘要分兩組：上排以條計、下排以項計。混在一排時 40 條與 3 項設定
             長得一樣，稽核會把不同單位的數字相加 -->
        <div class="panel summary-panel">
          <div
            v-for="group in summaryGroups"
            :key="group.key"
            class="summary-group"
          >
            <div class="summary-group-title">
              {{ group.title }}
            </div>
            <div class="summary-grid">
              <div
                v-for="cell in group.cells"
                :key="cell.key"
                class="summary-cell"
                :data-test="`summary-${cell.key}`"
                :title="cell.hint"
              >
                <span class="summary-value">
                  {{ cell.value }}<span class="summary-unit">{{ group.unit }}</span>
                </span>
                <span class="summary-label">{{ cell.label }}</span>
                <span
                  v-if="cell.note"
                  class="summary-note"
                >{{ cell.note }}</span>
              </div>
            </div>
          </div>
          <p class="unmapped-note">
            {{ $t('complianceMap.unmappedNote', { n: unmappedCount }) }}
          </p>
        </div>

        <div class="panel">
          <div class="panel-head">
            <span class="panel-title">{{ $t('complianceMap.clausesTitle') }}</span>
            <!-- 設定名稱搜尋：只知道設定叫什麼的稽核人員，不必猜它寫在哪一條。
                 命中即展開所屬條文並標出該列，條文清單本身不被篩掉 -->
            <span class="clause-search">
              <el-input
                v-model="searchInput"
                size="small"
                class="search-input"
                :placeholder="$t('complianceMap.searchPlaceholder')"
                :aria-label="$t('complianceMap.searchLabel')"
                data-test="setting-search"
                @keyup.enter="applySearch"
              />
              <el-button
                size="small"
                data-test="setting-search-submit"
                @click="applySearch"
              >
                {{ $t('common.search') }}
              </el-button>
              <el-button
                size="small"
                data-test="setting-search-reset"
                @click="resetSearch"
              >
                {{ $t('common.reset') }}
              </el-button>
              <span class="only-deviating">
                <el-button
                  size="small"
                  :type="onlyDeviating ? 'primary' : ''"
                  @click="onlyDeviating = !onlyDeviating"
                >
                  {{ $t('complianceMap.onlyDeviating') }}
                </el-button>
              </span>
            </span>
          </div>

          <p
            v-if="searchQuery"
            class="search-note"
            data-test="setting-search-note"
          >
            {{ matchedKeys.size > 0
              ? $t('complianceMap.searchHit', { n: matchedKeys.size })
              : $t('complianceMap.searchNoMatch') }}
          </p>

          <EmptyState
            v-if="visibleClauses.length === 0"
            :title="onlyDeviating
              ? $t('complianceMap.emptyDeviating')
              : $t('complianceMap.emptyTitle')"
            :hint="onlyDeviating ? '' : $t('complianceMap.emptyHint')"
          />

          <el-collapse
            v-else
            v-model="openClauses"
          >
            <el-collapse-item
              v-for="clause in visibleClauses"
              :key="clause.clause_no"
              :name="clause.clause_no"
            >
              <template #title>
                <div class="clause-head">
                  <span class="clause-title">{{ clauseTitle(clause) }}</span>
                  <span class="clause-keys">
                    {{ $t('complianceMap.clauseKeys', { n: clause.controls.length }) }}
                  </span>
                  <el-tag
                    size="small"
                    :type="resultTagType(clauseResultOf(clause))"
                  >
                    {{ resultLabel(clauseResultOf(clause)) }}
                  </el-tag>
                  <span class="clause-no">{{ $t('complianceMap.clauseNo', { no: clause.clause_no }) }}</span>
                </div>
              </template>

              <p
                v-if="clauseSummary(clause)"
                class="clause-summary"
              >
                {{ clauseSummary(clause) }}
              </p>

              <table
                v-if="clause.controls.length"
                class="key-table"
              >
                <thead>
                  <tr>
                    <th>{{ $t('complianceMap.colSetting') }}</th>
                    <th>{{ $t('complianceMap.colCurrent') }}</th>
                    <th>{{ $t('complianceMap.colExpectation') }}</th>
                    <th>{{ $t('complianceMap.colResult') }}</th>
                    <th>{{ $t('complianceMap.colLastChange') }}</th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="control in clause.controls"
                    :key="control.policy_key"
                    :class="{ 'key-row-hit': matchedKeys.has(control.policy_key) }"
                    :data-test="`key-row-${control.policy_key}`"
                  >
                    <td>{{ settingLabel(control.policy_key) }}</td>
                    <td>{{ currentValueOf(clause, control) }}</td>
                    <td>{{ expectationText(control, metaOf(clause, control)) }}</td>
                    <td>
                      <el-tag
                        size="small"
                        :type="resultTagType(verdictOf(clause, control).result)"
                      >
                        {{ resultLabel(verdictOf(clause, control).result) }}
                      </el-tag>
                      <span class="verdict-reason">
                        {{ reasonLabel(verdictOf(clause, control).reason) }}
                      </span>
                    </td>
                    <td>
                      <span class="last-change">{{ lastChangeOf(control.policy_key) }}</span>
                      <router-link
                        class="record-link"
                        :to="recordHref(control.policy_key)"
                      >
                        {{ $t('complianceMap.recordLink') }}
                      </router-link>
                    </td>
                  </tr>
                </tbody>
              </table>

              <!-- 兩種「不由系統判定」的條文，展開後把差別寫死在近旁：只看標籤的
                   非專業讀者會以為兩者都只是等著誰按一下確認 -->
              <p
                v-if="clause.controls.length && hasReviewControl(clause)"
                class="clause-note"
                :data-test="`clause-review-note-${clause.clause_no}`"
              >
                {{ $t('complianceMap.reviewNote') }}
              </p>

              <p
                v-if="!clause.controls.length"
                class="clause-note"
                :data-test="`clause-kind-note-${clause.clause_no}`"
              >
                {{ clause.kind === 'self_attested'
                  ? $t('complianceMap.selfAttestedNote')
                  : resultLabel(clause.kind) }}
              </p>

              <p
                v-if="clause.annotation && clause.annotation.note"
                class="clause-note"
              >
                {{ $t('complianceMap.annotationLabel') }}：{{ clause.annotation.note }}
              </p>
              <p
                v-if="needsConfirmation(clause)"
                class="clause-note"
              >
                <template v-if="clause.annotation && clause.annotation.confirmed_at">
                  {{ $t('complianceMap.confirmed', {
                    who: clause.annotation.confirmed_by,
                    when: formatDateTime(clause.annotation.confirmed_at),
                  }) }}
                  <span v-if="clause.annotation.confirmation_note">
                    · {{ clause.annotation.confirmation_note }}
                  </span>
                </template>
                <template v-else>
                  {{ $t('complianceMap.notConfirmed') }}
                </template>
              </p>
            </el-collapse-item>
          </el-collapse>
        </div>
      </div>

      <aside class="side-column">
        <div class="panel">
          <div class="panel-title">
            {{ $t('complianceMap.asideWhat') }}
          </div>
          <dl class="aside-list">
            <dt>{{ $t('complianceMap.asideName') }}</dt>
            <dd>{{ activeGroupMeta.name }}</dd>
            <dt v-if="activeGroupMeta.version">
              {{ $t('complianceMap.asideVersion') }}
            </dt>
            <dd v-if="activeGroupMeta.version">
              {{ activeGroupMeta.version }}
            </dd>
            <dt>{{ $t('complianceMap.asideSource') }}</dt>
            <dd>{{ sourceLabel(activeGroupMeta.source) }}</dd>
          </dl>
          <p
            v-if="activeGroupMeta.locale"
            class="aside-body"
          >
            {{ $t('complianceMap.asideOriginalLocale', { locale: activeGroupMeta.locale }) }}
          </p>
        </div>

        <div class="panel">
          <div class="panel-title">
            {{ $t('complianceMap.asideHow') }}
          </div>
          <p class="aside-body">
            {{ $t('complianceMap.asideHowBody') }}
          </p>
        </div>

        <div class="panel">
          <div class="panel-title">
            {{ $t('complianceMap.asideAuto') }}
          </div>
          <p class="aside-body">
            {{ $t('complianceMap.asideAutoNone') }}
          </p>
          <div class="panel-title">
            {{ $t('complianceMap.asideRecent') }}
          </div>
          <p class="aside-body">
            {{ $t('complianceMap.asideRecentNone') }}
          </p>
        </div>
      </aside>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import { getComplianceSnapshot } from '@/api/compliance'
import { formatDateTime } from '@/utils/format'
import {
  clauseResult,
  clauseSummary,
  clauseTitle,
  displayPolicyValue,
  expectationText,
  reasonLabel,
  resultLabel,
  resultTagType,
  settingLabel,
} from '@/utils/policyClauseText'

// 合規對照頁：**唯讀**。
//
// 這一頁回答的是「現在這一刻，設定對每一個政策組符不符」，而它的讀者是稽核人員。
// 頁上不放任何寫入元件——條文改在政策組頁、設定值改在安全政策頁，各自留下自己的
// 記錄；把寫入混進來，「這條要求是誰改的」就會分裂成兩套說法。
//
// 資訊層級以非專業人士為先：標題與結果在前，條號退為列尾小字。

const { t } = useI18n()

const loading = ref(false)
const snapshot = ref({})
const groups = ref([])
const summaries = ref([])
const clauses = ref([])
const activeGroup = ref('')
const onlyDeviating = ref(false)
// 搜尋欄與已送出的查詢分開：文字輸入按 enter 或「搜尋」才套用（介面慣例），
// 每敲一字就重排條文會讓人找不到剛剛看到的那一列
const searchInput = ref('')
const searchQuery = ref('')
// 展開中的條號。搜尋命中時由程式撐開，使用者仍可自行收合
const openClauses = ref([])

const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone

const verdicts = computed(() => snapshot.value.verdicts || [])

const activeGroupMeta = computed(
  () => groups.value.find((g) => g.code === activeGroup.value) || {}
)

const activeSummary = computed(
  () => summaries.value.find((s) => s.group_code === activeGroup.value) || {}
)

// 已自規範移除的條文不進畫面也不進計數：判定本來就不計入它們，
// 列出來會讓摘要與逐條兩處的條文數對不起來
const groupClauses = computed(() =>
  clauses.value.filter(
    (c) => c.group_code === activeGroup.value && !c.removed_in_version
  )
)

// 系統內建保護型的條文本期只進摘要格：它沒有可調的設定，逐條列出只是把
// 「產品本來就做到的事」混進機構要判讀的清單裡
const listedClauses = computed(() =>
  groupClauses.value.filter((c) => c.kind !== 'builtin_protection')
)

const clauseResultOf = (clause) => clauseResult(clause, verdicts.value)

const visibleClauses = computed(() =>
  onlyDeviating.value
    ? listedClauses.value.filter((c) => clauseResultOf(c) === 'deviating')
    : listedClauses.value
)

const unmappedCount = computed(() => activeSummary.value.unmapped ?? 0)

const builtinProtectionCount = computed(
  () => activeSummary.value.builtin_protection ?? 0
)

// 摘要分成兩組並各自帶單位：條文數以「條」計，五種判定以「項設定」計。
// 同一排混用兩種單位時，第一眼看不出 40 與 3 不能相加
const summaryGroups = computed(() => [
  {
    key: 'clauses',
    title: t('complianceMap.summaryGroupClauses'),
    unit: t('complianceMap.unitClause'),
    cells: [
      {
        key: 'clauses',
        label: t('complianceMap.summaryClauses'),
        value: groupClauses.value.length,
        hint: '',
        // 這個數含不逐條列出的內建保護，比下方清單長。差額寫在格內，
        // 讀者才不必自己相減去對清單長度
        note:
          builtinProtectionCount.value > 0
            ? t('complianceMap.summaryClausesBuiltinNote', {
                n: builtinProtectionCount.value,
              })
            : '',
      },
      {
        key: 'builtinProtection',
        label: t('complianceMap.summaryBuiltinProtection'),
        value: builtinProtectionCount.value,
        hint: t('complianceMap.summaryBuiltinProtectionHint'),
        note: '',
      },
    ],
  },
  {
    key: 'keys',
    title: t('complianceMap.summaryGroupKeys'),
    unit: t('complianceMap.unitSetting'),
    cells: [
      {
        key: 'compliant',
        label: t('complianceMap.summaryCompliant'),
        value: activeSummary.value.compliant ?? 0,
        hint: '',
        note: '',
      },
      {
        key: 'deviating',
        label: t('complianceMap.summaryDeviating'),
        value: activeSummary.value.deviating ?? 0,
        hint: '',
        note: '',
      },
      {
        key: 'needsReview',
        label: t('complianceMap.summaryNeedsReview'),
        value: activeSummary.value.needs_review ?? 0,
        hint: '',
        note: '',
      },
      {
        key: 'auditReview',
        label: t('complianceMap.summaryAuditReview'),
        value: activeSummary.value.audit_review ?? 0,
        hint: '',
        note: '',
      },
    ],
  },
])

const verdictOf = (clause, control) =>
  verdicts.value.find(
    (v) =>
      v.group_code === clause.group_code &&
      v.clause_no === clause.clause_no &&
      v.key === control.policy_key
  ) || {}

// 顯示中繼資料（單位、零值語義）跟著判定結果回來：這一頁是唯讀的稽核視角，
// 讀不到管理端的設定清單，缺了就只能少印單位，不能自己猜一個
const metaOf = (clause, control) => {
  const verdict = verdictOf(clause, control)
  return { unit_key: verdict.unit_key, zero_disables: verdict.zero_disables }
}

const currentValueOf = (clause, control) =>
  displayPolicyValue(
    control.policy_key,
    verdictOf(clause, control).current,
    metaOf(clause, control)
  )

// 一條條文裡有「有要求但不定值」的項目：展開後另寫一句說明它與機構自述的差別
const hasReviewControl = (clause) =>
  (clause.controls || []).some((c) => c.comparator === 'review')

// 待人工確認的條文才需要顯示確認資訊：其餘條文沒有可確認的東西，
// 印一行「尚未確認」只會讓人以為漏了一個動作
const needsConfirmation = (clause) =>
  (clause.controls || []).some((c) => c.reference_only)

const sourceLabel = (source) =>
  source === 'custom'
    ? t('complianceMap.asideSourceCustom')
    : t('complianceMap.asideSourceBuiltin')

// 最後變更取自判定結果本身：那是這一頁唯一讀得到的來源，而稽核角色與管理者
// 讀的是同一份結果——兩種角色因此看到同一個「何時被誰改的」
const lastChangeOf = (key) => {
  const verdict = verdicts.value.find((v) => v.key === key && v.updated_at)
  if (!verdict) return t('complianceMap.lastChangeUnknown')
  const who = verdict.updated_by ? ` · ${verdict.updated_by}` : ''
  return `${formatDateTime(verdict.updated_at)}${who}`
}

// 命中的設定鍵：比對顯示名與鍵名兩者。稽核人員手上拿到的可能是畫面上的中文名，
// 也可能是報告或日誌裡的英文鍵名，兩種都要找得到
const matchedKeys = computed(() => {
  const hit = new Set()
  const needle = searchQuery.value.trim().toLowerCase()
  if (!needle) return hit
  listedClauses.value.forEach((clause) => {
    const controls = clause.controls || []
    controls.forEach((control) => {
      const key = control.policy_key || ''
      const label = settingLabel(key) || ''
      if (key.toLowerCase().includes(needle) || label.toLowerCase().includes(needle)) {
        hit.add(key)
      }
    })
  })
  return hit
})

const applySearch = () => {
  searchQuery.value = searchInput.value
  // 命中即展開所屬條文：只把列標起來的話，收合狀態下什麼都看不到
  openClauses.value = listedClauses.value
    .filter((clause) =>
      (clause.controls || []).some((c) => matchedKeys.value.has(c.policy_key))
    )
    .map((clause) => clause.clause_no)
}

const resetSearch = () => {
  searchInput.value = ''
  searchQuery.value = ''
  openClauses.value = []
}

// 記錄連結帶資源與鍵：稽核人員要的是「這一個設定的變更」，
// 落到一份未篩選的日誌上等於把第三步變成一場搜尋
const recordHref = (key) =>
  `/audit-logs?resource=security_policy&key=${encodeURIComponent(key)}`

const load = async () => {
  loading.value = true
  try {
    const res = await getComplianceSnapshot()
    snapshot.value = res.data || {}
    groups.value = res.groups || []
    summaries.value = res.summaries || []
    clauses.value = res.clauses || []
    const stillValid = groups.value.some(
      (g) => g.code === activeGroup.value && g.enabled
    )
    if (!stillValid) {
      activeGroup.value = (groups.value.find((g) => g.enabled) || {}).code || ''
    }
  } catch (error) {
    console.error('讀取合規對照失敗:', error)
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.chip-row {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: var(--ot-space-sm);
  margin-bottom: var(--ot-space-md);
}

.chip-label {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.chip-inactive {
  margin-left: var(--ot-space-xs);
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-disabled);
}

.built-at {
  margin-left: auto;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.built-at-timezone {
  margin-left: var(--ot-space-xs);
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-disabled);
}

.layout {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 300px;
  gap: var(--ot-space-md);
  align-items: start;
}

@media (max-width: 1100px) {
  .layout {
    grid-template-columns: minmax(0, 1fr);
  }
}

.panel {
  padding: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  margin-bottom: var(--ot-space-md);
}

.panel-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: var(--ot-space-sm);
}

.panel-title {
  font-size: var(--ot-font-size-md);
  font-weight: 600;
  color: var(--ot-text-primary);
}

.summary-group + .summary-group {
  margin-top: var(--ot-space-md);
}

.summary-group-title {
  margin-bottom: var(--ot-space-xs);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(110px, 1fr));
  gap: var(--ot-space-sm);
}

.summary-unit {
  margin-left: var(--ot-space-xs);
  font-size: var(--ot-font-size-sm);
  font-weight: 400;
  color: var(--ot-text-secondary);
}

.summary-cell {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
  padding: var(--ot-space-sm);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  background-color: var(--ot-bg-elevated);
}

.summary-value {
  font-size: var(--ot-font-size-xl);
  font-weight: 600;
  color: var(--ot-text-primary);
}

.summary-label {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.summary-note {
  font-size: var(--ot-font-size-xs);
  line-height: 1.4;
  color: var(--ot-text-secondary);
}

.unmapped-note {
  margin: var(--ot-space-sm) 0 0;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.clause-search {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
}

.search-input {
  width: 220px;
}

.search-note {
  margin: 0 0 var(--ot-space-sm);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

/* 命中的列不只靠底色：底色是視覺，左緣的粗邊在灰階列印下仍分得出來 */
.key-row-hit td {
  background-color: var(--ot-bg-elevated);
}

.key-row-hit td:first-child {
  box-shadow: inset 3px 0 0 var(--ot-primary);
}

.clause-head {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  width: 100%;
}

.clause-title {
  color: var(--ot-text-primary);
  font-weight: 500;
}

.clause-keys {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.clause-no {
  margin-left: auto;
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-disabled);
}

.clause-summary,
.clause-note {
  margin: 0 0 var(--ot-space-sm);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.key-table {
  width: 100%;
  border-collapse: collapse;
  font-size: var(--ot-font-size-sm);
  margin-bottom: var(--ot-space-sm);
}

.key-table th,
.key-table td {
  padding: var(--ot-space-sm);
  text-align: left;
  border-bottom: 1px solid var(--ot-border-subtle);
  vertical-align: top;
}

.key-table th {
  color: var(--ot-text-secondary);
  font-weight: 500;
}

.key-table td {
  color: var(--ot-text-primary);
}

.verdict-reason {
  margin-left: var(--ot-space-xs);
  color: var(--ot-text-secondary);
}

.last-change {
  margin-right: var(--ot-space-xs);
  color: var(--ot-text-secondary);
}

.record-link {
  color: var(--ot-primary);
  text-decoration: none;
}

.record-link:hover {
  color: var(--ot-primary-hover);
}

.aside-list {
  margin: 0;
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  gap: var(--ot-space-xs) var(--ot-space-sm);
  font-size: var(--ot-font-size-sm);
}

.aside-list dt {
  color: var(--ot-text-secondary);
}

.aside-list dd {
  margin: 0;
  color: var(--ot-text-primary);
}

.aside-body {
  margin: var(--ot-space-sm) 0 0;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
  line-height: 1.6;
}
</style>
