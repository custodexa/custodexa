<template>
  <div class="rotation-evidence">
    <PageHeader
      :title="$t('menu.rotationEvidence')"
      :description="$t('rotationEvidence.headerDesc')"
    >
      <template #actions>
        <el-button
          :loading="loading"
          data-test="rotation-refresh"
          @click="loadReport()"
        >
          {{ $t('common.refresh') }}
        </el-button>
        <el-button
          type="primary"
          data-test="rotation-generate"
          @click="openGenerate"
        >
          {{ $t('rotationEvidence.generate') }}
        </el-button>
      </template>
    </PageHeader>

    <!-- 兩欄：主區是可核對的列（摘要、篩選、帳號表、區間記錄）；
         右欄是「這份報告本身」的狀態——合規率、口徑、排程與最近產出。
         稽核到場開這一頁，看到的就是報告的畫面版 -->
    <div class="layout">
      <div class="main-col">
        <!-- 母體與截止時點必須先講：讀者看到的每個數字都以這兩件事為前提 -->
        <el-alert
          type="info"
          :closable="false"
          show-icon
          data-test="rotation-basis"
          :title="basisText"
        />
        <el-alert
          v-if="meta.global_max_age_days === 0"
          type="warning"
          :closable="false"
          show-icon
          data-test="rotation-no-global-policy"
          :title="$t('rotationEvidence.globalUnsetNote')"
        />
        <el-alert
          v-if="truncation.rows_truncated"
          type="warning"
          :closable="false"
          show-icon
          data-test="rotation-truncated"
          :title="$t('rotationEvidence.rowsTruncated', { cap: truncation.rows_cap })"
        />
        <el-alert
          v-if="loadFailed"
          type="error"
          :closable="false"
          show-icon
          data-test="rotation-load-failed"
          :title="$t('rotationEvidence.loadFailed')"
        />

        <el-card v-loading="loading">
          <!-- 摘要數字列：六桶依判定順序排列，兩種合規率並列。
               分母為零時顯示「不適用」而非 0%——0% 會被讀成「一個都不合規」 -->
          <div class="summary-row">
            <div
              v-for="bucket in ROTATION_BUCKETS"
              :key="bucket"
              class="summary-cell"
              :class="{ 'summary-cell-active': bucketFilter === bucket }"
              :data-test="`rotation-summary-${bucket}`"
              @click="toggleBucket(bucket)"
            >
              <div class="summary-value">
                {{ bucketCount(bucket) }}
              </div>
              <div class="summary-label">
                {{ $t(`rotationEvidence.bucket.${bucket}`) }}
              </div>
            </div>
          </div>

          <div class="filter-row">
            <el-radio-group
              v-model="bucketFilter"
              data-test="rotation-bucket-filter"
            >
              <el-radio-button value="">
                {{ $t('rotationEvidence.filterAll', { count: rows.length }) }}
              </el-radio-button>
              <el-radio-button
                v-for="bucket in ROTATION_BUCKETS"
                :key="bucket"
                :value="bucket"
              >
                {{ $t(`rotationEvidence.bucket.${bucket}`) }}
              </el-radio-button>
            </el-radio-group>
          </div>

          <el-empty
            v-if="!filteredRows.length && !loading"
            data-test="rotation-empty"
            :description="$t('rotationEvidence.empty')"
          />
          <el-table
            v-else
            :data="filteredRows"
            style="width: 100%"
            stripe
            row-key="account_id"
          >
            <!-- 欄寬在兩欄版面內收斂：右欄佔去 300px 後，舊的欄寬會讓這張表橫捲，
                 而捲出去的第一欄正好是狀態 -->
            <el-table-column
              :label="$t('rotationEvidence.column.asset')"
              min-width="150"
            >
              <template #default="{ row }">
                <div :data-test="`rotation-asset-${row.account_id}`">
                  {{ row.asset_name }}
                </div>
                <div class="sub">
                  {{ row.asset_address }} · {{ row.protocol }}
                </div>
              </template>
            </el-table-column>

            <el-table-column
              :label="$t('rotationEvidence.column.account')"
              min-width="150"
            >
              <template #default="{ row }">
                <div :data-test="`rotation-account-${row.account_id}`">
                  {{ row.username }}
                  <span class="sub">（{{ credentialTypeText(row.credential_type) }}）</span>
                </div>
                <div class="tag-row">
                  <el-tag
                    v-if="row.privileged"
                    size="small"
                    type="danger"
                    effect="plain"
                    :data-test="`rotation-privileged-${row.account_id}`"
                  >
                    {{ $t('rotationEvidence.tag.privileged') }}
                  </el-tag>
                  <!-- 共用憑證：只反映系統知道的事（複製建號歸組、改密成功脫組），
                       人工改過的憑證不在其中。這一點寫進 tooltip，免得被讀成保證 -->
                  <el-tooltip
                    v-if="row.shared_credential"
                    placement="top"
                    :content="$t('rotationEvidence.tag.sharedHint')"
                  >
                    <el-tag
                      size="small"
                      type="warning"
                      effect="plain"
                      :data-test="`rotation-shared-${row.account_id}`"
                    >
                      {{ $t('rotationEvidence.tag.shared') }}
                    </el-tag>
                  </el-tooltip>
                  <el-tag
                    v-if="row.multi_plan"
                    size="small"
                    type="info"
                    effect="plain"
                    :data-test="`rotation-multiplan-${row.account_id}`"
                  >
                    {{ $t('rotationEvidence.tag.multiPlan') }}
                  </el-tag>
                </div>
              </template>
            </el-table-column>

            <el-table-column
              :label="$t('rotationEvidence.column.policy')"
              min-width="110"
            >
              <template #default="{ row }">
                <div :data-test="`rotation-maxage-${row.account_id}`">
                  {{ maxAgeText(row) }}
                </div>
                <div class="sub">
                  {{ planText(row) }}
                </div>
              </template>
            </el-table-column>

            <el-table-column
              :label="$t('rotationEvidence.column.lastSuccess')"
              min-width="155"
            >
              <template #default="{ row }">
                <div :data-test="`rotation-last-${row.account_id}`">
                  {{ row.last_success_at ? formatDateTime(row.last_success_at) : $t('rotationEvidence.noRecordValue') }}
                </div>
                <div class="sub">
                  {{ remainingText(row.remaining_days_a) }}
                </div>
              </template>
            </el-table-column>

            <el-table-column
              :label="$t('rotationEvidence.column.nextSchedule')"
              min-width="155"
            >
              <template #default="{ row }">
                <div :data-test="`rotation-next-${row.account_id}`">
                  {{ row.next_schedule_at ? formatDateTime(row.next_schedule_at) : $t('rotationEvidence.noSchedule') }}
                </div>
                <div class="sub">
                  {{ remainingText(row.remaining_days_b) }}
                </div>
              </template>
            </el-table-column>

            <el-table-column
              :label="$t('rotationEvidence.column.bucket')"
              width="90"
            >
              <template #default="{ row }">
                <el-tag
                  :type="BUCKET_TAG_TYPE[row.bucket] || 'info'"
                  effect="plain"
                  :data-test="`rotation-bucket-${row.account_id}`"
                >
                  {{ bucketLabel(row.bucket) }}
                </el-tag>
              </template>
            </el-table-column>
          </el-table>
        </el-card>

        <!-- 區間記錄明細：資料集端點不回明細（那是另一支端點的分頁查詢），
             故本區塊自成一次查詢。失敗的那幾筆是稽核最想看的東西 -->
        <el-card
          v-loading="recordsLoading"
          data-test="rotation-records-card"
        >
          <template #header>
            <span class="card-title">{{ $t('rotationEvidence.recordsTitle') }}</span>
            <span class="sub card-sub">{{ periodText }}</span>
          </template>
          <el-alert
            v-if="recordsTruncated"
            type="warning"
            :closable="false"
            show-icon
            data-test="rotation-records-truncated"
            :title="$t('rotationEvidence.recordsTruncated')"
          />
          <el-empty
            v-if="!records.length && !recordsLoading"
            data-test="rotation-records-empty"
            :description="$t('rotationEvidence.recordsEmpty')"
          />
          <el-table
            v-else
            :data="records"
            style="width: 100%"
            stripe
            row-key="record_id"
          >
            <el-table-column
              :label="$t('rotationEvidence.column.executedAt')"
              width="180"
            >
              <template #default="{ row }">
                {{ formatDateTime(row.executed_at) }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('rotationEvidence.column.plan')"
              min-width="150"
              prop="plan_name"
            />
            <el-table-column
              :label="$t('rotationEvidence.column.target')"
              min-width="180"
            >
              <template #default="{ row }">
                {{ row.asset_name }} / {{ row.account_username }}
                <el-tag
                  v-if="row.account_deleted"
                  size="small"
                  type="info"
                  effect="plain"
                >
                  {{ $t('rotationEvidence.accountDeleted') }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('rotationEvidence.column.result')"
              width="120"
            >
              <template #default="{ row }">
                <el-tag
                  :type="recordTagType(row.status)"
                  effect="plain"
                  :data-test="`rotation-record-status-${row.record_id}`"
                >
                  {{ recordStatusText(row.status) }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('rotationEvidence.column.reason')"
              min-width="220"
            >
              <template #default="{ row }">
                {{ reasonText(row.reason_code) }}
              </template>
            </el-table-column>
          </el-table>
          <div
            v-if="recordsTotal > 0"
            class="pagination"
          >
            <el-pagination
              v-model:current-page="recordsPage"
              v-model:page-size="recordsPageSize"
              :page-sizes="[20, 50, 100]"
              :total="recordsTotal"
              layout="total, sizes, prev, pager, next"
              @size-change="loadRecords()"
              @current-change="loadRecords()"
            />
          </div>
        </el-card>

        <!-- 排程管理：admin 專屬區，由右欄的「管理」展開。**不另立側欄項目**
             ——排程是這份報告的產出設定，離開這一頁看它就沒有上下文；
             預設收起則是因為到場的稽核要看的是帳號列，不是產出設定 -->
        <el-card
          v-if="isAdmin && schedulesExpanded"
          data-test="rotation-schedules"
        >
          <template #header>
            <span class="card-title">{{ $t('rotationEvidence.schedulesTitle') }}</span>
            <el-button
              type="primary"
              link
              data-test="rotation-schedule-create"
              @click="openScheduleCreate"
            >
              {{ $t('rotationEvidence.scheduleCreate') }}
            </el-button>
          </template>
          <el-empty
            v-if="!schedules.length"
            data-test="rotation-schedules-empty"
            :description="$t('rotationEvidence.schedulesEmpty')"
          />
          <el-table
            v-else
            :data="schedules"
            style="width: 100%"
            stripe
            row-key="id"
          >
            <el-table-column
              :label="$t('rotationEvidence.column.scheduleName')"
              min-width="160"
            >
              <template #default="{ row }">
                <div :data-test="`rotation-schedule-name-${row.id}`">
                  {{ row.name }}
                </div>
                <div class="sub">
                  {{ scopeText(row.scope_kind) }}
                </div>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('rotationEvidence.column.cron')"
              min-width="140"
            >
              <template #default="{ row }">
                <code>{{ row.cron }}</code>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('rotationEvidence.column.periodAnchor')"
              min-width="190"
            >
              <template #default="{ row }">
                <div>{{ formatDateTime(row.period_anchor) }}</div>
                <div class="sub">
                  {{ $t('rotationEvidence.periodAnchorHint') }}
                </div>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('rotationEvidence.column.retention')"
              width="120"
            >
              <template #default="{ row }">
                {{ $t('rotationEvidence.retentionDaysValue', { days: row.retention_days }) }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('rotationEvidence.column.language')"
              width="110"
            >
              <template #default="{ row }">
                {{ LOCALE_LABELS[row.language] || row.language }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.enabled')"
              width="90"
            >
              <template #default="{ row }">
                <el-tag
                  :type="row.enabled ? 'success' : 'info'"
                  effect="plain"
                >
                  {{ row.enabled ? $t('common.enabled') : $t('common.disabled') }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('auditExports.column.actions')"
              width="180"
            >
              <template #default="{ row }">
                <el-button
                  link
                  type="primary"
                  :data-test="`rotation-schedule-run-${row.id}`"
                  @click="runSchedule(row)"
                >
                  {{ $t('rotationEvidence.scheduleRun') }}
                </el-button>
                <el-button
                  link
                  :data-test="`rotation-schedule-edit-${row.id}`"
                  @click="openScheduleEdit(row)"
                >
                  {{ $t('common.edit') }}
                </el-button>
                <el-button
                  link
                  type="danger"
                  :data-test="`rotation-schedule-delete-${row.id}`"
                  @click="removeSchedule(row)"
                >
                  {{ $t('common.delete') }}
                </el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </div>

      <!-- 右欄：報告本身的狀態。排程與最近產出放在這裡——它們回答的是
           「這份報告怎麼來、上一份在哪」，屬於報告的後設資訊，
           不該與帳號列爭主區的位置 -->
      <aside class="side-col">
        <el-card
          class="side-card"
          data-test="rotation-aside"
        >
          <div class="side-section">
            <div class="side-title">
              {{ $t('rotationEvidence.aside.rateTitle') }}
            </div>
            <div class="rate-row">
              <div
                v-for="rate in RATE_FIELDS"
                :key="rate"
                class="rate-cell"
                :data-test="`rotation-rate-${rate}`"
              >
                <div class="summary-value">
                  {{ rateText(summary[rate]) }}
                </div>
                <div class="summary-label">
                  {{ $t(`rotationEvidence.rateShort.${rate}`) }}
                  <el-tooltip
                    placement="top"
                    :content="$t(`rotationEvidence.rateBasis.${rate}`)"
                  >
                    <el-icon class="basis-icon">
                      <CircleHelp />
                    </el-icon>
                  </el-tooltip>
                </div>
              </div>
            </div>
            <!-- 比例條：合規率只回答「合規的佔多少」，這一條回答「其餘的是哪幾種」
                 ——無記錄佔掉大半時要一眼看得出來 -->
            <div
              v-if="bucketBar.length"
              class="bucket-bar"
              data-test="rotation-bucket-bar"
            >
              <el-tooltip
                v-for="seg in bucketBar"
                :key="seg.bucket"
                placement="top"
                :content="seg.hint"
              >
                <div
                  class="bucket-seg"
                  :class="`bucket-seg-${seg.bucket}`"
                  :style="{ width: seg.width }"
                  :data-test="`rotation-bar-${seg.bucket}`"
                />
              </el-tooltip>
            </div>
          </div>

          <div class="side-section">
            <div class="side-title">
              {{ $t('rotationEvidence.aside.basisTitle') }}
            </div>
            <div class="side-note">
              <div>{{ $t('rotationEvidence.aside.basisRemainingA') }}</div>
              <div>{{ $t('rotationEvidence.aside.basisRemainingB') }}</div>
              <div>{{ $t('rotationEvidence.aside.basisNoRecord') }}</div>
            </div>
          </div>

          <div
            class="side-section"
            data-test="rotation-aside-schedule"
          >
            <div class="side-title-row">
              <span class="side-title">{{ $t('rotationEvidence.aside.scheduleTitle') }}</span>
              <el-button
                v-if="isAdmin"
                link
                type="primary"
                data-test="rotation-schedule-manage"
                @click="toggleSchedules"
              >
                {{ schedulesExpanded ? $t('rotationEvidence.aside.scheduleManageClose') : $t('rotationEvidence.aside.scheduleManage') }}
              </el-button>
            </div>
            <!-- auditor 沒有排程端點的讀取權：與其演一個看不到內容的區塊，
                 不如說清楚這件事由誰設定 -->
            <div
              v-if="!isAdmin"
              class="side-note"
              data-test="rotation-schedule-admin-only"
            >
              {{ $t('rotationEvidence.aside.scheduleAdminOnly') }}
            </div>
            <div
              v-else-if="!schedules.length"
              class="side-note"
              data-test="rotation-aside-schedule-empty"
            >
              {{ $t('rotationEvidence.schedulesEmpty') }}
            </div>
            <div
              v-else
              class="side-list"
            >
              <div
                v-for="s in scheduleDigest"
                :key="s.id"
                class="side-item"
                :data-test="`rotation-aside-schedule-${s.id}`"
              >
                <div class="side-item-head">
                  <span class="side-item-name">{{ s.name }}</span>
                  <el-tag
                    :type="s.enabled ? 'success' : 'info'"
                    size="small"
                    effect="plain"
                  >
                    {{ s.enabled ? $t('common.enabled') : $t('common.disabled') }}
                  </el-tag>
                </div>
                <div class="sub">
                  <code>{{ s.cron }}</code> · {{ $t('rotationEvidence.retentionDaysValue', { days: s.retention_days }) }}
                </div>
                <div class="sub">
                  {{ $t('rotationEvidence.aside.scheduleAnchor', { time: formatDateTime(s.period_anchor) }) }}
                </div>
              </div>
              <div
                v-if="schedules.length > scheduleDigest.length"
                class="sub"
                data-test="rotation-aside-schedule-more"
              >
                {{ $t('rotationEvidence.aside.scheduleMore', { count: schedules.length - scheduleDigest.length }) }}
              </div>
            </div>
          </div>

          <div
            class="side-section"
            data-test="rotation-aside-recent"
          >
            <div class="side-title">
              {{ $t('rotationEvidence.aside.recentTitle') }}
            </div>
            <EmptyState
              v-if="!recentReports.length"
              class="side-empty"
              :title="$t('rotationEvidence.aside.recentEmpty')"
              :icon="FileClock"
              data-test="rotation-aside-recent-empty"
            />
            <div
              v-else
              class="side-list"
            >
              <div
                v-for="job in recentReports"
                :key="job.id"
                class="side-item"
                :data-test="`rotation-recent-${job.id}`"
              >
                <div class="side-item-head">
                  <span class="side-item-name">{{ reportSourceText(job) }}</span>
                  <el-button
                    v-if="canDownloadReport(job)"
                    link
                    type="primary"
                    :loading="downloadingId === job.id"
                    :data-test="`rotation-recent-download-${job.id}`"
                    @click="downloadReport(job)"
                  >
                    {{ $t('auditExports.download') }}
                  </el-button>
                  <span
                    v-else
                    class="sub"
                    :data-test="`rotation-recent-status-${job.id}`"
                  >{{ jobStatusText(job.status) }}</span>
                </div>
                <div class="sub">
                  {{ $t('auditExports.requestedAt', { time: formatDateTime(job.requested_at) }) }}
                </div>
              </div>
            </div>
            <el-button
              link
              type="primary"
              class="side-link"
              data-test="rotation-recent-all"
              @click="goToExports"
            >
              {{ $t('rotationEvidence.aside.recentAll') }}
            </el-button>
          </div>
        </el-card>
      </aside>
    </div>

    <el-dialog
      v-model="generateVisible"
      :title="$t('rotationEvidence.generateTitle')"
      width="560px"
    >
      <el-form label-width="130px">
        <el-form-item :label="$t('rotationEvidence.scopeLabel')">
          <el-radio-group
            v-model="generateForm.scope_kind"
            data-test="rotation-scope-kind"
          >
            <el-radio-button
              v-for="kind in ROTATION_SCOPE_KINDS"
              :key="kind"
              :value="kind"
            >
              {{ scopeText(kind) }}
            </el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item
          v-if="generateForm.scope_kind === 'node'"
          :label="$t('rotationEvidence.scopeNode')"
        >
          <el-tree-select
            v-model="generateForm.scope_id"
            :data="nodeTreeOptions"
            :props="{ label: 'label', children: 'children' }"
            node-key="id"
            check-strictly
            clearable
            class="full-width"
            :placeholder="$t('rotationEvidence.scopeNodePlaceholder')"
          />
        </el-form-item>
        <el-form-item
          v-if="generateForm.scope_kind === 'plan'"
          :label="$t('rotationEvidence.scopePlan')"
        >
          <el-select
            v-model="generateForm.scope_id"
            class="full-width"
            :placeholder="$t('rotationEvidence.scopePlanPlaceholder')"
          >
            <el-option
              v-for="plan in plans"
              :key="plan.id"
              :label="plan.name"
              :value="plan.id"
            />
          </el-select>
        </el-form-item>
        <el-form-item :label="$t('rotationEvidence.period')">
          <el-date-picker
            v-model="generateForm.period"
            type="daterange"
            value-format="YYYY-MM-DD"
            :start-placeholder="$t('rotationEvidence.periodStart')"
            :end-placeholder="$t('rotationEvidence.periodEnd')"
            data-test="rotation-period"
          />
        </el-form-item>
        <el-form-item :label="$t('rotationEvidence.language')">
          <el-select
            v-model="generateForm.language"
            class="full-width"
            data-test="rotation-language"
          >
            <el-option
              v-for="lang in ROTATION_REPORT_LANGUAGES"
              :key="lang"
              :label="LOCALE_LABELS[lang] || lang"
              :value="lang"
            />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="generateVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="generating"
          :disabled="!canGenerate"
          data-test="rotation-generate-submit"
          @click="submitGenerate"
        >
          {{ $t('rotationEvidence.generateSubmit') }}
        </el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="scheduleVisible"
      :title="editingScheduleId ? $t('rotationEvidence.scheduleEditTitle') : $t('rotationEvidence.scheduleCreateTitle')"
      width="560px"
    >
      <el-form label-width="130px">
        <el-form-item :label="$t('rotationEvidence.scheduleName')">
          <el-input
            v-model="scheduleForm.name"
            data-test="rotation-schedule-name"
          />
        </el-form-item>
        <el-form-item :label="$t('rotationEvidence.cron')">
          <el-input
            v-model="scheduleForm.cron"
            :placeholder="$t('rotationEvidence.cronPlaceholder')"
            data-test="rotation-schedule-cron"
          />
        </el-form-item>
        <el-form-item :label="$t('rotationEvidence.scopeLabel')">
          <el-radio-group v-model="scheduleForm.scope_kind">
            <el-radio-button
              v-for="kind in ROTATION_SCOPE_KINDS"
              :key="kind"
              :value="kind"
            >
              {{ scopeText(kind) }}
            </el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item
          v-if="scheduleForm.scope_kind === 'node'"
          :label="$t('rotationEvidence.scopeNode')"
        >
          <el-tree-select
            v-model="scheduleForm.scope_id"
            :data="nodeTreeOptions"
            :props="{ label: 'label', children: 'children' }"
            node-key="id"
            check-strictly
            clearable
            class="full-width"
          />
        </el-form-item>
        <el-form-item
          v-if="scheduleForm.scope_kind === 'plan'"
          :label="$t('rotationEvidence.scopePlan')"
        >
          <el-select
            v-model="scheduleForm.scope_id"
            class="full-width"
          >
            <el-option
              v-for="plan in plans"
              :key="plan.id"
              :label="plan.name"
              :value="plan.id"
            />
          </el-select>
        </el-form-item>
        <el-form-item :label="$t('rotationEvidence.retentionDays')">
          <el-input-number
            v-model="scheduleForm.retention_days"
            :min="1"
            :max="3650"
            :step="1"
            step-strictly
            data-test="rotation-schedule-retention"
          />
          <span class="sub">{{ $t('rotationEvidence.retentionHint') }}</span>
        </el-form-item>
        <el-form-item :label="$t('rotationEvidence.language')">
          <el-select
            v-model="scheduleForm.language"
            class="full-width"
          >
            <el-option
              v-for="lang in ROTATION_REPORT_LANGUAGES"
              :key="lang"
              :label="LOCALE_LABELS[lang] || lang"
              :value="lang"
            />
          </el-select>
        </el-form-item>
        <el-form-item :label="$t('common.enabled')">
          <el-switch v-model="scheduleForm.enabled" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="scheduleVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="scheduleSaving"
          :disabled="!scheduleForm.name || !scheduleForm.cron"
          data-test="rotation-schedule-submit"
          @click="submitSchedule"
        >
          {{ $t('common.save') }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { CircleHelp, FileClock } from 'lucide-vue-next'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import {
  createRotationReportJob,
  createRotationReportSchedule,
  deleteRotationReportSchedule,
  getRotationReport,
  getRotationReportRecords,
  listRotationReportSchedules,
  runRotationReportSchedule,
  updateRotationReportSchedule,
} from '@/api/rotationReport'
import { downloadAuditExportJob, listAuditExportJobs } from '@/api/auditExport'
import { getAssetGroups } from '@/api/assets'
import { getChangeSecretPlans } from '@/api/changeSecret'
import {
  BUCKET_SUMMARY_FIELD,
  BUCKET_TAG_TYPE,
  DEFAULT_RETENTION_DAYS,
  ROTATION_BUCKETS,
  ROTATION_REPORT_LANGUAGES,
  ROTATION_SCOPE_KINDS,
} from '@/constants/rotationEvidence'
import { LOCALE_LABELS } from '@/i18n'
import { useRoles } from '@/composables/useRoles'
import { confirmDestructive } from '@/utils/confirm'
import { downloadBlob } from '@/utils/download'
import { formatDateTime } from '@/utils/format'

// 輪替證據頁。
//
// **同源**：摘要、表格與狀態桶篩選全部來自同一次資料集查詢——狀態桶篩選在
// 已取得的列上做，不重打端點。重打會讓摘要與表格出自兩次計算，於是「篩選逾期後
// 的列數」與「摘要的逾期數」可以合法地不一致，而那正是稽核最先核對的一件事。
//
// **不做圖**：這一頁的讀者要的是可核對的列，不是趨勢感。圖表留給報告輸出。

const { t, te } = useI18n()
const router = useRouter()
const { isAdmin } = useRoles()

const RATE_FIELDS = ['rate_excluding_no_record', 'rate_counting_no_record']

const meta = ref({})
const summary = ref({})
const rows = ref([])
const truncation = ref({})
const loading = ref(false)
const loadFailed = ref(false)
const bucketFilter = ref('')

const records = ref([])
const recordsTotal = ref(0)
const recordsPage = ref(1)
const recordsPageSize = ref(20)
const recordsLoading = ref(false)
const recordsTruncated = ref(false)

const schedules = ref([])
const schedulesExpanded = ref(false)
const nodes = ref([])
const plans = ref([])

// 右欄的「最近產出」：取下載中心同一份共用清單的前三筆，不另立端點。
// 三筆的用意是回答「上一份在哪」，要看全部就去下載中心
const RECENT_REPORT_LIMIT = 3
const recentReports = ref([])
const downloadingId = ref(0)

const filteredRows = computed(() =>
  bucketFilter.value ? rows.value.filter((r) => r.bucket === bucketFilter.value) : rows.value
)

const bucketCount = (bucket) => Number(summary.value[BUCKET_SUMMARY_FIELD[bucket]]) || 0

const bucketLabel = (bucket) =>
  ROTATION_BUCKETS.includes(bucket) ? t(`rotationEvidence.bucket.${bucket}`) : bucket || ''

// 桶格點擊即篩選，再點一次還原全部——摘要與篩選是同一件事的兩種呈現，
// 讓它們是兩套互不相干的控制項只會讓人以為數字對不上
const toggleBucket = (bucket) => {
  bucketFilter.value = bucketFilter.value === bucket ? '' : bucket
}

// 合規率：null＝分母為零。**顯示「不適用」而非 0%**——0% 是一個關於母體的斷言，
// 而分母為零時我們對母體一無所知
const rateText = (rate) =>
  rate === null || rate === undefined
    ? t('rotationEvidence.notApplicable')
    : `${(Number(rate) * 100).toFixed(1)}%`

// 比例條：每一桶佔母體的比例。**分母取六桶之和而非 total_accounts**——
// 兩者理應相等，但若後端多出一個畫面還不認得的桶，用總數當分母會讓那一段
// 悄悄消失；用桶和當分母則是條子填不滿，缺口看得見
const bucketBar = computed(() => {
  const counts = ROTATION_BUCKETS.map((bucket) => ({ bucket, count: bucketCount(bucket) }))
  const sum = counts.reduce((acc, c) => acc + c.count, 0)
  if (!sum) return []
  return counts
    .filter((c) => c.count > 0)
    .map((c) => ({
      bucket: c.bucket,
      width: `${((c.count / sum) * 100).toFixed(2)}%`,
      hint: t('rotationEvidence.aside.barSegment', {
        bucket: t(`rotationEvidence.bucket.${c.bucket}`),
        count: c.count,
        percent: ((c.count / sum) * 100).toFixed(1),
      }),
    }))
})

// 右欄只擺得下兩列排程；其餘以一行帶過，真要看全部就展開管理區
const SCHEDULE_DIGEST_LIMIT = 2
const scheduleDigest = computed(() => schedules.value.slice(0, SCHEDULE_DIGEST_LIMIT))

const toggleSchedules = () => {
  schedulesExpanded.value = !schedulesExpanded.value
}

const goToExports = () => {
  router.push({ path: '/audit/exports', query: { tab: 'reports' } })
}

const basisText = computed(() =>
  t('rotationEvidence.basis', {
    asOf: formatDateTime(meta.value.as_of),
    days:
      meta.value.global_max_age_days > 0
        ? t('rotationEvidence.globalDays', { days: meta.value.global_max_age_days })
        : t('rotationEvidence.globalUnset'),
    window: meta.value.due_soon_window_days ?? 30,
  })
)

// 記錄明細的區間。
//
// 資料集端點對「未指定區間」回的是起訖同一刻（它本來就不回明細），拿它去打
// 記錄端點會被 400 擋下——那支端點要求起早於迄。故畫面自己定一個預設回看窗，
// 並把實際用的區間寫在標題上：讀者要知道下面那張表涵蓋的是哪一段。
const RECORDS_LOOKBACK_DAYS = 90

const recordsPeriod = computed(() => {
  const from = meta.value.period_start
  const to = meta.value.period_end || meta.value.as_of
  if (from && to && new Date(from).getTime() < new Date(to).getTime()) {
    return { from, to }
  }
  if (!to) return null
  const end = new Date(to)
  const start = new Date(end.getTime() - RECORDS_LOOKBACK_DAYS * 86400000)
  return { from: start.toISOString(), to: end.toISOString() }
})

const periodText = computed(() =>
  recordsPeriod.value
    ? t('rotationEvidence.periodRange', {
      from: formatDateTime(recordsPeriod.value.from),
      to: formatDateTime(recordsPeriod.value.to),
    })
    : ''
)

const maxAgeText = (row) =>
  row.max_age_days > 0
    ? t('rotationEvidence.maxAgeValue', { days: row.max_age_days })
    : t('rotationEvidence.maxAgeUnset')

// 適用天數的來源：全域或某個計劃。來源是 `plan:<名稱>` 的形態，
// 名稱原樣取出——它是使用者自己命的名，翻不得
const planText = (row) => {
  const source = String(row.max_age_source || '')
  if (source === 'global') return t('rotationEvidence.sourceGlobal')
  if (source.startsWith('plan:')) {
    return t('rotationEvidence.sourcePlan', { plan: source.slice('plan:'.length) })
  }
  return row.plans?.length
    ? t('rotationEvidence.planList', { plans: row.plans.join(t('common.listSeparator')) })
    : t('rotationEvidence.noPlan')
}

const remainingText = (days) => {
  if (days === null || days === undefined) return t('rotationEvidence.remainingUnknown')
  return days < 0
    ? t('rotationEvidence.overdueDays', { days: Math.abs(days) })
    : t('rotationEvidence.remainingDays', { days })
}

const credentialTypeText = (type) =>
  te(`rotationEvidence.credentialType.${type}`)
    ? t(`rotationEvidence.credentialType.${type}`)
    : type || ''

const scopeText = (kind) =>
  ROTATION_SCOPE_KINDS.includes(kind) ? t(`rotationEvidence.scope.${kind}`) : kind || ''

const recordTagType = (status) =>
  ({ success: 'success', failed: 'danger', unverified: 'warning', skipped: 'info' })[status] || 'info'

const recordStatusText = (status) =>
  te(`changeSecretPlans.recordStatus.${status}`)
    ? t(`changeSecretPlans.recordStatus.${status}`)
    : status || ''

// 原因碼走既有的改密原因碼對照表（同一組機器碼，不另立第二份譯文）；
// 查不到的碼原樣顯示，不吞掉
const reasonText = (code) => {
  if (!code) return ''
  const key = `changeSecretPlans.reason.${code}`
  return te(key) ? t(key) : code
}

const loadReport = async () => {
  loading.value = true
  try {
    const res = await getRotationReport({})
    const data = res?.data || {}
    meta.value = data.meta || {}
    summary.value = data.summary || {}
    rows.value = data.rows || []
    truncation.value = data.truncation || {}
    loadFailed.value = false
    await loadRecords()
    await loadRecentReports()
  } catch (_e) {
    loadFailed.value = true
  } finally {
    loading.value = false
  }
}

const loadRecords = async () => {
  const period = recordsPeriod.value
  if (!period) return
  recordsLoading.value = true
  try {
    const res = await getRotationReportRecords({
      period_start: period.from,
      period_end: period.to,
      page: recordsPage.value,
      page_size: recordsPageSize.value,
    })
    records.value = res?.data || []
    recordsTotal.value = Number(res?.total) || 0
    recordsTruncated.value = Boolean(res?.truncated)
  } catch (_e) {
    records.value = []
    recordsTotal.value = 0
  } finally {
    recordsLoading.value = false
  }
}

// 最近產出：共用清單（不綁申請者）的前三筆。**排程名缺席＝手動產出**，
// 這一點與下載中心同一套說法，不另編一種措辭
const reportSourceText = (job) => {
  const name = job?.report?.schedule_name
  if (name) return name
  const by = job?.report?.generated_by || job?.requester
  return by ? t('auditExports.reportManualBy', { user: by }) : t('auditExports.reportManual')
}

const jobStatusText = (status) =>
  te(`auditExports.status.${status}`) ? t(`auditExports.status.${status}`) : status || ''

// 可下載＝已完成且產物還在。過期的列仍要留在畫面上——它證明那一期產過報告，
// 只是產物已依保留期限清除
const canDownloadReport = (job) =>
  job?.status === 'done' &&
  (!job.expires_at || new Date(job.expires_at).getTime() > Date.now())

const loadRecentReports = async () => {
  try {
    const res = await listAuditExportJobs({
      kind: 'rotation_report',
      page: 1,
      page_size: RECENT_REPORT_LIMIT,
    })
    recentReports.value = (res?.data || []).slice(0, RECENT_REPORT_LIMIT)
  } catch (_e) {
    recentReports.value = []
  }
}

const downloadReport = async (job) => {
  if (downloadingId.value) return
  downloadingId.value = job.id
  try {
    const blob = await downloadAuditExportJob(job.id)
    downloadBlob(blob, `rotation-report-job-${job.id}.zip`)
  } catch (_e) {
    ElMessage.error(t('auditExports.downloadFailed'))
  } finally {
    downloadingId.value = 0
  }
}

const loadSchedules = async () => {
  try {
    const res = await listRotationReportSchedules()
    schedules.value = res?.data || []
  } catch (_e) {
    schedules.value = []
  }
}

// 節點與計劃清單只為兩個對話框的範圍選擇器服務，缺了就少一種範圍可選，
// 不該連整頁都不給看
const loadScopeOptions = async () => {
  try {
    const res = await getAssetGroups()
    nodes.value = res?.data || []
  } catch (_e) {
    nodes.value = []
  }
  if (!isAdmin.value) return
  try {
    const res = await getChangeSecretPlans()
    plans.value = res?.data || []
  } catch (_e) {
    plans.value = []
  }
}

// 平面節點列表組樹（沿授權精靈同一形狀：label 取節點名，父子以 parent_id 串）
const nodeTreeOptions = computed(() => {
  const byId = new Map()
  nodes.value.forEach((n) => {
    byId.set(n.id, { id: n.id, label: n.name, parent_id: n.parent_id, children: [] })
  })
  const roots = []
  byId.forEach((n) => {
    if (n.parent_id && byId.has(n.parent_id)) byId.get(n.parent_id).children.push(n)
    else roots.push(n)
  })
  return roots
})

const generateVisible = ref(false)
const generating = ref(false)
const emptyGenerateForm = () => ({
  scope_kind: 'all',
  scope_id: null,
  period: [],
  language: 'zh-TW',
})
const generateForm = ref(emptyGenerateForm())

const canGenerate = computed(() => {
  const f = generateForm.value
  if (f.scope_kind !== 'all' && !f.scope_id) return false
  return Boolean(f.period?.length === 2 && f.period[0] && f.period[1])
})

const openGenerate = () => {
  generateForm.value = emptyGenerateForm()
  generateVisible.value = true
}

// 日期選到的是「日」，送出的是帶時區的時刻：起訖各取當地日界，
// 由瀏覽器補時區位移——報告的區間必須說得出自己是哪個時區的哪一天
const dayToISO = (day, endOfDay) =>
  new Date(`${day}T${endOfDay ? '23:59:59' : '00:00:00'}`).toISOString()

const submitGenerate = async () => {
  const f = generateForm.value
  generating.value = true
  try {
    await createRotationReportJob({
      scope_kind: f.scope_kind,
      scope_id: f.scope_kind === 'all' ? 0 : Number(f.scope_id),
      period_start: dayToISO(f.period[0], false),
      period_end: dayToISO(f.period[1], true),
      language: f.language,
    })
    generateVisible.value = false
    ElMessage.success(t('rotationEvidence.generateAccepted'))
    // 產出是非同步的，這一頁沒有進度可看——直接把人帶到取件的地方
    router.push({ path: '/audit/exports', query: { tab: 'reports' } })
  } catch (_e) {
    // 全域攔截器已 toast 技術原因；此處不重複
  } finally {
    generating.value = false
  }
}

const scheduleVisible = ref(false)
const scheduleSaving = ref(false)
const editingScheduleId = ref(null)
const emptyScheduleForm = () => ({
  name: '',
  cron: '',
  enabled: true,
  scope_kind: 'all',
  scope_id: null,
  retention_days: DEFAULT_RETENTION_DAYS,
  language: 'zh-TW',
})
const scheduleForm = ref(emptyScheduleForm())

const openScheduleCreate = () => {
  editingScheduleId.value = null
  scheduleForm.value = emptyScheduleForm()
  scheduleVisible.value = true
}

const openScheduleEdit = (row) => {
  editingScheduleId.value = row.id
  scheduleForm.value = {
    name: row.name,
    cron: row.cron,
    enabled: row.enabled,
    scope_kind: row.scope_kind || 'all',
    scope_id: row.scope_id || null,
    retention_days: row.retention_days || DEFAULT_RETENTION_DAYS,
    language: row.language || 'zh-TW',
  }
  scheduleVisible.value = true
}

// period_anchor 唯讀：它由後端在建立、成功建單與 cron 變更時各自推進，
// 送上去也不採用，故表單不帶這個欄位
const schedulePayload = () => {
  const f = scheduleForm.value
  return {
    name: f.name,
    cron: f.cron,
    enabled: f.enabled,
    scope_kind: f.scope_kind,
    scope_id: f.scope_kind === 'all' ? 0 : Number(f.scope_id),
    retention_days: f.retention_days,
    language: f.language,
  }
}

const submitSchedule = async () => {
  scheduleSaving.value = true
  try {
    if (editingScheduleId.value) {
      await updateRotationReportSchedule(editingScheduleId.value, schedulePayload())
    } else {
      await createRotationReportSchedule(schedulePayload())
    }
    scheduleVisible.value = false
    ElMessage.success(t('rotationEvidence.scheduleSaved'))
    await loadSchedules()
  } catch (_e) {
    // 名稱重複與 cron 格式的機器碼由全域攔截器譯出
  } finally {
    scheduleSaving.value = false
  }
}

const runSchedule = async (row) => {
  try {
    await runRotationReportSchedule(row.id)
    ElMessage.success(t('rotationEvidence.scheduleRunAccepted'))
    await loadSchedules()
    // 剛受理的那一份要立刻出現在右欄——否則使用者會以為按鈕沒作用
    await loadRecentReports()
  } catch (_e) {
    // 已有進行中工作單時後端回 409，訊息由攔截器譯出
  }
}

// 刪除排程只停未來的產出，已產出的報告仍在下載中心——這句要寫進確認框，
// 否則管理者會以為刪排程等於刪掉已交付的證據
const removeSchedule = async (row) => {
  try {
    await confirmDestructive(
      t('rotationEvidence.scheduleDeleteConfirm', { name: row.name }),
      t('rotationEvidence.scheduleDeleteTitle')
    )
  } catch (_e) {
    return
  }
  try {
    await deleteRotationReportSchedule(row.id)
    ElMessage.success(t('rotationEvidence.scheduleDeleted'))
    await loadSchedules()
  } catch (_e) {
    // 攔截器已說明
  }
}

// 對話框內的表單狀態直接曝給單測驅動：日期選擇器與樹選擇器都走 teleport，
// 測試環境點不到，但「送出的 payload 對不對」正是最該被釘住的事
defineExpose({ generateForm, openGenerate, submitGenerate, scheduleForm, submitSchedule })

onMounted(async () => {
  await loadReport()
  await loadRecentReports()
  await loadScopeOptions()
  if (isAdmin.value) await loadSchedules()
})
</script>

<style scoped>
.rotation-evidence {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-md);
}

.layout {
  display: flex;
  align-items: flex-start;
  gap: var(--ot-space-md);
}

.main-col {
  display: flex;
  flex: 1;
  flex-direction: column;
  min-width: 0;
  gap: var(--ot-space-md);
}

/* 右欄固定 300px：它承載的是固定形狀的幾段文字與數字，
   跟著視窗變寬只會把 60 字的口徑句拉成一行 */
.side-col {
  flex-shrink: 0;
  width: 300px;
}

/* 窄於 1200px 時右欄落到主區下方——在那個寬度硬留 300px，
   帳號表格就得橫捲，而那張表才是這一頁的主體 */
@media (max-width: 1200px) {
  .layout {
    flex-direction: column;
  }

  .side-col {
    width: 100%;
  }
}

.side-section + .side-section {
  padding-top: var(--ot-space-md);
  margin-top: var(--ot-space-md);
  border-top: 1px solid var(--ot-border-subtle);
}

.side-title {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}

.side-title-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.side-note {
  margin-top: var(--ot-space-xs);
  font-size: var(--ot-font-size-xs);
  line-height: 1.7;
  color: var(--ot-text-secondary);
}

.side-list {
  display: flex;
  flex-direction: column;
  margin-top: var(--ot-space-xs);
  gap: var(--ot-space-sm);
}

.side-item-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--ot-space-xs);
}

.side-item-name {
  overflow: hidden;
  font-size: var(--ot-font-size-sm);
  text-overflow: ellipsis;
  white-space: nowrap;
}

.side-link {
  margin-top: var(--ot-space-sm);
}

.side-empty :deep(.empty-state) {
  padding: var(--ot-space-md) 0;
}

.rate-row {
  display: flex;
  margin-top: var(--ot-space-xs);
  gap: var(--ot-space-sm);
}

.rate-cell {
  flex: 1 1 0;
  min-width: 0;
  padding: var(--ot-space-sm);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}

.bucket-bar {
  display: flex;
  height: 8px;
  margin-top: var(--ot-space-sm);
  overflow: hidden;
  border-radius: var(--ot-radius-sm);
}

.bucket-seg {
  height: 100%;
  background: var(--ot-border-subtle);
}

.bucket-seg-compliant {
  background: var(--ot-success);
}

.bucket-seg-overdue {
  background: var(--ot-danger);
}

.bucket-seg-due_soon {
  background: var(--ot-warning);
}

.bucket-seg-unverified {
  background: var(--ot-info);
}

.summary-row {
  display: flex;
  flex-wrap: wrap;
  gap: var(--ot-space-sm);
  margin-bottom: var(--ot-space-md);
}

.summary-cell {
  flex: 1 1 120px;
  padding: var(--ot-space-sm);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  cursor: pointer;
}

.summary-cell-active {
  border-color: var(--ot-primary);
}

.summary-value {
  font-size: var(--ot-font-size-lg);
  font-weight: 600;
  color: var(--ot-text-primary);
}

.summary-label {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}

.basis-icon {
  font-size: var(--ot-font-size-sm);
}

.filter-row {
  margin-bottom: var(--ot-space-sm);
}

.card-title {
  margin-right: var(--ot-space-sm);
  font-weight: 600;
}

.card-sub {
  margin-right: var(--ot-space-sm);
}

.sub {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
}

.tag-row {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  margin-top: 2px;
}

.full-width {
  width: 100%;
}

.pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: var(--ot-space-md);
}
</style>
