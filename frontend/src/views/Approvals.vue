<template>
  <div class="approvals">
    <PageHeader
      :title="$t('menu.approvals')"
      :description="historyOnly ? $t('approvals.historyOnlyNote') : $t('approvals.headerDesc')"
      :tag="historyOnly ? $t('approvals.readOnlyTag') : ''"
    >
      <template #actions>
        <el-button @click="fetchCurrentTab">
          <el-icon><RefreshCw /></el-icon>
          {{ $t('common.refresh') }}
        </el-button>
      </template>
    </PageHeader>

    <!-- 無審核資格：直接打 URL 進來時後端一律 403。此處必須明說
         「你沒有資格」，不得退化成一張空表格——那會被讀成「佇列是空的」 -->
    <div
      v-if="accessDenied"
      class="list-panel"
    >
      <EmptyState
        :icon="Lock"
        :title="$t('approvals.forbiddenTitle')"
        :hint="$t('approvals.forbiddenHint')"
      />
    </div>

    <!-- tabs 置頁面層（C8，對齊 Sessions/AuditLogs 結構），面板框在各頁籤內 -->
    <el-tabs
      v-else
      v-model="activeTab"
      @tab-change="onManualTabChange"
    >
      <!-- 待審 -->
      <el-tab-pane
        v-if="!historyOnly"
        :label="pendingLabel"
        name="pending"
      >
        <div class="list-panel">
          <!-- 由通知連結直達、待審清單裡沒有這張單：只用網址上的編號說明，不另外查這張單，
               所以不透露它是否存在、內容或由誰處理 -->
          <div
            v-if="directMissing === 'pending'"
            class="direct-notice"
            role="status"
            data-test="direct-not-found"
          >
            <el-icon class="direct-notice__icon">
              <Info />
            </el-icon>
            <span class="direct-notice__text">{{ $t('approvals.directNotFoundPending', { id: directId }) }}</span>
            <el-button
              size="small"
              data-test="direct-view-history"
              @click="viewDirectInHistory"
            >
              {{ $t('approvals.viewHistory') }}
            </el-button>
          </div>
          <!-- 批次列：勾選後出現。批次核准一律照申請內容，要調整請展開那一列逐項調整 -->
          <BatchSelectionBar
            v-if="pendingSelection.selected.value.length"
            test-id="pending-batch-bar"
            :count-text="$t('approvals.batch.selectedCount', { n: pendingSelection.selected.value.length })"
            :clear-text="$t('approvals.batch.clear')"
            :limit-text="limitText(pendingSelection, 'approvals.batch.limitHintSheets') || $t('approvals.batch.barHint')"
            @clear="pendingSelection.clear()"
          >
            <el-button
              type="danger"
              plain
              data-test="batch-reject-open"
              @click="pendingBatchRef?.open('reject')"
            >
              {{ $t('approvals.batch.rejectOpen', { n: pendingSelection.selected.value.length }) }}
            </el-button>
            <el-button
              type="primary"
              data-test="batch-approve-open"
              @click="pendingBatchRef?.open('approve')"
            >
              {{ $t('approvals.batch.approveOpen', { n: pendingSelection.selected.value.length }) }}
            </el-button>
          </BatchSelectionBar>
          <el-table
            ref="pendingTableRef"
            v-loading="loading"
            v-expand-row-a11y
            :data="pendingRequests"
            class="pending-table"
            data-test="pending-table"
            style="width: 100%"
            row-key="id"
            :row-class-name="(scope) => directRowClass('pending', scope)"
            @expand-change="onPendingExpand"
          >
            <el-table-column
              type="expand"
              width="40"
            >
              <template #default="{ row }">
                <!-- 展開區取表格的可見寬度、不隨表格橫捲：送出列與決定按鈕留在畫面內 -->
                <div
                  :class="['expand-sticky', { 'direct-expanded': isDirectRow('pending', row) }]"
                  data-test="expand-sticky"
                  :style="expandStyle"
                >
                  <PerItemApproval
                    :request="row"
                    :actor-id="currentUserId"
                    :adjusting="adjustingIds.has(row.id)"
                    :direct="isDirectRow('pending', row) && directFromLink"
                    :outcomes="outcomesByRequest[row.id] || {}"
                    @approve="openSingle(row, 'approve')"
                    @reject="openSingle(row, 'reject')"
                    @adjust="setAdjusting(row.id, true)"
                    @cancel-adjust="setAdjusting(row.id, false)"
                    @decided="afterItemDecision"
                  />
                </div>
              </template>
            </el-table-column>
            <!-- 主鍵欄：勾選框、單號（也是鍵盤可用的展開入口）與資產數；窄螢幕時申請人併在這一欄 -->
            <el-table-column
              :min-width="narrow ? 124 : 140"
              class-name="request-column"
            >
              <template #header>
                <BatchCheckbox
                  class="batch-select"
                  test-id="pending-select-all"
                  :checked="pendingPageState.checked"
                  :indeterminate="pendingPageState.indeterminate"
                  :disabled="pendingPageState.disabled"
                  :label="$t('approvals.batch.selectAllSheets')"
                  @change="pendingSelection.toggleAll(pendingRequests, canSelectPending)"
                />{{ $t('approvals.colRequest') }}
              </template>
              <template #default="{ row }">
                <div class="request-cell">
                  <BatchCheckbox
                    v-if="canSelectPending(row)"
                    class="batch-select"
                    test-id="pending-select-cell"
                    :data-id="row.id"
                    :checked="pendingSelection.isSelected(row)"
                    :disabled="!pendingSelection.canToggle(row, canSelectPending)"
                    :label="$t('approvals.batch.selectSheet', { id: row.id })"
                    @change="(checked) => pendingSelection.toggle(row, checked)"
                  />
                  <!-- 已沒有等這位審核人決定的項目：停用並說明原因 -->
                  <el-tooltip
                    v-else
                    :content="$t('approvals.batch.cannotSelect')"
                    placement="top"
                  >
                    <BatchCheckbox
                      class="batch-select"
                      test-id="pending-select-cell"
                      :data-id="row.id"
                      :checked="false"
                      disabled
                      :label="$t('approvals.batch.selectSheet', { id: row.id })"
                    />
                  </el-tooltip>
                  <div>
                    <!-- el-table 內建的展開圖示是 div，Tab 到不了、Enter 也按不下去。
                         展開的入口不能只有滑鼠可用 -->
                    <el-button
                      link
                      type="primary"
                      data-test="toggle-items"
                      :data-id="row.id"
                      @click="pendingTableRef?.toggleRowExpansion(row)"
                    >
                      {{ $t('approvals.requestNo', { id: row.id }) }}
                    </el-button>
                    <p class="sub-text">
                      <template v-if="narrow">
                        {{ row.requester?.username || `#${row.requester_id}` }}
                        <PrincipalBadge
                          v-if="row.requester?.kind"
                          :kind="row.requester.kind"
                          :owner-id="row.requester.owner_user_id"
                          :owner-name="row.requester.owner_username || (row.executor?.id === row.requester_id ? row.executor.owner_username : undefined)"
                        />
                        <span
                          v-if="row.executor && row.executor.id !== row.requester_id"
                          data-test="executor-principal"
                        >
                          {{ row.executor.username }} <PrincipalBadge
                            :kind="row.executor.kind"
                            :owner-id="row.executor.owner_user_id"
                            :owner-name="row.executor.owner_username"
                          />
                        </span>
                      </template>
                      <template v-else>
                        {{ $t('approvals.assetCount', { n: assetCount(row) }) }}
                      </template>
                    </p>
                  </div>
                </div>
              </template>
            </el-table-column>
            <el-table-column
              v-if="!narrow"
              :label="$t('approvals.colRequester')"
              min-width="130"
            >
              <template #default="{ row }">
                {{ row.requester?.username || `#${row.requester_id}` }}
                <PrincipalBadge
                  v-if="row.requester?.kind"
                  :kind="row.requester.kind"
                  :owner-id="row.requester.owner_user_id"
                  :owner-name="row.requester.owner_username || (row.executor?.id === row.requester_id ? row.executor.owner_username : undefined)"
                />
                <div
                  v-if="row.executor && row.executor.id !== row.requester_id"
                  data-test="executor-principal"
                >
                  {{ row.executor.username }} <PrincipalBadge
                    :kind="row.executor.kind"
                    :owner-id="row.executor.owner_user_id"
                    :owner-name="row.executor.owner_username"
                  />
                </div>
                <p v-else-if="!row.executor && row.executor_user_id && row.executor_user_id !== row.requester_id">
                  {{ $t('multiRequest.executorRef', { id: row.executor_user_id }) }}
                </p>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.asset')"
              :min-width="narrow ? 104 : 120"
            >
              <template #default="{ row }">
                <span data-test="asset-first">{{ assetNames(row)[0] }}</span>
                <el-tag
                  v-if="row.kind === 'break_glass'"
                  type="danger"
                  size="small"
                  effect="plain"
                >
                  {{ $t('common.emergency') }}
                </el-tag>
                <!-- 滑過或聚焦列出這張申請的全部資產（每列一個元件庫提示框在 200 列時太重，用原生提示） -->
                <p
                  v-if="assetCount(row) > 1"
                  class="sub-text asset-more"
                  tabindex="0"
                  data-test="asset-more"
                  :title="$t('approvals.assetAll', { names: assetNames(row).join(t('common.listSeparator')) })"
                  :aria-label="$t('approvals.assetAll', { names: assetNames(row).join(t('common.listSeparator')) })"
                >
                  {{ $t('approvals.assetMore', { n: assetCount(row), m: assetCount(row) - 1 }) }}
                </p>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.requestReason')"
              :min-width="narrow ? 96 : 130"
            >
              <template #default="{ row }">
                <span class="reason-clamp">{{ row.reason }}</span>
                <p class="sub-text">
                  {{ narrow ? formatShortDateTime(row.created_at) : $t('approvals.requestedAt', { time: formatShortDateTime(row.created_at) }) }}
                </p>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('approvals.colWishUse')"
              :width="narrow ? 84 : 100"
            >
              <template #default="{ row }">
                {{ formatMinutes(row.requested_duration_minutes) }}
                <div
                  v-if="row.requested_date_start"
                  class="sub-text"
                >
                  {{ $t('approvals.fromTime', { time: formatShortDateTime(row.requested_date_start) }) }}
                </div>
              </template>
            </el-table-column>
            <el-table-column
              v-if="quorumEnabled"
              :label="narrow ? $t('approvals.colProgressShort') : $t('approvals.colApprovalProgress')"
              :width="narrow ? 92 : 88"
            >
              <template #default="{ row }">
                <el-tooltip
                  :content="voterNames(row)"
                  :disabled="!approversOf(row).length"
                  placement="top"
                >
                  <span data-test="approval-progress">{{ approversOf(row).length }}/{{ requiredOf(row) }}</span>
                </el-tooltip>
                <p
                  v-if="approvedByMe(row, currentUserId)"
                  class="sub-text"
                  data-test="you-approved"
                >
                  {{ $t('approvals.youApproved') }}
                </p>
              </template>
            </el-table-column>
            <!-- 操作欄不固定在右側：固定欄在窄螢幕會蓋住其他欄。
                 展開時改為指向下方的說明，同一張申請在畫面上只有一組決定按鈕 -->
            <el-table-column
              :label="$t('common.actions')"
              :width="narrow ? 156 : 160"
              class-name="ops-column"
            >
              <template #default="{ row }">
                <!-- 上次送出沒有收到回應、也還查不到結果：不呈現成可以照常再按一次 -->
                <div
                  v-if="unconfirmedIds.has(row.id)"
                  class="row-unconfirmed"
                  data-test="row-unconfirmed"
                >
                  <span class="row-unconfirmed__tag">{{ $t('approvals.rowUnconfirmed') }}</span>
                  <el-button
                    link
                    type="primary"
                    size="small"
                    data-test="row-recheck"
                    @click="fetchPending"
                  >
                    {{ $t('approvals.batch.recheck') }}
                  </el-button>
                </div>
                <span
                  v-else-if="expandedIds.has(row.id)"
                  class="sub-text"
                  data-test="ops-below"
                >{{ $t('approvals.expandedOps') }}</span>
                <div
                  v-else
                  class="row-ops"
                >
                  <el-button
                    size="small"
                    type="danger"
                    plain
                    data-test="row-reject"
                    :data-id="row.id"
                    @click="openSingle(row, 'reject')"
                    @keydown.enter.prevent="openSingle(row, 'reject')"
                  >
                    {{ $t('approvals.reject') }}
                  </el-button>
                  <el-button
                    v-if="awaitsMe(row, currentUserId)"
                    size="small"
                    type="primary"
                    plain
                    data-test="row-approve"
                    :data-id="row.id"
                    @click="openSingle(row, 'approve')"
                    @keydown.enter.prevent="openSingle(row, 'approve')"
                  >
                    {{ $t('approvals.approve') }}
                  </el-button>
                  <span
                    v-else
                    class="sub-text"
                    data-test="row-waiting"
                  >{{ $t('approvals.waitOthers', { n: Math.max(1, othersNeeded(row)) }) }}</span>
                </div>
              </template>
            </el-table-column>
            <template #empty>
              <!-- 空清單要說得出「為什麼空」與「接下來去哪」：只寫一句沒有申請，
                   讀者分不出是真的沒有、還是自己站錯頁 -->
              <EmptyState
                :title="emptyTitleFor('approvals.emptyPending')"
                :hint="loadFailed ? '' : $t('approvals.emptyPendingHint')"
              />
            </template>
          </el-table>
          <!-- 全量數取待審計數（與側欄 badge 同源），放表格下方 -->
          <p
            class="loaded-of-total"
            data-test="pending-loaded-of-total"
          >
            <el-icon class="loaded-of-total-icon">
              <Info />
            </el-icon>
            <span>{{ $t('dashboard.loadedOfTotal', { loaded: pendingRequests.length, total: totalText(pendingTotal) }) }}</span>
          </p>
        </div>
      </el-tab-pane>

      <!-- 歷史 -->
      <el-tab-pane
        :label="$t('approvals.tabHistory')"
        name="history"
      >
        <div class="list-panel">
          <!-- 由逐項審核的「看這張申請單」帶進來時，那張單要自己展開；
               翻頁後不在本頁的要明說，不能靜靜地開一張看不出差別的歷史頁 -->
          <p
            v-if="highlightMissing"
            class="history-hint"
            data-test="history-highlight-missing"
          >
            {{ $t('approvals.requestNotOnPage', { id: highlightId }) }}
          </p>
          <el-table
            ref="historyTableRef"
            v-loading="loading"
            v-expand-row-a11y
            :data="historyRequests"
            class="history-table"
            row-key="id"
            :row-class-name="(scope) => directRowClass('history', scope)"
            style="width: 100%"
            stripe
          >
            <el-table-column type="expand">
              <template #default="{ row }">
                <div :class="['expand-sticky', { 'direct-expanded': isDirectRow('history', row) }]">
                  <p
                    v-if="isDirectRow('history', row) && directId && directFromLink"
                    class="history-direct"
                    data-test="history-direct-label"
                  >
                    <el-icon><Bell /></el-icon>{{ $t('itemReview.direct') }}
                  </p>
                  <RequestItems :request="row" />
                </div>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('approvals.colRequest')"
              min-width="130"
            >
              <template #default="{ row }">
                {{ $t('approvals.requestNo', { id: row.id }) }}<p
                  v-if="row.items"
                  class="sub-text"
                >
                  {{ $t('approvals.assetCount', { n: row.items.length }) }}
                </p>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('approvals.colRequester')"
              width="130"
            >
              <template #default="{ row }">
                {{ row.requester?.username || `#${row.requester_id}` }}
                <PrincipalBadge
                  v-if="row.requester?.kind"
                  :kind="row.requester.kind"
                  :owner-id="row.requester.owner_user_id"
                />
                <!-- 執行者就是申請人時只列一次 -->
                <div
                  v-if="row.executor && row.executor.id !== row.requester_id"
                  data-test="executor-principal"
                >
                  {{ row.executor.username }} <PrincipalBadge
                    :kind="row.executor.kind"
                    :owner-id="row.executor.owner_user_id"
                    :owner-name="row.executor.owner_username"
                  />
                </div>
                <p v-else-if="!row.executor && row.executor_user_id && row.executor_user_id !== row.requester_id">
                  {{ $t('multiRequest.executorRef', { id: row.executor_user_id }) }}
                </p>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.asset')"
              min-width="150"
            >
              <template #default="{ row }">
                {{ assetNames(row)[0] }}
                <p
                  v-if="assetCount(row) > 1"
                  class="sub-text"
                >
                  {{ $t('approvals.assetMore', { n: assetCount(row), m: assetCount(row) - 1 }) }}
                </p>
                <el-tag
                  v-if="row.kind === 'break_glass'"
                  type="danger"
                  size="small"
                  effect="plain"
                >
                  {{ $t('common.emergency') }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.requestReason')"
              min-width="200"
              show-overflow-tooltip
              prop="reason"
            />
            <el-table-column
              :label="$t('approvals.colResult')"
              width="120"
            >
              <template #default="{ row }">
                <el-tag :type="statusTagType(row.status)">
                  {{ statusText(row.status) }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('approvals.colHandler')"
              width="150"
            >
              <template #default="{ row }">
                <el-tag
                  v-if="row.auto_approved"
                  type="info"
                  size="small"
                >
                  {{ $t('common.systemAutoApproved') }}
                </el-tag>
                <!-- 核准人數以不同的人計，不以票數計（一人核准兩項仍是一人） -->
                <span
                  v-else
                  data-test="history-handler"
                >
                  {{ handlerNames(row) }}
                  <div
                    v-if="historyApprovers(row).length > 1"
                    class="sub-text"
                    data-test="approved-by-count"
                  >
                    {{ $t('approvals.approvedByCount', { n: historyApprovers(row).length }) }}
                  </div>
                </span>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('approvals.colHandledTime')"
              width="170"
            >
              <template #default="{ row }">
                {{ formatDateTime(row.decided_at) }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('approvals.note')"
              min-width="160"
              show-overflow-tooltip
            >
              <template #default="{ row }">
                {{ row.decision_note === 'system' ? '—' : row.decision_note || '—' }}
              </template>
            </el-table-column>
            <template #empty>
              <EmptyState :title="emptyTitleFor('approvals.emptyHistory')" />
            </template>
          </el-table>
          <div class="pagination">
            <el-pagination
              v-model:current-page="historyPage"
              v-model:page-size="historyPageSize"
              :page-sizes="[10, 20, 50, 100]"
              :total="historyTotal"
              layout="total, sizes, prev, pager, next, jumper"
              @size-change="handleHistorySizeChange"
              @current-change="fetchHistory"
            />
          </div>
        </div>
      </el-tab-pane>

      <!-- 有效限時連線 -->
      <el-tab-pane
        v-if="!historyOnly"
        :label="$t('approvals.tabTickets')"
        name="tickets"
      >
        <div class="list-panel">
          <el-table
            v-loading="loading"
            :data="ticketRows"
            class="tickets-table"
            data-test="tickets-table"
            style="width: 100%"
          >
            <!-- 同一張申請的列相鄰：第一列寫單號，其餘列寫「同一張申請」。清單依審核範圍過濾且有列數上限，
                 不寫整張的台數 -->
            <el-table-column
              :label="$t('approvals.colRequest')"
              min-width="120"
            >
              <template #default="{ row, $index }">
                <template v-if="row.request_id && ticketGroupStart($index)">
                  <span class="ticket-request">{{ $t('approvals.requestNo', { id: row.request_id }) }}</span>
                </template>
                <span
                  v-else-if="row.request_id"
                  class="sub-text"
                  data-test="same-request"
                >{{ $t('approvals.sameRequest') }}</span>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.user')"
              width="150"
            >
              <template #default="{ row }">
                {{ row.user?.username || `#${row.user_id}` }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.asset')"
              min-width="160"
            >
              <template #default="{ row }">
                {{ row.asset?.name || $t('common.assetRef', { id: row.asset_id }) }}
                <el-tag
                  v-if="row.kind === 'break_glass'"
                  type="danger"
                  size="small"
                  effect="plain"
                >
                  {{ $t('common.emergency') }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.connectableTime')"
              min-width="300"
            >
              <template #default="{ row }">
                {{ formatDateTime(row.date_start) }} ～ {{ formatDateTime(row.date_expired) }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('approvals.colApprover')"
              width="130"
            >
              <template #default="{ row }">
                {{ row.granted_by_user?.username || `#${row.granted_by}` }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.actions')"
              width="110"
              fixed="right"
            >
              <template #default="{ row }">
                <el-button
                  type="danger"
                  size="small"
                  link
                  @click="openRevokeDialog(row)"
                >
                  {{ $t('approvals.revokeEarly') }}
                </el-button>
              </template>
            </el-table-column>
            <template #empty>
              <EmptyState :title="emptyTitleFor('approvals.emptyTickets')" />
            </template>
          </el-table>
        </div>
      </el-tab-pane>

      <!-- 待補審：破窗連線事後補審 -->
      <el-tab-pane
        v-if="!historyOnly"
        :label="pendingReviewLabel"
        name="reviews"
      >
        <div class="list-panel">
          <div
            v-if="directMissing === 'reviews'"
            class="direct-notice"
            role="status"
            data-test="direct-not-found"
          >
            <el-icon class="direct-notice__icon">
              <Info />
            </el-icon>
            <span class="direct-notice__text">{{ $t('approvals.directNotFoundReview', { id: directId }) }}</span>
            <el-button
              size="small"
              data-test="direct-view-history"
              @click="viewDirectInHistory"
            >
              {{ $t('approvals.viewHistory') }}
            </el-button>
          </div>
          <!-- 批次只提供「確認無誤」；判定違規請逐筆補審 -->
          <BatchSelectionBar
            v-if="reviewSelection.selected.value.length"
            test-id="reviews-batch-bar"
            :count-text="$t('approvals.batch.reviewSelectedCount', { n: reviewSelection.selected.value.length })"
            :clear-text="$t('approvals.batch.clear')"
            :limit-text="limitText(reviewSelection, 'approvals.batch.limitHintItems')"
            @clear="reviewSelection.clear()"
          >
            <el-button
              type="primary"
              data-test="batch-review-open"
              @click="reviewBatchRef?.open()"
            >
              {{ $t('approvals.batch.reviewOpen') }}
            </el-button>
          </BatchSelectionBar>
          <el-table
            ref="reviewsTableRef"
            v-loading="loading"
            :data="pendingReviews"
            class="reviews-table"
            style="width: 100%"
            row-key="id"
            :row-class-name="(scope) => directRowClass('reviews', scope)"
            stripe
          >
            <el-table-column width="48">
              <template #header>
                <BatchCheckbox
                  test-id="reviews-select-all"
                  :checked="reviewPageState.checked"
                  :indeterminate="reviewPageState.indeterminate"
                  :disabled="reviewPageState.disabled"
                  :label="$t('approvals.batch.selectAllReviews')"
                  @change="reviewSelection.toggleAll(pendingReviews, selectAny)"
                />
              </template>
              <template #default="{ row }">
                <BatchCheckbox
                  test-id="reviews-select-cell"
                  :data-id="row.id"
                  :checked="reviewSelection.isSelected(row)"
                  :disabled="!reviewSelection.canToggle(row, selectAny)"
                  :label="$t('approvals.batch.selectReview', { user: row.requester?.username || `#${row.requester_id}` })"
                  @change="(checked) => reviewSelection.toggle(row, checked)"
                />
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.user')"
              width="130"
            >
              <template #default="{ row }">
                {{ row.requester?.username || `#${row.requester_id}` }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.asset')"
              min-width="150"
            >
              <template #default="{ row }">
                {{ row.asset?.name || $t('common.assetRef', { id: row.asset_id }) }}
                <el-tag
                  v-if="row.kind === 'break_glass'"
                  type="danger"
                  size="small"
                  effect="plain"
                >
                  {{ $t('common.emergency') }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('approvals.colEmergencyReason')"
              min-width="220"
              show-overflow-tooltip
            >
              <template #default="{ row }">
                {{ row.reason }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('approvals.colConnectTime')"
              width="170"
            >
              <template #default="{ row }">
                {{ formatDateTime(row.created_at) }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.actions')"
              width="140"
              fixed="right"
            >
              <template #default="{ row }">
                <el-button
                  link
                  type="primary"
                  size="small"
                  @click="openReviewDialog(row)"
                >
                  {{ $t('approvals.review') }}
                </el-button>
              </template>
            </el-table-column>
            <template #empty>
              <EmptyState :title="emptyTitleFor('approvals.emptyReviews')" />
            </template>
          </el-table>
          <!-- 全量數取待審計數（與側欄 badge 同源），放表格下方 -->
          <p
            class="loaded-of-total"
            data-test="reviews-loaded-of-total"
          >
            <el-icon class="loaded-of-total-icon">
              <Info />
            </el-icon>
            <span>{{ $t('dashboard.loadedOfTotal', { loaded: pendingReviews.length, total: totalText(reviewTotal) }) }}</span>
          </p>
        </div>
      </el-tab-pane>

      <!-- SQL 核准預留頁籤位（與現有核准共用同一收件匣，本版未開放） -->
      <el-tab-pane
        v-if="!historyOnly"
        :label="$t('approvals.tabSql')"
        name="sql"
        disabled
      />
    </el-tabs>

    <!-- 批次處理（逐張呼叫既有單張端點，非原子）：待審核准／拒絕、待補審確認無誤 -->
    <AccessRequestBatchDialog
      ref="pendingBatchRef"
      :requests="pendingSelection.selected.value"
      :current-user-id="currentUserId"
      @finished="afterPendingBatch"
    />
    <!-- 單張的整張核准、拒絕：沿用批次確認框的單張模式，送出內容與批次對單張相同 -->
    <AccessRequestBatchDialog
      ref="singleRef"
      single
      :requests="singleTarget ? [singleTarget] : []"
      :current-user-id="currentUserId"
      @finished="afterSingleDecision"
      @adjust="enterAdjustFromDialog"
    />
    <BreakGlassBatchReviewDialog
      ref="reviewBatchRef"
      :reviews="reviewSelection.selected.value"
      :current-user-id="currentUserId"
      @finished="afterReviewBatch"
    />

    <!-- 提前撤銷對話框：事由必填 -->
    <el-dialog
      v-model="revokeVisible"
      :title="$t('approvals.revokeDialogTitle', { id: revokeTarget?.request_id ?? '' })"
      width="520px"
      :close-on-click-modal="false"
      data-test="revoke-dialog"
    >
      <!-- 撤銷以申請為單位：列出清單中同一張申請、這次會一起收回的每一台與原本的到期時間 -->
      <el-alert
        v-if="revokeTarget"
        :title="$t('approvals.revokeAlertTitle')"
        type="warning"
        :closable="false"
        class="dialog-hint"
      >
        <template #default>
          <ul
            class="revoke-items"
            data-test="revoke-items"
          >
            <li
              v-for="ticket in revokeItems"
              :key="ticket.id"
            >
              {{ $t('approvals.revokeItemLine', {
                asset: ticket.asset?.name || $t('common.assetRef', { id: ticket.asset_id }),
                time: formatShortDateTime(ticket.date_expired),
              }) }}
            </li>
          </ul>
        </template>
      </el-alert>
      <p
        v-if="revokeTarget"
        class="revoke-body"
      >
        {{ $t('approvals.revokeAlertBody', { user: revokeTarget.user?.username || $t('common.user') }) }}
      </p>
      <el-form
        label-position="top"
        @submit.prevent
      >
        <el-form-item :label="$t('approvals.revokeReasonLabel')">
          <el-input
            v-model="revokeNote"
            type="textarea"
            :rows="3"
            maxlength="1000"
            :placeholder="$t('approvals.revokePlaceholder')"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="revokeVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="danger"
          :disabled="!revokeNote.trim()"
          :loading="deciding"
          data-test="revoke-submit"
          @click="submitRevoke"
        >
          {{ $t('approvals.revokeSubmit') }}
        </el-button>
      </template>
    </el-dialog>

    <!-- 補審對話框：處置＋備註 -->
    <el-dialog
      v-model="reviewVisible"
      :title="$t('approvals.reviewDialogTitle')"
      width="480px"
      :close-on-click-modal="false"
    >
      <div
        v-if="reviewTarget"
        class="approve-summary"
      >
        <i18n-t
          keypath="approvals.reviewSummary"
          tag="p"
          scope="global"
        >
          <template #user>
            <strong>{{ reviewTarget.requester?.username }}</strong>
          </template>
          <template #asset>
            <strong>{{ reviewTarget.asset?.name }}</strong>
          </template>
        </i18n-t>
        <p class="reason-text">
          {{ $t('approvals.reasonOriginLine', { reason: reviewTarget.reason }) }}
        </p>
      </div>
      <el-form
        label-position="top"
        @submit.prevent
      >
        <el-form-item :label="$t('approvals.reviewConclusionLabel')">
          <el-radio-group v-model="reviewForm.disposition">
            <el-radio label="confirmed">
              {{ $t('approvals.dispositionConfirmed') }}
            </el-radio>
            <el-radio label="violation">
              {{ $t('approvals.dispositionViolation') }}
            </el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item :label="$t('approvals.noteOptional')">
          <el-input
            v-model="reviewForm.note"
            type="textarea"
            :rows="2"
            maxlength="1000"
            :placeholder="$t('approvals.reviewNotePlaceholder')"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="reviewVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="deciding"
          @click="submitReview"
        >
          {{ $t('approvals.submitReview') }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { expandRowA11y as vExpandRowA11y } from '@/directives/expandRowA11y'
import { ref, computed, nextTick, onMounted, onBeforeUnmount, inject, watch, h } from 'vue'
import { routerKey } from 'vue-router'
import { useCapabilities } from '@/composables/useCapabilities'
import { RefreshCw, Lock, Info, Bell } from 'lucide-vue-next'
import { ElMessage } from 'element-plus'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import PrincipalBadge from '@/components/agent/PrincipalBadge.vue'
import RequestItems from '@/components/access-request/RequestItems.vue'
import PerItemApproval from '@/components/access-request/PerItemApproval.vue'
import BatchSelectionBar from '@/components/batch-review/BatchSelectionBar.vue'
import BatchCheckbox from '@/components/batch-review/BatchCheckbox.vue'
import AccessRequestBatchDialog from '@/components/batch-review/AccessRequestBatchDialog.vue'
import BreakGlassBatchReviewDialog from '@/components/batch-review/BreakGlassBatchReviewDialog.vue'
import { useBatchSelection } from '@/composables/useBatchReview'
import { formatDateTime, formatShortDateTime } from '@/utils/format'
import { useRoles } from '@/composables/useRoles'
import { parseApprovalsDirect, directInitialTab } from '@/components/access-request/approvalsDirect'
import {
  awaitsMe,
  approvedByMe,
  approversOf,
  requiredOf,
  othersNeeded,
  assetNames,
  assetCount,
  assetSummary,
  itemsAwaiting,
  requesterName,
  requestHref,
  formatMinutes,
  markInternalNav,
  consumeInternalNav,
} from '@/components/access-request/approvalsView'
import { t } from '@/i18n'
import {
  getPendingAccessRequests,
  getAccessRequestHistory,
  getActiveTickets,
  revokeAccessRequest,
  reviewBreakGlass,
  getPendingReviews,
  getPendingAccessRequestCount,
} from '@/api/accessRequests'

// 只持審核歷史讀取資格（稽核人員）：只有歷史分頁、唯讀，不讀待審、清冊、待補審與待審數
const { can } = useCapabilities()
const historyOnly = computed(() => !can('ui:approvals') && can('ui:approval-history'))
// 通知連結直達：tab 與 request 各自判斷，掛載前就決定頁籤，避免先開預設頁籤再切換
const direct = parseApprovalsDirect(window.location.search)
const activeTab = ref(directInitialTab(direct, { historyOnly: historyOnly.value }))
const loading = ref(false)
const deciding = ref(false)

const pendingRequests = ref([])
const pendingTableRef = ref(null)
const historyRequests = ref([])
const historyPage = ref(1)
const historyPageSize = ref(20)
const historyTotal = ref(0)
const tickets = ref([])
const pendingReviews = ref([])

// 頁籤數字取全量（與「已載入 N 筆，共 M 筆」的 M 同源）；列表被截斷時不得以已載入列數代替。
// 全量讀不到（null）或為 0 時只顯示頁籤名，不用載入數冒充
const pendingLabel = computed(() =>
  pendingTotal.value > 0
    ? t('approvals.pendingTabCount', { n: pendingTotal.value })
    : t('approvals.pendingTab')
)

// quorum：門檻 >1 才顯示進度欄
const { currentUserId } = useRoles()
const quorumEnabled = computed(() =>
  pendingRequests.value.some((r) => requiredOf(r) > 1)
)
const voterNames = (row) =>
  t('approvals.votedList', {
    names: approversOf(row).map((a) => a.name).join(t('common.listSeparator')),
  })
const pendingReviewLabel = computed(() =>
  reviewTotal.value > 0
    ? t('approvals.reviewTabCount', { n: reviewTotal.value })
    : t('approvals.reviewTab')
)

// —— 窄螢幕：1024 寬時申請人併入申請欄，欄寬收斂，操作欄不固定 ——
const NARROW_BELOW = 1200
const narrow = ref(typeof window !== 'undefined' && window.innerWidth < NARROW_BELOW)
const onResize = () => { narrow.value = window.innerWidth < NARROW_BELOW }
// 展開區取表格容器的可見寬度並黏在左側：表格即使橫捲，展開內容與送出列也不跟著捲出去
const visibleWidth = ref(0)
let resizeObserver = null
const expandStyle = computed(() => ({
  position: 'sticky',
  left: '0',
  ...(visibleWidth.value ? { width: `${visibleWidth.value}px` } : {}),
}))

// 載入結果狀態：**403 不得被吞成空陣列**。
// 不具審核資格者（例如僅具 admin 者，審核端點對他一律 403）看到空表格會把
// 「你看不到」謊報成「沒有東西」。'forbidden'＝無資格；'failed'＝其他載入失敗
const accessDenied = ref(false)
const loadFailed = ref(false)

const handleFetchError = (error, label) => {
  console.error(label, error)
  if (error?.response?.status === 403) {
    accessDenied.value = true
  } else {
    loadFailed.value = true
  }
}

// 任一頁籤載入成功即代表資格與連線正常，清掉兩個錯誤狀態
const markFetchOk = () => {
  accessDenied.value = false
  loadFailed.value = false
}

// 空態文案：載入失敗時不得沿用「沒有資料」的說法
const emptyTitleFor = (key) =>
  loadFailed.value ? t('approvals.loadFailed') : t(key)

// --- 批次處理：勾選以 id 去重、上限 BATCH_LIMIT；列表重讀即清空勾選 ---
const pendingSelection = useBatchSelection()
const reviewSelection = useBatchSelection()
const pendingBatchRef = ref(null)
const reviewBatchRef = ref(null)
// 待審：只有還有等這位審核人決定之項目的單可勾（已投票、等其他審核人的單送出必定被拒）。
// 待補審已排除本人破窗；其餘資格由伺服端逐張判定
const canSelectPending = (row) => awaitsMe(row, currentUserId.value)
const selectAny = () => true
const pendingPageState = computed(() => pendingSelection.pageState(pendingRequests.value, canSelectPending))
const reviewPageState = computed(() => reviewSelection.pageState(pendingReviews.value, selectAny))
const limitText = (selection, key) =>
  selection.atLimit.value || selection.truncated.value ? t(key, { limit: selection.limit }) : ''
const notifyApprovalsChanged = () => window.dispatchEvent(new CustomEvent('ot-approvals-changed'))
const afterPendingBatch = async () => {
  notifyApprovalsChanged()
  await fetchPending()
}
const afterReviewBatch = () => {
  notifyApprovalsChanged()
  void fetchReviews()
}

// 全量數：與側欄 badge 讀同一個計數端點（count＝待審、review_count＝待補審）。
// 讀不到就顯示「未取得」，不用載入數冒充全量
const pendingTotal = ref(null)
const reviewTotal = ref(null)
const totalText = (n) => (n === null ? t('dashboard.valueUnavailable') : n)
let countSeq = 0
const fetchTotals = async () => {
  const seq = ++countSeq
  try {
    const res = await getPendingAccessRequestCount({ skipErrorToast: true })
    if (seq !== countSeq) return
    pendingTotal.value = typeof res?.count === 'number' ? res.count : null
    reviewTotal.value = typeof res?.review_count === 'number' ? res.review_count : null
  } catch {
    if (seq !== countSeq) return
    pendingTotal.value = null
    reviewTotal.value = null
  }
}

const fetchPending = async () => {
  loading.value = true
  pendingSelection.clear()
  const totals = fetchTotals()
  try {
    const res = await getPendingAccessRequests()
    pendingRequests.value = res.data || []
    markFetchOk()
    // 讀得到清單時清單本身就是事實：上次無法確認的標示一併清掉
    unconfirmedIds.value = new Set()
    pruneRowState()
  } catch (error) {
    handleFetchError(error, '載入待審申請失敗:')
  } finally {
    loading.value = false
  }
  await totals
}

const fetchHistory = async () => {
  loading.value = true
  try {
    const res = await getAccessRequestHistory({
      page: historyPage.value,
      page_size: historyPageSize.value,
    })
    historyRequests.value = res.data || []
    historyTotal.value = res.total ?? 0
    markFetchOk()
    // 要標示的單在每次載入（含翻頁）後重新判斷是否在這一頁
    if (highlightId.value) await revealHighlight()
  } catch (error) {
    handleFetchError(error, '載入申請歷史失敗:')
  } finally {
    loading.value = false
  }
}

const handleHistorySizeChange = () => {
  historyPage.value = 1
  void fetchHistory()
}

const fetchTickets = async () => {
  loading.value = true
  try {
    const res = await getActiveTickets()
    tickets.value = res.data || []
    markFetchOk()
  } catch (error) {
    handleFetchError(error, '載入限時連線失敗:')
  } finally {
    loading.value = false
  }
}

const fetchReviews = async () => {
  loading.value = true
  reviewSelection.clear()
  void fetchTotals()
  try {
    const res = await getPendingReviews()
    pendingReviews.value = res.data || []
    markFetchOk()
  } catch (error) {
    handleFetchError(error, '載入待補審失敗:')
  } finally {
    loading.value = false
  }
}

const fetchCurrentTab = () => {
  if (historyOnly.value) {
    void fetchHistory()
    return
  }
  if (activeTab.value === 'pending') void fetchPending()
  else if (activeTab.value === 'history') void fetchHistory()
  else if (activeTab.value === 'tickets') void fetchTickets()
  else if (activeTab.value === 'reviews') void fetchReviews()
}

// —— 待審列的展開、逐項調整與送出結果 ——
const expandedIds = ref(new Set())
const adjustingIds = ref(new Set())
const unconfirmedIds = ref(new Set())
// 逐項調整送出後各項的結果文字：頁面重讀清單後，仍在待審的單照樣看得到自己剛做了什麼
const outcomesByRequest = ref({})

const onPendingExpand = (row, expandedRows) => {
  const list = Array.isArray(expandedRows) ? expandedRows : null
  const next = new Set(list ? list.map((r) => r.id) : expandedIds.value)
  if (!list) {
    if (expandedRows) next.add(row.id)
    else next.delete(row.id)
  }
  expandedIds.value = next
  // 收合即離開逐項調整，已選的決定不保留
  if (!next.has(row.id)) setAdjusting(row.id, false)
}

function setAdjusting(id, on) {
  const next = new Set(adjustingIds.value)
  if (on) next.add(id)
  else next.delete(id)
  adjustingIds.value = next
}

// 重讀後已不在清單的單：展開、調整、結果一併清掉
function pruneRowState() {
  const ids = new Set(pendingRequests.value.map((r) => r.id))
  expandedIds.value = new Set([...expandedIds.value].filter((id) => ids.has(id)))
  adjustingIds.value = new Set([...adjustingIds.value].filter((id) => ids.has(id)))
  const kept = {}
  for (const [id, value] of Object.entries(outcomesByRequest.value)) {
    if (ids.has(Number(id))) kept[id] = value
  }
  outcomesByRequest.value = kept
}

// —— 單張的整張核准與拒絕 ——
const singleRef = ref(null)
const singleTarget = ref(null)
const openSingle = async (row, kind) => {
  singleTarget.value = row
  await nextTick()
  await singleRef.value?.open(kind)
}

// 確認框的「改用逐項調整」：展開這一列並直接進入逐項調整
const enterAdjustFromDialog = async (id) => {
  const row = pendingRequests.value.find((r) => r.id === id)
  if (!row) return
  pendingTableRef.value?.toggleRowExpansion(row, true)
  const next = new Set(expandedIds.value)
  next.add(id)
  expandedIds.value = next
  setAdjusting(id, true)
}

// 結果提示：寫結果本身並附「看這張申請單」；停留較久、滑過不消失、可關閉
const router = inject(routerKey, null)
const notify = ({ type, title, body, id }) => {
  const href = requestHref(id)
  const onClick = (event) => {
    markInternalNav(id)
    if (!router) return
    event.preventDefault()
    void router.push(href).catch(() => {})
  }
  ElMessage({
    type,
    message: h('div', { class: 'decision-toast', 'data-test': 'decision-toast' }, [
      h('strong', { class: 'decision-toast__title' }, title),
      body ? h('p', { class: 'decision-toast__body' }, body) : null,
      h('a', { href, class: 'decision-toast__link', onClick }, t('itemReview.openRequest')),
    ]),
    duration: 8000,
    showClose: true,
    grouping: false,
    customClass: `decision-toast--${type}`,
  })
}

// 決定送出後：重讀待審清單與計數（頁籤、表格下方、側欄三處同源），焦點移到下一列
async function refreshAfterDecision(id) {
  const before = pendingRequests.value.map((r) => r.id)
  const index = before.indexOf(id)
  notifyApprovalsChanged()
  await fetchPending()
  if (directFound.value?.tab === 'pending' && directFound.value.id === id) {
    clearDirect()
    syncDirectQuery('pending', null)
  } else if (directId.value === id) {
    clearDirect()
    syncDirectQuery('pending', null)
  }
  const stillThere = pendingRequests.value.find((r) => r.id === id) || null
  const candidates = stillThere ? [id] : [...before.slice(index + 1), ...before.slice(0, Math.max(0, index)).reverse()]
  const nextId = candidates.find((candidate) => pendingRequests.value.some((r) => r.id === candidate))
  await nextTick()
  if (nextId != null) {
    pendingTableRef.value?.$el?.querySelector(`[data-test="toggle-items"][data-id="${nextId}"]`)?.focus?.()
  }
  return stillThere
}

async function afterSingleDecision(info) {
  const req = info.request || {}
  const id = info.id
  const user = requesterName(req)
  const row = await refreshAfterDecision(id)
  if (info.alreadyVoted) {
    notify({ type: 'warning', title: t('approvals.done.alreadyVotedTitle', { id }), body: t('approvals.done.alreadyVotedBody'), id })
    return
  }
  if (info.gone) {
    // 重讀後仍在待審：狀態有變動，不說它已不在待審
    if (row) notify({ type: 'warning', title: t('approvals.done.changedTitle', { id }), body: t('approvals.done.changedBody'), id })
    else notify({ type: 'warning', title: t('approvals.done.goneTitle', { id }), body: t('approvals.done.goneBody'), id })
    return
  }
  if (info.notDelivered) {
    notify({ type: 'info', title: t('approvals.done.notDeliveredTitle', { id }), body: t('approvals.done.notDeliveredBody'), id })
    return
  }
  if (info.unconfirmed || info.failed) {
    if (row && info.unconfirmed) unconfirmedIds.value = new Set([...unconfirmedIds.value, id])
    notify({
      type: 'warning',
      title: t('approvals.done.unconfirmedTitle', { id }),
      body: row && info.unconfirmed ? t('approvals.done.unconfirmedBody') : t('approvals.done.unconfirmedGoneBody'),
      id,
    })
    return
  }
  if (info.kind === 'reject') {
    notify({ type: 'success', title: t('approvals.done.rejectedTitle', { id }), body: t('approvals.done.rejectedBody', { user }), id })
    return
  }
  const outcome = info.outcome || {}
  if (info.waiting || outcome.kind === 'voted' || outcome.kind === 'partly') {
    const required = outcome.required || (row ? requiredOf(row) : requiredOf(req))
    const received = outcome.received || (row ? approversOf(row).length : approversOf(req).length + 1)
    notify({
      type: 'info',
      title: t('approvals.done.votedTitle', { received, required }),
      body: t('approvals.done.votedBody', { id, left: Math.max(1, required - received), user }),
      id,
    })
    return
  }
  notify({
    type: 'success',
    title: t('approvals.done.approvedTitle', { id }),
    body: t('approvals.done.approvedBody', { user, asset: assetSummary(req), duration: formatMinutes(req.requested_duration_minutes) }),
    id,
  })
}

// 逐項調整送出後：每一項的結果寫在該台上；仍在待審的單留在清單，處理完的單以提示呈現
async function afterItemDecision({ requestId, results, actionLabel }) {
  const req = pendingRequests.value.find((r) => r.id === requestId) || {}
  const user = requesterName(req)
  const ok = results.filter((r) => ['approved', 'voted', 'rejected'].includes(r.kind))
  const problem = results.filter((r) => ['gone', 'failed', 'unknown'].includes(r.kind))
  const outcomes = { ...(outcomesByRequest.value[requestId] || {}) }
  const lines = []
  for (const r of results) {
    const duration = formatMinutes(r.duration)
    switch (r.kind) {
      case 'approved':
        outcomes[r.itemId] = { tone: 'ok', text: r.shortened ? t('itemReview.res.approved', { duration, user }) : t('itemReview.res.approvedPlain', { user }) }
        lines.push(r.shortened ? t('approvals.done.lineApprovedShort', { asset: r.asset, duration }) : t('approvals.done.lineApproved', { asset: r.asset }))
        break
      case 'voted': {
        const required = r.required || 1
        const received = r.received || 1
        outcomes[r.itemId] = { tone: 'info', text: t('itemReview.res.voted', { received, required, left: Math.max(0, required - received), user }) }
        lines.push(t('approvals.done.lineVoted', { asset: r.asset, received, required }))
        break
      }
      case 'rejected':
        outcomes[r.itemId] = { tone: 'ok', text: t('itemReview.res.rejected') }
        lines.push(t('approvals.done.lineRejected', { asset: r.asset, user }))
        break
      case 'gone':
        outcomes[r.itemId] = { tone: 'warn', text: t('itemReview.res.gone', { action: actionLabel(r.action) }) }
        lines.push(t('approvals.done.itemGone', { asset: r.asset, action: actionLabel(r.action) }))
        break
      case 'failed':
        outcomes[r.itemId] = { tone: 'error', text: r.text }
        lines.push(t('approvals.done.lineFailed', { asset: r.asset, reason: r.text }))
        break
      default:
        outcomes[r.itemId] = { tone: 'warn', text: t('approvals.batch.state.unconfirmed') }
        lines.push(t('approvals.done.lineFailed', { asset: r.asset, reason: t('approvals.batch.state.unconfirmed') }))
    }
  }
  outcomesByRequest.value = { ...outcomesByRequest.value, [requestId]: outcomes }
  // 伺服器沒有接受、仍可再決定的台：留在調整模式讓審核人改了再送；其餘回到唯讀
  const keepAdjusting = results.some((r) => r.kind === 'failed')
  if (!keepAdjusting) setAdjusting(requestId, false)
  const row = await refreshAfterDecision(requestId)
  const body = lines.join(t('common.listSeparator') === '、' ? '；' : '; ')
  if (!row) {
    if (problem.length && !ok.length && results.every((r) => r.kind === 'gone')) {
      notify({ type: 'warning', title: t('approvals.done.goneTitle', { id: requestId }), body: t('approvals.done.goneBody'), id: requestId })
    } else if (problem.length) {
      notify({ type: 'warning', title: t('approvals.done.mixedTitle', { id: requestId, n: problem.length }), body, id: requestId })
    } else {
      notify({ type: 'success', title: t('approvals.done.allTitle', { id: requestId }), body, id: requestId })
    }
    return
  }
  const left = itemsAwaiting(row, currentUserId.value).length
  const leftText = left ? t('approvals.done.partBody', { id: requestId, n: left }) : t('approvals.done.partNone', { id: requestId })
  if (ok.length && ok.every((r) => r.kind === 'voted') && !problem.length) {
    const first = ok[0]
    const required = first.required || requiredOf(row)
    const received = first.received || approversOf(row).length
    notify({
      type: 'info',
      title: t('approvals.done.votedTitle', { received, required }),
      body: t('approvals.done.votedBody', { id: requestId, left: Math.max(1, required - received), user }),
      id: requestId,
    })
    return
  }
  if (results.length === 1 && results[0].kind === 'approved') {
    const r = results[0]
    notify({
      type: 'success',
      title: r.shortened
        ? t('approvals.done.partTitle', { asset: r.asset, duration: formatMinutes(r.duration) })
        : t('approvals.done.partTitlePlain', { asset: r.asset }),
      body: leftText,
      id: requestId,
    })
    return
  }
  notify({ type: problem.length ? 'warning' : 'success', title: body, body: leftText, id: requestId })
}

// —— 有效限時連線：同一張申請的列相鄰；撤銷以申請為單位 ——
const ticketRows = computed(() => {
  const order = new Map()
  tickets.value.forEach((ticket, index) => {
    const key = ticket.request_id ?? `t${ticket.id}`
    if (!order.has(key)) order.set(key, index)
  })
  return [...tickets.value]
    .map((ticket, index) => ({ ticket, index }))
    .sort((a, b) => {
      const ka = order.get(a.ticket.request_id ?? `t${a.ticket.id}`)
      const kb = order.get(b.ticket.request_id ?? `t${b.ticket.id}`)
      return ka - kb || a.index - b.index
    })
    .map(({ ticket }) => ticket)
})
const ticketsOfRequest = (requestId) => ticketRows.value.filter((ticket) => ticket.request_id === requestId)
const ticketGroupStart = (index) => index === 0 || ticketRows.value[index - 1]?.request_id !== ticketRows.value[index]?.request_id

// 提前撤銷：撤銷整張申請（帶 request_id、不帶 item_id），事由必填
const revokeVisible = ref(false)
const revokeTarget = ref(null)
const revokeNote = ref('')
const revokeItems = computed(() => {
  const target = revokeTarget.value
  if (!target) return []
  const same = target.request_id != null ? ticketsOfRequest(target.request_id) : []
  return same.length ? same : [target]
})

const openRevokeDialog = (row) => {
  revokeTarget.value = row
  revokeNote.value = ''
  revokeVisible.value = true
}

const submitRevoke = async () => {
  if (!revokeTarget.value || !revokeNote.value.trim()) return
  deciding.value = true
  try {
    // 有效限時連線列的 id 是授權記錄，撤銷走申請單——後端以 authorization_id
    // 回鏈，故此處帶申請單 id（票證列附 request_id）
    await revokeAccessRequest(revokeTarget.value.request_id, revokeNote.value.trim())
    ElMessage.success(t('approvals.revokeSuccess'))
    revokeVisible.value = false
  } catch (error) {
    // 403 非資格、409 已撤/到期由攔截器顯示後端訊息
    console.error('撤銷失敗:', error)
  } finally {
    deciding.value = false
    void fetchTickets()
  }
}

// 補審：破窗事後審核，處置＋備註
const reviewVisible = ref(false)
const reviewTarget = ref(null)
const reviewForm = ref({ disposition: 'confirmed', note: '' })

const openReviewDialog = (row) => {
  reviewTarget.value = row
  reviewForm.value = { disposition: 'confirmed', note: '' }
  reviewVisible.value = true
}

const submitReview = async () => {
  if (!reviewTarget.value) return
  deciding.value = true
  try {
    await reviewBreakGlass(
      reviewTarget.value.id,
      reviewForm.value.disposition,
      reviewForm.value.note || ''
    )
    ElMessage.success(t('approvals.reviewSuccess'))
    reviewVisible.value = false
  } catch (error) {
    // 403 自審/範圍外、409 已補審由攔截器顯示後端訊息
    console.error('補審失敗:', error)
  } finally {
    deciding.value = false
    void fetchReviews()
  }
}

const statusText = (status) => {
  const map = {
    approved: t('approvals.status.approved'),
    rejected: t('approvals.status.rejected'),
    cancelled: t('approvals.status.cancelled'),
    expired: t('approvals.status.expired'),
  }
  return map[status] || status
}

const statusTagType = (status) => {
  const map = {
    approved: 'success',
    rejected: 'danger',
    cancelled: 'info',
    expired: 'info',
  }
  return map[status] || 'info'
}

// 歷史的處理人：核准人以不同的人計（同一人核准多項只算一次），沒有核准票時沿用決定者
const historyApprovers = (row) => {
  const seen = new Map()
  const add = (vote) => {
    if (vote?.approver_id == null || seen.has(vote.approver_id)) return
    seen.set(vote.approver_id, vote.approver?.username || `#${vote.approver_id}`)
  }
  ;(row.approvals || []).forEach(add)
  ;(row.items || []).forEach((item) => (item.approvals || []).forEach(add))
  return [...seen.values()]
}
const handlerNames = (row) => {
  const approvers = historyApprovers(row)
  if (row.status === 'approved' && approvers.length) return approvers.join(t('common.listSeparator'))
  return row.approver?.username || '—'
}

// 逐項審核送出後的「看這張申請單」：不具 audit:view 的審核者導到這裡，
// 直接落在歷史頁的那一張單上並展開逐項結果。翻頁後仍找不到時要明說
// 「不在這一頁」，不能靜靜地開一張看不出差別的歷史頁
const highlightId = ref(null)
const highlightMissing = ref(false)
const historyTableRef = ref(null)
// 找得到時比照待審與待補審的直達：標示該列、展開、捲到畫面中央並把焦點移到列容器
const revealHighlight = async () => {
  if (!highlightId.value) return
  const row = historyRequests.value.find((item) => item.id === highlightId.value)
  highlightMissing.value = !row
  if (!row) {
    if (directFound.value?.tab === 'history') directFound.value = null
    return
  }
  directFound.value = { tab: 'history', id: row.id }
  await nextTick()
  historyTableRef.value?.toggleRowExpansion(row, true)
  await nextTick()
  focusDirectRow(historyTableRef)
}

// —— 通知連結直達 ——
// 找得到：捲到該列、加標示（涵蓋列與展開內容）、把鍵盤焦點移到列容器（tabindex=-1 的列本身，
// 不是任何按鈕、連結或表單控件，按 Enter 不觸發任何操作）；待審另展開唯讀內容，
// 不開任何決定對話框、不進入逐項調整、不預選決定。
// 找不到（待審、待補審）：清單上方說明加「查看歷史」，只用網址上的編號。
// 載入失敗與 403 沿用既有呈現，不顯示「找不到」。
const directId = ref(direct.request)
// 只有從網址帶單號進入（通知連結）才標「你從通知連結進來」；站內的「看這張申請單」「查看歷史」不標
const directFromLink = ref(!!direct.request && !consumeInternalNav(direct.request))
const directFound = ref(null) // { tab, id }
const directMissing = ref(null) // 'pending' | 'reviews'
const reviewsTableRef = ref(null)

const isDirectRow = (tab, row) =>
  !!directFound.value && directFound.value.tab === tab && row.id === directFound.value.id
const directRowClass = (tab, { row }) => (isDirectRow(tab, row) ? 'direct-row' : '')

const focusDirectRow = (tableRef) => {
  const tr = tableRef.value?.$el?.querySelector('tr.direct-row')
  if (!tr) return
  tr.setAttribute('tabindex', '-1')
  tr.focus({ preventScroll: true })
  tr.scrollIntoView?.({ block: 'center' })
}

const revealDirect = async (tab) => {
  if (!directId.value || accessDenied.value || loadFailed.value) return
  const list = tab === 'pending' ? pendingRequests.value : pendingReviews.value
  const row = list.find((item) => item.id === directId.value)
  if (!row) {
    directMissing.value = tab
    return
  }
  directMissing.value = null
  directFound.value = { tab, id: row.id }
  const tableRef = tab === 'pending' ? pendingTableRef : reviewsTableRef
  await nextTick()
  if (tab === 'pending') {
    tableRef.value?.toggleRowExpansion(row, true)
    const next = new Set(expandedIds.value)
    next.add(row.id)
    expandedIds.value = next
    await nextTick()
  }
  focusDirectRow(tableRef)
}

// 網址：頁籤參數跟著目前頁籤，request 依呼叫端決定保留或移除；其他參數原樣保留
const syncDirectQuery = (tab, request) => {
  const params = new URLSearchParams(currentSearch())
  params.set('tab', tab)
  if (request) params.set('request', String(request))
  else params.delete('request')
  const query = Object.fromEntries(params.entries())
  if (router) {
    void router.replace({ query }).catch(() => {})
    return
  }
  const qs = params.toString()
  window.history.replaceState(window.history.state, '', `${window.location.pathname}${qs ? `?${qs}` : ''}`)
}

const clearDirect = () => {
  directId.value = null
  directFound.value = null
  directMissing.value = null
  highlightId.value = null
  highlightMissing.value = false
}

// 使用者手動切頁籤：移除網址上的單號，畫面上的直達標示一併清掉
const onManualTabChange = (tab) => {
  // 換頁籤不保留逐項調整中沒有送出的選擇
  adjustingIds.value = new Set()
  if (directId.value || highlightId.value) {
    clearDirect()
    syncDirectQuery(tab, null)
  }
  fetchCurrentTab()
}

// 「查看歷史」：落到歷史頁籤並標出這張單（歷史頁籤既有的展開與「不在這一頁」）
const viewDirectInHistory = async () => {
  const id = directId.value
  directFromLink.value = false
  directMissing.value = null
  directFound.value = null
  highlightId.value = id
  activeTab.value = 'history'
  syncDirectQuery('history', id)
  await fetchHistory()
}

// 依頁籤讀清單並套用直達（進入頁面與站內換網址共用）
async function loadTab(tab, request) {
  if (tab === 'history') {
    if (request) highlightId.value = request
    await fetchHistory()
    return
  }
  if (tab === 'pending') {
    await fetchPending()
    await revealDirect('pending')
    return
  }
  if (tab === 'reviews') {
    await fetchReviews()
    await revealDirect('reviews')
    return
  }
  await fetchTickets()
}

const currentSearch = () => {
  if (router) {
    const query = router.currentRoute.value?.query || {}
    const params = new URLSearchParams()
    for (const [key, value] of Object.entries(query)) {
      for (const v of Array.isArray(value) ? value : [value]) {
        if (v != null) params.append(key, String(v))
      }
    }
    return params.toString()
  }
  return window.location.search
}

// 已在審核中心時於同一頁面內改換成直達網址（站內連結、瀏覽紀錄）：同樣切頁籤、捲動、標示、展開。
// 由本頁自己改網址（切頁籤、查看歷史、決定後移除單號）時參數與畫面已一致，不重複套用
async function applyDirectFromLocation() {
  const parsed = parseApprovalsDirect(currentSearch())
  const tab = directInitialTab(parsed, { historyOnly: historyOnly.value })
  const current = directId.value ?? highlightId.value ?? null
  if (tab === activeTab.value && (parsed.request ?? null) === current) return
  clearDirect()
  directId.value = parsed.request
  directFromLink.value = !!parsed.request && !consumeInternalNav(parsed.request)
  activeTab.value = tab
  await loadTab(tab, parsed.request)
}

let stopRouteWatch = null
const onPopState = () => { void applyDirectFromLocation() }

onMounted(async () => {
  window.addEventListener('resize', onResize)
  if (typeof ResizeObserver !== 'undefined') {
    resizeObserver = new ResizeObserver((entries) => {
      const width = entries[0]?.contentRect?.width
      if (width) visibleWidth.value = Math.floor(width)
    })
    const el = pendingTableRef.value?.$el
    if (el) resizeObserver.observe(el)
  }
  if (router) {
    stopRouteWatch = watch(() => router.currentRoute.value?.fullPath, (path, old) => {
      if (path !== old && router.currentRoute.value?.path?.startsWith('/approvals')) void applyDirectFromLocation()
    })
  } else {
    window.addEventListener('popstate', onPopState)
  }
  await loadTab(activeTab.value, direct.request)
})

onBeforeUnmount(() => {
  window.removeEventListener('resize', onResize)
  window.removeEventListener('popstate', onPopState)
  resizeObserver?.disconnect()
  stopRouteWatch?.()
})
</script>

<style scoped>
/* 「這張單不在本頁」是要照著做的指示（去翻頁），不是背景說明，留在主文字色 */
.loaded-of-total {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs, 4px);
  margin: var(--ot-space-md) 0 0;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.direct-notice {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  margin: 0 0 var(--ot-space-md);
  padding: var(--ot-space-sm) var(--ot-space-md);
  border: 1px solid var(--ot-border);
  border-radius: var(--ot-radius-md);
  background: var(--ot-bg-elevated);
  color: var(--ot-text-primary);
  font-size: var(--ot-font-size-sm);
  line-height: 1.6;
}

.direct-notice__icon {
  flex: none;
  color: var(--ot-primary);
}

.direct-notice__text {
  flex: 1;
  min-width: 0;
}

/* 直達的那一張：列與其展開內容用同一個外框框在一起（左側色條、淡底），
   聚焦與未聚焦同一樣式，不另畫焦點圈 */
.approvals :deep(.el-table__row.direct-row > td.el-table__cell) {
  background-color: color-mix(in srgb, var(--ot-info) 10%, transparent);
  box-shadow: inset 0 2px 0 0 var(--ot-info), inset 0 -2px 0 0 var(--ot-info);
}

.approvals :deep(.el-table__row.direct-row > td.el-table__cell:first-child) {
  box-shadow: inset 5px 0 0 0 var(--ot-info), inset 0 2px 0 0 var(--ot-info), inset 0 -2px 0 0 var(--ot-info);
}

.approvals :deep(.el-table__row.direct-row > td.el-table__cell:last-child) {
  box-shadow: inset -2px 0 0 0 var(--ot-info), inset 0 2px 0 0 var(--ot-info), inset 0 -2px 0 0 var(--ot-info);
}

/* 展開時：列與下方展開內容合成一個外框（列不畫下緣，由展開區畫下緣） */
.approvals :deep(.el-table__row.direct-row:has(+ tr > td.el-table__expanded-cell) > td.el-table__cell) {
  box-shadow: inset 0 2px 0 0 var(--ot-info);
}

.approvals :deep(.el-table__row.direct-row:has(+ tr > td.el-table__expanded-cell) > td.el-table__cell:first-child) {
  box-shadow: inset 5px 0 0 0 var(--ot-info), inset 0 2px 0 0 var(--ot-info);
}

.approvals :deep(.el-table__row.direct-row:has(+ tr > td.el-table__expanded-cell) > td.el-table__cell:last-child) {
  box-shadow: inset -2px 0 0 0 var(--ot-info), inset 0 2px 0 0 var(--ot-info);
}

.approvals :deep(.el-table__row.direct-row:focus) {
  outline: none;
}

.approvals :deep(.el-table__row.direct-row + tr > td.el-table__expanded-cell) {
  background-color: color-mix(in srgb, var(--ot-info) 6%, transparent);
  box-shadow: inset 5px 0 0 0 var(--ot-info), inset -2px 0 0 0 var(--ot-info), inset 0 -2px 0 0 var(--ot-info);
}

.approvals :deep(td.el-table__expanded-cell) {
  padding: 0;
}

.expand-sticky {
  box-sizing: border-box;
  max-width: 100%;
}

.history-direct {
  display: inline-flex;
  align-items: center;
  gap: var(--ot-space-xs);
  margin: var(--ot-space-sm) var(--ot-space-md) 0;
  color: var(--ot-info);
  font-size: var(--ot-font-size-xs);
}

.request-cell {
  display: flex;
  align-items: center;
}

.request-cell p,
.pending-table .sub-text {
  margin: 0;
}

.row-ops {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--ot-space-xs);
}

.row-ops .el-button + .el-button {
  margin-left: 0;
}

.reason-clamp {
  display: -webkit-box;
  max-height: 3.2em;
  overflow: hidden;
  line-height: 1.6;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
}

.asset-more {
  cursor: help;
}

.revoke-items {
  margin: var(--ot-space-xs) 0 0;
  padding: 0;
  list-style: none;
}

.revoke-body {
  margin: var(--ot-space-md) 0;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.ticket-request {
  color: var(--ot-text-primary);
  font-weight: 600;
}

.history-hint {
  margin: 0 0 var(--ot-space-sm);
  color: var(--ot-text-primary);
  font-size: var(--ot-font-size-md);
}

.approvals {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-lg);
}

/* 版面縱向間距一律由上面的 gap 給；PageHeader 自帶的下緣會與 gap 疊成 48px，
   那不在間距階上 */
.approvals > :deep(.page-header) {
  margin-bottom: 0;
}

/* 元件庫的分頁標頭預設留 15px，不在間距刻度上 */
.approvals :deep(.el-tabs__header) {
  margin-bottom: var(--ot-space-md);
}

.list-panel {
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  padding: var(--ot-space-lg);
}

.pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: var(--ot-space-md);
}

.approve-summary {
  margin-bottom: var(--ot-space-md);
  color: var(--ot-text-primary);
}

.approve-summary p {
  margin: 0 0 var(--ot-space-xs);
}

.reason-text {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.sub-text {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}
/* 主鍵欄內的批次勾選框：與任務編號同一行，不另佔一欄 */
.batch-select {
  margin-right: var(--ot-space-sm);
}
.pending-table :deep(.cell) { white-space: normal; overflow-wrap: anywhere; word-break: normal; }
/* 表頭與單號只在空白處換行：英文窄螢幕下不在字中斷開，單號不被裁掉 */
.pending-table :deep(th .cell),
.pending-table :deep(.request-column .el-button) { overflow-wrap: normal; }
.pending-table :deep(.request-column .el-button) { height: auto; white-space: normal; text-align: left; }

.row-unconfirmed {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 2px;
}

.row-unconfirmed__tag {
  color: var(--ot-warning);
  font-size: var(--ot-font-size-sm);
}
</style>

<style>
/* 決定後的結果提示（掛在 body 上，不吃 scoped 樣式） */
.decision-toast {
  display: flex;
  flex-direction: column;
  gap: 2px;
  max-width: 520px;
  line-height: 1.6;
}

.decision-toast__title {
  font-weight: 600;
}

.decision-toast__body {
  margin: 0;
}

.decision-toast__link {
  color: var(--ot-primary);
  text-decoration: none;
}

.el-message[class*='decision-toast--'] {
  align-items: flex-start;
}
</style>
