<template>
  <div class="my-connections">
    <PageHeader
      :title="$t('menu.myConnections')"
      :description="$t('myConnections.headerDesc')"
    >
      <template #actions>
        <el-button @click="fetchConnections">
          <el-icon><Refresh /></el-icon>
          {{ $t('common.refresh') }}
        </el-button>
      </template>
    </PageHeader>

    <!-- 唯讀精簡列表（my-connections）：僅資產/協議/時間/時長/狀態，
         無指令檢視與錄影入口（一般 user 是被監管對象，資料面即不可得） -->
    <div class="list-panel">
      <el-table
        v-loading="loading"
        :data="connections"
        style="width: 100%"
        stripe
      >
        <el-table-column
          :label="$t('common.asset')"
          min-width="180"
        >
          <template #default="{ row }">
            {{ row.asset_name || $t('myConnections.manualConnection') }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.protocol')"
          width="100"
        >
          <template #default="{ row }">
            <el-tag :type="protocolTagType(row.protocol)">
              {{ (row.protocol || '').toUpperCase() }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('myConnections.connectedAt')"
          width="180"
        >
          <template #default="{ row }">
            {{ formatDateTime(row.connected_at) }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('myConnections.duration')"
          width="140"
        >
          <template #default="{ row }">
            {{ formatDurationSeconds(row.duration_seconds) }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.status')"
          width="100"
        >
          <template #default="{ row }">
            <el-tag :type="row.status === 'active' ? 'success' : 'info'">
              {{ row.status === 'active' ? $t('common.stateActive') : $t('common.stateEnded') }}
            </el-tag>
          </template>
        </el-table-column>
        <!-- fixed right：溢寬時操作欄滑出可視範圍＝終止入口消失（Assets 同型教訓） -->
        <el-table-column
          :label="$t('common.actions')"
          width="100"
          fixed="right"
        >
          <template #default="{ row }">
            <el-button
              v-if="row.status === 'active'"
              link
              type="danger"
              size="small"
              @click="handleTerminate(row)"
            >
              {{ $t('myConnections.terminate') }}
            </el-button>
          </template>
        </el-table-column>

        <template #empty>
          <EmptyState
            :title="$t('myConnections.emptyTitle')"
            :hint="$t('myConnections.emptyHint')"
          />
        </template>
      </el-table>

      <div class="pagination">
        <el-pagination
          v-model:current-page="pagination.page"
          v-model:page-size="pagination.page_size"
          :page-sizes="[10, 20, 50, 100]"
          :total="pagination.total"
          layout="total, sizes, prev, pager, next, jumper"
          @size-change="handleSizeChange"
          @current-change="handlePageChange"
        />
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { Refresh } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import { getMyConnections, terminateMyConnection } from '@/api/myConnections'
import { formatDateTime, formatDurationSeconds } from '@/utils/format'
import { protocolTagType } from '@/utils/protocol'
import { t } from '@/i18n'

const loading = ref(false)
const connections = ref([])
const pagination = reactive({
  page: 1,
  page_size: 20,
  total: 0,
})

const fetchConnections = async () => {
  loading.value = true
  try {
    const res = await getMyConnections({
      page: pagination.page,
      page_size: pagination.page_size,
    })
    connections.value = res.data || []
    pagination.total = res.total ?? 0
  } catch (error) {
    console.error('載入我的連線失敗:', error)
  } finally {
    loading.value = false
  }
}

const handlePageChange = (page) => {
  pagination.page = page
  fetchConnections()
}

const handleSizeChange = (size) => {
  pagination.page_size = size
  pagination.page = 1
  fetchConnections()
}

// 自助終止（owner-scoped）：二次確認採既有 ElMessageBox 慣例（與 admin 終止一致）。
// 4xx（含「連線已自行結束」競態）由請求攔截器顯示後端訊息，這裡刷新列表即收斂
const handleTerminate = async (row) => {
  try {
    await ElMessageBox.confirm(
      t('myConnections.terminateConfirm', { name: row.asset_name || t('myConnections.manualConnection') }),
      t('myConnections.terminateConfirmTitle'),
      {
        confirmButtonText: t('common.confirm'),
        cancelButtonText: t('common.cancel'),
        type: 'warning',
      }
    )
  } catch {
    return // 使用者取消
  }

  try {
    await terminateMyConnection(row.id)
    ElMessage.success(t('myConnections.terminated'))
  } catch (error) {
    console.error('終止連線失敗:', error)
  } finally {
    fetchConnections()
  }
}


onMounted(fetchConnections)
</script>

<style scoped>
.list-panel {
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  padding: var(--ot-space-md);
}

.pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: var(--ot-space-md);
}
</style>
