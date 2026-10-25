<template>
  <div class="notification-channels-page">
    <PageHeader
      :title="$t('alerts.tabChannels')"
      :description="$t('alerts.channelsHeaderDesc')"
    >
      <template #actions>
        <el-button
          data-test="channels-refresh"
          @click="refresh"
        >
          <el-icon><RefreshCw /></el-icon>
          {{ $t('common.refresh') }}
        </el-button>
      </template>
    </PageHeader>

    <NotificationChannelPanel ref="panelRef" />
  </div>
</template>

<script setup>
// 通知通道的獨立頁：薄頁殼，面板本體沿用原告警頁的元件，不複製表單、不更改投遞。
// 面板不會自行載入，只對外提供 refresh；首次載入由這裡在掛載時呼叫一次，並提供手動刷新。
import { ref, onMounted } from 'vue'
import { RefreshCw } from 'lucide-vue-next'
import PageHeader from '@/components/PageHeader.vue'
import NotificationChannelPanel from '@/components/alerts/NotificationChannelPanel.vue'

const panelRef = ref(null)
const refresh = () => panelRef.value?.refresh()

onMounted(refresh)
</script>
