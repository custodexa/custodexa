<template>
  <div class="panel">
    <div class="panel__title">
      {{ $t('identitySources.preflight.title') }}
    </div>
    <div class="panel__lead">
      {{ isDirectory
        ? $t('identitySources.preflight.leadLdap')
        : $t('identitySources.preflight.leadOidc') }}
    </div>

    <!-- 第一塊：靜態檢核卡。**這一塊是提示，不是自動化**——本系統不代為
         呼叫提供者的管理介面，只把該做的事列清楚並附可複製的值 -->
    <div class="panel__section-head">
      {{ isDirectory
        ? $t('identitySources.preflight.checklistLdap')
        : $t('identitySources.preflight.checklistOidc') }}
    </div>
    <div
      v-for="item in checklist"
      :key="item.key"
      class="panel__item"
    >
      <div class="panel__item-main">
        <div class="panel__item-title">
          {{ item.title }}
        </div>
        <div
          v-if="item.value"
          class="panel__item-value"
        >
          {{ item.value }}
        </div>
        <div
          v-if="item.hint"
          class="panel__item-hint"
        >
          {{ item.hint }}
        </div>
      </div>
      <el-button
        v-if="item.copyable"
        type="primary"
        size="small"
        link
        @click="copy(item.value)"
      >
        {{ $t('common.copy') }}
      </el-button>
    </div>

    <el-divider />

    <!-- 第二塊：本系統自驗的狀態燈。一支彙總端點回齊，不由前端拼多支——
         分散成多支會讓燈號之間出現不同時點的混合狀態 -->
    <div class="panel__section-head">
      {{ $t('identitySources.preflight.statusHead') }}
    </div>
    <div
      v-if="statusUnavailable"
      class="panel__pending"
    >
      {{ $t('identitySources.backendPending') }}
    </div>
    <div
      v-else-if="statusNotConfigured"
      class="panel__pending"
    >
      {{ $t('identitySources.preflight.sourceNotConfigured') }}
    </div>
    <div
      v-for="light in lights"
      :key="light.key"
      class="panel__light"
    >
      <span
        class="panel__dot"
        :class="`panel__dot--${light.state}`"
      />
      <div class="panel__light-body">
        <span>{{ light.text }}</span>
        <div
          v-if="light.sub"
          class="panel__item-hint"
        >
          {{ light.sub }}
        </div>
      </div>
    </div>

    <el-divider />

    <!-- 第三塊：主動測試 -->
    <div class="panel__section-head">
      {{ $t('identitySources.preflight.testHead') }}
    </div>
    <div class="panel__buttons">
      <el-button
        v-if="!isDirectory"
        :loading="discovering"
        @click="$emit('rediscover')"
      >
        {{ $t('identitySources.preflight.rediscover') }}
      </el-button>
      <el-button
        v-else
        :loading="testing"
        @click="$emit('test')"
      >
        {{ $t('identitySources.testConnection') }}
      </el-button>
      <el-button
        :disabled="!sourceId"
        @click="openLoginTest"
      >
        {{ $t('identitySources.preflight.loginTest') }}
      </el-button>
    </div>
    <!-- 登入測試是真實登入，按鈕下方明寫後果：不做任何形式的假登入 -->
    <div class="panel__warning">
      {{ isDirectory
        ? $t('identitySources.preflight.loginTestNoticeLdap')
        : $t('identitySources.preflight.loginTestNoticeOidc') }}
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import i18n, { t } from '@/i18n'
import { formatDateTime } from '@/utils/format'
import { apiErrorSummary } from '@/api/redact'
import {
  getSourceStatus,
  isNotImplemented,
  errorCode,
  CODE_LDAP_DIRECTORY_NOT_FOUND,
} from '@/api/identitySources'

const props = defineProps({
  type: { type: String, required: true },
  sourceId: { type: [Number, String], default: null },
  // 回呼網址由對外基準網址算出，隨來源詳情回；未設基準網址時是可辨識的狀態而非空字串
  redirectUri: { type: String, default: '' },
  redirectUriState: { type: String, default: '' },
  logoutRedirectUri: { type: String, default: '' },
  discovering: { type: Boolean, default: false },
  testing: { type: Boolean, default: false },
})

// status：把這一支彙總的結果原封往上送。頁面標頭的「最近成功登入」與面板燈號
// 同源同時點，父層不另打一次請求——多打一次就會出現兩個時點混在同一畫面上
const emit = defineEmits(['rediscover', 'test', 'status'])

const logFailure = (event, error) => console.error(...apiErrorSummary(event, error))

const status = ref(null)
const statusUnavailable = ref(false)
// 目錄尚未設定：路由存在且回答了「沒有這個資源」。與端點缺席分開呈現，
// 否則管理者讀到的是「系統還沒做這塊」而不是「這裡還沒設定」
const statusNotConfigured = ref(false)

const isDirectory = computed(() => props.type === 'ldap')

const pendingValue = computed(() => t('identitySources.backendPending'))

const checklist = computed(() => {
  if (isDirectory.value) {
    return [
      {
        key: 'read_group_attr',
        title: t('identitySources.preflight.ldap.readGroupAttr'),
        hint: t('identitySources.preflight.ldap.readGroupAttrHint'),
      },
      {
        key: 'base_dn_covers',
        title: t('identitySources.preflight.ldap.baseDnCovers'),
        hint: t('identitySources.preflight.ldap.baseDnCoversHint'),
      },
    ]
  }
  const redirect = props.redirectUri
    ? props.redirectUri
    : props.redirectUriState === 'base_url_unset'
      ? t('identitySources.preflight.oidc.redirectUnset')
      : pendingValue.value
  return [
    {
      key: 'redirect',
      title: t('identitySources.preflight.oidc.redirect'),
      value: redirect,
      copyable: Boolean(props.redirectUri),
    },
    {
      key: 'logout',
      title: t('identitySources.preflight.oidc.logoutRedirect'),
      value: props.logoutRedirectUri || pendingValue.value,
      copyable: Boolean(props.logoutRedirectUri),
    },
    {
      key: 'app_type',
      title: t('identitySources.preflight.oidc.appType'),
      hint: t('identitySources.preflight.oidc.appTypeHint'),
    },
    {
      key: 'groups_claim',
      title: t('identitySources.preflight.oidc.groupsClaim'),
      hint: t('identitySources.preflight.oidc.groupsClaimHint'),
    },
    {
      key: 'secret',
      title: t('identitySources.preflight.oidc.secret'),
      hint: t('identitySources.preflight.oidc.secretHint'),
    },
  ]
})

// 三態燈號：true 綠、false 黃、null 或缺欄為灰（尚無資料）。
// **不知道不得畫成綠色**——缺欄與「驗過且通過」是兩件事
const lightOf = (value) => (value === true ? 'ok' : value === false ? 'warn' : 'unknown')

const unknownSub = computed(() => t('identitySources.preflight.noData'))

const lights = computed(() => {
  const s = status.value || {}
  const out = []
  if (isDirectory.value) {
    out.push({
      key: 'connection',
      state: lightOf(s.connection_ok),
      text: t('identitySources.preflight.light.connection'),
      sub: s.connection_ok === undefined || s.connection_ok === null ? unknownSub.value : '',
    })
    out.push({
      key: 'group_attr_readable',
      state: lightOf(s.group_attr_readable),
      text: t('identitySources.preflight.light.groupAttrReadable'),
      sub:
        s.group_attr_readable === undefined || s.group_attr_readable === null
          ? unknownSub.value
          : '',
    })
  } else {
    out.push({
      key: 'discovery',
      state: lightOf(s.discovery_reachable),
      text: t('identitySources.preflight.light.discovery'),
      sub: s.discovery_reachable === undefined || s.discovery_reachable === null
        ? unknownSub.value
        : '',
    })
  }
  out.push({
    key: 'credential',
    state: lightOf(s.credential_set),
    text: t('identitySources.preflight.light.credential'),
    sub: s.credential_set === undefined || s.credential_set === null ? unknownSub.value : '',
  })
  out.push({
    key: 'groups_seen',
    state: lightOf(s.last_login_groups_seen),
    text: t('identitySources.preflight.light.groupsSeen'),
    sub:
      s.last_login_groups_seen === true
        ? t('identitySources.preflight.light.groupsSeenCount', {
          count: s.last_login_groups_count ?? 0,
          time: s.last_login_at ? formatDateTime(s.last_login_at) : '',
        })
        : s.last_login_groups_seen === false
          ? t('identitySources.preflight.light.groupsSeenNone')
          : unknownSub.value,
  })
  out.push({
    key: 'rules',
    state: typeof s.rule_count === 'number' ? 'ok' : 'unknown',
    text:
      typeof s.rule_count === 'number'
        ? t('identitySources.preflight.light.rules', {
          count: s.rule_count,
          enabled: s.enabled_rule_count ?? 0,
          matched: s.last_recompute_matched_users ?? 0,
        })
        : t('identitySources.preflight.light.rulesUnknown'),
    sub: typeof s.rule_count === 'number' ? '' : unknownSub.value,
  })
  for (const w of s.warnings || []) {
    const key = `warnings.${w.code}`
    out.push({
      key: `warn_${w.code}`,
      state: 'warn',
      text: i18n.global.te(key) ? t(key) : t('identitySources.preflight.light.warningGeneric'),
      sub: t('identitySources.preflight.light.warningAction'),
    })
  }
  return out
})

const fetchStatus = async () => {
  if (!props.sourceId) {
    status.value = null
    statusUnavailable.value = false
    statusNotConfigured.value = false
    emit('status', null)
    return
  }
  try {
    status.value = await getSourceStatus(props.type, props.sourceId)
    statusUnavailable.value = false
    statusNotConfigured.value = false
  } catch (error) {
    status.value = null
    statusUnavailable.value = isNotImplemented(error)
    statusNotConfigured.value = errorCode(error) === CODE_LDAP_DIRECTORY_NOT_FOUND
    if (!statusUnavailable.value && !statusNotConfigured.value) {
      logFailure('identity_source_status_failed', error)
    }
  }
  emit('status', status.value)
}

const copy = async (value) => {
  try {
    await navigator.clipboard.writeText(value || '')
    ElMessage.success(t('identitySources.copied'))
  } catch {
    ElMessage.warning(t('common.copyFailed'))
  }
}

// 登入測試開新分頁走真實登入頁並預選此來源：不在本頁內另造一條登入路徑
const openLoginTest = () => {
  window.open(`/login?source=${props.type}:${props.sourceId}`, '_blank', 'noopener')
}

watch(() => props.sourceId, fetchStatus)
onMounted(fetchStatus)

defineExpose({ refresh: fetchStatus })
</script>

<style scoped>
/* 面板常駐右欄且自身可捲：內容比視窗高時若跟著整頁捲，底部的測試按鈕會被
   頁底固定動作列蓋住——那正是這一塊最需要按到的兩顆鍵 */
.panel {
  position: sticky;
  top: var(--ot-space-md);
  /* 扣掉頁首、標題列與頁底固定動作列的高度：面板的最後一句是登入測試的後果
     警語，它不能落在動作列底下（那是永遠捲不到的位置） */
  max-height: calc(100vh - 280px);
  overflow-y: auto;
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  padding: var(--ot-space-md);
}

.panel__title {
  font-weight: 600;
  color: var(--ot-text-primary);
}

.panel__lead {
  margin-top: 4px;
  margin-bottom: var(--ot-space-md);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
}

.panel__section-head {
  margin-bottom: var(--ot-space-sm);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
}

.panel__item {
  display: flex;
  align-items: flex-start;
  gap: var(--ot-space-xs);
  margin-bottom: var(--ot-space-sm);
}

.panel__item-main {
  flex: 1;
  min-width: 0;
}

.panel__item-title {
  font-size: var(--ot-font-size-sm);
  line-height: 1.5;
}

.panel__item-value {
  font-family: var(--ot-font-mono, monospace);
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
  word-break: break-all;
}

.panel__item-hint {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
}

.panel__light {
  display: flex;
  align-items: flex-start;
  gap: var(--ot-space-xs);
  margin-bottom: var(--ot-space-sm);
  font-size: var(--ot-font-size-sm);
}

.panel__light-body {
  flex: 1;
  min-width: 0;
  line-height: 1.5;
}

.panel__dot {
  width: 8px;
  height: 8px;
  margin-top: 6px;
  border-radius: 50%;
  flex-shrink: 0;
}

.panel__dot--ok {
  background-color: var(--el-color-success);
}

.panel__dot--warn {
  background-color: var(--ot-warning, #e6a23c);
}

/* 未知不得畫成綠色，也不是失敗：灰色代表「還沒有資料可說」 */
.panel__dot--unknown {
  background-color: var(--ot-text-disabled);
}

.panel__pending {
  margin-bottom: var(--ot-space-sm);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
}

.panel__buttons {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
}

.panel__buttons :deep(.el-button + .el-button) {
  margin-left: 0;
}

.panel__warning {
  margin-top: var(--ot-space-xs);
  color: var(--ot-warning, #e6a23c);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
}
</style>
