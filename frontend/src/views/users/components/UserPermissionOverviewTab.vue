<template>
  <div
    v-loading="loading"
    class="po-tab"
    data-test="permission-overview-tab"
  >
    <el-alert
      v-if="failed"
      type="error"
      :closable="false"
      show-icon
      :title="$t('permissionOverview.loadFailed')"
      data-test="po-load-failed"
    />
    <template v-else-if="overview">
      <PermissionOverviewProbe
        :user-id="userId"
        :role-defs="roleDefs"
      />
      <div class="po-tab__cols">
        <PermissionOverviewManage
          :management="overview.management"
          :role-defs="roleDefs"
        >
          <template #footer>
            <p
              v-if="usableTokens > 0"
              class="po-tab__api-tokens"
              data-test="po-api-tokens"
            >
              {{ $t('permissionOverview.apiTokens', { user: overview.username, n: usableTokens }) }}
              <a
                href="#"
                data-test="po-api-tokens-link"
                @click.prevent="emit('view-api-tokens')"
              >{{ $t('permissionOverview.apiTokensLink') }}</a>
            </p>
          </template>
        </PermissionOverviewManage>
        <PermissionOverviewConnect
          :connection="overview.connection"
          :out-of-scope-count="overview.connection?.out_of_scope_asset_count || 0"
          :username="overview.username"
        />
      </div>
      <p
        class="po-tab__separation"
        data-test="po-separation-note"
      >
        {{ $t('permissionOverview.separationNote') }}
      </p>
    </template>
  </div>
</template>

<script setup>
import { onMounted, ref, watch } from 'vue'
import { getPermissionOverview } from '@/api/permissionOverview'
import { listRoleDefinitions } from '@/api/roleDefinitions'
import { apiErrorSummary } from '@/api/redact'
import { getUserApiTokens } from '@/api/apiTokens'
import { summarize } from '@/constants/apiTokens'
import PermissionOverviewProbe from './PermissionOverviewProbe.vue'
import PermissionOverviewManage from './PermissionOverviewManage.vue'
import PermissionOverviewConnect from './PermissionOverviewConnect.vue'

/**
 * 權限一覽分頁（唯讀）：一次看懂這個人能管什麼、能連到哪、為什麼。
 * 所有集合、範圍與台數取自 GET /users/:id/permission-overview，這裡不推算。
 */
const props = defineProps({
  userId: { type: Number, required: true },
})
const emit = defineEmits(['view-api-tokens'])

const overview = ref(null)
const roleDefs = ref(new Map())
const loading = ref(false)
const failed = ref(false)
let loadSeq = 0

// 角色列表只用來決定全系統範圍寫「全系統」或「不適用」；讀不到時一律寫全系統，不猜
const loadRoleDefs = async () => {
  try {
    const res = await listRoleDefinitions({ skipErrorToast: true })
    roleDefs.value = new Map((res?.data || []).map((d) => [d.id, d]))
  } catch (error) {
    console.error(...apiErrorSummary('role_definitions_failed', error))
  }
}

const load = async () => {
  const seq = ++loadSeq
  loading.value = true
  failed.value = false
  overview.value = null
  try {
    const res = await getPermissionOverview(props.userId)
    if (seq !== loadSeq) return
    overview.value = res
  } catch (error) {
    if (seq !== loadSeq) return
    console.error(...apiErrorSummary('permission_overview_failed', error))
    failed.value = true
  } finally {
    if (seq === loadSeq) loading.value = false
  }
}

// 這個人可用的 API token 數：讀不到或沒有就不顯示那一句
const usableTokens = ref(0)
let tokenSeq = 0
const loadTokens = async () => {
  const seq = ++tokenSeq
  usableTokens.value = 0
  try {
    const res = await getUserApiTokens(props.userId)
    if (seq !== tokenSeq) return
    usableTokens.value = summarize(Array.isArray(res?.data) ? res.data : []).usable
  } catch (error) {
    if (seq !== tokenSeq) return
    console.error(...apiErrorSummary('user_api_token_list_failed', error))
  }
}

watch(() => props.userId, () => {
  void load()
  void loadTokens()
})
onMounted(() => {
  void loadRoleDefs()
  void load()
  void loadTokens()
})
</script>

<style scoped>
.po-tab {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-md);
  min-height: 120px;
}

.po-tab__cols {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: var(--ot-space-lg, 24px);
  align-items: start;
}

.po-tab__separation {
  margin: 0;
  color: var(--ot-text-secondary);
  font-size: 13px;
}
.po-tab__api-tokens {
  margin: 0;
  padding-top: var(--ot-space-sm);
  border-top: 1px solid var(--ot-border-subtle);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}
.po-tab__api-tokens a {
  color: var(--ot-primary);
}
</style>
