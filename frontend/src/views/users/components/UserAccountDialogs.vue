<template>
  <div class="account-dialogs">
    <!-- 修改密碼對話框 -->
    <el-dialog
      v-model="passwordDialogVisible"
      :title="$t('common.changePassword')"
      width="480px"
      :close-on-click-modal="false"
    >
      <el-alert
        :title="$t('users.currentUser')"
        :description="$t('users.currentUserDesc', { name: currentUser.username })"
        type="info"
        :closable="false"
        style="margin-bottom: 20px"
      />
      <el-form
        ref="passwordFormRef"
        :model="passwordForm"
        :rules="passwordRules"
        label-position="top"
      >
        <el-form-item
          :label="$t('common.newPassword')"
          prop="password"
        >
          <el-input
            v-model="passwordForm.password"
            type="password"
            :placeholder="$t('users.newPasswordPlaceholder')"
            show-password
          />
        </el-form-item>
        <el-form-item
          :label="$t('users.confirmPassword')"
          prop="confirmPassword"
        >
          <el-input
            v-model="passwordForm.confirmPassword"
            type="password"
            :placeholder="$t('users.confirmPasswordPlaceholder')"
            show-password
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="passwordDialogVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="submitting"
          @click="handlePasswordSubmit"
        >
          {{ $t('common.confirm') }}
        </el-button>
      </template>
    </el-dialog>

    <!-- 外部身分管理。
         承載形式定案為**抽屜**而非獨立路由頁：內容是既有列表列的縱深（基本資料
         已在列上），抽屜可保留列表脈絡且不需新增路由與側欄項目；表格本體抽成
         獨立元件，抽屜只是殼（happy-dom 對 el-drawer 的 teleport 不友善，
         元件單測直接測本體） -->
    <el-drawer
      v-model="identityDrawerVisible"
      :title="$t('externalIdentities.drawerTitle', { name: identityUser.username })"
      size="90%"
      direction="rtl"
    >
      <!-- 面板操作成功但列表刷新失敗：抽屜標頭與帳號狀態
           標籤仍是舊值，不得靜默——尤其「可轉換為僅外部登入」這種以舊狀態為前提
           的入口，會讓管理者對已轉換的帳號再按一次 -->
      <el-alert
        v-if="identityRefreshFailed"
        class="drawer-alert"
        type="warning"
        :title="$t('users.identityRefreshFailedTitle')"
        :description="$t('users.identityRefreshFailedHint')"
        :closable="false"
        show-icon
      >
        <template #default>
          <div>{{ $t('users.identityRefreshFailedHint') }}</div>
          <!-- 顯式帶 user id：handler 以 id 判定事件歸屬，直接綁事件會把
               MouseEvent 當成目標 id 傳進去 -->
          <el-button
            size="small"
            :loading="refreshing"
            @click="handleIdentitiesChanged(identityUser.id)"
          >
            {{ $t('common.retry') }}
          </el-button>
        </template>
      </el-alert>
      <!-- :key 綁 user id：換使用者時強制重建元件，
           連同在途請求與表單狀態一併丟棄，不倚賴元件內部的清理是否完備 -->
      <UserExternalIdentities
        v-if="identityDrawerVisible && identityUser.id"
        :key="identityUser.id"
        :user="identityUser"
        :account-state-stale="identityRefreshFailed"
        @changed="handleIdentitiesChanged"
      />
    </el-drawer>
    <!-- 修改密碼對話框 -->
    <el-dialog
      v-model="passwordDialogVisible"
      :title="$t('common.changePassword')"
      width="480px"
      :close-on-click-modal="false"
    >
      <el-alert
        :title="$t('users.currentUser')"
        :description="$t('users.currentUserDesc', { name: currentUser.username })"
        type="info"
        :closable="false"
        style="margin-bottom: 20px"
      />
      <el-form
        ref="passwordFormRef"
        :model="passwordForm"
        :rules="passwordRules"
        label-position="top"
      >
        <el-form-item
          :label="$t('common.newPassword')"
          prop="password"
        >
          <el-input
            v-model="passwordForm.password"
            type="password"
            :placeholder="$t('users.newPasswordPlaceholder')"
            show-password
          />
        </el-form-item>
        <el-form-item
          :label="$t('users.confirmPassword')"
          prop="confirmPassword"
        >
          <el-input
            v-model="passwordForm.confirmPassword"
            type="password"
            :placeholder="$t('users.confirmPasswordPlaceholder')"
            show-password
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="passwordDialogVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="submitting"
          @click="handlePasswordSubmit"
        >
          {{ $t('common.confirm') }}
        </el-button>
      </template>
    </el-dialog>

    <!-- 外部身分管理。
         承載形式定案為**抽屜**而非獨立路由頁：內容是既有列表列的縱深（基本資料
         已在列上），抽屜可保留列表脈絡且不需新增路由與側欄項目；表格本體抽成
         獨立元件，抽屜只是殼（happy-dom 對 el-drawer 的 teleport 不友善，
         元件單測直接測本體） -->
    <el-drawer
      v-model="identityDrawerVisible"
      :title="$t('externalIdentities.drawerTitle', { name: identityUser.username })"
      size="90%"
      direction="rtl"
    >
      <!-- 面板操作成功但列表刷新失敗：抽屜標頭與帳號狀態
           標籤仍是舊值，不得靜默——尤其「可轉換為僅外部登入」這種以舊狀態為前提
           的入口，會讓管理者對已轉換的帳號再按一次 -->
      <el-alert
        v-if="identityRefreshFailed"
        class="drawer-alert"
        type="warning"
        :title="$t('users.identityRefreshFailedTitle')"
        :description="$t('users.identityRefreshFailedHint')"
        :closable="false"
        show-icon
      >
        <template #default>
          <div>{{ $t('users.identityRefreshFailedHint') }}</div>
          <!-- 顯式帶 user id：handler 以 id 判定事件歸屬，直接綁事件會把
               MouseEvent 當成目標 id 傳進去 -->
          <el-button
            size="small"
            :loading="refreshing"
            @click="handleIdentitiesChanged(identityUser.id)"
          >
            {{ $t('common.retry') }}
          </el-button>
        </template>
      </el-alert>
      <!-- :key 綁 user id：換使用者時強制重建元件，
           連同在途請求與表單狀態一併丟棄，不倚賴元件內部的清理是否完備 -->
      <UserExternalIdentities
        v-if="identityDrawerVisible && identityUser.id"
        :key="identityUser.id"
        :user="identityUser"
        :account-state-stale="identityRefreshFailed"
        @changed="handleIdentitiesChanged"
      />
    </el-drawer>
  </div>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { changePassword } from '@/api/user'
import UserExternalIdentities from '@/components/UserExternalIdentities.vue'
import { t } from '@/i18n'

/**
 * 帳號動作的對話框與抽屜（修改密碼、外部身分管理）。
 * 列表頁與詳情頁各掛一個；`refreshUser(id)` 由頁面提供：重新讀取該帳號，
 * 回 `{ ok, user }`，讀不到或目標缺席時 ok 或 user 為假，抽屜據此標示狀態過期。
 */
const props = defineProps({
  refreshUser: { type: Function, required: true },
})
const emit = defineEmits(['opening'])

const refreshing = ref(false)

// 密碼表單
const currentUser = reactive({ id: null, username: '' })
const passwordForm = reactive({ password: '', confirmPassword: '' })
const passwordDialogVisible = ref(false)
const passwordFormRef = ref(null)
const submitting = ref(false)

// 密碼驗證規則
const validateConfirmPassword = (rule, value, callback) => {
  if (value !== passwordForm.password) {
    callback(new Error(t('users.passwordMismatch')))
  } else {
    callback()
  }
}

const passwordRules = computed(() => ({
  password: [
    { required: true, message: t('users.newPasswordRequired'), trigger: 'blur' },
  ],
  confirmPassword: [
    { required: true, message: t('users.confirmPasswordRequired'), trigger: 'blur' },
    { validator: validateConfirmPassword, trigger: 'blur' },
  ],
}))

// 取得用戶列表。
// 回傳成功與否：呼叫端若把「刷新完成」當成「拿到新資料」，

// 處理修改密碼
const handleChangePassword = (row) => {
  emit('opening')
  currentUser.id = row.id
  currentUser.username = row.username
  passwordForm.password = ''
  passwordForm.confirmPassword = ''
  passwordFormRef.value?.clearValidate()
  passwordDialogVisible.value = true
}

// 處理密碼提交
const handlePasswordSubmit = async () => {
  try {
    await passwordFormRef.value.validate()
    submitting.value = true
    await changePassword(currentUser.id, passwordForm.password)
    ElMessage.success(t('users.passwordChanged'))
    passwordDialogVisible.value = false
  } catch (error) {
    if (error?.errors) {
      // 驗證錯誤，不需要處理
      return
    }
  } finally {
    submitting.value = false
  }
}

// 「解綁後這個帳號還能不能登入」講清楚
const identityDrawerVisible = ref(false)
const identityUser = ref({ id: null, username: '' })
// 列表刷新失敗＝抽屜顯示的帳號狀態不可信；面板據此停掉不可逆的轉換入口
const identityRefreshFailed = ref(false)

const handleManageIdentities = (row) => {
  emit('opening')
  identityUser.value = { ...row }
  identityRefreshFailed.value = false
  identityDrawerVisible.value = true
}

// 面板內的破壞性操作（解綁＋停用、改為僅外部登入）會改變帳號本體狀態。
// 只刷新列表而不回填抽屜標頭，管理者會看到「操作成功」的 toast 消失後畫面
// 仍寫著舊狀態，無從自證剛才那一下是否生效。
//
// 刷新本身也會失敗：`fetchUserList` 吞掉錯誤並保留舊列表，
// 舊版把它當成一定成功，於是 external-only 轉換成功後畫面仍顯示「具本地密碼、
// 可轉換」——管理者會再按一次，或據此判斷轉換沒生效。失敗時一律標記狀態過期，
// 由抽屜警示與面板的入口停用共同承擔，不靜默
//
// 事件歸屬與順序：面板可在換人／卸載後才收到成功回應，
// 該事件帶的是**當時**的 user id；與目前抽屜不符時一律忽略，否則等於拿別人的
// 操作驅動這個帳號的狀態。同時以序號防止較舊的刷新覆蓋較新的結論
let identityRefreshSeq = 0

const handleIdentitiesChanged = async (userId) => {
  const targetId = identityUser.value?.id ?? null
  if (userId != null && userId !== targetId) return
  const seq = ++identityRefreshSeq
  refreshing.value = true
  let outcome
  try {
    outcome = await props.refreshUser(targetId)
  } finally {
    refreshing.value = false
  }
  // 期間又發生新的刷新或換了使用者：本次結論一律作廢
  if (seq !== identityRefreshSeq || identityUser.value?.id !== targetId) return
  if (!outcome?.ok) {
    identityRefreshFailed.value = true
    return
  }
  const fresh = outcome.user
  if (!fresh) {
    // 刷新成功但目標缺席（篩選、分頁，或操作本身讓帳號退出目前結果集）：
    // 抽屜上的帳號狀態同樣是舊值，清掉旗標等於重新開放不可逆入口
    identityRefreshFailed.value = true
    return
  }
  identityUser.value = { ...fresh }
  identityRefreshFailed.value = false
}
const close = () => {
  passwordDialogVisible.value = false
  identityDrawerVisible.value = false
}

defineExpose({
  openPassword: handleChangePassword,
  openIdentities: handleManageIdentities,
  close,
})
</script>
