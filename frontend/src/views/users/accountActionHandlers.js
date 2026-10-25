import { ElMessage } from 'element-plus'
import {
  updateUserStatus,
  deleteUser,
  adminDisableMFA,
  unlockUser,
} from '@/api/user'
import { confirmDestructive } from '@/utils/confirm'
import { apiErrorSummary } from '@/api/redact'
import { t, currentLocale } from '@/i18n'
import { renderDeleteConfirm, renderDisableMFAConfirm } from './accountActionCopy'

/**
 * 帳號動作的執行（列表頁與詳情頁共用同一組端點與確認框）。
 * 各函式回傳是否已送出並成功，呼叫端據此重新讀取。
 */
const logFailure = (event, error) => console.error(...apiErrorSummary(event, error))

/** 狀態開關：`row.active` 已由開關翻成新值；失敗時回復原狀。 */
export async function handleStatusChange(row) {
  row._statusLoading = true
  try {
    await updateUserStatus(row.id, row.active)
    ElMessage.success(t('users.statusUpdated'))
    return true
  } catch {
    row.active = !row.active
    return false
  } finally {
    row._statusLoading = false
  }
}

/** 管理員手動解鎖：清除失敗計數與鎖定時間（後端入審計）。 */
export async function unlockAccount(row) {
  try {
    await unlockUser(row.id)
    ElMessage.success(t('users.unlocked', { name: row.username }))
    return true
  } catch (error) {
    logFailure('user_unlock_failed', error)
    return false
  }
}

export async function disableAccountMfa(row) {
  try {
    await confirmDestructive(renderDisableMFAConfirm(row, t), t('users.disableMFATitle'), {
      confirmButtonText: t('common.confirm'),
      cancelButtonText: t('common.cancel'),
    })
  } catch {
    return false // 使用者取消
  }
  try {
    await adminDisableMFA(row.id)
    ElMessage.success(t('users.mfaDisabled'))
    return true
  } catch (error) {
    logFailure('user_mfa_disable_failed', error)
    return false
  }
}

export async function deleteAccount(row) {
  try {
    await confirmDestructive(renderDeleteConfirm(row, t, currentLocale()), t('common.deleteConfirmTitle'), {
      confirmButtonText: t('common.deleteConfirmButton'),
      cancelButtonText: t('common.cancel'),
    })
  } catch {
    return false // 使用者取消
  }
  try {
    await deleteUser(row.id)
    ElMessage.success(t('users.deleted'))
    return true
  } catch (error) {
    logFailure('user_delete_failed', error)
    return false
  }
}
