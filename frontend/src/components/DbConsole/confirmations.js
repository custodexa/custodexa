// 主控台的兩個確認框。
//
// 兩者都不是「你確定嗎」的儀式，而是揭露一件使用者看不到的後果：
// 重送＝同一個效果可能發生兩次；切庫（PostgreSQL）＝連線換人、未提交的交易消失。
// 後果不可逆，所以兩者都走共用的破壞性確認——焦點不落在確認鈕、確認鈕分色，
// 與關分頁、協議切離那兩個框同一套視覺與鍵盤行為。

import { confirmDestructive } from '@/utils/confirm'
import { t } from '@/i18n'

/**
 * 重送與未收束單位位元組相同的原文前確認。
 * @returns {Promise<boolean>} 使用者是否確認
 */
export async function confirmResend() {
  try {
    await confirmDestructive(
      t('dbConsole.resendConfirmMessage'),
      t('dbConsole.resendConfirmTitle'),
      {
        confirmButtonText: t('dbConsole.resendConfirmOk'),
        cancelButtonText: t('common.cancel'),
      }
    )
    return true
  } catch {
    return false
  }
}

/**
 * PostgreSQL 切庫前確認（連線綁在庫上，換庫即換連線）。
 * @param {string} database 目標庫
 * @param {boolean} txUnsettled 是否有未收束的交易
 * @returns {Promise<boolean>}
 */
export async function confirmSwitchDatabase(database, txUnsettled) {
  try {
    await confirmDestructive(
      txUnsettled
        ? t('dbConsole.switchConfirmMessageTx', { database })
        : t('dbConsole.switchConfirmMessage', { database }),
      t('dbConsole.switchConfirmTitle'),
      {
        confirmButtonText: t('dbConsole.switchConfirmOk'),
        cancelButtonText: t('common.cancel'),
      }
    )
    return true
  } catch {
    return false
  }
}
