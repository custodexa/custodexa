// 決策 3 的三條件判定。
// 這裡釘的是「誰有資格被貼上協定問題的標籤」——條件放寬一格就是狼來了，
// 收緊一格就是使用者永遠看不到解釋。
import { describe, it, expect, beforeEach } from 'vitest'
import {
  RELOGIN_INSECURE_TRANSPORT,
  consumeReloginContext,
  hasRefreshSucceeded,
  markRefreshSucceeded,
  recordInsecureTransportRelogin,
  resetReloginContext,
} from '../reloginContext'

describe('reloginContext', () => {
  beforeEach(() => {
    window.sessionStorage.clear()
    window.location.href = 'http://localhost:3000/dashboard'
  })

  it('http + 本分頁未曾成功續期 → 寫入脈絡', () => {
    expect(recordInsecureTransportRelogin()).toBe(true)
    expect(consumeReloginContext()).toBe(RELOGIN_INSECURE_TRANSPORT)
  })

  // 誤報抑制器：健康的明文部署（Secure 已關閉）續期會成功多次後才因閒置逾時
  // 結束，那不是協定問題。少了這格，每次正常逾時都會被扣上帽子
  it('本分頁曾成功續期後再失敗 → 不寫入（誤報抑制器）', () => {
    markRefreshSucceeded()
    expect(hasRefreshSucceeded()).toBe(true)
    expect(recordInsecureTransportRelogin()).toBe(false)
    expect(consumeReloginContext()).toBe('')
  })

  it('https 頁面 → 不寫入（此形態下 cookie 本來就保存得住）', () => {
    window.location.href = 'https://console.example.test/dashboard'
    expect(recordInsecureTransportRelogin()).toBe(false)
    expect(consumeReloginContext()).toBe('')
  })

  it('讀後即清：重新整理登入頁不重播同一則訊息', () => {
    recordInsecureTransportRelogin()
    expect(consumeReloginContext()).toBe(RELOGIN_INSECURE_TRANSPORT)
    expect(consumeReloginContext()).toBe('')
  })

  it('分頁狀態可整批重設（resetReloginContext）', () => {
    markRefreshSucceeded()
    recordInsecureTransportRelogin()
    resetReloginContext()
    expect(hasRefreshSucceeded()).toBe(false)
    expect(consumeReloginContext()).toBe('')
  })

  // sessionStorage 在隱私模式或封鎖儲存的設定下會擲例外。說明訊息不是功能本體，
  // 取不到就當作沒有——絕不讓它把登入流程整個炸掉
  it('sessionStorage 擲例外時靜默降級，不外拋', () => {
    const original = Object.getOwnPropertyDescriptor(window, 'sessionStorage')
    Object.defineProperty(window, 'sessionStorage', {
      configurable: true,
      get() {
        throw new Error('storage blocked')
      },
    })
    try {
      expect(() => markRefreshSucceeded()).not.toThrow()
      expect(() => recordInsecureTransportRelogin()).not.toThrow()
      expect(consumeReloginContext()).toBe('')
    } finally {
      Object.defineProperty(window, 'sessionStorage', original)
    }
  })
})
