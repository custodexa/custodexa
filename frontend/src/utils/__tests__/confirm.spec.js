// 破壞性確認框的預設焦點。
//
// 守的是一件「錯了不會報錯、只會多停用一個帳號」的事：Element Plus 預設把焦點
// 放在確認鈕上，於是「按 Enter 關掉這個框」等同執行破壞性操作。錯誤通知型的框
// （例如「無法解綁，是否改為解綁並停用？」）尤其危險——管理者的自然反應是
// 按 Enter 表示「知道了」。
import { describe, it, expect, vi, afterEach } from 'vitest'
import { ElMessageBox } from 'element-plus'
import { confirmDestructive, DESTRUCTIVE_CONFIRM_CLASS } from '../confirm'

const spyConfirm = () =>
  vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')

afterEach(() => {
  vi.restoreAllMocks()
})

describe('confirmDestructive', () => {
  it('一律關閉 autofocus，Enter 不會直接落在危險鈕上', async () => {
    const spy = spyConfirm()
    await confirmDestructive('msg', 'title')
    expect(spy.mock.calls[0][2].autofocus).toBe(false)
  })

  it('確認鈕帶 danger 樣式，與一般確認框在視覺上分開', async () => {
    const spy = spyConfirm()
    await confirmDestructive('msg', 'title')
    expect(spy.mock.calls[0][2].confirmButtonClass).toBe(DESTRUCTIVE_CONFIRM_CLASS)
    expect(spy.mock.calls[0][2].type).toBe('warning')
  })

  it('呼叫端選項可覆寫按鈕文字，但訊息與標題原樣傳遞', async () => {
    const spy = spyConfirm()
    await confirmDestructive('後果說明', '確認標題', {
      confirmButtonText: '解除綁定',
      cancelButtonText: '取消',
    })
    const [message, title, options] = spy.mock.calls[0]
    expect(message).toBe('後果說明')
    expect(title).toBe('確認標題')
    expect(options.confirmButtonText).toBe('解除綁定')
    // 覆寫選項不得把 autofocus 一起吃掉
    expect(options.autofocus).toBe(false)
  })

  it('取消時以 reject 回傳（呼叫端據此 return，不得誤判為確認）', async () => {
    vi.spyOn(ElMessageBox, 'confirm').mockRejectedValue('cancel')
    await expect(confirmDestructive('msg', 'title')).rejects.toBe('cancel')
  })
})
