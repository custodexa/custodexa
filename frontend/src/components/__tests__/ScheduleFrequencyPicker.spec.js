import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import ScheduleFrequencyPicker from '../ScheduleFrequencyPicker.vue'

// 頻率選擇器。斷言重心在三件會直接害到使用者的事：
//  1. 選了頻率就要看得到接下來真的會在什麼時候跑；
//  2. 自訂欄寫壞時，錯誤要就近講出原因，而且宿主表單要知道現在不能存；
//  3. 取不到執行時刻時要說「取不到」，不能留白——留白會被讀成「不會執行」。

enableAutoUnmount(afterEach)

const nextRunsMock = vi.fn()

vi.mock('@/api/schedules', () => ({
  getScheduleNextRuns: (...args) => nextRunsMock(...args),
}))

const mountPicker = async (props = {}) => {
  const wrapper = mount(ScheduleFrequencyPicker, {
    props,
    global: { plugins: [ElementPlus] },
  })
  await flushPromises()
  return wrapper
}

const lastEmitted = (wrapper, event) => {
  const events = wrapper.emitted(event)
  return events ? events[events.length - 1][0] : undefined
}

beforeEach(() => {
  nextRunsMock.mockReset()
  nextRunsMock.mockResolvedValue({
    runs: ['2027-01-01T00:00:00+08:00', '2028-01-01T00:00:00+08:00', '2029-01-01T00:00:00+08:00'],
    timezone: 'Asia/Taipei',
  })
})

describe('下次執行時刻預覽', () => {
  it('每年 1 月 1 日 00:00 列出接下來三次執行時刻', async () => {
    const wrapper = await mountPicker({ modelValue: '0 0 1 1 *' })

    expect(nextRunsMock).toHaveBeenCalledWith(
      { cron: '0 0 1 1 *', count: 3 },
      { skipErrorToast: true }
    )
    expect(wrapper.find('[data-test="schedule-summary"]').text()).toBe('每年 1 月 1 日 00:00')
    expect(wrapper.find('[data-test="schedule-next-run-0"]').text()).toBe('2027-01-01 00:00')
    expect(wrapper.find('[data-test="schedule-next-run-1"]').text()).toBe('2028-01-01 00:00')
    expect(wrapper.find('[data-test="schedule-next-run-2"]').text()).toBe('2029-01-01 00:00')
    expect(wrapper.find('[data-test="schedule-preview-timezone"]').text()).toContain('Asia/Taipei')
  })

  it('端點失敗時顯示原因而非空白', async () => {
    nextRunsMock.mockRejectedValue(new Error('network down'))
    const wrapper = await mountPicker({ modelValue: '0 0 1 1 *' })

    expect(wrapper.find('[data-test="schedule-next-run-0"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="schedule-preview-note"]').text()).toBe(
      '暫時無法取得下次執行時刻'
    )
  })

  it('端點說得出原因時照實顯示後端訊息', async () => {
    nextRunsMock.mockRejectedValue({
      response: { status: 400, data: { error: '排程字串無法解析' } },
    })
    const wrapper = await mountPicker({ modelValue: '0 0 1 1 *' })

    expect(wrapper.find('[data-test="schedule-preview-note"]').text()).toBe('排程字串無法解析')
  })

  it('不排程狀態不打端點，並說明不會自動執行', async () => {
    const wrapper = await mountPicker({ modelValue: '', allowEmpty: true })

    expect(nextRunsMock).not.toHaveBeenCalled()
    expect(wrapper.find('[data-test="schedule-preview-note"]').text()).toBe('沒有自動執行時刻。')
    expect(wrapper.find('[data-test="schedule-none-hint"]').exists()).toBe(true)
  })
})

describe('自訂欄格式檢查', () => {
  it('輸入四欄時就近顯示錯誤原因，且宿主收到不可儲存', async () => {
    const wrapper = await mountPicker({ modelValue: '*/15 * * * *' })
    expect(lastEmitted(wrapper, 'update:valid')).toBe(true)

    await wrapper.find('[data-test="schedule-custom-input"]').setValue('0 0 1 *')
    await flushPromises()

    const error = wrapper.find('[data-test="schedule-custom-error"]')
    expect(error.exists()).toBe(true)
    expect(error.text()).toContain('目前只有 4 個')
    expect(lastEmitted(wrapper, 'update:valid')).toBe(false)
    expect(wrapper.find('[data-test="schedule-preview-note"]').text()).toBe(
      '排程格式修正後才會顯示執行時刻。'
    )
  })

  it('改回合法五欄後恢復可儲存並重新取得時刻', async () => {
    const wrapper = await mountPicker({ modelValue: '*/15 * * * *' })
    await wrapper.find('[data-test="schedule-custom-input"]').setValue('0 0 1 *')
    await flushPromises()

    nextRunsMock.mockResolvedValue({ runs: ['2026-10-01T00:00:00+08:00'], timezone: 'Asia/Taipei' })
    await wrapper.find('[data-test="schedule-custom-input"]').setValue('*/30 * * * *')
    await flushPromises()

    expect(wrapper.find('[data-test="schedule-custom-error"]').exists()).toBe(false)
    expect(lastEmitted(wrapper, 'update:valid')).toBe(true)
    expect(lastEmitted(wrapper, 'update:modelValue')).toBe('*/30 * * * *')
  })
})

describe('既有值的呈現', () => {
  it('每季形狀反推為每季並顯示人話摘要', async () => {
    const wrapper = await mountPicker({ modelValue: '0 0 1 1,4,7,10 *' })

    expect(wrapper.vm.mode).toBe('quarterly')
    expect(wrapper.vm.fields.quarterStartMonth).toBe(1)
    expect(wrapper.find('[data-test="schedule-summary"]').text()).toBe('每季 1 日 00:00')
  })

  it('認不出形狀的既有值原樣落在自訂欄，掛載不改寫既有值', async () => {
    const wrapper = await mountPicker({ modelValue: '00 03 * * *' })

    expect(wrapper.vm.mode).toBe('custom')
    expect(wrapper.find('[data-test="schedule-custom-input"]').element.value).toBe(
      '00 03 * * *'
    )
    expect(wrapper.emitted('update:modelValue')).toBeUndefined()
  })

  it('宿主不接受空值時，空白起點換成可儲存的預設並主動回報', async () => {
    const wrapper = await mountPicker({ modelValue: '' })

    expect(wrapper.vm.mode).toBe('daily')
    expect(lastEmitted(wrapper, 'update:modelValue')).toBe('0 0 * * *')
    expect(lastEmitted(wrapper, 'update:valid')).toBe(true)
  })
})

describe('不排程狀態的出現條件', () => {
  it('宿主允許空值時才提供「不排程」選項', async () => {
    const withEmpty = await mountPicker({ modelValue: '0 0 * * *', allowEmpty: true })
    expect(withEmpty.find('[data-test="schedule-mode-none"]').exists()).toBe(true)

    const withoutEmpty = await mountPicker({ modelValue: '0 0 * * *' })
    expect(withoutEmpty.find('[data-test="schedule-mode-none"]').exists()).toBe(false)
  })

  it('切到不排程時對外送出空字串', async () => {
    const wrapper = await mountPicker({ modelValue: '0 0 * * *', allowEmpty: true })
    wrapper.vm.mode = 'none'
    await flushPromises()

    expect(lastEmitted(wrapper, 'update:modelValue')).toBe('')
    expect(lastEmitted(wrapper, 'update:valid')).toBe(true)
  })
})
