import { describe, it, expect, afterEach } from 'vitest'
import { mount, enableAutoUnmount, flushPromises } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import SessionSpanBars from '../SessionSpanBars.vue'

// 會話跨度條的兩層形態（auditor-workbench：會話時間跨度條）。
//
// 單層「每場一列」在基準資料集（67 場）下長到 1884px，把事件明細推到摺線
// 之下。兩層化的規格命題只有一條可量測的核心：**總覽高度不隨會話數線性
// 增長**——列數有固定上界，超出者摺成一列。
//
// 但把 67 場壓成聚合並不能換掉展開層的任何語義：並發可辨識、開放端、裁切、
// 最小寬度、文字等價、錄影三態，展開後全部要還在。本檔守的就是這兩件事
// 同時成立。

enableAutoUnmount(afterEach)

const FROM = '2026-08-12T00:00:00+08:00'
const TO = '2026-08-12T12:00:00+08:00'
const NOW = new Date('2026-08-12T06:00:00+08:00').getTime()

const at = (hours) =>
  new Date(new Date(FROM).getTime() + hours * 3600 * 1000).toISOString()

/**
 * 基準形態的資料集：10 台資產、67 場（場數刻意不均，用來釘住
 * 「超出上限時被摺起來的是場數最少的那幾台」）。
 */
const makeDataset = () => {
  // 10 台資產分配 67 場：12,10,9,8,7,6,5,4,3,3
  const perAsset = [12, 10, 9, 8, 7, 6, 5, 4, 3, 3]
  const spans = []
  let sid = 1
  perAsset.forEach((count, index) => {
    for (let i = 0; i < count; i += 1) {
      spans.push({
        session_id: sid,
        user_id: (i % 3) + 1,
        user_name: `user${(i % 3) + 1}`,
        asset_id: index + 1,
        asset_name: `asset-${index + 1}`,
        account: 'root',
        protocol: 'ssh',
        status: 'closed',
        recording_state: 'available',
        start: at(1 + (i % 8)),
        end: at(2 + (i % 8)),
      })
      sid += 1
    }
  })
  return spans
}

const mountBars = (spans, props = {}) =>
  mount(SessionSpanBars, {
    props: { spans, from: FROM, to: TO, now: NOW, ...props },
    global: {
      plugins: [ElementPlus],
      // el-tooltip 在 happy-dom 下掛載成本高，且本檔的斷言不依賴它的內部行為
      stubs: { 'el-tooltip': { template: '<div><slot /></div>' } },
    },
  })

const openOverview = async (wrapper) => {
  await wrapper.find('[data-test="spans-overview-toggle"]').trigger('click')
  await flushPromises()
  return wrapper
}

const assetRows = (wrapper) => wrapper.findAll('[data-test^="asset-row-"]')
const sessionRows = (wrapper) => wrapper.findAll('[data-test="span-row"]')

describe('SessionSpanBars 總覽層聚合', () => {
  it('67 場 10 資產：總覽層一台資產一列，不是一場一列', async () => {
    const spans = makeDataset()
    expect(spans).toHaveLength(67)
    const wrapper = await openOverview(mountBars(spans))
    expect(assetRows(wrapper)).toHaveLength(10)
    // 未展開任何資產時逐場列一條都不渲染——高度因此與會話數脫鉤
    expect(sessionRows(wrapper)).toHaveLength(0)
  })

  it('每台資產列附場數徽章（聚合不得把「這台有幾場」吃掉）', async () => {
    const wrapper = await openOverview(mountBars(makeDataset()))
    expect(wrapper.find('[data-test="asset-count-1"]').text()).toContain('12')
    expect(wrapper.find('[data-test="asset-count-10"]').text()).toContain('3')
  })

  it('收合態只有一列總覽，逐資產列與逐場列皆不渲染（初始版面不被跨度條吃掉）', () => {
    const wrapper = mountBars(makeDataset())
    expect(wrapper.find('[data-test="spans-overview-toggle"]').exists()).toBe(true)
    expect(assetRows(wrapper)).toHaveLength(0)
    expect(sessionRows(wrapper)).toHaveLength(0)
    // 收合態仍畫出全部連線的時段塊：資訊不消失，只是不分列
    expect(wrapper.findAll('.span-bar.is-block')).toHaveLength(67)
    expect(wrapper.find('[data-test="spans-overview-summary"]').text()).toContain('10')
    expect(wrapper.find('[data-test="spans-overview-summary"]').text()).toContain('67')
  })
})

describe('SessionSpanBars 列數上界與摺疊', () => {
  it('資產數超過上限時只列到上限，其餘摺成「其餘 N 台資產」一列', async () => {
    const wrapper = await openOverview(mountBars(makeDataset(), { maxAssetRows: 6 }))
    expect(assetRows(wrapper)).toHaveLength(6)
    const rest = wrapper.find('[data-test="spans-rest-toggle"]')
    expect(rest.exists()).toBe(true)
    expect(rest.text()).toContain('4')
  })

  it('被摺起來的是場數最少的那幾台（先看得到的是量體最大的）', async () => {
    const wrapper = await openOverview(mountBars(makeDataset(), { maxAssetRows: 3 }))
    const names = assetRows(wrapper).map((row) => row.text())
    expect(names[0]).toContain('asset-1')
    expect(names[2]).toContain('asset-3')
    expect(wrapper.find('[data-test="asset-row-10"]').exists()).toBe(false)
  })

  it('展開「其餘 N 台資產」還原全部資產列（摺疊是收納，不是丟棄）', async () => {
    const wrapper = await openOverview(mountBars(makeDataset(), { maxAssetRows: 6 }))
    await wrapper.find('[data-test="spans-rest-toggle"]').trigger('click')
    await flushPromises()
    expect(assetRows(wrapper)).toHaveLength(10)
    expect(wrapper.find('[data-test="asset-row-10"]').exists()).toBe(true)
  })

  it('資產數未超過上限時不出現摺疊列（不製造沒有內容的入口）', async () => {
    const wrapper = await openOverview(mountBars(makeDataset(), { maxAssetRows: 12 }))
    expect(assetRows(wrapper)).toHaveLength(10)
    expect(wrapper.find('[data-test="spans-rest-toggle"]').exists()).toBe(false)
  })

  it('預設上限為 12 列（規格條文，不是視覺偏好）', async () => {
    // 13 台各一場：只有預設上限真的是 12 才會摺起 1 台
    const spans = Array.from({ length: 13 }, (_, i) => ({
      session_id: i + 1,
      user_id: 1,
      user_name: 'admin',
      asset_id: i + 1,
      asset_name: `a-${i + 1}`,
      account: 'root',
      protocol: 'ssh',
      status: 'closed',
      recording_state: 'available',
      start: at(1),
      end: at(2),
    }))
    const wrapper = await openOverview(mountBars(spans))
    expect(assetRows(wrapper)).toHaveLength(12)
    expect(wrapper.find('[data-test="spans-rest-toggle"]').text()).toContain('1')
  })
})

describe('SessionSpanBars 展開層逐場語義', () => {
  const CONCURRENT = [
    {
      session_id: 21,
      user_id: 1,
      user_name: 'alice',
      asset_id: 5,
      asset_name: '測試 SSH',
      account: 'root',
      protocol: 'ssh',
      status: 'closed',
      recording_state: 'available',
      start: at(2),
      end: at(4),
    },
    {
      session_id: 22,
      user_id: 2,
      user_name: 'bob',
      asset_id: 5,
      asset_name: '測試 SSH',
      account: 'ops',
      protocol: 'ssh',
      status: 'closed',
      recording_state: 'purged',
      start: at(2.5),
      end: at(3.5),
    },
    {
      session_id: 23,
      user_id: 3,
      user_name: 'carol',
      asset_id: 5,
      asset_name: '測試 SSH',
      account: 'root',
      protocol: 'ssh',
      status: 'active',
      recording_state: 'none',
      start: at(3),
      end: null,
    },
  ]

  const openAsset = async (spans, key = '5') => {
    const wrapper = await openOverview(mountBars(spans))
    await wrapper.find(`[data-test="asset-row-${key}"]`).trigger('click')
    await flushPromises()
    return wrapper
  }

  it('展開資產列 → 逐場一列，同時段三人各佔一列（並發可辨識，SHALL NOT 合併）', async () => {
    const wrapper = await openAsset(CONCURRENT)
    expect(sessionRows(wrapper)).toHaveLength(3)
    const bars = [21, 22, 23].map((id) =>
      wrapper.find(`[data-test="span-bar-${id}"]`).attributes('style')
    )
    // 三條各有各的起點，落在同一條刻度尺上而非疊成一條
    expect(new Set(bars).size).toBe(3)
    expect(wrapper.text()).toContain('alice')
    expect(wrapper.text()).toContain('bob')
    expect(wrapper.text()).toContain('carol')
  })

  it('展開層保留文字等價（使用者／資產／起訖／時長）', async () => {
    const wrapper = await openAsset(CONCURRENT)
    const label = wrapper.find('[data-test="span-bar-21"]').attributes('aria-label')
    expect(label).toContain('alice')
    expect(label).toContain('測試 SSH')
    expect(label).toContain('2 時')
  })

  it('展開層保留錄影三態，且「已清除」不表現為回放失敗', async () => {
    const wrapper = await openAsset(CONCURRENT)
    expect(wrapper.find('[data-test="recording-21"]').text()).toBe('可回放')
    expect(wrapper.find('[data-test="recording-22"]').text()).toBe('錄影已依保留政策清除')
    expect(wrapper.find('[data-test="recording-23"]').text()).toBe('無錄影檔')
    expect(wrapper.find('[data-test="recording-23"]').attributes('title')).toContain('未設定')
  })

  it('展開層保留開放端（進行中不畫硬邊）', async () => {
    const wrapper = await openAsset(CONCURRENT)
    const bar = wrapper.find('[data-test="span-bar-23"]')
    expect(bar.classes()).toContain('is-ongoing')
    expect(bar.attributes('aria-label')).toContain('進行中')
    expect(wrapper.text()).toContain('進行中')
  })

  it('展開層保留裁切標記與 0 秒會話的 0% 寬度（靠 CSS min-width 保底可見）', async () => {
    const spans = [
      {
        session_id: 31,
        user_id: 1,
        user_name: 'alice',
        asset_id: 5,
        asset_name: '測試 SSH',
        account: 'root',
        protocol: 'ssh',
        status: 'closed',
        recording_state: 'available',
        start: at(-3),
        end: at(15),
      },
      {
        session_id: 32,
        user_id: 1,
        user_name: 'alice',
        asset_id: 5,
        asset_name: '測試 SSH',
        account: 'root',
        protocol: 'ssh',
        status: 'closed',
        recording_state: 'available',
        start: at(4),
        end: at(4),
      },
    ]
    const wrapper = await openAsset(spans)
    const clipped = wrapper.find('[data-test="span-bar-31"]')
    expect(clipped.classes()).toContain('is-clipped-start')
    expect(clipped.classes()).toContain('is-clipped-end')
    expect(wrapper.find('[data-test="span-bar-32"]').attributes('style')).toContain(
      'width: 0%'
    )
  })

  it('再點一次資產列即收回逐場列（展開是可逆的）', async () => {
    const wrapper = await openAsset(CONCURRENT)
    expect(sessionRows(wrapper)).toHaveLength(3)
    await wrapper.find('[data-test="asset-row-5"]').trigger('click')
    await flushPromises()
    expect(sessionRows(wrapper)).toHaveLength(0)
  })

  it('點跨度條發出 open-session（逐場的回放入口沒有隨兩層化消失）', async () => {
    const wrapper = await openAsset(CONCURRENT)
    await wrapper.find('[data-test="span-bar-21"]').trigger('click')
    expect(wrapper.emitted('open-session').at(-1)[0]).toBe(21)
  })
})

describe('SessionSpanBars 空資料', () => {
  it('窗內無會話時只給一句說明，不渲染任何層', () => {
    const wrapper = mountBars([])
    expect(wrapper.find('[data-test="spans-empty"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="spans-overview-toggle"]').exists()).toBe(false)
  })
})
