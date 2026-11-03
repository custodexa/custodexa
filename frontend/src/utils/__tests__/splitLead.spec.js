import { describe, it, expect } from 'vitest'
import { splitLead } from '@/utils/splitLead'

describe('splitLead', () => {
  it('中文以第一個「。」為界', () => {
    expect(splitLead('尚未設定：這台已有名為 ops 的帳號。要讓平台改用這個帳號，請改用「轉換既有帳號」。'))
      .toEqual({ head: '尚未設定：這台已有名為 ops 的帳號。', body: '要讓平台改用這個帳號，請改用「轉換既有帳號」。' })
  })
  it('英文以「. 」為界，帳號名內的點不拆', () => {
    expect(splitLead('Not set: svc.admin exists. Convert it instead.'))
      .toEqual({ head: 'Not set: svc.admin exists.', body: 'Convert it instead.' })
  })
  it('沒有句號時整段為首句', () => {
    expect(splitLead('Request failed')).toEqual({ head: 'Request failed', body: '' })
    expect(splitLead(undefined)).toEqual({ head: '', body: '' })
  })
})
