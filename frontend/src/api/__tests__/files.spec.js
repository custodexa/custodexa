// SFTP 端點的 session_id 線上格式（asset-multi-account D9）：後端一律以
// `c.Query("session_id")` 取值（含 multipart 上傳與 JSON body 的 mkdir），
// 故五個端點都必須把它放在 query；空值一律省略，不得送出 `session_id=null`。
import { describe, it, expect, vi, beforeEach } from 'vitest'

const requestMock = vi.fn()
vi.mock('../request', () => ({ default: (...args) => requestMock(...args) }))

import { listFiles, uploadFile, downloadFile, mkdir, deleteFile } from '../files'

describe('files API 的 session_id 參數', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    requestMock.mockResolvedValue({})
  })

  it('帶 session 時五端點皆於 query 附上 session_id', async () => {
    await listFiles(3, '/tmp', 42)
    expect(requestMock.mock.calls.at(-1)[0].params).toEqual({ path: '/tmp', session_id: 42 })

    await uploadFile(3, '/tmp', new File(['a'], 'a.txt'), 42)
    expect(requestMock.mock.calls.at(-1)[0].params).toEqual({ session_id: 42 })

    await downloadFile(3, '/tmp/a.txt', 42)
    expect(requestMock.mock.calls.at(-1)[0].params).toEqual({
      path: '/tmp/a.txt',
      session_id: 42,
    })

    await mkdir(3, '/tmp/sub', 42)
    expect(requestMock.mock.calls.at(-1)[0].params).toEqual({ session_id: 42 })

    await deleteFile(3, '/tmp/a.txt', 42)
    expect(requestMock.mock.calls.at(-1)[0].params).toEqual({
      path: '/tmp/a.txt',
      session_id: 42,
    })
  })

  it('無 session（獨立入口）時完全不出現 session_id', async () => {
    for (const call of [
      () => listFiles(3, '/tmp'),
      () => uploadFile(3, '/tmp', new File(['a'], 'a.txt')),
      () => downloadFile(3, '/tmp/a.txt'),
      () => mkdir(3, '/tmp/sub'),
      () => deleteFile(3, '/tmp/a.txt'),
    ]) {
      await call()
      expect(requestMock.mock.calls.at(-1)[0].params).not.toHaveProperty('session_id')
    }
  })

  it('null/0/空字串一律視為無 session（不得送出無效值）', async () => {
    for (const empty of [null, undefined, 0, '']) {
      await listFiles(3, '/tmp', empty)
      expect(requestMock.mock.calls.at(-1)[0].params).toEqual({ path: '/tmp' })
    }
  })

  it('字串型 session id 轉為數字（route params 常為字串）', async () => {
    await listFiles(3, '/tmp', '42')
    expect(requestMock.mock.calls.at(-1)[0].params).toEqual({ path: '/tmp', session_id: 42 })
  })
})
