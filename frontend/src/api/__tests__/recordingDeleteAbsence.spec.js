import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

// 錄影是證據：前端不得有任何刪除錄影的呼叫或入口。
// 掃描 src/**/*.{js,vue}（排除 __tests__），檢索兩類東西：
//   1. 對錄影端點的 delete 呼叫：路徑 `/sessions/<任意一段 id 寫法>/recording`（其後不是 `/` 或字元），
//      且與 `.delete(`、`method: 'delete'`（不分大小寫）在同一個呼叫內出現；
//   2. 刪錄影按鈕文案鍵。
// id 的寫法涵蓋三種：字面 `:id`、模板字串 `${…}`、字串串接 `' + id + '`。

const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..')

// `/sessions/` 之後接一段 id（字面、模板插值、或串接），再接 `/recording`，其後不是 `/` 或字元
const ID_PART = String.raw`(?:[^/'"\x60$+]+|\$\{[^}]*\}|['"\x60]\s*\+[^+]*\+\s*['"\x60])`
const RECORDING_PATH = String.raw`/sessions/${ID_PART}/recording(?![/\w-])`
// 一個呼叫的範圍：從起始括號到下一個分號或空行，足以涵蓋 request({ url, method }) 的物件字面
const DELETE_MARK = String.raw`(?:\.delete\s*\(|method\s*:\s*['"\x60]delete['"\x60])`

export const RECORDING_DELETE_PATTERNS = [
  // 路徑在前、delete 在後（request({ url: ..., method: 'delete' })、…/recording`, { method })
  new RegExp(String.raw`${RECORDING_PATH}[\s\S]{0,200}?${DELETE_MARK}`, 'i'),
  // delete 在前、路徑在後（http.delete(`/sessions/${id}/recording`)）
  new RegExp(String.raw`${DELETE_MARK}[\s\S]{0,200}?${RECORDING_PATH}`, 'i'),
]

// 刪錄影按鈕文案鍵（locale 或程式碼裡的 deleteRecording／removeRecording 類名稱）
export const RECORDING_DELETE_LABEL = /\b(?:delete|remove)Recording\w*|recording(?:Delete|Remove)\w*/i

export const hitsRecordingDelete = (text) => RECORDING_DELETE_PATTERNS.some((re) => re.test(text))

const walk = (dir, out = []) => {
  for (const name of fs.readdirSync(dir, { withFileTypes: true })) {
    if (name.name === '__tests__' || name.name === 'node_modules') continue
    const p = path.join(dir, name.name)
    if (name.isDirectory()) walk(p, out)
    else if (/\.(js|vue)$/.test(name.name)) out.push(p)
  }
  return out
}

describe('比對式自證：三種 id 寫法的正向樣本都會命中', () => {
  it('字面 :id', () => {
    expect(hitsRecordingDelete("request({ url: '/api/v1/sessions/:id/recording', method: 'delete' })")).toBe(true)
  })

  it('模板字串 ${…}', () => {
    expect(hitsRecordingDelete('http.delete(`/api/v1/sessions/${sessionId}/recording`)')).toBe(true)
    expect(hitsRecordingDelete("request({ url: `/sessions/${row.id}/recording`, method: 'DELETE' })")).toBe(true)
  })

  it('字串串接', () => {
    expect(hitsRecordingDelete("http.delete('/api/v1/sessions/' + id + '/recording')")).toBe(true)
    expect(hitsRecordingDelete("request({ url: '/sessions/' + id + '/recording', method: 'delete' })")).toBe(true)
  })

  it('反向樣本：讀取錄影與其子路徑不命中', () => {
    expect(hitsRecordingDelete('http.get(`/api/v1/sessions/${id}/recording`)')).toBe(false)
    expect(hitsRecordingDelete("http.delete('/api/v1/sessions/' + id + '/recording/download')")).toBe(false)
    expect(hitsRecordingDelete("request({ url: '/sessions/:id/recording', method: 'get' })")).toBe(false)
  })
})

describe('前端不存在刪錄影的呼叫與入口', () => {
  const files = walk(SRC)

  it('掃描範圍非空', () => {
    expect(files.length).toBeGreaterThan(50)
  })

  it('沒有對錄影端點的 delete 呼叫', () => {
    const offenders = files.filter((f) => hitsRecordingDelete(fs.readFileSync(f, 'utf8')))
    expect(offenders.map((f) => path.relative(SRC, f))).toEqual([])
  })

  it('沒有刪錄影按鈕文案鍵', () => {
    const offenders = files.filter((f) => RECORDING_DELETE_LABEL.test(fs.readFileSync(f, 'utf8')))
    expect(offenders.map((f) => path.relative(SRC, f))).toEqual([])
  })
})
