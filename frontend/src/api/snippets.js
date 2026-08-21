import request from './request'

/** 片段列表（user-scoped） */
export function getSnippets() {
  return request({ url: '/snippets', method: 'get' })
}

/** 建立片段 */
export function createSnippet(data) {
  return request({ url: '/snippets', method: 'post', data })
}

/** 更新片段 */
export function updateSnippet(id, data) {
  return request({ url: `/snippets/${id}`, method: 'put', data })
}

/** 刪除片段 */
export function deleteSnippet(id) {
  return request({ url: `/snippets/${id}`, method: 'delete' })
}
