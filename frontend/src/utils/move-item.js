/**
 * 不可變地將陣列元素從 from 移到 to（workspace 頁籤拖曳排序用）
 * 越界或無效索引時回傳原陣列
 * @param {Array} list
 * @param {number} from
 * @param {number} to
 * @returns {Array} 新陣列（或原陣列，當無需移動）
 */
export function moveItem(list, from, to) {
  if (
    !Array.isArray(list) ||
    from === to ||
    from < 0 || from >= list.length ||
    to < 0 || to >= list.length
  ) {
    return list
  }
  const next = [...list]
  const [moved] = next.splice(from, 1)
  next.splice(to, 0, moved)
  return next
}
