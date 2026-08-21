/**
 * 品牌單一事實源。
 * 頁面元件一律引用本檔與固定資產路徑（public/brand/icon.png），勿硬編碼品牌字。
 * 描述性副標在 i18n（key `brand.subtitle`，隨語言切換）；
 * name/tagline/icon 為品牌識別，不進 i18n。
 */
export const BRAND = {
  name: 'Custodexa',
  tagline: 'Guard Access. Preserve Evidence.',
  icon: '/brand/icon.png',
}
