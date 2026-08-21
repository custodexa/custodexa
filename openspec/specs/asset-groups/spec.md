# asset-groups

## Purpose

資產節點樹（parent_id 自參照、深度上限 10、同層唯一）與資產多歸屬（asset_nodes M2M）：
樹 CRUD、節點授權含子樹生效、左樹右表呈現、非特權樹收斂、授權列表節點全路徑。
政策不掛節點（見 access-policy）。
## Requirements

### Requirement: 分組管理
admin SHALL 能以樹狀節點組織資產：建立節點（任意父節點下，深度上限 10）、改名、搬移（更新父節點，SHALL 拒絕造成環路的目標）、刪除；節點名稱 SHALL 同層唯一（不同父節點下可重名）。資產 SHALL 可同時掛於多個節點（多歸屬），亦可不掛任何節點（未分組）。刪除節點 SHALL 僅允許「無子節點且無直掛資產」者；刪除 SHALL 於同一交易內軟刪除掛在該節點上的全部授權與審核範圍記錄（不留惰性記錄誤導審計），審計日誌 SHALL 記錄連動撤銷筆數。

#### Scenario: 樹狀建立與同層唯一
- **WHEN** admin 於根節點 prod 下建立子節點 kafka，再於 sit 下建立同名 kafka
- **THEN** 兩者並存（不同父）；於 prod 下再建 kafka 回 409

#### Scenario: 搬移拒環路
- **WHEN** admin 將節點 prod 搬移至其後代 prod/kafka 之下
- **THEN** 回 4xx 拒絕，樹不變

#### Scenario: 資產多歸屬
- **WHEN** admin 將資產 A 同時掛於 prod/kafka 與 sit/kafka
- **THEN** A 於兩節點下皆可見；自 prod/kafka 移除後 sit/kafka 歸屬不受影響

#### Scenario: 非空節點禁刪
- **WHEN** admin 刪除仍有子節點或直掛資產的節點
- **THEN** 回 4xx 拒絕並說明原因

#### Scenario: 刪節點連動撤銷授權
- **WHEN** 使用者僅經節點 N 的授權可及資產 A（A 另掛他節點），admin 清空並刪除 N
- **THEN** 掛 N 的授權記錄被軟刪除、授權列表不殘留；審計日誌含節點刪除與連動撤銷筆數

### Requirement: 組授權生效
對節點授予的權限 SHALL 對「該節點及其全部後代節點」下的資產生效（含子樹；資產或子節點加入後 SHALL 即時被涵蓋，無需重新授權）；與直接授權、群組授權沿同一聯集規則（取最高等級、無 deny）。授權生效範圍 SHALL 涵蓋所有以「使用者授權資產集合」為依據的查詢——逐資產授權檢查與授權資產列表 SHALL 使用一致的「直授 OR 節點（子樹）授權」語義，不得出現可連線但不在清單的資產。多歸屬資產 SHALL 於任一歸屬節點被授權即生效。

#### Scenario: 節點授權含子樹
- **WHEN** 使用者獲節點 prod 的 connect 授權，資產 A 掛於 prod/kafka
- **THEN** 使用者可連線 A；A 自 prod/kafka 移除（且無其他授權路徑）後即不可連線

#### Scenario: 新資產即時被涵蓋
- **WHEN** 節點 prod 已授權予使用者，admin 之後將新資產 B 掛入 prod/db
- **THEN** 使用者即刻可見並可連線 B（無需任何授權操作）

#### Scenario: 多歸屬任一路徑生效
- **WHEN** 資產 A 掛於 prod/kafka 與 sit/kafka，使用者僅獲 sit 的授權
- **THEN** 使用者可及 A；A 自 sit/kafka 移除後（僅剩 prod/kafka 歸屬）即不可及

#### Scenario: 節點授權資產出現在授權清單
- **WHEN** 使用者僅獲節點 N 的授權（無任何直接授權），資產 A 掛於 N 的後代節點，使用者呼叫 `GET /api/v1/assets`
- **THEN** 回應包含 A 且 `permission` 反映節點授權等級

### Requirement: 分組呈現
資產列表 SHALL 以「左樹＋右表」呈現：左欄節點樹（惰性載入）、點選節點過濾右表資產，**預設含子樹**且 SHALL 提供顯式的「僅當前節點／含子樹」切換；未掛任何節點的資產 SHALL 歸「未分組」虛擬節。工作區左欄 SHALL 以同一樹語義分節；多歸屬資產 SHALL 於其每個歸屬節點下皆出現。

#### Scenario: 樹過濾含子樹
- **WHEN** 使用者點選節點 prod（含子樹開啟），資產 A 掛於 prod/kafka
- **THEN** 右表列出 A；切換為「僅當前節點」後 A 不再列出（A 未直掛 prod）

#### Scenario: 未分組虛擬節
- **WHEN** 資產 B 未掛任何節點
- **THEN** B 出現於「未分組」節下，不出現於任何樹節點

### Requirement: 分組列表授權收斂
節點樹端點對非 admin/auditor 角色 SHALL 收斂回應範圍：僅回傳「含該使用者授權資產的節點」及其祖先鏈（維持樹可導覽），節點下資產僅列其授權者；完全無授權資產的節點與子樹 SHALL 不出現；不得經樹結構洩漏未授權資產或無關節點。admin/auditor 見全量樹。

#### Scenario: 一般使用者樹收斂
- **WHEN** 一般使用者取得節點樹，其授權資產僅掛於 prod/kafka，sit 子樹全無其授權資產
- **THEN** 回應含 prod 與 prod/kafka（祖先鏈）且資產僅列授權者；sit 及其子樹不出現

#### Scenario: 管理角色樹全量
- **WHEN** admin 或 auditor 取得節點樹
- **THEN** 回應含全部節點與各節點全部資產

### Requirement: 授權列表呈現組授權目標
授權列表（`GET /api/v1/authorizations`）SHALL 對節點授權記錄回傳節點目標資訊（`asset_group_id` 與**全路徑名稱**，如 `prod / kafka`），與直接授權的資產資訊（`asset_id`、`asset_name`）同等可辨識，不得出現無法辨識授權指向的記錄。

#### Scenario: 節點授權記錄可辨識
- **WHEN** admin 查詢某使用者的授權列表，其中一筆為對節點 prod/kafka 的授權
- **THEN** 該筆回應含節點 id 與全路徑名稱
