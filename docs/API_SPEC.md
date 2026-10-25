# Custodexa - API 規格文件

> 最後更新：2026-10-26（角色引用計數排除已刪除帳號：角色定義的 `references.direct`、`node_scoped_binding_count` 與刪除檢查的 409 `ROLE_DEFINITION_IN_USE` 只計未刪除帳號的直接指派，停用中的帳號計入。路由未變）
> 前次更新：2026-10-26（共用憑證相關回應的範圍化輸出：改密進度與其補跑、放棄、脫離回應，對範圍化檢視者只列範圍內成員並恆附 `out_of_scope_asset_count`；帳號列的五個寫入回應與列表同形；批次改密目標、批次詳情與計畫執行記錄對範圍外憑證收窄；改密候選的 `plan_id` 對不可見計畫為 0。路由未變）
> 前次更新：2026-10-25（說明修正：「有界重新驗證」補上讀不到群組時保留支持的上界及其適用前提，在 T 大於 0 且後續登入都經同一來源時，約為最近一次讀到之後一個時限加一個工作階段壽命；輪替成員補跑的點擊者承接改述為依憑證歸屬判定其當下能力。行為與路由未變）
> 前次更新：2026-10-25（角色範圍化範本與範圍摘要：`GET`／`PATCH /auth/me` 的 `scope_summary` 的 `binding_scope` 值域為 `global`／`nodes`，節點條目附 `nodes: [{id, path}]`；角色定義列表、單筆與草稿摘要新增 `scopable`、`node_range_no_effect`，單筆另有 `node_scoped_binding_count`，編輯描述的入口、細項與獨立能力新增 `scopable`；`PUT /role-definitions/:id` 新增 agent 持有者的 403；內建角色新增資產管理員與授權管理員。路由未變）
> 前次更新：2026-10-25（角色指派的節點選擇：新增 `GET /role-assignment-options`，供指派畫面讀取節點清單與各角色能否限定節點；`POST /role-assignment-previews` 新增選用欄位 `include_managed_asset_counts`，要求時多回可管理資產台數；管理介面的使用者與使用者群組「角色與範圍」分頁可以選擇節點。路由新增一條）
> 前次更新：2026-10-25（角色指派可限定節點：`PUT /users/:id/roles` 與 `PUT /user-groups/:id/role-bindings` 新增選用欄位 `role_nodes`，成功回應在有不會生效的節點範圍時多附 `node_range_no_effect`；新增 `GET /users/:id/role-bindings`，`GET /user-groups/:id/role-bindings` 的節點範圍列多附 `node_ids`；新增錯誤碼 `VALIDATION_ROLE_NOT_NODE_SCOPABLE`、`VALIDATION_ROLE_BINDING_NODES_EMPTY`、`VALIDATION_ROLE_BINDING_NODES_INVALID`，`VALIDATION_ROLE_BINDING_SCOPE_UNSUPPORTED` 的適用入口收斂為不收範圍的入口（外部群組映射沿用 `MAPPING_SCOPE_FIELD_REJECTED`）；新增審計 details 事件 `role_binding_range_changed`；路由新增一條）
> 前次更新：2026-10-24（資產與帳號表單的憑證欄位改依憑證語義能力判定：`POST /assets`、`PUT /assets/:id` 的帳號名稱、登入秘密、內嵌憑證與 SFTP 欄位，`POST /assets/:id/accounts` 與 `PUT /assets/:id/accounts/:accountId` 的帳號名稱，以及 `GET /assets/:id/accounts` 的憑證識別欄位，改由對應的 `credential:create`、`credential:update`、`credential:set-secret`、`credential:view` 或全域持有的 `credential:manage` 任一滿足；只經節點範圍持有語義能力的主體，於寫入交易內以送出的節點（新增資產）或路徑上的資產為目標判定，範圍不符回與目標不存在同形的 404，缺能力回 403 `AUTH_PERMISSION_DENIED`；帳號列表的回應形狀改由讀取當下重新解析的授權狀態決定。路由與錯誤碼未變）
> 前次更新：2026-10-21（存取政策權限點的範圍：`access_policy:manage` 的節點範圍指派改為生效，只經節點範圍持有者對 `PUT /assets/:id` 帶 `access_policy` 只作用於範圍內資產（範圍外與不存在同為 404 `NOTFOUND_ASSET`），`POST /assets` 與匯入帶非空覆寫時目的節點至少一個須在範圍內，否則整筆或整批拒絕（403 `AUTH_PERMISSION_DENIED`）；新增 `GET /assets/access-policy-overrides`（單台覆寫清單，依該權限點的範圍投影，`meta` 帶 `global_default` 與 `scoped`，範圍化時每列附 `out_of_scope_node_count`）；`access_policy:manage` 不再以 `asset:view` 為依賴。路由新增一條）
> 前次更新：2026-10-21（批次新增與改密的範圍收斂：只經節點範圍持有相應能力的主體，批次新增逐列以範圍判定節點與憑證（範圍外與不存在同形），帳號批次改密、改密候選與改密計畫只作用於範圍內目標，明列目標有範圍外或不存在者整批回 404 `NOTFOUND_BATCH_ITEMS_UNAVAILABLE`；改密頁三組讀取端點的讀取範圍明列四種情形；帳號批次改密先判模式所需能力，缺能力者不論目標與名稱狀態一律 403，並接選用欄位 `shared_credential_ownership`；改密計畫接選用欄位 `impact_confirmation_id`，`authorization_state` 新增 `needs_reconfirmation`（停止原因碼 `CHANGE_SECRET_SCOPE_BOUND_EXCEEDED`）；一鍵重新授權在承接交易內對計畫目標重驗。路由與錯誤碼未變）
> 前次更新：2026-10-21（審核範圍管理範圍化：`approverscope:manage` 指派到節點時只管理節點子樹內的資產型與節點型範圍，申請人型另需全域的 `approverscope:manage_applicant`；非超級管理者的列表與建立回應改為精簡欄位並附可審人數；新增 `GET /approver-scopes/approver-options` 與 `GET /approver-scopes/target-options`；輪替證據報告載明只經全域指派生效。路由新增兩條）
> 前次更新：2026-10-21（共用憑證的管理歸屬：憑證與詳情多附 `ownership`，範圍化檢視者另附 `out_of_scope_asset_count` 與列級旗標 `actions`（掛載列另有 `unbind`、`detach`）；列表新增 `ownership`、`owner_node_id` 篩選；建立、範圍轉換與單筆更新接選用欄位 `ownership`；資產帳號列表中引用範圍外憑證的列收窄並標記 `credential_out_of_scope`，附 `actions`；新增錯誤碼 `VALIDATION_CREDENTIAL_OWNERSHIP_INVALID`。兩條新路由與錯誤碼 `RULE_CREDENTIAL_IMPACT_CONFIRMATION_REQUIRED` 見下方 2026-10-20 的「共用憑證範圍外影響確認」與「共用憑證批次改歸」兩列）
> 前次更新：2026-10-21（授權規則範圍化：授權規則的建立、批量、帳號範圍調整與刪除對只持有節點範圍指派的主體照範圍判定；列表與兩個有效權限視角依檢視者範圍投影，列表附列級旗標 `actions`，溯因多附 `out_of_scope_node_count`；新增 `GET /authorizations/subject-options` 與 `GET /authorizations/target-options`；`PUT /authorizations/:id/accounts` 不再要求現況為超級管理者；`POST /access-requests/:id/revoke` 的資格新增授權規則管理範圍一條，撤銷審計改為與撤銷同交易並於提交後補記會話結果。路由新增兩條；資產批次操作：新增 `POST /assets/batch/move`、`/batch/tags`、`/batch/delete` 三條路由，整批單一交易、任一筆無法操作即整批回 404 `NOTFOUND_BATCH_ITEMS_UNAVAILABLE`，批次刪除遇範圍外歸屬回 409 `RULE_ASSET_BATCH_HAS_OUT_OF_SCOPE_NODES`（參數 `count`）；範圍化檢視者的標籤字典與 `tags` 篩選改為只依其可視資產，標籤書寫歸一改用呼叫者看得到的字典；資產變更審計多附 `batch_id`、`batch_size`）
> 前次更新：2026-10-20（共用憑證範圍外影響確認：新增 `POST /credentials/:id/impact-confirmations`，`/secret` 與 `/rotations` 接選用欄位 `impact_confirmation_id`，新增錯誤碼 `RULE_CREDENTIAL_IMPACT_CONFIRMATION_REQUIRED`）
> 前次更新：2026-10-20（共用憑證批次改歸：新增 `POST /credentials/ownership`，整批原子，任一筆不可操作整批拒絕並只回筆數；`PUT /credentials/:id` 的選用欄位 `ownership` 為單筆改歸）
> 前次更新：2026-10-20（資產範圍化：持有節點範圍指派的主體，資產列表與詳情多附列級旗標 `actions`、範圍外歸屬計數 `out_of_scope_node_count`，列表頂層多附 `management_scope`，`node_ids`／`node_paths` 只含其範圍內的歸屬；`PUT /assets/:id` 的 `node_ids` 對這類主體為合併語義；建立與更新後歸屬為空、刪除與停用遇範圍外歸屬分別新增 400 `RULE_ASSET_NODE_REQUIRED`、409 `RULE_ASSET_HAS_OUT_OF_SCOPE_NODES`（參數 `count`）；資產建立與歸屬變更的審計附涵蓋差異。未新增路由）
> 前次更新：2026-10-20（資產節點 API：節點寫入對只持有節點範圍指派的主體照範圍判定，範圍外回與不存在相同的 404、限超級管理者的動作回 403；刪除被管理範圍引用的節點回 409 `RULE_NODE_SCOPE_REFERENCED`（超級管理者另附 `references`）；範圍化檢視者的樹與列表多附列級旗標，樹的根層回應多附 `can_create_root`；`GET /asset-groups` 新增選用查詢參數 `purpose`；改描述單獨留痕、搬移審計多附涵蓋差異。未新增路由）
> 前次更新：2026-10-20（拒絕回應的形狀：能力拒絕一律回 403 單一形狀，body 只有 `error` 與 `code`（`AUTH_PERMISSION_DENIED`），不再帶 `required_permission`、角色參數或其他指出所需權限點與角色的欄位；專用於能力拒絕、以角色或權限命名的七個錯誤碼不再由任何端點發出（仍在目錄與三語譯文）；「統一回應格式」新增「授權拒絕與範圍拒絕的回應形狀」一節，寫明規則拒絕、範圍拒絕（404 與不存在同形）、整批無法操作的新碼 `NOTFOUND_BATCH_ITEMS_UNAVAILABLE`（參數 `count`）與最小揭露例外；五個規則拒絕碼的文案不再寫出操作者所需的身分；各端點段落中的舊拒絕碼與 `required_permission` 敘述同步更正。未新增路由、審計動作與資料表）
> 前次更新：2026-10-20（角色指派的保護角色擴及含高風險權限點（能刪除證據、關閉或改道告警、放寬安全控制或管理金鑰）的自訂角色：「角色指派的保護與開放邊界」補保護角色定義與高風險權限點清單，`AUTH_PROTECTED_ROLE_ASSIGNMENT` 兩處情形與 `assignment_state` 說明同步；未新增路由、錯誤碼、審計動作與資料表）
> 前次更新：2026-10-19（儀表板與版本說明：新增三組路由與段落，`GET`／`PUT /auth/me/release-guidance/:version`（本人對說明版本的關閉狀態）、`GET /dashboard/cards/:key`（儀表板逐卡取值與逐卡能力裁決）、`GET /dashboard/retention-adjustments`（升級時保留天數調整的告知）；新增資料表 `user_release_guidance`；未新增錯誤碼、審計動作與審計資源）
> 前次更新：2026-10-19（改密候選重試與逐台補跑接受選用的 `confirm_host_identity` 確認 body，被主機身分守衛擋下時回應多帶唯讀的 `host_identity`；新增 409 `CONFLICT_HOST_IDENTITY_MOVED`；系統告警登錄補至 19 種並列入 `concurrent_instance_detected`）
> 前次更新：2026-10-19（角色定義管理：新增「角色定義 API」一節（八條 `/role-definitions` 路由，含列表欄位、描述三組、摘要試算、四條寫入與錯誤碼、修改的告警）；新增 `GET /user-groups/:id/external-mappings`；`GET /users/:id` 單筆回應新增頂層 `account_ops`；`POST /role-assignment-previews` 新增 `operation`、逐人的路由增減、`manual_member_ids` 與 `mapping_rule_change`；舊 `GET /roles` 不變）
> 前次更新：2026-10-18（刪除錄影改由獨立權限點 `recording:delete` 把關，並寫明先審計、失敗不刪、建立系統告警與孤兒檔處置；四個資料保留鍵的值域改為 `{0} ∪ [7, 3650]`，補啟動對帳與高危設定告警的說明）
> 前次更新：2026-10-18（主機金鑰不符改為依路徑處置：終端、檔案傳輸與連線測試照常建立並以 `RULE_SSH_HOST_KEY_CHANGED` 警示（終端 notice、列目錄 `host_key_mismatch`、測試 `warning_code`），改密與輪替拒絕撥號（`CHANGE_SECRET_HOST_KEY_MISMATCH`），代理通道開的終端拒絕撥號（新碼 `RULE_SSH_HOST_KEY_MISMATCH_REFUSED`，憑證未送出）；留痕失敗或讀不到記錄回新碼 `RULE_SSH_HOST_KEY_CHECK_FAILED`；新路由 `POST /assets/:id/host-key/adopt`（超管保留）採用待確認指紋，GET 檢視多回 `mismatches`；採用與重置都發 `host_key_record_changed` 告警）
> 前次更新：2026-10-18（審查修正：K8s 上傳在本文暫存後再裁決一次；帳號範圍調整新增 403 `RULE_ACCOUNT_SCOPE_WIDEN_RESTRICTED`（非建立者只能縮小）；agent 擁有者轉移的 409 另涵蓋新 owner 仍有效的核准票；申請決定在交易內重判自核並只計獨立票。路由不變）
> 前次更新：2026-10-18（資料面與防自我授權：K8s 容器檔案上傳／下載改依連線裁決（與連線簽發同一組判定，管理權限點不是放行條件，登錄改為已認證）；新增 `GET /authorizations/self-subjects`；授權規則建立與帳號範圍調整新增 403 `RULE_AUTHORIZATION_SELF_SUBJECT`、申請人型審核範圍新增 400 `RULE_APPROVER_SCOPE_SUBJECT_OVERLAP`、agent 擁有者轉移新增 409 `RULE_AGENT_OWNER_TRANSFER_SELF_GRANT`；擁有者對自有 agent 所提申請的決定比照自核拒絕。路由新增一條）
> 前次更新：2026-10-18（存取政策覆寫成為獨立能力：`PUT /assets/:id` 的登錄基本要求改為僅需登入，能力由請求頂層鍵決定，只含 `access_policy` 者需 `access_policy:manage`，含其他鍵、空本文或不可解析者需 `asset:update`；`POST /assets` 帶非空 `access_policy`、`POST /assets/import` 與 `/import/preview` 任一列帶非空值另需 `access_policy:manage`，匯入整批拒絕。路由集合未變）
> 前次更新：2026-10-18（`PUT /users/:id/status` 啟用持有超級管理者或系統安全管理員身分的帳號同樣限超級管理者，其他操作者回 403 `AUTH_PROTECTED_ACCOUNT_OPERATION`，審計列 `details` 帶 `event=user_enable_rejected`；路由未變）
> 前次更新：2026-10-18（通知通道五支端點的拒絕回應改為能力語義：缺 `notification_channel:manage` 回 403 `AUTH_PERMISSION_DENIED`，不再回 `AUTH_ROLE_REQUIRED`／`role=admin`；路由未變）
> 前次更新：2026-10-18（憑證寫入端點的路由層改認任一憑證語義管理能力（服務層逐項判定不變），逐台補跑與放棄本輪改需 `credential:rotate`，放棄本輪在寫入前另以憑證全部掛載判定；路由未變）
> 前次更新：2026-10-18（資產帳號端點的帳號名稱欄位能力：`POST /assets/:id/accounts` 以請求帶入的帳號名稱建立帳號、`PUT /assets/:id/accounts/:accountId` 改為不同名稱，另需 `credential:manage`，與 `PUT /assets/:id` 的 `username` 同一欄位條件；缺能力 403 `AUTH_PERMISSION_DENIED`、零寫入。主機金鑰重置補記重複重置回 404。路由未變）
> 前次更新：2026-10-18（建立路徑補上憑證能力判定：`POST /assets` 與 `POST /assets/:id/accounts` 帶內嵌密碼或私鑰（新建一份專用憑證）另需 `credential:create`、帶 `credential_id` 掛既有共用憑證另需 `credential:bind`；`POST /assets/import`、`POST /assets/import/preview` 任一列帶 `credential_id` 即需 `credential:bind`。缺能力 403 `AUTH_PERMISSION_DENIED`、零寫入。路由未變）
> 前次更新：2026-10-18（合併檢查點第四版載荷：檢查點列表的第四版列帶 `perm` 鍵（不帶附證者為 `null`，第一至第三版列不帶此鍵），與資產建立／更新的欄位級能力逐欄列出並存；說明分見下列「資產建立／更新的欄位級能力」與「檢查點第四版載荷」兩列。路由未變）
> 前次更新：2026-10-18（資產建立／更新的欄位級能力逐欄列出：密碼與私鑰的更新另需 `credential:set-secret`；資產帳號更新寫入新密文同樣另需 `credential:set-secret`。路由未變）
> 前次更新：2026-10-18（合併同日兩項更新：檢查點列表的第四版列帶 `perm` 鍵，以及憑證讀取端點改需 `credential:view`、改密計劃回應帶 `authorization_state`；兩項說明見下兩列。路由未變）
> 前次更新：2026-10-18（群組角色指派的保護角色界線與直接指派對齊：被新增或移除的指派含超級管理者或系統安全管理員角色才限超級管理者，這兩種指派不變時持 `role:assign` 即可增減其他角色；成員異動與刪除群組仍看群組帶的全部指派。路由與拒絕碼未變）
> 前次更新：2026-10-18（檢查點第四版載荷：列表的第四版列一律帶 `perm`（權限附證的摘要、界標、對帳結果與起點旗標；不帶附證者為 `null`；第一至第三版列不帶此鍵）；`attestation_invalid` 語義縮窄。路由未變）
> 前次更新：2026-10-18（憑證列表、詳情與改密進度三支讀取端點改需 `credential:view`，寫入端點仍需 `credential:manage`；改密計劃回應帶 `authorization_state`（暫停待重新授權的標記）。路由未變）
> 前次更新：2026-10-18（輪替成員新增 `candidate_kept`：拆分模式放棄後，候選仍在的 `abandoned` 成員照列為未收束並可補跑；背景推進不再把 `terminal_failed`／`abandoned` 成員重新排入。路由未變）
> 前次更新：2026-10-17（憑證詳情新增 `unsettled_rotation_id`、RotationDTO 新增 `unsettled`：已有主機改動後才放棄的輪替仍可定址與逐台補跑；服務重啟時停在 `changing` 的成員於啟動時轉為 `changed_unverified`，原因碼 `CHANGE_SECRET_INTERRUPTED`。路由未變）
> 前次更新：2026-10-17（改密承接與其審計同一交易：計畫一鍵重新授權與輪替成員補跑承接，審計寫不進去即不承接並告警；放棄本輪不因成員已收束而失敗。路由與回應形狀未變）
> 前次更新：2026-10-17（檢查點落庫權限附證欄位（列表不外送附證簽章）；結構層新增 `attestation_invalid` 狀態；權限狀態重設的回應與審計另帶參考點與 `after_cp_seq`。路由未變）
> 前次更新：2026-10-17（合併同日兩項更新：使用者群組角色指派與角色指派影響預覽三條路由，以及權限狀態對帳無法判定時的檢查點回應與確認端點語義；兩項說明見下兩列）
> 前次更新：2026-10-17（新增使用者群組角色指派與角色指派影響預覽三條路由：`GET`／`PUT /user-groups/:id/role-bindings`、`POST /role-assignment-previews`；指派入口新增保護目標與指派能力的拒絕碼，見「使用者群組 API」）
> 前次更新：2026-10-17（權限狀態對帳無法判定時：檢查點結構層回應的 `chain` 另帶 `permission_state`，`POST /audit-failures/permission-state/accept` 改為重設比對基準、不再回 409；agent token 列表的還原失效說明對齊 `restore_invalidated`。路由未變）
> 前次更新：2026-10-17（`/auth/me` 能力投影新增呈現點 `ui:super-admin`：保留的內建超級管理者身分，供只限超管的畫面元素使用，與連線豁免分開。路由未變）
> 前次更新：2026-10-16（還原世代與權限附證不改任何既有回應：JWT、refresh、agent token、資產授權、檢查點端點沒有新欄；註明還原後的首次啟動在完成恢復前只開健康檢查與解封端點。路由未變）
> 前次更新：2026-10-16（`GET`／`PATCH /auth/me` 成功回應加能力投影兩欄 `permissions`、`scope_summary`；`ui:` 呈現點為不可指派的伺服器投影，僅供前端呈現，不是授權依據）
> 前次更新：2026-10-16（新增 `POST /audit-failures/permission-state/accept`：超管確認權限狀態「無來源變動」並接受風險；詳見「稽核失效事件」）
> 前次更新：2026-10-13（`GET /sessions/:id` 詳情與事件報告 `sessions.csv` 的 `recording_state` 同名不同義，兩處各補一句區分。路由未變）
> 前次更新：2026-10-13（登入方法清單加 `ldap`（啟用中的目錄，只含識別碼）；OIDC provider 列表頂層加 `redirect_uri`／`redirect_uri_state`；狀態彙總的 `last_success` 加 `account_removed`；回呼失敗 slug 加 `oidc_code_exchange_failed`。路由未變）
> 前次更新：2026-10-13（身分來源狀態彙總加 `last_attempt`、`last_success`、`discovery_checked_at`、`last_login_groups_at`、`groups_unknown_at`、`group_attr_configured`、`source_updated_at`、`login_test_url`、`login_test_state`；探索預覽加 `issuer_matches`、`id_token_signing_alg_values_supported`、`signing_alg_compatible`。路由未變）
> 前次更新：2026-10-13（錄影可讀性：本機錄影檔存在但讀不到時，metadata、下載、串流與 rtoken 串流一律回 500 `INTERNAL_RECORDING_FILE_UNREADABLE`，不存在回 404 `NOTFOUND_RECORDING_FILE`，下載不再回轉址或純文字 403；`GET /sessions/:id` 詳情加 `recording_state`／`recording_source`；證據包 manifest 加 `skipped_recordings`。路由未變）
> 前次更新：2026-10-13（OIDC provider 補寫 `force_shared` 三態：未帶＝不變更、`true`＝收緊、`false`＝撤回自己的收緊並清回未表態；未曾收緊的共用來源送 `false` 仍回 400。路由未變）
> 前次更新：2026-10-13（人工輸入私鑰的寫入入口（建立／更新資產、新增／更新資產帳號、建立共用憑證、直接寫入密文、單台脫離共用自訂私鑰）加 400 `VALIDATION_CREDENTIAL_PRIVATE_KEY_INVALID`；終端撥號與檔案管理遇私鑰無法解析改回 `RULE_SSH_PRIVATE_KEY_INVALID`（檔案管理為 400）。路由未變）
> 前次更新：2026-10-12（每日審閱單日明細的 Event 與操作日誌列表／單筆加 `reason_code`、`reason_params`；計數物件與 `daily_reviews.csv` 尾端加 `high_risk_criteria`；OIDC callback 失敗 slug 加 `oidc_account_removed`、`oidc_user_inactive`；刪除使用者作廢其外部身分綁定，審計列帶被刪帳號名稱與作廢數。路由未變）
> 前次更新：2026-10-11（PCI DSS 10.4.1 改以每日簽核的運作紀錄判定：判定結果加 `insufficient_data`、摘要加同名格、四個理由碼、判定上的 `signoff` 運作紀錄；套用預覽加 `notes`；證據包加 `daily_reviews.csv` 與清單檔 `daily_reviews` 段；合規報告 ZIP 對含此條文的組加 `daily_reviews.csv`；高危操作白名單只計寫入類動作、安全政策預覽改記為讀取；升級前的簽核 `alerts_after_sign` 為 `null`。路由未變）
> 前次更新：2026-10-11（每日審閱簽核改版：依業務時區切日、可補簽指定所屬日、新增待簽清單／單日明細／期間統計端點與 11 個錯誤碼；`GET /audit-logs` 加 `end_before`；`daily_review_overdue` 通知改列出全部未簽日）
> 前次更新：2026-10-06（`POST /seal/authorize` 在已解封時一律回 409 `SEAL_ALREADY_UNSEALED`；`POST /auth/login` 的帳號含控制字元時回 401 而非 500）
> 前次更新：2026-10-06（`GET /seal/status` 在已解封時多回現行 KEK 識別 `kek_id`）
> 前次更新：2026-10-01（資產批次新增：`POST /assets/import/preview` 預檢與 `POST /assets/import` 整批建立；資產列表加 `credential_pending` 欄與同名篩選參數；單筆建立完全沒有憑證來源時建零掛載資產）
> 前次更新：2026-09-30（外部群組映射新增角色明確路由、使用者群組規則、共用字典備註、用途確認及兩類計數）
> 前次更新：2026-09-29（告警審閱與三個核決端點加批次關聯碼 `batch_id`、告警批次審閱的三個條件與錯誤碼、告警列表 `ids` 查詢；通知通道加 `min_severity` 推送門檻欄與 `VALIDATION_CHANNEL_MIN_SEVERITY`；合規報告手動產出 `POST /compliance/report-jobs`，下載中心 `kind` 閉集加 `compliance_report`；登入回應與 `/auth/me` 的 `UserInfo` 加產品版本欄 `product_version`）

> 資料來源：`backend/cmd/server/main.go`（組裝根）, `backend/cmd/server/stage1.go`／`stage2.go`（兩段啟動）, `backend/internal/api/*.go`,
> `backend/internal/sshproxy/handler.go`, `backend/internal/proxy/handler.go`,
> `backend/internal/modules/*`（asset／identity／authz／policy／audit／session／keyvault 七模組）, `backend/internal/model/*.go`,
> `backend/internal/middleware/permission.go`, `backend/config/config.go`
> 相關文件：資料模型見 [DB_SCHEMA.md](DB_SCHEMA.md)；各能力行為規格見 `openspec/specs/`；動到路由時須同步本文件（見 [CONTRIBUTING.md](../CONTRIBUTING.md)）。

---

## 總覽

| 模組 | 端點數 | 基礎路徑 | 說明 |
|------|--------|----------|------|
| 系統 | 3 | `/health`, `/api/v1/ping` | 健康檢查（GET/POST）與 ping |
| 單實例守衛 | 3 | `/api/v1/instance-guard` | 守衛全貌快照（`instanceguard:view`；每次呼叫留一筆讀取稽核，介面不輪詢；粗狀態另隨 `/api/v1/seal/status` 出）＋攔下頁的狀態查詢與確認送出（不需 JWT，受來源網段限制） |
| 認證 / MFA | 12 | `/api/v1/auth`, `/api/v1/users` | 登入（本地/LDAP）、MFA 兩階段、強制註冊、自助改密、會話刷新、管理員救援 |
| 版本說明與儀表板 | 4 | `/api/v1/auth/me/release-guidance`、`/api/v1/dashboard` | 本人對說明版本的關閉狀態（讀取／關閉）、儀表板逐卡取值、升級時保留天數調整的告知 |
| OIDC 登入 | 4 | `/api/v1/auth/methods`, `/api/v1/auth/oidc` | 登入方法清單（公開）、SSO 發起／IdP 回呼／交棒憑證兌換 |
| OIDC provider | 7 | `/api/v1/oidc-providers` | 身分提供者 CRUD＋單筆詳情＋狀態彙總＋探索預覽（`oidc:manage`；secret write-only，身分域建後不可變） |
| LDAP 目錄 | 5 | `/api/v1/ldap-directory` | 目錄設定 singleton 資源＋連線測試＋狀態彙總（`ldap:manage`；bind 密碼 write-only，設定自 env 遷入 DB） |
| 身分來源與外部群組映射 | 16 | `/api/v1/identity-sources` | 來源列表、角色映射相容及明確路由、使用者群組映射、字典備註與用途查詢（`identity_source:manage`） |
| 安全政策 | 6 | `/api/v1/security-policies`, `/api/v1/auth/banner` | 安全政策查詢/批次更新、單一設定鍵的定義查詢、草稿判定與套用預覽（`securitypolicy:manage`）＋登入前告示讀取（公開） |
| 政策組 | 10 | `/api/v1/policy-groups` | 政策組與條文對照的維護：組建立/更名/生效開關/刪除、條文與要求整批取代、機構備註與人工確認（讀 `policygroup:view`，寫 `policygroup:manage`） |
| 合規對照 | 1 | `/api/v1/compliance` | 設定現值對各生效政策組的判定快照（唯讀，`compliance:view`） |
| 排程時刻預覽 | 1 | `/api/v1/schedules` | 由後端解析排程字串並回下次幾個執行時刻（`schedule:manage`；不讀寫任何資料） |
| 金鑰管理 | 4 | `/api/v1/keys` | 金鑰清冊/DEK 輪替/KEK 重包/退役材料清理（`key:manage`） |
| 資產 | 23 | `/api/v1/assets` | CRUD、批次新增（預檢與整批建立）、批次搬移／加標籤／刪除、連線測試、傳輸能力查詢、K8s pod 列表與檔案進出、標籤清單與治理、資產帳號 CRUD＋設預設 |
| 帳號憑證庫 | 15 | `/api/v1/credentials`、`/api/v1/assets/:id/accounts/:accountId/credential` | 憑證 CRUD、範圍轉換、直接寫入密文、掛載與卸載、更換掛載憑證、整組改密與逐台補跑、單台脫離共用（列表、詳情、改密進度需 `credential:view`；補跑與放棄需 `credential:rotate`；其餘寫入需任一憑證語義管理能力，各動作由服務層逐項判定） |
| Host Key | 2 | `/api/v1/assets/:id/host-key` | TOFU host key 檢視/重置 |
| 檔案管理（SFTP） | 5 | `/api/v1/assets/:id/files` | SSH 資產檔案列表/上下傳/建目錄/刪除 |
| 資產節點 | 6 | `/api/v1/asset-groups` | 節點樹 CRUD＋樹導覽＋搬移 |
| Session | 5 | `/api/v1/sessions` | 列表/詳情/活動/統計/終止（讀取需 `session:view`，終止需 `session:terminate`） |
| 自助連線 | 2 | `/api/v1/my/connections`（列表＋`:id/terminate` 自助終止） | 一般 user 自己的連線精簡紀錄與自助終止（僅需登入） |
| 指令稽核 | 2 | `/api/v1/sessions`, `/api/v1/commands` | 單會話指令流、跨會話搜尋 |
| 剪貼簿稽核 | 2 | `/api/v1/sessions/:id/clipboard-events` | RDP/VNC 剪貼簿留存事實列表＋單筆內容解密調閱（逐筆留痕） |
| 會話分享 | 3 | `/api/v1/sessions` | 建立/撤銷分享、分享觀看（WS） |
| 監看 / 會話指標 | 2 | `/api/v1/sessions`, `/api/v1/ssh` | 即時監看（WS）、目標主機指標 |
| 連線 | 3 | `/api/v1/connect`, `/api/v1/ssh`, `/api/v1/connect-tokens` | 圖形/文字終端 WS、一次性連線 token（傳輸政策閘：strict 400／warn 428） |
| 傳輸同意 | 1 | `/api/v1/transmission-consents` | 傳輸風險同意立據（warn 檔連線前） |
| 通道清冊 | 2 | `/api/v1/transmission-inventory` | 全通道加密狀態清冊＋匯出快照（`transmission:manage`，PCI Req 4） |
| 錄影 | 7 | `/api/v1/sessions`, `/api/v1/recordings` | 元數據/下載/串流/rtoken/刪除/統計 |
| 離機儲存 | 11 | `/api/v1/offsite-storage` | 設定（讀/寫/世代切換確認/停止離機/歷史世代/撤銷憑證）＋狀態、失敗清單、測試連線、批次與單筆重試（全數 `offsite:manage`；憑證 write-only） |
| 用戶 | 13 | `/api/v1/users` | CRUD + 角色（替換管理者指派集／冪等追加／釘住）/狀態/密碼 + 解鎖/閒置停用豁免 + 本地管理員計數 + 允許來源網段判定 |
| 角色 | 1 | `/api/v1/roles` | 角色列表 |
| 角色定義 | 8 | `/api/v1/role-definitions` | 角色定義列表／單筆／描述／摘要試算（讀取需 `role:view`）與自訂角色的新增、複製、修改、刪除（寫入由服務層限超級管理者） |
| 使用者群組 | 9 | `/api/v1/user-groups` | 群組 CRUD＋成員維護＋角色指派讀取與整組替換＋外部群組映射唯讀摘要（授權主體） |
| 角色指派預覽 | 1 | `/api/v1/role-assignment-previews` | 變更前試算有效能力的增減與危險組合（唯讀） |
| 授權 | 7 | `/api/v1/authorizations` | 資產/節點授權（主體 user/群組二擇一）＋多主體批量＋有效權限雙視角＋帳號範圍更新 |
| 連線申請 | 15 | `/api/v1/access-requests` | 三段存取政策申請核准流＋破窗/撤銷/補審：申請/破窗/撤回/我的單＋審核/撤銷/補審端點 |
| 審核範圍 | 5 | `/api/v1/approver-scopes` | approver 審核範圍維護（`approverscope:manage`，客體四維恰一：資產/節點/申請人/使用者群組）＋審核方與客體兩個選擇端點 |
| 稽核日誌 | 3 | `/api/v1/audit-logs` | 日誌查詢（依功能開關註冊） |
| 調查工作台 | 2 | `/api/v1/audit/timeline`, `/api/v1/audit/subjects` | 六類稽核資料的聚合時間軸＋樞紐候選（人／資產／來源位址；`audit:view`，唯讀） |
| 稽核匯出 | 4 | `/api/v1/audit-export` | 事件報告同步匯出＋證據包非同步 job（發起/清單/下載）（PCI 10.5.1） |
| 存取複審 | 4 | `/api/v1/access-reviews` | 存取矩陣/複審歷史/單筆快照/簽核（PCI 7.2.4；全端點無條件守門） |
| 告警規則 | 4 | `/api/v1/alert-rules` | 輸入指令／輸出敏感資料規則 CRUD |
| 告警查詢 / 審閱 | 2 | `/api/v1/command-alerts` | 告警記錄查詢 + 審閱處置（PCI 10.4.1） |
| 通知通道 | 5 | `/api/v1/notification-channels` | webhook 通道 CRUD + 測試 |
| 命令片段 | 4 | `/api/v1/snippets` | user-scoped 片段 CRUD |
| 改密 | 15 | `/api/v1/change-secret-plans`、`/api/v1/change-secret-candidates`、`/api/v1/change-secret-batches` | 計劃 CRUD、手動觸發、執行記錄；未驗證憑證清單／重試／清除；以帳號為主軸的批次改密 |
| 營運指標 | 1 | `/metrics` | Prometheus 曝光格式（刻意不在 `/api` 之下，故預設不被 edge 代理） |

**總計**: 241 端點（含 4 個 WebSocket 端點）。此數為上表各模組的人工加總，口徑是
「語義端點」；下方索引則是 gin 實際註冊的路由條目數，同一路徑的不同方法各計一條，
故兩者不相等屬正常。**以索引為準**。

### 端點索引（機器生成，勿手改）

下表由 `registerRoutes` 的實際註冊結果生成，並由 `TestAPIIndex` 守衛雙向相等：
索引缺少任一實際路由會失敗，索引含有不存在的路由亦會失敗。

`註冊條件` 為枚舉：`always` 表無條件註冊，其餘值為控制該路由是否註冊的環境變數名。
路徑採 gin 形式（`:id` 為路徑參數）。新增條件註冊機制時須同步擴充枚舉值域。

重新生成（**不可手改本區塊**）：

```bash
docker compose run --rm --no-deps -v ./docs:/app/cmd/server/testdata/docs-rw backend \
  go test ./cmd/server -run '^TestAPIIndex$' -update
```

一般測試容器只有唯讀的 `docs/` 掛載，故守衛無法竄改其驗證對象——重新生成須用上述
額外加掛可寫點的一次性容器。

<!-- BEGIN API-INDEX -->
| 方法 | 路徑 | 註冊條件 |
|---|---|---|
| POST | `/api/v1/access-requests` | always |
| POST | `/api/v1/access-requests/:id/approve` | always |
| POST | `/api/v1/access-requests/:id/cancel` | always |
| POST | `/api/v1/access-requests/:id/reject` | always |
| GET | `/api/v1/access-requests/:id/reports` | always |
| POST | `/api/v1/access-requests/:id/reports` | always |
| POST | `/api/v1/access-requests/:id/review` | always |
| POST | `/api/v1/access-requests/:id/revoke` | always |
| POST | `/api/v1/access-requests/break-glass` | always |
| GET | `/api/v1/access-requests/history` | always |
| GET | `/api/v1/access-requests/mine` | always |
| GET | `/api/v1/access-requests/mine/tickets` | always |
| GET | `/api/v1/access-requests/pending` | always |
| GET | `/api/v1/access-requests/pending/count` | always |
| GET | `/api/v1/access-requests/reviews/pending` | always |
| GET | `/api/v1/access-requests/tickets` | always |
| GET | `/api/v1/access-reviews` | always |
| POST | `/api/v1/access-reviews` | always |
| GET | `/api/v1/access-reviews/:id` | always |
| GET | `/api/v1/access-reviews/matrix` | always |
| GET | `/api/v1/agent-tasks` | always |
| GET | `/api/v1/agent-tasks/:requestId` | always |
| GET | `/api/v1/agent-tool-calls` | always |
| GET | `/api/v1/agent-tool-calls/:id/arguments` | always |
| GET | `/api/v1/alert-rules` | always |
| POST | `/api/v1/alert-rules` | always |
| DELETE | `/api/v1/alert-rules/:id` | always |
| PUT | `/api/v1/alert-rules/:id` | always |
| GET | `/api/v1/approver-scopes` | always |
| POST | `/api/v1/approver-scopes` | always |
| DELETE | `/api/v1/approver-scopes/:id` | always |
| GET | `/api/v1/approver-scopes/approver-options` | always |
| GET | `/api/v1/approver-scopes/target-options` | always |
| GET | `/api/v1/asset-groups` | always |
| POST | `/api/v1/asset-groups` | always |
| DELETE | `/api/v1/asset-groups/:id` | always |
| PUT | `/api/v1/asset-groups/:id` | always |
| PUT | `/api/v1/asset-groups/:id/move` | always |
| GET | `/api/v1/asset-groups/tree` | always |
| GET | `/api/v1/assets` | always |
| POST | `/api/v1/assets` | always |
| DELETE | `/api/v1/assets/:id` | always |
| GET | `/api/v1/assets/:id` | always |
| PUT | `/api/v1/assets/:id` | always |
| GET | `/api/v1/assets/:id/accounts` | always |
| POST | `/api/v1/assets/:id/accounts` | always |
| DELETE | `/api/v1/assets/:id/accounts/:accountId` | always |
| PUT | `/api/v1/assets/:id/accounts/:accountId` | always |
| PUT | `/api/v1/assets/:id/accounts/:accountId/credential` | always |
| POST | `/api/v1/assets/:id/accounts/:accountId/set-default` | always |
| DELETE | `/api/v1/assets/:id/files` | always |
| GET | `/api/v1/assets/:id/files` | always |
| GET | `/api/v1/assets/:id/files/download` | always |
| POST | `/api/v1/assets/:id/files/mkdir` | always |
| POST | `/api/v1/assets/:id/files/upload` | always |
| DELETE | `/api/v1/assets/:id/host-key` | always |
| GET | `/api/v1/assets/:id/host-key` | always |
| POST | `/api/v1/assets/:id/host-key/adopt` | always |
| GET | `/api/v1/assets/:id/k8s/download` | always |
| GET | `/api/v1/assets/:id/k8s/pods` | always |
| POST | `/api/v1/assets/:id/k8s/upload` | always |
| POST | `/api/v1/assets/:id/test-connection` | always |
| GET | `/api/v1/assets/:id/transfer-capabilities` | always |
| GET | `/api/v1/assets/access-policy-overrides` | always |
| POST | `/api/v1/assets/batch/delete` | always |
| POST | `/api/v1/assets/batch/move` | always |
| POST | `/api/v1/assets/batch/tags` | always |
| POST | `/api/v1/assets/import` | always |
| POST | `/api/v1/assets/import/preview` | always |
| GET | `/api/v1/assets/tags` | always |
| POST | `/api/v1/assets/tags/delete` | always |
| POST | `/api/v1/assets/tags/rename` | always |
| GET | `/api/v1/audit-checkpoints` | always |
| GET | `/api/v1/audit-checkpoints/public-key` | always |
| GET | `/api/v1/audit-checkpoints/verify` | always |
| GET | `/api/v1/audit-export` | always |
| GET | `/api/v1/audit-export/jobs` | always |
| POST | `/api/v1/audit-export/jobs` | always |
| GET | `/api/v1/audit-export/jobs/:id/download` | always |
| GET | `/api/v1/audit-export/public-key` | always |
| GET | `/api/v1/audit-failures` | always |
| POST | `/api/v1/audit-failures/permission-state/accept` | always |
| GET | `/api/v1/audit-integrity/verify` | always |
| GET | `/api/v1/audit-logs` | FEATURE_AUDIT_LOG_ENABLED |
| GET | `/api/v1/audit-logs/:id` | FEATURE_AUDIT_LOG_ENABLED |
| GET | `/api/v1/audit-logs/resource/:resource/:id` | FEATURE_AUDIT_LOG_ENABLED |
| GET | `/api/v1/audit/subjects` | always |
| GET | `/api/v1/audit/timeline` | always |
| GET | `/api/v1/auth/banner` | always |
| POST | `/api/v1/auth/change-password` | always |
| POST | `/api/v1/auth/login` | always |
| POST | `/api/v1/auth/logout` | always |
| GET | `/api/v1/auth/me` | always |
| PATCH | `/api/v1/auth/me` | always |
| GET | `/api/v1/auth/me/release-guidance/:version` | always |
| PUT | `/api/v1/auth/me/release-guidance/:version` | always |
| GET | `/api/v1/auth/methods` | always |
| POST | `/api/v1/auth/mfa/disable` | always |
| POST | `/api/v1/auth/mfa/enable` | always |
| POST | `/api/v1/auth/mfa/enroll/confirm` | always |
| POST | `/api/v1/auth/mfa/enroll/setup` | always |
| POST | `/api/v1/auth/mfa/setup` | always |
| POST | `/api/v1/auth/mfa/verify` | always |
| GET | `/api/v1/auth/oidc/:id/begin` | always |
| GET | `/api/v1/auth/oidc/callback` | always |
| POST | `/api/v1/auth/oidc/exchange` | always |
| POST | `/api/v1/auth/refresh` | always |
| GET | `/api/v1/authorizations` | always |
| POST | `/api/v1/authorizations` | always |
| DELETE | `/api/v1/authorizations/:id` | always |
| PUT | `/api/v1/authorizations/:id/accounts` | always |
| POST | `/api/v1/authorizations/batch` | always |
| GET | `/api/v1/authorizations/effective-assets` | always |
| GET | `/api/v1/authorizations/effective-users` | always |
| GET | `/api/v1/authorizations/self-subjects` | always |
| GET | `/api/v1/authorizations/subject-options` | always |
| GET | `/api/v1/authorizations/target-options` | always |
| GET | `/api/v1/change-secret-batches` | always |
| POST | `/api/v1/change-secret-batches` | always |
| GET | `/api/v1/change-secret-batches/:id` | always |
| GET | `/api/v1/change-secret-batches/targets` | always |
| GET | `/api/v1/change-secret-batches/usernames` | always |
| GET | `/api/v1/change-secret-candidates` | always |
| DELETE | `/api/v1/change-secret-candidates/:id` | always |
| POST | `/api/v1/change-secret-candidates/:id/retry` | always |
| GET | `/api/v1/change-secret-plans` | always |
| POST | `/api/v1/change-secret-plans` | always |
| DELETE | `/api/v1/change-secret-plans/:id` | always |
| PUT | `/api/v1/change-secret-plans/:id` | always |
| GET | `/api/v1/change-secret-plans/:id/records` | always |
| POST | `/api/v1/change-secret-plans/:id/run` | always |
| POST | `/api/v1/change-secret-plans/reauthorize` | always |
| GET | `/api/v1/command-alerts` | always |
| POST | `/api/v1/command-alerts/:id/review` | always |
| GET | `/api/v1/command-alerts/:id/system-detail` | always |
| GET | `/api/v1/commands` | always |
| POST | `/api/v1/compliance/report-jobs` | always |
| GET | `/api/v1/compliance/snapshot` | always |
| GET | `/api/v1/connect` | always |
| POST | `/api/v1/connect-tokens` | always |
| GET | `/api/v1/credentials` | always |
| POST | `/api/v1/credentials` | always |
| DELETE | `/api/v1/credentials/:id` | always |
| GET | `/api/v1/credentials/:id` | always |
| PUT | `/api/v1/credentials/:id` | always |
| POST | `/api/v1/credentials/:id/bindings` | always |
| DELETE | `/api/v1/credentials/:id/bindings/:accountId` | always |
| POST | `/api/v1/credentials/:id/bindings/:accountId/detach` | always |
| POST | `/api/v1/credentials/:id/impact-confirmations` | always |
| POST | `/api/v1/credentials/:id/rotations` | always |
| GET | `/api/v1/credentials/:id/rotations/:rid` | always |
| POST | `/api/v1/credentials/:id/rotations/:rid/abandon` | always |
| POST | `/api/v1/credentials/:id/rotations/:rid/members/:mid/retry` | always |
| POST | `/api/v1/credentials/:id/scope` | always |
| POST | `/api/v1/credentials/:id/secret` | always |
| POST | `/api/v1/credentials/ownership` | always |
| GET | `/api/v1/daily-reviews` | always |
| POST | `/api/v1/daily-reviews` | always |
| GET | `/api/v1/daily-reviews/days/:date` | always |
| GET | `/api/v1/daily-reviews/pending` | always |
| GET | `/api/v1/daily-reviews/pending/count` | always |
| GET | `/api/v1/daily-reviews/stats` | always |
| GET | `/api/v1/daily-reviews/status` | always |
| GET | `/api/v1/dashboard/cards/:key` | always |
| GET | `/api/v1/dashboard/retention-adjustments` | always |
| GET | `/api/v1/db-console` | always |
| GET | `/api/v1/db-console/sessions/:id/results/:event_id/export` | always |
| GET | `/api/v1/identity-sources` | always |
| GET | `/api/v1/identity-sources/:type/:sourceId/external-groups` | always |
| PUT | `/api/v1/identity-sources/:type/:sourceId/external-groups/:externalGroupId` | always |
| GET | `/api/v1/identity-sources/:type/:sourceId/mappings` | always |
| POST | `/api/v1/identity-sources/:type/:sourceId/mappings` | always |
| DELETE | `/api/v1/identity-sources/:type/:sourceId/mappings/:ruleId` | always |
| PUT | `/api/v1/identity-sources/:type/:sourceId/mappings/:ruleId` | always |
| GET | `/api/v1/identity-sources/:type/:sourceId/role-mappings` | always |
| POST | `/api/v1/identity-sources/:type/:sourceId/role-mappings` | always |
| DELETE | `/api/v1/identity-sources/:type/:sourceId/role-mappings/:ruleId` | always |
| PUT | `/api/v1/identity-sources/:type/:sourceId/role-mappings/:ruleId` | always |
| GET | `/api/v1/identity-sources/:type/:sourceId/user-group-mappings` | always |
| POST | `/api/v1/identity-sources/:type/:sourceId/user-group-mappings` | always |
| DELETE | `/api/v1/identity-sources/:type/:sourceId/user-group-mappings/:ruleId` | always |
| PUT | `/api/v1/identity-sources/:type/:sourceId/user-group-mappings/:ruleId` | always |
| GET | `/api/v1/identity-sources/:type/:sourceId/user-group-usage/:userGroupId` | always |
| GET | `/api/v1/instance-guard` | always |
| POST | `/api/v1/instance-guard/ack` | always |
| GET | `/api/v1/instance-guard/halt` | always |
| GET | `/api/v1/keys` | always |
| DELETE | `/api/v1/keys/retired-material` | always |
| DELETE | `/api/v1/keys/rewrap` | always |
| POST | `/api/v1/keys/rewrap` | always |
| POST | `/api/v1/keys/rotate` | always |
| GET | `/api/v1/keys/topology` | always |
| PUT | `/api/v1/keys/topology` | always |
| DELETE | `/api/v1/ldap-directory` | always |
| GET | `/api/v1/ldap-directory` | always |
| PUT | `/api/v1/ldap-directory` | always |
| GET | `/api/v1/ldap-directory/status` | always |
| POST | `/api/v1/ldap-directory/test` | always |
| POST | `/api/v1/mcp` | always |
| GET | `/api/v1/my/agents` | always |
| POST | `/api/v1/my/agents` | always |
| GET | `/api/v1/my/connections` | always |
| POST | `/api/v1/my/connections/:id/terminate` | always |
| GET | `/api/v1/notification-channels` | always |
| POST | `/api/v1/notification-channels` | always |
| DELETE | `/api/v1/notification-channels/:id` | always |
| PUT | `/api/v1/notification-channels/:id` | always |
| POST | `/api/v1/notification-channels/:id/test` | always |
| GET | `/api/v1/offsite-storage/failures` | always |
| POST | `/api/v1/offsite-storage/objects/:id/retry` | always |
| GET | `/api/v1/offsite-storage/profiles` | always |
| POST | `/api/v1/offsite-storage/profiles/:id/revoke-credentials` | always |
| POST | `/api/v1/offsite-storage/retry-failed` | always |
| GET | `/api/v1/offsite-storage/settings` | always |
| PUT | `/api/v1/offsite-storage/settings` | always |
| POST | `/api/v1/offsite-storage/settings/confirm` | always |
| POST | `/api/v1/offsite-storage/settings/disable` | always |
| GET | `/api/v1/offsite-storage/status` | always |
| POST | `/api/v1/offsite-storage/test` | always |
| GET | `/api/v1/oidc-providers` | always |
| POST | `/api/v1/oidc-providers` | always |
| DELETE | `/api/v1/oidc-providers/:id` | always |
| GET | `/api/v1/oidc-providers/:id` | always |
| PUT | `/api/v1/oidc-providers/:id` | always |
| GET | `/api/v1/oidc-providers/:id/status` | always |
| POST | `/api/v1/oidc-providers/discovery-preview` | always |
| GET | `/api/v1/ping` | always |
| GET | `/api/v1/policy-groups` | always |
| POST | `/api/v1/policy-groups` | always |
| DELETE | `/api/v1/policy-groups/:code` | always |
| GET | `/api/v1/policy-groups/:code` | always |
| PUT | `/api/v1/policy-groups/:code` | always |
| DELETE | `/api/v1/policy-groups/:code/clauses/:clause_no` | always |
| PUT | `/api/v1/policy-groups/:code/clauses/:clause_no` | always |
| PUT | `/api/v1/policy-groups/:code/clauses/:clause_no/annotation` | always |
| POST | `/api/v1/policy-groups/:code/clauses/:clause_no/confirm` | always |
| PUT | `/api/v1/policy-groups/:code/enabled` | always |
| GET | `/api/v1/recordings/stats` | always |
| GET | `/api/v1/recordings/stream` | always |
| GET | `/api/v1/role-assignment-options` | always |
| POST | `/api/v1/role-assignment-previews` | always |
| GET | `/api/v1/role-definitions` | always |
| POST | `/api/v1/role-definitions` | always |
| DELETE | `/api/v1/role-definitions/:id` | always |
| GET | `/api/v1/role-definitions/:id` | always |
| PUT | `/api/v1/role-definitions/:id` | always |
| POST | `/api/v1/role-definitions/:id/copy` | always |
| GET | `/api/v1/role-definitions/descriptors` | always |
| POST | `/api/v1/role-definitions/summary` | always |
| GET | `/api/v1/roles` | always |
| GET | `/api/v1/rotation-report` | always |
| POST | `/api/v1/rotation-report/jobs` | always |
| GET | `/api/v1/rotation-report/records` | always |
| GET | `/api/v1/rotation-report/schedules` | always |
| POST | `/api/v1/rotation-report/schedules` | always |
| DELETE | `/api/v1/rotation-report/schedules/:id` | always |
| PUT | `/api/v1/rotation-report/schedules/:id` | always |
| POST | `/api/v1/rotation-report/schedules/:id/run` | always |
| POST | `/api/v1/schedules/next-runs` | always |
| POST | `/api/v1/seal/authorize` | always |
| POST | `/api/v1/seal/seal` | always |
| GET | `/api/v1/seal/status` | always |
| POST | `/api/v1/seal/unseal` | always |
| GET | `/api/v1/security-policies` | always |
| PUT | `/api/v1/security-policies` | always |
| POST | `/api/v1/security-policies/apply-preview` | always |
| POST | `/api/v1/security-policies/compliance/preview` | always |
| GET | `/api/v1/security-policies/defs/:key` | always |
| GET | `/api/v1/sessions` | always |
| GET | `/api/v1/sessions/:id` | always |
| GET | `/api/v1/sessions/:id/clipboard-events` | always |
| GET | `/api/v1/sessions/:id/clipboard-events/:eventID/content` | always |
| GET | `/api/v1/sessions/:id/commands` | always |
| GET | `/api/v1/sessions/:id/monitor` | always |
| POST | `/api/v1/sessions/:id/monitor-token` | always |
| DELETE | `/api/v1/sessions/:id/recording` | always |
| GET | `/api/v1/sessions/:id/recording` | always |
| GET | `/api/v1/sessions/:id/recording/download` | always |
| GET | `/api/v1/sessions/:id/recording/stream` | always |
| POST | `/api/v1/sessions/:id/recording/token` | always |
| DELETE | `/api/v1/sessions/:id/share` | always |
| POST | `/api/v1/sessions/:id/share` | always |
| POST | `/api/v1/sessions/:id/terminate` | always |
| GET | `/api/v1/sessions/active` | always |
| GET | `/api/v1/sessions/share/:code/ws` | always |
| POST | `/api/v1/sessions/share/token` | always |
| GET | `/api/v1/sessions/statistics` | always |
| GET | `/api/v1/snippets` | always |
| POST | `/api/v1/snippets` | always |
| DELETE | `/api/v1/snippets/:id` | always |
| PUT | `/api/v1/snippets/:id` | always |
| GET | `/api/v1/ssh` | always |
| GET | `/api/v1/ssh/sessions/:id/stats` | always |
| GET | `/api/v1/syslog-settings` | always |
| PUT | `/api/v1/syslog-settings` | always |
| POST | `/api/v1/syslog-settings/test` | always |
| GET | `/api/v1/system-alert-types` | always |
| PUT | `/api/v1/system-alert-types/:key` | always |
| POST | `/api/v1/transmission-consents` | always |
| GET | `/api/v1/transmission-inventory` | always |
| POST | `/api/v1/transmission-inventory/export` | always |
| GET | `/api/v1/user-groups` | always |
| POST | `/api/v1/user-groups` | always |
| DELETE | `/api/v1/user-groups/:id` | always |
| PUT | `/api/v1/user-groups/:id` | always |
| GET | `/api/v1/user-groups/:id/authorization-count` | always |
| GET | `/api/v1/user-groups/:id/external-mappings` | always |
| PUT | `/api/v1/user-groups/:id/members` | always |
| GET | `/api/v1/user-groups/:id/role-bindings` | always |
| PUT | `/api/v1/user-groups/:id/role-bindings` | always |
| GET | `/api/v1/users` | always |
| POST | `/api/v1/users` | always |
| DELETE | `/api/v1/users/:id` | always |
| GET | `/api/v1/users/:id` | always |
| PUT | `/api/v1/users/:id` | always |
| GET | `/api/v1/users/:id/agent-breaker/events` | always |
| POST | `/api/v1/users/:id/agent-breaker/release` | always |
| GET | `/api/v1/users/:id/agent-tokens` | always |
| POST | `/api/v1/users/:id/agent-tokens` | always |
| DELETE | `/api/v1/users/:id/agent-tokens/:tokenId` | always |
| GET | `/api/v1/users/:id/external-identities` | always |
| POST | `/api/v1/users/:id/external-identities` | always |
| DELETE | `/api/v1/users/:id/external-identities/:identityId` | always |
| POST | `/api/v1/users/:id/external-identities/:identityId/unbind-and-disable` | always |
| POST | `/api/v1/users/:id/external-only` | always |
| PUT | `/api/v1/users/:id/inactivity-exempt` | always |
| POST | `/api/v1/users/:id/mfa/disable` | always |
| PUT | `/api/v1/users/:id/password` | always |
| GET | `/api/v1/users/:id/role-bindings` | always |
| PUT | `/api/v1/users/:id/roles` | always |
| POST | `/api/v1/users/:id/roles/:role` | always |
| POST | `/api/v1/users/:id/roles/pin` | always |
| PUT | `/api/v1/users/:id/status` | always |
| POST | `/api/v1/users/:id/unlock` | always |
| GET | `/api/v1/users/local-admin-count` | always |
| POST | `/api/v1/users/source-policy/check` | always |
| GET | `/health` | always |
| POST | `/health` | always |
| GET | `/healthz` | always |
| GET | `/metrics` | always |
<!-- END API-INDEX -->

---

## 認證機制

### JWT Token

- **Header**: `Authorization: Bearer <token>`
- **WebSocket**: 資產連線端點（`/ssh`、`/connect`）僅收一次性 `connect_token`（query-JWT
  直連已收口：繞過簽發閘＝繞過傳輸政策）；監看/分享等
  輔助 WS 端點仍以 `?token=<jwt>` 認證
- **有效期**: 15 分鐘（access token 固定短效；它是撤銷後殘餘存活上限，
  不進政策頁、不隨閒置政策放寬。會話續命走 `POST /auth/refresh` 輪替，不再發 24h 長效 token）
- **Claims**: `user_id`, `username`, `email`, `role`, `scope`（空值＝正式 session token；
  `mfa_pending`＝MFA 過渡 token；`mfa_enrollment`＝MFA 強制註冊過渡 token；`password_change`＝強制改密過渡 token）
- **簽章金鑰與還原世代**：HS256 金鑰由 `JWT_SECRET` 與 `authz_state.restore_generation` 派生（空世代即 `JWT_SECRET` 本身，升級與一般重啟不變）。
  以管理腳本還原備份後世代換新，還原前簽出的 access、MFA 過渡、改密過渡與解封授權 token 一律驗不過，回應與其他無效 token 相同。
  claims 形狀不變，回應沒有新欄。世代讀取失敗時拒絕所有 token，不退回原金鑰

### 短時效 token（取代 URL 中的長效 JWT）

| Token | 簽發端點 | TTL | 特性 |
|-------|---------|-----|------|
| `connect_token` | `POST /api/v1/connect-tokens` | 60 秒 | 一次性（Resolve 即焚），綁定 user+asset+account（`account_id` 選填，0＝預設帳號），簽發時已完成授權與帳號客體綁定檢查 |
| `rtoken`（錄影） | `POST /api/v1/sessions/:id/recording/token` | 120 秒 | TTL 內可重用（HTTP Range 多次 fetch），僅授權讀取指定 session 錄影 |
| `pending_token`（MFA） | `POST /api/v1/auth/login`（第一階段） | 5 分鐘 | scope `mfa_pending`；僅可用於 `POST /auth/mfa/verify` |
| `enrollment_token`（MFA 強制註冊） | `POST /api/v1/auth/login` | 15 分鐘 | scope `mfa_enrollment`；僅可用於 `POST /auth/mfa/enroll/setup`、`/confirm` |
| `change_token`（強制改密） | `POST /api/v1/auth/login`（或 MFA/註冊完成後） | 15 分鐘 | scope `password_change`；僅可用於 `POST /auth/change-password` |

**refresh_token（Web 會話刷新憑證）**：不透明 256-bit 隨機字串（非 JWT），
DB 僅存 SHA-256。**瀏覽器端的唯一載體是 `HttpOnly` cookie `custodexa_refresh`**——
回應 body 一律不含此憑證明文，前端讀不到也就無法寫入 localStorage。cookie 屬性：
`HttpOnly`、`SameSite=Strict`、`Path=/api/v1/auth/`（同時涵蓋刷新與登出）、
效期對齊憑證絕對壽命（輪替時取剩餘壽命，不因輪替延長）、`Secure` 由安全政策
`refresh_cookie_secure` 決定（發放時現讀，管理端調整即生效不需重啟；初值於首次啟動
自部署組態播種，詳見下方「政策鍵值域」）。
刷新時輪替（舊憑證即刻作廢），已輪替憑證再被提交視為洩漏訊號 → 撤銷該使用者全部
refresh（家族撤銷，RFC 9700）。壽命受安全政策控制：sliding 閒置窗（`web_idle_minutes`）
＋絕對壽命（`web_max_session_hours`；持有外部群組映射支持的帳號另受 `mapping_revalidation_hours` 上限）。詳見 `POST /auth/refresh`。

**access token 的瀏覽器端載體＝頁面記憶體**：前端不把 access token 寫入 localStorage、
sessionStorage 或任何跨頁面載入存續的儲存；應用啟動時會無條件清除舊版留下的殘值。
因此每次重新載入或開新分頁時記憶體是空的，前端在呈現受保護頁面之前先以 refresh cookie
呼叫 `POST /auth/refresh` 換發一枚新的 access token 恢復登入態（該次輪替照常留下稽核）；
瀏覽器不曾登入過時不呼叫此端點。任一分頁登出後，同瀏覽器的其他分頁會清除記憶體中的
憑證並回到登入頁。

此舉對純 HTTP 部署有一個直接後果：`refresh_cookie_secure` 為 true 時瀏覽器根本不保存
refresh cookie，重新載入即無從恢復，使用者每次重新載入都要重新登入。對外仍為 http 的
部署應將該政策鍵關閉（或改上 https）；登入頁在偵測到此情形時會呈現成因說明。

### 權限層級（RBAC）

| 角色 | 說明 | 權限 |
|------|------|------|
| `admin` | 管理員 | 全部權限 |
| `user` | 一般用戶 | `asset:view`（連線受資產授權限制；自己的連線紀錄走 `GET /my/connections`。session/audit/alert 檢視收斂為稽核職能，不授予） |
| `auditor` | 稽核人員 | `asset:view`, `session:view`, `audit:view`, `alert:view`, `alert:manage` |

多角色帳號的有效角色（JWT `role`）優先序為 `admin > auditor > user`（與前端路由守衛一致）。

細粒度權限檢查（`RequirePermission`）**無條件掛載**——權限檢查沒有開關，於所有模式生效；
關閉時對應端點僅需登入。各端點所需的權限點以其「權限」說明為準；部分端點在 handler 內另有超級管理者判定，說明中會註明。
**例外**：session 敏感讀取端點——列表 `GET /sessions`、詳情 `GET /sessions/:id`、活動 `/sessions/active`、統計 `/sessions/statistics`、per-session 指令 `GET /sessions/:id/commands`——無條件要求 `session:view`，不受此開關影響（安全敏感讀取無 debug 旁路；`POST /sessions/:id/terminate` 等寫入維持開關行為）。

---

## 統一回應格式

- **列表（分頁）**: `{"data": [...], "total": N, "page": 1, "page_size": 20}`
- **列表（不分頁）**: `{"data": [...], "total": N}`
- **錯誤封套**: `{"error": "使用者可讀繁中訊息", "code": "MACHINE_CODE", "params": {...}}`（內部錯誤細節僅留伺服器日誌，不外洩）
- **操作成功**: 直接回傳資源 JSON 或動作結果欄（如 `{"success": true, "status_code": 200}`）；**不帶 `message` 文案欄**——成功文案由前端 `$t` 自有

### 錯誤封套與 i18n

使用者可見的 HTTP 錯誤**一律**採機器可讀 code + 前端查譯，無例外軌：

- **`error`**（必）：繁中訊息，由該 code 的 `ZhFallback`（以 `params` 插值後）渲染，作為 wire fallback；後端不再有獨立的錯誤文字字面量。
- **`code`**（必）：穩定機器識別字，grammar `^[A-Z][A-Z0-9_]{0,63}$`，分域 `AUTH_*`/`VALIDATION_*`/`NOTFOUND_*`/`CONFLICT_*`/`INTERNAL_*`/`RULE_<DOMAIN>_*`。前端以 code 查 `apiError.*` 三語譯文顯示；一經發布不得改義或重用。**grammar 無例外**：全部錯誤碼皆符合上述分域與大寫格式，不存在小寫或未分域的例外碼。
- **`params`**（可選）：插值受控值（語義 ID 如 `{"resource":"asset"}`、數值，或宣告為 opaque 的自由字串），前端經 enum 查譯後插值；opaque 值原樣傳遞不翻譯且經淨化（限長、去換行/ANSI/控制字元）。參數不合契約時整組丟棄（不外洩），僅記伺服端日誌。
- **前端降級**：`code` 有當前語言譯文 → 顯示譯文；否則顯示 `error`；再否則通用語（三層降級，永不空白/裸 key）。
- **非文字 metadata（Meta 平鋪）**：`kind`、`risks`、`reason`、`policy`、`channel`、`level` 等結構化欄與 `error`/`code`/`params` **平鋪同層**共存——它們是前端控制流分支依據（如 connect 流程依 `reason` 決定彈框）而非文案，故不碼化、不進偵測鍵；保留欄名與值域不變。Meta 不得覆寫 `error`/`code`/`params` 三個保留欄（衝突時丟棄並記 log）。授權拒絕不使用 Meta 欄指出所需的權限點或角色，見下方「授權拒絕與範圍拒絕的回應形狀」。
- 範例：`{"error":"無效的資產 ID","code":"VALIDATION_INVALID_ID","params":{"resource":"asset"}}` → en 顯 "Invalid Asset ID"、ja 顯「無効なアセット ID です」。
- 外部/CLI client 只需自行以 `code` 查譯；繁中 `error` 非多語 API。

**單一出口，無例外軌**：

- 後端 HTTP 錯誤的唯一合法出口為 `apierror.Respond` / `apierror.RespondInternal` / `apierror.Write`
  （帶 `code` 的結構化寫出）。**不存在不帶 `code` 的錯誤回應路徑**，WS 與串流出口亦然。
- 錯誤碼 registry 與三語譯文為雙向完備：每個碼都有三語譯文，每則譯文都對應一個在用的碼。

**HTTP 狀態碼**:
| 狀態碼 | 說明 |
|--------|------|
| 400 | 請求格式/參數錯誤 |
| 401 | 未認證或 token 無效 |
| 403 | 權限不足（能力拒絕為單一形狀，見下節）；規則拒絕保留各自的碼 |
| 404 | 資源不存在（管理範圍外的目標與不存在同形，見下節） |
| 409 | 資源衝突（名稱重複、授權重複） |
| 202 | 已受理（異步批次，如改密觸發） |
| 502 | 上游/遠端失敗（SSH/K8s/DB 連線、webhook 投遞、SFTP 操作） |
| 500 | 伺服器內部錯誤 |

### 授權拒絕與範圍拒絕的回應形狀

授權拒絕分三種，回應形狀不同。

**能力拒絕（403，單一形狀）**：主體沒有任何含所需權限點的有效指派，或不具該操作保留給特定內建身分或資格的條件（例如只限超級管理者的操作、只限具審核資格者的入口）。不論由路由登錄閘、未登錄路由的預設拒絕或服務層判出，回應一律是 HTTP 403，body 恰為兩個鍵：

```json
{"error": "權限不足", "code": "AUTH_PERMISSION_DENIED"}
```

body 沒有 `params`，沒有任何 Meta 欄，`error` 與 `code` 都不透露所需的權限點、角色、內建身分，或主體自身的角色。服務層判出的能力拒絕包含：資產與帳號的欄位級能力、標籤清單與標籤治理、會話強制終止、角色指派與角色定義寫入、主機金鑰重置、權限狀態確認接受、授權帳號範圍調整、連線申請的審核與撤銷資格、監看票、儀表板逐卡能力與待審卡的審核資格、主機身分確認的改密能力。這些拒絕與路由閘的拒絕逐位元相同。

能力拒絕先於目標存在性與範圍判定，此順序適用於路由層、handler 開頭與保留身分的判定：沒有該能力的主體，對存在與不存在的識別碼得到同一個 403，而不是一個 403、一個 404。例外是在載入目標之後才判的服務層能力，例如資產與帳號的欄位級能力（見 `PUT /assets/:id` 一節）與角色指派（使用者的直接指派，以及使用者群組的角色、成員異動與刪除）；這些情形下目標不存在時回 404。資產的 `access_policy` 欄位不屬此例外，它在 handler 開頭即判，依上述順序。所需的權限點，或保留身分與資格條件的種類，只進審計列的 `details`（見 `docs/DB_SCHEMA.md` 的 `audit_logs` 一節），不在回應中。

**規則拒絕（403 或其他 4xx，保留各自的碼）**：主體具備所需能力，但被業務規則、目標狀態或主體類別擋下，例如連線授權的存取政策要求先申請核准（`RULE_ACCESS_APPROVAL_REQUIRED`，帶既有的 `reason`、`policy` 控制流欄位）、目標帳號受保護、自動化主體不得持有某些角色。這類回應保留自己登記的碼與控制流欄位，但 `params`、Meta、`error` 與三語譯文不含操作者所需的權限點、角色或內建身分名稱。五個碼的文案已據此改寫（碼、狀態與判定不變）：`AUTH_PROTECTED_ROLE_ASSIGNMENT`、`AUTH_PROTECTED_ACCOUNT_OPERATION`、`RULE_ACCESS_TICKET_NOT_REVOKE_ELIGIBLE`、`RULE_ACCOUNT_SCOPE_WIDEN_RESTRICTED`、`AUTH_TAG_FILTER_PRIVILEGED_ONLY`。描述目標本身屬性的文字（例如目標帳號受保護、目標使用者不具某角色）與「請聯絡管理員」一類的求助指引不是操作者所需的條件，維持原文。

規則拒絕可與能力拒絕共用 `AUTH_PERMISSION_DENIED`（例如替自動化主體指派其不得持有的角色）。此時審計仍記真實的拒絕原因（既有的 `deny_reason`），不記為缺少某個權限點。

**不再發出的碼**：下列七個專用於能力拒絕、以角色或權限命名的碼不再由任何端點發出，其拒絕一律改為上述單一形狀：`AUTH_ROLE_REQUIRED`、`AUTH_TAG_LIST_PRIVILEGED_ONLY`、`AUTH_TAG_GOVERNANCE_ADMIN_ONLY`、`AUTH_SESSION_TERMINATE_ADMIN_ONLY`、`AUTH_MONITOR_ROLE_REQUIRED`、`AUTH_APPROVER_REQUIRED`、`AUTH_ROLE_ASSIGNMENT_FORBIDDEN`。它們仍保留在錯誤碼目錄與三語譯文，供舊版前端與既有審計資料解讀。依這些碼或依 `required_permission`、`params.role` 分流的外部呼叫端，應改為只依 HTTP 403 與 `AUTH_PERMISSION_DENIED` 判斷。

**範圍拒絕（404，與不存在同形）**：主體具備能力，但目標不在其管理範圍內，或在範圍判定下不存在。回應是 HTTP 404，且與全域範圍主體對同一請求、在未通過範圍判定的那個目標不存在時得到的回應逐位元相同（狀態碼、`code`、`params`、鍵集合與 `error` 文字）。讀取與寫入同此口徑。資源種類的「不存在」回應由同一份對照產生，真不存在與範圍外共用同一個寫出函式：

| 種類 | 未通過的層級 | 回應 |
|---|---|---|
| 資產 | 資產 | 404 `NOTFOUND_ASSET` |
| 資產帳號 | 所屬資產在範圍外或不存在 | 404 `NOTFOUND_ASSET`（等於資產不存在，不是帳號不存在） |
| 資產帳號 | 資產在範圍內，帳號不存在 | 404 `NOTFOUND_ASSET_ACCOUNT` |

服務在寫入交易內判出範圍拒絕時，以同一個錯誤值回傳，由 handler 交給同一出口並整筆回滾。種類對照未登記的資源種類不會因此被放行，回應退為能力拒絕的 403 單一形狀。全域主體對不存在目標的回應不變。

範圍拒絕只發生在主體經節點範圍指派持有該能力時；只持全域指派的主體不會因範圍得到 404。權限目錄中標為範圍生效的權限點，其節點指派才生效，各資源章節寫明對應的範圍規則；未標為範圍生效的權限點，節點指派不生效，也不會被當成全域指派。

**整批無法操作（404 `NOTFOUND_BATCH_ITEMS_UNAVAILABLE`）**：批次請求中任一項無權、在範圍外或不存在時，整批被拒，回應為 HTTP 404，`params` 只有 `count`（無法操作的筆數）：

```json
{"error": "3 筆項目無法操作", "code": "NOTFOUND_BATCH_ITEMS_UNAVAILABLE", "params": {"count": 3}}
```

回應不含任何項目的識別碼、名稱或所屬節點，三種原因不可區分。目前使用這個回應的端點：資產批次搬移、加標籤與刪除（`POST /assets/batch/move`、`/assets/batch/tags`、`/assets/batch/delete`），共用憑證批次改歸（`POST /credentials/ownership`），以及只持節點範圍指派的操作者送出的授權規則批量建立（`POST /authorizations/batch`）。各端點何時回這個回應、全域主體遇到不存在目標時回什麼，以各端點章節為準。

**最小揭露例外**：回應中可提及管理範圍外資訊的情形由封閉登錄列出，恰為四條：共用憑證影響範圍外資產的匿名台數、多歸屬資產「另有 N 個範圍外節點」的匿名計數、全域唯一名稱衝突的同形錯誤、節點因被管理範圍引用而無法刪除的告知（只給引用筆數）。計數類例外只輸出整數，欄名由登錄固定（`out_of_scope_asset_count`、`out_of_scope_node_count`、`count`），值只經登錄的輸出函式產生。登錄以外的範圍外欄位由守衛測試攔下。現行輸出這三類計數的端點：

- `out_of_scope_asset_count`（只對範圍化檢視者出現）：`GET /credentials` 的列與 `GET /credentials/:id`、`DELETE /credentials/:id` 的 409 `RULE_CREDENTIAL_IN_USE`、`POST /credentials/:id/impact-confirmations` 的成功回應；`POST /credentials/:id/secret` 與 `POST /credentials/:id/rotations` 未帶有效確認時的 409 `RULE_CREDENTIAL_IMPACT_CONFIRMATION_REQUIRED` 以 `params.count` 輸出同一類台數。另有五個輪替端點的 `RotationDTO` 回應（`POST /credentials/:id/rotations`、`GET /credentials/:id/rotations/:rid`、`POST /credentials/:id/rotations/:rid/members/:mid/retry`、`POST /credentials/:id/rotations/:rid/abandon`、`POST /credentials/:id/bindings/:accountId/detach`）對範圍化檢視者恆帶此欄，值為本輪被省略成員的去重資產台數，0 也帶；全量檢視者的回應不帶。
- `out_of_scope_node_count`（只對範圍化檢視者出現）：`GET /assets` 的列與 `GET /assets/:id`（另含列級旗標 `actions.disable.count`、`actions.delete.count`）、`POST /assets` 與 `PUT /assets/:id` 的成功回應（與詳情同形；只經節點範圍持有 `access_policy:manage` 的主體送只含 `access_policy` 的更新時，改為覆寫清單的同一列，以該權限點的範圍計數）、`GET /credentials/:id` 的掛載列、`GET /assets/access-policy-overrides` 的列（此端點只對經節點範圍持有 `access_policy:manage` 的檢視者帶這個鍵，以該權限點的範圍計數，見「單台連線政策覆寫清單」）；資產寫入因資產另有範圍外歸屬而被拒的 409 `RULE_ASSET_HAS_OUT_OF_SCOPE_NODES` 以 `params.count` 輸出同一類計數。
- `count`（節點被管理範圍引用）：`DELETE /asset-groups/:id` 的 409 `RULE_NODE_SCOPE_REFERENCED`。

全域唯一名稱衝突（資產名稱 `CONFLICT_ASSET_NAME`、共用憑證名稱 `CONFLICT_CREDENTIAL_NAME`、改密計畫名稱 `CONFLICT_PLAN_NAME_EXISTS`）回 409，body 只有 `error` 與 `code`，不帶 `params`、衝突對象的識別碼、所在節點或其他屬性；衝突對象在操作者範圍內或外時，回應逐位元相同。

---

## 系統端點

### 健康檢查

```
GET /health
POST /health
```

POST 與 GET 同義（供告警通知 E2E 作為無認證、冪等的 webhook 測試收端）。

**回應** (200):
```json
{
  "status": "ok",
  "service": "custodexa-backend",
  "version": "1.0.1",
  "database": "connected",
  "oidc_dedicated_issuers_digest": "e3b0c44298fc"
}
```

`version` 直接輸出 `main.go` 的 `Version` 變數，該變數**由建置時注入**：正式版映像於
`docker/backend/Dockerfile` 以 `-ldflags -X main.Version=...` 帶入，值取自專案根 `VERSION` 檔
（單一事實源，與 `CHANGELOG.md` 的一致性由 `TestVersionFileMatchesChangelog` 釘住）。
未注入的建置（`go run`、`go test`）顯示 `dev`，開發容器顯示 `dev`。上例的值即當前發布版。
依安全政策只揭露版號，不揭露 commit hash 或建置時間。
`oidc_dedicated_issuers_digest` 為 `OIDC_DEDICATED_ISSUERS` 部署宣告的內容指紋
（正規化後 sha256 前 12 hex）：多副本部署時外部監控比對各副本
此值即可偵測設定分歧；輸出指紋而非原文，不洩漏宣告內容。未設宣告時為空集合的固定指紋。

### API Ping

```
GET /api/v1/ping
```

**回應** (200): `{"status": "ok"}`（原 `{"message": "pong"}`，移除 `message` 文案欄）

### 封存狀態、封存與解封

封存期間保留健康檢查與下列控制面路徑；其餘業務路徑回 503 與
`SEAL_SERVICE_SEALED`。ui、env 與委託模式都可在運行期間封存。

```
GET  /api/v1/seal/status
POST /api/v1/seal/authorize
POST /api/v1/seal/seal
POST /api/v1/seal/unseal
```

狀態查詢不要求 JWT。`POST /seal/seal` 要求既有超級管理者（全域 super_admin 範本）的 Bearer JWT，驗證沿用
身分系統的 scope、到期、撤銷、憑證世代與超級管理者身分檢查；不提供另行登入或簽發 token 的路徑。

**解封分兩段，三種模式一律相同**：先以 `POST /seal/authorize` 驗管理員帳號與密碼換一個短效的
**解封授權脈絡**，再以 `POST /seal/unseal` 帶著它送出材料或憑證。改前 `ui` 由「知道材料」單獨
承擔授權、`env` 與委託各要一個超級管理者的 Bearer JWT；自本版起材料證明是**驗證之後的第二道**，
而 Bearer JWT 不再被解封端點接受（封存仍走 Bearer）。

**還原後的首次啟動**：管理腳本還原備份時服務全程停止，API 不可用。還原交易提交後首次啟動（委託與 `ui` 模式為解封之後），後端先記下還原（權限事件鏈已啟用時另寫一筆 `restore` 事件，鏈在升級後第一次封章才啟用、預設封章週期 3600 秒，故啟用前做的備份還原後只會看到之後的 `activate`），再嘗試封出涵蓋新世代的檢查點，之後才開放其餘路由；在那之前與封存期間相同，只有健康檢查與本節控制面路徑。記下還原失敗時不開放業務路徑，還原在資料庫中維持待完成。記下之後，封章失敗或啟動時讀不到待封狀態都不阻擋開放：資料庫保留待封標記，後端發出機制為「還原後封章」的系統告警並寫一筆稽核紀錄，之後每次啟動與下一次排程封章都會補封，第一次成功即清除標記與告警。因此業務路徑已開放不代表涵蓋新世代的檢查點已封出；該告警解除前應視為未結。

`env` 解封仍是重讀行程可見的設定來源（不是在運行中重新讀取主機 `.env` 檔）；
**委託模式自本版起沒有「重讀部署來源」這條路**——憑證只存在於解封世代的記憶體，封存即抹除，
恢復一律經解封頁核對保管處並重新提供憑證。

**`POST /seal/seal`**：不需秘密請求體。成功回 200
`{"state":"sealed","generation":N}`，表示該世代的收束與結果留痕已完成；過程會停止
新業務並收束工作及連線。已有收束或非可封存狀態回 409 `SEAL_CLEANUP_PENDING`；
受理留痕失敗回 503 `SEAL_JOURNAL_IO_FAILURE`；收束或結果留痕失敗回 500
`SEAL_INIT_FAILED`，狀態保留故障，不能當作成功後直接解封。

認證失敗回 401，來源限制回 403 `SEAL_SOURCE_NOT_ALLOWED`。認證拒絕使用匿名稽核標記，
業務稽核服務可用時入列；封存期間仍保留不含憑證的拒絕日誌，該日誌不等同於資料庫稽核列。
超級管理者 JWT 失效時，env 部署可修正來源後重啟；ui 以 KEK 材料解封；委託部署一律經解封頁重新提供憑證。

**`GET /seal/status` 回應** (200)：

| 欄位 | 說明 |
|---|---|
| `state` | `sealed` / `unsealing` / `unsealed` / `sealed-faulted` |
| `generation` | 世代號（受理封存或取得解封持有權時遞增） |
| `mode` | `ui`／`env`／`kms`；決定解封的材料形態及授權方式 |
| `fault_code` | 僅 `sealed-faulted` 時出現，為失敗機器碼 |
| `kek_id` | 僅 `unsealed` 時出現，為行程實際持有的現行 KEK 識別：本地模式（`ui`／`env`）是材料的單向指紋，委託模式是金鑰 ID。值取自執行中的金鑰提供者，與金鑰清冊（`GET /keys`）的 `kek_id` 同源，不重讀設定或資料庫。`sealed`／`unsealing`／`sealed-faulted` 時不出現。只是識別、不含任何金鑰材料或憑證；部署工具在還原後據此核對實際解封所用的主金鑰，不必經手管理者帳密 |
| `cooldown_until` | 全域冷卻到期時間（RFC3339）；冷卻期滿自動恢復，**不需重啟行程** |
| `cleanup_pending` / `cleanup_generation` / `cleanup_reason` / `cleanup_started_at` | 前代持有者待收束狀態 |
| `journal_faulted` | 封存期留痕 I/O 故障（fail-close 拒收新嘗試，修復後自動恢復） |
| `timeout_total` | 段 2 逾時次數（逾時另計，不入材料失敗計數） |
| `timeout_retry_hint_code` | 發生過逾時時出現，值為 `SEAL_STAGE2_TIMEOUT`：**初始化可能已完成，請以第一次輸入的材料重試，切勿改用新材料** |
| `initialization_required` | 金鑰表為空（走初始化解封路徑）；判定失敗時回 500 而非以 `false` 頂替 |
| `trusted_proxy` / `source_restricted` / `bind_addr` | 可信代理、來源網段限制與獨立監聽位址的組態現況 |
| `authorization_required` | 恆 `true`：三模式一律先經管理者帳密驗證才顯示材料或憑證欄位。這是契約而非旋鈕 |
| `credential_form` | 僅委託模式出現，值為 `aws`／`gcp`／`vault`，決定憑證欄的形態（解封頁**不提供服務商選擇**） |
| `topology` | 僅委託模式出現的唯讀拓撲：`{provider, configured, address, transit_key_name, role_id, region, key_ref, digest}`。`key_ref` 取自金鑰列的 `kek_id`（尚無金鑰列時為空）；`digest` 為核對綁定摘要，解封請求須原樣帶回。拓撲尚未設定且金鑰表為空時 `digest` 為空字串。讀不到權威狀態時整個欄位省略，介面據此阻擋而非顯示一份可能錯誤的目的地 |
| `instance_guard` | 單實例守衛的粗狀態 `{state, since, reason, peers}`：`state` 為 `held`／`overridden`／`lost`／`halted`（關閉中短暫為 `stopping`／`released`）、`since` 狀態起始時間（RFC3339）、`reason` 為 `""`／`ack_page`／`ack_startup`／`contention`／`db_unreachable`／`permanent`／`unknown`、`peers` 偵測到的其他守衛版實例連線數。攔下模式下本端點的 `state` 恆為 `sealed`，**相位判定看 `instance_guard.state = halted`**。**不含識別資訊**（無持鎖者指紋、確認碼、主機名、pid）；供管理介面橫幅每 60 秒輪詢，本端點不寫稽核列。全貌走 `GET /api/v1/instance-guard`（下段） |

**`POST /seal/authorize` 請求體**（精確鍵集，未知鍵／重複鍵／尾隨內容一律拒絕）：

```json
{"username": "<管理員帳號>", "password": "<密碼>"}
```

成功回 200 `{"grant":"<不透明字串>","expires_at":"<RFC3339>","topology_digest":"<僅委託模式>"}`，
回應為 `Cache-Control: no-store`。脈絡是**行程記憶體內的短效憑據**（預設十分鐘，非 JWT、不進資料庫、
不跨行程），且**每次使用時重新確認**該管理員仍具資格——停用、降權、鎖定或憑證世代被推進即失效。
它 SHALL NOT 作為任何業務請求的憑證，解封成功也不會把它升級為工作階段。

**已封存狀態下只驗帳號與密碼，不索取動態驗證碼**：種子是受資料金鑰保護的欄位，封存時解不開，
要求它會構成「先解封才能驗證、先驗證才能解封」的循環。此邊界為已知取捨，**不得**被表述為
解封頁具備雙因子保護；其緩解是沿既有登入退避與鎖定、來源網段限制、回應不可區分與逐次留痕。

失敗一律回 401 `SEAL_AUTHORIZE_REJECTED`，且**帳號不存在、密碼錯、非管理角色、帳號停用、
鎖定中與請求體格式錯的回應逐字相同**（可區分即帳號枚舉）。退避與冷卻分別回 429
`SEAL_BACKOFF_ACTIVE` 與 `SEAL_COOLDOWN_ACTIVE`；被擋下的嘗試不驗證、不計入失敗計數、
不刷新到期時間。

**已解封時一律回 409 `SEAL_ALREADY_UNSEALED`**（與同一狀態下的 `POST /seal/unseal` 同碼）：
授權脈絡只服務解封，已解封時沒有後續步驟用得到它。此判定在讀取請求體之前，不驗帳密、
不計入退避，故帳密對錯、帳號是否存在都得到逐字相同的回應；揭露的只有 `GET /seal/status`
本就公開的狀態。來源網段不符仍先回 403 `SEAL_SOURCE_NOT_ALLOWED`。已解封時取不到脈絡，故照兩步流程
送出的 `POST /seal/unseal` 會回 401 `SEAL_GRANT_REQUIRED`；下表的 409 `SEAL_ALREADY_UNSEALED` 只在
持有效脈絡者送出時出現。客戶端判斷「是否已解封」以第一步的 409 或 `GET /seal/status` 為準。

帳密驗證**尊重帳號已寫入的鎖定期限**：鎖定未到期即回 401 `SEAL_AUTHORIZE_REJECTED`（與密碼錯不可區分），
但本端點的失敗**不寫入**帳號的失敗次數與鎖定期限。初始化解封與委託模式全新安裝請求本文內的
初始管理員帳密、以及守衛攔下頁的確認帳密，適用同一條鎖定判定。

（以下為 ui 模式；**所有模式**都要求標頭 `Authorization: SealGrant <grant>`，缺或無效回 401
`SEAL_GRANT_REQUIRED`／`SEAL_GRANT_INVALID`）：

```json
{
  "kek": "<32 字元 KEK 材料>",
  "kek_confirm": "<僅初始化解封：paste-back 二次輸入>",
  "confirm_saved": true,
  "username": "<僅初始化解封：初始管理員帳號>",
  "password": "<僅初始化解封：初始管理員密碼>"
}
```

- **一般解封**（金鑰表非空）只需 `kek`，**不驗格式**（既有部署的 KEK 可能早於格式規則），
  唯一判準是「以該材料解包現行代表列全數成功」。
- **委託解封**按服務商的**精確鍵集**：AWS 為 `access_key_id`＋`secret_access_key`，
  GCP 為 `service_account_json`，Vault 為 `vault_secret_id` **或** `vault_token`（二選一），
  四者皆另帶 `topology_digest`。摘要與後端現行拓撲不符即 409 `SEAL_TOPOLOGY_CHANGED`
  並要求重新核對——**舊核對結果不授權送往新目的地**。全新安裝的委託分支改帶初始管理員帳密
  與該服務商的拓撲欄位（AWS：`region`＋`key_ref`；GCP：`key_ref`；Vault：`address`＋
  `transit_key_name`＋`role_id`），**不帶** `topology_digest`。
  秘密欄一律解進可覆寫的位元組並交給該解封世代的憑證持有者，封存時歸零；
  `service_account_json` 另有 16 KiB 的欄位級上限，請求本文上限為 24 KiB。
- **初始化解封**（金鑰表為空）另要求 paste-back 二次輸入、保存確認、初始管理員憑證，
  並過完整格式驗證（長度 32、字元集、非出廠預設值）。`confirm_saved` 為 UX 意圖聲明、
  **不具授權力**；伺服端唯一信任的機械不變式是 `kek_confirm` 的逐字比對。
  憑證驗證走段 1 簡化路徑，**不套用安全政策的帳號鎖定**（該服務於段 2 才建構），
  其防爆破由下列退避／冷卻承擔；且**不豁免 `must_change_password`**。

**回應**：成功 200 `{"state":"unsealed","generation":N}`，並撤銷全部授權脈絡。
失敗一律走機器碼信封，且**帳密未過之前的失敗內容不可區分**（格式錯、材料錯、paste-back 不符、
憑證錯皆為 `SEAL_MATERIAL_INVALID`）；timing 差異不在承諾範圍內。

**管理者身分驗證通過之後**的憑證階段失敗**可區分**三類：`SEAL_CUSTODY_UNREACHABLE`（502，
保管處連不上）、`SEAL_CREDENTIAL_REJECTED`（400，憑證被保管處拒絕）、`SEAL_KEY_MISMATCH`
（400，保管處回應的金鑰與本部署不符）。三者皆為系統自定的分類，**不轉呈**保管處的原始回應，
不含秘密、請求本文或可供外部試探的認證細節。匿名探測拿不到它們——那些成因在建構上只可能產生於
身分驗證通過之後。逾時仍為 `SEAL_STAGE2_TIMEOUT`（504），不新增細分。

| 機器碼 | 狀態碼 | 情境 |
|---|---|---|
| `SEAL_MATERIAL_INVALID` | 400 | 材料類失敗（唯一出口，計入退避） |
| `SEAL_ABORTED` | 400 | 驗證前即中止，未取得任何判定（不計入退避） |
| `SEAL_UNSEAL_IN_PROGRESS` | 409 | 已有解封在飛（single-flight） |
| `SEAL_CLEANUP_PENDING` | 409 | 前代持有者待收束 |
| `SEAL_ALREADY_UNSEALED` | 409 | 已解封，且不重跑初始化 |
| `SEAL_SOURCE_NOT_ALLOWED` | 403 | 來源不在 `SEAL_UNSEAL_ALLOWED_CIDRS` 內 |
| `SEAL_BACKOFF_ACTIVE` / `SEAL_COOLDOWN_ACTIVE` | 429 | per-來源退避／全域冷卻期內 |
| `SEAL_INIT_FAILED` | 500 | 材料正確但段 2 初始化失敗（狀態轉 `sealed-faulted`，**行程續存、可重試**） |
| `SEAL_PUBLISH_UNCONFIRMED` | 500 | 段 2 完成但服務從未發佈（不鎖死，重試產生新世代） |
| `SEAL_STAGE2_TIMEOUT` | 504 | 段 2 逾時（不計入材料失敗計數） |
| `SEAL_JOURNAL_IO_FAILURE` | 503 | 封存期留痕寫入故障，fail-close 拒收新嘗試 |

**退避**：退避成長有封頂、冷卻有明確到期時間，
冷卻期間抵達的嘗試被直接拒絕且**不計入失敗、不延長冷卻**。未設定 `TRUSTED_PROXIES`
時 per-IP 退避**保守降級為全域退避**——無可信代理鏈約定時限速鍵可被轉送標頭污染，
寧可影響可用性也不提供可繞過的假防線。部署方 SHOULD 另以 `SEAL_UNSEAL_BIND_ADDR`
／`SEAL_UNSEAL_ALLOWED_CIDRS` 把解封端點收進管理網段：未認證端點上，任何速率手段
都無法保證管理員可用性。

**遺失語義**：B 模式的 KEK 遺失＝全部信封密文永久不可解，**產品不提供任何 recovery**。

### 單實例守衛快照（管理者限定）

```
GET /api/v1/instance-guard
```

**認證**: JWT ＋ `instanceguard:view` 權限；未登入 401、缺少該權限 403。

單實例守衛在段 1 以 postgres session 級 advisory lock 保證「第二個應用實例不會在操作者不知情下運作」：
第二實例啟動即被攔下並印出持鎖者指紋與確認碼，行程停在攔下模式並提供攔下頁（下段）；
於頁面完成三要件確認、或以 `INSTANCE_GUARD_ACK` 確認後可啟動，但留稽核事件；
執行期失鎖只告知不退出。守衛防的是不知情，不是不發生——確認後的並存不由守衛阻擋。營運面判讀見
`docs/ops/upgrade-sop.md` §2.6b／§3.4。

本端點回守衛的**完整快照**，含持鎖者指紋與本實例識別。管理介面只在橫幅出現時取一次
（與管理者手動重新整理），**不輪詢**；粗狀態的輪詢走 `GET /api/v1/seal/status` 的 `instance_guard` 欄
（不含識別資訊、不寫稽核列）。**本端點每次呼叫經稽核中介層留一筆讀取列**（資源 `instance_guard`）：
「哪個管理者何時看了衝突細節」本身是留痕。唯讀、無副作用。

**回應** (200):
```json
{
  "state": "overridden",
  "since": "2026-08-25T10:05:58Z",
  "reason": "ack_startup",
  "instance": {"hostname": "bb34e4ff1892", "pid": 1, "started_at": "2026-08-25T10:05:50Z"},
  "db_session_pid": 8744,
  "holder": {
    "application_name": "custodexa-instance-guard",
    "pid": 8510,
    "backend_start": "2026-08-25T10:04:22.2442Z",
    "code": "55bd875b8d97",
    "fingerprint_source": "pg_stat_activity"
  },
  "ack": "55bd875b8d97",
  "actor": "operator via env",
  "actor_source": "env",
  "lost_total": 0,
  "peers": 0
}
```

| 欄位 | 說明 |
|---|---|
| `state` | `held`（持鎖）／`overridden`（以確認啟動、尚未取得鎖）／`lost`（執行期失鎖，每週期重取中）；關閉中短暫為 `stopping`／`released`。攔下模式的 `halted` 不會出現在本端點——本端點要求 JWT，攔下模式未註冊它（見下段） |
| `since` | 目前狀態的起始時間（RFC3339） |
| `reason` | 進入目前狀態的原因：`""`（held）／`ack_page`（攔下頁確認）／`ack_startup`（環境變數確認）／`contention`／`db_unreachable`／`permanent`／`unknown` |
| `instance` | 本實例識別：`hostname`（容器主機名）、`pid`（應用行程 id）、`started_at`（守衛**開始**取鎖的時刻；實際持鎖時刻是 `since`，兩者可差數秒） |
| `db_session_pid` | 本實例釘選連線在 postgres 內的 `pg_backend_pid()` |
| `holder` | 持鎖者指紋（`overridden` 與 `lost{contention}` 時有值，否則 `null`）：`application_name`／`pid`（postgres 工作階段 id）／`backend_start`；`code` 為三欄正規化字串 sha256 前 12 碼＝確認碼；`fingerprint_source` 為 `pg_stat_activity`，查不到持鎖者細節時為 `unavailable`（此時 `code` 為降級碼，不綁定特定工作階段） |
| `actor`／`actor_source` | 確認啟動的確認者與來源：攔下頁路徑為通過驗證的管理員帳號＋`page`，環境變數路徑為 `operator via env`＋`env`；未經確認啟動（`held`）時皆為空字串。管理介面橫幅的次行由這兩欄組成 |
| `ack` | 本行程環境中的 `INSTANCE_GUARD_ACK` 值（去除前後空白），未設時為空字串。只有 `state=overridden` 代表它被用上；`state=held` 時它是留在環境裡的惰性值（啟動日誌會提示移除） |
| `lost_total` | 本行程累計失鎖次數 |
| `peers` | 偵測到的其他守衛版實例連線數（同一資料庫、同 `application_name`，每個驗證週期更新） |

回應**不含**連線字串、密碼、主機位址、資料庫名、任何工作階段的 `client_addr`。守衛狀態是**行程本地的**：
多個實例並存時，每個實例回的是自己的快照。

### 守衛攔下頁端點（不需 JWT）

```
GET  /api/v1/instance-guard/halt
POST /api/v1/instance-guard/ack
```

取鎖失敗且無相符確認時，本實例不退出行程，改停在**攔下模式**：保留釘選連線、每個 watchdog 週期重取，
並只開放 `/health`、`/healthz`、`/api/v1/seal/status`（`state` 恆 `sealed`、`instance_guard.state` 為
`halted`）與下列兩條端點；其餘路由一律 503（含未匹配的路徑，不對外透露路由是否存在）。

**可達條件**：兩條端點在完整路由樹上**恆註冊**，攔下模式與正常服務期皆可呼叫——只在攔下模式註冊
會讓監控分不出 503 與 404。非攔下狀態下 `GET` 回 `state=running`、`POST` 回 409＋
`INSTANCE_GUARD_NOT_HALTED`，兩者都在觸碰任何憑證之前返回。**皆不要求 JWT**：攔下期段 2 未建構、
服務未上線，JWT 不可能存在，把救援路徑擋在登入後等於讓它永遠用不到；授權改由確認送出的三要件承擔。
來源限制與解封端點**共用同一份組態**（`SEAL_UNSEAL_ALLOWED_CIDRS`，未設即不限制），
不在清單內回 403＋`SEAL_SOURCE_NOT_ALLOWED`。兩條端點在主服務埠上，不套用 `SEAL_UNSEAL_BIND_ADDR`。

**零寫入邊界**：攔下期間**不執行 migration、不產生任何資料庫寫入**。此模式的三個資料庫接觸點
（持鎖者指紋查詢、advisory lock 重取、管理員憑證讀取）全部唯讀；憑證讀取只依賴使用者表的既有欄位
（schema 版本未知），讀取失敗回 503 並指向環境變數路徑，**不猜測、不以憑證錯誤頂替未知狀態**。

**`GET /instance-guard/halt` 回應** (200)：唯讀、無副作用、不寫稽核列。

| 欄位 | 說明 |
|---|---|
| `state` | `halted`（停在攔下模式）／`running`（已取得鎖或已以確認啟動） |
| `since` | 進入攔下的時刻（RFC3339）；`running` 時為空字串 |
| `holder` | 持鎖者指紋，與 `GET /api/v1/instance-guard` 的 `holder` **同型**（`application_name`／`pid`／`backend_start`／`code`／`fingerprint_source`）；`running` 時為 `null` |
| `retry_interval_seconds` | watchdog 的重取週期（預設 15）：攔下頁據此輪詢，並據此告知「鎖被釋放後多久自動接手」 |

**`POST /instance-guard/ack` 請求體**：

```json
{
  "confirmed_primary_down": true,
  "code": "<重打頁面顯示的確認碼>",
  "username": "<管理員帳號>",
  "password": "<管理員密碼>"
}
```

三要件（承擔勾選、確認碼、管理員帳密）**缺一即 400**，且在觸碰資料庫之前返回；請求體不可解析同碼。
判定順序為「來源 → 攔下狀態 → 三要件齊備 → 退避 → 委派驗證」，由便宜到昂貴；委派內**先驗憑證再比對
確認碼**——碼先驗等於對未認證的呼叫者提供一台確認碼的線上校驗機。`code` 與**送出當下重查的持鎖者**
比對，不與頁面先前顯示的指紋比對：持鎖者在填表期間換人時舊碼必須失效。

成功 200 回 `{"state":"running","retry_interval_seconds":N}`，本實例即以確認啟動路徑繼續段 1 其餘步驟
與段 2（同一行程，**不需重啟**）；此期間服務埠短暫無回應，之後於同一埠重新開放。稽核事件 `overridden`
的 `actor` 為通過驗證的管理員帳號、`actor_source` 為 `page`、`reason` 為 `ack_page`，並帶確認前的憑證
失敗次數；環境變數路徑維持 `actor="operator via env"`、`actor_source=env`、`reason=ack_startup`。

| 機器碼 | 狀態碼 | 情境 |
|---|---|---|
| `INSTANCE_GUARD_ACK_INCOMPLETE` | 400 | 三要件缺一或請求體不可解析（不逐項回報缺哪一項） |
| `INSTANCE_GUARD_ACK_UNAUTHORIZED` | 401 | 管理員憑證驗證失敗（**不區分**帳號不存在／密碼錯／非管理員／已停用／鎖定中，避免帳號列舉；鎖定只讀判斷，攔下期不寫入帳號欄位） |
| `INSTANCE_GUARD_HOLDER_CHANGED` | 409 | 重打的碼不等於**當下**持鎖者的碼；回應體另平鋪 `state`／`holder`／`retry_interval_seconds`，操作者才有新碼可重打 |
| `INSTANCE_GUARD_NOT_HALTED` | 409 | 本實例不在攔下模式（鎖已取得或服務已上線） |
| `INSTANCE_GUARD_ACK_LOCKED` | 429 | 憑證失敗達上限，冷卻期內暫不受理 |
| `INSTANCE_GUARD_ACK_UNAVAILABLE` | 503 | 讀取使用者表失敗（schema 不相容或連線異常）；改走 `INSTANCE_GUARD_ACK` 環境變數路徑 |
| `SEAL_SOURCE_NOT_ALLOWED` | 403 | 來源不在允許網段內（兩條端點共用） |

**退避**：憑證失敗累計 5 次即暫拒 5 分鐘；到期即受理且計數歸零，鎖定期內的請求在計數之前就被擋下，
故**時窗不會被後續嘗試延長**；成功確認清空計數。這是**行程內**計數，隨行程結束歸零，且
**不寫入 `users` 的失敗次數與鎖定欄位**（零寫入邊界優先於既有帳號鎖定閘）——它擋的是自動化爆破，
不是有主機存取權的人，界線在此明說以免被誤讀為已享有帳號鎖定保護。未約定可信代理（`TRUSTED_PROXIES`）
時分組鍵**保守降級為全域**，與解封端點同一語義：轉送標頭不可信時 per-source 分組可被偽造繞過。

營運面的操作程序見 `docs/ops/standby-takeover.md` §4.2／§4.3 與 `docs/ops/upgrade-sop.md` §2.6b。

---

## 認證 API

### 登入

```
POST /api/v1/auth/login
```

**請求**:
```json
{"username": "admin", "password": "admin123"}
```

登入為固定順序的 gate chain（登入狀態機）：
**來源限流 → 鎖定檢查 → 密碼/LDAP 驗證 → 帳號啟用檢查 → 允許來源網段判定 →
MFA 分流（驗證或強制註冊）→ 強制改密 → 發正式 token**。
（網段判定在 MFA 分岔**之前**：該分岔會發出正式會話或受限票證（enrollment／password_change），
清單外的來源連受限票證也不該拿到。）
回應依所處階段為多形態（互斥，僅其一）：

**來源限流**：本端點有 per-IP 速率上限，超出回
`429` ＋ `AUTH_LOGIN_RATE_LIMITED`。**回應不含剩餘額度、重試秒數或 `Retry-After`**
——那些數值會讓攻擊者把流量精確調到門檻之下持續消耗。限流與既有的帳號級鎖定
是兩層不同的防護：帳號鎖定擋對單一帳號的暴力破解，來源限流擋換帳號輪流試的
密碼噴灑（每個帳號各試少數次，永遠碰不到帳號門檻）。被擋下的請求以聚合形式入
稽核（每個「來源×時間窗」一筆帶計數），不逐筆寫入。

**帳號啟用檢查在密碼驗證之後**：帳號不存在、密碼錯誤、帳號存在但已停用且密碼
錯誤——三者回應**完全相同**（`401` ＋ `AUTH_INVALID_CREDENTIALS`），使未認證者
無法藉回應差異枚舉帳號是否存在。憑證正確而帳號已停用者才回 `403` ＋
`AUTH_USER_INACTIVE`（此時請求者已證明持有該帳號憑證，告知不構成洩漏）。

**帳號字串含控制字元（含 NUL、換行、定位字元與 C1 控制字元）或非法 UTF-8 時**，在查詢帳號
之前即回與「帳號不存在」相同的 `401` 回應；判定只看輸入本身，不涉及任何帳號狀態。
這筆失敗照常入登入稽核，稽核列的帳號欄以 U+FFFD 取代無法存放的字元。

**允許來源網段判定也在憑證驗證之後**，且位於「發正式會話／發受限票證」的分岔之前，
故一次涵蓋正式會話、強制註冊票證與強制改密票證三條出口。不落使用者
`allowed_cidrs` 者回 `403` ＋ `AUTH_SOURCE_NOT_ALLOWED`。三點須注意：
- **MFA 第一階段（`mfa_required`）不判**：提前判會讓「密碼對但來源錯」在 pending 訊號
  之外多一個分岔，持有密碼但無第二因素者因此得以探知來源政策。判定移到多因素完成那一點。
- **回應不含來源位址值，也不含清單內容**——只說「此來源不允許」。位址與命中的清單快照
  只進稽核（登入稽核列的 `error_msg`／`details`）。
- 此類拒絕**不計入**失敗登入次數（憑證是對的），但仍受來源限流覆蓋；稽核 status 為 `denied`。

**回應** (200，全數通過，發正式會話):
```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": 1,
    "username": "admin",
    "email": "admin@example.com",
    "full_name": "Administrator",
    "active": true,
    "roles": ["admin"],
    "totp_enabled": false
  }
}
```

（Web 會話刷新憑證隨此回應以 `Set-Cookie: custodexa_refresh=...` 下發，不在 body 內。）

本端點的四種 200 回應**都是頂層物件，沒有 `data` 外層**：`{"data":…}` 只用於列表端點
（見「統一回應格式」）。程式取值請用 `token`／`user`／`mfa_required`／`pending_token`／
`mfa_enrollment_required`／`enrollment_token`／`password_change_required`／`change_token`，
取 `data.token` 會得到空值。四種形態互斥，以旗標欄位存在與否分流。

**回應** (200，MFA 用戶第一階段，需輸入 TOTP):
```json
{"mfa_required": true, "pending_token": "..."}
```

**回應** (200，受 MFA 強制但尚未註冊 TOTP，導向強制註冊):
```json
{"mfa_enrollment_required": true, "enrollment_token": "..."}
```

**回應** (200，認證全過但須先改密，PCI 8.3.5/2.2.2):
```json
{"password_change_required": true, "change_token": "...", "policy_hint": "密碼至少 12 字元，且須同時包含字母與數字",
 "password_change_reason": "policy_noncompliant", "reason_code": "RULE_USER_PASSWORD_TOO_SHORT", "reason_params": {"min": 12}}
```
（`policy_hint` 為改密表單提示文案，依現行密碼政策動態產生；政策頁 API 需 `securitypolicy:manage`，
未登入的改密表單靠此欄取得規則。`password_change_reason` 為觸發原因：
`must_change`＝首登/管理員重設、`policy_noncompliant`＝登入時偵測現行密碼不符政策（附
`reason_code`/`reason_params` 供 i18n 插值，值域同 apierror 碼）、`password_expired`＝密碼逾
`password_max_age_days` 政策（NULL 改密時間戳視為已過期）。合規偵測同時落稽核動作
`pw_noncompliant`（僅違規類別，無密碼材料）。MFA 用戶的偵測發生在第一階段，第二階段以
`must_change` 呈現）

**錯誤**: 401 認證失敗、403 帳號已停用（`AUTH_USER_INACTIVE`）或來源不在允許網段
（`AUTH_SOURCE_NOT_ALLOWED`）、423 帳號已鎖定（連續失敗達門檻，PCI 8.3.4；
訊息明示鎖定但不透露剩餘時間/次數）、500 內部錯誤（訊息泛化為「登入失敗」）。

登入失敗與成功均直接寫入稽核日誌（登入前無用戶 context，全局中間件會跳過）；MFA/註冊/改密等
中繼階段亦以對應標註（`mfa_pending`/`mfa_enrollment_required`/`password_change_required`）留痕。
密碼失敗與 TOTP 失敗共用同一鎖定計數。

**LDAP 認證**（`LDAP_ENABLED=true` 時）:
- 同一登入端點與請求格式，無需前端改動
- 分流規則：本地（非 `is_ldap`）用戶走本地密碼驗證；`is_ldap` 用戶或本地查無的帳號走
  LDAP search-then-bind 驗證
- 首次 LDAP 登入成功自動建立影子用戶（`is_ldap=true`、預設 `user` 角色、無可用本地密碼）
- LDAP 用戶若啟用 MFA，照常走兩階段登入
- LDAP 用戶不可使用 `PUT /users/:id/password` 改密（回 400，密碼由目錄服務管理）
- 登入稽核於 `error_msg` 欄位標註 `source=ldap`；本地登入維持既有輸出
- 環境變數：`LDAP_ENABLED` / `LDAP_URL` / `LDAP_BIND_DN` / `LDAP_BIND_PASSWORD` /
  `LDAP_BASE_DN` / `LDAP_USER_FILTER`（預設 `(uid=%s)`）/ `LDAP_ATTR_EMAIL`（預設 `mail`）/
  `LDAP_ATTR_FULLNAME`（預設 `cn`）/ `LDAP_SKIP_TLS_VERIFY`（僅測試環境）

### 登出

```
POST /api/v1/auth/logout
Authorization: Bearer <token>
```

**請求**：無 body 欄位。Web 會話刷新憑證由瀏覽器以 `custodexa_refresh` cookie 自動附帶
（cookie 的 `Path` 涵蓋本端點）。

**回應** (200): `{"username": "admin"}`（`message` 文案欄已移除）。
回應一律帶清除性 `Set-Cookie`（即時到期），無論撤銷成敗。

access token 無狀態，登出由客戶端刪除、殘餘存活 ≤15 分；cookie 帶有憑證時後端一併撤銷
（reason=`logout`）。若提交的是已輪替憑證＝分叉/洩漏訊號，觸發家族撤銷並記高價值稽核事件。
cookie 缺失不阻擋登出。登出事件由稽核中間件記錄。

### 當前用戶

```
GET /api/v1/auth/me
Authorization: Bearer <token>
```

**回應** (200): `UserInfo`（同登入回應的 `user` 欄位，含 `totp_enabled`、`is_ldap`）。
含後端 resolve 的 `display_name`（`local_display_name || full_name || username`，單一事實源）
與自助顯示名原始值 `local_display_name`（可為 `null`＝未自訂）。

另含 `source_ip`（**可選欄，`omitempty`**）：**本人這次請求的來源位址**，
**僅供顯示**（允許來源網段表單的「你目前的來源」），**不參與任何判定**——
「這個清單會不會把我鎖在外面」一律問判定端點（見「用戶 API」的允許來源網段段），
前端自行以 CIDR 函式庫比對必與強制點分歧。取不到時整欄不出現；
登入回應共用同一個型別但不填此欄，故既有登入回應的欄位集逐字不變。

另含身分三分的兩欄：`external_credential`（憑證由外部提供者管理，
前端的自助改密與密碼到期提示一律依此欄泛化——**不可續用 `is_ldap`**，OIDC 影子帳號的
`is_ldap` 為 `false`）與 `provisioning_origin`（`local`／`ldap`／`oidc`，建立後不可變）。
兩者分離是刻意的：混合帳號（OIDC 供應但保有本地密碼）兩者不同值。

另含「我的 agent」入口資格兩欄（登入回應的 `user` 同樣帶）：`owns_agents`（名下至少有一個
agent 主體，已刪除者不計）與 `can_self_create_agent`（安全政策 `agent_self_create_enabled`
目前為開）。前端以「兩者任一為真」決定「我的 agent」的選單與路由是否開放，**不看角色**；
值與 `GET /my/agents` 回應的自建狀態同源。兩欄只供顯示，查詢失敗時皆為 `false`，
`/my/agents` 與鑰匙端點各自的守衛才是強制點。與 `is_approver` 相同，它們在登入時與每次
`GET /auth/me` 時現算，建立或轉移 agent 後重新整理頁面即反映。

另含 `product_version`（**可選欄，`omitempty`**；登入回應的 `user` 與 `PATCH /auth/me` 的回應同樣帶）：
產品版本號，與 `/health` 的 `version` 是同一個建置時注入的值，介面側欄底部據此顯示版本。
值原樣轉出：開發建置為 `dev`，是否顯示由前端判定（只顯示發布版號形狀的值）。
此欄只出現在登入後才讀得到的回應裡。

另含能力投影兩欄（**僅 `GET /auth/me` 與 `PATCH /auth/me` 的成功回應**；登入、MFA、續期、改密的 `user` 與
所有錯誤回應不帶這兩欄）：

```json
{"permissions": ["asset:view", "credential:view", "ui:my-agents", "ui:self-service-actions"],
 "scope_summary": [
   {"permission": "asset:view", "binding_scope": "global"},
   {"permission": "credential:view", "binding_scope": "nodes",
    "nodes": [{"id": 12, "path": ["台北機房", "核心資料庫"]}]}]}
```
（示例的權限點與節點名稱不是常數。）

- `permissions`：伺服器**逐請求**解析的有效權限點，加上不可指派的 `ui:` 呈現點；排序、去重的字串陣列，
  空集合為 `[]`。不來自 token 內的角色宣告，下一次請求即採用最新的解析結果（不快取）。
- `ui:` 開頭的點是伺服器產生的**呈現點**，不是可指派的權限、不寫入角色指派、不出現在 `scope_summary`，
  也不是任何 API 的授權依據：`ui:approvals`（既有 `is_approver`）、`ui:my-agents`（`owns_agents` 或
  `can_self_create_agent`）、`ui:assets-global`（全域資產檢視的呈現）、`ui:self-service-actions`
  （申請／待申請操作的呈現）、`ui:connect-bypass`（保留的內建超級管理者身分，僅用於前端連線豁免呈現）、
  `ui:super-admin`（同一保留身分，供只限超級管理者的畫面元素使用，與連線豁免分開）。
  持有全部可指派權限不等於持有 `ui:connect-bypass`、`ui:super-admin` 或 `ui:approvals`。
- `scope_summary`：每個有效、可指派的權限點一筆 `{permission, binding_scope}`，按 `permission` 排序；`ui:` 點不列入。
  `binding_scope` 為 `"global"` 或 `"nodes"`：只要有一筆全系統生效的指派含此權限點並使其生效，就是 `"global"`
  （直接指派與經使用者群組的指派都算；沒有指派的主體與 agent 的固定範本視為全系統），此時只回這一筆、不帶 `nodes`，
  即使同一點另經節點範圍指派取得也一樣。只經節點範圍指派生效的點為 `"nodes"`，附
  `nodes: [{id, path}]`：`id` 是節點識別，`path` 是由根節點到該節點的**名稱陣列**（每層一個元素，不串接成字串）；
  節點是主體所有含此點的節點範圍指派（直接與群組）中仍存在的節點的聯集，去重、依路徑逐層字典序排序（同路徑依 `id`）。
  已刪除的節點不列、不給名稱；節點全部刪除或範圍為空的指派不使該點出現在 `scope_summary`。範圍節點的子節點與範圍外節點不出現。
  `GET` 與 `PATCH /auth/me` 的回應相同。需要節點路徑而讀取失敗時回 `500 INTERNAL_USER_INFO_QUERY`（`PATCH` 在寫入之前解析，
  失敗時顯示名不會被改動），不以 `global` 兜底。本欄描述**指派範圍**，只供呈現：不代表可見全部資產、可連線，
  也不是任何逐筆操作的授權依據。內建一般使用者與審核者只在全系統指派時生效，限定節點後不產生權限，系統照常儲存並提示。
  `ui:` 點不列入。同一權限點有任何全系統來源時只列 `global`、不附 `nodes`。
- 前端以完整鍵比對決定入口、選單與頁內操作的顯示（沒有角色回退）；強制點一律在後端，
  改動或偽造這兩欄不改變任何權限。
- 既有欄位的名稱、型別、值與省略語義不變；`source_ip` 仍只在 `GET` 帶，`PATCH` 仍不帶。
  解析主體失敗時回與原查詢失敗相同的 `500 INTERNAL_USER_INFO_QUERY`（`PATCH` 在寫入之前解析，
  失敗時顯示名不會被改動），不回以舊角色推估的值。

### 自助更新個人資料

```
PATCH /api/v1/auth/me
Authorization: Bearer <token>
```

自助更新個人資料。目前**僅放行 `local_display_name`**（自助顯示名）；正式身分
（`full_name`／`email`／`username`）維持唯讀（PAM 治理，未來由 IdP 權威同步）。
target 使用者一律取自 token claims，**不接受 path/body 指定他人**；端點重查帳號 active，
拒絕已停用/刪除帳號。

**請求**:
```json
{"local_display_name": "小王"}
```

- 空字串／`null`／全空白：trim 後寫回 `NULL`（清除顯示名，回退 `full_name`/`username`）。
- 驗證：長度上限 100（rune 計），拒控制字元/換行；違反回 `400`（`VALIDATION_DISPLAY_NAME`）。
- 其他欄位（`full_name`/`email`/`role`/`active`/`username`/`is_ldap`）一律忽略（僅 `local_display_name` 可寫）。
- **作用域收窄（安全紅線）**：`display_name` 僅用於裝飾/自我檢視場景（登入問候、側欄、Profile）；
  稽核 actor、授權 subject、審核方、admin 使用者列表、session owner、會話監看一律 `username`。

**回應** (200): canonical `UserInfo`（含 resolve 後的 `display_name`），並與 `GET /auth/me` 一樣
多帶 `permissions` 與 `scope_summary`（見「當前用戶」），前端以此整批替換目前的能力。
稽核歸類為 `resource=user, resource_id=當前使用者ID`。

### 版本說明的關閉狀態（release-guidance）

```
GET /api/v1/auth/me/release-guidance/:version
PUT /api/v1/auth/me/release-guidance/:version
Authorization: Bearer <token>
```

儀表板上的新版說明卡，由伺服器記住「這位使用者是否已關閉某個說明版本」，所以換瀏覽器或換裝置登入也不會再出現。兩條路由的登錄類別是本人資源（只需登入）；對象一律取自 token，路徑上沒有使用者識別，沒有任何參數能指定他人。自動化主體（agent token）一律拒絕：`403` `AUTH_AGENT_FORBIDDEN_ROUTE`。未帶 token 回 `401` `AUTH_TOKEN_MISSING`，token 無效或過期回 `401` `AUTH_TOKEN_INVALID`（認證中介層的既有碼）。

- **`:version` 是允許清單**：目前只有一個說明版本 `1.18.0`，它是說明主題的版本，與產品修補版號分開，同一說明版本只提醒一次。其他值回 `400` `VALIDATION_BAD_PARAMS`。
- **GET**：`200` `{"notice_version":"1.18.0","dismissed":false}`。沒有列就是尚未關閉，讀取不改任何狀態。
- **PUT**：請求本文只接受 `{"dismissed": true}`，即恰好一個 JSON 物件、只有 `dismissed` 一個欄位且值為 `true`、大小不超過 1024 位元組。未知欄位、`false`、缺欄位、第二個 JSON 值與過大的本文一律 `400` `VALIDATION_BAD_PARAMS`。沒有「取消關閉」的寫入；從使用者選單手動重開說明卡只是前端本次展開，不改伺服器上的狀態。成功回 `200` `{"notice_version":"1.18.0","dismissed":true}`，重複關閉同樣回 `200`。
- **帳號狀態與失敗**：PUT 時本人帳號已停用回 `403` `AUTH_USER_INACTIVE`，找不到本人回 `401` `AUTH_SESSION_EXPIRED`；其餘讀寫失敗回 `500`，GET 為 `INTERNAL_USER_INFO_QUERY`，PUT 為 `INTERNAL_USER_UPDATE`。
- **審計**：首次關閉時，偏好列與一列審計在同一交易寫入（`action=update`、`resource=user`、`resource_id=本人`，`details.event` 為 `release_guidance_dismissed`，另帶 `notice_version` 與 `dismissed`）；重複關閉不新增列，也不再寫這一列；審計寫入失敗則整筆回滾，狀態不變。PUT 的請求層審計與「自助更新個人資料」同一處理，歸 `resource=user`、`resource_id=本人`。這項偏好不改授權，不推進權限版本，也不發系統告警。
- **資料**：存放於 `user_release_guidance`（見 DB_SCHEMA 第 73 節），屬完整資料庫備份的範圍。

### 會話刷新（refresh）

```
POST /api/v1/auth/refresh
```

以 Web 會話刷新憑證換發新 access token 並輪替 refresh（公開端點：access 可能已過期）。

**請求**：無 body 欄位。憑證**僅**自 `custodexa_refresh` cookie 讀取，
不接受 request body 傳遞，亦無 body fallback。

**回應** (200): `{"token": "<新 access token>"}`；輪替後的新憑證以 `Set-Cookie` 下發，
`Max-Age` 取該憑證的剩餘絕對壽命。

- **rotation**：成功即輪替，舊 refresh 立刻作廢；新憑證由瀏覽器自動取代 cookie 內的舊值
- **reuse detection**：提交已輪替憑證 → 撤銷該使用者全部 refresh（家族撤銷，RFC 9700），記高價值稽核
- **壽命**：sliding 閒置窗（`web_idle_minutes` 政策）＋絕對壽命（`web_max_session_hours` 政策，
  以登入時刻起算、rotation 不重置；持有外部群組映射支持的帳號取它與 `mapping_revalidation_hours` 的較小者，
  見「身分來源與外部群組映射」的「有界重新驗證」）
- **允許來源網段**：刷新亦判來源。判定在交易內、世代複查之後、撤舊之前，不落清單者
  **零寫入**（不撤舊、不插新、不動 `last_used_at`），該憑證隨後自允許來源刷新照常成功，
  也不觸發家族撤銷。對外回應與其他刷新失敗**逐字相同**（401 `AUTH_SESSION_EXPIRED`），
  不新增訊號；成因只進稽核。前端沿既有「續期失敗導回登入頁」流，登入頁再以
  `AUTH_SOURCE_NOT_ALLOWED` 給出可行動的說明。**收緊清單後的殘窗＝access token 壽命**（15 分）
- **還原世代**：簽發時記下當下的還原世代（不出現在回應）；以管理腳本還原備份後，備份帶回的 refresh 一律以下述同一則 401 拒絕，不撤銷、不改寫該列
- **錯誤**：一律 401 同文案「會話已失效，請重新登入」（不洩漏憑證狀態，讓攻擊者無法區分猜錯與已失效）。
  **cookie 缺失走同一則失敗回應**（不是 400）——「未提供」與「無效／已撤銷」在回應上不可區分；
  失敗事件直記稽核

### 自助改密（change-password）

```
POST /api/v1/auth/change-password
Authorization: Bearer <token>
```

修改自己的密碼。接受兩種 token：**正式 session token**（自願改密）或
**`password_change` scoped token**（強制改密流程）；其餘 scope 一律拒。userID 一律取自 token claims，
不接受路徑參數（防改他人密碼）。

**請求**:
```json
{"old_password": "目前密碼", "new_password": "新密碼"}
```

**回應** (200)：成功後直接換發正式會話（不重走登入），格式同登入成功回應
（`{token, user}`，新的 Web 會話刷新憑證以 `Set-Cookie` 下發）。

**錯誤**:
- 400 政策違規（長度/組成/歷史重用，回可讀訊息）或目前密碼不符或 LDAP 用戶（密碼由目錄服務管理）
- 401 未提供/無效 token，或 token scope 不可用於改密
- 404 用戶不存在
- 503 改密服務未啟用（`userService` 未注入時）

改密成功會撤銷該使用者全部 refresh 會話（reason=`password_change`，8.3.5 語義延伸）。
自助改密不經 AuthMiddleware，事件由 handler 直記稽核（標註 `self_change_password`）。

### 多因素認證（MFA / TOTP）

啟用 MFA 的用戶登入為兩階段：`POST /auth/login` 驗證帳密通過後回傳
`{"mfa_required": true, "pending_token": "..."}`（pending token 有效 5 分鐘、
scope 限定 `mfa_pending`），再以 TOTP 驗證碼換取正式 JWT。

| 方法 | 路徑 | 說明 | 認證 |
|---|---|---|---|
| POST | `/auth/mfa/verify` | body: `{pending_token, code}` → `{token, user}`＋`Set-Cookie` 下發刷新憑證（若仍須改密則回 `password_change_required`） | 公開 |
| POST | `/auth/mfa/setup` | 產生 secret 與 otpauth URL：`{secret, otpauth_url}`（發行者 "Custodexa"；重做即覆蓋舊 secret）。POST 而非 GET：有寫入副作用（覆蓋 pending secret、重設 enabled） | JWT |
| POST | `/auth/mfa/enable` | body: `{code}`，驗證通過後啟用 | JWT |
| POST | `/auth/mfa/disable` | body: `{password}`，驗密後停用 | JWT |
| POST | `/auth/mfa/enroll/setup` | 強制註冊：以 `enrollment_token`（Bearer）產生 TOTP 設定 → `{secret, otpauth_url}`。已註冊者持 token 重放回 409（防改綁） | 公開（自帶 enrollment token） |
| POST | `/auth/mfa/enroll/confirm` | 強制註冊：body `{code}` ＋ `enrollment_token`（Bearer）完成綁定，直接換發正式會話；若仍須改密則回 `password_change_required`。綁定碼暴力達門檻回 423 | 公開（自帶 enrollment token） |
| POST | `/users/:id/mfa/disable` | 管理員救援停用（稽核記入 admin 身分＋目標用戶 ID） | JWT + `user:manage` |

啟用 MFA 的用戶登入為兩階段：`POST /auth/login` 驗證帳密通過後回
`{"mfa_required": true, "pending_token": "..."}`（pending token 5 分鐘、scope `mfa_pending`），
再以 TOTP 驗證碼換取正式 JWT。受 MFA 強制但尚未註冊者則走 `enroll/setup`→`enroll/confirm` 流程。
TOTP 防重放（PCI 8.5.1）：驗證僅接受 step 大於最後消耗值，以 CAS 原子推進擋同碼跨 skew 窗重放。
所有 MFA 事件（驗證成功/失敗、啟用/停用、強制註冊、管理員救援）均直接記入稽核日誌。

---

## OIDC 單一登入 API

多個 OIDC 身分提供者可並存，各自為獨立的 OAuth client；provider 設定存於資料庫，
部署層只決定三項環境變數（`PUBLIC_BASE_URL`／`OIDC_DEDICATED_ISSUERS`／`OIDC_ALLOWED_INTERNAL_HOSTS`，
見 [QUICKSTART.md](QUICKSTART.md) 與 `.env.example`）。

### 登入方法清單

```
GET /api/v1/auth/methods
```

未認證可讀（登入頁需在登入前取得 SSO 按鈕清單）。

**回應** (200):
```json
{"local": true, "oidc": [{"id": 1, "name": "公司 Entra ID"}, {"id": 2, "name": "Okta"}], "ldap": [{"id": 3}]}
```

`ldap` 只列啟用中的目錄、只含識別碼，供登入測試連結（`/login?source=ldap:<id>`）判斷目錄是否仍在
登入頁；停用、已刪除與不存在三者都是「不在清單」，對外不可區分。目錄清單讀取失敗時為空陣列。

只回識別與顯示所需欄位——**不含 issuer／client_id 等設定值**。
**停用者與設定不完整者皆不列出**（否則按鈕看得到、按下去必失敗）；
未設 `PUBLIC_BASE_URL` 時 `oidc` 恆為空陣列（fail-close）。
清單讀取失敗**不阻斷登入頁**：回 `{"local": true, "oidc": [], "ldap": [...]}`，前端降級為只顯示本地表單。

### 登入前告示

```
GET /api/v1/auth/banner
```

未認證可讀（登入頁需在登入前取得要顯示的告示）。它與 SSO 無關，列於此段是因為
兩者同為登入頁在登入前呼叫的公開端點。內容取自安全政策的
`login_banner_title` 與 `login_banner_body` 兩鍵（見下方安全政策 API）。

**回應** (200，未設定):
```json
{"enabled": false}
```

**回應** (200，已設定):
```json
{"enabled": true, "title": "授權使用者專用", "body": "本系統僅供獲授權之使用者存取。\n所有連線與操作將被記錄並錄影。"}
```

`enabled` 只由內文決定：內文為空即回前一種形狀，**標題單獨有值不成其為告示**；
`title` 可能是空字串（只填了內文）。回應**只含上述鍵**——不含其他政策鍵、
修改者、修改時間、基準建議值或符合性。這條路由沒有認證中介層，回應內容即等同對匿名者公開。

回應帶 `Cache-Control: no-store`：告示改完之後，下一個開啟登入頁的人就該看到新的。
封存期回 **503** `SEAL_SERVICE_SEALED`（與登入方法清單一致）。
**不寫稽核列、不寫資料庫**——一次登入頁載入不該在稽核軌跡上留下一列。
兩個鍵分兩次讀取，管理員儲存的那一瞬間可能一鍵新一鍵舊，於政策快取效期內收斂。

### SSO 三段流程

```
GET  /api/v1/auth/oidc/:id/begin?binding=<sha256>&next=<相對路徑>
GET  /api/v1/auth/oidc/callback?state=...&code=...
POST /api/v1/auth/oidc/exchange
```

三者皆為**公開端點**（使用者尚未登入即需發起）。流程：

1. **begin**：前端產生隨機 browser secret 存 `sessionStorage`，只把其 SHA-256 以 `binding`
   查詢參數送出（**明文不離開瀏覽器**）。後端建立流程狀態（state／nonce／PKCE verifier／
   binding hash／redirect_next／簽發當下的 provider 世代）後 **302** 導向 IdP 的授權端點。
   `binding` 缺漏回 400。`next` 經白名單化：只接受同源相對路徑，scheme-relative（`//evil`）、
   絕對 URL、反斜線與多重編碼一律退回 `/`（防開放重導向）。
   redirect_uri 固定為 `${PUBLIC_BASE_URL}/api/v1/auth/oidc/callback`（不從請求 Host 推導）。

2. **callback**：IdP 導回。後端以 state **原子消費**流程狀態（僅在未過期時取用並失效），
   交換 code、完整驗證 id_token（簽章演算法白名單／`iss`／`aud`／`azp`／`exp`／`iat`／`nbf`／
   ±60 秒 clock skew／`nonce`／`sub` 非空與長度），求值准入規則，完成身分對應與（必要時）供應，
   最後產生一次性**交棒憑證**並以 **302 + URL fragment** 交給 SPA：

   ```
   302 Location: ${PUBLIC_BASE_URL}/login#sso_ticket=<ticket>
   Referrer-Policy: no-referrer
   Cache-Control: no-store
   ```

   用 fragment 而非 query：query 會完整送到反向代理與其 access log，fragment 不送伺服器。
   失敗一律導回 `${PUBLIC_BASE_URL}/login#sso_error=<slug>`，slug 值域為
   `oidc_provider_error`（IdP 端回報錯誤）／`oidc_flow_invalid`（state/code 缺漏、流程狀態
   無效或過期、驗證失敗——**成因刻意收斂，不洩漏 IdP 內部狀態**）／`oidc_admission_denied`／
   `oidc_username_conflict`／`oidc_provider_unavailable`／`oidc_account_removed`（僅允許已綁定身分登入的
   provider，此人原有的帳號已被刪除，須由管理者重新建立帳號並綁定）／`oidc_user_inactive`（對應的帳號已停用）／`oidc_code_exchange_failed`（以授權碼向提供者換權杖失敗，
   多半是用戶端密碼錯誤或過期，屬設定面、重試不會改變結果）。
   前端據 slug 顯示可行動訊息。

3. **exchange**：SPA 讀出 fragment 後立即 `history.replaceState` 抹除，再兌換正式登入回應。

   **請求**:
   ```json
   {"ticket": "<自 fragment 取得>", "browser_secret": "<sessionStorage 的明文>"}
   ```

   **回應** (200)：
   ```json
   {"login": { "...與 POST /auth/login 完全同形（含 mfa_required／mfa_enrollment_required／password_change_required 分支）..." },
    "redirect_next": "/assets"}
   ```

   `redirect_next` 取自 begin 階段**已驗證**的值，**不於兌換階段重新採信前端提交值**。
   兌換為原子消費並比對 provider 與使用者兩個世代。

   發出正式會話時，Web 會話刷新憑證以 `Set-Cookie: custodexa_refresh=...` 下發，
   **巢狀的 `login` 物件內不含憑證明文**；尚待多因素驗證／強制註冊／強制改密的分支
   不下發該 cookie。

**瀏覽器綁定（login CSRF 防護）**：DB 保存 state 只證明「伺服器簽發且未用過」，不證明 callback
發生在發起的瀏覽器。攻擊者可自行發起流程、以自己的 IdP 帳號完成授權但攔住 callback，
再把該 URL 交給受害者——state/nonce/PKCE 全部有效，受害者會被登入攻擊者帳號，其後操作與稽核
全歸屬錯誤。故 `browser_secret` 明文必須在 exchange 時提出。**綁定不符時 ticket 不被消耗**
但累計失敗次數，達 3 次作廢——「消耗」與「請回到原分頁重試」互斥，故前 2 次可於原分頁重試。

**錯誤**（exchange／begin，統一錯誤封套）: 400 `AUTH_OIDC_PROVIDER_UNAVAILABLE`（provider 不存在／
停用／設定不完整）、400 `VALIDATION_OIDC_*`（binding 或 ticket 缺漏）、403 `AUTH_OIDC_ADMISSION_DENIED`、
409 `AUTH_OIDC_USERNAME_CONFLICT`、401 `AUTH_OIDC_FLOW_INVALID`（ticket／流程狀態無效、過期或已消費）、
403 帳號已停用、423 帳號已鎖定。

**與既有 gate chain 的關係**：exchange 走與本地登入相同的 `finishLogin`，故 MFA 與強制改密分支
一併適用；但**密碼類 gate 對外部帳號短路**（外部帳號無本地密碼可改）。
外部帳號無法使用本地密碼路徑（自助改密、admin 重設、本地登入）——一律回
`AUTH_EXTERNAL_USER_PASSWORD`。

### OIDC provider 管理（需 `oidc:manage`）

```
GET    /api/v1/oidc-providers
POST   /api/v1/oidc-providers
GET    /api/v1/oidc-providers/:id
PUT    /api/v1/oidc-providers/:id
DELETE /api/v1/oidc-providers/:id
GET    /api/v1/oidc-providers/:id/status
POST   /api/v1/oidc-providers/discovery-preview
```

**請求**（POST／PUT 同形）:
```json
{
  "name": "公司 Entra ID",
  "issuer": "https://login.microsoftonline.com/<tenant-id>/v2.0",
  "client_id": "…",
  "client_secret": "…",
  "scopes": "openid profile email",
  "admission_mode": "jit_with_rules",
  "admission_rules": "{…JSON…}",
  "force_shared": null,
  "enabled": true,
  "groups_claim": "groups",
  "username_claim": "",
  "email_claim": "",
  "display_name_claim": "",
  "risk_acknowledged": false
}
```

**宣告對應四鍵的三態**（`groups_claim`／`username_claim`／`email_claim`／`display_name_claim`）：
**未帶該鍵＝本次不動這一欄；帶空字串＝清回未設定**。要關掉一條設過的群組映射就送空字串。
四鍵各自去頭尾空白、長度上限 64、不得含空白、**不折疊大小寫**；違反回 400
`VALIDATION_OIDC_PROVIDER_PAYLOAD`。

**`force_shared` 的三態**（管理者收緊意圖；回應不回本值，只回現算的 `issuer_kind`／`issuer_kind_source`）：
- **未帶或 `null`＝本次不變更**。建立時即存為未表態。介面沒有動到這個開關時不送此鍵。
- **`true`＝收緊**：一律以多組織共用的規則把關。收緊永遠允許。
- **`false`＝撤回自己的收緊**：PUT 時，該 provider 原本存的是 `true`，或其 issuer 已由部署層
  宣告為專用，則接受並清回未表態（`NULL`）。撤回後判定依下方「回應語義」所列的優先序現算，未經部署層宣告者仍為
  `shared`；同一請求的准入規則以撤回後的判定驗證。
- 從未收緊、且系統判定為共用的 provider 收到 `false`（建立或更新）回 400
  `VALIDATION_OIDC_SHARED_WIDEN`：共用身分域不能由管理者改判為專用，專用只能由部署層宣告。

**回應**（列表為 `{"data": [...]}`；單筆 201／200）:
```json
{
  "id": 1, "name": "公司 Entra ID",
  "issuer": "https://login.microsoftonline.com/<tenant-id>/v2.0",
  "client_id": "…", "scopes": "openid profile email",
  "admission_mode": "jit_with_rules", "admission_rules": "{…}",
  "enabled": true, "has_secret": true,
  "issuer_kind": "dedicated", "issuer_kind_source": "deploy_declared",
  "config_complete": true, "identity_count": 12,
  "groups_claim": "groups", "username_claim": "", "email_claim": "", "display_name_claim": "",
  "redirect_uri": "https://pam.example.com/api/v1/auth/oidc/callback",
  "redirect_uri_state": "ready"
}
```

**回應語義**:
- **回應永不含 client_secret 的任何形式**；`has_secret` 僅告知「是否已設定」，供 UI 顯示
  「留空沿用」提示。PUT 時 `client_secret` 留空＝沿用既有值。
- `issuer_kind`（`shared`／`dedicated`）為 **effective 判定結果，現算不持久化**，優先序：
  內建共用清單 > `force_shared`（admin 收緊意圖）> 部署層 `OIDC_DEDICATED_ISSUERS` > 未知（一律 `shared`，fail-close）。
- `issuer_kind_source`（`builtin_list`／`admin_forced`／`deploy_declared`／`unknown_default`）
  使「部署宣告打錯字而未生效」可被立即看出，而非表現為「規則設定莫名被拒」。
  多副本部署時該欄反映**本副本**的判定。
- `identity_count`（列表端點）為已綁定此 provider 的外部身分數。兩處管理決策需要具體
  數字而非語義提示：切換為 `prebound_only` 時「既有 N 個身分沿用、新使用者不再自動供應」，
  以及刪除被拒時「請先解綁 N 個身分」——只說「有既有身分」無從判斷影響面。
- `config_complete=false`＋`incomplete_hint`：設定不完整（如未設 `PUBLIC_BASE_URL`），
  該 provider 不會出現在 `/auth/methods`。
- **宣告對應四欄恆出現**（未設定即空字串）。空值語義：`groups_claim` 空＝此 provider 的
  群組映射關閉（登入時不解析群組、不重算角色）；其餘三欄空＝沿用系統預設
  `preferred_username`／`email`／`name`。**`groups_claim` 刻意沒有預設值**——各家的鍵名由
  設定決定，猜一個的失敗方向是拿別的宣告當群組看待。
- `redirect_uri` 是**要登記到提供者端的回呼位址**，由對外基準網址算出、不落庫；
  `redirect_uri_state` 值域 `ready`｜`base_url_unset`，後者表示尚未設定對外基準網址、
  回呼網址無從算出（介面應據此指出要先設什麼，而不是顯示一個空字串）。
  兩欄一併出現在列表回應上（**不只詳情**）。列表回應的頂層另帶同名兩欄
  （`{"data": [...], "redirect_uri": "…", "redirect_uri_state": "ready"}`）：回呼網址對所有提供者相同，
  新增頁還沒有單筆可讀時取這裡的值。

**約束與錯誤**:
- `issuer` 與 `client_id` 組成身分域，**建後不可變**（PUT 送出不同值回 400
  `VALIDATION_OIDC_IMMUTABLE_FIELD`）。Entra 的 `sub` 為 per-application pairwise，
  換 client_id 後同一人會拿到不同 subject，此約束為硬需求。
- `(issuer, client_id)` 唯一（排除軟刪列）；重複回 409 `CONFLICT_OIDC_IDENTITY_DOMAIN`。
- 有外部身分關聯者**不可刪除**，回 409 `CONFLICT_OIDC_PROVIDER_IN_USE`（僅能停用）。
- `scopes` 走允許清單，未知 scope 回 400；`admission_rules` 鍵封閉，未知鍵／共用身分域
  未帶組織歸屬規則／消費者租戶值入清單一律回 400 `VALIDATION_OIDC_ADMISSION_RULES`。
- issuer 格式與 scheme 不合（release 拒 http）回 400 `VALIDATION_OIDC_ISSUER`。
- 404 `NOTFOUND_OIDC_PROVIDER`；`:id` 非正整數回 400 `VALIDATION_OIDC_PROVIDER_ID`。
- **設了 `groups_claim` 但 `scopes` 不含 `groups` 時回 422 `MAPPING_ACK_REQUIRED`**，
  主體帶 `warnings: [{"code": "MAPPING_GROUPS_SCOPE_MISSING"}]`。這是**警告加確認、不阻擋**：
  帶 `risk_acknowledged: true` 重送即存下，確認一併留痕。理由是多數提供者要在授權請求帶
  `groups` scope 才發出群組宣告，而宣告缺席會被判為空集合——症狀是規則列在頁上、狀態是啟用、
  卻沒有人拿到角色。有些提供者改由權杖設定發出群組而不需該 scope，故不能一律擋。
  **例外：issuer 主機為 `login.microsoftonline.com`（Microsoft Entra ID）時不觸發此確認**，
  建立以請求的 issuer、更新以既有列的 issuer 判定（issuer 建後不可變），
  狀態彙總亦不回 `MAPPING_GROUPS_SCOPE_MISSING`。Entra 的群組宣告由其權杖設定決定，
  且它不接受名為 `groups` 的 scope，帶了會使登入被拒。
  附加 scope 允許清單為 `profile`／`email`／`groups`（`offline_access` 仍不在清單）。

**單筆詳情** `GET /oidc-providers/:id`：回單一 provider 的完整形狀（同上，含 `redirect_uri`
與 `redirect_uri_state`），供設定頁載入。

**狀態彙總** `GET /oidc-providers/:id/status`：檢核面板的一次性燈號查詢。

```json
{
  "discovery_reachable": true,
  "credential_set": true,
  "last_login_at": "2026-09-08T08:47:03Z",
  "last_login_groups_seen": true,
  "last_login_groups_count": 5,
  "rule_count": 3, "enabled_rule_count": 2,
  "last_recompute_matched_users": 12,
  "warnings": [{"code": "MAPPING_SOURCE_ATTR_UNSET_WITH_RULES"}],
  "last_attempt": {
    "at": "2026-10-13T06:28:11Z", "outcome": "denied",
    "reason_code": "admission_tid", "username": "chen.y@example.com", "window_days": 30
  },
  "last_success": {"at": "2026-10-13T06:20:02Z", "mapping_eligible": true, "account_removed": false},
  "discovery_checked_at": "2026-10-13T01:12:40Z",
  "last_login_groups_at": "2026-10-13T06:20:02Z",
  "groups_unknown_at": null,
  "group_attr_configured": true,
  "source_updated_at": "2026-10-12T09:00:00Z",
  "login_test_url": "https://bastion.example.com/login?source=oidc:4",
  "login_test_state": "ready"
}
```

- **本端點一律不對外撥號**：只回報系統已經觀測到的事實（設定值、規則數、映射事實、
  登入時的群組觀測快照、探索文件的快取新鮮度）。頁面載入即撥號會把一支唯讀查詢
  變成可被反覆觸發的出站探測，也會與連線測試的資源上限互相干擾。**主動測試是介面上的
  獨立動作**（重新探索、測試連線），由操作者按下去才發生。
- **無從觀測的燈號回 `null`**（介面呈現為「尚無資料」）——不知道不得畫成綠色。
  `last_login_groups_seen` 為 null 即代表此來源尚無登入紀錄可判讀。
- `discovery_reachable` 取自探索文件的快取，快取為空時為 null；`discovery_checked_at` 是同一份
  快取的取得時間（只讀快取，不撥號），快取為空或已不新鮮時為 null。
- `last_attempt`：近 30 天內經這個來源最近一次登入嘗試，取自稽核紀錄（登入事件），窗內沒有
  任何嘗試時為 null。`window_days` 回時間窗天數（30），供介面寫出「近 N 天沒有登入嘗試」。
  - `outcome`：`success`／`pending`（身分提供者驗證通過，等待第二因素或變更密碼）／`denied`／`failed`。
  - `reason_code` 為受控機器碼，介面依碼查白話原因：`success`、`pending_mfa`、
    `pending_mfa_enrollment`、`pending_password_change`、`source_denied`、`admission_tid`、
    `admission_hd`、`admission_email_domain`、`admission_email_verified`、`admission_not_prebound`、
    `admission_rules_noncompliant`、`code_exchange_failed`、`id_token_missing`、`id_token_invalid`、
    `provider_unavailable`、`internal_error`、`provider_error`、`username_conflict`、
    `account_removed`、`user_inactive`、`unknown`。
  - `reason_detail` 只在兩個碼出現，且只取白名單值，名單外一律為 `other`：
    `admission_rules_noncompliant` 為 `shared_needs_org_rule`／`empty_rule_set`／`consumer_tenant`／
    `email_needs_verified`／`unknown_rule`／`invalid_rules`／`other`；`provider_error` 為
    `access_denied`／`invalid_scope`／`unauthorized_client`／`server_error`／
    `temporarily_unavailable`／`login_required`／`interaction_required`／`consent_required`／`other`。
  - `event` 只在 `reason_code=unknown` 時出現，為稽核事件名；不符 `^[a-z0-9_]{1,64}$` 即省略。
  - `provider_error`、`provider_error_description` 只在 `reason_code=provider_error` 時出現。
    **`provider_error_description` 是身分提供者自報的文字**，不是本系統的判讀；回應前截為
    200 個字元（以字元計，不切斷多位元組字元）。用戶端須以純文字呈現。
  - `username` 為稽核列的帳號名稱，沒有時為空字串。
- `last_success`：同一時間窗內最近一次成功類登入（`success` 或 `pending`）的時間，與該帳號目前
  是否適用群組映射（`mapping_eligible`；本地帳號綁定外部身分者為 `false`，帳號已不存在亦為
  `false`），以及該帳號是否已刪除（`account_removed`，介面據此不把它說成本地帳號）。窗內沒有時為 null。
- `last_login_groups_at`：最近一次群組觀測快照的時間（不是帳號的最近登入時間），沒有快照時為
  null；快照本身不受 30 天窗限制。`groups_unknown_at`：30 天窗內最近一次登入讀不到完整群組資料
  的時間，沒有時為 null。
- `group_attr_configured`：來源有沒有設群組宣告名，直接取自設定，不需等登入。
- `source_updated_at`：來源設定最近一次變更的時間。介面以它判斷最近一次登入是否早於設定變更。
- `login_test_url`／`login_test_state`：登入測試連結，以對外基準網址組成
  （`{基準網址}/login?source=oidc:{id}`），只含來源型別與編號。`login_test_state` 為 `ready`
  （有連結）、`base_url_unset`（對外基準網址未設定，連結為 null）、`source_disabled`
  （來源停用，連結為 null）。基準網址未設定優先於來源停用。

**探索預覽** `POST /oidc-providers/discovery-preview`，主體 `{"issuer": "https://…"}`：
以填在表單裡、**尚未儲存**的 issuer 取一次探索文件，回其端點與宣告／scope 清單，供設定頁
在存檔前確認鍵名。**不落庫、不建立任何 provider**；呼叫留痕。

```json
{"issuer": "…", "authorization_endpoint": "…", "token_endpoint": "…", "jwks_uri": "…",
 "userinfo_endpoint": "…",
 "claims_supported": ["sub", "email", "name", "groups"],
 "scopes_supported": ["openid", "profile", "email", "groups"],
 "id_token_signing_alg_values_supported": ["RS256"],
 "issuer_matches": true, "signing_alg_compatible": true}
```

回應另帶兩項檢查，預告登入時才會遇到的失敗（不改狀態碼、不新增錯誤碼）：

- `issuer_matches`：探索文件宣告的 `issuer` 與輸入值（去掉結尾斜線後）逐字相同。登入時會強制
  這項完整字串比對，為 `false` 時登入必定失敗。
- `signing_alg_compatible`：文件宣告的 `id_token_signing_alg_values_supported` 與本系統允許的
  簽章演算法（RS256、ES256）有交集；文件未宣告時為 `true`（登入時沿用本系統的允許集合）。
- `id_token_signing_alg_values_supported` 照抄文件宣告，未宣告時為空陣列。

取不到或不是合法探索文件時回 502 `OIDC_DISCOVERY_PREVIEW_FAILED`；issuer 不合信任邊界時
沿用既有的 issuer 驗證錯誤碼。**`claims_supported` 與 `scopes_supported` 是提供者自報的**，
不是本系統的保證：清單裡有 `groups` 不等於該帳號的權杖一定帶得到群組，仍以實際登入時的
群組觀測為準。

**停用／刪除／secret 輪替的失效語義**（安全紅線）：三者皆先推進該 provider 的 `auth_epoch`，
再撤銷 refresh、拒絕既簽 access、終斷該 provider 建立的協議連線、收線其監看與分享訂閱。
`auth_epoch` **重新啟用不回退**，故「停用後短時間重新啟用」不會復活攻擊者手上的既簽憑證。
secret 輪替一併走全套——僅推進世代不足夠，既有連線建立後不再使用憑證，世代對其無效。
**IdP 端的停權不在此列**：見 QUICKSTART.md「OIDC／SSO 部署注意」。

### LDAP 目錄設定（需 `ldap:manage`）

```
GET    /api/v1/ldap-directory
PUT    /api/v1/ldap-directory
DELETE /api/v1/ldap-directory
POST   /api/v1/ldap-directory/test
GET    /api/v1/ldap-directory/status
```

**singleton 資源**：無集合式建立端點、無資源 id。`PUT` 為 upsert（無列即建、有列即改），
`DELETE` 為軟刪。「至多一條有效設定」由資料庫層保證（`CHECK (singleton = 1)` ＋
partial unique index），不依賴服務層計數；並發寫入以交易範圍互斥鎖線性化，
取不到鎖回可重試機器碼而非 500。

**請求**（PUT）:
```json
{
  "name": "公司目錄",
  "url": "ldaps://dir.example.com:636",
  "bind_dn": "cn=svc-bind,dc=example,dc=com",
  "bind_password": "…",
  "clear_bind_password": false,
  "base_dn": "ou=users,dc=example,dc=com",
  "user_filter": "(&(objectClass=user)(sAMAccountName=%s))",
  "attr_email": "mail",
  "attr_fullname": "displayName",
  "attr_group": "memberOf",
  "skip_tls_verify": false,
  "enabled": true,
  "risk_acknowledged": false
}
```

**回應**（GET／PUT）:
```json
{
  "configured": true, "name": "公司目錄",
  "url": "ldaps://dir.example.com:636",
  "bind_dn": "cn=svc-bind,dc=example,dc=com",
  "has_bind_password": true,
  "base_dn": "ou=users,dc=example,dc=com",
  "user_filter": "(&(objectClass=user)(sAMAccountName=%s))",
  "attr_email": "mail", "attr_fullname": "displayName", "attr_group": "memberOf",
  "skip_tls_verify": false, "enabled": true
}
```

**`attr_group`（群組成員資格屬性名）**：**空字串＝本部署不依外部群組決定角色**——登入路徑
不向目錄索取這個屬性，也不動任何角色列，未設定的部署行為與這一欄出現之前逐字相同。
它**不列入啟用態的必填集**：既有部署升級後這一欄必然是空的，變成必填等於讓一次升級
把所有目錄使用者擋在門外。屬性名與既有的 `attr_email`／`attr_fullname` 在同一次搜尋裡
一併索取（同名不重複列入）。

未設定時回 `{"configured": false}`。**bind 密碼永不回讀**，僅以 `has_bind_password` 表達有無。

**密碼編輯語義**（與通知通道 secret 同族）: 空值＝沿用既存；`clear_bind_password: true`＝顯式清除
（同事務抹除密文，軟刪 tombstone 不留可解密內容）；兩者同時給＝400。
**URL 的 canonical origin 改變且既存有密碼時**，必須同時提供新密碼或顯式清除，否則 400——
否則「改指向 ＋ 留空沿用」會把既存憑證送往新位址。既存無密碼（草稿）時改 URL 不受此限。

**URL 文法**：僅接受 `ldap[s]://host[:port]`，拒絕 userinfo／path／query／fragment／空 host／
超界 port（`ldap://user:secret@host/...` 形態會使憑證流入 UI、錯誤訊息與稽核的目標欄位）。
比較、出站檢查與撥號共用同一份解析結果。

**`user_filter` 兩層驗證**（存檔即驗，非僅測試時）: 語法層要求 `%s` 恰一次、無其他格式化動詞、
括號配對、可解析為 RFC 4515；結構層要求 `%s` 所在等式斷言為**每條可滿足路徑的必要條件**
（其祖先不得為 OR／NOT）。`(|(uid=%s)(uid=svc-admin))` 語法合法但被結構層拒絕——
OR 的另一分支可在不含登入帳號時命中，配合「唯一命中即 bind」會使搜尋結果與登入身分脫鉤。

**存檔閘**（沿既有三通道共用契約）: 僅「儲存後為啟用且含傳輸風險」須過閘。strict 檔位拒存、
warn 檔位缺 `risk_acknowledged` 拒存（400，碼與 syslog／通知通道相同）；`enabled=false` 不受限。

**連線測試** `POST /ldap-directory/test`：測**表單當下未儲存的值**（先測後存）。
階梯為 撥號 → bind → 搜尋，`err == nil` 即階梯已執行（HTTP 200，失敗資訊在 body 的
`stages[]`／`failed_stage`／`code`）；`err != nil` 代表測試未執行（驗證/閘 400、限流 429）。

```json
{
  "success": true, "target": "ldaps://dir.example.com:636",
  "stages": [{"stage": "dial", "ok": true}, {"stage": "bind", "ok": true}, {"stage": "search", "ok": true}],
  "matched_count": 42, "matched_at_least": false,
  "attr_sample": {"sampled": true, "email_present": true, "fullname_present": true,
                  "group_configured": true, "group_present": true},
  "reused_stored_password": false
}
```

搜尋以未轉義 `*` 展開 `%s`（**全系統唯一不經 `EscapeFilter` 的例外**，登入路徑不受影響），
`SizeLimit` 1000（達上限時 `matched_at_least: true`，UI 顯示「至少 N 筆」）。

`attr_sample` 的 `group_configured` 與 `group_present` **刻意是兩欄不是一欄**：「沒設定屬性名」
與「設了卻在抽樣項目上讀不到」的處置完全不同，壓成一欄的話管理者看到的是同一種紅。
抽樣一律**只回布林、不回值**。

**狀態彙總** `GET /ldap-directory/status`：與 `GET /oidc-providers/:id/status` **共用同一組鍵**，
不適用於該型別的鍵回 `null` 而非不出現——目錄這一端讀的是 `connection_ok` 與
`group_attr_readable`（連線測試的群組屬性抽樣結果），`discovery_reachable` 恆為 `null`；
提供者那一端反過來。同樣**一律不對外撥號**。**目前 `connection_ok` 與 `group_attr_readable`
兩欄也恆為 `null`**：
連線測試的結果不落庫，本端點沒有可讀的來源。要判讀連線與群組屬性是否可讀，用
`POST /ldap-directory/test`（那是操作者按下去才發生的主動動作），介面以該頁最近一次測試的
結果與時間呈現這兩項。
目錄這一端另回 `last_login_groups_at`、`group_attr_configured`（是否設了群組屬性名）、
`source_updated_at`、`login_test_url`／`login_test_state`（連結為 `{基準網址}/login?source=ldap:{id}`），
語義同提供者端；`last_attempt`、`last_success`、`discovery_checked_at` 恆為 `null`，
`groups_unknown_at` 依同一套 30 天窗查法回報。
目錄尚未設定時回 404 `NOTFOUND_LDAP_DIRECTORY`。

**錯誤揭露的收斂**：撥號失敗一律回單一 `connect_failed`，**不細分** DNS／逾時／拒絕／TLS——
階梯本身已是 open/closed 訊號，再細分等於提供內網埠掃描解析度。失敗回應附 `diagnostic_id`
（不透明關聯碼，同值出現於回應、稽核與伺服端 operational log 三處），粗分類原因**只**寫入
operational log，需主機營運權限才能對照。出站政策拒絕另立 `egress_blocked`——該判定發生在
本地（IP 分類），封包從未送出，不揭露目標主機狀態。

**測試路徑亦受傳輸政策約束**且**不受請求的 `enabled` 限縮**：測試當下就會撥號送出 bind 密碼，
若比照存檔閘只在啟用時生效，關掉開關即可在 strict 下明文外送憑證。空密碼在本機即擋
（不對目錄發出 bind），確保「改 URL／勾清除」兩種情形下憑證不離開本機。

**出站位址政策**（登入與測試兩路徑皆過）: 拒絕 loopback／link-local（含雲端 metadata）／
未指定／multicast；**私有網段預設放行**（目錄常態位置為內網）。判定發生於名稱解析之後、
實際連線之前並套用於每個候選位址，故 DNS rebinding 無窗口；不改寫 host 為 IP，
`ldaps://` 的憑證主機名驗證不受影響。loopback 例外見 `LDAP_ALLOWED_LOOPBACK_ENDPOINTS`。

**設定來源與降版**：`.env` 的 `LDAP_*` 九鍵僅供首次啟動 seed，之後以本 API 為唯一事實源；
降版至舊版本前須將現行設定回填 `.env`，見 QUICKSTART.md。

### 身分來源與外部群組映射

把目錄與身分提供者合併成一份列表，在各來源底下分別維護「外部群組 → 系統角色」及「外部群組 → 使用者群組」規則。

**權限**：本節路由需 `identity_source:manage`；建立、修改、停用、啟用、刪除兩類規則時，另經角色指派共用的寫入關卡判定（見下方「寫入關卡與錯誤碼」）。

```
GET    /api/v1/identity-sources
GET    /api/v1/identity-sources/:type/:sourceId/mappings
POST   /api/v1/identity-sources/:type/:sourceId/mappings
PUT    /api/v1/identity-sources/:type/:sourceId/mappings/:ruleId
DELETE /api/v1/identity-sources/:type/:sourceId/mappings/:ruleId
```

`:type` 值域 `ldap`｜`oidc`；目錄為單例，其 `:sourceId` 即該單列的 id。
**路徑參數刻意不叫 `:id`**——稽核中介層以名為 `id` 的路徑參數填稽核列的資源欄位，
沿用該名會在稽核列上長出一個指向別種資源的錨點。

**合併列表** `GET /identity-sources` → `{"data": [SourceRow]}`：

```json
{"type": "oidc", "id": 2, "name": "公司 Entra ID",
 "address": "https://login.microsoftonline.com/<tenant-id>/v2.0",
 "enabled": true, "last_login_at": "2026-09-08T08:47:03Z", "mapping_rule_count": 3,
 "role_mapping_rule_count": 3, "user_group_mapping_rule_count": 2, "mapped_user_count": 4,
 "group_attribute_configured": true, "effective_role_loss_count": 2,
 "effective_member_loss_count": 1}
```

`address` 是目錄的位址或提供者的 issuer；`last_login_at` 可為 null（該來源尚無成功登入）；
`mapping_rule_count` 保持舊契約，只計角色規則；兩類規則計數均包含停用列。`mapped_user_count` 為此來源兩類現有規則支持涉及的去重帳號數。`group_attribute_configured` 表示來源已設定群組欄位；兩個 `effective_*_loss_count` 是按目前支持與手動成員計算的來源停用預覽，實際異動以提交時狀態為準。目錄至多一列；兩者皆未設定時回空陣列。

**規則的形狀**：

```json
RuleInput: {"match_value": "cn=PAM-Admins,ou=groups,dc=example,dc=com",
            "role": "admin", "enabled": true, "risk_acknowledged": false}
Rule:      {"id": 7, "source_type": "oidc", "source_id": 2,
            "match_value": "…", "role": "admin", "enabled": true,
            "affected_user_count": 4, "effective_role_loss_count": 2,
            "effective_member_loss_count": 0,
            "created_by": "admin", "created_at": "…", "updated_at": "…"}
```

- `role` 用角色**名**（非 id）。未知角色回 400 `VALIDATION_MAPPING_ROLE_UNKNOWN`。
  只有沒有範圍的內建角色能直接映射，判定看角色的內建識別而不看名稱；自訂角色（含取名為
  `admin` 的自訂角色）回 400 `MAPPING_ROLE_NOT_DIRECT_MAPPABLE`，要改用「外部群組 → 使用者群組」
  規則，再替該使用者群組指派角色。可直接映射的目標是六個內建角色：升級前就存在的四個，加上升級新增的
  身分管理員與系統安全管理員兩個鎖定範本；以超級管理者或系統安全管理員為目標的規則，寫入時受下方
  `AUTH_PROTECTED_ROLE_ASSIGNMENT` 的保護角色規則約束。
- 請求帶任何範圍或節點欄位（`nodes`、`node_ids`、`scope`、`scope_kind`、`scope_nodes`）時整筆
  回 400 `MAPPING_SCOPE_FIELD_REJECTED`，不寫任何資料；兩類規則皆同。映射規則本身沒有範圍。
- `match_value` **原樣存、不做正規化**。目錄側須逐字照目錄回傳的辨識名稱填：比對時兩邊
  各自解析成結構再比，**屬性型別不分大小寫、屬性值分大小寫**；解析不了的值回 400
  `VALIDATION_MAPPING_MATCH_VALUE_DN`。提供者側非空即可，比對是**逐字**的、不做任何正規化
  （兩家提供者的官方文件皆未定義比對規則，故取嚴）。
- `enabled: false` 的規則在登入重算時**視同不存在**，用來暫停一條映射而不必刪掉它。
- 角色與使用者群組規則新增時皆可帶選填 `note`；若相同來源與群組值已有字典列，新增規則不覆寫既有備註，請用獨立字典 API 修改。
- 建立成功回 201，更新回 200，刪除回 204。規則不存在回 `MAPPING_RULE_NOT_FOUND`。

**警告加確認，不阻擋**：以下情形且 `risk_acknowledged` 為 false 時回 **422**
`MAPPING_ACK_REQUIRED`，主體帶命中的警告清單：

```json
{"error": "…",
 "code": "MAPPING_ACK_REQUIRED",
 "meta": {"warnings": [{"code": "MAPPING_TARGETS_ADMIN_ROLE"},
                       {"code": "MAPPING_SOURCE_ATTR_UNSET"}]}}
```

- `MAPPING_TARGETS_ADMIN_ROLE`：這條規則會把管理員角色交給一個外部群組決定。
- `MAPPING_SOURCE_ATTR_UNSET`：來源尚未設定要從哪裡讀群組（目錄的群組屬性名或提供者的
  群組宣告名為空），故這條規則存下去也永遠不會命中。

帶 `risk_acknowledged: true` 重送即存下，**確認一併留痕**。這裡不採直接拒絕：規則本身是
管理者的意圖，擋下來只會把人推去改別的地方；要防的是「不知情」而不是「不發生」。

**寫入關卡與錯誤碼**：兩類規則的建立、修改（比對值、目標或啟用旗標）、啟用、停用與刪除，
以及釘住（見「用戶 API」的「角色的兩份集合」），與直接指派角色共用同一道關卡。關卡在來源鎖內、
同一交易裡以重讀的現值判定，舊目標與新目標各判一次：

| 碼 | HTTP | 情形 |
|---|---|---|
| `AUTH_PROTECTED_ROLE_ASSIGNMENT` | 403 | 舊目標或新目標是超級管理者或系統安全管理員角色，或是直接帶有這兩種角色指派的使用者群組，而操作者不是超級管理者。含高風險權限點（能刪除證據、關閉或改道告警、放寬安全控制或管理金鑰）的自訂角色同樣受保護，判定與這兩種角色相同（定義見「角色指派的保護與開放邊界」）。同一道關卡也管群組角色指派與成員異動：讓任何帳號取得或失去這兩種角色的群組操作（指派或移除這兩種角色、對帶這兩種指派的群組加人、移人或刪除）限超級管理者；這兩種指派不變、只增減其他角色，或群組不帶這兩種指派時，持 `role:assign` 即可 |
| `MAPPING_ROLE_NOT_DIRECT_MAPPABLE` | 400 | 角色規則的目標不是可直接映射的內建角色 |
| `MAPPING_SCOPE_FIELD_REJECTED` | 400 | 請求帶範圍或節點欄位 |

關卡先於風險確認判定：`risk_acknowledged`、`source_config_acknowledged` 只回應上面的警告，
帶任何值都不改變關卡的結論；目標是超級管理者角色時，超級管理者本人寫入也照常要確認。拒絕回應不帶角色名稱或權限名稱。
持有 `role:assign` 的操作者對非受保護目標的寫入放行，不檢查其自身是否持有該角色的權限。

**授權變更的留痕**：規則寫入與釘住在同一交易內寫審計，並在符合下列情形時產生系統告警
（見「系統告警目錄與明細」）；審計或告警寫不進去時，規則、支持收回與權限版本一併回滾。

- 會讓操作者本人取得角色或群組的寫入（建立、啟用、修改後命中操作者最近一次已知的群組觀測），
  以及釘住自己的映射角色：`self_privilege_increased`。
- 停用或刪除操作者本人正受其支持的規則：`self_privilege_decreased`。
- 目標是管理類角色或帶管理類角色指派的使用者群組：使規則開始生效的每次寫入（建立且啟用、由停用改為啟用、
  啟用中修改比對值或目標）各一筆 `management_role_granted`；建立時即停用的規則不產生。釘住他人的管理類角色
  同樣產生。判定依規則目標，不依當下命中人數。
- 目標不含管理類角色、且沒有命中操作者本人：只寫一般審計。目標是基礎使用者角色時，即使命中本人也一樣；
  指向其他非管理類角色而命中操作者本人時，屬上面第一種情形。

操作者是否「命中」以平台最近一次記下的群組觀測判定；身分提供者或目錄之後才把人加進群組，
平台看不到，也不會因此產生告警。

**身分來源設定變更**：目錄與身分提供者設定的建立、修改（含啟停與密鑰輪替）與刪除，
在同一交易內寫審計（身分提供者為 `oidc_provider_settings_change`）並產生 `identity_source_changed`
告警，內容列出變更的欄位與「此來源目前有 N 位超級管理者」（可經此來源登入、有效角色含超級管理者的
帳號數，經使用者群組取得的也算）。bind 密碼與 client secret 只記「已變更」，不帶值也不帶摘要。
這是留痕，不是限制：修改來源設定不另加權限門檻。

**來源刪除的相依**：仍有規則掛著的目錄或提供者不可刪除，回 409
`LDAP_DIRECTORY_HAS_MAPPINGS`／`OIDC_PROVIDER_HAS_MAPPINGS`；先移除規則再刪來源。

**規則怎麼變成角色**：每次登入對該通道的已知群組觀測重算逐規則支持。建立或啟用規則待下次登入授予；停用、刪除或改變群組值／目標時，舊規則支持立即收回。失去全部支持的有效角色被移除時，同交易推進憑證世代並撤刷新憑證。
群組資料的三種狀態各有不同處置：來源未設定要從哪裡讀群組、也沒有啟用中的規則時**完全不重算**；
設定了卻這次讀不到（或有啟用中的規則卻沒設群組屬性名／宣告名）時，在重新驗證時限內**保留現狀並留痕**
（不當成「沒有群組」而把角色全撤），超過時限即收回（見下方「有界重新驗證」）；
讀到了（**空集合也算讀到**）才依規則重算。

**有界重新驗證**（安全政策 `mapping_revalidation_hours`，整數小時，預設 12，可設 0 或 1–168，
0＝不設限；列於「安全政策 API」的政策鍵值域）：

- **工作階段上限**：時限 T 非 0 時，持有任何映射支持（角色或使用者群組，任一通道）的帳號，
  發放與輪替刷新憑證時的絕對壽命取 `web_max_session_hours` 與 T 的較小者（前者為 0 時取 T）；
  輪替只會縮短、不會延長，換發的存取權杖也不超過這個期限。到期後須重新登入，登入時只依規則重算
  該次登入來源的映射。沒有映射支持的帳號、以及 T 為 0 時，只依 `web_max_session_hours`。
  判定所需的映射支持讀不到時，發放與輪替被拒絕，不當成沒有支持而給長壽命。
- **讀不到群組的上界**：平台逐（帳號，通道）記錄最近一次讀到群組的時間（讀不到不更新）。
  某通道這次讀不到群組時，若最近一次讀到在 T 以內，照現況保留並寫跳過事件；若超過 T、或從未讀到過，
  收回該通道經映射取得的全部角色與使用者群組成員資格，寫 `membership_revalidation_expired`
  （細節記通道、時限、最近一次讀到的時間與收回的項目）；有效權限因此減少時，同交易推進憑證世代並撤銷
  刷新憑證。其他通道的支持、管理者指派的角色與手動成員不受影響。T 為 0 時讀不到一律保留。
  之後某次登入讀到了群組，即依規則重新計算。最近一次讀到的時間只在登入時比對：因保留而發放的工作階段
  自該次登入起算完整壽命，輪替也不再比對讀到時間，讀不到群組的登入不推進最近一次讀到的時間。故 T 大於 0、
  後續登入都經同一來源且期間不放寬政策時，若來源端收權而仍允許登入、只是不提供群組，該來源的映射權限
  在最近一次讀到之後最長約可再用 T 加一個工作階段壽命（至多 2T）。帳號可經另一個已綁定來源登入時，
  原來源的映射可能持續保留，不受此上界限制；需要即時收權時以 `PUT /users/:id/status` 停用帳號。
- **射程**：上界涵蓋網頁工作階段，以及之後新開的連線；工作階段到期時已建立的協議連線不由這個上界中斷。
  外部來源停用帳號、巢狀群組與群組改名後比對不到等既有限制不變。
- 調長時限或改為 0 會在政策寫入的同一交易內產生 `mapping_revalidation_relaxed` 告警
  （參數為前後時數，0 表示不設限）；調短或由 0 改為非 0 只寫政策變更審計。

**稽核**：映射造成的角色異動逐次留痕，可回答「誰、經哪條途徑、命中哪些群組、動了哪些角色、
憑證世代是否推進」；跳過重算的兩種情形（來源未設定屬性／宣告名、群組讀不到）各有自己的
機器碼。留痕失敗即整筆回滾——角色改了而稽核沒記下來，是本系統不接受的結果。

**明確路由與使用者群組規則**：上述 `/mappings` 四條舊路由仍只代表角色；同樣的四個方法可用 `/role-mappings`。`/user-group-mappings` 提供 GET、POST、PUT、DELETE，列表回 `data`，建立回 201、更新回 200、刪除回 204。請求含 `match_value`、`user_group_id`、`enabled`、`risk_acknowledged`、`source_config_acknowledged`，新增字典值時可帶選填 `note`。回應列含來源型別與 ID、`external_group_id`、`note`、`user_group_name`、`usage`、`affected_user_count`、兩種有效權限收回預覽、建立者與時間。來源未設群組欄位時沿用 `MAPPING_ACK_REQUIRED` 警告，須另送 `source_config_acknowledged: true`，用途確認不得代替來源設定確認。目標群組有資產授權、審核方或申請人範圍時，未確認回 409 `MAPPING_USAGE_ACK_REQUIRED`，`meta.usage` 分別列出 `asset_authorizations`、`approver_scopes`、`requester_scopes`；確認後送 `risk_acknowledged: true`。

`GET /user-group-usage/:userGroupId` 回上述三種用途實數。`GET /external-groups` 回來源內的共用群組字典；`PUT /external-groups/:externalGroupId` 以 `{ "note": "顯示名稱" }` 更新選填的 200 字備註，兩類規則同步顯示。字典不存在回 `EXTERNAL_GROUP_NOT_FOUND`，過長回 `VALIDATION_EXTERNAL_GROUP_NOTE_TOO_LONG`。備註全文不進通用請求稽核欄，獨立稽核只記前後長度。

使用者群組成員 GET 分列 `manual_user_ids`、`mapped_user_ids`、`member_sources`；PUT 帶 `manual_user_ids` 只替換手動成員。舊 `user_ids` 仍可送，代表期望有效全集，不會把僅由映射支持的成員轉為手動。LDAP 與 OIDC 已知群組觀測均在登入交易重算本來源兩類支持；未知與未設定依上方「有界重新驗證」在時限內保留既有支持並留痕、超過時限收回。停用規則或來源即時收回該規則或來源的支持，仍有其他支持的有效權限保留。

---

## 儀表板 API

兩組唯讀路由，供儀表板逐卡取值與新版說明卡使用。兩者都不改任何狀態；自動化主體（agent token）都不放行，回 `403` `AUTH_AGENT_FORBIDDEN_ROUTE`。

### 逐卡資料（`GET /dashboard/cards/:key`）

```
GET /api/v1/dashboard/cards/:key
Authorization: Bearer <token>
```

每次只回一張卡。路由登錄只要求已登入，但**登入本身不足以讀取卡片資料**：每張卡要什麼能力，由卡片登錄表在 handler 內逐卡裁決。對象取自 token，路徑上只有 `key` 一個參數。順序是：`key` 在登錄內 → 該卡的裁決 → 取值。`key` 不在登錄內回 `400` `VALIDATION_BAD_PARAMS`；未登錄的 `key` 一律拒絕，不以「持有任一管理能力」兜底。

| `key` | 單位 | 誰能讀 | 值 | `filters`（跳轉後落點頁套用的查詢參數） |
|---|---|---|---|---|
| `assets` | `count` | `asset:view` | 主體可見的資產總數（與資產列表同一分支） | 無 |
| `my-connections` | `count` | 本人（只需登入） | 本人連線紀錄總數 | 無 |
| `my-pending-requests` | `count` | 本人（只需登入） | 本人 `pending` 申請的全量件數，不受「我的申請」列表筆數上限影響 | `status=pending` |
| `active-sessions` | `count` | `session:view` | 進行中連線數 | `status=active` |
| `today-sessions` | `count` | `session:view` | 今日開始的連線數 | `start_time`、`end_time` |
| `total-sessions` | `count` | `session:view` | 全部連線數 | 無 |
| `today-alerts` | `count` | `audit:view` | 今日告警數 | `start_time`、`end_time` |
| `recording-storage` | `bytes` | `audit:view` | 錄影佔用總量 | 無 |
| `pending-approvals` | `count` | 實際審核資格（見下） | 待審件數加待補審件數 | 無 |
| `unreviewed-alerts` | `count` | `audit:view` | 未審閱告警數 | `unreviewed=true` |
| `recording-failures` | `count` | `session:view` | 進行中連線裡錄影異常的件數 | `status=active`、`recording_error=true` |
| `last-access-review` | `days` | `audit:view` | 距上次存取複審的天數，從未複審為 `-1` | 無 |

- **回應**（`200`）：`{"key","value","unit","filters"}`。`pending-approvals` 另帶 `count`（一般待審）與 `review_count`（待補審），`value` 是兩者之和；`last-access-review` 另帶 `overdue`（從未複審或超過建議週期）與 `review_period_days`（目前為 180）。卡片回應只有值與落點篩選，不含資源名稱。
- **`filters` 與日界線**：`filters` 的鍵是落點頁讀取的查詢參數名。`status`（連線卡）、`start_time`、`end_time`、`unreviewed` 同時也是對應列表 API 讀取的參數；`my-pending-requests` 的 `status=pending` 與 `recording-failures` 的 `recording_error=true` 由落點頁取回後自行篩選，列表 API 不讀這兩個參數。今日的 `start_time`、`end_time` 是伺服器本地日的閉區間字串，固定六位微秒（結尾為 `23:59:59.999999`），前端原樣放進跳轉與列表請求，不經時間型別轉換。
- **實際審核資格**：`pending-approvals` 不看管理角色，而是即時查 DB 的審核者角色與審核方群組（與連線申請的審核端點同一判定）；`admin` 角色本身不構成審核資格。不是有效審核者回 `403` `AUTH_PERMISSION_DENIED`（單一形狀）。
- **能力不足**：能力卡回 `403` `AUTH_PERMISSION_DENIED`（單一形狀），回應不帶該卡所需的能力鍵；所需能力只進審計。
- **讀取失敗**回 `500`，不回部分值；碼沿該卡來源的既有碼：`assets` 為 `INTERNAL_ASSET_QUERY`，`my-connections` 為 `INTERNAL_MY_CONNECTION_QUERY`，`my-pending-requests` 為 `INTERNAL_ACCESS_REQUEST_MINE_QUERY`，三張連線數卡為 `INTERNAL_SESSION_ADMIN_QUERY`，`today-alerts` 與 `unreviewed-alerts` 為 `INTERNAL_COMMAND_ALERT_QUERY`，`recording-storage` 為 `INTERNAL_RECORDING_STATS_QUERY`，`recording-failures` 為 `INTERNAL_SESSION_ACTIVE_QUERY`，`last-access-review` 為 `INTERNAL_ACCESS_REVIEW_LAST_QUERY`；`pending-approvals` 的件數讀取為 `INTERNAL_ACCESS_REQUEST_PENDING_COUNT`，待補審件數為 `INTERNAL_BREAK_GLASS_REVIEW_COUNT`，審核資格查詢失敗為 `INTERNAL_APPROVER_QUERY`（角色查詢失敗為 `INTERNAL_ROLE_QUERY`）。
- **審計**：每次請求的審計資源依該卡的資料來源歸類（`assets`→`asset`，連線類→`session`，告警類→`command_alert`，`recording-storage`→`recording`，`pending-approvals`→`access_request`，`last-access-review`→`access_review`，兩張本人卡→`user` 且 `resource_id` 為本人）。分類先於裁決設定，被拒的請求同樣記在它想讀的資料類別上。

### 升級時的保留調整告知（`GET /dashboard/retention-adjustments`）

```
GET /api/v1/dashboard/retention-adjustments
Authorization: Bearer <token>
```

新版說明卡用它列出升級時被調整的保留天數，以及檢查點保留目前未涵蓋的資料保留項目。**權限**與 `GET /security-policies` 相同：需 `securitypolicy:manage`，缺少時回 `403` `AUTH_PERMISSION_DENIED`（單一形狀）。

**回應**（`200`，下例的數值僅示意形狀）：

```json
{
  "notice_version": "1.18.0",
  "items": [
    {"key": "retention_audit_log_days", "old_days": 3, "new_days": 7, "reason": "below_floor", "raised_at": "2026-10-19T03:00:00Z"}
  ],
  "uncovered": [
    {"data_key": "retention_recording_days", "data_days": 0, "checkpoint_days": 90}
  ]
}
```

- **`items`**：來自升級時啟動對帳寫下的抬升紀錄（見 DB_SCHEMA 第 72 節）。同一個鍵有多筆紀錄時只取最後一筆（依抬升時間，同時間依寫入序）；天數為整數；`reason` 為 `below_floor`（資料保留值低於下限）或 `cross_key_follow`（檢查點保留為保住原本成立的涵蓋關係而跟隨抬升）。不依紀錄的產品版本過濾。這是升級當下的**調整紀錄，不是目前設定值**。
- **`uncovered`**：依目前設定算出的未涵蓋關係，`data_days`、`checkpoint_days` 以 `0` 表示永久保留。
- 兩者都沒有內容時是 `200` 與兩個空陣列（`[]`，不是 `null`）。
- **讀取失敗**回 `500` `INTERNAL_COMPLIANCE_SNAPSHOT`，回應不含 `items`、`uncovered`，不回部分結果或舊資料；紀錄中有無法轉成天數的值同樣整體失敗。
- **審計**：資源歸 `security_policy`。

---

## 資產 API

> 需要登入；並掛細粒度權限（見各端點）。

**支援協議**（`protocol` 欄位）: `ssh` / `rdp` / `vnc` / `mysql` / `postgres` / `redis` / `mssql` / `k8s`

### 列表

```
GET /api/v1/assets
```

**權限**: `asset:view`

**可視範圍**: 非 admin/auditor 一律由伺服端收斂為該使用者的授權資產集合——個人授權與所屬使用者群組授權的聯集（各自含直授與資產分組授權，四路徑）、僅計入時效窗內授權，一般使用者的 `authorized_only` 參數被忽略；admin/auditor 見全量且參數仍可自查；持有節點範圍管理指派的範圍化主體預設見管理可視與連線可視的聯集，帶 `authorized_only=true` 時只回連線可視的資產（同一台資產的列內容與不帶參數時逐欄相同，範圍外歸屬仍只顯示計數）。授權分支的每筆 Asset 額外帶 `permission` 欄位（該資產最高授權等級 `view`/`connect` 兩階取高，已移除 `manage`）；管理角色回應不帶該欄。approver 的審核範圍另構成第三個可視來源（範圍內資產可見、不可連）。

**連線入口三態**: 非 admin/auditor 的授權分支每筆 Asset 由伺服端統一標註 `access_state`（`connectable`＝可直接連線／`reason_required`＝填理由即連／`approval_required`＝需核准／`pending`＝已有在途申請，另帶 `pending_request_id`），持有效臨時授權時帶 `ticket_date_expired`；破窗可用時另帶 `break_glass_available`（伺服端事實源，omitempty）。前端按鈕狀態零推導，一律以此欄為準；點擊後仍以連線簽發點的政策閘回應為最終裁決（按鈕過時會被 403 自癒）。

**Query 參數**:
| 參數 | 類型 | 說明 |
|------|------|------|
| `search` | string | 名稱/主機搜尋 |
| `protocol` | string | 協議過濾 |
| `active` | bool | 啟用狀態 |
| `authorized_only` | bool | 僅顯示已授權資產。admin/auditor 可自查；範圍化主體帶此參數時只回連線可視（不帶時為管理可視與連線可視的聯集）；一般使用者恆強制授權範圍，參數不改變結果 |
| `node_id` | int | 節點過濾（僅列掛該節點的資產；兩分支皆生效） |
| `include_subtree` | bool | 含子樹（預設 true；顯式 `false` 僅直掛） |
| `ungrouped` | bool | 僅列未掛載任何節點的資產 |
| `tags` | string | 標籤篩選（逗號分隔多值 AND；整詞比對、大小寫不敏感、`%`/`_`/`\` 跳脫不作萬用字元；空 token 丟棄、超 20 個 400；**僅 admin/auditor 與範圍化檢視者**——其他非特權角色帶此參數 400，不靜默忽略；範圍化檢視者的篩選見下節） |
| `credential_pending` | bool | `true`＝只列待配憑證資產（沒有任何未刪除的掛載列）；**僅 admin/auditor**——非特權角色帶此參數回 400 `VALIDATION_BAD_PARAMS`，不靜默忽略 |
| `page` | int | 頁碼（從 1 開始，預設 1） |
| `page_size` | int | 每頁數量（預設 20） |

**回應** (200): `{"data": [Asset], "total": N, "page": 1, "page_size": 20}`（兩分支同格式，篩選與分頁在授權分支同樣生效）

**待配憑證**：兩分支的每筆 Asset 皆帶唯讀推導欄 `credential_pending`（bool）——該資產沒有任何未刪除的掛載列時為 `true`，
不落庫、以一次批次存在查詢填入。待配憑證資產的連線、撥測、檔案傳輸一律以既有的「無可用帳號」語義拒絕；
於資產編輯掛上共用憑證或建立專用帳號後即恢復為 `false`。建立回應同樣帶此欄；`GET /assets/:id` 不填（恆為 `false`）。

### 範圍化檢視者的資產回應與寫入

「範圍化檢視者」是持有任一經**節點範圍指派**（直接或經使用者群組）取得的資產或資產帳號權限點的主體，不論該指派的節點目前是否仍存在；節點管理權限點（`assetgroup:manage`）不計入這個判定。下列欄位與規則只對範圍化檢視者出現或生效；只持全域指派、超級管理者、稽核員、一般使用者與 agent 且沒有任何節點範圍指派的主體，資產路由的回應鍵集與行為不變。這個標記只決定回應是否帶上呈現欄位，不授予任何能力，也不決定任何操作的範圍。

**可視來源與聯集**：列表為「連線可視」（現行授權集合）與「管理可視」（`asset:view` 的節點範圍涵蓋該資產的任一歸屬節點）的聯集，同一資產只出現一次。搜尋、協定、啟用狀態、節點與 `credential_pending` 篩選先套用，再計 `total` 與分頁。範圍化檢視者可使用 `credential_pending` 與 `tags` 篩選；`tags` 篩選疊加在上述聯集上，於計 `total` 與分頁之前生效，只比對聯集內資產自己的標籤，語義（逗號分隔 AND、整詞、大小寫不敏感、20 項上限）與全域主體相同。其他非 admin/auditor 主體帶 `tags` 仍回 400。只經管理可視的列以資產列為底，帶 `credential_pending`，不帶 `permission`、`access_state` 等連線欄位；只經連線可視的列欄位不變。

**列表與詳情新增欄位**:
| 欄位 | 位置 | 說明 |
|------|------|------|
| `actions` | 每列、詳情 | 物件，鍵固定為 `edit`、`disable`、`delete`、`test_connection`、`manage_accounts`；值 `{"allowed": bool, "reason"?: string, "count"?: int}`。`reason` 取 `no_capability`（沒有含該權限點的有效指派）、`out_of_scope`（有該能力，但範圍不涵蓋這筆資產）、`out_of_scope_nodes`（刪除或停用被範圍外歸屬擋下，帶 `count`）。旗標只決定畫面，每個寫入端點仍自行裁決 |
| `out_of_scope_node_count` | 經管理可視的列、詳情 | 範圍外歸屬數（以 `asset:view` 的管理範圍計）；只有數字，不含範圍外節點的識別碼、名稱或路徑。只經連線可視的列不帶 |
| `node_ids`、`node_paths` | 經管理可視的列、詳情 | 只含範圍內歸屬（`node_paths` 含定位用的祖先名稱）；範圍內沒有歸屬時兩鍵省略 |
| `management_scope` | 列表頂層 | `{"effective_node_count": N, "inactive_node_count": N, "nodes": [{"id": N, "path": "..."}]}`：該主體節點範圍指派所指定的範圍節點本身（不展開其子節點；節點去重），仍存在者計入 `effective_node_count` 並列於 `nodes`（依 `path`、再依 `id` 升冪），已刪除者只計入 `inactive_node_count`，不帶名稱 |

`actions.disable.count` 與 `actions.delete.count` 各依 `asset:update`、`asset:delete` 的範圍計算，與 `out_of_scope_node_count` 不必相等。持有全域檢視捷徑的主體另帶標記時，`out_of_scope_node_count` 恆為 0。

**範圍外同形**：對範圍化檢視者，詳情端點遇到不在其管理或連線可視內的資產，回應與資產不存在相同（404），原因只進審計。寫入端點依該操作權限點的有效範圍判定：只以節點範圍指派持有該權限點的主體，遇到範圍外的資產得到與不存在相同的 404；持有該權限點全域指派的主體照現行可寫入。pod 清單對只經管理可視的資產另需 `asset:test` 涵蓋該資產；主機金鑰端點對這類資產只開放 `GET`。

**`node_ids` 的語義（`PUT /assets/:id`）**:
- 未送 `node_ids`：歸屬不變。不帶標記的主體送出時仍是整組取代。
- 範圍化主體送出集合 `R`：`R` 內每個節點都必須在其 `asset:update` 有效範圍內且存在（已刪除視同不存在），否則與 `NOTFOUND_ASSET_NODE` 同形回應、零變更。可被替換的部分是「現行歸屬 ∩ 該主體看得到的歸屬 ∩ `asset:update` 範圍」，其餘歸屬一律保留；新歸屬為 `R` 加上被保留的部分。送出遮蔽後的清單不會移除看不到的掛載。
- 重複識別碼會去重。

**建立與更新的成功回應**：範圍化主體的 `POST /assets` 與 `PUT /assets/:id` 成功回應，歸屬欄與詳情同一套規則：經管理可視的資產只含範圍內歸屬並附 `out_of_scope_node_count`；只經連線可視的資產照現行帶完整歸屬；憑全域指派寫入、但管理與連線皆不可視的資產（詳情對同一主體回 404），回應省略 `node_ids`／`node_paths`，`out_of_scope_node_count` 為全部歸屬數。回應不含範圍外節點的識別碼、名稱或路徑。

**建立與更新後的歸屬**：沒有全域 `asset:create` 的主體，`POST /assets` 的 `node_ids` 必須非空且全在 `asset:create` 的範圍內；沒有全域 `asset:update` 的主體，更新後的新歸屬為空即拒絕。兩者回 400 `RULE_ASSET_NODE_REQUIRED`，無參數。持有全域指派的主體照舊可建立與更新為未分組。

**刪除與停用**：沒有該權限點（刪除看 `asset:delete`，停用看 `asset:update`）全域指派的主體，若資產在該權限點範圍外仍有歸屬，回 409 `RULE_ASSET_HAS_OUT_OF_SCOPE_NODES`，參數只有 `count`（範圍外歸屬數）；主體可先把資產從自己範圍內的節點移出。請求帶 `active=false` 即視為停用並套用同一規則。未分組資產：持該權限點全域指派的主體（含超級管理者）維持現行行為，照常刪除或停用並照常審計；只持節點範圍指派的主體對未分組資產得到與不存在相同的 404。

**審計**：資產建立時的初始掛載與歸屬變更使用既有的掛載審計列，其 `details` 多附 `topology_coverage`（加入與移出的節點，以及因此新增或失去節點授權涵蓋的主體與受影響的管理範圍指派摘要；僅識別碼，每個清單最多 100 項並附總數）；這項記錄適用所有操作者，不阻擋任何加掛。批次匯入的初始掛載只在 `asset:create` 只經節點範圍持有的操作者時附這項記錄（見「批次新增」的範圍化主體逐列判定）。

### 標籤清單與治理

```
GET  /api/v1/assets/tags          標籤清單（admin/auditor 取全庫；範圍化檢視者只取其可視資產上的標籤；其他主體 403——全表彙整會洩漏未授權資產的標籤詞彙）
POST /api/v1/assets/tags/rename   全面改名/合併（超級管理員保留；其餘主體 403）
POST /api/v1/assets/tags/delete   全面刪除（超級管理員保留；其餘主體 403）
```

**清單回應** (200): `{"data": [{"name": "生產", "count": 2}]}`——全表動態彙整（無獨立 tag 表）、canonical 去重（NFC＋大小寫折疊，保首見書寫形）、升冪排序、附使用資產數；供資產頁篩選下拉、表單自動完成與治理介面共用。

**範圍化檢視者的投影**：只彙整其可視資產（與同一主體不帶篩選的資產列表同一聯集）的標籤；去重與首見書寫形都只依這些資產，`count` 只計這些資產，看不到的資產上的標籤詞彙不會出現。admin/auditor 的回應不變。

**改名請求**: `{"from": "DbA標籤", "to": "DBA"}` → `{"affected": N}`。to 與既有標籤 canonical 相等即為合併（歸一至既有書寫形、逐資產去重）；套用至所有含 from 的資產、單一交易、逐資產留操作者稽核。to 驗證：非空、不含逗號、≤64 字元（違規 400）。

**刪除請求**: `{"name": "廢棄"}` → `{"affected": N}`——自所有資產移除該標籤，其餘標籤不動。

**標籤儲存正規化**：Create/Update 與批次新增（預檢與提交）時伺服端正規化（trim/去空/canonical 去重保序/歸一至歸一參照內的既有書寫形）。批次加標籤的請求標籤是陣列，先逐項驗證（空白項、含逗號的項不會被略去或切分，而是整批回 400，見「批次操作」），通過後同樣 trim、canonical 去重並歸一。歸一參照是呼叫者看得到的標籤字典：admin/auditor 與其他非範圍化主體為全庫；範圍化檢視者為其可視資產上的標籤，因此寫入範圍外才有的書寫形時不會被歸一到它，回應也與寫入全新標籤同形。同一次請求內 canonical 相同的新標籤以請求內首見的書寫形為準。文法上限：單項 ≤64 字元、每資產 ≤20 項、序列化總長 ≤500（違規 400）。存量資料由 migration `20260722_normalize_asset_tags` 一次性清洗（冪等、不動 updated_at）。

**Asset 主要欄位**（密文欄位 `password_enc`/`private_key_enc`/`sftp_password_enc` 永不輸出）:
```json
{
  "id": 1,
  "name": "Production Server",
  "protocol": "ssh",
  "host": "192.168.1.100",
  "port": 22,
  "username": "root",
  "has_password": true,
  "has_private_key": false,
  "description": "",
  "tags": "production,linux",
  "active": true,
  "node_ids": [1, 4],
  "node_paths": ["prod", "prod / kafka"],
  "access_policy": "approval",
  "created_by": 1,
  "last_test_status": "reachable",
  "last_test_at": "2026-06-30T00:00:00Z",
  "last_test_latency_ms": 12,
  "db_name": "",
  "db_tls_mode": "",
  "allowed_databases": [],
  "k8s_namespace": "",
  "k8s_insecure_skip_tls": false,
  "sftp_enabled": false,
  "sftp_port": 22,
  "sftp_username": "",
  "has_sftp_password": false,
  "rotation_channel": "",
  "effective_rotation_channel": "posix_ssh",
  "has_winrm_ca_cert": false,
  "created_at": "2026-01-01T00:00:00Z",
  "updated_at": "2026-01-01T00:00:00Z"
}
```

`winrm_scheme`／`winrm_port`／`winrm_tls_mode`／`rotation_ssh_port` 為 omitempty，設了才出現；`winrm_ca_cert` 只在
`GET /assets/:id` 出現（供編輯表單回填），列表與建立／更新的回應一律抹去本體、以 `has_winrm_ca_cert` 代之。列表每筆另帶 `transmission_risks`
（omitempty，`[{key, label}]`）＝該資產的傳輸風險項，含連線通道與改密通道兩者的風險鍵（見傳輸安全 API）。

### 批次操作

```
POST /api/v1/assets/batch/move     批次搬移（asset:update）
POST /api/v1/assets/batch/tags     批次加標籤（asset:update）
POST /api/v1/assets/batch/delete   批次刪除（asset:delete）
```

**請求本文**:
| 路由 | 本文 |
|------|------|
| `batch/move` | `{"asset_ids": [1, 2], "target_node_id": 7}` |
| `batch/tags` | `{"asset_ids": [1, 2], "tags": ["生產"]}` |
| `batch/delete` | `{"asset_ids": [1, 2]}` |

`asset_ids` 去重後至少一筆。後端**不設筆數上限**；經內建前端代理送達時，請求本文受該代理的本文大小上限約束（預設 1 MiB，約十萬筆識別碼的量級），超過即回 413、不會送到後端。下列情形回 400 `VALIDATION_BAD_PARAMS`：本文無法解析、`asset_ids` 去重後為空、`batch/move` 的 `target_node_id` 缺少或為 0、`batch/tags` 的 `tags` 為空陣列。`tags` 逐項驗證，任一項不合即整批回 400、不執行：空白項回 `VALIDATION_TAG_EMPTY`，含逗號回 `VALIDATION_TAG_CONTAINS_COMMA`，超過 64 字元回 `VALIDATION_TAG_TOO_LONG`。這與標籤改名的 `to` 是同一套驗證；單筆更新收的是逗號分隔字串、空項直接略去，兩者不同。

**成功** (200): `{"data": {"affected": N, "unchanged": M}}`——實際改變的筆數，與本來就已是目標狀態的筆數。

**整批原子**：整批在單一交易內執行，交易一開始先取拓撲序列化點，再逐筆判定主體對每一台資產的能力與範圍。任何一台無法操作，整批都不執行，所有資產的歸屬、標籤與存在與否都與請求前相同。沒有「部分成功」。

**錯誤**:
| 情形 | 回應 |
|------|------|
| 主體沒有任何含該權限點的有效指派（含交易內被撤銷） | 403 單一 forbidden，不看 `asset_ids` |
| 有一筆以上對該主體無法操作：不存在、在其範圍外、或沒有該權限點涵蓋 | 404 `NOTFOUND_BATCH_ITEMS_UNAVAILABLE`，參數只有 `count`（無法操作的筆數）。三種原因不可區分，回應不含任何資產或節點的識別碼或名稱 |
| 批次刪除時，有資產在該主體的刪除範圍外仍有歸屬 | 409 `RULE_ASSET_BATCH_HAS_OUT_OF_SCOPE_NODES`，參數只有 `count`（受阻的資產台數，每台算一次，不是範圍外歸屬數）；規則與單筆刪除相同，持有全域刪除指派的主體不受影響 |
| 搬移的目的節點不存在或在 `asset:update` 範圍外 | 與單筆更新相同的 `NOTFOUND_ASSET_NODE`，兩種情形同形 |

**判定順序**：路由閘的 403 最先（沒有含該權限點的有效指派時不看本文）；其次是上述 400（本文與請求標籤的驗證都在交易之前）；進入交易後，重讀主體的能力拒絕（403）、逐筆判定的 404 `NOTFOUND_BATCH_ITEMS_UNAVAILABLE`、批次刪除的 409 依序判定，搬移的目的節點（404 `NOTFOUND_ASSET_NODE`）在逐筆判定之後，加標籤的每資產上限（400）在逐筆判定之後。同一請求同時含無法操作的資產與受阻的資產時，只回 404。

**搬移語義**：每台資產的新歸屬是「目的節點」加上該主體看不到或不在 `asset:update` 範圍內的既有歸屬，與單筆 `PUT /assets/:id` 送出 `node_ids=[目的]` 的結果相同；全域主體搬移後只剩目的節點。新歸屬與既有歸屬完全相同的資產才計入 `unchanged`；已掛在目的節點、但同時掛在可被替換的其他節點上的資產，會被移出那些節點並計入 `affected`。

**加標籤語義**：每台資產的標籤為既有標籤與請求標籤的聯集，書寫經上節的歸一參照；任何一台超過標籤文法上限則整批以既有的標籤驗證碼失敗。

**審計**：每台被改變的資產寫一列資產變更審計，與單筆同一 action 與資源，`details` 多附 `batch_id`（同一請求共用）與 `batch_size`（去重後筆數）；搬移的審計列與單筆一樣附 `topology_coverage`。批次刪除每台被刪除的資產有兩列 delete 審計：一列帶批次鍵，另一列是資產刪除本身寫出的刪除列（與單筆刪除相同、不帶批次鍵），兩者以 `batch_id` 區分。整批被拒絕時，只有請求層的一列審計，沒有逐台的資產變更列；該列 `details` 不含資產或節點識別碼，請求本文則照常記錄（含呼叫方送出的 `asset_ids`）。

### 創建

```
POST /api/v1/assets
```

**權限**: `asset:create`

**請求**（`CreateAssetRequest`）:
```json
{
  "name": "Production Server",
  "protocol": "ssh",
  "host": "192.168.1.100",
  "port": 22,
  "username": "root",
  "password": "secret123",
  "private_key": "",
  "description": "Main production server",
  "tags": "production,linux",
  "node_ids": [1, 4],
  "access_policy": "",
  "rdp_security": "",
  "rdp_verify_cert": false,
  "db_name": "",
  "db_tls_mode": "",
  "db_ca_cert": "",
  "allowed_databases": [],
  "k8s_namespace": "",
  "k8s_pod": "",
  "k8s_container": "",
  "k8s_ca_cert": "",
  "k8s_insecure_skip_tls": false,
  "sftp_enabled": false,
  "sftp_port": 22,
  "sftp_username": "",
  "sftp_password": "",
  "rotation_channel": "",
  "winrm_scheme": "",
  "winrm_port": 0,
  "winrm_tls_mode": "",
  "winrm_ca_cert": "",
  "rotation_ssh_port": 0
}
```

**登入憑證來源二擇一**（**BREAKING**）：頂層的 `username`／`password`／`private_key`
是「這台專用」的簡寫形式，等價的完整寫法是內嵌 `"credential": {…}` 物件；要改掛既有共用憑證
則改帶 `"credential_id": <憑證識別>`，此時建出來的預設掛載指向該憑證、就位版本為它當下的現行版本，
**建資產不對目標主機寫入任何秘密**。兩種來源同時出現回 400 `VALIDATION_CREDENTIAL_SOURCE_AMBIGUOUS`；
指定的憑證不是共用範圍回 409 `RULE_CREDENTIAL_DEDICATED_SINGLE_BINDING`；改密進行中回 409
`RULE_CREDENTIAL_ROTATION_ACTIVE`；帶已移除的 `copy_from_account_id` 回 400
`VALIDATION_ACCOUNT_COPY_FROM_REMOVED`。直填的私鑰（頂層或內嵌）無法解析為可用的簽章金鑰時
（格式錯誤、內容不完整、貼成公鑰、設有 passphrase）回 400 `VALIDATION_CREDENTIAL_PRIVATE_KEY_INVALID`，
不建立任何資料列；此碼的回應頂層另帶 `"field": "private_key"`（資產帳號、憑證庫入口同），供表單把錯誤標在私鑰欄；系統不支援設有 passphrase 的私鑰。判準與 SSH 連線所用的解析相同。
`PUT /assets/:id` 帶非空 `private_key` 時同樣檢查並回同一碼；未帶或空字串＝沿用現行私鑰，不重驗。
認證類型 `auth_method` **不在本端點的請求上**，
要設定它請走資產帳號端點 `POST /assets/:id/accounts`。掛載列的語義見「資產帳號（憑證掛載列）」。

**協議別驗證**:
- `username`：有登入秘密時必填於 ssh/rdp/mysql/postgres/mssql（缺則 400 `VALIDATION_ASSET_USERNAME_REQUIRED`）；vnc/redis/k8s 僅密碼（K8s 為 Bearer Token，走 `password` 欄加密儲存）。
  掛既有共用憑證時，帳號名取自該憑證，不必也不得在頂層另給。**完全沒有憑證來源**（`credential_id`、內嵌 `credential`、
  頂層 `username`／`password`／`private_key` 皆空）時任何協定皆可建立，結果為零掛載的待配憑證資產
- mssql 的 `host` **不得含逗號**（`-S host,port` 的分隔語義），違反回 `VALIDATION_ASSET_MSSQL_HOST_COMMA`
- `protocol=k8s` 時 `k8s_namespace` 必填（連線時選 pod；`k8s_pod`/`k8s_container` 為相容舊資料的選填）
- `db_name` 僅 mysql/postgres/redis/mssql 有意義（空＝連預設庫）；`db_tls_mode`: `''`/`disable`/`require`/`verify-ca`/`verify-full`
- `db_ca_cert` 對 mysql/postgres/redis 為 **CA bundle**；對 **mssql 為伺服器憑證釘選**（sqlcmd `-J`），語義不同，UI 另有說明文字
- `allowed_databases`: 查詢主控台的執行目標限制清單（字串陣列，選填，空＝不限制）；僅
  mysql/postgres/mssql 可為非空，其餘協議帶非空值 400；每項 1–128 字元、不含控制字元、
  不重複，至多 64 項；違反任一條回 `VALIDATION_ASSET_ALLOWED_DATABASES`。**不做正規化**
  （不 trim、不折大小寫），寫入什麼即比對什麼。Update 為指標欄位：省略＝不動、空陣列＝
  清空；**協議由三者之一改為其他協議時，伺服端一律清空本欄**（不論該次請求是否帶
  `allowed_databases`），並將清空事實與清空前的項數記入該次更新稽核
- `sftp_*` 僅 vnc 有意義（SFTP 側車檔案傳輸，選配）：`sftp_enabled=true` 時 `sftp_username` 必填、`sftp_port` 預設 22；`sftp_password` 後端 AES-256-GCM 加密存放，回應僅 `has_sftp_password` 布林；Update 時 `sftp_password` 空字串＝沿用既有
- `access_policy`: `open`（不需申請）/ `reason`（填理由即連）/ `approval`（需核准）；非法值 400。Create 空字串或省略＝NULL（繼承全域預設鍵 `access_policy_default`）；Update 為指標欄位——省略＝不動、空字串＝清除覆寫回 NULL（非沿用既有）；變更經 asset hooks 入稽核
- `node_ids`: 掛載節點 id 集（多歸屬；節點須存在否則 400）。Create 空/省略＝未分組；Update 省略（null）＝不動、空陣列＝清空全部掛載；成員變更以 `node_ids` 舊→新入稽核。回應恆帶 `node_ids`＋`node_paths`（全路徑顯示）
- `rotation_channel`：改密通道（僅 ssh／rdp 資產有意義）。值域：`''`（未設定，依協定推導：ssh→`posix_ssh`，其餘→`none`）／
  `posix_ssh`（限 ssh）／`windows_winrm`（限 rdp 或 ssh）／`windows_ssh`（限 rdp 或 ssh）／`none`（顯式不改密）；
  值域外或與協定不相容回 400 `VALIDATION_ASSET_ROTATION_CHANNEL`。
  `windows_winrm` 的附屬欄：`winrm_scheme`（`http`／`https`，必填）、`winrm_port`（0＝依 scheme 取 5985／5986）、
  `winrm_tls_mode`（僅 https：`system`＝作業系統信任錨／`ca`＝只信任上傳的 CA／`insecure`＝不驗證；https 必填，http 不得帶值）、
  `winrm_ca_cert`（僅 `ca` 模式，須為可解析的 PEM 憑證，儲存時即驗）。`windows_ssh` 的附屬欄：`rotation_ssh_port`
  （rdp 資產的目標 SSH 埠，0＝22；ssh 資產沿資產 `port`，本欄不參與）。兩個埠須為 0 或 1–65535。
  附屬欄不合回 400 `VALIDATION_ASSET_ROTATION_CHANNEL_PARAMS`。驗證以套用後的最終資產為準（協定與通道同次變動時一併檢查）。
  Update 為指標欄位：省略＝不動、`""`／0＝清回推導；**協定改為與通道不相容時，伺服端一律清空通道與全部附屬欄**
  （不論該次請求是否帶這些欄），並將清空事實與清空前的通道值記入該次更新稽核
  （`rotation_channel_cleared`、`previous_rotation_channel`）。
  回應恆帶 `effective_rotation_channel`（推導後的有效通道）與 `has_winrm_ca_cert`，兩者以該次請求套用後的值計算；
  **列表、建立與更新的回應都不回 `winrm_ca_cert` 本體**，只有 `GET /assets/:id` 回傳（供編輯表單回填）。改密的執行語義見改密 API。

**回應** (201): Asset JSON。**錯誤**: 400 協議無效、409 名稱重複。

**欄位級能力**: 路由本身的資產寫入能力之外，下列欄位的「實際變更」另需能力；缺任一即整筆拒絕（403 `AUTH_PERMISSION_DENIED`，單一形狀，任何欄位能力拒絕皆不回權限名），資產、帳號與憑證皆不寫入，也不產生成功變更的審計；請求層照一般拒絕規則留下一筆 `denied` 的審計紀錄。

| 欄位 | 建立（`POST /assets`） | 更新（`PUT /assets/:id`） |
|---|---|---|
| `username`、`sftp_username` | `credential:create` 或全域 `credential:manage` | `credential:update` 或全域 `credential:manage` |
| `sftp_password` | `credential:create` 或全域 `credential:manage` | `credential:set-secret` 或全域 `credential:manage` |
| `password`、`private_key` | `credential:create`（全域 `credential:manage` 只滿足欄位條件，仍需 `credential:create`） | `credential:set-secret`（全域 `credential:manage` 只滿足欄位條件，仍需 `credential:set-secret`） |
| `credential`（內嵌物件） | `credential:create` 或全域 `credential:manage`；物件內帶密碼或私鑰時需 `credential:create` | 更新請求沒有這欄 |
| `credential_id`（掛既有共用憑證） | `credential:bind` | 更新請求沒有這欄 |
| `access_policy`（單台連線政策覆寫） | 非空值另需 `access_policy:manage` | 本文出現此鍵即需 `access_policy:manage`（含清除用的空字串，不論值是否相同）；見下段 |

**`PUT /assets/:id` 的兩條欄位條件**: 此路由的登錄基本要求是僅需登入，能力由請求本文的頂層鍵決定，判定是 handler 的第一步，先於路徑參數驗證、資產查詢與本文綁定。本文只含 `access_policy` 一個頂層鍵時，只需 `access_policy:manage`，不需 `asset:update`；本文含其他任何頂層鍵（未知鍵也算）、為空或無法解析時，需 `asset:update`；本文出現 `access_policy` 鍵者另需 `access_policy:manage`。兩個權限點都沒有時一律 403 `AUTH_PERMISSION_DENIED`（單一形狀，所缺的權限點只進審計），與原守衛同序（資產 ID 不存在也是 403，不是 404）；只缺其中之一時同樣回此 403，審計記所缺的那一個。持 `access_policy:manage` 不能修改全系統預設（`access_policy_default` 仍由安全政策端點的設定能力判定）。單台覆寫使有效段位下降時，同一交易內寫入資產變更審計與 `access_policy_relaxed` 系統告警，任一寫入失敗整筆回滾；匯入（預檢與正式）任一列 `access_policy` 非空而無此權限點時整批拒絕（403），不逐列標欄。

**憑證欄位的語義能力與相容能力**: 上表的帳號與秘密欄位依路由登錄的欄位條件判定，持有該欄的憑證語義能力，或全域持有 `credential:manage`，任一即滿足欄位條件。`credential:manage` 是相容能力，只在全域持有時生效，經節點範圍指派持有它不算數。欄位條件只判定主體有沒有這項能力，範圍由服務在寫入交易內、資產寫入範圍判定之後以目標判定：

- 持有全域 `credential:manage` 的主體，這些欄位一律視為經相容能力通過（即使另持語義能力），帳號名稱、內嵌憑證的帳號名稱與 SFTP 欄位不另判語義能力，與只要求 `credential:manage` 時的行為相同。
- 未持全域 `credential:manage`、經語義能力通過時，以目標判定該語義能力。新增資產以請求送出的 `node_ids` 為目標：每個節點都須在該主體 `credential:create` 的範圍內，任一節點不涵蓋即整筆拒絕；省略 `node_ids` 或送空陣列時沒有節點可涵蓋，只有全域持有 `credential:create` 者能通過。更新資產以這台資產為目標：`username`、`sftp_username` 判 `credential:update`，`sftp_password` 判 `credential:set-secret`。
- 登入密碼與私鑰（含內嵌憑證所帶者）不論經哪一種能力滿足欄位條件，都另需語義能力：建立需 `credential:create`，在寫入交易內以送出的節點為目標，規則同上；更新需 `credential:set-secret`，見下文。

拒絕沿用既有回應形狀，任一拒絕皆零寫入：主體既沒有該欄的語義能力也沒有全域 `credential:manage`（含只經節點範圍指派持有 `credential:manage`），回 403 `AUTH_PERMISSION_DENIED`；目標資產或送出的節點在主體的資產寫入範圍外、不存在或已刪除，回與不存在同形的回應；目標在資產寫入範圍內、卻不在該語義能力的範圍內（含多個送出節點中的任一個），同樣回與該資產或節點不存在同形的 404，不回 403；新增資產省略 `node_ids` 或送空陣列，而 `credential:create` 只有節點範圍來源，回 403 `AUTH_PERMISSION_DENIED`。

欄位條件在寫入前判定：更新在載入目標之後判一次、交易內以重讀的列再判一次；建立在載入任何資料之前判一次，結果帶入寫入交易。更新帶入非空的 `password` 或 `private_key` 時，寫入預設帳號所引用的憑證之前，另於同一交易以資料庫現況重新解析操作者的能力，以這台資產為目標判定 `credential:set-secret`（與憑證庫直接寫入密文同一道關卡）。建立時帶入的秘密會新建一份專用憑證，語意與憑證庫直接建立相同，故判定 `credential:create`（改既有憑證秘密的 `credential:set-secret` 只用於更新）；`credential:create` 與 `credential:bind` 在載入所指憑證之前判一次（無權者拿不到「憑證不存在」與「無權」的差別），寫入交易內以實際組裝出的憑證來源再判一次（建立專用憑證時以送出的節點為目標）。更新時 `username`、`sftp_username` 與現值相同、秘密欄位為空字串（沿用既有）不算變更。`POST /assets/import`、`POST /assets/import/preview` 有兩類欄位能力限制：任一列帶非零 `credential_id`，需 `credential:bind`（與憑證掛載端點同一能力）；任一列 `access_policy` 去除前後空白後非空，需 `access_policy:manage`。缺任一所需能力即整批拒絕（預檢同樣回 403，提交時重判，不以預檢結果為授權票）。伺服器自有欄位（如 `created_by`、`last_test_status`）即使夾帶也不被採用。

**`access_policy:manage` 的範圍**: 這個權限點的節點範圍指派會生效。範圍只依這個權限點本身的有效指派計算，經節點範圍持有的 `asset:view`、`asset:update`、`asset:create` 或連線授權都不改變它。持有全域指派的主體與超級管理者不受範圍限縮，下列規則對他們不適用，回應不變。只經節點範圍指派持有這個權限點的主體：

- **更新**（`PUT /assets/:id` 本文帶 `access_policy` 鍵，含清除用的空字串）：資產至少有一個歸屬在這個權限點的範圍內才可寫入；否則回與資產不存在相同的 404 `NOTFOUND_ASSET`，不寫入任何欄位、不產生告警，審計列為 `denied` 並以範圍拒絕分類記錄。這項判定先於欄位值驗證，送非法段位值到範圍外資產同樣回 404。請求同時帶其他欄位時，其他欄位所需權限點的範圍另行判定，任一不涵蓋即回 404；因此能編輯某台資產、但存取政策範圍不涵蓋它的主體，夾帶 `access_policy` 也得到 404，不帶則照常編輯。判定與寫入在同一交易內，交易的第一個動作是取拓撲序列化鎖，之後以交易當下的指派與節點樹判定。`access_policy` 為 `null` 視同帶這個鍵，照同一範圍判定，但不改變覆寫值。本文只含 `access_policy` 時，成功回應是該資產在「單台連線政策覆寫清單」中的同一列（`node_ids`／`node_paths` 只含這個權限點範圍內的歸屬，並附 `out_of_scope_node_count`），不是詳情形狀。
- **建立**（`POST /assets` 帶非空 `access_policy`）：`node_ids` 至少一個須在這個權限點的範圍內，`node_ids` 為空也算不符；不符時整筆拒絕、零寫入，回應與不持這個權限點者帶覆寫相同（403 `AUTH_PERMISSION_DENIED`）。目的節點本身另依 `asset:create` 的範圍判定（見「範圍化檢視者的資產回應與寫入」），先於這一條。
- **匯入**（`POST /assets/import/preview` 與 `POST /assets/import`）：節點欄已解析成功、且帶非空 `access_policy` 的列，目的節點至少一個須在這個權限點的範圍內。任一列不符時，預檢與正式匯入都整批回 403 `AUTH_PERMISSION_DENIED`，與不持這個權限點者匯入同一批的回應相同，不含逐列結果，零列寫入；這項拒絕先於逐列錯誤回報。正式匯入在交易內以交易當下的指派與節點樹再判一次，不採信預檢結果。
- **降級與全系統預設**：範圍內的變更照「`PUT /assets/:id` 的兩條欄位條件」一段的規則判定降級，降級時同一交易寫入資產變更審計與 `access_policy_relaxed` 系統告警。不論範圍，這個權限點都不能修改 `access_policy_default`。

> 節點範圍指派可經 `PUT /users/:id/roles` 與 `PUT /user-groups/:id/role-bindings` 的 `role_nodes` 寫入（見「用戶 API」的「節點範圍」）；上述範圍規則適用於這類指派。

### 單台連線政策覆寫清單

```
GET /api/v1/assets/access-policy-overrides
```

**權限**: `access_policy:manage`；不持者回 403 `AUTH_PERMISSION_DENIED`（只持 `asset:view` 也是）；agent 主體一律拒絕。唯讀。

**查詢參數**:

| 參數 | 預設 | 說明 |
|---|---|---|
| `overridden` | `true` | `true` 列出已設單台覆寫的資產；`false` 列出尚未覆寫、可加入覆寫的資產，此時須帶 `search`，`search` 為空回 200、`data: []`、`total: 0`。值無法解析為布林時回 400 `VALIDATION_BAD_PARAMS` |
| `search` | 空 | 去除前後空白後，比對資產名稱或主機。比對直接使用資料庫的模式比對，`%` 與 `_` 具萬用字元語義，不會被當成一般字元；大小寫比對受資料庫字元處理限制，不保證所有語系的大小寫等價 |
| `page` | 1 | 小於 1 以 1 計；不是整數時回 400 `VALIDATION_BAD_PARAMS` |
| `page_size` | 20 | 小於 1 以 20 計，大於 1000 以 1000 計；不是整數時回 400 `VALIDATION_BAD_PARAMS` |

**範圍**: 結果只依檢視者 `access_policy:manage` 的有效指派投影，投影在覆寫條件、搜尋、計數與分頁之前套用。經節點範圍持有的資產檢視、資產編輯與連線授權都不擴大結果，也不讓檢視者變成範圍化：全域持有這個權限點、另經節點範圍持有資產檢視的主體，在這裡仍得到全部資產與完整歸屬。超級管理者同樣不受範圍限縮。只經節點範圍指派持有者，只得到至少一個歸屬在範圍內的資產。

**回應** (200):

```json
{
  "data": [
    {"id": 4, "name": "db-1", "protocol": "ssh", "access_policy": "reason",
     "node_ids": [1], "node_paths": ["prod / db"], "out_of_scope_node_count": 2}
  ],
  "total": 1, "page": 1, "page_size": 20,
  "meta": {"global_default": "reason", "scoped": true}
}
```

- `access_policy`：單台覆寫段位（`open`／`reason`／`approval`）。這個鍵固定存在；未覆寫的列通常回 `null`，資料庫既有的空字串值回 `""`，兩者都代表沿用全系統預設。`overridden=false` 的列範例：

  ```json
  {"id": 7, "name": "db-2", "protocol": "ssh", "access_policy": null,
   "node_ids": [1], "node_paths": ["prod / db"], "out_of_scope_node_count": 0}
  ```

- `node_ids`、`node_paths`：歸屬清單只列在檢視者範圍內的節點，兩者同序，路徑以「 / 」分隔。完整路徑仍含定位用的祖先名稱，即使祖先在範圍外。
- `out_of_scope_node_count`：只在 `meta.scoped` 為 `true` 時每列都帶（含 0），值為該資產在範圍外的歸屬數；其他範圍外歸屬只提供這個數量，不含這些節點的識別碼、名稱或路徑（上一條所述路徑中的祖先名稱除外）。其他檢視者的列沒有這個鍵。
- `total`：投影與篩選後、分頁前的筆數。排序依名稱、再依 `id` 升冪。
- `meta.global_default`：目前已儲存的全系統預設段位（`access_policy_default`），只供顯示；修改仍經安全政策端點並需 `securitypolicy:manage`。
- `meta.scoped`：檢視者是否只經節點範圍指派持有 `access_policy:manage`；只依這個權限點判定。

列內修改沿用 `PUT /assets/:id`、本文只送 `access_policy`，範圍規則見上一節的「`access_policy:manage` 的範圍」。

### 批次新增（預檢與整批建立）

```
POST /api/v1/assets/import/preview   （唯讀預檢）
POST /api/v1/assets/import           （整批建立）
```

**權限**: `asset:create`；agent 主體一律拒絕。兩端點的逐列規則同一套，預檢與寫入呼叫同一個驗證函式，
每列最後再走一次單筆建立的規則——批次不另立較寬或較嚴的建立條件（唯一例外見下方「不適用欄」）。

**預檢請求**（本文上限 1 MiB、資料列上限 500）：
- `Content-Type: text/csv`：CSV 原文。編碼須為 UTF-8（檔首 BOM 可有可無），非 UTF-8 整份拒收、不猜編碼；
  逗號分隔、RFC 4180 雙引號；第 1 列為表頭，比對時去前後空白、不分大小寫、容欄名前綴 `*`（範本以 `*` 標必填）；
  全空列略過；列號採 Excel 列號：表頭＝第 1 列，之後每筆記錄（含全空列）各佔一列，儲存格內換行不另計。欄名即下表 13 欄，
  `credential_id` 欄可帶一個前置 `#`，`nodes` 欄以 `;` 分隔多個節點全路徑。
- `Content-Type: application/json`：`{"source": "csv" | "form", "rows": [ImportRow]}`；`source` 省略＝`form`，只用於稽核標記。

**ImportRow**（未知欄位整批拒收）:
| 欄位 | 型別 | 規則 |
|------|------|------|
| `line` | int\|null | 畫面列號；null 時以陣列序（自 1 起）回報 |
| `name` | string | 必填；≤100 字元、不含控制字元；不得與既有資產或同批其他列同名 |
| `protocol` | string | 必填；`ssh`/`rdp`/`vnc`/`mysql`/`postgres`/`redis`/`mssql`/`k8s`，不分大小寫、存小寫 |
| `host` | string | 必填；≤255 字元、不含控制字元；mssql 不得含逗號 |
| `port` | int\|null | 1–65535；null＝協定預設埠（ssh 22、rdp 3389、vnc 5900、mysql 3306、postgres 5432、redis 6379、mssql 1433、k8s 6443） |
| `credential_id` | int\|null | 共用憑證編號（憑證主鍵）；null＝待配憑證，建出零掛載資產 |
| `tags` | string | 逗號分隔；先依全庫既有寫法、再依同批第一次出現的寫法歸一，最後套標籤上限 |
| `node_ids` | int[] | 節點 id |
| `node_paths` | string[] | 選填；以全路徑（層級以 ` / ` 分隔）指定節點，須完全比對唯一的既有節點。與 `node_ids` 同時帶時以路徑為準，且解析結果須與 `node_ids` 一致 |
| `description` | string | ≤500 字元 |
| `access_policy` | string | `open`/`reason`/`approval`；空＝跟隨全域預設 |
| `db_name` | string | 僅 mysql/postgres/redis/mssql；≤128 字元 |
| `k8s_namespace` | string | 僅 k8s，k8s 時必填 |
| `rdp_security` | string | 僅 rdp；空/`nla`/`tls`，須小寫 |
| `db_tls_mode` | string | 僅 mysql/postgres/redis/mssql；空/`disable`/`require`/`verify-ca`/`verify-full`，須小寫。驗證檔位不附 CA 允許（CSV 不收 PEM，CA 於匯入後在資產編輯中補；補上前連線在憑證驗證失敗，不會降級為不驗證） |

**不適用欄**：欄位不適用該列協定卻有值，回列錯誤 `VALIDATION_ASSET_IMPORT_FIELD_NOT_APPLICABLE`。單筆建立對此寬鬆（存了不生效），
批次刻意從嚴——試算表裡非適用欄出現值多半是整列錯欄或協定填錯，靜默忽略會讓使用者以為設了其實沒生效。

**不收秘密**：CSV 表頭或 JSON 列帶 `password`、`private_key`、`passphrase`、`secret`、`token`、`username`、`credential`
（或欄名含這些片段者）即整份 400 `VALIDATION_ASSET_IMPORT_SECRET_FIELD`，`params.column` 為欄名、不回顯值，不寫任何資料。
帳號名一律取自所指的共用憑證。

**預檢回應** (200，唯讀，只留一筆請求稽核):
```json
{
  "ok": false,
  "summary": { "total": 3, "valid": 1, "invalid": 2, "credential_pending": 1 },
  "rows": [
    {
      "index": 1, "line": 3,
      "values": { "line": 3, "name": "db-01", "protocol": "mysql", "host": "10.0.0.21", "port": null,
                  "credential_id": null, "tags": "", "node_ids": [], "description": "", "access_policy": "",
                  "db_name": "", "k8s_namespace": "", "rdp_security": "", "db_tls_mode": "" },
      "raw": { "port": "33o6" },
      "resolved": { "port_defaulted": false, "node_paths": [], "tags": "" },
      "errors": [ { "field": "port", "code": "VALIDATION_ASSET_IMPORT_PORT", "params": {} } ]
    }
  ]
}
```
- `values`：型別化後的值。埠留空時已代入協定預設埠，並以 `resolved.port_defaulted=true` 標示；CSV 中無法轉型的格（非整數的埠或憑證編號）在 `values` 為 null、原文放 `raw`。
- `resolved`：系統將如何解讀這一列——`credential`（所指憑證的 `id`／`name`／`username`，不含秘密；憑證存在且通過下述範圍判定時才有）、`node_paths`（節點解析後的全路徑，只含判定通過的節點）、`tags`（實際會落庫的寫法）。
- 同列多錯全部列出；`errors[].field` 為欄名（節點錯誤為 `nodes`），`code` 為機器碼、`params` 依碼而定（如同批重名帶 `other_line`、節點路徑帶 `path`、長度帶 `max`）。
- `summary.credential_pending` 計 `credential_id` 為 null 的列數（不論該列是否有錯）。

**寫入請求**：只收 `application/json`，形狀同預檢。以預檢回應每列的 `values` 送回，節點同時帶 `node_ids` 與 `node_paths`
（以選擇器指定節點的列，`node_paths` 取 `resolved.node_paths`）：帶路徑的列在交易內以當下全路徑重算比對，
預檢後節點被改名或搬移即整批不建立。

**範圍化主體的逐列判定**：節點與憑證各依自己的能力判定，節點看 `asset:create`，憑證看 `credential:bind`。該能力有任一全系統來源（或為超級管理者）者，該項照上述規則，回應不變；只經節點範圍持有者，預檢與寫入都另做下列判定：
- 節點：以 `node_paths` 指定而節點在範圍外者，與查無路徑同回列錯誤 `NOTFOUND_ASSET_IMPORT_NODE_PATH`，`params.path` 只帶該列填的路徑；以 `node_ids` 指定者，範圍外與不存在同回 `NOTFOUND_ASSET_NODE`。列未指定任何節點回 `RULE_ASSET_NODE_REQUIRED`（全系統持有者留空照舊建立未分組資產）。
- 憑證：所指憑證的歸屬不在範圍內（歸屬為全域也算）與憑證不存在同回 `NOTFOUND_CREDENTIAL`，且排在專用、協定族、改密中、未收斂四項檢查之前；此時該列不帶 `resolved.credential`。歸屬在範圍內的憑證照上述規則逐項檢查。
- 寫入時重判兩次。交易外逐列重驗（交易語義第 1 步）就發現不在範圍內的列，與其他列錯誤一樣回 400 `VALIDATION_ASSET_IMPORT_ROWS_INVALID`；通過交易外重驗、到交易內重算（第 2 步）才發現不在範圍內的列，整批回 409 `CONFLICT_ASSET_IMPORT_STATE_CHANGED`，該列不帶預檢時解析出的憑證名稱與節點路徑。
- 建立成功時，每台資產的節點掛載稽核附 `topology_coverage`，與單筆建立相同。

**交易語義**（無半成功）:
1. 交易外逐列完整重驗（與預檢同一函式）。預檢後才出現的同名資產等狀態變更若在此被發現，與其他列錯誤一樣回 400 `VALIDATION_ASSET_IMPORT_ROWS_INVALID`，回應另帶 `summary` 與 `rows`（與預檢同形的逐列報告），不開交易、零寫入。
2. 依固定順序持資產名稱鎖（與單筆建立、改名共用）與節點樹結構鎖，開**單一交易**；交易的第一個動作是取拓撲序列化鎖（與其他拓撲相關寫入共用同一把），之後重判欄位能力，並以交易當下的指派與節點樹重算下述逐列範圍判定，不採信預檢結果；再依憑證 id 遞增鎖定所指憑證列，逐列重驗名稱唯一、節點存在與路徑、憑證（存在、共用範圍、協定族相容、未在改密、上一輪已收斂），再寫入資產、預設掛載、帳號稽核、節點掛載與節點稽核。
3. 交易內重驗遇到競態 → 整筆回滾，409 `CONFLICT_ASSET_IMPORT_STATE_CHANGED`，`rows` 只含出事的列（列形狀同預檢，`errors` 標原因）。兩種回應皆零寫入；畫面皆回「檢查」步驟並標示錯誤列，供修正後重新檢查。
4. 成功 → 201 `{"created": 37, "credential_pending": 12, "asset_ids": [101, 102, …]}`。

**稽核**：每台資產各一筆建立稽核、掛共用憑證者另有帳號建立稽核、有節點者另有節點掛載稽核——與單筆建立同形，操作者為呼叫者；
整批請求列另帶 `import_source`（`csv`／`form`）與 `import_count`（建立台數，失敗為 0）。失敗（400／409）只留請求列。

**錯誤碼**:
| 碼 | HTTP | 層級 | 說明 |
|----|------|------|------|
| `VALIDATION_ASSET_IMPORT_ENCODING` | 400 | 檔案 | 非 UTF-8 |
| `VALIDATION_ASSET_IMPORT_TOO_LARGE` | 400 | 檔案 | 本文超過 1 MiB |
| `VALIDATION_ASSET_IMPORT_TOO_MANY_ROWS` | 400 | 檔案 | 超過 500 列（`params.max`） |
| `VALIDATION_ASSET_IMPORT_EMPTY` | 400 | 檔案 | 沒有資料列 |
| `VALIDATION_ASSET_IMPORT_CSV_MALFORMED` | 400 | 檔案 | 引號不成對等（`params.line`） |
| `VALIDATION_ASSET_IMPORT_HEADER` | 400 | 檔案 | 表頭欄位無法使用（`params.column`；原因 `unknown`／`duplicate`／`missing` 在回應頂層 `reason`） |
| `VALIDATION_ASSET_IMPORT_SECRET_FIELD` | 400 | 檔案 | 帶秘密或帳號名欄（`params.column`） |
| `VALIDATION_BAD_REQUEST` | 400 | 檔案 | JSON 格式錯誤、未知的非秘密欄、`source` 值域外、或寫入端點非 JSON |
| `VALIDATION_ASSET_IMPORT_ROWS_INVALID` | 400 | 寫入 | 有列未通過，附逐列報告 |
| `CONFLICT_ASSET_IMPORT_STATE_CHANGED` | 409 | 寫入 | 交易內重驗失敗，已整筆回滾，附出事的列 |
| `VALIDATION_ASSET_IMPORT_FIELD_REQUIRED` | — | 列 | 必填欄空白 |
| `VALIDATION_ASSET_IMPORT_FIELD_TOO_LONG` | — | 列 | 超過長度（`params.max`） |
| `VALIDATION_ASSET_IMPORT_PORT` | — | 列 | 埠非整數或不在 1–65535 |
| `VALIDATION_ASSET_IMPORT_FIELD_FORMAT` | — | 列 | 含控制字元，或 `credential_id` 不是正整數 |
| `VALIDATION_ASSET_IMPORT_FIELD_NOT_APPLICABLE` | — | 列 | 欄位不適用該協定 |
| `CONFLICT_ASSET_IMPORT_NAME_IN_BATCH` | — | 列 | 同批重名，兩列都標（`params.other_line`） |
| `NOTFOUND_ASSET_IMPORT_NODE_PATH` | — | 列 | 節點路徑查無、不唯一、與 `node_ids` 不符，或對範圍化主體在範圍外（`params.path`） |

列層級另沿用單筆建立的既有碼：`CONFLICT_ASSET_NAME`、`VALIDATION_ASSET_PROTOCOL`、`VALIDATION_ASSET_ACCESS_POLICY`、
`VALIDATION_ASSET_RDP_SECURITY`、`VALIDATION_ASSET_DB_TLS_MODE`、`VALIDATION_ASSET_MSSQL_HOST_COMMA`、`VALIDATION_ASSET_K8S_NAMESPACE_REQUIRED`、
`VALIDATION_TAG_*`、`NOTFOUND_ASSET_NODE`、`NOTFOUND_CREDENTIAL`、`RULE_CREDENTIAL_DEDICATED_SINGLE_BINDING`、
`RULE_CREDENTIAL_PROTOCOL_MISMATCH`、`RULE_CREDENTIAL_ROTATION_ACTIVE`、`RULE_CREDENTIAL_OUT_OF_SYNC`。

### 詳情 / 更新 / 刪除

```
GET    /api/v1/assets/:id     （asset:view＋逐資產可視守門）
PUT    /api/v1/assets/:id     （asset:update；UpdateAssetRequest 全欄位選填，密碼空字串不更新）
DELETE /api/v1/assets/:id     （asset:delete；軟刪除）
```

刪除回應 (200): `{}`（`message` 文案欄已移除；下同）

**逐資產可視守門**: `GET /assets/:id`、`GET /assets/:id/k8s/pods`、`GET /assets/:id/host-key` 統一掛 `RequireAssetVisible` 中介層——非 admin/auditor 須對該資產有 view（或更高）授權，未授權回 404「資產不存在」（不洩漏存在性）；守門無條件生效。

### 資產帳號（憑證掛載列）

一資產多系統帳號；未指定帳號的連線與系統路徑（改密 runner、k8s、SFTP 獨立入口）一律走
**預設帳號**。適用 ssh/rdp/vnc/mysql/postgres/redis/mssql；k8s 固定單一預設帳號。

**帳號列本身不持有登入秘密**。登入帳號名與密文的落點是憑證（見「帳號憑證庫 API」），
帳號列回答的是「這台主機以哪一筆憑證登入、當下就位在哪一個密文版本」——即**掛載列**。
一筆憑證掛在多台主機上時，那幾台共用同一組秘密，關係由憑證的範圍與掛載清單直接表達。

```
GET    /api/v1/assets/:id/accounts                         （asset:view＋逐資產可視守門）
POST   /api/v1/assets/:id/accounts                         （asset:update）
PUT    /api/v1/assets/:id/accounts/:accountId              （asset:update）
DELETE /api/v1/assets/:id/accounts/:accountId              （asset:update；204 No Content）
POST   /api/v1/assets/:id/accounts/:accountId/set-default  （asset:update）
```

**帳號名稱的欄位能力**：`POST` 以請求帶入的帳號名稱建立帳號（頂層 `username` 或 `credential.username`，不論是否設為預設），需 `credential:create` 或全域 `credential:manage`；`PUT` 把帳號改為與現值不同的名稱，需 `credential:update` 或全域 `credential:manage`。與 `PUT /assets/:id` 的 `username` 同一套規則：持有全域 `credential:manage` 者經相容能力通過，不另判語義能力；未持者經語義能力通過時，以路徑上的資產為目標判定該能力（建立在載入所指憑證之前與寫入交易內各判一次，改名在寫入交易內判定），資產在主體的資產寫入範圍內、卻不在該語義能力的範圍內時，回與資產不存在同形的 404，零寫入。非預設帳號同樣判定：它之後可經 `set-default` 成為預設帳號，名稱隨之成為資產上的帳號名稱。語義能力與全域 `credential:manage` 皆無（含只經節點範圍指派持有 `credential:manage`）即整筆拒絕（403 `AUTH_PERMISSION_DENIED`，不回權限名），帳號、憑證與資產上的帳號名稱皆不寫入，也不產生成功變更的審計；請求層照一般拒絕規則留下一筆 `denied` 的審計紀錄。帶 `credential_id` 掛既有共用憑證時帳號名稱取自該憑證，請求不帶名稱，由 `credential:bind` 判定。`PUT` 帶與現值相同的帳號名稱不算變更。

更換某一掛載所引用的憑證另有一支端點，掛在同一路徑下但授權點不同（路由層需任一憑證語義管理能力，服務層判定 `credential:bind`）：
`PUT /api/v1/assets/:id/accounts/:accountId/credential`，形狀見「帳號憑證庫 API」。

**回應 DTO 依讀取者能否看見憑證識別欄位分投影**。憑證識別欄位的欄位條件是 `credential:view` 或全域 `credential:manage` 任一。
回應形狀與範圍化檢視者的可見集合，都由讀取當下重新解析的同一份授權狀態決定，不沿用請求進入時的快照：

- 欄位條件成立、且不是範圍化檢視者（定義見「帳號憑證庫 API」的權限段）：完整版。
- 欄位條件成立、且是範圍化檢視者（例如只經節點範圍指派持有 `credential:view`）：完整版，引用其憑證可見集合外憑證的帳號列依下方「引用範圍外憑證的帳號列」收窄。
- 欄位條件不成立，包括請求進入後最後一筆相關指派被撤銷者：精簡版。

**投影只發生在列表端點**：建立、更新與設預設一律回完整版
（這三支的授權點是 `asset:update`）。

```json
// 憑證識別欄位可見：完整版 AssetAccountDTO
{
  "id": 3, "asset_id": 1, "username": "app",
  "is_default": false, "privileged": false, "auth_method": "sql", "note": "",
  "has_password": true, "has_private_key": false,
  "shared_credential": false,
  "credential_id": 106, "credential_name": "prod-01 / app",
  "credential_scope": "dedicated", "effective_version_no": 4, "binding_count": 1,
  "created_at": "2026-08-02T00:00:00Z", "updated_at": "2026-08-02T00:00:00Z"
}
```
```json
// 憑證識別欄位不可見：精簡版，只有這五個鍵
{"id": 3, "username": "app", "is_default": false, "has_password": true, "has_private_key": false}
```

**為什麼要分兩種**：憑證識別、名稱、範圍與掛載數合起來就是一張「哪些主機共用同一組秘密」
的地圖。對只需要挑一個帳號連線的人而言那是多餘的資訊，而知道甲台與乙台是同一組秘密，
等於知道拿下其中一台就等於拿下另一台。連線選帳號、工作區與帳號選單一律吃精簡版形狀，**不得**假設有
`privileged`／`asset_id`／`note`／任何 `credential_*` 欄位。

**憑證絕不出站**：密文欄於 model 標 `json:"-"`，兩種投影都只降為 `has_password`／
`has_private_key` 布林。列表為 `{"data":[...],"total":N}`，排序 `is_default DESC, username ASC, id ASC`；
建立回 201，更新與 set-default 回 200。

**引用範圍外憑證的帳號列**（列表端點與五個寫入端點，僅限範圍化檢視者；寫入端點為 `POST /assets/:id/accounts`、`PUT /assets/:id/accounts/:accountId`、`POST /assets/:id/accounts/:accountId/set-default`、`POST /credentials/:id/bindings`、`PUT /assets/:id/accounts/:accountId/credential`，成功回應與列表同一份判定、同形）：帳號列所引用的憑證不在其可見集合內（含歸屬全域者）時，該列收窄為不帶 `credential_id`、`credential_name` 與 `binding_count` 的形狀，並帶 `"credential_out_of_scope": true`；其餘欄位（`id`、`asset_id`、`username`、`is_default`、`privileged`、`auth_method`、`note`、`has_password`、`has_private_key`、`shared_credential`、`credential_scope`、`effective_version_no`、時間戳）照舊。該列另帶 `actions`，鍵為 `rebind`（更換憑證）、`remove`（移除帳號）、`secret_fix`（更正登記值）、`detach`（脫離共用），值 `{"allowed": bool, "reason"?: string}`，`reason` 為 `no_capability` 或 `out_of_scope`。每個旗標與對應寫入端點使用同一個判定函式：更換憑證與移除照所屬資產的能力與範圍，更正與脫離需該憑證歸屬在主體範圍內，範圍外憑證不可執行。範圍內憑證的帳號列與非範圍化檢視者的列不變、不帶 `actions`。旗標只決定畫面，每個寫入端點照常自行裁決。

**列表的帳號範圍過濾**: 依請求者有效授權帳號集合逐筆過濾——範圍外的帳號**直接不出現**
（不回 403，不成為帳號探測器）；admin 全量，auditor 於非 connect 權限時全量。

**建立請求：登入憑證來源二擇一**（**BREAKING**）。掛既有共用憑證，或這台自己一組：

```jsonc
{ "credential_id": 110, "is_default": false, "privileged": false, "note": "" }

{ "credential": { "username": "app", "password": "…", "private_key": "", "auth_method": "" },
  "is_default": false, "privileged": false, "note": "" }
```

- 頂層的 `username`／`password`／`private_key`／`auth_method` 是內嵌 `credential` 物件的
  簡寫形式，語義完全相同；`credential` 與頂層簡寫同時出現亦視為矛盾。
- `credential_id` 與內嵌形式**同時給** → 400 `VALIDATION_CREDENTIAL_SOURCE_AMBIGUOUS`。
  兩者表達的意圖相反（跟其他主機共用 vs 這台自己一組），靜默擇一會讓操作者以為建出來的
  是另一種。
- 掛既有共用憑證時**不建立任何密文版本**，就位版本設為該憑證當下的現行版本，
  且**對目標主機零寫入**——掛載只是宣告「這台用這組秘密登入」，秘密是否真的在那台機器上
  有效，由後續連線或改密揭露。
- 內嵌形式在同一交易建立一筆專用憑證與其第 1 版密文；該憑證隨這個掛載存在，
  掛載被刪時同交易刪除。
- `copy_from_account_id`（從其他資產帳號複製建號）**已移除**：帶值 → 400
  `VALIDATION_ACCOUNT_COPY_FROM_REMOVED`。複製出來的兩份密文是同一組秘密的兩個副本，
  系統事後無從得知它們是否還一樣，於是「這組秘密被哪些主機使用」永遠回答不了。
  共用意圖一律以共用憑證表達。
- 資產的第一個帳號強制成為預設（`is_default` 傳 false 亦然）。
- `auth_method`: 認證類型，值域 `sql`｜`domain`，未帶＝`sql`。**1.0 只接受 `sql`**——
  帶 `domain` 明確回 `VALIDATION_ACCOUNT_AUTH_METHOD_UNSUPPORTED`（**不靜默降級**），
  值域外回 `VALIDATION_ACCOUNT_AUTH_METHOD`。非 mssql 協議的帳號留在預設值且不參與連線組裝。

`POST /api/v1/assets` 的登入憑證欄位同一套二擇一規則與同一組錯誤碼（見「創建」段）。

**建立帳號的憑證能力**（與資產建立同一套）：帶 `credential_id` 掛既有共用憑證另需 `credential:bind`；
內嵌形式或頂層簡寫帶非空的 `password` 或 `private_key` 會新建一份專用憑證，另需 `credential:create`
（更新帳號時寫入新密文則是 `credential:set-secret`，見下方更新請求）。只帶帳號名、
不帶秘密也不掛憑證的建立不另需 `credential:bind`；帳號名稱依「帳號名稱的欄位能力」需 `credential:create` 或全域 `credential:manage`，經 `credential:create` 通過者以這台資產為目標判定。能力在載入所指憑證之前判一次、寫入交易內以資料庫現況
再判一次；缺能力回 403 `AUTH_PERMISSION_DENIED`（不回權限名），零寫入。只持資產寫入能力者因此不能把
共用憑證掛到自己可連線的資產上。

**更新請求**（欄位皆為指標，未帶＝不動）: `username`/`password`/`private_key`/`privileged`/`auth_method`/`note`；
密碼與私鑰**空字串＝沿用既有**。**無 `is_default` 欄位**——切換預設帳號只能走 set-default 端點。
`username` 與密文的更新作用在該掛載所引用的憑證上：前者改憑證的登入帳號名，後者在憑證上
追加一個新版本並讓這個掛載就位到它。

**寫入新密文另需 `credential:set-secret`**：更新帶入非空的 `password` 或 `private_key` 時，於寫入的交易內
以資料庫現況重新解析操作者的能力並判定 `credential:set-secret`（與憑證庫直接寫入密文同一道關卡），
缺能力回 403 `AUTH_PERMISSION_DENIED`（不回權限名），零寫入。只改 `username`、`privileged`、`auth_method`、
`note` 不需要這項能力。

**掛在共用憑證上的帳號不接受由本端點寫入新密文** → 409 `RULE_ACCOUNT_SHARED_CREDENTIAL_SECRET`。
那組秘密同時是其他主機的登入身分，由單台表單改寫會讓其餘掛載當場失去登入身分，而操作者
在那個畫面上看得見的只有這一台。出口有二：由憑證層整組寫入（`POST /api/v1/credentials/:id/secret`），
或先讓這台脫離共用。專用憑證維持既有行為。改密進行中的憑證一律拒絕寫入
（409 `RULE_CREDENTIAL_ROTATION_ACTIVE`）。

**default 語義**: 「至多一個」由 partial unique index 強制，「有帳號必有 default」由服務層
交易維護。刪除預設帳號時若資產尚有其他帳號 → 400 `RULE_ACCOUNT_DEFAULT_REQUIRED`；
資產僅剩該帳號時允許刪除（零帳號資產合法，同步清空資產顯示欄）。set-default 對已是預設者為
no-op（不寫稽核），否則在同一交易內先清舊預設再設新預設。

**刪除的語義是卸下掛載，不是改主機密碼**：`DELETE` 只移除掛載列與其就位版本，**目標主機上的
密碼原封不動**。被刪的若是某筆專用憑證的唯一掛載，該憑證於同一交易一併刪除；共用憑證則
留著，只是少一個掛載。要讓一台主機換掉自己的密碼並脫離共用，走的是脫離端點而非刪除。

**錯誤碼**（apierror 機器碼，前端查譯）:
`VALIDATION_INVALID_ACCOUNT_ID`(400)、`VALIDATION_ACCOUNT_USERNAME_INVALID`(400，含冒號或控制字元)、
`VALIDATION_ACCOUNT_USERNAME_RESERVED`(400，`@` 前綴為授權別名保留命名空間)、
`VALIDATION_ACCOUNT_USERNAME_TOO_LONG`(400)、`VALIDATION_ACCOUNT_NOTE_TOO_LONG`(400)、
`VALIDATION_CREDENTIAL_SOURCE_AMBIGUOUS`(400)、`VALIDATION_ACCOUNT_COPY_FROM_REMOVED`(400)、
`VALIDATION_CREDENTIAL_PRIVATE_KEY_INVALID`(400，新增或更新時帶入的私鑰無法解析：格式錯誤、內容不完整或設有
passphrase；更新時私鑰未帶或空字串＝沿用現行私鑰，不重驗)、
`VALIDATION_CREDENTIAL_USERNAME_IMMUTABLE`(400，共用憑證的登入帳號名不可改)、
`CONFLICT_ACCOUNT_USERNAME`(409，同資產同名)、`CONFLICT_ACCOUNT_DEFAULT`(409，併發撞 partial unique index)、
`RULE_ACCOUNT_DEFAULT_REQUIRED`(400)、`RULE_ACCOUNT_SHARED_CREDENTIAL_SECRET`(409)、
`RULE_CREDENTIAL_ROTATION_ACTIVE`(409)、`RULE_CREDENTIAL_DEDICATED_SINGLE_BINDING`(409，
指定的憑證是專用憑證，不可掛到第二台)、`RULE_CREDENTIAL_PROTOCOL_MISMATCH`(409，憑證協定族與
資產協定不相容)、`NOTFOUND_ASSET`(404)、`NOTFOUND_ASSET_ACCOUNT`(404)、
`NOTFOUND_CREDENTIAL`(404)、`INTERNAL_ASSET_ACCOUNT_*`(500)。

**稽核**: 建立/更新/刪除/切換預設各記一筆專屬稽核，Details **只記被變更的欄位名稱**，
絕不含密文或明文憑證。

### 連線測試

```
POST /api/v1/assets/:id/test-connection
```

**權限**: `asset:test`
**請求**（選填）: `{"timeout": 10}`（秒，預設 10）

**回應** (200，`ConnectionTestResult`；結果同時落庫至 `last_test_*` 欄位):
```json
{
  "success": true,
  "message": "",
  "latency_ms": 150,
  "error_code": "",
  "protocol": "ssh",
  "tested_at": "2026-07-01T10:00:00Z"
}
```

失敗時另帶 `code`（apierror 機器碼，前端查譯），`message` 降為過渡 fallback＝該碼的
zh-TW 文案（不再回填 guacd／驅動的原始訊息，原文只落伺服端日誌）；成功時 `message` 為空。
`error_code` 為既有粗分類機器欄（徽章用），語義不變。

### K8s Pod 列表（連線時選 pod）

```
GET /api/v1/assets/:id/k8s/pods
```

**權限**: `asset:view`

**回應** (200): `{"pods": [PodInfo]}`
```json
{
  "pods": [{
    "name": "web-abc123",
    "phase": "Running",
    "ready": "2/2",
    "restarts": 0,
    "started_at": "2026-06-30T00:00:00Z",
    "node": "node-1",
    "containers": [{"name": "app", "image": "nginx:1.25", "ready": true}],
    "default_container": "app"
  }]
}
```

**錯誤**: 502 + `{"error": "...", "kind": "unreachable|tls|unauthorized|forbidden|notfound|unknown"}`
（K8s 連線錯誤分類為六類人話）。

### K8s 容器檔案進出（kubectl cp）

```
POST /api/v1/assets/:id/k8s/upload      （已認證；資料面裁決；multipart: pod, container, dest_path, file）
GET  /api/v1/assets/:id/k8s/download    （已認證；資料面裁決；query: pod, container, path）
```

- 上傳回應 (200): `{"path": "/tmp/xxx", "size": 1024}`；下載回應為檔案附件
- **授權依連線裁決**：兩支端點是資料面操作，與連線簽發走同一組判定，依序檢查主體仍可連線與來源限定、
  資產存在且啟用、對該資產的連線授權、K8s 固定預設帳號、存取政策（核准時窗內的臨時授權放行；超級管理者
  依既有豁免放行並留 `policy_exemption` 審計標記）、傳輸安全。任一不通過即回該判定既有的拒絕碼
  （例：無連線授權 403 `AUTH_ASSET_CONNECT_DENIED`、需核准段位 403 `RULE_ACCESS_APPROVAL_REQUIRED`、
  停用資產 403 `RULE_ASSET_DISABLED`），不解封憑證、不連叢集。資產管理類權限點不是放行條件：沒有連線授權者
  即使持有 `asset:update` 亦被拒
- 上傳裁決兩次：讀本文前一次（被拒不解析本文、不建暫存檔），本文暫存完成後、解封憑證與遠端寫入前再一次；
  本文送達期間被撤權、資產停用或核准時窗到期的請求在第二次以對應碼被拒。下載沒有本文，維持單次。
  第二次裁決通過後、傳輸進行中的撤銷或到期不中斷該次傳輸
- 裁決通過後才判資料傳輸控管（`file_upload_enabled`／`file_download_enabled`，不通過回 403
  `RULE_TRANSFER_DENIED` 並留 `status=denied` 審計），兩道都通過才執行 `kubectl cp`
- 每次成功操作直接落稽核日誌（resource=file，含方向/pod/container/路徑/大小）
- 下載對「容器內不存在的來源」回 404（以本地是否產出檔案判斷）；目錄回 400
- `GET /assets/:id/k8s/pods` 與 `POST /assets/:id/test-connection` 屬管理探測，維持 `asset:view`／`asset:test`，
  只回 pod 中繼資料與可達性，其成功不構成檔案進出或連線的放行

---

## 帳號憑證庫 API

登入秘密的唯一真相。一筆**憑證**持有登入帳號名、秘密型別、協定族與一串**不可變的密文版本**；
資產帳號列只以外鍵引用它（見「資產帳號（憑證掛載列）」）。

- **範圍**：`dedicated`（專用）恰有一個掛載，隨掛載建立與刪除，名稱為空、顯示名由
  「資產名 / 帳號名」計算而不落庫；`shared`（共用）具名、可掛多台，是整組改密的對象。
- **版本**：已建立的密文版本不再改寫，變更秘密一律新增一版。每個掛載各自記著**就位版本**
  ——「這台用舊版、那台用新版」得以成立的前提，正是舊版密文原封不動。
- **就位版本是連線的唯一依據**：連線只取掛載的就位版本，不依憑證的現行或待生效版本推測、
  不自動試兩個版本。就位版本為空即該掛載尚無可用秘密，連線一律 fail-close。

**權限**：列表、詳情與改密進度三支讀取端點需 `credential:view`。逐台補跑與放棄本輪需 `credential:rotate`（放棄本輪，以及補跑重新排入最終失敗或已收束的成員，在寫入前另以憑證全部掛載判定，缺能力 403 且成員狀態不變；補跑的判定在取得該掛載的互斥鎖、於寫入交易內重讀成員之後才做，等鎖期間失權者同樣 403，通過時重排的操作者與當時的權限世代隨狀態一起落列，之後每次派送（含背景接手）除本輪發起者外另以重排者當下的能力重驗）。其餘寫入端點在路由層只確認持有任一憑證語義管理能力（`credential:create`、`update`、`set-secret`、`rotate`、`convert-scope`、`detach`、`delete`、`bind`，或相容的 `credential:manage`），缺全部者 403。服務層另依每個動作的能力判定（建立、更新、直接寫入密文、整組改密、範圍轉換、單台脫離、刪除、掛載），缺任一即拒；範圍化檢視者（持經節點範圍指派取得的資產、資產帳號或憑證權限點者）在此被拒（含寫入交易內重讀主體時指派已被撤銷）回 403 `AUTH_PERMISSION_DENIED`，能力判定先於目標解析、與憑證存在與否無關，其他主體沿用下方與不存在同形的回應；只有檢視能力者讀得到憑證與掛載清單，但不能做任何寫入。憑證是登入身分的本體，其管理面的權限不低於改資產。
列表、詳情與改密進度三支讀取端點每次呼叫各留一筆稽核（掛載清單隨詳情回，無獨立端點）。

**「不存在」與「不可見」共用同一碼**（`NOTFOUND_CREDENTIAL`）：憑證不存在、已軟刪、
操作者對受影響資產無權限，以及憑證落在範圍化檢視者該動作的範圍外，四者回位元相同的回應。分流即成為存在性探測器，而憑證識別是連號的。
以憑證識別定址的端點，範圍判定一律先於依憑證狀態分流的檢查：改密進行中、未收斂、零掛載、掛載是否存在、
輪次是否屬於該憑證與是否已結束、成員是否存在等，只有在範圍內（或不受範圍限制）的主體才看得到對應的 409 或專屬 404
（`NOTFOUND_CREDENTIAL_BINDING`、`NOTFOUND_CREDENTIAL_ROTATION`、`NOTFOUND_CREDENTIAL_ROTATION_MEMBER`）；
範圍外的憑證不論處於哪種狀態，卸載、整組改密、逐台補跑與放棄本輪都回上述同一個 `NOTFOUND_CREDENTIAL`。
請求本文的格式與值域檢查與目標無關，不屬上述狀態檢查。`POST /api/v1/credentials/ownership`（批次改歸）的逐筆不可操作另以 `NOTFOUND_BATCH_ITEMS_UNAVAILABLE` 只回筆數（見「建立、更新與範圍轉換」）。
錯誤回應同樣不回填憑證名、帳號名與資產名——那些是請求方可控的自由字串。

| 方法 | 路徑 | 說明 | 回應 |
|---|---|---|---|
| GET | `/api/v1/credentials` | 清單（篩選＋選用分頁） | 200 `{data, total}` |
| POST | `/api/v1/credentials` | 建立**共用**憑證 | 201 ＋ `CredentialDTO` |
| GET | `/api/v1/credentials/:id` | 詳情（含掛載清單） | 200 `{data, aggregate_state}` |
| PUT | `/api/v1/credentials/:id` | 改名稱、備註；專用另可改帳號名；共用另可單筆改歸（`ownership`） | 200 ＋ `CredentialDTO` |
| DELETE | `/api/v1/credentials/:id` | 刪除（仍有掛載即拒） | 204 |
| POST | `/api/v1/credentials/:id/scope` | 專用⇄共用範圍轉換 | 200 ＋ `CredentialDTO` |
| POST | `/api/v1/credentials/:id/secret` | 直接寫入新密文（不動遠端） | 200 ＋ `CredentialDTO` |
| POST | `/api/v1/credentials/ownership` | 批次改歸共用憑證的管理歸屬（整批原子） | 200 `{changed}` |
| POST | `/api/v1/credentials/:id/impact-confirmations` | 修改共用憑證前取得範圍外影響確認 | 200 `{required, confirmation_id?, in_scope_count, out_of_scope_asset_count?}` |
| POST | `/api/v1/credentials/:id/bindings` | 掛到一台資產 | 201 ＋ 與帳號列表同形的帳號列 |
| DELETE | `/api/v1/credentials/:id/bindings/:accountId` | 卸載（不動遠端） | 204 |
| POST | `/api/v1/credentials/:id/bindings/:accountId/detach` | 單台脫離共用（**同步**，會動遠端） | 200 `{data: RotationDTO}` |
| POST | `/api/v1/credentials/:id/rotations` | 發起改密（整組或拆分，**非同步**） | 202 `{data: RotationDTO}` |
| GET | `/api/v1/credentials/:id/rotations/:rid` | 改密進度（聚合態＋逐台成員） | 200 `{data: RotationDTO}` |
| POST | `/api/v1/credentials/:id/rotations/:rid/members/:mid/retry` | 逐台補跑（**同步**） | 200 `{data: RotationDTO}` |
| POST | `/api/v1/credentials/:id/rotations/:rid/abandon` | 放棄本輪（不回滾遠端） | 200 `{data: RotationDTO}` |
| PUT | `/api/v1/assets/:id/accounts/:accountId/credential` | 更換此掛載使用的憑證 | 200 ＋ 與帳號列表同形的帳號列 |

最後一支掛在資產帳號路徑下：它改的是**那一台**的登入身分，路徑上的主體是資產。
單台脫離共用只有 `/bindings/:accountId/detach` 這一支端點，資產編輯與憑證庫兩個介面入口都打它。

### 清單的查詢參數

全部選用，值域外一律回錯而非靜默不篩：

| 參數 | 值域 | 語義 |
|---|---|---|
| `scope` | `dedicated`｜`shared` | 值域外回 `VALIDATION_CREDENTIAL_SCOPE_INVALID` |
| `secret_type` | `password`｜`ssh_key` | 值域外回 `VALIDATION_CREDENTIAL_SECRET_TYPE_INVALID` |
| `ownership` | `global`｜`asset`｜`node` | 依管理歸屬篩選（`asset`＝專用憑證，隨資產）。值域外回 `VALIDATION_INVALID_QUERY_PARAM`（`params.field="ownership"`） |
| `owner_node_id` | 正整數 | 只留歸屬為該節點的憑證，等價於 `ownership=node` 再限定節點。非正整數回 `VALIDATION_INVALID_QUERY_PARAM`（`params.field="owner_node_id"`）。篩選與可見集合取交集：範圍外或不存在的節點回空陣列，不回錯誤 |
| `protocol` | 資產協定（`ssh`／`rdp`／`vnc`／`mysql`／`postgres`／`redis`／`mssql`／`k8s`） | 只留掛得上該協定資產的憑證。伺服端以資產協定與改密通道推導協定族後比對，**呼叫端不自行推導**——那份判準會在通道規則改變時開始說謊。值域外回 `VALIDATION_INVALID_QUERY_PARAM`（`params.field="protocol"`） |
| `windows_openssh` | 布林 | 該台的改密走 Windows OpenSSH，於是 `ssh` 協定推導為 `windows` 族。**與 `protocol` 缺一不擋**：只帶協定＝開關視為 false；只帶開關而無協定不構成篩選條件。非布林或與協定不相容（僅 `ssh`／`rdp` 相容）回 `VALIDATION_INVALID_QUERY_PARAM`（`params.field="windows_openssh"`） |
| `rotation_state` | `overdue`｜`due_soon`｜`unverified`｜`no_record`｜`no_policy`｜`compliant` | 該憑證全部掛載的狀態桶**取最嚴**；零掛載的憑證不屬於任何桶，不會出現在任何一次篩選裡。值域外回 `VALIDATION_INVALID_QUERY_PARAM`（`params.field="rotation_state"`） |
| `username` | 任意 | 帳號名**完全相等**比對，非模糊 |
| `search` | 任意 | 模糊比對三個面：共用憑證的名稱、憑證的帳號名，以及**專用憑證所掛資產的名稱**——專用的顯示名是計算值，搜資產名要找得到它 |
| `page` | ≥1 | **不帶＝回全部**（既有呼叫端行為不變）；帶了才切頁 |
| `page_size` | ≥1 | 預設 20、上限 200；只在帶 `page` 時生效 |

`page`／`page_size` 非正整數回 400 `VALIDATION_INVALID_QUERY_PARAM` 並以 `params.field` 指出是哪一個。
翻到超出範圍的頁碼回**空陣列**而非錯誤——那是正常操作。
**`total` 恆為套用全部篩選後的總筆數**，不是本頁筆數；未帶分頁時即 `data` 的長度。

輪替狀態的篩選在取回清單後於 API 層計算，不下推成 SQL：狀態是逐掛載狀態桶取最嚴的計算值，
沒有可篩的欄位，下推等於在資料庫裡再實作一次那套優先序，兩份口徑分岔出來的就是同一筆憑證
在兩個畫面上顯示成兩種合規狀態。

### 憑證的形狀

```jsonc
// CredentialDTO
{
  "id": 110,
  "name": "共用維運帳號",        // 共用＝落庫名稱；專用＝「資產名 / 帳號名」計算值（不可編輯）
  "scope": "shared",             // dedicated | shared
  "username": "ops",
  "secret_type": "password",     // password | ssh_key
  "auth_method": "sql",
  "protocol_family": "ssh",      // ssh | windows | vnc | database | k8s
  "note": "",
  "has_password": true,          // 密文本體永不出站，只投影布林
  "has_private_key": false,
  "binding_count": 2,            // 掛在幾台資產上
  "current_version_no": 1,       // 0＝尚無任何密文
  "rotation_active": false,
  "active_rotation_id": 0,       // 進行中那一輪的識別；0＝沒有進行中的輪替
  "ownership": { "kind": "node", "node_id": 7 },  // 管理歸屬，見下
  "created_at": "2026-09-06T16:29:00Z",
  "updated_at": "2026-09-06T16:29:00Z"
}
```

**管理歸屬 `ownership`**（所有主體的回應都帶）回答「誰能管理這筆憑證」，與 `scope`（共用／專用）是兩件事：
`kind` 為 `global`（只有不受範圍限制的主體能管理與掛載）、`node`（另帶 `node_id`；節點本身或其祖先在主體指派範圍內者可管理）或
`asset`（專用憑證，管理範圍依其掛載的資產判定，不可改歸）。共用憑證的歸屬只會是 `global` 或 `node`；升級前已存在的共用憑證由遷移一律設為 `global`。

**範圍化檢視者的欄位**：持有任一經節點範圍指派取得的資產、資產帳號或憑證權限點的主體，其列表與詳情另帶以下欄位，全域主體與其他主體不帶：

- `out_of_scope_asset_count`：這筆憑證掛在其範圍外的資產台數，只有整數，不含範圍外資產的識別、名稱或節點（欄名由最小揭露例外的登錄固定）。此時 `binding_count` 與詳情的 `bindings` 只計入並只列範圍內資產。
- `actions`：列級旗標，鍵為 `edit`、`set_secret`、`rotate`、`bind`、`convert_scope`、`reassign`、`delete`，值 `{"allowed": bool, "reason"?: string}`；`reason` 只有 `no_capability`（缺該動作的能力）與 `out_of_scope`（有能力但這筆憑證不在該能力的範圍內）。每個鍵依該動作自己的能力與持有該能力之指派的範圍逐項判定。詳情的每個掛載列另帶 `actions`，鍵為 `unbind`、`detach`，形狀與原因碼相同。
- 旗標只決定畫面呈現，不是授權依據：每個寫入端點照常自行裁決，旗標與端點判定不一致時以端點為準。
- 上述範圍化欄位只出現在列表與詳情。`PUT /credentials/:id`、`POST /credentials/:id/scope`、`POST /credentials/:id/secret` 的成功回應是未經範圍化的憑證物件：`binding_count` 為全部掛載台數，不帶 `out_of_scope_asset_count` 與 `actions`。要呈現範圍內的台數與動作旗標，請以列表或詳情重讀。

列表與詳情的可見集合由 `credential:view` 的各指派範圍聯集決定，持其他憑證能力但無 `credential:view` 者沿現行規則被讀取端點拒絕。

`active_rotation_id` 的用途是定址：進度端點以輪替識別查詢，少了這一欄，逐台進度就只有發起
那一次操作的呼叫端看得到，重新整理或換一台電腦打開只剩「輪替中」而看不出還差哪幾台。

`GET /api/v1/credentials/:id` 回 `CredentialDetailDTO`＝上表加一個 `bindings` 陣列，
頂層另帶 `aggregate_state`（值域見「改密的非同步語義」）。聚合態取不到時整個鍵不出現
——那是進度的補充資訊，缺它仍答得出這筆憑證是誰。

詳情另帶 `unsettled_rotation_id`：沒有進行中的輪替、而最近有一輪在已有主機改動後被放棄且仍有掛載
未收斂時，為那一輪的識別；否則整個鍵不出現。放棄後 `active_rotation_id` 即歸 0，少了這一欄，
逐台補跑在畫面上就沒有入口。判準：整組模式要求那一輪的目標仍是憑證的待生效版本，且有就位與
`changing` 以外、掛載仍在的成員；拆分模式的 `abandoned` 成員只在該掛載的候選仍在時算入（放棄時從未
動過遠端的成員連候選都已清除；動過遠端後才停成 `abandoned` 的，候選仍在，那台可能已在用它）。
只在詳情出現，列表不帶。

```jsonc
// bindings[]：掛載列
{
  "account_id": 20113, "asset_id": 2, "asset_name": "ssh-multi-test",
  "username": "ops", "is_default": true,
  "privileged": false,        // 逐掛載獨立：同一組秘密在不同主機上的特權性可以不同
  "note": "",
  "effective_version_no": 1,  // 該台當下用以連線的版本序號；0＝尚未取得任何密文
  "up_to_date": true,         // 就位版本即憑證的現行版本
  "node_paths": ["prod / web"] // 該台的所屬節點路徑，與資產列表同一投影
}
```

範圍化檢視者的掛載列中，`node_paths` 只含其檢視範圍內的歸屬節點，另附 `out_of_scope_node_count`（範圍外歸屬節點數，只有整數，欄名由最小揭露例外的登錄固定）；其他主體的掛載列帶全部歸屬節點、不帶該欄。

**協定族是憑證自持的欄位，不由成員推導**：零掛載的新建共用憑證沒有成員可推導，而資產表單的
「只列此協定可用的憑證」正需要在那個時候就能過濾。`windows` 族涵蓋 RDP 資產與走 Windows
OpenSSH 改密的 SSH 資產——族別回答的是「這組秘密拿去登入什麼樣的系統」。

### 建立、更新與範圍轉換

```jsonc
// POST /api/v1/credentials（本端點只建共用憑證）
{
  "name":            "必填、≤128、不得含控制字元、共用範圍內唯一",
  "username":        "可空；非空時沿用帳號名規則（不得含換行／冒號／控制字元、不得以 @ 開頭、≤100）。vnc／redis／k8s 等無帳號名的協定族留空",
  "secret_type":     "password｜ssh_key，可省略（由給了哪一種秘密推導）",
  "auth_method":     "sql｜domain，可省略（空＝sql）",
  "protocol_family": "ssh｜windows｜vnc｜database｜k8s",
  "note":            "≤255",
  "password":        "與 private_key 二擇一（至少其一）",
  "private_key":     ""
}
```

`POST /api/v1/credentials`、`POST /api/v1/credentials/:id/scope`（轉共用）與 `PUT /api/v1/credentials/:id` 另接選用欄位
`"ownership": {"kind": "global｜node", "node_id": 3}`（`kind` 不接受 `asset`；`node_id` 只在 `node` 時給）：

- 建立與轉共用：不受範圍限制的主體未帶歸屬即為 `global`；只經節點範圍持有該能力（建立為 `credential:create`、轉共用為 `credential:convert-scope`）的主體必須明確帶歸屬，未帶回 400 `VALIDATION_CREDENTIAL_OWNERSHIP_INVALID`。指定 `global` 限不受範圍限制的主體，其餘走能力拒絕。指定 `node` 時，不受範圍限制的主體只驗節點存在（不存在回 404 `NOTFOUND_ASSET_NODE`）；受範圍限制的主體，節點須在其範圍內，範圍外、已刪除與不存在的回應相同。
- `PUT`：帶 `ownership` 即單筆改歸，需 `credential:update`，與批次改歸同一組關卡（見下）。
- 歸屬欄形狀不合（`kind` 值域外、`node` 缺節點、`global` 帶節點）或對專用憑證指定歸屬，一律回 400 `VALIDATION_CREDENTIAL_OWNERSHIP_INVALID`。專用憑證的歸屬恆隨資產，由建立資產帳號等寫入路徑在同一交易內寫入，請求不得指定。

名稱撞名回 409 `CONFLICT_CREDENTIAL_NAME`；名稱唯一性只在共用範圍且未軟刪的列之間成立，
故軟刪之後同名可立即重用。缺秘密回 400 `VALIDATION_CREDENTIAL_SECRET_REQUIRED`
——一筆沒有秘密的共用憑證掛上去只會讓那台機器連不上。

`auth_method` 是**認證類型**（資料庫協定族登入目標的方式），與 `secret_type`（秘密是密碼還是
SSH 金鑰）是兩件事。值域 `sql`｜`domain`，未帶＝`sql`；**1.0 只接受 `sql`**——帶 `domain`
回 400 `VALIDATION_ACCOUNT_AUTH_METHOD_UNSUPPORTED`（**不靜默降級**：靜默接受一個做不到的設定，
會讓管理員以為域認證已生效），值域外回 400 `VALIDATION_ACCOUNT_AUTH_METHOD`。
非資料庫協定族的憑證留在預設值，該欄不參與連線組裝。

`PUT /api/v1/credentials/:id` 的三個欄位皆為指標語義（省略＝不動）：`name`、`note`、`username`。
**共用憑證的登入帳號名不可改** → 400 `VALIDATION_CREDENTIAL_USERNAME_IMMUTABLE`：改名等於讓
每一台掛載的登入身分同時變動，而遠端主機上的帳號並不會跟著改。專用憑證可改，改後於其唯一
掛載所屬資產內重驗不撞名。

`POST /api/v1/credentials/:id/scope` 帶 `{"scope": "dedicated｜shared", "name": "…"}`：
轉共用必須命名（否則 400 `RULE_CREDENTIAL_SHARED_REQUIRES_NAME`），並解除「恰一掛載」的限制；
轉專用只在剩下恰一個掛載時允許（多掛載回 409 `RULE_CREDENTIAL_TO_DEDICATED_MULTI_BINDING`、
零掛載回 409 `RULE_CREDENTIAL_TO_DEDICATED_NO_BINDING`），同交易清空名稱。
**兩個方向都不動密文版本、不動就位版本、不動遠端主機**：範圍是這組秘密的管理形態，不是它的內容。

`POST /api/v1/credentials/:id/secret` 帶 `{"password": "…", "private_key": "…"}`，
用於把遠端現況補登進系統：建立一筆新版本並讓**全部掛載**同時就位。操作者說的是「這組秘密現在
長這樣」，那句話的射程是整組；只改其中一台會讓其餘各台停在舊版而畫面上看不出差別。
本次未給的那一欄自現行版本原樣帶過（只補登密碼不會順手清掉私鑰）。**本端點不觸碰任何遠端主機**。
範圍化檢視者若這組憑證另有掛載在其 `credential:set-secret` 能力範圍外的資產，須在請求中帶 `impact_confirmation_id`（見下），
否則回 409 `RULE_CREDENTIAL_IMPACT_CONFIRMATION_REQUIRED`（`count` 為當下範圍外台數），且不寫入任何版本。

`POST /api/v1/credentials/:id/impact-confirmations` 帶 `{"operation": "set_secret｜rotate"}`，需對應的
`credential:set-secret` 或 `credential:rotate`；憑證不在主體範圍內時回應與憑證不存在相同。伺服器在憑證鎖內算出主體範圍外的掛載資產集合：
集合為空（含不受範圍限制的主體）回 `{"required": false, "in_scope_count": n}`，不建立確認紀錄（另有在能力範圍內但不可檢視的掛載時，加帶 `out_of_scope_asset_count`，見下）；
集合非空則保存一筆確認（同一操作者、憑證、動作只保留最新一筆）並回
`{"required": true, "confirmation_id": "…", "in_scope_count": n, "out_of_scope_asset_count": m}`。
回應不含任何範圍外資產的識別、名稱或節點；確認識別是不透明字串，只對發出它的操作者、憑證與動作有效。
本端點不修改憑證；不論是否建立確認，都留一筆憑證讀取稽核。`operation` 不是 `set_secret` 或 `rotate` 時回 400 `VALIDATION_BAD_REQUEST`。

**「範圍外」依該動作所需的能力判定**（`set_secret` 看 `credential:set-secret`、`rotate` 看 `credential:rotate`），不是依檢視範圍：
操作者看得到、但對該動作沒有能力的資產同樣算範圍外。伺服器把憑證當下的掛載資產切成三份：不在該能力範圍內者（確認保存的集合與 409 的 `count` 只算這份）、
在該能力範圍內且操作者可檢視者（回應的 `in_scope_count`，前端只列這些）、在該能力範圍內但操作者不可檢視者（只計台數、不列出、不進確認集合）。
確認端點回應的 `out_of_scope_asset_count` 為第一份加第三份，使「總台數＝範圍內台數＋範圍外台數」恆成立；409 的 `count` 只算第一份，兩數只在第三份非零時不同。
該台數為 0 時回應不帶此鍵。不受範圍限制的主體恆為 `{"required": false}`。

`POST /api/v1/credentials/:id/secret` 與 `POST /api/v1/credentials/:id/rotations`（整組與拆分）可帶選用欄位
`impact_confirmation_id`。提交時在憑證鎖內重算範圍外集合：集合為空時不看此欄；否則確認缺漏、已使用、
操作者／憑證／動作不符，或當下集合超出確認時保存的集合，一律回 409
`RULE_CREDENTIAL_IMPACT_CONFIRMATION_REQUIRED`（`count` 為當下範圍外台數），不寫入版本、不建立輪替、不連線任何遠端主機。
集合縮小或相同則照常執行並消耗該確認（單次使用），稽核 details 記範圍外台數 `out_of_scope_count` 與 `impact_confirmation_id`。
`operation` 為 `rotate` 的確認也用於儲存以該憑證為目標的改密計畫（`POST`／`PUT /change-secret-plans` 的 `impact_confirmation_id`），退回條件與 409 回應同上，在計畫的儲存交易內使用一次，見改密 API「計畫的範圍」。

`POST /api/v1/credentials/ownership` 帶 `{"credential_ids": [1, 2], "ownership": {"kind": "global｜node", "node_id": 3}}`，
需 `credential:update`。變更前與變更後的歸屬都要在操作者含該能力之指派的範圍內；專用憑證的歸屬恆隨資產，不可改歸。
逐筆判定與單筆 `PUT /api/v1/credentials/:id` 帶 `ownership` 同一組關卡：對該憑證的 `credential:update`（範圍化主體依憑證現行歸屬判定，不逐台驗掛載資產）、改密進行中拒絕、變更前後的歸屬皆在範圍內。
**整批原子**：任一筆不可操作（無權、範圍外、歸屬全域而操作者受範圍限制、不存在、專用、改密進行中）即整批不寫入，回 404 `NOTFOUND_BATCH_ITEMS_UNAVAILABLE`，只帶不可操作的筆數（`count`），不帶識別與原因，原因之間不可區分。
目的歸屬本身的錯誤與逐筆無關：受範圍限制的主體要求 `global` 回 403 `AUTH_PERMISSION_DENIED`；目的節點在範圍外或不存在回 404 `NOTFOUND_ASSET_NODE`；`credential_ids` 為空回 400 `VALIDATION_BAD_REQUEST`；缺 `ownership` 或其值域不合回 400 `VALIDATION_CREDENTIAL_OWNERSHIP_INVALID`。
成功回 `{"changed": n}`，`n` 為歸屬實際改變的筆數（原本即為目的者不計）；每筆改變各寫一列憑證更新稽核
（`fields=["ownership"]`，details 帶前後歸屬），權限版本於有任一筆改變時推進一次。

### 掛載與卸載

```jsonc
// POST /api/v1/credentials/:id/bindings
{ "asset_id": 2, "is_default": false, "privileged": false, "note": "" }

// PUT /api/v1/assets/:id/accounts/:accountId/credential
{ "credential_id": 110 }
```

- **掛載對目標主機零寫入**：新掛載的就位版本於同一交易設為該憑證當下的現行版本。
  這不宣稱該秘密在那台機器上必定有效——有效與否由後續連線或改密揭露。
- 掛載會檢核協定族相容（不符回 409 `RULE_CREDENTIAL_PROTOCOL_MISMATCH`）、同一資產不重複掛
  同一憑證（409 `CONFLICT_CREDENTIAL_BINDING`）、同資產同帳號名只掛一次（409 `CONFLICT_ACCOUNT_USERNAME`）；
  專用憑證不可掛第二台（409 `RULE_CREDENTIAL_DEDICATED_SINGLE_BINDING`）。
- **卸載只移除掛載列，不更動主機上的密碼**。介面必須就地說明這一點，與「脫離共用」（會改遠端）
  明確分開。卸載專用憑證的唯一掛載時，該憑證於同一交易被刪。
- 掛載與卸載的稽核列除憑證外另帶受影響的資產識別，使同一個動作在資產樞紐上也查得到——
  改變的是秘密在哪些主機上生效，只掛在憑證下會讓「這台機器的登入身分被誰換掉」查不出來。
- 憑證仍有掛載時刪除回 409，並於回應 body 帶受影響的資產名單：
  `{"code": "RULE_CREDENTIAL_IN_USE", "assets": ["ssh-multi-test", "web-01"]}`。
  名單走 body 而非錯誤 `params`（後者只收受控值域），且本端點已在憑證管理授權點之後。
- 仍有未決候選秘密時刪除回 409 `RULE_CREDENTIAL_PENDING_CANDIDATE`：那台機器現在吃哪一組秘密
  尚未確定，刪掉憑證即失去追回的依據。與前一碼分流，因為操作者的下一步不同——
  一個要先卸載，一個要等收斂。

### 改密的非同步語義

```jsonc
// POST /api/v1/credentials/:id/rotations
{ "mode": "group｜split", "policy": { "length": 16, "include_symbol": true, "exclude_ambiguous": true } }
```

`policy` 物件內用短名。改密計劃與批次改密另有各自的扁平欄位
（`password_length`／`password_include_symbol`／`password_exclude_ambiguous`），兩者不共用。
`mode` 省略＝`group`；值域外回 400 `VALIDATION_CREDENTIAL_ROTATION_MODE_INVALID`。
`group`＝全部掛載換到同一組新秘密；`split`＝每台各自隨機，收斂後各自成為專用憑證，共用關係解除。

```jsonc
// RotationDTO
{
  "id": 7, "credential_id": 110, "epoch": 1,
  "mode": "group", "status": "running",        // running | completed | abandoned
  "requested_by": 1, "requested_by_name": "admin",
  "started_at": "…", "finished_at": "…（未結束時整個鍵不出現）",
  "aggregate_state": "changing",
  "unsettled": true,                            // 只在已放棄、且是憑證詳情 unsettled_rotation_id 指的那一輪時出現
  "members": [{
    "id": 31, "account_id": 20113, "asset_id": 2, "asset_name": "ssh-multi-test",
    "username": "ops", "state": "changing", "attempt_count": 1,
    "next_attempt_at": "…（無則不出現）",
    "last_error": "…（機器碼，無則不出現）",
    "applied_at": "…（無則不出現）",
    "candidate_kept": true,                     // 只在 unsettled 那一輪、該掛載的候選仍在時出現
    "host_identity": { … },                     // 只在逐台補跑的回應、且只在被補跑的那一台出現，見「主機身分停止時的人工承接」
    "reason": "…（機器碼，只在帶確認的補跑因授權目標已改變而未執行時出現）"
  }],
  "out_of_scope_asset_count": 3                 // 只對範圍化檢視者出現，恆帶（0 也帶）；全量檢視者不帶
}
```

**範圍化檢視者的成員清單**：`members` 只列所屬資產在其憑證檢視範圍內的成員，範圍外成員整列省略，`out_of_scope_asset_count` 為被省略成員的去重資產台數，只有整數，不含範圍外資產的識別、名稱或帳號名。`unsettled`、`candidate_kept` 與 `host_identity`、`reason` 都只就列出的成員計算與附帶。輪替本身的推進與補跑、放棄的作用集合不受此影響，仍是全部成員。檢視範圍以產生回應當下的授權狀態判定；判定失敗時回該端點既有的內部錯誤，不出站任何成員。輪替快照可能與當下掛載不同，所以此台數不保證等於憑證詳情的 `out_of_scope_asset_count`。

**成員狀態七值**：`queued`（已排入本輪）／`changing`（正在對遠端下達）／`changed_unverified`
（遠端已下達但尚未以新值驗證成功，含遠端狀態不可知）／`applied`（已驗證並就位，本輪終態）／
`retry_wait`（可重試的失敗且未達上限，帶下次嘗試時刻）／`terminal_failed`（達上限或確定失敗，
待逐台補跑）／`abandoned`（本輪被放棄且該成員從未動過遠端，或該成員在遠端下達前因授權重驗未通過而停止）。
**只有 `applied` 會改寫該掛載的就位版本**，其餘六個狀態一律不動——遠端是否收下新秘密未知時，
謊稱新版已生效會使該台連不上且看不出原因。

**聚合態五值**：`idle`／`queued`／`changing`／`partial`／`out_of_sync`。
`partial` **先於** `changing`：一旦出現「有的已就位、有的還沒」，那就是要被看見的事實。
`out_of_sync` 有兩種來源——本輪已結束而待生效版本仍在且成員未全部就位，或全部成員都停在
終局失敗與收束（沒有一台還在動，也沒有一台就位）。憑證處於 `out_of_sync` 時不接受發起新一輪
（409 `RULE_CREDENTIAL_OUT_OF_SYNC`），出口是逐台補跑至收斂。

- `POST /rotations` 回 **202** 與剛建立的輪替（此時成員多為 `queued`）。推進在背景進行，
  **回應不代表任何一台已改完**。
- 前端輪詢 `GET /api/v1/credentials/:id/rotations/:rid`。建議節奏：前 2 分鐘每 3 秒、其後每 10 秒；
  `status` 轉 `completed`／`abandoned`，或全部成員落在 `applied`／`terminal_failed`／`abandoned`
  時停止輪詢。**不要顯示預估剩餘時間**：整輪的背景推進沒有整體上限，沒有可據以估算的來源。
- **成員補跑與單台脫離是同步的**（只動一台，操作者要當下的結果）：請求可能耗時數十秒，
  介面要有等待態與逾時提示。
- 成員狀態、聚合態與 `last_error` 都是機器碼，介面文案三語齊備，回應不含遠端回應原文。
- `changing` 只在一次成員推進期間存在。服務在那個窗口停止時，下次啟動、任何排程開始之前，
  該成員轉為 `changed_unverified`、`last_error`＝`CHANGE_SECRET_INTERRUPTED`，候選保留、遠端零 I/O，
  同一交易寫一筆系統審計（`operation`＝`rotation_interrupted`），並告警一次；審計寫不進去即維持 `changing`，
  下次啟動再處理。轉換後與其他 `changed_unverified` 成員相同：背景依該掛載候選的退避、補跑也一樣，
  只以新秘密登入驗證、不下達；逾本輪起始 24 小時仍驗不過即轉 `terminal_failed`，之後只有補跑會重新下達。
- **背景推進只碰本輪仍待處理的成員**：`queued`、到期的 `retry_wait`（重新下達）、到期的
  `changed_unverified`（只驗證）。成員自己的下次嘗試時刻未到時，候選到期也不推進。
  `terminal_failed`、`abandoned` 與已放棄輪替的成員一律不自動推進，只由補跑處理。進行中輪替裡不歸背景
  推進的成員、以及 `unsettled` 那一輪仍給補跑的成員，其候選到期時只延後下次嘗試時刻，不累計次數、
  不改原因碼、不告警，也不走候選清單的單帳號重試。
- `POST /rotations/:rid/abandon` **只表示停止自動化，不回滾**：已就位者不改回舊密、對遠端零額外
  操作。全部成員都不曾動過遠端時，待生效版本直接丟棄、憑證回到 `idle`；否則憑證進入
  `out_of_sync`，後續只能逐台補跑至收斂。已是 `abandoned` 的成員維持原狀，不使放棄失敗。輪替已結束時再呼叫回 409 `RULE_CREDENTIAL_ROTATION_NOT_RUNNING`。
- **補跑對已就位的成員不動作**：狀態為 `applied` 時直接回 200 與當下進度，不再往遠端跑一趟。
  `terminal_failed` 與 `abandoned` 的成員**可以補跑**，會被轉回 `queued` 重新執行，
  那正是未收斂狀態的出口；`queued`、`retry_wait` 與 `changed_unverified` 的成員直接推進一步。
  輪替沒有授權脈絡（升級前建立）或脈絡留自還原之前時，由點擊者承接：以其當下的憑證輪替能力，依憑證歸屬
  判定範圍（與其他憑證管理同一判定；帶資產上界、由批次拆分的輪替改以該成員的資產與帳號判定），不逐台檢查
  憑證的全部掛載；通過才新增授權脈絡、改掛到輪替上，並與承接審計在同一交易寫入；
  審計寫不進去即不承接、遠端不開始，成員以 `CHANGE_SECRET_AUTHZ_UNAVAILABLE` 停止並告警。補跑期間該成員的狀態已被其他路徑推進時（並發），回 409
  `RULE_CREDENTIAL_MEMBER_NOT_RETRYABLE`。
- 零掛載的具名共用憑證是合法的待用狀態，對它發起改密沒有任何遠端可動 → 409 `RULE_CREDENTIAL_ROTATION_NO_BINDING`。

### 主機身分停止時的人工承接

成員補跑與改密候選重試（見「改密 API」一節）共用同一套選用 body 與回應形狀。工作因主機身分
與送出當時綁定的不同而停止時，不帶確認的補跑只會再次停止；管理者核對新身分後，可在同一路由帶確認
明示承接。

```jsonc
// POST /api/v1/credentials/:id/rotations/:rid/members/:mid/retry
// body 整個省略、{}，或 {"confirm_host_identity": null} 都是「不帶確認」
{ "confirm_host_identity": {
    "transport": "ssh｜winrm",
    "record_id": 7, "algorithm": "ssh-ed25519", "fingerprint": "SHA256:…", "generation": 3,
    "accept_different_key": false } }
```

- **不帶確認**：行為與回應形狀同先前的逐台補跑（200 `{data: RotationDTO}`）。僅當被補跑的那一台被主機身分守衛擋下時，
  該成員多一個 `host_identity`；其他成員與其他情形都沒有這個鍵。
- **帶確認**：`transport=ssh` 時 `record_id`、`algorithm`、`fingerprint`、`generation` 四欄必填（`generation` 為正整數），
  `transport=winrm` 時四欄必須全部省略；`accept_different_key` 預設 `false`，核對後確認要改信任與原綁定不同的金鑰時才設為 `true`。
  確認內容只有這六個欄位，不接受任何主體或授權欄位。伺服器核對所確認的身分與當下記錄一致，並以呼叫者當下的能力重新判定授權
  （與不帶確認的補跑同一判準）後承接；承接後立即以新秘密驗證一次，驗證結果記在成員上。
  不論驗證通過與否都回 200 與整份 `RotationDTO`：驗證未通過時成員保留、仍可再次確認，原因在該成員的 `last_error`。
  承接過程不另外執行一般補跑。
- **授權目標已改變**：確認時發現工作建立之後授權目標已被改變，不承接、不改動工作列，回 200 與整份 `RotationDTO`，
  被確認的那一台多 `reason`＝`CHANGE_SECRET_AUTHZ_TARGET_CHANGED`。這不是主機身分的異動，不使用 `CONFLICT_HOST_IDENTITY_MOVED`。
- `host_identity` 與 `reason` 都只出現在這支補跑路由的回應；進度查詢與列表的成員不帶這兩個鍵。

`host_identity` 為唯讀檢視，只含判斷「要不要確認新身分」所需的事實，不含任何秘密、公鑰本體或來源資產：

| 欄位 | 說明 |
|---|---|
| `status` | `changed`／`unbound_legacy`／`record_missing`／`reset_pending`／`transport_changed` |
| `detail` | 停止細節：`unbound_legacy`／`transport_changed`／`record_missing`／`reset_pending`／`generation_changed`／`fingerprint_changed`／`commit_generation_changed` |
| `phase` | 最近一次停止的階段：`precheck`／`handshake`／`commit` |
| `verification_sent` | 該次驗證是否已用新秘密送出過認證：`true`／`false`／`unknown` |
| `original` | 送出當時綁定的身分 `{transport, record_id, algorithm, fingerprint, generation, binding, bound_at}`；升級前建立而從未綁定（legacy）時為 `null` |
| `current` | 主機當下的自身記錄 `{transport, record_id, algorithm, fingerprint, generation, reset_pending, recorded_at}`；沒有記錄時為 `null`。`recorded_at` 只代表最近一次更新，不是信任建立時間 |
| `candidate_applied` | 新秘密是否可能已在遠端生效 |
| `deadline` | 工作原本的截止時間（沿用，不重設）；無則 `null` |
| `expired` | 是否已逾 `deadline` |
| `confirmable` | 這種停止能否經人工確認承接；`transport_changed`、`record_missing`、`reset_pending` 為 `false` |

**錯誤**（候選重試與成員補跑相同，另加成員專屬的 404）：

| 狀態 | 碼 | 情形 |
|---|---|---|
| 400 | `VALIDATION_BAD_REQUEST` | body 不合法，且發生在任何查詢與服務呼叫之前：頂層出現 `confirm_host_identity` 以外的鍵（含 `force`）、確認內容多出六欄以外的欄位、`transport` 不是 `ssh`／`winrm`、`ssh` 缺身分欄位、`winrm` 帶身分欄位、不是 JSON、尾端多餘內容、body 超過 8 KiB |
| 403 | `AUTH_PERMISSION_DENIED` | 呼叫者的能力不足以承接，與其他權限不足同形狀 |
| 404 | `NOTFOUND_CREDENTIAL_ROTATION_MEMBER` | 成員不存在或不屬於路徑上的輪替（兩者同一回應，不呼叫承接） |
| 409 | `CONFLICT_HOST_IDENTITY_MOVED` | 所確認的身分與當下不同，或這項工作目前不可承接；頂層可另帶 `detail`（見下） |
| 500 | `INTERNAL_CREDENTIAL_ROTATION_RETRY` | 內部錯誤 |

409 的 `detail` 只在有明確原因時出現，值域三個：`not_confirmable`（工作目前不在可承接的狀態，或這種停止沒有可核對的端點身分）／
`confirmation_pending`（已有一筆尚未用完的確認）／`different_key_not_accepted`（確認的金鑰與原綁定不同，但未設 `accept_different_key`）。
沒有 `detail` 表示所確認的身分與當下記錄已不一致，重新讀取檢視後再確認。

### 單台脫離共用

```jsonc
// POST /api/v1/credentials/:id/bindings/:accountId/detach
{ "source": "random｜custom", "policy": { … }, "password": "…", "private_key": "…" }
```

以舊憑證登入該台、套用新秘密、再以新值驗證登入；驗證通過才改綁到一筆新的專用憑證。
`source` 為 `random` 時依 `policy` 產生，`custom` 時取請求帶的新秘密；**空值一律拒絕**
（400 `VALIDATION_CREDENTIAL_DETACH_SOURCE_INVALID`，二擇一不是三選一）。本操作僅適用共用憑證
（否則 409 `RULE_CREDENTIAL_NOT_SHARED`）。

脫離未完成時的回應**不是普通錯誤信封**，另帶終態與原因碼：

```jsonc
409 { "code": "RULE_CREDENTIAL_DETACH_FAILED", "state": "changed_unverified", "reason": "…" }
```

`state` 與 `reason` 皆為機器碼的封閉集合，**不含遠端回應原文**（那可能含主機名、路徑與帳號枚舉）。
兩者分開的理由是操作者的下一步不同：確定失敗可以直接再試，遠端結果不明則要先確認那台機器
現在到底吃哪一組秘密。

### 錯誤碼

| 家族 | 碼 |
|---|---|
| 路徑參數 | `VALIDATION_INVALID_CREDENTIAL_ID`、`VALIDATION_INVALID_ROTATION_ID`、`VALIDATION_INVALID_ROTATION_MEMBER_ID` |
| 名稱 | `VALIDATION_CREDENTIAL_NAME_REQUIRED`／`_TOO_LONG`／`_INVALID`、`CONFLICT_CREDENTIAL_NAME` |
| 歸屬 | `VALIDATION_CREDENTIAL_OWNERSHIP_INVALID` |
| 範圍與型別 | `VALIDATION_CREDENTIAL_SCOPE_INVALID`、`VALIDATION_CREDENTIAL_SECRET_TYPE_INVALID`、`VALIDATION_CREDENTIAL_SECRET_REQUIRED`、`VALIDATION_CREDENTIAL_PROTOCOL_FAMILY_INVALID` |
| 私鑰 | `VALIDATION_CREDENTIAL_PRIVATE_KEY_INVALID`（400；建立共用憑證、直接寫入密文、單台脫離共用的自訂私鑰無法解析：格式錯誤、內容不完整或設有 passphrase。直接寫入密文時私鑰為空＝自現行版本帶過，不重驗） |
| 帳號名與認證類型 | `VALIDATION_CREDENTIAL_USERNAME_IMMUTABLE`；帳號名本身的檢核沿用既有的 `VALIDATION_ACCOUNT_USERNAME_*` 三碼與 `VALIDATION_ACCOUNT_NOTE_TOO_LONG`；認證類型沿用 `VALIDATION_ACCOUNT_AUTH_METHOD`／`VALIDATION_ACCOUNT_AUTH_METHOD_UNSUPPORTED` |
| 來源二擇一 | `VALIDATION_CREDENTIAL_SOURCE_AMBIGUOUS`、`VALIDATION_ACCOUNT_COPY_FROM_REMOVED` |
| 改密請求 | `VALIDATION_CREDENTIAL_ROTATION_MODE_INVALID`、`VALIDATION_CREDENTIAL_DETACH_SOURCE_INVALID` |
| 計劃／批次 | `VALIDATION_PLAN_TARGET_KIND`、`VALIDATION_PLAN_TARGET_CREDENTIAL_REQUIRED`、`VALIDATION_PLAN_SHARED_CREDENTIAL_TARGET`、`VALIDATION_BATCH_CREDENTIAL_NAME_REQUIRED` |
| 找不到 | `NOTFOUND_CREDENTIAL`、`NOTFOUND_CREDENTIAL_BINDING`、`NOTFOUND_CREDENTIAL_ROTATION`、`NOTFOUND_CREDENTIAL_ROTATION_MEMBER` |
| 衝突 | `CONFLICT_CREDENTIAL_BINDING`、`CONFLICT_ACCOUNT_USERNAME`、`CONFLICT_HOST_IDENTITY_MOVED`（逐台補跑帶確認時，見「主機身分停止時的人工承接」） |
| 業務規則 | `RULE_CREDENTIAL_IN_USE`、`RULE_CREDENTIAL_PENDING_CANDIDATE`、`RULE_CREDENTIAL_ROTATION_ACTIVE`、`RULE_CREDENTIAL_OUT_OF_SYNC`、`RULE_CREDENTIAL_SHARED_REQUIRES_NAME`、`RULE_CREDENTIAL_TO_DEDICATED_MULTI_BINDING`、`RULE_CREDENTIAL_TO_DEDICATED_NO_BINDING`、`RULE_CREDENTIAL_DEDICATED_SINGLE_BINDING`、`RULE_CREDENTIAL_PROTOCOL_MISMATCH`、`RULE_CREDENTIAL_NOT_SHARED`、`RULE_CREDENTIAL_IMPACT_CONFIRMATION_REQUIRED`、`RULE_CREDENTIAL_ROTATION_NOT_RUNNING`、`RULE_CREDENTIAL_ROTATION_NO_BINDING`、`RULE_CREDENTIAL_MEMBER_NOT_RETRYABLE`、`RULE_CREDENTIAL_DETACH_FAILED`、`RULE_ACCOUNT_SHARED_CREDENTIAL_SECRET` |
| 5xx | `INTERNAL_CREDENTIAL_{LIST,GET,CREATE,UPDATE,DELETE,BIND,UNBIND,REBIND,SCOPE,SECRET,DETACH}`、`INTERNAL_CREDENTIAL_ROTATION_{START_FAILED,GET,RETRY,ABANDON}` |

---

## Host Key API（TOFU）

SSH 首連記錄 host key（SSH 終端、SFTP、SSH 直連測試、改密與輪替共用）。記錄同時帶撥號位址（主機與埠）：資產刪除後指紋記錄保留，同位址新建的資產沿用該記錄比對；位址若從未有過記錄，首次連線才信任並記錄（首次信任的限制不因告警而消失）。

之後指紋與記錄不符時，處置依連線路徑而定：
- **互動連線（人類終端、檔案傳輸、連線測試）由主機金鑰檢查允許繼續認證**（不符本身不阻止互動路徑進入 SSH 認證；允許繼續不等於認證成功或連線成功）。後續認證及通道建立成功時：終端在 `connected` 之後收到 `{"type":"notice","code":"RULE_SSH_HOST_KEY_CHANGED"}`、檔案管理的列目錄回應帶 `host_key_mismatch: true`、連線測試回 `success: true` 並附 `warning_code: "RULE_SSH_HOST_KEY_CHANGED"`。後續步驟失敗時仍回相應的失敗結果：終端的 `error` 幀另帶 `params.host_key_mismatch: "1"`，連線測試的失敗結果仍附 `warning_code`。自動化代理經代理通道開的終端屬背景作業，不符時拒絕、不送出任何憑證，以 `RULE_SSH_HOST_KEY_MISMATCH_REFUSED` 回覆（與互動連線的警示碼分開：警示碼的文案陳述憑證已送出）。
- **背景作業（改密執行、改密重試、憑證輪替，含經 SSH 連到 Windows）拒絕該次撥號**，不送出任何憑證或新秘密，作業以原因碼 `CHANGE_SECRET_HOST_KEY_MISMATCH` 結束。
- 兩類都在認證開始（或拒絕）之前、同一交易寫入：一筆 `host_key_mismatch` 審計（記錄中的指紋、這次出示的指紋與其演算法、記錄來源、撥號位址、路徑、處置、憑證曝露欄 `credentials`、連線使用者與連線識別）、該指紋的觀察紀錄（首次與最近出現時間、次數），以及此指紋第一次出現時一則系統安全告警 `host_key_mismatch`（位址與傳輸安全組，預設 high）。同一未確認指紋之後每次連線只寫審計並累計次數；例外是先前只在背景作業被拒絕的指紋第一次照常連線時再告警一次。出示另一個指紋會再告警。
- 互動路徑越過主機金鑰檢查、實際嘗試認證後，另寫一筆同 `correlation_id` 的 `host_key_cred_sent` 審計，記下登入憑證已送出與認證結果；允許繼續的連線都會留下這筆，不論認證成功與否。
- 留痕任一步寫不進去、或讀不到記錄時，連線以 `RULE_SSH_HOST_KEY_CHECK_FAILED` 中止，憑證未送出。
- 記錄不自動覆蓋：維持原指紋，直到超級管理者採用一個觀察到的指紋（下表 `POST .../adopt`）或重置後由下一次連線重新記錄；兩者都在同一交易產生系統安全告警 `host_key_record_changed`（預設 medium），採用另寫 `host_key_adopt` 審計。採用或重置只改這台資產的指紋記錄，不等於承接舊工作：因主機身分異動而停止的改密候選或輪替成員仍須各自經人工確認（見改密候選重試與輪替成員補跑的 `confirm_host_identity`）。

互動連線放行代表目標被冒充時憑證仍會送出；審計與告警只供事後追查，不能防止中間人攻擊。拒絕且不送出憑證的情境是代理終端與背景作業（改密、輪替）。

| 方法 | 路徑 | 說明 | 權限 |
|---|---|---|---|
| GET | `/assets/:id/host-key` | 檢視指紋記錄：`{id, asset_id, algorithm, fingerprint, created_at, updated_at}`（`fingerprint` 為 `SHA256:xxx`，公鑰本體不外露）；本資產尚無自身記錄但同位址有記錄時回沿用記錄 `{asset_id, algorithm, fingerprint, inherited: true}`，`asset_id` 為被查資產，不含 `id` 與任何時間戳；無記錄（或已標記待重置）回 404「尚無 host key 記錄」。資產有待確認的不符指紋時多回 `mismatches: [{algorithm, fingerprint, first_seen_at, last_seen_at, seen_count}]`（最近出現者在前，最多 5 筆，不含公鑰）；沒有觀察紀錄時不帶此欄 | 登入＋逐資產可視守門（非 admin/auditor 未授權回 404「資產不存在」，無條件生效） |
| POST | `/assets/:id/host-key/adopt` | 採用已觀察的指紋：請求 `{"fingerprint": "SHA256:..."}`，只接受該資產 `mismatches` 中存在的指紋。同一交易以該觀察的演算法、指紋、公鑰與撥號位址寫入自身記錄（取代原記錄並清除重置待記錄狀態）、清除該資產全部觀察紀錄、寫 `host_key_adopt` 審計、產生 `host_key_record_changed` 告警；任一步失敗整筆回滾回 500 `INTERNAL_HOST_KEY_ADOPT`。指紋不在觀察中回 404 `NOTFOUND_HOST_KEY_OBSERVATION`，記錄不變；缺指紋回 400。成功回 200 與新的檢視內容（與 GET 自身記錄同形，無 `mismatches`） | 超級管理員保留（不可指派給自訂角色） |
| DELETE | `/assets/:id/host-key` | 重置（主機重灌場景）：標記本資產「重置待記錄」，下次連線直接記錄當次指紋並清除觀察紀錄；只有沿用記錄（無自身記錄）時同樣可重置；不刪任何記錄列。生效的重置同交易產生 `host_key_record_changed` 告警（告警寫不進去即不生效）。本資產自身與同位址皆無記錄，或本資產已標記待重置（重複重置）時，回 404 無可重置，不發告警。有待確認指紋時建議改用採用 | 超級管理員保留（不可指派給自訂角色） |

---

## 檔案管理 API（SFTP，SSH 資產）

> 資產收口：client 只送 `asset_id` 與路徑，憑證由後端解析。
> 權限沿用連線授權（`connect` 權限，能連線即能傳檔）；全操作稽核（含 size 與 SHA-256 摘要）。
> 存取政策閘同套生效：reason/approval 段位無時窗內臨時授權時常設
> connect 亦被擋（admin 豁免；auditor 與一般 user 同攔）——檔案資料面不得繞過政策閘。
> 未授權（無 connect）與政策攔截統一回 404「資產不存在」（不洩漏存在性；申請入口在資產列表，
> 檔案端點僅擋不引導）。
> 遠端路徑必須為絕對路徑且不得包含 `..`（否則 400）；遠端操作失敗回 502。
> 帳號的私鑰無法解析（格式錯誤、內容不完整或設有 passphrase）時回 400 `RULE_SSH_PRIVATE_KEY_INVALID`
> （與終端連線同碼），不回該動作的失敗碼，回應不含解析原文。
> 五個端點均接受選填 query `session_id`：自某會話的檔案分頁進入時
> 沿用該會話的資產帳號連線；省略＝檔案管理獨立入口，走預設帳號。非本人或非該資產的
> `session_id` 一律 404 `NOTFOUND_SESSION`（fail-close，不退回預設帳號）。

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/assets/:id/files?path=/abs/dir` | 目錄列表 → `{"path": "...", "entries": [{name, size, mode, mod_time, is_dir}]}` |
| GET | `/assets/:id/files/download?path=/abs/file` | 串流下載（attachment） |
| POST | `/assets/:id/files/upload` | multipart: `path`（目錄）+ `file` → `{"path": "...", "size": N}` |
| POST | `/assets/:id/files/mkdir` | body: `{"path": "/abs/dir"}` → `{"path": "..."}` |
| DELETE | `/assets/:id/files?path=/abs/target` | 刪除檔案或空目錄 → `{"path": "..."}` |

---

## 資產節點 API（分組升級節點樹）

| 方法 | 路徑 | 說明 | 權限 |
|---|---|---|---|
| GET | `/asset-groups` | 節點平面列表 → `{data: [{id,name,description,parent_id,path,assets}], total}`（assets＝直掛成員；非 admin/auditor 收斂：每節點僅含該使用者授權的資產，保留「有授權資產的節點＋祖先鏈」——祖先空殼僅結構不洩漏資產；範圍化檢視者的節點與資產為連線可視與管理可視的聯集，見〈範圍化檢視者的回應〉）。選用 `?purpose=`（`asset_create`、`asset_update`、`credential_create`、`credential_update`、`credential_convert_scope`）：見下方〈節點選擇用途參數〉；範圍化檢視者的每個節點另附列級旗標，見〈範圍化檢視者的回應〉 | 登入 |
| GET | `/asset-groups/tree` | 樹導覽（惰性）：`?parent_id=` 空＝根層 → `{data: [{id,name,description,parent_id,path,asset_count,subtree_asset_count,has_children}]}`；非 admin/auditor 依可視節點鏈收斂（授權資產掛載節點＋全部祖先，無關子樹不洩漏；範圍化檢視者的節點與計數依連線可視與管理可視的聯集，見〈範圍化檢視者的回應〉）。範圍化檢視者的每個節點另附列級旗標，根層請求（無 `parent_id`）頂層另附 `can_create_root`，見〈範圍化檢視者的回應〉 | 登入 |
| POST | `/asset-groups` | 建立節點，body: `{name, description, parent_id}`（parent_id 空＝根節點；深度上限 10、同層同名 409） → 201。節點範圍持有者：父節點在範圍外或不存在 404、根層建立 403（見〈節點寫入的範圍判定〉） | `assetgroup:manage` |
| PUT | `/asset-groups/:id` | 更新名稱/描述（位置不動；同層同名 409）。節點範圍持有者：目標在範圍外 404、目標是自己的範圍根 403 | `assetgroup:manage` |
| PUT | `/asset-groups/:id/move` | 搬移，body: `{parent_id}`（null＝搬到根層）；環路（搬到自身/子孫）400、搬移後子樹深度超限 400、目標層同名 409。節點範圍持有者：來源或目的在範圍外 404；來源非嚴格子孫、搬到根層、被搬子樹含任何指派的範圍節點 403 | `assetgroup:manage` |
| DELETE | `/asset-groups/:id` | 刪除（僅「無子節點且無直掛資產」的空節點可刪，否則 400；掛該節點的授權與 approver 審核範圍連動軟刪＋稽核）。節點被任何角色指派用作範圍節點時 409 `RULE_NODE_SCOPE_REFERENCED`（含超級管理者）；節點範圍持有者：目標在範圍外 404、目標是自己的範圍根 403 | `assetgroup:manage` |

> 授權客體 `asset_group_id` 語義＝「節點＋全部後代節點的資產」（含子樹，隨掛隨涵蓋）；
> 政策不掛節點。

**錯誤**: 409 同層名稱重複、404 不存在、400 深度超限/環路/非空節點、409 `RULE_NODE_SCOPE_REFERENCED` 節點被管理範圍引用。

### 節點寫入的範圍判定

四個寫入端點（建立、更新、搬移、刪除）對「只經節點範圍指派持有 `assetgroup:manage`」的主體，在服務寫入交易內、取得拓撲鎖之後判定一次；全域持有者不受範圍限制，只受搬移子樹規則（被搬子樹內有指派的範圍節點時限超級管理者）與既有結構檢查約束；超級管理者不受這些規則限制。判定順序：解析（404）、動作規則（403）、刪除的引用檢查（409）、既有結構檢查、寫入。

| 動作 | 範圍外或不存在（404） | 限超級管理者（403） |
|---|---|---|
| 建立 | 父節點非空時，父節點（含其未刪除祖先）與持有者的範圍節點不相交，或父節點不存在或已刪除 | 在根層建立（`parent_id` 空） |
| 更新名稱／描述、刪除 | 目標（含其未刪除祖先）與持有者的範圍節點不相交 | 目標是持有者自己的範圍根（它不在任何範圍的嚴格子孫位置） |
| 搬移 | 來源同上；目的非空時同建立的父節點規則 | 來源不是嚴格子孫、搬到根層、被搬子樹（含自身，只計未刪除節點）內任一節點是任何角色指派的範圍節點 |

- 範圍外、已刪除與從未存在的節點，回應皆為既有的 404（`NOTFOUND_ASSET_NODE`，無 `params`），三者同形。
- 限超級管理者的 403 為能力拒絕的單一形狀（見「統一回應格式」）。全域持有者在根層建立或搬到根層時不受此限。
- 範圍內的更新只改描述時，審計紀錄 details 為 `asset_node_describe`（`old`、`new`）；只改名為 `asset_node_rename`；兩者都改則一筆含兩鍵；皆未改不寫。搬移的審計紀錄 details 另附 `topology_coverage`：因搬移新增或失去涵蓋的資產、連線授權、審核範圍與管理範圍，只含識別碼與等級／角色識別碼，每份清單最多 100 筆並附 `total` 與 `truncated`；經節點範圍指派授權的搬移另附 `cross_assignment`（布林值）。這些只出現在審計紀錄，不在回應中。

### 刪除被管理範圍引用的節點

節點被任何角色指派（使用者或使用者群組）用作範圍節點時，刪除回 409 `RULE_NODE_SCOPE_REFERENCED`，所有人皆然。引用以指派紀錄為準，被停用主體持有的指派同樣計入；查詢失敗時刪除不執行。

- `params`：`path`（節點路徑）、`count`（引用的不同指派筆數，主體種類、主體與角色各不同才算一筆）。
- 超級管理者的回應另帶頂層 `references`：`[{subject_kind, subject_id, subject_name, role_id, role_name, member_count?}]`，依主體種類、主體識別碼、角色識別碼升冪；`subject_kind` 為 `user` 或 `user_group`，`member_count` 只出現在 `user_group`。其他持有者的回應不帶 `references`，只有 `count`，不揭露主體。
- 節點刪除不會移除這些指派；呼叫端須先修改指派（使用者詳情頁與使用者群組詳情頁的「角色與範圍」分頁）。

### 範圍化檢視者的回應

「範圍化檢視者」指經節點範圍指派持有任一資產或資產帳號權限點，或持有 `assetgroup:manage` 的主體，不論範圍節點是否仍有效。只經全域指派的主體、超級管理者、稽核員與一般使用者走原有路徑，回應欄位不變。

- 不帶 `purpose` 時，範圍化檢視者的樹與平面列表回傳同一組節點：有連線可視直掛資產的節點，與管理可視子樹內的節點，兩者聯集，加上它們的祖先鏈（祖先只作定位）。資產為連線可視與管理可視資產的聯集，`assets` 與兩種計數只計這些資產。管理可視的資產若另掛在上述以外的節點，那些節點不因此回傳。
- 範圍化檢視者的樹與平面列表，每個節點多附：`manageable`（在節點管理可視範圍內）、`locator_only`（只因是其他回傳節點的祖先而出現，本身沒有可視的直掛資產且不在管理可視內）、`scope_root`（是檢視者自己某筆含節點管理權限點之指派的範圍節點）、`can_create_child`、`can_rename`（同時代表改描述）、`can_move`、`can_delete`。旗標由與上節同一組規則算出，`can_move` 另計被搬子樹內的範圍節點規則；伺服器於寫入時仍會再判定一次。
- `GET /asset-groups/tree` 的根層請求（無 `parent_id`）頂層多附 `can_create_root`；惰性子層請求的節點同樣附列級旗標。
- 管理可視來自節點範圍指派的 `asset:view` 或 `assetgroup:manage` 所涵蓋的子樹；全域 `asset:view` 不算。

### 節點選擇用途參數（`GET /asset-groups?purpose=`）

選用查詢參數，用於讓呼叫端知道哪些節點可作為某個動作的目標。參數不授予任何能力，寫入端點仍各自裁決。

| `purpose` | 對應權限點 |
|---|---|
| `asset_create` | `asset:create` |
| `asset_update` | `asset:update` |
| `credential_create` | `credential:create` |
| `credential_update` | `credential:update` |
| `credential_convert_scope` | `credential:convert-scope` |

- 不帶參數時，請求與回應與原來相同。
- 值不在上表（含空字串、大小寫不同、權限鍵字串、重複給值）回 400 `VALIDATION_BAD_PARAMS`，對任何主體相同。
- 範圍化檢視者，或經節點範圍指派持有該用途對應權限點的主體：每個節點多附 `selectable`（節點在該權限點的有效範圍子樹內為 `true`，僅作為上層路徑的節點為 `false`），頂層多附 `selectable_all`（有效範圍為全部時為 `true` 且每個節點皆 `true`；為空時為 `false` 且每個節點皆 `false`）。位於有效範圍子樹內、但原本不可視的節點與其上層路徑一併列出，這些節點的 `assets` 只含檢視者原本可視的資產。
- 其他主體（只經全域指派、超級管理者、稽核員、一般使用者）帶合法參數時，回應與不帶參數相同，不附欄位，呼叫端沿現行把全部節點視為可選。
- 列級旗標仍只依範圍化檢視者的判定附加，`purpose` 不改變它們。

---

## Session API

> 需要登入；權限 `session:view`；終止為 `session:terminate`，且 handler 內另限超級管理者。
> 一般 user 檢視自己的連線紀錄請改用 [自助連線 API](#自助連線-apimy-connections)（`GET /my/connections`）。
> session:view 讀取端點（列表/詳情/活動/統計/per-session 指令）無條件守門。

### 列表

```
GET /api/v1/sessions
```

**Query 參數**:
| 參數 | 類型 | 說明 |
|------|------|------|
| `user_id` | uint | 用戶 ID |
| `asset_id` | uint | 資產 ID |
| `protocol` | string | ssh/rdp/vnc/mysql/postgres/redis/mssql/k8s |
| `status` | string | active/disconnected/closed |
| `start_time` | RFC3339 | 開始時間（起） |
| `end_time` | RFC3339 | 開始時間（迄） |
| `page`, `page_size` | int | 分頁（預設 1 / 20） |

**回應** (200): `{"data": [Session], "total": N, "page": 1, "page_size": 20}`

**Session 主要欄位**:
```json
{
  "id": 1,
  "session_id": "sess_1735700000000000000_1",
  "status": "closed",
  "protocol": "ssh",
  "user_id": 1,
  "user": {"id": 1, "username": "admin"},
  "asset_id": 1,
  "asset": {"id": 1, "name": "Server1"},
  "client_ip": "192.168.1.10",
  "start_time": "2026-07-01T10:00:00Z",
  "end_time": "2026-07-01T10:30:00Z",
  "duration": 1800,
  "end_reason": "normal",
  "recording_path": "...",
  "recording_size": 102400,
  "has_recording": true,
  "recording_error": "",
  "offsite_object_id": 42,
  "offsite_status": "uploaded",
  "k8s_namespace": "", "k8s_pod": "", "k8s_pod_uid": "",
  "k8s_container": "", "k8s_image": "", "k8s_node": ""
}
```

`end_reason`: `normal` / `idle_timeout` / `max_duration` / `admin_terminate` / `user_terminate`
（自助終止）/ `backend_restart` / `orphaned`（啟動清掃孤兒）/ `revoked`（授權撤銷）。
K8s 會話帶不可變 pod 快照（uid/image/node 於連線當下釘住）。

agent 會話（`actor_kind=agent`）的列表與詳情另帶兩個唯讀名稱欄：`owner_username`（當時負責人）與 `on_behalf_of_username`（這次連線替誰做）。兩者由快照的 user id 即時投影目前帳號名，非資料表欄位；主體已刪時該鍵不出現。

**離機儲存兩欄**（`offsite_object_id`／`offsite_status`）:
- `offsite_object_id`：保管帳冊列的識別；本會話的錄影尚未（或不會）進入離機佇列時**該鍵不出現**（`omitempty`）。
- `offsite_status`：**恆出現**（未進佇列時為空字串）。值域＝帳冊七態
  `pending`／`uploading`／`uploaded`／`failed`／`integrity_mismatch`／`foreign`／`local_purged`，
  另加回填掃描的兩個分類 `skipped_missing`（本機檔讀不到）／`skipped_expired`（已逾錄影保留期）
  ——後兩者**不建帳冊列**，故沒有對應的 `offsite_object_id`。
- 兩欄皆為**顯示用快取**（權威在帳冊），供列表與詳情頁免 join；離機功能從未設定的部署，
  存量與新建會話的 `offsite_status` 恆為空字串。逐態的語義見 [DB_SCHEMA.md](DB_SCHEMA.md) 第 45 節。

### 詳情 / 活動 / 統計 / 終止

```
GET  /api/v1/sessions/:id            → Session＋recording_state／recording_source
GET  /api/v1/sessions/active         → [Session]（純陣列，無封套）
GET  /api/v1/sessions/statistics     → {"active_sessions": 5, "today_sessions": 50, "total_sessions": 1000}
POST /api/v1/sessions/:id/terminate  → {}
```

**詳情的錄影可讀狀態**（只在 `GET /sessions/:id`；列表與活動連線不帶）:

| 欄位 | 值域 | 說明 |
|---|---|---|
| `recording_state` | `available`／`missing`／`unreadable` | 錄影本體目前讀不讀得到。`has_recording=false` 時不出現 |
| `recording_source` | `local`／`offsite` | 只在 `available` 時出現：由本機交付，或需先自離機副本取回 |

- 判定是**唯讀探測**：只檢查本機檔存在、是一般檔、開得了（開即關，不讀內容）；本機不可用而該錄影已排入離機保存時，
  只讀帳冊列判斷有無可用副本（有則 `available`＋`offsite`；帳冊判為完整性不符為 `unreadable`；
  沒有副本時依本機狀況為 `missing` 或 `unreadable`）。**不觸發離機取回、不發網路請求**。
- 探測無法下結論時（例如帳冊查詢失敗）兩欄都**省略**，詳情照常回 200；原因只記伺服器日誌。
- 權限與詳情相同（`session:view`），不產生錄影取證稽核列——看詳情不等於調閱錄影。
- 列表的 `has_recording` 依持久化欄位，不逐列檢查檔案；列表顯示有錄影而詳情顯示讀不到時，以詳情為準。
- 事件報告 ZIP 的 `sessions.csv` 也有一欄 `recording_state`，但值域是 `available`／`purged`／`none`，依持久化欄位與保留期清理水位推算，不檢查檔案；兩者同名不同義，不可互相代換。

終止需 `session:terminate`，且僅超級管理者可執行（否則 403）；已關閉的 session 回 400。

---

## 自助連線 API（my-connections）

> 僅需登入（任何已認證帳號，不需 `session:view`）。owner 一律取自 JWT，回傳呼叫者**自己**的連線精簡紀錄。
> owner 條件由服務層先行固定（取自 JWT），client 無法以查詢參數覆蓋擁有者範圍。

```
GET  /api/v1/my/connections
POST /api/v1/my/connections/:id/terminate
```

**Query 參數**（列表）:
| 參數 | 類型 | 說明 |
|------|------|------|
| `page`, `page_size` | int | 分頁（預設 1 / 20；`page_size` 上限 100，逾者夾為 100） |

任何 client 傳入的 `user_id`（query/body/header/path）皆被忽略，回應永遠僅限呼叫者自己的 session。
穩定排序 `start_time DESC, id DESC`。

**回應** (200): `{"data": [MyConnectionDTO], "total": N, "page": 1, "page_size": 20}`

**MyConnectionDTO**（獨立精簡投影，結構性不含指令/錄影/client IP/目標主機/K8s 快照/憑證）:
```json
{
  "id": 10,
  "asset_name": "Server1",
  "protocol": "ssh",
  "connected_at": "2026-07-01T10:00:00Z",
  "duration_seconds": 1800,
  "status": "active"
}
```

- `id`：session 識別碼，供自助終止指定目標（owner-scoped，對他人 id 一律 404）。
- `connected_at`：session 的 `StartTime`（連線起始，非 GORM 建列時間）。
- `status`：機器值 `active` / `ended`（`disconnected` 與 `closed` 皆歸 `ended`；前端顯示為「進行中/已結束」）。
- `duration_seconds`：`ended` 用持久化 `Duration`；`active` 為 `floor(now - StartTime)`，時鐘異常負值夾為 0。

### 自助終止

```
POST /api/v1/my/connections/:id/terminate
```

owner-scoped 終止呼叫者**自己**的 active 連線（實際斷開 WebSocket，`end_reason=user_terminate`）。owner 一律取自 JWT，`WHERE id=? AND user_id=?` 雙條件取回。owner 檢查即授權，**其安全語義不依賴任何 RBAC 權限判定**。

| 情境 | 回應 |
|---|---|
| 自己的 active 連線 | 200 `{}` |
| 他人的或不存在的 id | 404 `{"error":"連線不存在"}`（無可區分，不洩漏存在性） |
| 自己的非 active 連線 | 400 `{"error":"連線已結束"}` |

> admin/auditor 的全域強制終止仍走 `POST /sessions/:id/terminate`（需 `session:terminate`，且僅超級管理者可執行，`end_reason=admin_terminate`），與自助端點分離。

---

## 指令稽核 API

指令由 SSH 按鍵流重組（Backspace 修正、keypad/Unicode keysym 映射）；
資料庫 CLI（mysql/postgres）以多行語句累積為單一 SQL；K8s logs 唯讀模態不產生指令。
**查詢主控台的每個執行單位同樣寫在本表**，並額外帶結果事實欄（狀態、目標庫、列數、耗時等）；
兩種來源以 `result_status` 是否為空字串區分（空＝文字終端列）。

| 方法 | 路徑 | 說明 | 權限 |
|---|---|---|---|
| GET | `/sessions/:id/commands` | 單會話指令流（seq 升冪，全量）→ `{data, total}` | `session:view` |
| GET | `/commands` | 跨會話搜尋 → `{data, total, page, page_size, degraded_total}` | `audit:view` |

**`/commands` Query 參數**: `keyword`（ILIKE 子字串）、`user_id`、`asset_id`、
`start_time`/`end_time`（RFC3339）、`page`/`page_size`、
`degraded`（`true`＝只要降級列／`false`＝只要有文字的列／未帶＝不過濾；無法解析時不套用）。

**結果事實篩選**（查詢主控台）:

| 參數 | 說明 |
|---|---|
| `source` | `console`＝主控台列／`cli`＝文字終端列／未帶＝不過濾。判別鍵是 `result_status` 是否為空 |
| `target_database` | 送出當下的目標資料庫名（完整比對） |
| `result_status` | 終態，**可重複帶**（`?result_status=ok&result_status=partial` ＝聯集）。值域＝八個非空狀態值 |
| `error_code` | 目標端錯誤碼（完整比對） |

**四者的值域外輸入一律 400 `VALIDATION_BAD_PARAMS`，不套用亦不靜默忽略**——
與上列 `user_id` 之類的寬鬆解析刻意不同紀律：那些解析失敗時得到的是超集（多給，呼叫端立刻看得出來），
而值域外的狀態若照樣送進查詢，得到的是空集，那看起來與「範圍內真的沒有這種列」完全一樣。

四者**只影響結果列，不影響 `degraded_total`**：後者回答的是「這個時間窗／人／資產範圍內
有幾輪沒有文字可搜」，跟著結果事實條件走會讓它在 `source=console` 的查詢下歸零，
而那個事實與主控台無關。

**`degraded_total`**：本次查詢的**時間窗／人／資產範圍內**，
指令文字無法可信重組的輪數。**刻意不套用 `keyword` 與 `degraded` 兩個條件**——
降級列的 `command` 恆為空字串，`command ILIKE '%rm -rf%'` 永遠不會命中它們；
本欄若跟著 keyword 走，稽核人員搜 `rm -rf` 得到 0 筆時它也是 0，
於是「這個區間有 N 輪根本沒有文字可搜」仍然無從得知——而那正是本欄存在的理由
（前端據此常駐誠實橫幅）。

**SessionCommand 欄位**（搜尋結果另附 `username`、`asset_name`）:
```json
{
  "id": 1, "session_id": 10, "user_id": 1, "asset_id": 2,
  "command": "rm -rf /tmp/x", "seq": 3,
  "executed_at": "2026-07-01T10:00:05Z",
  "degraded": false, "degrade_reason": "",
  "k8s_pod": "", "k8s_container": "",
  "result_truncated": false,
  "username": "admin", "asset_name": "Server1"
}
```

主控台列另帶結果事實欄（文字終端列一律留在預設值，故序列化時缺席）:
```json
{
  "event_id": "01JB7Q9K2M4N6P8R0S2T4V6W8X", "target_database": "app",
  "result_status": "partial", "result_reason": "error_after_results",
  "result_rows": 12, "rows_affected": 3, "result_sets": 1,
  "error_code": "23505", "duration_ms": 148,
  "result_truncated": false, "tx_state_after": "active"
}
```
`result_rows`／`rows_affected`／`result_sets`／`duration_ms` 為 null 時代表不適用或未回填。
`running` 停在已結束的會話上＝結果未回填，**不得呈現為「執行中」**。

---

## 告警 API

### 告警規則（需 `alertrule:manage`）

輸入指令只套用啟用的 input 規則；阻斷在送出前執行，告警在指令入庫後比對。輸入規則 CUD 後快取即時重載。輸出旁路只套用 output 規則並產生「可能含敏感資料」告警；新增、停用與修改於新會話生效，進行中的會話沿用啟動時規則集。

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/alert-rules` | 規則列表 → `{data, total}` |
| POST | `/alert-rules` | 新增 → 201；regex 以 `regexp.Compile` 驗證，無效回 400 附原因 |
| PUT | `/alert-rules/:id` | 更新 |
| DELETE | `/alert-rules/:id` | 刪除 |

**請求**（`AlertRuleRequest`）:
```json
{
  "name": "刪除根目錄",
  "pattern": "rm\\s+-rf\\s+/",
  "severity": "high",
  "action": "block",
  "direction": "input",
  "subject_kind": "all",
  "enabled": true
}
```

- `severity`: `high`/`medium`/`low`；`action`: `alert`（預設）/`block`（阻斷）；`enabled` 未傳預設啟用
- `protocols`（逗號分隔協議，空＝全協議，用於 shell/SQL 規則分流）：Create/Update 皆可傳，
  會驗證值域並寫入，非法值回 400（`ErrInvalidProtocols`）；migration/seed 亦會設定

- `subject_kind`: `all`／`human`／`agent`；建立省略為 all、更新省略保留。未知或空字串回 400 `BAD_PARAMS`。規則列表回傳此欄；認證型別未知時僅比對 all，仍執行比對。兩條 agent 專屬 input/block 種子分別防橫向移動與敏感路徑讀取，適用 SSH／K8s；既有 14 條為 all。橫向移動種子比對整行原文，不做 shell 分詞：名稱前須為行首、空白、`;` `&` `|` `(`、反引號、換行、`$`、`=` 或 `\`（中間的引號與路徑前綴會略過），名稱後須為空白、行尾或 `;` `&` `|` `)`（可先接引號）。因此引數位置的同名詞也會命中，例如 `man ssh`、`echo ssh`、`grep ssh file`、`which nc`、`ls /usr/bin/ssh`；名稱前緊接 `.`（`~/.ssh`），或名稱後接 `/`、`-`、`.` 等字元（`/etc/ssh/`、`sshd`、`ssh-keygen`、`ssh.exe`）則不命中。這個邊界刻意從寬，寧可多擋也不漏擋，擋錯的代價是中斷該 agent 的工作。同時命中多條阻斷規則時，歸因於其中規則 id 最小（最早建立）的一條，與規則在資料庫中的儲存順序無關；非阻斷告警則對每一條命中規則各記一筆。出廠種子裡橫向移動規則的 id 小於敏感路徑規則，所以 `scp ~/.ssh/id_rsa host:` 這類兩條都命中的指令歸因於橫向移動。自訂規則沿用一般正則語義，比對邊界由其 pattern 自行決定。
- `direction`: `input`／`output`；Create 未傳預設 input，Update 未傳保留原值。未知值（含顯式空字串）回 400，code=`VALIDATION_ALERT_DIRECTION`。
- 建立與更新皆拒 `direction=output`＋`action=block`，回 400（`VALIDATION_ALERT_OUTPUT_BLOCK`），不寫入資料庫；位元組送達後無從收回。
- 輸出只掃解析後文字流（SSH／K8s／資料庫主控台），不含 RDP／VNC 畫面、加密／壓縮／編碼內容，不剝除終端控制序列；未命中不表示不存在。
- 內建卡號 pattern 原樣時另做 Luhn 校驗；編輯 pattern 後視為一般正則。遮罩只作用於 MCP 通道回給 agent 的文字與任務報告本文（見「MCP agent channel」），人類終端、錄影與指令證據一律保留原文。
- **遮罩是規則驅動、逐條列舉**：套用的是「已啟用、`direction=output`、`subject_kind` 涵蓋 agent、協議相符」的規則集，不是一套通用的敏感資料防護。種子只給兩條（卡號 pattern 與私鑰標頭 pattern），其餘形態（例如密碼雜湊、API 金鑰、個資欄位）沒有對應規則就不會被遮罩也不會告警。部署方須依自身敏感資料清單自行補規則。
- 輸出告警沿既有查詢／通知／syslog 鏈，kind=rule、command 為空，reason_code=`o1:<base36 count>`；同（規則、會話）5 秒內彙總，triggered_at 為首命中時刻。webhook 的 optional `possible_sensitive_output.count` 提供次數，沒有命中原文或位移。
- 旁路佇列溢出停用該場掃描時，稽核查詢可見 action=`output_scan_disabled`、resource=session、resource_id=會話主鍵、details 的 session_id 與 reason=`queue_overflow`；不表示會話被阻斷。

### 告警查詢

```
GET /api/v1/command-alerts
```

**權限**: `audit:view`
**Query 參數**: `severity`（非法值直接 400）、`kind`（來源類別，見下文六類）、`user_id`、`asset_id`、`session_id`（正整數，只列該會話的告警）、`blocked`（`true`／`false`，只列被阻斷／未阻斷的指令告警；會話詳情以 `session_id`＋`blocked=true` 取被擋指令）、`start_time`/`end_time`、
`unreviewed`（`=true` 僅列未審閱＝`reviewed_at IS NULL`，供每日審閱走查，PCI 10.4.1）、`ids`（逗號分隔的告警 id，至多 50 個，供批次審閱中斷後查回每筆的實際處置；格式不合或超過 50 個回 400 `VALIDATION_INVALID_ALERT_ID`）、`page`/`page_size`。`session_id` 非正整數或 `blocked` 非 `true`／`false` 回 400 `VALIDATION_BAD_PARAMS`；各條件 AND 合併。

**回應** (200): `{data, total, page, page_size}`；data 項為 CommandAlert + `username`/`asset_name`，
`rule_name`/`severity` 為觸發當下快照（規則後續改名/刪除不影響歷史）。
data 項另含審閱處置欄位 `reviewed_by`/`reviewed_at`/`disposition`（`pending`/`benign`/`escalated`）/`note`，
以及**可選** `client_ip`（該告警所屬會話的來源位址；查不到所屬會話時整欄不出現）。

**`kind` 六類**（前五類如下，第六類 `system_security` 見下方）：`rule`（規則比對／阻斷）／`audit_degraded`（指令稽核降級）／
`new_source_ip`（**該帳號首次自某來源位址建線**）／`agent_breaker_tripped`（agent 熔斷跳閘）／
`sensitive_reveal`（**稽核者解密調閱了機敏原文**：工具呼叫帳本的機敏參數或剪貼簿內容）。非規則類的 `rule_id` 為 `null`、`command` 為空字串，
機器碼落 `reason_code`（`audit_degraded_span`／`new_source_ip_session`／`RULE_AGENT_BREAKER_TRIPPED`／`sensitive_reveal`）。
另有第六類 `system_security`（系統安全告警：系統對自身高風險設定與授權變更產生的告警），
`rule_id` 為 `null`、`command` 為空字串，`rule_name` 與 `reason_code` 都是類型鍵；細節見「系統告警目錄與明細」。
`sensitive_reveal` 只在安全政策 `alert_on_sensitive_reveal` 開啟時產生（出廠關閉），為 `severity=medium`，`note` 帶來源類別（`agent_tool_call`／`clipboard_event`）、來源 id、任務 id（若有）與調閱者填寫的理由；`command` 不放被調閱的原文。它是「有人看了機敏內容」的加強訊號，逐筆調閱稽核列不論政策開關都存在。
`new_source_ip` 為 `severity=medium`；它記錄的是「這個帳號以前沒從這個位址連過」，
**不表示該次連線被阻擋**——是否放行由允許來源網段（見「用戶 API」）決定，兩者互不影響。

**`reason_code` 字典**：值為穩定機器碼，四種形態——
- 系統安全告警（`kind=system_security`）：類型鍵，見「系統告警目錄與明細」。
- `audit_degraded_span`／`new_source_ip_session`／`sensitive_reveal`：上述非規則告警的固定碼。
- `RULE_*`（如 `RULE_AGENT_BREAKER_TRIPPED`）：系統事件類告警沿用 apierror 碼。
- `o1:<base36>`：輸出面規則告警專用。冒號前為**格式版本**（`o` 表輸出面、`1` 表第 1 版），
  冒號後為該規則在同一 5 秒彙總視窗內的**命中次數**，以 base36 編碼（`o1:2` ＝ 2 次、
  `o1:a` ＝ 10 次）。次數不是規則 id、不是嚴重度、也不是位移；命中原文與位置都不入庫。
  規則身分讀同列的 `rule_id`／`rule_name`。
  此次數與帳本的 `masked_count` 是兩條獨立計數（一條出自輸出流掃描、一條出自回傳值遮罩），
  數值常一致但不保證相等，對帳時各以自身來源為準。

### 告警審閱處置（PCI 10.4.1）

```
POST /api/v1/command-alerts/:id/review
```

**權限**: `alert:manage`（內建超級管理者與稽核員範本持有；一般使用者範本無）

標記告警已審閱並記處置分類與備註；動作入稽核（`resource=command_alert`、`action=update`，
`error_msg=alert_disposition_<disposition>`）。冪等：重覆審閱同一告警視為更新處置（可修正誤判），
`reviewed_at` 刷新為最新。

**請求**:
```json
{"disposition": "benign", "note": "誤報，屬例行維運", "batch_id": "6f1c2a0e-8a4b-4c1d-9e2f-0a1b2c3d4e5f"}
```
（`disposition` 必填，僅接受 `benign`＝誤報/無害 或 `escalated`＝升級處理；`note` 選填，不超過 500 字（超過回 400 `VALIDATION_ALERT_BATCH_NOTE`）；`batch_id` 選填，UUID 格式）

`note` 與 `batch_id` 原樣記入請求的稽核列。

**批次審閱**：前端批次審閱對同一批的每筆告警逐筆呼叫本端點，帶同一個 `batch_id`。帶 `batch_id` 時另有三個條件：
`note` 去除空白後不得為空且不超過 500 字（400 `VALIDATION_ALERT_BATCH_NOTE`）；審閱者自己連線觸發的告警不收
（403 `RULE_ALERT_BATCH_SELF_TRIGGERED`，請改用單筆審閱）；只處置送出當下仍未審閱的告警，已有審閱結果者回
409 `CONFLICT_ALERT_ALREADY_REVIEWED` 且既有處置不變。不帶 `batch_id` 時維持上述冪等語義。批次是逐筆處理，
可能部分完成；`batch_id` 只讓同批送出的各筆稽核列可辨認，未送出的項目不會有紀錄。

**回應** (200): `{"success": true}`

**錯誤**: 400 無效告警 ID、`disposition` 非 `benign`/`escalated`、`batch_id` 非 UUID、`note` 超過 500 字或批次理由不合、403 批次中的本人觸發告警、404 告警不存在、409 批次送出時已有審閱結果、500 內部錯誤。

### 系統告警目錄與明細

系統安全告警（`kind=system_security`）由系統在高風險設定與授權變更、連線時主機金鑰不符、服務啟動時偵測到其他實例的同一交易內產生，
**不能刪除、不能停用，只能調整分級**；告警記錄只隨告警保留期限（`retention_alert_days`）清除。類型由後端登錄表產生，目錄 API 與介面都讀同一份登錄，
登錄共 19 種，分五組：位址與傳輸安全、密碼、身分與權限、系統安全設定、通知。每一種都有對應的產生路徑；
`concurrent_instance_detected`（系統安全設定組，預設 high，操作者為系統）在服務啟動時偵測到可能有其他實例同時運行時產生，
參數為 `signal`（`overridden`／`peers`）、`peers_query`（`ok`／`failed`），並依情形帶 `peers`、`confirm_source`（`env`／`page`）、`confirmed_by`。

| 方法 | 路徑 | 權限 | 說明 |
|---|---|---|---|
| GET | `/system-alert-types` | `systemalert:manage` | 依登錄順序回 `{types: [{key, group, default_severity, effective_severity, adjusted, recent_30d?}]}`；呼叫者另有 `audit:view` 時才帶 `recent_30d`（近 30 天該類型筆數） |
| PUT | `/system-alert-types/:key` | `systemalert:manage` | 只接受 `{"severity": "high" \| "medium" \| "low"}`，回 `{key, severity_before, severity_after}` |
| GET | `/command-alerts/:id/system-detail` | `audit:view` | 一筆系統告警的明細：類型、分組、產生當下的分級、操作者、目標、宣告參數、`correlation_id` 對應的操作日誌 `audit_log_id`（找不到為 null）與該筆的來源位址 `client_ip`（找不到為空字串）、各目的地的 `deliveries[]{dest_type, dest_name, state, attempts, delivered_at?, next_attempt_at}`；`management_role_granted` 另帶 `scope_nodes[]{id, path}`（發放含節點範圍時的節點清單，節點已刪除時 `path` 為空字串），其宣告參數新增 `scope_node_ids`（升冪逗號接）與 `scope_node_count`（不重複節點數，清單被截短時仍為實際數量） |

- `PUT` 嚴格解碼：主體帶 `severity` 以外的任何欄位（含啟停或刪除意圖）回 400 `VALIDATION_SYSTEM_ALERT_LOCKED`；
  值不在三值內回 400 `VALIDATION_SYSTEM_ALERT_SEVERITY`；未登錄的鍵回 404 `NOTFOUND_SYSTEM_ALERT_TYPE`。
  分級覆寫與審計（`resource=system_alert_type`、`action=update`，details 記類型鍵與前後分級）同一交易，
  審計寫不進去即不改分級。沒有刪除或停用的路由。
- `system-detail` 對不存在或不是系統告警的列回 404 `NOTFOUND_COMMAND_ALERT`。投遞狀態 `state`
  四值：`pending`／`retrying`／`delivered`／`abandoned`；明細不含目的地網址、密鑰或錯誤原文。
- 產生告警的業務寫入若告警寫不進去，整筆回滾，回該端點既有的 500 內部錯誤碼（`INTERNAL_SYSTEM_ALERT_RAISE` 用於分級調整寫入失敗）。

**分級只影響呈現與送出順序，不決定是否產生或送出**：每筆系統告警在產生當下為**每一個啟用中的通知通道**
各排一筆投遞，**不受通道 `min_severity` 門檻過濾**；分級（產生當下的有效分級快照）只決定投遞順序
（高、中、低）與畫面上的標示。沒有任何啟用通道時不排投遞、事後也不補送，明細的 `deliveries` 為空；
syslog 轉發照常。啟用中但網址或密鑰密文解不開的通道不擋下產生告警的業務寫入：告警與其他目的地照常，
該通道在 `deliveries` 中是一筆 `abandoned`、`attempts` 為 0 的投遞（伺服器日誌另記原因）；這樣的通道仍可修改或刪除。

**投遞語義**：投遞佇列存在資料庫，由背景程序每 2 秒處理一輪，服務重啟後依資料庫狀態續送。
送達以對端回 2xx 為準。失敗以 1 秒起倍增、上限 10 分鐘的間隔重試，自排入起 72 小時仍未送達即標為
`abandoned`（明細可見，並記伺服器日誌），不提供人工重送。語義為**至少一次**：重試可能讓收端收到重複，
收端以 `delivery_id` 去重：它是排入當下給每筆投遞的隨機識別（32 個十六進位字元的字串，不是佇列列編號），
重送不變；還原備份後新產生的投遞必為新值，不會與還原前發出的識別重複，收端已見識別的紀錄不必重設。重送一律用排入當下的目的地快照，通道之後改址或刪除不影響已排入的投遞。
syslog 轉發由同一背景程序對每筆告警做一次。

webhook 通道收到的形狀（散文不入 payload；有 secret 時沿用 `X-OT-Signature`）：

```json
{"event": "system_security_alert",
 "alert": {"id": 88, "type": "notification_channel_changed", "severity": "high",
           "occurred_at": "…", "actor": {"user_id": 1, "username": "admin"},
           "target": {"kind": "notification_channel", "id": "3"}, "params": {"change": "updated"}},
 "delivery_id": "3f9c2a7e0b1d4c6e8a5f7b9d1e3c5a70", "sent_at": "…"}
```

Slack 通道依該通道的 `language` 由伺服端翻譯目錄渲染類型名稱、分級與參數。

---

## 通知通道 API

**權限**：本節路由（含測試發送）需 `notification_channel:manage`，缺此能力回 403 `AUTH_PERMISSION_DENIED`（單一形狀）。

一般告警（指令規則、稽核降級等）產生時異步推送 JSON payload 至推送門檻放行的啟用通道（見下方 `min_severity`）；設定 secret 時以
HMAC-SHA256 簽名（`X-OT-Signature` header）。失敗重試 3 次（1s/2s/4s）後放棄並記 log。
系統安全告警不走這條路徑，見「系統告警目錄與明細」。

**通道變更本身會產生系統告警**：新增、修改、停用、啟用、刪除通道時，在同一交易內寫審計
（`resource=notify_channel`，沿用 create／update／delete；details 記變更的欄位與遮罩後的前後網址，
不含 secret 與完整網址；傳輸風險確認與門檻前後值併入同一列）並產生 `notification_channel_changed`。
這筆告警除了送到其他啟用通道，**也送到本通道變更前與變更後的目的地**（以類型、網址、secret 去重；
停用與刪除時舊目的地仍會收到）。任一步失敗整筆回滾，通道設定不變。沒有任何欄位實際變動的重複存檔
只寫審計、不產生告警。刪除不等外部回應：通道列在同一交易刪除，通知由投遞佇列在提交後自快照送出。
測試發送不是變更，不產生告警。

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/notification-channels` | 列表 → `{data, total}`（`secret` 不隨 JSON 輸出） |
| POST | `/notification-channels` | 新增 → 201；URL 僅允許 http/https，非法回 400 |
| PUT | `/notification-channels/:id` | 更新 |
| DELETE | `/notification-channels/:id` | 刪除 |
| POST | `/notification-channels/:id/test` | 同步測試發送 |

**請求**: `{"name": "...", "type": "webhook", "url": "https://...", "secret": "", "enabled": true, "language": "zh-TW", "min_severity": "low"}`
（`type` 為 `webhook`／`slack`，未傳預設 webhook；`enabled` 未傳預設啟用；
Update 另可傳 `clear_secret: true` 顯式清除簽名密鑰，Create 忽略此欄）

**`language`（per-channel 語系）**: 三值 `zh-TW`／`en-US`／`ja-JP`，
Create 未傳預設 `zh-TW`；Update **省略＝保留舊值**，顯式傳空字串或白名單外值一律拒
（400＋`VALIDATION_CHANNEL_LANGUAGE`）。僅影響 Slack 通道的伺服端組字語言
（webhook 通道可設但目前無作用，UI 已註明）；列表與詳情回應皆帶此欄。

**`min_severity`（推送門檻）**: 三值 `low`（全部告警）／`medium`（中、高等級）／`high`（只有高等級），
Create 未傳預設 `low`；Update **省略＝保留舊值**，顯式傳空字串或白名單外值一律拒
（400＋`VALIDATION_CHANNEL_MIN_SEVERITY`）。只作用於告警推送：告警等級不低於門檻才推送到該通道，
等級為空或不在三值內照送；系統事件推送與測試發送不受影響。列表與詳情回應皆帶此欄。
門檻實際改變時另寫一筆稽核列（`resource=notify_channel`、details 帶 `changes[]{field,old,new}`）。

**測試回應**:
- 送達對端 (200): `{"success": true, "status_code": 200}`（對端 2xx 才算 success）
- 連線層失敗 (502): `{"error": ..., "code": "INTERNAL_CHANNEL_TEST_CONN_FAILED"}`；
  逾時為 `INTERNAL_CHANNEL_TEST_TIMEOUT`（原始錯誤僅留伺服器日誌，URL 可能含 secret 不回傳原文）

**推送 payload 形狀（散文零入 payload）**

webhook 通道分兩型。**指令告警**（`event` 為 `command_alert`；測試發送同形狀但 `event` 為 `test`）：

```json
{
  "event": "command_alert",
  "alert": {"id": 12, "command": "rm -rf /", "severity": "high",
            "rule_name": "危險刪除", "blocked": true, "triggered_at": "..."},
  "session": {"id": 34, "user_id": 2, "asset_id": 9, "client_ip": "198.51.100.7"}
}
```

- `session.client_ip`（可選）：該會話的來源位址；查不到所屬會話時整欄不出現（純加法，既有欄位集不變）。

- `blocked`（布林）：規則是否為阻斷型，觸發當下快照。原以 `rule_name` 後綴「（已阻斷）」承載散文，**已移除**——`rule_name` 自此為純淨的規則名稱快照。
- 測試發送（`POST /notification-channels/:id/test`）的 `rule_name` 固定為機器識別字 `"test"`，不再夾帶中文「測試發送」字樣。

**系統訊息**（稽核失效／恢復／進行中、每日審閱逾期、存取申請與破窗事件等）：

```json
{"event": "audit_failure",
 "params": {"mechanism": "syslog_forward", "cause_code": "syslog_connect_failed",
            "started_at": "2026-08-01T10:00:00+08:00"},
 "sent_at": "2026-08-01T10:00:00+08:00"}
```

- `event`：具名機器識別字（`access_request.created`／`access_request.approved`／
  `access_request.approval_progress`／`access_request.rejected`／`break_glass_used`／
  `ticket_revoked`／`break_glass_review_overdue`／`audit_failure`／`audit_failure_resolved`／
  `audit_failure_ongoing`／`daily_review_overdue`／`test`）。
- `params`：結構化參數，每個 event 由 `EventSpec` 宣告值層契約（`enum`／`int`／`opaque`／`date_list` 四 kind）；
  opaque 值原樣傳遞不翻譯，經淨化（限長 128 rune、去換行/ANSI/控制字元，超限可見截斷）。
  `date_list` 在 webhook payload 中是 `YYYY-MM-DD` 字串的 JSON 陣列，其餘 kind 的值都是字串。
- `daily_review_overdue` 的 params：`date`（最早未簽日，與 `earliest_pending_date` 同值）、
  `pending_dates`（`date_list`，由最早排起，至多 31 個）、`pending_count`（未簽日的真實總數，可大於清單長度）、
  `overdue_count`（其中已過準時期限的天數）、`earliest_pending_date`、`timezone`（切日的業務時區）。例：

  ```json
  {"event": "daily_review_overdue",
   "params": {"date": "2026-07-29", "pending_dates": ["2026-07-29", "2026-07-30", "2026-07-31"],
              "pending_count": "3", "overdue_count": "2", "earliest_pending_date": "2026-07-29",
              "timezone": "Asia/Taipei"},
   "sent_at": "2026-08-01T01:00:00Z"}
  ```

  Slack 通道把日期逐行列出，總數多於清單時加一行「另有 N 天未列出」。
  去識別紅線不變：事由全文與底層錯誤原文（forensic detail）**不入出站 payload**。
- `degraded`（可選布林）：event 未註冊或 params 不合契約時降級投遞並附此旗標——
  合規告警不因目錄問題靜默消失。
- 舊形狀 `{event, title, text}`（散文 title/text）**已移除**（BREAKING，dev 階段不設相容期）。

**Slack 通道**：送 `{"text": "<mrkdwn>"}`，系統文案（測試通知標題內文、等級與「已阻斷」標示）
一律由伺服端翻譯目錄 `internal/notifycat` 依**該通道的 `language` 欄**渲染；使用者資料
（規則名、指令）原樣呈現只做 Slack `&<>` 跳脫。目錄無鍵時走 generic 降級渲染，仍投遞。

**遮罩**: `secret` 與 `url` 信封加密落庫；回應 `url` 遮罩為
`scheme://host/****末4碼`，全文不外洩。更新時空 `url`／空 `secret` 皆＝沿用既有值
（前端無從回填遮罩值）。

**傳輸政策閘**: 存檔（POST/PUT）受 `transport_notify_level` 政策約束——
`warn` 檔且 URL 為 http 時須帶 `"risk_acknowledged": true`（未帶回 400＋
`{code: "VALIDATION_TRANSMISSION_ACK_REQUIRED", risks}`，確認聲明入稽核）；`strict` 檔拒存 http
（400＋`{code: "VALIDATION_TRANSMISSION_STRICT_REJECT", risks}`）；`off`（預設）行為不變。
（`ack_required`／`strict_reject` 等小寫碼已收斂為 registry 碼，
`risks` 仍以 Meta 平鋪保留供前端確認框列示。）
列表回應每列附 `transmission_deviation`（存量不安全通道誠實標偏離，不自動停用）。

---

## 傳輸安全 API（PCI Req 4）

六通道傳輸強制階梯（off/warn/strict）掛安全政策鍵（`transport_{rdp,vnc,db,ldap,syslog,notify}_level`＋
`transport_consent_ttl_days`），判定核心收口於 `TransmissionPolicyService`（閘門、徽章、清冊共用同一規則）。

### 連線同意（warn 檔連線類通道）

| 方法 | 路徑 | 說明 |
|---|---|---|
| POST | `/connect-tokens` | 簽發前經停用硬擋：資產 `active=false`→**403＋`{reason: "asset_disabled"}`**（授權檢查之後、政策閘之前；admin 不豁免——停用是資產態非權限態，須先重新啟用留稽核）；再經傳輸閘：strict 命中→400＋`{channel, level, risks}`；warn 無有效同意→428＋`{channel, level, risks}`（與 strict 同一 body 形狀）；off/無風險→照常簽發。SFTP 檔案端點同收口（停用資產 403 `asset_disabled`）；token 兌換點（`/ssh`、`/connect`）建線前重查 active——簽發後停用者殘窗內同 403。停用硬擋後另經**錄影前置檢查**（偵測/告警恆做；政策鍵 `recording_failclose_enabled` 開啟且錄影目錄不可寫→**403＋`{reason: "recording_unavailable"}`**，admin 唯一例外放行＋稽核豁免標記 `recording_exemption`） |
| POST | `/transmission-consents` | 傳輸風險同意立據（主體可連線與 connect 授權，同簽發資產邊界） |

以上兩個 POST 的資產不存在或無 connect 權限，皆回 **404** `{"code":"NOTFOUND_ASSET","error":"資產不存在"}`，本文只有這兩欄，相關標頭相同，不回風險或權限原因；兩者均先判資產資格，才進各自後續的政策／風險處理。admin 沿既有 connect 例外，auditor 仍須具 connect 授權。已授權後的 `reason_required`／`approval_required` 403、傳輸同意428及其他政策回應維持。

**同意請求**: `{"asset_id": 9, "risk_keys": ["vnc_unencrypted"]}`（`risk_keys`＝使用者看到的風險項 key 集合）
- 成功 (200): `{"consented_at": "..."}`；同意入稽核（誰／何時／資產／風險項）；per user×asset 冪等更新
- 資產不存在或無 connect 權限 (404): 同上 `NOTFOUND_ASSET` 封套，不寫同意；前端顯示既有資產不存在文案並中止，不再重試簽發
- 風險已變 (409): `{"error": "風險項已變更，請重新確認"}`（TOCTOU 守衛：立據集合與當下不符）
- strict 檔／無風險 (400): 不受理立據（strict 不吃同意、off 無需同意）

**同意有效性**: 效期動態判定（`consented_at`＋`transport_consent_ttl_days`，政策改動立即全域生效；0=永不過期）；
資產傳輸屬性變更→風險項集合雜湊（`risk_fingerprint`）不符→同意自然失效，無需監聽資產寫路徑。

### 通道加密清冊（需 `transmission:manage`）

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/transmission-inventory` | 全通道加密狀態彙整（讀取入稽核，資源分類 transmission） |
| POST | `/transmission-inventory/export` | 匯出 JSON 快照（含 `generated_at`＋`generated_by`，匯出入稽核） |

清冊讀時彙整不落表：資產類 SQL group by 聚合（不逐列）＋部署層設定狀態（LDAP scheme/SkipTLSVerify、
nginx 標「部署方管理」）＋各通道政策等級＋「若切 strict 將被拒資產數／將拒絕 LDAP 登入」預檢。

**通道欄位 i18n**：每個 channel 除繁中 fallback `note`／`strict_preflight`／`detail`（`(未設定)` 等）外，另附機器碼供前端查譯——`note_code`＋`note_params`（查 `transportNote.<code>`，如 `syslog_protocol` 帶 `{protocol}`）、`preflight_code`＋`preflight_params`（查 `transportPreflight.<code>`，`rdp/vnc/db_reject` 帶整數 `{n}` 走 count plural）、`detail_codes`（完整 machine-keyed 明細，技術複合鍵原樣＋`(未設定)`→`unset`，新前端整份取代 `detail`）、`display_params`（供清冊 risk label 查譯，如 syslog `{protocol}`）；風險項 `risks` 沿既有 `{key,label}`，前端以 `key` 查 `riskLabel.<key>`。所有碼欄位 additive omitempty、向後相容；稽核僅記 event 碼、不含中文。

**改密通道（`winrm`）**：資產的改密通道設為 `windows_winrm` 時，該資產同時受其連線協議通道與 `winrm` 通道管轄，
清冊分列一列 `channel: "winrm"`。此通道**無政策鍵、無等級**：改密是系統路徑，不經使用者連線，
不觸發 `/connect-tokens` 的同意閘，也不接受同意立據。`detail_codes` 依 `scheme=http`、`scheme=https,tls=<system|ca|insecure>`
計數，`note_code` 為 `winrm_rotation_channel`；只列設定了該通道的資產（rdp 資產未設通道即不改密，不在此列）。
風險鍵：`winrm_http_ntlm`（scheme 為 http：載荷有 NTLM 訊息層加密但無 TLS）、`winrm_tls_insecure`（https 且 TLS 模式為 `insecure`）；
https 配 `system` 或 `ca` 無風險。兩鍵同時進資產列表的 `transmission_risks`（徽章）與三語 `riskLabel.<key>`。

---

## 金鑰管理 API（需 `key:manage`）

信封加密金鑰清冊與換鑰精靈；系統永不自動輪換，所有換鑰為管理員手動操作。
路徑段 `keys` 由稽核 middleware 歸類為 `key_management` 資源、讀取入稽核。

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/keys` | 金鑰清冊：DB 側金鑰版本鏈（DataKey，不含金鑰材料）＋env 側四鑰一致顯示指紋（KEK／JWT_SECRET 為 secret 摘要指紋，匯出簽章鑰與檢查點簽章鑰為 Ed25519 公鑰指紋，並附公鑰供複製/下載）＋KEK 退役史（from→to）＋切換待收斂提示＋遷移與重包狀態＋超齡提醒 |
| POST | `/keys/rotate` | 輪替金鑰。`{"purpose": "data"}` 生成新 DEK 並批次重加密（上限 `KEY_ROTATION_MAX_PER_RUN`）；現行版本仍有殘值時以現版續跑（回應 `resumed: true`，不鑄新版本），殘值歸零才鑄新版；`{"purpose": "audit_integrity"}` 僅新章換鑰、歷史不重算。KEK 重包待切換期間回 409（`rewrap_pending`，切換完成後恢復） |
| GET | `/keys/topology` | 委託模式的**非秘密**保管處拓撲（主金鑰送去哪裡解）：`{provider, configured, address, transit_key_name, role_id, region, key_ref, editable_fields, digest, updated_by, updated_at}`。`provider` 取自部署檔的 `KEK_KMS_PROVIDER`（**不可經介面改**——金鑰列的 `kek_id` 已釘死哪一家能解）；`key_ref` 取自金鑰列的 `kek_id`，拓撲表不另存一份可與之分歧的副本 |
| PUT | `/keys/topology` | 更新拓撲。請求本文為**該服務商的精確鍵集**：Vault 為 `{address, transit_key_name, role_id}`、AWS 為 `{region}`；GCP 沒有可編輯欄位，一律回 400 `KEY_TOPOLOGY_NOT_EDITABLE`（其完整 CryptoKey 資源名沿 `kek_id`，全新安裝時於解封頁收取）。多一鍵、少一鍵、未知鍵皆拒。逐欄驗證（位址須 `https://`、區域與識別須符合正規形式）；非法值**整筆拒絕且既有值維持不變**，回 400 `KEY_TOPOLOGY_INVALID` 並附 `fields`（只列欄位名，不回顯值）。**變更是安全變更**：成功與被拒都寫入稽核且本文查得到前後值，前後值不同時，於同一交易建立 `key_topology_changed` 系統告警（只帶變更類別，不帶位址；前後值查同交易的稽核列）；稽核或告警寫不進去時整筆回滾、拓撲不變，告警寫入失敗回 500 `INTERNAL_SYSTEM_ALERT_RAISE`。告警紀錄不依賴通知通道；通知通道未設定或不可達時只有紀錄與稽核，介面不得宣稱已通知。核對點（解封頁的唯讀呈現、換鑰精靈的目的地預檢）是本次操作者的核對，**不是**第二人審批，也不阻止直接改資料庫的人 |
| POST | `/keys/rewrap` | KEK 重包：以**呼叫端指定的目標 KEK** 重包全部金鑰、新舊雙包裹並存。請求體為 discriminated union——本地目標 `{mode:"local", new_kek, new_kek_confirm, confirm_saved}`、委託目標 `{mode:"kms", key_ref, region}`／`{mode:"vault", key_ref, address, role_id}`／`{mode:"gcp"\|"hsm", key_ref}`（委託變體自本版起一併收該服務商的拓撲欄位；**憑證不經精靈**，它們只在解封頁輸入）；混合欄位一律 400 拒絕。拓撲於**重包成功之後**才落庫——先落庫的話一次預檢失敗會留下「拓撲指向新保管處、金鑰仍由舊 KEK 包裹」，那是開不了機的形態。**伺服端不生成、不回傳、不落庫、不落日誌任何 KEK 明文**（明文流向反轉）。遷移未完成回 409；委託目標的連通性預檢失敗回 502 `INTERNAL_KEY_REWRAP_TARGET_UNAVAILABLE`；該模式未交付回 501 `VALIDATION_KEY_REWRAP_TARGET_UNSUPPORTED` |
| DELETE | `/keys/rewrap` | 放棄尚未切換的 KEK 重包：**軟退役**新 KEK 的未切換包裹列（`kek_retired_reason=abandoned`，材料保留至顯式清理）、清除待切換狀態，回應 `{"deleted": n}`（鍵名保留 wire 相容，值＝軟退役筆數）。無待切換重包時回 409；另一金鑰操作進行中回 409 `CONFLICT_KEY_OP_BUSY` |
| DELETE | `/keys/retired-material` | 清理退役金鑰材料：**系統唯一的材料銷毀點**。前置全收斂閘（有待切換 pending 或退役 backlog 即回 409 `CONFLICT_KEY_CLEANUP_NOT_CONVERGED`）＋逐 slot 自證（現行 KEK 須有可解包的 live 材料列）＋退役 DEK 版本引用掃描（仍被存量密文或稽核列引用者拒清並逐項回報）。回應 `{"purged": [{purpose, version, kek_id}], "skipped": [{purpose, version, kek_id, refs, reason}]}`；指紋與退役軌跡永久保留，清理後留佔位列使版本鏈不斷號。清理明細顯式留痕稽核 |

**清冊回應**（節錄）: `{"keys": [{purpose, version, status, kek_id, age_days, over_cryptoperiod, material_purged, ...}], "env_keys": [{name, name_code, fingerprint, public_key, managed_by, note, note_code}], "kek_id": "...", "rewrap_pending": false, "kek_history": [{from_kek_id, to_kek_id, retired_at, rows, material_rows}], "finalize_pending": 0, "retire_backlog": 0, "converge_state_error": false, "migration_pending": 0, "rotation_pending": 0, "reminder_days": 0}`
——`rotation_pending`＝現行 data DEK 版本尚未覆蓋的值數（partial 續跑提示）；`migration_pending`＝尚待信封化的 legacy 值數。兩者均以 Go 層嚴格信封判定計數。`env_keys` 四鑰（KEK、`JWT_SECRET`、匯出簽章鑰、檢查點簽章鑰）皆顯示 `fingerprint`，兩筆 Ed25519 另附 `public_key`（base64，供複製/下載，私鑰不外洩）；檢查點簽章鑰另帶 `version`。`kek_history`＝KEK 退役史（每筆 `from_kek_id`→`to_kek_id` 指紋＋退役時間＋退役列數 `rows`，不選取 wrapped_key）；`finalize_pending`／`retire_backlog`＝KEK 切換收尾待收斂筆數（>0 表 best-effort 收尾未竟、需重啟收斂）；`converge_state_error=true` 表上述兩數讀取失敗、數字不可信（UI 顯示未知態並保守禁用清理，不得以 0 呈現為健康）。`material_purged`（每筆金鑰）／`material_rows`（每筆退役史）為材料存量衍生欄位——SQL 端比較運算式產出，不取 `wrapped_key` 本值。

**重包回應**（**恰三鍵，任何分支皆不含明文欄**）: `{"target_mode": "local|kms|hsm", "new_kek_id": "...", "rewrapped_keys": 3}`
——`target_mode` 為 union 判別子；`new_kek_id` 本地目標＝材料指紋、委託目標＝外部識別（KMS 正規 key ARN／HSM `token:label`），皆為非機密。
本地目標：材料由管理員自行提供並保存，重包後存入 `ENCRYPTION_KEY` 後重啟；**遺失即資料永久不可解，系統不提供任何救回途徑**。
委託目標（kms）：重包後 clone 列的 `wrapped_key` 為 `wk:2:kms:` 格式，管理員移除本地 KEK 材料鍵並設 `KEK_PROVIDER=kms` 後重啟。
兩者共通：新 KEK 開機驗證成功才**軟退役**舊包裹列並完成切換（材料保留至顯式清理），未切換前以舊 KEK 照常運作（不鎖死）。回應帶 `Cache-Control: no-store`＋`Pragma: no-cache`。

---

## 剪貼簿稽核 API

> **內容以信封加密落庫**：列表僅回**事實投影**（不含內容），
> 內容須經下方單筆調閱端點解密取得，且**逐筆入稽核**（伺服器端留痕為交付前置，fail-close）。
> 兩端點皆掛 `audit:view`。

### 列表（事實投影）

```
GET /api/v1/sessions/:id/clipboard-events
```

**權限**: `audit:view`（此端點恆掛權限檢查）

**回應** (200): `{"data": [ClipboardEventFact], "total": N}`
```json
{"id": 1, "session_id": 10, "direction": "send", "content_length": 402, "content_status": "available", "created_at": "..."}
```

- 列表為**顯式 DTO**（`clipboardEventFact`），**不含內容**：識別、方向、內容長度、內容狀態、時間。
- `direction`: `send`（入遠端）/ `recv`（回拷）。
- `content_length`: 明文**位元組**數（與 64KB 截斷上限同單位）。
- `content_status`: `available`（內容可調閱）/ `failed`（內容留存失敗的缺口紀錄）；
  呈現端據此區分「可調閱」與「缺口」，**不以密文為空或長度為零推斷**。
- 列表本身入頁面級稽核（`audit_details.result_count`＝本次取走幾筆）。

### 單筆內容調閱（解密＋逐筆留痕）

```
GET /api/v1/sessions/:id/clipboard-events/:eventID/content
```

**權限**: `audit:view`

**回應** (200): `{"data": {...}}`
```json
{"id": 1, "session_id": 10, "direction": "send", "content_length": 402, "content_status": "available", "created_at": "...", "content": "..."}
```

- 伺服器端解密該筆並回全文；**每次調閱逐筆入稽核**（操作者、會話、事件識別、時間；
  `resource=clipboard_event`、`action=read`）。留痕成功是回傳內容的前置條件（**fail-close**）：
  稽核寫入不可用時拒絕該次調閱、回收斂錯誤、不交付明文，該失敗沿既有稽核失敗告警鏈揭露。
- 選填 query `reason`（≤1000 bytes）：調閱理由，有值即進稽核列 details 與 `sensitive_reveal` 告警的 note。
- 安全政策 `alert_on_sensitive_reveal` 開啟時，每次成功交付另發一筆 `kind=sensitive_reveal` 告警（見告警 API）；告警寫入失敗沿稽核失敗告警鏈揭露，不撤銷已交付內容。
- 缺口紀錄（`content_status=failed`）回 200＋事實，但 **`content` 鍵缺席**（不以空字串冒充內容）。
- 以單一受權查詢同時約束事件識別與所屬會話：事件不存在、識別非法、或**不屬路徑中會話**
  三種情形一律收斂為同一 **404 `NOTFOUND_CLIPBOARD_EVENT`**，不洩存在性細節、不產生歸屬錯誤的稽核。

**錯誤**: 404 `NOTFOUND_CLIPBOARD_EVENT`（收斂拒絕）；500 `INTERNAL_CLIPBOARD_QUERY`
（解密失敗／稽核不可用等，原因只進伺服器 log 與告警鏈，對外不展開）。

---

## 錄影 API

**錄製格式**: SSH/DB CLI/K8s exec 為 asciinema v2（`.cast`）；RDP/VNC 為 Guacamole 原生（`.guac`）。
舊 `.typescript` 檔案於首次串流時自動轉換為 `.cast`。

### 錄影元數據

```
GET /api/v1/sessions/:id/recording
```

**權限**: `audit:view`

**回應** (200，`RecordingMetadata`):
```json
{
  "session_id": 1,
  "file_path": "/var/lib/custodexa/recordings/session-1.cast",
  "file_size": 102400,
  "duration": 1800,
  "created_at": "2026-07-01T10:00:00Z",
  "protocol": "ssh",
  "username": "admin",
  "asset_name": "Server1",
  "source": "local"
}
```

`source`：本體來源 `local`／`offsite`（見〈來源判定與離機退路〉）；離機時 `file_size` 取帳冊記載的大小。

### 下載 / 串流

```
GET /api/v1/sessions/:id/recording/download   （audit:view；attachment；支援 HTTP Range）
GET /api/v1/sessions/:id/recording/stream     （audit:view；支援 HTTP Range）
```

- Content-Type：`.cast` 為 `application/x-asciicast`，`.guac` 等其餘格式為 `application/octet-stream`
- 下載以 `Content-Disposition: attachment` 交付，檔名取會話的錄影檔名

### 錄影可讀性判定

metadata、下載、串流與 rtoken 串流四個請求共用同一個判定：本機錄影檔須**存在、是一般檔、開得了**
（判定只開檔即關，不讀內容）。對外只分兩類，細部原因（權限、是否為目錄等）只記伺服器日誌，不進回應與稽核：

| 情境 | 狀態碼 | 機器碼 |
|---|---|---|
| 錄影檔不存在 | 404 | `NOTFOUND_RECORDING_FILE` |
| 錄影檔存在但讀不到：權限不足、取得檔案資訊失敗、路徑不是一般檔（例如是目錄）、開檔失敗 | 500 | `INTERNAL_RECORDING_FILE_UNREADABLE` |

- 錄影未排入離機保存、或離機沒有可取回的副本時，四個請求對同一份本機錄影回相同的狀態碼與機器碼；
  回應一律為錯誤信封（JSON），不交付任何錄影位元組，不回轉址或純文字錯誤。
- 串流與下載在**實際開啟要交付的檔案**時再依同一規則分類（判定之後檔案被刪回 404、被換成目錄回 500），
  `.typescript` 錄影改交付的轉檔快取 `.cast` 亦同。
- 已排入離機保存者，本機讀不到時改由離機副本交付（見下一節）；離機沒有副本時，本機讀不到回 500
  `INTERNAL_RECORDING_FILE_UNREADABLE`，本機缺檔回 404 `NOTFOUND_RECORDING_FILE`。
- 既有差異：下載對已排入離機者比對整檔雜湊、metadata 與串流不比對，故「大小相同而內容被改」的本機檔，
  下載會退到離機、串流仍交付本機。

### 來源判定與離機退路

下載、串流與 rtoken 串流三條路徑在交付位元組之前都會先做**來源判定**：本機副本可讀且大小不小於
帳冊記載者，直接由本機交付（現況行為）；本機檔缺席、開不了或被截斷，而帳冊記載該錄影已離機時，
才改由物件儲存取回。**下載走整檔路徑**，故順帶比對整檔雜湊——大小相同而內容已被改動的本機檔，
在此也會退到離機來源。

取回一律**先落暫存、驗過才交付**（含 Range 播放）：暫存檔的 SHA-256 與大小須與帳冊相符，
不符即刪除暫存、拒絕交付並把該帳冊列標為完整性不符。收口不變——仍走既有的 rtoken 或 JWT 授權，
**不簽發任何指向物件儲存的直連網址**。代價是首次播放的等待與暫存磁碟佔用（容器本地，有存活期與總量上限）。

**離機取回失敗回 409 ＋機器碼**（零位元組交付，並留稽核）:

| 機器碼 | 狀態碼 | 情境 |
|---|---|---|
| `CONFLICT_OFFSITE_INTEGRITY_MISMATCH` | 409 | 取回內容的雜湊或大小與帳冊不符，已拒絕交付 |
| `CONFLICT_OFFSITE_PROFILE_MISSING` | 409 | 帳冊列指向的設定世代不存在（多半是部分還原）；fail-close，不改用現行設定猜 |
| `CONFLICT_OFFSITE_FOREIGN_CREDENTIALS_MISSING` | 409 | 該世代的憑證已撤銷或缺席；**不回退預設憑證鏈** |
| `CONFLICT_OFFSITE_CREDENTIALS_UNAVAILABLE` | 409 | 憑證解密失敗（金鑰事故）。**不併吞為「功能未設定」** |

**稽核的 `source` 與 `fallback_reason`**：離機取回成功時，該次交付的稽核列 `details` 會多帶
`"source": "offsite"` 與 `"fallback_reason"`（值域 `local_missing`／`local_unreadable`／
`local_truncated`／`local_divergent`），記「這一次交付的位元組來自哪裡、為何不是本機」。
**只在離機來源時標記**——本機來源的稽核列與離機功能上線前逐位元組相同，
「未設定＝行為完全不變」在稽核面沒有例外。

> 錄影元數據回應的 `source` 描述該次判定的本體來源；會話層的離機狀態請讀 Session 回應的
> `offsite_status`（見 [Session API](#session-api)）。

### 錄影 token 串流（播放器建議路徑）

```
POST /api/v1/sessions/:id/recording/token     （audit:view）→ {"token": "<rtoken>"}
GET  /api/v1/recordings/stream?rtoken=<token>  （無需 JWT；token 即授權）
```

rtoken 不透明、120 秒 TTL 內可重用、僅授權讀取簽發時綁定的 session 錄影；
取代「把長效 JWT 放進播放 URL query」（避免 JWT 進 access log）。
無效或逾時回 401。

### 刪除 / 統計

```
DELETE /api/v1/sessions/:id/recording   （recording:delete 權限點）
GET    /api/v1/recordings/stats         （audit:view）
```

**刪除錄影（`DELETE /api/v1/sessions/:id/recording`）**：

- **權限**：由路由登錄的 `recording:delete` 把關（設定組、管理類、僅限全域範圍、無依賴權限點；
  超級管理者持有，自訂角色可勾選納入）。它不再是 `session:terminate`，handler 內也沒有另外的 admin 檢查。
  沒有此權限點的主體在路由層得到 403 `AUTH_PERMISSION_DENIED`（單一形狀，所缺的權限點只進審計）；
  產品介面沒有任何刪除入口，只有這支 API。
- **流程與保證**：同一交易內依序鎖定會話列並重讀、寫入稽核（`resource=recording`、`action=delete`，
  details 帶會話 ID、檔案種類、大小與 `correlation_id`，不帶檔案內容）、產生 `recording_deleted` 系統告警
  （同一 `correlation_id`）、清空會話上的錄影欄位；提交成功之後才移除本機檔案。稽核或告警寫不進去時整筆回滾、
  檔案不動：稽核寫入失敗回 500 `INTERNAL_RECORDING_DELETE`，告警寫入失敗回 500 `INTERNAL_SYSTEM_ALERT_RAISE`。
  這筆稽核不受稽核日誌總開關、任何政策鍵或角色影響。會話不存在回 404 `NOTFOUND_SESSION`，
  沒有錄影回 404 `NOTFOUND_SESSION_RECORDING`，兩者都不寫稽核。成功回 200 空 JSON 物件，並使該會話先前簽出的錄影票立即失效。
- **提交後移除本機檔案失敗**：資料庫已不再指向該檔，回 500 `INTERNAL_RECORDING_DELETE`，另寫一筆 `status=failure`
  的稽核（details 帶同一 `correlation_id` 與 `reason=file_remove_failed`），檔案成為孤兒檔。孤兒檔不保證會被保留清理移除：
  `retention_recording_days` 為正數時，保留清理會依檔案修改時間嘗試移除它，但造成移除失敗的原因若仍在，清理同樣會失敗，
  且該輪錄影清理在這個檔案處中止；為 0（永久保留）時沒有任何機制自動清除。請先排除原因，或自行移除該檔。
- **不涵蓋的範圍**：已上傳到離機儲存的遠端物件不會被這支 API 刪除。

**stats 回應** (200): `{"total_size": 10737418240, "count": 100, "oldest_date": "...", "newest_date": "..."}`

`total_size` 取自錄影目錄的實際檔案大小加總（`filepath.Walk`），非 `sessions.recording_size`
欄位之和。**系統不設任何阻擋性儲存上限**：沒有任何建線或錄影路徑會因儲存量而被拒絕，
磁碟容量本身由部署方的基礎設施監控承擔。

---

## 離機儲存 API

> 把錄影與證據包的副本上傳到物件儲存，並在本機副本不可用時由該處取回。
> **全部端點需 `offsite:manage`**（路由登錄的單一權限點，無更細的分項）。
> 儲存桶本身的建立、版本化、保留與生命週期規則歸部署方，產品只上傳、記帳、取回時驗證，
> 並在測試連線與狀態端點**中性揭露**儲存桶的現況（建議參數見 `docs/ops/`）。

```
GET    /api/v1/offsite-storage/settings                        讀取現行設定
PUT    /api/v1/offsite-storage/settings                        寫入設定（可能回「需確認」）
POST   /api/v1/offsite-storage/settings/confirm                確認世代切換
POST   /api/v1/offsite-storage/settings/disable                停止離機（退役現行世代）
GET    /api/v1/offsite-storage/profiles                        歷史世代清單
POST   /api/v1/offsite-storage/profiles/:id/revoke-credentials 撤銷某世代的憑證
GET    /api/v1/offsite-storage/status                          總覽（設定＋佇列＋治理揭露）
GET    /api/v1/offsite-storage/failures                        失敗清單（分頁）
POST   /api/v1/offsite-storage/test                            測試連線（以表單當下值，未儲存）
POST   /api/v1/offsite-storage/retry-failed                    批次重試全部失敗件
POST   /api/v1/offsite-storage/objects/:id/retry               單筆重試
```

### 設定的 write-only 語義

**回應永不含憑證**。讀取投影（`ProfileView`，`GET /settings`、`PUT /settings`、
`/settings/confirm`、`/settings/disable`、`GET /profiles` 共用）固定 17 欄：

| 欄位 | 說明 |
|---|---|
| `configured` | 設定表是否有任何世代（`false`＝從未設定） |
| `disabled` | 有歷史世代但無現行世代（＝已停止離機） |
| `generation_id` | 世代識別（**不可重用**，識別一律用它） |
| `profile_fingerprint` | 設定指紋；**可重複**，只作切換判準與顯示，不是識別 |
| `provider` | `s3`／`gcs` |
| `endpoint_origin` | 端點的**正規化 origin**。path、query 與 fragment 一律不回顯 |
| `bucket`／`prefix`／`region`／`path_style` | 連線參數 |
| `credential_mode` | `stored`／`default_chain`／`revoked` |
| `has_credentials` | 是否存有本世代自己的憑證（布林，**不是遮罩值**） |
| `credentials_cleared_at` | 憑證撤銷時刻（`revoked` 時非空） |
| `created_at`／`activated_at`／`retired_at` | 世代的時刻軌跡；`retired_at` 為空即現行世代 |
| `object_count` | 該世代的帳冊存量（清單端點填入） |

**寫入請求**（`PUT /settings`、`/settings/confirm` 與 `/test` 共用形狀）：
`provider`、`endpoint`、`bucket`、`prefix`、`region`、`path_style`，
憑證欄依 provider 為 `access_key_id`＋`secret_access_key`（s3）或 `service_account_json`（gcs），
另有 `clear_credentials` 布林旗標。憑證欄的三種意圖：

- **填值**＝設定新憑證；
- **`clear_credentials: true`**＝改走雲端 SDK 的預設憑證鏈；
- **兩者皆無＝沿用既存憑證**，但**僅在落點未變時成立**——provider、端點或 bucket 任一改變時，
  沿用既存憑證會被拒（`RULE_OFFSITE_CREDENTIAL_REUSE_ON_MOVE`，409）。換落點必須重新輸入憑證，
  這條規則恰與世代切換對齊：憑證不會跟著設定被送到另一個地方去。

未設定時 `GET /settings` 回 **200 `configured:false`**，不是 404——「還沒設定」是本資源的正常狀態。

### 世代切換的確認流程

`PUT /settings` 算出的新指紋與現行世代不同、且帳冊已有存量物件時，**不逕行儲存**，
改回 **200** ＋確認要求：

```json
{
  "needs_confirmation": true,
  "object_count": 128,
  "expected_current_generation_id": 3,
  "settings_digest": "<sha256>"
}
```

前端據此顯示確認對話框（物件數、舊世代去向），並把後兩個值**原樣攜回** `POST /settings/confirm`。
確認在鎖內依序做：以 `expected_current_generation_id` 對現行世代做 CAS（0＝預期目前無現行世代）→
重算請求體摘要與 `settings_digest` 比對 → **以與 `PUT /settings` 完全相同的驗證核心重驗全部輸入**
→ 重數存量 → 才寫入。同一交易內完成「舊世代退役、新世代建立並啟用、舊世代的帳冊列轉為只讀、稽核」。

CAS 或摘要不符時回 409（`CONFLICT_OFFSITE_SETTINGS_STALE_CONFIRMATION`／
`CONFLICT_OFFSITE_SETTINGS_DIGEST_MISMATCH`），訊息只說「設定已被其他操作變更，請重新讀取後再試」，
**不回顯現行設定的任何細節**。兩名管理員並發確認時先到者成立，任何交錯都不會留下兩個現行世代。

不需確認時（指紋相同，或帳冊零存量）直接回 `ProfileView` ＋ `"needs_confirmation": false`。

**`POST /settings/disable`（停止離機）** 退役現行世代而**不建新列**，該世代的帳冊列一併轉為只讀，
回 `ProfileView`（此時 `configured:true`、`disabled:true`）。**憑證不隨停用撤銷**——歷史取回還要用。
無現行世代時回 409 `CONFLICT_OFFSITE_NO_CURRENT_GENERATION`。

**變更告警**：已有現行世代時，`PUT /settings`（指紋不同且不需確認的直接切換）與 `POST /settings/confirm` 切到新世代，
以及 `POST /settings/disable` 停止離機，都會在同一交易內於保管鏈事件之後建立 `offsite_or_syslog_changed` 系統告警
（`change` 為 `destination_changed` 或 `disabled`；初次建立不告警）。告警寫不進去時整筆回滾、設定不變，
回 500 `INTERNAL_SYSTEM_ALERT_RAISE`。

**`POST /profiles/:id/revoke-credentials`** 在單一交易內清除該世代的密文、置為 `revoked`、
記錄撤銷時刻並使該世代的用戶端快取立即失效，回 **204**。撤銷後該世代的物件取回一律以
`CONFLICT_OFFSITE_FOREIGN_CREDENTIALS_MISSING` 失敗，**不會回退到雲端預設憑證鏈**。
世代不存在或識別非法收斂同一個 404（`NOTFOUND_OFFSITE_GENERATION`）；已撤銷者回 409。

### 測試連線

`POST /offsite-storage/test` 收**表單當下值**（尚未儲存）執行實測。憑證沿用的三條件與寫入相同
（未帶憑證＋落點未變＋未帶 clear 旗標；**先證同落點才解密**）。**兩種失敗語義嚴格分立**：

- **測試未能執行**（請求格式錯、限流、內部錯）→ 4xx／5xx ＋機器碼，回應無 `stages`。
- **測試已執行但其中有失敗** → **200** ＋逐步結果陣列。

```json
{
  "passed": false,
  "stages": [
    {"step": "probe_bucket", "outcome": "ok",   "code": "", "detail": "..."},
    {"step": "versioning",   "outcome": "ok",   "code": "", "detail": "..."},
    {"step": "retention",    "outcome": "warn", "code": "offsite.test_governance_unknown", "detail": "..."},
    {"step": "write",        "outcome": "ok",   "code": "", "detail": ""},
    {"step": "read",         "outcome": "ok",   "code": "", "detail": ""},
    {"step": "delete",       "outcome": "warn", "code": "offsite.test_delete_denied", "detail": "..."}
  ]
}
```

- `step`：`probe_bucket`／`versioning`／`retention`／`write`／`read`／`delete`。
  前三步是**只讀的資訊性揭露**（儲存桶可達性、版本化與保留設定的現況）——
  **只回報現況、不判好壞**，開不開是部署方的決定；讀不到（權限不足）記 `warn`「無法確認，不影響上傳」。
  後三步是寫入、讀回比對、刪除自己的探測物。
- `outcome`：`ok`／`warn`／`fail`。
- `code`：`offsite.test_*` 機器碼（`test_bucket_unreachable`／`test_governance_unknown`／
  `test_write_failed`／`test_read_failed`／`test_read_mismatch`／`test_delete_denied`），成功步為空字串。
  **刪除被拒收斂單一 `warn`、不細分原因**：儲存桶保留設定擋下與憑證缺刪除權限都只是 `warn`，
  而產品的正式路徑對遠端零刪除，不依賴刪除能力；該探測物由部署方的生命週期規則或人工清除，不計入產品追蹤。
- 回應**不含端點 origin 以外的任何連線資訊**，整體結果入稽核。
- **限流**：逐操作者權杖桶（穩態每分鐘 5 次）＋全域在途上限；超出回 **429 `RULE_OFFSITE_TEST_RATE_LIMITED`**，
  且**不揭露命中哪一道界線、不回 `Retry-After`**。端點是管理員輸入的任意主機，此處防的是把服務當成對外探測器。

### 狀態、失敗清單與重試

**`GET /status`**：`ProfileView` 的全部欄位，另加

- `credential_state`：`unconfigured`（無現行世代）／`ok`／`failed`（讀取或解密失敗）。
  **`failed` 不得被讀成「功能未設定」**——那是金鑰事故，上傳與取回會停在失敗態。
- `counts`：帳冊各狀態的計數；`total_objects`：帳冊總列數（管理介面的空狀態判準）。
- `oldest_pending_age_seconds`：各狀態最老待處理件的年齡（秒）。
- `governance`（**僅探測成功時出現**）：`versioning`（`enabled`／`disabled`／`unknown`）、
  `retention`（`none`／`bucket_policy`／`per_object`／`unknown`）與 `retention_detail`（現況描述，無判斷語）。
  探測失敗**不使本端點失敗**——遠端出事時管理員更需要看得到佇列。

**`GET /failures`**：`page`／`size`（預設 1／20），回
`{"data": [...], "total": N, "page": P, "page_size": S}`。每列：`object_id`、`kind`、`owner_id`、
`origin`、`provider`、`bucket`、`attempts`、`error_code`、`generation_id`、`updated_at`；
擁有者模組能描述時另有 `label`、`ended_at`、`retention_deadline`、`days_to_deadline`。
**排序在頁內成立**：距保留到期近者在前、無到期日者殿後——到期日不在帳冊裡，跨頁的全域排序需要
把全部失敗列取出並逐列點查詢。每一頁都看得見「距到期天數」，到期在即的件不會因為排在第二頁而被漏看。

**`POST /retry-failed`** 與 **`POST /objects/:id/retry`** 都回 `{"retried": n}`（重新排入佇列的件數）。
單筆重試在識別非法、帳冊列不存在或該列不可重試時，**一律收斂 404 `NOTFOUND_OFFSITE_OBJECT`**
——三者的差異只對探測者有意義（帳冊列的存在性），對管理員則是同一個修正動作。

### 機器碼

設定與操作面（狀態碼由拒因決定，未列於下者為 400）:

| 機器碼 | 狀態碼 | 情境 |
|---|---|---|
| `VALIDATION_OFFSITE_PROVIDER_INVALID` | 400 | provider 不在值域內 |
| `VALIDATION_OFFSITE_BUCKET_REQUIRED` | 400 | 未填儲存桶 |
| `VALIDATION_OFFSITE_ENDPOINT_INVALID` | 400 | 端點格式不合法 |
| `VALIDATION_OFFSITE_ENDPOINT_HAS_SECRETS` | 400 | 端點帶了帳密、query 或 fragment（端點淨化拒收） |
| `VALIDATION_OFFSITE_REGION_OR_ENDPOINT_REQUIRED` | 400 | region 與端點皆空 |
| `VALIDATION_OFFSITE_CREDENTIAL_HALF_SET` | 400 | 憑證只填了一半 |
| `VALIDATION_OFFSITE_CREDENTIAL_CONFLICT` | 400 | 同時帶新憑證與清除旗標，或帶了與 provider 不相稱的憑證欄 |
| `RULE_OFFSITE_CREDENTIAL_REUSE_ON_MOVE` | 409 | 落點已變更卻要沿用既存憑證 |
| `CONFLICT_OFFSITE_SETTINGS_STALE_CONFIRMATION` | 409 | 確認所依據的現行世代已被其他操作變更 |
| `CONFLICT_OFFSITE_SETTINGS_DIGEST_MISMATCH` | 409 | 確認攜回的設定摘要與請求體不符 |
| `CONFLICT_OFFSITE_NO_CURRENT_GENERATION` | 409 | 該操作需要現行世代，但目前沒有 |
| `CONFLICT_OFFSITE_CREDENTIALS_ALREADY_REVOKED` | 409 | 該世代憑證已撤銷 |
| `CONFLICT_OFFSITE_PROFILE_BUSY` | 409 | 另一項設定變更正在進行（可重試，非內部錯誤） |
| `NOTFOUND_OFFSITE_GENERATION` | 404 | 世代不存在或識別非法 |
| `NOTFOUND_OFFSITE_OBJECT` | 404 | 帳冊列不存在、識別非法，或該列不可重試 |
| `RULE_OFFSITE_TEST_RATE_LIMITED` | 429 | 測試連線超出資源上限 |
| `INTERNAL_OFFSITE_CREDENTIAL_ENCRYPT` | 500 | 憑證加密失敗 |
| `INTERNAL_OFFSITE_CREDENTIAL_DECRYPT` | 500 | 憑證解密失敗 |
| `INTERNAL_OFFSITE_STATUS` / `INTERNAL_OFFSITE_SETTINGS_SAVE` / `INTERNAL_OFFSITE_TEST` / `INTERNAL_OFFSITE_RETRY` | 500 | 各端點的內部錯誤出口 |

取回面的四個 409 見〈來源判定與離機退路〉。全部機器碼三語齊備（介面依碼查譯）。

---

## 自助建立自動化帳號

`POST /api/v1/my/agents` 與 `GET /api/v1/my/agents` 需已認證且啟用中的 human；不需 admin 角色。兩端點不在 agent 路由允許清單，以 agent 憑證呼叫皆回 `403 AUTH_AGENT_FORBIDDEN_ROUTE`；未認證回既有 401。

- POST 請求：`{"username":"nightly-worker","purpose":"每日報表"}`。名稱 trim 後 3–50 字元，用途 trim 後 1–2000 字元；缺欄或值域外回 `400 VALIDATION_BAD_PARAMS`。成功回 `201 {"data":<user>}`，kind 固定 agent、owner 固定認證呼叫者。額外的 owner_user_id、kind、password、roles 等欄位不採信，無可用密碼、不具登入能力，沿用既有角色與審核者守衛。
- GET 成功回 `200 {"data":[<user>],"total":N,"self_create":{enabled,max_per_owner,current},"self_create_enabled":<bool>}`，依 id 排序，只列本人名下未軟刪的 agent（含停用者），不列他人主體。用途不屬 users 欄位，清單不回傳用途。`self_create_enabled` 即政策鍵現值，供介面決定要不要提供建立入口。
- `agent_self_create_enabled` 出廠 false，關閉時 POST 回 `403 RULE_AGENT_SELF_CREATE_DISABLED`；GET 不受此鍵限制，負責人在出廠預設下仍可列出並管理名下既有 agent（列清單與自助建立是兩件事，責任不隨建立入口關閉而消失）。`agent_self_create_max_per_owner` 出廠 3，合法值 1–100，達上限的 POST 回 `403 RULE_AGENT_SELF_CREATE_LIMIT`。上限計入本人所有未軟刪 agent，含管理員建立與停用者；軟刪後釋放額度。上限調低或政策關閉不影響既有主體，管理員 `/users` 建立不受配額限制。
- `alert_on_sensitive_reveal`（bool，出廠 `false`，agent／稽核控制域，不計合規偏離）：開啟後每一次伺服器端解密交付機敏原文——工具呼叫帳本的機敏參數（`GET /agent-tool-calls/:id/arguments`）與剪貼簿內容（`GET /sessions/:id/clipboard-events/:eventID/content`）——除逐筆調閱稽核列外另發一筆 `kind=sensitive_reveal` 告警（人、位置、事件識別、理由）。關閉時只留稽核列。這是高機敏環境的加強訊號，不是留痕本體；告警寫入失敗沿稽核失敗告警鏈揭露，不撤銷已交付內容。

- 自助建立在同一交易內鎖 owner、重讀政策與資格、計數並建立主體；主體投影稽核維持 system actor，另以 owner 為 actor 留 self_service=true、purpose 與兩政策值的建立活動列。任何交易失敗均不留下帳號或上述稽核列。管理員建立不帶 self_service 旗標。無 schema 或 migration 變更。


## 用戶 API

> 帳號管理端點需 `user:manage`；agent token 三端點允許 human 超級管理者或該 agent 的 owner。

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/users` | 列表 → `{data, total}`；query: `search`（用戶名/郵箱）、`active`、`page`、`page_size`、`include_agents=true`（預設只含 human） |
| POST | `/users` | 創建 → 201 `{data: User}` |
| GET | `/users/:id` | 詳情 → `{data: User}` |
| PUT | `/users/:id` | 更新基本資訊（不含密碼/角色） |
| DELETE | `/users/:id` | 軟刪除，同一交易內作廢該帳號的外部身分綁定；不能刪除最後一個管理員（400）。目標帳號持有超級管理者或系統安全管理員身分（任一來源）時只有超級管理者能刪，其他操作者回 403 `AUTH_PROTECTED_ACCOUNT_OPERATION`，該次審計列 `details` 帶 `event=user_delete_rejected`、`deny_reason=protected_account`。審計列帶被刪帳號名稱與作廢的外部身分數（`details` 的 `target_username`、`external_identities_revoked`），`username` 仍是操作者 |
| GET | `/users/:id/role-bindings` | 使用者的直接角色指派 → `{data: [{role_id, role_name, builtin_key, source}], total}`；需 `user:manage`；`source` 為 `manual`、`mapped` 或 `both`；節點範圍的列另帶 `node_ids`，全系統的列沒有此鍵；不含經使用者群組取得的角色；使用者不存在 404（見下文「節點範圍」） |
| PUT | `/users/:id/roles` | body: `{"manual_roles": ["admin", "auditor"], "role_nodes": {…}}`（**替換管理者指派集**，不是有效角色集；`role_nodes` 為選用，見下段與「節點範圍」） |
| POST | `/users/:id/roles/:role` | 冪等追加單一角色（不觸碰其他角色，重複追加 no-op）→ `{}`；未知角色 400。一站式代配（審核範圍表單）用此端點避免整包替換的 lost-update。**副作用**：目標角色若目前只由外部群組映射賦予，本端點會把它釘成管理者指派（見下段） |
| POST | `/users/:id/roles/pin` | body: `{"role": "auditor"}` → `{"role_sets": {…}}`；把一個由外部群組映射賦予的角色**釘住**（改記為管理者一併指派），使它不再隨群組異動消失。該角色不是映射賦予時回 400 `VALIDATION_ROLE_NOT_MAPPED` |
| PUT | `/users/:id/status` | body: `{"active": false}`；不能停用最後一個管理員（400）。停用或啟用（`{"active": true}`）持有超級管理者或系統安全管理員身分（任一來源）的帳號只有超級管理者能做，其他操作者回 403 `AUTH_PROTECTED_ACCOUNT_OPERATION`，該次審計列 `details` 帶 `event=user_disable_rejected`（停用）或 `event=user_enable_rejected`（啟用）、`deny_reason=protected_account`；解除綁定並停用（`POST /users/:id/external-identities/:identityId/unbind-and-disable`）同此限制。解除登入鎖定（`POST /users/:id/unlock`）不改變啟用狀態，不在此限 |
| PUT | `/users/:id/password` | body: `{"password": "..."}`；長度/組成/歷史重用由密碼政策 validator 統一判定（單一事實源；預設最小長度 12、須含字母與數字、禁重用近 N 筆），違規回 400 附可讀原因；LDAP 用戶回 400 |
| POST | `/users/:id/unlock` | 管理員手動解鎖帳號（PCI 8.3.4）：清零 `failed_login_attempts` 與 `locked_until` → `{}`；顯式稽核 action=`unlock` |
| PUT | `/users/:id/inactivity-exempt` | 設定閒置停用豁免（PCI 8.2.6）：body `{"exempt": true}` → `{}`；豁免旗標變更顯式稽核（`inactivity_exempt_granted`/`revoked`） |
| POST | `/users/source-policy/check` | 允許來源網段草稿的判定 → `{data 見下}`；**純判定、不寫任何狀態**（見下段） |
| GET | `/users/local-admin-count` | 現存本地管理員數 → `{"count": n}`；唯讀、不入快取。計數直接來自 `service.CountLocalAdmins`，與「不得自一以上降為零」不變式的判定同一定義（啟用、具 admin 角色、密碼非空、憑證未外部化）。管理端據此條件式警示：`0` 表示遇 KEK 重啟時無人能解封 |

**創建請求**（`CreateUserRequest`）:
```json
{
  "username": "newuser",
  "password": "password123",
  "email": "newuser@example.com",
  "full_name": "New User",
  "roles": ["user"]
}
```
（`username` 3-50 字元、用戶名重複回 400；`email` 依 `kind` 區分：human 必填且需合法，agent 選填（省略或空字串存 NULL），有帶仍須合法；`password` 除 binding 下限外，
另過密碼政策 validator——預設最小長度 12、須含字母與數字，違規回 400 附可讀原因）

建立的 human 帳號一律標記 `must_change_password`：使用者以此處設定的初始密碼首次登入時，
`POST /auth/login` 回 `password_change_required` 與 `change_token`（原因 `must_change`），
完成改密後才換發正式會話。此標記不受 `force_change_on_reset` 政策影響。

**更新請求**（`UpdateUserRequest`）: `{"email": "...", "full_name": "...", "allowed_cidrs": ["10.0.0.0/8"]}`
（`allowed_cidrs` 的 presence 三態見下段——**送 `[]` 會清空既有限制**）

**User 欄位**: `id, username, email, full_name, active, is_ldap, totp_enabled, roles[], created_at, updated_at`，
另含下列可見欄位 `locked_until`、`must_change_password`、`password_changed_at`、
`last_login_at`、`inactivity_exempt`（`password`、`totp_secret_enc`、`failed_login_attempts`、
`totp_last_step` 永不輸出），以及允許來源網段三欄 `allowed_cidrs`、`allowed_cidrs_status`、
`allowed_cidrs_families`（見下段）。

注意：登入/`/auth/me` 回應用的是精簡 `UserInfo`（`id/username/email/full_name/local_display_name/
display_name/active/roles/totp_enabled/is_ldap/external_credential/provisioning_origin/is_approver/
owns_agents/can_self_create_agent/product_version`），
不含上述欄位；完整欄位僅見於 `/users` 管理端點。

### Agent 主體與 token

`User` 另含 `kind`（`human`／`agent`，省略預設 human）、`owner_user_id`（agent 必填）、
`breaker_pending_at`（只讀、可空）。POST `/users` 建 agent 時須省略 `password`，指定啟用中的
human owner，例如 `{"username":"automation-worker","kind":"agent","owner_user_id":12,"roles":["user"]}`；
`email` 對 agent 選填，省略時以 NULL 儲存，多個無 email 的 agent 可並存。
agent 不能登入、改密、使用 MFA，也不能取得 admin／auditor／approver 角色或審核範圍。
`kind` 建立後不可變；PUT `/users/:id` 可更換 agent 的 owner，仍須為啟用中的 human。
把 owner 改為某使用者時，若該使用者曾建立以此 agent 為主體、仍有效的授權規則（含核准產生、尚未到期的臨時授權）、
以此 agent 為申請人的審核範圍，或對此 agent 所提申請投下仍有效的核准票（項目待審中，或已核准且臨時授權未到期），
回 409 `RULE_AGENT_OWNER_TRANSFER_SELF_GRANT`、owner 不變、票不作廢（新 owner 為超級管理者時不判定；
只在轉移當下判定，規則刪除或過期、項目拒絕或臨時授權到期後同一轉移可成功）。
owner 仍有 agent 時刪除回 409，附 `agent_ids`。列表預設排除 agent，顯式 `include_agents=true` 才合併列出。

| 方法 | 路徑 | 請求與回應 |
|---|---|---|
| POST | `/users/:id/agent-tokens` | `{"name":"automation","expires_at":"2026-12-01T00:00:00Z"}` → 201，token 欄位與一次性明文 `token`；`Cache-Control: no-store` |
| GET | `/users/:id/agent-tokens` | 200 `{"data":[AgentToken...]}`，不含明文與雜湊；每列另投影 `created_by_username`（建立者目前帳號名，唯讀、非快照）；簽發世代早於目前還原世代的鑰匙（備份帶回的舊鑰匙，真實入口已拒絕）另帶 `restore_invalidated: true`，為假時不出現；此欄不入庫、只在本列表投影 |
| DELETE | `/users/:id/agent-tokens/:tokenId` | 可帶 `{"note":"rotation"}` → 204，冪等撤銷，並終止該 token 的既有會話 |

三端點只允許 human admin 或目標 agent 的 owner，其他身分為 403。名稱必填且至多 100 字元；
`expires_at` 必填且在未來；`breaker_pending_at` 非空時發證回 409 `RULE_AGENT_BREAKER_PENDING`，
撤銷或重建 token 不清除旗標；清除只經 `POST /users/:id/agent-breaker/release`（見後段「agent 熔斷」），沒有直接寫入旗標的端點。
`AgentToken` 可讀欄位為 `id,user_id,name,created_by,created_at,expires_at,last_used_at,revoked_at,revoked_by,revoke_note,suspended_at,suspended_reason`。
簽發時的還原世代不在回應內。以管理腳本還原備份後，備份帶回的 token 認證一律失敗（同下述 401）；列表上的 `revoked_at`／`suspended_at` 不因此改變，但該列帶 `restore_invalidated: true`，畫面標示為「已因還原失效」。需重新簽發，舊列可照常撤銷。

agent 以 `Authorization: Bearer cxa_…` 認證，每次現查憑證、主體、owner 狀態與來源網段；
不合格一律 401 `AUTH_AGENT_TOKEN_INVALID`，撤銷／停用的真實原因僅記稽核。
允許面為資產與帳號唯讀、建立／查自己的／撤回自己的申請、自身連線清單、任務報告提交與 MCP。
每條允許路由仍受原有權限與所有權檢查；報告與 MCP 由後續 change 實作，此處未提供建線入口。
其餘端點回 403 `AUTH_AGENT_FORBIDDEN_ROUTE`，包含 `POST /connect-tokens` 與
`GET /ssh`、`GET /db-console`、`GET /connect` 三種 WS 握手；不存在的目標亦同。

停用 agent、owner 停用或憑證世代進位、已綁定 provider 失效會停用相關 token 並收線。
撤銷／停用提交後才做實際關閉，部分失敗留痕且不回滾憑證失效。
終止時效目標為 ≤3 秒；超過目標記 `agent_sessions_terminate_late`，不承諾毫秒級時效。
稽核另記 `agent_token_revoked`／`agent_token_suspended` 與 `agent_sessions_terminated`，
終止事件含成功及失敗的會話 ID 清單，超時事件含會話 ID 與實際耗時（秒）。

**帳號來源**：`/users` 列表另回 `auth_provider_names`
（該帳號已綁定的 OIDC provider 實例名陣列，依名稱排序；非持久化欄位，查詢時組出）。
多 provider 並存下管理者要看的是實例名（「Azure AD」）而非籠統的 `oidc`，且綁多個時
全部列出——只顯示第一個會讓人誤判解綁的影響面。

列表查詢參數另支援 `provisioning_origin`（值域 `local`／`ldap`／`oidc`，**未知值回 400
`VALIDATION_USER_ORIGIN_FILTER`** 而非靜默忽略）與 `auth_provider_id`（依 provider 實例篩選）。
兩者皆為伺服端篩選：列表是分頁的，在前端篩當頁會讓使用者看到「第 2 頁明明有 oidc 帳號，
篩選後卻說沒有」。依 provider 篩選以子查詢實作，綁多個身分的帳號不會重複出現。

### 角色的兩份集合（管理者指派與外部群組映射）

一個帳號的角色可能來自兩處：管理者的指派，與外部群組映射在登入時的重算結果。
**有效角色集是兩者的聯集**，而管理端點操作的一律是**管理者指派集**那一半。

**讀取** `GET /users/:id` 的回應多一個頂層鍵 `role_sets`；`data.roles`（有效角色集）保留不動
——拆分是**增加一種讀法，不是換掉原本那一種**。

```json
{"role_sets": {"manual": ["admin"], "mapped": ["auditor"]}}
```

`GET /users/:id` 的回應另有頂層 `account_ops`，列出八個帳號操作（`set_password`、`disable_mfa`、`bind_identity`、`unbind_identity`、`unbind_and_disable`、`disable`、`enable`、`delete`）對目前操作者的分類，值為 `allowed`、`notify` 或 `super_only`。**這只是保護身分這一層的分類，不代表可以執行**：超級管理者操作者一律為 `allowed`；agent、外部帳號、是否啟用多因素驗證、帳號狀態等條件由各服務另行裁決，伺服器的拒絕仍是最終結果。測試：`TestRoleAssignmentProjection`。

`manual` 是帶有管理者指派成分的角色，`mapped` 是帶有映射成分的角色。**兩者並存的角色會同時
出現在兩份裡**，那是實情不是重複。

**替換** `PUT /users/:id/roles`，主體鍵名是 `manual_roles`：

```json
{"manual_roles": ["admin", "user"]}
```

- 主體描述的是**管理者指派集的完整內容**。**舊鍵名 `roles` 一出現即回 400**
  `VALIDATION_ROLES_LEGACY_FIELD`（兩鍵同時出現也拒絕），不會有一半生效的中間態。
- 主體含「目前只由映射賦予」的角色時，該角色**被忽略**：不建列、不改來源、不報錯。
  要把它固定下來請用釘住端點——在替換的語義下把它寫成管理者指派，會讓一次例行的
  角色整理靜默改變它的來源。

成功回應（200）：

```json
{"role_sets": {"manual": ["admin"], "mapped": ["auditor"]},
 "disclosures": [{"code": "role.mapped_ignored", "params": {"roles": "auditor"}}]}
```

`disclosures` 這個鍵一定存在，沒有東西被忽略時為 `null`；`params.roles` 是逗號分隔的角色名字串。
**後端不回散文**，對外文字一律由介面依機器碼決定。

#### 節點範圍

`PUT /users/:id/roles` 與 `PUT /user-groups/:id/role-bindings` 是僅有的兩個可以寫入節點範圍指派的入口，兩者都是整組替換。本文多收一個選用欄位 `role_nodes`，把角色對應到範圍：

```json
{"manual_roles": ["user", "ops-lead"], "role_nodes": {"ops-lead": [12, 15]}}
{"role_ids": [3, 7], "role_nodes": {"7": [12, 15]}}
```

鍵在使用者入口是角色名，在群組入口是角色 ID 的十進位字串。值的語義兩個入口相同：

- 鍵不存在：本次送出的角色清單內，已持有的角色保留現有範圍，新加入的角色為全系統。
- 物件內某個角色的值為 `null`：該角色改為（或維持）全系統。`role_nodes` 整體省略或整體為 `null`，均視為沒有指定任何角色的範圍，依上一項「鍵不存在」處理；角色移出清單與下述來源改變照常生效。
- 值為非空的節點 ID 陣列：改為這個節點集合，重複的 ID 去除後儲存，父子節點重疊時不合併。
- 值為空陣列：400 `VALIDATION_ROLE_BINDING_NODES_EMPTY`。這在請求通過其他前置關卡、且該角色不是被忽略的映射角色時成立。
- 鍵不在本次送出的角色清單內，或 `role_nodes` 的形狀不是「物件（整體 `null` 除外），值為 `null` 或無號整數陣列」：400 `VALIDATION_BAD_PARAMS`，整筆拒絕。
- 使用者入口中，只由外部群組映射持有的角色帶 `role_nodes` 會被忽略，與 `manual_roles` 對這類角色的處理相同。
- 使用者入口中，來源為 `both`（手動與映射並存）的角色，`role_nodes` 作用於這一筆直接指派，手動與映射兩個來源共用同一範圍。若本次送出的 `manual_roles` 不再含這個角色而映射仍在，來源改為 `mapped`，節點限制隨之清除，該角色改回全系統生效。管理介面在管理者於「管理者指派的角色」移除這類角色時，直接在「來自映射的角色」中該角色那一列提示該角色仍由外部群組給予、移除後改為全系統生效（角色原本就是全系統時只提示仍由外部群組給予），不加確認步驟，也不阻擋儲存。

節點範圍只能給權限集合全是「可依節點生效」的角色。角色含任何只能套用到全系統的權限（例如稽核類權限點）時，帶節點範圍回 400 `VALIDATION_ROLE_NOT_NODE_SCOPABLE`；節點不存在或已刪除回 400 `VALIDATION_ROLE_BINDING_NODES_INVALID`，兩種情形同形，不帶節點名稱。任一拒絕都整筆零寫入。其餘關卡（保護角色、指派能力、審核者不能指派給群組）與全系統指派相同。另有一項限制：涉及 agent 的指派不能帶節點範圍，即使角色是一般使用者或空權限集，也回 403 `AUTH_PERMISSION_DENIED`。已持有的角色範圍有變時，另留一筆審計（`details` 事件 `role_binding_range_changed`）並推進權限版本；若範圍縮小使該使用者失去原本涵蓋、且其他指派未補回的範圍，另推進受影響使用者的憑證世代並撤銷其 refresh token，純擴大不會。

這兩個入口以外的指派入口不收範圍：冪等追加、建立帳號帶角色、釘住的請求帶範圍或節點欄位，回 400 `VALIDATION_ROLE_BINDING_SCOPE_UNSUPPORTED`。外部群組映射不提供範圍設定，請求帶 `nodes`、`node_ids`、`scope`、`scope_kind`、`scope_nodes` 任一欄位且值不是 `null` 時，回 400 `MAPPING_SCOPE_FIELD_REJECTED`；其他欄位（例如 `role_nodes`）不保證被拒絕，可能被忽略，勿傳給映射入口。兩個整組替換入口收到 `role_nodes` 以外的範圍或節點欄位（鍵名含 `scope` 或 `node`）回 400 `VALIDATION_ROLE_BINDING_SCOPE_UNSUPPORTED`。冪等追加一個已以節點範圍持有的角色時，不改它的範圍。

**成功回應的 `node_range_no_effect`**：寫入後，該對象自身的節點範圍指派中，依角色定義分類為「範圍不生效」的全部角色（使用者入口只含直接指派，不含經群組取得的角色），每個元素為 `{"role": <角色>, "reason": <原因>}`。`role` 與該入口 `role_nodes` 的鍵同形，包含本次請求沒有改動、甚至沒有帶 `role_nodes` 的角色；清單為空時不出現這個欄位。`reason` 有兩種：

- `builtin_global_only`：內建的一般使用者與審核者只在全系統指派時生效，限定節點後不產生權限。通過其他指派關卡的使用者直接指派，系統照常儲存，並在這個欄位與管理介面的畫面上提示，不擋下也不改為全系統；審核者仍不能指派給使用者群組。
- `no_scoped_permission`：自訂角色不含任何會依節點範圍生效的權限點（例如空權限集），範圍不會產生權限。

這不是節點是否仍有效、也不是全部授權結果的診斷清單。對象只有全系統指派時，回應形狀與沒有這個功能時相同。

**讀取**：`GET /users/:id/role-bindings` 與 `GET /user-groups/:id/role-bindings` 用同一條規則：列有 `node_ids` 欄就是節點範圍，沒有就是全系統（群組端點改以 `scope` 為準，節點集合為空的異常資料可能省略 `node_ids`，不得據此視為全系統）。`node_ids` 只回節點 ID，照實列出，含已被刪除的節點 ID；名稱、路徑與台數不在這裡回。群組端點的每列另有 `scope` 鍵（`global` 或 `nodes`），使用者端點沒有 `scope` 鍵。

節點範圍只限制這個角色的權限適用於哪些節點，不會因此授予連線到節點下資產的權限；連線仍由授權規則決定。

**釘住** `POST /users/:id/roles/pin`（主體 `{"role": "auditor"}`）把一個由映射賦予的角色
改記為「管理者一併指派」。**有效角色集不變**，故不推進憑證世代、不改變任何人當下能做的事；
變的是它不再隨群組異動消失。釘住與映射規則共用同一道寫入關卡（見「身分來源與外部群組映射」的
「寫入關卡與錯誤碼」）：非超級管理者釘住超級管理者或系統安全管理員角色回 403
`AUTH_PROTECTED_ROLE_ASSIGNMENT`。釘住在同一交易內寫一筆審計（`role_mapping_pin`），釘住自己或釘住他人的
管理類角色另產生系統告警；審計寫不進去時角色維持原本的映射來源。已是兩者並存的角色再釘一次不寫審計。舊的 `POST /users/:id/roles/:role`（冪等追加）對映射角色
有同樣的副作用——一站式代配審核範圍時順帶追加角色，會把該角色釘成管理者指派。

**本地管理員計數只認管理者指派的成分**（`GET /users/local-admin-count` 與
「不得自一以上降為零」的不變式同一定義）：只由映射賦予的管理員角色會隨群組異動在下一次
登入消失，撐不住遇 KEK 重啟時的解封能力。

### 允許來源網段（`allowed_cidrs`）

限制某個帳號**可以從哪些來源位址使用系統**。清單為空＝不限來源。
它限制的是可用來源，**不是**帳號憑證的強度，也不取代密碼政策、鎖定或多因素。

**回應三欄**（Create／Update／Get／List 皆有）：

```jsonc
{
  "allowed_cidrs": ["10.0.0.0/8", "198.51.100.0/24"],  // 已正規化、去重、排序
  "allowed_cidrs_status": "restricted",                 // 見下表
  "allowed_cidrs_families": ["v4"]                      // 僅 effectively_unrestricted 時出現
}
```

| `allowed_cidrs_status` | 語義 |
|---|---|
| `unrestricted` | 清單為空＝不限來源 |
| `effectively_unrestricted` | 清單非空但含全域前綴（`0.0.0.0/0` 或 `::/0`），**實際等同不限**；`allowed_cidrs_families` 指出被全放行的是哪一族（`v4`／`v6`／兩者） |
| `restricted` | 其他 |

**本欄由伺服端算出，前端不得自行推導**——「清單非空即已限定」在含全域前綴時會把實際放行呈現為受限。

> **命名注意**：`User` 物件上的欄位是 **`allowed_cidrs_families`**；
> 下方判定端點回覆裡的同一份資料則叫 **`families`**。兩者**不同名**，串接時勿互換。

**`PUT /users/:id` 的 presence 三態**（最容易做錯的一點）——**缺欄＝保留、`null`＝保留、`[]`＝清空**：

| 送出的 body | 後端行為 | 欄位級稽核 diff |
|---|---|---|
| **省略** `allowed_cidrs` 欄 | 保留現值 | 無該欄 |
| `"allowed_cidrs": null` | 保留現值（**與省略同**） | 無該欄 |
| `"allowed_cidrs": []` | **清除為不限來源** | 記前後清單 |
| `"allowed_cidrs": [...]` | 整體取代 | 記前後清單 |

把整份表單物件送出的客戶端請注意：**未編輯清單時要送 `null` 或省略該欄，不可送 `[]`**
——後者會把既有限制清空。

驗證失敗**整體拒絕**（不靜默丟棄任何一項）：
- `VALIDATION_SOURCE_PREFIX_INVALID`（400）：含無法解析為位址或 CIDR 的項目
- `VALIDATION_SOURCE_PREFIX_LIMIT`（400）：去重後超過 32 項

**判定端點**（前端不自行判落入）：

```
POST /api/v1/users/source-policy/check
```

**權限**: `user:manage`。**純判定**：不寫任何狀態、不儲存草稿。
判定權單一化是刻意的——IPv6 縮寫、IPv4-mapped 位址對 IPv4 前綴、遮罩正規化
（`10.1.2.3/8` → `10.0.0.0/8`）這些行為在兩套實作之間必然分歧，分歧的後果是
介面說「你還進得來」而下一次登入被擋在門外。本端點與登入、刷新、簽發、兌換各判定點
共用同一份判定實作。

**請求**:
```jsonc
{
  "allowed_cidrs": ["10.0.0.0/8"],   // 草稿清單（尚未儲存）
  "address": "203.0.113.9"           // 省略＝以本請求的來源判定（自鎖預警走這條）
}
```

**回應** (200):
```jsonc
{
  "valid": true,                      // 清單整體是否合法
  "items": [                          // 逐項結果，順序同請求
    {"input": "10.1.2.3/8", "normalized": "10.0.0.0/8"},
    {"input": "bad", "error_code": "invalid"}        // 或 "too_many"
  ],
  "normalized": ["10.0.0.0/8"],       // 去重排序後（清單合法時）
  "status": "restricted",             // 同上表的 allowed_cidrs_status 三值
  "families": ["v4"],                 // 僅 status 為 effectively_unrestricted 時出現
  "source": {
    "address": "203.0.113.9",         // 不可解析時為顯式 null（不是空字串）
    "reason": "provided"              // "request"（取自本請求）｜"provided"（呼叫端指定）｜"unresolvable"
  },
  "allowed": false                    // 該來源在此清單下是否放行
}
```

`allowed` 的判準與各強制點**同源**且 fail-close：清單不合法、或清單非空而來源不可解析
皆為 `false`；清單為空為 `true`。自鎖警告直接消費本欄。

**稽核語義為讀取**（`action=read`、`resource=user`）。POST 的動詞推導預設會把它記成「建立使用者」
——那是假事件，故中介層依路徑訂正為讀取。該列的 `details` **記形狀不記內容**，六個鍵：

| 鍵 | 值 | 答的問題 |
|---|---|---|
| `check` | `source_policy` | 這一列是哪一種試算 |
| `cidr_count` | 草稿項數 | 送了幾條進來 |
| `valid` | `true`／`false` | 草稿本身合不合法 |
| `address_source` | `request`／`provided`／`unresolvable` | 試算的是他自己的來源還是指定的位址 |
| `allowed` | `true`／`false` | 試算結果 |
| `status` | 涵蓋狀態（**僅 `valid=true` 時才寫**） | 這份草稿等不等於不限 |

**草稿清單與被試算的位址一律不進 `details`**：那是一份從未儲存的草稿，寫進去等於把試算輸入
永久留存於受檢查點鏈保護、刪不掉的紀錄裡，卻換不到任何課責。
草稿本體另由 `request_body` 承擔：`allowed_cidrs` 自 2026-08-26 起登記為稽核放行的實質欄位
（清單變更是安全開關，不放行就與改名寫出同一列），而遮罩以鍵名為單位、分不出端點，
故本端點的草稿清單也會原樣入庫；被試算的 `address` 不在白名單內，入庫即為 `***MASKED***`。

**自鎖與復原**：後端**不阻擋**把自己鎖在外面的儲存（管理者可能刻意設定尚未切換過去的網段），
介面只就近顯示 warning。真的鎖住時的復原途徑見
`docs/ops/deployment-topology-limits.md` 的「允許來源網段對部署的影響」段。

---

## 角色 API

```
GET /api/v1/roles
```

**權限**: `role:view`

**回應** (200): `{"data": [{"id": 1, "name": "admin", "description": "..."}], "total": 3}`
（預定義角色：`admin` / `user` / `auditor`）

**相容邊界**：本端點只列升級前存量的角色目錄，欄位與排序語義不變；升級新增的兩個鎖定範本與日後建立的自訂角色不會出現在這個列表。可指派的角色不以這個列表為限：指派相關入口（`PUT /users/:id/roles`、`POST /users/:id/roles/:role`、`POST /users/:id/roles/pin`、建立帳號帶角色、使用者群組角色指派、外部群組映射的角色目標）同樣接受這兩個範本與自訂角色，並照常經過保護角色、指派能力、範圍欄位與 agent 規則（見「角色指派的保護與開放邊界」）；自訂角色不能直接映射，要經使用者群組。全部角色與各角色對目前操作者的指派狀態，以及角色定義的讀取與寫入，走下一節的 `/role-definitions`，本端點不變（資料表見 `docs/DB_SCHEMA.md` 第 67 節）。

---

## 角色定義 API

八條路由，路徑前綴 `/api/v1/role-definitions`。與上節的 `GET /roles`（相容目錄）並行，後者不變。

**權限**：四條讀取路由（列表、單筆、描述、摘要試算）需 `role:view`。四條寫入路由（新增、複製、修改、刪除）在路由層只要求已認證，**超級管理者限制只在服務交易內重驗**，沒有路由層的角色閘；非超級管理者呼叫寫入回 403 `AUTH_PERMISSION_DENIED`。

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/role-definitions` | 列表 → `{data, total, can_define}` |
| GET | `/role-definitions/:id` | 單筆 |
| GET | `/role-definitions/descriptors` | 編輯器用的描述資料（三組） |
| POST | `/role-definitions/summary` | 以一組權限鍵試算摘要，不寫資料 |
| POST | `/role-definitions` | 新增自訂角色 → 201 |
| POST | `/role-definitions/:id/copy` | 複製為新的自訂角色 → 201 |
| PUT | `/role-definitions/:id` | 修改名稱、說明與權限 → 200 |
| DELETE | `/role-definitions/:id?expected_version=N` | 刪除自訂角色 → 204 |

**列表每列**：`id`、`name`、`description`、`builtin_key`、`locked`、`definition_version`、`template_role_id`、`summary`，以及列表專有的投影欄 `assignment_state`（`open`／`not_open`／`protected`）、`management_class`、`direct_mappable`、`group_bindable`、`user_count`、`references`（`direct`、`group_bindings`、`mapping_rules` 三個計數；`direct` 只計未刪除帳號的直接指派，停用中的帳號計入），以及節點限定的兩個布林 `scopable`、`node_range_no_effect`（見下「節點限定欄位」）。`summary` 含 `manage`、`partial`、`read`、`available`、`hidden`（權限鍵分組；`partial` 是持有入口的寫入鍵、卻未涵蓋管理態全部鍵的入口，不再列入 `read`）、`permission_count`、`catalog_count`、`scope_global_only`、`connection_separate`、`assignment_trust_hint`、`unattributed`（不屬任何入口或獨立能力的權限鍵；部分管理入口已持有的鍵不再列入）。兩個鎖定範本與自訂角色都會出現在列表中。`assignment_state` 依目前操作者計算：超級管理者看到的每個角色都是 `open`；其他操作者看到保護角色（超級管理者、系統安全管理員，以及含高風險權限點的自訂角色，見「角色指派的保護與開放邊界」）為 `protected`，其餘為 `open`。`not_open` 表示角色不在可指派的目標集合內，本版的目標集合涵蓋全部角色，因此不會出現。`open` 只表示不受保護角色與目標集合限制，操作者能否指派仍由指派入口依指派能力與 agent 規則裁決。測試：`TestRoleAssignmentProjection`、`TestRoleDefinitionRoutes`。

**單筆**：同列表欄位去掉投影欄（`assignment_state`、`management_class`、`direct_mappable`、`group_bindable`、`user_count`、`references`），加 `permissions`、`missing_dependencies`、`blocked_screens`，以及 `scopable`、`node_range_no_effect`、`node_scoped_binding_count`。新增、複製、修改的成功回應同為單筆形狀，三個欄位一併帶出。

**節點限定欄位**（只增加讀取欄位，路由與寫入 body 不變）：
- `scopable`（布林）：角色可否在指派時限定節點，若且唯若角色的權限集合不含任何只能全系統生效的權限點。內建一般使用者與審核者為 `true`（可寫入節點範圍，但見下一欄）；超級管理者、稽核員、身分管理員與系統安全管理員含只能全系統生效的點，為 `false`；資產管理員與授權管理員為 `true`。與 `GET /role-assignment-options` 的 `node_assignable_role_ids` 同義。
- `node_range_no_effect`（布林）：限定節點後範圍是否不會產生權限。內建一般使用者與審核者為 `true`：內建一般使用者與審核者只在全系統指派時生效，限定節點後不產生權限，系統照常儲存並提示；權限集合為空的自訂角色也為 `true`；含任一只能全系統生效或尚未實作節點限定的權限點時，`scopable` 與本欄皆為 `false`，指定節點的寫入會被拒絕。資產管理員與授權管理員為 `false`。注意這個鍵與 `PUT /users/:id/roles`、`PUT /user-groups/:id/role-bindings` 寫入回應的 `node_range_no_effect` 同名不同型（那裡是 `[{role, reason}]` 陣列），不可共用解析。
- `node_scoped_binding_count`（整數，**只在單筆讀取與寫入成功回應**，列表不帶）：目前以節點範圍持有此角色的指派筆數，直接指派與使用者群組指派合計；直接指派只計未刪除帳號，停用中的帳號計入。
- 列表與單筆依角色本身（內建識別加權限集合）判定；草稿摘要與編輯描述沒有內建識別，以「自訂角色加該集合」判定。

**描述**（`GET /role-definitions/descriptors`）三組：`entries`（每項 `id`、`group`、`states[{name, keys}]`、`write_keys`、`details[{id, key, scopable}]`、`scopable`；`write_keys` 是依歸屬入口規則算出的寫入鍵：管理態中歸屬於該入口、且不在該入口唯讀態的鍵，前端據此判定部分管理）、`capabilities`（每項 `id`、`key`、`trust_hint`、`requires_entry`、`scopable`；目前三項：`role_assign`、`access_policy_override`、`recording_delete`，只有 `role_assign` 的 `trust_hint` 為真）、`fixed_entries`（固定入口，7 項）。`scopable` 是新增的布林：細項與獨立能力各對應一個權限點，該點在節點範圍指派下會依節點生效即為真；入口以其最後一態（管理或可用態，含依賴鍵）的完整權限集合判定，該集合在節點範圍指派下會依節點生效才為真，含任一只能全系統生效的鍵（例如依賴鍵中的使用者管理）或沒有任何會依節點生效的鍵時為假。

**摘要試算**（`POST /role-definitions/summary`）：body 只收 `{"permissions": [...]}`，嚴格解碼；回 `{summary, missing_dependencies, blocked_screens, scopable, node_range_no_effect}`，後兩個布林是新增的草稿判定（不套用內建識別，把草稿當自訂角色）。含不合法的權限鍵回 400 `ROLE_PERMISSION_INVALID`。

**寫入 body**（皆嚴格解碼，多餘鍵回 400 `VALIDATION_BAD_PARAMS`）：新增 `{name, description, permissions, template_role_id}`；複製 `{name, description}`；修改 `{name, description, permissions, expected_version}`，其中 `permissions` 與 `expected_version` 必帶；刪除不收本文，`expected_version` 以查詢參數帶入且必須是唯一的查詢參數。新增、複製、修改的成功回應為單筆形狀。

**寫入錯誤**：

| HTTP | 碼 | 情形 |
|---|---|---|
| 400 | `VALIDATION_BAD_PARAMS` | 欄位缺漏、多餘或格式錯誤 |
| 400 | `ROLE_PERMISSION_INVALID` | 權限集合含不合法項目，整筆拒絕 |
| 403 | `AUTH_PERMISSION_DENIED` | 操作者不是超級管理者 |
| 403 | `AUTH_PERMISSION_DENIED` | 僅 `PUT /role-definitions/:id`：修改後的權限集合含自動化主體（agent）不得持有的管理、稽核或審核類權限點，而已有 agent 經直接指派或經使用者群組持有該角色。與指派 agent 時的角色拒絕同碼同形（body 只有 `error` 與 `code`，不帶 agent 清單或權限點），角色內容、版本與指派不變 |
| 404 | 角色不存在 | 目標角色不存在 |
| 409 | `ROLE_DEFINITION_LOCKED` | 內建角色與鎖定範本不可修改、刪除 |
| 409 | `ROLE_DEFINITION_IN_USE` | 刪除時仍有未刪除帳號的直接指派（停用中的帳號計入）、群組指派或有效的外部群組映射 |
| 409 | `ROLE_DEFINITION_CONFLICT` | 期望版本已過期，或名稱已被使用 |
| 500 | `INTERNAL_ROLE_DEFINITION_WRITE` | 內部失敗；原因只進伺服器日誌，回應不帶角色名或權限名 |

測試：`TestRoleDefinitionRoutes`、`TestRoleDefinitionWriteWiring`、`TestRoleDefinitionExposureBoundary`。

**修改與 agent 持有者**：修改自訂角色的權限集合時，伺服器在鎖定該角色之後的同一交易內讀取已提交的持有者（直接與經群組，未刪除的 agent），新集合含 agent 不得持有的權限點且有任一 agent 持有時，整筆拒絕（上表第二個 403），判定與指派 agent 時同一規則。**拒絕細節併入該次請求的審計列**，不另寫獨立的審計：該列的 `action` 是依路由分類的 `update`、資源為角色、`resource_id` 為該角色、狀態為拒絕，`details` 帶 `deny_reason`（`agent_role_forbidden`）、`agent_count`（受影響的 agent 數）與 `restricted_permissions`（新集合中 agent 不得持有的權限點，逗號分隔、升冪）；細節不放進回應。不涉及 agent 的修改照常。修改與 agent 的指派並發而兩筆都提交時，提交前的檢查看不到彼此，因此兩側各在自己的寫入提交之後以新交易重查：命中時建立 `management_role_granted` 系統告警（目標為該 agent，`path` 為 `role_update_detected` 或 `assignment_detected`），並寫審計 details 事件 `role_update_agent_restricted_detected`（帶角色、agent、`detected_by`）；登入時外部身分映射重算觸發的重查沒有可指認的操作者，只寫審計、不建告警；這項偵測發生在寫入生效之後，不回復也不阻擋該寫入，告警或審計寫入失敗只留伺服器日誌。

**修改的告警**（`TestRoleDefinitionGrantEvents`）：以權限集合的差判定，只改名稱或說明不產生事件。操作者本人持有該角色時，有新增的權限鍵為高分級、只有移除為低分級（沿用 `self_privilege_increased`／`self_privilege_decreased`，參數 `path=role_definition`）。新增的權限鍵含管理類權限，且角色有操作者以外的持有者、被使用者群組指派或被映射規則指向時，產生一筆以角色為目標的 `management_role_granted`（目標種類 `role`，不逐持有者展開）。事件、審計與角色內容在同一交易內寫入；被修改的角色有持有者或引用，而分級器未注入時整筆拒絕。新增與複製沒有持有者；刪除有任何引用即被拒。

**自訂角色與範本的指派**：自訂角色與兩個鎖定範本可經「角色 API」相容邊界列出的指派入口指派，照常經過保護角色、指派能力、範圍欄位與 agent 規則；自訂角色不能直接設為外部群組映射的目標，要經使用者群組（見外部群組映射的目標規則）。`GET /roles` 的列表內容不因此改變。

---

## 安全政策 API（需 `securitypolicy:manage`）

安全政策的 key-value 設定。政策值以字串儲存，型別語義與值域由服務層常數表定義，
各組規範對各鍵的要求則是政策組的條文資料；無對應列時以出廠預設生效。變更於單一交易內批次落庫（中途失敗全回滾），
每項變更寫入稽核日誌（`resource=security_policy`，`old→new`，PCI 10.2.2）。

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/security-policies` | 取全部政策項（現值＋**對各生效政策組的判定**）→ `{data: [PolicyView + verdicts], groups: [PolicyGroup]}` |
| PUT | `/security-policies` | 批次更新，body `{"policies": {"key": "value", ...}}`（僅送有變更的鍵）；成功回同 GET 格式 |
| GET | `/security-policies/defs/:key` | 單一設定鍵的定義、可選比較方式、值域與現值（條文表單選鍵後取用） |
| POST | `/security-policies/compliance/preview` | 以尚未儲存的草稿值重算一份判定（唯讀） |
| POST | `/security-policies/apply-preview` | 套用政策建議值的預覽（只算不寫） |

後三項與政策組的對照維護同屬一套判定契約，逐項形狀見下方「政策組與合規對照 API」一章。

同一組政策另有一個公開讀取端點 `GET /api/v1/auth/banner`，只回登入前告示的兩個鍵，見上方「登入前告示」。

**PolicyView 欄位**（每項政策）:
```json
{
  "key": "lockout_max_attempts",
  "type": "int",
  "default": "10",
  "direction": "max",
  "label": "登入失敗鎖定次數上限",
  "unit": "次",
  "unit_key": "count",
  "value": "10",
  "updated_by": "admin",
  "updated_at": "2026-07-03T00:00:00Z"
}
```

**設定鍵不承載合規要求**：某一組規範對某個鍵要求什麼值，是政策組的條文資料，
不是設定鍵的屬性；判定隨列表以 `verdicts` 一起回（見下方「安全政策列表的判定投影」）。
`direction` 只說明這個鍵的危險方向朝哪邊（`max`＝值越大越鬆），供表單提示與判定比較使用。

**多組並行**：一個鍵可同時被多組對照，且各組的要求可能方向相反（密碼最小長度一組
要求 ≥12、另一組只要求 ≥6）。判定逐組各給一個結果，偏離數不跨組合計——同一項可能
符合其一而偏離另一。「一次滿足所有政策」取各組要求的交集且**不放寬**：已比要求更嚴的
現值不會被拉回要求值，否則「套用合規基準」這個動作反而降低系統安全性。
出廠預設值不因任何一組而改變（合規為一鍵之遙，非強制）。

`label`／`unit` 為繁中顯示 fallback；前端 i18n 以穩定 `key` 查 `policyLabel.<key>`、以語義 `unit_key`（值域 `count`／`minutes`／`chars`／`records`／`hours`／`days`／`persons`）查 `policyUnit.<unit_key>`——切語言顯示對應譯文，漏譯降級回 `label`／`unit`。

**文字型政策鍵**（`type: "text"`）另有兩個欄位，只在該型別的項目上出現
（其餘型別不帶這兩欄，`multiline` 為 false 時亦省略）：

- `max_length`：字元數上限，**以 Unicode code point 計**（非位元組、非 UTF-16 單位）。
- `multiline`：值是否允許換行。false 時值內含換行即拒絕。

寫入時先正規化再驗證，落庫的是正規化後的值：`\r\n` 與單獨的 `\r` 統一為 `\n`、
去除首尾空白；非合法 UTF-8、控制字元（僅放行 TAB，以及 `multiline` 為 true 時的換行）、
超過 `max_length` 一律拒絕，回 400 `VALIDATION_POLICY_INVALID_VALUE` 並以 `params.key` 指名該鍵
（**拒絕原因不進回應**）。正規化後為空字串等同未設定，是合法值。
值存的是純文字，不做 HTML 轉義也不剝除標記——不把它渲染成標記是呈現層的責任。
文字鍵不能作為條文要求的對象（自由文字沒有任何一種比較方式是有意義的），故不產生判定、不計入偏離數。

文字型鍵的**變更稽核**改用結構化欄位：詳情欄為
`{"changes":[{"field":"<鍵名>","old":"<舊值全文>","new":"<新值全文>"}]}`（單行 JSON，
換行以逸出序列表示，故 CSV 匯出不會多出實體換行），訊息欄只留 `policy=<鍵名>`。
非文字鍵維持既有的單行 `policy=<鍵> old=<舊> new=<新>` 且詳情欄為空。

**政策鍵值域**（型別與出廠預設見 [DB_SCHEMA.md](DB_SCHEMA.md) security_policies 一節）:
`lockout_max_attempts`、`lockout_duration_minutes`、`password_min_length`、`password_require_alnum`、
`password_history_count`、`force_change_on_reset`、`mfa_required`（enum: off/admin_only/all）、
`web_idle_minutes`、`web_max_session_hours`、
`mapping_revalidation_hours`（外部群組映射重新驗證時限，整數小時，預設 12，可設 0 或 1–168，0＝不設限；持有映射支持的帳號工作階段不超過此時數，讀不到群組超過此時數即收回映射權限，見「身分來源與外部群組映射」的「有界重新驗證」；調長或設 0 產生 `mapping_revalidation_relaxed` 系統告警）、
`refresh_cookie_secure`（bool，預設 true——refresh cookie 是否標記 `Secure`（僅在 https 連線下由瀏覽器保存與回送）。
發放 cookie 時現讀，改值即生效不需重啟；初值於首次啟動自部署組態播種
（`AUTH_REFRESH_COOKIE_SECURE` 顯式值 → `PUBLIC_BASE_URL` 的 scheme；兩者皆缺則不寫政策列、出廠預設生效），
播種後本鍵以政策為準、改 env 不再介入。**不在任何內建組的對照內**：正確取值由部署對外協定決定
（https 部署開啟、刻意明文部署關閉），不是合規基準線，故不入「一次滿足所有政策」也不計偏離）、
`session_idle_minutes`、`session_max_minutes`、
`inactive_disable_days`；日誌保留與審閱（PCI Req 10）:
`retention_audit_log_days`、`retention_session_command_days`、`retention_alert_days`（預設 0=永久，PCI 365）、
`retention_recording_days`（預設 90，初始值由 `RECORDING_RETENTION_DAYS` env 播種；env 值落在 1–6 時視為不合法而忽略，沿用 90）、
`retention_checkpoint_days`（檢查點鏈保留，預設 0＝永久、上界 3650、不在任何內建組的對照內——
其合規語義是**跨鍵**關係，見下方跨鍵約束）、
`daily_review_enabled`、`failure_alert_enabled`（bool，預設 false，PCI true）；存取政策（PCI 7.2）:
`access_policy_default`（enum: open/reason/approval，預設 open，PCI approval——資產未個別設定政策時的全域段位）、
`access_request_max_duration_minutes`（預設 1440）、`access_request_pending_timeout_hours`（預設 72）、
`access_request_min_approvals`（int，預設 1、區間 1–10——最少核准人數，內控強化選項非 PCI 要求，不在任何內建組的對照內）；
破窗與撤銷（PCI 7.2）: `break_glass_enabled`（bool，預設 false——破窗 opt-in）、
`break_glass_duration_minutes`（預設 60）、`break_glass_review_timeout_hours`（預設 24）、
`access_revoke_disconnect`（bool，預設 false——撤銷預設只擋新連線不硬斷）；
金鑰管理（PCI Req 3）: `key_cryptoperiod_reminder_days`（int，預設 0＝不提醒，
PCI 建議 365——金鑰超齡提醒天數，反映於金鑰清冊的 `reminder_days`）；
`dek_cache_ttl_seconds`（int，空值合法；空＝資料金鑰解封後常駐記憶體不限期（預設）、`0`＝每次使用時向 KEK 保管處現解且用完即清、`N`＝自解封起 N 秒固定期限到期重解不續期；全部 KEK 模式可設；封存時立即失效；保管處故障不回退舊快取）；
登入前告示（`text` 型，無基準建議值）: `login_banner_title`（`max_length` 120、單行）、
`login_banner_body`（`max_length` 2000、`multiline`；內文為空即登入頁不顯示告示，
標題不會單獨顯示。兩鍵的內容於登入前對任何人可讀，見上方登入前告示段）。

另有兩組政策鍵於他處詳述而不重複列於此：錄影 fail-close（`recording_failclose_enabled`，見連線簽發段）
與傳輸風險（7 個 `transport_*`，見傳輸安全段）。

**保留政策的值域**：四個資料保留鍵（`retention_audit_log_days`、`retention_session_command_days`、
`retention_alert_days`、`retention_recording_days`）的合法值為 `{0} ∪ [7, 3650]`，0＝永久保留；
儲存 1–6 回 400 `VALIDATION_POLICY_INVALID_VALUE` 並以 `params.key` 指出該鍵，同一批的其他鍵一併不生效。
`retention_checkpoint_days` 不設下界（0 或 1–3650），只受下方跨鍵約束。直接改庫寫入的 1–6 於讀取時視為不合法，
退回最後已知合法值（沒有則用出廠預設）。啟動時另有一個冪等對帳步驟，把已存為 1–6 的資料保留鍵抬升為 7
（必要時檢查點保留跟隨抬升為 7），每筆寫稽核 `retention_floor_raised`，不產生告警，也不修補原本就違反跨鍵約束的存量。

**保留與高危設定的告警**：政策批次中，下調四個資料保留鍵（含由 0 改為正數）產生 `retention_shortened`
系統告警，`recording_failclose_enabled` 由 true 改 false 產生 `recording_failclose_disabled`，
`access_policy_default` 降級產生 `access_policy_relaxed`；告警與稽核同交易，任一寫不進去整批回滾。
調長、改為 0、開啟只寫稽核。告警保證的是建立與留痕，送達取決於通知通道。

**保留政策的跨鍵約束**：`retention_checkpoint_days` SHALL NOT
低於四個資料保留鍵中最長者，**0 視為無限大**（任一資料鍵為 0＝永久時，檢查點鍵僅允許 0）。
批次只要觸及這五個鍵中任一個，就以**批次套用後的終值**對四組關係全部驗一遍
（結果不因鍵在請求中的先後順序而異）；違反即整批拒絕，回
`VALIDATION_POLICY_RETENTION_CROSS_KEY` 並以 `params.key` 指出觸發的資料保留鍵。
出廠五鍵為 `0/0/0/90/0`，`RetentionCovers(0, 任意)` 恆真，故出廠狀態下的任何保留鍵
編輯都不會被誤擋。理由：檢查點是「這段資料沒被動過」的證明，證明活得比資料短
等於在資料還在的期間先把證明丟掉。約束於 retention 執行期亦成立——政策若經 SQL
直改而違規，鏈修剪保守跳過並記告警（不刪比資料更早的檢查點）。

**錯誤**: 400 未知鍵（`ErrPolicyUnknownKey`）或值不合法（型別/範圍，`ErrPolicyInvalidValue`）、
跨鍵約束違反（`VALIDATION_POLICY_RETENTION_CROSS_KEY`）、
未提供任何政策項；500 寫入失敗。

---

## 政策組與合規對照 API

安全設定與外部規範條文的對照。一個**政策組**是一份對照的容器，內含若干**條文**，
每條條文可對一到多個安全設定鍵提出**要求**；系統據此判定現值是否達到要求，
並可為每條條文留下**機構備註**與**人工確認**記錄。

三件事分屬三組路由，**寫入只有一個入口**：對照的內容改在 `/policy-groups`（寫入需 `policygroup:manage`），
設定值改在 `/security-policies`，`/compliance` 唯讀。同一份對照若有兩個寫入面，
「這條要求是誰改的」就會分裂成兩套記錄。讀取面開放給 auditor——看不到對照的內容，
就判讀不了判定結果。

政策組分兩種來源：**內建組**（`source: "builtin"`）的條文與要求隨產品版本發布，
啟動時由種子寫入，管理面只能切換生效與加註備註；**自建組**（`source: "custom"`）的內容
全部由管理者維護。內建組的內容版本記在 `version`，自建組的原文語言記在 `locale`。

### 政策組維護（`/policy-groups`）

| 方法 | 路徑 | 權限 | body | 回應 |
|---|---|---|---|---|
| GET | `/policy-groups` | `policygroup:view` | — | `{data: [PolicyGroup]}`（依代號排序） |
| GET | `/policy-groups/:code` | `policygroup:view` | — | `{data: {group: PolicyGroup, clauses: [ClauseView]}}` |
| POST | `/policy-groups` | `policygroup:manage` | `{code, name, locale?}` | 201 `{data: PolicyGroup}` |
| PUT | `/policy-groups/:code` | `policygroup:manage` | `{name}` | `{data: PolicyGroup}` |
| PUT | `/policy-groups/:code/enabled` | `policygroup:manage` | `{enabled: bool}` | `{data: PolicyGroup}` |
| DELETE | `/policy-groups/:code` | `policygroup:manage` | — | `{data: {code}}` |
| PUT | `/policy-groups/:code/clauses/:clause_no` | `policygroup:manage` | `{title, summary, kind, controls: [...]}` | `{data: ClauseView}` |
| DELETE | `/policy-groups/:code/clauses/:clause_no` | `policygroup:manage` | — | `{data: {code, clause_no}}` |
| PUT | `/policy-groups/:code/clauses/:clause_no/annotation` | `policygroup:manage` | `{note}` | `{data: PolicyClauseAnnotation}` |
| POST | `/policy-groups/:code/clauses/:clause_no/confirm` | `policygroup:manage` | `{note}` | `{data: PolicyClauseAnnotation}` |

**PolicyGroup**：`{code, name, source, enabled, version, locale, created_at, updated_at}`。

**生效開關的 `enabled` 為必填欄**，缺欄位回 400 `VALIDATION_BAD_REQUEST` 而非讀成 `false`
——漏帶欄位若被讀成「請停用這一組」，該組的偏離會整批消失在畫面上。**內建組的生效開關
與備註同樣可寫**：一份對照要不要生效由機構決定，產品升級不改動它。

**ClauseView**（條文卡片，管理頁與合規對照頁共用；下為形狀示意）：

```json
{
  "group_code": "<組代號>", "clause_no": "<條號>",
  "title": "<條文標題>", "summary": "",
  "kind": "setting", "removed_in_version": "",
  "created_at": "2026-09-09T00:00:00Z", "updated_at": "2026-09-09T00:00:00Z",
  "controls": [
    {"id": 1, "group_code": "<組代號>", "clause_no": "<條號>",
     "policy_key": "password_min_length", "comparator": "min",
     "expected_value": "12", "reference_only": false}
  ],
  "annotation": {"group_code": "<組代號>", "clause_no": "<條號>",
                 "note": "", "confirmed_by": "", "confirmed_at": null,
                 "confirmation_note": ""}
}
```

`annotation` 在該條無備註時**整個欄位缺席**；`controls` 無要求時為空陣列。

**`kind` 三值**（條文型別）：

| 值 | 語義 | 是否掛要求 |
|---|---|---|
| `setting` | 設定要求：條文指向一到多個設定鍵並帶要求值，系統據以判定 | 是 |
| `self_attested` | 由機構自行確認：不指向任何設定鍵，系統只呈現不判定 | 否 |
| `builtin_protection` | 系統內建保護：產品無條件提供，沒有可調的設定值 | 否 |

後兩者都不產生鍵層判定，但責任歸屬不同——`self_attested` 的責任在機構，
`builtin_protection` 的責任在產品本身。型別與要求數不相容時回 400
`VALIDATION_POLICY_GROUP_CLAUSE_KIND`。

**`comparator` 四值**（要求的比較方式）：

| 值 | 語義 | 適用型別 |
|---|---|---|
| `min` | 現值須不小於要求值 | 整數 |
| `max` | 現值須不大於要求值 | 整數 |
| `equals` | 現值須等於要求值 | 開關、選項 |
| `review` | 條文涉及這個鍵但**未定值**，要求值須留空 | 整數、開關、選項 |

`review` 不是漏填：條文寫的是語境式要求（如「使用足夠強度之加密」）時，沒有一個數字或
開關值代表得了它，系統不替條文發明一個門檻，改為連同目前值列出、由稽核人員判讀。
開關與選項一律 `equals`——這兩類的取值之間沒有強弱序，以序位比較會讓要求值被靜默解讀成
「至少這麼嚴」而判錯。自由文字型的設定鍵不可作為要求對象（400
`VALIDATION_POLICY_GROUP_KEY_TYPE`）。

**條文的 `controls` 是整批取代**：送進來的就是這條條文的全部要求。未定值的要求送
`comparator: "review"` 加空的 `expected_value`，帶值會回 400
`VALIDATION_POLICY_GROUP_EXPECTED_VALUE`。**同一組內同一個設定鍵只能出現一條要求**
（唯一索引釘住；重複回 400 `VALIDATION_POLICY_GROUP_DUPLICATE_KEY`）——同組內對同一個鍵
給出兩個要求，該組即對自己自相矛盾，而判定結果會取決於資料列的讀取順序。

**刪除的連帶範圍不對稱**：刪整組會連帶清除它的條文、要求與備註；**刪單條條文不刪備註**
——備註是機構寫的東西，升級與編輯都不得清掉它。同理，內建組升級移除某條條文時只把
`removed_in_version` 標成該內容版本、不刪列：標記後判定與對照不再計入本條，管理頁仍看得到它。

四類寫入（組、條文、備註、確認）**各留一列稽核**（`resource=policy_group`），
詳情帶組代號、條號、操作名與舊值→新值。

**錯誤碼**：

| code | 狀態 | 什麼時候 |
|---|---|---|
| `POLICY_GROUP_BUILTIN_READONLY` | 403 | 想改內建組的名稱、條文，或刪掉它 |
| `POLICY_GROUP_NOT_FOUND` | 404 | 組代號不存在（**不回空結果**：打錯字與「這組真的沒有對照」在畫面上分不出來） |
| `POLICY_GROUP_DUPLICATE_CODE` | 409 | 建組時代號已被使用 |
| `VALIDATION_POLICY_GROUP_CODE` | 400 | 代號或名稱為空／超出長度上限 |
| `VALIDATION_POLICY_GROUP_CLAUSE_NO` | 400 | 條號為空／超出長度上限 |
| `VALIDATION_POLICY_GROUP_CLAUSE_KIND` | 400 | 條文型別與所填的要求數不相容 |
| `VALIDATION_POLICY_GROUP_UNKNOWN_KEY` | 400 | 要求指向不存在的設定鍵（`defs/:key` 上為 404） |
| `VALIDATION_POLICY_GROUP_KEY_TYPE` | 400 | 該型別的設定鍵不能作為要求對象 |
| `VALIDATION_POLICY_GROUP_COMPARATOR` | 400 | 比較方式與設定鍵的型別不符 |
| `VALIDATION_POLICY_GROUP_EXPECTED_VALUE` | 400 | 要求值超出該鍵的值域，或未定值卻仍填了值 |
| `VALIDATION_POLICY_GROUP_DUPLICATE_KEY` | 400 | 同組同鍵已有另一條要求 |
| `INTERNAL_POLICY_GROUP_READ` / `INTERNAL_POLICY_GROUP_WRITE` | 500 | 資料庫讀寫失敗 |

### 合規判定快照

```
GET /api/v1/compliance/snapshot?group=<code>
```

**權限**: `compliance:view`，**唯讀**。`group` 省略即全部生效組。指定不存在的組回 404
`POLICY_GROUP_NOT_FOUND`。判定建構失敗回 500 `INTERNAL_COMPLIANCE_SNAPSHOT`。

回應四段是同一個畫面的四個區塊，一次帶齊——判定是有時點的，分四支端點讀會讓摘要與逐條
結果來自不同時點而對不起來：

```json
{
  "data": {
    "built_at": "2026-09-09T11:15:03Z",
    "draft": false,
    "groups": [{"code": "pci_dss_4_0_1", "version": "4.0.1", "enabled": true}],
    "verdicts": [
      {"key": "password_min_length", "group_code": "pci_dss_4_0_1", "clause_no": "8.3.6",
       "result": "deviating", "reason": "below_minimum",
       "current": "8", "expected": "12", "comparator": "min"}
    ],
    "unmapped_keys": ["login_banner_title"],
    "key_count": 55,
    "builtin_protection_clauses": {"<組代號>": 14}
  },
  "groups":    [ PolicyGroup ],
  "summaries": [ {"group_code": "...", "compliant": 9, "deviating": 15, "needs_review": 1,
                  "audit_review": 6, "insufficient_data": 0, "unmapped": 24,
                  "builtin_protection": 0} ],
  "clauses":   [ ClauseView ]
}
```

- `data` 是判定本身。`data.groups` 含**未生效**的組（畫面要標示得出來），
  頂層 `groups` 是本次查詢範圍內的政策組本體（帶組名），`summaries` **只含生效組**。
- `built_at` 是這份判定建構的時刻（UTC）。`draft` 為真表示這份結果建立在尚未儲存的草稿值上
  ——草稿與已儲存的結果長得一樣，不標示就無從分辨畫面上的數字是現況還是預期。
- **判定只吃生效的組與未標記移除的條文**，且 `self_attested` 與 `builtin_protection` 型的條文
  不產生鍵層判定。政策列不存在的設定鍵以其出廠預設判定。

**`result` 六值**：

| 值 | 語義 |
|---|---|
| `compliant` | 現值達到該組對該鍵的要求 |
| `deviating` | 現值未達要求 |
| `needs_review` | 該組以參考值呈現、未給規範明定值，待機構人工確認 |
| `review` | 該組有條文涉及該鍵但條文未定值，附目前值待稽核判讀 |
| `insufficient_data` | 該組以運作紀錄判定該鍵（`comparator=signoff_record`），而紀錄期間不足或取不到紀錄；不計入符合或偏離 |
| `unmapped` | 該鍵不在任何生效組的條文內 |

`current`（判定當下的設定值）**每一種結果都帶**：待稽核判讀要靠它才判讀得出設定是否合理，
其餘結果也要它才說得出「要求 12、目前 8」。`expected`／`comparator` 在未對照與未定值時為空；
`confirmed_by`／`confirmed_at` 只在該條有人工確認記錄時出現。

`updated_by`／`updated_at`（該鍵最後一次由誰、在何時改的）**同樣每一種結果都帶**，含未對照的鍵
——追證的下一步問的是「這個設定何時被誰改的」，而那與判定結果是符合還是偏離無關；
另一個答得出這件事的地方是管理端的設定列表，而稽核角色讀不到那一支。該鍵從未被改過
（值即出廠預設）時兩欄缺席。

**`reason` 是機器碼不是句子**（人話與三語由呈現層依語系組出，句子留在呈現層才翻譯得了，
也才不會有兩份措辭）：

| reason | 何時 |
|---|---|
| `meets_expectation` | 現值達到要求 |
| `below_minimum` | 現值低於「至少」型的要求 |
| `above_maximum` | 現值高於「至多」型的要求 |
| `value_mismatch` | 明確值型的要求不相符 |
| `disabled_by_zero` | 該鍵的零值代表機制停用，而要求非零 |
| `value_not_comparable` | 現值或要求值在這個鍵上無法比較 |
| `reference_value_unconfirmed` | 參考值，機構尚未確認 |
| `reference_value_confirmed` | 參考值，機構已確認 |
| `expectation_unspecified` | 條文涉及這個鍵但未定值 |
| `no_control` | 沒有任何生效組對照這個鍵 |
| `daily_review_disabled` | 運作紀錄判定：每日審閱簽核未開啟（結果為 `deviating`） |
| `signoff_source_unavailable` | 運作紀錄判定：取不到每日簽核紀錄（結果為 `insufficient_data`） |
| `signoff_insufficient_data` | 運作紀錄判定：目前這段連續啟用累計未滿 7 天（結果為 `insufficient_data`） |
| `signoff_unsigned_days` | 運作紀錄判定：近 30 天有應簽而未簽的日子（結果為 `deviating`） |

**摘要七格**（`summaries` 的每一列）：前六格 `compliant`／`deviating`／`needs_review`／
`audit_review`／`insufficient_data`／`unmapped` 數的是**設定鍵**，**合計恆等於 `key_count`**。
第七格 `builtin_protection` 數的是**條文**（該組由產品無條件承擔、沒有可調設定值的條數），
**不進上面六格的合計**——把條文數加進去會讓分母憑空長大。同一組的條數另由
`data.builtin_protection_clauses` 依組代號給出。

**每日審閱條文的運作紀錄判定**：內建 PCI DSS 組的 10.4.1 以比較方式 `signoff_record`
對照 `daily_review_enabled`（要求值固定 `true`），不只看開關。依序：開關未開 → `deviating`
／`daily_review_disabled`；取不到紀錄 → `insufficient_data`／`signoff_source_unavailable`
（**不退回只看開關而判符合**）；目前這段連續啟用累計未滿 7 天 → `insufficient_data`／
`signoff_insufficient_data`；近 30 天未簽 0 天 → `compliant`（遲簽只計數，不影響結果）；
否則 `deviating`／`signoff_unsigned_days`。啟用狀態由升級遷移推定而來的日子照樣計入應簽，
不另成資料不足的理由。其他內建組對同一鍵維持 `equals`（只看開關）。自建組不可選用
`signoff_record`（寫入回 400 `VALIDATION_POLICY_GROUP_COMPARATOR`）。

此類判定另帶 **`signoff`**（開關未開或取不到紀錄時**缺席**，畫面不以任何預設值推算）：

| 欄位 | 說明 |
|---|---|
| `from`／`to` | 近 30 天起訖（業務時區日期，截至昨日；今天不屬於期間） |
| `as_of` | 紀錄的計算時點 |
| `timezone` | 期間末日的切日時區 |
| `required` | 應簽天數：期間內在啟用範圍內（含推定為啟用者）且準時期限已過的日子，至多 29 |
| `on_time`／`late`／`unsigned` | 應簽之中準時、遲簽、未簽的天數 |
| `sign_rate_percent` | （準時＋遲簽）／應簽，無條件捨去到整數；應簽為 0 時 `null` |
| `inferred_days` | 應簽之中啟用狀態由推定而來的天數（只用於呈現） |
| `enabled_since`／`enabled_since_inferred` | 目前這段連續啟用的起點與其是否為推定 |
| `enabled_days` | 自啟用起點所屬日至昨日的所屬日數（7 天門檻的依據） |
| `earliest_unsigned` | 計入統計且未簽的最早日期（`omitempty`） |

期間、應簽與累計天數與 `GET /daily-reviews/stats` 的近 30 天出自同一支計算。

**未對照的分母規則**：不在任何生效組對照範圍內的鍵，在 `verdicts` 內各有一列
（`group_code` 為空、`result` 為 `unmapped`），同時列在 `unmapped_keys`，並計入該組摘要的
`unmapped` 格。**它們不得併入符合數**——沒有人對照過的設定，與「有人對照且達到要求」
是兩件事；偏離數的分母也不含它們。

#### 產出報告

```
POST /api/v1/compliance/report-jobs
```

**權限**: `compliance:view`（與快照同閘；缺少時 403）。建一張下載中心工作單（`kind=compliance_report`），
不改動任何條文、要求或設定值。

**請求**: `{"group": "pci-dss", "language": "zh-TW", "retention_days": 90}`

| 欄位 | 說明 |
|---|---|
| `group` | 政策組代號，必填；須存在且生效 |
| `language` | 報告語言，`zh-TW`／`en-US`／`ja-JP`，省略為 `zh-TW` |
| `retention_days` | 產物在下載中心的保留天數，1–3650，省略為 90 |

沒有期間參數：報告的資料時點是**打包當下**的判定快照（截至現在，不回推）。

**回應** (202): `{"data": {"id": <job id>, "status": "pending"}}`。去重鍵＝種類＋（政策組、語言、保留天數），
不含發起者：同參數的工作單仍在 `pending`／`running` 時回同一張。

**錯誤**: 缺 `group` 或 JSON 格式錯、政策組未生效 → 400 `VALIDATION_BAD_PARAMS`；保留天數越界 → 400
`VALIDATION_ROTATION_SCHEDULE_BAD_RETENTION`；語言不支援 → 400 `VALIDATION_ROTATION_REPORT_BAD_LANGUAGE`（沿輪替報告的語言碼）；政策組不存在 → 404
（同快照）；進行中額度已滿 → 409 `CONFLICT_EXPORT_JOB_LIMIT`。受理與被拒皆入稽核
（`resource=compliance_map`，訊息 `compliance_report.job_created`，帶組代號、語言、保留天數或拒絕理由）。

**產物**（下載中心取件，`GET /audit-export/jobs/:id/download`，`audit:view` 即可、不綁申請者）：ZIP 依序為

- `report.pdf`：第 1 頁封面與摘要（組名、版本、來源、資料時點、產出時刻、產出者、工作單編號、範圍聲明、
  條文與設定兩組摘要（設定組含資料不足格）、不在本組對照範圍的設定數、由產品承擔的條文逐條列條號與標題），其後例外清單
  （偏離、每日審閱簽核段、待人工確認、待稽核判讀）、由機構自行確認的條文、判定口徑、附表 A。每頁頁尾帶工作單編號、產出時刻與頁碼。
  每日審閱簽核段只在本組含 `signoff_record` 條文時出現：結果與理由、近 30 天起訖（業務時區與位移）、資料時點、
  應簽／已簽（簽核率）／其中補簽／未簽、推定日天數（大於 0 時）、逐日表節錄（未簽、補簽與未到期全列，準時至多 5 列），
  段末聲明之後的補簽不會回寫已產出的報告。數字只彙總 `daily_reviews.csv` 中 `counts_toward_stats=true` 的列。
- `clauses.csv`：UTF-8 BOM、CRLF、公式注入轉義；首行為 `# as_of=<RFC3339>` 註解列，其後一列一個（條文，設定鍵）
  判定，另加由機構自行確認與由產品承擔的條文各一列。PDF 摘要數字＝本檔依結果欄分組的列數。
- `daily_reviews.csv`（僅含 `signoff_record` 條文的組，即 PCI DSS）：近 30 天每一個在啟用範圍內（或有簽核紀錄）
  的所屬日一列，欄位與證據包的同名檔相同（見〈稽核證據匯出〉）。與判定、PDF 段落讀同一份運作紀錄。
- `manifest.json`：`kind`／`mode`＝`compliance_report`、`job_id`、`exported_by`、`exported_at`（打包時刻）、
  `job_requested_at`、`filter`（`group`、`group_version`、`language`、`retention_days`、`as_of`、
  `csv_as_of_prefix`、`product_version`）、逐檔 SHA-256；含 `daily_reviews.csv` 時 `counts.daily_reviews` 為其列數。

ZIP 檔序：`report.pdf`、`clauses.csv`、（含該條文時）`daily_reviews.csv`、`manifest.json`、`manifest.sig`。
報告的共用前提（不綁發起者）：內容只有設定值、條文、操作者名，以及每日簽核紀錄（所屬日、簽核時刻、簽核者名、
稽核人員自填的延遲原因與備註）；不含錄影、剪貼簿或秘密材料。
- `manifest.sig`：Ed25519 簽章（離線驗簽見〈離線驗簽〉）。

**保留期**: 打包完成時刻加 `retention_days`，逾期從下載中心移除（410）。產物落在 `EXPORT_ARTIFACT_PATH`
（容器本機、不在備份範圍），保留天數是下載中心的到期日，不是保管承諾；需要長期留存者請下載保存。

### 安全政策列表的判定投影

`GET /security-policies` 的每一項在原有 `PolicyView` 欄位之外附 **`verdicts`**：該鍵對各生效組
的判定（形狀同上；未被任何生效組對照時是一列 `group_code` 為空、`result` 為 `unmapped`）。
頂層另有 **`groups`**：生效組清單（`PolicyGroup`，帶組名），供各承載頁的頁首列出
「現在對照的是哪幾組」。

判定隨列表一起回，是因為設定頁的每個分區都要立刻算得出偏離數；分兩支端點讀會讓值與判定
來自兩個時點。**判定讀不到時整頁回 500 `INTERNAL_COMPLIANCE_SNAPSHOT`，不退回「零偏離」的
列表**——後者會讓畫面顯示全部符合，那是安全控制的呈現在失效方向上說謊。

**判定是符合性的唯一來源**：回應不另帶任何一份自算的符合性或偏離計數。
分區偏離數由 `verdicts` 推導（同一個鍵偏離多組只算一次）。

### 單一設定鍵的定義（條文表單用）

```
GET /api/v1/security-policies/defs/:key
```

**權限**: `securitypolicy:manage`。條文表單選定設定鍵之後打這支，取表單要問的四件事：型別、可用的比較方式、
合法值域、以及現在是多少（據以即時說出「儲存後這一條會顯示為偏離」）。未知鍵回 404
`VALIDATION_POLICY_GROUP_UNKNOWN_KEY`。

| 欄位 | 說明 |
|---|---|
| `key`／`type`／`label`／`unit`／`unit_key`／`default` | 設定鍵定義（`type` ∈ `int`／`bool`／`enum`／`text`） |
| `value` | 目前生效值（無政策列時為出廠預設） |
| `comparators` | 可選的比較方式：`int` → `["min","max","review"]`；`bool`／`enum` → `["equals","review"]`；`text` → `[]`（不可作為要求對象）。運作紀錄判定 `signoff_record` 只供內建組，不在此列 |
| `min`／`max`／`zero_disables`／`max_length`／`multiline` | 值域欄位，`omitempty`（`max` 為 0 表示沿用共用上界） |
| `enum_order` | 選項的可選值（弱→強），僅 `enum` 型 |
| `updated_by`／`updated_at` | 最後一次變更（`omitempty`） |

### 草稿判定

```
POST /api/v1/security-policies/compliance/preview?group=<code>
```

**權限**: `securitypolicy:manage`，**唯讀、不寫入任何東西**。body `{"draft": {"<key>": "<value>", ...}}`。
**稽核語義為讀取**（`action=read`）：POST 的動詞推導預設會記成建立，中介層依路徑訂正為讀取。
回 `{"data": <同快照的 data>}`，其中 `draft` 為 `true`。

草稿由後端重算而不是前端自己算：前端算一份會與伺服器的判定漂移，而兩者的分歧不會有任何
一處報錯。草稿裡未定義的鍵靜默略過；**不合法的值原樣採用並據實判成偏離**——管理者打字打到
一半就回 400 會讓畫面空掉。

### 套用預覽

```
POST /api/v1/security-policies/apply-preview
```

**權限**: `securitypolicy:manage`，**只算不寫**。**稽核語義為讀取**（`action=read`），理由同上。body：

```json
{"scope": ["password_min_length", "..."], "mode": "group", "group_code": "<code>",
 "draft": {"<key>": "<value>"}}
```

`mode` 為 `group`（依指定的一個生效組）或 `strictest`（一次滿足所有生效組）。
模式未知、單組模式未指名組、或指定的組未生效，一律回 400 `VALIDATION_APPLY_PREVIEW_MODE`
——回一份空預覽在畫面上與「沒有任何要變動的鍵」長得一樣。

```json
{"data": {"mode": "group", "group_code": "<code>",
          "changes": [{"key": "...", "current": "8", "proposed": "12", "source_group": "<code>"}],
          "conflicts": [{"key": "...", "reasons": [{"group": "<code>", "expected": "12", "comparator": "min"}]}],
          "unchanged_count": 30, "unmapped_count": 19,
          "notes": [{"key": "daily_review_enabled", "group": "<code>", "clause_no": "10.4.1",
                     "reason": "signoff_unsigned_days", "unsigned": 4, "earliest_unsigned": "2026-10-06"}]}}
```

`notes` 列出**套用設定解決不了**的偏離（目前只有一種：以運作紀錄判定的每日審閱條文，開關已開而因
未簽偏離）。該鍵不在 `changes`、計入 `unchanged_count`；畫面據 `notes` 另說一行「需到每日簽核補簽」並給入口。
`signoff_record` 在設定值這一層等同「開關須為 `true`」：開關關閉時照常列為 `changes`（改為 `true`）。
指定單組時只列該組的說明；範圍外的鍵不列。恆為陣列（沒有時為 `[]`）。

`mode`／`group_code` 是回聲欄位，送出前重打一次預覽時拿來比對是同一種套用。
**確認套用只把 `changes` 填進表單**，儲存仍走 `PUT /security-policies` 的既有流程與稽核
——預覽端點自己落庫，會讓一次「看看會變成什麼」變成一次沒有經過確認的變更。

**收斂規則**（同一個鍵上多條要求怎麼合成一個結論）：

1. **只有可自動套用的要求參與**。待人工確認（參考值）與待稽核判讀（未定值）的要求**不進來**
   ——前者的數字沒有條文出處、後者根本沒有值，兩者都由人決定。這些鍵因此落在「不變動」，
   而不是衝突：它們沒有與任何要求對立。
2. **多條要求收斂成一個可接受區間**：「至少」抬高下界、「至多」壓低上界、明確值同時是上下界。
   三種比較方式落在同一個區間模型上，衝突判定因此只有一條規則。
3. **現值落在區間內就不動**；低於下界改成下界、高於上界改成上界。**移動的終點是被違反的那一端
   ——不放寬**：已經比要求更嚴的現值不會被拉回要求值，「套用政策建議值」這個動作不該降低系統
   的安全性。
4. **零值代表停用的整數鍵**：現值為 0 而要求非零時，改成非零的那一端。0 在數值上小於任何要求，
   但它的語義是「機制沒開」而不是「更嚴的數」。
5. **下界高於上界即衝突**（開關與選項的兩條要求值不同，同樣落在這一條），該鍵**不自動改**，
   列在 `conflicts` 並附每一條要求的來源組、要求值與比較方式，畫面據此說得出是哪兩條規則對立。

**只動 `scope` 內的鍵**：`scope` 是本頁的鍵集合，範圍外的鍵一律不動——一個按鈕改掉四個頁面的
設定，管理者按下去之前看不出影響範圍。`scope` 內未被任何生效組對照的鍵計入 `unmapped_count`，
其餘不需變動者計入 `unchanged_count`。指定單組時仍以**全部**生效組建構判定，其他組的要求只在
現值已經符合它們時納入為約束——那是「不放寬已符合其他生效組的值」這條規則的約束來源，
不是要套用的目標。

---

## 日誌合規 API（PCI Req 10）

### syslog 轉發設定（需 `syslog:manage`，10.3.3）

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/syslog-settings` | 設定與狀態 → `{data: {setting: {enabled, host, port, protocol, tls_ca, updated_by, updated_at}, dropped: N}}`（dropped=累計丟棄筆數，只增不歸零） |
| PUT | `/syslog-settings` | 更新設定；`protocol` 為 `udp`/`tcp`/`tcp+tls`；`tls_ca` 為 PEM（空=系統信任庫）；啟用時 host 必填；變更入稽核（`resource=syslog_setting`，不含 CA 內容僅記 `tls_ca_set`）；設定與稽核（含風險確認聲明）在同一交易，由啟用改為停用、或變更後為啟用且 host／port／protocol 任一與變更前不同（含由停用改為啟用到不同目的地）時，同交易另建 `offsite_or_syslog_changed` 系統告警（`change` 為 `disabled` 或 `destination_changed`），稽核或告警寫不進去時整筆回滾，告警寫入失敗回 500 `INTERNAL_SYSTEM_ALERT_RAISE`；轉發器在提交成功之後才重載 |
| POST | `/syslog-settings/test` | 以請求 body 的表單值（未儲存也可測）同步發送測試訊息。**成敗由狀態碼表達**：送達成功 `200 {data:{success:true}}`；送達失敗 `502 {error, code:"INTERNAL_SYSLOG_TEST_FAILED"}`（泛化訊息，連線拒絕／逾時／TLS 驗證失敗等具體原因僅記伺服端 log）；傳輸政策閘未確認 `400 {error, code:"VALIDATION_TRANSMISSION_ACK_REQUIRED", risks}` |

轉發語義：audit_logs 與 command_alerts 於 DB 寫入成功後 tee，RFC5424（TCP 用 octet-counting framing），
MSG 為 JSON 含 PCI 10.2.2 六要素；有界緩衝（4096）滿即丟並計數，斷線指數退避重連，
任何轉發故障不阻塞稽核寫入。

### 每日審閱簽核（10.4.1；查詢 `audit:view`、簽核 `alert:manage`）

每一天以**業務時區**（安全政策 `daily_review_timezone`）切成一個「所屬日」，起訖為該時區的 00:00 至隔日 00:00（`window_start` 含、`window_end` 不含）。改時區自下一個日期生效：轉換日的起點接在前一天的結束時刻，所以那一天可能長於或短於 24 小時；兩時區差過大時，被跳過的日期不列入。所屬日結束後列入待簽，結束後 30 分鐘（`signable_at`）起可簽；準時期限（`due_at`）是所屬日加兩個日曆日在該時區的 00:00，期限之後簽核為遲簽，須填延遲原因。簽核時刻一律由伺服器寫入，請求夾帶的時刻欄位被忽略。

功能開啟期間（任一時刻開著即算）的日子都在範圍內，從開啟當天起算。升級時無法由紀錄證明當天開著的日子一律當作開啟並標示推定（`enabled_basis` 為 `presumed_purged`／`presumed_gap`／`presumed_tail`；有紀錄證明者為 `recorded`），這些日子照樣列入待簽、可簽、計入統計與逾期提醒。

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/daily-reviews/status` | 卡片摘要（見下） |
| GET | `/daily-reviews/pending` | 待簽日清單，由最早排起；`page`／`page_size`（每頁至多 31，超出或不合法時取 31）→ `{data: {items: [PendingDay], total, page, page_size}}` |
| GET | `/daily-reviews/pending/count` | 側欄徽章 → `{data: {count, overdue_count}}` |
| GET | `/daily-reviews/days/:date` | 單日明細（見下）；`:date` 為 `YYYY-MM-DD`，格式不合回 400 `VALIDATION_DAILY_REVIEW_DATE_INVALID`，晚於明天回 400 `RULE_DAILY_REVIEW_DAY_NOT_ENDED` |
| GET | `/daily-reviews/stats` | 期間統計（見下） |
| GET | `/daily-reviews` | 已簽紀錄，新到舊；`page`／`page_size`、`late_only=true` 只列遲簽 → `{data: {items: [Review], total}}` |
| POST | `/daily-reviews` | 簽核指定所屬日，body `{"review_date": "YYYY-MM-DD", "note": "...", "delay_reason": "..."}` → `{data: 簽核列}`（Review 的欄位，不含 `late_days`）；簽核入稽核（`action=create`、`resource=daily_review`） |

全部查詢端點（六支 GET）的權限檢查在處理之前：無權者對任何日期都得到同一個 403。

**`GET /daily-reviews/status`**：

```json
{"data": {
  "enabled": true,
  "timezone_state": {
    "active": "Asia/Taipei",
    "today": {"date": "2026-10-11", "window_start": "2026-10-11T00:00:00+08:00", "window_end": "2026-10-12T00:00:00+08:00"},
    "pending": null
  },
  "yesterday": {"date": "2026-10-10", "timezone": "Asia/Taipei", "window_start": "…", "window_end": "…",
                "due_at": "…", "signable_at": "…", "signable": true, "in_scope": true, "enabled_basis": "recorded",
                "signed": false, "review": null, "counts": {…}, "counts_fixed": false},
  "pending_count": 3, "overdue_count": 1, "earliest_pending_date": "2026-10-08",
  "pending_dates": ["2026-10-08", "2026-10-09", "2026-10-10"],
  "stats_30d": {…}
}}
```

- `timezone_state.pending`：已儲存但尚未生效的時區變更 `{value, effective_date, effective_at}`，沒有時為 `null`。
- `yesterday.counts`：未簽時為即時計數，已簽時為簽核時固化的計數（`counts_fixed=true`）。
- `pending_dates` 至多 10 個（由最早排起）；`stats_30d` 同 `GET /daily-reviews/stats?period=30d`。
- 功能關閉時 `enabled=false`，仍回 `timezone_state`；`pending_count`／`overdue_count` 為 0、`pending_dates` 為空陣列，`yesterday`／`earliest_pending_date`／`stats_30d` 為 `null`。

**PendingDay**：`{date, timezone, timezone_inferred, window_start, window_end, due_at, signable_at, signable, overdue, late_days, enabled_basis, counts}`。`timezone_inferred=true` 表示該日的切日時區是升級時以當時設定推得的。`counts` 見下方計數物件。

**計數物件**（`counts`，與簽核快照同形）：`{date, login_failures, login_failures_source, high_risk_ops, high_risk_ops_source, high_risk_criteria, unreviewed_alerts, alerts_total, alerts_benign, alerts_escalated, alerts_source}`。`*_source` 為 `complete`／`partial`／`purged`：依保留期清除的水位判定，`purged` 時該項計數為 `null`（不以 0 冒充），`partial` 時計數是下限。`high_risk_criteria` 是 `high_risk_ops` 所依據的高危判準版本（整數）：即時計數與新簽核為現行版本 `2`；簽核快照沒有此鍵者（1.17.2 之前簽核）讀出為 `1`。版本 `2` 不計入保留期限清除、外部登入時沒有角色增減的映射重算，以及同一件事除帶請求路徑那一列以外的重複紀錄；這些紀錄仍在操作日誌。已簽日的快照不重算，與即時計數版本不同時兩者依不同判準計算。

**`GET /daily-reviews/days/:date`**：

```json
{"data": {
  "date": "2026-10-10", "status": "pending",
  "timezone": "Asia/Taipei", "timezone_inferred": false,
  "window_start": "…", "window_end": "…", "due_at": "…", "signable_at": "…",
  "enabled_basis": "recorded", "overdue": false, "late_days": 0,
  "sources": {"audit_log": "complete", "command_alert": "complete"},
  "counts": {…},
  "unreviewed_alerts": [{"id": 12, "rule_name": "…", "kind": "rule", "severity": "high", "command": "…",
                         "user_id": 3, "asset_id": 5, "triggered_at": "…", "disposition": "pending"}],
  "login_failures": {"total": 25, "items": [Event], "source_status": "complete"},
  "high_risk_ops": {"total": 7, "items": [Event], "source_status": "complete"},
  "review": null, "signed_snapshot": null, "alerts_after_sign": null
}}
```

- `status`：`pending`（待簽）、`settling`（已結束、寬限內）、`signed`、`out_of_scope`（不在範圍或改時區時被跳過的日期；功能關閉時，所有尚未簽核的日子都回此值，已簽日仍回 `signed`）、`not_ended`（今天或明天）。
- `unreviewed_alerts` 全部列出；`login_failures`／`high_risk_ops` 各列前 20 筆，`total` 是此刻查得到的筆數（來源已清除時為 0，並以 `source_status=purged` 標示）。Event 為 `{id, created_at, user_id, username, action, resource, status, client_ip, path, error_msg, reason_code, reason_params}`。明細與計數使用同一組查詢條件。`reason_code`（字串）與 `reason_params`（字串對字串的物件）是伺服器對該列的原因分類，供前端組出原因句；無法分類、而列本身已帶請求路徑或錯誤訊息時沒有碼，兩鍵皆不出現（前端照舊顯示 `error_msg` 或 `path`），有碼但無參數時只出現 `reason_code`。原因碼值域為封閉集合，前端以 `dailyReview.reason.<code>` 對應三語文案。分類所用的紀錄細節不隨本回應出站。
- 已簽日：時區、起訖與 `enabled_basis` 取簽核時固化的值；`review` 為簽核紀錄，`signed_snapshot` 為簽核時固化的計數，`alerts_after_sign` 為簽核後才出現、觸發時刻屬於該日的未審閱告警數，只對 `coverage=full_day` 的簽核計算（簽核當時該日未審閱告警必須為 0，此刻仍未審閱者必然是事後寫入）。`coverage=until_signed` 的升級前簽核不檢查告警處置，無法區分簽核前後，`alerts_after_sign` 一律為 `null`；此刻仍未審閱的告警照常列在 `unreviewed_alerts`。

**`GET /daily-reviews/stats`**：`period=30d`（預設）或 `90d`；或以 `from`／`to`（業務時區日期，含頭尾，最長 366 天，`to` 不得晚於今天）自訂。不合法回 400 `VALIDATION_DAILY_REVIEW_PERIOD_INVALID`。近 N 天以昨天為 `to`；今天尚未結束，不計入。

```json
{"data": {
  "from": "2026-09-11", "to": "2026-10-10", "as_of": "2026-10-11T12:00:00+08:00", "timezone": "Asia/Taipei",
  "required": 26, "on_time": 23, "late": 2, "unsigned": 1,
  "sign_rate": 0.9615, "sign_rate_percent": 96, "inferred_days": 0,
  "enabled_since": "2026-08-01T00:00:00+08:00", "enabled_since_inferred": false, "enabled_days": 71,
  "days": [{"date": "2026-10-10", "result": "not_due", "counts_toward_stats": false, "enabled_basis": "recorded", "late_days": 0}]
}}
```

- 應簽（`required`）只計期間內在範圍內且準時期限已過的日子；`result=not_due` 的日子不計。推定日照樣計入，`inferred_days` 為其中推定日的天數。
- `sign_rate_percent` 無條件捨去；`required=0` 時 `sign_rate`／`sign_rate_percent` 為 `null`。
- `enabled_since` 為目前這段連續啟用的起點（目前未啟用時為 `null`），`enabled_since_inferred=true` 表示起點是升級時推定的。

**Review**（簽核紀錄）：`{id, review_date, reviewer_id, reviewer_name, snapshot_json, note, created_at, signed_at, timezone, timezone_inferred, window_start, window_end, due_at, late, late_days, delay_reason, coverage, source_status, enabled_basis}`。`coverage` 為 `full_day`，升級前的舊紀錄為 `until_signed`（快照只涵蓋到簽核時刻）；`delay_reason` 只在遲簽時有值；`late_days` 為簽核日期與所屬日隔天相差的天數。

**簽核錯誤**（`POST /daily-reviews`）：

| HTTP | code | 條件 |
|---|---|---|
| 400 | `VALIDATION_DAILY_REVIEW_DATE_INVALID` | `review_date` 不是 `YYYY-MM-DD` |
| 400 | `VALIDATION_DAILY_REVIEW_TEXT_TOO_LONG` | `note` 或 `delay_reason` 超過 500 字；params `{field}`（`note`／`delay_reason`） |
| 400 | `RULE_DAILY_REVIEW_DAY_NOT_ENDED` | 該日尚未結束（今天或未來） |
| 400 | `RULE_DAILY_REVIEW_DAY_SETTLING` | 結束後的 30 分鐘寬限內；params `{signable_at}`（RFC3339） |
| 409 | `CONFLICT_DAILY_REVIEW_SIGNED` | 該日已有人簽核；params `{date, signer, signed_at, timezone}`（`signed_at` 為 RFC3339，以該日的切日時區呈現） |
| 400 | `RULE_DAILY_REVIEW_DAY_OUT_OF_SCOPE` | 該日不在啟用範圍內，或是改時區時被跳過的日期 |
| 400 | `VALIDATION_DAILY_REVIEW_DELAY_REASON_REQUIRED` | 遲簽而延遲原因為空白 |
| 400 | `RULE_DAILY_REVIEW_ALERTS_PENDING` | 該日仍有未審閱的告警；params `{count}` |
| 400 | `RULE_DAILY_REVIEW_DISABLED` | 功能未啟用 |

查詢端點的內部錯誤分別為 `INTERNAL_DAILY_REVIEW_PENDING_QUERY`、`INTERNAL_DAILY_REVIEW_DAY_QUERY`、`INTERNAL_DAILY_REVIEW_STATS_QUERY`（500）。

簽核的稽核列 details 為 `{review_date, timezone, signed_at, late, late_days, snapshot}`，不含備註與延遲原因全文。

高危操作計數白名單（以審計列的 `action` 判斷，不看 HTTP 方法）：任何資源的 `delete`；`security_policy`／`syslog_setting`／`audit_export` 的
`create`／`update`／`delete`；同步匯出（`GET /api/v1/audit-export`，審計記為 `read`＋`audit_export`，因為它把稽核證據帶出系統而收錄）；
`user` 的 `create`／`update`。上述三類資源的讀取（政策清單、條文定義、syslog 設定、匯出清單、公鑰、匯出產物下載）、
預覽（`apply-preview`、`compliance/preview`，審計記為 `read`；舊版本記為 `create` 的列以路徑排除）與 syslog 連線測試（`execute`）都不計入。
此口徑自 1.17.0 起生效：已固化的簽核快照不重算，只影響之後的新簽核、即時計數與單日明細，因此同一天在升級前後簽核的數字可能不同。

逾期提醒：每 15 分鐘檢查一次，業務時區當地時間過了 09:00、當天尚未送過、且至少一天已過準時期限時，經通知通道送一則 `daily_review_overdue`，列出全部未簽日（見「通知通道」的系統訊息）；只有昨天未簽（仍在準時期限內）、全部補齊或功能關閉時不送。

### 稽核失效事件（10.7.2/10.7.3；`audit:view`）

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/audit-failures` | 失效事件列表（`page`/`page_size`）→ `{data: {items: [{mechanism, started_at, ended_at, cause, cause_code, cause_params, details}], total}}`；`ended_at` null=進行中 |
| POST | `/audit-failures/permission-state/accept` | 僅超級管理者（非超管 403 `AUTH_PERMISSION_DENIED`，單一形狀）。body `{reason}`（1 至 500 字、不可含控制字元）。對帳判定權限狀態不符（含被偵測到的無來源變動）時確認並接受風險：同一交易寫入 `accept` 事件（以目前狀態為新基準）與審計列（`permission_state_accepted`，記確認人、原因、差集摘要），不改任何角色或授權；對帳無法判定（變更紀錄缺漏、驗證不過或沒有可用基準）時同一入口改為重設比對基準，事件帶重設標記，審計列另記 `mode=rebase`、`state` 與無法判定的原因摘要，被破壞的紀錄原樣保留。重設時另記 `after_cp_seq`（重設寫入當下鏈上最新的檢查點序號，用以判定重設與附證的先後），差集改以最後一個可信參考點對目前狀態計算，有參考點時審計列與回應另帶 `reference_event_seq`／`reference_cp_seq`；重設提交後立即重跑對帳，未以這次重設起算時不回成功。成功回 `{data: {op_id, event_seq, missing_count, extra_count, missing?, extra?, reference_event_seq?, reference_cp_seq?}}`（`missing`／`extra` 最多 20 筆），告警結案。原因不合 400 `VALIDATION_PERMISSION_STATE_ACCEPT_REASON`；相符或尚未涵蓋（沒有可確認的差異）409 `CONFLICT_PERMISSION_STATE_NOT_ACCEPTABLE`；失敗 500 `INTERNAL_PERMISSION_STATE_ACCEPT`（取不到完整性密鑰時交易已回滾；重設已提交卻未被對帳採用時同樣回此碼，已寫入的事件與審計列保留） |

機制：`audit_write`（稽核批量寫庫失敗降級 fallback 檔）、`syslog_forward`（斷線/緩衝溢出）、
`recording_probe`/`recording_text`/`recording_graphics`（錄影三路）、`session_record`、`kek_retirement`。
事件記錄恆開；通知（失效/恢復，經通知通道）受政策 `failure_alert_enabled` 控制，進行中節流。

**cause 機器碼化**：

- `cause_code`（權威表述）：機器碼，值域見 `backend/internal/model/audit_failure.go` 的 `Cause*` 常數
  （如 `recording_start_failed`／`audit_write_fallback_file`／`syslog_connect_failed`／
  `kek_retirement_backlog`），前端按碼查譯顯示；三語短語另由 `internal/notifycat` 的 cause 詞庫渲染。
- `cause_params`：**物件**形態輸出（DB 存 JSON 字串，API 解碼後回物件，解不開即空物件不讓整份列表失敗）。
  含 `detail` 鍵時為 forensic 明細（底層錯誤原文），**僅落庫與 UI，不進出站 webhook payload**（去識別紅線）。
- `cause`（散文）：降為顯示 fallback（zh-TW 短語＋forensic detail），保留以免未改查譯的既有讀取點白屏。
- 同源一致：`sessions.recording_error` 自此存**同一組 cause code**（不再存散文），前端 tooltip 亦按碼查譯。

### 稽核完整性（10.3.4；`/audit-integrity/verify` 需 `audit:integrity_view`）

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/audit-integrity/verify?from=YYYY-MM-DD&to=YYYY-MM-DD` | 範圍掃描重算逐列 HMAC → `{data: {checked, passed, mismatched, mismatched_ids(上限 100), legacy}}`；`legacy`=功能上線前無 HMAC 的歷史列（不算不符）；預設近 7 天 |
| GET | `/audit-export/public-key` | 匯出簽章公鑰（`audit:view`）→ `{data: {algorithm: "Ed25519", public_key: base64}}` |

匯出 ZIP 內新增 `manifest.sig`（Ed25519 簽 `manifest.json` 檔案位元組的 base64），
以公鑰可離線驗證 manifest 未被竄改。能力邊界：逐列 HMAC 可偵測改內容，
**整列連 HMAC 刪除由檢查點鏈偵測**（見下節；本端點自身不涵蓋序列完整性）。

`/audit-integrity/verify` 與下節的檢查點鏈端點同樣需 `audit:integrity_view`（內建稽核員範本持有）：
稽核員既能證序列完整，也能自行驗內容真偽，不必由被監督者代為出具監督證明。

### 稽核檢查點鏈（需 `audit:integrity_view`，唯讀）

檢查點鏈對 `audit_logs` 的 **id 閉區間 `[id_from, id_to]`** 逐段蓋章：每小時或每 10000 筆先到先觸發，
記下 `id_hi = MAX(id)` 並延遲 grace（預設 30 秒）後掃描區間，算出
`(id, key_version, integrity_hmac)` 三元組的串流 SHA-256，與前一檢查點的雜湊鏈接後
以 Ed25519 簽章落庫。空區間照蓋（`row_count=0`），故 `seq` 恆為嚴格連續。

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/audit-checkpoints?page=&page_size=` | 檢查點列表（seq 倒序）→ `{data: {items: [...], total}}`；每筆含 `seq`／`id_from`／`id_to`／`row_count`／`agg_hash`／`agg_scheme`／`prev_checkpoint_hash`／`sealed_at`／`signing_key_version`／`signature`／`anchor_status`／`purged_at`；第三版起另含帳本區間四欄；**第四版（`agg_scheme` 為 `cp-agg-v4`）的列一律帶 `perm`**：帶權限附證者為八鍵物件 `{format, model, catalog, snapshot_digest, event_seq, event_head, reconciled, origin}`（只含整數、雜湊與布林，不含快照本體），不帶附證者明寫 `null`；第三版以前的列不帶此鍵。附證欄組合不合法的第四版列不帶此鍵（離線驗證回報「載荷無法重建」）。離線重建規則見 `docs/security/audit-checkpoint-offline-verification.md` 第四版一節 |
| GET | `/audit-checkpoints/verify` | **結構層**（預設全鏈）→ `{data: {chain: {total, latest_seq, oldest_seq, passed, failed, status, failures, unsealed_rows, unsealed_from_id, anchor_disabled, role_state, principal_state, agent_token_state, permission_state?}}}`（`permission_state` 只在權限狀態對帳無法判定時出現） |
| GET | `/audit-checkpoints/verify?content=true&seq_from=&seq_to=` | 加驗**內容層**（亦支援 `from=`／`to=` 日期映射）→ 另回 `content.intervals[]`，逐區間帶 `status` 與 `remain_rows` |
| GET | `/audit-checkpoints/public-key` | 鏈簽章公鑰 → `{data: {algorithm: "Ed25519", public_key, fingerprint, version}}`，供離線驗章 |

**兩層驗證的分工**：結構層純讀檢查點表（驗簽章、驗 prev hash 鏈接、驗 seq 連續），
10 年鏈約 8.8 萬列仍是秒級，故常開；內容層要重掃 `audit_logs` 重算聚合，
**必須帶範圍**，不帶回 `400 VALIDATION_CHECKPOINT_RANGE_REQUIRED`（範圍格式錯誤
回 `VALIDATION_CHECKPOINT_RANGE_FORMAT`）——不設此閘則一個無參數請求就會啟動
全歷史掃描。日期範圍映射不到任何檢查點時回空結果，不退化成全鏈。

逐區間狀態（十態，前端逐態有獨立文案與視覺分級）：

| 狀態 | 語義 |
|---|---|
| `passed` | 列數與聚合雜湊皆相符 |
| `purged_legal` | 區間已依保留政策整段清除，tombstone 簽章驗過（**非錯誤**） |
| `purged_invalid` | 列已不存在卻無有效 tombstone＝竄改 |
| `count_mismatch` | 殘留列數少於封章主張 |
| `hash_mismatch` | 列數相符但聚合不符（含多出的列其列級 HMAC 無效） |
| `extra_rows_valid_hmac` | 多出列且列級 HMAC 皆有效（遲到交易或持蓋章鑰者插列，需人工研判） |
| `signature_invalid` | 檢查點自身簽章驗不過 |
| `chain_broken` | `prev_checkpoint_hash` 與前一點重算值不符 |
| `seq_gap` | seq 斷洞，且無修剪記錄可解釋 |
| `attestation_invalid` | 檢查點本身驗過，但附證形狀不對：第四版之前的點帶權限附證欄（那些欄不在其簽章內），或鏈上已有附證之後（或修剪錨記載曾有附證／曾有驗不過的點）又出現不帶附證的第四版點（只出現在結構層）。第四版的附證被清空或改動時，該點本身簽章驗不過，回報 `signature_invalid`；部分清空回報 `payload_invalid` |

**角色指派維度**（`chain.role_state`）：每個檢查點另簽入封章當下的角色指派，
結構層驗證因此順帶回報一份對帳結果——把現況與最近一個含快照的檢查點加上其後
每一筆有留痕的授予與撤銷相比。欄位為 `covered`（是否已有可比對的基準）、
`state`（`match`／`mismatch`／`not_covered`）、`since_seq`（作為基準的檢查點序號）、
`missing`／`extra`（差集，逐筆帶 `user_id`／`role_id` 與對應的 `username`／`role_name`）、
`last_event`（不符時附最近一筆相關的稽核失效事件，供前端連結）。
`not_covered` 出現在尚未封出任何含快照的檢查點時（升級後首個封章之前），
**它不是相符**；欄位整段缺席表示本次未附帶對帳結果，同樣不得讀成相符。
帳號名與角色名只在本端點的回應內出現：快照與失效事件一律只帶識別。

**主體與憑證維度**：`chain.principal_state`（`user_principals`）與
`chain.agent_token_state`（`agent_tokens`）和既有 `role_state` 並列，既有角色欄位不變。
兩者各帶 `covered`、`state`、`since_seq`、`expected_hash`、`actual_hash`、
`missing`／`extra`（僅帳號或憑證識別值陣列，空差集省略）與不符時的 `last_event`。
`state` 為 `match`／`mismatch`／`not_covered`／`unknown`；讀取或推演失敗為
`unknown`，不會使其他項失去結果，也不可視為相符。升級後首次含新項的封章前，
新兩列為「尚未涵蓋」。`last_event` 形狀沿用角色事件，機制為
`principal_state_integrity`、成因為 `principal_state_mismatch`；事件參數帶項名與差集識別值，
不帶帳號名、電子郵件、憑證材料或其原始雜湊。
對帳在驗證、封章及核發憑證前執行，偵測非即時；發證前不符不阻斷發證，
對帳錯誤只記日誌，不修改主體或憑證現況，也不記為相符。
服務層投影狀態列 actor 記 `system`，操作者由既有 HTTP 稽核列承擔。

**權限附證只在無法判定時出現在本組回應**：自本版起每個檢查點另帶權限狀態附證（見 DB_SCHEMA 第 37、66 節），本組端點的正常回應欄位不變。附證或權限狀態對帳不符時，經上述 `principal_state_integrity` 失效事件回報，事件參數的項名為 `permission_state`。對帳無法判定（變更紀錄缺漏、驗證碼不符、沒有可用基準）時，同一項目另開一筆固定識別的失效事件（`actual_hash=unknown`、`since_seq=0`，整段期間只一筆），結構層回應的 `chain` 另帶 `permission_state: {state: "unknown", last_event?: {id, mechanism, cause_code, started_at, ended_at?}}`，不帶錯誤原文；相符、不符與尚未涵蓋時此欄不出現。超級管理員的確認與重設基準見「稽核失效事件」的 `POST /audit-failures/permission-state/accept`。

**寫入面刻意不存在**：本組端點無任何 POST/PUT/DELETE——「可以被系統改的檢查點」
在稽核面前一文不值。到期修剪只由 retention 排程依 `retention_checkpoint_days` 執行。

誠實邊界（R0-R6 全文見 `openspec/specs/audit-checkpoint-chain/spec.md`，驗證頁亦逐條呈現）：
鏈證明「**DB 內的序列未被動**」，不證明「所有事件都進了 DB」（降級寫檔與滿載丟棄的
列不在 DB 也無 HMAC）；持簽章私鑰者可偽造整鏈，對抗手段是 syslog 離機錨定，
未啟用轉發時 `anchor_disabled=true` 且驗證頁顯示不可關閉的降級橫幅。

---

## 使用者群組 API（需 `usergroup:manage`）

> 使用者群組是**授權主體**的分組（與 RBAC 角色相互獨立，不影響端點權限）；
> 群組授權對全體成員生效，成員加入/移出即時反映（下次權限判定生效，無快取）。

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/user-groups` | 群組列表（含成員）→ `{data, total}` |
| POST | `/user-groups` | 建立 → 201；名稱重複 409 |
| PUT | `/user-groups/:id` | 更新名稱/描述 |
| DELETE | `/user-groups/:id` | 刪除 → `{message, revoked_authorizations}`；同交易軟刪成員關係＋掛該群組的全部授權並寫稽核（含連動撤銷筆數） |
| PUT | `/user-groups/:id/members` | 成員全量替換（穿梭框語義），body `{"user_ids": [...]}`；成員不存在 400 |
| GET | `/user-groups/:id/authorization-count` | 群組授權筆數 → `{authorization_count}`（刪除確認 UI「將連動撤銷 N 筆授權」） |
| GET | `/user-groups/:id/role-bindings` | 群組目前的角色指派 → `{data: [{role_id, role_name, scope}], total}`，`scope` 為 `global` 或 `nodes`，節點範圍的列通常另帶 `node_ids`，判讀以 `scope` 為準；需使用者群組管理能力 |
| GET | `/user-groups/:id/external-mappings` | 啟用中的外部群組映射摘要 → `{data: [{rule_id, source_type, source_name, source_enabled, external_group_label}], total}`；需使用者群組管理能力；來源已停用的規則仍列出並以 `source_enabled=false` 標示；不含成員名單與成員數；群組不存在 404 |
| PUT | `/user-groups/:id/role-bindings` | 整組替換，body `{"role_ids": [...], "role_nodes": {…}}`，`role_nodes` 為選用，語義見「用戶 API」的「節點範圍」；成功回應與 GET 同形，有不會生效的節點範圍時另附 `node_range_no_effect`；需指派角色能力。`role_nodes` 以外的範圍或節點欄位整筆拒絕；審核者身分不能指派給群組；群組不存在 404 |


### 角色指派的保護與開放邊界

指派入口（`PUT /users/:id/roles`、`POST /users/:id/roles/:role`、建立帳號帶角色、`PUT /user-groups/:id/role-bindings`、`PUT /user-groups/:id/members`、`DELETE /user-groups/:id`）共用同一道關卡；其中只有兩個整組替換入口收節點範圍（見「用戶 API」的「節點範圍」）。關卡拒絕時回應不帶角色名稱或權限名稱，細節只進審計；操作者缺少路由本身要求的能力時，請求在路由授權層就被拒，回應是全站一致的 403 `AUTH_PERMISSION_DENIED`（單一形狀）。關卡的拒絕碼如下：

**保護角色**指超級管理者、系統安全管理員兩個內建角色，以及權限集合含任一「高風險權限點」的自訂角色。高風險權限點是能刪除證據、關閉或改道告警、放寬安全控制或管理金鑰的權限點，共 9 個：`alertrule:manage`、`key:manage`、`notification_channel:manage`、`offsite:manage`、`policygroup:manage`、`recording:delete`、`securitypolicy:manage`、`syslog:manage`、`systemalert:manage`。它們都是系統安全管理員專屬的權限點（系統安全管理員範本持有、而超級管理者以外的其他內建範本都不持有）。系統安全管理員其餘的專屬權限點 `instanceguard:view`、`rotation_schedule:manage`、`schedule:manage`、`transmission:manage` 屬唯讀檢視、排程與清冊，不使自訂角色成為保護角色；`policygroup:view` 稽核員範本也有，不屬專屬權限點。

| 碼 | HTTP | 情形 |
|---|---|---|
| `AUTH_PROTECTED_ROLE_ASSIGNMENT` | 403 | 被新增或移除的指派是保護角色，或對帶保護角色指派的群組加人、移人或刪除，而操作者不是超級管理者。保護角色在寫入前後都不變、只增減其他角色時不在此限，持 `role:assign` 即可 |
| `AUTH_PROTECTED_ACCOUNT_OPERATION` | 403 | 非超級管理者對超級管理者帳號設定密碼、停用多因素驗證、綁定外部身分或寫入角色；或對持有超級管理者、系統安全管理員身分的帳號停用（含解除綁定並停用）、啟用或刪除 |
| `VALIDATION_ROLE_BINDING_SCOPE_UNSUPPORTED` | 400 | 不收範圍的入口（冪等追加、建立帳號帶角色、釘住）的請求本文頂層帶任何範圍或節點欄位（鍵名含 `scope` 或 `node`），或兩個整組替換入口帶了 `role_nodes` 以外的範圍或節點欄位；整筆拒絕、不寫任何資料，不會改存為全域 |
| `VALIDATION_ROLE_NOT_NODE_SCOPABLE` | 400 | `role_nodes` 把節點範圍給了含只能套用到全系統權限的角色 |
| `VALIDATION_ROLE_BINDING_NODES_EMPTY` | 400 | `role_nodes` 的某個值是空陣列；要全系統請送 `null` |
| `VALIDATION_ROLE_BINDING_NODES_INVALID` | 400 | `role_nodes` 含不存在或已刪除的節點，兩者同形，不帶節點名稱 |
| `VALIDATION_ROLE_NOT_GROUP_BINDABLE` | 400 | 審核者身分不經使用者群組取得 |

開放邊界：升級後新增的兩個鎖定範本與日後建立的自訂角色，與升級前存量的角色一樣可經這些入口被指派，照常經過上表的保護角色、指派能力與範圍欄位規則；`GET /roles` 的列表內容不因此改變（見「角色 API」的相容邊界）。身分管理員可為系統安全管理員帳號設定密碼、停用多因素驗證或綁定外部身分，這些操作成功後觸發系統告警並留下審計，不是被阻擋。

### `GET /role-assignment-options`

唯讀，供指派畫面選擇節點用，不寫業務資料（請求本身的操作紀錄仍依既有審計設定與機制處理）。需指派角色能力，且只能由全域持有該能力者使用（超級管理者經同一登錄）；沒有這項能力的呼叫者得到與其他受保護路由相同的拒絕回應，不帶任何節點資料。agent 主體不可使用。

回應（頂層欄位，沒有 `data` 包裝）：

- `nodes`：全部未刪除節點的扁平陣列，每項有 `id`、`name`、`parent_id`（根層為 `null`）、`depth`（根為 1）、`path`、`subtree_asset_count`（該節點與其子孫節點下的未刪除資產台數，同一資產只計一次）。
- `node_assignable_role_ids`：目前可以限定節點的角色 ID。
- `node_range_no_effect_role_ids`：上一項的子集，這些角色可以照常以節點範圍指派，但範圍不會產生權限。
- `node_range_no_effect_reasons`：物件，鍵為上一項每個角色 ID 的十進位字串，值為 `builtin_global_only` 或 `no_scoped_permission`，與寫入回應 `node_range_no_effect` 的 `reason` 同義（見「用戶 API」的「節點範圍」）；鍵集合恰等於上一項。

沒有可限定的角色、沒有節點時，對應欄位為空陣列或空物件，不省略。只回節點名稱、路徑與台數，不回資產名稱、位址、識別碼或資產清單；台數不依呼叫者自己的連線授權或管理範圍收斂。這條路由只提供畫面的選項，選項不保證具體指派一定可寫入，實際能否限定節點由兩個寫入入口判定。專為部分節點設計的角色範本尚未提供，這裡不列範本。來源讀取失敗回 500 `INTERNAL_ROLE_QUERY`。

### `POST /role-assignment-previews`

唯讀試算，不寫業務資料、不推進權限版本。請求本身在操作日誌記為讀取（資源為角色），成功與驗證失敗相同；`POST /assets/import/preview` 與 `POST /oidc-providers/discovery-preview` 同為唯讀試算，也記為讀取。需指派角色能力，並須具備被預覽的那種寫入所需能力（角色定義修改的預覽限超級管理者）。

body：`{"kind": "direct_roles" | "group_roles" | "group_members" | "role_definition", ...}`，各種類欄位為 `user_id`、`group_id`、`role_ids`、`member_ids`、`manual_member_ids`、`role_id`、`permissions`。`direct_roles` 與 `group_roles` 另接受選用欄位 `role_nodes`，值的語義同寫入，但鍵一律為角色 ID 的十進位字串（使用者入口實際寫入的鍵為角色名），以送出的範圍試算；預覽仍是唯讀。`group_members` 的 `manual_member_ids` 與 `member_ids` 二擇一，兩者同送回 400，其求值與寫入共用同一份手動成員求值。新種類 `mapping_rule_change` 試算一條外部群組映射規則的新增、修改、刪除，欄位為 `rule_type`、`source_type`、`source_id`、`rule_id`、`match_value`、`role_id`、`group_id`、`enabled`、`delete`，嚴格解碼，需身分來源管理能力；受影響者為授出側命中與收回側支持的聯集，操作者本人優先求值，逐人求值上限 200，總數取全部；此種類的回應不帶 `subject_ids` 輸入。

**可管理資產台數**：`direct_roles` 與 `group_roles` 另接受選用布林欄位 `include_managed_asset_counts`（預設 false）。為真時，回應多附變更後的資產台數，只有數字，不含資產名稱、位址或識別碼；台數是資產列表管理範圍的試算台數，不是角色所有操作可作用的資產數；未帶或為 false 時，回應不多任何鍵。口徑與資產列表的管理範圍相同：超級管理者與稽核員為全部未刪除資產；其他主體只計節點範圍指派所涵蓋節點與其子孫節點下的未刪除資產，同一資產只計一次，已刪除的節點不計。各角色台數，以及超級管理者與稽核員以外主體的總量，只計授權解析認定為資產檢視有效節點範圍來源的指派，沒有成為該來源的指派（例如角色不含資產檢視權限點）貢獻 0；對超級管理者與稽核員以外的主體，經全域指派持有的資產檢視權限不計入總量，也不使台數變成全部；只經連線授權可見的資產不計。數字是套用試算指派後的結果。

- `direct_roles`：`managed_assets: {before, after}` 為該使用者變更前後的可管理資產台數（含經群組取得的範圍）；`role_assets: [{role_id, direct, from_groups_extra, total}]` 為試算後以節點範圍持有的每個角色一列，`direct` 為管理者直接指派所涵蓋、且屬資產檢視有效節點來源的台數，`total` 為直接指派與經群組取得的範圍聯集後同樣只計該來源的台數，`from_groups_extra` 等於 `total` 減 `direct`。僅以全系統範圍持有的角色不列；同角色另有節點範圍指派時仍列出。
- `group_roles`：`group_assets: {before, after}` 為該群組自己的指派集合變更前後的台數；`role_assets: [{role_id, total}]` 為試算後以節點範圍持有的每個角色一列。

`group_members`、`role_definition`、`mapping_rule_change` 帶這個欄位時不回台數，也不因此被拒。要求台數不改變預覽既有的能力要求，也不改其他輸出；只持指派角色能力、沒有該預覽種類所需能力的呼叫者照舊被拒。

回應：`{total, matched, truncated, operation, subjects: [{user_id, self, assign_capable, entries_gained, entries_lost, routes_gained, routes_lost, combos, new_combos, self_direction, management_granted, marks}]}`。頂層 `operation`（`marks`、`self_direction`、`management_granted`、`routes_gained`、`routes_lost`、`entries_gained`、`entries_lost`、`evaluated`）以與寫入相同的分類函式求得，不受逐人列出條件與 100 筆上限影響。每位主體的 `routes_gained`／`routes_lost` 與前端導覽使用同一份入口規則，登入即可與依本人資格的入口不列入。測試：`TestRoleAssignmentPreviewContract`。清單只列操作者本人與變更後新命中危險組合者，上限 100 筆，其餘只計入 `total`。種類不明或對象不存在回 400 `VALIDATION_BAD_PARAMS`，失敗 500 `INTERNAL_ROLE_ASSIGNMENT_PREVIEW`。寫入路徑不要求先預覽。

---

## 授權 API

> 授權規則管理端點要求 `authorization:manage`；`GET /authorizations/self-subjects` 供已認證人類主體查詢自己的範圍。
> 各端點的額外條件以下文為準。權限解析為四路徑聯集取最高（個人直授/個人組授/群組直授/群組組授），
> 無 deny、無「個人優先」；僅計入時效窗內授權（`date_start`/`date_expired`，空值＝永久；
> 建立 API 不接受手填時效，傳入即忽略——時效唯一來源為後續核准流）。
>
> **本人範圍限制**：操作者的「本人範圍」＝操作者本人、操作者直接所屬的使用者群組（不分手動或映射來源）、
> 擁有者為操作者的 agent 主體（含停用中者），於寫入交易內現查。非超級管理者建立授權規則（單筆與批量）時，
> 主體含本人範圍任一者整筆拒絕，回 403 `RULE_AUTHORIZATION_SELF_SUBJECT`、零寫入（批量不部分成功）；
> 調整主體屬本人範圍的既有規則的帳號範圍同碼拒絕（帳號範圍更新端點對非超級管理者的持有者同樣套用此判定，見該節），
> 刪除不受此限。超級管理者不受本限制。
> 只在建立或調整當下判定，事後的群組成員異動不追溯；兩位操作者互相對對方建立規則不在此判定範圍內。拒絕回應不帶主體名稱、識別值或規則數量。
>
> **管理範圍**：持有 `authorization:manage` 的主體，其指派可限於部分節點（管理範圍）。範圍限制只作用於規則的**客體**（資產與節點）；
> 規則的主體（使用者、群組、agent）是全域實體，不受節點範圍限制。寫入端點（建立、批量、帳號範圍更新、刪除）在同一交易內
> 重解操作者的有效指派並判定客體是否在管理範圍內，列表與兩個有效權限視角依同一範圍投影；全域持有者（含超級管理者）
> 不受範圍限縮。範圍外與不存在回相同的回應：單筆建立的資產客體回 404 `NOTFOUND_GRANT_REFERENCE`（`entity=asset`）、
> 節點客體同碼（`entity=asset_group`）；對既有規則的帳號範圍更新與刪除回 404 `NOTFOUND_AUTHORIZATION`。
> 沒有任何生效的 `authorization:manage` 指派（含範圍節點已全數刪除者）回單一 403 `AUTH_PERMISSION_DENIED`。
> 節點範圍指派可經 `PUT /users/:id/roles` 與 `PUT /user-groups/:id/role-bindings` 的 `role_nodes` 寫入（見「用戶 API」的「節點範圍」）；上述範圍規則適用於這類指派。

### 創建授權

```
POST /api/v1/authorizations
```

**請求**（主體 `user_id` 與 `user_group_id` 二擇一、客體 `asset_id` 與 `asset_group_id` 二擇一，違反回 400）:
```json
{"user_id": 2, "asset_id": 1, "permission": "connect"}
```
群組主體: `{"user_group_id": 1, "asset_id": 1, "permission": "connect"}`；
節點客體（含子樹）: `{"user_id": 2, "asset_group_id": 1, "permission": "view"}`

**Permission 類型**: `view`（查看）/ `connect`（連線，含 view）——兩階制。
`manage` 已移除：建立/批量 API binding 拒收（400）；歷史軟刪列不動，
活躍 manage 已由 migration 收斂為 connect（碰撞安全）。

**source 欄位**: `manual`（管理員手動授權，預設）/ `ticket`（申請核准流產生的臨時授權，帶
`date_start`/`date_expired` 時效窗）。臨時授權不佔用手動授權的去重空間（partial 唯一索引
排除 `source='ticket'`），撤銷語義相同。

**accounts 欄位（帳號範圍）**: 建立與批量授權的請求皆可帶
`"accounts": ["app", "deploy"]`——**省略（null）＝`@ALL`**（客體範圍內資產的全部帳號，
與多帳號引入前行為一致）；顯式送 `[]` 拒收（要撤銷請刪授權列）。批量授權展開出的每一筆
共用同一帳號範圍。回應恆帶 `accounts` 且恆非空（空值顯化為 `["@ALL"]`）。

**回應** (200，注意非 201):
```json
{
  "id": 1,
  "user_id": 2,
  "username": "user1",
  "asset_id": 1,
  "asset_name": "Server1",
  "permission": "connect",
  "granted_by": 1,
  "created_at": "2026-07-01T00:00:00Z"
}
```
（群組主體回 `user_group_id`/`user_group_name`；節點客體回 `asset_group_id`/`asset_group_name`，涵蓋＝節點＋子樹資產）

**錯誤**: 409 授權已存在（撤銷後重授同組合不受歷史記錄阻擋）、404 用戶/群組/資產不存在、403 `RULE_AUTHORIZATION_SELF_SUBJECT`（主體落在操作者本人範圍，見本節開頭）。
操作者的管理範圍不含該資產或節點時，回應與客體不存在相同（見本節開頭「管理範圍」）。

### 批量授權

```
POST /api/v1/authorizations/batch
```

**請求**（主體集×客體集×單一等級，伺服端於單一交易展開為多筆單主體單客體記錄）:
```json
{"user_ids": [2, 3], "user_group_ids": [1], "asset_ids": [1, 2, 3], "asset_group_ids": [], "permission": "connect"}
```

**回應** (200): `{"created": 8, "skipped": 1}`——已存在的組合原子跳過不報錯（`ON CONFLICT DO NOTHING`，並發安全）。

**錯誤**: 400 主體集或客體集為空／展開筆數超過上限 10000（不部分寫入）、404 任一引用不存在（整批拒絕）、
403 `RULE_AUTHORIZATION_SELF_SUBJECT`（主體集含操作者本人範圍任一者，整批拒絕、零寫入）。
操作者只持有範圍限定的指派時，客體集中任一資產或節點在範圍外或不存在，整批不寫，回 404 `NOTFOUND_BATCH_ITEMS_UNAVAILABLE`，
`params` 只有 `count`（無法操作的客體數，依客體 ID 去重，不計主體）；全域持有者的不存在引用沿用 `NOTFOUND_BATCH_GRANT_REFERENCE`。
稽核記一筆批量事件。

### 列表 / 刪除

```
GET    /api/v1/authorizations                （零篩選＝全量分頁；user_id、user_group_id、asset_id、node_id 至多一個，多於一個 400）
GET    /api/v1/authorizations?validity=expired&source=ticket  （伺服端篩選，COUNT 與分頁前生效）
DELETE /api/v1/authorizations/:id            → {}
```

列表回應: `{"data": [...], "total": N, "page": 1, "page_size": 20}`
（`page_size` 逾 100 或小於 1 一律**重設為 20**，非夾為 100；`/my/connections` 才是夾為 100）。
篩選參數：`validity` = `active`/`scheduled`/`expired`（三態時窗，白名單否則 400）、
`source` = `manual`/`ticket`。

`node_id` 篩選＝**涵蓋盤點語義**：回傳授權有效範圍與該節點子樹有交集的記錄，
三分支聯集——(1) 節點客體位於目標之祖先鏈/自身/後代（掛祖先因子樹涵蓋、掛後代落在範圍內）；
(2) 節點客體之子樹內存在同時掛載於目標子樹的資產（多歸屬橋接）；(3) 資產客體掛載於目標子樹內。
每筆授權僅出現一次；與 `validity`/`source` AND 疊加、COUNT 與分頁前生效。

列表項目主體與客體皆可辨識：user 主體帶 `user_id`/`username`、群組主體帶 `user_group_id`/`user_group_name`；
直接授權帶 `asset_id`/`asset_name`/`asset_protocol`、節點授權帶 `asset_group_id`/`asset_group_name`（全路徑）。
每列另含 `source`、`date_start`/`date_expired`（有值才出）、`validity_state`（`scheduled`/`active`/`expired`，
伺服端計算與解析引擎同語義）；`source='ticket'` 列附 `request_id`（反查申請單，無單省略）與
`revocable`（有單且時窗內＝true，前端按鈕零推導）。引用已軟刪實體的列帶 `subject_deleted`/`target_deleted` 標示。

列表只含客體（資產或節點）在檢視者管理範圍內的規則，篩選、計數與分頁都在範圍條件之後。客體在範圍外、但涵蓋範圍內資產的規則
（例如掛在範圍根的祖先節點上的規則）不出現在列表，檢視者對它沒有寫入能力；它對範圍內資產的影響在有效權限視角以溯因呈現。

檢視者不是超級管理者時，每一列另帶 `actions`（檢視者是超級管理者時各列不帶）：
`{"update_accounts": {allowed, reason?, limit?}, "delete": {allowed, reason?}, "revoke"?: {allowed, reason?}}`；`revoke` 只在 `source='ticket'` 的列出現。
`reason` 只在不可操作時有值，取值為 `self_subject`（規則主體在操作者本人範圍，帳號範圍不可調整）、`ticket_bound`（臨時授權：帳號範圍不可調整、有關聯申請單者不可直接刪除）、
`not_revocable`（無關聯申請單、已不在時窗內或沒有可撤銷的票證）、`revoke_not_eligible`（操作者不具撤銷資格）；
`limit` 只在可操作時有值，恆為 `narrow_only`，表示操作者不是規則建立者，帳號範圍只能縮小。
旗標只決定畫面，各端點仍各自裁決，與旗標共用同一組判定。

DELETE 對 `source='ticket'` 且有關聯申請單的授權回 **409**（撤銷唯一路徑＝`POST /access-requests/:id/revoke`，
資格/附註/`access_revoke_disconnect` 斷線聯動見連線申請 API）；反查無單的孤兒 ticket 放行刪除並記稽核。

### 本人範圍（自身唯讀）

```
GET /api/v1/authorizations/self-subjects
```

**權限**: 任何已登入的人類主體（登錄類別 self；agent token 回既有路由拒絕）。

**回應** (200): `{"applies": true, "user_id": 7, "user_group_ids": [3, 9], "agent_ids": [21]}`
——`user_group_ids` 為本人直接所屬的群組、`agent_ids` 為擁有者為本人的 agent 主體（含停用中者），
資料與授權規則的本人範圍守衛同一函式；超級管理者 `applies=false`、清單照列。
介面據此在批次授權精靈把本人、本人擁有的 agent、本人所屬群組列為不可勾選，並在授權列表對主體屬
本人範圍的列停用帳號範圍動作；介面停用只是體驗，後端判定照常執行。不加到既有授權列表或使用者列表回應。

### 帳號範圍更新

```
PUT /api/v1/authorizations/:id/accounts
```

**權限**: `authorization:manage`。能力與管理範圍在寫入交易內以現況重解並判定（不看 JWT 角色快照）：
無生效指派回 403 `AUTH_PERMISSION_DENIED`（單一形狀）；規則的客體在管理範圍外與規則不存在同為 404 `NOTFOUND_AUTHORIZATION`。
非超級管理者的持有者可縮小帳號範圍；擴大須由規則建立者或超級管理者執行（見下方 `RULE_ACCOUNT_SCOPE_WIDEN_RESTRICTED`）。
範圍判定先於臨時授權的 409。

**請求**: `{"accounts": ["app"]}` 或 `{"accounts": ["@ALL"]}`
- 欄位為指標型別：**省略或 null → 400 `VALIDATION_ACCOUNT_SCOPE_REQUIRED`**（此端點不把
  未帶當 @ALL——收緊範圍是安全動作，必須顯式表態）。
- 顯式 `[]`、超過 200 項、項目全空白、含冒號／控制字元／`@` 前綴、單項逾 100 字元
  → 400 `VALIDATION_ACCOUNT_SCOPE_INVALID`。
- `source='ticket'` 的授權列 → 409 `CONFLICT_TICKET_ACCOUNT_SCOPE_IMMUTABLE`
  （臨時授權的帳號範圍源自申請單，不得事後改）。
- 授權不存在 → 404 `NOTFOUND_AUTHORIZATION`；id 非法 → 400 `VALIDATION_INVALID_AUTHORIZATION_ID`。
- 服務層另有兩項守衛，超級管理者皆豁免；其餘持有者受其約束：
  規則主體屬操作者本人範圍（本人、本人所屬群組、本人擁有的 agent）→ 403 `RULE_AUTHORIZATION_SELF_SUBJECT`，
  帳號範圍不變（刪除該規則仍可）；操作者非該規則的 `granted_by` 而新範圍超出現有範圍（擴大）→ 403
  `RULE_ACCOUNT_SCOPE_WIDEN_RESTRICTED`，帳號範圍與 `granted_by` 皆不變（縮小可、建立者擴大可）。

**回應** (200): 該授權列的完整序列化（同列表項目形狀，含更新後的 `accounts`，但不含 `actions`）。

**語義**: 有效帳號集合＝使用者全部命中授權列（含群組授權與 ticket 臨時授權）帳號範圍之**聯集**
（`@ALL` 展開為資產全帳號，聯集取寬）；admin 全量。強制點收斂三處——connect token **簽發**、
**兌換複查**、工作區**帳號選擇器過濾**；系統路徑（改密計劃、k8s、SFTP 側車）走預設帳號、不經此判定。
帳號範圍收緊於**兌換點 DB 現查**即時生效（已簽發 token 不因效期未到而放行）。

**申請單傳遞**: `POST /api/v1/access-requests` 的 `accounts` 於核准時以最終核定的子集落入該項 ticket 授權列；
核准人**不得上調**（同既有「時長/起始只可下修」語義）。

### 有效權限雙視角（需 `authorization:manage`）

```
GET /api/v1/authorizations/effective-assets?user_id=153   主體視角：該使用者實際可及的資產＋溯因
GET /api/v1/authorizations/effective-users?asset_id=1     客體視角：實際可及該資產的使用者＋溯因
```

subject 顯式參數解析（不自 request context 推導），來源六種聯集與執行期判定一致：
授權記錄四路徑（`direct_user`/`user_group`/`asset_node`/`user_group_asset_node`，帶 `authorization_id`＋時窗）、
`approver_scope`（審核範圍隱含 view，`authorization_id` 空）、`role_override`（admin/auditor 角色隱含——
主體視角回 `role_override` 欄位供 UI 摘要橫幅；客體視角回 `role_override_note` 說明，不逐人列舉）。
每資產/使用者帶最高 `permission` 與 `paths` 溯因列表（`via_group_name`/`via_node_path` 等）。
404＝主體/資產不存在。

**範圍化檢視者**（只持有範圍限定指派者；全域檢視者的回應不變）：
- 主體視角：主體不限範圍（任何存在的使用者），回傳的資產與檢視者管理範圍取交集，交集外的資產不出現。
- 客體視角：資產在範圍外與不存在同為 404；使用者清單照實計算（任何路徑可及即列）。
- 溯因遮蔽：`authorization_id` 只在該規則出現在檢視者的列表時保留；可見節點＝管理範圍子樹加上其祖先鏈（祖先節點只作定位）。經由祖先節點的溯因照常保留節點名稱與路徑；經由不在可見節點內的溯因不帶節點名稱、路徑與識別碼，
  並在該資產列（主體視角）或被遮蔽的使用者列（客體視角）多附 `out_of_scope_node_count`，值為該資產在管理範圍外的歸屬節點數（只給數量）。

### 授權畫面選擇器（需 `authorization:manage`）

```
GET /api/v1/authorizations/subject-options?kind=user|user_group&search=&page=&page_size=
GET /api/v1/authorizations/target-options?kind=asset|node|tag&search=&node_id=&tags=&page=&page_size=
```

兩條端點只供授權畫面挑選對象，欄位固定，回應不授予使用者管理頁或帳號寫入的能力（回傳的 `id` 是建立授權規則時引用對象用的值）。
回應外殼為 `{kind, data, total, page, page_size}`；`page_size` 超過上限 1000 時靜默截為 1000，不回 400。
無生效的授權規則管理指派（含範圍節點全數刪除者）回單一 403 `AUTH_PERMISSION_DENIED`。

- **subject-options**：`kind` 必填。使用者列回 `id`、`username`、`display_name`、`kind`（人或 agent）、`active`、`roles`（角色名稱清單）；群組列回 `id`、`name`、`description`、`member_count`。
  不回信箱、身分來源、多因素與登入紀錄；已刪除者不列，停用者照列並標狀態。主體目錄不依節點範圍過濾。
- **target-options**：`kind` 必填，結果一律依授權規則管理的管理範圍投影。資產列回 `id`、`name`、`protocol`、`host`、
  範圍內歸屬節點 `nodes`（`id`、`path`），有範圍外歸屬節點時另帶 `out_of_scope_node_count`（只給數量）；節點列回 `id`、`name`、`path`、
  `selectable`（假者只作定位祖先，不可授權）；標籤列回 `name` 與範圍內使用數 `count`，只含範圍內候選資產上出現過的標籤。
  `node_id` 取該節點子樹，`tags` 為多值 AND；範圍外的 `node_id` 與不存在同為空頁。

---

## 連線申請 API

三段存取政策（`open`/`reason`/`approval`，分組欄位→全域鍵）在連線 token 簽發點與 SFTP 檔案端點
設閘：非 open 段位僅時窗內臨時授權（`source='ticket'`）放行，常設 connect 被政策蓋過；admin 豁免
（稽核帶 `policy_exemption='admin'` 標記），auditor 不豁免。簽發點政策攔截回 403＋機器可辨 body
（`code: reason_required|approval_required`、`max_duration_minutes`、在途單帶 `pending_request_id`），
前端據此分流（填理由框／導向申請）。

**狀態機**（全轉移 CAS，終態不可再轉移）: `pending` → `approved` / `rejected` / `cancelled`（申請人撤回）
/ `expired`（待審逾時，scheduler 每 5 分鐘掃描＋讀取惰性過濾雙保險）。

### 申請人端點（登入即可）

| 方法 | 路徑 | 說明 |
|---|---|---|
| POST | `/access-requests` | 提出申請，body `{asset_id, accounts?, reason, duration_minutes, date_start?}` 或 `{items:[{asset_id,accounts?}], executor_user_id?, reason, duration_minutes, date_start?}` → 201；reason 段自動核准；open 段僅人類自行執行拒建，agent 執行項自動核准 |
| POST | `/access-requests/break-glass` | 破窗緊急連線，body `{asset_id, reason(≤1000 必填)}` → 201；時長固定政策鍵（client 傳入即忽略）；即時核准＋建 ticket 授權＋標記待補審 |
| GET | `/access-requests/mine` | 我的申請（全狀態；破窗單帶 `kind='break_glass'`、撤銷單帶 `revoked_at`/`revoke_note`）→ `{data, total}` |
| GET | `/access-requests/mine/tickets` | 我的有效限時連線（時窗內 ticket 授權，帶 `request_id` 回鏈）→ `{data, total}` |
| POST | `/access-requests/:id/cancel` | 撤回自己的 pending 單（他人單 403、非 pending 409） |

**錯誤**: 409 同資產已有在途單（帶在途單資訊；若在途單實已逾時，伺服端就地作廢後重試建單）、
400 時長超過 `access_request_max_duration_minutes`／open 段位；資產不存在、不可視或指定 executor 不可用時，均回404 `{"code":"NOTFOUND_ACCESS_REQUEST","error":"申請單不存在"}`，本文僅有這兩欄，相關標頭相同，不回候選狀態或項目細節。

**多項任務**：新形狀 `items` 限 1–20 個不同資產，不可同時帶外層 `asset_id`／`accounts`。
`reason` 必填、至多 1000 字；`duration_minutes` ≥1 且不超過政策上限。舊單資產形狀仍建立一項。
每項以執行者判定政策與帳號範圍；agent 執行項必須指定具體帳號，不接受省略、空集合或 `@ALL`。
`executor_user_id` 只在建立時可指定，必須為正整數且指向啟用中的 agent；省略或null時由申請人執行。
不存在、停用、非agent或不具全部項目可視交集的executor均回上述404 `NOTFOUND_ACCESS_REQUEST`，不再以400 `VALIDATION_EXECUTOR_NOT_AGENT` 區分。形狀錯誤仍400：明示0為 `VALIDATION_BAD_PARAMS`；負數、字串、非整數等綁定失敗為 `VALIDATION_ACCESS_REQUEST_FIELDS`；items的互斥、數量及重複限制維持原400。
建立時先驗純形狀，再確認全部項目的申請人可視與executor資格／雙方可視交集，全部成立才驗帳號、政策及建立單與項，避免項目排序改變拒絕結果；拒絕不建立部分單、項或票證。輔助模式在建單與每次連線判定現查交集，委派不要求申請人為agent owner。

回應保留所有既有欄位與省略規則，新增 `items[]`、可空省略的 `executor_user_id`／`closed_at`。
`asset_id`、`accounts`、`authorization_id` 為第一項鏡像；每項帶 `id,request_id,requester_id,asset_id,accounts,status`、
核定值 `approved_duration_minutes,approved_date_start`、決定者／時間、票證 `authorization_id`、撤銷附註與
JSON 物件 `policy_snapshot`（`segment,required_approvals`，自動核准另帶 `auto_basis`）。
快照於決定時保存，其後政策改動不回寫。每項帶 `approvals,approvals_received,approvals_required`；
列表同樣帶 items。`mine/tickets` 與 `tickets` 的每張項票證均帶所屬 `request_id`。
尚有 pending 項則整單 pending；一項拒絕／刪項／撤銷不使其他項失效。
全部已授權項到期或被撤銷且無 pending 項時，首次寫入 `closed_at`，並收線任務名下殘存會話。

**新增錯誤**：400 `VALIDATION_BAD_PARAMS`（新舊形狀混用／項數／重複資產等）、
`VALIDATION_ACCOUNT_NOT_ON_ASSET`（帳號未掛載於該資產）、`VALIDATION_AGENT_ACCOUNTS_REQUIRED`；409 重複 pending 項附 top-level `request_id,item_id`；
429 `RULE_AGENT_REQUEST_RATE`（agent 每小時建單／同時 pending 上限，預設 30／5）。
人類不受 agent 速率鍵限制。agent 嘗試審核或拒絕回 403 `AUTH_AGENT_FORBIDDEN_ROUTE`。

**破窗錯誤**: 403 `break_glass_disabled`（政策開關關閉，機器可辨 code）／
無破窗資格（需時窗內常設 connect，票證不算）／admin 與 auditor 不受理；409 同資產已有有效破窗票證
（帶單號＋到期時間）；400 事由缺漏／open 段位。破窗每次入稽核獨立標記（`break_glass:true`），
事件 `break_glass_used` 廣播全體範圍命中的有效審核者（範圍無人時單維持待補審並持續逾期告警，
**不由 admin 兜底**——見下節；不阻斷破窗本身）。

### 審核端點（**有效審核者**：approver 角色 OR 屬任一審核方群組；即時查 DB roles 不看 JWT）

> **`admin` 角色本身不構成審核資格**，僅具 admin 者對本節端點一律 403。
> 理由＝職責分離：管理員自行指派權限又自行核准特權存取不可接受。
> 因此審核者須顯式以 `PUT /api/v1/users/{id}/roles` 指派 `approver` 角色，或納入審核方群組
> ——指派即時生效、無 token 殘窗。
> **脫困路徑保證**：角色指派（`user:manage`）與 `/approver-scopes`（`approverscope:manage`）屬管理權限、**不經審核端點守衛**，
> 故即使系統中有效審核者為零，持有這些權限的超級管理者仍能重建可審池，系統不會死鎖。
> **撤銷端點例外**：`POST /:id/revoke` 屬遏制動作非審核，**未收斂**（進入條件為超級管理者、有效審核者，
> 或持有 `authorization:manage` 的有效指派者；細緻資格見下方「撤銷資格」）——一併收斂會造成 admin 無法撤銷已核出的票證＝安全倒退。
> **自核禁止擴及自有 agent**：操作者對其擁有的 agent 主體所提申請執行核准或拒絕（逐項、整單、批次皆同），
> 一律回 403 `RULE_ACCESS_REQUEST_SELF_APPROVAL`，擁有關係以決定當下現查為準；這些單也不出現在該操作者的
> 待審列表與待審計數（`/pending`、`/pending/count`），其他具資格者照常決定。

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/access-requests/pending` | 待審列表（僅審核範圍內＋排除本人單）→ `{data, total}`。每個 `items[]` 另投影唯讀的 `asset_name`（審核者對該資產未必有讀取權，名稱是決定所需資訊，故隨項目一起回；批次解析，不需逐項回頭查資產）與 `asset_deleted`（資產已軟刪時為 true，名稱照舊可讀）；資料列已被硬刪時 `asset_name` 為空字串。同樣適用於 `/reviews/pending`、`/history`、`/mine` 與 `GET /agent-tasks/:requestId` 的項目 |
| GET | `/access-requests/pending/count` | 待審＋待補審計數（同範圍語義，導航 badge 輪詢用）→ `{count, review_count}` |
| GET | `/access-requests/history` | 歷史（一律依審核範圍過濾；分頁）→ `{data, total, page, page_size}` |
| GET | `/access-requests/tickets` | 有效限時連線（審核視角，帶 `request_id` 回鏈供撤銷）→ `{data, total}` |
| GET | `/access-requests/reviews/pending` | 待補審破窗單（範圍過濾＋排除本人單）→ `{data, total}` |
| POST | `/access-requests/:id/approve` | 核准（quorum 逐票）；body 可空（照申請值），或 `{item_id?, accounts?, duration_minutes?(僅可下修), date_start?(僅可推遲), remove?, note?}`／`{items:[{item_id,accounts?,duration_minutes?,date_start?,remove?}],note?}`；三種形態皆可另帶 `batch_id`（UUID，批次核決的關聯碼，原樣記入稽核列，不改變核決語義）；核准數達 `access_request_min_approvals` 門檻的那一票才同交易建 ticket 授權並回填 `authorization_id`，未達門檻回 pending 單＋進度；同人重複核准 409 |
| POST | `/access-requests/:id/reject` | 拒絕，body `{item_id?,note,batch_id?}`，note 必填；省略 item_id 拒絕全部 pending 項，指定時只拒該項；任一具資格者即拒（既有核准記錄留存供稽核） |
| POST | `/access-requests/:id/revoke` | 提前撤銷限時連線，body `{item_id?,note}`，note 必填；省略 item_id 撤整單，指定時只撤該項；軟刪票證＋撤銷附註，其他項不受影響。agent 無條件收線，人類沿撤銷斷線政策。**守衛為 `RequireRevokeEligibility`（超級管理者、有效審核者，或持有 `authorization:manage` 的任一有效指派），與上列審核端點分離；此守衛只篩進入條件，完整資格在撤銷交易內逐項判定（見「撤銷資格」）** |
| POST | `/access-requests/:id/review` | 破窗事後補審，body `{disposition(confirmed\|violation), note?, batch_id?}`；破窗人自審 403、CAS 防重複 |

**裁決資格**（雙側聯集）: 資產側範圍命中（直配資產 OR 經節點含子樹）**OR**
申請人側範圍命中（申請人本人 OR 其所屬使用者群組）；**admin 身分不再兜底**，範圍未命中即
無人可裁，解法為 admin 補建審核範圍或指派 approver。**禁自核硬擋**（申請人＝操作者一律 403，
兼具 admin 身分者也不例外）。**錯誤**: 400 上調時長/提前起始/放寬帳號/空帳號集合、403 範圍外或自核、409 非 pending 或已逾時
（CAS 帶 `pending_expires_at > now` 守衛——逾期單核准落敗）、409 同人重複核准。

**最少核准人數**（政策鍵 `access_request_min_approvals`，預設 1、區間 1–10）: 每筆核准逐票記錄於
`access_request_approvals`（同項同人唯一；歷史無 item_id 列維持同單同人唯一）；兼具 admin 身分的有效審核者一票計入但不單票繞過門檻
（雙人完整性）。可審池不足門檻時 **SHALL NOT 由 admin 以 admin 身分補位**，須擴充可審池。申請單回應帶
`approvals`（逐票：誰/何時/note）與 `approvals_received`/`approvals_required` 進度欄；未達門檻的核准
回 200＋pending 單。政策值於每次核准時讀取。自動核准（reason 段）與破窗不受門檻約束。

**撤銷資格**: 一般核准單＝admin OR 原核准人；自動核准單與破窗單（無真人核准人）
＝admin OR 範圍命中 approver。**另加一條**：持有 `authorization:manage`、且本次撤銷會變更狀態的每一個任務項的資產
都在其管理範圍內者也具撤銷資格（全域持有者範圍涵蓋全部資產；agent 主體不因此取得資格）。整單撤銷的判定集合含仍有有效票證的已核准項，
以及整單撤銷一併結束的待審項；已到期或已撤銷而被略過的項不計。判定集合任一項在範圍外時這一條不成立，改由既有資格逐項判定。
未通過進入條件者回單一 403 `AUTH_PERMISSION_DENIED`；通過進入條件但逐項不符者回 403 `RULE_ACCESS_TICKET_NOT_REVOKE_ELIGIBLE`。
**撤銷審計**: 撤銷審計與撤銷在同一交易內寫入（action 不變），寫入失敗則整筆撤銷回滾；提交並收線會話後另寫一列同 action 的
補記（`details.event=sessions_terminated`，帶 `terminated_session_ids`），補記寫入失敗只記 log、不回滾撤銷。
所有撤銷（含超級管理者）都走此路徑，每次撤銷因此多一列補記；另有每個已認證 API 請求都會寫的請求紀錄，所以經 HTTP 的一次撤銷在審計表共有三列同 action 的紀錄（請求紀錄、交易內撤銷紀錄、補記）。**撤銷錯誤**: 403 非資格、409 無有效票證可撤（已到期或已撤，語義分離）、
400 事由缺漏。agent 執行項撤銷無條件收線，人類則在 `access_revoke_disconnect=true` 時收線該 user×asset 的 active 會話
（`end_reason='revoked'`，收線失敗不回滾撤銷）。**補審錯誤**: 403 破窗人自審／範圍外、
409 已補審、400 處置值非法／非破窗單。逾期未補審（`break_glass_review_timeout_hours`）發
`break_glass_review_overdue` 升級告警。**逾期後週期重發**——以該單最近一次告警時刻節流，
仍待補審就每 24 小時再升級一次，直到有人補審為止（補審後即離開待補審視圖，不再命中）。

### 審核範圍 API（需 `approverscope:manage`）

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/approver-scopes` | 範圍列表 → `{data, total}`；非超級管理者另帶 `coverage`、`min_approvals`、`applicant_manageable`，只能管理部分節點者再帶 `management_scope`（見下） |
| POST | `/approver-scopes` | 建立，body 審核方恰一 `{approver_id XOR approver_group_id}` × 客體恰一 `{asset_id XOR asset_group_id XOR subject_user_id XOR subject_group_id}` → 201；個人審核方須具 approver 角色、群組審核方零代配（群組即資格）；重複組合 409；申請人型範圍（`subject_user_id`／`subject_group_id`）的審核方集合（個人本人或審核方群組的現有成員）與申請人集合（申請人本人或申請人群組的現有成員）相交即 400 `RULE_APPROVER_SCOPE_SUBJECT_OVERLAP`、不建立（資產型與節點型不檢查；只在建立當下判定，事後成員異動不追溯） |
| DELETE | `/approver-scopes/:id` | 移除（範圍內申請即刻不可見/不可裁） |
| GET | `/approver-scopes/approver-options` | 審核方候選目錄（見下） |
| GET | `/approver-scopes/target-options` | 客體候選：資產或節點（見下） |

**管理範圍。** `approverscope:manage` 可以全域指派，也可以指派到節點。指派到節點的持有者只能管理客體落在那些節點子樹內的資產型與節點型範圍。申請人型範圍（`subject_user_id`／`subject_group_id`）另需 `approverscope:manage_applicant`，而且兩個權限點都要是全域指派；`approverscope:manage_applicant` 只接受全域指派，指派到節點不生效。

- 建立：對於指派到節點的持有者，資產型或節點型的客體在管理範圍外時，回應與客體不存在相同（資產 404 `NOTFOUND_ASSET`、節點 404 `NOTFOUND_ASSET_NODE`），不建立。建立申請人型範圍而沒有同時全域持有兩個權限點時回 403 `AUTH_PERMISSION_DENIED`，本文只有 `code` 與 `error`。
- 移除：範圍外的列、不存在的 ID，以及沒有同時全域持有兩個權限點者對申請人型列的移除，一律回 404 `NOTFOUND_APPROVER_SCOPE`。
- 超級管理者的列表、建立與移除不受上述限制，回應形狀不變。

**非超級管理者的列表與建立回應。** 每列只帶標量欄位 `id`、`approver_id`、`approver_group_id`、`asset_id`、`asset_group_id`、`subject_user_id`、`subject_group_id`、`granted_by`、`created_at`，以及巢狀物件 `approver`、`approver_group`、`asset`、`asset_group`、`subject_user`、`subject_group`。巢狀物件只有 `id` 與顯示名稱（使用者為 `username`，其餘為 `name`），取不到名稱時只有 `id`；不帶 email、角色與資產位址。排序為 `created_at` 由新到舊，`total` 是過濾後的筆數。頂層另帶：

| 欄位 | 說明 |
|---|---|
| `coverage` | 每個可管理節點的可審人數 `[{node_id, approver_count}]`：該節點與其祖先上、檢視者看得到的節點型範圍的審核方去重計數（個人計本人，群組計目前成員）；管理範圍外祖先上的範圍不計入 |
| `min_approvals` | 最少核准人數：政策值大於 1 時為政策值，否則為 1 |
| `applicant_manageable` | 申請人型管理旗標，同時全域持有兩個權限點時為真；為假時列表不含申請人型列 |
| `management_scope` | 只能管理部分節點者固定為 `"nodes"`；全域持有者不帶此鍵 |

非超級管理者建立成功時，201 本文與列表的單列相同。超級管理者的列表與建立回應維持完整模型，不帶以上四個鍵。

**選擇端點。** 兩條都要求 `approverscope:manage`，不持有者回 403。總覽頁與新增對話框只靠列表與這兩條取得候選，不需要使用者、群組或資產的讀取權限。

```
GET /api/v1/approver-scopes/approver-options
→ {users: [{id, username, display_name, active, is_approver, selectable}], groups: [{id, name}]}
```

列出 agent 以外、未刪除的使用者與全部使用者群組，不依管理範圍過濾，不帶 email。`display_name` 為使用者自訂的顯示名稱，未設定時與 `username` 相同。`selectable` 對超級管理者與稽核員為假，依內建身分判定，不看角色顯示名稱；停用的使用者照常列出，以 `active` 表示狀態。

```
GET /api/v1/approver-scopes/target-options?kind=asset|node&search=&node_id=&page=&page_size=
→ {kind, data, total, page, page_size}
```

依 `approverscope:manage` 的管理範圍投影。`kind` 只接受 `asset` 與 `node`，其他值回 400 `VALIDATION_BAD_PARAMS`；`page_size` 預設 50、上限 1000。

- `kind=asset`：`data` 每筆為 `{id, name}`，依名稱排序。`search` 比對資產名稱，不分大小寫；`node_id` 只留該節點子樹內的資產。
- `kind=node`：`data` 每筆為 `{id, name, path, selectable}`，`path` 是以「 / 」串接的全路徑，依路徑排序；`search` 比對路徑，`node_id` 只留該節點與其子孫。`selectable` 為真者是可管理的節點。只能管理部分節點者在不帶 `search` 與 `node_id` 時，另會收到可管理節點的祖先，其 `selectable` 為假，只用來定位，不能當建立的客體。
- `node_id` 在管理範圍外與不存在時回應相同：`data` 為空、`total` 為 0。

approver 為可疊加角色（不進 JWT 三階 primaryRole 判定）。**審核資格＝具 approver 角色 OR 屬任一審核方
群組**（群組即資格：入組即可審、離組即失效；守衛 `RequireApproverRole` 與 `/auth/me` 的
`is_approver` 欄**共用同一述詞**、即時判定，兩者對 admin 結論一致，皆不放行）。**資產側**範圍（asset/asset_group）隱含範圍內資產 `view`（可視第三來源，
可見不可連；個人與群組成員同語義）；**申請人側**範圍（subject_user/subject_group）僅影響待審路由，
不隱含任何資產可視。前端管理入口：`/approver-scopes` 雙視角總覽頁（預設按資產/節點含可審人數與涵蓋
缺口警示；按審核人員矩陣，身分與權限組，需 `approverscope:manage`）＋使用者管理列內對話框（共用同一表單組件；
一站式新增——個人未具角色明示代配、群組零代配）。申請/核准/拒絕/撤回/逾時全動作入稽核（`resource=access_request`）；事件廣播至
告警通道（payload 最小化：單號/資產名/事件/連結，無事由全文；通道未配置不阻斷）。

---

## 稽核日誌 API

> 僅在 `FEATURE_AUDIT_LOG_ENABLED=true` 時註冊（程式碼預設 true，見 `config/config.go:173`）。
> 權限 `audit:view`。

### 列表

```
GET /api/v1/audit-logs
```

**Query 參數**:
| 參數 | 類型 | 說明 |
|------|------|------|
| `user_id` | uint | 操作者 ID |
| `action` | string | create/read/update/delete/execute/login/logout/unlock/file_list/file_upload/file_download/file_mkdir/file_delete/recording_failed/approve/reject/cancel/expire/revoke/review |
| `resource` | string | asset/session/recording/user/user_group/auth/file/security_policy/command_alert/audit_export/access_review/retention/daily_review/syslog_setting/audit_log/command/key_management/transmission/access_request/approver_scope/change_secret_plan/authorization/audit_timeline/clipboard_event/audit_checkpoint/audit_failure/audit_integrity/alert_rule/notify_channel/oidc_provider/ldap_directory/asset_group/snippet/role/unclassified（共 35，權威來源為 `backend/internal/model/audit_log.go` 的 `Resource*` 常數；前後端值域由雙向守衛釘住） |
| `status` | string | success/failure/denied |
| `client_ip` | string | 客戶端 IP |
| `key` | string | 只看某一個安全政策設定鍵的變更列（例：`password_min_length`）；與 `resource` 併用為 AND |
| `request_id` | string | 精確比對請求識別碼（至多 100 字元），取回同一次請求寫下的全部列；與其他條件併用為 AND |
| `start_time`, `end_time` | RFC3339 | 時間範圍（含頭尾） |
| `end_before` | RFC3339／RFC3339Nano | 排他的尾端（`created_at < end_before`），用於以所屬日的 `window_start`／`window_end` 查一整天；與 `end_time` 並存時兩條件都套用 |
| `page`, `page_size` | int | 分頁 |
| `sort_by` | string | 排序欄位（預設 created_at） |
| `sort_order` | string | asc/desc（預設 desc） |

**回應** (200): `{"data": [AuditLog], "total": N, "page": 1, "page_size": 20}`

**AuditLog 欄位**: `id, action, resource, resource_id, status, user_id, username, method, path,
client_ip, status_code, duration_ms, request_body, error_msg, details, request_id, created_at`，
另加 `reason_code`、`reason_params`（列表與單筆詳情皆有；語意與省略規則同每日審閱單日明細的 Event，
見〈每日審閱簽核〉）。這兩欄是回應時計算的分類，不是審計列本身的欄位，不進完整性驗證碼，證據包的
`audit_logs.json` 也不含；資源歷史（`/audit-logs/resource/...`）的 `logs` 不帶這兩欄。

角色指派類列的原因碼：`user_role_assign`（全系統指派）、`user_role_assign_nodes`（限節點指派，另帶 `nodes`、`nodes_count`）、`user_role_revoke`、`user_group_role_assign`、`user_group_role_revoke`，參數為 `role`、`target`、`origin`（群組兩碼不帶 `origin`）；只改範圍的事件列（`event.role_binding_range_changed`）帶 `target_kind`、`before`、`after` 與對應的 `_count`；授權分級列（`event.grant_change_graded`）只陳述已建立的告警，參數為 `marks`。參數中的角色、對象與節點在讀取時才換成現名（`#<id>` 為尚存物件的佔位，換算後為名稱或節點路徑）；對象已刪除時回退顯示編號，不報錯，不改寫已存的審計列。操作者在這些列上為實際操作者，不再是空白。

### 詳情 / 資源歷史

```
GET /api/v1/audit-logs/:id                        → AuditLog（不存在回 404）
GET /api/v1/audit-logs/resource/:resource/:id     → {"resource": "asset", "resource_id": 1, "total": N, "logs": [...]}
```

`:resource` 僅接受 `asset`/`session`/`user`（其餘 400）。
`recording` **不是合法樞紐型別**：該分類的
`resource_id` 已改為**連線 id**，留在白名單會讓 `/audit-logs/resource/recording/7` 讀起來像
「第 7 號錄影」而實際是「第 7 場連線」。錄影調閱事件改由連線樞紐帶出（見下）。

連線樞紐（`:resource=session`）的回應**涵蓋該連線的取證讀取列**：取走剪貼簿明文
（`resource=clipboard_event`）、調閱錄影本體（`resource=recording`）與查詢指令原文
（`resource=command`）皆已獨立分類，三者的 `resource_id` 均為連線 id，樞紐查詢對同 id 空間的
子資源展開後合併，並依 `created_at` 重排為單一時間軸；`resource` 欄仍回樞紐型別本身。
跨會話端點（`/commands`、`/recordings/stats`）的列 `resource_id` 為空，不匹配任何樞紐
識別字，故不會被展開撈入。

`unclassified` 是分類器的**兜底哨兵**（同一 change 起），不對應任何實體：帶身分卻未被分類器
辨識的路由會寫出該分類的列。它使漏分類可以 `resource=unclassified` 單查詢計數，且不再污染
`asset_id`——訂正前兜底落 `asset`，帶路徑識別字的未分類端點會把別的實體 id 寫進 `asset_id`。

---

## 調查工作台 API

> 權限 `audit:view`（**無條件強制**，不隨任何部署組態進退）。兩支端點皆**唯讀**：
> 工作台不提供任何狀態變更端點——稽核工具一旦能改東西，它產出的證據就要先自證沒被自己改過。
> 兩支的讀取本身入稽核（`resource=audit_timeline`、`action=read`）。

### 時間軸

```
GET /api/v1/audit/timeline
```

把六類稽核資料（`alert`／`audit_log`／`clipboard`／`command`／`file_transfer`／`session`）
聚合到一條時間軸上，依所選**樞紐**取出與該主體相關的列。

**Query 參數**:
| 參數 | 類型 | 說明 |
|------|------|------|
| `subject` | string | 樞紐種類：`user`／`asset`／`ip`（必填；未知值 400） |
| `subject_id` | uint | 人／資產樞紐的主體 id。**`subject=ip` 時本參數被忽略**（不構成錯誤） |
| `subject_ip` | string | **位址樞紐的主體鍵**（`subject=ip` 時必填）。不是合法位址時回 400 `VALIDATION_SOURCE_ADDRESS`；保留字 `unknown` **不被接受**（樞紐需要一個具體位址） |
| `client_ip` | string | 人／資產樞紐下的來源位址篩選。保留字 **`unknown`**＝只看未知來源列（位址欄為空，或所屬會話缺失）；其餘須為合法位址，否則 400 `VALIDATION_SOURCE_ADDRESS`。**位址樞紐下再帶本參數為 400**（樞紐已經是位址，再篩一次沒有語義） |
| `from`, `to` | RFC3339 | 時間範圍 |
| `types` | string | 逗號分隔的類別子集；空＝全部。**未知值回 400**，不靜默忽略——靜默忽略會回一份看起來完整、實際少了一整類的時間軸 |
| `cursor` | string | 分頁游標（由前一頁的 `next_cursor` 取得） |
| `limit` | int | 每頁筆數（預設 200、上限 500） |

**回應** (200): `{"events": [...], "spans": [...], "coverage": [...], "counts": {...}, "next_cursor": "...", "truncated": false}`

**事件欄（`events[]`）**：`id`、`ts`、`type`、`summary_code`、`params`、`counterpart`、`refs`、`severity`，
另有來源位址三欄：

- **`client_ip`**：`string | null`。**三樞紐皆帶，刻意不設 `omitempty`**——無位址時輸出**顯式 `null`**
  而不是缺欄。「每筆事件皆帶來源位址」是條文；省略欄位會讓呼叫端無法區分「未帶」與「未知」，
  筆數口徑也就無從定義。
- **`client_ip_reason`**：只在 `client_ip` 為 `null` 時出現，三值閉集合：
  `system`（系統發起的操作日誌列，無請求來源）／`unresolvable`（有請求脈絡但位址欄為空，
  寫入當下來源無法解析）／`session_missing`（指令或告警列經 `session_id` 找不到所屬會話列
  ——三表皆刻意無外鍵）。
- **`actor`**：`{kind:"user", id, name}`，**只在位址樞紐下出現**，未認證列為缺欄。
  位址軸上多帳號的事件會混在同一軸（NAT 共用出口），每列必須同時標「誰 · 哪台」——
  `counterpart` 在位址樞紐下裝資產，人由本欄承載。

**跨度欄（`spans[]`，僅會話類有跨度）** 同樣帶 `client_ip`（`string | null`、不設 `omitempty`）
與 `client_ip_reason`，語義同上。

### 樞紐候選

```
GET /api/v1/audit/subjects?type=<user|asset|ip>&q=<prefix>&limit=<n>
```

供工作台的樞紐選擇器做前綴查詢。**`type=ip` 的回應與 `user`／`asset` 是不同形狀**：

```jsonc
// type=user / type=asset
{"data": [{"id": 7, "name": "alice", "display_name": "Alice", "active": true, "deleted": false}], "total": 1}

// type=ip —— 位址沒有整數 id，也沒有啟停與軟刪語義
{"data": [{"ip": "198.51.100.7", "last_seen_at": "2026-08-26T10:00:00+08:00"}], "total": 1}
```

`type=ip` 的候選自帳號來源位址基準表導出，**只含成功登入或建線過的位址**，依最近見到時間降序。
只出現在拒絕列的位址不會進候選——但時間軸接受任一合法位址，呼叫端直接輸入即可查詢。

**讀取留痕**：本端點與時間軸同樣入稽核（`resource=audit_timeline`、`action=read`）。

---

## 稽核證據匯出 API（PCI 10.5.1）

> 權限 `audit:view`（**無條件強制**，不隨任何部署組態進退）。匯出動作本身入稽核
>（`resource=audit_export`、`action=read`，記匯出者、範圍與各部分筆數/截斷標記）。
>
> **兩種包，包型由 `pack` 決定**：
> - **事件報告**（`pack=event_report`）：六來源的**事件事實**，**不含**剪貼簿內容、傳輸檔案本體與錄影檔。
>   報告的職能是陳述發生了什麼；證物本體屬取證動作，於介面上逐筆個別取得並各自留痕。
>   走**同步**匯出（本端點 `GET /audit-export`），既有呼叫端行為不變。
> - **證據包**（`pack=evidence_bundle`）：含操作稽核、指令、**剪貼簿內容全文**、關聯會話錄影**本體**，
>   以及告警／檔案傳輸的事件事實。體積不可控，改為**非同步**交付——**不由本端點回傳**，改經下方
>   `POST /audit-export/jobs` 發起、由申請者本人限時下載。
>
> **`pack` 缺席時沿既有推斷**（帶 `subject` 或 `types`＝事件報告，否則證據包）：不帶 `pack` 的既有
> 呼叫端行為逐位不變。證據包自此也吃樞紐（`subject`）後，`subject` 不再單獨分辨得出包型，故以 `pack` 明示為正解。

```
GET /api/v1/audit-export
```

**同步匯出，僅事件報告。** 證據包模式一律以 **400 `RULE_AUDIT_EXPORT_BUNDLE_ASYNC_ONLY`** 拒絕
（**不轉為 job 發起**——安全方法 GET 不得產生建立副作用，否則快取／預取／重試會誤觸發起；
拒絕在設定任何串流標頭之前，回應零 bundle 位元組）。

**權限**: `audit:view`
**Produce**: `application/zip`（`Content-Disposition: attachment; filename="audit-evidence-<時間戳>.zip"`）

**Query 參數**（至少須指定一個範圍條件，全無條件回 400，避免匯出整庫；
任一參數解析失敗回 400 `VALIDATION_INVALID_QUERY_PARAM` 並帶 `field`，**不靜默忽略**）:
| 參數 | 類型 | 說明 |
|------|------|------|
| `pack` | `event_report`｜`evidence_bundle` | 包型明示（缺席沿舊推斷；未知值→400 `field=pack`）。本同步端點僅受理 `event_report` |
| `session_id` | uint | 指定單一會話；**事件報告模式不接受**（證據包模式接受） |
| `user_id` | uint | 使用者 ID；`subject=user` 時即樞紐 id（必填） |
| `asset_id` | uint | 資產 ID；`subject=asset` 時即樞紐 id（必填） |
| `start_time` | RFC3339 | 起始時間；事件報告模式必填 |
| `end_time` | RFC3339 | 結束時間；事件報告模式必填，且須晚於 `start_time` |
| `subject` | `user`｜`asset` | 樞紐宣告。事件報告模式**必填**；證據包模式**選填**（帶了即比照校驗其 id） |
| `types` | csv | 類別篩選，值域同時間軸：`session`／`command`／`audit_log`／`file_transfer`／`clipboard`／`alert`。空＝六類全收；未知值回 400。**事件報告**模式缺 `subject` 而單獨帶 `types` 回 400；**證據包**模式選 `alert`／`file_transfer` 時須同時帶樞紐與正向時間窗（否則 400 `field=subject`／`range`） |

**ZIP 內容（事件報告模式，本端點同步產出）**: 逐類別各一個 CSV，第一欄一律為紀錄編號
`record_ref`（格式 `<類別>:<編號>`，與時間軸事件 id 同源，可回系統查對原始紀錄）。
- `sessions.csv` — 含 `recording_state`（`available`／`purged`／`none`）與 `recording_error`；**不含錄影本體**。此欄依持久化欄位與保留期清理水位推算（`purged`＝已過清理水位），不檢查檔案；與 `GET /sessions/:id` 詳情的 `recording_state`（`available`／`missing`／`unreadable`，唯讀探測檔案當下讀不讀得到）同名不同義
- `commands.csv` — 含 `command_seq`、`command`
- `audit_logs.csv`／`file_transfers.csv` — 同表互斥切分（後者為 `resource=file`）
- `clipboard_events.csv` — 含 `direction` 與 `content_length`；**不含內容**
- `alerts.csv` — 含規則、風險等級、是否阻斷、審閱處置
- `manifest.json`（＋ `manifest.sig`）

**ZIP 內容（證據包模式，經 job 產出）**：**未被選取的類別段整段不入包**（其 `counts`／`truncated`
鍵一併缺席——寫個 0 會讓「沒選」與「選了但範圍內沒有」看起來是同一回事）。`types` 缺席＝六類全收。
- `audit_logs.json` — 操作日誌（`asset_id` 篩選已套用，manifest 標明該關聯的歷史起始邊界）〔類別 `audit_log`〕
- `commands.csv` — 指令流，**十七欄**〔類別 `command`〕：前六欄
  `session_id`／`user_id`／`asset_id`／`seq`／`command`／`executed_at`，
  其後十一欄為查詢主控台的結果事實
  `event_id`／`target_database`／`result_status`／`result_reason`／`result_rows`／
  `rows_affected`／`result_sets`／`error_code`／`duration_ms`／`result_truncated`／`tx_state_after`。
  文字終端列的後十一欄為空（`result_status` 空即代表這不是主控台列）。
  稽核據 `result_status`＋`result_reason` 判讀「這句到底生效了沒有」：
  `partial` 與 `effect_unknown` 都不得讀成成功或未發生
- `clipboard_contents.json` — 剪貼簿**解密全文**，逐筆含 `record_ref`／`id`／`session_id`／`occurred_at`／`direction`／`content_status`／`content_length`／`content`（缺口列 `content_status=failed`、`content` 鍵缺席）〔類別 `clipboard`〕
- `recordings/session-<id>.<ext>` — 有錄影的會話本體（`.cast`/`.guac`；讀不到的逐筆略過、不阻斷整包，並列入 manifest `skipped_recordings`）〔類別 `session`〕
- `alerts.csv`／`file_transfers.csv` — 無本體之類別以**事件事實**列入（重用事件報告的寫入器）〔類別 `alert`／`file_transfer`〕
- `daily_reviews.csv` — 每日簽核紀錄，**不隨類別篩選、不隨樞紐改變**（每日審閱涵蓋全部安全事件），事件報告不收。
  時間窗內、起訖與時間窗有交集且已結束的所屬日，凡在啟用範圍內或有簽核紀錄者各一列——**未簽與尚未到期的日子也是一列**。
  欄位：`review_date`、`timezone`、`timezone_inferred`、`enabled_basis`（`recorded`，或 `presumed_purged`／
  `presumed_gap`／`presumed_tail` 表示啟用狀態由升級遷移推定及其成因；已簽列取簽核時固化的值）、`window_start`、
  `window_end`、`due_at`、`status`（`on_time`／`late`／`unsigned`／`not_due`）、`counts_toward_stats`（已到期才為
  `true`；昨日即使已簽也為 `false`）、`signed_at`、`signer`、`late_days`、`delay_reason`、`note`、`coverage`、
  `audit_log_source`／`command_alert_source`（`complete`／`partial`／`purged`）、`login_failures`、`alerts_total`、
  `alerts_benign`、`alerts_escalated`、`high_risk_ops`、`alerts_after_sign`、`review_ref`（`daily_review:<id>`）、
  `high_risk_criteria`（`high_risk_ops` 所依據的高危判準版本：已簽列取簽核快照，1.17.2 之前的簽核為 `1`；未簽列為現行版本 `2`；
  高危數因來源清除而留空時仍填版本）。欄序即契約，新欄只在尾端追加，既有欄位位置不變。
  已簽列的計數取簽核時固化的值，未簽列為匯出當下的即時計數；**來源已清除的計數留空，不是 0**。
  `coverage=until_signed`（升級前的簽核）列另有兩處留空，與資料是否清除無關：`alerts_total`／`alerts_benign`／
  `alerts_escalated` 留空，因為升級前的簽核只記下未審閱告警數，沒有記錄告警總數與處置分布；`alerts_after_sign` 留空，
  因為升級前的簽核不檢查告警處置，無法區分此刻未審閱的告警出現在簽核之前或之後。這類列的 `command_alert_source`
  仍可能是 `complete`，代表告警來源沒有被清除。
  與合規報告的同名檔為同一支寫法：UTF-8 BOM、CRLF、公式注入轉義（本檔是包內 CSV 形態的例外）
- `manifest.json`（＋ `manifest.sig`）

**CSV 儲存格轉義（兩種模式的每一個 CSV）**：首字元為 `=`、`+`、`-`、`@`、Tab、CR 之一的儲存格前置單引號，以防試算表公式注入；純數值字面（可帶負號、小數、指數）豁免。這是檔案內容與原始事實之間的一處改寫，manifest `disclosures[]` 以 `export.limit.csv_formula_escape` 揭露；需要逐字原文時以 `record_ref` 回系統查對原始紀錄。JSON 檔不套用。形態維持 UTF-8 無 BOM、LF（`daily_reviews.csv` 例外，見上）。

**manifest.json 欄位**:
| 欄位 | 說明 |
|---|---|
| `mode` | `evidence_bundle`｜`event_report`（置於最前，讀者須先知道拿到的是哪一種包） |
| `exported_by`／`exported_by_id`／`exported_at` | 保管鏈（`exported_at`＝實際打包執行時刻） |
| `job_requested_at` | 證據包專屬：job 發起時刻。與 `exported_at` 併為**雙時戳**，使收包方能判斷內容對應的資料時點 |
| `filter` | 原始查詢條件字串化 |
| `job_id` | 非同步工作單編號（證據包與報告皆有；報告 PDF 頁尾的報告識別即 `job-<id>`） |
| `filter.csv_as_of_prefix` | 報告專屬：兩個 CSV 首行註解列的前綴（`# as_of=`），其後為截止時點 RFC3339 帶時區位移 |
| `scope` | 事件報告專屬：樞紐、樞紐 id 與名稱、時間區間、類別 |
| `selected_types` | 證據包專屬：本包實際收錄的類別清單（缺席＝展開為全部六類） |
| `files[]` | 各檔 `name`／`size`／`sha256` |
| `counts` | 本包**收錄**筆數（逐類別；未選類別鍵缺席） |
| `totals` | 範圍內**真實**筆數（逐類別，不受上限影響）。與 `counts` 不等即代表截斷 |
| `truncated` | 逐類別截斷旗標 |
| `clipboard` | 證據包剪貼簿段三數：`events`（事件總數）／`content_available`（內容可用）／`content_failed`（留存失敗） |
| `daily_reviews` | 證據包每日簽核段：`rows`（收錄）／`in_range`（範圍內真實列數）／`truncated`、`not_filtered_by_type`＝`true`（不隨類別篩選）、`pivot_independent`＝`true`（樞紐不改變收錄）、保留覆蓋兩層——`signoff_retention`＝`not_retained`（簽核紀錄本身不受自動清除）與 `source_partial_rows`／`source_purged_rows`（任一事件來源為部分清除／已清除的列數）——以及 `presumed_rows`（啟用依據為推定的列數）。`counts`／`totals`／`truncated` 另有 `daily_reviews` 鍵 |
| `coverage[]` | 逐類別保留覆蓋三態（`present`／`purged`／`not_retained`）＋保留天數、清除截止與最近清除時刻、`archive_unit_range`（封存單位編號區間）、`note_code`＋`note_params` |
| `signed`／`signed_reason` | 是否已簽章；未簽時給機器碼原因（**不靜默省略**） |
| `disclosures[]` | 這個包能證明什麼、不能證明什麼（`code`＋選用 `params`；`export.proves.*` 全數排在 `export.limit.*` 之前）；兩種模式恆含 `export.limit.csv_formula_escape`（CSV 儲存格已轉義）。證據包含明文剪貼簿內容時，**明載本包含明文內容**（僅 `content_available>0` 時寫入——全缺口包不宣告，宣告即假警報） |
| `note_codes` | 各段的範圍說明機器碼（如資產關聯的歷史邊界） |
| `skipped_recordings` | 證據包選取會話類別時**恆出現**（無略過為空陣列）：範圍內有錄影紀錄、但錄影本體讀不到而未收錄的會話，逐筆 `session_id`＋`reason`（`missing`＝錄影檔不存在且無可取回的副本；`unreadable`＝存在但讀不到，含路徑不是一般檔與離機取回失敗）。不含檔案路徑或錯誤字樣；會話本來就沒有錄影者不列。未選會話類別或事件報告模式不出現。在 manifest 雜湊與簽章涵蓋範圍內 |

**manifest 內零散文**：`coverage[].note_code`、`disclosures[].code`、`note_codes`
一律只給機器碼與參數，不含任何自然語言句子（後端零散文出站，三語才可能齊備）。
對應文字由 i18n 依碼提供；**目前的已知缺口**：離線開包的讀者只會看到碼，
需要可讀說明時請在系統介面上檢視同一組碼的說明。

**上限**（超過即截斷並於 manifest 標明，不靜默截斷）:
證據包＝操作日誌 50000、指令 50000、錄影 100 檔、每日簽核 3660 列（十年）；事件報告＝**每一類別各自** 50000 列
（刻意不共用總上限，否則「哪一類被截斷」不可辨識）。

**完整性判準**: `manifest.json` 是最後寫入的檔案。**包內若無 `manifest.json`，
即代表匯出中途失敗、此包不完整，不得作為證據**——事件報告一旦開始串流 body 即無法改狀態碼，
故串流中途失敗只記伺服器日誌並留一筆失敗稽核（HTTP 狀態已為 200）；證據包則由 job worker
於背景寫檔，失敗落 job `failed` 態並清除半成品。

**離線驗簽**: 取公鑰 `GET /api/v1/audit-export/public-key`（base64 Ed25519），
以該公鑰對 ZIP 內 `manifest.json` 的**位元組**驗證 `manifest.sig`（base64 簽章）；
通過即證明清單與其中每個檔案的 SHA-256 自匯出後未被更動。
`tools/checkpoint-verify/` 是封存鏈的獨立驗證工具，**不涵蓋匯出包**（已知缺口，明載不粉飾）。

**錯誤**: 400 未指定任何篩選條件（`VALIDATION_AUDIT_EXPORT_FILTER_REQUIRED`）；
400 參數不合法（`VALIDATION_INVALID_QUERY_PARAM`，`params.field` 指出是哪一個）；
400 對同步端點請求證據包（`RULE_AUDIT_EXPORT_BUNDLE_ASYNC_ONLY`）。

### 證據包非同步 job 端點

> 證據包體積不可控，改為非同步：發起後進入打包排程，產物落於系統指定暫存位置
>（`EXPORT_ARTIFACT_PATH`，預設 `/var/lib/custodexa/exports`），由申請者本人限時下載。
> 三端點同屬 `/audit-export` 路由群、同掛 `audit:view`；下載另綁**申請者本人**。
> 產物保留 **24h**（逾期自動清除並轉 `expired`）；job 終態紀錄另有 30 天保存期，兩者分別計。

```
POST /api/v1/audit-export/jobs                發起打包（僅證據包）
GET  /api/v1/audit-export/jobs                申請者本人的 job 清單（分頁）
GET  /api/v1/audit-export/jobs/:id/download   下載產物（綁申請者本人）
```

**POST `/audit-export/jobs`**（發起）：篩選參數與同步端點同一套解析。僅受理證據包——
帶 `subject` 或 `types`（即被推斷為事件報告）者回 **400 `RULE_EXPORT_JOB_BUNDLE_ONLY`**。
- **回應** (202): `{"data": ExportJob, "deduplicated": <bool>}`。命中 `pending`／`running` 去重時回既有 job（`deduplicated=true`，冪等，非錯誤）。
- **額度**: 每申請者進行中（`pending`＋`running`）上限 3、全域 10；上限檢查與 job 建立為原子。超額回 **409 `CONFLICT_EXPORT_JOB_LIMIT`**。
- 發起（成功與被拒）皆入稽核，含完整篩選快照。

**GET `/audit-export/jobs`**（清單）：`page`（預設 1）／`page_size`（預設 20），id 降冪穩定排序。
**僅列申請者本人**的 job（與下載授權同判準）。回應 `{"data": [ExportJob], "total": N, "page": P, "page_size": S}`。
另接受 `kind`（`evidence_bundle`｜`rotation_report`｜`compliance_report`），**缺省 `evidence_bundle`**，故既有呼叫端行為不變；
閉集外的值回 400 `VALIDATION_INVALID_QUERY_PARAM`（`params.field=kind`）。`kind=rotation_report` 與
`kind=compliance_report` 不加申請者條件——兩種報告的例外成立條件見〈輪替證據報告 API〉的產物與下載段、
〈合規判定快照〉的產出報告段。報告列帶 `report`（參數的顯示投影）而非 `filter`：輪替報告為範圍與區間，
合規報告為 `group`、`group_name`、`language`、`retention_days`、`generated_by`。報告的下載同樣只需 `audit:view`，
檔名 `rotation-report-job-<id>.zip`／`compliance-report-job-<id>.zip`。

**GET `/audit-export/jobs/:id/download`**（下載）：認證＋`audit:view` 由路由群承擔，本端點另加**申請者本人**。
- 成功回產物 ZIP（`attachment; filename="audit-evidence-job-<id>.zip"`），下載入稽核（誰、何時、哪個包＋SHA-256）。
- **非申請者**（含其他具 `audit:view` 帳號）、job 不存在、識別非法：一律收斂 **403 `AUTH_EXPORT_JOB_REQUESTER_ONLY`**
  （分成 404/403 會讓具權限的探測者以狀態碼枚舉 job 存在性；真實原因只進稽核）。
- 申請者本人但**不可下載態**（`pending`／`running`／`failed`／`expired`、或產物已清）：**410 `RULE_EXPORT_ARTIFACT_UNAVAILABLE`**。

**離機退路**（本機產物不可讀時）：上述可下載性判定**先於**任何取回動作——逾期的 job 即使遠端副本仍在，
一樣回 410。通過判定後，本機產物檔缺席或大小與紀錄不符，而該 job 有離機帳冊列時，改由物件儲存取回，
**驗過 SHA-256 與大小才交付**；驗證不符或該世代不可用時回 **409 ＋離機機器碼**（四碼同錄影側，
見〈來源判定與離機退路〉），零位元組交付並留稽核。帳冊記載「從未上傳」而本機產物仍在者，
照常交付本機那一份（既有行為不變）。

**產品不代刪遠端**：產物到期（24h）只清本機產物檔並轉 `expired`，job 列的 30 天保存期到期只清 job 列
——**兩者都不對物件儲存發出刪除**。已離機的證據包副本何時消失，取決於部署方在儲存桶上設定的
生命週期規則；產品不偵測、不同步這兩個期限。

**ExportJob 回應投影**（顯式 DTO；`artifact_path`／`filter_json` 為伺服器內部，不出站）:
| 欄位 | 說明 |
|---|---|
| `id` | job 識別 |
| `kind` | `evidence_bundle`｜`rotation_report`；**恆輸出**。決定清單範圍與下載授權走哪一支判準 |
| `status` | `pending`／`running`／`done`／`failed`／`expired` |
| `requested_at` | 發起時刻 |
| `artifact_size` | 產物位元組大小 |
| `filter` | 篩選條件的顯示投影（`DisplayMap`；id 字串化，不含名稱）。**僅證據包種類** |
| `report` | 報告參數的顯示投影（範圍、區間、語言、排程名、發起者）。**僅報告種類**——兩種快照格式不同，故以種類分流而非共用一個鍵 |
| `artifact_sha256` | 產物 SHA-256（done 後出現） |
| `error_summary` | 失敗摘要機器碼（`export_job.pack_failed`／`export_job.requester_revoked`；`failed` 時出現） |
| `packaged_at` | 實際打包完成時刻（done 後出現） |
| `expires_at` | 產物過期時刻（done 後出現） |
| `offsite_status` | 產物副本的離機狀態；**恆輸出**（未進佇列時為空字串），值域同 Session 的同名欄 |
| `offsite_sha256` | 已離機副本的 SHA-256（僅 `uploaded` 態出現）。**與 `artifact_sha256` 不同源**：前者取自保管帳冊（上傳當下量得），後者是打包完成時記的產物雜湊 |

> 投影**刻意不輸出帳冊識別碼**：那對申請者無用——重試離機上傳是管理員在離機儲存頁的動作。

打包 worker 對申請者於**領件與每次重試時**重驗主體狀態與 `audit:view` 權限——已停用／刪除／失權者
job 取消（落 `failed`＋`error_summary=export_job.requester_revoked`）並清除已產出的產物；worker 異常
不終止服務行程，重試上限 3，服務重啟時遺留的進行中 job 可恢復或重排。

---

## 輪替證據報告 API

> 資產帳號的憑證輪替證據：以登記於系統內的資產帳號為母體，陳述每個帳號的適用天數、
> 最後成功改密事實、剩餘天數與狀態桶，供稽核核對。
> **畫面表格、CSV 與 PDF 出自同一次建構的資料集**，三者的數字必然一致。
> 讀取面權限 `audit:view`（內建超級管理者與稽核員範本具備），排程管理面需 `rotation_schedule:manage`。
> 這兩個權限點都只經全域指派生效：`audit:view` 的範圍過濾尚未提供，`rotation_schedule:manage` 只接受全域指派。
> 指派到節點的持有者呼叫本節任何端點都回 403 `AUTH_PERMISSION_DENIED`，不會取得依節點裁切的內容。
> 報告的範圍參數（`scope_kind`／`scope_id`）只決定報告母體，不是管理範圍：呼叫者的管理範圍不會縮小母體，報告範圍也不限制誰能讀取。
> 產出為非同步：發起後建立一張**種類為 `rotation_report`** 的匯出工作單，
> 產物於下載中心取得（端點與判定見〈稽核證據匯出 API〉的 job 端點）。

```
GET    /api/v1/rotation-report                     資料集（摘要＋帳號列）
GET    /api/v1/rotation-report/records             區間改密記錄明細（分頁）
POST   /api/v1/rotation-report/jobs                手動產出（建立工作單）
GET    /api/v1/rotation-report/schedules           排程列表（`rotation_schedule:manage`）
POST   /api/v1/rotation-report/schedules           建立排程（`rotation_schedule:manage`）
PUT    /api/v1/rotation-report/schedules/:id       修改排程（`rotation_schedule:manage`）
DELETE /api/v1/rotation-report/schedules/:id       刪除排程（`rotation_schedule:manage`）
POST   /api/v1/rotation-report/schedules/:id/run   立即產出（`rotation_schedule:manage`）
```

### 母體、範圍與已知邊界

母體是範圍內**登記於系統且未刪除**的資產帳號。系統不探勘目標主機上的帳號，
故報告陳述的是系統管理中的帳號；主機上另行存在而未登記者不在報告內。此口徑寫在每一種輸出上。

**範圍三選一**（`scope_kind`，缺省 `all`）：

| 值 | `scope_id` | 母體 |
|---|---|---|
| `all` | 須為 0 | 全系統 |
| `node` | 資產節點 id | 該節點與其全部子孫節點所掛載的資產（同一資產多處掛載只計一次） |
| `plan` | 改密計劃 id | 該計劃的資產集合與其帳號範圍的交集 |

未知的 `scope_kind`、`all` 帶非零 id、`node`／`plan` 帶 0，一律回 400：
查詢參數形式（兩支 GET）回 `VALIDATION_INVALID_QUERY_PARAM`（`params.field=scope_kind`），
請求體形式（產出與排程）回 `VALIDATION_ROTATION_REPORT_BAD_SCOPE`（範圍指向的節點或計劃不存在時同碼）。

另有兩處邊界，報告本身也明載：

- **共用憑證標記讀的是憑證範圍。** 該帳號掛的憑證範圍為共用時標記為真，掛專用憑證時為假；
  真相在憑證本體，標記只是它的投影。一台脫離共用之後即改綁到自己的專用憑證，標記隨之為假。
  **管理者在系統外自行把兩台主機設成同一組密碼，系統無從判定**——那組秘密沒有經過憑證庫，
  不會有任何一筆共用憑證指向它。標記本身只以布林呈現；**憑證名稱與該台的就位版本序號隨列出站**
  （`credential_name`／`effective_version_no`），供稽核對照當下用的是哪一組秘密。
  憑證識別與密文一律不出本端點。
- **`no_record` 不等於逾期。** 系統無該帳號成功改密記錄時狀態為 `no_record`，不計入逾期數、
  不列入 PDF 例外清單，明細仍在附表與帳號 CSV 內；它在兩種合規率上的處置由口徑決定（見下）。

### 狀態桶與合規率口徑

**狀態桶**（`bucket`）互斥，依序判定，第一個成立者即為該帳號的狀態：

| 桶 | 條件 |
|---|---|
| `unverified` | 存在未驗證候選憑證 |
| `no_policy` | 適用天數未設定（全域政策鍵為 0 且涵蓋計劃皆未覆蓋） |
| `no_record` | 系統無該帳號的成功改密記錄 |
| `overdue` | 剩餘天數 A 小於 0 |
| `due_soon` | 剩餘天數 A 介於 0 與 30（含兩端） |
| `compliant` | 其餘 |

到期預警窗為 30 日固定值（`meta.due_soon_window_days`）。
**適用天數**取涵蓋該帳號的已啟用計劃中天數覆蓋大於 0 者的最小值，無者取全域政策鍵；
`max_age_source` 記出處（`global`、`plan:<計劃名>`，未設定時為空字串）。
**剩餘天數 A** ＝適用天數減去截止時點距最後成功改密時刻的整日數；
**剩餘天數 B** ＝下次排程時刻距截止時點的整日數。兩者無從計算時為 `null`。
最後成功改密時刻一律以帳號識別碼比對，**不以帳號名比對**，故帳號改名後仍對得上舊記錄。

**兩種合規率並列**，各自的分母基數 X ＝總帳號數 −`no_policy` −`unverified`：

| 欄位 | 口徑 |
|---|---|
| `rate_excluding_no_record` | `compliant ÷ (X − no_record)`。排除無記錄者，回答「有記錄可看的帳號裡合規比例多少」 |
| `rate_counting_no_record` | `compliant ÷ X`。無記錄計為不合規，回答「以稽核最嚴的看法合規比例多少」 |

**分母為 0 時該欄為 `null`**，呼叫端須顯示「不適用」，不得顯示 0%——兩者的意思不同。
全域政策鍵為 0 時報告照常產出，帳號落在 `no_policy` 並於摘要載明全域未設定；
未設定本身就是稽核要看的發現，不因此擋下產出。

### 資料集

```
GET /api/v1/rotation-report
```

**權限**: `audit:view`

**Query 參數**: `scope_kind`／`scope_id`（見上）；`as_of`（RFC3339 截止時點，缺省為現在：
天數與狀態等派生值以此為基準；改密記錄以此為上界，晚於它的成功記錄不計入最後成功時刻與區間明細；
母體（帳號清冊）、改密計劃與政策值取產出當下的值，本端點不做全庫時光回溯）；`language`（`zh-TW`／`en-US`／`ja-JP`，缺省 `zh-TW`，影響狀態桶名與口徑文字）。

**回應** (200)：

```json
{"data": {
  "meta": {"scope_kind": "all", "scope_id": 0, "scope_label": "",
           "period_start": "2026-09-02T15:04:10Z", "period_end": "2026-09-02T15:04:14Z",
           "as_of": "2026-09-02T15:04:14Z", "generated_at": "2026-09-02T15:04:14Z",
           "global_max_age_days": 90, "due_soon_window_days": 30,
           "language": "zh-TW", "generated_by": ""},
  "summary": {"total_accounts": 80, "compliant": 3, "overdue": 5, "due_within_30": 3,
              "no_record": 68, "unverified": 1, "no_policy": 0,
              "shared_credential": 2, "multi_plan": 1,
              "rate_excluding_no_record": 0.273, "rate_counting_no_record": 0.038},
  "rows": [{"account_id": 1, "asset_id": 1, "asset_name": "…", "asset_address": "…",
            "protocol": "ssh", "username": "root", "credential_type": "password",
            "privileged": true, "shared_credential": false,
            "credential_name": "prod-01 / root", "effective_version_no": 3,
            "plans": ["週度改密-核心主機"], "multi_plan": false,
            "max_age_days": 60, "max_age_source": "plan:週度改密-核心主機",
            "last_success_at": "2026-08-21T02:00:00Z", "last_record_status": "success",
            "remaining_days_a": 12, "next_schedule_at": "2026-09-05T02:00:00Z",
            "remaining_days_b": 3, "candidate_state": "none", "bucket": "compliant"}],
  "records": null,
  "truncation": {"rows_cap": 20000, "rows_truncated": false,
                 "records_cap": 50000, "records_truncated": false}
}}
```

- `records` 於本端點**恆為 `null`**：記錄明細另有端點，資料集不夾帶。
- `max_age_days` 為 0 代表未設定；`plans` 為空陣列代表無計劃涵蓋。
- `credential_type`: `password`／`ssh_key`／`none`；`candidate_state`: `none`／`pending`／`abandoned`。
- `multi_plan` 為真時 `plans` 列出全部計劃，天數與排程取最嚴（天數最小、排程最近）。
- 帳號列上限 20,000；超過即截斷並以 `truncation` 標明，**不靜默截斷**。
- 回應**不含**改密計劃的密碼策略欄，亦不含任何密文或候選秘密。憑證面只出
  型別（`credential_type`）與 `shared_credential`／`credential_name`／`effective_version_no`。
- 本端點對整個母體一次算完。呼叫端的狀態桶篩選應在既有資料上進行，不必為每次篩選重打
  ——「同源」指的正是這件事。

### 記錄明細

```
GET /api/v1/rotation-report/records
```

**權限**: `audit:view`

**Query 參數**: 範圍與語言同上；`period_start`／`period_end`（RFC3339，**兩者必填**且起須早於迄
——沒有起訖的區間就是全庫掃描）；`page`（≥1，預設 1）、`page_size`（預設 20，上限 100）。

**回應** (200)：

```json
{"data": [{"record_id": 12, "executed_at": "2026-08-14T02:00:03Z", "plan_name": "…",
           "batch_id": 0, "asset_name": "…", "account_username": "root", "account_deleted": false,
           "credential_name": "共用維運帳號", "version_no": 4,
           "secret_type": "password", "status": "failed",
           "reason_code": "remote_exit_nonzero"}],
 "total": 16, "page": 1, "page_size": 20, "truncated": false}
```

明細含 `failed`／`skipped` 等非成功結果。`reason_code` **只有機器碼，不含目標主機回傳的原文**
（對外回應收斂的一貫作法；可讀說明由介面依碼提供）。帳號已刪除者以當時的帳號名快照列出並標示。
`credential_name` 與 `version_no` 是執行當下的快照，掛載事後改綁到別的憑證也不會被覆蓋
——稽核問的是「當時動的是哪一組秘密」。`plan_name` 為空且 `batch_id` 非 0 者來自批次改密。
記錄上限 50,000，達上限時 `truncated` 為真。

### 手動產出

```
POST /api/v1/rotation-report/jobs
```

**權限**: `audit:view`

```json
{"scope_kind": "all", "scope_id": 0,
 "period_start": "2026-07-01T00:00:00Z", "period_end": "2026-09-30T00:00:00Z",
 "language": "zh-TW"}
```

**回應** (202): `{"data": {"id": 18, "status": "pending"}}`。
產出是非同步的，回應不含任何檔案；完成後於下載中心的報告分頁下載。
申請者為發起人，產物保留期沿既有證據包保留期。發起入稽核。
範圍、語言或區間不合法時回 400（`VALIDATION_ROTATION_REPORT_BAD_SCOPE`／`_BAD_LANGUAGE`／`_BAD_PERIOD`）。
`language` 缺省 `zh-TW`；帶值時須落在 `zh-TW`／`en-US`／`ja-JP` 三語閉集，閉集外的值回 400
`VALIDATION_ROTATION_REPORT_BAD_LANGUAGE`，不收斂為預設值。

### 排程

```
GET    /api/v1/rotation-report/schedules
POST   /api/v1/rotation-report/schedules
PUT    /api/v1/rotation-report/schedules/:id
DELETE /api/v1/rotation-report/schedules/:id
POST   /api/v1/rotation-report/schedules/:id/run
```

**權限**: `rotation_schedule:manage`。建立、修改與刪除各入稽核。

請求與回應同一形狀：

```json
{"id": 1, "name": "月報", "cron": "0 1 1 * *", "enabled": true,
 "scope_kind": "all", "scope_id": 0, "retention_days": 400, "language": "zh-TW",
 "period_anchor": "2026-09-02T15:04:10Z",
 "created_at": "2026-09-02T15:04:10Z", "updated_at": "2026-09-02T15:04:10Z"}
```

| 欄位 | 值域 |
|---|---|
| `name` | 1–128 字（空名回 400 `VALIDATION_ROTATION_SCHEDULE_NAME_EMPTY`，超過 128 字回 400 `VALIDATION_ROTATION_SCHEDULE_NAME_TOO_LONG`），**全系統唯一**（重名回 409 `CONFLICT_ROTATION_SCHEDULE_NAME_EXISTS`）。它是報告封面上的人可讀識別 |
| `cron` | 標準五欄；不合法回 400 `VALIDATION_ROTATION_SCHEDULE_BAD_CRON` |
| `retention_days` | 1–3650；產物到期時刻＝**打包完成時刻**加此天數 |
| `language` | 三語閉集 |
| `period_anchor` | **唯讀**（送上來不採用）：下一份報告的記錄區間起點 |

**記錄區間 ＝ [`period_anchor`, 觸發時刻)**，且觸發成功建單後錨點推進為該次觸發時刻，
故連續兩期首尾相接、不重疊也不漏。錨點於排程建立時為建立時刻，於 cron 被修改時重設為修改時刻
（修改當期以修改時刻切）。`/run` 是**提前的一期**，同樣推進錨點；手動產出不影響任何排程的錨點。

同一排程至多一張進行中的工作單，已有進行中者回 **409 `CONFLICT_ROTATION_SCHEDULE_INFLIGHT`**。
`/run` 成功回 **202** `{"data": {"id": <工作單 id>, "status": "pending"}}`。
排程觸發產生的工作單，申請者記為系統。

### 下次執行時刻預覽（排程表單共用）

```
POST /api/v1/schedules/next-runs
```

**權限**: `schedule:manage`。**不讀寫任何資料**：只把一個排程字串解析成接下來的幾個時刻，
供任何編輯排程的表單即時顯示（本頁的報告排程與改密計劃共用同一支）。

```json
// request
{"cron": "0 0 1 1,4,7,10 *", "count": 3}
// 200
{"runs": ["2026-10-01T00:00:00Z", "2027-01-01T00:00:00Z", "2027-04-01T00:00:00Z"],
 "timezone": "UTC"}
```

**本端點的 200 回應不包 `data` 信封**，呼叫端讀的是頂層的 `runs` 與 `timezone`；
錯誤仍沿統一錯誤封套。

- `cron` 為標準五欄（分 時 日 月 週），**欄位集與排程器載入計劃時所用的完全相同**——
  預覽與實際觸發若各用一套解析，兩者會在邊界形態上分岔，而分岔的方向剛好是
  「畫面說會跑、實際不跑」。不合法回 400 `VALIDATION_SCHEDULE_BAD_CRON`。
- `count` 省略或為 0 即取 3，範圍 1–10，超出回 400 `VALIDATION_SCHEDULE_RUN_COUNT`。
  有上限是因為每一筆都要往前推算一次日曆。
- `timezone` 是後端排程器實際採用的時區名，時刻以該時區呈現，**呼叫端只顯示不換算**。
- 形狀合法但永遠不會發生的時刻（如 2 月 30 日）回**已算出的部分**（可能是空陣列），
  呼叫端據此顯示「沒有下次執行」，而不是一個假的時刻。

### 產物與下載

產物是單一 ZIP：`report.pdf`、`accounts.csv`、`records.csv`、`manifest.json`、`manifest.sig`。
**`manifest.json` 最後寫入**——包內若無清單檔即代表打包中途失敗、此包不完整，判準與證據包相同。
清單檔載明種類、範圍、記錄區間、截止時點、發起與打包雙時戳、發起者（使用者或排程名）、
逐檔 SHA-256、各段筆數與截斷標示、簽章狀態。SHA-256、簽章、離機上傳、到期清理與下載端點
全部沿用既有匯出工作單機制，離線驗簽的公鑰端點亦同。
CSV 為 UTF-8 帶 BOM、CRLF，首行為 `# as_of=<RFC3339 帶時區位移>` 註解列（載明截止時點，使單獨抽出的 CSV 仍可重算剩餘天數），第二行起為表頭與資料；欄名依報告語言，儲存格套用公式注入轉義。PDF 每頁頁尾的報告識別為 `job-<工作單編號>`，與 manifest 的 `job_id` 同源。
PDF 內嵌可正確呈現繁體中文與日文的字型，圖表以繪圖原語繪製。
帳號 CSV 是 PDF 附表 A 的欄位超集：附表省略位址、協定、天數來源與最近記錄狀態四欄以維持可讀。

**下載中心的種類參數**：

```
GET /api/v1/audit-export/jobs?kind=rotation_report&page=1&page_size=20
```

`kind` **缺省為 `evidence_bundle`**，故既有呼叫端行為逐位不變；閉集外的值回 400
`VALIDATION_INVALID_QUERY_PARAM`（`params.field=kind`）。
報告種類的工作單，其回應以 `report` 段取代證據包的 `filter` 段：

```json
{"id": 18, "kind": "rotation_report", "status": "done", "requester": "system",
 "requested_at": "…", "packaged_at": "…", "expires_at": "2027-10-07T15:04:14Z",
 "artifact_size": 75905, "artifact_sha256": "5e0e…", "offsite_status": "uploaded",
 "report": {"scope_kind": "all", "period_start": "…", "period_end": "…",
            "language": "zh-TW", "schedule_name": "月報", "generated_by": "月報"}}
```

`report.schedule_name` 缺席即為手動產出，此時 `generated_by` 與 `requester` 皆為發起者帳號名。
`expires_at` 在 `done` 之前是預定值，`done` 之後才是實際值（保留期自打包完成起算）。

**報告種類不綁申請者——這是對證據包「綁本人」規則的顯式例外。**
`rotation_report` 的工作單，任一具 `audit:view` 的帳號都可列出與下載；下載端點與證據包同一支。
成立條件是**報告不含錄影、剪貼簿內容或任何秘密材料**，其內容全是本已對稽核開放的事實投影，
且排程產出的工作單沒有自然人申請者可綁。此例外**只適用於這一個種類**：
證據包的申請者本人判準一字不動，並有雙向守衛（證據包不因種類欄新增而放寬、報告不因證據包規則而誤拒）。
每次下載照常入稽核（誰、哪份報告、SHA-256）。
排程產出的工作單申請者為系統，打包時**跳過申請者重驗**（無自然人主體可失效）；
由人發起的工作單不論種類皆照常重驗。

---

## 存取複審 API（PCI 7.2.4）

> 週期性存取複審 v1：矩陣檢視與複審歷史限 `audit:view`；提交簽核需 `accessreview:manage`（管理層確認語意）。
> 一筆簽核＝複審者＋時間＋範圍＋結論＋複審當下的存取矩陣 JSON 快照（append-only 不可變證據）。

### 存取矩陣

```
GET /api/v1/access-reviews/matrix
```

**權限**: `audit:view`

當下完整存取矩陣（所有授權展開，join 用戶/資產/群組名稱）。

**回應** (200): `{"data": [AccessMatrixEntry], "total": N}`
```json
{
  "authorization_id": 1,
  "user_id": 2,
  "username": "user1",
  "asset_id": 1,
  "asset_name": "Server1",
  "permission": "connect",
  "granted_by": 1,
  "granted_at": "2026-07-01T00:00:00Z"
}
```
主體 `user_*` 與 `user_group_*`（`user_group_id`/`user_group_name`）二擇一、
客體 `asset_*` 與 `asset_group_*`（`asset_group_id`/`group_name`）二擇一，
未使用側省略（omitempty）。

### 複審歷史

```
GET /api/v1/access-reviews
```

**權限**: `audit:view`

近 50 筆複審簽核（`reviewed_at` 倒序）＋距上次複審天數（供存取複審頁逾期提示）。

**回應** (200): `{"data": [AccessReviewView], "last_review_days_ago": N, "review_period_days": 180, "overdue": false}`
- `last_review_days_ago`: 整數天數；`-1` 表示從未複審
- `review_period_days`/`overdue`: 建議週期（v1 固定 180）與逾期判定，伺服端單源回傳，前端不硬編碼
  （週期政策鍵化登 backlog）
- `AccessReviewView` 為 AccessReview 欄位（不含大型 `matrix_snapshot`）＋ `days_ago`

### 單筆複審檢視

```
GET /api/v1/access-reviews/:id
```

**權限**: `audit:view`

單筆簽核完整內容：中繼資料＋`matrix`（快照 `json.Unmarshal` 後的 `[AccessMatrixEntry]` 型別化陣列）。
快照損壞回明確 500（不回空內容）；不存在 404。路由註冊 `/matrix` 先於 `/:id`。

> 複審四端點（matrix/list/:id/POST）權限一律**無條件**強制（讀取 `audit:view`、簽核 `accessreview:manage`），
> 無條件強制（比照 session 敏感讀取端點先例）。
> UI 入口為稽核區「存取複審」獨立頁（需 `audit:view`；自資產授權頁遷出）。

### 提交複審簽核

```
POST /api/v1/access-reviews
```

**權限**: `accessreview:manage`（管理層確認語意）

快照當下存取矩陣並記一筆簽核；動作入稽核（`resource=access_review`、`action=create`）。

**請求**（`note` 選填）:
```json
{"note": "本季存取權複審完成，無異常授權"}
```

**回應** (201): `AccessReview` JSON（不含 `matrix_snapshot`，避免回應肥大）
```json
{
  "id": 1,
  "reviewed_by": 1,
  "reviewer_name": "admin",
  "reviewed_at": "2026-07-03T00:00:00Z",
  "scope": "全部使用者存取權（user × asset/group × permission）",
  "note": "本季存取權複審完成，無異常授權",
  "authorization_count": 12,
  "created_at": "2026-07-03T00:00:00Z"
}
```

簽核為不可變證據：ORM 層 `BeforeUpdate`/`BeforeDelete` 拒絕修改與刪除（縱深防禦），無更新/刪除路由。

---

## 命令片段 API

> user-scoped：查詢一律帶 user_id 條件，他人資源視為不存在（404）。內容僅注入終端輸入，不直接執行。

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/snippets` | 當前用戶全部片段 → `{data, total}` |
| POST | `/snippets` | body: `{"name": "...", "content": "..."}` → 201 |
| PUT | `/snippets/:id` | 更新 |
| DELETE | `/snippets/:id` | 刪除 → `{}` |

`name` 上限 128、`content` 上限 4096 字元（超出 400）。

---

## 改密 API（需 `changesecret:manage`）

輪換納管資產的帳號憑證：**帳號級**密碼改密（POSIX SSH 與 Windows 本機帳號）與 SSH 金鑰輪替（POSIX SSH）。
執行記錄與任何回應皆不含秘密材料。改密走哪條路由資產的改密通道決定（資產 API 的 `rotation_channel`），見下「改密通道」。

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/change-secret-plans` | 計劃列表 → `{data, total}` |
| POST | `/change-secret-plans` | 建立 → 201 |
| PUT | `/change-secret-plans/:id` | 更新（CUD 後排程器即時重載） |
| DELETE | `/change-secret-plans/:id` | 刪除 |
| POST | `/change-secret-plans/:id/run` | 手動觸發（異步）→ 202 `{}` |
| POST | `/change-secret-plans/reauthorize` | 一鍵重新授權：目前所有標為待重新授權（升級後無從歸屬發起者，或還原後世代不符而暫停）或待重新確認（見下「計畫的範圍」）的計畫改由目前操作者承接 → 200 `{plan_ids, count, skipped_plan_ids}`；只查、只承接操作者可見的計畫，兩個 ID 清單只含可見計畫；承接前逐一在承接交易內、以操作者當下的能力對該計畫的目標重驗（帳號計畫需對其資產的帳號輪替、憑證計畫需對該憑證的憑證輪替；待重新確認的計畫另須憑證輪替有全系統來源），未通過者不承接、維持暫停並列在 `skipped_plan_ids`（不使整批失敗）；承接與其審計同一交易，審計寫不進去的計畫同樣不承接、列在 `skipped_plan_ids` 並告警；之後每次執行仍依該操作者當下的能力重驗 |
| GET | `/change-secret-plans/:id/records?limit=100` | 執行記錄 → `{data, total}` |
| GET | `/change-secret-candidates` | 未驗證憑證清單 → `{data, total}`（**不含任何秘密材料**） |
| POST | `/change-secret-candidates/:id/retry` | 立即重試一次 → `{promoted: bool}`；被主機身分守衛擋下時多帶 `host_identity`；可選帶 `confirm_host_identity` 明示承接（見下） |
| DELETE | `/change-secret-candidates/:id` | 清除候選（破壞性，見下）→ 200 `{}` |

**候選的讀取範圍**依檢視者的帳號改密能力（`account:rotate`）分四種情形：

1. 該能力有全系統來源（含超級管理者）：全部候選，與先前相同。
2. 沒有任何角色指派含帳號改密、但 `changesecret:manage` 有全系統來源：全部候選（相容既有行為）。指派含帳號改密、但其範圍節點已全部不存在者不屬此種，結果與第 4 種相同。
3. 帳號改密只經節點範圍持有（`changesecret:manage` 另有全系統來源者亦同）：只列所屬資產在其範圍內的候選；對範圍外候選重試或清除（`DELETE /change-secret-candidates/:id`），與不存在的候選同回 404 `NOTFOUND_CHANGE_SECRET_CANDIDATE`，範圍外候選不被清除。
4. 其餘：清單為空；對任何候選重試或清除都回 404 `NOTFOUND_CHANGE_SECRET_CANDIDATE`。

四種情形都先經入口權限檢查：沒有任何含 `changesecret:manage` 的有效指派者回 403 `AUTH_PERMISSION_DENIED`。

**候選重試與主機身分確認**：`POST /change-secret-candidates/:id/retry` 的 body 為選用，形狀、`confirm_host_identity` 六個欄位與
`host_identity` 欄位表同「帳號憑證庫 API」一節的「主機身分停止時的人工承接」。

- **不帶確認**（body 省略、`{}` 或 `{"confirm_host_identity": null}`）：同步重試一次，回 200 `{"promoted": bool}`。
  僅當這次被主機身分守衛擋下時，回應多一個 `host_identity`（`{"promoted": false, "host_identity": {…}}`）；其他情形不帶這個鍵。
- **帶確認**：核對所確認的身分與授權後承接，並立即以新秘密驗證一次。驗證通過回 200 `{"promoted": true}`；
  驗證未通過回 200 `{"promoted": false}`，候選保留、可再次確認，原因在候選的最近錯誤，這是重試的正常結果之一，不是 4xx。
- **授權目標已改變**：回 200 `{"promoted": false, "reason": "CHANGE_SECRET_AUTHZ_TARGET_CHANGED"}`，不承接、不改動候選與工作列；
  不使用 `CONFLICT_HOST_IDENTITY_MOVED`。
- 錯誤：400 `VALIDATION_INVALID_ID`（路徑 id 不是數字）、400 `VALIDATION_BAD_REQUEST`（body 不合法，情形同上節，先於一切查詢）、
  403 `AUTH_PERMISSION_DENIED`（能力不足以承接）、404 `NOTFOUND_CHANGE_SECRET_CANDIDATE`、
  409 `CONFLICT_HOST_IDENTITY_MOVED`（`detail` 值域同上節）、500 `INTERNAL_CHANGE_SECRET_CANDIDATE_QUERY`。

計劃的回應（列表、建立、更新）帶 `authorization_state`：空字串＝正常排程，`needs_reauthorization`＝暫停中、待一鍵重新授權，`needs_reconfirmation`＝憑證目標計畫因範圍外掛載超出該版上界而暫停、待重新確認（見下「計畫的範圍」）。兩種暫停都不排程執行，cron 與啟用設定保留；以 `PUT` 儲存新版即清除。發起者授權的內部紀錄與掛載上界不在回應中。

**請求**（`ChangeSecretPlanRequest`）:
```json
{
  "name": "每月輪換", "asset_ids": [1, 3], "accounts": ["@ALL"],
  "target_kind": "account", "target_credential_id": 0,
  "secret_type": "password", "key_strategy": "append_replace",
  "password_length": 16, "password_include_symbol": true,
  "password_exclude_ambiguous": true,
  "cron": "0 3 1 * *", "enabled": true
}
```

- `target_kind`：目標種類，`account`（預設，空值讀成它）或 `credential`。值域外回 400
  `VALIDATION_PLAN_TARGET_KIND`。`credential` 時 `target_credential_id` 必填（缺回 400
  `VALIDATION_PLAN_TARGET_CREDENTIAL_REQUIRED`），該憑證須存在（不存在回 404
  `NOTFOUND_CREDENTIAL`）。**不另造排程器**：cron、
  啟用旗標、密碼策略與適用天數全部沿用計劃既有欄位，本欄只決定「要改的是哪一組東西」。
  `credential` 目標的執行走整組改密，成員集合＝該憑證當下的全部掛載，逐台結果落在同一組執行記錄上。
- `accounts`：帳號範圍。`["@ALL"]`（預設）＝該資產全部帳號；否則為帳號 username 明列集合。
  空值一律讀成 `@ALL`。**以帳號為目標的計劃不得命中共用憑證的成員**，兩層各擋一次：
  儲存計劃時掃描選取範圍，命中即整筆回 400 `VALIDATION_PLAN_SHARED_CREDENTIAL_TARGET`
  （命中一個就拒絕整筆——靜默跳過那幾台會讓管理員以為它們也被涵蓋了）；執行時再判一次，
  仍命中的目標記 skipped 帶原因碼 `SHARED_CREDENTIAL_TARGET_REQUIRED`。
  只改共用的其中一員會讓同組其餘主機失去可用秘密，自動擴張到其餘掛載則是去改操作者沒有選取的
  機器；兩條都不走，要改整組請以憑證為目標。
- `secret_type`：`password`（POSIX 通道走 chpasswd；Windows 通道走 PowerShell `Set-LocalUser`）或 `ssh_key`
  （authorized_keys 輪替，僅 `posix_ssh` 通道；Windows 通道遇之記 skipped）；其他值回 400
  `VALIDATION_PLAN_BAD_SECRET_TYPE`。
- `key_strategy`（僅 `ssh_key`）：`append_replace`（預設，加新 → 驗新 → 刪舊，零鎖死）或
  `exclusive`（清空重寫，高風險）；其他值回 400 `VALIDATION_PLAN_BAD_KEY_STRATEGY`。
- 密碼策略：長度 12–64（預設 16，越界回 400 `VALIDATION_PLAN_BAD_PASSWORD_LENGTH`）、是否含符號、
  是否排除易混淆字元。**shell 敏感字元與控制字元為系統級硬排除，無任何設定可放寬**。
- `cron` 空值＝僅手動觸發；非法 cron 回 400；名稱重複 409。
- `impact_confirmation_id`（選用）：範圍化發起者儲存憑證目標計畫時的影響確認識別（見下「計畫的範圍」）；其餘情形忽略。

**計畫的範圍**：帳號目標計畫依 `account:rotate`、憑證目標計畫依 `credential:rotate`，各自分成「候選的讀取範圍」所列的四種情形；第 1、2 種看得到全部計畫，建立、修改與執行與先前相同。只經節點範圍持有者（第 3 種），以及第 4 種：

- 可見性：帳號目標計畫的 `asset_ids` 全部在範圍內才可見；憑證目標計畫的目標憑證歸屬在範圍內才可見，該憑證另掛在範圍外資產上不影響可見性。第 4 種看不到任何計畫。
- 不可見的計畫：`PUT`、`DELETE`、`POST /:id/run` 與不存在同回 404 `NOTFOUND_CHANGE_SECRET_PLAN`，`GET /:id/records` 回空清單。可見計畫的執行記錄只列目標資產在範圍內者。
- 建立與修改：帳號目標的 `asset_ids` 有不存在或範圍外者，整份回 404 `NOTFOUND_BATCH_ITEMS_UNAVAILABLE`（`params.count`），計畫不儲存；憑證目標的憑證歸屬在範圍外與不存在同回 404 `NOTFOUND_CREDENTIAL`。
- 憑證目標的影響確認：目標憑證若有掛在操作者 `credential:rotate` 範圍外資產上的掛載，先以 `POST /credentials/:id/impact-confirmations` 帶 `{"operation": "rotate"}` 取得確認，再於本請求帶 `impact_confirmation_id`。缺漏、已使用、不符或當下範圍外集合超出確認時回 409 `RULE_CREDENTIAL_IMPACT_CONFIRMATION_REQUIRED`（`count` 為當下範圍外台數），計畫不儲存；確認在儲存交易內使用一次。同一交易內，伺服器把該憑證當下的全部掛載（資產帳號列）存為這一版的掛載上界，不需確認時也照存。
- 每次執行，在建立任何候選之前，把當下掛載依該次發起者（排程為計畫的發起者，手動執行為點擊者）當下的 `credential:rotate` 範圍分成範圍內與範圍外兩部分。該次發起者只經節點範圍持有此能力，且範圍外部分有不在這一版上界內的掛載（版本沒有上界時以空集合比對）時整次停止、不連線任何主機，停止的稽核與告警帶原因碼 `CHANGE_SECRET_SCOPE_BOUND_EXCEEDED`。排程執行，以及計畫發起者的 `credential:rotate` 沒有全系統來源時的手動執行，計畫轉 `needs_reconfirmation`，稽核與告警只在轉入當下各一次。比對上界之後計畫若已存成新版，舊版的這次執行照樣停止、不連線任何主機，新版不轉 `needs_reconfirmation`，這次停止不另保證稽核與告警。計畫發起者的 `credential:rotate` 有全系統來源時，範圍化點擊者的手動執行只拒絕這一次，計畫狀態與排程不變；讀不到計畫發起者時同樣只拒絕這一次，無從判定其能力時也只拒絕這一次、原因碼為 `CHANGE_SECRET_AUTHZ_UNAVAILABLE`。範圍內新增的掛載不觸發停止，與其他目標一起執行。
- 恢復：只經節點範圍持有者以 `PUT` 重新儲存（當下仍有範圍外掛載時須重新取得確認），產生新版與新上界，狀態隨之清空；一鍵重新授權把其可見的此類計畫列在 `skipped_plan_ids`，手動執行同樣在建立候選前停止。憑證輪替有全系統來源者可以一鍵重新授權承接，之後依全系統規則執行、不寫也不比對上界；或手動執行一次，該次涵蓋當下全部掛載，計畫維持 `needs_reconfirmation`。

憑證輪替有全系統來源的發起者儲存憑證目標計畫時不需確認、不寫掛載上界，執行時涵蓋當下全部掛載，與先前相同。

**執行記錄的憑證欄位**：計畫的執行記錄（`GET /change-secret-plans/:id/records`）與批次詳情的 `records` 同一形狀。範圍化檢視者看到的記錄，若該筆記錄自身保存的憑證不在其憑證檢視範圍內，則不帶 `credential_id`、`credential_name`、`target_version_id`，並帶 `"credential_out_of_scope": true`；憑證在範圍內、未解析到憑證的記錄與全量檢視者的記錄不變。次數、狀態、錯誤碼等其餘欄位照舊。

**計畫的憑證與資產欄位**：計畫列表與建立、更新的回應（`GET`／`POST /change-secret-plans`、`PUT /change-secret-plans/:id`）對範圍化檢視者依其憑證檢視範圍輸出。目標憑證不在範圍內時，`target_credential_id` 為 `null` 並帶 `"credential_out_of_scope": true`；`asset_ids` 只保留範圍內的資產，被省略的台數放在 `out_of_scope_asset_count`（沒有省略時不帶此欄）。全量檢視者的回應不變。

**執行記錄欄位**: `{id, plan_id, asset_id, account_id, account_username, credential_id,
credential_name, target_version_id, secret_type, status, error, executed_at}`；
`status`:

| 值 | 語義 |
|---|---|
| `success` | 已驗證並就位為該掛載使用的密文版本 |
| `failed` | 遠端**確定未變更**（指令非零退出／登入失敗／指令送出前無法建立工作階段）；就位版本原樣，無殘留候選 |
| `unverified` | 遠端狀態**不可知**或驗證未通過；就位版本維持舊值，候選保留待系統重試 |
| `skipped` | 無改密通道（`CHANGE_SECRET_CHANNEL_NOT_CONFIGURED`：通道為 `none`，含未設定通道的 rdp 資產）、通道不支援計劃的秘密型別（`CHANGE_SECRET_SECRET_TYPE_UNSUPPORTED`：Windows 通道遇 `ssh_key`）、協定不在改密射程（`CHANGE_SECRET_PROTOCOL_UNSUPPORTED`：vnc／資料庫／k8s）、目標掛的是共用憑證而計劃以帳號為目標（`SHARED_CREDENTIAL_TARGET_REQUIRED`）、無可用憑證、或該帳號已有未驗證候選 |

`credential_id`／`credential_name`／`target_version_id` 是執行當下的**快照**：掛載事後可能改指
別的憑證，回頭 join 讀到的會是現況而不是那一次動的是誰。

`error` 欄存機器碼（前端按碼查譯三語文案），不存遠端原文。多數碼帶 `CHANGE_SECRET_` 前綴；
`SHARED_CREDENTIAL_TARGET_REQUIRED` 刻意不帶，因為它描述的是目標種類選錯，不是改密過程的失敗。

**改密通道**：

| 通道 | 適用協定 | 連線 | 改密方式 | 秘密型別 |
|---|---|---|---|---|
| `posix_ssh` | ssh（未設定時的預設） | SSH（沿資產埠與 host key TOFU） | `chpasswd`／`authorized_keys` | `password`、`ssh_key` |
| `windows_winrm` | rdp、ssh | WinRM：NTLM 認證，訊息層加密恆啟用；http（預設埠 5985）或 https（預設埠 5986，TLS 模式 `system`／`ca`／`insecure`） | PowerShell `Set-LocalUser` | `password` |
| `windows_ssh` | rdp、ssh | SSH 到 Windows OpenSSH（rdp 資產用 `rotation_ssh_port`，0＝22；沿 host key TOFU） | 同上；指令顯式以 `powershell.exe -NoProfile -NonInteractive -EncodedCommand` 執行，不依賴目標預設 shell（cmd 亦可） | `password` |
| `none` | 任一 | 不連線 | 記 skipped | 不適用 |

Windows 兩通道的共同契約：

- 新密碼與舊密碼只經標準輸入投遞（第一行新密碼、第二行舊密碼）；指令字串（含編碼後的腳本）不含密碼。標準輸入缺任一行時腳本在觸碰帳號前以結局碼 3 結束，
  記 failed 帶 `CHANGE_SECRET_STDIN_NOT_DELIVERED`。誠實邊界：新舊密碼在目標 PowerShell 行程記憶體中會短暫以明文存在，
  這是 `Set-LocalUser` 介面所致。
- 目標端自驗與回滾：腳本在 `Set-LocalUser` 之後於目標本機驗證新密碼可登入，不通過即當場以舊密碼改回。目標機離開腳本時只會是「已驗證的新密碼」或「舊密碼」。
  腳本改密前先以舊密碼校準本機驗證器；驗證器連舊密碼都驗不過或拋出例外時視為不可用，改密後不自驗、不回滾，交系統的重連驗證判定。
  腳本每個結束點先在標準輸出印一行 `ROTATION_RESULT=<結局碼>` 再以同一碼退出；系統以標記為準、退出碼為輔（目標的預設 shell 可能改寫退出碼，例如 Windows OpenSSH 預設 shell 為 PowerShell 時非零一律成 1）。結局碼契約：

  | 結局碼 | 目標狀態 | 記錄 | 原因碼 | 候選 |
  |---|---|---|---|---|
  | 0 | 新密碼（目標已自驗） | 重連驗證通過即 success | 無 | 提交後刪除 |
  | 1 | 舊密碼（`Set-LocalUser` 失敗） | failed | `CHANGE_SECRET_REMOTE_REJECTED` | 清除 |
  | 3 | 舊密碼（未觸碰） | failed | `CHANGE_SECRET_STDIN_NOT_DELIVERED` | 清除 |
  | 4 | 舊密碼（自驗不通過，已改回） | failed | `CHANGE_SECRET_REMOTE_SELF_VERIFY_FAILED` | 清除 |
  | 5 | 不可知（自驗不通過，改回也失敗） | unverified | `CHANGE_SECRET_REMOTE_SELF_VERIFY_ROLLBACK_FAILED` | 保留，交系統重試 |
  | 6 | 新密碼（驗證器不可用，未自驗） | 同 0 | 無 | 同 0 |
  | 標記缺失、退出碼非零 | 不可知 | unverified | `CHANGE_SECRET_REMOTE_STATE_UNKNOWN` | 保留，交系統重試 |
  | 標記缺失、退出碼 0 | 依重連驗證 | 同 0 | 無 | 同 0 |
  | 標記值不在上表內 | 不可知 | unverified | `CHANGE_SECRET_REMOTE_STATE_UNKNOWN` | 保留，交系統重試 |

  兩通道的分流相同；標記存在時，退出碼與標記不一致只在伺服端 log 記一行。
- 帳號名於送出前依 Windows 本機帳號的規則本地驗證：長度 1 至 20（UTF-16 碼元）、不含 `" / \ [ ] : ; | = , + * ? < >` 與控制字元、不可全為點或空白、首尾非空白；
  其餘字元（含非 ASCII 字元、`@`、`$`、單引號）皆可。帳號名與密碼一樣只經標準輸入投遞（第三行，UTF-8），不進腳本文字。
  違者記 failed 帶 `CHANGE_SECRET_ACCOUNT_NAME_INVALID`，遠端未被觸碰；反斜線被拒即不支援 `DOMAIN\user` 形態，本版只做本機帳號。含 `\r`／`\n`／NUL 或為空的新密碼同樣在本地擋下（`CHANGE_SECRET_INVALID_NEW_SECRET`）；
  舊密碼同一條行協定（`CHANGE_SECRET_INVALID_OLD_SECRET`）：截斷的舊密碼會讓目標端回滾把帳號改到錯的值，故不送出。
- 驗證＝以新密碼另建連線（WinRM 新工作階段或 SSH 新連線）跑無副作用指令，固定序列重試三次（立即、2 秒後、再 5 秒後）；
  用盡仍失敗記 unverified、候選保留交系統重試。
- 失敗分流以「改密指令是否已送出」為閘。指令送出前（WinRM 建立工作階段階段、SSH 舊憑證登入階段）的失敗＝failed、候選清除：
  WinRM 目標無法建立訊息層加密的安全工作階段帶 `CHANGE_SECRET_WINRM_ENCRYPTION_UNAVAILABLE`（**拒連，不回退明文**）、憑證被拒帶 `CHANGE_SECRET_OLD_CREDENTIAL_LOGIN_FAILED`、
  其餘連線層錯誤（連線被拒或未回應、建立工作階段逾時 30 秒、TLS 憑證不受信任、交握回非預期狀態碼）帶 `CHANGE_SECRET_REMOTE_UNREACHABLE`；SSH 通道的登入階段失敗一律帶 `CHANGE_SECRET_OLD_CREDENTIAL_LOGIN_FAILED`。
  指令送出後：回報完成即依上表的結局碼分流（stderr 只進伺服端 log）；未回報完成（連線中斷、指令逾時 90 秒，兩通道同值；逾時即關閉連線不再等目標）＝unverified（`CHANGE_SECRET_REMOTE_STATE_UNKNOWN`，候選保留）。
- WinRM 不支援 Basic 認證，沒有關閉加密的設定；系統對 WinRM 請求全行程序列化（同一時刻只有一則請求在飛），批次改密不並行。
- 目標機前置條件與 TLS 三模式的部署說明見 `docs/ops/upgrade-sop.md`。

**未驗證憑證（候選）**：新秘密於動遠端**之前**即加密落庫，驗證成功才成為該掛載就位的密文版本
並立即刪除候選。候選內容**不出現於任何 API 回應、UI、日誌或稽核欄位**，只供系統重試登入。清單欄位為
`{id, asset_id, account_id, account_username, plan_id, secret_type, applied, abandoned,
attempt_count, last_attempt_at, next_attempt_at, last_error, created_at}`。範圍化檢視者看到的候選，其 `plan_id` 對自己不可見的計畫輸出為 0，候選本身照列、可處置。

系統以指數退避重試（上限 1 小時、總期限 24 小時），逾期標 `abandoned` 並告警；**已放棄的候選不會被
系統自動刪除**——它是那把可能已在遠端生效的秘密的唯一副本。`DELETE` 為持有 `changesecret:manage` 者的顯式逃生口，
會產生稽核記錄；清除後若遠端確實已改密，只能以主機 console 等帶外途徑重設救回。

**帶憑證快照的候選由輪替引擎推進，不走單帳號轉正**：整組改密與拆分建立的候選屬於某一輪的成員，
重試排程一律把它們交回成員路徑。走錯路徑的後果是在共用憑證上多開一個版本、在成員轉移之外
改寫就位版本，拆分模式下更會把那台唯一的新秘密寫回原本要脫離的共用憑證。

### 帳號批次改密（change-secret-batches）

以**帳號名**為軸的一次性改密：選一個帳號名（例如各台主機都有的 `ops`），勾選多台資產或全部符合者，
一次對它們改密。與計劃並列而非隱藏的計劃——批次沒有排程、跑完即結束，記錄以 `batch_id` 指回批次
（此時 `plan_id` 為 0）。只支援密碼型別；SSH 金鑰輪替仍走計劃。

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/change-secret-batches/usernames` | 登記於系統的帳號名清單 → `{data: [{username, asset_count}], total}` |
| GET | `/change-secret-batches/targets?username=` | 該帳號名的全部目標 → `{data: [目標], total, as_of}` |
| POST | `/change-secret-batches` | 建立並非同步執行 → 202 `{data: 批次}` |
| GET | `/change-secret-batches` | 最近批次（新到舊，最多 50 筆）→ `{data, total}` |
| GET | `/change-secret-batches/:id` | 單一批次含逐目標記錄 → `{data: {batch, records}}`（記錄的憑證欄位對範圍化檢視者的收窄同「執行記錄的憑證欄位」） |

**目標**：集合＝掛在**未刪除資產**上、名為該帳號名的未刪除帳號，不探勘目標機。每個目標是輪替證據報告
資料集的同一列（狀態桶、剩餘天數、共用憑證與特權標記等欄位同 `GET /rotation-report`），外加兩欄：
`rotation_channel`（推導後的有效改密通道）與 `ineligible_reason`（執行前即可判定的不可改密原因碼，
空＝可改密；值域為 `CHANGE_SECRET_CHANNEL_NOT_CONFIGURED`、`CHANGE_SECRET_PROTOCOL_UNSUPPORTED`、
`CHANGE_SECRET_NO_CREDENTIAL`、`CHANGE_SECRET_NO_PASSWORD_CREDENTIAL`、`CHANGE_SECRET_CANDIDATE_PENDING`、
`CHANGE_SECRET_ASSET_LOOKUP_FAILED`）。
不可改密的目標仍列出，由前端停用勾選。

範圍化檢視者的目標列，若所掛憑證不在其憑證檢視範圍內，該列不帶 `credential_name`，並帶 `"credential_out_of_scope": true`；憑證在範圍內的列與全量檢視者的列不變。

**請求**（`POST`）:
```json
{
  "username": "ops", "account_ids": [12, 34], "all": false,
  "password_mode": "per_target", "credential_name": "",
  "password_length": 16, "password_include_symbol": true, "password_exclude_ambiguous": true
}
```

- 目標選擇二擇一：`all: true`＝全部符合者；否則 `account_ids` 明列，每個都必須是該帳號名的目標，
  任一不符回 400 `VALIDATION_BATCH_TARGET_MISMATCH`；零目標回 400 `VALIDATION_BATCH_NO_TARGETS`；
  缺帳號名回 400 `VALIDATION_BATCH_USERNAME_REQUIRED`。
- `password_mode`：`per_target`＝每個目標各自隨機；`shared`＝批次開始時產生一組密碼供全部目標使用。
  其他值回 400 `VALIDATION_BATCH_BAD_PASSWORD_MODE`。
- `credential_name`：`shared` 模式**必填**（缺回 400 `VALIDATION_BATCH_CREDENTIAL_NAME_REQUIRED`），
  其他模式忽略。**`shared` 模式會建立一筆以此為名的共用憑證**，成功提交的目標改綁到它並就位同一個
  密文版本，於是憑證庫、帳號列表與輪替證據報告據同一個來源標示共用關係——同一組密碼在多台生效，
  任一台外洩即全部外洩，這個事實必須看得見。名稱沿共用憑證的檢核（≤128、不含控制字元、
  共用範圍內唯一；撞名回 409 `CONFLICT_CREDENTIAL_NAME`），且在**送出前**即檢核，
  不讓操作者改完一批機器才被撞名擋下。那組密碼不存於批次列，只經各目標的候選憑證信封加密保存。
- `shared_credential_ownership`（`{kind: "global"|"node", node_id?}`，形狀同憑證庫建立共用憑證的歸屬欄）：
  `shared` 模式新建那筆共用憑證的管理歸屬，其他模式忽略。未帶時，憑證建立能力有全系統來源者為全域；
  只經節點範圍持有者須指定其範圍內的節點，未帶回 400 `VALIDATION_CREDENTIAL_OWNERSHIP_INVALID`，
  要求全域回 403，範圍外與不存在的節點同回 404 `NOTFOUND_ASSET_NODE`。歸屬在建立批次時判定並保存，
  執行時建立憑證前以同一規則再判一次。
- 密碼策略三欄與計劃同語義、同預設（16、含符號、排除易混淆），長度越界回 400 `VALIDATION_PLAN_BAD_PASSWORD_LENGTH`。

**建立的判定順序**（所有主體相同）：
1. 本文形狀：帳號名、模式、密碼長度，以及 `shared` 模式的憑證名稱與歸屬欄形狀，不合回上列 400。
2. 模式所需能力：所有批次需 `account:rotate`，`shared` 模式另需 `credential:create` 與 `credential:bind`。任一能力沒有任何有效來源（全系統或節點範圍皆無）即回 403 `AUTH_PERMISSION_DENIED`，先於目標比對、零目標判定與名稱查重，缺能力者不會得到 `VALIDATION_BATCH_TARGET_MISMATCH`、`VALIDATION_BATCH_NO_TARGETS` 或 `CONFLICT_CREDENTIAL_NAME`。
3. 建立交易內解析目標。`account:rotate` 只經節點範圍持有者，`all: true` 只展開範圍內資產上的帳號；明列的 `account_ids` 先計「不存在、所屬資產已刪除或在範圍外」的筆數，大於 0 即整批回 404 `NOTFOUND_BATCH_ITEMS_UNAVAILABLE`（`params` 只有 `count`），批次、記錄與候選都不寫入；全部可用之後才比對帳號名，不符回 400 `VALIDATION_BATCH_TARGET_MISMATCH`；目標為零回 400 `VALIDATION_BATCH_NO_TARGETS`。該能力有全系統來源者對不存在的 ID 照舊回 `VALIDATION_BATCH_TARGET_MISMATCH`。
4. 逐目標的管理授權、`shared_credential_ownership` 的歸屬判定，最後是共用憑證名稱查重。

**讀取範圍**依檢視者的帳號改密能力（`account:rotate`）分四種情形，帳號名清單、目標、批次列表與詳情同一口徑：

1. 該能力有全系統來源（含超級管理者）：全量，與先前相同。
2. 沒有任何角色指派含帳號改密、但 `changesecret:manage` 有全系統來源：全量（相容既有行為）。指派含帳號改密、但其範圍節點已全部不存在者不屬此種，結果與第 4 種相同。
3. 帳號改密只經節點範圍持有（`changesecret:manage` 另有全系統來源者亦同）：資產數與目標只含範圍內資產上的帳號；批次只列建立時的目標至少一台在範圍內者；詳情的逐目標記錄、目標數與四種計數只計範圍內，範圍外批次的詳情與不存在的批次同回 404 `NOTFOUND_CHANGE_SECRET_BATCH`。
4. 其餘：帳號名清單、目標與批次列表為空，任何批次的詳情都回 404 `NOTFOUND_CHANGE_SECRET_BATCH`。

目標列上的涵蓋計畫、適用天數與排程只由檢視者可見的計畫彙總（計畫可見性見上節「計畫的範圍」）。四種情形都先經入口權限檢查：沒有任何含 `changesecret:manage` 的有效指派者回 403 `AUTH_PERMISSION_DENIED`。

**執行**逐目標沿用計劃的狀態機與執行器（候選先落庫、動遠端、驗證、就位、憑證改綁、記錄、告警）；
單一目標的失敗不中斷批次，每個目標的 `success`／`failed`／`unverified`／`skipped` 各自獨立落記錄。
批次列欄位：`{id, username, password_mode, password_length, password_include_symbol, password_exclude_ambiguous,
target_count, success_count, failed_count, unverified_count, skipped_count, status, requested_by, requested_by_name,
started_at, finished_at, created_at}`；`status` 為 `running`／`completed`，四種計數於全部目標處理完後一次寫入。
記錄欄位同計劃的執行記錄，另帶 `batch_id`。批次不可中止；重跑＝再建一個批次。不存在的批次回 404 `NOTFOUND_CHANGE_SECRET_BATCH`。

---

## 營運指標端點（Prometheus）

```
GET /metrics
```

**路徑刻意不在 `/api` 之下**。正式版 edge（`docker/frontend/nginx.conf`）只代理 `location /api`
與 `/ws`，`/metrics` 不在其中——故本端點在**預設部署下自外部打不到**，這道安全性由拓撲保證，
而非由「有沒有記得掛上認證中介層」這種每次改路由都可能失手的人為保證。


**認證**: 由 `METRICS_TOKEN` 環境變數決定

| `METRICS_TOKEN` | 行為 |
|---|---|
| 未設（預設） | 免認證曝光；安全性由「edge 不代理」承擔 |
| 已設 | 強制 `Authorization: Bearer <token>`，常數時間比對。不符回 **401**，且回應體不含任何指標名稱或值；401 不區分「未帶 token」與「token 錯誤」 |

**要對外暴露就必須同時設 token**：跨機採集需要在反向代理上另開 `/metrics` 通道，
該動作與設定 `METRICS_TOKEN` 是同一件事的兩半——不存在「只開洞、不設 token」的正當中間狀態，
否則等於把端點清單、各功能使用量與錯誤率公開。

**回應** (200): Prometheus 文字曝光格式，`Content-Type: text/plain; version=0.0.4; charset=utf-8`，
含 `# HELP`／`# TYPE` 標頭，標準採集端可直接解析。

**指標盤**（`custodexa_` 前綴，單位入名，累計量以 `_total` 結尾）:

| 指標 | 型別 | 標籤 |
|---|---|---|
| `custodexa_active_sessions` | gauge | `protocol` |
| `custodexa_active_connections` | gauge | — |
| `custodexa_recording_storage_bytes` | gauge | — |
| `custodexa_command_alerts_pending` | gauge | `severity`（未審閱數，非累計產生數） |
| `custodexa_audit_queue_depth` | gauge | — |
| `custodexa_audit_dropped_total` | counter | `reason`（`fallback_file` 降級寫檔／`discarded` 永久遺失） |
| `custodexa_seal_state` | gauge | `state`（列舉形態：目前所處的態為 1、其餘為 0） |
| `custodexa_instance_guard_held` | gauge | —（單實例鎖是否由本實例持有：1 持有、0 未持有） |
| `custodexa_instance_guard_lost_total` | counter | —（本行程偵測到失鎖的累計次數） |
| `custodexa_instance_guard_overridden` | gauge | —（本實例以 `INSTANCE_GUARD_ACK` 啟動且尚未取得鎖：1 是、0 否） |
| `custodexa_instance_guard_peers` | gauge | —（偵測到的其他守衛版實例連線數；同一資料庫、同 `application_name`） |
| `custodexa_http_requests_total` | counter | `method`, `path`, `status` |
| `custodexa_http_request_duration_seconds` | histogram | `method`, `path` |
| `go_*` / `process_*` | — | Go runtime 標準 collector |

`path` 標籤一律取**路由模板**（`/api/v1/assets/:id`）而非實際 URL；未匹配任何路由的請求
歸入單一固定值 `<unmatched>`，使序列數不隨資料量或掃描次數成長。

**高成本指標讀的是快取值**：活躍會話（查資料庫）與錄影儲存量（遍歷檔案系統）由背景任務
定期刷新（預設 30 秒）後供讀取，不於每次採集時同步查詢；其值因此最多落後一個刷新週期。

**封存期（尚未解封）可採集，但只有縮減盤**：僅曝光 `custodexa_seal_state`、四條 `custodexa_instance_guard_*`
序列與 Go runtime 指標，使監控能區分「系統封存中待解封」與「系統當機」——兩者的處置完全不同。
守衛序列自段 1 起就存在（守衛在 migration 之前取鎖），封存期即可看到 `overridden`／`held`。封存期尚未建構的服務
（會話、錄影、稽核佇列、HTTP 統計），其指標**缺席而非為 0**：0 值會讓採集端把「服務不存在」
讀成「服務正常且計數為零」，而缺值在 PromQL 中可由 `absent()` 明確偵測。守衛序列同理：
資料源未注入時四條序列缺席而非為 0。

**守衛序列的判讀**：`held 1／overridden 0／peers 0` 是正常態；`held 0` 配 `overridden 1` 表示本實例以確認碼啟動、
尚未取得鎖；`held 0` 配 `overridden 0` 表示執行期失鎖（`lost_total` 同步加 1）；`peers > 0` 表示持鎖實例看到了
其他守衛版實例的連線。四條序列都是**行程本地**的：兩個實例並存時各報各的，不做跨副本聚合。
守衛失鎖不影響 `/health`。營運面判讀見 `docs/ops/upgrade-sop.md` §3.4。

**多副本下各報各的**：行程內 gauge（活躍連線、佇列深度）不做跨副本聚合，與現行單實例部署
不變式一致。

---

## WebSocket 連線

### 圖形協議連線（RDP/VNC，經 guacd）

```
GET /api/v1/connect?connect_token=<token>&width=<px>&height=<px>
Upgrade: websocket（子協議 guacamole）
```

**認證**: 僅收一次性 `connect_token`（授權與傳輸政策閘於簽發時完成；缺省或無效回 401）。
本端點**僅接受一次性 `connect_token`**：不接受以 query 參數攜帶 JWT 或 `asset_id` 直連——
那會繞過簽發閘，連同其上的授權檢查與傳輸政策一併落空。
兌換時重載狀態（殘窗收斂）：使用者停用 403／鎖定 423；資產停用 403＋`{reason: "asset_disabled"}`；
**兌換當下的來源不在該帳號的允許來源網段** 403＋`{code: "AUTH_SOURCE_NOT_ALLOWED", reason: "source_not_allowed"}`
——token 簽發後、兌換前被停用或來源改變者同擋，不因 token 尚在效期放行。

**連線收口**:
- 只收 token + asset_id；目標主機與憑證由後端從資產庫解密注入 guacd 握手，
  前端與 URL 全程不出現 hostname/username/password（帶 `hostname`/`password` 參數直接 400）
- SSH 已退出此路徑：`protocol=ssh` 資產回 400，請改用 `GET /api/v1/ssh`
- RDP 啟用磁碟重導（Shared drive，每連線獨立路徑）；RDP/VNC 皆啟用 Guacamole 原生錄製（`.guac`）
- RDP/VNC 剪貼簿內容旁路留存

### 文字終端連線（SSH / 資料庫 CLI / K8s exec）

```
GET /api/v1/ssh?connect_token=<token>&cols=<n>&rows=<n>[&k8s_mode=][&k8s_pod=][&k8s_container=]
Upgrade: websocket
```

**Query 參數**:
| 參數 | 必填 | 說明 |
|------|------|------|
| `connect_token` | 是 | 一次性連線 token（唯一入口；缺省 401。舊 `?token=<jwt>`+`asset_id` 直連已移除） |
| `cols`, `rows` | 是 | 初始終端尺寸（1-1000 / 1-500，超界 400） |
| `k8s_pod` | k8s 必填 | 連線目標 pod（namespace 取自資產，server-trusted） |
| `k8s_container` | 否 | 容器名（缺省用 default annotation 或第一個容器） |
| `k8s_mode` | 否 | 空＝互動 shell；`logs`＝kubectl logs -f 唯讀；`oneshot` 目前一律拒絕（400，v1.1 再開放） |

**行為**:
- 憑證後端解密注入（SSH）；mysql/postgres/redis/mssql 以本地 CLI 子程序 + PTY 代理；k8s 走 kubectl exec/logs
- SSH 握手/CLI 啟動在 WS 升級前完成；失敗時對 WS 升級請求改為升級後送 `{"type":"error", "code", "data"}` 再關閉
  （瀏覽器讀不到握手失敗的 HTTP body），非 WS 請求維持一般 HTTP 錯誤（502 為主）。
  SSH 撥號失敗帶 `RULE_SSH_*` code（`HOST_KEY_CHECK_FAILED`／`HOST_KEY_MISMATCH_REFUSED`／`PRIVATE_KEY_INVALID`／`AUTH_FAILED`／`DIAL_TIMEOUT`／`UNREACHABLE`，
  入 apierror registry 受三語完備性守衛）；k8s/database 啟動失敗僅帶 `data` zh 文案。
  `RULE_SSH_PRIVATE_KEY_INVALID`＝帳號的私鑰無法解析（格式錯誤、內容不完整或設有 passphrase），尚未向目標主機出示認證；
  此時 `data` 為該碼的 zh fallback 全文，不含解析原文。`RULE_SSH_AUTH_FAILED` 專指目標主機拒絕了出示的認證。
  `RULE_SSH_HOST_KEY_CHECK_FAILED`＝讀不到主機金鑰記錄，或不符時審計、觀察紀錄、告警寫不進去，都在送出憑證前中止；
  `RULE_SSH_HOST_KEY_MISMATCH_REFUSED`＝主機金鑰與記錄不符且該連線路徑不放行（代理通道開的終端），在送出憑證前拒絕，`data` 為該碼的 zh fallback 全文；
  人類終端遇主機金鑰與記錄不符則不是撥號失敗：連線照常建立，`connected` 之後以 `{"type":"notice","code":"RULE_SSH_HOST_KEY_CHANGED"}` 送達警示（見 Host Key API）
- 兌換時重載狀態（殘窗收斂）：使用者停用/鎖定即擋；資產停用回 403＋`{reason: "asset_disabled"}`（簽發後停用者同擋）；
  來源不在允許來源網段回 403＋`{code: "AUTH_SOURCE_NOT_ALLOWED", reason: "source_not_allowed"}`（**兌換當下現讀清單，不信簽發時的判定**）
- 全模態 asciinema 錄製；指令稽核與阻斷（K8s logs 唯讀模態除外）；接入即時監看 room
- 閒置/最大時長自動斷線：由安全政策 `session_idle_minutes`（出廠預設 **60**）與 `session_max_minutes`（0＝不限）決定。
  `SSH_IDLE_TIMEOUT_MINUTES`／`SSH_MAX_SESSION_MINUTES` 僅於首次啟動播種政策列；生產路徑一律走政策，
  env 值不再生效（handler 內的 30 分鐘僅為政策未注入時的 fallback，正常部署不可達）

**WS 訊息協議**（JSON envelope，雙向）:
```json
{"type": "data|resize|ping|pong|connected|error", "data": "...", "code": "..."}
```
`resize` 的 data 為 `{"cols": N, "rows": N}` JSON 字串；`code` 僅 `error` 訊息使用（機器可讀錯誤碼，可缺省）。

### 資料庫查詢主控台連線（mysql / postgres / mssql）

```
GET /api/v1/db-console?connect_token=<token>
Upgrade: websocket
```

**認證與連線收口**: 與 `/ssh` 同一條兌換路徑——同一支 `POST /api/v1/connect-tokens` 簽發的
一次性 `connect_token`（綁 user+asset+account、兌換即焚）、同一張閘序表、同一個憑證解封點、
同樣的會話記錄 fail-close（無會話主鍵即無錄影、語句稽核與監看，一律拒連）。
前端與 URL 全程不出現主機、帳號或密碼。缺 token 401，無效 token 401。

比文字終端入口多兩道閘：

| 閘 | 條件 | 回應 |
|---|---|---|
| 協議 | 資產協議不是 mysql／postgres／mssql | 400 `RULE_DB_CONSOLE_UNSUPPORTED_PROTOCOL`。redis 是資料庫協議但沒有 SQL 執行單位、結果集與交易態，請改用文字終端入口 |
| admission | 同時進行的主控台會話數達上限（每人 4、全域 64） | 429 `RULE_DB_CONSOLE_LIMIT_REACHED`。計數口徑是**運行時的連線註冊表**，不是會話表的 active 列——等待收斂的孤兒列不佔名額 |

**執行形態**:
- 後端以資料庫 driver 直連目標，**不啟動命令列子程序**；單一連線、無連線池、**不自動重連**
- 會話記入 `sessions`（`db_console=true`），出現在會話列表、即時監看與調查工作台，
  有開始、結束與時長；伺服端另寫一份純文字**轉錄**錄影（`.cast`，每行帶事件 ID）——
  轉錄**不含結果資料列**（體積無上界且含敏感資料），結構化語句紀錄才是真相來源
- 每個執行單位一筆語句紀錄；紀錄寫入失敗即不執行（`RULE_DB_CONSOLE_AUDIT_UNAVAILABLE`）
- 指令阻斷規則同樣套用；比對器不可用即拒絕執行（`RULE_DB_CONSOLE_BLOCKER_UNAVAILABLE`）
- 閒置／最大時長沿安全政策 `session_idle_minutes`／`session_max_minutes`（與文字終端同源）

**客→服訊息**（JSON）:

| type | 欄位 | 說明 |
|---|---|---|
| `hello` | `previous_session_id?`、`pending_event_id?` | 選填首則。重連時由客戶端自報上一場會話與未收到結果的事件；**伺服端只記錄不信任**——僅用來查本人的既有列，不做任何授權推導 |
| `query` | `sql` | 執行單位原文（編輯器全文或選取範圍）。目標＝當前資料庫，不帶 database 參數。**每會話同時只允許一個進行中的送出**，第二個回 `RULE_DB_CONSOLE_BUSY` |
| `cancel` | `event_id` | 取消指定事件 |
| `tree` | `level`（`databases`／`tables`／`columns`）、`schema?`、`table?` | 目錄樹一層；只對當前庫 |
| `switch` | `database` | 切換目標資料庫；值須為伺服器目錄剛回傳的名稱 |

**服→客訊息**:

| type | 主要欄位 |
|---|---|
| `ready` | `session_id`、`dialect`、`database`、`database_allowed`、`databases[{name, connectable}]`、`capabilities{file_download}`、`tx_state`、`limits`、`pending_result?{event_id, status, result_reason}` |
| `unit_started` | `event_id`、`seq`、`batch_index`、`batch_count`。**先於執行送出**，使畫面在多批次時能逐批對應 |
| `result` | `event_id`、`seq`、`status`、`result_reason?`、`sets[{set_index, columns[{name, type_name, kind}], rows, row_count, truncated}]`、`rows_affected`、`duration_ms`、`truncated`、`tx_state?`、`db_error?` |
| `error` | `event_id?`、`code`（機器碼）、`params?`、`db_error?{code, message?}` |
| `notice` | `code`（`database_not_allowed`／`database_drift_denied`／`database_switched`）、`params?`。非錯誤，是「狀態變了，畫面該跟著變」 |
| `closed` | `reason`（`target_closed`／`slow_consumer`／`idle_timeout`／`max_duration`／`terminated`／`client_gone`） |
| `tree_result` | `level`、`database`、`schema?`、`table?`、`databases?`／`tables?`／`columns?`、`truncated` |

`databases[].connectable` 是**預檢不是保證**：它答的是「目錄說這個庫上線且此帳號有連線權」，
真連下去仍可能因主機端規則或連線數上限而失敗。MySQL 恆為 true（`SHOW DATABASES` 本身已依權限過濾）。

**結果值一律以字串傳輸**，`null` 代表 SQL NULL：2^53 以上的整數與 decimal 尾數若走 JSON number
會在瀏覽器端靜默失真——對金額與識別碼，那是資料錯誤而不是顯示問題。

**事件識別**: 每個執行單位在阻斷比對之前配發一個 26 字元 ULID。同一個值出現於
語句紀錄的 `event_id`、`unit_started`／`result`／`error` 訊息、轉錄的每一行、
結果匯出 URL 與會話詳情錨點。

**執行單位狀態**（`result.status`，與語句紀錄 `result_status` 同一組值）:
`running`／`ok`／`error`／`partial`／`blocked`／`cancelled`／`timeout`／`effect_unknown`。
`ok` **不等於已提交**——單位落在使用者開啟的交易內時，最終命運由後續的
COMMIT／ROLLBACK／會話結束回滾決定。`cancelled` ＝確認未生效；`effect_unknown` ＝已送出而
目標端既未回報完成也未確認取消——**兩者都不得讀成「未生效」**。原因碼在 `result_reason`
（`matcher_hit`／`matcher_unavailable`／`error_after_results`／`cancel_confirmed`／`batch_stopped`／
`timeout_confirmed`／`cancel_unconfirmed`／`timeout_unconfirmed`／`connection_lost`／`cell_truncated`）。

**交易態**（`ready.tx_state`／`result.tx_state`）: `none`／`active`／`failed`／`unknown`，
取自逐單位本就會做的一次探詢。稽核據此能判讀「這筆 `ok` 落在未提交的交易內」。
**MySQL 恆為 `unknown`**（無失敗交易態，且探詢進行中交易需要額外權限）。

**機器碼**:

| 碼 | 時機 |
|---|---|
| `RULE_DB_CONSOLE_UNSUPPORTED_PROTOCOL` | 協議閘 |
| `RULE_DB_CONSOLE_LIMIT_REACHED` | admission 閘 |
| `RULE_DB_CONSOLE_BUSY` | 上一次送出尚未完成 |
| `RULE_DB_CONSOLE_AUDIT_UNAVAILABLE` | 語句紀錄寫入失敗（fail-close，不執行） |
| `RULE_DB_CONSOLE_BLOCKER_UNAVAILABLE` | 阻斷比對器不可用（fail-close，不執行） |
| `RULE_DB_CONSOLE_STATEMENT_BLOCKED` | 阻斷規則命中；規則名以 `params.rule` 單獨傳遞 |
| `RULE_DB_CONSOLE_DATABASE_NOT_ALLOWED` | 目標庫不在資產的允許清單內 |
| `RULE_DB_CONSOLE_CONNECT_FAILED` | 起始連線失敗（認證／TLS／網路三類共用一碼，**不帶 `db_error`**） |
| `RULE_DB_CONSOLE_DATABASE_UNAVAILABLE` | 目標庫不可用（拓撲／伺服器狀態類，含切庫失敗）；帶 `db_error.code`，**不帶訊息** |
| `RULE_DB_CONSOLE_CONNECTION_LOST` | 送出後目標連線中斷；該單位結果為未知，且不自動重連 |
| `VALIDATION_DB_CONSOLE_STATEMENT_TOO_LARGE` | 語句文字逾上限；於訊息層拒絕，**不產生語句紀錄列** |
| `VALIDATION_DB_CONSOLE_GO_COUNT_UNSUPPORTED` | MSSQL 的 `GO n` 重複執行語法；拒絕而非忽略（忽略會讓使用者以為執行了 n 次） |
| `NOTFOUND_DB_CONSOLE_RESULT` | 結果匯出的六種不成立情形共用（見下節） |

**錯誤訊息的邊界**: 連線階段（起始連線、PostgreSQL 切庫）**永不回目標端訊息原文**；
切庫回應永不帶訊息（只帶 `db_error.code`）；只有「已建連線上、使用者自己語句的 SQL 層錯誤」
才回原文——那是他自己的產品內容，而連線與拓撲層的錯誤字串常含主機、埠、憑證主體與主機端規則。
語句紀錄一律**只記錯誤碼不記訊息**（錯誤文本可能夾帶資料片段，而稽核列是長期保存的）。

**上限**（伺服端常數，本版不提供設定面；`ready.limits` 為其投影）:

| 項 | 值 | `limits` 鍵 |
|---|---|---|
| 單次送出的語句文字 | 256 KiB | `statement_bytes` |
| 單一執行單位回傳的資料列（跨結果集合計） | 1000 | `rows_per_unit` |
| 單次送出序列化後的位元組（跨單位合計） | 8 MiB | `bytes_per_submission` |
| 單一欄位原始值 | 64 KiB | `cell_bytes` |
| 目錄樹每層節點 | 2000 | `tree_nodes_per_level` |
| 單一執行單位逾時 | 60 秒 | `statement_timeout_seconds` |

列數與位元組是**回傳**上限，不是查詢上限：目標端仍會算完整個結果，只是不搬回來；
截斷即於該單位標記 `truncated`。單欄逾限者截斷該欄並於值內附標記，
使畫面與 CSV 都看得出是哪一欄被砍。

**允許資料庫清單**: 資產的 `allowed_databases` 為空即不限制；非空時目錄樹只列交集，
`switch` 與每個執行單位之前都**重讀**該欄並確認目標庫落在清單內（否則
`RULE_DB_CONSOLE_DATABASE_NOT_ALLOWED` 並留痕）。
**限制的是執行目標，不解析 SQL**——單位內的 `USE`、跨庫限定名都不在辨識範圍，
真正的資料庫級存取控制在目標端的帳號權限上。**文字終端會話不受本欄影響。**

**誠實邊界**（全文見 `openspec/specs/db-query-console/spec.md` 的「主控台的誠實邊界」）:
該節逐條列出本能力管得到與管不到什麼，其中阻斷比對的可規避性、畫面結果表無伺服端強制點、
驅動程式內部可能保留認證材料等屬稽核與管理視角。**主控台介面只呈現與連線者操作直接相關的
五項**（結果上限與匯出範圍、成功不等於已提交、取消與切庫對連線的影響、允許清單、操作留痕），
其餘不呈現給連線者。

### 查詢主控台結果匯出

```
GET /api/v1/db-console/sessions/:id/results/:event_id/export?set=<n>&format=csv
Authorization: Bearer <token>
```

**Query 參數**: `set`（結果集索引，非負整數，預設 0；MSSQL 多批次時每批次各自可匯出）、
`format`（僅接受 `csv`，缺省即 csv；其他值視為識別不成立）。

**匯出範圍＝伺服端快取中「最近一次送出」的結果，不重新執行查詢。**
匯出內容即畫面所見（受列數與位元組上限截斷）——重跑會讓非冪等語句生效兩次，
且在稽核上那是一次新的執行。此差異於介面 tooltip 同步揭露。

**權限**: JWT ＋ 會話本人 ＋ 會話為進行中 ＋ `event_id` 在當前快取內；
另受既有傳輸政策 `file_download_enabled` 強制（`ready.capabilities.file_download` 只是投影，
會過期，**端點每次重驗**）。

**存在性收斂**: 會話不存在、非本人、非進行中、事件識別非當前快取、結果集索引逾界、
識別格式非法——**六者一律回同一則 404 `NOTFOUND_DB_CONSOLE_RESULT`，回應逐位元組相同**
（狀態碼、內容、標頭集合皆同）；分述即開出會話存在性的探測面，真實原因只進稽核。
政策拒絕的判定排在身分之後，對**本人**回 403 `RULE_TRANSFER_DENIED`（帶受控的 `action`／`reason`）
——對非本人回同一則 403 就等於確認了「這個結果存在」。

**Produce**: `text/csv; charset=utf-8`，
`Content-Disposition: attachment; filename="<資產名>-<seq>-<UTC 時戳>.csv"`。

**CSV 形態**: UTF-8 **無 BOM**（BOM 會讓非試算表的消費端多讀到三個位元組）、RFC 4180 引用、
首列為欄名、NULL 為空欄。
**防公式注入**：儲存格首字元為 `=`、`+`、`-`、`@`、Tab、CR 之一的**文字**欄位會前置單引號 `'`；
**純數值字面豁免**（`^-?\d+(\.\d+)?([eE][+-]?\d+)?$`）——負號開頭的數字不是公式，
而把 `-5` 寫成 `'-5` 會讓數值欄在試算表裡變成文字，
「數值在畫面與 CSV 逐字元相同」這條保證就在 CSV 這一側失效了。

**留痕**: 成功、政策拒絕、存在性拒絕與串流中止一律寫稽核（`action=file_download`、`resource=file`）。
成功記列數、位元組與 SHA-256；中止記**我方寫入 socket 的**位元組與其摘要，
不是客戶端實收的量。

### 一次性連線 token 簽發

```
POST /api/v1/connect-tokens
Authorization: Bearer <token>
```

**請求**: `{"asset_id": 1, "account_id": 3, "access_request_id": 12}`（`account_id` 選填，省略／0＝該資產的預設帳號）
**回應** (200): `{"connect_token": "<hex>", "expires_in": 60}`

簽發時完成資產存在性與連線授權檢查；資產不存在與無connect授權皆回 **404** `{"code":"NOTFOUND_ASSET","error":"資產不存在"}`，不簽票。本文只含code與error，兩種結果的相關標頭相同，不帶reason、帳號或風險資訊；前端顯示既有不存在文案並中止。
token 綁定 user+asset+account，Resolve 即焚。guacd 與原生 SSH 兩路徑共用同一 token 管理器。

這項404回應僅用於本REST簽發的資產授權拒絕；行程內簽發、token兌換及重撥維持原拒絕語義。已通過資產授權後的reason_required／approval_required 403及傳輸同意428不變。存在性拒絕的相關標頭包括內容型別、長度（存在時）、快取、驗證挑戰、重新導向及跨來源設定；逐請求的時間與追蹤識別不表示資源狀態差異。

`access_request_id` 對人類選填，帶入時於簽發及 SSH／圖形／DB console 兌換現查任務主體、
資產、解析後的帳號、核准時窗、撤銷及關閉狀態；不符回 403 `AUTH_REQUEST_ITEM_MISMATCH`，
附 `dimension`（asset／scope／window）；稽核的 `request_item_dimension` 記拒絕維度並帶任務及目標資產。既有較前置閘的拒絕碼仍優先。
未帶任務的人類保留原路徑：無有效常設 connect 時只採 ticket；同資產多張票不聯集，
按項 `decided_at` 新到舊、同時刻 id 大到小取一張；有常設 connect 時維持原聯集。
agent HTTP bearer 對 REST connect-tokens 與三種 WS 仍一律 403 `AUTH_AGENT_FORBIDDEN_ROUTE`。
agent 的行程內簽發必帶任務 id，使用與 HTTP 相同的簽發閘序；這不是額外公開端點。
連線成功在 session 保存 `access_request_id`。撤銷僅終止本系統代理會話，不終止目標端已脫離會話的背景程序。

**允許來源網段**：簽發端也判來源，位置在角色現查之後、請求綁定之前——只依主體判定，
不需要資產，也就不對「來源不對」的請求洩漏資產是否存在或有無授權。
不落清單回 **403 ＋ `{code: "AUTH_SOURCE_NOT_ALLOWED", reason: "source_not_allowed"}`**。
兩條兌換入口（`/connect`、`/ssh`）**各自現讀清單再判一次，不信簽發時的結論**：
只擋簽發側時，自允許網段簽票、換個位址兌換即成立。
`reason` 值刻意不與 `asset_disabled`／`recording_unavailable`／`approval_required`／`reason_required`
重疊，前端據此顯示「目前來源不在允許範圍」而**不彈申請框**。
**回應不回顯位址，也不回顯清單**；位址與命中的清單快照只進拒絕留痕。
清單讀不到或字串損壞時**走同一組回應值**，對外不分岔——分岔等於告訴呼叫端
「這個帳號的政策壞了」，那是探測面；成因（`read_error`／`parse_error`）只進稽核。

`account_id` 為**憑證選擇器、非授權快照**：簽發點於授權檢查之後、
政策閘之前以 `(account_id, asset_id, deleted_at IS NULL)` DB 現查客體綁定，不屬該資產或
已刪除→**404 `NOTFOUND_ASSET_ACCOUNT`**（不區分「不存在」與「屬於他資產」，避免成為帳號探測器）；
K8s 資產固定單一預設帳號，帶 `account_id`→**400 `RULE_ACCOUNT_K8S_DEFAULT_ONLY`**。
兌換點（`/ssh`、`/connect`）以同一條件重查後才取憑證：帳號於簽發後被刪除者兌換即拒
（404 `NOTFOUND_ASSET_ACCOUNT`），**絕不靜默退回預設帳號**。連線成功的 session 記錄
`account_id` 與連線當下的 `account_username` 雙快照，帳號日後改名／刪除不改寫歷史。

### 會話即時監看（內建超級管理者與稽核員範本）

兩段式：先以登入憑證換一張一次性觀看票，WebSocket 只收該票。

```
POST /api/v1/sessions/:id/monitor-token        # Authorization: Bearer <jwt>
→ {"connect_token": "...", "expires_in": 60}

GET /api/v1/sessions/:id/monitor?connect_token=<觀看票>
Upgrade: websocket
```

- 准入判定在簽發端：僅內建超級管理者與稽核員範本（403 否則，角色以現時有效角色判定，不採信憑證內的角色
  快照）；僅進行中的文字終端會話可監看（400 否則）；目標不存在回 404
- 觀看票短效、單次、綁定簽票者與目標會話；兌換即失效。缺票、無效票、過期票、重放票，
  以及用途或客體不符的票一律回 **401 `AUTH_CONNECT_TOKEN_INVALID`**（缺票為
  `AUTH_CONNECT_TOKEN_MISSING`），拒絕原因只進稽核、不對外分流
- 唯讀：觀察者輸入一律忽略；斷線不影響被監看會話
- 會話剛結束的競態：回 `{"type": "error", "data": "會話已結束"}` 後關閉

### 會話分享

| 方法 | 路徑 | 說明 |
|---|---|---|
| POST | `/sessions/:id/share` | 會話本人建立分享碼（JWT）；body: `{"ttl_minutes": 10}`（1-60，預設 10；再建立即覆蓋舊碼）→ `{"code": "...", "share_path": "/share/<code>", "expires_at": "..."}` |
| DELETE | `/sessions/:id/share` | 撤銷分享（JWT；無有效分享回 404） |
| POST | `/sessions/share/token` | 任何已登入用戶以分享碼換一次性觀看票（JWT）；body: `{"code": "..."}` → `{"connect_token": "...", "expires_in": 60}`。碼走請求本體而非路徑——請求路徑會進入操作日誌，而分享碼是短期憑證 |
| GET | `/sessions/share/:code/ws?connect_token=<觀看票>` | 持票加入唯讀觀看（WS）；加入與拒絕皆留痕 |

**建立／撤銷錯誤**：POST與DELETE在會話不存在或非本人時，皆回404 `{"code":"NOTFOUND_SESSION","error":"Session 不存在"}`，本文僅這兩欄，相關標頭相同；admin／auditor對他人會話也不豁免。拒絕先於在線或分享狀態判斷，不建立、替換或撤銷分享；畫面沿用會話不存在文案，不提示擁有者資格。本人通過資格後，POST非活躍會話仍400 `RULE_SESSION_SHARE_NOT_ACTIVE`；DELETE無有效分享仍404 `NOTFOUND_SESSION_SHARE`，成功仍200 `{"revoked":true}`。

觀看票綁定簽票者與該分享碼，短效且單次；分享碼的有效性於加入時判定，簽票後才失效或
被撤銷者加入回 404。票證相關的拒絕與監看同形（401，成因只進稽核）。

會話結束時分享自動撤銷。

### 會話即時指標

```
GET /api/v1/ssh/sessions/:id/stats
Authorization: Bearer <token>
```

**授權**: 會話本人或 admin/auditor。會話不存在或不具上述資格時皆回404 `{"code":"NOTFOUND_SESSION","error":"Session 不存在"}`，本文僅這兩欄，相關標頭相同，不揭露是否在線或採集能力；前端沿用會話不存在文案。通過資格後，非活躍會話仍回404 `RULE_SESSION_NOT_ONLINE`（`會話不在線上`）。
僅 SSH 會話支援（DB CLI/K8s 無 SSH channel）；目標主機需支援 `/proc`（否則 502）。

**回應** (200，`SessionStats`；counters 為原始值，CPU%/網速由前端兩次輪詢差分):
```json
{
  "hostname": "server1",
  "uptime_sec": 12345.67,
  "load1": 0.5, "load5": 0.4, "load15": 0.3,
  "mem_total_kb": 8000000, "mem_avail_kb": 4000000,
  "cpu_busy": 12345, "cpu_total": 67890,
  "net_rx_bytes": 1024, "net_tx_bytes": 2048
}
```

---

## 功能開關

以下功能可透過環境變數控制（`backend/config/config.go`）：

| 功能 | 環境變數 | 程式碼預設 | 說明 |
|------|----------|--------|------|
| 稽核日誌 | `FEATURE_AUDIT_LOG_ENABLED` | true | API 操作記錄；關閉時 `/audit-logs` 端點不註冊 |
| 異步寫入 | `FEATURE_ASYNC_AUDIT_ENABLED` | true | 異步日誌寫入 |
| 檔案降級 | `FEATURE_AUDIT_FALLBACK_TO_FILE` | true | 寫庫失敗時寫入檔案 |
| 異常偵測 | `FEATURE_ANOMALY_DETECTION_ENABLED` | false | 連線異常偵測 |
| 告警系統 | `FEATURE_ALERTING_ENABLED` | false | 告警通知 |

**其他環境變數**:

| 環境變數 | 預設 | 說明 |
|----------|------|------|
| `RECORDING_PATH` | `/var/lib/custodexa/recordings` | 錄影儲存目錄 |
| `SSH_IDLE_TIMEOUT_MINUTES` | 60 | **僅首次啟動播種政策 `session_idle_minutes`**；之後以政策為準（0＝停用） |
| `SSH_MAX_SESSION_MINUTES` | 0（不限） | 文字終端最大會話時長（同上，播種 `session_max_minutes`） |
| `RECORDING_RETENTION_DAYS` | 未設＝不播種 | 僅首次啟動播種政策 `retention_recording_days`（政策自身出廠值 90） |
| `AUDIT_LOG_PATH` | `logs/audit_fallback`（相對路徑） | 稽核寫庫失敗時的降級檔案目錄；compose/生產以掛載卷指定絕對路徑 |
| `KEY_ROTATION_MAX_PER_RUN` | 100000 | 單次 DEK 輪替的重加密上限 |
| `RETENTION_MAX_PER_RUN` | 100000 | 單次保留期清理的刪除上限 |
| `K8S_LIST_TIMEOUT_SECONDS` | 10 | K8s pod 列表逾時（秒） |
| `CORS_ALLOWED_ORIGINS` | 空 | 逗號分隔允許來源；release 模式未設＝僅允許同源 |
| `ADMIN_INITIAL_PASSWORD` | 無預設 | **全新空 DB 必須設定合格值**（>=12 bytes、非預設/placeholder、無前後空白、無換行或控制字元；**中間空白允許**），未設或不合格即 `log.Fatal` 拒絕啟動（不因 dev/release 放寬）；既有 DB 不需要此值，僅在仍留著**合格**值時記警告提醒移除（不合格值於既有 DB 靜默忽略） |
| `LDAP_*` | 見認證 API 一節 | LDAP 認證設定 |

## Agent 稽核、任務報告與熔斷控制

所有路徑以下省略 `/api/v1`。HTTP 連線四入口仍拒 agent；agent 的任務兌換走同一行程內服務，須帶已認證主體與 access_request_id。

| 方法／路徑 | 資格與行為 |
|---|---|
| GET `/agent-tool-calls` | `audit:integrity_view`；查詢 user_id、access_request_id、from／to（RFC3339）、decision、offset／limit。回 `{data,total}`，含 result_digest／result_excerpt／masked_count；另由會話投影 `asset_name`／`account_username`（唯讀，會話外的呼叫或無資產的會話留空）；decision=pending 表示已記錄，是否送出與結果皆未知，非成功（契約 §9.13）。|
| GET `/agent-tool-calls/:id/arguments` | `audit:view`；query `reason` **必填**（1–1000 bytes，空白視同缺漏 → 400 `VALIDATION_BAD_PARAMS`）。回 `{data:{id, session_id, access_request_id, arguments}}`，`arguments` 為該列參數的**未遮罩原文**物件（憑證欄仍為指紋）；回應帶 `Cache-Control: no-store`。500 `INTERNAL_TOOL_CALL_ARGUMENTS`（解密失敗、稽核不可用等，原因只進伺服器 log 與告警鏈）。伺服器端**先寫調閱稽核列**（action `agent_tool_call_args_viewed`，details 含帳本列 id、會話、任務、理由）**再解密交付**；稽核寫入不可用即拒絕並回收斂錯誤（fail-close）。列不存在、或該列沒有加密原文（參數未命中機敏規則、或本版本前寫入）一律 404 `NOTFOUND_TOOL_CALL_ARGUMENTS`，不可用回應差異探測某列是否含機敏。agent token 一律 403。政策 `alert_on_sensitive_reveal` 開啟時另發 `sensitive_reveal` 告警（見告警 API）。|
| POST `/access-requests/:id/reports` | 任務原執行 agent 提交 `{body}`，201 回不可變的新版本；任務關閉後 24 小時內可補交／修訂；時鐘以持久化 closed_at 為準。人類或其他 agent 為 403、超窗 409、本文錯誤 400。|
| GET `/access-requests/:id/reports` | admin／auditor、原執行者、申請者或執行者當前owner；成功200回 latest、versions、closed_at、missing_report_at_close，無報告仍為200空版本列表。任務不存在或無讀取資格皆404 `{"code":"NOTFOUND_ACCESS_REQUEST","error":"申請單不存在"}`，本文僅這兩欄且相關標頭相同，不回版本、缺報告或執行者資訊；前端沿用申請單不存在文案。關閉時沒有版本即缺報告，後續補交不改該事實。此GET拒絕不改上列POST的400／403／409與作者限制。|
| GET `/access-requests/history` | 即時有效審核者 OR auditor。auditor 跨範圍唯讀；其他審核者維持原核准範圍。approve／reject／revoke／review 沿原資格，純 auditor 仍 403。|
| POST `/users/:id/agent-breaker/release` | owner 或超級管理者，必填 `{reason}`（API 上限 1000 字元，服務層另限制 1000 bytes）；成功 204，原因入稽核。清除未處置旗標，不復活已停用 token；須重新核發。錯誤：400 `VALIDATION_BAD_PARAMS`（reason 缺漏、空白或超長）、403 `AUTH_PERMISSION_DENIED`（非 owner 亦非 admin、呼叫者非人類、或目標非 agent 主體）、409 `CONFLICT_AGENT_BREAKER_NOT_PENDING`（該主體目前沒有待處置熔斷——此端點只清旗標，沒有旗標即無事可清）。|

**帳本參數留存規則**（`args_redacted`）：帳本逐字保存執行者送入的參數原文——`run_command` 的指令、`query` 的 SQL、`send_keys` 的按鍵、`close_task` 的報告、各工具的任務／資產／帳號識別與理由——被拒絕與被阻斷的呼叫尤其如此，那是稽核者判讀異常的唯一依據。兩個例外：能力句柄 `session_handle` 以 `fp:` 前綴的不可逆指紋取代（同句柄各列指紋一致，可關聯不可還原）；參數命中輸出面敏感資料規則（卡號、私鑰等）的片段在 `args_redacted` 內以固定標記取代並計入 `masked_count`，原文另以靜態加密留存於 `args_sealed`，只能經上表 `GET /agent-tool-calls/:id/arguments` 帶理由取得。每列另帶 `args_retained`（bool）：本規則前寫入的列為 `false`，其參數當時被整欄遮罩、原文已不存在，呈現面標「未留存」而非遮罩標記。`args_sealed` 不進列級 HMAC 與檢查點鏈，其完整性由加密 AEAD 標籤保證；證據包匯出 `args_redacted` 與 `args_retained`，不匯出 `args_sealed`。

被阻斷的 `run_command`：執行者收到阻斷機器碼與規則名；該工作階段的錄影在阻斷標記後另有一行被攔下的指令原文（人類會話因逐字回顯已留痕，錄影標記不變）；指令稽核（`session_commands`）維持只記已送出的指令，被擋的指令以告警列（`blocked=true`）與帳本列（decision=denied）留痕。

任務報告每版以任務 id、版本與 body_hash 寫專屬稽核列，HTTP 稽核不複製正文。申請端點的 reason 與核准／駁回／撤銷／補審端點的 note 僅在端點專屬遮罩集放行；憑證鍵仍遮蔽。報告／熔斷通知沿既有 webhook／Slack 推送並帶 owner_id，沒有新增個人收件匣或送達保證。

會話詳情帶 access_request_id、agent_token_id、actor_kind、on_behalf_of_user_id、owner_user_id、revoked_during_session_at。主體快照取建線當下；人類會話的原欄位保持原值，新快照欄為可空。撤權後收線記獨立事件。

agent 會話的列表與詳情另投影兩個唯讀名稱欄：`owner_username`（快照 owner_user_id 的目前帳號名）與 `on_behalf_of_username`（快照 on_behalf_of_user_id 的目前帳號名，即這次連線替誰做）。兩者非欄位、非歷史快照，主體已刪時該鍵不出現（`omitempty`）；人類會話不帶這兩個鍵。詳情與列表走同一組投影，兩處顯示一致。

範圍外引用的對外回應皆為相同 404；目標不存在或軟刪為 retired，有 exposure 為 revoked，其餘為 never_visible。只計 never_visible，主體內同一 id 每窗一次，政策鍵 `agent_probe_trip_count=3`／`agent_probe_window_seconds=300`。

**這道計數的涵蓋範圍要先看清楚**：跳閘門檻只數 never_visible，也就是**目標資產確實存在、但從未對該主體曝光過**的引用。對外回應雖然三類相同，但列舉不存在的資產 id（含已軟刪者）歸 retired、有過曝光紀錄者歸 revoked，兩者都**不累計、不會跳閘**，僅留事件列供查。因此「以遞增 id 掃描」這種最常見的探測形態，只要掃到的 id 多半不存在，就不會撞上這道熔斷。它防的是「拿真實但不該看到的資產反覆試」，不是通用的 id 掃描偵測；要涵蓋後者請另配告警規則與速率政策。事件列的 `class` 欄即為此三分類，可用 `GET /users/:id/agent-breaker/events` 逐筆核對。跳閘停該 token、失效其已換出憑證與既有會話，主體標未處置；其間發證回 409 `RULE_AGENT_BREAKER_PENDING`。告警 `kind=agent_breaker_tripped` 可無會話（session_id=null）；既有會話告警仍回數值 session_id。曝光紀錄自升級起累積，不回推升級前歷史，詳見升級 SOP。

工作台 timeline 與證據包 manifest 的 command coverage 共用完整性來源：同樞紐、半開時間窗 `[from,to)` 的留存 `input_without_command` 降級列。存在時新增 `incomplete=true` 與 `degraded_count`；零列時省略，既有欄位保持一致。此軸與 present／purged／not_retained 保留期三態並存；不含已清除列，也不證明原指令從未遺漏。無樞紐的舊式 session 匯出仍不提供 coverage。

agent 種子是指令文字規則，只涵蓋可列舉形態，無法窮舉寫檔、別名或其他工具的等效操作；仍需任務範圍與報告對照，不代表操作面已受完整控制。

檢查點新章採 v3，舊 v1／v2 照原載荷驗證。工具帳本區間列數、id 範圍與不可變第一階段聚合進鏈；第二階段結果由逐列 HMAC 保護，不進鏈聚合。pending 列可在封章後完成，驗證仍須檢查三層；持有 HMAC 鑰者能偽造結果欄，不能把列級結果驗證說成鏈對結果的承諾。

### Agent UI 唯讀增量契約

以下沿既有 AuthMiddleware，未登入回 401。新增端點與既有禁用端點對 agent token 回 403；admin／auditor 的跨主體稽核權限是明示權限，普通 human 不能藉他人 id 取得資料。既有 POST `/access-requests` 與 GET `/access-requests/mine` 沿原 agent 允許清單。

| 端點 | 性質／所需角色 | 增量契約 |
|---|---|---|
| GET `/agent-tasks` | 唯讀；`audit:view` | `subject`、`owner` 為正整數主體／目前負責人 id；`from`／`to` 為 RFC3339 建立時間半開窗；`report_status=submitted|missing|not_submitted`。offset 預設 0、limit 預設／上限 100（0 或超限收斂為 100，負值回 400）。回 `{data,total}`；列含 id、subject、username、owner_user_id、owner_username、on_behalf_of_username、reason、status、report_status、created_at、closed_at；reason 為申請理由的唯讀投影，供列表直接呈現任務主旨；on_behalf_of_username 為申請人帳號名（agent 自行開單時為空字串），供列表答出「替誰做」。submitted=有報告版本；missing=已關閉但沒有任何版本；not_submitted=尚未關閉且沒有版本，不取代報告 API 的 missing_report_at_close。owner 是目前主體關聯，非歷史快照。 |
| GET `/agent-tasks/:requestId` | 唯讀稽核；`audit:view` | 回 `{request,approval_total,session_ids,session_total,reports:{versions,total,closed_at,missing_report_at_close}}`。request 為 agent 申請單、最多 20 項、executor 投影與原核准註記；`executor_user_id` 一律帶有效執行者（agent 自行開單時申請人即執行者，此欄回申請人 id，不回 null——儲存欄位本身不變）；每項另投影 `decided_by_username`（決定者帳號名，自動核准無決定者故留空）與 `requested_accounts`（申請當時的帳號範圍，核准縮限前已留存於 policy_snapshot；未留存的舊項回 null）；每張核准票另投影 `approver_username`（核准者目前帳號名，唯讀、非快照）；核准註記另用 approval_offset（預設 0）、同 limit 分頁，approval_total 為全部票數；session_ids 與 reports.versions 共用 offset／limit（預設／上限 100），版本降序；缺報告旗標按關閉時刻全版本查證，不受分頁影響。未知／人類任務 404，非法 id 400；requestId 及遮罩 query 留痕。 |
| GET `/agent-tool-calls` | 唯讀稽核；`audit:integrity_view` | 既有 query 增正整數 `session_id`，AND 合併其他條件；回應每列附會話目標投影 `asset_name`／`account_username`；保留既有 limit 預設 100、最大 500（超限回預設），敏感讀取稽核記查詢條件。 |
| GET `/users/:id/agent-breaker/events` | 唯讀稽核；admin／auditor 或該 agent 的 human owner | offset／limit 同任務列表（上限 100），from／to 為事件時間半開窗；回 `{data,total,breaker_pending_at}`。事件列為原 id、user_id、agent_token_id、asset_ref、endpoint、class、created_at，按時間與 id 降序；另投影唯讀的 `asset_name` 與 `asset_deleted`，取資產目前名稱（非事件當時快照），已移除的資產仍取得出名稱並以 `asset_deleted=true` 標示，查無該資產時 `asset_name` 為空字串。未知主體／非 owner 一律 403，避免藉 id 探測；空結果 data=[]。breaker_pending_at 只描述主體目前未處置狀態，不是逐事件解除歷史；不回推 exposure 升級前資料。此端點歸 audit_integrity，resource_id 為主體 id、無 asset pivot，GET query 留痕。 |
| GET `/users` | 唯讀；`user:manage` | 新 query `kind=human|agent` 由伺服器篩選並共用 total；明示 kind 優先 include_agents，未指定時維持原行為，非法 kind 回 400。 |
| GET `/my/agents` | 唯讀；已認證 active human 本人 | 200 加 `self_create:{enabled,max_per_owner,current}` 與布林 `self_create_enabled`；current 為目前本人名下未軟刪 agent 數，含停用主體。政策關閉不影響本端點，仍回 200 與名下清單（`self_create_enabled=false`）；受政策鍵限制的只有 POST。不洩漏他人主體或計數，不接受 owner query。 |
| GET `/access-requests/mine` | 唯讀；已認證本人，含既有 agent | 只查 requester_id=認證主體；忽略 client requester_id。回應增 executor 與項目 decision_bounds。 |
| GET `/access-requests/pending`、`/reviews/pending`、`/history` | 唯讀；原有效審核者及其範圍；history 另開 auditor 跨範圍唯讀 | 增 `executor:{id,username,kind,owner_user_id,owner_username}`（目前主體投影）及每項 `decision_bounds:{max_duration,earliest_start,accounts}`；只在原範圍查詢後附加。max_duration 是原申請分鐘，earliest_start=max(now,requested_date_start)，accounts 沿原 scope（包括 @ALL sentinel）。界線不是決定授權，不放寬角色／範圍，送出仍由原服務檢查。 |
| GET `/sessions` | 唯讀；`session:view` | 新 query `access_request_id` 為正整數，以任務關聯篩選並共用 total；帶此 query 時 page_size 上限 100，條件於 HTTP 稽核列留痕；非法 id 回 400。`actor_kind=human|agent` agent 比對已存種類；human 包含明示 human 及 kind／agent_token_id 皆 NULL 的既有人類建線形態，不改原 JSON，非法值 400。 |
| GET `/sessions`、`/sessions/:id` | 唯讀；`session:view` | agent 會話兩處均投影 `owner_username` 與 `on_behalf_of_username`（快照 user id 的目前帳號名，唯讀、非歷史快照，詳情與列表同一組投影）。新 `agent_token_name` 為建立時快照，既有會話 NULL；不 join token 現值。增量 migration 只加 sessions 一欄，既有建線交易一處賦值；Down 保留資料，停用讀寫由舊版應用承擔。 |
| GET `/audit/subjects?type=user` | 唯讀；`audit:view` | 在最小主體 DTO 增 kind 與有值時的 owner_user_id，含停用／軟刪主體供調查；資產主體不增加虛構種類。 |

`POST /access-requests` 不是唯讀端點，寫入權限與判定均不改：429 `RULE_AGENT_REQUEST_RATE` 增 `details:{used,limit,window_seconds,dimension}`（hour=3600；pending=0，表示無滾動窗）；400 `VALIDATION_ACCOUNT_NOT_ON_ASSET` 增 `details:{item_index,asset_id}`，item_index 為 **0 起算**。裸 sentinel 仍保留原碼，服務實際帳號檢查回具項目資料的 typed error；其他錯誤 envelope 欄原樣保留。

### Agent 前端路由

此處是瀏覽器頁面路由。`/audit/agent-tasks` 與 `/audit/agent-tasks/:requestId` 沿 `audit:view` 權限，列表由伺服器依主體、目前負責人、時間與報告狀態篩選；詳情依主體、授權、會話／帳本、自述報告四段呈現。核准票、會話與報告分頁讀取；缺報告依關閉時刻判定，補交不抹除事實。列表與 executor 的 owner 為目前關聯，執行當時 owner／token 名稱取會話快照。調查工作台僅 kind=agent 提供任務出口。

`/agent-breakers?user_id=<id>` 讀事件端點，admin 或 owner 可解除（包括兼任 auditor 的 owner）；其他 auditor 唯讀；列表選主體沿既有權限，普通使用者只查本人，auditor 可由主體 id 進入。never_visible 只計本頁不同目標數，並非目前時間窗的熔斷總數；token 依已存停用時間／原因呈現，無法回推歷次跳閘完整名單或通知送達。`/my-agents` 讀同端點 self_create 控制建立，政策關閉的 403 不冒稱名下為空。會話帳本用 session_id、任務帳本用 access_request_id，共用 ToolCallLedger；pending 沿契約顯示「已記錄，是否送出與結果皆未知」。

`ToolCallLedger` 共用元件以既有帳本 query（含 `session_id`）查詢與伺服器分頁，同一元件掛載於任務詳情與會話詳情兩處（前段 `GET /agent-tool-calls` 與呈現面說明）。區塊說明為「錄影保留原始畫面、帳本保留回傳摘要與雜湊」；節錄不等同全文，pending 不證明呼叫已送出。解除必填原因，且明示不復活已停用 token、熔斷當下的已換發票證與既有連線已失效。

## MCP agent channel: POST /api/v1/mcp

Authenticate with `Authorization: Bearer cxa_...` (an active agent token). Human JWTs and cookies are rejected. Streamable HTTP uses POST only; GET and DELETE are not new agent routes. Hosts that support only stdio use `custodexa-mcp`, a separate client that runs on the agent's machine and forwards to the same endpoint. Get it from https://github.com/custodexa/custodexa-mcp, either with `go install github.com/custodexa/custodexa-mcp@latest` or as a release binary verified against the `checksums.txt` published with that release. Set `CUSTODEXA_MCP_URL` and `CUSTODEXA_AGENT_TOKEN` in its environment; use HTTPS outside local development. No local grants, target connections or evidence store exist in the client.

`initialize` reports `protocolVersion` and a `serverInfo` naming **the peer you are actually talking to**, so the two transports differ: a direct HTTP connection answers `serverInfo.name: "custodexa"` with `version: "1"` (the service), while the stdio client, the forwarder in front of it, answers `serverInfo.name: "custodexa-mcp"` with its own release as `version` (for example `"1.0.0"`). Neither `version` is the version of the Custodexa server. Do not use `serverInfo` to assert which product or release is on the other end, and do not require a single value across transports; identify the deployment from its URL and its own version endpoints instead. A direct HTTP `initialize` also returns an `Mcp-Session-Id` response header that subsequent requests on that connection must carry.

The ten tools are `list_assets`, `request_access`, `check_request`, `open_session`, `close_session`, `run_command`, `send_keys`, `query`, `read_screen` and `close_task`. Discover their schemas with `tools/list`. Supply explicit per-asset `accounts` to request access, and an explicit `request_id` to open a session. Handles use `session_handle`; reset uses `key` (`ctrl-c`, `ctrl-d`, `enter`); reports use `report`. No HTTP connect-token or WebSocket route is available to agent credentials.

**Who decides a `request_access` task.** The decision is not agent-specific: each requested asset carries an access policy segment, taken from the asset's own `access_policy` when set and otherwise from the `access_policy_default` security policy. A requested item in the `approval` segment stays `pending` until a human approver with that asset in scope decides it. Items in the `open` and `reason` segments are approved at submission time and the request comes back `status: "approved"` immediately, recorded with `auto_approved: true` and a policy snapshot of `{"segment": ..., "auto_basis": ..., "required_approvals": 0}`. Under the shipped defaults most assets fall outside `approval`, so an integrator who never changes the policy will see every agent task approve itself. **To put agent tasks in front of a human, set `access_policy` to `approval` on the assets concerned, or set `access_policy_default` to `approval`**; `access_request_min_approvals` then sets how many approvals such a request needs. A request that was auto-approved has no approval votes, and `POST /access-requests/:id/approve` on it returns `409` because it has already left `pending`.

`check_request` reports `approvals_required` from the items' policy snapshots: the largest `required_approvals` among the items, which is `0` when every item was auto-approved and the configured threshold when an item is in the `approval` segment. The task detail reports the same snapshot value per item, so the two views agree on one request. `approvals_received` counts recorded approvals and is meaningful only while `status` is `pending`; read `status` first.

Four operational boundaries:

1. `completed` means a prompt was observed again; it guarantees neither termination nor success. Prompts and stale-output attribution are heuristics. `timed_out` has an unknown outcome; inspect subsequent output before retrying. Optional same-handle idempotency keys suppress repeated writes for 60 seconds, not across process restarts.
2. `read_screen` is the tail of a line buffer, not a virtual terminal screen. `needs_input` never triggers automatic interruption; the caller must request `send_keys` explicitly.
3. Agent-visible output and report text are masked; recordings and command records retain the original. Masking is rule-driven and enumerated, not a general sensitive-data filter: it applies the enabled alert rules with `direction=output` whose subject kind covers agents and whose protocol list covers the session, and it replaces each matched span with `[REDACTED]`. Anything no enabled rule matches reaches the agent in full. The shipped rule set contains two output rules (a card-number pattern and a private-key header pattern); other categories, such as password hashes or API keys, need rules of their own before they are masked or alerted on. `masked_count` on the tool-call ledger row states how many spans were replaced in that response. Attributable calls first create a pending ledger row and update that same row on completion. Unattributable task/handle calls are rejected before that ledger and recorded in the same HTTP request's audit row (principal, tool, reason, time). Pending proves recorded intent, not delivery or completion. Command coverage exists in the Investigation Workbench and batch export, not a single-session export.
4. Token expiry, bound-item expiry and task closure terminate existing sessions and in-flight tools without waiting for command completion. The 250ms sampling interval is not a completion SLA. Only system-created sessions are controlled; detached target processes may survive. Cancellation during a request closes its session; silent departure between POSTs is detected through a five-minute idle lease, not immediately. Handles cannot transfer across tokens, MCP connections, restart or takeover.

**What a block looks like.** A command that matches an enabled `action=block` input rule comes back as `{"status": "blocked", "code": "RULE_COMMAND_BLOCKED", "notices": [{"code": "RULE_COMMAND_BLOCKED"}]}` and is recorded in the tool-call ledger with `decision: "denied"`. The typed bytes are never forwarded to the target, and an interrupt byte is then written to the target to clear whatever is already in its line buffer. That interrupt is part of the mechanism, so the `output` field of a blocked response is not reliably empty: depending on the target's shell and echo settings it can contain `^C` and a fresh prompt, and the same `^C` appears at that point in the recording. **A `^C` next to a blocked command is the platform clearing the line, not an operator pressing Ctrl-C**; the blocked command's own text never reaches the target, so no interpretation of it is needed. Reviewers should read the accompanying alert row (`blocked: true` plus rule identity) rather than the terminal text, and the recording carries a standalone marker line containing `[RULE_COMMAND_BLOCKED]` and the rule name, in a fixed server-side format, so it stays greppable across viewer locales. If that line-clearing write fails, the session is terminated rather than continued, so that no fragment of a blocked command can be completed by a later Enter.

Terminal recovery fields are structured: `needs_input` includes `recovery: {tool: "send_keys", key: "ctrl-c", automatic: false}`; a confirmed reset includes `reset: true` and `next_action: "run_command"`. A stale running response includes `dispatched: false` and `next_action: "observe_or_send_keys"`. These fields describe local observations and available actions, not a guarantee about the remote process.
