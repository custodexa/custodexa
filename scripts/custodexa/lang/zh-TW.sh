# shellcheck shell=bash disable=SC2034
# custodexa.sh 訊息，繁體中文。鍵集與 en.sh 相同（測試檢查）。
# 每則是 printf 格式；引號內換行就是畫面上的換行。每行不超過 73 欄（help_* 為 80），
# 前面加上狀態標記也不超過 80。
MSG_platform_not_linux='custodexa.sh 只支援 Linux（這台主機回報 %s）。
要在這台電腦上試用 Custodexa，請改用原始碼中的 scripts/quickstart.sh。'
MSG_root_home_invalid='CUSTODEXA_HOME=%s 不是 Custodexa 部署目錄
（裡面沒有 state.json，也沒有 releases/）。'
MSG_root_not_found='無法判斷這個腳本屬於哪個部署目錄（%s）。
請在部署目錄內執行，或設定 CUSTODEXA_HOME。'
MSG_root_path_chars='部署目錄 %s 含有不允許的字元。
只能使用英文字母、數字與 . _ / -（不能有空白或引號）。沒有做任何變更。'
MSG_images_env_bad_line='%s 第 %s 行不是 CUSTODEXA_IMAGE_<名稱>=<映像參照> 的格式。
沒有啟動任何服務。'
MSG_overlay_unknown='state.json 記載了不認得的部署形態「%s」。'
MSG_state_bad='狀態檔 %s 在第 %s 行格式不符。沒有做任何變更。'
MSG_state_bad_prev='前一版在 %s。請先檢查內容，確認無誤後用下面的指令還原：'
MSG_usage_unknown_command='不認得的子命令「%s」。請見：custodexa.sh --help'
MSG_usage_unknown_option='不認得的選項「%s」。請見：custodexa.sh --help'
MSG_usage_missing_value='選項 %s 需要一個值。'
MSG_usage_images_from_value='不認得的映像來源「%s」；請選 auto 或 source。'
MSG_usage_images_from_command='--images-from 只適用於 install 或帶目標的 upgrade。'
MSG_usage_images_from_conflict='--images-from source 不可與 --images 同時使用。'
MSG_legacy_refused='這是舊版 git clone 部署，custodexa.sh 無法在此目錄安裝或升級。
沒有變更部署檔案或服務。

請先確認備份與部署設定，再依「升級操作程序」中的舊原始碼部署
手動遷移說明處理；或在另一個乾淨目錄安裝安裝包，再依
「備份與還原」程序手動還原。不要在現有資料目錄直接執行 install。'
MSG_command_not_in_build='這個版本的腳本沒有「%s」子命令。'
MSG_lock_busy='這個部署已有另一個 custodexa.sh 正在執行（PID %s）。請等它結束。'
MSG_run_interrupted='上次的 %s 在第 %s 步中斷。'
MSG_run_install_rerun='install 可以安全重跑，從第一步重新開始。'
MSG_run_recover_first='請先處理上次的中斷。查看狀態與紀錄檔：'
MSG_run_recover_install='請先完成上次的 install，它可以安全重跑：'
MSG_run_load_rerun='load 只載入與比對映像，可以安全重跑。'
MSG_run_signal='在第 %s 步被中斷，沒有復原任何動作。接下來請執行：'
MSG_confirm_needs_yes='這一步需要確認，但目前沒有終端機可以詢問。請加上 --yes 重新執行。'
MSG_log_initial_password='已產生（不記錄值）'

# ---- --help。子命令說明沿用同一組段落。 ----
MSG_help_title='Custodexa 管理腳本 %s'
MSG_help_usage='用法：custodexa.sh <子命令> [選項]'
MSG_help_commands='子命令'
MSG_help_cmd_install='  install              第一次安裝：檢查主機、產生設定、取得映像、啟動'
MSG_help_cmd_upgrade='  upgrade              查詢有沒有新版（不做任何變更）
  upgrade <版本>        下載並升級到指定版本（會停機、會先備份）
  upgrade <安裝包路徑>  用已下載的安裝包升級（離線可用）'
MSG_help_cmd_status='  status               顯示版本、服務、備份與上次升級的狀態（不做任何變更）'
MSG_help_cmd_backup='  backup               完整備份（會暫停服務約十幾分鐘）'
MSG_help_cmd_load='  load <離線包>         載入離線映像包（不啟動服務）'
MSG_help_options='選項'
MSG_help_opt_yes='  --yes                不詢問確認，自動化時使用'
MSG_help_opt_backup_ref='  --backup-ref <識別>  （upgrade）已自行備份，填入快照名稱，腳本不再備份'
MSG_help_opt_backup_time='  --backup-time <時間> （upgrade）與 --backup-ref 並用：快照開始時間，須晚於停機'
MSG_help_opt_backup_restore='  --backup-restore <位置>（upgrade）與 --backup-ref 並用：還原程序的文件位置'
MSG_help_opt_images='  --images <路徑>      （install、upgrade）指定離線映像包'
MSG_help_opt_images_from='  --images-from <模式> （install、帶目標的 upgrade）auto 或 source；
                       預設 auto；source 從安裝包原始碼建置自家映像'
MSG_help_opt_lang='  --lang <語言>         zh-TW、ja、en；見下方「顯示語言」'
MSG_help_opt_no_color='  --no-color           不使用顏色'
MSG_help_opt_version='  --version            顯示腳本版本'
MSG_help_opt_help='  -h, --help           顯示說明；custodexa.sh <子命令> --help 只顯示該子命令'
MSG_help_footer='部署目錄是本腳本所在的目錄；要指定別處，設定環境變數 CUSTODEXA_HOME。
每次執行的紀錄在 <部署目錄>/logs/。
詳細程序見「部署與升級 SOP」與「備份與還原」。'
MSG_help_language='顯示語言
  畫面語言依系統語系（LC_ALL、LC_MESSAGES 或 LANG）；sudo 常會重設語系，
  畫面就會是英文。要指定語言，加上 --lang（帶不帶子命令都可以）：
    custodexa.sh --lang zh-TW          繁體中文
    custodexa.sh --lang ja             日本語
    custodexa.sh --lang en             English
  或在 sudo 下保留系統語系：
    sudo env LANG=zh_TW.UTF-8 custodexa.sh'

# ---- 發行清單、安裝標題、時間 ----
MSG_manifest_missing='找不到發行清單 %s。安裝包可能不完整，請重新下載。'
MSG_manifest_bad='發行清單 %s 在第 %s 行格式不符，無法讀取。安裝包可能損壞，請重新下載。'
MSG_install_title='Custodexa %s 安裝    部署目錄 %s'
MSG_dur_s='%s 秒'
MSG_dur_ms='%s 分 %02d 秒'

# ---- 第 1 步：檢查這台主機 ----
MSG_step_preflight='檢查這台主機'
MSG_pre_docker_ok='Docker %s、Compose %s'
MSG_pre_docker_down='連不到 Docker：%s'
MSG_pre_docker_perm='沒有使用 Docker 的權限'
MSG_pre_compose_missing='找不到 Docker Compose v2（需要 %s 以上）'
MSG_pre_compose_old='Docker %s、Compose %s 太舊（需要 %s 以上）'
MSG_pre_arch_ok='架構 %s'
MSG_pre_arch_bad='不支援的架構 %s（只支援 x86_64 與 aarch64）'
MSG_pre_openssl_missing='找不到 openssl（產生密碼與金鑰需要它）'
MSG_pre_existing_state='這個目錄已安裝 Custodexa %s'
MSG_pre_existing_git='這個目錄是 git clone 部署'
MSG_pre_existing_container='這台主機已有 custodexa-backend 容器，不是這次安裝建立的'
MSG_pre_ports_ok='對外埠 %s 沒有被使用'
MSG_pre_port_busy='對外埠 %s 已被使用：%s'
MSG_pre_ports_unchecked='沒有 ss 也沒有 lsof，未檢查對外埠 %s'
MSG_pre_holder='%s（pid %s）'
MSG_pre_holder_unnamed='不明程序（以 root 執行才看得到是誰）'
MSG_pre_holder_container='%s，替容器 %s 轉送'
MSG_pre_list_sep='、'
MSG_pre_disk='磁碟可用 %s GB（至少需要 %s GB）'
MSG_pre_disk_root='部署目錄所在磁碟可用 %s GB（至少需要 %s GB）'
MSG_pre_disk_unknown='讀不到 %s 的可用空間，未檢查'
MSG_pre_not_writable='無法寫入部署目錄 %s'
MSG_pre_nothing_changed='沒有做任何變更。'
MSG_text_pre_port='對外埠 %s 已被 %s使用。請先請主機管理者處理埠衝突，
再重新執行：'
MSG_text_pre_port_change='若要改用其他埠，請先確認 %s/.env 已存在並完成設定，
再把 TLS_HTTPS_PORT 和 TLS_HTTP_PORT 改成沒人用的埠（常用 8443 和
8088）。改了之後，使用者要輸入的網址會帶埠號，例如
https://%s:8443'
MSG_text_pre_port_change_ingress='若要改用其他埠，請先確認 %s/.env 已存在並完成設定，
再把 HTTP_PORT 改成沒人用的埠。'
MSG_text_pre_docker_perm='請以 sudo 執行，或把這個帳號加入 docker 群組。'
MSG_text_pre_sudo='請以有權寫入部署目錄的帳號執行，例如：'
MSG_text_pre_existing='這台主機已有部署，install 不會覆蓋它。查看狀態或升級請用：'

# ---- 設定檔 .env ----
MSG_env_compose_file_bad='.env 的 COMPOSE_FILE=%s 不是這個安裝包的部署形態。
請改成 current/compose.yml（外部入口或外部資料庫再以 : 接上對應的檔）。'
MSG_env_project_bad='.env 的 COMPOSE_PROJECT_NAME=%s，這個部署固定用 %s。請改回後重跑。'
MSG_env_kek_bad='.env 的 KEK_PROVIDER=%s 不是 env、ui、kms、hsm 之一。請先修正。'
MSG_env_db_external='已設定外部資料庫（EXTERNAL_DB_HOST），DB_PASSWORD 卻是空的或範本值。
請在 %s 填入該資料庫帳號的密碼後重跑（沒有產生任何值）。'

# ---- 第 3 步：取得程式映像 ----
MSG_step_images='取得程式映像'
MSG_img_order='依序嘗試：這台主機 → 離線包 → GHCR → Docker Hub → 用原始碼建置'
MSG_img_source_mode='映像來源：從安裝包內原始碼建置；上游映像另行取得'
MSG_img_source_check='正在核對安裝包內原始碼的校驗和…'
MSG_img_source_ok='原始碼校驗和與發行清單相符'
MSG_img_wait_local='正在檢查這台主機的 %s…'
MSG_img_wait_bundle_check='正在核對離線映像包 %s…'
MSG_img_wait_bundle_load='正在載入離線映像包 %s…'
MSG_img_wait_registry='正在取得 %s（來源：%s）…'
MSG_img_wait_digest='正在核對 %s 的內容摘要…'
MSG_img_wait_build='正在用原始碼建置 %s；首次建置可能需要數分鐘…'
MSG_img_wait_fallback='GHCR 失敗（%s），改試 Docker Hub'
MSG_img_head_own='%s %s'
MSG_img_head_upstream='%s %s（上游 %s）'
MSG_img_and=' 與 '
MSG_img_local_absent='這台主機：還沒有這個版本'
MSG_img_local_ok='這台主機：已有，內容摘要相符'
MSG_img_local_mismatch='這台主機：%s 的內容摘要不符，不使用'
MSG_img_offline_none='離線包：沒有找到 %s
（找過 %s）'
MSG_img_offline_absent='離線包：裡面沒有這個映像'
MSG_img_offline_bad='離線包 %s 不使用：
%s'
MSG_img_offline_ok='離線包 %s
已載入，內容摘要與發行清單相符'
MSG_img_bundle_unreadable='讀不到離線包的 index.json 或 manifest.json'
MSG_img_bundle_manifest_bad='%s 的 manifest 內容與它的摘要不符'
MSG_img_bundle_config_bad='%s 的設定摘要與發行清單不符'
MSG_img_bundle_no_sums='%s 裡沒有 SHA256SUMS，無法核對校驗和'
MSG_img_bundle_not_listed='SHA256SUMS 沒有列出這個離線包'
MSG_img_bundle_sum_bad='校驗和與 SHA256SUMS 不符；檔案可能下載不完整或損壞，請重新下載'
MSG_img_bundle_load_failed='docker load 失敗（完整輸出在紀錄檔）'
MSG_img_bundle_id_bad='載入後 %s 的映像 ID 與載入前核對的不同。
檔案可能下載不完整或損壞，請重新下載'
MSG_img_try_failed='%s %s：%s'
MSG_img_switched='，
已改從 %s 取得並核對內容'
MSG_img_reason_timeout='連線逾時（30 秒）'
MSG_img_reason_notfound='找不到這個版本'
MSG_img_reason_other='失敗（%s）'
MSG_img_pulled_own='%s %s
已下載，內容摘要與發行清單相符'
MSG_img_pulled_up='%s %s 已下載'
MSG_img_pulled_mismatch='%s %s 下載後的內容摘要不符，不使用。
檔案可能下載不完整或損壞，請重新下載'
MSG_img_build_note='用原始碼建置需要能連到 Go 模組、npm 與基底映像的來源，
第一次約 5 到 10 分鐘'
MSG_img_build_source_bad='用原始碼建置：原始碼與發行清單的校驗和不符。
檔案可能下載不完整或損壞，請重新下載；不會建置'
MSG_img_build_failed='用原始碼建置失敗（完整輸出在紀錄檔）'
MSG_img_build_ok='用原始碼建置 %s
已建置（本機產物，沒有發行者簽章）'
MSG_img_none='%s：每個來源都失敗，無法取得'
MSG_img_running_bad='%s 執行的映像 %s 不是剛取得的 %s'
MSG_step_images_done='取得程式映像（%s 個，%s）'
MSG_ver_all='校驗和、簽章、出處證明都已驗證'

# ---- 發行者驗證（未驗時的確認畫面） ----
MSG_trust_title='這次只確認了檔案沒有損壞，沒有確認發行者'
MSG_trust_row_checksum='校驗和     安裝包與映像和發行清單一致'
MSG_trust_label_sig='發行者簽章 '
MSG_trust_label_prov='建置出處   '
MSG_trust_verified='已驗證'
MSG_trust_no_cosign='這台主機沒有安裝 cosign'
MSG_trust_no_gh='這台主機沒有安裝 gh'
MSG_trust_offline='離線，連不到簽章服務'
MSG_trust_gh_login='gh 尚未登入（gh auth login）'
MSG_trust_local_build='用原始碼建置的映像沒有發行者簽章'
MSG_trust_mf_unverified='離線包旁的發行清單未經驗證（%s）'
MSG_trust_pkg_unverified='安裝包簽章未驗證（%s）'
MSG_trust_mf_no_sig='旁邊沒有 SHA256SUMS.sigstore.json'
MSG_trust_mismatch='簽章不符，來源未經證實'
MSG_trust_prov_mismatch='建置出處不符，來源未經證實'
MSG_ver_sig_mismatch='簽章不符，來源未經證實'
MSG_ver_prov_mismatch='建置出處不符，來源未經證實'
MSG_text_trust_explain='  校驗和確認檔案內容與發行清單一致，來源仍未經證實。若單位要求
  驗證來源，請另外核對下列完整摘要：'
MSG_trust_recorded='  驗了哪幾層會寫進紀錄檔。'
MSG_ver_sig_only='校驗和、簽章已驗證，未驗出處證明'
MSG_ver_checksum_only='已核對校驗和，未驗發行者'
MSG_usage_extra_args='多了一個參數「%s」。請看：custodexa.sh --help'

# ---- install：第 2、4 到 7 步與收尾 ----
MSG_step_env='產生設定檔 .env'
MSG_env_item_jwt='登入簽章金鑰'
MSG_env_item_kek='主金鑰'
MSG_env_item_db='資料庫密碼'
MSG_env_item_admin='初始管理者密碼'
MSG_env_item_sep='、'
MSG_env_item_last='、'
MSG_env_generated='%s已產生'
MSG_env_generated_none='沒有產生新值，沿用 .env 既有的設定'
MSG_env_kek_ui='主金鑰模式：網頁輸入（不寫入伺服器磁碟）'
MSG_env_kek_env='主金鑰模式：設定檔（ENCRYPTION_KEY，存於 .env）'
MSG_env_kek_kms='主金鑰模式：外部金鑰保管服務（KMS）'
MSG_env_kek_hsm='主金鑰模式：硬體安全模組（HSM）'
MSG_env_url='網址：%s（要改請編輯 .env 的 PUBLIC_BASE_URL）'
MSG_step_recordings='準備錄影目錄（權限 1000:0 2770）'
MSG_install_recordings_failed='無法設定 %s 的擁有者與權限
（docker 的輸出在紀錄檔）'
MSG_install_recordings_mode='%s 目前是 %s，不是 %s'
MSG_step_start='啟動服務（執行中的映像就是剛取得的映像）'
MSG_install_up_failed='啟動服務失敗（完整輸出在紀錄檔）'
MSG_step_ready_wait='等待服務就緒'
MSG_step_ready='等待服務就緒（後端版本 %s）'
MSG_install_not_ready='後端在 %s 秒內沒有回報就緒'
MSG_install_not_ready_hint='服務維持啟動。原因寫在後端的紀錄；拒絕啟動時會寫出是哪個設定、
為什麼：'
MSG_install_version_bad='後端回報的版本是 %s，不是 %s'
MSG_step_done='完成'
MSG_install_stopped='安裝停在第 %s 步，已完成的部分都保留。處理上面的問題後重新執行
（已完成的步驟會安全地再做一次）：'
MSG_install_log='紀錄檔：%s'
MSG_install_declined='已依你的選擇停止，沒有啟動任何服務。確認發行者後重新執行：'
MSG_done_title_setup='安裝完成。接下來請用瀏覽器完成初始化。'
MSG_done_title_login='安裝完成。接下來請用瀏覽器登入。'
MSG_done_address='網址      %s'
MSG_done_account='帳號      admin'
MSG_done_password='密碼      %s'
MSG_done_password_where='（也寫在 %s 的 ADMIN_INITIAL_PASSWORD）'
MSG_done_password_kept='密碼      %s 裡 ADMIN_INITIAL_PASSWORD 的值'
MSG_done_ui_1='第一次開網址會進入「主金鑰初始化」頁。主金鑰在瀏覽器
產生；Custodexa 不會把它存到伺服器的磁碟，請自行妥善
保存。之後每次重新啟動，都要有人在解封頁輸入它，系統
才會開始服務。'
MSG_done_ui_2='用上面的帳號密碼授權初始化，再登入。第一次登入會要求改密碼；
改完後請把 .env 裡的 ADMIN_INITIAL_PASSWORD 那一行刪掉。'
MSG_done_login='用上面的帳號密碼登入。第一次登入會要求改密碼；
改完後請把 .env 裡的 ADMIN_INITIAL_PASSWORD 那一行刪掉。'
MSG_done_kms_1='第一次開網址會進入解封頁。請用上面的帳號密碼驗證，再提供
金鑰保管服務的憑證；系統解封後才會開始服務。'
MSG_done_cert='這個網站使用自己產生的憑證。請下載
%s
安裝到要連線的電腦上，瀏覽器才會顯示為安全連線。'
MSG_done_status='查看狀態   %s'
MSG_done_log='紀錄檔     %s'

# ---- load ----
MSG_load_usage='請指定要載入的離線映像包，例如：
custodexa.sh load custodexa-images-1.13.0-amd64.tar'
MSG_load_missing='%s 不存在。'
MSG_load_bad_name='%s 的檔名不是離線映像包的格式
（custodexa-images-<版本>-<架構>.tar）。'
MSG_load_no_manifest='找不到版本 %s 的發行清單：這個部署裡沒有，%s 的
SHA256SUMS 也沒有列出 MANIFEST.json。'
MSG_load_manifest_sum_bad='發行清單的校驗和與 SHA256SUMS 不符。
檔案可能下載不完整或損壞，請重新下載。'
MSG_load_title='載入離線映像包'
MSG_load_file='  檔案   %s（%s）'
MSG_load_sum_ok='校驗和與 SHA256SUMS 相符'
MSG_load_sum_none='%s 沒有 SHA256SUMS，無法核對校驗和。請把同一版的 SHA256SUMS
放在離線包旁邊。沒有載入任何映像。'
MSG_load_sum_unlisted='%s 的 SHA256SUMS 沒有列出這個離線包。沒有載入任何映像。'
MSG_load_sum_bad='校驗和與 SHA256SUMS 不符，檔案可能下載不完整或損壞，請重新下載。
沒有載入任何映像。'
MSG_load_arch_ok='架構 %s，和這台主機相同'
MSG_load_arch_bad='這個離線包是 %s 架構，這台主機是 %s；請改用 %s。
沒有載入任何映像。'
MSG_load_check_bad='離線包和發行清單不符。檔案可能下載不完整或損壞，
請重新下載。沒有載入任何映像：
%s'
MSG_load_empty='離線包裡沒有版本 %s 的映像。沒有載入任何映像。'
MSG_load_failed='docker load 失敗（完整輸出在紀錄檔）。'
MSG_load_loaded='已載入 %s 個映像'
MSG_load_digests_ok='每個映像的內容摘要都和發行清單（MANIFEST）相符'
MSG_load_id_bad='載入後 %s 的映像 ID 和載入前核對的不同。請不要使用，
改用重新複製的離線包再載入一次。'
MSG_load_trust_ok='發行者簽章與建置出處都已驗證'
MSG_load_trust_skip='%s：%s'
MSG_trust_name_sig='發行者簽章'
MSG_trust_name_prov='建置出處'
MSG_text_load_unverified='  映像已載入但來源尚未驗證。若單位要求驗證來源，請先請維運人員在
  已安裝 cosign、gh 且可上網的電腦，用完整摘要驗證（執行 install
  或 upgrade 時會列出驗證指令），通過後再執行下面的指令。'
MSG_load_next='映像已就緒，還沒有啟動任何服務。接下來：'
MSG_load_next_upgrade='或升級：'
# status。各段下的行在執行時以 56 欄換行；這裡的換行照樣保留。
MSG_status_title='Custodexa 狀態    %s    %s'
MSG_status_sec_version='版本'
MSG_status_sec_services='服務'
MSG_status_sec_images='映像'
MSG_status_sec_backup='備份'
MSG_status_sec_upgrade='上次升級'
MSG_status_pkg_sig_mismatch='安裝包簽章不符，來源未經證實'
MSG_status_pkg_sig_unverified='安裝包簽章未驗證，來源未經證實'
MSG_status_sec_disk='磁碟'
MSG_status_sec_reminders='提醒'
MSG_status_label_current='目前'
MSG_status_label_previous='上一版'
MSG_status_kind_installed='安裝包部署，%s 安裝'
MSG_status_kind_upgraded='安裝包部署，%s 升級'
MSG_status_previous_kept='保留在 releases/'
MSG_status_not_installed='尚未安裝。安裝：'
MSG_status_install_unfinished='安裝沒有完成（停在第 %s 步）。完成安裝：'
MSG_status_services_ok_oneshot='%s 個服務程序已啟動（tls-init 為一次性，已完成）'
MSG_status_services_ok='%s 個服務程序已啟動'
MSG_status_services_down='有 %s 個服務沒有在執行（共 %s 個）：%s'
MSG_status_services_none='找不到這個部署的容器'
MSG_status_services_hint='查看容器回報的狀態：'
MSG_status_health_ok='後端回報正常，版本 %s'
MSG_status_health_version='後端回報的版本是 %s，但記錄的版本是 %s'
MSG_status_health_bad='後端沒有回應 /health。查看它的紀錄：'
MSG_status_sealed='系統仍已封存，尚未對使用者提供服務。請到
%s 輸入主金鑰'
MSG_status_seal_init='主金鑰尚未初始化，系統還沒有對使用者提供服務。請到
%s 完成初始化'
MSG_status_unsealed='已解封，正在對使用者提供服務'
MSG_status_seal_unknown='無法從後端取得封存狀態'
MSG_status_images='來源 %s；%s'
MSG_status_src_local='這台主機'
MSG_status_src_offline='離線包'
MSG_status_src_build='用原始碼建置'
MSG_status_backup='最近一次 %s（%s，%s）'
MSG_status_backup_upgrade='升級前自動備份'
MSG_status_backup_script='custodexa.sh backup'
MSG_status_backup_external='自備備份'
MSG_status_backup_none='沒有備份紀錄'
MSG_status_days_0='今天'
MSG_status_days_1='1 天前'
MSG_status_days_n='%s 天前'
MSG_status_upgrade_ok='%s → %s 成功，%s'
MSG_status_upgrade_failed='%s → %s 在第 %s 步失敗，%s。紀錄檔：'
MSG_status_upgrade_unfinished='%s → %s 沒有完成，中斷在第 %s 步。紀錄檔：'
MSG_status_disk='data/ %s、backups/ %s；可用 %s'
MSG_status_env_unreadable='無法讀取 .env；請以 sudo 執行 status 才能檢查提醒項目'
MSG_status_remind_password='.env 仍保留初始管理者密碼（ADMIN_INITIAL_PASSWORD）。
管理者改過密碼後，請刪除這一行。'
MSG_status_remind_recordings='錄影目錄 %s 目前是 %s，應為 %s
（擁有者 1000、群組 0）。修正方法：'
MSG_status_load_unfinished='上次的 load 在第 %s 步中斷。它只會改動 Docker 裡的映像，
重跑即可完成：'

# ---- backup (used by upgrade and rollback) ----
MSG_bk_title='備份預覽（還沒有做任何變更）'
MSG_bk_pause='會暫停後端、連線服務與網頁，約 %s 分鐘（資料庫保持運作），
備份完成後自動啟動。'
MSG_bk_warn_seal='主金鑰模式是網頁輸入：備份後系統會回到「已封存」，
要有人到解封頁輸入主金鑰才會恢復服務。'
MSG_bk_size='預估 %s；備份位置還有 %s'
MSG_bk_confirm='開始備份嗎？[y/N]'
MSG_bk_step_stop='停止服務（資料庫保持運作）'
MSG_bk_step_db='資料庫'
MSG_bk_step_files='錄影與稽核檔'
MSG_bk_step_conf='設定檔與憑證'
MSG_bk_step_start='啟動服務'
MSG_bk_step_verify='確認備份可讀取'
MSG_bk_done='備份完成：%s（%s）'
MSG_bk_contents='內容：%s'
MSG_bk_item_sep='、'
MSG_bk_item_db='資料庫'
MSG_bk_item_rec='錄影'
MSG_bk_item_audit='稽核檔'
MSG_bk_item_env='設定檔 .env'
MSG_bk_item_env_kek='設定檔 .env（含主金鑰）'
MSG_bk_item_tls='憑證 tls/'
MSG_bk_warn_keep='這份備份含機敏資料，而且現在和 .env 在同一台主機上。
請加密後另存到別處，並和主金鑰材料分開保管。'
MSG_bk_warn_sealed='系統已封存，請到 %s 解封。'
MSG_bk_log='紀錄檔 %s'
MSG_bk_warn_snapshot='四個金鑰指紋沒有全部取得，這份備份不能用來自動核對金鑰。
升級後請到金鑰清冊頁人工比對；原因記在 snapshot.txt。'
MSG_bk_external_db='這個部署使用外接資料庫，腳本不備份資料庫。請用你們自己的
資料庫備份程序，並把資料目錄、.env 與 tls/ 一起保存。'
MSG_bk_db_unreachable='無法從資料庫取得大小，不能估算備份需要的空間。
請確認資料庫容器正在執行。沒有停止任何服務。'
MSG_bk_no_space='備份空間不足：預估需要 %s，%s 只剩 %s。
沒有停止任何服務。'
MSG_bk_dir_failed='無法在 %s 建立備份資料夾。沒有停止任何服務。'
MSG_bk_failed='備份沒有完成。已寫出的檔案在 %s，
裡面的 INCOMPLETE 標示這份備份不能使用。'
MSG_bk_start_again='服務可能仍在停止中。恢復服務：'

# ---- own backup (used by upgrade and rollback) ----
MSG_br_title='升級前備份'
MSG_br_opt1='[1] 由腳本做完整備份（建議）'
MSG_br_opt1_detail='資料庫、錄影、稽核檔、設定檔、憑證。預估 %s，約 %s 分鐘'
MSG_br_opt2='[2] 我要用自己的備份'
MSG_br_opt2_detail='例如虛擬機快照、儲存設備快照'
MSG_br_choose='請選擇 [1/2]：'
MSG_br_chosen='你選擇使用自己的備份'
MSG_br_times='稽核紀錄在 %s 確認全部寫入，服務在 %s 停止。
請現在做快照。快照須在停機後開始，並確認資料目錄、.env 和憑證
目錄都包含在同一次可還原的備份中。'
MSG_br_must='快照必須包含'
MSG_br_item_data='資料目錄   %s（資料庫、錄影、稽核檔）'
MSG_br_item_env='設定檔     %s'
MSG_br_item_tls='憑證目錄   %s'
MSG_br_item_db='資料庫     外接資料庫在 %s 之後的完整備份'
MSG_br_cannot_check='腳本無法檢查快照的內容。之後若要回退、而這次又有資料庫結構變更，
腳本不會替你還原：它會停在還原之前，列出用這份快照還原的步驟。'
MSG_br_enter='快照完成後依序輸入（會寫進升級紀錄）：'
MSG_br_ask_ref='快照名稱或識別             > '
MSG_br_ask_time='快照開始時間（YYYY-MM-DD HH:MM）> '
MSG_br_time_format='請用 YYYY-MM-DD HH:MM 的格式輸入，例如 2026-09-30 02:18'
MSG_br_time_ok='%s 晚於停機時間 %s'
MSG_br_ask_restore='還原程序在哪裡（文件名稱或位置）> '
MSG_br_ask_yes='快照包含上面每一項，而且照這份程序能還原嗎？輸入 yes > '
MSG_br_time_early='快照時間 %s 早於停機時間 %s'
MSG_br_time_early_detail='這份快照沒有停機前最後寫入的紀錄，用它還原會少資料。
請重新做快照，或改選 [1] 由腳本備份。服務目前仍停止，沒有其他
變更。'
MSG_br_cancel_hint='若要取消升級，請恢復全部服務並確認：'
MSG_br_not_confirmed='沒有確認這份快照（名稱、還原程序與 yes 都需要）。
服務目前仍停止，沒有其他變更。'
MSG_br_flags_incomplete='--backup-ref 必須與 --backup-time、--backup-restore 一起使用。
沒有做任何變更。'
MSG_br_ref_running='自備備份必須在服務停止之後做；請互動執行，腳本會在停機後等你做
快照，或改用腳本備份。沒有做任何變更。'
MSG_br_stop_unknown='讀不到後端的停止時間，無法核對快照時間。沒有做任何變更。'
MSG_br_drain_timeout='後端紀錄顯示停止時稽核佇列排空逾時，有稽核紀錄沒有確認寫入。
這個狀態的快照不完整，不能使用。沒有做任何變更。'
MSG_br_ref_used='使用你提供的備份 %s（%s，晚於停機 %s）；腳本不做備份'

# ---- upgrade version rules (used by upgrade and rollback) ----
MSG_vr_bad_version='「%s」不是版本號（例如 1.13.2）。'
MSG_vr_older='不能升級到 %s：它比目前的 %s 舊'
MSG_vr_older_detail='要回到舊版，請用升級前的備份照「備份與還原」第 5 節「還原程序」
手動還原。'
MSG_vr_same='目前已經是 %s'
MSG_vr_same_detail='沒有需要升級的內容。查看這個部署的狀態：'
MSG_vr_skip='%s 不接受從 %s 直接升級，最低需要 %s'
MSG_vr_skip_detail='請先升到 %s，確認正常後再升到 %s：'

# ---------- upgrade: entry, package, check for a newer version ----------
MSG_up_title='Custodexa 升級預覽（還沒有做任何變更）'
MSG_up_row_installed='  目前版本     %s'
MSG_up_row_target='  升級到       %s'
MSG_up_row_root='  部署目錄     %s'
MSG_up_confirm='開始升級嗎？[y/N]'
MSG_up_not_target='「%s」不是版本號，也不是安裝包檔案（custodexa-<版本>.tar.gz）'
MSG_up_incoming_failed='無法建立暫存目錄 %s'
MSG_up_download_failed='無法從 GitHub 下載 %s 的安裝包。離線升級請指定已下載的安裝包：'
MSG_up_pkg_no_sums='找不到 %s。安裝包要和它的 SHA256SUMS 放在同一個資料夾'
MSG_up_pkg_sum_bad='%s 的校驗和與 SHA256SUMS 不符，檔案可能下載不完整或損壞，請重新下載'
MSG_up_pkg_sig_bad='%s：簽章不符，來源未經證實'
MSG_up_pkg_sig_missing='%s：沒有簽章檔，來源未經證實'
MSG_up_pkg_sig_skip='%s 只驗了校驗和，沒有驗發行者簽章（這台主機沒有 cosign）'
MSG_up_pkg_ok='%s 的校驗和與發行者簽章已驗證'
MSG_up_pkg_layout='%s 不是 %s 版的安裝包（找不到該版的管理腳本或版本檔）'
MSG_up_release_differs='%s 已經存在，內容和這個安裝包不同。請先確認那是什麼，再重新執行'
MSG_up_no_deployment='這裡沒有部署：%s'
MSG_up_no_deployment_running='執行中的部署在 %s。請指定部署目錄執行：'
MSG_q_installed='目前版本   %s（安裝包部署，%s）'
MSG_q_latest='最新版本   %s（%s 發佈）'
MSG_q_up_to_date='目前已經是最新版本'
MSG_q_direct='可以直接升級（%s 接受從 %s 以上的版本直接升級）'
MSG_q_migrations_none='不會套用資料庫結構變更'
MSG_q_migrations_one='會套用 1 項資料庫結構變更。升級後如果要回退，
必須還原升級前的備份'
MSG_q_migrations_many='會套用 %s 項資料庫結構變更。升級後如果要回退，
必須還原升級前的備份'
MSG_q_migrations_unknown='讀不到資料庫目前的結構版本，無法算出會套用幾項結構變更'
MSG_q_verified='發行清單（MANIFEST）的校驗和與發行者簽章已驗證'
MSG_q_unverified='發行清單只驗了校驗和，沒有驗發行者簽章（這台主機沒有
cosign），以下結果未經來源驗證'
MSG_q_no_sig='沒有發行清單簽章檔，來源未經證實。
升級查詢結果依據已核對校驗和的發行清單'
MSG_q_verify_fail_2='發行清單（MANIFEST）的校驗和與 SHA256SUMS 不符。
檔案可能下載不完整或損壞，請重新下載。
無法判斷能不能升級'
MSG_q_verify_fail_3='發行清單簽章不符，來源未經證實。升級查詢結果依據已核對校驗和的發行清單'
MSG_q_notes='  版本說明  %s'
MSG_q_run='要升級，請執行：'
MSG_q_only='這個指令只查詢，沒有做任何變更。'
MSG_q_offline='連不到 GitHub；離線升級請指定安裝包路徑：'
# ---------- upgrade: checks before the preview, and the preview ----------
MSG_up_row_kek='  主金鑰模式   %s'
MSG_up_kek_ui='網頁輸入'
MSG_up_kek_env='設定檔'
MSG_up_kek_kms='外部金鑰保管服務（KMS）'
MSG_up_kek_hsm='硬體安全模組（HSM）'
MSG_up_will='會做的事'
MSG_up_will_1='  1. 等稽核紀錄全部寫進資料庫，再停止服務（資料庫保持運作）'
MSG_up_will_2='  2. 完整備份：資料庫、錄影、稽核檔、設定檔、憑證
     預估 %s；備份位置還有 %s'
MSG_up_will_2_external='  2. 資料庫不在這台主機的部署裡，腳本不備份它；停止服務後，
     會請你確認一份在停機之後做的備份'
MSG_up_will_3='  3. 換成 %s 並啟動'
MSG_up_will_4='  4. 核對：版本、資料是不是原本那一份、金鑰有沒有變'
MSG_up_know='需要知道的事'
MSG_up_know_pause='  - 預計停機 %s 到 %s 分鐘。停機期間無法連線，進行中的連線會中斷
    （目前有 %s 條連線正在進行）'
MSG_up_know_pause_unknown='  - 預計停機 %s 到 %s 分鐘。停機期間無法連線，進行中的連線會中斷'
MSG_up_know_backend_down='  - 後端目前沒有在執行，無法確認稽核佇列，會直接停止服務'
MSG_up_know_mig_none='  - 這次沒有資料庫結構變更'
MSG_up_know_mig_one='  - 這次有 1 項資料庫結構變更。升級後若要回退，必須還原這次的備份，
    備份之後產生的紀錄會遺失'
MSG_up_know_mig_many='  - 這次有 %s 項資料庫結構變更。升級後若要回退，必須還原這次的備份，
    備份之後產生的紀錄會遺失'
MSG_up_know_mig_unknown='  - 讀不到資料庫目前的結構版本，無法算出這次有幾項結構變更'
MSG_up_know_ui='  - 升級完成後系統會停在「已封存」，需要有人到網頁輸入主金鑰解封'
MSG_up_know_kms='  - 升級完成後系統會停在「已封存」。請先備妥三樣：本地管理者帳密、
    金鑰保管處的憑證、部署拓撲紀錄'
MSG_up_know_old_images='  - 這台主機找不到目前版本的部分映像，回退時需要重建或重新取得
    舊版映像'
MSG_up_know_tmux='  - 建議由熟悉主機操作的人員，在可維持工作階段的終端工具（如
    tmux 或 screen）中執行，降低 SSH 斷線造成升級中斷的風險'
MSG_dg_step='等稽核紀錄寫完'
MSG_dg_left_first='待寫入 %s 筆'
MSG_dg_left_next=' ... %s 筆'
MSG_dg_done='等稽核紀錄寫完（待寫入 0 筆）'
MSG_dg_timeout='等稽核紀錄寫完：120 秒後仍有 %s 筆待寫入'
MSG_dg_timeout_what='服務仍在運作，沒有做任何變更。
通常代表資料庫忙碌或寫入變慢。請在使用量較低時再執行升級。
想自己看目前的數字：'
MSG_dg_sealed='等稽核紀錄寫完：系統已封存，稽核寫入尚未啟動，沒有待寫入的紀錄'
MSG_dg_stopped='等稽核紀錄寫完：後端沒有在執行，沒有要等的紀錄'
MSG_dg_unknown='等稽核紀錄寫完：無法確認'
MSG_dg_unknown_detail='        讀不到待寫入筆數，也讀不到系統是否已封存（查詢被來源位址
        限制擋下，或後端沒有回應）。'
MSG_dg_unknown_what='因無法確認待寫入紀錄，腳本已停止升級，服務仍在運作，沒有做任何
變更。
請先執行 sudo %s status%s 確認後端狀態；
若仍讀不到，請將這則錯誤與升級紀錄檔交給維運人員，檢查來源位址
限制（SEAL_UNSEAL_ALLOWED_CIDRS）後再重試。'
# ---------- upgrade: stopping the old version ----------
MSG_st_stop_failed='停止服務失敗；服務可能停了一部分'
MSG_st_log_unreadable='讀不到後端日誌，無法確認停止時稽核紀錄已經寫完'
MSG_st_drain_timeout='停止服務：稽核紀錄沒有在關閉時限內全部寫進資料庫'
MSG_st_drain_counts='未確認寫入 %s 筆（改寫到備援檔 %s 筆、處理中未回報 %s 筆、遺失 %s 筆）'
MSG_st_drain_detail='備援檔在 %s。升級已停下，服務維持停止，
沒有做其他變更。請先核對這些紀錄，再恢復舊版服務。'
MSG_st_resume='恢復舊版服務：'
MSG_st_gone='確認舊版已完全停止（資料庫連線 0）'
MSG_st_conn_left='舊版停止後，應用帳號在資料庫仍有 %s 條連線'
MSG_st_conn_unknown='讀不到應用帳號在資料庫的連線數，無法確認舊版已完全停止'
MSG_st_conn_detail='可能還有舊版後端在別的主機或別的 compose 專案執行，或連線還沒被
回收。升級已停下，服務維持停止。找到並停止它，直到下面的查詢為 0：'

# upgrade: an interrupted upgrade, the next time it is run
MSG_up_rerun_safe='停在服務停止之前：服務照常運作，沒有做任何變更。這次從頭開始。'
MSG_up_rerun_resumed='服務已恢復運作，版本與資料都沒有換過。這次從頭開始，會重新備份。'
MSG_up_hint_stopped='服務目前停止，版本與資料都沒有換過。先恢復舊版服務，再執行一次升級。'
MSG_up_hint_again='再執行一次升級：'
MSG_up_hint_switched='已經切換到新版。先查看後端日誌找原因：'
MSG_up_hint_backup='升級前的備份：%s'

# upgrade：預覽之後的步驟、啟動後的核對、結束畫面
MSG_up_run_title='升級 %s → %s'
MSG_up_step_env='檢查環境'
MSG_up_step_images='取得並驗證新版映像'
MSG_up_step_confirmed='已確認開始'
MSG_up_step_backup='備份'
MSG_up_bk_snap='記下升級前的資料筆數與金鑰指紋'
MSG_up_bk_db='資料庫   %s  %s'
MSG_up_bk_files='錄影與稽核檔  %s  %s'
MSG_up_unseal_after='主金鑰模式是網頁輸入，服務恢復後要再解封一次。'
MSG_up_step_switch='切換到 %s'
MSG_up_step_start='啟動'
MSG_up_step_ready='等待就緒'
MSG_up_step_check='核對'
MSG_up_step_record='寫紀錄'
MSG_up_failed_at='上次的升級停在第 %s 步。'
MSG_up_know_verified='  - 映像的校驗和、簽章、出處證明都已驗證'
MSG_up_fail_switch='升級停在第 9/13 步：無法切換到新版'
MSG_up_fail_start='升級停在第 10/13 步：新版沒有啟動'
MSG_up_fail_ready='升級停在第 11/13 步：後端在 %s 秒內沒有回報就緒'
MSG_up_fail_checks='升級停在第 12/13 步：核對沒有通過'
MSG_up_state_title='目前狀態'
MSG_up_state_switched='已切換到 %s'
MSG_up_state_not_ready='已切換到 %s，服務已啟動，但後端沒有就緒'
MSG_up_state_backup='升級前的備份完整：%s'
MSG_up_state_backup_own='升級前的備份是你的快照，紀錄在 %s'
MSG_up_state_no_auto='腳本不會自動回退'
MSG_up_logs_first='先查看後端日誌找原因：'
MSG_up_logs_more='若仍無法判斷，請將這份日誌與升級紀錄檔交給維運人員。'
MSG_up_done_sealed='新版已啟動：%s；尚需解封並完成下列人工檢查，才能開放使用者連線'
MSG_up_done='新版已啟動：%s；尚需完成下列人工檢查，才能開放使用者連線'
MSG_up_todo='還要請你做'
MSG_up_todo_unseal_ui='系統目前「已封存」。請到 %s 輸入主金鑰。'
MSG_up_todo_unseal_kms='系統目前「已封存」。請以本地管理者帳密開啟 %s，
核對保管處資訊後提供憑證。'
MSG_up_todo_manual_after='解封後，開放使用者連線之前，請手動確認（腳本做不到）：
- 稽核鏈驗證通過
- 播放一段升級前的錄影
- 新建一條測試連線，執行幾個指令，確認它們出現在稽核紀錄
  （這一項不可省略：連線正常不代表稽核有寫進去）'
MSG_up_todo_manual='開放使用者連線之前，請手動確認（腳本做不到）：
- 稽核鏈驗證通過
- 播放一段升級前的錄影
- 新建一條測試連線，執行幾個指令，確認它們出現在稽核紀錄
  （這一項不可省略：連線正常不代表稽核有寫進去）'
MSG_up_done_rollback='需要回退    用下列備份，照「備份與還原」第 5 節「還原程序」手動還原'
MSG_up_done_backup='備份        %s'
MSG_up_done_log='紀錄檔      %s'
MSG_pc_title='核對結果'
MSG_pc_services_bad='服務           沒有正常執行：%s'
MSG_pc_version='版本           後端回報 %s'
MSG_pc_version_bad='版本           後端回報 %s，應為 %s'
MSG_pc_images_bad='映像           執行中的映像和取得時記下的不同'
MSG_pc_data_unknown='資料           讀不到升級前或升級後的筆數，無法比對；請人工核對'
MSG_pc_mig_missing='資料庫結構     升級前的結構版本不見了：%s'
MSG_pc_mig_none='資料庫結構     沒有結構變更'
MSG_pc_mig_one='資料庫結構     套用 1 項：%s'
MSG_pc_mig_many='資料庫結構     套用 %s 項：%s'
MSG_pc_same_data='同一份資料     使用者 %s、連線紀錄 %s，與升級前相同；
               稽核紀錄 %s（升級前 %s，啟動時新增 %s）'
MSG_pc_counts_bad='同一份資料     使用者 %s（升級前 %s）、連線紀錄 %s（升級前 %s）、
               稽核紀錄 %s（升級前 %s）'
MSG_pc_keys_manual='金鑰           升級前或升級後的指紋不完整，無法自動比對；
               請到金鑰清冊頁人工核對'
MSG_pc_keys_changed='金鑰           金鑰指紋和升級前不同'
MSG_pc_keys_same='金鑰           四把金鑰的指紋和升級前相同'
MSG_pc_lock_other='單一實例       資料庫鎖由另一個資料庫工作階段持有：另有一個後端
               連到同一個資料庫'
MSG_pc_lock_held='單一實例       這台的後端取得資料庫鎖'
MSG_pc_lock_unknown='單一實例       後端日誌沒有資料庫鎖的紀錄，無法確認'
MSG_pc_entry_bad='對外入口       %s 沒有回應'
MSG_pc_empty_title='新版接到的是一個空的資料庫，已立即停止所有服務'
MSG_pc_empty_moved='新版把資料庫當成全新安裝建立了（使用者 %s、連線紀錄 %s；
升級前是 %s 與 %s）。原本資料所在的路徑
%s 沒有被這次升級改寫或刪除。
最常見的原因是 .env 的 DATA_PATH 指到了別的地方：
  目前 DATA_PATH=%s
  升級前資料在 %s'
MSG_pc_empty_moved_do='請不要登入，也不要初始化主金鑰，也先不要刪除任何目錄。
1. 請維運人員核對新舊兩個資料路徑：確認
   %s 只含這次誤建的資料（使用者 %s、連線
   紀錄 %s），且 %s 仍是原本的資料
2. 核對後，把 .env 的 DATA_PATH 改回 %s
3. 確認沒有問題後再刪除 %s
4. 要回到升級前的版本，請用升級前的備份照「備份與還原」
   第 5 節「還原程序」手動還原'
MSG_pc_empty_same='新版把資料庫當成全新安裝建立了（使用者 %s、連線紀錄 %s；
升級前是 %s 與 %s）。資料路徑 %s
沒有被這次升級改寫或刪除；新版可能連到了別的資料庫。'
MSG_pc_empty_same_do='請不要登入，也不要初始化主金鑰，也先不要刪除任何目錄。
1. 請維運人員核對 .env 的資料庫設定與後端日誌，找出新版沒有
   讀到原本資料的原因
2. 核對後要回到升級前的版本，請用升級前的備份照「備份與還原」
   第 5 節「還原程序」手動還原'

# Main menu (custodexa.sh without a command, on a terminal).
MSG_menu_title='Custodexa 管理腳本 %s    部署目錄 %s'
MSG_menu_state_none='目前狀態：尚未安裝'
MSG_menu_state_package='目前狀態：已安裝 %s（安裝包部署）'
MSG_menu_language='語言：--lang en English、--lang ja 日本語'
MSG_menu_install='安裝'
MSG_menu_load_first='載入離線映像包（主機不能上網時，先做這一步）'
MSG_menu_status='查看狀態'
MSG_menu_upgrade='升級'
MSG_menu_backup='備份（會暫停服務約十幾分鐘）'
MSG_menu_load='載入離線映像包'
MSG_menu_help='說明'
MSG_menu_quit='離開'
MSG_menu_choose='請選擇 [0-%s]：'
MSG_menu_choose_sub='請選擇 [1-%s]，直接按 Enter 回到主選單：'
MSG_menu_invalid='沒有這個選項，請輸入方括號裡的數字。'
MSG_menu_other_path='輸入其他路徑'
MSG_menu_bundle_found='載入離線映像包。目前目錄 %s 有這些離線包：'
MSG_menu_bundle_none='載入離線映像包。目前目錄 %s 沒有離線包
（檔名像 custodexa-images-%s-amd64.tar）。'
MSG_menu_ask_bundle='離線包路徑，直接按 Enter 回到主選單 > '
MSG_menu_up_title='要升級到哪個版本？'
MSG_menu_up_latest='最新版（先查詢有沒有新版，有就接著升級）'
MSG_menu_up_version='指定版本'
MSG_menu_up_package='已下載的安裝包（離線可用）'
MSG_menu_ask_version='版本（例如 1.13.2），直接按 Enter 回到主選單 > '
MSG_menu_package_found='用已下載的安裝包升級。目前目錄 %s 有這些安裝包：'
MSG_menu_package_none='用已下載的安裝包升級。目前目錄 %s 沒有安裝包
（檔名像 custodexa-%s.tar.gz）。'
MSG_menu_ask_package='安裝包路徑，直接按 Enter 回到主選單 > '

MSG_up_restore_guide='決定回到 %s 時，請用上面的備份，照「備份與還原」
第 5 節「還原程序」手動還原。'
MSG_menu_images_install='映像來源'
MSG_menu_images_upgrade='升級到 %s 的映像來源'
MSG_menu_images_auto='  [1] 自動（預設）：這台主機、離線包、GHCR、Docker Hub，最後用原始碼建置'
MSG_menu_images_source='  [2] 從安裝包內原始碼建置（較慢；上游映像仍須取得）'
MSG_menu_images_choose='請選擇 [1-2]，直接按 Enter 使用自動：'
MSG_q_wait_download='正在取得最新版的 %s…'
MSG_q_download_ok='已取得 %s'
MSG_q_optional_signature_missing='無法取得簽章檔，發行者未經驗證'
MSG_q_wait_checksum='正在核對發行清單與 SHA256SUMS 的校驗和…'
MSG_q_checksum_ok='發行清單校驗和相符'
MSG_q_wait_signature='正在驗證發行清單簽章…'
MSG_up_wait_download='正在取得 %s…'
MSG_up_download_ok='已取得 %s'
MSG_up_wait_checksum='正在核對 %s 與 SHA256SUMS 的校驗和…'
MSG_up_checksum_ok='%s 的校驗和相符'
MSG_up_wait_signature='正在驗證發行清單簽章…'
MSG_up_step_reserved='此步驟無須執行'

# Whole-deployment service controls.
MSG_menu_start='啟動服務'
MSG_menu_stop='停止服務'
MSG_help_cmd_start='  start                啟動整組服務並等待後端就緒'
MSG_help_cmd_stop='  stop                 確認並停止整組服務'
MSG_svc_stop_title='停止服務'
MSG_svc_stop_warn='現有使用者連線會中斷。請先通知使用者；稽核佇列排空後才會停止服務。'
MSG_svc_stop_confirm='確定停止整組服務嗎？[y/N]'
MSG_svc_stop_done='服務已停止'
MSG_svc_stop_already='服務已停止，無需重複停止。'
MSG_svc_start_title='啟動服務'
MSG_svc_start_done='服務已啟動；請查看狀態，若系統已封存仍需解封。'
MSG_svc_start_already='服務已在執行，後端已就緒。'
MSG_svc_drain_run='等待稽核紀錄寫入完成'
MSG_svc_drain_done='稽核佇列已排空'
MSG_svc_drain_fail='無法確認稽核佇列已排空；服務未停止。'
MSG_svc_stop_run='停止整組服務'
MSG_svc_start_run='啟動整組服務'
MSG_svc_ready_run='等待後端就緒（最多 180 秒）'
MSG_svc_stop_failed='停止未完成；請查看狀態。'
MSG_svc_start_failed='啟動未完成；請查看狀態。'
MSG_svc_ready_failed='後端未在 180 秒內就緒；請查看狀態。'
MSG_svc_cancelled='沒有變更服務。'
MSG_svc_status_hint='請用下列指令查看狀態：'
MSG_svc_containers_up='容器已啟動'
MSG_svc_ready_done='後端已就緒'
MSG_svc_not_installed='尚未安裝，無法控制服務。'
MSG_svc_resume_hint='服務可能只完成部分啟停。請先查看狀態，再執行 start 恢復整組服務：'
MSG_svc_pending_run='前次 %s 尚未完成；請先依既有恢復指令處理。'
