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
MSG_usage_backup_only='選項 %s 只適用於 backup。請見：custodexa.sh --help'
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
MSG_run_backup_unfinished='上次的備份（%s）沒有完成，暫存目錄
%s 可以刪除。'
MSG_run_backup_unfinished_nodir='上次的備份（%s）沒有完成。'
MSG_run_backup_upgrade='上次的備份（%s）沒有完成，升級前要先有一份完成的備份。
服務若仍停著，先啟動；接著重新備份，備份完成後再升級：'
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
MSG_help_cmd_backup='  backup               備份成單一檔案（會暫停服務；檔案可搬到其他主機）'
MSG_help_cmd_load='  load <離線包>         載入離線映像包（不啟動服務）'
MSG_help_options='選項'
MSG_help_opt_yes='  --yes                不詢問確認，自動化時使用'
MSG_help_opt_with_recordings='  --with-recordings    （backup）錄影一併放進備份檔（預設不放）'
MSG_help_opt_passphrase_file='  --passphrase-file <檔案>（backup）以檔案第一行為通行密語加密備份檔；
                       檔案須為 0600、屬於你或 root。不要把密語直接寫在指令上'
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
# shellcheck disable=SC2016 # the commands as they are typed
MSG_help_passphrase_file_make='  建立密語檔（不會留在指令歷史）：
    sudo install -m 600 -o root /dev/null /root/cx-pass
    sudo bash -c '"'"'IFS= read -r -s p && printf "%%s\\n" "$p" > /root/cx-pass'"'"''
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
MSG_status_backup_encrypted='%s（已加密）'
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
MSG_bk_confirm='開始備份嗎？[y/N]'
MSG_bk_step_stop='停止服務（資料庫保持運作）'
MSG_bk_step_db='資料庫'
MSG_bk_step_files='錄影與稽核檔'
MSG_bk_step_conf='設定檔與憑證'
MSG_bk_step_verify='確認備份可讀取'
MSG_bk_contents='內容：%s'
MSG_bk_item_sep='、'
MSG_bk_item_db='資料庫'
MSG_bk_item_rec='錄影'
MSG_bk_item_audit='稽核檔'
MSG_bk_item_env='設定檔 .env'
MSG_bk_item_env_kek='設定檔 .env（含主金鑰）'
MSG_bk_item_tls='憑證 tls/'
MSG_pb_item_tpl='代理範本 %s'
MSG_bk_log='紀錄檔 %s'
MSG_bk_db_unreachable='無法從資料庫取得大小，不能估算備份需要的空間。
請確認資料庫容器正在執行。沒有停止任何服務。'
MSG_bk_dir_failed='無法在 %s 建立備份資料夾。沒有停止任何服務。'
MSG_bk_failed='備份沒有完成。已寫出的檔案在 %s，
裡面的 INCOMPLETE 標示這份備份不能使用。'
MSG_bk_start_again='服務可能仍在停止中。恢復服務：'

# ---- portable backup (custodexa.sh backup) ----
MSG_pb_step_audit='稽核檔'
MSG_pb_step_start='啟動服務並等待就緒'
MSG_pb_step_verify='確認各部分可讀取'
MSG_pb_step_pack='組成單一備份檔並讀回核對'
MSG_pb_done='備份完成（%s）'
MSG_pb_sidecar='校驗檔 %s（同一目錄）'
MSG_pb_summary='版本 %s；%s；主金鑰模式：%s'
MSG_pb_db_bundled='內建資料庫'
MSG_pb_mode_env='本機設定檔'
MSG_pb_mode_ui='網頁輸入'
MSG_pb_mode_kms='金鑰託管服務（%s）'
MSG_pb_mode_hsm='硬體安全模組（HSM）'
MSG_pb_kek_in='主金鑰在備份檔的 .env 裡（指紋 %s），還原時會一併取回。'
MSG_pb_kek_out='主金鑰不在備份檔裡（指紋 %s）。還原後要由持有解封材料的人
到解封頁輸入，指紋必須相同。'
MSG_pb_kek_kms='主金鑰由金鑰託管服務（%s）保管，不在備份檔裡。金鑰識別：
%s
還原後要到解封頁重新提供託管憑證，金鑰識別必須相同；
新主機也要連得到託管服務。'
MSG_pb_kek_in_nofp='主金鑰在備份檔的 .env 裡，還原時會一併取回。'
MSG_pb_kek_out_nofp='主金鑰不在備份檔裡。還原後要由持有解封材料的人
到解封頁輸入，指紋必須相同。'
MSG_pb_kek_kms_nofp='主金鑰由金鑰託管服務（%s）保管，不在備份檔裡。
還原後要到解封頁重新提供託管憑證，金鑰識別必須相同；
新主機也要連得到託管服務。'
MSG_pb_warn_kek_fp='取不到主金鑰指紋，還原時無法自動核對主金鑰；原因記在備份檔內的
snapshot.txt。'
MSG_pb_warn_fps='四個金鑰指紋沒有全部取得（主金鑰指紋有取得），還原後其餘金鑰要到
金鑰清冊頁人工比對；原因記在備份檔內的 snapshot.txt。'
MSG_pb_warn_rec='錄影沒有放進備份檔。錄影在 %s，
請另外保存，或重新備份並選擇放入錄影。'
MSG_pb_warn_plain='這個備份檔沒有加密，含機敏資料（資料庫密碼、登入權杖簽章密鑰、
憑證私鑰），而且現在和 .env 在同一台主機上。請另存到別處並限制
存取；備份時也可以選擇以通行密語加密。'
MSG_pb_warn_plain_kek='這個備份檔沒有加密，含主金鑰與其他機敏資料（資料庫密碼、登入權杖
簽章密鑰、憑證私鑰）。拿到這個檔就能解開所有加密保存的憑證，
請另存到別處並限制存取；備份時也可以選擇以通行密語加密。'
MSG_pb_svc_back='服務已恢復。'
MSG_pb_svc_ui='服務已啟動，待解封：請到 %s 輸入主金鑰。'
MSG_pb_svc_kms='服務已啟動，待解封：請以本地管理者帳密開啟 %s，
核對保管處資訊後提供憑證。'
MSG_pb_svc_timeout='後端在 %s 秒內沒有就緒，使用者可能還不能連線。備份仍繼續完成。
查看狀態，必要時再啟動一次：'
MSG_pb_failed='備份沒有完成，沒有產生備份檔。已取得的部分在
%s，不能用來還原，
而且含機敏明文；查明原因後請刪除。'
MSG_pb_valid='備份檔有效：'
MSG_pb_after_both='但後續沒有做完：狀態檔沒有更新（status 仍顯示前一份備份），
暫存目錄 %s 沒有刪掉。
請確認磁碟空間與權限後，手動刪除暫存目錄；下次備份會更新狀態檔。'
MSG_pb_after_state='但後續沒有做完：狀態檔沒有更新（status 仍顯示前一份備份）。
請確認磁碟空間與權限；下次備份會更新狀態檔。'
MSG_pb_after_partial='但後續沒有做完：暫存目錄 %s 沒有刪掉。
請確認磁碟空間與權限後，手動刪除暫存目錄。'
MSG_pb_sig_valid='備份在收尾時被中斷，但備份檔已經完成而且有效：'
MSG_pb_sig_both='狀態檔沒有更新（status 仍顯示前一份備份），暫存目錄
%s 沒有刪掉，請手動刪除。'
MSG_pb_sig_partial='暫存目錄 %s 沒有刪掉，請手動刪除。'
MSG_pb_sig_timeout='後端在 %s 秒內沒有就緒，使用者可能還不能連線。
查看狀態，必要時再啟動一次：'
MSG_pb_version_mismatch='狀態檔記載已安裝 %s，但 current/MANIFEST.json 是 %s，
無法確定這份備份屬於哪個版本。沒有停止任何服務。
請先執行下列指令查看：'
MSG_pb_tool_version='這個腳本的發行清單 %s 是 %s 版，
和腳本版本 %s 不同，無法記錄產生備份的工具。沒有停止任何服務。'
MSG_pb_kek_material='.env 的 KEK_PROVIDER 是 %s，但 ENCRYPTION_KEY 有值。這是矛盾的設定，
後端下次啟動也會拒絕；備份會把它當成主金鑰帶出去，所以不做。
沒有停止任何服務。請確認要用哪種模式，再把另一邊清掉。'
MSG_pb_kek_none='.env 沒有設定 KEK_PROVIDER，也沒有 ENCRYPTION_KEY，無法判定主金鑰模式。
後端下次啟動會拒絕。沒有停止任何服務。'
MSG_pb_kek_env_empty='.env 的 KEK_PROVIDER 是 env，但 ENCRYPTION_KEY 是空的。
後端下次啟動會拒絕。沒有停止任何服務。'
MSG_pb_kek_unknown='.env 的 KEK_PROVIDER 值不認得（只接受 env、ui、kms、hsm，大小寫須相同）。
沒有停止任何服務。'
MSG_pb_tpl_missing='.env 的 TLS_NGINX_TEMPLATE 指向 %s，
但那不是讀得到的檔案。備份要一併帶走這個檔，所以不做。
沒有停止任何服務。請改正路徑，或清掉這一行改用內附範本，再執行一次。'
MSG_pb_tpl_chars='.env 的 TLS_NGINX_TEMPLATE 是 %s，
路徑含有備份檔記不下的字元（雙引號、反斜線、Tab，或中文等
非 ASCII 字元）。備份要記下這個路徑，還原時才放得回去，所以不做。
沒有停止任何服務。請把範本放到不含這些字元的路徑，或清掉這一行
改用內附範本，再執行一次。'
MSG_pb_ts_taken='%s 已有這個時間（%s）的備份檔或暫存目錄。
沒有停止任何服務。請過幾秒再執行一次。'
MSG_pb_need='需要 %s（備份檔約 %s，加上組裝時的暫存與 1 GB 餘裕）；
備份位置還有 %s'
MSG_pb_no_space='備份空間不足：需要 %s（含組裝時的暫存與 1 GB 餘裕），
%s 只剩 %s。沒有停止任何服務。'
MSG_pb_no_space_hint='可以：把舊的備份檔搬到別處後刪除，或（若選了放入錄影）
改成不放錄影再執行一次。'
MSG_pb_no_space_ls='目前的備份檔：%s'
MSG_pb_sig_failed='備份在第 %s 步被中斷，沒有產生備份檔。已停止這次啟動的工具程序。
已取得的部分在 %s，
不能用來還原，而且含機敏明文；請刪除。'
MSG_pb_sig_again='要重新備份，直接再執行一次：'
MSG_pb_sizes='資料庫 %s、稽核檔 %s、錄影 %s；備份位置還有 %s'
MSG_pb_rec_q='錄影要放進備份檔嗎？'
MSG_pb_rec_no='不放（預設）：備份檔約 %s，服務暫停約 %s'
MSG_pb_rec_yes='放入：備份檔約 %s，服務暫停約 %s'
MSG_pb_rec_short='需要 %s，備份位置空間不足，選這項會被擋下'
MSG_pb_rec_keep='不放的話，請另外保存錄影目錄。'
MSG_pb_choose='請選擇 [1-2]，直接按 Enter 使用預設：'
MSG_pb_enc_q='要用通行密語把備份檔加密嗎？'
MSG_pb_enc_why='不加密的備份檔裡有資料庫密碼、憑證私鑰等機敏資料，
任何拿到檔案的人都能讀。'
MSG_pb_enc_why_env='不加密的備份檔裡有資料庫密碼、主金鑰、憑證私鑰等機敏資料，
任何拿到檔案的人都能讀。'
MSG_pb_enc_no='不加密（預設）：檔案可直接用 tar 開啟'
MSG_pb_enc_yes='加密：還原時要輸入同一個通行密語。密語遺失就無法還原，
腳本與開發者都救不回來。'
MSG_pb_pass_rules='通行密語：12 到 256 個字元，只能用半形英文字母、數字、空白與半形符號；
空白也算在密語裡。'
MSG_pb_pass_prompt='通行密語    > '
MSG_pb_pass_again='再輸入一次  > '
MSG_pb_pass_match='兩次輸入相同'
MSG_pb_tries_n='還可以再試 %s 次'
MSG_pb_tries_1='還可以再試 1 次'
MSG_pb_pass_differ='兩次輸入不同，請重新輸入（%s）。'
MSG_pb_pass_short='通行密語至少要 12 個字元，請重新輸入（%s）。'
MSG_pb_pass_chars='通行密語含有不接受的字元（例如中文或全形符號），請重新輸入（%s）。'
MSG_pb_pass_long='通行密語最多 256 個字元，請重新輸入（%s）。'
MSG_pb_pass_cancel='三次都沒有設定好通行密語，備份已取消。沒有做任何變更。'
MSG_pb_rec_line_no='錄影：不放入'
MSG_pb_rec_line_yes='錄影：放入'
MSG_pb_rec_line_hint='錄影：不放入（要放入請加 --with-recordings）'
MSG_pb_enc_line_no='加密：不加密'
MSG_pb_enc_line_yes='加密：以通行密語加密（AES-256）'
MSG_pb_enc_line_hint='加密：不加密（要加密請加 --passphrase-file <檔案>）'
MSG_pb_enc_line_file='加密：以通行密語檔 %s 加密'
MSG_pb_pause='會暫停後端、連線服務與網頁，約 %s（資料庫保持運作）。
資料取完後自動啟動並等待就緒，之後再花約 %s組成並檢查備份檔。'
MSG_pb_warn_seal_ui='主金鑰模式是網頁輸入：重新啟動後系統會回到「已封存」，
要有人到解封頁輸入主金鑰，使用者才能連線。'
MSG_pb_warn_seal_kms='主金鑰由金鑰託管服務保管：重新啟動後系統會回到「已封存」，
要有人到解封頁重新提供託管憑證，使用者才能連線。'
MSG_pb_warn_seal_hsm='主金鑰由硬體安全模組保管：重新啟動後系統會回到「已封存」，
要有人到解封頁完成解封，使用者才能連線。'
MSG_pb_dur_m='%s 分鐘'
MSG_pb_dur_m1='1 分鐘'
MSG_pb_dur_h='%s 小時'
MSG_pb_dur_h1='1 小時'
MSG_pb_dur_more_m='%s 分鐘'
MSG_pb_dur_more_m1='1 分鐘'
MSG_pb_dur_more_h='%s'
MSG_pb_step_pack_enc='組成單一備份檔、加密並讀回核對'
MSG_pb_done_enc='備份完成（%s，已加密）'
MSG_pb_warn_pass='還原時要輸入同一個通行密語。密語遺失就無法還原，
請把密語和備份檔分開保管。'
MSG_pb_warn_enc_host='這個備份檔現在和 .env 在同一台主機上，請另存到別處。'
MSG_pb_enc_scheme='加密方式：AES-256-CBC，金鑰由通行密語以 PBKDF2-SHA256 60 萬次導出'
MSG_pb_no_openssl='這台主機沒有加密用的 openssl 映像（應在安裝或升級時取得）。
沒有停止任何服務。請載入這個版本（%s）的離線映像包，或改選不加密。
離線映像包檔名像 %s，與安裝包放在同一個發行頁：'
MSG_pb_pf_read='讀不到通行密語檔 %s（不存在、不是一般檔案、是符號連結
或沒有讀取權限）。沒有停止任何服務。'
MSG_pb_pf_perm='通行密語檔 %s 其他帳號也能讀寫（權限 %s），或不屬於你或
root，或設有額外的存取控制清單。沒有停止任何服務。修正後再執行：'
MSG_pb_pf_line='通行密語檔 %s 的第一行不符規則：需要 12 到 256 個字元，
只能用半形英文字母、數字、空白與半形符號。沒有停止任何服務。'

# ---- own backup (used by upgrade and rollback) ----
MSG_br_title='升級前備份'
MSG_br_opt1='[1] 由腳本做完整備份（建議）'
MSG_br_opt1_detail='資料庫、錄影、稽核檔、設定檔、憑證。預估 %s，約 %s 分鐘'
MSG_br_opt1_detail_notls='資料庫、錄影、稽核檔、設定檔。預估 %s，約 %s 分鐘'
MSG_br_opt2='[2] 我要用自己的備份'
MSG_br_opt2_detail='例如虛擬機快照、儲存設備快照'
MSG_br_choose='請選擇 [1/2]：'
MSG_br_chosen='你選擇使用自己的備份'
MSG_br_times='稽核紀錄在 %s 確認全部寫入，服務在 %s 停止。
請現在做快照。快照須在停機後開始，並確認資料目錄、.env 和憑證
目錄都包含在同一次可還原的備份中。'
MSG_br_times_notls='稽核紀錄在 %s 確認全部寫入，服務在 %s 停止。
請現在做快照。快照須在停機後開始，並確認資料目錄和 .env 都包含在
同一次可還原的備份中。'
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
MSG_up_will_2_ref='  2. 使用你以 --backup-ref 指定的自備備份，腳本這次不另做備份'
MSG_up_will_2_own='  2. 這次無法由腳本備份外接資料庫（原因見下方）；停止服務後，
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
MSG_up_bk_db='資料庫        %s'
MSG_up_bk_files='錄影與稽核檔  %s'
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
MSG_menu_backup='備份成單一檔案（可搬到其他主機，會暫停服務）'
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

# The backup of an external database (lib/dbext.sh, lib/backup_external.sh).
MSG_pb_summary_ext='版本 %s；外接資料庫 %s（PostgreSQL %s）；
主金鑰模式：%s'
MSG_pb_ext_tool='匯出工具：PostgreSQL %s 客戶端（隨這個版本發行、已核對）'
MSG_pb_ext_conn='連線：%s，%s'
MSG_pb_ext_mode_system='verify-full（由 PGSSLROOTCERT=system 決定，與後端相同）'
MSG_pb_ext_verify_none_none='不驗證伺服器憑證'
MSG_pb_ext_verify_none_file='不驗證伺服器憑證（CA 檔仍會放進備份檔）'
MSG_pb_ext_verify_ca_system='以系統信任的憑證機構驗證伺服器憑證，不核對主機名稱'
MSG_pb_ext_verify_ca_file='以 CA 檔驗證伺服器憑證，不核對主機名稱（CA 會放進備份檔）'
MSG_pb_ext_verify_full_system='以系統信任的憑證機構驗證伺服器'
MSG_pb_ext_verify_full_file='以 CA 檔驗證伺服器（CA 會放進備份檔）'
MSG_pb_ext_standby='備份期間不要啟動備援主機接手這個資料庫，否則備份可能不一致。'
MSG_pb_pause_ext='會暫停後端、連線服務與網頁，約 %s（外接資料庫不受影響）。
資料取完後自動啟動並等待就緒，之後再花約 %s組成並檢查備份檔。'
MSG_pb_step_stop_ext='停止服務（外接資料庫不受影響）'
MSG_pb_ext_and='、'
MSG_pb_ext_no_tool='外接資料庫是 PostgreSQL %s，這個版本只帶 %s 的匯出工具，
腳本只用與伺服器主版本相同的工具。沒有停止任何服務。
請用你們自己的資料庫備份程序；升級時可改用自備備份（--backup-ref）。'
MSG_pb_ext_unreachable='連不上外接資料庫 %s（使用 .env 的 DB_USER、
DB_NAME、DB_SSLMODE）。原因記在紀錄檔。沒有停止任何服務。'
MSG_pb_ext_unreachable_hint='可依序檢查：
  1. 這台主機能否連到該位址與連接埠（名稱解析、防火牆）
  2. 後端目前能否連上資料庫：%s
  3. DB_SSLMODE 與伺服器的 TLS 設定是否相符
  4. DB_USER 的密碼是否在資料庫端被改過'
MSG_pb_ext_no_image='這台主機沒有外接資料庫用的匯出工具映像（PostgreSQL 16／17／18 客戶端，
應在安裝或升級時取得）。沒有停止任何服務。請載入這個版本（%s）的
離線映像包：'
MSG_pb_ext_unsupported='外接資料庫有這個備份不支援的設定，換到新的資料庫伺服器時無法照原樣重建：
%s
沒有停止任何服務。請用你們自己的資料庫備份程序，或先調整上面各項。'
MSG_pb_ext_dep_ts='自訂表空間：%s（%s 個物件）'
MSG_pb_ext_dep_owner='擁有者不只 %s：另有 %s（%s 個物件）'
MSG_pb_ext_dep_ext='擴充套件：%s'
MSG_pb_ext_dep_ca='CA 檔 PGSSLROOTCERT=%s 不在腳本找得到的位置'
MSG_pb_ext_dep_cert='用戶端憑證 PGSSLCERT=%s 不在腳本找得到的位置'
MSG_pb_ext_dep_keypath='用戶端私鑰 PGSSLKEY=%s 不在腳本找得到的位置'
MSG_pb_ext_dep_key='用戶端私鑰 PGSSLKEY 放在會被打包的稽核目錄下'
MSG_pb_ext_dep_key_rec='用戶端私鑰 PGSSLKEY 放在會被打包的錄影目錄下'
MSG_pb_ext_dep_sysca='DB_SSLMODE=verify-ca 但匯出工具裡沒有系統 CA 檔，無法以相同方式驗證伺服器'
MSG_pb_ext_roles='外接資料庫裡有權限授予其他角色：%s。
換到新的資料庫伺服器時，這些角色要先建立，否則還原後的權限會不同。'

# ---- upgrade of an external database, and step 7 as one backup file ----
MSG_up_bk_file='備份檔  %s  %s'
MSG_up_bk_unrecorded='備份檔已完成：%s
但沒能寫進 state.json。升級已停下，服務維持停止，沒有換版。'
MSG_st_gone_unchecked='確認舊版已停止（服務已停止；外接資料庫的連線數腳本查不到，
請確認沒有其他主機的後端連著這個資料庫，例如備援主機）'
MSG_up_no_space_hint='可以：把舊的備份檔搬到別處後刪除。'
MSG_up_ext_major_sep='／'
MSG_up_ext_own_version='這次無法由腳本備份外接資料庫：外接資料庫是 PostgreSQL %s，
這個版本沒有同主版本的匯出工具。第 7 步只能用你自己的備份。'
MSG_up_ext_own_image='這次無法由腳本備份外接資料庫：取不到外接資料庫用的匯出工具映像
（PostgreSQL %s 客戶端，原因記在紀錄檔）。
第 7 步只能用你自己的備份。'
MSG_up_ext_own_connect='這次無法由腳本備份外接資料庫：連不上
外接資料庫 %s，原因記在紀錄檔。
第 7 步只能用你自己的備份。'
MSG_up_ext_own_unsupported='這次無法由腳本備份外接資料庫，第 7 步只能用你自己的備份。
外接資料庫有這個備份不支援的設定：'
MSG_up_ext_ni_version='無法由腳本備份外接資料庫（外接資料庫是 PostgreSQL %s，這個版本沒有
同主版本的匯出工具），而這次是非互動執行（沒有終端機，或帶了 --yes），
無法改選自備備份。沒有做任何變更。請依序：'
MSG_up_ext_ni_image='無法由腳本備份外接資料庫（取不到外接資料庫用的匯出工具映像：
PostgreSQL %s 客戶端，原因記在紀錄檔），而這次是非互動執行
（沒有終端機，或帶了 --yes），無法改選自備備份。
沒有做任何變更。請依序：'
MSG_up_ext_ni_connect='無法由腳本備份外接資料庫（連不上外接資料庫 %s，
原因記在紀錄檔），而這次是非互動執行（沒有終端機，或帶了 --yes），
無法改選自備備份。沒有做任何變更。請依序：'
MSG_up_ext_ni_unsupported='無法由腳本備份外接資料庫（外接資料庫有下列這個備份不支援的設定），
而這次是非互動執行（沒有終端機，或帶了 --yes），無法改選自備備份。
沒有做任何變更。'
MSG_up_ext_ni_order='請依序：'
MSG_up_ext_ni_1='1. 排空稽核紀錄並停止服務：'
MSG_up_ext_ni_2='2. 確認服務已停止：'
MSG_up_ext_ni_3='3. 在停機之後開始你自己的備份，涵蓋外接資料庫、資料目錄、.env 與 tls/，
   記下備份開始的時間。'
MSG_up_ext_ni_3_notls='3. 在停機之後開始你自己的備份，涵蓋外接資料庫、資料目錄與 .env，
   記下備份開始的時間。'
MSG_up_ext_ni_4='4. 以下列旗標重跑升級：'
MSG_up_ext_ni_flags='--backup-ref <快照名稱> --backup-time "YYYY-MM-DD HH:MM" \\
--backup-restore <還原程序位置>'

# ---------- restore：入口、選項與還原種類 ----------
MSG_help_cmd_restore='  restore <備份檔>     從可攜備份檔還原。已安裝的主機：先做安全備份，
                       再取代現有資料。尚未安裝的主機：先安裝備份當時的
                       版本，再還原
  restore --resume     接續上一次沒有完成的還原，包括解封後的主金鑰核對
  restore --revert     用還原前的安全備份還原回去
  restore --abandon    放棄新主機上沒有完成的還原，回到尚未安裝'
MSG_help_restore_options='restore 的選項
  --same-host | --new-host     沒有終端機時必須指明是哪一種還原
  --confirm-data-loss          沒有終端機時確認會覆蓋現有資料（與 --yes 一起用）
  --passphrase-file <檔>       加密備份的通行密語檔（權限規則與 backup 相同）
  --no-checksum-file           沒有 .sha256 校驗檔也繼續（仍逐一核對檔內雜湊）
  --package <安裝包>           備份版本的安裝包，同一目錄要有 SHA256SUMS
                               （離線用）
  --images <離線包>            備份版本的離線映像包
  --backup-ref、--backup-time、--backup-restore
                               以服務停止後的自備備份代替安全備份
                               （安全備份沒完成時也可以加在 --resume）
  --data-path、--tls-domain、--tls-ip-san、--public-base-url
                               新主機的主機值（不給時用這台的建議值）
  --db-client-cert、--db-client-key
                               外接資料庫的用戶端憑證與私鑰
  --accept-grant-loss          外接資料庫缺少角色時，略過授權給這些角色的項目
  --nginx-template <路徑>      他機上自訂 nginx 範本的新位置（原路徑不可用時）'
MSG_usage_restore_only='選項 %s 只適用於 restore。請見：custodexa.sh --help'
MSG_rs_no_file='請指定備份檔：custodexa.sh restore <備份檔>。
請見：custodexa.sh restore --help'
MSG_rs_option_with='選項 %s 不能和 %s 一起用。請見：custodexa.sh restore --help'
MSG_rs_flow_both='--same-host 與 --new-host 不能同時使用。'
MSG_rs_flow_needed_same='沒有終端機時要指明是哪一種還原。這台已經安裝，資料會被備份取代：
請加 --same-host。'
MSG_rs_flow_needed_new='沒有終端機時要指明是哪一種還原。這台尚未安裝：請加 --new-host。'
MSG_rs_flow_wrong_same='這台尚未安裝，這是還原到新主機：請改用 --new-host，不是 --same-host。'
MSG_rs_flow_wrong_new='這台已經安裝，資料會被取代：請改用 --same-host，不是 --new-host。'
# Going back after an upgrade.
MSG_rb_flags_only='--resume 與 --revert 只能用於 rollback 與 restore。'
MSG_rb_flags_conflict='--resume 與 --revert 請擇一使用。'
MSG_rb_no_pending='沒有尚未完成的指回可以接續。沒有做任何變更。'
MSG_rb_confirm='開始嗎？[y/N]'
MSG_rb_preview='回到上一版：預覽（還沒有做任何變更）'
MSG_rb_versions='目前版本   %s
回到       %s（升級前的版本）'
MSG_rb_basis_same='資料庫     升級後沒有結構變更，和升級前的紀錄相同'
MSG_rb_basis_not_started='資料庫     新版沒有啟動過，資料庫沒有被改動'
MSG_rb_basis_compatible='資料庫     升級後有 %s 項結構變更，但 %s 的發行清單註明
           可以直接回到 %s（發版前已演練）'
MSG_rb_basis_compatible_one='資料庫     升級後有 %s 項結構變更，但 %s 的發行清單註明
           可以直接回到 %s（發版前已演練）'
MSG_rb_keep_data='所以只換回舊版，資料、設定檔與憑證保持不動，不需要還原備份。'
MSG_rb_images='舊版映像   %s 個都在這台主機，啟動後會核對執行中的就是它們'
MSG_rb_steps='會做的事：停止服務 → 再確認資料庫沒有變動後換回 %s →
啟動 → 核對版本與執行中的映像'
MSG_rb_keep_records='升級之後產生的紀錄都會保留。'
MSG_rb_step_stop='停止服務'
MSG_rb_step_stopped='服務已停止'
MSG_rb_step_switch='再確認資料庫沒有變動，換回 %s'
MSG_rb_step_revert='換回 %s'
MSG_rb_step_start='啟動服務'
MSG_rb_step_check='核對：後端回報 %s，執行中的映像和升級前相同'
MSG_rb_check_health='核對：後端在 %s 秒內沒有就緒'
MSG_rb_check_diff='核對：執行中的版本或映像與記錄不同：%s'
MSG_rb_done='已回到 %s。'
MSG_rb_unseal='系統已封存，請到 %s 解封。'
MSG_rb_upgrade_later='之後要再升級，照常執行 upgrade。'
MSG_rb_revert_title='回到 %s（這次指回開始之前的版本）'
MSG_rb_state_title='目前狀態'
MSG_rb_state_version='目前版本：%s'
MSG_rb_state_links='記錄的版本：%s；current 連結：%s'
MSG_rb_state_services='執行中的服務：%s'
MSG_rb_unchanged_data='資料、設定檔與憑證都沒有被改動'
MSG_rb_resume='查明原因後，接續完成這次回到上一版：'
MSG_rb_revert='或回到升級後的 %s：'
MSG_rb_resume_revert='接續回到升級後的 %s：'
MSG_rb_refused='不能直接回到 %s：升級後資料庫已經被 %s 改過。
沒有做任何變更，%s。'
MSG_rb_services_running='服務仍在執行'
MSG_rb_services_stopped='服務維持停止'
MSG_rb_refused_after='不能直接回到 %s：停止服務後再確認，資料庫已經被 %s 改過。
沒有換版；應用服務已停止，資料庫仍在執行。'
MSG_rb_reason_changed='原因       升級後資料庫有 %s 項結構變更（%s），
           %s 無法正確使用變更後的資料庫'
MSG_rb_reason_unreadable='原因       讀不到資料庫目前的結構，無法確認升級後有沒有變更'
MSG_rb_more='，另有 %s 項'
MSG_rb_restore='要回到 %s，請用升級前的備份還原。還原會先讓你確認，
再把資料與版本都回到升級前；升級之後產生的資料會被取代。'
MSG_rb_keep_new='不還原、讓 %s 繼續服務：'
MSG_rb_too_old='不能直接回到 %s：腳本只能回到 1.16.0 以後的版本。
沒有做任何變更。'
MSG_rb_no_previous='沒有可以回到的上一版，沒有做任何變更。'
MSG_rb_premise_none='這個部署沒有由腳本升級過。'
MSG_rb_premise_changed='上次升級之後，版本紀錄已經改變。'
MSG_rb_premise_link='目前執行的版本與紀錄不一致。'
MSG_rb_already='上一次版本變動已經是回到上一版（%s 從 %s 回到 %s）。
腳本只能退一版；要回到 %s，請照常執行 upgrade。'
MSG_rb_before_switch='上次的升級停在第 %s 步，還沒有換到新版，不需要回到上一版。'
MSG_rb_status_hint='查看這個部署的狀態：'
MSG_rb_images_bad='回到 %s 需要升級前的映像，但其中 %s 個不在這台主機或與升級前不同，
沒有做任何變更。'
MSG_rb_image_missing='%s  不在這台主機'
MSG_rb_image_diff='%s  這台的映像與升級前記錄不同
           升級前 %s  目前 %s'
MSG_rb_load='請載入 %s 的離線映像包後再執行一次：'
MSG_rb_upgrade_hint='決定回到 %s 時執行下面的指令。腳本會先確認資料庫沒有被新版改過，
才直接換回 %s；改過的話會告訴你怎麼用上面的備份還原。
停機之前會先問你：'
MSG_rb_upgrade_done='需要回到 %s    sudo %s/custodexa.sh rollback%s'
MSG_status_upgrade_rolled_back='上次升級 %s → %s，
已於 %.0s%s 回到 %s'
MSG_status_rollback_unfinished='回到上一版沒有完成（從 %s 回到 %s，停在第 %s 步）'
MSG_status_rollback_reverting='回到升級後的版本沒有完成（回到 %s，停在第 %s 步）'
MSG_status_rollback_reverted='上次回到上一版已取消，回到 %s'
MSG_status_rollback_refused='上次回到上一版在換版前停下：
資料庫已被 %s 改過，仍是 %s'
MSG_status_upgrade_failed_handed='%s → %s 在第 %s 步失敗，%s，之後由還原接手。紀錄檔：'
MSG_help_cmd_rollback='  rollback             回到升級前的版本：資料庫沒有被新版改過時，只換回舊版，
                       資料不動；改過時不做任何變更，並告訴你怎麼還原
  rollback --resume    接續上一次沒有完成的回到上一版
  rollback --revert    放棄上一次沒有完成的回到上一版，回到升級後的版本'
MSG_help_opt_resume='  --resume             （rollback、restore）接續未完成的作業'
MSG_help_opt_revert='  --revert             （rollback、restore）撤回未完成的作業'

MSG_rb_refused_unreadable='不能直接回到 %s：升級後資料庫可能已被 %s 改過。
沒有做任何變更，%s。'

MSG_rb_refused_unreadable_after='不能直接回到 %s：停止服務後再確認，無法確認 %s
沒有改過資料庫。沒有換版；應用服務已停止，資料庫仍在執行。'

MSG_rb_image_unrecorded='%s  缺少升級前的映像 ID 紀錄'

MSG_rb_state_not_ready='已換回 %s，服務已啟動但後端沒有就緒'

MSG_rb_state_before='還沒有換版，仍是 %s'

MSG_rb_state_start_failed='已換回 %s，服務沒有全部啟動'

MSG_rb_reverted='回到 %s（這次指回開始之前的版本）'

MSG_rb_no_services='無'

MSG_rb_basis_compatible_unreadable='資料庫     讀不到目前結構，但 %s 的發行清單註明
           可以直接回到 %s（發版前已演練）'

MSG_rb_step_check_revert='核對：後端回報 %s，執行中的映像和這次指回前相同'

MSG_status_rollback_unreadable='上次回到上一版在換版前停下：
資料庫可能已被 %s 改過，仍是 %s'

MSG_rb_images_unverified='回到 %s 所需的發行資料或升級前映像 ID 紀錄無法核對，
因此無法確認所需映像都與升級前一致。沒有做任何變更。'

MSG_rb_release_unverified='讀不到所需的發行資料。'

# Reading a portable backup before a restore.
MSG_rs_unchanged='沒有變更任何資料。'

MSG_rs_bad='備份檔不完整或被改動過，不能還原：'

MSG_rs_copy_again='請改用另一份備份，或從原處重新複製這個檔案（連同 .sha256）。'

MSG_rs_bad_sidecar='校驗檔與備份檔不符。'

MSG_rs_bad_members='成員多出、缺少或重複。'

MSG_rs_bad_type='成員是目錄、連結或帶路徑。'

MSG_rs_bad_manifest='備份清單欄位缺少或不合法：%s。'

MSG_rs_bad_sums='成員清單與 SHA256SUMS 不一致。'

MSG_rs_bad_hash='%s 的雜湊和備份時記下的不同。'

MSG_rs_bad_cross='發行清單、migration、主金鑰指紋或版本紀錄與備份清單不符。'

MSG_rs_bad_inner='內層壓縮檔含不允許的路徑或連結。'

MSG_rs_bad_name='檔名與加密檔頭不符。'

MSG_rs_bad_decrypt='加密檔已截斷或長度不合法。'

MSG_rs_bad_read='讀不到備份檔。'

MSG_rs_bad_grants='內建資料庫授權給其他角色：%s。
請照文件「備份與還原」第 5 節手動還原。'

MSG_rs_bad_grants_read='讀不到資料庫匯出檔的授權項目。'

MSG_rs_reading='讀取備份檔 %s'

MSG_rs_sum_ok='校驗檔相符'

MSG_rs_sum_absent='沒有校驗檔，改以檔內雜湊核對'

MSG_rs_no_sum='找不到校驗檔 %s。
非互動執行要在沒有校驗檔時繼續，請加 --no-checksum-file。'

MSG_rs_missing_sum='找不到校驗檔 %s，
無法確認這個檔案在搬運途中沒有損壞。'

MSG_rs_missing_sum_checks='繼續的話，檔內每個部分都要和備份時記下的雜湊相符、各項紀錄彼此一致，
才會往下做；
任何一項不符就停下，不會變更任何資料。'

MSG_rs_missing_sum_enc='這是加密檔：少了校驗檔，解不開時無法分辨是通行密語錯誤還是檔案損壞。'

MSG_rs_missing_sum_ask='沒有校驗檔也要繼續嗎？[y/N]'

MSG_rs_pass_intro='這個備份檔有加密。請輸入建立備份時設定的通行密語（輸入時不會顯示）：'

MSG_rs_pass_prompt='通行密語：'

MSG_rs_pass_needed='這份備份已加密。非互動執行請使用 --passphrase-file。'

MSG_rs_decrypt_matched='解不開：通行密語不對（檔案本身已核對完整）。還可以再試 %s 次。'

MSG_rs_decrypt_absent='解不開：通行密語不對，或檔案已經損壞（沒有校驗檔，無法分辨）。
還可以再試 %s 次。'

MSG_rs_decrypt_cancel='三次都沒有解開，還原已取消。沒有變更任何資料。'

MSG_rs_no_openssl='這台主機沒有 %s 發行版的 openssl 工具映像。
還原需要它；請先載入該版本的離線映像包。'

MSG_rs_parts='逐一核對內容（%s 個部分）'

MSG_rs_manifest='備份清單：格式 1，版本 %s，%s 備份'

MSG_rs_cross_ok='交叉核對：發行清單、migration、主金鑰指紋一致'

MSG_rs_old_file='這不是 1.16.0 起產生的備份檔，腳本不能還原它。'

MSG_rs_old_folder='%s 是 1.16.0 之前的備份資料夾，
沒有備份清單，看不出版本與部署型態。'

MSG_rs_no_manifest='這個檔裡沒有備份清單。'

MSG_rs_old_guide='這類備份只能在原主機照文件「備份與還原」第 5 節手動還原，
或先把原主機升級到 1.16.0 以上，再重新備份。'


# Checking the data and keys before a restore.
MSG_rs_data_old='這份備份的資料屬於 %s，早於 1.16.0，腳本不能還原它。'

MSG_rs_data_old_guide='是升級時替 %s 部署做的升級前備份。
1.16.0 之前的版本解封後不會回報主金鑰識別，
腳本無法確認還原後的主金鑰是否正確，
所以不會開始還原。請照文件「備份與還原」手動還原：
  先照「從單一備份檔取出各檔」取出各檔；
  要在這台回到升級前的版本，接著照「以管理腳本升級後，
  回到升級前的版本」；
  要還原到另一台主機，接著照「還原程序」。'

MSG_rs_engine_old='這個管理腳本是 %s，備份的資料屬於較新的 %s。'

MSG_rs_engine_old_guide='還原要用不舊於備份版本的管理腳本。
新主機：以 get-custodexa.sh 取得 %s 以上的版本，再用它還原。
已安裝的主機：先升級到 %s 以上，再還原。'

MSG_rs_fp_missing='這份備份沒有記下主金鑰指紋（備份時讀不到唯一的一個），
腳本無法確認還原後的主金鑰是否正確，所以不會開始還原。'

MSG_rs_fp_manual='請照文件「備份與還原」第 5 節手動還原，並照第 6 節逐項人工核對金鑰清冊。'

MSG_rs_hsm='這份備份的主金鑰模式是 hsm。這個版本沒有可用的 HSM 實作，
腳本不能還原它。'

MSG_rs_external='這是外接資料庫部署的備份，這個版本的腳本還不能還原它。'

MSG_rs_key_mismatch='設定檔裡的主金鑰和這份備份的資料不符：'

MSG_rs_key_fingerprints='設定檔的主金鑰指紋   %s
備份記下的指紋       %s'

MSG_rs_key_wrong='用這把主金鑰還原，加密保存的憑證會全部解不開，所以不會開始還原。
請改用另一份完整的備份。'

MSG_rs_key_ok='設定檔裡的主金鑰指紋 %s 與備份相符'

MSG_rs_jwt_ok='設定檔的登入權杖簽章金鑰指紋與備份快照相符'

MSG_rs_jwt_unknown='設定檔的登入權杖簽章金鑰：備份快照沒有記下指紋，未核對'

MSG_rs_bad_jwt='設定檔的登入權杖簽章金鑰指紋與備份快照不符。'

MSG_rs_bad_secret='設定檔缺少必要密鑰，或含有不可用的範本值：%s。'

MSG_rs_extracted='取出到暫存目錄 %s'


MSG_rs_bad_release='發行清單的雜湊或版本與備份清單不符。'

MSG_rs_bad_migrations='migration 摘要或筆數與備份清單不符。'

MSG_rs_bad_fingerprint='主金鑰指紋與快照不符。'

MSG_rs_bad_state='state.json 的版本與備份清單不符。'

MSG_rs_parts_enc='解密並逐一核對內容（%s 個部分）'

MSG_rs_bad_decrypt_tool='無法執行解密工具。'

# Obtaining the backup version and checking its data structure.
MSG_rs_release_absent='%s 沒有發行附檔，無法在這台主機安裝備份當時的版本。'

MSG_rs_release_absent_guide='這份備份的資料屬於 %s，只能用同一版還原；腳本不會改裝別的版本。
如果你手上有 custodexa-%s.tar.gz 與同一目錄的 SHA256SUMS，可以指定它：'

MSG_rs_release_other='否則請改用其他版本的備份。'

MSG_rs_release_download='下載 %s 的安裝包失敗（連不上 github.com）。'

MSG_rs_release_offline='這台主機不能上網時，把 custodexa-%s.tar.gz 與 SHA256SUMS 放在同一目錄，
再以 --package 指定；映像以 --images 指定 %s 的離線映像包。'

MSG_rs_release_manifest='%s 安裝包裡的發行清單，和備份時記下的不同。'

MSG_rs_release_manifest_guide='安裝包可能不是正式發行的那一份；腳本不會用它還原。'

MSG_rs_migration_bad='備份的資料含 %s 不認得的資料結構變更，不能用 %s 還原：'

MSG_rs_migration_unknown='%s（不在 %s 的發行清單裡）'

MSG_rs_migration_missing='%s（%s 需要這項，但備份快照裡沒有）'

MSG_rs_migration_guide='這表示備份時資料已經被較新的版本改過。
腳本不會把較新的資料放進較舊的版本。'

MSG_rs_migration_missing_guide='備份缺少這個版本所需的資料結構變更，腳本不會用它還原。'


# Host values and the custom template destination.
MSG_rs_host_intro='以下四項依這台主機設定，其餘設定一律沿用備份。'

MSG_rs_host_intro_external='以下資料目錄與對外網址依這台主機設定，其餘設定一律沿用備份。'

MSG_rs_host_data_path='資料目錄 DATA_PATH'

MSG_rs_host_tls_domain='憑證主機名 TLS_DOMAIN'

MSG_rs_host_tls_ip_san='憑證 IP TLS_IP_SAN'

MSG_rs_host_public_base_url='對外網址 PUBLIC_BASE_URL'

MSG_rs_host_values='       備份來源  %s
       這台建議  %s'

MSG_rs_host_ask_path='直接按 Enter 用建議值，輸入 - 沿用備份來源的值，
或輸入其他絕對路徑 > '

MSG_rs_host_ask='直接按 Enter 用建議值，輸入 - 沿用備份來源的值，或輸入其他值 > '

MSG_rs_data_absolute='DATA_PATH 必須是絕對路徑。'

MSG_rs_data_nonempty='新主機的這個目錄必須沒有資料庫或稽核資料：%s。'

MSG_rs_host_tls_nginx_template='自訂 nginx 範本 TLS_NGINX_TEMPLATE'

MSG_rs_template_source='       備份來源  %s
                 （這台無法使用 %s 下的原位置）'

MSG_rs_template_ask='請輸入這台要放範本的絕對路徑，設定檔會改指向它 > '

MSG_rs_template_needed='這台無法使用範本的原位置：%s。
請以 --nginx-template 指定新的絕對路徑。'

MSG_rs_template_invalid='範本須為絕對路徑，父目錄須存在，且不能是連結、目錄
或發行版管理的路徑：%s。'


# Space estimates before a restore.
MSG_rs_space_bad='空間不夠，不會開始還原：'

MSG_rs_space_row='%s（%s）需要 %s GB，還有 %s GB'

MSG_rs_space_margin='數字含 10%%～20%% 的估算餘裕；備份檔記下的大小是備份當時的估計。'

MSG_rs_space_work='暫存目錄'

MSG_rs_space_safety='安全備份'

MSG_rs_space_data='資料目錄'

MSG_rs_space_images='映像'

MSG_rs_space_unknown='讀不到 %s 的可用空間，不會開始還原。'

MSG_rs_space_estimate='無法估算安全備份所需的目前資料庫大小，不會開始還原。'

# Restore preview and confirmation.
MSG_rs_label_backup='  備份檔     '
MSG_rs_label_data_version='  資料版本   '
MSG_rs_label_install='  會先安裝   '
MSG_rs_label_version='  版本       '
MSG_rs_label_deployment='  部署型態   '
MSG_rs_label_restores='  會還原     '
MSG_rs_label_recordings='  錄影       '
MSG_rs_label_host='  主機值     '
MSG_rs_label_replaced='  會取代     '
MSG_rs_label_safety='  安全備份   '
MSG_rs_label_kept='  保留       '
MSG_rs_label_downtime='  停機       '
MSG_rs_label_space='  空間       '

MSG_rs_preview_new='還原預覽：這台新主機（還沒有變更任何資料）'

MSG_rs_preview_same='還原會取代這台現有的資料，備份之後產生的紀錄都會遺失'

MSG_rs_preview_encrypted='已加密'

MSG_rs_preview_plain='未加密'

MSG_rs_backup_here='%s 在這台主機（%s）備份'

MSG_rs_backup_source='%s 在 %s 備份；%s'

MSG_rs_backup_integrity='備份檔內部完整性：已核對'

MSG_rs_data_engine='%s（這個管理腳本是 %s）'

MSG_rs_versions='目前 %s，還原後 %s'

MSG_rs_versions_changed='目前 %s，還原後 %s（版本會一起回到備份時）'

MSG_rs_other_host='[WARN] 這份備份來自另一台主機 %s；
       這台的資料會被它取代'

MSG_rs_package_checked='安裝包 %s：校驗和相符'

MSG_rs_package_local='安裝包校驗和：未重新核對；使用本機已有的發行版'

MSG_rs_signature_ok='發行者簽章：已驗證'

MSG_rs_signature_no_cosign='發行者簽章：這台沒有 cosign，沒有驗證'

MSG_rs_signature_no_bundle='發行者簽章：沒有簽章檔，沒有驗證'

MSG_rs_signature_bad='[WARN] 發行者簽章不符'

MSG_rs_signature_local='發行者簽章：未重新驗證本機已有的發行版'

MSG_rs_manifest_identical='發行清單與備份裡記下的逐位元組相同'

MSG_rs_preview_images_offline='映像 %s 個，來自離線包 %s'

MSG_rs_preview_images_local='映像 %s 個，本機已有'

MSG_rs_preview_images_source='映像 %s 個；程式映像將從原始碼建置'

MSG_rs_preview_images_auto='映像 %s 個；缺少的映像將依序從本機離線包、
registry、原始碼建置取得'

MSG_rs_deployment='內建資料庫；%s；主金鑰模式：%s'

MSG_rs_tls_selfsigned='自簽憑證'

MSG_rs_tls_provided='自備憑證'

MSG_rs_tls_external='外部入口'

MSG_rs_provider_ui='網頁輸入'

MSG_rs_provider_env='設定檔提供'

MSG_rs_provider_kms='金鑰託管'

MSG_rs_restores_new='資料庫 %s、稽核檔 %s、設定檔 .env'

MSG_rs_restores_same='資料庫、稽核檔'

MSG_rs_restores_tls='、憑證 tls/'

MSG_rs_settings_same='設定檔 .env 回到備份時的內容，
包含登入簽章金鑰、資料庫密碼等密鑰值；
DATA_PATH、TLS_DOMAIN、TLS_IP_SAN、PUBLIC_BASE_URL
保留這台目前的值'

MSG_rs_settings_same_external='設定檔 .env 回到備份時的內容，
包含登入簽章金鑰、資料庫密碼等密鑰值；
DATA_PATH、PUBLIC_BASE_URL 保留這台目前的值'

MSG_rs_preview_template='自訂 nginx 範本 → %s'

MSG_rs_template_repointed='（設定檔改指向此處）'

MSG_rs_template_keep='既有檔改名保留為 %s'

MSG_rs_recordings_restore='從備份放回；同名的現有檔案保留，不覆蓋'

MSG_rs_recordings_kept='這份備份不含錄影：現有錄影原地保留，不刪除也不覆蓋'

MSG_rs_recordings_missing='沒有放在備份檔裡（來源有 %s）；
完成後會列出要補的錄影'

MSG_rs_host_differences='主機值與備份不同：'

MSG_rs_host_difference='%s：備份 %s；這台 %s'

MSG_rs_reissue='位址和來源不同：沿用備份裡的憑證機構，
重簽一張這台位址的伺服器憑證'

MSG_rs_cert_mismatch='[WARN] 自備憑證不涵蓋這台的位址。請換成涵蓋此位址的憑證；
       腳本不修改它。'

MSG_rs_cert_unknown='[WARN] 無法核對自備憑證涵蓋的位址，請手動核對；腳本不修改它。'

MSG_rs_replaced='這台目前的全部資料與設定
（使用者、資產、授權、政策都回到備份時）：'

MSG_rs_counts_current='目前有稽核紀錄 %s 筆、連線紀錄 %s 筆'

MSG_rs_counts_backup='，
備份裡是 %s 筆、%s 筆'

MSG_rs_counts_caution='筆數差只是參考，不是會遺失的筆數：
刪除、修改與其他主機的資料都看不出來'

MSG_rs_counts_unknown='目前的筆數讀不到'

MSG_rs_safety_own='自備備份：%s
備份時間 %s'

MSG_rs_safety_script='開始覆蓋之前，先把目前的資料備份成
%s（不含錄影），
讀回驗證通過才往下做'

MSG_rs_safety_none='不需要：這台還沒有任何資料'

MSG_rs_kept='目前的資料庫、稽核檔、憑證目錄改名保留，不刪除：'

MSG_rs_downtime='約 %s 分鐘（安全備份 %s 分鐘、匯入 %s 分鐘、
啟動與核對 5 分鐘）'

MSG_rs_preview_space_same='%s 需要 %s GB，還有 %s GB'

MSG_rs_preview_env='主金鑰在設定檔裡，指紋 %s 已核對相符'

MSG_rs_preview_ui_same='[WARN] 主金鑰模式是網頁輸入：還原後系統會回到「已封存」，
       要有人到解封頁輸入主金鑰，指紋必須是 %s。'

MSG_rs_preview_ui_new='[WARN] 主金鑰模式是網頁輸入：還原要完成，得有人到解封頁輸入主金鑰，
       並用備份裡的管理者帳號登入授權。
       主金鑰指紋必須是 %s。'

MSG_rs_preview_kms='[WARN] 主金鑰由金鑰託管服務保管：還原要完成，得有人到解封頁
       核對託管服務並重新提供託管憑證；
       這台的位址要在託管服務允許的來源內。'

MSG_rs_after_noninteractive='完成並核對之後，會印出查詢最新版本的指令，不會自動升級。'

MSG_rs_after_same_version='完成並核對之後，會查詢最新版本，再問要不要升級。'

MSG_rs_after_newer_engine='完成並核對之後，會查詢最新版本，再問要不要升級
（這台已有 %s）。'

MSG_rs_confirm_version='確認請輸入還原後的版本號 %s：'

MSG_rs_confirm_cancel='輸入的不是 %s，還原已取消。沒有變更任何資料。'

MSG_rs_confirm_new='開始還原嗎？[y/N]'

MSG_rs_confirm_flags='不輸入版本號就取代這台資料，必須同時指定
--yes 與 --confirm-data-loss。'

MSG_rs_confirm_new_flags='非互動執行請以 --yes 確認還原。'

MSG_rs_preview_space_new='需要 %s GB；%s 還有 %s GB'

MSG_rs_kept_no_tls='目前的資料庫、稽核檔目錄改名保留，不刪除：'

MSG_rs_control_revert='正在還原回去，先把它做完。'

MSG_rs_control_abandon='正在放棄這次還原，先把它做完。'

MSG_rs_control_engine='請用開始這次還原的管理腳本接續處理。'

MSG_rs_control_placed='還原的資料已放好，但服務要由接續啟動，
才會核對執行中的映像與主金鑰。'

MSG_rs_control_before='還原尚未覆蓋資料。請用 --revert 啟動原本的服務。'

MSG_rs_control_unchecked='還原停在第 %s 步，資料還沒有核對，不能啟動服務。'

MSG_rs_control_choices='重跑接續，或用安全備份還原回去：'

MSG_rs_control_after_unseal='解封之後完成核對：'

MSG_rs_control_previous='上一次還原還沒有結束，先接續、還原回去或放棄。'

MSG_rs_control_own='請依你登記的還原程序，使用自備備份 %s：'

MSG_rs_status_title='還原'

MSG_rs_status_pending='還原未完成：%s（%s 開始，資料版本 %s）'

MSG_rs_status_from='來源 %s'

MSG_rs_status_resume='接續：%s'

MSG_rs_status_failed='還原停在第 %s 步（失敗）'

MSG_rs_status_done='最近一次還原：%s 完成，來源 %s'

MSG_rs_status_kept='保留的還原前資料 %s 處，第 6 節核對無誤後可以刪除'

MSG_rs_status_retained='保留的資料 %s 處'

MSG_rs_status_reverted='最近一次還原：%s 已還原回去'

MSG_rs_status_abandoned='最近一次還原：%s 已放棄，回到尚未安裝'

MSG_rs_status_revert='還原回去還沒有做完'

MSG_rs_status_abandon='放棄這次還原還沒有做完'

MSG_menu_rs_state='目前狀態：還原未完成（%s；資料版本 %s）'

MSG_menu_rs_state_revert='目前狀態：還原回去還沒有做完'

MSG_menu_rs_state_abandon='目前狀態：放棄這次還原還沒有做完'

MSG_menu_rs_resume='接續還原'

MSG_menu_rs_unseal='接續還原（解封之後完成核對）'

MSG_menu_rs_revert='用安全備份還原回去'

MSG_menu_rs_abandon='放棄這次還原，回到尚未安裝'

MSG_menu_rs_finish_revert='把還原回去做完'

MSG_menu_rs_finish_abandon='把放棄這次還原做完'

MSG_rs_control_upgrade='還原還沒有完成（%s；%s 開始），不能升級。'

MSG_rs_control_backup='還原還沒有完成（%s；%s 開始），不能備份。'

MSG_rs_control_rollback='還原還沒有完成（%s；%s 開始），不能回退。'

MSG_rs_phase_checked='已檢查、等待放置發行版'

MSG_rs_phase_prepared='發行版已就緒、等待安全備份'

MSG_rs_phase_safety='安全備份已就緒'

MSG_rs_phase_stopped='服務已停止'

MSG_rs_phase_swapped='原資料已保留、等待匯入'

MSG_rs_phase_imported='已匯入、等待核對資料'

MSG_rs_phase_db_checked='資料庫已核對、等待放回檔案'

MSG_rs_phase_placed='資料已放好、等待接續啟動服務'

MSG_rs_phase_started='服務已啟動、等待就緒與主金鑰核對'

MSG_rs_phase_awaiting_unseal='已匯入、等待解封後核對'

MSG_rs_phase_done='已核對完成'

MSG_rs_control_choices_new='重跑接續，或放棄這次還原：'

# 1 arguments
MSG_rs_safety_reason_fingerprint='目前資料庫讀不到唯一的主金鑰識別（讀到 %s 個），
這樣的備份會缺主金鑰指紋。'

# 0 arguments
MSG_rs_safety_reason_hsm='目前的主金鑰模式是 hsm。'

# 0 arguments
MSG_rs_safety_reason_key='設定檔的主金鑰指紋與資料庫不符。'

# 1 arguments
MSG_rs_safety_reason_secret='設定檔缺少必要密鑰：%s。'

# 1 arguments
MSG_rs_safety_reason_engine='這個管理腳本比目前版本舊，請使用 %s。'

# 1 arguments
MSG_rs_safety_reason_old='目前版本 %s 早於 1.16.0，它的備份需要手動還原。'

# 1 arguments
MSG_rs_safety_reason_manifest='發行清單不存在或與 current/MANIFEST.json 不同：
%s'

# 1 arguments
MSG_rs_safety_reason_images='目前版本的映像不在本機：%s。
請先以 load 載入該版的離線映像包。'

# 0 arguments
MSG_rs_safety_preflight_warn='腳本為這台做的安全備份，將無法用 restore --revert 自動還原：'

# 0 arguments
MSG_rs_safety_preflight_own='所以這次要用你自己在服務停止後取得的備份（例如儲存快照）當安全備份。
服務還沒有停止，沒有變更任何資料。'

# 1 arguments
MSG_rs_safety_preflight_fail='腳本為這台做的安全備份將無法自動還原（%s）。
非互動執行請以 --backup-ref、--backup-time、
--backup-restore 登記服務停止後的自備備份。'

# 0 arguments
MSG_rs_safety_choose_title='還原會覆蓋這台的資料，開始之前要先備份目前的資料。'

# 0 arguments
MSG_rs_safety_choose_again='上次的安全備份沒有完成。這次要怎麼備份目前的資料？'

# 1 arguments
MSG_rs_safety_choose_script='[1] 由腳本備份（預設）：停止服務後備份資料庫、稽核檔、設定與憑證，
    約 %s 分鐘，不含錄影（錄影不會被還原動到）'

# 1 arguments
MSG_rs_safety_choose_retry='[1] 由腳本重新備份（預設）：停止服務後備份資料庫、稽核檔、設定與憑證，
    約 %s 分鐘，不含錄影（錄影不會被還原動到）'

# 0 arguments
MSG_rs_safety_choose_own='[2] 我會在服務停止後自己備份（例如儲存快照），再回來輸入它的識別'

# 0 arguments
MSG_rs_safety_choose_prompt='請選擇 [1-2]，直接按 Enter 使用預設：'

# 0 arguments
MSG_rs_safety_choose_only='請選擇 [2]：'

# 0 arguments
MSG_rs_safety_id='識別'

# 0 arguments
MSG_rs_safety_time='時間'

# 0 arguments
MSG_rs_safety_procedure='程序'

# 0 arguments
MSG_rs_safety_failed_title='3/10  安全備份'

# 0 arguments
MSG_rs_safety_failed_write='備份位置寫入失敗（No space left on device）。'

# 0 arguments
MSG_rs_safety_failed_read='安全備份讀回時核對不符，不能用來還原'

# 1 arguments
MSG_rs_safety_failed_unusable='安全備份完整，但這個腳本無法用它自動還原（%s）'

# 0 arguments
MSG_rs_safety_failed_body='還原前的安全備份沒有完成，所以不會開始覆蓋。資料沒有任何變更；
服務維持停止。'

# 0 arguments
MSG_rs_safety_resume='處理之後，重跑接續（從安全備份開始）：'

# 0 arguments
MSG_rs_safety_resume_own='改用自備備份接續：'

# 0 arguments
MSG_rs_safety_revert='或放棄還原、啟動原本的服務：'

# 0 arguments
MSG_rs_safety_use_own='也可以改用服務停止之後取得的自備備份：互動接續時選 [2]，
或在接續指令加上三個旗標：'

# 1 arguments
MSG_rs_safety_stop_time='自備備份的時間不能早於這次還原停止服務的 %s。'

# 0 arguments
MSG_rs_safety_restarted='服務正在執行、停機紀錄之後曾被啟動，或無法確認停機。
請先 restore --revert 再重新開始。'

# 0 arguments
MSG_rs_safety_flags_phase='自備備份三旗標只適用於安全備份尚未完成、且還沒有開始覆蓋的接續。'

# 0 arguments
MSG_rs_safety_enter='快照完成後，請輸入（會寫入還原紀錄）：'

# 0 arguments
MSG_rs_safety_setup_failed='無法建立安全備份目錄。'

# 0 arguments
MSG_rs_safety_failed_operation='無法寫入安全備份，詳細原因請見還原紀錄檔。'

MSG_rs_safety_reason_fingerprint_short='目前資料庫讀不到唯一的主金鑰識別'

MSG_rs_journal_uncertain='無法判定還原動作是否完成：%s。'

MSG_rs_journal_guide='請先停在這裡。變更這些路徑前，請依「備份與還原」的手動還原程序處理。'

MSG_rs_journal_missing='還原已開始覆蓋資料，但操作紀錄已遺失。
請以 --revert 使用安全備份還原回去。'

MSG_rs_import_start='資料庫服務無法啟動。'

MSG_rs_import_ready='資料庫尚無法透過 TCP 連線到目標資料庫。'

MSG_rs_import_encoding='資料庫的編碼、排序或字元分類與備份不同，匯入已停止。'

MSG_rs_import_failed='資料庫匯入失敗。接續時會保留半成品，並在空資料庫重新匯入。'

# ---------- 主選單：還原項與備份檔挑選；還原後的錄影 ----------
# 0 arguments
MSG_menu_restore_new='從備份檔還原到這台新主機（先安裝備份當時的版本）'

# 0 arguments
MSG_menu_restore='從備份檔還原（取代這台的資料，會停止服務）'

# 2 arguments: the backups folder, the current folder
MSG_menu_restore_found='從備份檔還原。在 %s 與目前目錄 %s 找到這些備份檔：'

# 2 arguments: the backups folder, the current folder
MSG_menu_restore_none='從備份檔還原。在 %s 與目前目錄 %s 沒有找到備份檔。'

# 0 arguments
MSG_menu_restore_encrypted='（已加密）'

# 0 arguments
MSG_menu_ask_restore='備份檔路徑，直接按 Enter 回到主選單 > '

# 1 argument: the number of files
MSG_rs_rec_put_back='錄影：從備份放回 %s 個檔案；同名的現有檔案保留，不覆蓋'

# 0 arguments
MSG_rs_rec_same_kept='錄影沒有從備份還原：這份備份不含錄影，現有錄影原地保留。
錄影檔可能和備份時點不一致：備份之後新錄的仍在磁碟上，但系統不會再列出；
備份之後被清掉的不會回來。'

# 0 arguments
MSG_rs_rec_all_here='錄影：系統記錄的錄影檔都在這台'

# 3 arguments: how many, the list file, the recordings folder of the source host
MSG_rs_rec_missing='錄影沒有從備份還原：系統記錄的錄影中有 %s 段的檔案不在這台。
清單在 %s，
請從來源主機的 %s 複製過來。'

# 0 arguments
MSG_rs_rec_offsite='已上傳到異地儲存的錄影，播放時會從異地取回。'

# ---------- restore: the external database, checked before anything stops ----------
# 0 arguments
MSG_rs_ext_refused='外接資料庫還不能還原，原因：'
# 4 arguments: count, database, sources, applications
MSG_rs_ext_conns='有 %s 個其他連線正在使用 %s（來自 %s，應用程式 %s）。
請先停止原主機的服務，並確認沒有備援主機接手這個資料庫。'
# 3 arguments: database, source, application
MSG_rs_ext_conns_one='有 1 個其他連線正在使用 %s（來自 %s，應用程式 %s）。
請先停止原主機的服務，並確認沒有備援主機接手這個資料庫。'
# 0 arguments
MSG_rs_ext_from_local='本機 socket'
# 4 arguments: object, its owner, DB_USER, DB_USER
MSG_rs_ext_owner='物件 %s 的擁有者是 %s，不是 %s；
腳本只能清空 %s 擁有的物件。'
# 1 argument: DB_USER
MSG_rs_ext_owner_more='還有其他物件的擁有者不是 %s。'
# 2 arguments: server version, client majors
MSG_rs_ext_no_client='伺服器是 PostgreSQL %s，沒有對應的客戶端；
這個版本附的客戶端是 PostgreSQL %s。'
# 2 arguments: server version, the server major of the backup
MSG_rs_ext_server_old='伺服器是 PostgreSQL %s，低於備份來源的 PostgreSQL %s。'
# 2 arguments: client major, the tool that made the dump
MSG_rs_ext_client_old='這個版本的 PostgreSQL %s 客戶端比產生備份的工具（%s）舊。'
# 2 arguments: DB_USER, DB_NAME
MSG_rs_ext_not_owner='%s 不是資料庫 %s 的擁有者；重建 schema public 需要資料庫擁有者。'
# 1 argument: the extensions
MSG_rs_ext_extension='資料庫有 plpgsql 以外的擴充套件（%s）；
腳本不清空、也不還原擴充套件。'
# 3 arguments: encoding, collation, character type
MSG_rs_ext_encoding='資料庫的編碼或排序規則與備份不同。
請以相同設定建立資料庫：ENCODING '"'"'%s'"'"' LC_COLLATE '"'"'%s'"'"' LC_CTYPE '"'"'%s'"'"''
# 2 arguments: host:port, log file
MSG_rs_ext_unreachable='連不上外接資料庫 %s，或登入失敗；原因記在 %s。'
# 2 arguments: the check now, the check the backup recorded
MSG_rs_ext_tls_lower='伺服器憑證的驗證程度會低於備份時（現在 %s，備份時 %s）。'
# 1 argument: path
MSG_rs_ext_ca_conflict='憑證機構檔的目的地 %s 已有內容不同的檔；請先移開它。'
# 0 arguments
MSG_rs_ext_client_missing='備份的資料庫連線要用用戶端憑證：請以 --db-client-cert 與
--db-client-key 提供憑證與私鑰。'
# 1 argument: path
MSG_rs_ext_client_unreadable='讀不到 %s。'
# 1 argument: path
MSG_rs_ext_client_conflict='%s 已有內容不同的檔；請先移開它，或指定同一個檔。'
# 2 arguments: client major, release
MSG_rs_ext_no_image='這台沒有 PostgreSQL %s 客戶端映像（隨 %s 發行），還原需要它；
請先載入這個版本的離線映像包。'
# 0 arguments
MSG_rs_ext_ask_cert='用戶端憑證檔路徑 > '
# 0 arguments
MSG_rs_ext_ask_key='用戶端私鑰檔路徑 > '
# 2 arguments: count, roles
MSG_rs_ext_roles_missing='目標資料庫伺服器上沒有 %s 個備份裡授權過的角色：%s。
先建立這些角色，或加 --accept-grant-loss 略過它們的授權。'
# 1 argument: the role
MSG_rs_ext_roles_missing_one='目標資料庫伺服器上沒有 1 個備份裡授權過的角色：%s。
先建立這個角色，或加 --accept-grant-loss 略過它的授權。'
# 0 arguments
MSG_rs_ext_step_stop='停止服務（外接資料庫不受影響）'
# 0 arguments
MSG_rs_ext_step_quiet='確認沒有其他連線'
# 4 arguments: count, database, sources, applications
MSG_rs_ext_still='：停止之後，仍有 %s 個其他連線
在使用 %s（來自 %s，應用程式 %s）。'
# 3 arguments: database, source, application
MSG_rs_ext_still_one='：停止之後，仍有 1 個其他連線
在使用 %s（來自 %s，應用程式 %s）。'
# 1 argument: step
MSG_rs_ext_stopped_at='還原停在第 %s 步。還沒有覆蓋任何資料；服務維持停止。'
# 0 arguments
MSG_rs_ext_end_conn='請找出並結束這個連線（確認不是備援主機接手），再重跑接續：'

# Imported data checks and recovery instructions.
# 1 arguments
MSG_rs_db_check_migrations='核對資料庫：匯入後的 migration 和備份記下的不同（%s）'
# 2 arguments
MSG_rs_db_extra='多 %s 項：%s'
# 2 arguments
MSG_rs_db_missing='少 %s 項：%s'
# 3 arguments
MSG_rs_db_check_counts='核對資料庫：%s 筆數不同（匯入後 %s，備份 %s）'
# 2 arguments
MSG_rs_db_check_kek='核對資料庫：active 主金鑰識別不同（匯入後 %s，備份 %s）'
# 0 arguments
MSG_rs_db_check_read='核對資料庫：讀不到匯入後的資料'
# 1 arguments
MSG_rs_failure_stopped='還原停在第 %s 步。服務維持停止，沒有自動回復。'
# 1 arguments
MSG_rs_failure_running='還原停在第 %s 步。服務可能已部分或全部啟動，還原尚未核對。'
# 1 arguments
MSG_rs_failure_unknown='還原停在第 %s 步，讀不到服務狀態。'
# 0 arguments
MSG_rs_failure_no_safety='這台原本沒有資料，所以沒有安全備份。'
# 0 arguments
MSG_rs_failure_uncovered='還沒有覆蓋任何資料。'
# 3 arguments
MSG_rs_failure_kept='還原前的資料改名保留在 %s 等 %s 處；
安全備份 %s 已確認可以還原。'
# 1 arguments
MSG_rs_failure_resume='查明原因後，重跑接續（從第 %s 步開始）：'
# 0 arguments
MSG_rs_failure_revert='或用安全備份還原回去：'
# 0 arguments
MSG_rs_failure_abandon='或放棄這次還原，回到尚未安裝（這次放進來的資料改名保留，不刪除）：'
# 3 arguments
MSG_rs_failure_own='或依你登記的程序還原回去：%s（備份 %s，%s）'
# 1 arguments
MSG_rs_failure_plaintext='暫存目錄 %s 有資料庫與設定檔的明文，
完成或還原回去之後會清掉。'
# 1 arguments
MSG_rs_failure_log='紀錄檔 %s'

# Startup and runtime master-key checks.
# 1 arguments
MSG_rs_unseal_wait='資料已匯入、服務已啟動，等待解封後核對（%s）'
# 0 arguments
MSG_rs_unseal_ui='還原還沒有完成。主金鑰模式是網頁輸入：請有人到解封頁，以備份裡的
管理者帳號登入授權後輸入主金鑰：'
# 0 arguments
MSG_rs_unseal_kms='還原還沒有完成。主金鑰由金鑰託管服務保管：請有人到解封頁，
以備份裡的管理者帳號登入，核對畫面上的託管服務
（它隨資料庫一起還原，是備份當時的設定）後
重新提供託管憑證；這台的位址要在託管服務允許的來源內：'
# 1 arguments
MSG_rs_unseal_fingerprint='主金鑰指紋必須是 %s。'
# 0 arguments
MSG_rs_unseal_finish='解封之後執行下面的指令完成核對；核對完成之前不能升級，也不能備份：'
# 0 arguments
MSG_rs_unseal_still='系統仍是「已封存」，還沒有解封，還原還不能完成。沒有變更任何東西。'
# 1 arguments
MSG_rs_unseal_again='到 %s 解封之後，再執行一次：'
# 0 arguments
MSG_rs_unseal_unreadable='讀不到封存狀態或執行期主金鑰識別，還原尚未核對。請查看狀態後再接續：'
# 2 arguments
MSG_rs_runtime_mismatch='主金鑰核對不符：解封後讀到的識別是 %s，備份記下的是 %s。'
# 0 arguments
MSG_rs_runtime_stopped='已停止服務，還原沒有完成。'
# 0 arguments
MSG_rs_runtime_guide='請照文件「備份與還原」第 6 節第 6 項核對金鑰清冊，再決定：'
# 0 arguments
MSG_rs_runtime_resume='重跑接續：重新啟動服務，等有人以正確的主金鑰解封之後再核對一次'
# 0 arguments
MSG_rs_runtime_resume_env='重跑接續：先重新核對設定檔的主金鑰，仍不符就不啟動服務'
# 1 arguments
MSG_rs_ready_timeout='啟動服務並等待就緒：%s 秒內沒有就緒'
# 0 arguments
MSG_rs_ready_body='還原還沒有完成。服務已啟動，但後端沒有回報就緒，使用者可能還不能連線。'
# 0 arguments
MSG_rs_ready_status='查看狀態：'
# 0 arguments
MSG_rs_ready_resume='處理之後，重跑接續（先確認服務在運作，再等待就緒）：'
# 1 argument
MSG_rs_runtime_match='主金鑰：解封後讀到的識別 %s 與備份相同'
# 1 argument
MSG_rs_restore_done='還原完成（%s）'
# 1 argument
MSG_rs_resume_original='需要原備份檔 %s，檔案校驗和必須與開始還原時相同。'
# 1 argument
MSG_rs_resume_changed='還原暫存檔已改變：%s，已停止接續。'
# 1 arguments
MSG_rs_interrupted_stopped='還原在第 %s 步被中斷，已停止這次啟動的工具程序。
服務維持停止，沒有自動回復。'
# 1 arguments
MSG_rs_interrupted_running='還原在第 %s 步被中斷，已停止這次啟動的工具程序。
服務可能已部分或全部啟動，還原尚未核對。'
# 1 arguments
MSG_rs_interrupted_unknown='還原在第 %s 步被中斷，已停止這次啟動的工具程序。讀不到服務狀態。'
# 0 arguments
MSG_rs_revert_start_failed='原本的服務尚未回報就緒，還原回去還沒有完成。處理原因後再執行 --revert：'
# 1 arguments
MSG_rs_revert_done='已用安全備份還原回去（%s）'
# 1 argument
MSG_rs_revert_original_done='原本的服務已恢復（%s）。'

# Restore recovery and exit confirmation.
# 0 arguments
MSG_rs_exit_yes='非互動時，請加 --yes 確認這個動作。'
# 1 arguments
MSG_rs_exit_confirm_original='還沒有覆蓋任何資料。這會清掉這次還原的紀錄，
並以 %s 啟動原本的服務。繼續嗎？[y/N]'
# 0 arguments
MSG_rs_exit_cancelled='已取消這個動作。'
# 0 arguments
MSG_rs_revert_title='用安全備份還原回去（還沒有變更任何資料）'
# 3 arguments
MSG_rs_revert_details='安全備份   %s
           %s，還原前已確認可以還原
回到       %s，這次還原開始之前的狀態'
# 2 arguments
MSG_rs_revert_partial='沒完成的   這次還原放進來的資料改名保留，不刪除：
           %s 等 %s 處'
# 1 arguments
MSG_rs_revert_downtime='停機       約 %s 分鐘'
# 1 arguments
MSG_rs_revert_confirm_version='確認請輸入版本號 %s：'
# 1 arguments
MSG_rs_exit_wrong='這種還原流程不能使用 --%s。'
# 0 arguments
MSG_rs_no_pending='沒有尚未完成的還原。'
# 1 arguments
MSG_rs_revert_finished='最近一次還原已經完成（%s），--revert 只處理沒有完成的還原。'
# 0 arguments
MSG_rs_revert_fresh='要回到還原前的資料，用當時的安全備份再做一次還原；
那是一次新的還原，會先替目前的資料做安全備份：'

# Restore completion.
# 1 arguments
MSG_rs_finish_title='還原完成，服務已恢復（%s）'
# 2 arguments
MSG_rs_finish_from='來源     %s（%s）'
# 1 arguments
MSG_rs_finish_address='網址     %s'
# 1 arguments
MSG_rs_finish_key_env='主金鑰   本機設定檔；解封後讀到的識別 %s 與備份相同'
# 1 arguments
MSG_rs_finish_key_ui='主金鑰   瀏覽器輸入；解封後讀到的識別 %s 與備份相同'
# 1 arguments
MSG_rs_finish_key_kms='主金鑰   金鑰服務保管；解封後讀到的識別 %s 與備份相同'
# 3 arguments
MSG_rs_finish_kept='保留     還原前的資料改名保留在 %s 等 %s 處；
         安全備份 %s。
         第 6 節核對無誤後，可以自行刪除保留的目錄。'
# 3 arguments
MSG_rs_finish_kept_own='保留     %s，另有 %s 處；
         自備備份：%s。'
# 1 arguments
MSG_rs_finish_oidc='對外網址改成了 %s。有接外部登入（OIDC）的話，
請到身分提供者更新回呼位址。'
# 0 arguments
MSG_rs_finish_checklist='請照文件「備份與還原」第 6 節逐項核對，確認無誤再交給使用者。'
# 1 arguments
MSG_rs_upgrade_existing='這台已有 %s，可以升級：'
# 1 arguments
MSG_rs_upgrade_before='已回到升級前的版本（%s）。之後要升級時：'
# 0 arguments
MSG_rs_upgrade_later='之後要查詢最新版本並升級：'
# 0 arguments
MSG_rs_upgrade_lookup='查詢最新版本：'
# 0 arguments
MSG_rs_upgrade_unknown='無法確認最新版本。'
# 0 arguments
MSG_rs_upgrade_lookup_later='之後要查詢最新版本：'
# 1 arguments
MSG_rs_upgrade_ask='要現在升級到 %s 嗎？升級會先停機備份，再換版。[y/N]'
# 0 arguments
MSG_rs_upgrade_declined='之後要升級：'
# 1 arguments
MSG_rs_upgrade_current='%s 已是最新版本'

# Giving up an unfinished new-host restore.
# 0 arguments
MSG_rs_abandon_title='放棄這次還原（這台會回到尚未安裝）'
# 1 arguments
MSG_rs_abandon_services='服務       先停止這次還原啟動的服務（目前 %s 個在運作），
           確認停止後才往下做'
# 0 arguments
MSG_rs_abandon_stopped='服務       沒有在運作的服務'
# 0 arguments
MSG_rs_abandon_kept='改名保留   這次放進來的資料改名保留，不刪除：'
# 1 arguments
MSG_rs_abandon_path='           %s'
# 0 arguments
MSG_rs_abandon_old_env='           失敗安裝留下的 .env 放回原處'
# 1 arguments
MSG_rs_abandon_old_template='           %s：原本的檔案放回原處'
# 3 arguments
MSG_rs_abandon_tail='不動       錄影目錄 %s：可能有這次放回的檔，
           也可能有你先複製過來的檔，一律不刪除
版本       current 指回 %s；releases/%s 保留
暫存       刪除暫存目錄裡的資料庫與設定檔明文'
# 0 arguments
MSG_rs_exit_confirm_abandon='確認放棄嗎？[y/N]'
# 0 arguments
MSG_rs_abandon_done='已放棄這次還原，這台回到尚未安裝。
改名保留的目錄確認不需要之後，可以自行刪除。'
# 0 arguments
MSG_rs_abandon_stop_failed='無法確認全部服務已停止，沒有改名任何東西。
排除原因後再執行一次 --abandon：'

# 1 argument
MSG_rs_failure_new_stopped='還原停在第 %s 步。服務沒有啟動，沒有自動回復。'

# ---------- restore: the external database, roles the server lacks ----------
# 2 arguments: count, the role names (one per line, indented)
MSG_rs_ext_roles_ask='備份裡有授權給下面 %s 個角色，但目標資料庫伺服器上沒有這些角色：
%s
略過的話，只有授權給這些角色的項目不會還原，其餘照常還原。'
# 1 argument: the role name (indented)
MSG_rs_ext_roles_ask_one='備份裡有授權給下面 1 個角色，但目標資料庫伺服器上沒有這個角色：
%s
略過的話，只有授權給這個角色的項目不會還原，其餘照常還原。'
# 0 arguments
MSG_rs_ext_roles_create='[1] 先去建立這些角色（預設；結束還原，沒有變更任何資料）'
# 0 arguments
MSG_rs_ext_roles_create_one='[1] 先去建立這個角色（預設；結束還原，沒有變更任何資料）'
# 0 arguments
MSG_rs_ext_roles_skip='[2] 略過這些角色的授權，繼續還原'
# 0 arguments
MSG_rs_ext_roles_skip_one='[2] 略過這個角色的授權，繼續還原'
# 0 arguments
MSG_rs_ext_grants_unsure='有授權語句無法確定只涉及缺少的角色，腳本不能只略過那幾項。
請先在伺服器上建立這些角色，再還原。'
# 1 argument: count
MSG_rs_ext_skipped_row='給這 %s 個角色的授權項不會還原'
# 0 arguments
MSG_rs_ext_skipped_row_one='給這 1 個角色的授權項不會還原'
# 0 arguments
MSG_rs_label_skipped='  略過的授權 '

# Restore execution progress and database client diagnostics.
MSG_rs_space_join='%s與%s'
MSG_rs_space_short_row='%s（%s）需要 %s GB，只有 %s GB'
MSG_rs_progress_release_same='放置 %s 與映像'
MSG_rs_progress_release_new='安裝 %s：放置發行版與映像'
MSG_rs_progress_stop='停止服務（資料庫保持運作）'
MSG_rs_progress_safety='安全備份 %s'
MSG_rs_progress_own='自備備份 %s（%s）'
MSG_rs_progress_verify='確認安全備份可以還原'
MSG_rs_progress_swap='停止資料庫；目前的資料改名保留'
MSG_rs_progress_settings='寫入設定檔（沿用備份，主機值改為這台）'
MSG_rs_progress_import='匯入資料庫'
MSG_rs_progress_check='核對資料庫：migration %s 項、筆數、主金鑰識別都與備份相同'
MSG_rs_progress_files_same='放回稽核檔、憑證與設定檔'
MSG_rs_progress_files_new='放回稽核檔與憑證'
MSG_rs_progress_files_new_reissue='放回稽核檔與憑證；重簽這台位址的伺服器憑證'
MSG_rs_progress_start_same='啟動服務並等待就緒：後端回報 %s'
MSG_rs_progress_start_new='啟動服務並核對執行中的映像'
MSG_rs_progress_ready='等待就緒：後端回報 %s'
MSG_rs_progress_key_wait='主金鑰：等待解封後核對'
MSG_rs_import_error='pg_restore 回報錯誤（完整訊息在紀錄檔）。'
MSG_rs_import_error_detail='pg_restore 回報錯誤（完整訊息在紀錄檔）：'

# ---------- restore: the external database, emptied and imported in one transaction ----------
# 0 arguments
MSG_rs_ext_step_import='清空並匯入資料庫（同一個交易）'
# 1 argument: the log file
MSG_rs_ext_import_unreachable='連不上外接資料庫，還沒有開始匯入。原因記在 %s。'
# 1 argument: the log file
MSG_rs_ext_import_make='無法產生或核對匯入用的 SQL；交易沒有開始，外接資料庫沒有被動過。
原因記在 %s。'
# 0 arguments
MSG_rs_ext_import_rolled_back='資料庫匯入失敗。這次的清空與匯入已整筆撤回，外接資料庫保持原狀。'
# 0 arguments
MSG_rs_ext_import_unknown='無法確認匯入是否已提交。接續時會先核對外接資料庫，再決定重匯或往下。'
# 2 arguments: the digest before the import, the digest now
MSG_rs_ext_import_unknown_stop='外接資料庫既不是匯入前的樣子，也不是完整匯入後的樣子，
無法判定上一次的匯入是否已提交；不會重匯。
  匯入前：%s
  現在：  %s'

# ---------- restore: reading the backup, the data release's database tool image ----------
# 1 argument: the data release
MSG_rs_no_dbtool='這台主機沒有 %s 發行版的資料庫工具映像。
還原讀取備份需要它；請先載入該版本的離線映像包。'

# ---------- restore: a new host's external database, exported before it is emptied ----------
# 0 arguments
MSG_rs_ext_step_export='匯出目前的外接資料庫作為安全備份'
# 1 argument: the log file
MSG_rs_ext_export_failed='外接資料庫無法匯出並完整讀回驗證，資料庫本身沒有變更。原因記在 %s。'
# 1 argument: the export file
MSG_rs_ext_revert_confirm='從 %s 匯回外接資料庫，並放棄這次還原？[y/N] '
# 1 argument: the export file
MSG_rs_ext_revert_failed='外接資料庫沒能回到匯出時的內容；%s 保留不刪。請再執行一次同一條指令：'
# 0 arguments
MSG_rs_ext_revert_done='外接資料庫已回到還原前匯出時的內容；這次還原已放棄。'

# ---------- restore: the external database in the preview, the steps, a failure and giving up ----------
# 0 arguments
MSG_rs_label_database='  資料庫     '
# 2 arguments: the certificate setup, the master key mode
MSG_rs_deployment_external='外接資料庫；%s；主金鑰模式：%s'
# 3 arguments: host:port, database, server version
MSG_rs_ext_preview_server='外接 %s／%s（PostgreSQL %s）'
# 2 arguments: client major, the management script's release
MSG_rs_ext_preview_tool='匯入工具：PostgreSQL %s 客戶端（隨 %s 發行、已核對）'
# 1 argument each: the sslmode in effect
MSG_rs_ext_conn_full_system='連線：%s，以系統信任的憑證機構驗證伺服器'
MSG_rs_ext_conn_full_file='連線：%s，以備份裡的 CA 檔驗證伺服器'
MSG_rs_ext_conn_ca_system='連線：%s，以系統信任的憑證機構驗證伺服器憑證，不核對主機名稱'
MSG_rs_ext_conn_ca_file='連線：%s，以備份裡的 CA 檔驗證伺服器憑證，不核對主機名稱'
MSG_rs_ext_conn_none_none='連線：%s，不驗證伺服器憑證'
MSG_rs_ext_conn_none_file='連線：%s，不驗證伺服器憑證'
# 1 argument: DB_USER
MSG_rs_ext_preview_rights='權限：%s 擁有這個資料庫與其中全部物件；沒有其他連線'
# 4 arguments: DB_USER, count, sources, applications
MSG_rs_ext_preview_rights_listed='權限：%s 擁有這個資料庫與其中全部物件；目前有 %s 個其他連線
（來自 %s，應用程式 %s），停止服務之後會再檢查一次'
# 2 arguments: schema, count (en: count, schema)
MSG_rs_ext_objects='schema %s 內的 %s 個物件'
# 1 argument: the objects of each schema
MSG_rs_ext_preview_emptied='會清空：%s，與匯入在同一個交易裡完成；
失敗時整筆撤回，資料庫保持原狀。其他資料庫、角色與表空間不動。'
# 0 arguments
MSG_rs_ext_preview_empty='目標資料庫是空的，不需要清空'
# 1 argument: the export file
MSG_rs_ext_preview_export='先把目前的資料庫匯出到
%s，完整讀回一遍、確認可用再往下做'
# 1 argument: GB
MSG_rs_ext_preview_space='匯入完成前，資料庫伺服器上新舊資料會同時存在，約需 %s GB 可用空間；
腳本量不到伺服器的磁碟，請先確認。'
# 0 arguments
MSG_rs_kept_external='目前的稽核檔、憑證目錄改名保留，不刪除：'
# 0 arguments
MSG_rs_kept_external_no_tls='目前的稽核檔目錄改名保留，不刪除：'
# 1 argument: database
MSG_rs_confirm_db='確認請輸入要清空的資料庫名稱 %s：'
# 0 arguments
MSG_rs_ext_import_error='psql 回報錯誤（完整訊息在紀錄檔）。'
# 0 arguments
MSG_rs_ext_import_error_detail='psql 回報錯誤（完整訊息在紀錄檔）：'
# 0 arguments
MSG_rs_ext_failure_rolled_back='這次的清空與匯入已整筆撤回，外接資料庫保持原狀。'
# 1 argument: the export file
MSG_rs_ext_failure_rolled_back_export='這次的清空與匯入已整筆撤回，外接資料庫保持原狀；安全匯出在 %s'
# 1 argument: the export file
MSG_rs_ext_failure_unknown_export='無法確認匯入是否已提交。接續時會先核對外接資料庫，再決定重匯或往下；
安全匯出在 %s'
# 1 argument: the export file
MSG_rs_ext_failure_committed_export='匯入已提交，外接資料庫現在是備份的內容；安全匯出在 %s'
# 1 argument: the export file
MSG_rs_ext_failure_unsent_export='外接資料庫沒有被改動；安全匯出在 %s'
# 0 arguments
MSG_rs_ext_failure_revert='或用安全匯出還原外接資料庫，並放棄這次還原：'
# 0 arguments
MSG_rs_ext_failure_abandon='或放棄這次還原，回到尚未安裝（這次放進來的資料改名保留，不刪除；
外接資料庫裡這次匯入的資料不會被清掉）：'
# 0 arguments
MSG_menu_rs_revert_export='用安全匯出還原外接資料庫，並放棄這次還原'
# 2 arguments: host:port, database
MSG_rs_ext_abandon_kept='外接資料庫   %s／%s 裡這次匯入的資料不會被清掉；
           需要清空時請由資料庫管理者處理，
           下次還原會把它當成非空的目標先做安全匯出'
# 2 arguments: host:port, database
MSG_rs_ext_abandon_maybe='外接資料庫   %s／%s 可能已有這次匯入的資料，不會被清掉；
           需要清空時請由資料庫管理者處理'
# 1 argument: the export file
MSG_rs_ext_abandon_export='安全匯出   %s
           保留，不刪除；確認不需要之後可以自行刪除'
# 0 arguments
MSG_rs_ext_abandon_refused='外接資料庫已經開始清空與匯入，不能直接放棄；請用安全匯出把它還原回去
（完成後這台也會回到尚未安裝）：'
# 2 arguments: count, the list file
MSG_rs_ext_finish_skipped='略過     伺服器上沒有的角色，有 %s 項授權沒有還原；清單在
         %s'
# 1 argument: the export file
MSG_rs_ext_finish_export='安全匯出 外接資料庫還原前的內容（明文）保留在
         %s；
         第 6 節核對無誤後請自行刪除。'

# ---------- status: a failed upgrade that a restore which finished has settled ----------
# 1 argument: when the restore settled it
MSG_status_upgrade_settled='這次升級失敗已由 %s 的還原處理，
可以再次升級'
