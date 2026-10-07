# shellcheck shell=bash disable=SC2034
# custodexa.sh メッセージ（日本語）。キーの集合は en.sh と同じ（テストで確認）。
# 各値は printf 書式。引用符内の改行は画面上の改行になる。1 行は 73 桁以内（help_* は 80 桁）。
MSG_platform_not_linux='custodexa.sh は Linux 専用です（このホストは %s と報告しています）。
このコンピューターで Custodexa を試す場合は、ソースに含まれる
scripts/quickstart.sh を使ってください。'
MSG_root_home_invalid='CUSTODEXA_HOME=%s は Custodexa の配置フォルダーではありません
（state.json も releases/ もありません）。'
MSG_root_not_found='このスクリプトがどの配置フォルダーのものか判断できません（%s）。
配置フォルダー内で実行するか、CUSTODEXA_HOME を設定してください。'
MSG_root_path_chars='配置フォルダー %s に使えない文字が含まれています。
英字、数字、. _ / - だけが使えます（空白や引用符は不可）。
何も変更していません。'
MSG_images_env_bad_line='%s の %s 行目が CUSTODEXA_IMAGE_<名前>=<イメージ参照> の形に
なっていません。サービスは起動していません。'
MSG_overlay_unknown='state.json に不明な配置形態「%s」が記録されています。'
MSG_state_bad='状態ファイル %s の %s 行目が壊れています。何も変更していません。'
MSG_state_bad_prev='一つ前の版は %s にあります。内容を確認し、正しければ
次のコマンドで戻してください：'
MSG_usage_unknown_command='不明なサブコマンド「%s」です。custodexa.sh --help を参照してください。'
MSG_usage_unknown_option='不明なオプション「%s」です。custodexa.sh --help を参照してください。'
MSG_usage_missing_value='オプション %s には値が必要です。'
MSG_usage_images_from_value='不明なイメージ取得元「%s」です。auto または source を指定してください。'
MSG_usage_images_from_command='--images-from は install または対象を指定した upgrade だけで使えます。'
MSG_usage_images_from_conflict='--images-from source と --images は併用できません。'
MSG_usage_backup_only='オプション %s は backup 専用です。
custodexa.sh --help を参照してください。'
MSG_legacy_refused='これは旧 git clone 配置です。このディレクトリでは custodexa.sh による
インストールやアップグレードはできません。
配置ファイルとサービスは変更していません。

先にバックアップと配置設定を確認してください。
アップグレード手順書の手動移行、または別の空ディレクトリへの
パッケージ導入後にバックアップと復元の手順で手動復元してください。
既存のデータディレクトリで install を実行しないでください。'
MSG_command_not_in_build='このバージョンのスクリプトには「%s」サブコマンドがありません。'
MSG_lock_busy='この配置では別の custodexa.sh が実行中です（PID %s）。
終了するまで待ってください。'
MSG_run_interrupted='前回の %s はステップ %s で中断されました。'
MSG_run_install_rerun='install は繰り返し実行しても安全です。最初のステップからやり直します。'
MSG_run_recover_first='先に前回の中断に対処してください。状態とログファイルを確認します：'
MSG_run_recover_install='先に前回の install を完了してください。再実行しても安全です：'
MSG_run_load_rerun='load はイメージの読み込みと照合だけを行うため、再実行しても
安全です。'
MSG_run_backup_unfinished='前回のバックアップ（%s）は完了していません。一時フォルダー
%s は削除してかまいません。'
MSG_run_backup_unfinished_nodir='前回のバックアップ（%s）は完了していません。'
MSG_run_backup_upgrade='前回のバックアップ（%s）は完了していません。アップグレードの前に
完了したバックアップが必要です。サービスが停止したままなら起動し、
もう一度バックアップして、完了してからアップグレードしてください：'
MSG_run_signal='ステップ %s で中断されました。元に戻す処理は行っていません。
続けるには次を実行してください：'
MSG_confirm_needs_yes='この手順には確認が必要ですが、確認を求める端末がありません。
--yes を付けて再実行してください。'
MSG_log_initial_password='生成済み（値は記録しない）'

# ---- --help。サブコマンド別のヘルプも同じ段落を使う。 ----
MSG_help_title='Custodexa 管理スクリプト %s'
MSG_help_usage='使い方：custodexa.sh <サブコマンド> [オプション]'
MSG_help_commands='サブコマンド'
MSG_help_cmd_install='  install                初回インストール：ホスト確認、設定作成、
                         イメージ取得、起動'
MSG_help_cmd_upgrade='  upgrade                新しいバージョンの有無を確認（何も変更しない）
  upgrade <バージョン>   指定バージョンへ更新（サービスを停止し、
                         先にバックアップする）
  upgrade <パッケージ>   ダウンロード済みのパッケージで更新（オフライン可）'
MSG_help_cmd_status='  status                 バージョン、サービス、バックアップ、前回の更新の
                         状態を表示（何も変更しない）'
MSG_help_cmd_backup='  backup                 単一ファイルにバックアップ（サービスを停止する。
                         ファイルは他のホストへ移せる）'
MSG_help_cmd_load='  load <バンドル>        オフラインイメージバンドルを読み込む（起動しない）'
MSG_help_options='オプション'
MSG_help_opt_yes='  --yes                  確認を求めない（自動化用）'
MSG_help_opt_with_recordings='  --with-recordings      （backup）録画もバックアップファイルに含める
                         （既定では含めない）'
MSG_help_opt_passphrase_file='  --passphrase-file <ファイル>
                         （backup）ファイルの 1 行目をパスフレーズとして
                         バックアップファイルを暗号化する。ファイルは 0600 で、
                         所有者があなたか root であること。パスフレーズを
                         コマンドラインに直接書かないこと'
MSG_help_opt_backup_ref='  --backup-ref <識別子>  （upgrade）自分でバックアップ済み。スナップショット
                         名を指定すると、スクリプトはバックアップしない'
MSG_help_opt_backup_time='  --backup-time <時刻>   （upgrade）--backup-ref と併用：スナップショットの
                         開始時刻。サービス停止より後であること'
MSG_help_opt_backup_restore='  --backup-restore <場所>（upgrade）--backup-ref と併用：復元手順の文書の場所'
MSG_help_opt_images='  --images <パス>        （install、upgrade）使うオフラインイメージバンドル'
MSG_help_opt_images_from='  --images-from <方式>   （install、対象を指定した upgrade）auto または source。
                         既定は auto。source は同梱ソースから
                         自社イメージをビルド'
MSG_help_opt_lang='  --lang <言語>          zh-TW、ja、en。下の「表示言語」を参照'
MSG_help_opt_no_color='  --no-color             色を使わない'
MSG_help_opt_version='  --version              スクリプトのバージョンを表示'
MSG_help_opt_help='  -h, --help             このヘルプ。custodexa.sh <サブコマンド> --help は
                         そのサブコマンドだけを表示'
# shellcheck disable=SC2016 # the commands as they are typed
MSG_help_passphrase_file_make='  パスフレーズファイルの作り方（シェルの履歴に残りません）：
    sudo install -m 600 -o root /dev/null /root/cx-pass
    sudo bash -c '"'"'IFS= read -r -s p && printf "%%s\\n" "$p" > /root/cx-pass'"'"''
MSG_help_footer='配置フォルダーはこのスクリプトがあるフォルダーです。別の場所を使うには、
環境変数 CUSTODEXA_HOME を設定してください。実行ごとの記録は
<配置フォルダー>/logs/ に残ります。詳しい手順は「デプロイとアップグレードの
SOP」と「バックアップとリストア」を参照してください。'
MSG_help_language='表示言語
  画面の言語はシステムの言語（LC_ALL、LC_MESSAGES または LANG）に従います。
  sudo ではこれがリセットされることが多く、その場合は英語になります。
  言語を選ぶには --lang を付けます（サブコマンドの有無は問いません）：
    custodexa.sh --lang ja             日本語
    custodexa.sh --lang zh-TW          繁體中文
    custodexa.sh --lang en             English
  sudo でシステムの言語を保つ場合：
    sudo env LANG=ja_JP.UTF-8 custodexa.sh'

# ---- リリースマニフェスト、インストール見出し、所要時間 ----
MSG_manifest_missing='リリースマニフェスト %s がありません。パッケージが不完全な
可能性があります。もう一度ダウンロードしてください。'
MSG_manifest_bad='リリースマニフェスト %s の %s 行目を読めません。パッケージが
壊れている可能性があります。もう一度ダウンロードしてください。'
MSG_install_title='Custodexa %s インストール    配置フォルダー %s'
MSG_dur_s='%s 秒'
MSG_dur_ms='%s 分 %02d 秒'

# ---- ステップ 1：このホストの確認 ----
MSG_step_preflight='このホストを確認'
MSG_pre_docker_ok='Docker %s、Compose %s'
MSG_pre_docker_down='Docker に接続できません：%s'
MSG_pre_docker_perm='Docker を使う権限がありません'
MSG_pre_compose_missing='Docker Compose v2 が見つかりません（%s 以上が必要）'
MSG_pre_compose_old='Docker %s、Compose %s は古すぎます（%s 以上が必要）'
MSG_pre_arch_ok='アーキテクチャ %s'
MSG_pre_arch_bad='アーキテクチャ %s には対応していません（x86_64 と aarch64 のみ）'
MSG_pre_openssl_missing='openssl が見つかりません（パスワードと鍵の生成に必要）'
MSG_pre_existing_state='このフォルダーには Custodexa %s がインストール済みです'
MSG_pre_existing_git='このフォルダーは git clone による配置です'
MSG_pre_existing_container='今回のインストールで作成していない custodexa-backend コンテナがあります'
MSG_pre_ports_ok='公開ポート %s は空いています'
MSG_pre_port_busy='公開ポート %s は使用中です：%s'
MSG_pre_ports_unchecked='ss も lsof もないため、公開ポート %s は確認していません'
MSG_pre_holder='%s（pid %s）'
MSG_pre_holder_unnamed='不明なプロセス（root で実行すると確認できます）'
MSG_pre_holder_container='%s、コンテナ %s のために転送'
MSG_pre_list_sep='、'
MSG_pre_disk='ディスク空き %s GB（必要 %s GB 以上）'
MSG_pre_disk_root='配置フォルダーのディスク空き %s GB（必要 %s GB 以上）'
MSG_pre_disk_unknown='%s の空き容量を読めないため、確認していません'
MSG_pre_not_writable='配置フォルダー %s に書き込めません'
MSG_pre_nothing_changed='何も変更していません。'
MSG_text_pre_port='公開ポート %s は %s が使用中です。ホスト管理者にポートの競合を
解消してもらってから、もう一度実行してください：'
MSG_text_pre_port_change='別のポートを使う場合は、まず %s/.env が存在し設定済みであることを
確認し、TLS_HTTPS_PORT と TLS_HTTP_PORT を空いているポート（よく使われるのは
8443 と 8088）に変更してください。変更後は、利用者が入力するアドレスに
ポート番号が付きます。例：https://%s:8443'
MSG_text_pre_port_change_ingress='別のポートを使う場合は、まず %s/.env が存在し設定済みであることを
確認し、HTTP_PORT を空いているポートに変更してください。'
MSG_text_pre_docker_perm='sudo で実行するか、このアカウントを docker グループに追加してください。'
MSG_text_pre_sudo='配置フォルダーに書き込めるアカウントで実行してください。例：'
MSG_text_pre_existing='このホストには既に配置があり、install は上書きしません。状態の確認や
アップグレードには次を使ってください：'

# ---- 設定ファイル .env ----
MSG_env_compose_file_bad='.env の COMPOSE_FILE=%s はこのパッケージの配置形態ではありません。
current/compose.yml に変更してください（外部入口や外部データベースを
使う場合は、対応するファイルを : でつなげます）。'
MSG_env_project_bad='.env の COMPOSE_PROJECT_NAME=%s ですが、この配置は常に %s を使います。
元に戻して再実行してください。'
MSG_env_kek_bad='.env の KEK_PROVIDER=%s は env、ui、kms、hsm のいずれでもありません。
先に修正してください。'
MSG_env_db_external='外部データベース（EXTERNAL_DB_HOST）が設定されていますが、DB_PASSWORD が
空かテンプレートの値です。%s にそのデータベースアカウントのパスワードを
入れて再実行してください（何も生成していません）。'

# ---- 手順 3：プログラムのイメージ ----
MSG_step_images='プログラムのイメージを取得'
MSG_img_order='順に試行：このホスト → オフラインバンドル → GHCR → Docker Hub →
ソースからビルド'
MSG_img_source_mode='イメージ取得元：同梱ソースからビルド。上流イメージは別途取得します'
MSG_img_source_check='同梱ソースのチェックサムを確認しています…'
MSG_img_source_ok='ソースのチェックサムはリリースマニフェストと一致します'
MSG_img_wait_local='このホストの %s を確認しています…'
MSG_img_wait_bundle_check='オフラインバンドル %s を確認しています…'
MSG_img_wait_bundle_load='オフラインバンドル %s を読み込んでいます…'
MSG_img_wait_registry='%s を取得しています（取得元：%s）…'
MSG_img_wait_digest='%s の内容ダイジェストを確認しています…'
MSG_img_wait_build='ソースから %s をビルドしています。初回は数分かかる場合があります…'
MSG_img_wait_fallback='GHCR が失敗しました（%s）。Docker Hub を試します'
MSG_img_head_own='%s %s'
MSG_img_head_upstream='%s %s（上流 %s）'
MSG_img_and=' と '
MSG_img_local_absent='このホスト：このバージョンはまだありません'
MSG_img_local_ok='このホスト：あり、内容ダイジェスト一致'
MSG_img_local_mismatch='このホスト：%s は内容ダイジェストが一致しないため使いません'
MSG_img_offline_none='オフラインバンドル：%s が見つかりません
（探した場所 %s）'
MSG_img_offline_absent='オフラインバンドル：このイメージは含まれていません'
MSG_img_offline_bad='オフラインバンドル %s は使いません：
%s'
MSG_img_offline_ok='オフラインバンドル %s
読み込み済み、内容ダイジェストはリリースマニフェストと一致'
MSG_img_bundle_unreadable='バンドルの index.json または manifest.json を読めません'
MSG_img_bundle_manifest_bad='%s の manifest の内容がダイジェストと一致しません'
MSG_img_bundle_config_bad='%s の設定ダイジェストがリリースマニフェストと一致しません'
MSG_img_bundle_no_sums='%s に SHA256SUMS がなく、チェックサムを確認できません'
MSG_img_bundle_not_listed='SHA256SUMS にこのバンドルがありません'
MSG_img_bundle_sum_bad='チェックサムが SHA256SUMS と一致しません。
ダウンロードが不完全か、ファイルが破損している
可能性があります。再ダウンロードしてください'
MSG_img_bundle_load_failed='docker load に失敗しました（全出力はログファイル）'
MSG_img_bundle_id_bad='読み込み後の %s のイメージ ID が確認済みのものと
異なります。ダウンロードが不完全か、ファイルが破損している
可能性があります。再ダウンロードしてください'
MSG_img_try_failed='%s %s：%s'
MSG_img_switched='、
%s から取得して内容を確認しました'
MSG_img_reason_timeout='接続タイムアウト（30 秒）'
MSG_img_reason_notfound='このバージョンはありません'
MSG_img_reason_other='失敗（%s）'
MSG_img_pulled_own='%s %s
ダウンロード済み、内容ダイジェストはリリースマニフェストと一致'
MSG_img_pulled_up='%s %s ダウンロード済み'
MSG_img_pulled_mismatch='%s %s はダウンロード後の内容ダイジェストが
一致しないため使いません。
ダウンロードが不完全か、ファイルが破損している
可能性があります。再ダウンロードしてください'
MSG_img_build_note='ソースからのビルドには Go モジュール、npm、ベースイメージの
取得元への接続が必要です。初回は 5〜10 分ほどかかります'
MSG_img_build_source_bad='ソースからビルド：ソースのチェックサムが
リリースマニフェストと一致しません。
ダウンロードが不完全か、ファイルが破損している
可能性があります。再ダウンロードしてください。
ビルドしません'
MSG_img_build_failed='ソースからのビルドに失敗しました（全出力はログファイル）'
MSG_img_build_ok='ソースから %s としてビルド
（ローカルビルドのため発行者の署名はありません）'
MSG_img_none='%s：すべての取得元で失敗し、取得できません'
MSG_img_running_bad='%s が実行中のイメージ %s は、取得したもの（%s）ではありません'
MSG_step_images_done='プログラムのイメージを取得（%s 個、%s）'
MSG_ver_all='チェックサム・署名・ビルド来歴を検証済み'

# ---- 発行元の検証（未検証時の確認画面） ----
MSG_trust_title='ファイルの破損は確認しましたが、発行元は確認していません'
MSG_trust_row_checksum='チェックサム     パッケージとイメージがリリース一覧と一致'
MSG_trust_label_sig='発行者の署名     '
MSG_trust_label_prov='ビルド来歴       '
MSG_trust_verified='検証済み'
MSG_trust_no_cosign='このホストに cosign がありません'
MSG_trust_no_gh='このホストに gh がありません'
MSG_trust_offline='オフラインのため署名サービスに接続できません'
MSG_trust_gh_login='gh にログインしていません（gh auth login）'
MSG_trust_local_build='ソースからビルドしたイメージには発行者の署名がありません'
MSG_trust_mf_unverified='パッケージ横のリリースマニフェストは未検証です（%s）'
MSG_trust_pkg_unverified='パッケージの署名は未検証です（%s）'
MSG_trust_mf_no_sig='横に SHA256SUMS.sigstore.json がありません'
MSG_trust_mismatch='署名が一致せず、発行元は未確認です'
MSG_trust_prov_mismatch='ビルド来歴が一致せず、発行元は未確認です'
MSG_ver_sig_mismatch='署名が一致せず、発行元は未確認です'
MSG_ver_prov_mismatch='ビルド来歴が一致せず、発行元は未確認です'
MSG_text_trust_explain='  チェックサムはファイル内容とリリース一覧の一致を示します。
  発行元は未確認です。必要に応じて以下の完全なダイジェストを
  別途検証してください：'
MSG_trust_recorded='  どの検証を行ったかはログファイルに記録されます。'
MSG_ver_sig_only='チェックサム・署名を検証済み、ビルド来歴は未検証'
MSG_ver_checksum_only='チェックサムを確認済み、発行元は未検証'
MSG_usage_extra_args='余分な引数「%s」があります。参照：custodexa.sh --help'

# ---- install：手順 2、4〜7 と完了時の案内 ----
MSG_step_env='設定ファイル .env を作成'
MSG_env_item_jwt='ログイン署名鍵'
MSG_env_item_kek='マスターキー'
MSG_env_item_db='データベースのパスワード'
MSG_env_item_admin='初期管理者パスワード'
MSG_env_item_sep='、'
MSG_env_item_last='、'
MSG_env_generated='%sを生成しました'
MSG_env_generated_none='新しい値は生成していません（.env の既存の設定を使います）'
MSG_env_kek_ui='マスターキーの方式：ブラウザーで入力（サーバーのディスクに書き込まない）'
MSG_env_kek_env='マスターキーの方式：設定ファイル（.env の ENCRYPTION_KEY）'
MSG_env_kek_kms='マスターキーの方式：外部の鍵管理サービス（KMS）'
MSG_env_kek_hsm='マスターキーの方式：ハードウェアセキュリティモジュール（HSM）'
MSG_env_url='アドレス：%s（変更は .env の PUBLIC_BASE_URL を編集）'
MSG_step_recordings='録画フォルダーを準備（権限 1000:0 2770）'
MSG_install_recordings_failed='%s の所有者と権限を設定できませんでした
（docker の出力はログファイルにあります）'
MSG_install_recordings_mode='%s は %s です（%s であるべきです）'
MSG_step_start='サービスを起動（実行中のイメージは取得したばかりのもの）'
MSG_install_up_failed='サービスの起動に失敗しました（全出力はログファイルにあります）'
MSG_step_ready_wait='準備完了を待機'
MSG_step_ready='準備完了を待機（バックエンドのバージョン %s）'
MSG_install_not_ready='バックエンドが %s 秒以内に準備完了を報告しませんでした'
MSG_install_not_ready_hint='サービスは起動したままです。原因はバックエンドのログにあります。
起動を拒否した場合は、どの設定がなぜ拒否されたかが書かれています：'
MSG_install_version_bad='バックエンドの報告したバージョンは %s で、%s ではありません'
MSG_step_done='完了'
MSG_install_stopped='インストールは手順 %s で停止しました。済んだ部分はそのまま残します。
上の問題を解決してから再実行してください（済んだ手順は安全に
繰り返されます）：'
MSG_install_log='ログファイル：%s'
MSG_install_declined='選択に従って停止しました。サービスは起動していません。発行元を
確認してから再実行してください：'
MSG_done_title_setup='インストールが完了しました。ブラウザーで初期設定を行ってください。'
MSG_done_title_login='インストールが完了しました。ブラウザーでログインしてください。'
MSG_done_address='アドレス    %s'
MSG_done_account='アカウント  admin'
MSG_done_password='パスワード  %s'
MSG_done_password_where='（%s の ADMIN_INITIAL_PASSWORD にも記載）'
MSG_done_password_kept='パスワード  %s の ADMIN_INITIAL_PASSWORD の値'
MSG_done_ui_1='初めてアクセスすると「マスターキー初期化」ページが開きます。
マスターキーはブラウザーで生成され、Custodexa はサーバーの
ディスクに保存しません。各自で安全に保管してください。再起動の
たびに、誰かが封印解除ページで入力するまでサービスを提供しません。'
MSG_done_ui_2='上のアカウントで初期化を承認してからログインしてください。
初回ログインでパスワードの変更を求められます。変更後は .env の
ADMIN_INITIAL_PASSWORD の行を削除してください。'
MSG_done_login='上のアカウントでログインしてください。初回ログインでパスワードの
変更を求められます。変更後は .env の ADMIN_INITIAL_PASSWORD の行を
削除してください。'
MSG_done_kms_1='初めてアクセスすると封印解除ページが開きます。上のアカウントで
認証してから、鍵管理サービスの認証情報を入力してください。封印が
解除されるとサービスを開始します。'
MSG_done_cert='このサイトは自己生成した証明書を使っています。
%s
をダウンロードして接続するコンピューターにインストールすると、
ブラウザーで安全な接続として表示されます。'
MSG_done_status='状態を確認  %s'
MSG_done_log='ログ        %s'

# ---- load ----
MSG_load_usage='読み込むオフラインイメージパッケージを指定してください。例：
custodexa.sh load custodexa-images-1.13.0-amd64.tar'
MSG_load_missing='%s は存在しません。'
MSG_load_bad_name='%s はオフラインイメージパッケージの名前の形式ではありません
（custodexa-images-<バージョン>-<アーキテクチャ>.tar）。'
MSG_load_no_manifest='バージョン %s のリリースマニフェストが見つかりません。この配置に
なく、%s の SHA256SUMS にも MANIFEST.json がありません。'
MSG_load_manifest_sum_bad='リリースマニフェストのチェックサムが
SHA256SUMS と一致しません。ダウンロードが不完全か、
ファイルが破損している可能性があります。
再ダウンロードしてください。'
MSG_load_title='オフラインイメージパッケージを読み込み'
MSG_load_file='  ファイル  %s（%s）'
MSG_load_sum_ok='チェックサムが SHA256SUMS と一致'
MSG_load_sum_none='%s に SHA256SUMS がなく、チェックサムを確認できません。
同じリリースの SHA256SUMS をパッケージの横に置いてください。
何も読み込んでいません。'
MSG_load_sum_unlisted='%s の SHA256SUMS にこのパッケージがありません。
何も読み込んでいません。'
MSG_load_sum_bad='チェックサムが SHA256SUMS と一致しません。
ダウンロードが不完全か、ファイルが破損している
可能性があります。再ダウンロードしてください。
何も読み込んでいません。'
MSG_load_arch_ok='アーキテクチャ %s、このホストと同じ'
MSG_load_arch_bad='このパッケージは %s 用で、このホストは %s です。%s を使って
ください。何も読み込んでいません。'
MSG_load_check_bad='パッケージがリリースマニフェストと一致しません。
ダウンロードが不完全か、ファイルが破損している
可能性があります。再ダウンロードしてください。
何も読み込んでいません：
%s'
MSG_load_empty='パッケージにバージョン %s のイメージがありません。何も読み込んで
いません。'
MSG_load_failed='docker load に失敗しました（全出力はログファイルにあります）。'
MSG_load_loaded='%s 個のイメージを読み込み'
MSG_load_digests_ok='すべてのイメージの内容ダイジェストがリリースマニフェスト
（MANIFEST）と一致'
MSG_load_id_bad='読み込み後の %s のイメージ ID が、読み込み前に確認したものと
異なります。使わずに、コピーし直したパッケージで読み込み直してください。'
MSG_load_trust_ok='発行者の署名とビルド来歴を検証済み'
MSG_load_trust_skip='%s：%s'
MSG_trust_name_sig='発行者の署名'
MSG_trust_name_prov='ビルド来歴'
MSG_text_load_unverified='  イメージは読み込みましたが、発行元はまだ確認していません。発行元の
  確認が必要なら、cosign と gh があり、インターネットに接続できる
  コンピューターで、運用担当者に完全なダイジェストで検証してもらい
  （検証コマンドは install または upgrade の実行時に表示されます）、
  通過してから下のコマンドを実行してください。'
MSG_load_next='イメージの準備ができました。サービスはまだ起動していません。次に：'
MSG_load_next_upgrade='アップグレードする場合：'
# status。各セクションの行は実行時に 56 桁で折り返す。ここでの改行はそのまま残る。
MSG_status_title='Custodexa の状態    %s    %s'
MSG_status_sec_version='バージョン'
MSG_status_sec_services='サービス'
MSG_status_sec_images='イメージ'
MSG_status_sec_backup='バックアップ'
MSG_status_sec_upgrade='前回のアップグレード'
MSG_status_pkg_sig_mismatch='パッケージの署名が一致せず、発行元は未確認です'
MSG_status_pkg_sig_unverified='パッケージの署名は未検証で、発行元は未確認です'
MSG_status_sec_disk='ディスク'
MSG_status_sec_reminders='お知らせ'
MSG_status_label_current='現在'
MSG_status_label_previous='一つ前'
MSG_status_kind_installed='パッケージ配置、%s にインストール'
MSG_status_kind_upgraded='パッケージ配置、%s にアップグレード'
MSG_status_previous_kept='releases/ に保存'
MSG_status_not_installed='まだインストールされていません。インストールするには：'
MSG_status_install_unfinished='インストールが完了していません（ステップ %s で停止）。
完了するには：'
MSG_status_services_ok_oneshot='%s 個のサービスプロセスが起動済み（tls-init は一度だけ実行され、
完了済み）'
MSG_status_services_ok='%s 個のサービスプロセスが起動済み'
MSG_status_services_down='%s 個のサービスが動いていません（全 %s 個）：%s'
MSG_status_services_none='この配置のコンテナーが見つかりません'
MSG_status_services_hint='コンテナーの状態を確認するには：'
MSG_status_health_ok='バックエンドは正常、バージョン %s'
MSG_status_health_version='バックエンドの報告はバージョン %s、記録上のバージョンは %s'
MSG_status_health_bad='バックエンドが /health に応答しません。ログを確認するには：'
MSG_status_sealed='システムはまだ封印されていて、利用者にサービスを提供して
いません。次の URL でマスターキーを入力してください：
%s'
MSG_status_seal_init='マスターキーがまだ初期化されておらず、利用者にサービスを
提供していません。次の URL で初期化してください：
%s'
MSG_status_unsealed='封印解除済み、利用者にサービスを提供中'
MSG_status_seal_unknown='バックエンドから封印の状態を取得できませんでした'
MSG_status_images='取得元 %s；%s'
MSG_status_src_local='このホスト'
MSG_status_src_offline='オフラインバンドル'
MSG_status_src_build='ソースからビルド'
MSG_status_backup='最新 %s（%s、%s）'
MSG_status_backup_upgrade='アップグレード前の自動バックアップ'
MSG_status_backup_script='custodexa.sh backup'
MSG_status_backup_external='自前のバックアップ'
MSG_status_backup_none='バックアップの記録がありません'
MSG_status_backup_encrypted='%s（暗号化済み）'
MSG_status_days_0='今日'
MSG_status_days_1='1 日前'
MSG_status_days_n='%s 日前'
MSG_status_upgrade_ok='%s → %s 成功、%s'
MSG_status_upgrade_failed='%s → %s はステップ %s で失敗、%s。ログ：'
MSG_status_upgrade_unfinished='%s → %s は完了していません（ステップ %s で中断）。
ログ：'
MSG_status_disk='data/ %s、backups/ %s；空き %s'
MSG_status_env_unreadable='.env を読めません。お知らせを確認するには sudo で status を
実行してください'
MSG_status_remind_password='.env に初期管理者パスワード（ADMIN_INITIAL_PASSWORD）が
残っています。管理者がパスワードを変更したら、この行を削除して
ください。'
MSG_status_remind_recordings='録画フォルダー %s は %s です。%s である必要があります
（所有者 1000、グループ 0）。修正するには：'
MSG_status_load_unfinished='前回の load はステップ %s で中断しました。変更するのは
Docker 内のイメージだけです。再実行すれば完了します：'

# ---- backup (used by upgrade and rollback) ----
MSG_bk_title='バックアップのプレビュー（まだ何も変更していません）'
MSG_bk_confirm='バックアップを開始しますか？[y/N]'
MSG_bk_step_stop='サービスを停止（データベースは動作したまま）'
MSG_bk_step_db='データベース'
MSG_bk_step_files='録画と監査ファイル'
MSG_bk_step_conf='設定ファイルと証明書'
MSG_bk_step_verify='バックアップを読み取れるか確認'
MSG_bk_contents='内容：%s'
MSG_bk_item_sep='、'
MSG_bk_item_db='データベース'
MSG_bk_item_rec='録画'
MSG_bk_item_audit='監査ファイル'
MSG_bk_item_env='設定ファイル .env'
MSG_bk_item_env_kek='設定ファイル .env（マスターキーを含む）'
MSG_bk_item_tls='証明書 tls/'
MSG_pb_item_tpl='プロキシテンプレート %s'
MSG_bk_log='ログファイル %s'
MSG_bk_db_unreachable='データベースのサイズを取得できず、必要な容量を見積もれません。
データベースのコンテナーが動作しているか確認してください。
サービスは停止していません。'
MSG_bk_dir_failed='%s にバックアップフォルダーを作成できません。
サービスは停止していません。'
MSG_bk_failed='バックアップは完了していません。途中までのファイルは %s にあり、
そこにある INCOMPLETE が使えないバックアップであることを示します。'
MSG_bk_start_again='サービスが停止したままの可能性があります。サービスを起動するには：'

# ---- portable backup (custodexa.sh backup) ----
MSG_pb_step_audit='監査ファイル'
MSG_pb_step_start='サービスを起動して準備完了を待つ'
MSG_pb_step_verify='各部分を読み取れるか確認'
MSG_pb_step_pack='単一ファイルにまとめ、読み戻して確認'
MSG_pb_done='バックアップ完了（%s）'
MSG_pb_sidecar='チェックサムファイル（同じフォルダー）：
%s'
MSG_pb_summary='バージョン %s、%s、マスターキー：%s'
MSG_pb_db_bundled='内蔵データベース'
MSG_pb_mode_env='設定ファイル'
MSG_pb_mode_ui='ブラウザーで入力'
MSG_pb_mode_kms='鍵管理サービス（%s）'
MSG_pb_mode_hsm='ハードウェアセキュリティモジュール（HSM）'
MSG_pb_kek_in='マスターキーはバックアップファイル内の .env にあり、
復元時に一緒に戻ります（指紋 %s）。'
MSG_pb_kek_out='マスターキーはバックアップファイルに含まれません。
指紋：%s
復元後、封印解除の材料を持つ人が封印解除ページで入力します。
指紋が一致する必要があります。'
MSG_pb_kek_kms='マスターキーは鍵管理サービス（%s）が保管し、バックアップファイルには
含まれません。鍵 ID：
%s
復元後、封印解除ページで保管先の認証情報を改めて入力してください。
鍵 ID が一致する必要があり、新しいホストからもサービスに
接続できる必要があります。'
MSG_pb_kek_in_nofp='マスターキーはバックアップファイル内の .env にあり、
復元時に一緒に戻ります。'
MSG_pb_kek_out_nofp='マスターキーはバックアップファイルに含まれません。
復元後、封印解除の材料を持つ人が封印解除ページで入力します。
指紋が一致する必要があります。'
MSG_pb_kek_kms_nofp='マスターキーは鍵管理サービス（%s）が保管し、バックアップファイルには
含まれません。
復元後、封印解除ページで保管先の認証情報を改めて入力してください。
鍵 ID が一致する必要があり、新しいホストからもサービスに
接続できる必要があります。'
MSG_pb_warn_kek_fp='マスターキーの指紋を取得できなかったため、復元時にマスターキーを
自動照合できません。理由はバックアップファイル内の snapshot.txt に
記録しています。'
MSG_pb_warn_fps='鍵の指紋 4 つのうち取得できないものがありました（マスターキーの
指紋は取得済み）。復元後、ほかの鍵は鍵一覧ページで照合してください。
理由はバックアップファイル内の snapshot.txt に記録しています。'
MSG_pb_warn_rec='録画はバックアップファイルに含まれていません。録画は
%s にあります。別の方法で保管するか、
録画を含めてもう一度バックアップしてください。'
MSG_pb_warn_plain='このバックアップファイルは暗号化されておらず、機密データ（データベースの
パスワード、サインイン用トークンの署名鍵、証明書の秘密鍵）を含み、
いまは .env と同じホストにあります。アクセスを制限した別の場所に
保管してください。バックアップ時にパスフレーズで暗号化することも
できます。'
MSG_pb_warn_plain_kek='このバックアップファイルは暗号化されておらず、マスターキーと
ほかの機密データ（データベースのパスワード、サインイン用トークンの
署名鍵、証明書の秘密鍵）を含みます。このファイルがあれば保存済みの
認証情報をすべて復号できます。アクセスを制限した別の場所に保管して
ください。バックアップ時にパスフレーズで暗号化することもできます。'
MSG_pb_svc_back='サービスは復旧しました。'
MSG_pb_svc_ui='サービスは起動し、封印解除待ちです：%s で
マスターキーを入力してください。'
MSG_pb_svc_kms='サービスは起動し、封印解除待ちです。
ローカル管理者アカウントで次のページを開いてください：
%s
保管先の情報を確認してから認証情報を入力してください。'
MSG_pb_svc_timeout='バックエンドが %s 秒以内に準備完了になりませんでした。利用者はまだ
接続できない可能性があります。バックアップは続行します。状態を確認し、
必要ならもう一度起動してください：'
MSG_pb_failed='バックアップは完了しておらず、バックアップファイルは作成されていません。
途中までのデータは次の場所にあります：
%s
復元には使えず、機密データを平文で含みます。
原因を確認したら削除してください。'
MSG_pb_valid='バックアップファイルは有効です：'
MSG_pb_after_both='ただし後続の処理が完了していません：state.json は更新されておらず
（status は前回のバックアップを表示します）、一時フォルダー
%s は削除されていません。
ディスク容量と権限を確認してから一時フォルダーを手動で削除してください。
次回のバックアップで state.json が更新されます。'
MSG_pb_after_state='ただし後続の処理が完了していません：state.json は更新されていません
（status は前回のバックアップを表示します）。ディスク容量と権限を
確認してください。次回のバックアップで state.json が更新されます。'
MSG_pb_after_partial='ただし後続の処理が完了していません：一時フォルダー
%s は削除されていません。
ディスク容量と権限を確認してから、手動で削除してください。'
MSG_pb_sig_valid='バックアップは最後の処理中に中断されましたが、バックアップファイルは
完成しており有効です：'
MSG_pb_sig_both='state.json は更新されておらず（status は前回のバックアップを表示）、
一時フォルダー %s は
削除されていません。手動で削除してください。'
MSG_pb_sig_partial='一時フォルダー %s は
削除されていません。手動で削除してください。'
MSG_pb_sig_timeout='バックエンドが %s 秒以内に準備完了になりませんでした。利用者はまだ
接続できない可能性があります。状態を確認し、
必要ならもう一度起動してください：'
MSG_pb_version_mismatch='state.json のインストール済みバージョンは %s ですが、
current/MANIFEST.json は %s です。
このバックアップのバージョンを判断できません。
サービスは停止していません。次のコマンドで確認してください：'
MSG_pb_tool_version='このスクリプトのリリースマニフェスト %s は %s 用ですが、
スクリプトは %s です。バックアップを作成したツールを記録できません。
サービスは停止していません。'
MSG_pb_kek_material='.env の KEK_PROVIDER は %s ですが、ENCRYPTION_KEY に値があります。
矛盾した設定で、バックエンドも次回の起動時に拒否します。バックアップ
するとマスターキーとして持ち出すことになるため、実行しません。
サービスは停止していません。どちらの方式を使うか決めて、
もう一方を消してください。'
MSG_pb_kek_none='.env に KEK_PROVIDER も ENCRYPTION_KEY もないため、マスターキーの
方式を判断できません。バックエンドは次回の起動時に拒否します。
サービスは停止していません。'
MSG_pb_kek_env_empty='.env の KEK_PROVIDER は env ですが、ENCRYPTION_KEY が空です。
バックエンドは次回の起動時に拒否します。サービスは停止していません。'
MSG_pb_kek_unknown='.env の KEK_PROVIDER の値を認識できません（env、ui、kms、hsm のみ、
小文字で指定）。サービスは停止していません。'
MSG_pb_tpl_missing='.env の TLS_NGINX_TEMPLATE の指定先：
%s
読み取れるファイルではありません。バックアップにはこのファイルも含める
ため、実行しません。サービスは停止していません。パスを直すか、この行を
消して同梱のテンプレートを使うようにしてから、もう一度実行してください。'
MSG_pb_tpl_chars='.env の TLS_NGINX_TEMPLATE は %s ですが、
このパスにはバックアップファイルに記録できない文字（二重引用符、
バックスラッシュ、タブ、日本語などの非 ASCII 文字）が含まれています。
復元時にテンプレートを元の場所へ戻すためにパスを記録するので、
実行しません。サービスは停止していません。これらの文字を含まないパスに
テンプレートを置くか、この行を消して同梱のテンプレートを使うように
してから、もう一度実行してください。'
MSG_pb_ts_taken='%s にはこの時刻（%s）のバックアップファイルか
一時フォルダーがすでにあります。サービスは停止していません。
数秒後にもう一度実行してください。'
MSG_pb_need='必要な空き %s（バックアップファイル約 %s、
組み立て中の一時領域と 1 GB の余裕を含む）。
バックアップ先の空き %s'
MSG_pb_no_space='バックアップ先の空き容量が足りません：%s 必要です（組み立て中の
一時領域と 1 GB の余裕を含む）が、%s の空きは %s です。
サービスは停止していません。'
MSG_pb_no_space_hint='古いバックアップファイルを別の場所へ移してからここで削除するか、
（録画を含めた場合は）録画を含めずにもう一度実行してください。'
MSG_pb_no_space_ls='現在のバックアップファイル：%s'
MSG_pb_sig_failed='バックアップはステップ %s で中断され、バックアップファイルは作成されて
いません。起動したツールのプロセスは停止しました。途中までのデータは
%s にあります。
復元には使えず、機密データを平文で含みます。削除してください。'
MSG_pb_sig_again='もう一度バックアップするには、再実行してください：'
MSG_pb_sizes='データベース %s、監査ファイル %s、録画 %s。 バックアップ先の空き %s'
MSG_pb_rec_q='録画をバックアップファイルに含めますか？'
MSG_pb_rec_no='含めない（既定）：ファイル約 %s、サービス停止 約 %s'
MSG_pb_rec_yes='含める：ファイル約 %s、サービス停止 約 %s'
MSG_pb_rec_short='必要な空き：%s。容量不足のため、この選択肢では実行できません'
MSG_pb_rec_keep='含めない場合は、録画フォルダーを別の方法で保管してください。'
MSG_pb_choose='[1-2] を選んでください。Enter で既定を使います：'
MSG_pb_enc_q='バックアップファイルをパスフレーズで暗号化しますか？'
MSG_pb_enc_why='暗号化しないファイルにはデータベースのパスワード、証明書の秘密鍵などの
機密データが含まれ、ファイルを手にした人ならだれでも読めます。'
MSG_pb_enc_why_env='暗号化しないファイルにはデータベースのパスワード、マスターキー、
証明書の秘密鍵などの機密データが含まれ、ファイルを手にした人なら
だれでも読めます。'
MSG_pb_enc_no='暗号化しない（既定）：ファイルはそのまま tar で開けます'
MSG_pb_enc_yes='暗号化する：復元には同じパスフレーズが必要です。
パスフレーズを失うと、スクリプトでも開発者でも
このバックアップから復元することはできません。'
MSG_pb_pass_rules='パスフレーズ：12～256 文字。半角の英字、数字、空白、半角記号のみ
使えます。空白もパスフレーズの一部として数えます。'
MSG_pb_pass_prompt='パスフレーズ  > '
MSG_pb_pass_again='もう一度入力  > '
MSG_pb_pass_match='2 回の入力は一致しました'
MSG_pb_tries_n='あと %s 回'
MSG_pb_tries_1='あと 1 回'
MSG_pb_pass_differ='2 回の入力が一致しません。もう一度入力してください（%s）。'
MSG_pb_pass_short='パスフレーズは 12 文字以上必要です。もう一度入力してください（%s）。'
MSG_pb_pass_chars='パスフレーズに使えない文字（日本語や全角記号など）が含まれています。
もう一度入力してください（%s）。'
MSG_pb_pass_long='パスフレーズは 256 文字以内にしてください。
もう一度入力してください（%s）。'
MSG_pb_pass_cancel='3 回試してもパスフレーズを設定できなかったため、バックアップを
取り消しました。何も変更していません。'
MSG_pb_rec_line_no='録画：含めない'
MSG_pb_rec_line_yes='録画：含める'
MSG_pb_rec_line_hint='録画：含めない（含めるには --with-recordings を付ける）'
MSG_pb_enc_line_no='暗号化：しない'
MSG_pb_enc_line_yes='暗号化：パスフレーズで暗号化（AES-256）'
MSG_pb_enc_line_hint='暗号化：しない（暗号化するには --passphrase-file <ファイル> を付ける）'
MSG_pb_enc_line_file='暗号化：パスフレーズファイル %s で暗号化'
MSG_pb_pause='バックエンド、接続サービス、Web 画面を約 %s停止します（データベースは
動作したまま）。データを取り終えると自動で起動して準備完了を待ち、
その後さらに約 %sかけてファイルをまとめて確認します。'
MSG_pb_warn_seal_ui='マスターキーはブラウザーで入力する方式です。再起動後はシステムが封印
状態に戻り、だれかが封印解除ページでマスターキーを入力するまで利用者は
接続できません。'
MSG_pb_warn_seal_kms='マスターキーは鍵管理サービスが保管しています。再起動後はシステムが
封印状態に戻り、だれかが封印解除ページで保管先の認証情報を改めて入力
するまで利用者は接続できません。'
MSG_pb_warn_seal_hsm='マスターキーはハードウェアセキュリティモジュールが保管しています。
再起動後はシステムが封印状態に戻り、だれかが封印解除ページで封印を
解除するまで利用者は接続できません。'
MSG_pb_dur_m='%s 分'
MSG_pb_dur_m1='1 分'
MSG_pb_dur_h='%s 時間'
MSG_pb_dur_h1='1 時間'
MSG_pb_dur_more_m='%s 分'
MSG_pb_dur_more_m1='1 分'
MSG_pb_dur_more_h='%s'
MSG_pb_step_pack_enc='単一ファイルにまとめて暗号化し、読み戻して確認'
MSG_pb_done_enc='バックアップ完了（%s、暗号化済み）'
MSG_pb_warn_pass='復元には同じパスフレーズが必要です。失うと復元できません。
パスフレーズはバックアップファイルとは別に保管してください。'
MSG_pb_warn_enc_host='このファイルはいま .env と同じホストにあります。
別の場所に保管してください。'
MSG_pb_enc_scheme='暗号化方式：AES-256-CBC。鍵はパスフレーズから
PBKDF2-SHA256（60 万回）で導出'
MSG_pb_no_openssl='このホストには暗号化に使う openssl イメージがありません
（インストールまたはアップグレードのときに取得されます）。
サービスは停止していません。このリリース（%s）のオフライン
イメージバンドルを読み込むか、暗号化しない設定でやり直してください。
バンドルのファイル名は %s のような形で、
インストールパッケージと同じリリースページにあります：'
MSG_pb_pf_read='パスフレーズファイル %s を読み取れません（存在しない、通常の
ファイルではない、シンボリックリンクである、または読み取り権限が
ない）。サービスは停止していません。'
MSG_pb_pf_perm='パスフレーズファイル：%s
次のいずれかに該当します：
- ほかのアカウントが読み取りまたは書き込み可能（権限 %s）
- 所有者があなたでも root でもない
- 追加のアクセス制御リストが設定されている
サービスは停止していません。
修正してからもう一度実行してください：'
MSG_pb_pf_line='パスフレーズファイル %s の 1 行目が規則に合いません：12～256 文字で、
半角の英字、数字、空白、半角記号のみ使えます。
サービスは停止していません。'

# ---- own backup (used by upgrade and rollback) ----
MSG_br_title='アップグレード前のバックアップ'
MSG_br_opt1='[1] スクリプトで完全バックアップを取る（推奨）'
MSG_br_opt1_detail='データベース、録画、監査ファイル、設定ファイル、証明書。
推定 %s、約 %s 分'
MSG_br_opt1_detail_notls='データベース、録画、監査ファイル、設定ファイル。
推定 %s、約 %s 分'
MSG_br_opt2='[2] 自分のバックアップを使う'
MSG_br_opt2_detail='例：仮想マシンのスナップショット、ストレージのスナップショット'
MSG_br_choose='選択してください [1/2]：'
MSG_br_chosen='自分のバックアップを使うことを選びました'
MSG_br_times='監査記録は %s にすべて書き込み済みを確認し、
サービスは %s に停止しました。
いまスナップショットを取ってください。停止後に開始し、データフォルダー、
.env、証明書フォルダーが同じ復元可能なバックアップに含まれることを
確認してください。'
MSG_br_times_notls='監査記録は %s にすべて書き込み済みを確認し、
サービスは %s に停止しました。
いまスナップショットを取ってください。停止後に開始し、データフォルダーと
.env が同じ復元可能なバックアップに含まれることを確認してください。'
MSG_br_must='スナップショットに含めるもの'
MSG_br_item_data='データフォルダー  %s（データベース、録画、監査ファイル）'
MSG_br_item_env='設定ファイル      %s'
MSG_br_item_tls='証明書フォルダー  %s'
MSG_br_item_db='データベース      %s 以降に取得した外部データベースの完全バックアップ'
MSG_br_cannot_check='スクリプトはスナップショットの中身を確認できません。後でロールバックする
際、このバージョンでデータベース構造が変わっていれば、スクリプトは復元を
代行しません。復元の前で止まり、このスナップショットから復元する手順を
示します。'
MSG_br_enter='スナップショットができたら順に入力してください
（アップグレード記録に残ります）：'
MSG_br_ask_ref='スナップショットの名前または ID     > '
MSG_br_ask_time='スナップショットの開始時刻（YYYY-MM-DD HH:MM）> '
MSG_br_time_format='YYYY-MM-DD HH:MM の形式で入力してください（例：2026-09-30 02:18）'
MSG_br_time_ok='%s は停止時刻 %s より後です'
MSG_br_ask_restore='復元手順の場所（文書名または保管場所）> '
MSG_br_ask_yes='スナップショットに上のすべての項目が含まれ、この手順で復元できますか？
yes と入力 > '
MSG_br_time_early='スナップショットの時刻 %s は停止時刻 %s より前です'
MSG_br_time_early_detail='このスナップショットには停止直前に書き込まれた記録が含まれず、復元すると
データが欠けます。スナップショットを取り直すか、[1] を選んで
スクリプトにバックアップさせてください。サービスは停止したままで、
ほかは何も変更していません。'
MSG_br_cancel_hint='アップグレードを取りやめるには、すべてのサービスを起動して確認します：'
MSG_br_not_confirmed='スナップショットが確認されませんでした
（名前、復元手順、yes が必要です）。
サービスは停止したままで、ほかは何も変更していません。'
MSG_br_flags_incomplete='--backup-ref は --backup-time と --backup-restore と一緒に指定します。
何も変更していません。'
MSG_br_ref_running='自分のバックアップはサービス停止後に取る必要があります。
対話的に実行するか（停止後にスクリプトがスナップショットを待ちます）、
スクリプトのバックアップを使ってください。何も変更していません。'
MSG_br_stop_unknown='バックエンドの停止時刻を読み取れず、スナップショットの時刻を確認
できません。何も変更していません。'
MSG_br_drain_timeout='バックエンドのログに、停止時に監査キューを書き切れなかった記録が
あります。この状態のスナップショットは不完全なので使えません。
何も変更していません。'
MSG_br_ref_used='あなたのバックアップ %s を使います（%s、停止 %s より後）。
スクリプトはバックアップを取りません。'

# ---- upgrade version rules (used by upgrade and rollback) ----
MSG_vr_bad_version='「%s」はバージョン番号ではありません（例：1.13.2）。'
MSG_vr_older='%s にはアップグレードできません：現在の %s より古いバージョンです'
MSG_vr_older_detail='古いバージョンに戻すには、アップグレード前のバックアップを
「バックアップとリストア」第 5 節「リストアの手順」に沿って手動で
リストアしてください。'
MSG_vr_same='すでに %s です'
MSG_vr_same_detail='アップグレードするものはありません。この配置の状態を確認するには：'
MSG_vr_skip='%s は %s から直接アップグレードできません。%s 以上が必要です'
MSG_vr_skip_detail='先に %s へアップグレードし、動作を確認してから
%s へアップグレードしてください：'

# ---------- upgrade: entry, package, check for a newer version ----------
MSG_up_title='Custodexa アップグレードのプレビュー（まだ何も変更していません）'
MSG_up_row_installed='  現在のバージョン   %s'
MSG_up_row_target='  アップグレード先   %s'
MSG_up_row_root='  配置ディレクトリ   %s'
MSG_up_confirm='アップグレードを開始しますか？[y/N]'
MSG_up_not_target='「%s」はバージョンでもパッケージファイル（custodexa-<バージョン>.tar.gz）
でもありません'
MSG_up_incoming_failed='一時ディレクトリ %s を作成できません'
MSG_up_download_failed='GitHub から %s のパッケージをダウンロードできません。オフラインで
アップグレードするには、ダウンロード済みのパッケージを指定してください：'
MSG_up_pkg_no_sums='%s が見つかりません。
パッケージは SHA256SUMS と同じフォルダに置いてください'
MSG_up_pkg_sum_bad='%s のチェックサムが SHA256SUMS と一致しません。
ダウンロードが不完全か、ファイルが破損している
可能性があります。再ダウンロードしてください'
MSG_up_pkg_sig_bad='%s：署名が一致せず、発行元は未確認です'
MSG_up_pkg_sig_missing='%s：署名ファイルがなく、発行元は未確認です'
MSG_up_pkg_sig_skip='%s はチェックサムのみ検証し、発行者署名は検証していません
（このホストに cosign がありません）'
MSG_up_pkg_ok='%s のチェックサムと発行者署名を検証しました'
MSG_up_pkg_layout='%s は %s のパッケージではありません（そのバージョンのスクリプトまたは
VERSION ファイルがありません）'
MSG_up_release_differs='%s はすでに存在し、このパッケージと内容が異なります。中身を確認してから
再実行してください'
MSG_up_no_deployment='ここには配置がありません：%s'
MSG_up_no_deployment_running='稼働中の配置は %s にあります。
配置ディレクトリを指定して実行してください：'
MSG_q_installed='現在のバージョン   %s（パッケージ配置、%s）'
MSG_q_latest='最新バージョン     %s（%s 公開）'
MSG_q_up_to_date='すでに最新バージョンです'
MSG_q_direct='直接アップグレードできます（%s は %s 以降からの直接アップグレードに対応）'
MSG_q_migrations_none='データベース構造の変更はありません'
MSG_q_migrations_one='データベース構造の変更が 1 件適用されます。アップグレード後に
ロールバックするには、アップグレード前のバックアップの復元が必要です'
MSG_q_migrations_many='データベース構造の変更が %s 件適用されます。アップグレード後に
ロールバックするには、アップグレード前のバックアップの復元が必要です'
MSG_q_migrations_unknown='データベースの現在の構造バージョンを読めないため、適用される構造変更の
件数が分かりません'
MSG_q_verified='リリースマニフェスト（MANIFEST）のチェックサムと発行者署名を検証しました'
MSG_q_unverified='リリースマニフェストはチェックサムのみ検証し、発行者署名は検証して
いません（このホストに cosign がありません）。
以下の結果は出所が未検証です'
MSG_q_no_sig='リリースマニフェストの署名ファイルがなく、
発行元は未確認です。アップグレード確認には
チェックサムを確認済みのマニフェストを使用します'
MSG_q_verify_fail_2='リリースマニフェスト（MANIFEST）のチェックサムが
SHA256SUMS と一致しません。ダウンロードが不完全か、
ファイルが破損している可能性があります。
再ダウンロードしてください。
アップグレードできるか判断できません'
MSG_q_verify_fail_3='リリースマニフェストの署名が一致せず、
発行元は未確認です。アップグレード確認には
チェックサムを確認済みのマニフェストを使用します'
MSG_q_notes='  リリースノート  %s'
MSG_q_run='アップグレードするには、次を実行します：'
MSG_q_only='この操作は確認のみで、何も変更していません。'
MSG_q_offline='GitHub に接続できません。オフラインでアップグレードするには、
パッケージのパスを指定してください：'
# ---------- upgrade: checks before the preview, and the preview ----------
MSG_up_row_kek='  マスターキー方式   %s'
MSG_up_kek_ui='ブラウザで入力'
MSG_up_kek_env='設定ファイル'
MSG_up_kek_kms='外部鍵管理サービス（KMS）'
MSG_up_kek_hsm='ハードウェアセキュリティモジュール（HSM）'
MSG_up_will='実行する内容'
MSG_up_will_1='  1. 監査記録がすべてデータベースに書き込まれるのを待ってから、
     サービスを停止します（データベースは動作したまま）'
MSG_up_will_2='  2. 完全バックアップ：データベース、録画、監査ファイル、設定、
     証明書。見込み %s、バックアップ先の空き %s'
MSG_up_will_2_ref='  2. --backup-ref で指定した自前のバックアップを使います。
     スクリプトは今回バックアップを作りません'
MSG_up_will_2_own='  2. 今回は外部データベースをスクリプトでバックアップできません
     （理由は下記）。停止後、停止より後に取った自前のバックアップを
     確認していただきます'
MSG_up_will_3='  3. %s に切り替えて起動します'
MSG_up_will_4='  4. 確認：バージョン、元と同じデータか、鍵が変わっていないか'
MSG_up_know='知っておくこと'
MSG_up_know_pause='  - 停止時間は %s〜%s 分の見込みです。停止中は接続できず、
    進行中の接続は切断されます（現在 %s 本の接続が進行中）'
MSG_up_know_pause_unknown='  - 停止時間は %s〜%s 分の見込みです。停止中は接続できず、
    進行中の接続は切断されます'
MSG_up_know_backend_down='  - バックエンドが動作していないため監査キューを確認できません。
    そのままサービスを停止します'
MSG_up_know_mig_none='  - 今回はデータベース構造の変更はありません'
MSG_up_know_mig_one='  - 今回はデータベース構造の変更が 1 件あります。アップグレード後に
    戻すにはこのバックアップの復元が必要で、バックアップ後の記録は
    失われます'
MSG_up_know_mig_many='  - 今回はデータベース構造の変更が %s 件あります。アップグレード後に
    戻すにはこのバックアップの復元が必要で、バックアップ後の記録は
    失われます'
MSG_up_know_mig_unknown='  - データベースの現在の構造バージョンを読めないため、構造変更の
    件数がわかりません'
MSG_up_know_ui='  - アップグレード後、システムは「封印中」のままです。誰かがブラウザで
    マスターキーを入力して封印を解除する必要があります'
MSG_up_know_kms='  - アップグレード後、システムは「封印中」のままです。次の三つを
    用意してください：ローカル管理者の認証情報、鍵保管先の認証情報、
    デプロイ構成の記録'
MSG_up_know_old_images='  - 現在のバージョンのイメージの一部がこのホストにありません。
    ロールバックには再ビルドか再取得が必要です'
MSG_up_know_tmux='  - ホスト操作に慣れた担当者が、セッションを維持できる端末ツール
    （tmux や screen など）の中で実行してください。SSH の切断で
    アップグレードが中断する危険を減らせます'
MSG_dg_step='監査記録の書き込み完了を待つ'
MSG_dg_left_first='残り %s 件'
MSG_dg_left_next=' ... %s 件'
MSG_dg_done='監査記録の書き込み完了を待つ（残り 0 件）'
MSG_dg_timeout='監査記録の書き込み完了を待つ：120 秒後も %s 件が
書き込み待ちです'
MSG_dg_timeout_what='サービスは動作したままで、何も変更していません。
通常はデータベースが混雑しているか、書き込みが遅くなっています。
利用の少ない時間帯にもう一度アップグレードしてください。
現在の数値を自分で確認するには：'
MSG_dg_sealed='監査記録の書き込み完了を待つ：システムは封印中で、監査の
書き込みはまだ始まっていないため、待つ記録はありません'
MSG_dg_stopped='監査記録の書き込み完了を待つ：バックエンドが動作していない
ため、待つ記録はありません'
MSG_dg_unknown='監査記録の書き込み完了を待つ：確認できません'
MSG_dg_unknown_detail='              書き込み待ちの件数も、封印中かどうかも読めません
              （送信元アドレスの制限で拒否されたか、バックエンドが
              応答しません）。'
MSG_dg_unknown_what='書き込み待ちの記録を確認できないため、アップグレードを中止しました。
サービスは動作したままで、何も変更していません。
まず sudo %s status%s でバックエンドの状態を
確認してください。それでも読めない場合は、このエラーとアップグレードの
記録ファイルを運用担当に渡し、送信元アドレスの制限
（SEAL_UNSEAL_ALLOWED_CIDRS）を確認してから再試行してください。'
# ---------- upgrade: stopping the old version ----------
MSG_st_stop_failed='サービスの停止に失敗しました。一部だけ停止している可能性があります'
MSG_st_log_unreadable='バックエンドのログを読めないため、停止時に監査記録がすべて
書き込まれたか確認できません'
MSG_st_drain_timeout='サービスの停止：終了の制限時間内に監査記録をすべて
データベースへ書き込めませんでした'
MSG_st_drain_counts='未確認 %s 件（予備ファイルへ %s 件、処理中で未報告 %s 件、
失われた記録 %s 件）'
MSG_st_drain_detail='予備ファイルは %s にあります。アップグレードは
ここで止まり、サービスは停止したままで、ほかは何も変更していません。
これらの記録を確認してから旧バージョンのサービスを再開してください。'
MSG_st_resume='旧バージョンのサービスを再開するには：'
MSG_st_gone='旧バージョンの完全停止を確認（データベース接続 0）'
MSG_st_conn_left='停止後もアプリケーションのアカウントにデータベース接続が
%s 本残っています'
MSG_st_conn_unknown='アプリケーションのアカウントの接続数を読めないため、
旧バージョンが完全に停止したか確認できません'
MSG_st_conn_detail='旧バージョンのバックエンドが別のホストや別の compose プロジェクトで
動いているか、接続がまだ回収されていない可能性があります。
アップグレードはここで止まり、サービスは停止したままです。
見つけて停止し、下の問い合わせが 0 になるまで確認してください：'

# upgrade: an interrupted upgrade, the next time it is run
MSG_up_rerun_safe='サービス停止の前で止まっていました。サービスは動作を続けており、
何も変更されていません。最初からやり直します。'
MSG_up_rerun_resumed='サービスは再開されており、バージョンとデータは変わっていません。
最初からやり直し、バックアップも取り直します。'
MSG_up_hint_stopped='サービスは停止中です。バージョンとデータは変わっていません。
旧バージョンを再開してから、もう一度アップグレードしてください。'
MSG_up_hint_again='もう一度アップグレードするには：'
MSG_up_hint_switched='新バージョンへの切り替えは済んでいます。先にバックエンドのログで
原因を確認してください：'
MSG_up_hint_backup='アップグレード前のバックアップ：%s'

# upgrade：プレビュー後の手順、起動後の確認、終了画面
MSG_up_run_title='アップグレード %s → %s'
MSG_up_step_env='環境の確認'
MSG_up_step_images='新バージョンのイメージの取得と検証'
MSG_up_step_confirmed='開始を確認済み'
MSG_up_step_backup='バックアップ'
MSG_up_bk_snap='アップグレード前の件数と鍵のフィンガープリントを記録'
MSG_up_bk_db='データベース        %s'
MSG_up_bk_files='録画と監査ファイル  %s'
MSG_up_unseal_after='マスターキーはブラウザで入力する方式のため、サービス再開後に
もう一度封印解除が必要です。'
MSG_up_step_switch='%s に切り替え'
MSG_up_step_start='起動'
MSG_up_step_ready='準備完了を待つ'
MSG_up_step_check='確認'
MSG_up_step_record='記録'
MSG_up_failed_at='前回のアップグレードはステップ %s で停止しました。'
MSG_up_know_verified='  - イメージのチェックサム、署名、来歴証明はすべて検証済みです'
MSG_up_fail_switch='アップグレードはステップ 9/13 で停止しました：新バージョンに
切り替えられませんでした'
MSG_up_fail_start='アップグレードはステップ 10/13 で停止しました：新バージョンが
起動しませんでした'
MSG_up_fail_ready='アップグレードはステップ 11/13 で停止しました：バックエンドが
%s 秒以内に準備完了を報告しませんでした'
MSG_up_fail_checks='アップグレードはステップ 12/13 で停止しました：確認に合格しません
でした'
MSG_up_state_title='現在の状態'
MSG_up_state_switched='%s に切り替え済み'
MSG_up_state_not_ready='%s に切り替え済み。サービスは起動しましたが、バックエンドが
準備完了になっていません'
MSG_up_state_backup='アップグレード前のバックアップは完全です：%s'
MSG_up_state_backup_own='アップグレード前のバックアップはお客様のスナップショットです。
記録：%s'
MSG_up_state_no_auto='スクリプトは自動でロールバックしません'
MSG_up_logs_first='まずバックエンドのログで原因を確認してください：'
MSG_up_logs_more='それでも判断できない場合は、このログとアップグレードのログ
ファイルを運用担当者に渡してください。'
MSG_up_done_sealed='新バージョンが起動しました：%s。利用者の接続を許可する前に、
封印解除と下記の手動確認が必要です'
MSG_up_done='新バージョンが起動しました：%s。利用者の接続を許可する前に、
下記の手動確認が必要です'
MSG_up_todo='残りの作業'
MSG_up_todo_unseal_ui='システムは現在「封印中」です。%s で
マスターキーを入力してください。'
MSG_up_todo_unseal_kms='システムは現在「封印中」です。ローカル管理者アカウントで %s を
開き、保管先の情報を確認してから認証情報を入力してください。'
MSG_up_todo_manual_after='封印解除後、利用者の接続を許可する前に、手動で確認してください
（スクリプトではできません）：
- 監査チェーンの検証に合格する
- アップグレード前の録画を 1 本再生できる
- テスト接続を作成していくつかコマンドを実行し、監査記録に
  残ることを確認する（省略不可：接続できても監査記録が
  書き込まれているとは限りません）'
MSG_up_todo_manual='利用者の接続を許可する前に、手動で確認してください
（スクリプトではできません）：
- 監査チェーンの検証に合格する
- アップグレード前の録画を 1 本再生できる
- テスト接続を作成していくつかコマンドを実行し、監査記録に
  残ることを確認する（省略不可：接続できても監査記録が
  書き込まれているとは限りません）'
MSG_up_done_rollback='ロールバック    下のバックアップを「バックアップとリストア」
                第 5 節「リストアの手順」に沿って手動でリストア'
MSG_up_done_backup='バックアップ    %s'
MSG_up_done_log='ログファイル    %s'
MSG_pc_title='確認結果'
MSG_pc_services_bad='サービス       正常に動作していません：%s'
MSG_pc_version='バージョン     バックエンドの報告 %s'
MSG_pc_version_bad='バージョン     バックエンドの報告 %s、本来は %s'
MSG_pc_images_bad='イメージ       実行中のイメージが取得時の記録と異なります'
MSG_pc_data_unknown='データ         前後の件数を読み取れず比較できません。手動で
               確認してください'
MSG_pc_mig_missing='DB 構造        アップグレード前の構造バージョンがありません：
               %s'
MSG_pc_mig_none='DB 構造        構造の変更なし'
MSG_pc_mig_one='DB 構造        1 件適用：%s'
MSG_pc_mig_many='DB 構造        %s 件適用：%s'
MSG_pc_same_data='同じデータ     ユーザー %s、接続記録 %s、アップグレード前と同じ。
               監査記録 %s（前 %s、起動時に %s 件追加）'
MSG_pc_counts_bad='同じデータ     ユーザー %s（前 %s）、接続記録 %s（前 %s）、
               監査記録 %s（前 %s）'
MSG_pc_keys_manual='鍵             前後のフィンガープリントが不完全で自動比較でき
               ません。鍵の一覧ページで手動確認してください'
MSG_pc_keys_changed='鍵             鍵のフィンガープリントがアップグレード前と異なります'
MSG_pc_keys_same='鍵             4 つの鍵のフィンガープリントはアップグレード前と同じ'
MSG_pc_lock_other='単一インスタンス データベースロックを別のデータベースセッションが
               保持しています：別のバックエンドが同じ DB に接続中'
MSG_pc_lock_held='単一インスタンス このバックエンドがデータベースロックを取得'
MSG_pc_lock_unknown='単一インスタンス バックエンドのログにロックの記録がなく確認できません'
MSG_pc_entry_bad='入口           %s が応答しません'
MSG_pc_empty_title='新バージョンが空のデータベースに接続しました。すべてのサービスを
直ちに停止しました'
MSG_pc_empty_moved='新バージョンはデータベースを新規インストールとして作成しました
（ユーザー %s、接続記録 %s。アップグレード前は %s と %s）。
元のデータがあるパス %s は、
このアップグレードで書き換えも削除もされていません。
よくある原因は .env の DATA_PATH が別の場所を指していることです：
  現在の DATA_PATH=%s
  アップグレード前のデータ %s'
MSG_pc_empty_moved_do='ログインしないでください。マスターキーの初期化もディレクトリの
削除もまだ行わないでください。
1. 運用担当者に新旧 2 つのデータパスを確認してもらう：
   %s には今回誤って作成されたデータ
   （ユーザー %s、接続記録 %s）だけがあり、
   %s には元のデータが残っていること
2. 確認後、.env の DATA_PATH を %s に戻す
3. 問題がないと確認してから %s を削除する
4. アップグレード前のバージョンに戻す場合は、アップグレード前の
   バックアップを「バックアップとリストア」第 5 節「リストアの手順」に
   沿って手動でリストアする'
MSG_pc_empty_same='新バージョンはデータベースを新規インストールとして作成しました
（ユーザー %s、接続記録 %s。アップグレード前は %s と %s）。
データパス %s は、このアップグレードで
書き換えも削除もされていません。新バージョンが別のデータベースに
接続している可能性があります。'
MSG_pc_empty_same_do='ログインしないでください。マスターキーの初期化もディレクトリの
削除もまだ行わないでください。
1. 運用担当者に .env のデータベース設定とバックエンドのログを確認
   してもらい、新バージョンが元のデータを読めなかった原因を探す
2. 確認後にアップグレード前のバージョンに戻す場合は、アップグレード前の
   バックアップを「バックアップとリストア」第 5 節「リストアの手順」に
   沿って手動でリストアする'

# Main menu (custodexa.sh without a command, on a terminal).
MSG_menu_title='Custodexa 管理スクリプト %s    配置フォルダー %s'
MSG_menu_state_none='現在の状態：未インストール'
MSG_menu_state_package='現在の状態：インストール済み %s（パッケージ配置）'
MSG_menu_language='言語：--lang en English、--lang zh-TW 繁體中文'
MSG_menu_install='インストール'
MSG_menu_load_first='オフラインイメージバンドルを読み込む（ネット接続がない場合は先に）'
MSG_menu_status='状態を表示'
MSG_menu_upgrade='アップグレード'
MSG_menu_backup='単一ファイルにバックアップ（他のホストへ移せる。サービスを停止する）'
MSG_menu_load='オフラインイメージバンドルを読み込む'
MSG_menu_help='ヘルプ'
MSG_menu_quit='終了'
MSG_menu_choose='選択してください [0-%s]：'
MSG_menu_choose_sub='選択してください [1-%s]（Enter でメインメニューに戻る）：'
MSG_menu_invalid='その選択肢はありません。角かっこ内の数字を入力してください。'
MSG_menu_other_path='別のパスを入力'
MSG_menu_bundle_found='オフラインイメージバンドルを読み込みます。
現在のフォルダー %s にあるバンドル：'
MSG_menu_bundle_none='オフラインイメージバンドルを読み込みます。
現在のフォルダー %s にバンドルがありません
（ファイル名の例：custodexa-images-%s-amd64.tar）。'
MSG_menu_ask_bundle='バンドルのパス（Enter でメインメニューに戻る）> '
MSG_menu_up_title='どのバージョンにアップグレードしますか？'
MSG_menu_up_latest='最新版（新しいバージョンを確認し、あればそのままアップグレード）'
MSG_menu_up_version='バージョンを指定'
MSG_menu_up_package='ダウンロード済みのパッケージ（オフラインでも可）'
MSG_menu_ask_version='バージョン（例：1.13.2）（Enter でメインメニューに戻る）> '
MSG_menu_package_found='ダウンロード済みのパッケージでアップグレードします。
現在のフォルダー %s にあるパッケージ：'
MSG_menu_package_none='ダウンロード済みのパッケージでアップグレードします。
現在のフォルダー %s にパッケージがありません
（ファイル名の例：custodexa-%s.tar.gz）。'
MSG_menu_ask_package='パッケージのパス（Enter でメインメニューに戻る）> '

MSG_up_restore_guide='%s に戻す場合は、上のバックアップを「バックアップとリストア」
第 5 節「リストアの手順」に沿って手動でリストアしてください。'
MSG_menu_images_install='イメージ取得元'
MSG_menu_images_upgrade='%s へのアップグレードで使うイメージ取得元'
MSG_menu_images_auto='  [1] 自動（既定）：このホスト、オフラインバンドル、GHCR、Docker Hub、
      最後にソースからビルド'
MSG_menu_images_source='  [2] 同梱ソースからビルド（時間がかかります。上流イメージは別途取得）'
MSG_menu_images_choose='[1-2] を選択。Enter で自動：'
MSG_q_wait_download='最新版の %s をダウンロードしています…'
MSG_q_download_ok='%s をダウンロードしました'
MSG_q_optional_signature_missing='署名ファイルを取得できません。発行元は未確認です'
MSG_q_wait_checksum='リリースマニフェストと SHA256SUMS のチェックサムを確認しています…'
MSG_q_checksum_ok='リリースマニフェストのチェックサムは一致します'
MSG_q_wait_signature='リリースマニフェストの署名を検証しています…'
MSG_up_wait_download='%s をダウンロードしています…'
MSG_up_download_ok='%s をダウンロードしました'
MSG_up_wait_checksum='%s と SHA256SUMS のチェックサムを確認しています…'
MSG_up_checksum_ok='%s のチェックサムは一致します'
MSG_up_wait_signature='リリースマニフェストの署名を検証しています…'
MSG_up_step_reserved='このステップで行う処理はありません'

# Whole-deployment service controls.
MSG_menu_start='サービスを起動'
MSG_menu_stop='サービスを停止'
MSG_help_cmd_start='  start                  全サービスを起動し、バックエンドの準備完了を待つ'
MSG_help_cmd_stop='  stop                   確認して全サービスを停止'
MSG_svc_stop_title='サービスを停止'
MSG_svc_stop_warn='現在の接続は切断されます。利用者に通知してください。
監査キューの排出後に停止します。'
MSG_svc_stop_confirm='全サービスを停止しますか？[y/N]'
MSG_svc_stop_done='サービスを停止しました'
MSG_svc_stop_already='サービスはすでに停止しています。'
MSG_svc_start_title='サービスを起動'
MSG_svc_start_done='起動しました。状態を確認し、必要なら封印を解除してください。'
MSG_svc_start_already='サービスは稼働中で、バックエンドも準備完了です。'
MSG_svc_drain_run='監査記録の書き込みを待機'
MSG_svc_drain_done='監査キューの排出が完了'
MSG_svc_drain_fail='監査キューの排出を確認できません。サービスは稼働中です。'
MSG_svc_stop_run='全サービスを停止中'
MSG_svc_start_run='全サービスを起動中'
MSG_svc_ready_run='バックエンドの準備完了を待機（最大 180 秒）'
MSG_svc_stop_failed='停止が完了しませんでした。状態を確認してください。'
MSG_svc_start_failed='起動が完了しませんでした。状態を確認してください。'
MSG_svc_ready_failed='180 秒以内にバックエンドが準備完了になりませんでした。
状態を確認してください。'
MSG_svc_cancelled='サービスは変更されていません。'
MSG_svc_status_hint='次のコマンドで状態を確認してください：'
MSG_svc_containers_up='コンテナーを起動しました'
MSG_svc_ready_done='バックエンドの準備が完了しました'
MSG_svc_not_installed='未インストールのため、サービスを操作できません。'
MSG_svc_resume_hint='サービスの状態が一部だけ変更された可能性があります。
状態を確認し、start で全サービスを復旧してください：'
MSG_svc_pending_run='前回の %s が完了していません。先に復旧コマンドに従ってください。'

# The backup of an external database (lib/dbext.sh, lib/backup_external.sh).
MSG_pb_summary_ext='バージョン %s
外部データベース %s（PostgreSQL %s）
マスターキー：%s'
MSG_pb_ext_tool='エクスポートツール：PostgreSQL %s クライアント（同梱・確認済み）'
MSG_pb_ext_conn='接続：%s、%s'
MSG_pb_ext_mode_system='verify-full（PGSSLROOTCERT=system による。バックエンドと同じ）'
MSG_pb_ext_verify_none_none='サーバー証明書を検証しない'
MSG_pb_ext_verify_none_file='サーバー証明書を検証しない（CA ファイルはバックアップに含める）'
MSG_pb_ext_verify_ca_system='システムが信頼する認証局でサーバー証明書を検証、ホスト名は照合しない'
MSG_pb_ext_verify_ca_file='CA ファイルでサーバー証明書を検証、ホスト名は照合しない
CA ファイルはバックアップに含める'
MSG_pb_ext_verify_full_system='システムが信頼する認証局でサーバーを検証'
MSG_pb_ext_verify_full_file='CA ファイルでサーバーを検証（CA はバックアップに含める）'
MSG_pb_ext_standby='バックアップ中は待機ホストにこのデータベースを引き継がせないでください。
バックアップの内容が不整合になるおそれがあります。'
MSG_pb_pause_ext='バックエンド、接続サービス、Web 画面を
約 %s停止します（外部データベースには影響しません）。
データを取り終えると自動で起動し、準備完了を待ちます。
その後、さらに約 %sかけてファイルをまとめて確認します。'
MSG_pb_step_stop_ext='サービスを停止（外部データベースには影響しない）'
MSG_pb_ext_and='、'
MSG_pb_ext_no_tool='外部データベースは PostgreSQL %s です。
このリリースのエクスポートツールは %s のみです。
サーバーと同じメジャーバージョンのツールしか使いません。
何も停止していません。
各自のデータベースのバックアップ手順を使ってください。
アップグレードでは自前のバックアップ
（--backup-ref）を使えます。'
MSG_pb_ext_unreachable='外部データベース %s に接続できません。
.env の DB_USER、DB_NAME、DB_SSLMODE を使用しています。
原因はログファイルにあります。何も停止していません。'
MSG_pb_ext_unreachable_hint='次の順に確認してください：
  1. このホストからそのアドレスとポートに届くか
     （名前解決、ファイアウォール）
  2. バックエンドが今データベースに接続できているか：
     %s
  3. DB_SSLMODE がサーバーの TLS 設定と合っているか
  4. DB_USER のパスワードがデータベース側で変更されていないか'
MSG_pb_ext_no_image='このホストには外部データベース用のエクスポートツールのイメージ
（PostgreSQL 16／17／18 クライアント。インストールかアップグレードで
取得するもの）がありません。何も停止していません。このリリース（%s）
のオフラインイメージバンドルを読み込んでください：'
MSG_pb_ext_unsupported='外部データベースに、このバックアップが対応しない設定があります。新しい
データベースサーバーではそのまま再構築できません：
%s
何も停止していません。各自のデータベースのバックアップ手順を使うか、
先に上の項目を変更してください。'
MSG_pb_ext_dep_ts='カスタムテーブルスペース：%s（%s 個のオブジェクト）'
MSG_pb_ext_dep_owner='%s 以外の所有者：%s（%s 個のオブジェクト）'
MSG_pb_ext_dep_ext='拡張機能：%s'
MSG_pb_ext_dep_ca='CA ファイルがスクリプトから見つからない場所にある：
PGSSLROOTCERT=%s'
MSG_pb_ext_dep_cert='クライアント証明書がスクリプトから見つからない場所にある：
PGSSLCERT=%s'
MSG_pb_ext_dep_keypath='クライアント秘密鍵がスクリプトから見つからない場所にある：
PGSSLKEY=%s'
MSG_pb_ext_dep_key='クライアント秘密鍵 PGSSLKEY がバックアップ対象の監査フォルダーにある'
MSG_pb_ext_dep_key_rec='クライアント秘密鍵 PGSSLKEY がバックアップ対象の録画フォルダーにある'
MSG_pb_ext_dep_sysca='DB_SSLMODE=verify-ca ですが、エクスポートツールに
システムの CA ファイルがなく、同じ方法でサーバーを
検証できない'
MSG_pb_ext_roles='外部データベースに、ほかのロールへ付与された権限があります：
%s
新しいデータベースサーバーでは、先にこれらのロールを
作成しないと、復元後の権限が変わります。'

# ---- upgrade of an external database, and step 7 as one backup file ----
MSG_up_bk_file='バックアップファイル
%s  %s'
MSG_up_bk_unrecorded='バックアップファイルは完成しました：
%s
ただし state.json を更新できませんでした。
アップグレードは止まり、サービスは停止したままです。
バージョンも切り替えていません。'
MSG_st_gone_unchecked='旧バージョンの停止を確認（サービスは停止済み。外部
データベースの接続数はスクリプトから数えられません。
待機ホストなど他のホストのバックエンドが
接続していないことを確認してください）'
MSG_up_no_space_hint='古いバックアップファイルを別の場所へ移してから、
ここで削除してください。'
MSG_up_ext_major_sep='／'
MSG_up_ext_own_version='今回は外部データベースをスクリプトでバックアップできません。
外部データベースは PostgreSQL %s で、このリリースには同じメジャー
バージョンのエクスポートツールがありません。手順 7 では自分の
バックアップしか使えません。'
MSG_up_ext_own_image='今回は外部データベースをスクリプトでバックアップできません。
エクスポートツールのイメージ（PostgreSQL %s クライアント）を取得
できませんでした（理由はログファイルにあります）。手順 7 では自分の
バックアップしか使えません。'
MSG_up_ext_own_connect='今回は外部データベースをスクリプトでバックアップできません。
外部データベースに接続できませんでした：
%s
理由はログファイルにあります。
手順 7 では自分のバックアップしか使えません。'
MSG_up_ext_own_unsupported='今回は外部データベースをスクリプトでバックアップできないため、
手順 7 では自分のバックアップしか使えません。外部データベースに、
このバックアップが対応していない設定があります：'
MSG_up_ext_ni_version='スクリプトで外部データベースをバックアップできません（外部データベースは
PostgreSQL %s で、このリリースには同じメジャーバージョンの
エクスポートツールがありません）。さらに今回は非対話の実行（端末なし、
または --yes 指定）のため、自分のバックアップを選べません。何も変更して
いません。次の順に進めてください：'
MSG_up_ext_ni_image='スクリプトで外部データベースをバックアップできません。
エクスポートツール（PostgreSQL %s クライアント）の
イメージを取得できませんでした。理由はログファイルにあります。
今回は非対話の実行（端末なし、または --yes 指定）のため、
この実行中に自分のバックアップへ切り替えることはできません。
何も変更していません。次の順に進めてください：'
MSG_up_ext_ni_connect='スクリプトで外部データベースをバックアップできません。
外部データベースに接続できませんでした：
%s
理由はログファイルにあります。
今回は非対話の実行（端末なし、または --yes 指定）のため、
この実行中に自分のバックアップへ切り替えることはできません。
何も変更していません。次の順に進めてください：'
MSG_up_ext_ni_unsupported='スクリプトで外部データベースをバックアップできません（このバックアップが
対応していない下記の設定があります）。さらに今回は非対話の実行
（端末なし、または --yes 指定）のため、自分のバックアップを選べません。
何も変更していません。'
MSG_up_ext_ni_order='次の順に進めてください：'
MSG_up_ext_ni_1='1. 監査記録の書き込み完了を待ってから、サービスを停止：'
MSG_up_ext_ni_2='2. サービスが停止したことを確認：'
MSG_up_ext_ni_3='3. 停止後に自分のバックアップを開始し、外部データベース、データ
   フォルダー、.env と tls/ を含め、開始時刻を控える。'
MSG_up_ext_ni_3_notls='3. 停止後に自分のバックアップを開始し、外部データベース、データ
   フォルダーと .env を含め、開始時刻を控える。'
MSG_up_ext_ni_4='4. 次のオプションを付けてアップグレードを再実行：'
MSG_up_ext_ni_flags='--backup-ref <スナップショット名> --backup-time "YYYY-MM-DD HH:MM" \\
--backup-restore <復元手順の場所>'

# ---------- restore：入口、オプション、復元の種類 ----------
MSG_help_cmd_restore='  restore <バックアップファイル>
                       ポータブルバックアップファイルから復元する。
                       導入済みのホスト：安全バックアップを取ってから
                       データを置き換える。未導入のホスト：バックアップ時の
                       バージョンを先に導入してから復元する
  restore --resume     完了しなかった復元を続ける（封印解除後の
                       マスターキー照合を含む）
  restore --revert     復元前に取った安全バックアップで元に戻す
  restore --abandon    新しいホストで完了しなかった復元を取りやめ、
                       未導入の状態に戻す'
MSG_help_restore_options='restore のオプション
  --same-host | --new-host     端末がないときは必須：どちらの復元かを指定
  --confirm-data-loss          端末がないとき、既存データの上書きを確認する
                               （--yes と併用）
  --passphrase-file <ファイル> 暗号化バックアップのパスフレーズファイル
                               （権限の規則は backup と同じ）
  --no-checksum-file           .sha256 がなくても続ける（中のチェックサムは
                               すべて照合する）
  --package <パッケージ>       バックアップ時のバージョンのパッケージ
                               （同じフォルダーに SHA256SUMS、オフライン用）
  --images <バンドル>          バックアップ時のバージョンのオフライン
                               イメージバンドル
  --backup-ref、--backup-time、--backup-restore
                               安全バックアップの代わりに、サービス停止後に
                               自分で取ったバックアップを使う（安全バック
                               アップが完了しなかったときは --resume にも
                               付けられる）
  --data-path、--tls-domain、--tls-ip-san、--public-base-url
                               新しいホストのホスト値（指定しないときは
                               このホストの推奨値）
  --db-client-cert、--db-client-key
                               外部データベースのクライアント証明書と秘密鍵
  --accept-grant-loss          外部データベースにロールがないとき、それらの
                               ロールへの権限付与を省く
  --nginx-template <パス>      新しいホストでカスタム nginx テンプレートを
                               置く場所（元のパスが使えないとき）'
MSG_usage_restore_only='オプション %s は restore 専用です。参照：custodexa.sh --help'
MSG_rs_no_file='バックアップファイルを指定してください：
custodexa.sh restore <バックアップファイル>。
参照：custodexa.sh restore --help'
MSG_rs_option_with='オプション %s は %s と一緒に使えません。
参照：custodexa.sh restore --help'
MSG_rs_flow_both='--same-host と --new-host は同時に指定できません。'
MSG_rs_flow_needed_same='端末がないときは、どちらの復元かを指定してください。このホストは
導入済みで、データはバックアップで置き換えられます：--same-host を
付けてください。'
MSG_rs_flow_needed_new='端末がないときは、どちらの復元かを指定してください。このホストは
未導入です：--new-host を付けてください。'
MSG_rs_flow_wrong_same='このホストは未導入なので、新しいホストへの復元です：--same-host
ではなく --new-host を使ってください。'
MSG_rs_flow_wrong_new='このホストは導入済みで、データが置き換えられます：--new-host
ではなく --same-host を使ってください。'
# Going back after an upgrade.
MSG_rb_flags_only='--resume と --revert は rollback と restore 専用です。'
MSG_rb_flags_conflict='--resume と --revert は同時に指定できません。'
MSG_rb_no_pending='再開する未完了のロールバックはありません。何も変更していません。'
MSG_rb_confirm='開始しますか？[y/N]'
MSG_rb_preview='前のバージョンに戻す：確認（まだ何も変更していません）'
MSG_rb_versions='現在のバージョン   %s
戻すバージョン     %s（アップグレード前のバージョン）'
MSG_rb_basis_same='データベース   アップグレード後の構造変更はなく、
               アップグレード前の記録と一致しています'
MSG_rb_basis_not_started='データベース   新しいバージョンは一度も起動していないため、
               データベースは変更されていません'
MSG_rb_basis_compatible='データベース   アップグレード後に %s 件の構造変更がありますが、
               %s のリリースマニフェストには %s に直接戻せると
               記載されています（リリース前に検証済み）'
MSG_rb_basis_compatible_one='データベース   アップグレード後に %s 件の構造変更がありますが、
               %s のリリースマニフェストには %s に直接戻せると
               記載されています（リリース前に検証済み）'
MSG_rb_keep_data='バージョンだけを戻します。データ、設定ファイル、証明書は
そのまま維持されるため、バックアップの復元は不要です。'
MSG_rb_images='旧バージョンのイメージ   全 %s 個がこのホストにあります。
起動後、実行中のコンテナがそのイメージを使用しているか確認します。'
MSG_rb_steps='手順：サービス停止 → データベースを再確認して %s に戻す →
起動 → バージョンと実行中のイメージを確認'
MSG_rb_keep_records='アップグレード後に作成された記録はすべて保持されます。'
MSG_rb_step_stop='サービスを停止'
MSG_rb_step_stopped='サービスは停止済み'
MSG_rb_step_switch='データベースを再確認し、%s に戻す'
MSG_rb_step_revert='%s に戻す'
MSG_rb_step_start='サービスを起動'
MSG_rb_step_check='確認：バックエンドの応答は %s。実行中のイメージは
アップグレード前のものと一致'
MSG_rb_check_health='確認：%s 秒以内にバックエンドが準備完了になりませんでした'
MSG_rb_check_diff='確認：実行中のバージョンまたはイメージが記録と異なります：%s'
MSG_rb_done='%s に戻りました。'
MSG_rb_unseal='システムはシールされています。%s でシールを解除してください。'
MSG_rb_upgrade_later='再度アップグレードする場合は、通常どおり upgrade を実行してください。'
MSG_rb_revert_title='%s に戻す（このロールバックを開始する前のバージョン）'
MSG_rb_state_title='現在の状態'
MSG_rb_state_version='現在のバージョン：%s'
MSG_rb_state_links='記録上のバージョン：%s、current のリンク先：%s'
MSG_rb_state_services='実行中のサービス：%s'
MSG_rb_unchanged_data='データ、設定ファイル、証明書は変更していません'
MSG_rb_resume='原因を解消したら、前のバージョンに戻す処理を再開してください：'
MSG_rb_revert='または、アップグレード後のバージョン %s に戻してください：'
MSG_rb_resume_revert='アップグレード後のバージョン %s に戻す処理を再開してください：'
MSG_rb_refused='%s に直接戻せません。アップグレード後に %s が
データベースを変更しています。何も変更していません。%s。'
MSG_rb_services_running='サービスは引き続き実行中です'
MSG_rb_services_stopped='サービスは停止したままです'
MSG_rb_refused_after='%s に直接戻せません。サービス停止後の再確認で、%s が
データベースを変更したことが分かりました。バージョンは
切り替えていません。アプリケーションは停止済みで、
データベースは引き続き実行中です。'
MSG_rb_reason_changed='理由   アップグレード後に %s 件の構造変更（%s）があり、
       %s は変更後のデータベースを正しく使用できません'
MSG_rb_reason_unreadable='理由   データベースの現在の構造を読み取れず、
       アップグレード後に変更されたか確認できません'
MSG_rb_more='、ほか %s 件'
MSG_rb_restore='%s に戻すには、アップグレード前のバックアップを復元してください。
復元は確認を求めてから、データとバージョンの両方を
アップグレード前に戻します。アップグレード後のデータは置き換わります。'
MSG_rb_keep_new='復元せずに %s でサービスを続ける場合：'
MSG_rb_too_old='%s に直接戻せません。このスクリプトで戻せるのは
1.16.0 以降のバージョンです。何も変更していません。'
MSG_rb_no_previous='戻せる前のバージョンがありません。何も変更していません。'
MSG_rb_premise_none='このデプロイはスクリプトでアップグレードされていません。'
MSG_rb_premise_changed='前回のアップグレード後にバージョンの記録が変わっています。'
MSG_rb_premise_link='実行中のバージョンが記録と一致していません。'
MSG_rb_already='前回のバージョン変更はロールバックでした（%s、%s から %s）。
戻せるのは 1 つ前のバージョンだけです。%s に戻すには、
通常どおり upgrade を実行してください。'
MSG_rb_before_switch='前回のアップグレードは手順 %s で停止しています。
まだ新しいバージョンに切り替えていないため、戻す必要はありません。'
MSG_rb_status_hint='このデプロイの状態を確認してください：'
MSG_rb_images_bad='%s に戻すにはアップグレード前のイメージが必要ですが、
%s 個がこのホストにないか、以前と異なります。何も変更していません。'
MSG_rb_image_missing='%s  このホストにありません'
MSG_rb_image_diff='%s  ホストのイメージが記録と異なります
           以前 %s、現在 %s'
MSG_rb_load='%s のオフラインイメージバンドルを読み込んでから再実行してください：'
MSG_rb_upgrade_hint='%s に戻すには、次のコマンドを実行してください。スクリプトは
新しいバージョンがデータベースを変更していないことを確認してから、
%s に直接戻します。変更されていた場合は、上記のバックアップの
復元方法を案内します。サービス停止前に確認を求めます：'
MSG_rb_upgrade_done='%s に戻す   sudo %s/custodexa.sh rollback%s'
MSG_status_upgrade_rolled_back='前回のアップグレード %s → %s。%s にロールバック済み（%s）%.0s'
MSG_status_rollback_unfinished='前のバージョンに戻す処理が未完了です
（%s から %s、手順 %s で停止）'
MSG_status_rollback_reverting='アップグレード後のバージョンに戻す処理が未完了です
（%s に戻す途中、手順 %s で停止）'
MSG_status_rollback_reverted='前回のロールバックを取り消し、%s に戻りました'
MSG_status_rollback_refused='前回のロールバックは切り替え前に停止しました。%s が
データベースを変更していたため、%s のままです'
MSG_status_upgrade_failed_handed='%s → %s はステップ %s で失敗、%s。
その後、復元処理に引き継ぎました。ログ：'
MSG_help_cmd_rollback='  rollback             アップグレード前のバージョンに戻す。新しいバージョンが
                       データベースを変更していなければ、データを保持して
                       バージョンだけを戻す。変更されていれば何も変更せず、
                       復元方法を案内する
  rollback --resume    未完了のロールバックを再開する
  rollback --revert    未完了のロールバックを取り消し、
                       アップグレード後のバージョンに戻す'
MSG_help_opt_resume='  --resume               （rollback、restore）未完了の処理を再開する'
MSG_help_opt_revert='  --revert               （rollback、restore）未完了の処理を取り消す'

MSG_rb_refused_unreadable='%s に直接戻せません。アップグレード後に %s がデータベースを
変更した可能性があります。何も変更していません。%s。'

MSG_rb_refused_unreadable_after='%s に直接戻せません。サービス停止後の再確認で、%s が
データベースを変更していないことを確認できませんでした。
バージョンは切り替えていません。アプリケーションは停止済みで、
データベースは引き続き実行中です。'

MSG_rb_image_unrecorded='%s  アップグレード前のイメージ ID の記録がありません'

MSG_rb_state_not_ready='%s に戻してサービスを起動しましたが、
バックエンドは準備完了になっていません'

MSG_rb_state_before='まだバージョンを切り替えていません。%s のままです'

MSG_rb_state_start_failed='%s に戻しましたが、一部のサービスが起動していません'

MSG_rb_reverted='%s に戻りました（このロールバックを開始する前のバージョン）'

MSG_rb_no_services='なし'

MSG_rb_basis_compatible_unreadable='データベース   現在の構造を読み取れませんが、%s のリリース
               マニフェストには %s に直接戻せると記載されています
               （リリース前に検証済み）'

MSG_rb_step_check_revert='確認：バックエンドの応答は %s。実行中のイメージは
このロールバックを開始する前のものと一致'

MSG_status_rollback_unreadable='前回のロールバックは切り替え前に停止しました。%s が
データベースを変更した可能性があり、%s のままです'

MSG_rb_images_unverified='%s に戻すために必要なリリース情報、またはアップグレード前の
イメージ ID の記録を確認できません。必要なイメージがすべて
アップグレード前のものと一致するか確認できないため、
何も変更していません。'

MSG_rb_release_unverified='必要なリリース情報を読み取れません。'

# Reading a portable backup before a restore.
MSG_rs_unchanged='データは何も変更していません。'

MSG_rs_bad='バックアップファイルが不完全か変更されているため、復元できません：'

MSG_rs_copy_again='別のバックアップを使用するか、元の場所からこのファイルを
.sha256 と一緒にコピーし直してください。'

MSG_rs_bad_sidecar='チェックサムファイルがバックアップファイルと一致しません。'

MSG_rs_bad_members='余分な構成ファイル、欠落、または重複があります。'

MSG_rs_bad_type='構成ファイルがディレクトリ、リンク、またはパス付きです。'

MSG_rs_bad_manifest='バックアップマニフェストの項目が欠落しているか無効です：%s。'

MSG_rs_bad_sums='構成ファイルの一覧と SHA256SUMS が一致しません。'

MSG_rs_bad_hash='%s のチェックサムがバックアップ作成時の記録と異なります。'

MSG_rs_bad_cross='リリースマニフェスト、migration、マスター鍵のフィンガープリント、
または記録されたバージョンがバックアップマニフェストと一致しません。'

MSG_rs_bad_inner='内側のアーカイブに許可されていないパスまたはリンクがあります。'

MSG_rs_bad_name='ファイル名と暗号化ファイルのヘッダーが一致しません。'

MSG_rs_bad_decrypt='暗号化ファイルが途中で切れているか、長さが無効です。'

MSG_rs_bad_read='バックアップファイルを読み取れません。'

MSG_rs_bad_grants='内蔵データベースが他のロールに権限を付与しています：%s。
「バックアップとリストア」の第 5 節に従って手動で復元してください。'

MSG_rs_bad_grants_read='データベースのダンプから権限付与の項目を読み取れません。'

MSG_rs_reading='バックアップファイル %s を読み取ります'

MSG_rs_sum_ok='チェックサムファイルが一致しました'

MSG_rs_sum_absent='チェックサムファイルがないため、ファイル内のチェックサムで照合します'

MSG_rs_no_sum='チェックサムファイル %s がありません。
非対話実行でこのファイルなしに続行するには、
--no-checksum-file を付けてください。'

MSG_rs_missing_sum='チェックサムファイル %s がないため、
転送中にファイルが破損しなかったか確認できません。'

MSG_rs_missing_sum_checks='続行する場合、内部の各ファイルがバックアップ作成時のチェックサムと
一致し、記録同士も一致していることを確認してから次に進みます。
一つでも一致しなければ、何も変更せずに復元を中止します。'

MSG_rs_missing_sum_enc='このファイルは暗号化されています。チェックサムファイルがない場合、
復号できない原因がパスフレーズの誤りか破損かを区別できません。'

MSG_rs_missing_sum_ask='チェックサムファイルなしで続行しますか？[y/N]'

MSG_rs_pass_intro='このバックアップファイルは暗号化されています。作成時に設定した
パスフレーズを入力してください（入力中は表示されません）：'

MSG_rs_pass_prompt='パスフレーズ： '

MSG_rs_pass_needed='このバックアップは暗号化されています。非対話実行では
--passphrase-file を使用してください。'

MSG_rs_decrypt_matched='復号できません：パスフレーズが違います（ファイル自体の完全性は
確認済みです）。あと %s 回試せます。'

MSG_rs_decrypt_absent='復号できません：パスフレーズが違うか、ファイルが破損しています
（チェックサムファイルがないため区別できません）。あと %s 回試せます。'

MSG_rs_decrypt_cancel='3 回とも復号できなかったため、復元を中止しました。
データは何も変更していません。'

MSG_rs_no_openssl='このホストにはリリース %s の openssl ツールイメージがありません。
復元に必要です。
このリリースのオフラインイメージを先に読み込んでください。'

MSG_rs_parts='各構成ファイルを照合しました（%s 個）'

MSG_rs_manifest='バックアップマニフェスト：形式 1、バージョン %s、作成日時 %s'

MSG_rs_cross_ok='相互照合：リリースマニフェスト、migration、マスター鍵の
フィンガープリントが一致しました'

MSG_rs_old_file='これは 1.16.0 以降で作成されたバックアップファイルではないため、
スクリプトでは復元できません。'

MSG_rs_old_folder='%s は 1.16.0 より前のバックアップフォルダーです。
バックアップマニフェストがないため、バージョンと構成が不明です。'

MSG_rs_no_manifest='このファイルにはバックアップマニフェストがありません。'

MSG_rs_old_guide='この形式は作成元のホストで「バックアップとリストア」の第 5 節に従って
手動で復元してください。または、作成元を 1.16.0 以降にアップグレードし、
バックアップを作成し直してください。'


# Checking the data and keys before a restore.
MSG_rs_data_old='このバックアップのデータは %s のもので、1.16.0 より前のため、
スクリプトでは復元できません。'

MSG_rs_data_old_guide='は、アップグレード時に %s の環境から作成したバックアップです。
1.16.0 より前のバージョンは封印解除後にマスター鍵 ID を返さないため、
復元後のマスター鍵を確認できず、復元を開始しません。
「バックアップとリストア」に従って手動で復元してください：
  まず「単一のバックアップファイルから各ファイルを取り出す」に従います。
  このホストをアップグレード前のバージョンに戻す場合は、続いて
  「管理スクリプトでアップグレードした後、
  アップグレード前のバージョンに戻す」に従います。
  別のホストに復元する場合は、続いて「リストアの手順」に従います。'

MSG_rs_engine_old='この管理スクリプトは %s ですが、バックアップのデータは
より新しい %s のものです。'

MSG_rs_engine_old_guide='復元にはバックアップ以上のバージョンの管理スクリプトが必要です。
新しいホスト：get-custodexa.sh で %s 以降を取得して復元してください。
インストール済みのホスト：先に %s 以降にアップグレードしてから、
復元してください。'

MSG_rs_fp_missing='このバックアップにはマスター鍵のフィンガープリントがありません
（作成時に一意の値を読み取れませんでした）。復元後のマスター鍵を
確認できないため、復元を開始しません。'

MSG_rs_fp_manual='「バックアップとリストア」の第 5 節に従って手動で復元し、
第 6 節に従って鍵台帳を項目ごとに確認してください。'

MSG_rs_hsm='このバックアップのマスター鍵モードは hsm です。このリリースには
動作する HSM 実装がないため、スクリプトでは復元できません。'

MSG_rs_external='これは外部データベースを使う構成のバックアップです。
このビルドのスクリプトではまだ復元できません。'

MSG_rs_key_mismatch='設定ファイルのマスター鍵がこのバックアップのデータと一致しません：'

MSG_rs_key_fingerprints='設定ファイルの鍵のフィンガープリント   %s
バックアップに記録された値           %s'

MSG_rs_key_wrong='この鍵で復元すると保存済みの認証情報を復号できないため、
復元を開始しません。別の完全なバックアップを使用してください。'

MSG_rs_key_ok='設定ファイルのマスター鍵のフィンガープリント %s が記録と一致しました'

MSG_rs_jwt_ok='設定ファイルのログイントークン署名鍵のフィンガープリントが
バックアップのスナップショットと一致しました'

MSG_rs_jwt_unknown='設定ファイルのログイントークン署名鍵：スナップショットに
フィンガープリントが記録されていないため、未照合です'

MSG_rs_bad_jwt='設定ファイルのログイントークン署名鍵のフィンガープリントが
バックアップのスナップショットと一致しません。'

MSG_rs_bad_secret='設定ファイルに必要な鍵がないか、使用できないテンプレート値です：%s。'

MSG_rs_extracted='作業フォルダー %s に取り出しました'


MSG_rs_bad_release='リリースマニフェストのハッシュまたはバージョンが記録と一致しません。'

MSG_rs_bad_migrations='migration のハッシュまたは件数がバックアップマニフェストと一致しません。'

MSG_rs_bad_fingerprint='マスター鍵のフィンガープリントがスナップショットと一致しません。'

MSG_rs_bad_state='state.json のバージョンがバックアップマニフェストと一致しません。'

MSG_rs_parts_enc='復号し、各構成ファイルを照合しました（%s 個）'

MSG_rs_bad_decrypt_tool='復号ツールを実行できません。'

# Obtaining the backup version and checking its data structure.
MSG_rs_release_absent='%s のリリースファイルがないため、バックアップ作成時の
バージョンをこのホストに導入できません。'

MSG_rs_release_absent_guide='このバックアップのデータは %s のもので、同じバージョンでのみ
復元できます。スクリプトは別のバージョンを導入しません。
custodexa-%s.tar.gz と同じフォルダーの SHA256SUMS が手元にある場合は、
次のように指定してください：'

MSG_rs_release_other='それ以外の場合は、別のバージョンのバックアップを使用してください。'

MSG_rs_release_download='%s のパッケージをダウンロードできませんでした
（github.com に接続できません）。'

MSG_rs_release_offline='このホストからインターネットに接続できない場合は、
custodexa-%s.tar.gz と SHA256SUMS を同じフォルダーに置き、
--package で指定してください。%s のオフラインイメージは
--images で指定してください。'

MSG_rs_release_manifest='%s のパッケージ内のリリースマニフェストが、
バックアップ作成時の記録と一致しません。'

MSG_rs_release_manifest_guide='公開されたパッケージではない可能性があります。
スクリプトはこのパッケージで復元しません。'

MSG_rs_migration_bad='バックアップのデータには %s が認識しない構造変更があるため、
%s では復元できません：'

MSG_rs_migration_unknown='%s（%s のリリースマニフェストにありません）'

MSG_rs_migration_missing='%s（%s で必要ですが、バックアップのスナップショットにありません）'

MSG_rs_migration_guide='バックアップ作成時点で、より新しいバージョンがデータを変更していた
ことを意味します。新しいデータを古いバージョンには戻しません。'

MSG_rs_migration_missing_guide='このバージョンに必要な構造変更がバックアップにないため、
スクリプトでは復元しません。'


# Host values and the custom template destination.
MSG_rs_host_intro='以下の四つの値をこのホストに合わせます。
それ以外の設定はすべてバックアップを引き継ぎます。'

MSG_rs_host_intro_external='以下のデータフォルダーと公開 URL をこのホストに合わせます。
それ以外の設定はすべてバックアップを引き継ぎます。'

MSG_rs_host_data_path='データフォルダー DATA_PATH'

MSG_rs_host_tls_domain='証明書のホスト名 TLS_DOMAIN'

MSG_rs_host_tls_ip_san='証明書の IP TLS_IP_SAN'

MSG_rs_host_public_base_url='公開 URL PUBLIC_BASE_URL'

MSG_rs_host_values='       バックアップの値  %s
       このホストの推奨値  %s'

MSG_rs_host_ask_path='Enter で推奨値、- でバックアップの値を使います。
または別の絶対パスを入力してください > '

MSG_rs_host_ask='Enter で推奨値、- でバックアップの値を使います。
または別の値を入力してください > '

MSG_rs_data_absolute='DATA_PATH は絶対パスで指定してください。'

MSG_rs_data_nonempty='新しいホストでは、ここにデータベースや監査データを置けません：%s。'

MSG_rs_host_tls_nginx_template='カスタム nginx テンプレート TLS_NGINX_TEMPLATE'

MSG_rs_template_source='       バックアップの値  %s
         （このホストでは %s 内の元の場所を使えません）'

MSG_rs_template_ask='このホストでテンプレートを置く絶対パスを入力してください。
設定ファイルの参照先を変更します > '

MSG_rs_template_needed='このホストではテンプレートの元の場所を使えません：%s。
--nginx-template で新しい絶対パスを指定してください。'

MSG_rs_template_invalid='テンプレートは親フォルダーがある絶対パスで指定してください。
リンク、ディレクトリ、リリース管理下のパスは使えません：%s。'


# Space estimates before a restore.
MSG_rs_space_bad='空き容量が不足しているため、復元を開始しません：'

MSG_rs_space_row='%s（%s）：必要 %s GB、空き %s GB'

MSG_rs_space_margin='数値には 10%%～20%% の余裕を含みます。バックアップファイル内の
サイズは、バックアップ作成時の推定値です。'

MSG_rs_space_work='作業フォルダー'

MSG_rs_space_safety='復元前のバックアップ'

MSG_rs_space_data='データフォルダー'

MSG_rs_space_images='イメージ'

MSG_rs_space_unknown='%s の空き容量を取得できないため、復元を開始しません。'

MSG_rs_space_estimate='復元前のバックアップに必要な現在のデータベース容量を
推定できないため、復元を開始しません。'

# Restore preview and confirmation.
MSG_rs_label_backup='  バックアップ   '
MSG_rs_label_data_version='  データ版       '
MSG_rs_label_install='  先に導入       '
MSG_rs_label_version='  バージョン     '
MSG_rs_label_deployment='  配置形態       '
MSG_rs_label_restores='  復元対象       '
MSG_rs_label_recordings='  録画           '
MSG_rs_label_host='  ホストの値     '
MSG_rs_label_replaced='  置換対象       '
MSG_rs_label_safety='  事前の保存     '
MSG_rs_label_kept='  保管           '
MSG_rs_label_downtime='  停止時間       '
MSG_rs_label_space='  容量           '

MSG_rs_preview_new='復元プレビュー：この新しいホスト（まだ何も変更していません）'

MSG_rs_preview_same='このホストのデータをバックアップで置き換えます。
バックアップ後の記録はすべて失われます'

MSG_rs_preview_encrypted='暗号化済み'

MSG_rs_preview_plain='暗号化なし'

MSG_rs_backup_here='%s にこのホスト
（%s）で作成'

MSG_rs_backup_source='%s に %s で作成；
%s'

MSG_rs_backup_integrity='バックアップファイル内部の整合性：確認済み'

MSG_rs_data_engine='%s（この管理スクリプトは %s）'

MSG_rs_versions='現在 %s、復元後 %s'

MSG_rs_versions_changed='現在 %s、復元後 %s
（バージョンもデータとともにバックアップ時点に戻ります）'

MSG_rs_other_host='[WARN] このバックアップの作成元は別のホスト %s です。
       このホストのデータを置き換えます。'

MSG_rs_package_checked='パッケージ %s：チェックサム一致'

MSG_rs_package_local='パッケージのチェックサム：再確認なし。本機のリリースを使用'

MSG_rs_signature_ok='発行者の署名：検証済み'

MSG_rs_signature_no_cosign='発行者の署名：このホストに cosign がないため未検証'

MSG_rs_signature_no_bundle='発行者の署名：署名ファイルがないため未検証'

MSG_rs_signature_bad='[WARN] 発行者の署名が一致しません'

MSG_rs_signature_local='発行者の署名：本機のリリースは再検証していません'

MSG_rs_manifest_identical='リリースマニフェストはバックアップ内の記録とバイト単位で一致'

MSG_rs_preview_images_offline='イメージ %s 個、オフラインバンドル
%s から取得'

MSG_rs_preview_images_local='イメージ %s 個、本機に配置済み'

MSG_rs_preview_images_source='イメージ %s 個。プログラムのイメージはソースからビルド'

MSG_rs_preview_images_auto='イメージ %s 個。不足分は本機のオフラインバンドル、
レジストリー、ソースビルドの順で取得'

MSG_rs_deployment='内蔵データベース；%s；マスター鍵：
%s'

MSG_rs_tls_selfsigned='自己署名証明書'

MSG_rs_tls_provided='持ち込み証明書'

MSG_rs_tls_external='外部の入口'

MSG_rs_provider_ui='ブラウザーで入力'

MSG_rs_provider_env='設定ファイルで指定'

MSG_rs_provider_kms='鍵管理サービスで保管'

MSG_rs_restores_new='データベース %s、監査ファイル %s、設定ファイル
.env'

MSG_rs_restores_same='データベース、監査ファイル'

MSG_rs_restores_tls='、証明書 tls/'

MSG_rs_settings_same='設定ファイル .env は、ログイン署名鍵やデータベースの
パスワードなどの秘密情報を含めてバックアップ時点に戻ります。
DATA_PATH、TLS_DOMAIN、TLS_IP_SAN、PUBLIC_BASE_URL は
このホストの現在の値を保持します'

MSG_rs_settings_same_external='設定ファイル .env は、ログイン署名鍵やデータベースの
パスワードなどの秘密情報を含めてバックアップ時点に戻ります。
DATA_PATH と PUBLIC_BASE_URL はこのホストの現在の値を保持します'

MSG_rs_preview_template='カスタム nginx テンプレート → %s'

MSG_rs_template_repointed='（設定ファイルの参照先を変更）'

MSG_rs_template_keep='既存ファイルは名前を変えて保管します：
%s'

MSG_rs_recordings_restore='バックアップから戻します。同名の既存ファイルは保持し、
上書きしません'

MSG_rs_recordings_kept='このバックアップに録画はありません。現在の録画をそのまま保持し、
削除も上書きもしません'

MSG_rs_recordings_missing='バックアップに含まれません（作成元に %s）。
持ち込む録画の一覧を完了後に表示します'

MSG_rs_host_differences='ホストの値がバックアップと異なります：'

MSG_rs_host_difference='%s：バックアップ %s；このホスト %s'

MSG_rs_reissue='作成元とアドレスが異なります。バックアップの認証局を保持し、
このホストのアドレス用にサーバー証明書を再発行します'

MSG_rs_cert_mismatch='[WARN] 持ち込み証明書がこのホストのアドレスを含みません。
       対応する証明書に交換してください。ここでは変更しません。'

MSG_rs_cert_unknown='[WARN] 持ち込み証明書のアドレスを確認できません。
       手動で確認してください。証明書は変更しません。'

MSG_rs_replaced='このホストの現在のデータと設定をすべて置き換えます。
ユーザー、資産、権限、ポリシーはバックアップ時点に戻ります：'

MSG_rs_counts_current='現在の監査記録 %s 件、接続記録 %s 件'

MSG_rs_counts_backup='、
バックアップでは %s 件、%s 件'

MSG_rs_counts_caution='件数の差は参考値であり、失われる件数ではありません。
削除、変更、別のホストのデータはこの差からは分かりません'

MSG_rs_counts_unknown='現在の件数を取得できません'

MSG_rs_safety_own='持ち込みバックアップ：%s
作成日時 %s'

MSG_rs_safety_script='上書きする前に現在のデータを次のファイルにバックアップします：
%s
録画は含みません。読み戻して検証に通った後に処理を続けます'

MSG_rs_safety_none='不要：このホストにはまだデータがありません'

MSG_rs_kept='現在のデータベース、監査、証明書のフォルダーを
削除せず、名前を変えて保管します：'

MSG_rs_downtime='約 %s 分（復元前バックアップ %s 分、インポート %s 分、
起動と確認 5 分）'

MSG_rs_preview_space_same='必要 %s GB（%s）、空き %s GB'

MSG_rs_preview_env='マスター鍵は設定ファイル内にあります。
フィンガープリント %s は照合済みです'

MSG_rs_preview_ui_same='[WARN] マスター鍵はブラウザーで入力します。復元後は封印されるため、
       封印解除ページでマスター鍵を入力する必要があります。
       フィンガープリントは %s でなければなりません。'

MSG_rs_preview_ui_new='[WARN] マスター鍵はブラウザーで入力します。復元を完了するには、
       封印解除ページでマスター鍵を入力し、バックアップ内の管理者
       アカウントで認証します。フィンガープリントは
       %s でなければなりません。'

MSG_rs_preview_kms='[WARN] マスター鍵は鍵管理サービスにあります。復元を完了するには、
       封印解除ページでサービスを確認し、認証情報を再入力します。
       このホストのアドレスがサービス側で許可されている必要があります。'

MSG_rs_after_noninteractive='完了して確認が済んだら、最新バージョンを調べるコマンドを表示します。
自動ではアップグレードしません。'

MSG_rs_after_same_version='完了して確認が済んだら、最新バージョンを調べ、
アップグレードするかどうかを尋ねます。'

MSG_rs_after_newer_engine='完了して確認が済んだら、最新バージョンを調べ、
アップグレードするかどうかを尋ねます（本機に %s は配置済み）。'

MSG_rs_confirm_version='確認するには、復元後のバージョン %s を入力してください：'

MSG_rs_confirm_cancel='入力が %s と異なるため、復元を中止しました。
データは何も変更していません。'

MSG_rs_confirm_new='復元を開始しますか？[y/N] '

MSG_rs_confirm_flags='バージョン入力なしでこのホストのデータを置き換えるには、
--yes と --confirm-data-loss の両方が必要です。'

MSG_rs_confirm_new_flags='非対話実行では --yes で復元を確認してください。'

MSG_rs_preview_space_new='必要 %s GB（%s）、空き %s GB'

MSG_rs_kept_no_tls='現在のデータベースと監査ファイルのディレクトリを
削除せず、名前を変えて保管します：'

MSG_rs_control_revert='復元前に戻す処理が進行中です。先に完了してください。'

MSG_rs_control_abandon='この復元を中止する処理が進行中です。先に完了してください。'

MSG_rs_control_engine='この復元を開始した管理スクリプトで処理を続けてください。'

MSG_rs_control_placed='復元データは配置済みですが、サービスの起動は再開処理で行います。
実行中のイメージとマスター鍵を照合するためです。'

MSG_rs_control_before='復元ではまだデータを上書きしていません。
元のサービスを起動するには --revert を使ってください。'

MSG_rs_control_unchecked='復元は手順 %s で停止し、データの照合が済んでいません。
サービスは起動できません。'

MSG_rs_control_choices='処理を再開するか、復元前バックアップで元に戻してください：'

MSG_rs_control_after_unseal='封印解除後に照合を完了してください：'

MSG_rs_control_previous='前回の復元が終わっていません。先に再開するか、
復元前に戻すか、中止してください。'

MSG_rs_control_own='登録した復元手順に従い、用意したバックアップ %s を使ってください：'

MSG_rs_status_title='復元'

MSG_rs_status_pending='復元は未完了：%s（%s 開始、データ版 %s）'

MSG_rs_status_from='復元元 %s'

MSG_rs_status_resume='再開：%s'

MSG_rs_status_failed='復元は手順 %s で停止しました（失敗）'

MSG_rs_status_done='前回の復元：%s に完了、復元元
%s'

MSG_rs_status_kept='復元前のフォルダーを %s か所保管しています。
第 6 節の確認が済んだら削除できます'

MSG_rs_status_retained='フォルダーを %s か所保管しています'

MSG_rs_status_reverted='前回の復元：%s に復元前へ戻しました'

MSG_rs_status_abandoned='前回の復元：%s に中止し、未インストールの状態に戻りました'

MSG_rs_status_revert='復元前に戻す処理がまだ完了していません'

MSG_rs_status_abandon='復元の中止処理がまだ完了していません'

MSG_menu_rs_state='状態：復元は未完了（%s、データ版 %s）'

MSG_menu_rs_state_revert='状態：復元前に戻す処理が未完了'

MSG_menu_rs_state_abandon='状態：復元の中止処理が未完了'

MSG_menu_rs_resume='復元を再開'

MSG_menu_rs_unseal='復元を再開（封印解除後に照合を完了）'

MSG_menu_rs_revert='復元前バックアップで元に戻す'

MSG_menu_rs_abandon='この復元を中止して未インストールの状態に戻す'

MSG_menu_rs_finish_revert='復元前に戻す処理を完了'

MSG_menu_rs_finish_abandon='復元の中止処理を完了'

MSG_rs_control_upgrade='復元がまだ完了していません（%s、%s 開始）。
アップグレードは実行できません。'

MSG_rs_control_backup='復元がまだ完了していません（%s、%s 開始）。
バックアップは実行できません。'

MSG_rs_control_rollback='復元がまだ完了していません（%s、%s 開始）。
ロールバックは実行できません。'

MSG_rs_phase_checked='検査済み、リリース配置待ち'

MSG_rs_phase_prepared='リリース準備済み、復元前バックアップ待ち'

MSG_rs_phase_safety='復元前バックアップ準備済み'

MSG_rs_phase_stopped='サービス停止済み'

MSG_rs_phase_swapped='元データ保管済み、インポート待ち'

MSG_rs_phase_imported='インポート済み、データ照合待ち'

MSG_rs_phase_db_checked='データベース照合済み、ファイル配置待ち'

MSG_rs_phase_placed='データ配置済み、再開によるサービス起動待ち'

MSG_rs_phase_started='サービス起動済み、準備完了とマスター鍵照合待ち'

MSG_rs_phase_awaiting_unseal='インポート済み、封印解除後のマスター鍵照合待ち'

MSG_rs_phase_done='照合・復元完了'

MSG_rs_control_choices_new='処理を再開するか、この復元を中止してください：'

# 1 arguments
MSG_rs_safety_reason_fingerprint='現在のデータベースから一意のマスターキー識別子を読み取れません（%s 個）。
このバックアップにはマスターキーの指紋が含まれません。'

# 0 arguments
MSG_rs_safety_reason_hsm='現在のマスターキーモードは hsm です。'

# 0 arguments
MSG_rs_safety_reason_key='設定ファイルのマスターキーの指紋がデータベースと一致しません。'

# 1 arguments
MSG_rs_safety_reason_secret='設定ファイルに必要なキーがありません：%s。'

# 1 arguments
MSG_rs_safety_reason_engine='この管理スクリプトは現在のバージョンより古いものです。
%s を使ってください。'

# 1 arguments
MSG_rs_safety_reason_old='現在のバージョン %s は 1.16.0 より古いため、
バックアップは手動で復元してください。'

# 1 arguments
MSG_rs_safety_reason_manifest='リリースマニフェストがないか、current/MANIFEST.json と異なります：
%s'

# 1 arguments
MSG_rs_safety_reason_images='現在のバージョンのイメージがローカルにありません：%s。
先に load でそのバージョンのオフラインイメージを読み込んでください。'

# 0 arguments
MSG_rs_safety_preflight_warn='このホストでスクリプトが作成する安全バックアップは、
restore --revert で自動復元できません：'

# 0 arguments
MSG_rs_safety_preflight_own='今回はサービス停止後に自分で取得したバックアップ
（ストレージスナップショットなど）を安全バックアップに使ってください。
サービスはまだ停止していません。何も変更していません。'

# 1 arguments
MSG_rs_safety_preflight_fail='スクリプトが作成する安全バックアップは自動復元できません
（%s）。
端末なしで実行する場合は、サービス停止後に取得したバックアップを
--backup-ref、--backup-time、--backup-restore で登録してください。'

# 0 arguments
MSG_rs_safety_choose_title='復元はこのホストのデータを上書きするため、
先に現在のデータをバックアップします。'

# 0 arguments
MSG_rs_safety_choose_again='前回の安全バックアップは完了していません。
今回は現在のデータをどう保存しますか？'

# 1 arguments
MSG_rs_safety_choose_script='[1] スクリプトで保存（既定）：サービス停止後にデータベース、
    監査ファイル、設定と証明書を保存します。約 %s 分、
    録画は含みません（復元で変更しません）。'

# 1 arguments
MSG_rs_safety_choose_retry='[1] スクリプトで再保存（既定）：サービス停止後にデータベース、
    監査ファイル、設定と証明書を保存します。約 %s 分、
    録画は含みません（復元で変更しません）。'

# 0 arguments
MSG_rs_safety_choose_own='[2] サービス停止後に自分でバックアップを取得し
    （ストレージスナップショットなど）、その識別情報を入力します'

# 0 arguments
MSG_rs_safety_choose_prompt='[1-2] を選択してください。Enter で既定値を使います：'

# 0 arguments
MSG_rs_safety_choose_only='[2] を選択してください：'

# 0 arguments
MSG_rs_safety_id='識別'

# 0 arguments
MSG_rs_safety_time='時刻'

# 0 arguments
MSG_rs_safety_procedure='手順'

# 0 arguments
MSG_rs_safety_failed_title='3/10  安全バックアップ'

# 0 arguments
MSG_rs_safety_failed_write='バックアップ先への書き込みに失敗しました（No space left on device）。'

# 0 arguments
MSG_rs_safety_failed_read='安全バックアップの読み戻し検証に失敗したため、復元には使えません'

# 1 arguments
MSG_rs_safety_failed_unusable='安全バックアップは完全ですが、このスクリプトでは自動復元できません（%s）'

# 0 arguments
MSG_rs_safety_failed_body='復元前の安全バックアップが完了しなかったため、上書きは開始しません。
データは変更していません。サービスは停止したままです。'

# 0 arguments
MSG_rs_safety_resume='原因を解消してから、安全バックアップから再開してください：'

# 0 arguments
MSG_rs_safety_resume_own='自前のバックアップで再開してください：'

# 0 arguments
MSG_rs_safety_revert='または復元を取りやめ、元のサービスを起動してください：'

# 0 arguments
MSG_rs_safety_use_own='サービス停止後に取得した自前のバックアップも使えます。
端末での再開時に [2] を選ぶか、
再開コマンドに次の 3 つのオプションを付けてください：'

# 1 arguments
MSG_rs_safety_stop_time='自前のバックアップの時刻は、
この復元がサービスを停止した %s 以降が必要です。'

# 0 arguments
MSG_rs_safety_restarted='サービスが稼働中、記録した停止後に起動済み、または停止を確認できません。
restore --revert を実行してからやり直してください。'

# 0 arguments
MSG_rs_safety_flags_phase='自前のバックアップの 3 オプションは、
安全バックアップを待っている再開時に、
上書きが始まる前だけ指定できます。'

# 0 arguments
MSG_rs_safety_enter='スナップショットが完了したら入力してください（復元記録に保存されます）：'

# 0 arguments
MSG_rs_safety_setup_failed='安全バックアップ用のフォルダーを作成できません。'

# 0 arguments
MSG_rs_safety_failed_operation='安全バックアップを書き込めません。詳細は復元ログを確認してください。'

MSG_rs_safety_reason_fingerprint_short='現在のデータベースから一意のマスターキー識別子を読み取れません'

MSG_rs_journal_uncertain='復元操作が完了したか判断できません：%s。'

MSG_rs_journal_guide='ここで停止してください。これらのパスを変更する前に、
「バックアップとリストア」の手動復元手順を確認してください。'

MSG_rs_journal_missing='データの上書きは始まっていますが、操作記録がありません。
--revert で安全バックアップから復元してください。'

MSG_rs_import_start='データベースサービスを起動できませんでした。'

MSG_rs_import_ready='TCP 接続で対象データベースに接続できる状態になりませんでした。'

MSG_rs_import_encoding='データベースのエンコーディング、照合順序、文字分類が
バックアップと異なるため、インポートを停止しました。'

MSG_rs_import_failed='データベースのインポートに失敗しました。再開時に未完成のデータを
保持し、空のデータベースに再インポートします。'

# ---------- メインメニュー：復元の項目とバックアップファイルの選択。復元後の録画 ----------
# 0 arguments
MSG_menu_restore_new='バックアップファイルからこの新しいホストへ復元
（バックアップ時のバージョンを先にインストール）'

# 0 arguments
MSG_menu_restore='バックアップファイルから復元（このホストのデータを置き換える。
サービスを停止する）'

# 2 arguments: the backups folder, the current folder
MSG_menu_restore_found='バックアップファイルから復元します。%s と
現在のフォルダー %s にあるバックアップファイル：'

# 2 arguments: the backups folder, the current folder
MSG_menu_restore_none='バックアップファイルから復元します。%s と
現在のフォルダー %s にバックアップファイルがありません。'

# 0 arguments
MSG_menu_restore_encrypted='（暗号化済み）'

# 0 arguments
MSG_menu_ask_restore='バックアップファイルのパス（Enter でメインメニューに戻る）> '

# 1 argument: the number of files
MSG_rs_rec_put_back='録画：バックアップから %s 個のファイルを戻しました。同名の既存ファイルは
保持し、上書きしていません'

# 0 arguments
MSG_rs_rec_same_kept='録画はバックアップから復元されていません。このバックアップに録画はなく、
現在の録画はそのまま保持しています。録画はバックアップ時点と一致しない
ことがあります。バックアップ後に録画したものはディスクに残りますが、
システムには表示されません。バックアップ後に削除したものは戻りません。'

# 0 arguments
MSG_rs_rec_all_here='録画：システムに記録された録画のファイルはすべてこのホストにあります'

# 3 arguments: how many, the list file, the recordings folder of the source host
MSG_rs_rec_missing='録画はバックアップから復元されていません。システムに記録された録画の
うち %s 件のファイルがこのホストにありません。
一覧は次のファイルにあります：
%s
作成元ホストの %s から
コピーしてください。'

# 0 arguments
MSG_rs_rec_offsite='オフサイト保管にアップロード済みの録画は、再生時にそこから取得されます。'

# ---------- restore: the external database, checked before anything stops ----------
# 0 arguments
MSG_rs_ext_refused='外部データベースはまだ復元できません。理由：'
# 4 arguments: count, database, sources, applications
MSG_rs_ext_conns='%s 件の別の接続が %s を使用しています（接続元 %s、
アプリケーション %s）。先に元のホストのサービスを停止し、待機系ホストが
このデータベースを引き継いでいないことを確認してください。'
# 3 arguments: database, source, application
MSG_rs_ext_conns_one='1 件の別の接続が %s を使用しています（接続元 %s、
アプリケーション %s）。先に元のホストのサービスを停止し、待機系ホストが
このデータベースを引き継いでいないことを確認してください。'
# 0 arguments
MSG_rs_ext_from_local='ローカルソケット'
# 4 arguments: object, its owner, DB_USER, DB_USER
MSG_rs_ext_owner='オブジェクト %s の所有者は %s で、%s ではありません。
スクリプトが空にできるのは %s が所有するオブジェクトだけです。'
# 1 argument: DB_USER
MSG_rs_ext_owner_more='%s 以外が所有するオブジェクトはほかにもあります。'
# 2 arguments: server version, client majors
MSG_rs_ext_no_client='サーバーは PostgreSQL %s で、対応するクライアントがありません。
このリリースのクライアントは PostgreSQL %s です。'
# 2 arguments: server version, the server major of the backup
MSG_rs_ext_server_old='サーバーは PostgreSQL %s で、バックアップ元の PostgreSQL %s より
古いです。'
# 2 arguments: client major, the tool that made the dump
MSG_rs_ext_client_old='このリリースの PostgreSQL %s クライアントは、バックアップを作成した
ツール（%s）より古いです。'
# 2 arguments: DB_USER, DB_NAME
MSG_rs_ext_not_owner='%s はデータベース %s の所有者ではありません。schema public の
再作成にはデータベースの所有者が必要です。'
# 1 argument: the extensions
MSG_rs_ext_extension='データベースに plpgsql 以外の拡張機能があります（%s）。
スクリプトは拡張機能を空にすることも復元することもしません。'
# 3 arguments: encoding, collation, character type
MSG_rs_ext_encoding='データベースのエンコーディングまたは照合順序がバックアップと
異なります。同じ設定でデータベースを作成してください：
ENCODING '"'"'%s'"'"' LC_COLLATE '"'"'%s'"'"' LC_CTYPE '"'"'%s'"'"''
# 2 arguments: host:port, log file
MSG_rs_ext_unreachable='外部データベース %s に接続できないか、ログインに失敗しました。
原因は %s に記録されています。'
# 2 arguments: the check now, the check the backup recorded
MSG_rs_ext_tls_lower='サーバー証明書の検証がバックアップ時より弱くなります（現在 %s、
バックアップ時 %s）。'
# 1 argument: path
MSG_rs_ext_ca_conflict='CA ファイルの配置先 %s に内容の異なるファイルがあります。
先に移動してください。'
# 0 arguments
MSG_rs_ext_client_missing='バックアップのデータベース接続はクライアント証明書を使います。
--db-client-cert と --db-client-key で証明書と秘密鍵を指定してください。'
# 1 argument: path
MSG_rs_ext_client_unreadable='%s を読み取れません。'
# 1 argument: path
MSG_rs_ext_client_conflict='%s に内容の異なるファイルがあります。先に移動するか、
同じファイルを指定してください。'
# 2 arguments: client major, release
MSG_rs_ext_no_image='このホストに PostgreSQL %s クライアントイメージ（%s 同梱）が
ありません。復元に必要です。先にこのリリースのオフラインイメージ
バンドルを読み込んでください。'
# 0 arguments
MSG_rs_ext_ask_cert='クライアント証明書ファイルのパス > '
# 0 arguments
MSG_rs_ext_ask_key='クライアント秘密鍵ファイルのパス > '
# 2 arguments: count, roles
MSG_rs_ext_roles_missing='対象のデータベースサーバーに、バックアップで権限を付与している
%s 個のロールがありません：%s。
先にロールを作成するか、--accept-grant-loss を付けてその権限付与を省いて
ください。'
# 1 argument: the role
MSG_rs_ext_roles_missing_one='対象のデータベースサーバーに、バックアップで権限を付与している
1 個のロールがありません：%s。
先にこのロールを作成するか、--accept-grant-loss を付けてその権限付与を
省いてください。'
# 0 arguments
MSG_rs_ext_step_stop='サービスを停止（外部データベースには影響しません）'
# 0 arguments
MSG_rs_ext_step_quiet='他の接続がないことを確認'
# 4 arguments: count, database, sources, applications
MSG_rs_ext_still='：停止後も %s 件の別の接続が
%s を使用しています（接続元 %s、アプリケーション %s）。'
# 3 arguments: database, source, application
MSG_rs_ext_still_one='：停止後も 1 件の別の接続が
%s を使用しています（接続元 %s、アプリケーション %s）。'
# 1 argument: step
MSG_rs_ext_stopped_at='復元はステップ %s で止まりました。まだ何も上書きしていません。
サービスは停止したままです。'
# 0 arguments
MSG_rs_ext_end_conn='その接続を見つけて終了し（待機系ホストの引き継ぎでないことを
確認）、再開してください：'

# Imported data checks and recovery instructions.
# 1 arguments
MSG_rs_db_check_migrations='データベースを確認：取り込み後の migration がバックアップと
       異なります（%s）'
# 2 arguments
MSG_rs_db_extra='追加 %s 件：%s'
# 2 arguments
MSG_rs_db_missing='不足 %s 件：%s'
# 3 arguments
MSG_rs_db_check_counts='データベースを確認：%s の行数が異なります
       （取り込み後 %s、バックアップ %s）'
# 2 arguments
MSG_rs_db_check_kek='データベースを確認：active マスター鍵 ID が異なります
       （取り込み後 %s、バックアップ %s）'
# 0 arguments
MSG_rs_db_check_read='データベースを確認：取り込み後のデータを読み取れません'
# 1 arguments
MSG_rs_failure_stopped='復元はステップ %s で停止しました。サービスは停止したままで、
自動的に元に戻してはいません。'
# 1 arguments
MSG_rs_failure_running='復元はステップ %s で停止しました。サービスの一部または全部が
起動している可能性があり、復元は未確認です。'
# 1 arguments
MSG_rs_failure_unknown='復元はステップ %s で停止しました。サービス状態を読み取れません。'
# 0 arguments
MSG_rs_failure_no_safety='このホストには元のデータがなかったため、安全バックアップはありません。'
# 0 arguments
MSG_rs_failure_uncovered='データはまだ上書きしていません。'
# 3 arguments
MSG_rs_failure_kept='復元前のデータは名前を変更して %s
ほか %s か所に保持しています。安全バックアップ
%s は復元可能と確認済みです。'
# 1 arguments
MSG_rs_failure_resume='原因を解決したら、ステップ %s から再開してください：'
# 0 arguments
MSG_rs_failure_revert='または安全バックアップを使って元に戻します：'
# 0 arguments
MSG_rs_failure_abandon='または今回の復元を中止して未インストールに戻します
（配置したデータは名前を変更して保持し、削除しません）：'
# 3 arguments
MSG_rs_failure_own='または登録した手順で元に戻します：%s（バックアップ %s、%s）'
# 1 arguments
MSG_rs_failure_plaintext='作業フォルダー %s にはデータベースと
設定の平文があります。復元の完了または元に戻した後で消去します。'
# 1 arguments
MSG_rs_failure_log='ログファイル %s'

# Startup and runtime master-key checks.
# 1 arguments
MSG_rs_unseal_wait='データを取り込み、サービスを起動しました。封印解除後の
マスター鍵確認を待っています（%s）'
# 0 arguments
MSG_rs_unseal_ui='復元はまだ完了していません。マスター鍵はブラウザーで入力します。
封印解除ページでバックアップ内の管理者アカウントで認証し、
マスター鍵を入力してください：'
# 0 arguments
MSG_rs_unseal_kms='復元はまだ完了していません。マスター鍵は鍵管理サービスにあります。
封印解除ページでバックアップ内の管理者として認証し、
表示されたサービス（設定はデータベースと共に復元済み）を確認して
認証情報を再入力してください。このホストのアドレスを
鍵管理サービスの許可元に含めてください：'
# 1 arguments
MSG_rs_unseal_fingerprint='マスター鍵の指紋は %s である必要があります。'
# 0 arguments
MSG_rs_unseal_finish='封印解除後、次のコマンドで確認を完了してください。
確認が済むまでアップグレードとバックアップはできません：'
# 0 arguments
MSG_rs_unseal_still='システムはまだ封印中のため、復元を完了できません。
何も変更していません。'
# 1 arguments
MSG_rs_unseal_again='%s で封印を解除してから再実行してください：'
# 0 arguments
MSG_rs_unseal_unreadable='封印状態または実行時のマスター鍵 ID を読み取れません。
復元は未確認です。状態を確認してから再開してください：'
# 2 arguments
MSG_rs_runtime_mismatch='マスター鍵が一致しません。封印解除後の識別は %s、
バックアップの記録は %s です。'
# 0 arguments
MSG_rs_runtime_stopped='サービスを停止しました。復元は完了していません。'
# 0 arguments
MSG_rs_runtime_guide='「バックアップとリストア」の第 6 節、項目 6 に従って
鍵台帳を確認してから判断してください。'
# 0 arguments
MSG_rs_runtime_resume='再開：サービスを再起動し、正しいマスター鍵で封印を解除した後、
再度確認します'
# 0 arguments
MSG_rs_runtime_resume_env='再開：まず設定ファイルのマスター鍵を再確認します。
一致しなければサービスを起動しません'
# 1 arguments
MSG_rs_ready_timeout='サービスを起動して準備完了を待機：%s 秒以内に完了しませんでした'
# 0 arguments
MSG_rs_ready_body='復元は完了していません。サービスは起動しましたが、バックエンドが
準備完了を返していないため、まだ接続できない可能性があります。'
# 0 arguments
MSG_rs_ready_status='状態を確認：'
# 0 arguments
MSG_rs_ready_resume='対処後に再開してください（サービスの稼働を確認してから
準備完了を待ちます）：'
# 1 argument
MSG_rs_runtime_match='マスター鍵：封印解除後に読み取った ID %s は
バックアップと一致しました'
# 1 argument
MSG_rs_restore_done='復元が完了しました（%s）'
# 1 argument
MSG_rs_resume_original='元のバックアップ %s が必要です。
復元開始時と同じチェックサムである必要があります。'
# 1 argument
MSG_rs_resume_changed='復元の作業ファイルが変更されています：%s。再開を停止しました。'
# 1 arguments
MSG_rs_interrupted_stopped='復元は手順 %s で中断されました。起動したツールを停止しました。
サービスは停止したままで、自動的に元に戻してはいません。'
# 1 arguments
MSG_rs_interrupted_running='復元は手順 %s で中断されました。起動したツールを停止しました。
サービスの一部または全部が稼働中の可能性があり、復元は未確認です。'
# 1 arguments
MSG_rs_interrupted_unknown='復元は手順 %s で中断されました。起動したツールを停止しました。
サービスの状態を読み取れません。'
# 0 arguments
MSG_rs_revert_start_failed='元のサービスが準備完了を返していません。元に戻す処理は未完了です。
原因に対処してから --revert を再実行してください：'
# 1 arguments
MSG_rs_revert_done='安全バックアップに戻りました（%s）'
# 1 argument
MSG_rs_revert_original_done='元のサービスを再開しました（%s）。'

# Restore recovery and exit confirmation.
# 0 arguments
MSG_rs_exit_yes='端末がない場合は --yes を付けて操作を確認してください。'
# 1 arguments
MSG_rs_exit_confirm_original='まだデータは上書きされていません。今回の復元の記録を片付け、
%s で元のサービスを起動します。続けますか？[y/N] '
# 0 arguments
MSG_rs_exit_cancelled='操作を取り消しました。'
# 0 arguments
MSG_rs_revert_title='安全バックアップで元に戻す（まだ何も変更していません）'
# 3 arguments
MSG_rs_revert_details='安全バックアップ  %s
                  %s、復元前に復元可能と確認済み
戻す先            %s、今回の復元を始める前の状態'
# 2 arguments
MSG_rs_revert_partial='未完了のデータ    今回配置したデータは名前を変えて残します。
                  削除しません：
                  %s
                  ほか %s か所'
# 1 arguments
MSG_rs_revert_downtime='停止時間          約 %s 分'
# 1 arguments
MSG_rs_revert_confirm_version='確認のため、バージョン %s を入力してください：'
# 1 arguments
MSG_rs_exit_wrong='この復元の種類では --%s は使えません。'
# 0 arguments
MSG_rs_no_pending='未完了の復元はありません。'
# 1 arguments
MSG_rs_revert_finished='前回の復元は完了しています（%s）。--revert は
未完了の復元だけを扱います。'
# 0 arguments
MSG_rs_revert_fresh='復元前のデータに戻すには、そのときの安全バックアップで復元します。
これは新しい復元で、まず現在のデータの安全バックアップを作成します：'

# Restore completion.
# 1 arguments
MSG_rs_finish_title='復元が完了し、サービスが復旧しました（%s）'
# 2 arguments
MSG_rs_finish_from='復元元        %s（%s）'
# 1 arguments
MSG_rs_finish_address='アドレス      %s'
# 1 arguments
MSG_rs_finish_key_env='マスターキー  設定ファイル内。封印解除後に読んだ識別子
              %s はバックアップと一致'
# 1 arguments
MSG_rs_finish_key_ui='マスターキー  ブラウザーで入力。封印解除後に読んだ識別子
              %s はバックアップと一致'
# 1 arguments
MSG_rs_finish_key_kms='マスターキー  キー管理サービスで保管。封印解除後に読んだ識別子
              %s はバックアップと一致'
# 3 arguments
MSG_rs_finish_kept='保持          復元前のデータは名前を変えて残しています：
              %s
              ほか %s か所。安全バックアップ：
              %s。
              第 6 節の確認後、不要な保持フォルダーは手動で削除できます。'
# 3 arguments
MSG_rs_finish_kept_own='保持          %s、ほか %s か所。
              自分で用意したバックアップ：%s。'
# 1 arguments
MSG_rs_finish_oidc='公開 URL が %s に変わりました。外部ログイン
（OIDC）を使う場合は、ID プロバイダーでコールバック URL を
更新してください。'
# 0 arguments
MSG_rs_finish_checklist='「バックアップとリストア」第 6 節を項目ごとに確認してから、
利用者にシステムを引き渡してください。'
# 1 arguments
MSG_rs_upgrade_existing='このホストには %s があり、アップグレードできます：'
# 1 arguments
MSG_rs_upgrade_before='アップグレード前のバージョン（%s）に戻りました。
後でアップグレードするには：'
# 0 arguments
MSG_rs_upgrade_later='後で最新版を調べてアップグレードするには：'
# 0 arguments
MSG_rs_upgrade_lookup='最新版を調べています：'
# 0 arguments
MSG_rs_upgrade_unknown='最新バージョンを確認できませんでした。'
# 0 arguments
MSG_rs_upgrade_lookup_later='後で最新版を調べるには：'
# 1 arguments
MSG_rs_upgrade_ask='今すぐ %s にアップグレードしますか？サービスを停止して
バックアップを取ってから、バージョンを切り替えます。[y/N] '
# 0 arguments
MSG_rs_upgrade_declined='後でアップグレードするには：'
# 1 arguments
MSG_rs_upgrade_current='%s は最新バージョンです'

# Giving up an unfinished new-host restore.
# 0 arguments
MSG_rs_abandon_title='今回の復元を断念する（このホストを未インストールに戻します）'
# 1 arguments
MSG_rs_abandon_services='サービス          今回起動したサービスを先に停止します
                  （現在 %s 個が稼働中）。停止を確認してから進みます'
# 0 arguments
MSG_rs_abandon_stopped='サービス          稼働中のサービスはありません'
# 0 arguments
MSG_rs_abandon_kept='名前を変えて保持  今回配置したデータは名前を変えて残します。
                  削除しません：'
# 1 arguments
MSG_rs_abandon_path='                  %s'
# 0 arguments
MSG_rs_abandon_old_env='                  以前のインストール失敗時の .env を元の場所に戻します'
# 1 arguments
MSG_rs_abandon_old_template='                  %s：元のファイルを元の場所に戻します'
# 3 arguments
MSG_rs_abandon_tail='変更しないもの    録画フォルダー %s：今回復元した
                  ファイルと事前にコピーしたファイルがある場合が
                  あります。いずれも削除しません
バージョン        current は %s に戻し、releases/%s は残します
作業ファイル      作業フォルダー内の平文のデータベースと設定を削除します'
# 0 arguments
MSG_rs_exit_confirm_abandon='断念しますか？[y/N] '
# 0 arguments
MSG_rs_abandon_done='復元を断念し、このホストは未インストールに戻りました。
名前を変えたフォルダーは、不要と確認してから手動で削除してください。'
# 0 arguments
MSG_rs_abandon_stop_failed='全サービスの停止を確認できず、名前は変更していません。
原因を解消して --abandon をもう一度実行してください：'

# 1 argument
MSG_rs_failure_new_stopped='復元はステップ %s で停止しました。サービスは起動していません。
自動で元には戻していません。'

# ---------- restore: the external database, roles the server lacks ----------
# 2 arguments: count, the role names (one per line, indented)
MSG_rs_ext_roles_ask='バックアップでは次の %s 個のロールに権限を付与していますが、対象の
データベースサーバーにこれらのロールがありません：
%s
省く場合、これらのロールへの権限付与だけが復元されず、ほかはすべて
復元されます。'
# 1 argument: the role name (indented)
MSG_rs_ext_roles_ask_one='バックアップでは次の 1 個のロールに権限を付与していますが、対象の
データベースサーバーにこのロールがありません：
%s
省く場合、このロールへの権限付与だけが復元されず、ほかはすべて
復元されます。'
# 0 arguments
MSG_rs_ext_roles_create='[1] 先にこれらのロールを作成する（既定。復元を終了し、何も変更
    しません）'
# 0 arguments
MSG_rs_ext_roles_create_one='[1] 先にこのロールを作成する（既定。復元を終了し、何も変更
    しません）'
# 0 arguments
MSG_rs_ext_roles_skip='[2] これらのロールへの権限付与を省いて続ける'
# 0 arguments
MSG_rs_ext_roles_skip_one='[2] このロールへの権限付与を省いて続ける'
# 0 arguments
MSG_rs_ext_grants_unsure='欠けているロールだけに関わるのか判別できない権限付与文があり、
スクリプトではそれらだけを省けません。
先にサーバーでこれらのロールを作成してから復元してください。'
# 1 argument: count
MSG_rs_ext_skipped_row='これら %s 個のロールへの権限付与は復元されません'
# 0 arguments
MSG_rs_ext_skipped_row_one='この 1 個のロールへの権限付与は復元されません'
# 0 arguments
MSG_rs_label_skipped='  省く権限付与   '

# Restore execution progress and database client diagnostics.
MSG_rs_space_join='%sと%s'
MSG_rs_space_short_row='%s（%s）：必要 %s GB、空き %s GB'
MSG_rs_progress_release_same='%s とイメージを配置'
MSG_rs_progress_release_new='%s をインストール：リリースとイメージを配置'
MSG_rs_progress_stop='サービスを停止（データベースは稼働を継続）'
MSG_rs_progress_safety='復元前のバックアップ %s'
MSG_rs_progress_own='自前のバックアップ %s（%s）'
MSG_rs_progress_verify='復元前のバックアップから復元できることを確認'
MSG_rs_progress_swap='データベースを停止し、現在のデータを改名して保持'
MSG_rs_progress_settings='設定ファイルを書き込み（バックアップを引き継ぎ、
ホスト値はこのホストに合わせる）'
MSG_rs_progress_import='データベースをインポート'
MSG_rs_progress_check='データベースを照合：%s 件の migration、行数、
マスター鍵 ID がバックアップと一致'
MSG_rs_progress_files_same='監査ファイル、証明書、設定ファイルを戻す'
MSG_rs_progress_files_new='監査ファイルと証明書を戻す'
MSG_rs_progress_files_new_reissue='監査ファイルと証明書を戻し、このホストのアドレス用に
サーバー証明書を再発行'
MSG_rs_progress_start_same='サービスを起動して準備完了を待機：
バックエンドの応答は %s'
MSG_rs_progress_start_new='サービスを起動し、実行中のイメージを確認'
MSG_rs_progress_ready='準備完了を待機：バックエンドの応答は %s'
MSG_rs_progress_key_wait='マスター鍵：封印解除後に照合'
MSG_rs_import_error='pg_restore がエラーを返しました（詳細はログに記録）。'
MSG_rs_import_error_detail='pg_restore がエラーを返しました（詳細はログに記録）：'

# ---------- restore: the external database, emptied and imported in one transaction ----------
# 0 arguments
MSG_rs_ext_step_import='データベースを空にしてインポート（1 つのトランザクション）'
# 1 argument: the log file
MSG_rs_ext_import_unreachable='外部データベースに接続できません。インポートはまだ始まっていません。
原因は %s に記録されています。'
# 1 argument: the log file
MSG_rs_ext_import_make='インポート用の SQL を作成または検証できませんでした。トランザクション
は開始しておらず、外部データベースは変更されていません。
原因は %s に記録されています。'
# 0 arguments
MSG_rs_ext_import_rolled_back='データベースのインポートに失敗しました。今回の消去とインポートは
まとめて取り消され、外部データベースは元のままです。'
# 0 arguments
MSG_rs_ext_import_unknown='インポートがコミットされたかどうか確認できません。続行すると、
まず外部データベースを確認してから、再インポートするか先へ進むかを
決めます。'
# 2 arguments: the digest before the import, the digest now
MSG_rs_ext_import_unknown_stop='外部データベースはインポート前の状態でも、インポート完了後の状態
でもないため、前回のインポートがコミットされたか判断できません。
再インポートはしません。
  インポート前：%s
  現在：        %s'

# ---------- restore: reading the backup, the data release's database tool image ----------
# 1 argument: the data release
MSG_rs_no_dbtool='このホストにはリリース %s のデータベースツールイメージがありません。
バックアップの読み取りに必要です。
このリリースのオフラインイメージを先に読み込んでください。'

# ---------- restore: a new host's external database, exported before it is emptied ----------
# 0 arguments
MSG_rs_ext_step_export='現在の外部データベースを安全バックアップとしてエクスポート'
# 1 argument: the log file
MSG_rs_ext_export_failed='外部データベースをエクスポートして全体を読み戻すことができませんでした。
外部データベースは変更していません。原因は %s に記録されています。'
# 1 argument: the export file
MSG_rs_ext_revert_confirm='%s から外部データベースを戻し、この復元を中止しますか？[y/N] '
# 1 argument: the export file
MSG_rs_ext_revert_failed='外部データベースをエクスポート時の内容に戻せませんでした。
%s は残してあります。同じコマンドをもう一度実行してください：'
# 0 arguments
MSG_rs_ext_revert_done='外部データベースは復元前にエクスポートした内容に戻りました。
この復元は中止しました。'

# ---------- restore: the external database in the preview, the steps, a failure and giving up ----------
# 0 arguments
MSG_rs_label_database='  データベース   '
# 2 arguments: the certificate setup, the master key mode
MSG_rs_deployment_external='外部データベース；%s；マスター鍵：
%s'
# 3 arguments: host:port, database, server version
MSG_rs_ext_preview_server='外部 %s／%s
（PostgreSQL %s）'
# 2 arguments: client major, the management script's release
MSG_rs_ext_preview_tool='インポートツール：PostgreSQL %s クライアント（%s に同梱、
確認済み）'
# 1 argument each: the sslmode in effect
MSG_rs_ext_conn_full_system='接続：%s、システムが信頼する認証局でサーバーを検証'
MSG_rs_ext_conn_full_file='接続：%s、バックアップの CA ファイルでサーバーを検証'
MSG_rs_ext_conn_ca_system='接続：%s、システムが信頼する認証局でサーバー証明書を検証、
ホスト名は確認しない'
MSG_rs_ext_conn_ca_file='接続：%s、バックアップの CA ファイルでサーバー証明書を検証、
ホスト名は確認しない'
MSG_rs_ext_conn_none_none='接続：%s、サーバー証明書は検証しない'
MSG_rs_ext_conn_none_file='接続：%s、サーバー証明書は検証しない'
# 1 argument: DB_USER
MSG_rs_ext_preview_rights='権限：%s がこのデータベースとその中のすべてを所有；
他の接続なし'
# 4 arguments: DB_USER, count, sources, applications
MSG_rs_ext_preview_rights_listed='権限：%s がこのデータベースとその中のすべてを所有；
現在 %s 個の他の接続（%s から、アプリケーション %s）、
サービス停止後にもう一度確認'
# 2 arguments: schema, count (en: count, schema)
MSG_rs_ext_objects='スキーマ %s の %s 個のオブジェクト'
# 1 argument: the objects of each schema
MSG_rs_ext_preview_emptied='消去：%sを、インポートと
同じトランザクションで消去。失敗時はすべて取り消され、
データベースは元のまま。他のデータベース、ロール、
テーブルスペースには触れない。'
# 0 arguments
MSG_rs_ext_preview_empty='対象データベースは空のため、消去は不要'
# 1 argument: the export file
MSG_rs_ext_preview_export='現在のデータベースをまず
%s
にエクスポートし、全体を読み戻して使えることを確認してから進む'
# 1 argument: GB
MSG_rs_ext_preview_space='インポートが終わるまで、データベースサーバー上に新旧のデータが
両方あり、約 %s GB の空きが必要です。スクリプトはサーバーの
ディスクを確認できないため、先に確認してください。'
# 0 arguments
MSG_rs_kept_external='現在の監査、証明書のフォルダーを
削除せず、名前を変えて保管します：'
# 0 arguments
MSG_rs_kept_external_no_tls='現在の監査ファイルのディレクトリを
削除せず、名前を変えて保管します：'
# 1 argument: database
MSG_rs_confirm_db='確認のため、消去するデータベース名 %s を入力してください：'
# 0 arguments
MSG_rs_ext_import_error='psql がエラーを報告しました（全文はログにあります）。'
# 0 arguments
MSG_rs_ext_import_error_detail='psql がエラーを報告しました（全文はログにあります）：'
# 0 arguments
MSG_rs_ext_failure_rolled_back='今回の消去とインポートはまとめて取り消され、外部データベースは
元のままです。'
# 1 argument: the export file
MSG_rs_ext_failure_rolled_back_export='今回の消去とインポートはまとめて取り消され、外部データベースは
元のままです。事前のエクスポートは %s にあります。'
# 1 argument: the export file
MSG_rs_ext_failure_unknown_export='インポートがコミットされたかどうか確認できません。続行すると、
まず外部データベースを確認してから、再インポートするか先へ進むかを
決めます。事前のエクスポートは %s にあります。'
# 1 argument: the export file
MSG_rs_ext_failure_committed_export='インポートはコミット済みで、外部データベースは今バックアップの内容です。
事前のエクスポートは %s にあります。'
# 1 argument: the export file
MSG_rs_ext_failure_unsent_export='外部データベースは変更されていません。
事前のエクスポートは %s にあります。'
# 0 arguments
MSG_rs_ext_failure_revert='または事前のエクスポートで外部データベースを戻し、今回の復元を
中止します：'
# 0 arguments
MSG_rs_ext_failure_abandon='または今回の復元を中止して未インストールに戻します
（配置したデータは名前を変更して保持し、削除しません。外部データベースに
今回インポートしたデータは消去しません）：'
# 0 arguments
MSG_menu_rs_revert_export='事前のエクスポートで外部データベースを戻し、今回の復元を中止する'
# 2 arguments: host:port, database
MSG_rs_ext_abandon_kept='外部データベース  %s／%s に今回インポートした
                  データは消去しません。必要なら
                  データベース管理者が消去してください。次回の復元では
                  空でない対象として先にエクスポートします'
# 2 arguments: host:port, database
MSG_rs_ext_abandon_maybe='外部データベース  %s／%s には今回インポートした
                  データがある可能性があります。消去はしません。必要なら
                  データベース管理者が消去してください'
# 1 argument: the export file
MSG_rs_ext_abandon_export='事前のエクスポート %s
                  は削除せず保持します。不要と確認できたら自分で削除して
                  ください'
# 0 arguments
MSG_rs_ext_abandon_refused='外部データベースの消去とインポートが始まっているため、そのまま
中止することはできません。事前のエクスポートで戻してください
（完了するとこのホストも未インストールに戻ります）：'
# 2 arguments: count, the list file
MSG_rs_ext_finish_skipped='権限付与      サーバーにないロールへの権限付与 %s 文は復元して
              いません。一覧は %s'
# 1 argument: the export file
MSG_rs_ext_finish_export='エクスポート  外部データベースの復元前の内容（平文）を残しています：
              %s
              第 6 節の確認後、自分で削除してください。'

# ---------- status: a failed upgrade that a restore which finished has settled ----------
# 1 argument: when the restore settled it
MSG_status_upgrade_settled='この失敗は %s の復元で対処済みです。
再度アップグレードできます'
