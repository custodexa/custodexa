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
MSG_compose_explicit_incomplete='内部エラー：プロジェクト名、プロジェクトフォルダー、compose ファイルの
いずれかが欠けた呼び出しを拒否しました。'
MSG_state_bad='状態ファイル %s の %s 行目が壊れています。何も変更していません。'
MSG_state_bad_prev='一つ前の版は %s にあります。内容を確認し、正しければ
次のコマンドで戻してください：'
MSG_usage_unknown_command='不明なサブコマンド「%s」です。custodexa.sh --help を参照してください。'
MSG_usage_unknown_option='不明なオプション「%s」です。custodexa.sh --help を参照してください。'
MSG_usage_missing_value='オプション %s には値が必要です。'
MSG_command_not_in_build='このバージョンのスクリプトには「%s」サブコマンドがありません。'
MSG_lock_busy='この配置では別の custodexa.sh が実行中です（PID %s）。
終了するまで待ってください。'
MSG_run_interrupted='前回の %s はステップ %s で中断されました。'
MSG_run_install_rerun='install は繰り返し実行しても安全です。最初のステップからやり直します。'
MSG_run_recover_first='先に前回の中断に対処してください。状態とログファイルを確認します：'
MSG_run_recover_install='先に前回の install を完了してください。再実行しても安全です：'
MSG_run_load_rerun='load はイメージの読み込みと照合だけを行うため、再実行しても
安全です。'
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
MSG_help_cmd_backup='  backup                 完全バックアップ（サービスを十数分停止する）'
MSG_help_cmd_load='  load <バンドル>        オフラインイメージバンドルを読み込む（起動しない）'
MSG_help_options='オプション'
MSG_help_opt_yes='  --yes                  確認を求めない（自動化用）'
MSG_help_opt_backup_ref='  --backup-ref <識別子>  （upgrade）自分でバックアップ済み。スナップショット
                         名を指定すると、スクリプトはバックアップしない'
MSG_help_opt_backup_time='  --backup-time <時刻>   （upgrade）--backup-ref と併用：スナップショットの
                         開始時刻。サービス停止より後であること'
MSG_help_opt_backup_restore='  --backup-restore <場所>（upgrade）--backup-ref と併用：復元手順の文書の場所'
MSG_help_opt_images='  --images <パス>        （install、upgrade）使うオフラインイメージバンドル'
MSG_help_opt_lang='  --lang <言語>          zh-TW、ja、en。下の「表示言語」を参照'
MSG_help_opt_no_color='  --no-color             色を使わない'
MSG_help_opt_version='  --version              スクリプトのバージョンを表示'
MSG_help_opt_help='  -h, --help             このヘルプ。custodexa.sh <サブコマンド> --help は
                         そのサブコマンドだけを表示'
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
MSG_img_bundle_sum_bad='チェックサムが SHA256SUMS と一致しません（ファイル破損の可能性）'
MSG_img_bundle_load_failed='docker load に失敗しました（全出力はログファイル）'
MSG_img_bundle_id_bad='読み込み後の %s のイメージ ID が確認済みのものと異なります'
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
一致しないため使いません'
MSG_img_build_note='ソースからのビルドには Go モジュール、npm、ベースイメージの
取得元への接続が必要です。初回は 5〜10 分ほどかかります'
MSG_img_build_source_bad='ソースからビルド：ソースのチェックサムがリリースマニフェストと
一致しないため、ビルドしません'
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
MSG_trust_mf_no_sig='横に SHA256SUMS.sigstore.json がありません'
MSG_load_mf_sig_bad='%s の SHA256SUMS の署名の検証に失敗しました。署名者は次である
必要があります：
%s
イメージは読み込んでいません。'
MSG_text_trust_explain='  チェックサムで転送中の破損がないことは確認できますが、
  Custodexa が発行したことは確認できません。発行元の確認が必要なら
  ここで N を選び、cosign と gh があり、インターネットに接続できる
  コンピューターで、下に示す完全なダイジェストを使って運用担当者に
  検証してもらってから、このコマンドを再実行してください：'
MSG_trust_recorded='  どの検証を行ったかはログファイルに記録されます。'
MSG_trust_continue='続行しますか？[y/N]'
MSG_trust_sig_bad='イメージ署名の検証に失敗しました。署名者は次のはずです：
%s
停止しました。サービスは起動していません。'
MSG_trust_prov_bad='ビルド来歴の検証に失敗しました（%s のはず）。
停止しました。サービスは起動していません。'
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
MSG_load_title='オフラインイメージパッケージを読み込み'
MSG_load_file='  ファイル  %s（%s GB）'
MSG_load_sum_ok='チェックサムが SHA256SUMS と一致'
MSG_load_sum_none='%s に SHA256SUMS がなく、チェックサムを確認できません。
同じリリースの SHA256SUMS をパッケージの横に置いてください。
何も読み込んでいません。'
MSG_load_sum_unlisted='%s の SHA256SUMS にこのパッケージがありません。
何も読み込んでいません。'
MSG_load_sum_bad='チェックサムが SHA256SUMS と一致しません。ファイルが破損している
可能性があります。コピーし直してください。何も読み込んでいません。'
MSG_load_arch_ok='アーキテクチャ %s、このホストと同じ'
MSG_load_arch_bad='このパッケージは %s 用で、このホストは %s です。%s を使って
ください。何も読み込んでいません。'
MSG_load_check_bad='パッケージがリリースマニフェストと一致しません。何も読み込んで
いません：
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
MSG_status_sec_disk='ディスク'
MSG_status_sec_reminders='お知らせ'
MSG_status_label_current='現在'
MSG_status_label_previous='一つ前'
MSG_status_kind_installed='パッケージ配置、%s にインストール'
MSG_status_kind_upgraded='パッケージ配置、%s にアップグレード'
MSG_status_previous_kept='releases/ に保存'
MSG_status_legacy='git clone 配置、まだ変換していません'
MSG_status_legacy_next='次に custodexa.sh upgrade を実行すると、先にフォルダーを
新しい構成に整理します'
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
MSG_bk_pause='バックエンド、接続サービス、Web 画面を約 %s 分間停止します
（データベースは動作したまま）。バックアップが終わると自動で起動します。'
MSG_bk_warn_seal='マスターキーはブラウザーで入力する方式です。バックアップ後はシステムが
封印状態に戻り、封印解除ページでマスターキーを入力するまで使えません。'
MSG_bk_size='推定 %s、バックアップ先の空き %s'
MSG_bk_confirm='バックアップを開始しますか？[y/N]'
MSG_bk_step_stop='サービスを停止（データベースは動作したまま）'
MSG_bk_step_db='データベース'
MSG_bk_step_files='録画と監査ファイル'
MSG_bk_step_conf='設定ファイルと証明書'
MSG_bk_step_start='サービスを起動'
MSG_bk_step_verify='バックアップを読み取れるか確認'
MSG_bk_done='バックアップ完了：%s（%s）'
MSG_bk_contents='内容：%s'
MSG_bk_item_sep='、'
MSG_bk_item_db='データベース'
MSG_bk_item_rec='録画'
MSG_bk_item_audit='監査ファイル'
MSG_bk_item_env='設定ファイル .env'
MSG_bk_item_env_kek='設定ファイル .env（マスターキーを含む）'
MSG_bk_item_tls='証明書 tls/'
MSG_bk_warn_keep='このバックアップは機密データを含み、いまは .env と同じホストにあります。
暗号化して別の場所に保管し、マスターキーの材料とは分けてください。'
MSG_bk_warn_sealed='システムは封印されています。
%s で封印を解除してください。'
MSG_bk_log='ログファイル %s'
MSG_bk_warn_snapshot='鍵の指紋 4 つのうち取得できないものがありました。
このバックアップでは鍵を自動照合できません。
アップグレード後は鍵一覧ページで照合してください。
理由は snapshot.txt に記録しています。'
MSG_bk_external_db='この配置は外部データベースを使っているため、このスクリプトは
データベースをバックアップしません。各自の手順でバックアップし、
データフォルダー、.env、tls/ も一緒に保管してください。'
MSG_bk_db_unreachable='データベースのサイズを取得できず、必要な容量を見積もれません。
データベースのコンテナーが動作しているか確認してください。
サービスは停止していません。'
MSG_bk_no_space='バックアップ先の空き容量が足りません：約 %s 必要ですが、
%s の空きは %s です。サービスは停止していません。'
MSG_bk_dir_failed='%s にバックアップフォルダーを作成できません。
サービスは停止していません。'
MSG_bk_failed='バックアップは完了していません。途中までのファイルは %s にあり、
そこにある INCOMPLETE が使えないバックアップであることを示します。'
MSG_bk_start_again='サービスが停止したままの可能性があります。サービスを起動するには：'

# ---- own backup (used by upgrade and rollback) ----
MSG_br_title='アップグレード前のバックアップ'
MSG_br_opt1='[1] スクリプトで完全バックアップを取る（推奨）'
MSG_br_opt1_detail='データベース、録画、監査ファイル、設定ファイル、証明書。
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
MSG_up_row_installed_legacy='  現在のバージョン   %s（git clone 配置、%s）'
MSG_up_row_target_legacy='  アップグレード先   %s'
MSG_up_legacy_intro='  このホストはまだ git clone 配置です。管理スクリプトでの初めての
  アップグレードなので、先に配置ディレクトリを新しい構成に整理し、
  それからアップグレードを完了します。'
MSG_up_confirm='アップグレードを開始しますか？[y/N]'
MSG_up_confirm_convert='開始しますか？[y/N]'
MSG_up_yes_needs_target='このホストは git clone 配置で、初回のアップグレードで配置ディレクトリを
整理します。--yes を付けるときは、アップグレード先のバージョンまたは
パッケージのパスを指定してください。例：'
MSG_up_not_target='「%s」はバージョンでもパッケージファイル（custodexa-<バージョン>.tar.gz）
でもありません'
MSG_up_incoming_failed='一時ディレクトリ %s を作成できません'
MSG_up_download_failed='GitHub から %s のパッケージをダウンロードできません。オフラインで
アップグレードするには、ダウンロード済みのパッケージを指定してください：'
MSG_up_pkg_no_sums='%s が見つかりません。
パッケージは SHA256SUMS と同じフォルダに置いてください'
MSG_up_pkg_sum_bad='%s のチェックサムが SHA256SUMS と一致しません。このパッケージは使いません'
MSG_up_pkg_sig_bad='%s：SHA256SUMS の発行者署名を検証できません。このパッケージは使いません'
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
MSG_q_verify_fail_2='リリースマニフェスト（MANIFEST）のチェックサムが SHA256SUMS と一致
しません。アップグレードできるか判断できません。後で再試行するか、
ダウンロード済みのパッケージを使ってください'
MSG_q_verify_fail_3='リリースマニフェストの発行者署名を検証できません。アップグレードできるか
判断できません。後で再試行するか、ダウンロード済みのパッケージを
使ってください'
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
MSG_up_will_2_external='  2. データベースはこのデプロイの外にあるため、スクリプトは
     バックアップしません。停止後、停止より後に取った自前の
     バックアップを確認していただきます'
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
MSG_up_dev_form='このデプロイは開発版の compose ファイル（COMPOSE_FILE=%s）を
使っています。デプロイ形態ではないため、管理スクリプトでは
アップグレードしません'
# ---------- upgrade: waiting for the audit queue ----------
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
まず sudo %s status でバックエンドの状態を
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
MSG_up_bk_db='データベース   %s  %s'
MSG_up_bk_files='録画と監査ファイル  %s  %s'
MSG_up_unseal_after='マスターキーはブラウザで入力する方式のため、サービス再開後に
もう一度封印解除が必要です。'
MSG_up_step_convert_skip='ディレクトリの整理（不要）'
MSG_up_step_switch='%s に切り替え'
MSG_up_step_start='起動'
MSG_up_step_ready='準備完了を待つ'
MSG_up_step_check='確認'
MSG_up_step_record='記録'
MSG_up_failed_at='前回のアップグレードはステップ %s で停止しました。'
MSG_up_legacy_compose_unknown='%s の compose プロジェクト名または compose ファイルを確認できません'
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
MSG_menu_backup='バックアップ（サービスを十数分停止する）'
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

# upgrade: git clone デプロイの初回変換（プレビュー、ステップ 8、失敗時と次回実行時）
MSG_cv_will='実行する内容（順番に）'
MSG_cv_will_1='  1. 監査記録がすべてデータベースに書き込まれるのを待つ'
MSG_cv_will_2='  2. 既存の %s でサービスを停止
     （データベースは動かしたまま）'
MSG_cv_will_3='  3. 完全バックアップ（約 %s。バックアップ先の空きは %s）'
MSG_cv_will_3_external='  3. データベースはこのデプロイに含まれないため、ご自身でバックアップ
     （サービス停止後に確認します）'
MSG_cv_will_4='  4. 古いコンテナを削除し（data/ のデータには影響なし）、
     ディレクトリを整理'
MSG_cv_will_5='  5. %s に切り替えて起動し、バージョン・データ・鍵を確認'
MSG_cv_dir='ディレクトリの整理'
MSG_cv_stays='  そのまま     .env、tls/、data/'
MSG_cv_moves='  移動先       releases/%s/（旧バージョンとして保持）
               git 管理下の製品ファイルと .git'
MSG_cv_copies='  コピー       旧コンテナ内のレポートのエクスポート → data/exports/'
MSG_cv_env_label='  設定の書換   '
MSG_cv_env_indent='               '
MSG_cv_env_row='.env %s 行目  %s=%s'
MSG_cv_env_row_raw='.env %s 行目  %s'
MSG_cv_env_to='                          →  %s=%s'
MSG_cv_env_to_comment='                          →  コメントアウト（新バージョンは同梱の
                             テンプレートを使用）'
MSG_cv_env_sep='、'
MSG_cv_env_add_1='%s の 1 行を追加'
MSG_cv_env_add_2='%s の 2 行を追加'
MSG_cv_env_add_n='%s 行を追加：%s'
MSG_cv_env_saved='書き換える前に .env の写しを保存'
MSG_cv_compose_dropped='.env の COMPOSE_FILE が %s を使っていますが、
新バージョンには引き継がれません'
MSG_cv_know_pause='  - 停止時間はおよそ %s〜%s 分'
MSG_cv_know_mig='  - 今回はデータベース構造の変更があります。%s に戻すには今回の
    バックアップのリストアが必要で、バックアップ以降の記録は失われます'
MSG_cv_know_manage='  - 完了後は %s/custodexa.sh で管理してください。
    %s は git ディレクトリではなくなるため、
    git pull で更新しないでください'
MSG_cv_step='ディレクトリの整理'
MSG_cv_fail='アップグレードは 8/13（ディレクトリの整理）で停止しました：%s'
MSG_cv_why_env_copy='.env を %s に保存できません'
MSG_cv_why_down='古いコンテナを削除できません'
MSG_cv_why_exports='レポートのエクスポートを旧バックエンドコンテナからコピーできません'
MSG_cv_why_move='%s の移動に失敗しました'
MSG_cv_why_env='.env を書き換えられません'
MSG_cv_why_copy='%s を releases/ に置けません'
MSG_cv_why_state='state.json を書き込めません'
MSG_cv_why_signal='実行が中断されました'
MSG_cv_stopped='サービスは停止しています'
MSG_cv_dir_same='ディレクトリはまだ変更していません'
MSG_cv_dir_part='ディレクトリは途中まで整理されています'
MSG_cv_start_old='旧バージョンを起動：'
MSG_cv_revert_title='次のコマンドを順に実行し、元の git clone の構成に戻してください。
どれかが失敗したらそこで止め、ログファイルを運用担当者に渡してください：'
MSG_cv_revert_check='git の表示が backups/ と .custodexa.lock だけであることを確認：'
MSG_cv_start_old_after='上の確認でほかに何も表示されなかった場合のみ、旧バージョンを起動：'
MSG_cv_unseal='マスターキーはブラウザで入力する方式のため、起動後に
もう一度封印解除が必要です。'
MSG_cv_hint='ディレクトリの整理が途中で、サービスは停止しています。'
MSG_cv_interrupted='前回のアップグレードはディレクトリの整理中に中断されました。'
MSG_cv_no_git='git コマンドがないため、%s の製品ファイルが変更されたか確認できません'
MSG_cv_git_failed='%s で git status を実行できません'
MSG_cv_dirty='%s の git 作業ツリーに変更があるため、ディレクトリを整理できません。
下の項目を元に戻すか移動するかコミットし、git status が何も表示しなく
なってから再実行してください：'
MSG_up_restore_guide='%s に戻す場合は、上のバックアップを「バックアップとリストア」
第 5 節「リストアの手順」に沿って手動でリストアしてください。'
