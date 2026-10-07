# shellcheck shell=bash disable=SC2034
# custodexa.sh messages, English. Every key here exists in zh-TW.sh and ja.sh (checked by tests).
# Each value is a printf format; a line break inside the quotes is a line break on screen.
# Lines stay within 73 columns (80 for help_*), so a status mark in front still fits 80.
MSG_platform_not_linux='custodexa.sh runs on Linux only (this host reports %s).
To evaluate Custodexa on this computer, use scripts/quickstart.sh
from the source tree instead.'
MSG_root_home_invalid='CUSTODEXA_HOME=%s is not a Custodexa deployment folder
(it has neither state.json nor releases/).'
MSG_root_not_found='Cannot tell which deployment folder this script belongs to (%s).
Run it from the deployment folder, or set CUSTODEXA_HOME.'
MSG_root_path_chars='The deployment folder %s contains characters that are not allowed.
Use only letters, digits, and . _ / - (no spaces or quotes).
Nothing was changed.'
MSG_images_env_bad_line='%s line %s is not CUSTODEXA_IMAGE_<NAME>=<image reference>.
Nothing was started.'
MSG_overlay_unknown='Unknown deployment form "%s" in state.json.'
MSG_state_bad='The state file %s is damaged at line %s. Nothing was changed.'
MSG_state_bad_prev='The previous copy is %s. Check it, and if it is correct,
restore it with:'
MSG_usage_unknown_command='Unknown command "%s". See: custodexa.sh --help'
MSG_usage_unknown_option='Unknown option "%s". See: custodexa.sh --help'
MSG_usage_missing_value='Option %s needs a value.'
MSG_usage_images_from_value='Unknown image source "%s"; choose auto or source.'
MSG_usage_images_from_command='--images-from is only for install or upgrade with a target.'
MSG_usage_images_from_conflict='--images-from source cannot be combined with --images.'
MSG_usage_backup_only='Option %s is only for backup. See: custodexa.sh --help'
MSG_legacy_refused='This is an older git clone deployment. custodexa.sh cannot install
or upgrade here. Deployment files and services are unchanged.

Check backups and deployment settings first. Follow the manual migration
section in the Upgrade SOP, or install the package in a separate clean
directory and restore by hand using Backup and Restore. Do not install
against the existing data directory.'
MSG_command_not_in_build='The command "%s" is not part of this build.'
MSG_lock_busy='Another custodexa.sh is running on this deployment (PID %s).
Wait for it to finish.'
MSG_run_interrupted='The last %s run was interrupted at step %s.'
MSG_run_install_rerun='install is safe to repeat; starting over from the first step.'
MSG_run_recover_first='Handle that first. Check the state and the log file:'
MSG_run_recover_install='Finish that first; install is safe to run again:'
MSG_run_load_rerun='load only loads and checks images, so it is safe to run again.'
MSG_run_backup_unfinished='The last backup (%s) did not finish; the temporary
folder %s can be deleted.'
MSG_run_backup_unfinished_nodir='The last backup (%s) did not finish.'
MSG_run_backup_upgrade='The last backup (%s) did not finish, and an upgrade
needs a finished one first. If the services are still stopped, start
them; then back up again, and upgrade once that backup is done:'
MSG_run_signal='Interrupted at step %s. Nothing was undone. To continue:'
MSG_confirm_needs_yes='This step needs a confirmation, and there is no terminal to ask on.
Run again with --yes.'
MSG_log_initial_password='generated (value not recorded)'

# ---- --help. The per-command help reuses these blocks. ----
MSG_help_title='Custodexa management script %s'
MSG_help_usage='Usage: custodexa.sh <command> [options]'
MSG_help_commands='Commands'
MSG_help_cmd_install='  install                First install: check the host, create settings,
                         get the images, start'
MSG_help_cmd_upgrade='  upgrade                Check for a newer version (changes nothing)
  upgrade <version>      Download and upgrade to that version (stops the
                         service and backs up first)
  upgrade <package>      Upgrade from a package you downloaded (works
                         offline)'
MSG_help_cmd_status='  status                 Show version, services, backups and the last
                         upgrade (changes nothing)'
MSG_help_cmd_backup='  backup                 Back up to a single file (pauses the service;
                         the file can be moved to another host)'
MSG_help_cmd_load='  load <bundle>          Load an offline image bundle (starts nothing)'
MSG_help_options='Options'
MSG_help_opt_yes='  --yes                  Do not ask for confirmation (for automation)'
MSG_help_opt_with_recordings='  --with-recordings      (backup) Put the recordings in the backup file
                         (left out by default)'
MSG_help_opt_passphrase_file='  --passphrase-file <file>
                         (backup) Encrypt the backup file with the
                         passphrase on the first line of the file; the file
                         must be mode 0600 and owned by you or root. Do not
                         put the passphrase itself on the command line'
MSG_help_opt_backup_ref='  --backup-ref <id>      (upgrade) You made your own backup; give the
                         snapshot name and the script makes none'
MSG_help_opt_backup_time='  --backup-time <time>   (upgrade) With --backup-ref: when the snapshot
                         started; must be after the services stopped'
MSG_help_opt_backup_restore='  --backup-restore <doc> (upgrade) With --backup-ref: where the restore
                         procedure is documented'
MSG_help_opt_images='  --images <path>        (install, upgrade) Offline image bundle to use'
MSG_help_opt_images_from='  --images-from <mode>   (install, upgrade with target) auto or source;
                         auto is the default, source builds own images locally'
MSG_help_opt_lang='  --lang <language>      zh-TW, ja or en; see Language below'
MSG_help_opt_no_color='  --no-color             No colors'
MSG_help_opt_version='  --version              Show the script version'
MSG_help_opt_help='  -h, --help             This help; custodexa.sh <command> --help shows
                         one command'
# shellcheck disable=SC2016 # the commands as they are typed
MSG_help_passphrase_file_make='  To create a passphrase file (it does not end up in the shell history):
    sudo install -m 600 -o root /dev/null /root/cx-pass
    sudo bash -c '"'"'IFS= read -r -s p && printf "%%s\\n" "$p" > /root/cx-pass'"'"''
MSG_help_footer='The deployment folder is the folder this script is in; set the
environment variable CUSTODEXA_HOME to use another one. Each run is
logged under <deployment folder>/logs/. For the full procedures see the
Deployment and Upgrade SOP and Backup and Restore.'
MSG_help_language='Language
  Screens follow the system language (LC_ALL, LC_MESSAGES or LANG); sudo
  often resets it, and the screens are then in English. To choose one, add
  --lang, with or without a command:
    custodexa.sh --lang zh-TW          繁體中文 (Traditional Chinese)
    custodexa.sh --lang ja             日本語 (Japanese)
    custodexa.sh --lang en             English
  Or keep the system language under sudo:
    sudo env LANG=zh_TW.UTF-8 custodexa.sh'

# ---- release manifest, install title, durations ----
MSG_manifest_missing='The release manifest %s is missing. The package may be incomplete;
download it again.'
MSG_manifest_bad='The release manifest %s cannot be read (line %s). The package may be
damaged; download it again.'
MSG_install_title='Custodexa %s install    Deployment directory %s'
MSG_dur_s='%ss'
MSG_dur_ms='%sm %02ds'

# ---- step 1: check this host ----
MSG_step_preflight='Check this host'
MSG_pre_docker_ok='Docker %s, Compose %s'
MSG_pre_docker_down='Cannot reach Docker: %s'
MSG_pre_docker_perm='No permission to use Docker'
MSG_pre_compose_missing='Docker Compose v2 not found (%s or later needed)'
MSG_pre_compose_old='Docker %s, Compose %s is too old (%s or later needed)'
MSG_pre_arch_ok='Architecture %s'
MSG_pre_arch_bad='Architecture %s is not supported (x86_64 and aarch64 only)'
MSG_pre_openssl_missing='openssl not found (needed to create passwords and keys)'
MSG_pre_existing_state='Custodexa %s is already installed in this folder'
MSG_pre_existing_git='This folder is a git clone deployment'
MSG_pre_existing_container='A custodexa-backend container exists that this install did not create'
MSG_pre_ports_ok='Ports %s are free'
MSG_pre_port_busy='Port %s is already in use by %s'
MSG_pre_ports_unchecked='Neither ss nor lsof is installed; ports %s not checked'
MSG_pre_holder='%s (pid %s)'
MSG_pre_holder_unnamed='an unnamed process (run as root to see which)'
MSG_pre_holder_container='%s, publishing it for container %s'
MSG_pre_list_sep=', '
MSG_pre_disk='%s GB free (%s GB needed)'
MSG_pre_disk_root='Deployment folder: %s GB free (%s GB needed)'
MSG_pre_disk_unknown='Cannot read the free space of %s; not checked'
MSG_pre_not_writable='Cannot write to the deployment folder %s'
MSG_pre_nothing_changed='Nothing was changed.'
MSG_text_pre_port='Port %s is already in use by %s. Ask the host
administrator to resolve the port conflict, then run again:'
MSG_text_pre_port_change='To use different ports instead, first make sure
%s/.env exists and is set up, then set TLS_HTTPS_PORT
and TLS_HTTP_PORT to ports nothing else uses (8443 and 8088 are
common). The address people type will then include the port, for
example https://%s:8443'
MSG_text_pre_port_change_ingress='To use a different port instead, first make sure
%s/.env exists and is set up, then set HTTP_PORT to a port
nothing else uses.'
MSG_text_pre_docker_perm='Run it with sudo, or add this account to the docker group.'
MSG_text_pre_sudo='Run it with an account that can write the deployment folder, e.g.:'
MSG_text_pre_existing='This host already has a deployment; install does not overwrite it.
To see its state or upgrade it:'

# ---- settings file .env ----
MSG_env_compose_file_bad='COMPOSE_FILE=%s in .env is not a form of this package.
Set it to current/compose.yml (append the external ingress or database
file with : when used).'
MSG_env_project_bad='COMPOSE_PROJECT_NAME=%s in .env; this deployment always uses %s.
Change it back and run again.'
MSG_env_kek_bad='KEK_PROVIDER=%s in .env is not one of env, ui, kms, hsm. Fix it first.'
MSG_env_db_external='An external database is set (EXTERNAL_DB_HOST) but DB_PASSWORD is
empty or the template value. Put the password of that database account
into %s and run again (nothing was generated).'

# ---- step 3: program images ----
MSG_step_images='Get the program images'
MSG_img_order='Trying in order: this host, offline bundle, GHCR, Docker Hub,
build from source'
MSG_img_source_mode='Image source: package source build; obtain upstream images separately'
MSG_img_source_check='Checking the checksum of the package source…'
MSG_img_source_ok='Source checksum matches the release manifest'
MSG_img_wait_local='Checking this host for %s…'
MSG_img_wait_bundle_check='Checking offline bundle %s…'
MSG_img_wait_bundle_load='Loading offline bundle %s…'
MSG_img_wait_registry='Obtaining %s from %s…'
MSG_img_wait_digest='Checking the content digest of %s…'
MSG_img_wait_build='Building %s from source; the first build may take minutes…'
MSG_img_wait_fallback='GHCR failed (%s); trying Docker Hub'
MSG_img_head_own='%s %s'
MSG_img_head_upstream='%s %s (upstream %s)'
MSG_img_and=' and '
MSG_img_local_absent='This host: not present yet'
MSG_img_local_ok='This host: present, content digest matches'
MSG_img_local_mismatch='This host: %s has a different content digest; not used'
MSG_img_offline_none='Offline bundle: %s not found
(looked in %s)'
MSG_img_offline_absent='Offline bundle: this image is not in it'
MSG_img_offline_bad='Offline bundle %s not used:
%s'
MSG_img_offline_ok='Offline bundle %s
loaded; content digest matches the release manifest'
MSG_img_bundle_unreadable='index.json or manifest.json cannot be read from the bundle'
MSG_img_bundle_manifest_bad='the manifest of %s does not match its digest'
MSG_img_bundle_config_bad='the config digest of %s does not match the release manifest'
MSG_img_bundle_no_sums='no SHA256SUMS in %s to check the checksum against'
MSG_img_bundle_not_listed='SHA256SUMS does not list this bundle'
MSG_img_bundle_sum_bad='checksum does not match SHA256SUMS;
the file may be incomplete or damaged; download it again'
MSG_img_bundle_load_failed='docker load failed (full output in the log file)'
MSG_img_bundle_id_bad='after loading, the image ID of %s differs from the one checked;
the file may be incomplete or damaged; download it again'
MSG_img_try_failed='%s %s: %s'
MSG_img_switched=',
switched to %s and verified'
MSG_img_reason_timeout='connection timed out (30s)'
MSG_img_reason_notfound='this version is not there'
MSG_img_reason_other='failed (%s)'
MSG_img_pulled_own='%s %s
downloaded; content digest matches the release manifest'
MSG_img_pulled_up='%s %s
downloaded'
MSG_img_pulled_mismatch='%s %s downloaded, but its content digest differs;
the file may be incomplete or damaged; download it again. Not used'
MSG_img_build_note='Building from source needs access to Go modules, npm and the base
images; the first build takes about 5 to 10 minutes'
MSG_img_build_source_bad='Build from source: the source checksum does not match the release
manifest. Files may be incomplete or damaged; download them again.
Not building'
MSG_img_build_failed='Build from source failed (full output in the log file)'
MSG_img_build_ok='Built from source as %s
(a local build; it carries no publisher signature)'
MSG_img_none='%s: every source failed; the image could not be obtained'
MSG_img_running_bad='%s runs image %s, not the one just obtained (%s)'
MSG_step_images_done='Get the program images (%s; %s)'
MSG_ver_all='checksums, signatures and
build provenance verified'

# ---- publisher checks (the screen shown when some were skipped) ----
MSG_trust_title='Files were checked for damage, but the publisher was not verified'
MSG_trust_row_checksum='Checksums             package and images match the release list'
MSG_trust_label_sig='Publisher signature   '
MSG_trust_label_prov='Build provenance      '
MSG_trust_verified='verified'
MSG_trust_no_cosign='cosign is not installed on this host'
MSG_trust_no_gh='gh is not installed on this host'
MSG_trust_offline='offline, the signing service is unreachable'
MSG_trust_gh_login='gh is not signed in (gh auth login)'
MSG_trust_local_build='images built from source carry no publisher signature'
MSG_trust_mf_unverified='the release manifest next to the bundle is not verified (%s)'
MSG_trust_pkg_unverified='the package signature was not verified (%s)'
MSG_trust_mf_no_sig='no SHA256SUMS.sigstore.json next to it'
MSG_trust_mismatch='signature mismatch, publisher unverified'
MSG_trust_prov_mismatch='build provenance mismatch, publisher unverified'
MSG_ver_sig_mismatch='signature mismatch, publisher unverified'
MSG_ver_prov_mismatch='build provenance mismatch, publisher unverified'
MSG_text_trust_explain='  Checksums confirm the file contents match the release list. The
  publisher is unverified. Verify the full digests below independently
  if your organization requires publisher verification:'
MSG_trust_recorded='  Which checks ran is recorded in the log file.'
MSG_ver_sig_only='checksums and signatures verified;
build provenance not verified'
MSG_ver_checksum_only='content digests checked;
publisher not verified'
MSG_usage_extra_args='Unexpected argument "%s". See: custodexa.sh --help'

# ---- install: steps 2 and 4 to 7, and the closing block ----
MSG_step_env='Create the settings file .env'
MSG_env_item_jwt='sign-in signing key'
MSG_env_item_kek='master key'
MSG_env_item_db='database password'
MSG_env_item_admin='initial admin password'
MSG_env_item_sep=', '
MSG_env_item_last=' and '
MSG_env_generated='%s generated'
MSG_env_generated_none='Nothing generated; the values already in .env are kept'
MSG_env_kek_ui='Master key mode: entered in the browser (not written to the
server'"'"'s disk)'
MSG_env_kek_env='Master key mode: settings file (ENCRYPTION_KEY in .env)'
MSG_env_kek_kms='Master key mode: external key service (KMS)'
MSG_env_kek_hsm='Master key mode: hardware security module (HSM)'
MSG_env_url='Address: %s (edit PUBLIC_BASE_URL in .env to change)'
MSG_step_recordings='Prepare the recordings folder (1000:0, mode 2770)'
MSG_install_recordings_failed='Could not set the owner and mode of %s
(the docker output is in the log file)'
MSG_install_recordings_mode='%s is %s, not %s'
MSG_step_start='Start the services (running the images just
obtained)'
MSG_install_up_failed='Starting the services failed (full output in the log file)'
MSG_step_ready_wait='Wait until ready'
MSG_step_ready='Wait until ready (backend version %s)'
MSG_install_not_ready='The backend did not report ready within %s seconds'
MSG_install_not_ready_hint='The services are left running. The backend log says why; a refused
start names the setting and the reason:'
MSG_install_version_bad='The backend reports version %s, not %s'
MSG_step_done='Done'
MSG_install_stopped='Install stopped at step %s; what was done is kept. Fix the problem
above, then run it again (the steps already done are repeated safely):'
MSG_install_log='Log file: %s'
MSG_install_declined='Stopped as you chose; no service was started. Once the publisher is
verified, run again:'
MSG_done_title_setup='Installed. Finish the setup in your browser.'
MSG_done_title_login='Installed. Sign in with your browser.'
MSG_done_address='Address   %s'
MSG_done_account='Account   admin'
MSG_done_password='Password  %s'
MSG_done_password_where='(also stored as ADMIN_INITIAL_PASSWORD in %s)'
MSG_done_password_kept='Password  the ADMIN_INITIAL_PASSWORD value in %s'
MSG_done_ui_1='The first visit opens the master key setup page. The master
key is created in the browser; Custodexa does not save it to
the server'"'"'s disk. Keep a copy yourself, safely. After every
restart, someone has to enter it on the unseal page before
the system serves users.'
MSG_done_ui_2='Authorize the setup with the account above, then sign in.
The first sign-in asks for a new password; after that, delete
the ADMIN_INITIAL_PASSWORD line from .env.'
MSG_done_login='Sign in with the account above. The first sign-in asks for a new
password; after that, delete the ADMIN_INITIAL_PASSWORD line from .env.'
MSG_done_kms_1='The first visit opens the unseal page. Verify with the account
above, then provide the credentials of the key service; the
system serves users once it is unsealed.'
MSG_done_cert='This site uses a certificate it created itself. Download
%s
and install it on the computers that connect, so browsers
show the site as secure.'
MSG_done_status='Status     %s'
MSG_done_log='Log file   %s'

# ---- load ----
MSG_load_usage='Name the offline image bundle to load, for example:
custodexa.sh load custodexa-images-1.13.0-amd64.tar'
MSG_load_missing='%s does not exist.'
MSG_load_bad_name='%s is not named like an offline image bundle
(custodexa-images-<version>-<architecture>.tar).'
MSG_load_no_manifest='The release manifest of version %s was not found: not in this
deployment, and no MANIFEST.json listed in SHA256SUMS in %s.'
MSG_load_manifest_sum_bad='Release manifest checksum does not match SHA256SUMS.
The file may be incomplete or damaged; download it again.'
MSG_load_title='Load the offline image bundle'
MSG_load_file='  File   %s (%s)'
MSG_load_sum_ok='Checksum matches SHA256SUMS'
MSG_load_sum_none='No SHA256SUMS in %s to check the bundle against.
Copy it from the same release next to the bundle. Nothing was loaded.'
MSG_load_sum_unlisted='SHA256SUMS in %s does not list this bundle. Nothing was loaded.'
MSG_load_sum_bad='Checksum does not match SHA256SUMS; the file may be incomplete
or damaged; download it again. Nothing was loaded.'
MSG_load_arch_ok='Architecture %s, same as this host'
MSG_load_arch_bad='The bundle is for %s, this host is %s; use %s.
Nothing was loaded.'
MSG_load_check_bad='The bundle does not match the release manifest; the file may be
incomplete or damaged; download it again. Nothing was loaded:
%s'
MSG_load_empty='The bundle holds no image of version %s. Nothing was loaded.'
MSG_load_failed='docker load failed (full output in the log file).'
MSG_load_loaded='%s images loaded'
MSG_load_digests_ok='Every image digest matches the release manifest (MANIFEST)'
MSG_load_id_bad='After loading, %s does not have the image ID checked before
loading. Do not use it; load the bundle again from a fresh copy.'
MSG_load_trust_ok='Publisher signature and build provenance verified'
MSG_load_trust_skip='%s: %s'
MSG_trust_name_sig='Publisher signature'
MSG_trust_name_prov='Build provenance'
MSG_text_load_unverified='  The images are loaded but the publisher is not verified. If your
  organization requires that, have operations verify with the full
  digest on a computer with cosign, gh and internet access (the
  verification commands are shown when you run install or upgrade),
  then run the command below.'
MSG_load_next='The images are ready; no service was started. Next:'
MSG_load_next_upgrade='or, to upgrade:'
# status. Lines under a section are wrapped to 56 columns at run time; a line break here stays one.
MSG_status_title='Custodexa status    %s    %s'
MSG_status_sec_version='Version'
MSG_status_sec_services='Services'
MSG_status_sec_images='Images'
MSG_status_sec_backup='Backup'
MSG_status_sec_upgrade='Last upgrade'
MSG_status_pkg_sig_mismatch='Package signature mismatch, publisher unverified'
MSG_status_pkg_sig_unverified='Package signature was not checked, publisher unverified'
MSG_status_sec_disk='Disk'
MSG_status_sec_reminders='Reminders'
MSG_status_label_current='Installed'
MSG_status_label_previous='Previous'
MSG_status_kind_installed='package deployment, installed %s'
MSG_status_kind_upgraded='package deployment, upgraded %s'
MSG_status_previous_kept='kept in releases/'
MSG_status_not_installed='Not installed yet. To install:'
MSG_status_install_unfinished='The install did not finish (it stopped at step %s). To finish it:'
MSG_status_services_ok_oneshot='%s service processes started (tls-init runs once and has finished)'
MSG_status_services_ok='%s service processes started'
MSG_status_services_down='%s of %s services are not running: %s'
MSG_status_services_none='No container of this deployment was found'
MSG_status_services_hint='What the containers report:'
MSG_status_health_ok='Backend healthy, version %s'
MSG_status_health_version='The backend reports version %s; the version on record is %s'
MSG_status_health_bad='The backend does not answer on /health. Its log:'
MSG_status_sealed='The system is still sealed and not yet serving users.
Someone must enter the master key at %s'
MSG_status_seal_init='The master key is not set up yet, so the system is not
serving users. Set it up at %s'
MSG_status_unsealed='Unsealed and serving users'
MSG_status_seal_unknown='Could not read the seal status from the backend'
MSG_status_images='From %s; %s'
MSG_status_src_local='this host'
MSG_status_src_offline='the offline bundle'
MSG_status_src_build='a build from source'
MSG_status_backup='Latest %s (%s; %s)'
MSG_status_backup_upgrade='automatic, before the upgrade'
MSG_status_backup_script='custodexa.sh backup'
MSG_status_backup_external='your own backup'
MSG_status_backup_none='No backup on record'
MSG_status_backup_encrypted='%s (encrypted)'
MSG_status_days_0='today'
MSG_status_days_1='1 day ago'
MSG_status_days_n='%s days ago'
MSG_status_upgrade_ok='%s -> %s succeeded, %s'
MSG_status_upgrade_failed='%s -> %s failed at step %s, %s. Log:'
MSG_status_upgrade_unfinished='%s -> %s did not finish; it stopped at step %s. Log:'
MSG_status_disk='data/ %s, backups/ %s; %s free'
MSG_status_env_unreadable='.env cannot be read; run status with sudo to see the reminders'
MSG_status_remind_password='.env still holds the initial admin password
(ADMIN_INITIAL_PASSWORD). Once the admin has changed the
password, delete that line.'
MSG_status_remind_recordings='The recordings folder %s is %s;
it must be %s (owner 1000, group 0). To fix it:'
MSG_status_load_unfinished='The last load was interrupted at step %s. It changes
nothing but the images in Docker; run it again to finish:'

# ---- backup (used by upgrade and rollback) ----
MSG_bk_title='Backup preview (nothing has been changed yet)'
MSG_bk_confirm='Start the backup? [y/N]'
MSG_bk_step_stop='Stop the services (database keeps running)'
MSG_bk_step_db='Database'
MSG_bk_step_files='Recordings and audit files'
MSG_bk_step_conf='Settings and certificates'
MSG_bk_step_verify='Check the backup can be read'
MSG_bk_contents='Contains: %s'
MSG_bk_item_sep=', '
MSG_bk_item_db='database'
MSG_bk_item_rec='recordings'
MSG_bk_item_audit='audit files'
MSG_bk_item_env='settings file .env'
MSG_bk_item_env_kek='settings file .env (includes the master key)'
MSG_bk_item_tls='certificates tls/'
MSG_pb_item_tpl='proxy template %s'
MSG_bk_log='Log file %s'
MSG_bk_db_unreachable='Cannot read the database size to estimate the backup space.
Check that the database container is running. Nothing was stopped.'
MSG_bk_dir_failed='Cannot create a backup folder in %s. Nothing was stopped.'
MSG_bk_failed='The backup did not finish. The files so far are in %s;
the INCOMPLETE file there marks this backup as unusable.'
MSG_bk_start_again='The services may still be stopped. To start them again:'

# ---- portable backup (custodexa.sh backup) ----
MSG_pb_step_audit='Audit files'
MSG_pb_step_start='Start the services and wait until ready'
MSG_pb_step_verify='Check each part can be read'
MSG_pb_step_pack='Build the single file and read it back'
MSG_pb_done='Backup done (%s)'
MSG_pb_sidecar='Checksum file %s (same folder)'
MSG_pb_summary='Version %s; %s; master key: %s'
MSG_pb_db_bundled='bundled database'
MSG_pb_mode_env='in the settings file'
MSG_pb_mode_ui='entered in the browser'
MSG_pb_mode_kms='key custody service (%s)'
MSG_pb_mode_hsm='hardware security module (HSM)'
MSG_pb_kek_in='The master key is in the .env inside the backup file (fingerprint
%s) and comes back with a restore.'
MSG_pb_kek_out='The master key is not in the backup file (fingerprint %s).
After a restore, whoever holds the unseal material enters it on the
unseal page; the fingerprint has to match.'
MSG_pb_kek_kms='The master key is held by the key custody service (%s) and is not in
the backup file. Key ID:
%s
After a restore, provide the custody credentials on the unseal page
again; the key ID has to match, and a new host must reach the service.'
MSG_pb_kek_in_nofp='The master key is in the .env inside the backup file and comes back
with a restore.'
MSG_pb_kek_out_nofp='The master key is not in the backup file.
After a restore, whoever holds the unseal material enters it on the
unseal page; the fingerprint has to match.'
MSG_pb_kek_kms_nofp='The master key is held by the key custody service (%s) and is not in
the backup file.
After a restore, provide the custody credentials on the unseal page
again; the key ID has to match, and a new host must reach the service.'
MSG_pb_warn_kek_fp='The master key fingerprint could not be read, so a restore cannot
check the master key automatically; the reason is in snapshot.txt
inside the backup file.'
MSG_pb_warn_fps='Not all four key fingerprints could be read (the master key'"'"'s
was), so after a restore the other keys have to be compared by
hand on the key inventory page; the reason is in snapshot.txt
inside the backup file.'
MSG_pb_warn_rec='The recordings are not in the backup file. They are in
%s; keep them some other way, or
back up again and choose to include them.'
MSG_pb_warn_plain='This file is not encrypted and holds sensitive data (database
password, sign-in token secret, certificate private keys), and it
sits on the same host as .env. Store it elsewhere with limited
access; a backup can also be encrypted with a passphrase.'
MSG_pb_warn_plain_kek='This file is not encrypted and holds the master key and other
sensitive data (database password, sign-in token secret,
certificate private keys). Whoever has it can decrypt every stored
credential. Store it elsewhere with limited access; a backup can
also be encrypted with a passphrase.'
MSG_pb_svc_back='The services are back.'
MSG_pb_svc_ui='The services are started and waiting to be unsealed: enter the
master key at %s'
MSG_pb_svc_kms='The services are started and waiting to be unsealed: open
%s with the local administrator account,
check the key custody details and provide the credentials.'
MSG_pb_svc_timeout='The backend was not ready within %s seconds, so users may not be
able to connect yet. The backup goes on. Check the status, and
start again if needed:'
MSG_pb_failed='The backup did not finish and no backup file was made. What was
taken so far is in %s;
it cannot be restored from and holds sensitive plaintext. Delete it
once you know the cause.'
MSG_pb_valid='The backup file is valid:'
MSG_pb_after_both='But the work after it did not finish: state.json was not updated
(status still shows the previous backup), and the temporary folder
%s was not removed.
Check the disk space and permissions, then delete the temporary
folder by hand; the next backup updates state.json.'
MSG_pb_after_state='But the work after it did not finish: state.json was not updated
(status still shows the previous backup).
Check the disk space and permissions; the next backup updates
state.json.'
MSG_pb_after_partial='But the work after it did not finish: the temporary folder
%s was not removed.
Check the disk space and permissions, then delete the temporary
folder by hand.'
MSG_pb_sig_valid='The backup was interrupted while finishing, but the backup file is
complete and valid:'
MSG_pb_sig_both='state.json was not updated (status still shows the previous backup),
and the temporary folder %s
was not removed; delete it by hand.'
MSG_pb_sig_partial='The temporary folder %s
was not removed; delete it by hand.'
MSG_pb_sig_timeout='The backend was not ready within %s seconds, so users may not be
able to connect yet. Check the status, and start again if needed:'
MSG_pb_version_mismatch='state.json says %s is installed, but current/MANIFEST.json is
%s, so the version of this backup cannot be told. Nothing was
stopped. Check with:'
MSG_pb_tool_version='The release manifest of this script, %s, is for %s,
but the script is %s, so the tool that makes the backup cannot be
recorded. Nothing was stopped.'
MSG_pb_kek_material='KEK_PROVIDER in .env is %s, but ENCRYPTION_KEY has a value. That is a
contradictory setting the backend also refuses at its next start, and
the backup would carry it out as a master key, so nothing is done.
Nothing was stopped. Decide which mode you use and clear the other.'
MSG_pb_kek_none='.env sets neither KEK_PROVIDER nor ENCRYPTION_KEY, so the master key
mode cannot be told. The backend refuses this at its next start.
Nothing was stopped.'
MSG_pb_kek_env_empty='KEK_PROVIDER in .env is env, but ENCRYPTION_KEY is empty. The
backend refuses this at its next start. Nothing was stopped.'
MSG_pb_kek_unknown='KEK_PROVIDER in .env has a value that is not recognized (only env,
ui, kms and hsm, in lower case). Nothing was stopped.'
MSG_pb_tpl_missing='TLS_NGINX_TEMPLATE in .env names %s,
but that is not a file that can be read. The backup takes that file
with it, so nothing is done. Nothing was stopped. Correct the path, or
clear the line to use the shipped template, then run it again.'
MSG_pb_tpl_chars='TLS_NGINX_TEMPLATE in .env is %s,
and the path has a character the backup file cannot record (a double
quote, a backslash, a tab, or a letter outside ASCII). The backup
keeps that path so a restore can put the template back, so nothing
is done. Nothing was stopped. Put the template under a path without
such characters, or clear the line to use the shipped template, then
run it again.'
MSG_pb_ts_taken='%s already holds a backup file or a temporary folder for
this time (%s). Nothing was stopped. Run it again in a few seconds.'
MSG_pb_need='Needs %s (a file of about %s, room to build it and 1 GB
spare); %s free where backups go'
MSG_pb_no_space='Not enough space for the backup: %s needed (including room to
build the file and 1 GB spare), %s has %s
free. Nothing was stopped.'
MSG_pb_no_space_hint='You can move older backup files elsewhere and delete them here, or (if
you chose to include the recordings) run it again without them.'
MSG_pb_no_space_ls='The backup files now: %s'
MSG_pb_sig_failed='The backup was interrupted at step %s and no backup file was made.
The tool processes it started have been stopped. What was taken so
far is in %s; it cannot
be restored from and holds sensitive plaintext. Delete it.'
MSG_pb_sig_again='To back up again, run it again:'
MSG_pb_sizes='Database %s, audit files %s, recordings %s; %s free where backups go'
MSG_pb_rec_q='Put the recordings in the backup file?'
MSG_pb_rec_no='No (default): a file of about %s, services paused about %s'
MSG_pb_rec_yes='Yes: a file of about %s, services paused about %s'
MSG_pb_rec_short='Needs %s, more than is free; this choice will be refused'
MSG_pb_rec_keep='Without them, keep the recordings folder some other way.'
MSG_pb_choose='Choose [1-2], or press Enter for the default: '
MSG_pb_enc_q='Encrypt the backup file with a passphrase?'
MSG_pb_enc_why='Without encryption the file holds the database password, certificate
private keys and other sensitive data, readable by anyone who has it.'
MSG_pb_enc_why_env='Without encryption the file holds the database password, the master
key, certificate private keys and other sensitive data, readable by
anyone who has it.'
MSG_pb_enc_no='No (default): the file opens with tar as it is'
MSG_pb_enc_yes='Yes: a restore needs the same passphrase. If the passphrase is
lost the backup cannot be restored, by the script or by anyone.'
MSG_pb_pass_rules='Passphrase: 12 to 256 characters; letters, digits, spaces and symbols
from a US keyboard only. Spaces count as part of the passphrase.'
MSG_pb_pass_prompt='Passphrase        > '
MSG_pb_pass_again='Type it again     > '
MSG_pb_pass_match='Both entries match'
MSG_pb_tries_n='%s more tries'
MSG_pb_tries_1='1 more try'
MSG_pb_pass_differ='The two entries differ; type it again (%s).'
MSG_pb_pass_short='The passphrase needs at least 12 characters; type it again (%s).'
MSG_pb_pass_chars='The passphrase has characters that are not accepted (for example
non-English letters or full-width symbols); type it again (%s).'
MSG_pb_pass_long='The passphrase can have at most 256 characters; type it again (%s).'
MSG_pb_pass_cancel='No passphrase was set after three tries; the backup is cancelled.
Nothing was changed.'
MSG_pb_rec_line_no='Recordings: not included'
MSG_pb_rec_line_yes='Recordings: included'
MSG_pb_rec_line_hint='Recordings: not included (add --with-recordings to include them)'
MSG_pb_enc_line_no='Encryption: none'
MSG_pb_enc_line_yes='Encryption: with a passphrase (AES-256)'
MSG_pb_enc_line_hint='Encryption: none (add --passphrase-file <file> to encrypt)'
MSG_pb_enc_line_file='Encryption: with the passphrase in %s'
MSG_pb_pause='The backend, connection service and web pages pause for about
%s (the database keeps running). They start again once the
data is taken and the script waits until they are ready; building
and checking the file takes about %s.'
MSG_pb_warn_seal_ui='The master key is entered in the browser: after the restart the
system is sealed until someone enters the master key on the
unseal page, and users cannot connect until then.'
MSG_pb_warn_seal_kms='The master key is held by a key custody service: after the
restart the system is sealed until someone provides the custody
credentials on the unseal page again, and users cannot connect
until then.'
MSG_pb_warn_seal_hsm='The master key is held by a hardware security module: after the
restart the system is sealed until someone unseals it on the unseal
page, and users cannot connect until then.'
MSG_pb_dur_m='%s minutes'
MSG_pb_dur_m1='1 minute'
MSG_pb_dur_h='%s hours'
MSG_pb_dur_h1='1 hour'
MSG_pb_dur_more_m='%s more minutes'
MSG_pb_dur_more_m1='1 more minute'
MSG_pb_dur_more_h='%s more'
MSG_pb_step_pack_enc='Build the single file, encrypt it and read it back'
MSG_pb_done_enc='Backup done (%s, encrypted)'
MSG_pb_warn_pass='A restore needs the same passphrase. If it is lost the backup
cannot be restored; keep the passphrase apart from the file.'
MSG_pb_warn_enc_host='The file sits on the same host as .env; store it elsewhere.'
MSG_pb_enc_scheme='Encryption: AES-256-CBC, key derived from the passphrase with
PBKDF2-SHA256, 600,000 rounds'
MSG_pb_no_openssl='This host does not have the openssl image used for encryption (it
is obtained at install or upgrade). Nothing was stopped. Load the
offline image bundle of this release (%s), or choose no
encryption. The bundle is named like %s
and is on the same release page as the package:'
MSG_pb_pf_read='Cannot read the passphrase file %s (missing, not a regular
file, a symbolic link, or not readable). Nothing was stopped.'
MSG_pb_pf_perm='Other accounts can read or write the passphrase file %s
(mode %s), or it is owned by someone other than you or root, or it
has an extra access control list. Nothing was stopped. Fix it and
run again:'
MSG_pb_pf_line='The first line of the passphrase file %s does not fit the
rules: 12 to 256 characters; letters, digits, spaces and symbols from
a US keyboard only. Nothing was stopped.'

# ---- own backup (used by upgrade and rollback) ----
MSG_br_title='Backup before the upgrade'
MSG_br_opt1='[1] Let the script make a full backup (recommended)'
MSG_br_opt1_detail='Database, recordings, audit files, settings, certificates.
About %s, roughly %s minutes'
MSG_br_opt1_detail_notls='Database, recordings, audit files, settings.
About %s, roughly %s minutes'
MSG_br_opt2='[2] Use my own backup'
MSG_br_opt2_detail='For example a virtual machine or storage snapshot'
MSG_br_choose='Choose [1/2]: '
MSG_br_chosen='You chose to use your own backup'
MSG_br_times='All audit records were confirmed written at %s and the
services stopped at %s. Take the snapshot now. It must start
after the services stop, and cover the data folder, .env and the
certificates folder in the same restorable backup.'
MSG_br_times_notls='All audit records were confirmed written at %s and the
services stopped at %s. Take the snapshot now. It must start
after the services stop, and cover the data folder and .env in
the same restorable backup.'
MSG_br_must='The snapshot must include'
MSG_br_item_data='Data folder      %s (database, recordings,
                 audit files)'
MSG_br_item_env='Settings file    %s'
MSG_br_item_tls='Certificates     %s'
MSG_br_item_db='Database         a full backup of the external database taken
                 after %s'
MSG_br_cannot_check='The script cannot check what is in the snapshot. If you roll back
later and this version changed the database structure, the script
will not restore it for you: it stops before the restore and lists
the steps to restore from this snapshot.'
MSG_br_enter='When the snapshot is done, enter (this goes into the upgrade record):'
MSG_br_ask_ref='Snapshot name or ID                   > '
MSG_br_ask_time='Snapshot start time (YYYY-MM-DD HH:MM) > '
MSG_br_time_format='Enter the time as YYYY-MM-DD HH:MM, for example 2026-09-30 02:18'
MSG_br_time_ok='%s is after the stop time %s'
MSG_br_ask_restore='Where is the restore procedure (document name or location)
                                      > '
MSG_br_ask_yes='Does the snapshot include every item above, and can it be
restored with that procedure? Type yes > '
MSG_br_time_early='The snapshot time %s is before the stop time %s'
MSG_br_time_early_detail='That snapshot misses the last records written before the stop;
restoring it would lose data. Take a new snapshot, or choose [1]
and let the script back up. The services are still stopped;
nothing else was changed.'
MSG_br_cancel_hint='To cancel the upgrade, start all the services again and confirm:'
MSG_br_not_confirmed='The snapshot was not confirmed (yes, a name and a restore procedure
are all needed). The services are still stopped; nothing else was
changed.'
MSG_br_flags_incomplete='--backup-ref needs --backup-time and --backup-restore with it.
Nothing was changed.'
MSG_br_ref_running='Your own backup has to be taken after the services stop. Run
interactively (the script waits for your snapshot after the stop)
or let the script back up. Nothing was changed.'
MSG_br_stop_unknown='Cannot read when the backend stopped, so the snapshot time cannot be
checked. Nothing was changed.'
MSG_br_drain_timeout='The backend log says the audit queue did not drain when it stopped:
some audit records were not confirmed written. A snapshot of this
state is incomplete and is not accepted. Nothing was changed.'
MSG_br_ref_used='Using your backup %s (%s, after the stop at %s);
the script makes none.'

# ---- upgrade version rules (used by upgrade and rollback) ----
MSG_vr_bad_version='"%s" is not a version number (for example 1.13.2).'
MSG_vr_older='Cannot upgrade to %s: it is older than the installed %s'
MSG_vr_older_detail='To go back to an older version, restore the backup taken before the
upgrade by hand, as in "Backup and Restore", section 5 "Restore
procedure".'
MSG_vr_same='%s is already installed'
MSG_vr_same_detail='There is nothing to upgrade. To see the state of this deployment:'
MSG_vr_skip='%s cannot be installed directly over %s; it needs %s
or later'
MSG_vr_skip_detail='Upgrade to %s first, check that it works, then upgrade to %s:'

# ---------- upgrade: entry, package, check for a newer version ----------
MSG_up_title='Custodexa upgrade preview (nothing has been changed yet)'
MSG_up_row_installed='  Installed          %s'
MSG_up_row_target='  Upgrade to         %s'
MSG_up_row_root='  Deployment         %s'
MSG_up_confirm='Start the upgrade? [y/N]'
MSG_up_not_target='"%s" is neither a version nor a package file (custodexa-<version>.tar.gz)'
MSG_up_incoming_failed='Could not create the temporary folder %s'
MSG_up_download_failed='Could not download the %s package from GitHub. To upgrade offline,
give the path of a downloaded package:'
MSG_up_pkg_no_sums='%s is missing. Keep the package in the same folder as its SHA256SUMS'
MSG_up_pkg_sum_bad='The checksum of %s does not match SHA256SUMS; the file may be
incomplete or damaged; download it again'
MSG_up_pkg_sig_bad='%s: signature mismatch, publisher unverified'
MSG_up_pkg_sig_missing='%s: no signature file; publisher unverified'
MSG_up_pkg_sig_skip='%s: only the checksum was checked, not the publisher signature
(cosign is not installed)'
MSG_up_pkg_ok='%s: checksum and publisher signature verified'
MSG_up_pkg_layout='%s is not a %s package (the script or VERSION file of that version is
missing)'
MSG_up_release_differs='%s already exists and differs from this package. Find out what it is,
then run again'
MSG_up_no_deployment='There is no deployment here: %s'
MSG_up_no_deployment_running='The running deployment is in %s. Run it for that folder:'
MSG_q_installed='Installed   %s (package deployment, %s)'
MSG_q_latest='Latest      %s (released %s)'
MSG_q_up_to_date='This is the latest version'
MSG_q_direct='Direct upgrade is possible (%s accepts %s or later)'
MSG_q_migrations_none='No database structure change will be applied'
MSG_q_migrations_one='1 database structure change will be applied. Rolling back
after the upgrade means restoring the pre-upgrade backup'
MSG_q_migrations_many='%s database structure changes will be applied. Rolling back
after the upgrade means restoring the pre-upgrade backup'
MSG_q_migrations_unknown='The database structure version could not be read, so the number of
structure changes is not known'
MSG_q_verified='Release manifest checksum and publisher signature verified'
MSG_q_unverified='Only the release manifest checksum was checked, not the publisher
signature (cosign is not installed); the result below is unverified'
MSG_q_no_sig='Release manifest signature file is absent; publisher unverified.
The upgrade result uses the checksum-checked manifest'
MSG_q_verify_fail_2='The release manifest checksum does not match SHA256SUMS.
The file may be incomplete or damaged; download it again.
Whether you can upgrade is not known'
MSG_q_verify_fail_3='Release manifest signature mismatch, publisher unverified.
The upgrade result uses the checksum-checked manifest'
MSG_q_notes='  Release notes  %s'
MSG_q_run='To upgrade, run:'
MSG_q_only='This only checked for updates. Nothing was changed.'
MSG_q_offline='Cannot reach GitHub. To upgrade offline, give the path of a package:'
# ---------- upgrade: checks before the preview, and the preview ----------
MSG_up_row_kek='  Master key mode    %s'
MSG_up_kek_ui='entered in the browser'
MSG_up_kek_env='settings file'
MSG_up_kek_kms='external key service (KMS)'
MSG_up_kek_hsm='hardware security module (HSM)'
MSG_up_will='What will happen'
MSG_up_will_1='  1. Wait until all audit records are in the database, then stop the
     services (the database keeps running)'
MSG_up_will_2='  2. Full backup: database, recordings, audit files, settings,
     certificates. About %s; %s free where backups go'
MSG_up_will_2_ref='  2. Use the backup of your own given with --backup-ref; the script
     makes none this time'
MSG_up_will_2_own='  2. The script cannot back up the external database this time (see
     below); after the stop you confirm a backup of your own taken
     after the stop'
MSG_up_will_3='  3. Switch to %s and start it'
MSG_up_will_4='  4. Check the version, that it is the same data as before, and that
     the keys did not change'
MSG_up_know='Good to know'
MSG_up_know_pause='  - Expect %s to %s minutes of downtime. Nobody can connect meanwhile,
    and open connections will be cut (%s are open now)'
MSG_up_know_pause_unknown='  - Expect %s to %s minutes of downtime. Nobody can connect meanwhile,
    and open connections will be cut'
MSG_up_know_backend_down='  - The backend is not running, so the audit queue cannot be checked;
    the services are stopped directly'
MSG_up_know_mig_none='  - This version does not change the database structure'
MSG_up_know_mig_one='  - This version changes the database structure once. Rolling back
    afterwards means restoring this backup; anything recorded after
    the backup is lost'
MSG_up_know_mig_many='  - This version makes %s database structure changes. Rolling back
    afterwards means restoring this backup; anything recorded after
    the backup is lost'
MSG_up_know_mig_unknown='  - The database structure version could not be read, so the number
    of structure changes is not known'
MSG_up_know_ui='  - After the upgrade the system stays sealed until someone enters
    the master key on the unseal page'
MSG_up_know_kms='  - After the upgrade the system stays sealed. Have three things
    ready: the local administrator sign-in, the key service
    credentials, and the deployment topology record'
MSG_up_know_old_images='  - Some images of the installed version are not on this host; a
    rollback would need them rebuilt or pulled again'
MSG_up_know_tmux='  - Have someone familiar with operating this host run it inside a
    terminal tool that keeps the session alive (such as tmux or
    screen), to reduce the risk that a dropped SSH connection stops
    the upgrade'
MSG_dg_step='Wait for audit records to be written'
MSG_dg_left_first='%s left'
MSG_dg_left_next=' ... %s left'
MSG_dg_done='Wait for audit records to be written (0 left)'
MSG_dg_timeout='Wait for audit records to be written: %s still
waiting after 120 seconds'
MSG_dg_timeout_what='The services are still running. Nothing was changed.
This usually means the database is busy or writing slowly. Try the
upgrade again when usage is low. To check the number yourself:'
MSG_dg_sealed='Wait for audit records to be written: the system is
sealed, so audit writing has not started; nothing to wait for'
MSG_dg_stopped='Wait for audit records to be written: the backend is not
running, so nothing is waiting'
MSG_dg_unknown='Wait for audit records to be written: cannot confirm'
MSG_dg_unknown_detail='              Neither the number of waiting records nor the sealed
              state could be read (the request was blocked by the
              source address limit, or the backend did not answer).'
MSG_dg_unknown_what='Since the number of pending records could not be confirmed, the
script stopped the upgrade; the services are still running and
nothing was changed.
Run sudo %s status%s first to check the
backend. If it still cannot be read, hand this error and the
upgrade log file to operations to check the source address limit
(SEAL_UNSEAL_ALLOWED_CIDRS) before trying again.'
# ---------- upgrade: stopping the old version ----------
MSG_st_stop_failed='Stopping the services failed; some of them may be stopped'
MSG_st_log_unreadable='The backend log could not be read, so it is not known whether all
audit records were written when it stopped'
MSG_st_drain_timeout='Stop the services: not all audit records were written to the
database within the shutdown limit'
MSG_st_drain_counts='%s not confirmed written (%s moved to the fallback file, %s still
being handled, %s lost)'
MSG_st_drain_detail='The fallback file is in %s. The upgrade
stopped here; the services stay stopped and nothing else was
changed. Check these records before starting the old version again.'
MSG_st_resume='To start the old version again:'
MSG_st_gone='Confirm the old version has fully stopped
(0 database connections)'
MSG_st_conn_left='After the stop, the application account still has %s
connections to the database'
MSG_st_conn_unknown='The connections of the application account could not be read,
so it is not known whether the old version has fully stopped'
MSG_st_conn_detail='An old backend may still run on another host or under another
compose project, or its connection is not reclaimed yet. The
upgrade stopped here; the services stay stopped. Find it and stop
it until the query below reads 0:'

# upgrade: an interrupted upgrade, the next time it is run
MSG_up_rerun_safe='It stopped before the services were stopped: they kept running and
nothing was changed. Starting over.'
MSG_up_rerun_resumed='The services are running again; the version and the data were not
changed. Starting over, with a new backup.'
MSG_up_hint_stopped='The services are stopped; the version and the data were not changed.
Start the old version again, then run the upgrade once more.'
MSG_up_hint_again='Run the upgrade again:'
MSG_up_hint_switched='The new version is already in place. Check the backend log for the
reason first:'
MSG_up_hint_backup='Pre-upgrade backup: %s'

# upgrade: the steps after the preview, the checks after the start, the closing screens
MSG_up_run_title='Upgrade %s -> %s'
MSG_up_step_env='Check the environment'
MSG_up_step_images='Get and verify the new images'
MSG_up_step_confirmed='Confirmed'
MSG_up_step_backup='Back up'
MSG_up_bk_snap='Record row counts and key fingerprints'
MSG_up_bk_db='Database                    %s'
MSG_up_bk_files='Recordings and audit files  %s'
MSG_up_unseal_after='The master key is entered in the browser, so unseal once more
after the services start.'
MSG_up_step_switch='Switch to %s'
MSG_up_step_start='Start'
MSG_up_step_ready='Wait until ready'
MSG_up_step_check='Check'
MSG_up_step_record='Record'
MSG_up_failed_at='The last upgrade stopped at step %s.'
MSG_up_know_verified='  - Image checksums, signatures and build provenance are verified'
MSG_up_fail_switch='The upgrade stopped at step 9/13: could not switch to the new
version'
MSG_up_fail_start='The upgrade stopped at step 10/13: the new version did not start'
MSG_up_fail_ready='The upgrade stopped at step 11/13: the backend did not report
ready within %s seconds'
MSG_up_fail_checks='The upgrade stopped at step 12/13: the checks did not pass'
MSG_up_state_title='Where things stand'
MSG_up_state_switched='Switched to %s'
MSG_up_state_not_ready='Switched to %s; the services started but the backend is
not ready'
MSG_up_state_backup='The pre-upgrade backup is complete:
%s'
MSG_up_state_backup_own='The pre-upgrade backup is your own snapshot, recorded in
%s'
MSG_up_state_no_auto='The script does not roll back on its own'
MSG_up_logs_first='Check the backend log for the reason first:'
MSG_up_logs_more='If you still cannot tell why, hand this log and the upgrade log
file to operations.'
MSG_up_done_sealed='The new version has started: %s. Unsealing and the checks
below are still required before users can connect'
MSG_up_done='The new version has started: %s. The checks below are still
required before users can connect'
MSG_up_todo='Still to do'
MSG_up_todo_unseal_ui='The system is sealed. Enter the master key at
%s'
MSG_up_todo_unseal_kms='The system is sealed. Open %s with the
local administrator account, check the key custody details and
provide the credentials'
MSG_up_todo_manual_after='After unsealing, and before letting users connect, check by hand
(the script cannot do these):
- The audit chain verification passes
- A recording from before the upgrade plays
- Open a test connection, run a few commands, and confirm they
  show up in the audit records (do not skip this: a working
  connection does not prove audit records are being written)'
MSG_up_todo_manual='Before letting users connect, check by hand (the script cannot
do these):
- The audit chain verification passes
- A recording from before the upgrade plays
- Open a test connection, run a few commands, and confirm they
  show up in the audit records (do not skip this: a working
  connection does not prove audit records are being written)'
MSG_up_done_rollback='Roll back    restore the backup below by hand, as in "Backup and
             Restore", section 5 "Restore procedure"'
MSG_up_done_backup='Backup       %s'
MSG_up_done_log='Log file     %s'
MSG_pc_title='Checks'
MSG_pc_services_bad='Services        not running as expected: %s'
MSG_pc_version='Version         the backend reports %s'
MSG_pc_version_bad='Version         the backend reports %s, expected %s'
MSG_pc_images_bad='Images          a running image differs from the one obtained'
MSG_pc_data_unknown='Data            the counts before or after cannot be read, so
                they cannot be compared; check them by hand'
MSG_pc_mig_missing='Database        structure versions from before are missing:
                %s'
MSG_pc_mig_none='Database        no structure change'
MSG_pc_mig_one='Database        1 structure change applied:
                %s'
MSG_pc_mig_many='Database        %s structure changes applied:
                %s'
MSG_pc_same_data='Same data       %s users and %s connection records, as
                before; %s audit records (%s
                before, %s added at startup)'
MSG_pc_counts_bad='Same data       %s users (%s before), %s connection records
                (%s before), %s audit records (%s before)'
MSG_pc_keys_manual='Keys            the fingerprints before or after are incomplete
                and cannot be compared; check them on the key
                inventory page'
MSG_pc_keys_changed='Keys            a key fingerprint differs from before the upgrade'
MSG_pc_keys_same='Keys            all four key fingerprints are unchanged'
MSG_pc_lock_other='Single instance the database lock is held by another database
                session: another backend uses the same database'
MSG_pc_lock_held='Single instance this backend holds the database lock'
MSG_pc_lock_unknown='Single instance the backend log does not show the database lock'
MSG_pc_entry_bad='Entry           %s does not answer'
MSG_pc_empty_title='The new version found an empty database. All services were
stopped right away'
MSG_pc_empty_moved='It set up the database as a fresh install (%s user, %s connection
records; before the upgrade: %s and %s). The path holding the
original data, %s, was not rewritten or deleted
by this upgrade. The usual cause is DATA_PATH in .env pointing
elsewhere:
  DATA_PATH now          %s
  data before upgrade    %s'
MSG_pc_empty_moved_do='Do not sign in, do not set up a master key, and do not delete any
folder yet.
1. Have operations check both data paths: confirm
   %s holds only the data this run created
   by mistake (%s user, %s connection records), and
   %s still has the original data
2. Once checked, set DATA_PATH in .env back to
   %s
3. Only delete %s once you are sure
4. To go back to the previous version, restore the pre-upgrade
   backup by hand, as in "Backup and Restore", section 5 "Restore
   procedure"'
MSG_pc_empty_same='It set up the database as a fresh install (%s user, %s connection
records; before the upgrade: %s and %s). The data path %s
was not rewritten or deleted by this upgrade; the new version may
be connected to another database.'
MSG_pc_empty_same_do='Do not sign in, do not set up a master key, and do not delete any
folder yet.
1. Have operations check the database settings in .env and the
   backend log for why the new version did not find the data
2. Once checked, to go back to the previous version, restore the
   pre-upgrade backup by hand, as in "Backup and Restore", section 5
   "Restore procedure"'

# Main menu (custodexa.sh without a command, on a terminal).
MSG_menu_title='Custodexa management script %s    Deployment directory %s'
MSG_menu_state_none='Status: not installed'
MSG_menu_state_package='Status: installed %s (package deployment)'
MSG_menu_language='Language: --lang zh-TW 繁體中文, --lang ja 日本語'
MSG_menu_install='Install'
MSG_menu_load_first='Load an offline image bundle (first, if this host has no internet)'
MSG_menu_status='Show status'
MSG_menu_upgrade='Upgrade'
MSG_menu_backup='Back up to a single file (portable; pauses the service)'
MSG_menu_load='Load an offline image bundle'
MSG_menu_help='Help'
MSG_menu_quit='Quit'
MSG_menu_choose='Choose [0-%s]: '
MSG_menu_choose_sub='Choose [1-%s], or press Enter for the main menu: '
MSG_menu_invalid='No such choice; type one of the numbers in brackets.'
MSG_menu_other_path='Enter another path'
MSG_menu_bundle_found='Load an offline image bundle. Bundles in the current directory %s:'
MSG_menu_bundle_none='Load an offline image bundle. No bundle in the current directory %s
(named like custodexa-images-%s-amd64.tar).'
MSG_menu_ask_bundle='Bundle path, or press Enter for the main menu > '
MSG_menu_up_title='Upgrade to which version?'
MSG_menu_up_latest='The latest (check for a newer version, then upgrade to it)'
MSG_menu_up_version='A version you name'
MSG_menu_up_package='A package you downloaded (works offline)'
MSG_menu_ask_version='Version (for example 1.13.2), or press Enter for the main menu > '
MSG_menu_package_found='Upgrade from a downloaded package. Packages in the current directory %s:'
MSG_menu_package_none='Upgrade from a downloaded package. No package in the current directory %s
(named like custodexa-%s.tar.gz).'
MSG_menu_ask_package='Package path, or press Enter for the main menu > '

MSG_up_restore_guide='To go back to %s, restore the backup above by hand as described
in "Backup and Restore", section 5 "Restore procedure".'
MSG_menu_images_install='Image source'
MSG_menu_images_upgrade='Image source for upgrade to %s'
MSG_menu_images_auto='  [1] Auto (default): this host, offline bundle, GHCR, Docker Hub,
      then build from source'
MSG_menu_images_source='  [2] Build from the source in the package (slower; upstream images
      still have to be obtained)'
MSG_menu_images_choose='Choose [1-2], or press Enter for Auto: '
MSG_q_wait_download='Downloading %s for the latest release…'
MSG_q_download_ok='Downloaded %s'
MSG_q_optional_signature_missing='Signature bundle is unavailable; publisher unverified'
MSG_q_wait_checksum='Checking the release manifest checksum against SHA256SUMS…'
MSG_q_checksum_ok='Release manifest checksum matches'
MSG_q_wait_signature='Verifying the release manifest signature…'
MSG_up_wait_download='Downloading %s…'
MSG_up_download_ok='Downloaded %s'
MSG_up_wait_checksum='Checking the package checksum for %s against SHA256SUMS…'
MSG_up_checksum_ok='Checksum matches for %s'
MSG_up_wait_signature='Verifying the release manifest signature…'
MSG_up_step_reserved='No action at this step'

# Whole-deployment service controls.
MSG_menu_start='Start services'
MSG_menu_stop='Stop services'
MSG_help_cmd_start='  start                  Start all services and wait for backend readiness'
MSG_help_cmd_stop='  stop                   Confirm and stop all services'
MSG_svc_stop_title='Stop services'
MSG_svc_stop_warn='Active user connections will end. Notify users first;
services stop after the audit queue drains.'
MSG_svc_stop_confirm='Stop all services? [y/N]'
MSG_svc_stop_done='Services stopped'
MSG_svc_stop_already='Services are already stopped.'
MSG_svc_start_title='Start services'
MSG_svc_start_done='Services started; check status and unseal if needed.'
MSG_svc_start_already='Services are running and backend is ready.'
MSG_svc_drain_run='Waiting for audit records'
MSG_svc_drain_done='Audit queue drained'
MSG_svc_drain_fail='Audit queue could not be confirmed empty; services remain running.'
MSG_svc_stop_run='Stopping all services'
MSG_svc_start_run='Starting all services'
MSG_svc_ready_run='Waiting for backend readiness (up to 180 seconds)'
MSG_svc_stop_failed='Stop incomplete; check status.'
MSG_svc_start_failed='Start incomplete; check status.'
MSG_svc_ready_failed='Backend was not ready within 180 seconds; check status.'
MSG_svc_cancelled='Services unchanged.'
MSG_svc_status_hint='Check status with:'
MSG_svc_containers_up='Containers started'
MSG_svc_ready_done='Backend ready'
MSG_svc_not_installed='Not installed; services cannot be controlled.'
MSG_svc_resume_hint='Services may be partially changed. Check status, then run start
to restore all services:'
MSG_svc_pending_run='Previous %s run is unfinished; follow its recovery command first.'

# The backup of an external database (lib/dbext.sh, lib/backup_external.sh).
MSG_pb_summary_ext='Version %s; external database %s
(PostgreSQL %s); master key: %s'
MSG_pb_ext_tool='Export tool: PostgreSQL %s client (shipped with this release, verified)'
MSG_pb_ext_conn='Connection: %s, %s'
MSG_pb_ext_mode_system='verify-full (set by PGSSLROOTCERT=system, as in the backend)'
MSG_pb_ext_verify_none_none='server certificate not checked'
MSG_pb_ext_verify_none_file='server certificate not checked (the CA file still goes into the
backup file)'
MSG_pb_ext_verify_ca_system='server certificate checked against the system'"'"'s trusted
certificate authorities, host name not checked'
MSG_pb_ext_verify_ca_file='server certificate checked against the CA file, host name not
checked (the CA goes into the backup file)'
MSG_pb_ext_verify_full_system='server checked against the system'"'"'s trusted certificate
authorities'
MSG_pb_ext_verify_full_file='server checked against the CA file (the CA goes into the backup file)'
MSG_pb_ext_standby='Do not let a standby host take over this database during the
backup, or the backup may be inconsistent.'
MSG_pb_pause_ext='The backend, connection service and web pages pause for about
%s (the external database is not touched). They start again
once the data is taken and the script waits until they are ready;
building and checking the file takes about %s.'
MSG_pb_step_stop_ext='Stop the services (the external database is not touched)'
MSG_pb_ext_and=' and '
MSG_pb_ext_no_tool='The external database runs PostgreSQL %s; this release carries
export tools for %s, and the script only uses the tool
of the server'"'"'s own major version. Nothing was stopped. Use your
own database backup procedure; an upgrade can take your own backup
instead (--backup-ref).'
MSG_pb_ext_unreachable='Cannot reach the external database %s (with
DB_USER, DB_NAME and DB_SSLMODE from .env). The reason is in the
log file. Nothing was stopped.'
MSG_pb_ext_unreachable_hint='Check in this order:
  1. This host can reach that address and port (name lookup, firewall)
  2. The backend can reach the database now:
     %s
  3. DB_SSLMODE matches the server'"'"'s TLS setup
  4. The password of DB_USER was not changed on the database side'
MSG_pb_ext_no_image='This host does not have the export tool images for the external
database (PostgreSQL 16/17/18 clients, obtained at install or
upgrade). Nothing was stopped. Load the offline image bundle of this
release (%s):'
MSG_pb_ext_unsupported='The external database has settings this backup does not support; on
a new database server they could not be rebuilt as they are:
%s
Nothing was stopped. Use your own database backup procedure, or
change the items above first.'
MSG_pb_ext_dep_ts='Custom tablespace: %s (%s objects)'
MSG_pb_ext_dep_owner='Owners other than %s: %s (%s objects)'
MSG_pb_ext_dep_ext='Extension: %s'
MSG_pb_ext_dep_ca='CA file PGSSLROOTCERT=%s is not where the script
can find it'
MSG_pb_ext_dep_cert='Client certificate PGSSLCERT=%s is not where the
script can find it'
MSG_pb_ext_dep_keypath='Client private key PGSSLKEY=%s is not where the script
can find it'
MSG_pb_ext_dep_key='Client private key PGSSLKEY is inside the audit folder, which is
packed into the backup'
MSG_pb_ext_dep_key_rec='Client private key PGSSLKEY is inside the recordings folder, which
can be packed into the backup'
MSG_pb_ext_dep_sysca='DB_SSLMODE=verify-ca, but the export tool has no system CA file to
check the server the same way'
MSG_pb_ext_roles='The external database grants privileges to other roles:
%s. On a new database server those roles have
to exist first, or the restored privileges will differ.'

# ---- upgrade of an external database, and step 7 as one backup file ----
MSG_up_bk_file='Backup file  %s  %s'
MSG_up_bk_unrecorded='The backup file is complete: %s
but state.json could not be updated. The upgrade stopped; the services
stay stopped and the version was not changed.'
MSG_st_gone_unchecked='Old version stopped (its services are stopped; the
script cannot count connections on the external
database: make sure no backend on another host,
such as a standby, is connected to it)'
MSG_up_no_space_hint='You can move older backup files elsewhere and delete them here.'
MSG_up_ext_major_sep='/'
MSG_up_ext_own_version='The script cannot back up the external database this time: it runs
PostgreSQL %s, and this release has no export tool of that major
version. Step 7 can only take your own backup.'
MSG_up_ext_own_image='The script cannot back up the external database this time: the
export tool images for it (PostgreSQL %s clients) could not be
obtained; the reason is in the log file. Step 7 can only take your
own backup.'
MSG_up_ext_own_connect='The script cannot back up the external database this time: it
cannot be reached at %s; the reason is in the log file.
Step 7 can only take your own backup.'
MSG_up_ext_own_unsupported='The script cannot back up the external database this time, so step
7 can only take your own backup. The external database has settings
this backup does not support:'
MSG_up_ext_ni_version='The script cannot back up the external database (it runs PostgreSQL
%s, and this release has no export tool of that major version), and
this run is non-interactive (no terminal, or --yes was given), so your
own backup cannot be chosen here. Nothing was changed. In this order:'
MSG_up_ext_ni_image='The script cannot back up the external database (the export tool
images for it, PostgreSQL %s clients, could not be obtained; the
reason is in the log file), and this run is non-interactive (no
terminal, or --yes was given), so your own backup cannot be chosen
here. Nothing was changed. In this order:'
MSG_up_ext_ni_connect='The script cannot back up the external database (it cannot be
reached at %s; the reason is in the log file), and this
run is non-interactive (no terminal, or --yes was given), so your own
backup cannot be chosen here. Nothing was changed. In this order:'
MSG_up_ext_ni_unsupported='The script cannot back up the external database (it has the
settings below, which this backup does not support), and this run is
non-interactive (no terminal, or --yes was given), so your own backup
cannot be chosen here. Nothing was changed.'
MSG_up_ext_ni_order='In this order:'
MSG_up_ext_ni_1='1. Drain the audit queue and stop the services:'
MSG_up_ext_ni_2='2. Check that the services are stopped:'
MSG_up_ext_ni_3='3. After the stop, start your own backup of the external database, the
   data folder, .env and tls/, and note when the backup started.'
MSG_up_ext_ni_3_notls='3. After the stop, start your own backup of the external database, the
   data folder and .env, and note when the backup started.'
MSG_up_ext_ni_4='4. Run the upgrade again with:'
MSG_up_ext_ni_flags='--backup-ref <snapshot name> --backup-time "YYYY-MM-DD HH:MM" \\
--backup-restore <restore procedure>'

# ---------- restore: entry, options and the kind of restore ----------
MSG_help_cmd_restore='  restore <backup file>   Restore from a portable backup file. On an installed
                          host: take a safety backup, then replace the data.
                          On a host not yet installed: install the backup'\''s
                          version first, then restore
  restore --resume        Carry on with a restore that did not finish,
                          including the master key check after unseal
  restore --revert        Go back with the safety backup taken before the
                          restore
  restore --abandon       Give up on an unfinished restore on a new host and
                          return to not installed'
MSG_help_restore_options='Options for restore
  --same-host | --new-host     Required without a terminal: which kind of
                               restore this is
  --confirm-data-loss          Without a terminal, confirm that existing data
                               is overwritten (with --yes)
  --passphrase-file <file>     Passphrase file of an encrypted backup (same
                               permission rules as backup)
  --no-checksum-file           Go on without the .sha256 file (every checksum
                               inside is still checked)
  --package <package>          Package of the backup'\''s version, with
                               SHA256SUMS in the same folder (offline)
  --images <bundle>            Offline image bundle of the backup'\''s version
  --backup-ref, --backup-time, --backup-restore
                               Use your own backup taken after the services
                               stopped instead of the safety backup (also
                               with --resume when the safety backup did not
                               finish)
  --data-path, --tls-domain, --tls-ip-san, --public-base-url
                               Host values on a new host (this host'\''s
                               suggestions when not given)
  --db-client-cert, --db-client-key
                               Client certificate and private key for an
                               external database
  --accept-grant-loss          External database lacks roles: skip the grants
                               to those roles
  --nginx-template <path>      Where the custom nginx template goes on a new
                               host (when its original path cannot be used)'
MSG_usage_restore_only='Option %s is only for restore. See: custodexa.sh --help'
MSG_rs_no_file='Name the backup file: custodexa.sh restore <backup file>.
See: custodexa.sh restore --help'
MSG_rs_option_with='Option %s cannot be used with %s. See: custodexa.sh restore --help'
MSG_rs_flow_both='--same-host and --new-host cannot be given together.'
MSG_rs_flow_needed_same='Without a terminal, say which kind of restore this is. This host
is installed, so its data is replaced by the backup: add --same-host.'
MSG_rs_flow_needed_new='Without a terminal, say which kind of restore this is. This host
is not installed yet: add --new-host.'
MSG_rs_flow_wrong_same='This host is not installed yet, so the restore is onto a new host:
use --new-host instead of --same-host.'
MSG_rs_flow_wrong_new='This host is already installed, so its data would be replaced: use
--same-host instead of --new-host.'
# Going back after an upgrade.
MSG_rb_flags_only='--resume and --revert are only for rollback and restore.'
MSG_rb_flags_conflict='Choose either --resume or --revert.'
MSG_rb_no_pending='There is no unfinished rollback to continue. Nothing was changed.'
MSG_rb_confirm='Start? [y/N]'
MSG_rb_preview='Back to the previous version: preview (nothing has been changed yet)'
MSG_rb_versions='Installed      %s
Go back to     %s (the version before the upgrade)'
MSG_rb_basis_same='Database       no structure change since the upgrade; it matches the
               record taken before the upgrade'
MSG_rb_basis_not_started='Database       the new version never started, so the database
               was not touched'
MSG_rb_basis_compatible='Database       %s structure changes since the upgrade, but the %s
               release manifest states it can go straight back to
               %s (rehearsed before release)'
MSG_rb_basis_compatible_one='Database       %s structure change since the upgrade, but the %s
               release manifest states it can go straight back to
               %s (rehearsed before release)'
MSG_rb_keep_data='So only the version is switched back; the data, the settings file and
the certificates stay as they are, and no restore is needed.'
MSG_rb_images='Old images     all %s are on this host; the running containers are
               checked against them after the start'
MSG_rb_steps='Steps: stop the services, check the database again and switch back
to %s, start, check the version and the running images.'
MSG_rb_keep_records='Everything recorded since the upgrade is kept.'
MSG_rb_step_stop='Stop the services'
MSG_rb_step_stopped='The services are already stopped'
MSG_rb_step_switch='Check the database again, switch back to %s'
MSG_rb_step_revert='Switch back to %s'
MSG_rb_step_start='Start the services'
MSG_rb_step_check='Check: the backend reports %s and the running
images are the ones from before the upgrade'
MSG_rb_check_health='Check: the backend was not ready within %s seconds'
MSG_rb_check_diff='Check: the running version or images differ from the record: %s'
MSG_rb_done='Back on %s.'
MSG_rb_unseal='The system is sealed; unseal it at
%s'
MSG_rb_upgrade_later='To upgrade again later, run upgrade as usual.'
MSG_rb_revert_title='Back on %s (the version before this rollback started)'
MSG_rb_state_title='Current state'
MSG_rb_state_version='Version: %s'
MSG_rb_state_links='Recorded version: %s; current link: %s'
MSG_rb_state_services='Running services: %s'
MSG_rb_unchanged_data='The data, the settings file and the certificates were not changed'
MSG_rb_resume='Once the cause is fixed, finish going back to the previous version:'
MSG_rb_revert='Or return to %s, the version after the upgrade:'
MSG_rb_resume_revert='Finish returning to %s, the version after the upgrade:'
MSG_rb_refused='Cannot go straight back to %s: %s has already changed the
database. Nothing was changed; %s.'
MSG_rb_services_running='the services are still running'
MSG_rb_services_stopped='the services remain stopped'
MSG_rb_refused_after='Cannot go straight back to %s: a second check after the services
stopped found that %s has changed the database. The version was
not switched; the application services are stopped and the database
is still running.'
# The count (%.0s) is left out of the English reason; the list names the changes.
MSG_rb_reason_changed='Why            %.0sthe database structure changed after the upgrade
               (%s), and %s cannot work
               correctly with the changed database'
MSG_rb_reason_unreadable='Why            the current database structure could not be read, so
               it is not known whether the upgrade changed it'
MSG_rb_more=', and %s more'
MSG_rb_restore='To go back to %s, restore the backup taken before the upgrade. The
restore asks you first, then returns both the data and the version to
how they were before the upgrade; the data created since the upgrade is
replaced.'
MSG_rb_keep_new='To keep %s running instead of restoring:'
MSG_rb_too_old='Cannot go straight back to %s: the script can only go back to
1.16.0 or later. Nothing was changed.'
MSG_rb_no_previous='There is no previous version to go back to. Nothing was changed.'
MSG_rb_premise_none='This deployment has not been upgraded by the script.'
MSG_rb_premise_changed='The version record has changed since the last upgrade.'
MSG_rb_premise_link='The running version does not match the record.'
MSG_rb_already='The last version change was already a rollback (%s, from
%s back to %s). The script goes back one version only; to
return to %s, run upgrade as usual.'
MSG_rb_before_switch='The last upgrade stopped at step %s, before the switch to the
new version; there is nothing to go back from.'
MSG_rb_status_hint="Check this deployment's state:"
MSG_rb_images_bad='Going back to %s needs the images from before the upgrade, but
%s of them are not on this host or differ from before. Nothing was
changed.'
MSG_rb_image_missing='%s  not on this host'
MSG_rb_image_diff='%s  the image on this host differs from the one recorded before
           the upgrade: before %s, now %s'
MSG_rb_load='Load the %s offline image bundle, then run again:'
MSG_rb_upgrade_hint='To go back to %s, run the command below. The script first makes sure
the new version has not changed the database, and only then switches
straight back to %s; if it has, the script tells you how to restore
the backup above. You are asked before anything stops:'
MSG_rb_upgrade_done='Back to %s   sudo %s/custodexa.sh rollback%s'
MSG_status_upgrade_rolled_back='Last upgrade %s → %s, rolled back to %s on %s%.0s'
MSG_status_rollback_unfinished='Going back to the previous version did not finish
(from %s to %s, stopped at step %s)'
MSG_status_rollback_reverting='Returning to the version after the upgrade
did not finish (back to %s, stopped at step %s)'
MSG_status_rollback_reverted='The last rollback was undone; back on %s'
MSG_status_rollback_refused='The last rollback stopped before the switch:
%s had changed the database; still on %s'
MSG_status_upgrade_failed_handed='%s -> %s failed at step %s, %s, handed over to restore afterwards. Log:'
MSG_help_cmd_rollback='  rollback             Go back to the version before the upgrade. When the
                       new version has not changed the database, only the
                       version is switched back and the data is kept;
                       otherwise nothing is changed and you are told how to
                       restore
  rollback --resume    Finish an unfinished rollback
  rollback --revert    Abandon an unfinished rollback and return to the
                       version after the upgrade'
MSG_help_opt_resume='  --resume               (rollback, restore) Carry on with the unfinished one'
MSG_help_opt_revert='  --revert               (rollback, restore) Undo the unfinished one'

MSG_rb_refused_unreadable='Cannot go straight back to %s: the database may have been changed by
%s since the upgrade. Nothing was changed; %s.'

MSG_rb_refused_unreadable_after='Cannot go straight back to %s: a second check after the services
stopped could not confirm that %s left the database unchanged.
The version was not switched; the application services are stopped
and the database is still running.'

MSG_rb_image_unrecorded='%s  the image ID from before the upgrade is missing from the record'

MSG_rb_state_not_ready='Switched back to %s; the services are started but the
backend is not ready'

MSG_rb_state_before='The version has not been switched; still on %s'

MSG_rb_state_start_failed='Switched back to %s; not all services have started'

MSG_rb_reverted='Back on %s (the version before this rollback started)'

MSG_rb_no_services='none'

MSG_rb_basis_compatible_unreadable='Database       its structure could not be read, but the %s release
               manifest states it can go straight back to %s
               (rehearsed before release)'

MSG_rb_step_check_revert='Check: the backend reports %s and the running
images are the ones from before this rollback'

MSG_status_rollback_unreadable='The last rollback stopped before the switch:
%s may have changed the database; still on %s'

MSG_rb_images_unverified='Cannot verify the release information or image ID records needed to
go back to %s, so the required images cannot all be confirmed as the
ones from before the upgrade. Nothing was changed.'

MSG_rb_release_unverified='Release information could not be read.'

# Reading a portable backup before a restore.
MSG_rs_unchanged='Nothing has been changed.'

MSG_rs_bad='The backup file is incomplete or has been changed, and cannot be
restored:'

MSG_rs_copy_again='Use another backup, or copy this file again from where it came from
(with its .sha256).'

MSG_rs_bad_sidecar='The checksum file does not match the backup file.'

MSG_rs_bad_members='A member is extra, missing or repeated.'

MSG_rs_bad_type='An archive member is a directory, a link, or has a path.'

MSG_rs_bad_manifest='A backup manifest field is missing or invalid: %s.'

MSG_rs_bad_sums='The member list and SHA256SUMS do not agree.'

MSG_rs_bad_hash='The checksum of %s differs from the one written when the backup
was made.'

MSG_rs_bad_cross='The release manifests, migrations, master key fingerprint or recorded
version do not agree with the backup manifest.'

MSG_rs_bad_inner='An inner archive has a path or a link that is not allowed.'

MSG_rs_bad_name='The file name and encrypted file header do not agree.'

MSG_rs_bad_decrypt='The encrypted file is truncated or has an invalid length.'

MSG_rs_bad_read='The backup file could not be read.'

MSG_rs_bad_grants='The bundled database grants privileges to other roles: %s.
Restore it by hand following section 5 of "Backup and Restore".'

MSG_rs_bad_grants_read='The database dump could not be read to check its grants.'

MSG_rs_reading='Reading the backup file %s'

MSG_rs_sum_ok='The checksum file matches'

MSG_rs_sum_absent='No checksum file; checking against the checksums inside instead'

MSG_rs_no_sum='The checksum file %s
is not there. To go on without it when nobody is at the terminal, add
--no-checksum-file.'

MSG_rs_missing_sum='The checksum file %s
is not there, so there is no way to tell whether the file was damaged
on the way here.'

MSG_rs_missing_sum_checks='If you go on, every part inside has to match the checksums written when
the backup was made, and its records have to agree with each other,
before anything else happens. Any mismatch stops the restore with
nothing changed.'

MSG_rs_missing_sum_enc='This file is encrypted: without the checksum file, a failure to decrypt
cannot tell a wrong passphrase from a damaged file.'

MSG_rs_missing_sum_ask='Go on without the checksum file? [y/N]'

MSG_rs_pass_intro='This backup file is encrypted. Enter the passphrase set when the backup
was made (it is not shown as you type):'

MSG_rs_pass_prompt='Passphrase: '

MSG_rs_pass_needed='This backup is encrypted. Without a terminal, use --passphrase-file.'

MSG_rs_decrypt_matched='Could not decrypt: the passphrase is wrong (the file itself checked
out whole). %s more tries.'

MSG_rs_decrypt_absent='Could not decrypt: either the passphrase is wrong or the file is
damaged (without the checksum file the two look the same). %s more
tries.'

MSG_rs_decrypt_cancel='Three tries did not decrypt it; the restore is cancelled. Nothing
has been changed.'

MSG_rs_no_openssl='The openssl tool image of release %s is not on this host.
Restore needs it; load that release'\''s offline image bundle first.'

MSG_rs_parts='Checked every part (%s parts)'

MSG_rs_manifest='Backup manifest: format 1, version %s, taken %s'

MSG_rs_cross_ok='Cross-checks: release manifest, migrations and master key
fingerprint agree'

MSG_rs_old_file='This is not a backup file made by 1.16.0 or later, and the script
cannot restore it.'

MSG_rs_old_folder='%s is a backup folder from before
1.16.0. It has no backup manifest, so its version and deployment form
are unknown.'

MSG_rs_no_manifest='This file has no backup manifest.'

MSG_rs_old_guide='Such a backup can only be restored by hand on the host that made it,
following section 5 of "Backup and Restore", or after upgrading that
host to 1.16.0 or later and backing up again.'


# Checking the data and keys before a restore.
MSG_rs_data_old='The data in this backup belongs to %s, which is older than
1.16.0, and the script cannot restore it.'

MSG_rs_data_old_guide='is the backup an upgrade took of the %s deployment.
Versions before 1.16.0 do not report the master key ID after unsealing,
so the script cannot confirm the master key after a restore and will
not start one. Restore it by hand following "Backup and Restore":
  first take the files out as "Taking the files out of a single backup
  file" describes;
  to go back to the version before the upgrade on this host, continue
  with "Going back to the previous version after an upgrade by the
  management script";
  to restore onto another host, continue with "Restore procedure".'

MSG_rs_engine_old='This management script is %s, and the backup'\''s data belongs
to the newer %s.'

MSG_rs_engine_old_guide='A restore needs a management script no older than the backup.
On a new host: get %s or later with get-custodexa.sh and restore
with it.
On an installed host: upgrade to %s or later first, then restore.'

MSG_rs_fp_missing='This backup has no master key fingerprint (a single one could not
be read when it was made), so the script cannot confirm the master
key after a restore and will not start one.'

MSG_rs_fp_manual='Restore it by hand following section 5 of "Backup and Restore", and
check the key inventory item by item as section 6 describes.'

MSG_rs_hsm='This backup'\''s master key mode is hsm. This release has no working
HSM implementation, so the script cannot restore it.'

MSG_rs_external='This is a backup of a deployment with an external database, which
this build of the script cannot restore yet.'

MSG_rs_key_mismatch='The master key in the settings file does not belong to this
backup'\''s data:'

MSG_rs_key_fingerprints='Fingerprint of the key in the settings file   %s
Fingerprint recorded with the backup          %s'

MSG_rs_key_wrong='Restored with this key, none of the stored credentials could be
decrypted, so the restore will not start.
Use another, complete backup.'

MSG_rs_key_ok='The master key in the settings file has fingerprint %s, as recorded'

MSG_rs_jwt_ok='The sign-in token key fingerprint in the settings file matches the
backup'\''s snapshot'

MSG_rs_jwt_unknown='Sign-in token key in the settings file: the backup'\''s snapshot has no
fingerprint for it, not checked'

MSG_rs_bad_jwt='The sign-in token key fingerprint in the settings file differs from
the backup'\''s snapshot.'

MSG_rs_bad_secret='The settings file lacks a required key or contains an unusable
template value: %s.'

MSG_rs_extracted='Taken out to the working folder %s'


MSG_rs_bad_release='A release manifest hash or version differs from the backup manifest.'

MSG_rs_bad_migrations='The migration hash or count differs from the backup manifest.'

MSG_rs_bad_fingerprint='The master key fingerprint differs from the snapshot.'

MSG_rs_bad_state='The version in state.json differs from the backup manifest.'

MSG_rs_parts_enc='Decrypted and checked every part (%s parts)'

MSG_rs_bad_decrypt_tool='The decryption tool could not be run.'

# Obtaining the backup version and checking its data structure.
MSG_rs_release_absent='%s has no release files, so the version the backup was made
with cannot be installed on this host.'

MSG_rs_release_absent_guide='The data in this backup belongs to %s and can only be restored with
that version; the script will not install a different one.
If you have custodexa-%s.tar.gz with SHA256SUMS in the same folder,
name it:'

MSG_rs_release_other='Otherwise use a backup of another version.'

MSG_rs_release_download='The %s package could not be downloaded (github.com is not
reachable).'

MSG_rs_release_offline='If this host has no internet, put custodexa-%s.tar.gz and
SHA256SUMS in one folder and name the package with --package; name the
%s offline image bundle with --images.'

MSG_rs_release_manifest='The release manifest in the %s package differs from the one
recorded with the backup.'

MSG_rs_release_manifest_guide='The package may not be the published one; the script will not restore
with it.'

MSG_rs_migration_bad='The backup'\''s data has a structure change that %s does not know,
so it cannot be restored with %s:'

MSG_rs_migration_unknown='%s (not in the %s release manifest)'

MSG_rs_migration_missing='%s (required by %s, but absent from the backup snapshot)'

MSG_rs_migration_guide='This means a newer version had already changed the data when the backup
was made. The script does not put newer data under an older version.'

MSG_rs_migration_missing_guide='The backup is missing a structure change required by this version.
The script will not restore it.'


# Host values and the custom template destination.
MSG_rs_host_intro='The four values below are set for this host; every other setting is
taken from the backup.'

MSG_rs_host_intro_external='The data folder and public address below are set for this host;
every other setting is taken from the backup.'

MSG_rs_host_data_path='Data folder DATA_PATH'

MSG_rs_host_tls_domain='Certificate host name TLS_DOMAIN'

MSG_rs_host_tls_ip_san='Certificate IP TLS_IP_SAN'

MSG_rs_host_public_base_url='Public address PUBLIC_BASE_URL'

MSG_rs_host_values='       From the backup   %s
       For this host     %s'

MSG_rs_host_ask_path='Press Enter for this host'\''s value, type - to keep the backup'\''s, or type
another absolute path > '

MSG_rs_host_ask='Press Enter for this host'\''s value, type - to keep the backup'\''s, or type
another value > '

MSG_rs_data_absolute='DATA_PATH must be an absolute path.'

MSG_rs_data_nonempty='The new host must have no database or audit data here: %s.'

MSG_rs_host_tls_nginx_template='Custom nginx template TLS_NGINX_TEMPLATE'

MSG_rs_template_source='       From the backup   %s
                         (the original location under %s is unavailable)'

MSG_rs_template_ask='Enter an absolute path on this host for the template; the settings
file will point to it > '

MSG_rs_template_needed='The original template location is unavailable on this host: %s.
Use --nginx-template to name a new absolute path.'

MSG_rs_template_invalid='The template path must be absolute, with an existing parent folder,
and not a link, a directory or a path managed by a release: %s.'


# Space estimates before a restore.
MSG_rs_space_bad='Not enough space; the restore will not start:'

MSG_rs_space_row='%s (%s) needs %s GB, has %s GB'

MSG_rs_space_margin='The figures include a 10 to 20 percent margin; the sizes in the backup
file are estimates from when it was made.'

MSG_rs_space_work='working folder'

MSG_rs_space_safety='safety backup'

MSG_rs_space_data='data folder'

MSG_rs_space_images='images'

MSG_rs_space_unknown='Could not read the free space for %s; the restore will not start.'

MSG_rs_space_estimate='Could not estimate the current database for the safety backup.
The restore will not start.'

# Restore preview and confirmation.
MSG_rs_label_backup='  Backup file    '
MSG_rs_label_data_version='  Data version   '
MSG_rs_label_install='  Installs first '
MSG_rs_label_version='  Version        '
MSG_rs_label_deployment='  Deployment     '
MSG_rs_label_restores='  Restores       '
MSG_rs_label_recordings='  Recordings     '
MSG_rs_label_host='  Host values    '
MSG_rs_label_replaced='  Replaced       '
MSG_rs_label_safety='  Safety backup  '
MSG_rs_label_kept='  Kept           '
MSG_rs_label_downtime='  Downtime       '
MSG_rs_label_space='  Space          '

MSG_rs_preview_new='Restore preview: this new host (nothing has been changed yet)'

MSG_rs_preview_same='The restore replaces this host'\''s data; everything recorded after
the backup is lost'

MSG_rs_preview_encrypted='encrypted'

MSG_rs_preview_plain='not encrypted'

MSG_rs_backup_here='taken %s on this host
(%s)'

MSG_rs_backup_source='taken %s on %s;
%s'

MSG_rs_backup_integrity='backup file internal integrity: checked'

MSG_rs_data_engine='%s (this management script is %s)'

MSG_rs_versions='now %s, after the restore %s'

MSG_rs_versions_changed='now %s, after the restore %s
(the version goes back with the data)'

MSG_rs_other_host='[WARN] This backup comes from another host, %s;
       it will replace this host'\''s data.'

MSG_rs_package_checked='package %s: checksum matches'

MSG_rs_package_local='package checksum: not checked again; using the local release'

MSG_rs_signature_ok='publisher signature: verified'

MSG_rs_signature_no_cosign='publisher signature: not checked, cosign is not on
this host'

MSG_rs_signature_no_bundle='publisher signature: not checked, the signature file is absent'

MSG_rs_signature_bad='[WARN] publisher signature does not match'

MSG_rs_signature_local='publisher signature: not checked again for the local release'

MSG_rs_manifest_identical='release manifest identical to the one in the backup'

MSG_rs_preview_images_offline='%s images, from the offline bundle
%s'

MSG_rs_preview_images_local='%s images, already on this host'

MSG_rs_preview_images_source='%s images; the program images will be built from source'

MSG_rs_preview_images_auto='%s images; missing images will be obtained in the usual order
(local bundle, registry, then source build)'

MSG_rs_deployment='bundled database; %s; master key:
%s'

MSG_rs_tls_selfsigned='self-signed certificate'

MSG_rs_tls_provided='provided certificate'

MSG_rs_tls_external='external ingress'

MSG_rs_provider_ui='entered in the browser'

MSG_rs_provider_env='in the settings file'

MSG_rs_provider_kms='held by a key service'

MSG_rs_restores_new='database %s, audit files %s, settings file
.env'

MSG_rs_restores_same='database, audit files'

MSG_rs_restores_tls=', certificates tls/'

MSG_rs_settings_same='The settings file .env returns to its content at backup
time, secrets included (sign-in token key, database
password); DATA_PATH, TLS_DOMAIN, TLS_IP_SAN and
PUBLIC_BASE_URL keep this host'\''s current values'

MSG_rs_settings_same_external='The settings file .env returns to its content at backup
time, secrets included (sign-in token key, database
password); DATA_PATH and PUBLIC_BASE_URL keep this host'\''s
current values'

MSG_rs_preview_template='custom nginx template → %s'

MSG_rs_template_repointed='(the settings file now points here)'

MSG_rs_template_keep='the file already there is renamed and kept as
%s'

MSG_rs_recordings_restore='restored from the backup; existing files with the same name
are kept, not overwritten'

MSG_rs_recordings_kept='this backup has none: the recordings here stay where they
are, neither deleted nor overwritten'

MSG_rs_recordings_missing='not in the backup file (%s at the source); a list of
the recordings to bring over comes at the end'

MSG_rs_host_differences='Host values differ from the backup:'

MSG_rs_host_difference='%s: backup %s; this host %s'

MSG_rs_reissue='The address differs from the source: the backup'\''s
certificate authority is kept, and a server certificate
for this host'\''s address is issued'

MSG_rs_cert_mismatch='[WARN] The provided certificate does not cover this host'\''s
address. Replace it with one that does; it is kept unchanged.'

MSG_rs_cert_unknown='[WARN] The provided certificate'\''s addresses could not be
checked. Check them by hand; the certificate is kept unchanged.'

MSG_rs_replaced='all the data and settings on this host now (users,
assets, grants and policies go back to backup time):'

MSG_rs_counts_current='%s audit records and %s connection records here'

MSG_rs_counts_backup=',
%s and %s in the backup'

MSG_rs_counts_caution='The difference is only a guide, not a count of what is
lost: deletions, edits and another host'\''s data do not
show in it'

MSG_rs_counts_unknown='the current counts could not be read'

MSG_rs_safety_own='your own backup: %s
taken at %s'

MSG_rs_safety_script='before anything is overwritten, the current data is
backed up to
%s
(without recordings), and the restore goes on only once
it reads back correctly'

MSG_rs_safety_none='not needed: this host has no data yet'

MSG_rs_kept='the current database, audit and certificate folders are
renamed and kept, not deleted:'

MSG_rs_downtime='about %s minutes (safety backup %s, import %s, start and
checks 5)'

MSG_rs_preview_space_same='needs %s GB on %s; %s GB free'

MSG_rs_preview_env='The master key is in the settings file; its fingerprint
%s has been checked'

MSG_rs_preview_ui_same='[WARN] The master key is entered in the browser: after the restore the
       system is sealed until someone enters the master key on the
       unseal page; its fingerprint has to be %s.'

MSG_rs_preview_ui_new='[WARN] The master key is entered in the browser: to finish the restore,
       someone enters the master key on the unseal page and signs in
       with an administrator account from the backup. Its fingerprint
       has to be %s.'

MSG_rs_preview_kms='[WARN] The master key is held by a key service: to finish the restore,
       confirm that service on the unseal page and provide its
       credentials again. This host'\''s address must be allowed by it.'

MSG_rs_after_noninteractive='Once it is done and checked, the command to look up the latest
version is printed; nothing is upgraded automatically.'

MSG_rs_after_same_version='Once it is done and checked, the latest version is looked up and you
are asked whether to upgrade.'

MSG_rs_after_newer_engine='Once it is done and checked, the latest version is looked up and you
are asked whether to upgrade (%s is already on this host).'

MSG_rs_confirm_version='To confirm, type the version after the restore, %s:'

MSG_rs_confirm_cancel='The entry was not %s; the restore was cancelled.
Nothing has been changed.'

MSG_rs_confirm_new='Start the restore? [y/N] '

MSG_rs_confirm_flags='Replacing this host'\''s data without a version prompt requires both
--yes and --confirm-data-loss.'

MSG_rs_confirm_new_flags='Without a terminal, use --yes to confirm the restore.'

MSG_rs_preview_space_new='needs %s GB; %s GB free on %s'

MSG_rs_kept_no_tls='the current database and audit folders are
renamed and kept, not deleted:'

MSG_rs_control_revert='Going back is under way; finish it first.'

MSG_rs_control_abandon='Giving up on this restore is under way; finish it first.'

MSG_rs_control_engine='Use the management script that started this restore to carry it on.'

MSG_rs_control_placed='The restored data is in place, but the services have to be started by
carrying on, so that the running images and the master key get checked.'

MSG_rs_control_before='The restore has not overwritten data yet. Use --revert to start the
original services.'

MSG_rs_control_unchecked='The restore stopped at step %s and the data has not been checked,
so the services cannot be started.'

MSG_rs_control_choices='Carry on, or go back with the safety backup:'

MSG_rs_control_after_unseal='After the unseal, finish the check:'

MSG_rs_control_previous='The previous restore has not ended; carry on with it, go back, or give
up first.'

MSG_rs_control_own='Follow your registered restore procedure for backup %s:'

MSG_rs_status_title='Restore'

MSG_rs_status_pending='A restore has not finished: %s (started %s, data version %s)'

MSG_rs_status_from='From %s'

MSG_rs_status_resume='To carry on: %s'

MSG_rs_status_failed='The restore stopped at step %s (failed)'

MSG_rs_status_done='Last restore: finished %s, from
%s'

MSG_rs_status_kept='%s folders from before the restore are kept; delete them once
section 6 checks out'

MSG_rs_status_retained='%s folders are kept'

MSG_rs_status_reverted='Last restore: went back on %s'

MSG_rs_status_abandoned='Last restore: given up on %s, back to not installed'

MSG_rs_status_revert='Going back has not finished'

MSG_rs_status_abandon='Giving up on the restore has not finished'

MSG_menu_rs_state='Status: a restore has not finished (%s; data version %s)'

MSG_menu_rs_state_revert='Status: going back has not finished'

MSG_menu_rs_state_abandon='Status: giving up on the restore has not finished'

MSG_menu_rs_resume='Carry on with the restore'

MSG_menu_rs_unseal='Carry on with the restore (finish the check after unseal)'

MSG_menu_rs_revert='Go back with the safety backup'

MSG_menu_rs_abandon='Give up on this restore and return to not installed'

MSG_menu_rs_finish_revert='Finish going back'

MSG_menu_rs_finish_abandon='Finish giving up on the restore'

MSG_rs_control_upgrade='A restore has not finished (%s; started %s), so the system cannot be
upgraded.'

MSG_rs_control_backup='A restore has not finished (%s; started %s), so the system cannot be
backed up.'

MSG_rs_control_rollback='A restore has not finished (%s; started %s), so the system cannot be
rolled back.'

MSG_rs_phase_checked='checked, waiting to prepare the release'

MSG_rs_phase_prepared='release ready, waiting for the safety backup'

MSG_rs_phase_safety='safety backup ready'

MSG_rs_phase_stopped='services stopped'

MSG_rs_phase_swapped='original data kept, waiting to import'

MSG_rs_phase_imported='imported, waiting to check the data'

MSG_rs_phase_db_checked='database checked, waiting to put back the files'

MSG_rs_phase_placed='data in place, waiting for the restore to start services'

MSG_rs_phase_started='services started, waiting for readiness and the key check'

MSG_rs_phase_awaiting_unseal='imported, waiting for unseal to check
the master key'

MSG_rs_phase_done='checked and finished'

MSG_rs_control_choices_new='Carry on, or give up on this restore:'

# 1 arguments
MSG_rs_safety_reason_fingerprint='a single master key ID cannot be read from the current database (%s were
found), and such a backup has no master key fingerprint.'

# 0 arguments
MSG_rs_safety_reason_hsm='the current master key mode is hsm.'

# 0 arguments
MSG_rs_safety_reason_key='the master key fingerprint in the settings differs from the database.'

# 1 arguments
MSG_rs_safety_reason_secret='the settings lack a required key: %s.'

# 1 arguments
MSG_rs_safety_reason_engine='this script is older than the current version. Use %s.'

# 1 arguments
MSG_rs_safety_reason_old='the current version, %s, is older than 1.16.0; its backups require
restoring by hand.'

# 1 arguments
MSG_rs_safety_reason_manifest='the release manifest is missing or differs from current/MANIFEST.json:
%s'

# 1 arguments
MSG_rs_safety_reason_images='images for the current version are missing locally: %s.
Use load with that version'\''s offline image bundle first.'

# 0 arguments
MSG_rs_safety_preflight_warn='A safety backup the script takes of this host could not be restored
automatically with restore --revert:'

# 0 arguments
MSG_rs_safety_preflight_own='So this time the safety backup has to be one you take yourself after the
services stop (a storage snapshot, for example).
The services have not been stopped; nothing has been changed.'

# 1 arguments
MSG_rs_safety_preflight_fail='A safety backup the script takes of this host could not be restored
automatically (%s). Without a terminal, register a backup of your own
taken after the services stop with --backup-ref, --backup-time and
--backup-restore.'

# 0 arguments
MSG_rs_safety_choose_title='The restore overwrites this host'\''s data, so the current data is
backed up first.'

# 0 arguments
MSG_rs_safety_choose_again='The last safety backup did not finish. How should the current data
be backed up this time?'

# 1 arguments
MSG_rs_safety_choose_script='[1] The script backs it up (default): after stopping the services it
    backs up the database, audit files, settings and certificates,
    about %s minutes, without recordings (the restore does not touch
    them)'

# 1 arguments
MSG_rs_safety_choose_retry='[1] The script backs it up again (default): after stopping the services
    it backs up the database, audit files, settings and certificates,
    about %s minutes, without recordings (the restore does not touch
    them)'

# 0 arguments
MSG_rs_safety_choose_own='[2] I will back it up myself once the services are stopped (a storage
    snapshot, for example) and then enter what identifies it'

# 0 arguments
MSG_rs_safety_choose_prompt='Choose [1-2], or press Enter for the default: '

# 0 arguments
MSG_rs_safety_choose_only='Choose [2]: '

# 0 arguments
MSG_rs_safety_id='id'

# 0 arguments
MSG_rs_safety_time='time'

# 0 arguments
MSG_rs_safety_procedure='procedure'

# 0 arguments
MSG_rs_safety_failed_title='3/10  Safety backup'

# 0 arguments
MSG_rs_safety_failed_write='Writing to the backup location failed (No space left on device).'

# 0 arguments
MSG_rs_safety_failed_read='The safety backup did not check out when read back and cannot be
restored from'

# 1 arguments
MSG_rs_safety_failed_unusable='The safety backup is whole, but this script cannot restore from it
automatically (%s)'

# 0 arguments
MSG_rs_safety_failed_body='The safety backup before the restore did not finish, so nothing will be
overwritten. No data has changed; the services stay stopped.'

# 0 arguments
MSG_rs_safety_resume='Once that is dealt with, carry on from the safety backup:'

# 0 arguments
MSG_rs_safety_resume_own='Carry on with a backup of your own:'

# 0 arguments
MSG_rs_safety_revert='Or give up and start the original services:'

# 0 arguments
MSG_rs_safety_use_own='You can also use a backup of your own taken after the services stopped:
choose [2] when carrying on at the terminal, or add the three options to
the command that carries on:'

# 1 arguments
MSG_rs_safety_stop_time='The backup has to be no older than %s, when this restore
stopped the services.'

# 0 arguments
MSG_rs_safety_restarted='The services are running, have been started since the recorded stop,
or their stop cannot be verified. Use restore --revert and start again.'

# 0 arguments
MSG_rs_safety_flags_phase='The three own-backup options are only accepted while the restore is
waiting for its safety backup, before any data is overwritten.'

# 0 arguments
MSG_rs_safety_enter='When the snapshot is done, enter (this goes into the restore record):'

# 0 arguments
MSG_rs_safety_setup_failed='The safety backup folder could not be created.'

# 0 arguments
MSG_rs_safety_failed_operation='The safety backup could not be written. See the restore log for details.'

MSG_rs_safety_reason_fingerprint_short='a single master key ID cannot be read from the current database'

MSG_rs_journal_uncertain='Cannot determine whether the restore operation finished: %s.'

MSG_rs_journal_guide='Stop here. See the manual restore instructions in the backup and restore
guide before changing these paths.'

MSG_rs_journal_missing='The restore has started overwriting data, but its operation journal
is missing. Use --revert to restore the safety backup.'

MSG_rs_import_start='The database service could not be started.'

MSG_rs_import_ready='The database did not become ready for a TCP connection to the target
database.'

MSG_rs_import_encoding='The database encoding, collation or character classification differs
from the backup. Import has stopped.'

MSG_rs_import_failed='The database import failed. Carry on to keep the partial database
and import again into an empty database.'

# ---------- main menu: restore items and the backup file picker; recordings after a restore ----------
# 0 arguments
MSG_menu_restore_new='Restore a backup file onto this new host (installs the backup'\''s
version first)'

# 0 arguments
MSG_menu_restore='Restore from a backup file (replaces this host'\''s data; stops
the service)'

# 2 arguments: the backups folder, the current folder
MSG_menu_restore_found='Restore from a backup file. Backup files found in %s
and in the current directory %s:'

# 2 arguments: the backups folder, the current folder
MSG_menu_restore_none='Restore from a backup file. No backup file found in %s
or in the current directory %s.'

# 0 arguments
MSG_menu_restore_encrypted=' (encrypted)'

# 0 arguments
MSG_menu_ask_restore='Backup file path, or press Enter for the main menu > '

# 1 argument: the number of files
MSG_rs_rec_put_back='Recordings: %s files put back from the backup; existing files
with the same name are kept, not overwritten'

# 0 arguments
MSG_rs_rec_same_kept='The recordings were not restored from the backup: it has none,
and the recordings already here stay where they are. They may not
match the backup'\''s point in time: recordings made after the backup
stay on disk but the system no longer lists them, and recordings
cleared after the backup do not come back.'

# 0 arguments
MSG_rs_rec_all_here='Recordings: every recording the system knows about has its file
on this host'

# 3 arguments: how many, the list file, the recordings folder of the source host
MSG_rs_rec_missing='The recordings were not restored from the backup: %s of the
recordings the system knows about have no file on this host.
The list is in
%s;
copy them over from %s on the source
host.'

# 0 arguments
MSG_rs_rec_offsite='Recordings already uploaded to offsite storage are fetched from
there when played.'

# ---------- restore: the external database, checked before anything stops ----------
# 0 arguments
MSG_rs_ext_refused='The external database cannot be restored yet, because:'
# 4 arguments: count, database, sources, applications
MSG_rs_ext_conns='%s other connections are using %s (from %s, application
%s). Stop the services on the original host first,
and make sure no standby host has taken this database over.'
# 3 arguments: database, source, application
MSG_rs_ext_conns_one='1 other connection is using %s (from %s, application
%s). Stop the services on the original host first,
and make sure no standby host has taken this database over.'
# 0 arguments
MSG_rs_ext_from_local='a local socket'
# 4 arguments: object, its owner, DB_USER, DB_USER
MSG_rs_ext_owner='The object %s is owned by %s, not %s;
the script can only empty objects that %s owns.'
# 1 argument: DB_USER
MSG_rs_ext_owner_more='More objects are owned by roles other than %s.'
# 2 arguments: server version, client majors
MSG_rs_ext_no_client='The server runs PostgreSQL %s, which has no client here; this
release carries clients for PostgreSQL %s.'
# 2 arguments: server version, the server major of the backup
MSG_rs_ext_server_old='The server runs PostgreSQL %s, older than the PostgreSQL %s the
backup was taken from.'
# 2 arguments: client major, the tool that made the dump
MSG_rs_ext_client_old='The PostgreSQL %s client of this release is older than the tool
that made the backup (%s).'
# 2 arguments: DB_USER, DB_NAME
MSG_rs_ext_not_owner='%s does not own the database %s; rebuilding schema public needs
the owner of the database.'
# 1 argument: the extensions
MSG_rs_ext_extension='The database has extensions other than plpgsql (%s); the script
neither empties nor restores extensions.'
# 3 arguments: encoding, collation, character type
MSG_rs_ext_encoding='The database'"'"'s encoding or collation differs from the backup'"'"'s.
Create the database with the same settings:
ENCODING '"'"'%s'"'"' LC_COLLATE '"'"'%s'"'"' LC_CTYPE '"'"'%s'"'"''
# 2 arguments: host:port, log file
MSG_rs_ext_unreachable='Cannot reach the external database %s, or the login failed;
the reason is in %s.'
# 2 arguments: the check now, the check the backup recorded
MSG_rs_ext_tls_lower='The server certificate would be checked less than when the backup
was taken (now %s, at the backup %s).'
# 1 argument: path
MSG_rs_ext_ca_conflict='The CA file goes to %s, where a file with other
content already is; move it away first.'
# 0 arguments
MSG_rs_ext_client_missing='The backup'"'"'s database connection uses a client certificate: give
the certificate and its private key with --db-client-cert and
--db-client-key.'
# 1 argument: path
MSG_rs_ext_client_unreadable='%s cannot be read.'
# 1 argument: path
MSG_rs_ext_client_conflict='%s already holds a file with other content; move it away
first, or name that same file.'
# 2 arguments: client major, release
MSG_rs_ext_no_image='This host does not have the PostgreSQL %s client image (shipped
with %s), which the restore needs; load the offline image bundle
of this release first.'
# 0 arguments
MSG_rs_ext_ask_cert='Client certificate file > '
# 0 arguments
MSG_rs_ext_ask_key='Client private key file > '
# 2 arguments: count, roles
MSG_rs_ext_roles_missing='The target database server lacks %s roles the backup grants rights
to: %s.
Create them first, or add --accept-grant-loss to skip their grants.'
# 1 argument: the role
MSG_rs_ext_roles_missing_one='The target database server lacks 1 role the backup grants rights
to: %s.
Create it first, or add --accept-grant-loss to skip its grants.'
# 0 arguments
MSG_rs_ext_step_stop='Stop the services (the external database is not affected)'
# 0 arguments
MSG_rs_ext_step_quiet='Make sure no other connection is open'
# 4 arguments: count, database, sources, applications
MSG_rs_ext_still=':
once they stopped, %s other connections are still using
%s (from %s, application %s).'
# 3 arguments: database, source, application
MSG_rs_ext_still_one=':
once they stopped, 1 other connection is still using
%s (from %s, application %s).'
# 1 argument: step
MSG_rs_ext_stopped_at='The restore stopped at step %s. Nothing has been overwritten; the
services stay stopped.'
# 0 arguments
MSG_rs_ext_end_conn='Find and end that connection (make sure no standby host has taken
over), then carry on:'

# Imported data checks and recovery instructions.
# 1 arguments
MSG_rs_db_check_migrations='Check the database: the migrations after the import differ
       from the backup'\''s (%s)'
# 2 arguments
MSG_rs_db_extra='%s extra: %s'
# 2 arguments
MSG_rs_db_missing='%s missing: %s'
# 3 arguments
MSG_rs_db_check_counts='Check the database: %s row count differs (imported %s, backup %s)'
# 2 arguments
MSG_rs_db_check_kek='Check the database: active master key IDs differ
       (imported %s, backup %s)'
# 0 arguments
MSG_rs_db_check_read='Check the database: the imported data could not be read'
# 1 arguments
MSG_rs_failure_stopped='The restore stopped at step %s. The services stay stopped; nothing was
undone automatically.'
# 1 arguments
MSG_rs_failure_running='The restore stopped at step %s; some or all services may be running;
the restore has not been checked.'
# 1 arguments
MSG_rs_failure_unknown='The restore stopped at step %s; the service state could not be read.'
# 0 arguments
MSG_rs_failure_no_safety='This host had no data before, so there is no safety backup.'
# 0 arguments
MSG_rs_failure_uncovered='No data has been overwritten yet.'
# 3 arguments
MSG_rs_failure_kept='The data from before the restore is renamed and kept in
%s and %s more
places; the safety backup
%s checked as
restorable.'
# 1 arguments
MSG_rs_failure_resume='Once the cause is fixed, carry on from step %s:'
# 0 arguments
MSG_rs_failure_revert='Or go back with the safety backup:'
# 0 arguments
MSG_rs_failure_abandon='Or give up on this restore and return to not installed (what it put in
place is renamed and kept, not deleted):'
# 3 arguments
MSG_rs_failure_own='Or go back with your recorded procedure: %s (backup %s, %s)'
# 1 arguments
MSG_rs_failure_plaintext='The working folder %s holds the
database and settings in plaintext; it is cleared once the restore
finishes or goes back.'
# 1 arguments
MSG_rs_failure_log='Log file %s'

# Startup and runtime master-key checks.
# 1 arguments
MSG_rs_unseal_wait='The data is imported and the services are started; waiting for
unseal to check the master key (%s)'
# 0 arguments
MSG_rs_unseal_ui='The restore is not finished yet. The master key is entered in the
browser: someone signs in on the unseal page with an administrator
account from the backup, then enters the master key:'
# 0 arguments
MSG_rs_unseal_kms='The restore is not finished yet. The master key is held by a key
management service: sign in on the unseal page with an administrator
account from the backup, check the service shown (its settings came
with the database), and provide its credentials again. This host'\''s
address has to be allowed by that service:'
# 1 arguments
MSG_rs_unseal_fingerprint='Its fingerprint has to be %s.'
# 0 arguments
MSG_rs_unseal_finish='After the unseal, run the command below to finish the check; until then
the system cannot be upgraded or backed up:'
# 0 arguments
MSG_rs_unseal_still='The system is still sealed, so the restore cannot finish yet.
Nothing was changed.'
# 1 arguments
MSG_rs_unseal_again='Unseal it at %s, then run this again:'
# 0 arguments
MSG_rs_unseal_unreadable='The seal state or the runtime master key ID could not be read.
The restore has not been checked. Check status, then carry on:'
# 2 arguments
MSG_rs_runtime_mismatch='The master key does not match: the ID read after unseal is
%s, and the backup recorded %s.'
# 0 arguments
MSG_rs_runtime_stopped='The services have been stopped; the restore is not finished.'
# 0 arguments
MSG_rs_runtime_guide='Check the key inventory as item 6 of section 6 of "Backup and Restore"
describes, then decide.'
# 0 arguments
MSG_rs_runtime_resume='Carry on: the services start again, and once someone unseals with the
right master key the check runs again'
# 0 arguments
MSG_rs_runtime_resume_env='Carry on: the master key in the settings file is checked again first;
if it still does not match, the services are not started'
# 1 arguments
MSG_rs_ready_timeout='Start the services and wait until ready: not ready within
       %s seconds'
# 0 arguments
MSG_rs_ready_body='The restore is not finished. The services are started, but the backend
has not reported ready, so users may not be able to connect yet.'
# 0 arguments
MSG_rs_ready_status='Check the status:'
# 0 arguments
MSG_rs_ready_resume='Once that is dealt with, carry on (it checks that the services are
running, then waits):'
# 1 argument
MSG_rs_runtime_match='Master key: the ID read after unseal, %s, matches
the backup'
# 1 argument
MSG_rs_restore_done='Restore done (%s)'
# 1 argument
MSG_rs_resume_original='The original backup is required at %s, with the same file checksum.'
# 1 argument
MSG_rs_resume_changed='The restore working files have changed: %s. Carrying on was stopped.'
# 1 arguments
MSG_rs_interrupted_stopped='The restore was interrupted at step %s; the tool processes it started
have been stopped. The services stay stopped; nothing was undone
automatically.'
# 1 arguments
MSG_rs_interrupted_running='The restore was interrupted at step %s; the tool processes it started
have been stopped. Some or all services may be running; the restore
has not been checked.'
# 1 arguments
MSG_rs_interrupted_unknown='The restore was interrupted at step %s; the tool processes it started
have been stopped. The service state could not be read.'
# 0 arguments
MSG_rs_revert_start_failed='The original services did not report ready. Going back has not
finished; fix the cause, then run --revert again:'
# 1 arguments
MSG_rs_revert_done='Back on the safety backup (%s)'
# 1 argument
MSG_rs_revert_original_done='The original services are running again (%s).'

# Restore recovery and exit confirmation.
# 0 arguments
MSG_rs_exit_yes='Without a terminal, use --yes to confirm this action.'
# 1 arguments
MSG_rs_exit_confirm_original='Nothing has been overwritten yet. This clears the record of this restore
and starts the original services on %s. Go on? [y/N] '
# 0 arguments
MSG_rs_exit_cancelled='The action was cancelled.'
# 0 arguments
MSG_rs_revert_title='Go back with the safety backup (nothing has been changed yet)'
# 3 arguments
MSG_rs_revert_details='Safety backup  %s
               %s, checked restorable before the restore
Back to        %s, as it was before this restore started'
# 2 arguments
MSG_rs_revert_partial='Unfinished     what this restore put in place is renamed and kept, not
               deleted:
               %s
               and %s more places'
# 1 arguments
MSG_rs_revert_downtime='Downtime       about %s minutes'
# 1 arguments
MSG_rs_revert_confirm_version='To confirm, type the version, %s:'
# 1 arguments
MSG_rs_exit_wrong='--%s is not available for this kind of restore.'
# 0 arguments
MSG_rs_no_pending='There is no unfinished restore.'
# 1 arguments
MSG_rs_revert_finished='The last restore finished (%s); --revert only handles
a restore that has not finished.'
# 0 arguments
MSG_rs_revert_fresh='To get the data from before it back, restore the safety backup it took.
That is a new restore, and it takes a safety backup of the current data
first:'

# Restore completion.
# 1 arguments
MSG_rs_finish_title='Restore done; the service is back (%s)'
# 2 arguments
MSG_rs_finish_from='From         %s (%s)'
# 1 arguments
MSG_rs_finish_address='Address      %s'
# 1 arguments
MSG_rs_finish_key_env='Master key   in the settings file; the ID read after unseal,
             %s, matches the backup'
# 1 arguments
MSG_rs_finish_key_ui='Master key   entered in the browser; the ID read after unseal,
             %s, matches the backup'
# 1 arguments
MSG_rs_finish_key_kms='Master key   held by a key service; the ID read after unseal,
             %s, matches the backup'
# 3 arguments
MSG_rs_finish_kept='Kept         the data from before the restore is renamed and kept in
             %s
             and %s more places; safety backup
             %s.
             Once section 6 checks out, delete the kept folders yourself.'
# 3 arguments
MSG_rs_finish_kept_own='Kept         %s and %s more places;
             your backup: %s.'
# 1 arguments
MSG_rs_finish_oidc='The public address is now %s. If an external
sign-in (OIDC) is connected, update the callback address at the
identity provider.'
# 0 arguments
MSG_rs_finish_checklist='Go through section 6 of "Backup and Restore" item by item before
handing the system to users.'
# 1 arguments
MSG_rs_upgrade_existing='%s is already on this host and can be upgraded to:'
# 1 arguments
MSG_rs_upgrade_before='Back on the version from before the upgrade (%s). To upgrade later:'
# 0 arguments
MSG_rs_upgrade_later='To look up the latest version and upgrade later:'
# 0 arguments
MSG_rs_upgrade_lookup='Looking up the latest version:'
# 0 arguments
MSG_rs_upgrade_unknown='The latest version could not be confirmed.'
# 0 arguments
MSG_rs_upgrade_lookup_later='To look up the latest version later:'
# 1 arguments
MSG_rs_upgrade_ask='Upgrade to %s now? The upgrade takes a backup with the
services stopped, then switches version. [y/N] '
# 0 arguments
MSG_rs_upgrade_declined='To upgrade later:'
# 1 arguments
MSG_rs_upgrade_current='%s is the latest version'

# Giving up an unfinished new-host restore.
# 0 arguments
MSG_rs_abandon_title='Give up on this restore (this host goes back to not installed)'
# 1 arguments
MSG_rs_abandon_services='Services       the services this restore started are stopped first
               (%s running now); nothing else happens until they are'
# 0 arguments
MSG_rs_abandon_stopped='Services       none running'
# 0 arguments
MSG_rs_abandon_kept='Renamed, kept  what this restore put in place is renamed and kept, not
               deleted:'
# 1 arguments
MSG_rs_abandon_path='               %s'
# 0 arguments
MSG_rs_abandon_old_env='               the .env left by an earlier failed install is put back'
# 1 arguments
MSG_rs_abandon_old_template='               %s: the file that was there is put back'
# 3 arguments
MSG_rs_abandon_tail='Not touched    the recordings folder %s: it
               may hold files this restore put back and files you copied
               in yourself; none are deleted
Version        current points back to %s; releases/%s is kept
Working files  the plaintext database and settings in the working
               folder are deleted'
# 0 arguments
MSG_rs_exit_confirm_abandon='Give up? [y/N] '
# 0 arguments
MSG_rs_abandon_done='The restore is given up; this host is back to not installed. Delete
the renamed folders yourself once you are sure they are not needed.'
# 0 arguments
MSG_rs_abandon_stop_failed='The services could not all be stopped. Nothing has been renamed.
Fix the cause and run --abandon again:'

# 1 argument
MSG_rs_failure_new_stopped='The restore stopped at step %s. The services were not started; nothing
was undone automatically.'

# ---------- restore: the external database, roles the server lacks ----------
# 2 arguments: count, the role names (one per line, indented)
MSG_rs_ext_roles_ask='The backup grants rights to the %s roles below, and the target
database server does not have them:
%s
If you skip them, only the grants to these roles are left out;
everything else is restored.'
# 1 argument: the role name (indented)
MSG_rs_ext_roles_ask_one='The backup grants rights to the 1 role below, and the target
database server does not have it:
%s
If you skip it, only the grants to this role are left out;
everything else is restored.'
# 0 arguments
MSG_rs_ext_roles_create='[1] Create these roles first (default; ends the restore with nothing
    changed)'
# 0 arguments
MSG_rs_ext_roles_create_one='[1] Create this role first (default; ends the restore with nothing
    changed)'
# 0 arguments
MSG_rs_ext_roles_skip='[2] Skip the grants to these roles and go on'
# 0 arguments
MSG_rs_ext_roles_skip_one='[2] Skip the grants to this role and go on'
# 0 arguments
MSG_rs_ext_grants_unsure='Some grant statements cannot be told apart from the ones for the
missing roles, so the script cannot skip just those.
Create the roles on the server first, then restore.'
# 1 argument: count
MSG_rs_ext_skipped_row='the grants to these %s roles are not restored'
# 0 arguments
MSG_rs_ext_skipped_row_one='the grants to this role are not restored'
# 0 arguments
MSG_rs_label_skipped='  Skipped grants '

# Restore execution progress and database client diagnostics.
MSG_rs_space_join='%s and %s'
MSG_rs_space_short_row='%s (%s) needs %s GB, has %s GB'
MSG_rs_progress_release_same='Put %s and its images in place'
MSG_rs_progress_release_new='Install %s: put the release and its images in place'
MSG_rs_progress_stop='Stop the services (database keeps running)'
MSG_rs_progress_safety='Safety backup %s'
MSG_rs_progress_own='Backup of your own %s (%s)'
MSG_rs_progress_verify='Check the safety backup can be restored'
MSG_rs_progress_swap='Stop the database; rename and keep the current data'
MSG_rs_progress_settings='Write the settings file (from the backup, host values for
this host)'
MSG_rs_progress_import='Import the database'
MSG_rs_progress_check='Check the database: %s migrations, row counts and master
key ID match the backup'
MSG_rs_progress_files_same='Put back audit files, certificates and settings'
MSG_rs_progress_files_new='Put back audit files and certificates'
MSG_rs_progress_files_new_reissue='Put back audit files and certificates; issue a server
certificate for this host'\''s address'
MSG_rs_progress_start_same='Start the services and wait until ready: the backend
reports %s'
MSG_rs_progress_start_new='Start the services and check the running images'
MSG_rs_progress_ready='Wait until ready: the backend reports %s'
MSG_rs_progress_key_wait='Master key: to be checked after unseal'
MSG_rs_import_error='pg_restore reported an error (the full message is in the log).'
MSG_rs_import_error_detail='pg_restore reported an error (the full message is in the log):'

# ---------- restore: the external database, emptied and imported in one transaction ----------
# 0 arguments
MSG_rs_ext_step_import='Empty and import the database (one transaction)'
# 1 argument: the log file
MSG_rs_ext_import_unreachable='The external database cannot be reached; the import has not
started. The reason is in %s.'
# 1 argument: the log file
MSG_rs_ext_import_make='The SQL for the import could not be made or checked; no transaction
was opened and the external database was not touched. The reason is
in %s.'
# 0 arguments
MSG_rs_ext_import_rolled_back='The database import failed. The emptying and the import were rolled
back as a whole; the external database is as it was.'
# 0 arguments
MSG_rs_ext_import_unknown='Whether the import was committed cannot be told. Carrying on checks
the external database first, then imports again or goes on.'
# 2 arguments: the digest before the import, the digest now
MSG_rs_ext_import_unknown_stop='The external database is neither as it was before the import nor
as a finished import leaves it, so whether the last import was
committed cannot be told; it is not imported again.
  Before the import: %s
  Now:               %s'

# ---------- restore: reading the backup, the data release's database tool image ----------
# 1 argument: the data release
MSG_rs_no_dbtool='The database tool image of release %s is not on this host.
Restore needs it to read the backup; load that release'\''s offline
image bundle first.'

# ---------- restore: a new host's external database, exported before it is emptied ----------
# 0 arguments
MSG_rs_ext_step_export='Export the current external database as the safety backup'
# 1 argument: the log file
MSG_rs_ext_export_failed='The external database could not be exported and read back in full;
it has not been changed. The reason is in %s.'
# 1 argument: the export file
MSG_rs_ext_revert_confirm='Put the external database back from %s and give up
this restore? [y/N] '
# 1 argument: the export file
MSG_rs_ext_revert_failed='The external database could not be put back as it was exported;
%s is kept. Run the same command again:'
# 0 arguments
MSG_rs_ext_revert_done='The external database is back as it was exported before the
restore; the restore is given up.'

# ---------- restore: the external database in the preview, the steps, a failure and giving up ----------
# 0 arguments
MSG_rs_label_database='  Database       '
# 2 arguments: the certificate setup, the master key mode
MSG_rs_deployment_external='external database; %s; master key:
%s'
# 3 arguments: host:port, database, server version
MSG_rs_ext_preview_server='external %s/%s
(PostgreSQL %s)'
# 2 arguments: client major, the management script's release
MSG_rs_ext_preview_tool='Import tool: PostgreSQL %s client (shipped with %s,
verified)'
# 1 argument each: the sslmode in effect
MSG_rs_ext_conn_full_system='Connection: %s, server checked against the
system'\''s trusted certificate authorities'
MSG_rs_ext_conn_full_file='Connection: %s, server checked against the CA
file from the backup'
MSG_rs_ext_conn_ca_system='Connection: %s, server certificate checked against
the system'\''s trusted certificate authorities, host name
not checked'
MSG_rs_ext_conn_ca_file='Connection: %s, server certificate checked against
the CA file from the backup, host name not checked'
MSG_rs_ext_conn_none_none='Connection: %s, server certificate not checked'
MSG_rs_ext_conn_none_file='Connection: %s, server certificate not checked'
# 1 argument: DB_USER
MSG_rs_ext_preview_rights='Rights: %s owns this database and everything in
it; no other connections'
# 4 arguments: DB_USER, count, sources, applications
MSG_rs_ext_preview_rights_listed='Rights: %s owns this database and everything in
it; %s other connections now (from %s, application
%s), checked again once the services stop'
# 2 arguments: count, schema (zh-TW and ja: schema, count)
MSG_rs_ext_objects='the %s objects in schema %s'
# 1 argument: the objects of each schema
MSG_rs_ext_preview_emptied='Emptied: %s, in the same
transaction as the import; on failure all of it is
rolled back and the database stays as it was. Other
databases, roles and tablespaces are not touched.'
# 0 arguments
MSG_rs_ext_preview_empty='The target database is empty; nothing needs emptying'
# 1 argument: the export file
MSG_rs_ext_preview_export='the current database is first exported to
%s,
read back in full and checked usable'
# 1 argument: GB
MSG_rs_ext_preview_space='Until the import finishes, the old and new data are both on the
database server, which needs about %s GB free; the script cannot
see the server'\''s disk, so check it first.'
# 0 arguments
MSG_rs_kept_external='the current audit and certificate folders are
renamed and kept, not deleted:'
# 0 arguments
MSG_rs_kept_external_no_tls='the current audit folder is renamed and kept, not
deleted:'
# 1 argument: database
MSG_rs_confirm_db='To confirm, type the name of the database to empty, %s:'
# 0 arguments
MSG_rs_ext_import_error='psql reported an error (the full message is in the log).'
# 0 arguments
MSG_rs_ext_import_error_detail='psql reported an error (the full message is in the log):'
# 0 arguments
MSG_rs_ext_failure_rolled_back='This emptying and import were rolled back as a whole; the external
database is as it was.'
# 1 argument: the export file
MSG_rs_ext_failure_rolled_back_export='This emptying and import were rolled back as a whole; the external
database is as it was. The safety export is in %s.'
# 1 argument: the export file
MSG_rs_ext_failure_unknown_export='Whether the import was committed cannot be told. Carrying on checks
the external database first, then imports again or goes on. The
safety export is in %s.'
# 1 argument: the export file
MSG_rs_ext_failure_committed_export='The import was committed: the external database now holds the
contents of the backup. The safety export is in %s.'
# 1 argument: the export file
MSG_rs_ext_failure_unsent_export='The external database was not changed. The safety export is in %s.'
# 0 arguments
MSG_rs_ext_failure_revert='Or put the safety export back into the external database and give up
on this restore:'
# 0 arguments
MSG_rs_ext_failure_abandon='Or give up on this restore and return to not installed (what it put in
place is renamed and kept, not deleted; the data this restore imported
into the external database is not removed):'
# 0 arguments
MSG_menu_rs_revert_export='Put the safety export back into the external database and give up
on this restore'
# 2 arguments: host:port, database
MSG_rs_ext_abandon_kept='External database  the data this restore imported into
               %s/%s is not removed; have the database
               administrator empty it if needed. A later restore treats
               it as not empty and exports it first'
# 2 arguments: host:port, database
MSG_rs_ext_abandon_maybe='External database  %s/%s may hold data this
               restore imported; it is not removed. Have the database
               administrator empty it if needed'
# 1 argument: the export file
MSG_rs_ext_abandon_export='Safety export  %s
               is kept, not deleted; delete it yourself once it is not
               needed'
# 0 arguments
MSG_rs_ext_abandon_refused='Emptying and importing the external database has started, so the
restore cannot simply be given up. Put the safety export back
(this host then goes back to not installed as well):'
# 2 arguments: count, the list file
MSG_rs_ext_finish_skipped='Skipped      %s grant statements for roles the server lacks were not
             restored; the list is in %s'
# 1 argument: the export file
MSG_rs_ext_finish_export='Export       the safety export (the external database from before
             the restore, in plaintext) is kept in
             %s;
             delete it yourself once section 6 checks out.'

# ---------- status: a failed upgrade that a restore which finished has settled ----------
# 1 argument: when the restore settled it
MSG_status_upgrade_settled='The restore on %s dealt with this failure;
you can upgrade again'
