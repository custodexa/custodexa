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
MSG_compose_explicit_incomplete='Internal error: a compose call without project name, project folder
or compose file was refused.'
MSG_state_bad='The state file %s is damaged at line %s. Nothing was changed.'
MSG_state_bad_prev='The previous copy is %s. Check it, and if it is correct,
restore it with:'
MSG_usage_unknown_command='Unknown command "%s". See: custodexa.sh --help'
MSG_usage_unknown_option='Unknown option "%s". See: custodexa.sh --help'
MSG_usage_missing_value='Option %s needs a value.'
MSG_command_not_in_build='The command "%s" is not part of this build.'
MSG_lock_busy='Another custodexa.sh is running on this deployment (PID %s).
Wait for it to finish.'
MSG_run_interrupted='The last %s run was interrupted at step %s.'
MSG_run_install_rerun='install is safe to repeat; starting over from the first step.'
MSG_run_recover_first='Handle that first. Check the state and the log file:'
MSG_run_recover_install='Finish that first; install is safe to run again:'
MSG_run_load_rerun='load only loads and checks images, so it is safe to run again.'
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
MSG_help_cmd_backup='  backup                 Full backup (pauses the service for ten minutes
                         or more)'
MSG_help_cmd_load='  load <bundle>          Load an offline image bundle (starts nothing)'
MSG_help_options='Options'
MSG_help_opt_yes='  --yes                  Do not ask for confirmation (for automation)'
MSG_help_opt_backup_ref='  --backup-ref <id>      (upgrade) You made your own backup; give the
                         snapshot name and the script makes none'
MSG_help_opt_backup_time='  --backup-time <time>   (upgrade) With --backup-ref: when the snapshot
                         started; must be after the services stopped'
MSG_help_opt_backup_restore='  --backup-restore <doc> (upgrade) With --backup-ref: where the restore
                         procedure is documented'
MSG_help_opt_images='  --images <path>        (install, upgrade) Offline image bundle to use'
MSG_help_opt_lang='  --lang <language>      zh-TW, ja or en; see Language below'
MSG_help_opt_no_color='  --no-color             No colors'
MSG_help_opt_version='  --version              Show the script version'
MSG_help_opt_help='  -h, --help             This help; custodexa.sh <command> --help shows
                         one command'
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
MSG_load_file='  File   %s (%s GB)'
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
MSG_status_legacy='git clone deployment, not converted yet'
MSG_status_legacy_next='The next custodexa.sh upgrade reorganizes the folder first'
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
MSG_bk_pause='The backend, connection service and web pages pause for about
%s minutes (the database keeps running) and start again when the
backup is done.'
MSG_bk_warn_seal='The master key is entered in the browser: after the backup
the system is sealed until someone enters the master key on
the unseal page.'
MSG_bk_size='About %s; %s free where backups go'
MSG_bk_confirm='Start the backup? [y/N]'
MSG_bk_step_stop='Stop the services (database keeps running)'
MSG_bk_step_db='Database'
MSG_bk_step_files='Recordings and audit files'
MSG_bk_step_conf='Settings and certificates'
MSG_bk_step_start='Start the services'
MSG_bk_step_verify='Check the backup can be read'
MSG_bk_done='Backup done: %s (%s)'
MSG_bk_contents='Contains: %s'
MSG_bk_item_sep=', '
MSG_bk_item_db='database'
MSG_bk_item_rec='recordings'
MSG_bk_item_audit='audit files'
MSG_bk_item_env='settings file .env'
MSG_bk_item_env_kek='settings file .env (includes the master key)'
MSG_bk_item_tls='certificates tls/'
MSG_bk_warn_keep='This backup holds sensitive data and sits on the same host
as .env. Encrypt it, store it elsewhere, and keep it apart
from the master key material.'
MSG_bk_warn_sealed='The system is sealed; unseal it at %s'
MSG_bk_log='Log file %s'
MSG_bk_warn_snapshot='Not all four key fingerprints could be read, so this backup
cannot be used to check the keys automatically. After an upgrade,
compare them on the key inventory page. The reason is in snapshot.txt.'
MSG_bk_external_db='This deployment uses an external database, which this script does
not back up. Back it up with your own database procedure, and keep
the data folder, .env and tls/ with it.'
MSG_bk_db_unreachable='Cannot read the database size to estimate the backup space.
Check that the database container is running. Nothing was stopped.'
MSG_bk_no_space='Not enough space for the backup: about %s needed,
%s has %s free. Nothing was stopped.'
MSG_bk_dir_failed='Cannot create a backup folder in %s. Nothing was stopped.'
MSG_bk_failed='The backup did not finish. The files so far are in %s;
the INCOMPLETE file there marks this backup as unusable.'
MSG_bk_start_again='The services may still be stopped. To start them again:'

# ---- own backup (used by upgrade and rollback) ----
MSG_br_title='Backup before the upgrade'
MSG_br_opt1='[1] Let the script make a full backup (recommended)'
MSG_br_opt1_detail='Database, recordings, audit files, settings, certificates.
About %s, roughly %s minutes'
MSG_br_opt2='[2] Use my own backup'
MSG_br_opt2_detail='For example a virtual machine or storage snapshot'
MSG_br_choose='Choose [1/2]: '
MSG_br_chosen='You chose to use your own backup'
MSG_br_times='All audit records were confirmed written at %s and the
services stopped at %s. Take the snapshot now. It must start
after the services stop, and cover the data folder, .env and the
certificates folder in the same restorable backup.'
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
MSG_up_row_installed_legacy='  Installed    %s (git clone deployment, %s)'
MSG_up_row_target_legacy='  Upgrade to   %s'
MSG_up_legacy_intro='  This host still runs a git clone deployment. This is the first
  upgrade with the management script, so the deployment folder is
  reorganized first and the upgrade is then completed.'
MSG_up_confirm='Start the upgrade? [y/N]'
MSG_up_confirm_convert='Start? [y/N]'
MSG_up_yes_needs_target='This host runs a git clone deployment; its first upgrade reorganizes
the deployment folder. With --yes, name the version or the package to
upgrade to, for example:'
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
MSG_up_will_2_external='  2. The database is not part of this deployment, so the script does
     not back it up; after the stop you confirm a backup of your own
     taken after the stop'
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
MSG_up_dev_form='This deployment uses the development compose file (COMPOSE_FILE=%s).
That is not a deployment form; the management script does not
upgrade it'
# ---------- upgrade: waiting for the audit queue ----------
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
MSG_up_bk_db='Database   %s  %s'
MSG_up_bk_files='Recordings and audit files  %s  %s'
MSG_up_unseal_after='The master key is entered in the browser, so unseal once more
after the services start.'
MSG_up_step_convert_skip='Reorganize the folder (not needed)'
MSG_up_step_switch='Switch to %s'
MSG_up_step_start='Start'
MSG_up_step_ready='Wait until ready'
MSG_up_step_check='Check'
MSG_up_step_record='Record'
MSG_up_failed_at='The last upgrade stopped at step %s.'
MSG_up_legacy_compose_unknown='Cannot tell the compose project name or files of %s'
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
MSG_menu_backup='Back up (pauses the service for ten minutes or more)'
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

# upgrade: the first conversion of a git clone deployment (preview, step 8, failure, next run)
MSG_cv_will='What will happen, in order'
MSG_cv_will_1='  1. Wait until all audit records are in the database'
MSG_cv_will_2='  2. Stop the services with the existing
     %s (the database keeps running)'
MSG_cv_will_3='  3. Full backup, about %s; %s free where backups go'
MSG_cv_will_3_external='  3. The database is not part of this deployment: you back it up
     yourself (asked for once the services are stopped)'
MSG_cv_will_4='  4. Remove the old containers (the data in data/ is not touched)
     and reorganize the folder'
MSG_cv_will_5='  5. Switch to %s, start it, check the version, data and keys'
MSG_cv_dir='Folder reorganization'
MSG_cv_stays='  Stays in place   .env, tls/, data/'
MSG_cv_moves='  Moves to         releases/%s/ (the old version, kept)
                   the product files tracked by git, and .git'
MSG_cv_copies='  Copied out       report exports in the old container -> data/exports/'
MSG_cv_env_label='  Setting change   '
MSG_cv_env_indent='                   '
MSG_cv_env_row='.env line %s   %s=%s'
MSG_cv_env_row_raw='.env line %s   %s'
MSG_cv_env_to='                              ->  %s=%s'
MSG_cv_env_to_comment='                              ->  commented out (the new version
                                  uses its built-in template)'
MSG_cv_env_sep=', '
MSG_cv_env_add_1='one new line: %s'
MSG_cv_env_add_2='two new lines: %s'
MSG_cv_env_add_n='%s new lines: %s'
MSG_cv_env_saved='.env is copied aside before the change'
MSG_cv_compose_dropped='COMPOSE_FILE in .env uses %s; the new version does not'
MSG_cv_know_pause='  - Expect %s to %s minutes of downtime'
MSG_cv_know_mig='  - This version changes the database structure. Going back to
    %s means restoring this backup; anything recorded after the
    backup is lost'
MSG_cv_know_manage='  - Afterwards, manage it with %s/custodexa.sh.
    %s is no longer a git folder: do not use git pull'
MSG_cv_step='Reorganize the folder'
MSG_cv_fail='The upgrade stopped at step 8/13 (reorganize the folder):
%s'
MSG_cv_why_env_copy='cannot copy .env to %s'
MSG_cv_why_down='cannot remove the old containers'
MSG_cv_why_exports='cannot copy the report exports out of the old backend container'
MSG_cv_why_move='moving %s failed'
MSG_cv_why_env='cannot rewrite .env'
MSG_cv_why_copy='cannot put %s into releases/'
MSG_cv_why_state='cannot write state.json'
MSG_cv_why_signal='the run was interrupted'
MSG_cv_stopped='The services are stopped'
MSG_cv_dir_same='The folder is not changed yet'
MSG_cv_dir_part='The folder is partly reorganized'
MSG_cv_start_old='Start the old version:'
MSG_cv_revert_title='Run these commands in order to put the git clone layout back. If
any of them fails, stop and hand the log file to operations:'
MSG_cv_revert_check='Check that git lists nothing but backups/ and .custodexa.lock:'
MSG_cv_start_old_after='Only when that check lists nothing else, start the old version:'
MSG_cv_unseal='The master key is entered in the browser, so unseal once more
after it starts.'
MSG_cv_hint='The folder is partly reorganized and the services are stopped.'
MSG_cv_interrupted='The last upgrade was interrupted while reorganizing the folder.'
MSG_cv_no_git='The git command is not on this host, so whether the product files
in %s were edited cannot be told'
MSG_cv_git_failed='git status failed in %s'
MSG_cv_dirty='The git work tree in %s has changes, so
the folder cannot be reorganized. Restore, move away or commit the
items below until git status prints nothing, then run it again:'
MSG_up_restore_guide='To go back to %s, restore the backup above by hand as described
in "Backup and Restore", section 5 "Restore procedure".'
