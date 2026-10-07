# Controlled integration runs

The bats suite (`scripts/custodexa/tests/run.sh`) drives `custodexa.sh` against a fake `docker`
and a fake database dump. That proves the script's decisions, not that a real PostgreSQL export
restores, that real `openssl` builds agree on a ciphertext, or that a real install comes up. The
runs in this folder use the real tools, each scenario on its own throw-away Docker engine.

```
bash scripts/custodexa/tests/integration/run.sh <scenario|group>...   # e.g. smoke, selfcheck
bash scripts/custodexa/tests/integration/run.sh list                  # scenarios and groups
bash scripts/custodexa/tests/integration/run.sh clean [--cache]       # remove everything it left
```

Each scenario prints `ok - ...` lines, then `PASS <scenario>` and exits 0, or `FAIL <scenario>`.
`run.sh` exits non-zero when any scenario failed and ends with the total time.

## What runs where

| Piece | Where | Network |
|---|---|---|
| `run.sh` | this machine (bash 3.2 or later, `docker`, `git`) | yes |
| builder host | `custodexa-it-<run>-build`: makes the package, fills the cache, then removed | yes (registries, GitHub) |
| scenario host | `custodexa-it-<run>-<scenario>`: one per scenario, removed when it ends | **none** (unless its header says `network: bridge`) |
| two-host scenario | `custodexa-it-<run>-<scenario>-<name>` per name of its `hosts:` line, sharing only the volume `custodexa-it-<run>-<scenario>-transfer`; removed when it ends | **none**, also between them |

Both hosts are privileged containers of `host.Dockerfile` (`docker:29-dind`, pinned by digest,
plus bash, GNU coreutils and tar, jq, ss). Their engine listens on its unix socket only: no TCP
port, nothing published to this machine. Everything a scenario starts (the deployment, database
servers, tool containers) lives inside its host and goes away with it; servers that publish a
port bind `127.0.0.1` of that host. The working tree is mounted read-only at `/src`.

On this machine a run creates only containers and volumes named `custodexa-it-*` with the label
`org.custodexa.integration=1`, removed at exit (also on Ctrl-C), and the images it builds:
`custodexa-it-host:1`, `custodexa-it-openssl111:1`, `-openssl30:1`, `-openssl32:1` and `custodexa-it-testimage:1` (the bats
runner's `../Dockerfile` under its own tag, so the bats tag `custodexa-script-test:1` is never
rebuilt from here; the shared layer cache gives it the same OpenSSL). `run.sh clean` removes any
leftover containers and volumes; `--cache` also removes the cache folder and those images.
Nothing touches the dev compose project.

## The package

The builder runs `scripts/release/build-package.sh` from the working tree, with:

- source: the files `git ls-files -co --exclude-standard` lists (tracked and untracked, not
  ignored), less the files a release leaves out and the release tooling the script refuses
  in a source tree; so uncommitted changes are in the package;
- images: those of the published release `CX_IT_VERSION` (default `1.15.2`), read from its
  `MANIFEST.json` on GitHub and checked against its `SHA256SUMS`. The backend then reports that
  version, which is what install's readiness check compares. The run stops if the package's
  image list differs from the release's (the PostgreSQL client tool images aside: a release
  before them does not list them).

The offline bundle comes from `build-package.sh offline` and is cached under the hash of the
image list (it holds images only); `CX_IT_REBUILD_BUNDLE=1` rebuilds it. Scenario hosts have no
network, so installs take their images from that bundle (`install --images`), as an offline site
does. A scenario whose header says `network: bridge` (`upgrade-external`, for its online upgrade)
gets a host on Docker's default bridge: what it pulls comes from the registries the release names.

### Versions built from the working tree

Going back to the version before an upgrade needs two versions that both support it, and no
published release is one yet. A scenario whose header says `needs: package local-versions` gets
three versions the builder makes from the working tree (`lib/localver.sh`), with version numbers no
release takes:

| Version | Made from |
|---|---|
| `1.16.90` | the working tree |
| `1.16.91` | the same source; only the version differs, so the migrations are the same |
| `1.16.92` | the working tree with `fixtures/rollback-probe-migration.patch` applied to a copy: one more migration, `it_rollback_probe`, that changes nothing. When `migrations.go` moves on and the patch no longer applies, the build stops and names it |

For each, the builder builds the backend and frontend images from `docker/<component>/Dockerfile`
(target `production`; the backend with the build argument `VERSION`, so it reports that version),
then makes the install package and the offline bundle with `build-package.sh` and
`build-package.sh offline`, unchanged. The images are only on the builder, tagged
`ghcr.io/custodexa-it/<component>:<version>`: the registry index and manifest `build-package.sh`
reads for them are written by the builder (the index lists the image built here under both
architectures; only this architecture is installed), and the offline mode's `pull`, `tag` and
`image rm` of them are answered by a `docker` wrapper first on its `PATH`. The scenario host gets
`/it-run/pkg-<version>/` and `/bundle-<version>` for each, and `/it-run/local-versions` lists them.
The images are kept in `local-versions/` of the cache under a hash of what goes into them (the
backend, the frontend, their Dockerfiles, the patch), so later runs load them instead of building
(the first build takes several minutes). `run.sh` records `git status --porcelain` of the working
tree before and after the builder (`/it-run/worktree-status.before`, `.after`).

Registry manifests that `build-package.sh` reads are cached by digest (the cached bytes must hash
to the digest), so repeated runs do not hit Docker Hub's anonymous limits.

## Cache

`CX_IT_CACHE` (default `${XDG_CACHE_HOME:-~/.cache}/custodexa-it`):

| Path | Holds |
|---|---|
| `release/<version>/` | the release's `MANIFEST.json` and `SHA256SUMS` |
| `registry/` | registry manifests by digest |
| `images/<key>-<arch>-<id>.tar` | the images of `images.txt` |
| `local-versions/<version>-<arch>-<hash>.tar` | the images built from the working tree |
| `bundles/<version>-<arch>-<hash>/` | offline bundle and its `SHA256SUMS` |
| `published/<version>-<arch>/` | a release's published package and offline bundle, with their lines of its `SHA256SUMS` |
| `runs/<run>/` | the package of that run (`pkg/`) and one log per scenario |

The first run downloads about 1.3 GB (offline bundle and database images); later runs reuse it.

## Writing a scenario

A scenario is `scenarios/<name>.sh` defining `scenario()`; errexit ends it at the first failing
command. Header lines that `run.sh` reads:

```
# about: one line for `run.sh list`
# needs: package          the run builds the package; /it-run/pkg and /bundle are mounted
# needs: package upgrade  also a package of the older release CX_IT_FROM_VERSION (default 1.15.1),
#                         from the same working tree: /it-run/pkg-from and /bundle-from
# needs: package upgrade twice   also the release before that, CX_IT_FROM2_VERSION (default
#                         1.15.0): /it-run/pkg-from2 and /bundle-from2
# needs: package local-versions   also the versions built from the working tree (above):
#                         /it-run/pkg-<version> and /bundle-<version>
# needs: published        the release CX_IT_PUBLISHED_VERSION (default 1.15.2) as published: its own
#                         install package and offline bundle for this architecture, downloaded and
#                         checked against the release's SHA256SUMS, at /published (nothing rebuilt)
# images: pg16 openssl-3.5.4   keys of images.txt, loaded before scenario() runs
# network: bridge         the scenario host can reach the internet (default: none)
# hosts: a b              two scenario hosts instead of one (see "Two hosts" below)
```

Add it to a group in `scenarios/groups.txt` to run it with others. Libraries (in `lib/`), all
loaded for every scenario:

| Library | Functions |
|---|---|
| `common.sh` | `it_check <what> <cmd...>`, `it_expect_fail <what> <regex> <cmd...>`, `it_same <what> <expected> <actual>`, `it_step`, `it_image <key>`, `it_store` |
| `deploy.sh` | `it_unpack <parent> [from]`, `it_env_preset <root> KEY=VALUE...`, `it_cx <root> <args>`, `it_bundle_file [from]`, `it_package_file` |
| `openssl.sh` | `it_openssl <3.5.4\|3.5.7\|1.1.1> <args>` (stdin passed through, `/it/work` at `/work`) |
| `pg.sh` | `it_pg_start <name> <16\|17\|18> [--tls\|--tls-only\|--client-cert]`, `it_pg_sql`, `it_pg_client`, `it_pg_port`, `it_pg_stop`, `it_pki_ca`, `it_pki_cert` |
| `snap.sh` | `it_snap_take <file> <JWT_SECRET> <sql command...>` (the script's own `cx_snap_take` against any database), `it_snap_same <what> <expected> <actual>` |
| `versions.sh` | a built-in deployment that goes between the versions built from the working tree: `lv_install <version>`, `lv_upgrade <version> [exit]`, `lv_cx <label> <args>` (`LV_OUT`, `LV_RC`), `lv_bg` and `lv_signal_at_up` (SIGTERM while the run starts the services), `lv_st <key>`, `lv_version`, `lv_ids_running`, `lv_ps`, `lv_tools_left`, `lv_api <method> <path> [json]` (as the administrator), `lv_sql`, `lv_files_sha`; `LV_INJECT` (test only, a `docker` wrapper first on the script's `PATH`): `recordings-fail` (upgrade step 9 fails), `health-fail` (the readiness question fails), `hold-up` (the start waits for the scenario), `pause-after-up` (the started backend is paused), `hold-after-up`, `restore-place-fail`, `restore-check-fail`, `hold-import` and `hold-swap` (a restore held or failed at one of its stages; the file says where) |
| `restore.sh` | the restore of a deployment of `versions.sh`: `ri_data <label>`, `ri_has <label>`, `ri_facts <file>` (version, row counts, migrations, a hash of the sorted `pg_dump --data-only`, every sequence's `last_value`, the grants by `aclexplode`), `ri_same_facts`, `ri_backup <label> [args]` (`RI_FILE`), `ri_snap_same` (the script's own snapshot against a backup's `snapshot.txt`), `ri_kek_id` (from seal/status), `ri_rec_sha`, `ri_running_same`; master key mode ui: `ri_ui_install`, `ri_seal_state`, `ri_is_unsealed`, `ri_unseal <material> [init]` |
| `extrestore.sh` | the restore of an external database deployment of 1.16.90 (`needs: package local-versions`): `xr_install <root> <port>`, `xr_new_host <root>` (unpacked, its bundle loaded), `xr_cx <label> <root> <args>` (`XR_OUT`, `XR_RC`), `xr_digest <server>` (the target digest by the script's own query, `CX_RS_EXT_DIGEST_SQL`), `xr_lines <server>` (the lines that digest hashes), `xr_quiet`, `xr_gone` (the original host's containers removed), `xr_mark`, `xr_snap_same` (the script's snapshot against a backup's, audit rows up to the mark), `xr_rs_dir`; `XR_INJECT` (test only, a `docker` wrapper first on the script's `PATH`; every `docker run` it sees is logged): `body-prefix`, `body-term`, `body-kill`, `body-error`, `grants-fail`, `grants-filter` (the SQL makers of the import), `import-kill`, `import-terminate` (the import's session while it copies `public.it_bulk`), `place-fail` (the stop before the file placement) |
| `extdb.sh` | external database deployments: `ex_pg_start <name> <16\|17\|18> <port> [plain\|tls-only\|client-cert]` (a server on the host network of the integration host, at `ex_addr`), `ex_db_create`, `ex_db_sql`, `ex_preset <root> KEY=VALUE...` (the template's lines replaced, as an operator edits them), `ex_install <root> <now\|from> <port>`, `ex_env`, `ex_backup`, `ex_refused`, `ex_upgrade <root> <online\|offline> [from]`, `ex_status`, `ex_teardown` |

The three openssl builds: `alpine/openssl:3.5.4` (the release pin), the bats test image's
Debian OpenSSL 3.5.7, and OpenSSL 1.1.1 from Alpine 3.15 (`openssl111.Dockerfile`). Four more,
only for the `-saltlen` probe of `encrypt`: 3.0 (Alpine 3.17, `openssl30.Dockerfile`),
`alpine/openssl:3.1.4`, 3.2 (Fedora 40 from the Fedora archive, `openssl32.Dockerfile`) and
`alpine/openssl:3.3.0`.

PostgreSQL servers are `it-pg-<name>` on the network `it-pg` of the scenario host, reachable as
`<name>:5432` from containers on that network (attach a deployment with
`docker network connect it-pg <container>`) and as `127.0.0.1:$(it_pg_port <name>)` on the host.
The superuser is `postgres` with a fixed test password. TLS servers use a certificate for
`<name>`, `localhost` and `127.0.0.1` from a test CA in `/it/pki/test/` (`ca.crt`);
`--tls-only` rejects plain connections in `pg_hba.conf`, `--client-cert` also requires a client
certificate whose CN is the user (`it_pki_cert test <user> client`). To add a server of another
major version, add `pg<major>` to `images.txt` with a digest pin (`pg15` is there for a server the
release has no client for).

`CX_IT_STORE=classic|containerd` picks the image store of the scenario hosts (default: the
engine's, containerd on 29.x). `CX_IT_KEEP=1` leaves a failed scenario's host running for
`docker exec -it <name> bash`; `run.sh clean` removes it.

### Two hosts

For a backup made on one machine and taken to another that never saw it, a scenario's header
names its hosts instead of using the one default host:

```
# hosts: a b              two or more names, lowercase letters and digits, in the order they run
```

`run.sh` then starts one host per name, `custodexa-it-<run>-<scenario>-<name>` with hostname
`it-host-<name>`, all before the first part runs and all with the same mounts (`/it-run`, the
image tars, the bundles the `needs:` line asks for, the images of the `images:` line loaded on
each). None has a network: there is no route between them or off them, and no name of one
resolves on another. The only thing they share is one volume, `custodexa-it-<run>-<scenario>-transfer`,
mounted read-write at `/transfer` on each: what the operator would carry from one machine to the
other. A `network:` line is refused in such a scenario.

The scenario file defines `scenario_<name>()` for each host instead of `scenario()`. They run in
the header's order, each on its own host (`IT_HOST` holds the name); a host's part ends with
`ok - host <name> done`, the last one prints `PASS <scenario>`, and the first part that fails
ends the scenario with `FAIL <scenario> (host <name>, exit N)`. Every host keeps running until
the scenario ends: a server an earlier part leaves running (started with `setsid nohup ... &`)
is still up while the later parts probe for it. All hosts' output goes to the one log `runs/<run>/<scenario>.log`. With `CX_IT_KEEP=1` a failed scenario's hosts and its
transfer volume stay; `run.sh clean` removes them. `two-hosts` is the minimal example.

## Scenarios

| Scenario | Proves |
|---|---|
| `smoke` | the package built from the working tree installs a built-in deployment from the offline bundle; `status` reports it |
| `openssl-versions` | the three openssl builds run, and each decrypts what the pinned 3.5.4 encrypted |
| `pg-roundtrip` | PostgreSQL 16, 17, 18 servers start; `pg_dump` of each restores into a new empty database; TLS-only and client-certificate servers refuse what they should |
| `two-hosts` | the two-host form: host `a` writes a 4 MiB file to `/transfer`, host `b` reads the same SHA-256; neither host has a default route or reaches an address off it; `a` answers `nc` and `wget` on its own port, while from `b` the same probes fail both by `a`'s hostname (no address for it) and on `127.0.0.1` (a separate network namespace) |
| `pg-smoke` | the external database servers the backup is checked against: PostgreSQL 16, 17 and 18 created the way a deployment creates its database (`public` keeps its default owner `pg_database_owner`, `DB_USER` owns the tables), a client-certificate server, one with a table of another owner in a tablespace of its own, one with grants to roles named `report reader` and `報表`; `DB_USER` connects to each with `psql`, also from a client on the host network by the server's address on `it-pg`; the 16, 17 and 18 client images carry `/etc/ssl/certs/ca-certificates.crt` |
| `overlays` | the built-in form and the external ingress form each go through install (older release), `backup`, `status`, `upgrade` to the package's release, `status` and `backup` again; openssl is a service image in the first, a recorded tool image (never a container) in the second; the backup file and the upgrade's backup folder are where, and with the modes, the deployment guide says |
| `restore` | a real backup of a built-in deployment (`DB_USER` not `postgres`) restores with `pg_restore` run as `DB_USER`, a login role that owns a new empty database on another PostgreSQL 16 server and is not a superuser; the script's snapshot of the restored database equals the backup's `snapshot.txt` |
| `encrypt` | a real `backup --yes --passphrase-file` of a built-in deployment: no process holds the passphrase in its arguments or environment while it runs, no file of the deployment holds it; the `.tar.enc` opens with openssl 3.5.4, 3.5.7 and 1.1.1 by the restore commands (1.1.1 without `-saltlen`, which it lacks) to the same tar, and not with a wrong passphrase; the known answer vector gives its recorded plaintext with each; OpenSSL 1.1.1, 3.0, 3.1, 3.2, 3.3, 3.5.4 and 3.5.7 each open the file with the command the operations guide picks by whether `enc -help` lists `-saltlen`, and 3.2 is the first line that lists it |
| `large` | the script's pack step (`cx_pb_pack`: `tar --format=gnu`, read-back, commit) on a member over 8 GiB (a sparse 9 GiB `db.dump`); GNU tar lists and extracts it at full size |
| `interrupt` | `kill -TERM` of a real `backup` while it packs the audit files (services stopped), and again while the encryption container runs: no process that ran under it and no tool container is left, no file is made, `start` brings the services back, the next backup finishes and records the interrupted one |
| `docs` | the restore procedure of `docs/ops/backup-and-restore.md` (5.2, then 5; the check commands of 3.8), taken from the guide at run time and run with only the placeholders filled in: an unencrypted file in place, an encrypted file on a fresh install; the loaded database equals `snapshot.txt` and the backend starts with the restored master key |
| `overlays-external` | the external database form and the external database with external ingress form, on PostgreSQL 17, each go through install (older release), `backup`, `status`, `upgrade` to the package's release, `status` and `backup` again; the PostgreSQL 16, 17 and 18 clients are recorded tool images, no database service runs, the export uses the 17 client, the upgrade's backup is one portable file |
| `restore-external` | a backup of an external database deployment on PostgreSQL 16, 17 and 18 each: exported with the client of the server's major; `pg_restore` of that major, run as `DB_USER` (not a superuser), loads it into a new empty database on a fresh server of the same major; row counts, `schema_migrations` and the key fingerprints equal its `snapshot.txt` |
| `external` | backups of an external database deployment against real PostgreSQL TLS servers: `verify-full` and `verify-ca` with the system's trust (the test CA mounted read-only over the client's system CA file, test only), `require` and `verify-full` with a CA file, `PGSSLROOTCERT=system`, `allow` and `prefer` with a CA file that does not sign the server's certificate on a TLS-only server (backed up, not checked, as the backend); a wrong CA and an unset `DB_SSLMODE` against a TLS-only server are refused before any service stops, and the backend fails to connect the same way; a client certificate (the key in no member); `public` of its default owner backs up; another owner's table, a tablespace, an extension, a CA file outside the backend's folders and a client key in the audit folder are refused before any service stops; roles named `report reader` and `報表` come back from the manifest as the server names them |
| `upgrade-external` | an external database deployment on PostgreSQL 17 upgrades from the older release to the package's, online (no `--images`: the PostgreSQL clients and the release's images pulled from their registries) and offline (`--images`, nothing from a registry): the upgrade's backup is one portable file exported with the 17 client, the snapshot before equals its `snapshot.txt`, the check after the start passes |
| `upgrade-bundled` | a built-in deployment upgrades from the older release: the upgrade's backup is one portable file (no folder), its `state.json` member is the state before, the snapshot before equals its `snapshot.txt`, the check after the start passes |
| `upgrade-twice` | a built-in deployment upgrades twice in a row; each upgrade's backup file holds the `state.json` of before that upgrade (`current.*` the version then running, `previous.*` the one before) |
| `upgrade-from-published` | two hosts, one per form: the published 1.15.2 (its own package and offline bundle) installed in the built-in form (host `builtin`) and the external ingress form (host `ingress`), a user and an asset written through its API, then `upgrade` to 1.16.90 with that package and its offline bundle: exit 0, nothing from a registry, the backend reports 1.16.90, `current` and `state.json` (`current.*`, `previous.*`, `last_upgrade.*`) name it, the running images are the recorded ones, the external ingress overlay is kept with no `tls/`; the upgrade's backup is one portable file of 1.15.2 (checksum, members, manifest, `state.json` member, the snapshot before, a dump that lists and holds the user); the user and the asset read the same from the database and the API, `status` passes and the frontend answers; `rollback` exits 3 before anything stops (1.15.2 is older than 1.16.0), nothing changed, its screen naming that backup file for the restore by hand |
| `local-versions` | the builder made 1.16.90, 1.16.91 and 1.16.92 from the working tree: each package and bundle matches its `SHA256SUMS` and names its version and its own images, 1.16.91 has the migrations of 1.16.90, 1.16.92 exactly one more (`it_rollback_probe`), and the working tree's git status is the same after the build |
| `rollback-switch` | a built-in deployment upgraded from 1.16.90 to 1.16.91 goes back with `rollback --yes`: the backend reports 1.16.90, the running images are the ones recorded before the upgrade, `.env`, every file under `tls/` and a recording keep their checksums, and a user, an asset and their audit events written through the API on 1.16.91 (and on 1.16.90 before the upgrade) read the same through 1.16.90; a second `rollback` exits 3 with the same containers and images; after another upgrade, a rollback sent SIGTERM while it starts the services finishes with the `rollback --resume` its screen gives, leaving no tool container; a rollback whose old backend does not become ready (paused, `CX_READY_TRIES` shortened) returns to 1.16.91 with `rollback --revert`; a `--revert` that cannot confirm the drain keeps the record unfinished and the command on its screen finishes it; a `--revert` sent SIGTERM while it starts the services is finished by `rollback --resume` (the revert, the same versions on record); with the old backend image removed, `rollback` exits 3 naming it, and after `load` of the 1.16.90 bundle it goes back |
| `rollback-refused` | upgraded from 1.16.90 to 1.16.92 (one more migration), `rollback` exits 3 before anything stops, names `it_rollback_probe` and prints the restore command of the backup file the upgrade recorded, which exists; from three starting points: the upgrade succeeded, failed at step 11 (readiness), was sent SIGTERM at step 11. With the upgrade unfinished, `load` of the 1.16.90 bundle is not held back and `rollback` still gets to its decision. Then the restore command is run as printed: while this build's restore stops after its confirmation, the scenario prints `PENDING restore-hint <starting point>` |
| `rollback-race` | against the real PostgreSQL of a built-in deployment on 1.16.91: a row committed into `schema_migrations` while the preview of an interactive `rollback` (a terminal from `script`) waits makes the second check refuse (exit 1, `refused`, no 1.16.90 container started, the link unchanged); a row inserted in a transaction left open does not count and the rollback finishes (the database stop ends that session); one row committed before the run is refused before the preview and listed, an uncommitted one is not; after an upgrade that failed at step 9, a rollback interrupted after the switch and reverted (which starts 1.16.91), or a `start` of 1.16.91, followed by a committed row, is refused on a real query, not on the never-started basis |
| `restore-external-checks` | the restore of an external database deployment, up to the checks before anything stops, against real PostgreSQL 15, 16, 17 and 18 (the deployments are installed from the package and labelled with the first data version a restore takes, so their backups reach these checks): a backup taken on 16 passes on 16, 17 and 18, each asked with the client of its own major, and is refused on 15 (no client); on 17, a connection held open by the original host or another client (on a host not installed yet), a table of another owner, an extension, another collation, a TLS-only server whose CA the client's system trust lacks, and a client-certificate server without the certificate or the key are each refused before anything stops, with the target database's objects, whole-table hashes, sequences and grants the same after; with the certificate and key given the checks pass and the key lands in no file; on the backup's own host its running backend's connections are listed, not refused, and the restore goes on to the confirmation |
| `restore-external-atomic` | the import of an external database is one transaction, on a PostgreSQL 17 server that holds data (a table of two million rows granted to `report reader`): a new host's restore held after its database check (the file placement fails) has the target digest, measured by the script's own query, of the source when it was backed up, line for line; its safety export lists and reads back in full, and `--revert` puts the target back to the digest of the export and removes the file. With the role dropped and `--accept-grant-loss`: `body.sql` cut after a valid prefix, its maker sent SIGTERM and SIGKILL part way, the grants maker failing and a grant the filter cannot split open no transaction, and an error after the first COPY data rolls the one transaction back; the target digest is unchanged after each. The import's psql killed, and on the same host its session ended by the server, while it copies: the record says begun, the digest is that of before, `--resume` compares the two, imports again and finishes with the backup's snapshot and master key, the skipped grant listed |
| `restore-external-db` | an external database deployment of 1.16.90 on PostgreSQL 16, 17 and 18 each: on its own host, its backend connected and listed, the restore stops the services itself; a failing `body.sql` maker opens no transaction; held after the database check the target digest is the source's at the backup, and `--revert` (the safety backup) brings back the version, rows, data, sequences and grants; the finished restore has the backup's snapshot and master key. A new host, into the same database: refused while the original host is connected; once that host is gone, the same, its `--revert` putting the safety export back to the digest of before. On 17, a `psql` connection held open is listed before the stop, stops the restore after it (step 2) with nothing emptied, and `--revert` starts the services again |
| `docs-external` | the restore procedure of `docs/ops/backup-and-restore.md` for a deployment with an external database (5.2, then 5 with step 5 replaced by the two blocks of 5.3), taken from the guide at run time and run on a terminal with only the placeholders filled in and the new server's port set in `.env`: a real backup file of a PostgreSQL 17 deployment (verify-full with a CA file, grants to roles named `report reader` and `報表`) loads onto another PostgreSQL 17 server with `pg_restore` exit code 0, the password typed at its prompt; the loaded database equals `snapshot.txt`, the grants came back, and the backend starts on the new server |
| `restore-same-host` | a built-in deployment on 1.16.90 (master key mode env) restores its own backup with `restore --same-host`, run as the guide gives it (`./custodexa.sh` in the deployment folder): the script's snapshot of the database equals the backup's `snapshot.txt`, a user written after the backup is gone, the database, audit and `tls` folders from before are kept, the recordings folder is unchanged, seal/status reports the backup's master key fingerprint; the deployment's own proxy template (`TLS_NGINX_TEMPLATE`), changed after the backup, is the backup's again (same SHA-256), the changed one is kept as `.before-restore-<STAMP>`, and `nginx -T` of the running proxy shows the backup's; `--revert` after the end exits 3, and a restore of the safety backup brings back the version, row counts, migrations, sorted `pg_dump --data-only` hash, sequences and grants from before; a restore whose stop before the file placement fails (after the database check) exits 1 at `db_checked` and `--revert` brings back the same, every service running its recorded image |
| `restore-new-host` | two hosts: host `a` installs 1.16.90 (env, then a new ui deployment unsealed through the API), writes data and sessions with recordings, and takes an encrypted backup of each; host `b`, with no network, unpacks the package, loads the offline bundle and restores each file with `--new-host --package --images`, run as the guide gives it; `a`'s env deployment has its own proxy template under `/etc/custodexa/`, a folder `b` does not have, so `b` names another path with `--nginx-template`: the file there has the same SHA-256, `.env` points at it and `nginx -T` of `b`'s proxy shows it; the snapshot, active `kek_id` and master key fingerprint equal `a`'s and seal/status reports it; the ui restore exits 4 sealed, a wrong key is refused by the backend and `--resume` still exits 4 with the phase unchanged, the right key then lets `--resume` finish; `b`'s server certificate names `b` and verifies against `a`'s certificate authority; `missing-recordings.txt` lists as many recordings as `a`'s database |
| `restore-interrupt` | restores of a built-in deployment on 1.16.90 interrupted for real: SIGTERM while `pg_restore` loads the dump (no tool container or process left, `--resume` finishes with the backup's snapshot); SIGKILL between the rename of the database folder and that of the audit folder, finished with `--resume` and, again, with `--revert` (no database container started in between); SIGTERM after the services were started, before they are ready (the screen says they may be running, as `docker ps` shows, and `--resume` finishes); a failed database check gone back with `--revert` (version, rows, data, sequences, grants from before); a new host waiting for the unseal (ui) given up with `--abandon`: no container runs, `status` says not installed |
| `restore-cross-version` | two hosts: host `a` installs the published 1.15.2 (its own package and offline bundle) and upgrades it to 1.16.90; the upgrade's backup (data of 1.15.2) is refused with exit 3 before anything stops, the services, version, data folders and `.env` unchanged and nothing downloaded; host `b`, never installed, refuses the same file the same way with no container, no 1.15.2 release and nothing downloaded; after `load` of the 1.16.90 bundle, from a 1.16.90 backup: a snapshot naming a migration the engine does not know is refused before anything starts, a release whose `VERSION` file alone says 1.16.99 is refused, and a snapshot that disagrees with the dump (member checksums recomputed) stops at the check after the import; no backend container is ever created on `b` |
| `restore-kek-modes` | master key held outside the deployment, against the real backend. kms with a dev-mode Vault (pinned by digest, TLS from a test CA): a restore waits for the unseal (exit 4); with the key service reachable `--resume` finishes and the runtime key ID equals the backup's `kek.fingerprint`; with it unreachable, and with the same key name holding other material in a new Vault, the unseal is refused, `--resume` stays at exit 4 and `upgrade` is refused (the first finishes once the service is back). ui: the wrong material is refused and the restore does not finish; the right one finishes it |

Group `rollback-matrix` runs `local-versions rollback-switch rollback-refused rollback-race`.
Group `selfcheck` runs its four (`smoke`, `openssl-versions`, `pg-roundtrip`, `two-hosts`); group `backup-matrix` runs `overlays restore encrypt large interrupt docs`
(the portable backup scenarios); group `external-matrix` runs `overlays-external restore-external external
upgrade-external upgrade-bundled upgrade-twice upgrade-from-published docs-external` (the external database
form and the upgrade's portable backup). Group `restore-external` runs `restore-external restore-external-checks restore-external-atomic
restore-external-grants restore-external-db` (the restore of an external database deployment); a group
name comes before a scenario name, so `run.sh restore-external` runs the group, the scenario of that
name first.
