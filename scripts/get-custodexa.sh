#!/usr/bin/env bash
# Download and verify a release package, then hand execution to its management script.
# The published copy is a fixed-name release asset; bash may read it from a curl pipe.
set -euo pipefail
set +o xtrace

release_base=${CX_GET_RELEASE_BASE:-https://github.com/custodexa/custodexa/releases}
target=/opt/custodexa
version=''
forward=()
lang_flag=''

while [ "$#" -gt 0 ]; do
  case $1 in
    --dir | --version)
      if [ "$#" -lt 2 ] || [ -z "$2" ] || [[ $2 == -* ]]; then
        printf '[FAIL] %s requires a value\n' "$1" >&2
        exit 2
      fi
      case $1 in --dir) target=$2 ;; --version) version=$2 ;; esac
      shift 2
      ;;
    -h | --help)
      cat <<'USAGE'
Usage: get-custodexa.sh [--version X.Y.Z] [--dir /opt/custodexa] [custodexa.sh arguments]
Without a child command, an interactive terminal opens the custodexa.sh menu.
USAGE
      exit 0
      ;;
    --)
      shift
      forward+=("$@")
      break
      ;;
    *) forward+=("$1"); shift ;;
  esac
done

for ((i=0; i<${#forward[@]}; i++)); do
  if [ "${forward[$i]}" = --lang ] && [ "$((i + 1))" -lt "${#forward[@]}" ]; then
    lang_flag=${forward[$((i + 1))]}
  fi
done
locale=${lang_flag:-${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}}
case $locale in
  zh-TW | zh_TW* | zh_Hant* | zh-Hant*) lang=zh-TW ;;
  ja | ja_* | ja-* | ja.*) lang=ja ;;
  *) lang=en ;;
esac

msg() {
  local key=$1 item=${2:-}
  case $lang:$key in
    en:root) printf 'Run with sudo to install or operate the deployment.' ;;
    zh-TW:root) printf '請以 sudo 執行，以安裝或操作部署。' ;;
    ja:root) printf '導入または運用するには sudo で実行してください。' ;;
    en:platform) printf 'This guide supports Linux x86_64 and aarch64 only.' ;;
    zh-TW:platform) printf '此引導腳本僅支援 Linux x86_64 與 aarch64。' ;;
    ja:platform) printf 'この案内スクリプトは Linux x86_64 と aarch64 のみ対応します。' ;;
    en:version) printf 'Use --version X.Y.Z (three numeric components).' ;;
    zh-TW:version) printf '請使用 --version X.Y.Z（三段數字）。' ;;
    ja:version) printf -- '--version X.Y.Z（数字三段）を指定してください。' ;;
    en:directory) printf 'Use an absolute deployment directory with letters, digits, dot, underscore, hyphen and slash.' ;;
    zh-TW:directory) printf '部署目錄須為絕對路徑，只含英數字、點、底線、連字號與斜線。' ;;
    ja:directory) printf '導入先は英数字、ピリオド、アンダースコア、ハイフン、スラッシュだけの絶対パスを指定してください。' ;;
    en:tty) printf 'No terminal is available for the menu. Pass a child command, for example: install --yes' ;;
    zh-TW:tty) printf '沒有可用終端機，無法開啟選單；請帶子命令，例如 install --yes。' ;;
    ja:tty) printf 'メニュー用の端末がありません。install --yes などのサブコマンドを指定してください。' ;;
    en:exists) printf 'Deployment directory already exists and is not an installed Custodexa package: %s' "$item" ;;
    zh-TW:exists) printf '部署目錄已存在，且不是已安裝的 Custodexa 安裝包：%s' "$item" ;;
    ja:exists) printf '導入先は既に存在し、Custodexa の導入済みパッケージではありません：%s' "$item" ;;
    en:owner) printf 'Check owner and permissions: %s must be owned by root, not writable by group or others, and have no unexpected link.' "$item" ;;
    zh-TW:owner) printf '請檢查擁有者與權限：%s 須由 root 擁有，群組與其他人不可寫入，且不可有非預期連結。' "$item" ;;
    ja:owner) printf '所有者と権限を確認してください：%s は root が所有し、グループや他のユーザーが書き込めず、想定外のリンクがない必要があります。' "$item" ;;
    en:handoff) printf 'Existing deployment found; handing off without overwriting files: %s' "$item" ;;
    zh-TW:handoff) printf '找到既有部署；不覆寫檔案，交給現有腳本：%s' "$item" ;;
    ja:handoff) printf '既存の導入を検出しました。上書きせず既存のスクリプトに引き継ぎます：%s' "$item" ;;
    en:download) printf 'Downloading %s…' "$item" ;;
    zh-TW:download) printf '正在下載 %s…' "$item" ;;
    ja:download) printf '%s をダウンロードしています…' "$item" ;;
    en:downloaded) printf 'Downloaded %s' "$item" ;;
    zh-TW:downloaded) printf '已下載 %s' "$item" ;;
    ja:downloaded) printf '%s をダウンロードしました' "$item" ;;
    en:download_fail) printf 'Could not download %s from the release; check the network or version and try again.' "$item" ;;
    zh-TW:download_fail) printf '無法從 Release 下載 %s；請檢查網路或版本後重試。' "$item" ;;
    ja:download_fail) printf 'Release から %s を取得できません。ネットワークとバージョンを確認して再試行してください。' "$item" ;;
    en:manifest) printf 'Latest release manifest has no valid X.Y.Z version.' ;;
    zh-TW:manifest) printf '最新版發行清單沒有有效的 X.Y.Z 版本。' ;;
    ja:manifest) printf '最新版のリリース一覧に有効な X.Y.Z バージョンがありません。' ;;
    en:checksum_start) printf 'Checking the package checksum against SHA256SUMS…' ;;
    zh-TW:checksum_start) printf '正在以 SHA256SUMS 核對安裝包校驗和…' ;;
    ja:checksum_start) printf 'SHA256SUMS とパッケージのチェックサムを照合しています…' ;;
    en:checksum_ok) printf 'Package checksum matches SHA256SUMS' ;;
    zh-TW:checksum_ok) printf '安裝包校驗和與 SHA256SUMS 相符' ;;
    ja:checksum_ok) printf 'パッケージのチェックサムは SHA256SUMS と一致します' ;;
    en:checksum_fail) printf 'Package checksum is missing or does not match SHA256SUMS; download again before unpacking.' ;;
    zh-TW:checksum_fail) printf '安裝包校驗和未列出或與 SHA256SUMS 不符；請重新下載，勿解壓。' ;;
    ja:checksum_fail) printf 'パッケージのチェックサムがないか SHA256SUMS と一致しません。展開前に再ダウンロードしてください。' ;;
    en:signature) printf 'This guide checks SHA-256 only. Verify the package signature manually as documented; custodexa.sh handles image signatures.' ;;
    zh-TW:signature) printf '此引導腳本只核對 SHA-256；請依文件手動驗證安裝包簽章。映像簽章由 custodexa.sh 處理。' ;;
    ja:signature) printf 'この案内スクリプトは SHA-256 のみ確認します。パッケージ署名は文書に沿って手動で検証してください。イメージ署名は custodexa.sh が扱います。' ;;
    en:unpack) printf 'Unpacking the verified package…' ;;
    zh-TW:unpack) printf '正在解壓已核對的安裝包…' ;;
    ja:unpack) printf '検証済みパッケージを展開しています…' ;;
    en:unpacked) printf 'Package unpacked into %s' "$item" ;;
    zh-TW:unpacked) printf '安裝包已解壓到 %s' "$item" ;;
    ja:unpacked) printf 'パッケージを %s に展開しました' "$item" ;;
    en:archive) printf 'Package archive is invalid or has an unexpected top-level directory.' ;;
    zh-TW:archive) printf '安裝包壓縮檔無效，或頂層目錄結構不符。' ;;
    ja:archive) printf 'パッケージが無効か、最上位ディレクトリの構造が一致しません。' ;;
    en:move) printf 'Could not place the verified package in %s; check permissions and existing files.' "$item" ;;
    zh-TW:move) printf '無法把已核對安裝包放入 %s；請檢查權限與現有檔案。' "$item" ;;
    ja:move) printf '検証済みパッケージを %s に配置できません。権限と既存ファイルを確認してください。' "$item" ;;
    en:tool) printf 'Need curl or wget, tar, stat, and sha256sum or shasum.' ;;
    zh-TW:tool) printf '需要 curl 或 wget、tar、stat，以及 sha256sum 或 shasum。' ;;
    ja:tool) printf 'curl または wget、tar、stat、sha256sum または shasum が必要です。' ;;
  esac
}

line() { printf '%s %s\n' "$1" "$2"; }
fail() { line '[FAIL]' "$(msg "$@")" >&2; exit 1; }

if [[ ! $target =~ ^/[A-Za-z0-9._/-]+$ ]] || [ "$target" = / ] || [[ /$target/ == */../* || /$target/ == */./* ]]; then
  fail directory
fi
while [[ $target == */ ]]; do target=${target%/}; done
if [ -n "$version" ] && [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then fail version; fi
if [ "$(uname -s)" != Linux ]; then fail platform; fi
case $(uname -m) in x86_64 | aarch64 | arm64) ;; *) fail platform ;; esac
if [ "$EUID" -ne 0 ]; then fail root; fi
command -v stat >/dev/null 2>&1 || fail tool
parent=${target%/*}
[ -n "$parent" ] || parent=/

# Only execute a script from a deployment whose immediate parent and executable chain cannot be
# replaced by another user. The release package has exactly two internal links: current and the
# root entry script. Other links, including links to an external executable, are refused.
secure_path() {
  local path=$1 kind=$2 mode
  if [ -L "$path" ] || [ ! -O "$path" ]; then fail owner "$path"; fi
  case $kind in
    dir) [ -d "$path" ] || fail owner "$path" ;;
    file) [ -f "$path" ] || fail owner "$path" ;;
  esac
  mode=$(stat -c %a -- "$path" 2>/dev/null) || fail owner "$path"
  (( (8#$mode & 0022) == 0 )) || fail owner "$path"
}
secure_link() {
  local path=$1 expected=$2
  if [ ! -L "$path" ] || [ "$(stat -c %u -- "$path" 2>/dev/null)" != "$EUID" ] \
    || [ "$(readlink -- "$path")" != "$expected" ]; then
    fail owner "$path"
  fi
}
secure_handoff_tree() {
  local root=$1 current root_parent
  root_parent=${root%/*}
  [ -n "$root_parent" ] || root_parent=/
  secure_path "$root_parent" dir
  secure_path "$root" dir
  if [ -L "$root/custodexa.sh" ]; then
    secure_link "$root/custodexa.sh" current/custodexa.sh
    current=$(readlink -- "$root/current" 2>/dev/null) || fail owner "$root/current"
    [[ $current =~ ^releases/[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail owner "$root/current"
    secure_link "$root/current" "$current"
    secure_path "$root/releases" dir
    secure_path "$root/$current" dir
    secure_path "$root/$current/custodexa.sh" file
  else
    secure_path "$root/custodexa.sh" file
  fi
}

# A piped script leaves stdin connected to its own bytes. Give the child the controlling terminal.
tty_available=0
if [ -t 0 ] || (: </dev/tty) 2>/dev/null; then tty_available=1; fi
if [ "${#forward[@]}" -eq 0 ] && [ "$tty_available" -eq 0 ]; then fail tty; fi
handoff() {
  secure_handoff_tree "$target"
  if [ -t 0 ]; then
    exec "$target/custodexa.sh" "${forward[@]}"
  elif [ "$tty_available" -eq 1 ]; then
    exec "$target/custodexa.sh" "${forward[@]}" </dev/tty
  else
    exec "$target/custodexa.sh" "${forward[@]}" </dev/null
  fi
}

if [ -e "$target" ] || [ -L "$target" ]; then
  [ -f "$target/custodexa.sh" ] || fail exists "$target"
  secure_handoff_tree "$target"
  line '[ OK ]' "$(msg handoff "$target")"
  handoff
fi

if command -v curl >/dev/null 2>&1; then
  downloader=curl
elif command -v wget >/dev/null 2>&1; then
  downloader=wget
else
  fail tool
fi
if command -v sha256sum >/dev/null 2>&1; then
  hasher=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  hasher=(shasum -a 256)
else
  fail tool
fi
command -v tar >/dev/null 2>&1 || fail tool

tmp=$(mktemp -d)
stage=''
cleanup() {
  [ -z "$stage" ] || rm -rf -- "$stage"
  rm -rf -- "$tmp"
}
trap cleanup EXIT
download() {
  local label=$1 url=$2 out=$3
  line '[ .. ]' "$(msg download "$label")"
  if [ "$downloader" = curl ]; then
    curl -fsSL --retry 2 -o "$out" "$url" >/dev/null 2>&1 || fail download_fail "$label"
  else
    wget -q -O "$out" "$url" >/dev/null 2>&1 || fail download_fail "$label"
  fi
  line '[ OK ]' "$(msg downloaded "$label")"
}

if [ -z "$version" ]; then
  download MANIFEST.json "$release_base/latest/download/MANIFEST.json" "$tmp/MANIFEST.json"
  manifest=$(<"$tmp/MANIFEST.json")
  if [[ $manifest =~ \"version\"[[:space:]]*:[[:space:]]*\"([0-9]+\.[0-9]+\.[0-9]+)\" ]]; then
    version=${BASH_REMATCH[1]}
  else
    fail manifest
  fi
fi

package=custodexa-$version.tar.gz
download "$package" "$release_base/download/v$version/$package" "$tmp/$package"
download SHA256SUMS "$release_base/download/v$version/SHA256SUMS" "$tmp/SHA256SUMS"
line '[ .. ]' "$(msg checksum_start)"
expected=''
while read -r digest name extra; do
  [ -z "${extra:-}" ] || continue
  name=${name#\*}
  if [ "$name" = "$package" ]; then
    [ -z "$expected" ] || fail checksum_fail
    expected=$digest
  fi
done <"$tmp/SHA256SUMS"
[[ $expected =~ ^[0-9a-f]{64}$ ]] || fail checksum_fail
read -r actual _ < <("${hasher[@]}" "$tmp/$package")
[ "$actual" = "$expected" ] || fail checksum_fail
line '[ OK ]' "$(msg checksum_ok)"
line '[WARN]' "$(msg signature)"

line '[ .. ]' "$(msg unpack)"
tar -tzf "$tmp/$package" >"$tmp/members" 2>/dev/null || fail archive
[ -s "$tmp/members" ] || fail archive
while IFS= read -r member; do
  case $member in custodexa | custodexa/*) ;; *) fail archive ;; esac
  case /$member/ in */../* | */./*) fail archive ;; esac
done <"$tmp/members"
# The published package's two links remain inside custodexa/. Reject every other archive link
# before extraction, so a link member cannot redirect later extraction outside the private stage.
tar -tvzf "$tmp/$package" >"$tmp/listing" 2>/dev/null || fail archive
while IFS= read -r listing_line; do
  read -r -a fields <<<"$listing_line"
  case ${fields[0]:0:1} in
    - | d) ;;
    l)
      if [ "${#fields[@]}" -ne 8 ] || [ "${fields[6]}" != '->' ]; then fail archive; fi
      case ${fields[5]}:${fields[7]} in
        "custodexa/current:releases/$version" | custodexa/custodexa.sh:current/custodexa.sh) ;;
        *) fail archive ;;
      esac
      ;;
    *) fail archive ;;
  esac
done <"$tmp/listing"
(umask 022; mkdir -p -- "$parent") || fail move "$target"
secure_path "$parent" dir
stage=$(mktemp -d "$parent/.custodexa-get.XXXXXXXX") || fail move "$target"
tar -xzf "$tmp/$package" -C "$stage" --no-same-owner >/dev/null 2>&1 || fail archive
[ -f "$stage/custodexa/custodexa.sh" ] || fail archive
secure_handoff_tree "$stage/custodexa"
if [ -e "$target" ] || [ -L "$target" ]; then fail exists "$target"; fi
mv -T -n -- "$stage/custodexa" "$target" || fail move "$target"
[ ! -e "$stage/custodexa" ] || fail move "$target"
line '[ OK ]' "$(msg unpacked "$target")"
cleanup
trap - EXIT
handoff
