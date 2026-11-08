#!/usr/bin/env bats
# Threat (A): a screen sends the operator to a section of the operations guide, and the section was
# renamed or removed. The screens that refuse because the .env names an external database over a
# built-in one (the form refusal and the form warning of the management script, and the refusal of
# scripts/quickstart.sh) point to "Switching to an external database"; each language has to find
# that section in its own guide, under the name the screen prints.

load helper

# The name each language prints, and the guide that has to carry it as a heading.
EN_NAME="Switching to an external database"
ZH_NAME="換到外接資料庫"
JA_NAME="外部データベースへの切り替え"
DOCS=/src/docs

# squeezed <file>: the file as one line with runs of blanks as one blank (a message may break its line
# inside the name).
squeezed() { tr '\n' ' ' <"$1" | tr -s ' '; }

# mentions <file> <name>: how many times the name is printed in quotes.
mentions() {
  local text
  text=$(squeezed "$1")
  grep -Eo "(\\\\?\"|「)${2}(\\\\?\"|」)" <<<"$text" | wc -l | tr -d ' '
}

# heading_in <guide> <name>: a heading whose text ends with the name.
heading_in() { grep -Eq "^#{2,4} ([0-9]+(\\.[0-9]+)* )?${2}\$" "$1"; }

@test "English screens name the section and the English guide has it as a heading" {
  [ "$(mentions "$SRC/lang/en.sh" "$EN_NAME")" -ge 2 ] || return 1
  heading_in "$DOCS/ops/backup-and-restore.md" "$EN_NAME" || return 1
}

@test "zh-TW screens name the section and the zh-TW guide has it as a heading" {
  [ "$(mentions "$SRC/lang/zh-TW.sh" "$ZH_NAME")" -ge 2 ] || return 1
  heading_in "$DOCS/zh-TW/ops/backup-and-restore.md" "$ZH_NAME" || return 1
}

@test "ja screens name the section and the ja guide has it as a heading" {
  [ "$(mentions "$SRC/lang/ja.sh" "$JA_NAME")" -ge 2 ] || return 1
  heading_in "$DOCS/ja/ops/backup-and-restore.md" "$JA_NAME" || return 1
}

@test "the refusal of scripts/quickstart.sh names the section and the file that has it" {
  [ "$(mentions /src/scripts/quickstart.sh "$EN_NAME")" -ge 2 ] || return 1
  grep -q 'docs/ops/backup-and-restore.md' /src/scripts/quickstart.sh || return 1
  [ -f "$DOCS/ops/backup-and-restore.md" ] || return 1
}

@test "the three guides number the section the same way" {
  local n e z j
  e=$(sed -n "s/^#\\{2,4\\} \\([0-9.]*\\) ${EN_NAME}\$/\\1/p" "$DOCS/ops/backup-and-restore.md")
  z=$(sed -n "s/^#\\{2,4\\} \\([0-9.]*\\) ${ZH_NAME}\$/\\1/p" "$DOCS/zh-TW/ops/backup-and-restore.md")
  j=$(sed -n "s/^#\\{2,4\\} \\([0-9.]*\\) ${JA_NAME}\$/\\1/p" "$DOCS/ja/ops/backup-and-restore.md")
  n=$(printf '%s\n%s\n%s\n' "$e" "$z" "$j" | sort -u | wc -l | tr -d ' ')
  [ -n "$e" ] || return 1
  [ "$n" = 1 ] || return 1
}
