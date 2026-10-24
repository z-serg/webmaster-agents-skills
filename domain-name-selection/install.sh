#!/usr/bin/env bash
# Быстрая установка скилла domain-name-selection в каталог навыков агента.
#
# Использование:
#   ./install.sh                симлинк в ~/.agents/skills (по умолчанию)
#   ./install.sh --copy         копирование вместо симлинка
#   ./install.sh --dest ПУТЬ    другой каталог установки
#   ./install.sh --force        заменить существующую установку (с бэкапом)

set -euo pipefail

SKILL_NAME="domain-name-selection"
DEST_DIR="${HOME}/.agents/skills"
METHOD="symlink"
FORCE=0

die() {
  echo "Ошибка: $*" >&2
  exit 1
}

usage() {
  cat <<EOF
Использование: $(basename "$0") [параметры]

Устанавливает скилл $SKILL_NAME в каталог навыков агента
(по умолчанию: ~/.agents/skills).

Параметры:
  -s, --symlink   Установить симлинком (по умолчанию). Обновление скилла
                  происходит через git pull без переустановки.
  -c, --copy      Установить копированием. Для обновления запустите скрипт снова.
  -d, --dest DIR  Каталог установки (по умолчанию: ~/.agents/skills).
  -f, --force     Заменить существующую установку; прежняя сохранится рядом
                  с суффиксом .bak.<дата-время>.
  -h, --help      Показать эту справку.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    -s|--symlink) METHOD="symlink" ;;
    -c|--copy) METHOD="copy" ;;
    -d|--dest)
      [ $# -ge 2 ] || die "параметру $1 нужен путь"
      DEST_DIR="$2"
      shift
      ;;
    -f|--force) FORCE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "неизвестный параметр: $1 (см. --help)" ;;
  esac
  shift
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)" \
  || die "не удалось определить каталог скрипта"
SOURCE_DIR="$SCRIPT_DIR"

[ -f "$SOURCE_DIR/SKILL.md" ] \
  || die "рядом со скриптом нет SKILL.md — запускайте скрипт из папки скилла в репозитории"

mkdir -p "$DEST_DIR" || die "не удалось создать каталог $DEST_DIR"
DEST_DIR="$(cd "$DEST_DIR" && pwd -P)"
TARGET_DIR="${DEST_DIR%/}/$SKILL_NAME"

# Уже установлен этим скриптом (цель указывает на текущую папку)?
if [ -e "$TARGET_DIR" ] && [ "$TARGET_DIR" -ef "$SOURCE_DIR" ]; then
  echo "Скилл уже установлен: $TARGET_DIR — ничего не делаю."
  exit 0
fi

if [ -e "$TARGET_DIR" ] || [ -L "$TARGET_DIR" ]; then
  [ "$FORCE" -eq 1 ] \
    || die "$TARGET_DIR уже существует. Запустите с --force, чтобы заменить его (прежний будет сохранён в бэкап)."
  BACKUP="${TARGET_DIR}.bak.$(date +%Y%m%d-%H%M%S)"
  mv "$TARGET_DIR" "$BACKUP"
  echo "Существующая установка сохранена: $BACKUP"
fi

if [ "$METHOD" = "symlink" ]; then
  ln -s "$SOURCE_DIR" "$TARGET_DIR"
  echo "Установлен симлинк: $TARGET_DIR -> $SOURCE_DIR"
else
  cp -a "$SOURCE_DIR" "$TARGET_DIR"
  # в установленную копию кэш Python не нужен
  find "$TARGET_DIR" -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
  echo "Скопировано в: $TARGET_DIR"
fi

[ -f "$TARGET_DIR/SKILL.md" ] || die "установка не удалась: SKILL.md не найден в $TARGET_DIR"

echo
echo "Готово. Перезапустите агента, чтобы он подхватил навык."
