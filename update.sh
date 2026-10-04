#!/bin/sh
set -e

REPO_USER="ib0lit"
REPO_NAME="SubParser"
BRANCH="main"
COMMIT_FILE="/etc/subparser_commit"
VERSION_FILE="/etc/subparser_version"

echo "=== [1/4] Проверка наличия обновлений ==="

REMOTE_SHA=$(curl -sL \
  -H "User-Agent: OpenWrt-SubParser-Updater" \
  "https://api.github.com/repos/${REPO_USER}/${REPO_NAME}/commits/${BRANCH}" \
  | grep '"sha":' | head -n 1 | cut -d '"' -f 4)

if [ -z "$REMOTE_SHA" ]; then
    echo "[!] Не удалось определить версию на GitHub. Выполняем принудительное обновление..."
else
    if [ -f "$COMMIT_FILE" ]; then
        LOCAL_SHA=$(cat "$COMMIT_FILE" 2>/dev/null || true)
        if [ "$LOCAL_SHA" = "$REMOTE_SHA" ]; then
            CURRENT_VER=$(cat "$VERSION_FILE" 2>/dev/null || echo "v2.x")
            echo ""
            echo "=========================================================="
            echo " [i] Обновлений нет. Установлена актуальная версия: ${CURRENT_VER}"
            echo " SHA коммита: ${LOCAL_SHA:0:7}"
            echo "=========================================================="
            exit 0
        fi
    fi
    echo "[*] Найдена новая версия: ${REMOTE_SHA:0:7}"
fi

echo "=== [2/4] Загрузка компонентов с GitHub ==="
TMP_DIR="/tmp/subparser-update"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

curl -sL "https://github.com/${REPO_USER}/${REPO_NAME}/archive/refs/heads/${BRANCH}.tar.gz?nocache=$(date +%s)" | tar -xz -C "$TMP_DIR"
SRC_PATH="${TMP_DIR}/${REPO_NAME}-${BRANCH}/root"

echo "=== [3/4] Применение обновлений и миграция настроек ==="
mkdir -p /etc/hotplug.d/uci /usr/bin /etc/init.d /usr/share/luci/menu.d /usr/share/rpcd/acl.d /www/luci-static/resources/view

cp -f "${SRC_PATH}/usr/bin/"* /usr/bin/
cp -f "${SRC_PATH}/etc/init.d/"* /etc/init.d/
cp -f "${SRC_PATH}/usr/share/luci/menu.d/"* /usr/share/luci/menu.d/
cp -f "${SRC_PATH}/usr/share/rpcd/acl.d/"* /usr/share/rpcd/acl.d/
cp -f "${SRC_PATH}/www/luci-static/resources/view/"* /www/luci-static/resources/view/
[ -f "${SRC_PATH}/etc/subparser_version" ] && cp -f "${SRC_PATH}/etc/subparser_version" /etc/subparser_version
[ -d "${SRC_PATH}/etc/hotplug.d/uci" ] && cp -f "${SRC_PATH}/etc/hotplug.d/uci/"* /etc/hotplug.d/uci/ 2>/dev/null || true

# Удаление устаревшего ACL-дубликата, если он остался от прошлых версий
rm -f /usr/share/rpcd/acl.d/subparser.json 2>/dev/null || true

chmod +x /usr/bin/subparser* /etc/init.d/subparser*

# --- Мягкая миграция UCI-конфига ---
set_default_uci() {
    local opt="$1"
    local val="$2"
    if [ -z "$(uci -q get subparser.settings.${opt})" ]; then
        uci -q set subparser.settings.${opt}="${val}"
    fi
}

set_default_uci "custom_hour" "3"
set_default_uci "custom_minute" "0"
set_default_uci "ping_threshold" "350"
set_default_uci "max_jitter" "150"
set_default_uci "max_best_nodes" "0"
set_default_uci "filter_ru" "1"
set_default_uci "per_section_config" "0"
set_default_uci "update_mode" "replace"
set_default_uci "sec_mode_main" "replace"
set_default_uci "sec_en_main" "1"

if [ -z "$(uci -q get subparser.settings.target_section)" ]; then
    uci -q add_list subparser.settings.target_section='main'
fi

# Вычищаем старые параметры, если они существовали
uci -q delete subparser.settings.cron_interval 2>/dev/null || true
uci -q delete subparser.settings.custom_interval_min 2>/dev/null || true
uci commit subparser

if [ -n "$REMOTE_SHA" ]; then
    echo "$REMOTE_SHA" > "$COMMIT_FILE"
fi

echo "=== [4/4] Перезапуск служб и очистка кэша LuCI ==="
/etc/init.d/subparser restart >/dev/null 2>&1 || true

EN=$(uci -q get subparser.settings.enabled)
if [ "$EN" = "1" ]; then
    /etc/init.d/subparser-bot restart >/dev/null 2>&1 || true
else
    /etc/init.d/subparser-bot stop >/dev/null 2>&1 || true
fi

rm -rf /tmp/luci-indexcache /tmp/luci-modulecache
/etc/init.d/rpcd reload >/dev/null 2>&1 || true

rm -rf "$TMP_DIR"

NEW_VER=$(cat "$VERSION_FILE" 2>/dev/null || echo "2.0.0")
echo ""
echo "=========================================================="
echo " [OK] SubParser успешно обновлен до версии ${NEW_VER}!"
echo " Все подписки, настройки и токен бота сохранены."
echo "=========================================================="