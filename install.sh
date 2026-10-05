#!/bin/sh
set -e

REPO_USER="ib0lit"
REPO_NAME="SubParser"
BRANCH="main"
COMMIT_FILE="/etc/subparser_commit"
VERSION_FILE="/etc/subparser_version"

echo "=== [1/6] Определение пакетного менеджера и зависимостей ==="
set +e

install_pkg() {
    local pkg="$1"
    if command -v apk >/dev/null 2>&1; then
        apk add "$pkg" >/dev/null 2>&1 || true
    elif command -v opkg >/dev/null 2>&1; then
        opkg install "$pkg" >/dev/null 2>&1 || true
    fi
}

if command -v apk >/dev/null 2>&1; then
    echo "[*] Обнаружен менеджер apk (OpenWrt 25+)"
    apk update
    apk add python3 curl ca-certificates
    apk add conntrack-tools >/dev/null 2>&1 || apk add conntrack >/dev/null 2>&1 || true
elif command -v opkg >/dev/null 2>&1; then
    echo "[*] Обнаружен менеджер opkg (OpenWrt 19-24)"
    opkg update
    opkg install python3 curl ca-certificates ca-bundle
    opkg install conntrack-tools >/dev/null 2>&1 || opkg install conntrack >/dev/null 2>&1 || true
else
    echo "[!] Предупреждение: пакетный менеджер не найден. Пропуск шага."
fi

set -e

echo "=== [2/6] Загрузка компонентов с GitHub ==="
TMP_DIR="/tmp/subparser-install"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

curl -sL "https://github.com/${REPO_USER}/${REPO_NAME}/archive/refs/heads/${BRANCH}.tar.gz?nocache=$(date +%s)" | tar -xz -C "$TMP_DIR"
SRC_PATH="${TMP_DIR}/${REPO_NAME}-${BRANCH}/root"

echo "=== [3/6] Развертывание системных файлов и конфигурации ==="
mkdir -p /etc/config /etc/init.d /usr/bin /usr/lib/subparser \
         /usr/share/luci/menu.d /usr/share/rpcd/acl.d /www/luci-static/resources/view /etc/hotplug.d/uci

if [ ! -f /etc/config/subparser ]; then
    cp -f "${SRC_PATH}/etc/config/subparser" /etc/config/subparser
else
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
    uci -q delete subparser.settings.cron_interval 2>/dev/null || true
    uci -q delete subparser.settings.custom_interval_min 2>/dev/null || true
    uci commit subparser
fi

# Копирование модулей Python и системных утилит
rm -rf /usr/lib/subparser/*
cp -rf "${SRC_PATH}/usr/lib/subparser/"* /usr/lib/subparser/ 2>/dev/null || true

cp -f "${SRC_PATH}/etc/init.d/"* /etc/init.d/ 2>/dev/null || true
cp -f "${SRC_PATH}/usr/bin/"* /usr/bin/ 2>/dev/null || true
cp -f "${SRC_PATH}/usr/share/luci/menu.d/"* /usr/share/luci/menu.d/ 2>/dev/null || true
cp -f "${SRC_PATH}/usr/share/rpcd/acl.d/"* /usr/share/rpcd/acl.d/ 2>/dev/null || true
cp -f "${SRC_PATH}/www/luci-static/resources/view/"* /www/luci-static/resources/view/ 2>/dev/null || true
[ -f "${SRC_PATH}/etc/subparser_version" ] && cp -f "${SRC_PATH}/etc/subparser_version" /etc/subparser_version
[ -d "${SRC_PATH}/etc/hotplug.d/uci" ] && cp -f "${SRC_PATH}/etc/hotplug.d/uci/"* /etc/hotplug.d/uci/ 2>/dev/null || true

# Удаление устаревшего ACL-дубликата
rm -f /usr/share/rpcd/acl.d/subparser.json 2>/dev/null || true

echo "=== [4/6] Настройка прав доступа и компиляция ==="
chmod +x /etc/init.d/subparser /etc/init.d/subparser-bot 2>/dev/null || true
chmod +x /usr/bin/subparser* 2>/dev/null || true

# Проверка синтаксиса модулей
python3 -m py_compile /usr/lib/subparser/*.py /usr/bin/subparser-bot.py /usr/bin/subparser.py >/dev/null 2>&1 || true

echo "=== [5/6] Регистрация задач и автозапуск ==="
CRON_TMP="/tmp/cron_subparser_inst.tmp"
crontab -l 2>/dev/null | grep -v "subparser" > "$CRON_TMP" || true
echo "*/5 * * * * /usr/bin/subparser-watchdog.sh >/dev/null 2>&1" >> "$CRON_TMP"
crontab "$CRON_TMP" 2>/dev/null || true
rm -f "$CRON_TMP"
/etc/init.d/cron restart >/dev/null 2>&1 || true

REMOTE_SHA=$(curl -sL \
  -H "User-Agent: OpenWrt-SubParser-Installer" \
  "https://api.github.com/repos/${REPO_USER}/${REPO_NAME}/commits/${BRANCH}" \
  | grep '"sha":' | head -n 1 | cut -d '"' -f 4)

if [ -n "$REMOTE_SHA" ]; then
    echo "$REMOTE_SHA" > "$COMMIT_FILE"
fi

/etc/init.d/subparser enable
/etc/init.d/subparser-bot enable

EN=$(uci -q get subparser.settings.enabled)
if [ "$EN" = "1" ]; then
    /etc/init.d/subparser start
    /etc/init.d/subparser-bot start
fi

echo "=== [6/6] Обновление кэша LuCI ==="
rm -rf /tmp/luci-indexcache /tmp/luci-modulecache
/etc/init.d/rpcd reload >/dev/null 2>&1 || true

rm -rf "$TMP_DIR"

echo ""
echo "=========================================================="
echo " [OK] SubParser успешно установлен!"
echo " Откройте веб-интерфейс: LuCI -> 'Службы' -> 'SubParser'"
echo "=========================================================="