#!/bin/sh
set -e

REPO_USER="ib0lit"
REPO_NAME="SubParser"
BRANCH="main"
VERSION_FILE="/etc/subparser_version"

echo "=== [1/6] Определение пакетного менеджера и зависимостей ==="
# Временно отключаем строгий выход по ошибке на этапе пакетов
set +e

if command -v apk >/dev/null 2>&1; then
    echo "[*] Обнаружен менеджер apk (OpenWrt 25+)"
    apk update
    apk add python3 python3-urllib conntrack curl ca-certificates
elif command -v opkg >/dev/null 2>&1; then
    echo "[*] Обнаружен менеджер opkg (OpenWrt 21-24)"
    opkg update
    # Ставим только гарантированно существующие пакеты OpenWrt 21-24
    opkg install python3 python3-urllib conntrack curl ca-bundle ca-certificates
else
    echo "[!] Предупреждение: пакетный менеджер не найден. Пропуск шага."
fi

# Возвращаем строгий режим после проверки пакетов
set -e

echo "=== [2/6] Загрузка компонентов с GitHub ==="
TMP_DIR="/tmp/subparser-install"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

curl -sL "https://github.com/${REPO_USER}/${REPO_NAME}/archive/refs/heads/${BRANCH}.tar.gz?nocache=$(date +%s)" | tar -xz -C "$TMP_DIR"
SRC_PATH="${TMP_DIR}/${REPO_NAME}-${BRANCH}/root"

echo "=== [3/6] Развертывание системных файлов ==="
if [ ! -f /etc/config/subparser ]; then
    mkdir -p /etc/config
    cp -f "${SRC_PATH}/etc/config/subparser" /etc/config/subparser
fi

mkdir -p /etc/init.d /usr/bin /usr/share/luci/menu.d /usr/share/rpcd/acl.d /www/luci-static/resources/view

cp -f "${SRC_PATH}/etc/init.d/"* /etc/init.d/ 2>/dev/null || true
cp -f "${SRC_PATH}/usr/bin/"* /usr/bin/ 2>/dev/null || true
cp -f "${SRC_PATH}/usr/share/luci/menu.d/"* /usr/share/luci/menu.d/ 2>/dev/null || true
cp -f "${SRC_PATH}/usr/share/rpcd/acl.d/"* /usr/share/rpcd/acl.d/ 2>/dev/null || true
cp -f "${SRC_PATH}/www/luci-static/resources/view/"* /www/luci-static/resources/view/ 2>/dev/null || true

echo "=== [4/6] Настройка прав доступа ==="
[ -f /etc/init.d/subparser ] && chmod +x /etc/init.d/subparser
[ -f /etc/init.d/subparser-bot ] && chmod +x /etc/init.d/subparser-bot
chmod +x /usr/bin/subparser* 2>/dev/null || true

echo "=== [5/6] Регистрация задач и фиксация версии ==="
if ! crontab -l 2>/dev/null | grep -q "subparser-watchdog.sh"; then
    (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/bin/subparser-watchdog.sh >/dev/null 2>&1") | crontab -
fi

REMOTE_SHA=$(curl -sL \
  -H "User-Agent: OpenWrt-SubParser-Installer" \
  "https://api.github.com/repos/${REPO_USER}/${REPO_NAME}/commits/${BRANCH}" \
  | grep '"sha":' | head -n 1 | cut -d '"' -f 4)

if [ -n "$REMOTE_SHA" ]; then
    echo "$REMOTE_SHA" > "$VERSION_FILE"
fi

if [ -f /etc/init.d/subparser ]; then
    /etc/init.d/subparser enable
    /etc/init.d/subparser start
fi

if [ -f /etc/init.d/subparser-bot ]; then
    /etc/init.d/subparser-bot enable
    /etc/init.d/subparser-bot start
fi

echo "=== [6/6] Обновление кэша LuCI ==="
rm -rf /tmp/luci-indexcache /tmp/luci-modulecache
/etc/init.d/rpcd reload >/dev/null 2>&1 || true

rm -rf "$TMP_DIR"

echo ""
echo "=========================================================="
echo " [OK] SubParser успешно установлен!"
if [ -f "$VERSION_FILE" ]; then
    echo " Установленная версия (SHA): $(cat "$VERSION_FILE")"
fi
echo " Откройте веб-интерфейс: LuCI -> 'Службы' -> 'SubParser'"
echo "=========================================================="