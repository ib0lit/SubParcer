#!/bin/sh
set -e

REPO_USER="ib0lit"
REPO_NAME="SubParcer"
BRANCH="main"

echo "=== [1/6] Установка системных зависимостей ==="
if command -v apk >/dev/null 2>&1; then
    echo "Используется пакетный менеджер apk..."
    apk update
    apk add python3 python3-urllib python3-ssl conntrack-tools curl
elif command -v opkg >/dev/null 2>&1; then
    echo "Используется пакетный менеджер opkg..."
    opkg update
    opkg install python3 python3-urllib python3-ssl conntrack curl
else
    echo "Пакетный менеджер не обнаружен, пропускаем установку зависимостей."
fi

echo "=== [2/6] Загрузка компонентов из GitHub ==="
TMP_DIR="/tmp/subparser-install"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

curl -sL "https://github.com/${REPO_USER}/${REPO_NAME}/archive/refs/heads/${BRANCH}.tar.gz" | tar -xz -C "$TMP_DIR"

# Папка с исходными файлами из распакованного архива
SRC_PATH="${TMP_DIR}/${REPO_NAME}-${BRANCH}/root"

echo "=== [3/6] Копирование компонентов в систему ==="
# Копируем конфигурацию только если её еще нет в системе
if [ ! -f /etc/config/subparser ]; then
    mkdir -p /etc/config
    cp -f "${SRC_PATH}/etc/config/subparser" /etc/config/subparser
fi

mkdir -p /etc/init.d /usr/bin /usr/share/luci/menu.d /usr/share/rpcd/acl.d /www/luci-static/resources/view

cp -f "${SRC_PATH}/etc/init.d/"* /etc/init.d/
cp -f "${SRC_PATH}/usr/bin/"* /usr/bin/
cp -f "${SRC_PATH}/usr/share/luci/menu.d/"* /usr/share/luci/menu.d/
cp -f "${SRC_PATH}/usr/share/rpcd/acl.d/"* /usr/share/rpcd/acl.d/
cp -f "${SRC_PATH}/www/luci-static/resources/view/"* /www/luci-static/resources/view/

echo "=== [4/6] Настройка прав исполнения файлов ==="
chmod +x /etc/init.d/subparser /etc/init.d/subparser-bot
chmod +x /usr/bin/subparser*

echo "=== [5/6] Регистрация задач и запуск служб ==="
# Добавляем watchdog в cron, если задачи еще нет
if ! crontab -l 2>/dev/null | grep -q "subparser-watchdog.sh"; then
    (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/bin/subparser-watchdog.sh >/dev/null 2>&1") | crontab -
fi

/etc/init.d/subparser enable
/etc/init.d/subparser start

/etc/init.d/subparser-bot enable
/etc/init.d/subparser-bot start

echo "=== [6/6] Обновление кэша веб-интерфейса LuCI ==="
rm -rf /tmp/luci-indexcache /tmp/luci-modulecache
/etc/init.d/rpcd restart >/dev/null 2>&1 || true

rm -rf "$TMP_DIR"

echo ""
echo "=========================================================="
echo " [OK] SubParser успешно установлен и обновлен!"
echo " Откройте веб-интерфейс: LuCI -> 'Службы' -> 'SubParser'"
echo "=========================================================="