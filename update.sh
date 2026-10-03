#!/bin/sh
set -e

REPO_USER="ib0lit"
REPO_NAME="SubParcer"
BRANCH="main"

echo "=== [1/4] Загрузка актуальной версии с GitHub ==="
TMP_DIR="/tmp/subparser-update"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

# Скачиваем архив ветки с обходом кэша
curl -sL "https://github.com/${REPO_USER}/${REPO_NAME}/archive/refs/heads/${BRANCH}.tar.gz?nocache=$(date +%s)" | tar -xz -C "$TMP_DIR"
SRC_PATH="${TMP_DIR}/${REPO_NAME}-${BRANCH}/root"

echo "=== [2/4] Обновление исполняемых файлов и интерфейса ==="
cp -f "${SRC_PATH}/usr/bin/"* /usr/bin/
cp -f "${SRC_PATH}/etc/init.d/"* /etc/init.d/
cp -f "${SRC_PATH}/usr/share/luci/menu.d/"* /usr/share/luci/menu.d/
cp -f "${SRC_PATH}/usr/share/rpcd/acl.d/"* /usr/share/rpcd/acl.d/
cp -f "${SRC_PATH}/www/luci-static/resources/view/"* /www/luci-static/resources/view/

chmod +x /usr/bin/subparser* /etc/init.d/subparser*

echo "=== [3/4] Перезапуск фоновых служб ==="
/etc/init.d/subparser restart >/dev/null 2>&1 || /etc/init.d/subparser start
/etc/init.d/subparser-bot restart >/dev/null 2>&1 || /etc/init.d/subparser-bot start

echo "=== [4/4] Сброс кэша интерфейса LuCI ==="
rm -rf /tmp/luci-indexcache /tmp/luci-modulecache
/etc/init.d/rpcd reload >/dev/null 2>&1 || true

rm -rf "$TMP_DIR"

echo ""
echo "=========================================================="
echo " [OK] SubParser успешно обновлен до последней версии!"
echo " Все ваши подписки и токены сохранены без изменений."
echo "=========================================================="