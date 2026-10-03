#!/bin/sh
set -e

REPO_USER="ib0lit"
REPO_NAME="SubParcer"
BRANCH="main"
VERSION_FILE="/etc/subparser_version"

echo "=== [1/4] Проверка наличия обновлений ==="

# Получаем SHA последнего коммита из GitHub API
REMOTE_SHA=$(curl -sL \
  -H "User-Agent: OpenWrt-SubParser-Updater" \
  "https://api.github.com/repos/${REPO_USER}/${REPO_NAME}/commits/${BRANCH}" \
  | grep '"sha":' | head -n 1 | cut -d '"' -f 4)

# Если не удалось получить SHA (например, проблемы с сетью), переходим к обновлению без проверки
if [ -z "$REMOTE_SHA" ]; then
    echo "[!] Не удалось определить версию на GitHub. Выполняем принудительное обновление..."
else
    # Проверяем локальную версию
    if [ -f "$VERSION_FILE" ]; then
        LOCAL_SHA=$(cat "$VERSION_FILE" 2>/dev/null || true)
        if [ "$LOCAL_SHA" = "$REMOTE_SHA" ]; then
            echo ""
            echo "=========================================================="
            echo " [i] Обновлений нет. У вас установлена актуальная версия!"
            echo " SHA коммита: ${LOCAL_SHA}"
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

echo "=== [3/4] Применение обновлений ==="
cp -f "${SRC_PATH}/usr/bin/"* /usr/bin/
cp -f "${SRC_PATH}/etc/init.d/"* /etc/init.d/
cp -f "${SRC_PATH}/usr/share/luci/menu.d/"* /usr/share/luci/menu.d/
cp -f "${SRC_PATH}/usr/share/rpcd/acl.d/"* /usr/share/rpcd/acl.d/
cp -f "${SRC_PATH}/www/luci-static/resources/view/"* /www/luci-static/resources/view/

chmod +x /usr/bin/subparser* /etc/init.d/subparser*

# Сохраняем новый хэш коммита
if [ -n "$REMOTE_SHA" ]; then
    echo "$REMOTE_SHA" > "$VERSION_FILE"
fi

echo "=== [4/4] Перезапуск служб и очистка кэша LuCI ==="
/etc/init.d/subparser restart >/dev/null 2>&1 || /etc/init.d/subparser start
/etc/init.d/subparser-bot restart >/dev/null 2>&1 || /etc/init.d/subparser-bot start

rm -rf /tmp/luci-indexcache /tmp/luci-modulecache
/etc/init.d/rpcd reload >/dev/null 2>&1 || true

rm -rf "$TMP_DIR"

echo ""
echo "=========================================================="
echo " [OK] SubParser успешно обновлен до последней версии!"
echo " Все ваши подписки и токены сохранены без изменений."
echo "=========================================================="