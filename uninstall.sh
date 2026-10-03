#!/bin/sh
set -e

echo "=== [1/5] Остановка и отключение служб ==="
/etc/init.d/subparser stop >/dev/null 2>&1 || true
/etc/init.d/subparser disable >/dev/null 2>&1 || true

/etc/init.d/subparser-bot stop >/dev/null 2>&1 || true
/etc/init.d/subparser-bot disable >/dev/null 2>&1 || true

# Убиваем возможные зависшие процессы ядра или бота
killall -9 subparser.py subparser-bot.py subparser-watchdog.sh >/dev/null 2>&1 || true

echo "=== [2/5] Удаление задач планировщика (cron) ==="
if crontab -l 2>/dev/null | grep -q "subparser"; then
    crontab -l 2>/dev/null | grep -v "subparser" | crontab -
fi

echo "=== [3/5] Удаление файлов приложения ==="
rm -f /usr/bin/subparser*
rm -f /etc/init.d/subparser /etc/init.d/subparser-bot
rm -f /etc/subparser_version
rm -f /tmp/subparser* /tmp/subparser_last_update 2>/dev/null || true

echo "=== [4/5] Удаление файлов интерфейса LuCI ==="
rm -f /usr/share/luci/menu.d/luci-app-subparser.json
rm -f /usr/share/rpcd/acl.d/luci-app-subparser.json
rm -f /usr/share/rpcd/acl.d/subparser.json
rm -f /www/luci-static/resources/view/subparser.js

# Удаляем файл настроек
rm -f /etc/config/subparser

echo "=== [5/5] Очистка кэша веб-интерфейса ==="
rm -rf /tmp/luci-indexcache /tmp/luci-modulecache
/etc/init.d/rpcd reload >/dev/null 2>&1 || true
/etc/init.d/uhttpd restart >/dev/null 2>&1 || true

echo ""
echo "=========================================================="
echo " [OK] SubParser полностью удален с маршрутизатора!"
echo " Меню LuCI и фоновые процессы очищены."
echo "=========================================================="