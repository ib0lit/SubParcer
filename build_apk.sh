#!/bin/sh
set -e

PKG_NAME="luci-app-subparser"
PKG_VER="1.0.0"
PKG_REL="1"
OUT_DIR="./dist"

mkdir -p "$OUT_DIR"
APK_FILE="${PKG_NAME}-${PKG_VER}-r${PKG_REL}.apk"

# Если запуск внутри Alpine (в GitHub Actions), собираем напрямую через apk mkpkg
if command -v apk >/dev/null 2>&1 && apk --help 2>&1 | grep -q "mkpkg"; then
  echo "[*] Обнаружен нативный apk-tools, собираем пакет..."
  mkdir -p /tmp/scripts
  cat << 'EOF' > /tmp/scripts/post-install
#!/bin/sh
/etc/init.d/subparser enable >/dev/null 2>&1 || true
/etc/init.d/subparser-bot enable >/dev/null 2>&1 || true
CRON_TMP="/tmp/cron_subparser_apk.tmp"
crontab -l 2>/dev/null | grep -v "subparser-watchdog.sh" > "$CRON_TMP" || true
echo "*/5 * * * * /usr/bin/subparser-watchdog.sh >/dev/null 2>&1" >> "$CRON_TMP"
crontab "$CRON_TMP" 2>/dev/null || true
rm -f "$CRON_TMP"
/etc/init.d/cron restart >/dev/null 2>&1 || true
rm -rf /tmp/luci-indexcache /tmp/luci-modulecache
/etc/init.d/rpcd reload >/dev/null 2>&1 || true
exit 0
EOF
  chmod 755 /tmp/scripts/post-install

  cat << 'EOF' > /tmp/scripts/pre-deinstall
#!/bin/sh
/etc/init.d/subparser stop >/dev/null 2>&1 || true
/etc/init.d/subparser disable >/dev/null 2>&1 || true
/etc/init.d/subparser-bot stop >/dev/null 2>&1 || true
/etc/init.d/subparser-bot disable >/dev/null 2>&1 || true
killall -9 subparser.py subparser-bot.py subparser-watchdog.sh >/dev/null 2>&1 || true
CRON_TMP="/tmp/cron_subparser_prerm.tmp"
crontab -l 2>/dev/null | grep -v "subparser" > "$CRON_TMP" || true
crontab "$CRON_TMP" 2>/dev/null || true
rm -f "$CRON_TMP"
/etc/init.d/cron restart >/dev/null 2>&1 || true
exit 0
EOF
  chmod 755 /tmp/scripts/pre-deinstall

  tar -czf /tmp/data.tar.gz -C root .

  apk mkpkg \
    --output "$OUT_DIR/$APK_FILE" \
    --info "name:$PKG_NAME" \
    --info "version:${PKG_VER}-r${PKG_REL}" \
    --info "description:LuCI interface and proxy parser for Podkop" \
    --info "url:https://github.com/ib0lit/SubParser" \
    --info "arch:all" \
    --info "depends:python3 curl ca-certificates conntrack" \
    --script "post-install:/tmp/scripts/post-install" \
    --script "pre-deinstall:/tmp/scripts/pre-deinstall" \
    --data /tmp/data.tar.gz

  echo "[OK] Пакет собран: $OUT_DIR/$APK_FILE"
  exit 0
fi

# Если запуск локально на Windows и Docker запущен
if docker info >/dev/null 2>&1; then
  echo "[*] Сборка через Docker..."
  docker run --rm -v "$(pwd)":/work -w /work alpine:edge sh -c "
    apk update && apk add apk-tools tar gzip
    ./build_apk.sh
  "
  exit 0
fi

echo "[!] Локальный Docker не запущен. Пакет соберется автоматически в GitHub Actions при пуше релиза."