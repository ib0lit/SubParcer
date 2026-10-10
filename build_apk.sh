#!/bin/sh
set -e

PKG_NAME="luci-app-subparser"
PKG_VER="1.0.0"
PKG_REL="1"
OUT_DIR="./dist"

mkdir -p "$OUT_DIR"
APK_FILE="${PKG_NAME}-${PKG_VER}-r${PKG_REL}.apk"

# 1. Если apk mkpkg уже доступен в системе
if ! command -v apk >/dev/null 2>&1 || ! apk --help 2>&1 | grep -q "mkpkg"; then
  echo "[*] Установка зависимостей и сборка нативного apk-tools 3..."
  sudo apt-get update -qq
  sudo apt-get install -y -qq meson ninja-build libssl-dev libzstd-dev zlib1g-dev scdoc
  
  TMP_SRC="/tmp/apk_tools_build"
  rm -rf "$TMP_SRC"
  git clone --depth 1 https://gitlab.alpinelinux.org/alpine/apk-tools.git "$TMP_SRC"
  meson setup "$TMP_SRC/build" "$TMP_SRC" -Ddocs=disabled -Dhelp=disabled
  ninja -C "$TMP_SRC/build"
  sudo cp "$TMP_SRC/build/src/apk" /usr/local/bin/apk
fi

echo "[*] Сборка пакета через apk mkpkg..."
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
  /tmp/data.tar.gz

ls -lh "$OUT_DIR/$APK_FILE"
echo "[OK] Пакет собран: $OUT_DIR/$APK_FILE"