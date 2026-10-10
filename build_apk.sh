#!/bin/sh
set -e

PKG_NAME="luci-app-subparser"
PKG_VER="1.0.0"
PKG_REL="1"
OUT_DIR="./dist"

mkdir -p "$OUT_DIR"
APK_FILE="${PKG_NAME}-${PKG_VER}-r${PKG_REL}.apk"

echo "[*] Сборка нативного ADB v3 пакета через Alpine Edge..."

# Запуск в официальном контейнере Alpine Edge с нативным apk-tools 3
docker run --rm -v "$(pwd)":/work -w /work alpine:edge sh -e -c '
  apk update && apk add apk-tools tar gzip

  WORKDIR="/tmp/apk_work"
  rm -rf "$WORKDIR"
  mkdir -p "$WORKDIR"

  # 1. Скрипты post-install и pre-deinstall
  cat << "EOF" > "$WORKDIR/post-install"
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
  chmod 755 "$WORKDIR/post-install"

  cat << "EOF" > "$WORKDIR/pre-deinstall"
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
  chmod 755 "$WORKDIR/pre-deinstall"

  # 2. Формирование data-архива
  tar -czf "$WORKDIR/data.tar.gz" -C root .

  # 3. Формирование control-архива (.PKGINFO + хуки)
  cat << EOF > "$WORKDIR/.PKGINFO"
pkgname = '"$PKG_NAME"'
pkgver = '"$PKG_VER-r$PKG_REL"'
pkgdesc = LuCI interface and proxy parser for Podkop (SubParser)
url = https://github.com/ib0lit/SubParser
builddate = $(date +%s)
packager = ib0lit
size = $(du -sb root | awk "{print \$1}")
arch = all
origin = '"$PKG_NAME"'
depend = python3 curl ca-certificates conntrack
EOF

  tar -czf "$WORKDIR/control.tar.gz" -C "$WORKDIR" .PKGINFO post-install pre-deinstall

  # 4. Сборка валидного контейнера ADB v3 через apk mkpkg
  apk mkpkg \
    --output "'"$OUT_DIR/$APK_FILE"'" \
    --info "name:'"$PKG_NAME"'" \
    --info "version:'"${PKG_VER}-r${PKG_REL}"'" \
    --info "description:LuCI interface and proxy parser for Podkop" \
    --info "url:https://github.com/ib0lit/SubParser" \
    --info "arch:all" \
    --info "depends:python3 curl ca-certificates conntrack" \
    --script "post-install:$WORKDIR/post-install" \
    --script "pre-deinstall:$WORKDIR/pre-deinstall" \
    --data "$WORKDIR/data.tar.gz" 2>/dev/null || \
  apk mkpkg \
    -o "'"$OUT_DIR/$APK_FILE"'" \
    -I "name:'"$PKG_NAME"'" \
    -I "version:'"${PKG_VER}-r${PKG_REL}"'" \
    -I "arch:all" \
    -I "depends:python3 curl ca-certificates conntrack" \
    "$WORKDIR/control.tar.gz" \
    "$WORKDIR/data.tar.gz"

  rm -rf "$WORKDIR"
'

ls -lh "$OUT_DIR/$APK_FILE"