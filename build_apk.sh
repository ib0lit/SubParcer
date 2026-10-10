#!/bin/sh
set -e

PKG_NAME="luci-app-subparser"
PKG_VER="1.0.0"
PKG_REL="1"
OUT_DIR="./dist"

mkdir -p "$OUT_DIR"
APK_FILE="${PKG_NAME}-${PKG_VER}-r${PKG_REL}.apk"

echo "[*] Сборка нативного пакета APK..."

python3 - << 'EOF'
import os
import sys
import tarfile
import hashlib
import io
import time

pkg_name = "luci-app-subparser"
pkg_ver = "1.0.0-r1"
root_dir = "root"
out_apk = "dist/luci-app-subparser-1.0.0-r1.apk"

pkginfo = f"""pkgname = {pkg_name}
pkgver = {pkg_ver}
pkgdesc = LuCI interface and proxy parser for Podkop (SubParser)
url = https://github.com/ib0lit/SubParser
builddate = {int(time.time())}
packager = ib0lit
size = 200000
arch = all
origin = {pkg_name}
depend = python3 curl ca-certificates conntrack
"""

post_install = """#!/bin/sh
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
"""

pre_deinstall = """#!/bin/sh
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
"""

# 1. Поток control.tar.gz
control_buf = io.BytesIO()
with tarfile.open(fileobj=control_buf, mode="w:gz") as tar:
    def add_file(name, content, mode=0o644):
        data = content.encode("utf-8")
        ti = tarfile.TarInfo(name=name)
        ti.size = len(data)
        ti.mtime = int(time.time())
        ti.mode = mode
        tar.addfile(ti, io.BytesIO(data))

    add_file(".PKGINFO", pkginfo)
    add_file(".post-install", post_install, 0o755)
    add_file(".pre-deinstall", pre_deinstall, 0o755)
control_bytes = control_buf.getvalue()

# 2. Поток data.tar.gz со всеми файлами из root
data_buf = io.BytesIO()
with tarfile.open(fileobj=data_buf, mode="w:gz", format=tarfile.PAX_FORMAT) as tar:
    for r, dirs, files in os.walk(root_dir):
        for f in files:
            full_p = os.path.join(r, f)
            rel_p = os.path.relpath(full_p, root_dir).replace("\\", "/")
            with open(full_p, "rb") as fp:
                data = fp.read()
            ti = tarfile.TarInfo(name=rel_p)
            ti.size = len(data)
            ti.mtime = int(os.path.getmtime(full_p))
            ti.mode = 0o755 if ("usr/bin" in rel_p or "etc/init.d" in rel_p) else 0o644
            
            # Чексумма для валидации apk-tools
            sha1 = hashlib.sha1(data).digest()
            ti.pax_headers['APK-TOOLS.checksum.SHA1'] = sha1.hex()
            tar.addfile(ti, io.BytesIO(data))
data_bytes = data_buf.getvalue()

# Запись итогового apk
os.makedirs(os.path.dirname(out_apk), exist_ok=True)
with open(out_apk, "wb") as f_out:
    f_out.write(control_bytes)
    f_out.write(data_bytes)

print(f"[OK] Размер APK файла: {os.path.getsize(out_apk)} байт")
EOF

ls -lh "$OUT_DIR/$APK_FILE"