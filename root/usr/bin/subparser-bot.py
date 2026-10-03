#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import time
import json
import ssl
import socket
import subprocess
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

CONFIG_NAME = "subparser"
LOCK_FILE = "/var/run/subparser.lock"
SINGBOX_BIN = "/usr/bin/sing-box"
LOG_FILE = "/tmp/subparser_sync.log"
BLOCKED_FILE = "/tmp/bot_blocked_macs.json"
TEST_URL_GLOBAL = "https://www.gstatic.com/generate_204"

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

def get_uci_val(opt, default=""):
    try:
        out = subprocess.check_output(["uci", "-q", "get", f"{CONFIG_NAME}.settings.{opt}"], text=True).strip()
        return out if out else default
    except Exception:
        return default

def set_uci_val(opt, val):
    try:
        subprocess.run(["uci", "set", f"{CONFIG_NAME}.settings.{opt}={val}"], check=False)
        subprocess.run(["uci", "commit", CONFIG_NAME], check=False)
        return True
    except Exception:
        return False

def check_credentials():
    token = get_uci_val("tg_bot_token")
    admin_id = get_uci_val("tg_chat_id")
    if not token or not admin_id or token == "null" or admin_id == "null":
        return None, None
    return str(token).strip(), str(admin_id).strip()

def tg_api(token, method, params=None, timeout=15):
    url = f"https://api.telegram.org/bot{token}/{method}"
    if params:
        data = json.dumps(params).encode('utf-8')
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    else:
        req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except Exception:
        return None

def send_msg(token, chat_id, text, reply_markup=None):
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
    if reply_markup: payload["reply_markup"] = reply_markup
    return tg_api(token, "sendMessage", payload, timeout=10)

def edit_msg(token, chat_id, message_id, text, reply_markup=None):
    payload = {"chat_id": chat_id, "message_id": message_id, "text": text, "parse_mode": "HTML"}
    if reply_markup: payload["reply_markup"] = reply_markup
    return tg_api(token, "editMessageText", payload, timeout=10)

def answer_callback(token, cb_id, text=None):
    payload = {"callback_query_id": cb_id}
    if text: payload["text"] = text
    tg_api(token, "answerCallbackQuery", payload, timeout=5)

def get_blocked_macs():
    if os.path.exists(BLOCKED_FILE):
        try:
            with open(BLOCKED_FILE, "r") as f:
                raw = json.load(f)
                return [m.upper() for m in raw]
        except Exception:
            return []
    return []

def save_blocked_macs(mac_list):
    try:
        with open(BLOCKED_FILE, "w") as f:
            json.dump([m.upper() for m in mac_list], f)
    except Exception: pass

def init_bot_firewall():
    subprocess.run(["nft", "add", "table", "inet", "bot_block"], stderr=subprocess.DEVNULL, check=False)
    subprocess.run([
        "nft", "add", "chain", "inet", "bot_block", "prerouting",
        "{ type filter hook prerouting priority -300; policy accept; }"
    ], stderr=subprocess.DEVNULL, check=False)
    subprocess.run(["nft", "add", "set", "inet", "bot_block", "blocked_ips", "{ type ipv4_addr; }"], stderr=subprocess.DEVNULL, check=False)
    subprocess.run(["nft", "flush", "chain", "inet", "bot_block", "prerouting"], stderr=subprocess.DEVNULL, check=False)
    subprocess.run(["nft", "add", "rule", "inet", "bot_block", "prerouting", "ip", "saddr", "@blocked_ips", "meta", "l4proto", "tcp", "reject", "with", "tcp", "reset"], stderr=subprocess.DEVNULL, check=False)
    subprocess.run(["nft", "add", "rule", "inet", "bot_block", "prerouting", "ip", "saddr", "@blocked_ips", "reject"], stderr=subprocess.DEVNULL, check=False)

def get_ip_by_mac(mac):
    mac_upper = mac.upper()
    try:
        with open("/tmp/dhcp.leases", "r") as f:
            for l in f:
                p = l.strip().split()
                if len(p) >= 4 and p[1].upper() == mac_upper:
                    return p[2]
    except Exception: pass
    try:
        with open("/proc/net/arp", "r") as f:
            for l in f.readlines()[1:]:
                p = l.strip().split()
                if len(p) >= 4 and p[3].upper() == mac_upper:
                    return p[0]
    except Exception: pass
    return None

def apply_mac_firewall(mac, block=True):
    init_bot_firewall()
    ip = get_ip_by_mac(mac)
    if block:
        if ip:
            subprocess.run(["nft", "add", "element", "inet", "bot_block", "blocked_ips", f"{{ {ip} }}"], stderr=subprocess.DEVNULL, check=False)
            subprocess.run(["conntrack", "-D", "-s", ip], stderr=subprocess.DEVNULL, check=False)
            subprocess.run(["conntrack", "-D", "-d", ip], stderr=subprocess.DEVNULL, check=False)
            subprocess.run(["ip", "neigh", "flush", "to", ip], stderr=subprocess.DEVNULL, check=False)
    else:
        if ip:
            subprocess.run(["nft", "delete", "element", "inet", "bot_block", "blocked_ips", f"{{ {ip} }}"], stderr=subprocess.DEVNULL, check=False)

def get_podkop_links():
    try:
        raw = subprocess.check_output(["uci", "-q", "get", "podkop.main.urltest_proxy_links"], text=True).strip()
        return [l.strip() for l in raw.split() if l.strip()] if raw else []
    except Exception:
        return []

def get_node_name(link, idx):
    try:
        frag = urllib.parse.urlsplit(link).fragment
        if frag: return urllib.parse.unquote(frag)
    except Exception: pass
    return f"Сервер #{idx+1}"

def get_wifi_stations():
    wifi_data = {}
    try:
        res = subprocess.check_output(["ubus", "list", "hostapd.*"], text=True, stderr=subprocess.DEVNULL)
        h_objs = [line.strip() for line in res.splitlines() if line.strip()]
        for obj in h_objs:
            band = "5G" if ("5" in obj or "phy1" in obj) else "2.4G"
            try:
                raw_json = subprocess.check_output(["ubus", "call", obj, "get_clients"], text=True, stderr=subprocess.DEVNULL)
                c_data = json.loads(raw_json)
                clients_map = c_data.get("clients", {})
                for mac, meta in clients_map.items():
                    sig = meta.get("signal", -100)
                    tx_rate = meta.get("tx", {}).get("rate", 0)
                    tx_mbps = f"{tx_rate / 1000:.1f} M" if tx_rate > 1000 else (f"{tx_rate} M" if tx_rate > 0 else "")
                    if sig >= -55: s_ico = "📶 Отличный"
                    elif sig >= -70: s_ico = "📶 Хороший"
                    elif sig >= -82: s_ico = "🛜 Средний"
                    else: s_ico = "🛜 Слабый"

                    wifi_data[mac.upper()] = {
                        "type": f"Wi-Fi {band}",
                        "signal": f"{s_ico} ({sig} dBm)",
                        "tx": tx_mbps
                    }
            except Exception: pass
    except Exception: pass

    if not wifi_data:
        try:
            out = subprocess.check_output(["iw", "dev"], text=True, stderr=subprocess.DEVNULL)
            import re
            ifaces = re.findall(r"Interface\s+([a-zA-Z0-9_\-\.]+)", out)
            for iface in ifaces:
                band = "5G" if ("5" in iface or "rax" in iface) else "2.4G"
                st_dump = subprocess.check_output(["iw", "dev", iface, "station", "dump"], text=True, stderr=subprocess.DEVNULL)
                cur_mac = None
                for line in st_dump.splitlines():
                    m = re.match(r"^Station\s+([0-9a-fA-F:]{17})", line.strip())
                    if m:
                        cur_mac = m.group(1).upper()
                        wifi_data[cur_mac] = {"type": f"Wi-Fi {band}", "signal": "Wi-Fi", "tx": ""}
                    elif cur_mac:
                        if "signal:" in line:
                            val = line.split("signal:")[1].strip().split()[0]
                            try:
                                s = int(float(val))
                                s_ico = "📶 Отличный" if s >= -60 else ("📶 Хороший" if s >= -72 else "🛜 Средний")
                                wifi_data[cur_mac]["signal"] = f"{s_ico} ({s} dBm)"
                            except Exception: pass
                        elif "tx bitrate:" in line:
                            wifi_data[cur_mac]["tx"] = line.split("tx bitrate:")[1].strip().split()[0] + " M"
        except Exception: pass

    return wifi_data

def get_clients_screen():
    clients = {}
    lease_file = "/tmp/dhcp.leases"
    if os.path.exists(lease_file):
        try:
            with open(lease_file, "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        mac = parts[1].upper()
                        ip = parts[2]
                        hname = parts[3]
                        if hname == "*": hname = "Без имени"
                        clients[ip] = {"mac": mac, "name": hname}
        except Exception: pass

    arp_file = "/proc/net/arp"
    if os.path.exists(arp_file):
        try:
            with open(arp_file, "r") as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 6:
                        ip = parts[0]
                        mac = parts[3].upper()
                        flags = parts[2]
                        if flags != "0x0" and mac != "00:00:00:00:00:00":
                            if ip not in clients:
                                clients[ip] = {"mac": mac, "name": "Статический IP"}
        except Exception: pass

    if not clients:
        text = "👥 <b>Подключенные устройства</b>\n\nАктивные клиенты не обнаружены."
        kb = {"inline_keyboard": [[{"text": "◀️ В главное меню", "callback_data": "home"}]]}
    else:
        wifi_info = get_wifi_stations()
        blocked = get_blocked_macs()

        def ip_sort_key(ip_str):
            try: return [int(p) for p in ip_str.split(".")]
            except Exception: return [0, 0, 0, 0]

        sorted_ips = sorted(clients.keys(), key=ip_sort_key)
        lines = []
        keyboard = []

        for i, ip in enumerate(sorted_ips, 1):
            c = clients[ip]
            mac = c["mac"]
            is_bl = mac in blocked
            bl_icon = "🚫 " if is_bl else ""

            if mac in wifi_info:
                w = wifi_info[mac]
                tx_part = f" (<code>{w['tx']}</code>)" if w.get("tx") else ""
                conn_badge = f"🛜 <b>{w['type']}</b> | {w['signal']}{tx_part}"
            else:
                conn_badge = "🔌 <b>LAN Кабель</b>"

            lines.append(
                f"{i}. {bl_icon}<b>{c['name']}</b>\n"
                f"   ├ IP: <code>{ip}</code> | MAC: <code>{mac}</code>\n"
                f"   └ Связь: {conn_badge}"
            )
            keyboard.append([{"text": f"⚙️ {bl_icon}{c['name'][:18]} ({ip})", "callback_data": f"dev:{mac}"}])

        text = (
            f"👥 <b>Устройства в сети ({len(clients)} шт.)</b>\n\n"
            + "\n\n".join(lines) +
            "\n\n<i>Выберите устройство для управления доступом:</i>"
        )
        keyboard.append([{"text": "🔄 Обновить список", "callback_data": "clients"}])
        keyboard.append([{"text": "◀️ В главное меню", "callback_data": "home"}])
        kb = {"inline_keyboard": keyboard}

    return text, kb

def get_device_action_screen(mac, force_blocked=None):
    mac_u = mac.upper()
    if force_blocked is not None:
        is_blocked = force_blocked
    else:
        blocked = [m.upper() for m in get_blocked_macs()]
        is_blocked = mac_u in blocked

    ip = get_ip_by_mac(mac_u) or "н/д"
    hname = "Устройство"
    if os.path.exists("/tmp/dhcp.leases"):
        try:
            with open("/tmp/dhcp.leases", "r") as f:
                for line in f:
                    p = line.strip().split()
                    if len(p) >= 4 and p[1].upper() == mac_u:
                        hname = p[3] if p[3] != "*" else "Без имени"
                        break
        except Exception: pass

    if is_blocked:
        status_badge = "🔴 <b>Интернет заблокирован</b>"
        btn_text = "✅ Разблокировать доступ"
        action = f"unblk:{mac_u}"
    else:
        status_badge = "🟢 <b>Доступ открыт</b>"
        btn_text = "🚫 Заблокировать интернет"
        action = f"blk:{mac_u}"

    text = (
        f"📱 <b>Управление клиентом: {hname}</b>\n\n"
        f"• <b>IP адрес:</b> <code>{ip}</code>\n"
        f"• <b>MAC адрес:</b> <code>{mac_u}</code>\n"
        f"• <b>Статус:</b> {status_badge}\n"
    )
    kb = {
        "inline_keyboard": [
            [{"text": btn_text, "callback_data": action}],
            [{"text": "◀️ Назад к списку устройств", "callback_data": "clients"}]
        ]
    }
    return text, kb

def analyze_custom_url(raw_input):
    try:
        text = raw_input.strip()
        if "://" in text:
            parsed = urllib.parse.urlsplit(text)
            domain = parsed.hostname or parsed.netloc
            test_url = text
        else:
            domain = text.split("/")[0].split(":")[0]
            test_url = f"https://{text}"

        is_proxied = False
        resolved_ip = "н/д"
        try:
            addrinfo = socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
            if addrinfo:
                resolved_ip = addrinfo[0][4][0]
                if resolved_ip.startswith("198.18.") or resolved_ip.startswith("198.19."):
                    is_proxied = True
        except Exception:
            resolved_ip = "DNS ошибка"

        headers = {"User-Agent": "curl/7.88.1"}
        ms = -1
        status_text = "🔴 Не отвечает"
        t0 = time.time()
        try:
            req = urllib.request.Request(test_url, headers=headers)
            with urllib.request.urlopen(req, timeout=3.5, context=SSL_CTX) as r:
                ms = int((time.time() - t0) * 1000)
                status_text = f"🟢 Доступен ({r.status}, <code>{ms} ms</code>)"
        except urllib.error.HTTPError as he:
            ms = int((time.time() - t0) * 1000)
            status_text = f"🟢 Доступен (HTTP {he.code}, <code>{ms} ms</code>)"
        except Exception:
            status_text = "🔴 Ошибка соединения / Блок"

        route_badge = "🛡 <b>Туннель Podkop (Fake-IP)</b>" if is_proxied else "🇷🇺 <b>Напрямую без VPN (Провайдер РФ)</b>"
        return (
            f"🔍 <b>Диагностика маршрута:</b> <code>{domain}</code>\n\n"
            f"• <b>Маршрут:</b> {route_badge}\n"
            f"• <b>Резолв IP:</b> <code>{resolved_ip}</code>\n"
            f"• <b>Отклик:</b> {status_text}\n"
            f"• <b>Проверен URL:</b> <code>{test_url[:50]}</code>"
        )
    except Exception as e:
        return f"⚠️ Ошибка при анализе адреса: {e}"

def get_system_metrics():
    uptime_str = "н/д"
    try:
        with open("/proc/uptime", "r") as f:
            up_secs = int(float(f.readline().split()[0]))
            d, rem = divmod(up_secs, 86400)
            h, rem = divmod(rem, 3600)
            m, s = divmod(rem, 60)
            uptime_str = f"{d}д {h}ч {m}м" if d > 0 else f"{h}ч {m}м {s}с"
    except Exception: pass

    temp_str = "н/д"
    for path in ["/sys/class/thermal/thermal_zone0/temp", "/sys/class/hwmon/hwmon0/temp1_input"]:
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    val = float(f.read().strip())
                    if val > 1000: val /= 1000
                    temp_str = f"{val:.1f}°C"
                    break
            except Exception: pass

    load_str = "н/д"
    try:
        with open("/proc/loadavg", "r") as f:
            parts = f.read().strip().split()
            load_str = f"{parts[0]}, {parts[1]}, {parts[2]}"
    except Exception: pass

    ram_str = "н/д"
    ram_bar = ""
    try:
        mem = {}
        with open("/proc/meminfo", "r") as f:
            for l in f:
                k, v = l.split(":")
                mem[k.strip()] = int(v.split()[0])
        total = mem.get("MemTotal", 0) // 1024
        avail = mem.get("MemAvailable", mem.get("MemFree", 0)) // 1024
        used = total - avail
        pct = int((used / total) * 100) if total > 0 else 0
        filled = pct // 10
        ram_bar = f"[{'█' * filled}{'░' * (10 - filled)}] {pct}%"
        ram_str = f"{used} MB / {total} MB"
    except Exception: pass

    text = (
        "📟 <b>Системные ресурсы роутера</b>\n\n"
        f"• <b>Время работы:</b> <code>{uptime_str}</code>\n"
        f"• <b>Температура SoC:</b> <code>{temp_str}</code>\n"
        f"• <b>Load Average:</b> <code>{load_str}</code>\n"
        f"• <b>Память RAM:</b> <code>{ram_str}</code>\n"
        f"  <code>{ram_bar}</code>\n"
    )
    kb = {
        "inline_keyboard": [
            [{"text": "🔄 Обновить показатели", "callback_data": "sysinfo"}],
            [{"text": "◀️ В главное меню", "callback_data": "home"}]
        ]
    }
    return text, kb

def check_single_service(item):
    name, domain, url = item
    is_proxied = False
    try:
        addrinfo = socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
        if addrinfo:
            ip = addrinfo[0][4][0]
            if ip.startswith("198.18.") or ip.startswith("198.19."):
                is_proxied = True
    except Exception: pass

    headers = {"User-Agent": "curl/7.88.1"}
    ms = -1
    ok = False
    t0 = time.time()
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=3.0, context=SSL_CTX) as r:
            ms = int((time.time() - t0) * 1000)
            ok = True
    except urllib.error.HTTPError:
        ms = int((time.time() - t0) * 1000)
        ok = True
    except Exception:
        ok = False

    return name, is_proxied, ok, ms

def get_services_status_screen():
    targets = [
        ("YouTube", "www.youtube.com", "https://www.youtube.com/generate_204"),
        ("Discord", "discord.com", "https://discord.com/api/v9/gateway"),
        ("Steam", "store.steampowered.com", "https://store.steampowered.com/"),
        ("Instagram", "www.instagram.com", "https://www.instagram.com/robots.txt"),
        ("TikTok", "www.tiktok.com", "https://www.tiktok.com/robots.txt"),
        ("Яндекс", "ya.ru", "https://ya.ru/robots.txt"),
        ("Госуслуги", "www.gosuslugi.ru", "https://www.gosuslugi.ru/robots.txt")
    ]
    with ThreadPoolExecutor(max_workers=7) as pool:
        results = list(pool.map(check_single_service, targets))

    lines = []
    for name, is_proxied, ok, ms in results:
        route_badge = "🛡 <i>Прокси</i>" if is_proxied else "🇷🇺 <i>Прямой</i>"
        if ok and ms > 0:
            status_badge = f"🟢 <code>{ms} ms</code>"
        else:
            status_badge = "🔴 <b>Блок / Таймаут</b>"
        lines.append(f"• <b>{name}</b>: {status_badge} | {route_badge}")

    text = (
        "🧭 <b>Маршрутизация и доступность сервисов</b>\n\n"
        + "\n".join(lines) +
        "\n\n<i>🛡 Прокси — через туннель Podkop (Fake-IP)\n🇷🇺 Прямой — без VPN через провайдера РФ\n\n💡 <b>Отправьте любую ссылку в чат для проверки!</b></i>"
    )
    kb = {
        "inline_keyboard": [
            [{"text": "🔄 Перепроверить статус", "callback_data": "check_services"}],
            [{"text": "◀️ В главное меню", "callback_data": "home"}]
        ]
    }
    return text, kb

def get_config_screen():
    threshold = get_uci_val("ping_threshold", "350")
    filter_ru = get_uci_val("filter_ru", "1")
    ru_state = "ВКЛ 🇷🇺" if filter_ru == "1" else "ВЫКЛ 🌐"
    text = (
        "⚙️ <b>Параметры парсинга SubParser</b>\n\n"
        f"• <b>Порог пинга:</b> <code>{threshold} ms</code>\n"
        f"• <b>Фильтр узлов РФ:</b> <code>{ru_state}</code>\n\n"
        "<i>Нажмите кнопку ниже для быстрой смены параметров:</i>"
    )
    kb = {
        "inline_keyboard": [
            [
                {"text": "250 ms" + (" ✅" if threshold == "250" else ""), "callback_data": "th:250"},
                {"text": "350 ms" + (" ✅" if threshold == "350" else ""), "callback_data": "th:350"},
                {"text": "450 ms" + (" ✅" if threshold == "450" else ""), "callback_data": "th:450"}
            ],
            [{"text": f"Фильтр РФ: {ru_state}", "callback_data": "toggle_ru"}],
            [{"text": "📄 Лог парсера", "callback_data": "view_log"}],
            [{"text": "◀️ В главное меню", "callback_data": "home"}]
        ]
    }
    return text, kb

def get_log_screen():
    log_text = "Лог пуст или еще не создан."
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                log_text = "".join(lines[-15:]).strip()
        except Exception as e:
            log_text = f"Ошибка чтения лога: {e}"

    text = f"📄 <b>Последние строки лога парсера:</b>\n\n<pre>{log_text[:3500]}</pre>"
    kb = {
        "inline_keyboard": [
            [{"text": "🔄 Обновить лог", "callback_data": "view_log"}],
            [{"text": "◀️ К настройкам", "callback_data": "settings"}]
        ]
    }
    return text, kb

def get_reboot_confirm_screen():
    text = "⚠️️ <b>Подтверждение перезагрузки роутера</b>\n\nВы действительно хотите перезагрузить устройство?"
    kb = {
        "inline_keyboard": [
            [{"text": "✅ Да, перезагрузить!", "callback_data": "do_reboot"}],
            [{"text": "❌ Отмена", "callback_data": "home"}]
        ]
    }
    return text, kb

def get_podkop_service_status():
    pid = ""
    try:
        pids = subprocess.check_output(["pidof", "sing-box"], text=True, stderr=subprocess.DEVNULL).strip().split()
        if pids: pid = pids[0]
    except Exception: pass

    service_ok = False
    try:
        res = subprocess.run(["/etc/init.d/podkop", "status"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode == 0 or "running" in res.stdout.lower() or pid:
            service_ok = True
    except Exception:
        if pid: service_ok = True

    ram_mb = "н/д"
    if pid:
        try:
            with open(f"/proc/{pid}/status", "r") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        rss_kb = int(line.split()[1])
                        ram_mb = f"{rss_kb / 1024:.1f} MB"
                        break
        except Exception: pass

    mode_str = "TPROXY / iptables"
    try:
        ip_out = subprocess.check_output(["ip", "-o", "link", "show"], text=True, stderr=subprocess.DEVNULL)
        for line in ip_out.splitlines():
            for ifn in ["tun-podkop", "sing-tun", "podkop", "tun0"]:
                if f" {ifn}:" in line or f" {ifn}@" in line:
                    mode_str = f"TUN ({ifn})"
                    break
    except Exception: pass

    return service_ok, pid, ram_mb, mode_str

def get_status_screen():
    links = get_podkop_links()
    svc_ok, pid, ram_mb, mode_str = get_podkop_service_status()
    st_badge = "🟢 Запущена" if svc_ok else "🔴 Остановлена"
    
    ps_check = subprocess.run(["pgrep", "-f", "subparser.py"], stdout=subprocess.PIPE, text=True)
    is_sync = "⏳ Выполняется" if ps_check.stdout.strip() else "💤 В ожидании"

    text = (
        "📊 <b>Детальный статус системы и Podkop</b>\n\n"
        f"• <b>Служба Podkop:</b> {st_badge}\n"
        f"• <b>Ядро sing-box:</b> " + (f"🟢 PID {pid} (RAM: <code>{ram_mb}</code>)" if pid else "🔴 Остановлен") + "\n"
        f"• <b>Режим трафика:</b> <code>{mode_str}</code>\n"
        f"• <b>Серверов в пуле:</b> <code>{len(links)} шт.</code>\n"
        f"• <b>Синхронизация SubParser:</b> {is_sync}\n\n"
        "<i>Нажмите кнопки ниже для просмотра системных журналов:</i>"
    )
    kb = {"inline_keyboard": [
        [{"text": "📜 Лог системы (logread)", "callback_data": "log_sys"}],
        [{"text": "🖨 Лог ядра (dmesg)", "callback_data": "log_dmesg"}],
        [{"text": "🔄 Обновить статус", "callback_data": "status"}, {"text": "♻️ Рестарт Podkop", "callback_data": "restart"}],
        [{"text": "◀️ В главное меню", "callback_data": "home"}]
    ]}
    return text, kb

def get_logread_screen():
    out = "Лог пуст."
    try:
        res = subprocess.check_output(["logread"], text=True, stderr=subprocess.DEVNULL)
        lines = res.strip().splitlines()
        out = "\n".join(lines[-30:]) if lines else "Лог пуст."
    except Exception as e:
        out = f"Ошибка чтения logread: {e}"

    text = f"📜 <b>Системный лог (последние 30 строк):</b>\n\n<pre>{out[:3500]}</pre>"
    kb = {"inline_keyboard": [
        [{"text": "🔄 Обновить logread", "callback_data": "log_sys"}],
        [{"text": "◀️ Назад к статусу", "callback_data": "status"}]
    ]}
    return text, kb

def get_dmesg_screen():
    out = "Лог пуст."
    try:
        res = subprocess.check_output(["dmesg"], text=True, stderr=subprocess.DEVNULL)
        lines = res.strip().splitlines()
        out = "\n".join(lines[-20:]) if lines else "Лог пуст."
    except Exception as e:
        out = f"Ошибка чтения dmesg: {e}"

    text = f"🖨 <b>Лог ядра dmesg (последние 20 строк):</b>\n\n<pre>{out[:3500]}</pre>"
    kb = {"inline_keyboard": [
        [{"text": "🔄 Обновить dmesg", "callback_data": "log_dmesg"}],
        [{"text": "◀️ Назад к статусу", "callback_data": "status"}]
    ]}
    return text, kb

def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def batch_ping_nodes(links):
    results = {}
    test_url = urllib.parse.quote(TEST_URL_GLOBAL, safe="")
    try:
        req = urllib.request.Request("http://192.168.1.1:9090/proxies")
        with urllib.request.urlopen(req, timeout=3, context=SSL_CTX) as r:
            proxies_data = json.loads(r.read().decode()).get("proxies", {})
    except Exception:
        proxies_data = {}

    for i, link in enumerate(links):
        name = get_node_name(link, i)
        val = -1
        if name in proxies_data:
            enc_name = urllib.parse.quote(name)
            probe_url = f"http://192.168.1.1:9090/proxies/{enc_name}/delay?url={test_url}&timeout=3000"
            try:
                with urllib.request.urlopen(probe_url, timeout=3.5, context=SSL_CTX) as pr:
                    res = json.loads(pr.read().decode())
                    val = int(res.get("delay", -1))
            except Exception:
                hist = proxies_data[name].get("history", [])
                if hist and hist[-1].get("delay", 0) > 0: val = hist[-1]["delay"]
        results[i] = val

    if all(v == -1 for v in results.values()) and links:
        api_port = find_free_port()
        outbounds, tag_map = [], {}
        sys.path.insert(0, "/usr/bin")
        import subparser
        for i, l in enumerate(links):
            t = f"b_{i}"
            try:
                ob = subparser.parse_link_to_singbox_outbound(l, t)
                outbounds.append(ob)
                tag_map[t] = i
            except Exception: pass
        outbounds.append({"type": "direct", "tag": "direct", "routing_mark": 255})
        cfg = {
            "log": {"level": "warn"},
            "experimental": {"clash_api": {"external_controller": f"127.0.0.1:{api_port}"}},
            "dns": {
                "servers": [
                    {"tag": "dns-direct", "type": "udp", "server": "77.88.8.8", "server_port": 53, "detour": "direct"},
                    {"tag": "dns-cf", "type": "udp", "server": "1.1.1.1", "server_port": 53, "detour": "direct"}
                ],
                "rules": [{"outbound": "any", "server": "dns-direct"}],
                "strategy": "prefer_ipv4"
            },
            "route": {
                "auto_detect_interface": True,
                "rules": [{"protocol": "dns", "outbound": "direct"}]
            },
            "outbounds": outbounds
        }
        tmp_cfg = f"/tmp/sb_tg_test_{api_port}.json"
        with open(tmp_cfg, "w") as f: json.dump(cfg, f)
        proc = subprocess.Popen([SINGBOX_BIN, "run", "-c", tmp_cfg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2.5)
        try:
            for t, idx in tag_map.items():
                d = subparser.query_node_delay(api_port, t, timeout_ms=3000)
                if d > 0: results[idx] = d
        finally:
            proc.terminate()
            try: proc.wait(1.5)
            except Exception: proc.kill()
            if os.path.exists(tmp_cfg): os.remove(tmp_cfg)

    return results

def get_main_screen():
    text = "🎛 <b>Панель управления SubParser & OpenWrt</b>\n\nВыберите необходимое действие:"
    kb = {"inline_keyboard": [
        [{"text": "📋 Серверы и пинг", "callback_data": "servers"}, {"text": "🔄 Запустить парсер", "callback_data": "sync"}],
        [{"text": "📟 Ресурсы роутера", "callback_data": "sysinfo"}, {"text": "👥 Клиенты сети", "callback_data": "clients"}],
        [{"text": "🛡 Доступ к сервисам", "callback_data": "check_services"}, {"text": "⚙️ Параметры парсера", "callback_data": "settings"}],
        [{"text": "📊 Статус", "callback_data": "status"}, {"text": "♻ Рестарт Podkop", "callback_data": "restart"}],
        [{"text": "⚠️ Reboot роутера", "callback_data": "reboot"}]
    ]}
    return text, kb

def delete_node(index):
    links = get_podkop_links()
    if index < 0 or index >= len(links): return False, "Неверный индекс"
    removed = links.pop(index)
    subprocess.run(["uci", "-q", "delete", "podkop.main.urltest_proxy_links"], check=False)
    for l in links: subprocess.run(["uci", "add_list", f"podkop.main.urltest_proxy_links={l}"], check=False)
    subprocess.run(["uci", "commit", "podkop"], check=False)
    subprocess.Popen(["/etc/init.d/podkop", "restart"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return True, get_node_name(removed, index)

def get_servers_screen(delays_map=None):
    links = get_podkop_links()
    if not links:
        return "📋 В конфигурации Podkop сейчас нет серверов.", {"inline_keyboard": [[{"text": "◀️ В главное меню", "callback_data": "home"}]]}

    keyboard = []
    for i, link in enumerate(links):
        name = get_node_name(link, i)
        prefix = f"[{delays_map[i]} ms]" if delays_map and delays_map.get(i, -1) > 0 else (f"[DEAD]" if delays_map else f"#{i+1}")
        keyboard.append([{"text": f"{prefix} {name[:24]}", "callback_data": f"sel:{i}"}])

    keyboard.append([{"text": "⚡ Замерить пинг всех узлов", "callback_data": "ping_all"}])
    keyboard.append([{"text": "◀️ В главное меню", "callback_data": "home"}])
    return f"📋 <b>Серверы Podkop</b> ({len(links)} шт.):\nВыберите узел для удаления или обновите пинг:", {"inline_keyboard": keyboard}

def main():
    offset = 0
    print("[*] SubParser Bot запущен...")
    init_bot_firewall()
    
    while True:
        token, admin_id = check_credentials()
        if not token or not admin_id:
            time.sleep(10)
            continue

        try:
            updates = tg_api(token, "getUpdates", {"offset": offset, "timeout": 20}, timeout=25)
            if not updates or not updates.get("ok"):
                time.sleep(2)
                continue

            for u in updates.get("result", []):
                offset = u["update_id"] + 1

                if "message" in u:
                    msg = u["message"]
                    user_id = str(msg.get("from", {}).get("id", "")).strip()
                    if user_id != admin_id:
                        continue

                    raw_text = msg.get("text", "").strip()
                    if not raw_text:
                        continue

                    if raw_text in ("/start", "/menu", "/help"):
                        t, kb = get_main_screen()
                        send_msg(token, user_id, t, kb)
                    else:
                        wait_m = send_msg(token, user_id, "⏳ <i>Анализирую маршрут и доступность узла...</i>")
                        wait_id = wait_m.get("result", {}).get("message_id") if wait_m else None
                        rep = analyze_custom_url(raw_text)
                        kb_back = {"inline_keyboard": [[{"text": "◀️ В главное меню", "callback_data": "home"}]]}
                        if wait_id:
                            edit_msg(token, user_id, wait_id, rep, kb_back)
                        else:
                            send_msg(token, user_id, rep, kb_back)

                elif "callback_query" in u:
                    cb = u["callback_query"]
                    cb_id = cb["id"]
                    user_id = str(cb.get("from", {}).get("id", "")).strip()
                    if user_id != admin_id:
                        continue

                    data = cb.get("data", "")
                    msg_obj = cb.get("message", {})
                    msg_id = msg_obj.get("message_id")
                    chat_id = msg_obj.get("chat", {}).get("id")

                    if data == "home":
                        answer_callback(token, cb_id)
                        t, kb = get_main_screen()
                        edit_msg(token, chat_id, msg_id, t, kb)

                    elif data == "sysinfo":
                        answer_callback(token, cb_id)
                        t, kb = get_system_metrics()
                        edit_msg(token, chat_id, msg_id, t, kb)

                    elif data == "clients":
                        answer_callback(token, cb_id)
                        t, kb = get_clients_screen()
                        edit_msg(token, chat_id, msg_id, t, kb)

                    elif data.startswith("dev:"):
                        mac = data.split("dev:")[1]
                        answer_callback(token, cb_id)
                        t, kb = get_device_action_screen(mac)
                        edit_msg(token, chat_id, msg_id, t, kb)

                    elif data.startswith("blk:"):
                        mac = data.split("blk:")[1].upper()
                        bl = [m.upper() for m in get_blocked_macs()]
                        if mac not in bl:
                            bl.append(mac)
                            save_blocked_macs(bl)
                        answer_callback(token, cb_id, "Интернет заблокирован")
                        t, kb = get_device_action_screen(mac, force_blocked=True)
                        edit_msg(token, chat_id, msg_id, t, kb)
                        apply_mac_firewall(mac, block=True)

                    elif data.startswith("unblk:"):
                        mac = data.split("unblk:")[1].upper()
                        bl = [m.upper() for m in get_blocked_macs()]
                        if mac in bl:
                            bl.remove(mac)
                            save_blocked_macs(bl)
                        answer_callback(token, cb_id, "Доступ разблокирован")
                        t, kb = get_device_action_screen(mac, force_blocked=False)
                        edit_msg(token, chat_id, msg_id, t, kb)
                        apply_mac_firewall(mac, block=False)

                    elif data == "settings":
                        answer_callback(token, cb_id)
                        t, kb = get_config_screen()
                        edit_msg(token, chat_id, msg_id, t, kb)

                    elif data.startswith("th:"):
                        val = data.split(":")[1]
                        set_uci_val("ping_threshold", val)
                        answer_callback(token, cb_id, f"Порог установлен: {val} ms")
                        t, kb = get_config_screen()
                        edit_msg(token, chat_id, msg_id, t, kb)

                    elif data == "toggle_ru":
                        cur = get_uci_val("filter_ru", "1")
                        new_val = "0" if cur == "1" else "1"
                        set_uci_val("filter_ru", new_val)
                        answer_callback(token, cb_id, "Фильтр РФ переключен")
                        t, kb = get_config_screen()
                        edit_msg(token, chat_id, msg_id, t, kb)

                    elif data == "view_log":
                        answer_callback(token, cb_id)
                        t, kb = get_log_screen()
                        edit_msg(token, chat_id, msg_id, t, kb)

                    elif data == "log_sys":
                        answer_callback(token, cb_id)
                        t, kb = get_logread_screen()
                        edit_msg(token, chat_id, msg_id, t, kb)

                    elif data == "log_dmesg":
                        answer_callback(token, cb_id)
                        t, kb = get_dmesg_screen()
                        edit_msg(token, chat_id, msg_id, t, kb)

                    elif data == "check_services":
                        answer_callback(token, cb_id, "Тестирую доступ...")
                        edit_msg(token, chat_id, msg_id, "⏳ <b>Проверяю маршруты и доступность (параллельно)...</b>")
                        t, kb = get_services_status_screen()
                        edit_msg(token, chat_id, msg_id, t, kb)

                    elif data == "status":
                        answer_callback(token, cb_id)
                        t, kb = get_status_screen()
                        edit_msg(token, chat_id, msg_id, t, kb)

                    elif data == "reboot":
                        answer_callback(token, cb_id)
                        t, kb = get_reboot_confirm_screen()
                        edit_msg(token, chat_id, msg_id, t, kb)

                    elif data == "do_reboot":
                        answer_callback(token, cb_id, "Роутер перезагружается...")
                        edit_msg(token, chat_id, msg_id, "⚠️ <b>Роутер уходит в перезагрузку...</b>\nСвязь восстановится через 1-2 минуты.")
                        subprocess.Popen(["/sbin/reboot"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                    elif data == "restart":
                        answer_callback(token, cb_id, "Служба перезапускается...")
                        text_pending = "♻️ <b>Служба Podkop перезапускается...</b>\nСоединение восстановится через 3-5 секунд."
                        kb_pending = {"inline_keyboard": [
                            [{"text": "🔄 Проверить статус", "callback_data": "status"}],
                            [{"text": "◀️ В главное меню", "callback_data": "home"}]
                        ]}
                        edit_msg(token, chat_id, msg_id, text_pending, kb_pending)
                        subprocess.Popen(["/etc/init.d/podkop", "restart"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                    elif data == "sync":
                        ps_check = subprocess.run(["pgrep", "-f", "subparser.py"], stdout=subprocess.PIPE, text=True)
                        if ps_check.stdout.strip():
                            answer_callback(token, cb_id, "Парсинг уже идет!")
                            t_sync = "⚠️ <b>Парсинг уже выполняется в данный момент.</b>"
                        else:
                            answer_callback(token, cb_id, "Запуск...")
                            subprocess.run(["rm", "-f", LOCK_FILE], check=False)
                            subprocess.Popen(["/usr/bin/subparser.py", "--force"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                            t_sync = "⏳ <b>Парсинг подписок и замер узлов запущены!</b>\nИтоговый отчет поступит отдельным сообщением."

                        edit_msg(token, chat_id, msg_id, t_sync, {"inline_keyboard": [
                            [{"text": "📊 Статус выполнения", "callback_data": "status"}],
                            [{"text": "◀️ В главное меню", "callback_data": "home"}]
                        ]})

                    elif data == "servers":
                        answer_callback(token, cb_id)
                        t, kb = get_servers_screen()
                        edit_msg(token, chat_id, msg_id, t, kb)

                    elif data == "ping_all":
                        answer_callback(token, cb_id)
                        edit_msg(token, chat_id, msg_id, "⏳ <b>Замеряю задержку всех узлов Podkop...</b>")
                        links = get_podkop_links()
                        delays = batch_ping_nodes(links)
                        t, kb = get_servers_screen(delays)
                        edit_msg(token, chat_id, msg_id, t, kb)

                    elif data.startswith("sel:"):
                        idx = int(data.split(":")[1])
                        links = get_podkop_links()
                        if idx >= len(links):
                            answer_callback(token, cb_id, "Узел уже отсутствует.")
                            t, kb = get_servers_screen()
                            edit_msg(token, chat_id, msg_id, t, kb)
                            continue

                        name = get_node_name(links[idx], idx)
                        proto = urllib.parse.urlsplit(links[idx]).scheme.upper()
                        card = f"🌐 <b>Сервер #{idx+1}</b>\n\n• <b>Имя:</b> <code>{name}</code>\n• <b>Протокол:</b> <code>{proto}</code>\n\nНажмите кнопку для удаления сервера из пула:"
                        kb = {"inline_keyboard": [
                            [{"text": "🗑 Удалить из Podkop", "callback_data": f"del:{idx}"}],
                            [{"text": "◀️ Назад к списку", "callback_data": "servers"}]
                        ]}
                        answer_callback(token, cb_id)
                        edit_msg(token, chat_id, msg_id, card, kb)

                    elif data.startswith("del:"):
                        idx = int(data.split(":")[1])
                        answer_callback(token, cb_id, "Удаляю...")
                        ok, res = delete_node(idx)
                        alert = f"🗑 Удален: <b>{res}</b>" if ok else f"⚠️ Ошибка: {res}"
                        t, kb = get_servers_screen()
                        edit_msg(token, chat_id, msg_id, f"{alert}\n\n{t}", kb)

        except Exception:
            time.sleep(3)

if __name__ == "__main__":
    main()