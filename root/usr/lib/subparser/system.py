# -*- coding: utf-8 -*-
import os
import time
import json
import socket
import subprocess
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from .config import BLOCKED_FILE, SSL_CTX

def get_blocked_macs():
    if os.path.exists(BLOCKED_FILE):
        try:
            with open(BLOCKED_FILE, "r") as f:
                return [m.upper() for m in json.load(f)]
        except Exception:
            return []
    return []

def save_blocked_macs(mac_list):
    try:
        with open(BLOCKED_FILE, "w") as f:
            json.dump([m.upper() for m in mac_list], f)
    except Exception:
        pass

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
    except Exception:
        pass
    try:
        with open("/proc/net/arp", "r") as f:
            for l in f.readlines()[1:]:
                p = l.strip().split()
                if len(p) >= 4 and p[3].upper() == mac_upper:
                    return p[0]
    except Exception:
        pass
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
                    if sig >= -55:
                        s_ico = "📶 Отличный"
                    elif sig >= -70:
                        s_ico = "📶 Хороший"
                    elif sig >= -82:
                        s_ico = "🛜 Средний"
                    else:
                        s_ico = "🛜 Слабый"

                    wifi_data[mac.upper()] = {
                        "type": f"Wi-Fi {band}",
                        "signal": f"{s_ico} ({sig} dBm)",
                        "tx": tx_mbps
                    }
            except Exception:
                pass
    except Exception:
        pass
    return wifi_data

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

def check_single_service(item):
    name, domain, url = item
    is_proxied = False
    try:
        addrinfo = socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
        if addrinfo:
            ip = addrinfo[0][4][0]
            if ip.startswith("198.18.") or ip.startswith("198.19."):
                is_proxied = True
    except Exception:
        pass

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
