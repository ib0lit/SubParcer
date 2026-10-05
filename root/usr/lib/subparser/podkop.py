# -*- coding: utf-8 -*-
import subprocess
import urllib.request
import urllib.parse
import json
from concurrent.futures import ThreadPoolExecutor
from .config import SSL_CTX, TEST_URL_GLOBAL, LOCK_FILE, set_uci_val

CACHED_DELAYS = {}

def get_all_podkop_sections():
    try:
        raw_secs = subprocess.check_output(["uci", "-q", "show", "podkop"], text=True)
        detected = []
        for line in raw_secs.splitlines():
            if "=podkop" in line:
                s = line.split(".")[1].split("=")[0]
                if s not in detected:
                    detected.append(s)
            elif "urltest_proxy_links" in line:
                s = line.split(".")[1]
                if s not in detected:
                    detected.append(s)
        return detected if detected else ["main"]
    except Exception:
        return ["main"]

def get_podkop_links(section="main"):
    try:
        raw = subprocess.check_output(["uci", "-q", "get", f"podkop.{section}.urltest_proxy_links"], text=True).strip()
        return [l.strip() for l in raw.split() if l.strip()] if raw else []
    except Exception:
        return []

def get_node_name(link, idx):
    try:
        frag = urllib.parse.urlsplit(link).fragment
        if frag:
            return urllib.parse.unquote(frag)
    except Exception:
        pass
    return f"Сервер #{idx+1}"

def get_podkop_service_status():
    pid = ""
    try:
        pids = subprocess.check_output(["pidof", "sing-box"], text=True, stderr=subprocess.DEVNULL).strip().split()
        if pids:
            pid = pids[0]
    except Exception:
        pass

    service_ok = False
    try:
        res = subprocess.run(["/etc/init.d/podkop", "status"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode == 0 or "running" in res.stdout.lower() or pid:
            service_ok = True
    except Exception:
        if pid:
            service_ok = True

    ram_mb = "н/д"
    if pid:
        try:
            with open(f"/proc/{pid}/status", "r") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        rss_kb = int(line.split()[1])
                        ram_mb = f"{rss_kb / 1024:.1f} MB"
                        break
        except Exception:
            pass

    mode_str = "TPROXY / iptables"
    try:
        ip_out = subprocess.check_output(["ip", "-o", "link", "show"], text=True, stderr=subprocess.DEVNULL)
        for line in ip_out.splitlines():
            for ifn in ["tun-podkop", "sing-tun", "podkop", "tun0"]:
                if f" {ifn}:" in line or f" {ifn}@" in line:
                    mode_str = f"TUN ({ifn})"
                    break
    except Exception:
        pass

    return service_ok, pid, ram_mb, mode_str

def get_section_routing_state(section="main"):
    try:
        req = urllib.request.Request("http://192.168.1.1:9090/proxies")
        with urllib.request.urlopen(req, timeout=0.8, context=SSL_CTX) as resp:
            proxies = json.loads(resp.read().decode()).get("proxies", {})
            selector_data = proxies.get(f"{section}-out") or proxies.get(section)
            if not selector_data or selector_data.get("type", "").lower() != "selector":
                for k, v in proxies.items():
                    if section in k and v.get("type", "").lower() == "selector":
                        selector_data = v
                        break
            if selector_data:
                now_val = selector_data.get("now", "")
                if "urltest" in now_val.lower():
                    return "", True
                else:
                    return now_val, False
    except Exception:
        pass
    return "", True

def switch_active_node(section, index):
    tag = f"{section}-{index+1}-out"
    selector_name = f"{section}-out"
    try:
        req = urllib.request.Request("http://192.168.1.1:9090/proxies")
        with urllib.request.urlopen(req, timeout=0.8, context=SSL_CTX) as resp:
            proxies = json.loads(resp.read().decode()).get("proxies", {})
            if selector_name not in proxies:
                for k, v in proxies.items():
                    if section in k and v.get("type", "").lower() == "selector":
                        selector_name = k
                        break
    except Exception:
        pass

    enc_group = urllib.parse.quote(selector_name)
    url = f"http://192.168.1.1:9090/proxies/{enc_group}"
    payload = json.dumps({"name": tag}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, method="PUT", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=1.2, context=SSL_CTX) as resp:
            if resp.status in (200, 204):
                return True, tag
    except Exception:
        pass
    return False, tag

def reset_to_auto_urltest(section="main"):
    target_urltest = f"{section}-urltest-out"
    selector_name = f"{section}-out"
    try:
        req = urllib.request.Request("http://192.168.1.1:9090/proxies")
        with urllib.request.urlopen(req, timeout=0.8, context=SSL_CTX) as resp:
            proxies = json.loads(resp.read().decode()).get("proxies", {})
            if selector_name not in proxies:
                for k, v in proxies.items():
                    if section in k and v.get("type", "").lower() == "selector":
                        selector_name = k
                        for cand in v.get("all", []):
                            if "urltest" in cand.lower():
                                target_urltest = cand
                                break
                        break
            else:
                for cand in proxies[selector_name].get("all", []):
                    if "urltest" in cand.lower():
                        target_urltest = cand
                        break
    except Exception:
        pass

    enc_group = urllib.parse.quote(selector_name)
    url = f"http://192.168.1.1:9090/proxies/{enc_group}"
    payload = json.dumps({"name": target_urltest}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, method="PUT", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=1.2, context=SSL_CTX) as resp:
            if resp.status in (200, 204):
                return True
    except Exception:
        pass
    return False

def delete_node(index, section="main"):
    links = get_podkop_links(section)
    if index < 0 or index >= len(links):
        return False, "Неверный индекс"
    removed = links.pop(index)
    subprocess.run(["uci", "-q", "delete", f"podkop.{section}.urltest_proxy_links"], check=False)
    for l in links:
        subprocess.run(["uci", "add_list", f"podkop.{section}.urltest_proxy_links={l}"], check=False)
    subprocess.run(["uci", "commit", "podkop"], check=False)
    subprocess.Popen(["/etc/init.d/podkop", "restart"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return True, get_node_name(removed, index)

def batch_ping_nodes(links, section="main"):
    results = {}
    test_url = urllib.parse.quote(TEST_URL_GLOBAL, safe="")
    try:
        group_tag = urllib.parse.quote(f"{section}-urltest-out")
        url = f"http://192.168.1.1:9090/group/{group_tag}/delay?url={test_url}&timeout=2500"
        with urllib.request.urlopen(url, timeout=3.0, context=SSL_CTX) as resp:
            data = json.loads(resp.read().decode())
            for i in range(len(links)):
                t = f"{section}-{i+1}-out"
                if t in data and data[t] > 0:
                    results[i] = data[t]
    except Exception:
        pass

    missing = [i for i in range(len(links)) if i not in results]
    if missing:
        def probe_node(idx):
            t = urllib.parse.quote(f"{section}-{idx+1}-out")
            u = f"http://192.168.1.1:9090/proxies/{t}/delay?url={test_url}&timeout=2500"
            try:
                with urllib.request.urlopen(u, timeout=3.0, context=SSL_CTX) as r:
                    d = json.loads(r.read().decode()).get("delay", -1)
                    return idx, d
            except Exception:
                return idx, -1

        with ThreadPoolExecutor(max_workers=10) as pool:
            for idx, d in pool.map(probe_node, missing):
                results[idx] = d

    return results

def run_parser_process(mode_override=None):
    ps_check = subprocess.run(["pgrep", "-f", "subparser.py"], stdout=subprocess.PIPE, text=True)
    if ps_check.stdout.strip():
        return False, "⚠️ Парсинг уже выполняется в данный момент."

    if mode_override:
        set_uci_val("update_mode", mode_override)

    subprocess.run(["rm", "-f", LOCK_FILE], check=False)
    subprocess.Popen(["/usr/bin/subparser.py", "--force"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return True, "⏳ <b>Парсинг подписок и замер узлов запущены!</b>\nИтоговый отчет поступит отдельным сообщением."
