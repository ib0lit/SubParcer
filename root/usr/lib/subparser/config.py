# -*- coding: utf-8 -*-
import subprocess
import json
import os
import ssl

CONFIG_NAME = "subparser"
LOCK_FILE = "/var/run/subparser.lock"
SINGBOX_BIN = "/usr/bin/sing-box"
LOG_FILE = "/tmp/subparser_sync.log"
BLOCKED_FILE = "/tmp/bot_blocked_macs.json"
STATE_FILE = "/tmp/subparser_bot_state.json"
TEST_URL_GLOBAL = "https://www.gstatic.com/generate_204"

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

UA_CHOICES = {
    "v2rayN": "v2rayN/6.42",
    "flclash": "FlClashX / ClashMeta",
    "singbox": "Sing-Box",
    "happ": "Happ (iOS)",
    "incy": "Incy (Android)"
}
UA_LIST = ["v2rayN", "flclash", "singbox", "happ", "incy"]

def get_uci_val(opt, default=""):
    try:
        res = subprocess.run(["uci", "-q", "get", f"{CONFIG_NAME}.settings.{opt}"], stdout=subprocess.PIPE, text=True)
        out = res.stdout.strip().strip("'\"")
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

def get_user_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def set_user_state(state_dict):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(state_dict, f)
    except Exception:
        pass
