# -*- coding: utf-8 -*-
import json
import urllib.request
from .config import SSL_CTX

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
    if reply_markup:
        payload["reply_markup"] = reply_markup
    return tg_api(token, "sendMessage", payload, timeout=10)

def edit_msg(token, chat_id, message_id, text, reply_markup=None):
    payload = {"chat_id": chat_id, "message_id": message_id, "text": text, "parse_mode": "HTML"}
    if reply_markup:
        payload["reply_markup"] = reply_markup
    return tg_api(token, "editMessageText", payload, timeout=10)

def delete_msg(token, chat_id, msg_id):
    return tg_api(token, "deleteMessage", {"chat_id": chat_id, "message_id": msg_id}, timeout=5)

def answer_callback(token, cb_id, text=None):
    payload = {"callback_query_id": cb_id}
    if text:
        payload["text"] = text
    tg_api(token, "answerCallbackQuery", payload, timeout=5)
