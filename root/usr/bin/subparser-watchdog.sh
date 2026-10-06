#!/bin/sh

ENABLED=$(uci -q get subparser.settings.enabled)
[ "$ENABLED" = "1" ] || exit 0

if pgrep -f "subparser.py" >/dev/null 2>&1; then
    exit 0
fi

TOKEN=$(uci -q get subparser.settings.tg_bot_token)
CHAT_ID=$(uci -q get subparser.settings.tg_chat_id)

notify() {
    [ -n "$TOKEN" ] && [ -n "$CHAT_ID" ] || return 0
    local msg="$1"
    curl -s -m 10 -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" \
        -d "chat_id=${CHAT_ID}" \
        -d "text=${msg}" \
        -d "parse_mode=HTML" >/dev/null 2>&1
}


# --- Мониторинг лимитов подписок (раз в 24 часа) ---
check_sub_limits() {
    [ -f "/tmp/subparser_subinfo.json" ] || return 0
    local state_file="/tmp/subparser_sub_alerts.json"
    
    python3 -c "
import json, time, os, subprocess

SUB_FILE = '/tmp/subparser_subinfo.json'
ALERT_FILE = '/tmp/subparser_sub_alerts.json'
TOKEN = '$TOKEN'
CHAT_ID = '$CHAT_ID'

if not TOKEN or not CHAT_ID or not os.path.exists(SUB_FILE):
    exit(0)

try:
    with open(SUB_FILE, 'r', encoding='utf-8') as f:
        subs = json.load(f)
except Exception:
    exit(0)

alerts_hist = {}
if os.path.exists(ALERT_FILE):
    try:
        with open(ALERT_FILE, 'r', encoding='utf-8') as f:
            alerts_hist = json.load(f)
    except Exception:
        pass

now = int(time.time())
warns = []

for name, info in subs.items():
    total = info.get('total', 0)
    used = info.get('upload', 0) + info.get('download', 0)
    expire = info.get('expire', 0)

    # Проверка интервала отправки (не чаще 1 раза в сутки для конкретной подписки)
    last_sent = alerts_hist.get(name, 0)
    if (now - last_sent) < 86400:
        continue

    alert_needed = False
    reasons = []

    # 1. Проверка срока (осталось менее 3 дней)
    if expire and expire > 0:
        days_left = (expire - now) / 86400.0
        if 0 <= days_left <= 3:
            alert_needed = True
            reasons.append(f'до окончания осталось <b>{days_left:.1f} дн.</b>')
        elif days_left < 0:
            alert_needed = True
            reasons.append('срок действия <b>истёк!</b>')

    # 2. Проверка трафика (израсходовано > 90%)
    if total and total > 0:
        pct = (used / total) * 100
        if pct >= 90:
            alert_needed = True
            reasons.append(f'израсходовано <b>{pct:.1f}% трафика</b>')

    if alert_needed:
        alerts_hist[name] = now
        warns.append(f'⚠️ Подписка <b>{name}</b>: ' + ', '.join(reasons))

if warns:
    msg = '🔔 <b>Внимание: лимиты подписок на исходе!</b>\n\n' + '\n'.join(warns) + '\n\n<i>Рекомендуется продлить подписку у провайдера.</i>'
    try:
        import urllib.request, urllib.parse
        data = urllib.parse.urlencode({'chat_id': CHAT_ID, 'text': msg, 'parse_mode': 'HTML'}).encode('utf-8')
        url = f'https://api.telegram.org/bot{TOKEN}/sendMessage'
        req = urllib.request.Request(url, data=data)
        urllib.request.urlopen(req, timeout=5)
        with open(ALERT_FILE, 'w', encoding='utf-8') as f:
            json.dump(alerts_hist, f)
    except Exception:
        pass
"
}
check_sub_limits

# 1. Проверяем процесс sing-box
if ! pidof sing-box >/dev/null 2>&1; then
    notify "🚨 <b>Внимание: Podkop упал!</b>%0AСлужба sing-box не активна. Перезапускаю Podkop..."
    /etc/init.d/podkop restart >/dev/null 2>&1
    sleep 4
fi

# sing-box слушает на LAN IP (192.168.1.1:9090)
API_HOST="192.168.1.1:9090"
if ! curl -s -m 2 "http://${API_HOST}/proxies" >/dev/null 2>&1; then
    LAN_IP=$(uci -q get network.lan.ipaddr | cut -d'/' -f1)
    [ -n "$LAN_IP" ] && API_HOST="${LAN_IP}:9090"
fi

TEST_URL="https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204"

# 2. Определяем рабочую группу (приоритет main-urltest-out)
TARGET_GROUP="main-urltest-out"
if ! curl -s "http://${API_HOST}/proxies/${TARGET_GROUP}" | grep -q '"name"'; then
    FALLBACK=$(curl -s "http://${API_HOST}/proxies" | grep -o '"[a-zA-Z0-9_-]*urltest[a-zA-Z0-9_-]*"' | tr -d '"' | head -n 1)
    [ -n "$FALLBACK" ] && TARGET_GROUP="$FALLBACK"
fi

[ -z "$TARGET_GROUP" ] && exit 0

check_delay() {
    local resp
    resp=$(curl -s -m 6 "http://${API_HOST}/proxies/${TARGET_GROUP}/delay?url=${TEST_URL}&timeout=4000" 2>/dev/null)
    echo "$resp" | grep -o '"delay":[0-9]*' | cut -d':' -f2
}

DELAY=$(check_delay)

# Защита от кратковременных просадок связи: пауза 6 секунд и контрольный замер
if [ -z "$DELAY" ] || [ "$DELAY" -le 0 ]; then
    sleep 6
    DELAY=$(check_delay)
fi

# Экстренный парсинг только при подтверждённом падении прокси
if [ -z "$DELAY" ] || [ "$DELAY" -le 0 ]; then
    # Если на роутере вообще нет интернета (провайдер упал), парсить бесполезно
    if ! curl -s -m 4 "https://1.1.1.1" >/dev/null 2>&1; then
        exit 0
    fi

    notify "⚠️ <b>Сбой проксирования Podkop!</b>%0AГруппа [${TARGET_GROUP}] не отвечает. Запускаю экстренный парсинг..."
    rm -f /var/run/subparser.lock
    /usr/bin/python3 /usr/bin/subparser.py --force >/dev/null 2>&1 &
fi
