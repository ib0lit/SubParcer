#!/bin/sh

ENABLED=$(uci -q get subparser.settings.enabled)
[ "$ENABLED" = "1" ] || exit 0

# Если парсер уже запущен — не вмешиваемся
if pgrep -f "subparser.py" >/dev/null 2>&1; then
    exit 0
fi

TOKEN=$(uci -q get subparser.settings.tg_bot_token)
CHAT_ID=$(uci -q get subparser.settings.tg_chat_id)
STATE_FILE="/tmp/subparser_watchdog.state"

notify() {
    [ -n "$TOKEN" ] && [ -n "$CHAT_ID" ] || return 0
    local msg="$1"
    curl -s -m 10 -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" \
        -d "chat_id=${CHAT_ID}" \
        -d "text=${msg}" \
        -d "parse_mode=HTML" >/dev/null 2>&1
}

# 1. Помехоустойчивая проверка интернета (WAN): 3 пакета, достаточно 1 ответа
check_wan_alive() {
    if ping -c 3 -W 1 77.88.8.8 >/dev/null 2>&1 || ping -c 3 -W 1 1.1.1.1 >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# 2. Мониторинг лимитов подписок (раз в 24 часа)
check_sub_limits() {
    [ -f "/tmp/subparser_subinfo.json" ] || return 0
    local alert_file="/tmp/subparser_sub_alerts.json"
    
    python3 -c "
import json, time, os
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

    last_sent = alerts_hist.get(name, 0)
    if (now - last_sent) < 86400:
        continue

    alert_needed = False
    reasons = []

    if expire and expire > 0:
        days_left = (expire - now) / 86400.0
        if 0 <= days_left <= 3:
            alert_needed = True
            reasons.append(f'до окончания осталось <b>{days_left:.1f} дн.</b>')
        elif days_left < 0:
            alert_needed = True
            reasons.append('срок действия <b>истёк!</b>')

    if total and total > 0:
        pct = (used / total) * 100
        if pct >= 90:
            alert_needed = True
            reasons.append(f'израсходовано <b>{pct:.1f}% трафика</b>')

    if alert_needed:
        alerts_hist[name] = now
        warns.append(f'⚠️ Подписка <b>{name}</b>: ' + ', '.join(reasons))

if warns:
    msg = '🔔 <b>Внимание: лимиты подписок на исходе!</b>\n\n' + '\n'.join(warns)
    try:
        import urllib.request, urllib.parse
        data = urllib.parse.urlencode({'chat_id': CHAT_ID, 'text': msg, 'parse_mode': 'HTML'}).encode('utf-8')
        req = urllib.request.Request(f'https://api.telegram.org/bot{TOKEN}/sendMessage', data=data)
        urllib.request.urlopen(req, timeout=5)
        with open(ALERT_FILE, 'w', encoding='utf-8') as f:
            json.dump(alerts_hist, f)
    except Exception:
        pass
"
}
check_sub_limits

# 3. Контроль зависания процесса sing-box
if ! pidof sing-box >/dev/null 2>&1; then
    if ! check_wan_alive; then
        exit 0
    fi
    notify "🚨 <b>Внимание: Podkop упал!</b>%0AСлужба sing-box не активна. Перезапускаю Podkop..."
    /etc/init.d/podkop restart >/dev/null 2>&1
    sleep 4
fi

# 4. Проверка доступности прокси-ядра
API_HOST="192.168.1.1:9090"
if ! curl -s -m 2 "http://${API_HOST}/proxies" >/dev/null 2>&1; then
    LAN_IP=$(uci -q get network.lan.ipaddr | cut -d'/' -f1)
    [ -n "$LAN_IP" ] && API_HOST="${LAN_IP}:9090"
fi

TEST_URL="https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204"
TARGET_GROUP="main-urltest-out"
if ! curl -s "http://${API_HOST}/proxies/${TARGET_GROUP}" | grep -q '"name"'; then
    FALLBACK=$(curl -s "http://${API_HOST}/proxies" | grep -o '"[a-zA-Z0-9_-]*urltest[a-zA-Z0-9_-]*"' | tr -d '"' | head -n 1)
    [ -n "$FALLBACK" ] && TARGET_GROUP="$FALLBACK"
fi

[ -z "$TARGET_GROUP" ] && exit 0

check_delay() {
    local resp
    resp=$(curl -s -m 5 "http://${API_HOST}/proxies/${TARGET_GROUP}/delay?url=${TEST_URL}&timeout=3500" 2>/dev/null)
    echo "$resp" | grep -o '"delay":[0-9]*' | cut -d':' -f2
}

# Серия из 3 попыток (0с -> 7с -> 7с) для отсеивания кратковременных просадок
DELAY=""
ATTEMPT=1
while [ "$ATTEMPT" -le 3 ]; do
    DELAY=$(check_delay)
    if [ -n "$DELAY" ] && [ "$DELAY" -gt 0 ]; then
        break
    fi
    if [ "$ATTEMPT" -lt 3 ]; then
        sleep 7
    fi
    ATTEMPT=$((ATTEMPT + 1))
done

# 5. Обработка сбоев и 45-минутный кулдаун
NOW=$(date +%s)
FAIL_COUNT=0
LAST_RETRY=0

if [ -f "$STATE_FILE" ]; then
    FAIL_COUNT=$(sed -n '1p' "$STATE_FILE" 2>/dev/null)
    LAST_RETRY=$(sed -n '2p' "$STATE_FILE" 2>/dev/null)
fi

case "$FAIL_COUNT" in ''|*[!0-9]*) FAIL_COUNT=0 ;; esac
case "$LAST_RETRY" in ''|*[!0-9]*) LAST_RETRY=0 ;; esac

# Если задержка в норме — сбрасываем статус сбоя
if [ -n "$DELAY" ] && [ "$DELAY" -gt 0 ]; then
    rm -f "$STATE_FILE" 2>/dev/null
    exit 0
fi

# Если интернет у провайдера отсутствует — тихо выходим
if ! check_wan_alive; then
    exit 0
fi

# Кулдаун: если экстренный парсинг уже запускался менее 45 минут (2700 сек) назад
ELAPSED=$((NOW - LAST_RETRY))
if [ "$FAIL_COUNT" -ge 1 ] && [ "$ELAPSED" -lt 2700 ] && [ "$ELAPSED" -ge 0 ]; then
    exit 0
fi

FAIL_COUNT=$((FAIL_COUNT + 1))
printf "%s\n%s\n" "$FAIL_COUNT" "$NOW" > "$STATE_FILE"

notify "⚠️ <b>Сбой проксирования Podkop!</b>%0AГруппа [${TARGET_GROUP}] не отвечает. Запускаю экстренный отбор узлов..."
rm -f /var/run/subparser.lock
/usr/bin/python3 /usr/bin/subparser.py --force >/dev/null 2>&1 &
