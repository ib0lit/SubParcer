#!/bin/sh

ENABLED=$(uci -q get subparser.settings.enabled)
[ "$ENABLED" = "1" ] || exit 0

# Защита: если парсер активен или идет фоновая синхронизация — не вмешиваемся
if pgrep -f "subparser.py" >/dev/null 2>&1 || pgrep -f "subparser-helper.sh" >/dev/null 2>&1 || pgrep -f "podkop" >/dev/null 2>&1 || [ -f "/var/run/subparser.lock" ] || [ -f "/tmp/podkop.lock" ]; then
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

# 1. Помехоустойчивая проверка WAN
check_wan_alive() {
    if ping -c 2 -W 2 77.88.8.8 >/dev/null 2>&1 || ping -c 2 -W 2 1.1.1.1 >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# 2. Мониторинг лимитов подписок
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

# 3. Контроль процесса sing-box с защитой от переходных процессов
if ! pidof sing-box >/dev/null 2>&1; then
    sleep 10
    if ! pidof sing-box >/dev/null 2>&1; then
        if ! check_wan_alive; then
            exit 0
        fi
        notify "🚨 <b>Внимание: Podkop упал!</b>%0AСлужба sing-box не активна. Перезапускаю Podkop..."
        /etc/init.d/podkop restart >/dev/null 2>&1
        exit 0
    fi
fi

# 4. Проверка доступности REST API ядра
API_HOST="192.168.1.1:9090"
if ! curl -s -m 2 "http://${API_HOST}/proxies" >/dev/null 2>&1; then
    LAN_IP=$(uci -q get network.lan.ipaddr | cut -d'/' -f1)
    [ -n "$LAN_IP" ] && API_HOST="${LAN_IP}:9090"
fi

TEST_URL="https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204"
TARGET_GROUP="main-urltest-out"
if ! curl -s -m 3 "http://${API_HOST}/proxies/${TARGET_GROUP}" | grep -q '"name"'; then
    FALLBACK=$(curl -s -m 3 "http://${API_HOST}/proxies" | grep -o '"[a-zA-Z0-9_-]*urltest[a-zA-Z0-9_-]*"' | tr -d '"' | head -n 1)
    [ -n "$FALLBACK" ] && TARGET_GROUP="$FALLBACK"

# Защита: если sing-box поднят менее 35 секунд назад — пропускаем раунд
SB_PID=$(pidof sing-box 2>/dev/null | awk '{print $1}')
if [ -n "$SB_PID" ] && [ -d "/proc/$SB_PID" ]; then
    UPTIME_SYS=$(cut -d'.' -f1 /proc/uptime)
    START_TIME_TICKS=$(cut -d' ' -f22 "/proc/$SB_PID/stat" 2>/dev/null || echo 0)
    CLK_TCK=$(getconf CLK_TCK 2>/dev/null || echo 100)
    PROC_START_SEC=$((START_TIME_TICKS / CLK_TCK))
    PROC_AGE=$((UPTIME_SYS - PROC_START_SEC))
    if [ "$PROC_AGE" -ge 0 ] && [ "$PROC_AGE" -lt 35 ]; then
        exit 0
    fi
fi
fi

[ -z "$TARGET_GROUP" ] && exit 0

check_delay() {
    local resp
    resp=$(curl -s -m 8 "http://${API_HOST}/proxies/${TARGET_GROUP}/delay?url=${TEST_URL}&timeout=4000" 2>/dev/null)
    echo "$resp" | grep -o '"delay":[0-9]*' | cut -d':' -f2
}

# Серия проверок с фильтрацией микросбоев
DELAY=""
ATTEMPT=1
while [ "$ATTEMPT" -le 3 ]; do
    DELAY=$(check_delay)
    if [ -n "$DELAY" ] && [ "$DELAY" -gt 0 ]; then
        break
    fi
    if [ "$ATTEMPT" -lt 3 ]; then
        sleep 5
    fi
    ATTEMPT=$((ATTEMPT + 1))
done

# Если связь через узел есть — сбрасываем счетчик ошибок и выходим
if [ -n "$DELAY" ] && [ "$DELAY" -gt 0 ]; then
    rm -f "$STATE_FILE" 2>/dev/null
    exit 0
fi

# Если упал сам интернет провайдера — не трогаем прокси
if ! check_wan_alive; then
    exit 0
fi

# 5. Двухэтапное подтверждение аварии
NOW=$(date +%s)
FAIL_COUNT=0
LAST_RETRY=0

if [ -f "$STATE_FILE" ]; then
    FAIL_COUNT=$(sed -n '1p' "$STATE_FILE" 2>/dev/null)
    LAST_RETRY=$(sed -n '2p' "$STATE_FILE" 2>/dev/null)
fi

case "$FAIL_COUNT" in ''|*[!0-9]*) FAIL_COUNT=0 ;; esac
case "$LAST_RETRY" in ''|*[!0-9]*) LAST_RETRY=0 ;; esac

# Если это первый сбой — фиксируем и даем ядру 1 цикл (5 мин) на самовосстановление
if [ "$FAIL_COUNT" -lt 1 ]; then
    printf "%s\n%s\n" "1" "$NOW" > "$STATE_FILE"
    exit 0
fi

# Кулдаун 45 минут (2700 сек) между экстренными парсингами
ELAPSED=$((NOW - LAST_RETRY))
if [ "$ELAPSED" -lt 2700 ] && [ "$ELAPSED" -ge 0 ]; then
    exit 0
fi

printf "%s\n%s\n" "2" "$NOW" > "$STATE_FILE"

notify "⚠️ <b>Сбой проксирования Podkop!</b>%0AГруппа [${TARGET_GROUP}] не отвечает. Запускаю экстренный отбор узлов..."
rm -f /var/run/subparser.lock
/usr/bin/python3 /usr/bin/subparser.py --force >/dev/null 2>&1 &
