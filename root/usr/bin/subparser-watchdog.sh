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

if ! pidof sing-box >/dev/null 2>&1; then
    notify "🚨 <b>Внимание: Podkop упал!</b>%0AСлужба sing-box не активна. Перезапускаю Podkop..."
    /etc/init.d/podkop restart >/dev/null 2>&1
    sleep 3
fi

LAN_IP=$(uci -q get network.lan.ipaddr | cut -d'/' -f1)
[ -z "$LAN_IP" ] && LAN_IP="192.168.1.1"

CHECK_SEC=$(uci -q get subparser.settings.target_section | awk '{print $1}')
[ -z "$CHECK_SEC" ] && CHECK_SEC="main"

TEST_URL="https%3A%2F%2Fcp.cloudflare.com%2Fgenerate_204"
RESP=$(curl -s -m 6 "http://${LAN_IP}:9090/proxies/${CHECK_SEC}-urltest-out/delay?url=${TEST_URL}&timeout=4000" 2>/dev/null)
DELAY=$(echo "$RESP" | grep -o '"delay":[0-9]*' | cut -d':' -f2)

if [ -z "$DELAY" ] || [ "$DELAY" -le 0 ]; then
    sleep 4
    RESP=$(curl -s -m 6 "http://${LAN_IP}:9090/proxies/${CHECK_SEC}-urltest-out/delay?url=${TEST_URL}&timeout=4000" 2>/dev/null)
    DELAY=$(echo "$RESP" | grep -o '"delay":[0-9]*' | cut -d':' -f2)
fi

if [ -z "$DELAY" ] || [ "$DELAY" -le 0 ]; then
    notify "⚠️ <b>Сбой проксирования Podkop!</b>%0AУзлы в секции [${CHECK_SEC}] не отвечают. Запускаю экстренный парсинг..."
    rm -f /var/run/subparser.lock
    /usr/bin/python3 /usr/bin/subparser.py --force >/dev/null 2>&1 &
fi