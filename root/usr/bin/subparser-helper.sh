#!/bin/sh
ACTION="$1"
SECTION="$2"
[ -z "$SECTION" ] && SECTION="main"

LAN_IP=$(uci -q get network.lan.ipaddr | cut -d'/' -f1)
[ -z "$LAN_IP" ] && LAN_IP="192.168.1.1"
API_HOST="${LAN_IP}:9090"

PID_FILE="/tmp/subparser_sync.pid"
LOG_FILE="/tmp/subparser_sync.log"
LOCK_FILE="/var/run/subparser.lock"

case "$ACTION" in
    get_podkop_sections)
        SECTIONS=$(uci -q show podkop 2>/dev/null | grep -E "=podkop|urltest_proxy_links" | cut -d"." -f2 | cut -d"=" -f1 | sort -u)
        [ -z "$SECTIONS" ] && SECTIONS="main"
        
        # Автоматическая синхронизация конфига subparser: чистим старое, добавляем актуальное
        CUR_SECS=$(uci -q get subparser.settings.target_section)
        uci -q delete subparser.settings.target_section
        for s in $SECTIONS; do
            uci add_list subparser.settings.target_section="$s"
        done
        uci commit subparser
        
        echo "["
        FIRST=1
        for s in $SECTIONS; do
            [ $FIRST -eq 0 ] && echo ","
            FIRST=0
            printf '  "%s"' "$s"
        done
        echo ""
        echo "]"
        ;;

    test_tg)
        TOKEN=$(uci -q get subparser.settings.tg_bot_token)
        CHAT_ID=$(uci -q get subparser.settings.tg_chat_id)
        if [ -z "$TOKEN" ] || [ -z "$CHAT_ID" ]; then
            echo '{"status": "error", "message": "Токен или Chat ID не заполнены в UCI!"}'
            exit 0
        fi
        MSG="🔔 <b>SubParser</b>: Тестовое сообщение успешно доставлено!"
        RES=$(curl -s -m 8 -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" \
            -d "chat_id=${CHAT_ID}" \
            -d "text=${MSG}" \
            -d "parse_mode=HTML" 2>&1)
        if echo "$RES" | grep -q '"ok":true'; then
            echo '{"status": "ok"}'
        else
            ERR=$(echo "$RES" | sed 's/"/\\"/g' | tr -d '\r\n')
            echo "{\"status\": \"error\", \"message\": \"$ERR\"}"
        fi
        ;;

    bg_sync)
        if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
            echo '{"status": "running"}'
            exit 0
        fi

        if [ -f "$LOG_FILE" ]; then
            tail -n 200 "$LOG_FILE" > "${LOG_FILE}.tmp" 2>/dev/null
            mv "${LOG_FILE}.tmp" "$LOG_FILE"
        fi

        echo "=== Старт синхронизации: $(date) ===" >> "$LOG_FILE"

        (
            flock -n 9 || {
                echo "[!] Синхронизация уже запущена другим процессом." >> "$LOG_FILE"
                exit 1
            }
            /usr/bin/python3 /usr/bin/subparser.py --force >> "$LOG_FILE" 2>&1
            rm -f "$PID_FILE"
        ) 9>"$LOCK_FILE" </dev/null >/dev/null 2>&1 &

        echo $! > "$PID_FILE"
        echo '{"status": "started"}'
        ;;

    check_sync)
        if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
            echo '{"status": "running"}'
        else
            rm -f "$PID_FILE"
            if grep -q "Podkop успешно обновлен" "$LOG_FILE" 2>/dev/null; then
                echo '{"status": "done"}'
            else
                echo '{"status": "error"}'
            fi
        fi
        ;;

    update_cron)
        /etc/init.d/subparser restart >/dev/null 2>&1
        echo '{"status": "ok"}'
        ;;

    get_links)
        LINKS=$(uci -q get podkop.${SECTION}.urltest_proxy_links)
        echo "["
        FIRST=1
        for link in $LINKS; do
            [ $FIRST -eq 0 ] && echo ","
            FIRST=0
            printf '  "%s"' "$link"
        done
        echo ""
        echo "]"
        ;;

    save_selected)
        SRC_FILE="/tmp/subparser_selected.txt"
        if [ ! -s "$SRC_FILE" ]; then
            echo '{"status": "error", "message": "Файл пуст или не найден"}'
            exit 1
        fi
        uci -q delete podkop.${SECTION}.urltest_proxy_links
        while IFS= read -r link || [ -n "$link" ]; do
            link_clean=$(echo "$link" | tr -d '\r\n')
            [ -n "$link_clean" ] && uci add_list podkop.${SECTION}.urltest_proxy_links="$link_clean"
        done < "$SRC_FILE"
        rm -f "$SRC_FILE"
        uci commit podkop
        /etc/init.d/podkop restart >/dev/null 2>&1
        echo '{"status": "ok"}'
        ;;

    ping_group)
        URL="https://www.gstatic.com/generate_204"
        RES=$(curl -s -m 5 "http://${API_HOST}/group/${SECTION}-urltest-out/delay?url=${URL}&timeout=3000" 2>/dev/null)
        [ -n "$RES" ] && echo "$RES" || echo '{}'
        ;;

    ping_node)
        TAG="$2"
        URL="https://www.gstatic.com/generate_204"
        RES=$(curl -s -m 4 "http://${API_HOST}/proxies/${TAG}/delay?url=${URL}&timeout=3000" 2>/dev/null)
        [ -n "$RES" ] && echo "$RES" || echo '{"delay": -1}'
        ;;

    *)
        echo '{"error": "unknown action"}'
        exit 1
        ;;
esac
