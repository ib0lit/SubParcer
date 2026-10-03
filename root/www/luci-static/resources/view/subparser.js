'use strict';
'require view';
'require form';
'require fs';
'require ui';

return view.extend({
    serverLinks: [],

    load: function() {
        return fs.exec('/usr/bin/subparser-helper.sh', ['get_links']).then(function(res) {
            try { return JSON.parse(res.stdout.trim() || '[]'); } catch(e) { return []; }
        });
    },

    parseNodeInfo: function(link) {
        var proto = 'UNKNOWN', name = 'Без названия';
        try {
            var parts = link.split('://');
            proto = parts[0].toUpperCase();
            var rest = parts[1] || '';
            var hashIdx = rest.indexOf('#');
            name = (hashIdx !== -1) ? decodeURIComponent(rest.substring(hashIdx + 1)).trim() : (rest.split('@')[1] || rest);
        } catch(e) {}
        return { proto: proto, name: name, raw: link };
    },

    renderCards: function(container) {
        var self = this;
        container.innerHTML = '';
        if (!this.serverLinks || this.serverLinks.length === 0) {
            container.appendChild(E('div', { 'style': 'padding: 15px; color: #888;' }, _('В Podkop нет активных серверов. Выполните парсинг подписок выше.')));
            return;
        }
        var grid = E('div', { 'style': 'display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 12px; margin-top: 15px;' });
        this.serverLinks.forEach(function(link, idx) {
            var info = self.parseNodeInfo(link);
            var tag = 'main-' + (idx + 1) + '-out';
            var card = E('div', {
                'id': 'card_' + tag,
                'style': 'background: #1e1e1e; border: 1px solid #333; border-radius: 8px; padding: 12px 14px; display: flex; flex-direction: column; justify-content: space-between; color: #eee; box-shadow: 0 2px 4px rgba(0,0,0,0.2);'
            }, [
                E('div', { 'style': 'display: flex; align-items: flex-start; justify-content: space-between; gap: 8px;' }, [
                    E('div', { 'style': 'font-weight: 600; font-size: 13px; line-height: 1.3; word-break: break-word; flex: 1;' }, info.name),
                    E('input', { 'type': 'checkbox', 'checked': true, 'data-link': link, 'style': 'cursor: pointer; width: 18px; height: 18px; margin-top: 2px;' })
                ]),
                E('div', { 'style': 'display: flex; align-items: center; justify-content: space-between; margin-top: 14px; font-size: 12px;' }, [
                    E('span', { 'style': 'color: #999; text-transform: uppercase; font-weight: 500;' }, info.proto),
                    E('span', { 'id': 'badge_' + tag, 'class': 'node-delay-badge', 'data-tag': tag, 'style': 'color: #00e676; font-weight: bold; font-family: monospace; font-size: 13px;' }, '--- ms')
                ])
            ]);
            grid.appendChild(card);
        });
        container.appendChild(grid);
    },

    render: function(loadedLinks) {
        var self = this;
        this.serverLinks = loadedLinks || [];
        var m = new form.Map('subparser', _('SubParser'), _('Многопоточный парсер подписок с выбором User-Agent и ручным управлением узлами Podkop.'));

        var s = m.section(form.NamedSection, 'settings', 'subparser', _('Общие параметры'));
        
        var o = s.option(form.Flag, 'enabled', _('Включить сервис'));
        o.rmempty = false;

        o = s.option(form.ListValue, 'interval', _('Интервал автопроверки'));
		o.value('30m', _('Каждые 30 минут'));
		o.value('1h', _('Каждый 1 час'));
		o.value('2h', _('Каждые 2 часа'));
		o.value('3h', _('Каждые 3 часа'));
		o.value('4h', _('Каждые 4 часа'));
		o.value('6h', _('Каждые 6 часов'));
		o.value('8h', _('Каждые 8 часов'));
		o.value('12h', _('Каждые 12 часов'));
		o.value('24h', _('Раз в сутки (в 04:00)'));
		o.default = '3h';

		o = s.option(form.Value, 'tg_bot_token', _('Telegram Bot Token'));
		o.placeholder = '123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ';
		o.rmempty = true;

		o = s.option(form.Value, 'tg_chat_id', _('Telegram Chat ID'));
		o.placeholder = '123456789';
		o.rmempty = true;

		o = s.option(form.Button, '_test_tg', _('Проверка связи'));
		o.inputtitle = _('Отправить тест в Telegram');
		o.inputstyle = 'action';
		o.onclick = function(ev) {
			var btn = ev.target;
			btn.disabled = true;
			btn.innerText = _('Отправка...');
			return fs.exec('/usr/bin/subparser-helper.sh', ['test_tg']).then(function(res) {
				btn.disabled = false;
				btn.innerText = _('Отправить тест в Telegram');
				var data = {};
				try { data = JSON.parse(res.stdout.trim()); } catch(e) {}
				if (data.status === 'ok') {
					ui.addNotification(null, E('p', {}, _('Тестовое уведомление успешно отправлено!')), 'info');
				} else {
					ui.addNotification(null, E('p', {}, _('Ошибка: ') + (data.message || 'Сбой сети')), 'danger');
				}
			});
		};

		o = s.option(form.Value, 'ping_threshold', _('Порог задержки (мс)'));
        o.datatype = 'uinteger';
        o.default = '350';

        o = s.option(form.Flag, 'filter_ru', _('Фильтровать RU / обход узлы'));
        o.default = '1';

        o = s.option(form.Button, '_run_now', _('Синхронизация'));
        o.inputtitle = _('Синхронизировать сейчас');
        o.inputstyle = 'apply';
        o.onclick = function() {
			ui.showModal(_('Синхронизация'), [
				E('p', { 'class': 'spinning' }, _('Тестирование и отбор узлов...')),
				E('pre', {
					'id': 'sync_live_log',
					'style': 'max-height: 180px; overflow-y: auto; background: #111; color: #4af626; font-size: 11px; padding: 8px; border-radius: 4px; margin-top: 10px; text-align: left;'
				}, 'Инициализация синхронизации...')
			]);

			return fs.exec('/usr/bin/subparser-helper.sh', ['bg_sync']).then(function() {
				var poll = setInterval(function() {
					fs.read_direct('/tmp/subparser_sync.log').then(function(logTxt) {
						var el = document.getElementById('sync_live_log');
						if (el && logTxt) {
							el.textContent = logTxt;
							el.scrollTop = el.scrollHeight;
						}
					});

					fs.exec('/usr/bin/subparser-helper.sh', ['check_sync']).then(function(cRes) {
						var st = (cRes.stdout || '').trim();
						if (st.indexOf('"done"') !== -1) {
							clearInterval(poll);
							setTimeout(function() {
								ui.hideModal();
								window.location.reload();
							}, 800);
						} else if (st.indexOf('"error"') !== -1) {
							clearInterval(poll);
							ui.hideModal();
							ui.addNotification(null, E('p', _('Синхронизация завершилась с ошибкой. Проверьте лог.')), 'error');
						}
					});
				}, 1500);
			}).catch(function(err) {
				ui.hideModal();
				ui.addNotification(null, E('p', _('Ошибка вызова: ') + err.message), 'error');
			});
		};

        var s_subs = m.section(form.GridSection, 'subscription', _('Источники подписок'));
        s_subs.addremove = true;
        s_subs.anonymous = true;

        var sub_en = s_subs.option(form.Flag, 'enabled', _('Активна'));
        sub_en.default = '1';
        sub_en.editable = true;

        var sub_name = s_subs.option(form.Value, 'name', _('Название'));
        sub_name.placeholder = 'Провайдер 1';

        var sub_url = s_subs.option(form.Value, 'url', _('URL подписки'));
        sub_url.placeholder = 'https://...';
        sub_url.rmempty = false;

        var sub_ua = s_subs.option(form.ListValue, 'user_agent', _('User-Agent'));
        sub_ua.value('flclash', 'FlClashX / ClashMeta (HWID)');
        sub_ua.value('incy', 'Incy (Android / Xiaomi)');
		sub_ua.value('v2rayN', 'v2rayN/6.42');
        sub_ua.value('clashmeta', 'Clash.Meta (Mihomo)');
        sub_ua.value('clash', 'Clash for Windows');
        sub_ua.value('singbox', 'Sing-box');
        sub_ua.value('happ', 'Happ (iOS)');
        sub_ua.value('shadowrocket', 'Shadowrocket');
        sub_ua.value('curl', 'curl (Generic)');
        sub_ua.default = 'v2rayN';

        var s2 = m.section(form.NamedSection, 'settings', 'subparser', _('Активные узлы в Podkop'));
        var dashboardContainer = E('div', { 'id': 'subparser_dashboard_box' });

        var toolbar = E('div', { 'style': 'display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 10px;' }, [
            E('button', {
                'class': 'btn cbi-button-action',
                'click': function(ev) { ev.preventDefault(); self.refreshPings(dashboardContainer); }
            }, _('⚡ Обновить пинги')),
            E('button', {
                'class': 'btn cbi-button-positive',
                'click': function(ev) { ev.preventDefault(); self.saveSelectedNodes(dashboardContainer); }
            }, _('💾 Применить выбранные узлы')),
            E('button', {
                'class': 'btn cbi-button-neutral',
                'click': function(ev) {
                    ev.preventDefault();
                    var cbs = dashboardContainer.querySelectorAll('input[type="checkbox"]');
                    var allChecked = Array.from(cbs).every(function(c) { return c.checked; });
                    cbs.forEach(function(c) { c.checked = !allChecked; });
                }
            }, _('Выделить все / Снять'))
        ]);

        var dummy = s2.option(form.DummyValue, '_dashboard');
        dummy.rawhtml = true;
        dummy.render = function() { return E('div', {}, [toolbar, dashboardContainer]); };
        self.renderCards(dashboardContainer);

		return m.render();
    },

    refreshPings: function(container) {
        var badges = container.querySelectorAll('.node-delay-badge');
        badges.forEach(function(b) { b.innerText = '...'; b.style.color = '#888'; });

        fs.exec('/usr/bin/subparser-helper.sh', ['ping_group']).then(function(res) {
            var groupDelays = {};
            try { groupDelays = JSON.parse(res.stdout.trim() || '{}'); } catch(e) {}

            badges.forEach(function(b) {
                var tag = b.getAttribute('data-tag');
                var d = groupDelays[tag];
                if (typeof d === 'number' && d > 0) {
                    b.innerText = d + ' ms';
                    b.style.color = d < 180 ? '#00e676' : (d < 350 ? '#ffb300' : '#ff5252');
                } else {
                    fs.exec('/usr/bin/subparser-helper.sh', ['ping_node', tag]).then(function(nodeRes) {
                        try {
                            var data = JSON.parse(nodeRes.stdout.trim());
                            if (data.delay && data.delay > 0) {
                                b.innerText = data.delay + ' ms';
                                b.style.color = data.delay < 180 ? '#00e676' : (data.delay < 350 ? '#ffb300' : '#ff5252');
                            } else {
                                b.innerText = 'timeout';
                                b.style.color = '#ff5252';
                            }
                        } catch(err) {
                            b.innerText = 'timeout';
                            b.style.color = '#ff5252';
                        }
                    });
                }
            });
        });
    },

    saveSelectedNodes: function(container) {
        var checkboxes = container.querySelectorAll('input[type="checkbox"]:checked');
        var selectedLinks = [];
        checkboxes.forEach(function(cb) {
            var link = cb.getAttribute('data-link');
            if (link) selectedLinks.push(link);
        });

        if (selectedLinks.length === 0) {
            ui.addNotification(null, E('p', {}, _('Выберите хотя бы один сервер!')), 'danger');
            return;
        }

        ui.showModal(_('Сохранение'), [ E('p', { 'class': 'spinning' }, _('Запись выбранных узлов в Podkop (' + selectedLinks.length + ' шт.)...')) ]);
        var payload = selectedLinks.join('\n') + '\n';

        fs.write('/tmp/subparser_selected.txt', payload).then(function() {
            return fs.exec('/usr/bin/subparser-helper.sh', ['save_selected']);
        }).then(function() {
            ui.hideModal();
            ui.addNotification(null, E('p', {}, _('Серверы успешно сохранены в Podkop! (' + selectedLinks.length + ' шт.)')), 'info');
            setTimeout(function() { window.location.reload(); }, 800);
        }).catch(function(err) {
            ui.hideModal();
            ui.addNotification(null, E('p', {}, _('Ошибка сохранения: ') + err), 'danger');
        });
    }
});
