// nettools — unified dashboard app.js
// Tab switching, connection status, notification system, export handling

var App = (function () {
    'use strict';

    var tabs = {
        ping:   { module: PingTab,   section: null, button: null },
        trace:  { module: TraceTab,  section: null, button: null },
        mapper: { module: MapperTab, section: null, button: null },
    };

    var activeTab = 'ping';
    var $connBadge;
    var $notifications;

    function switchTab(name) {
        if (name === activeTab) return;
        if (!tabs[name]) return;
        var current = tabs[activeTab];
        current.section.classList.add('hidden');
        current.button.classList.remove('active');
        current.module.deactivate();
        activeTab = name;
        var next = tabs[name];
        next.section.classList.remove('hidden');
        next.button.classList.add('active');
        next.module.activate();
    }

    function updateConnectionStatus() {
        fetch('/api/status')
            .then(function (resp) { return resp.json(); })
            .then(function () {
                $connBadge.textContent = 'Connected';
                $connBadge.className = 'status-badge connected';
            })
            .catch(function () {
                $connBadge.textContent = 'Disconnected';
                $connBadge.className = 'status-badge disconnected';
            });
    }

    function showNotification(msg, cls) {
        var el = document.createElement('div');
        el.className = 'notification' + (cls ? ' ' + cls : '');
        el.textContent = msg;
        $notifications.prepend(el);
        setTimeout(function () { if (el.parentNode) el.parentNode.removeChild(el); }, 10000);
        while ($notifications.children.length > 8) $notifications.removeChild($notifications.lastChild);
    }

    // -----------------------------------------------------------------------
    // Export handling
    // -----------------------------------------------------------------------

    function handleExport(tool, format) {
        var url;
        if (tool === 'ping') {
            url = '/api/ping/export?format=' + format;
        } else if (tool === 'trace') {
            url = '/api/trace/export?format=' + format;
        } else if (tool === 'mapper') {
            url = '/api/mapper/export?format=' + format;
        } else {
            return;
        }

        showNotification('Exporting ' + tool + ' data as ' + format.toUpperCase() + '...');

        fetch(url)
            .then(function (resp) {
                if (!resp.ok) throw new Error('Export failed');
                var ct = resp.headers.get('content-type') || '';
                if (ct.indexOf('json') >= 0) {
                    return resp.json().then(function (data) {
                        downloadBlob(JSON.stringify(data, null, 2), tool + '_export.' + format, 'application/json');
                    });
                } else if (ct.indexOf('csv') >= 0) {
                    return resp.text().then(function (text) {
                        downloadBlob(text, tool + '_export.csv', 'text/csv');
                    });
                } else if (ct.indexOf('svg') >= 0) {
                    return resp.text().then(function (text) {
                        downloadBlob(text, tool + '_topology.svg', 'image/svg+xml');
                    });
                } else if (ct.indexOf('visio') >= 0 || ct.indexOf('vsdx') >= 0 || format === 'vsdx') {
                    return resp.blob().then(function (blob) {
                        var url = URL.createObjectURL(blob);
                        var a = document.createElement('a');
                        a.href = url;
                        a.download = tool + '_topology.vsdx';
                        document.body.appendChild(a);
                        a.click();
                        setTimeout(function () { document.body.removeChild(a); URL.revokeObjectURL(url); }, 100);
                    });
                } else {
                    return resp.text().then(function (text) {
                        downloadBlob(text, tool + '_export.' + format, 'application/octet-stream');
                    });
                }
            })
            .then(function () {
                showNotification('Export complete!', 'phase');
            })
            .catch(function (err) {
                showNotification('Export failed: ' + err.message, 'alert');
            });
    }

    function downloadBlob(content, filename, mimeType) {
        var blob = new Blob([content], { type: mimeType });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        setTimeout(function () {
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }, 100);
    }

    // -----------------------------------------------------------------------
    // Boot
    // -----------------------------------------------------------------------

    function boot() {
        $connBadge = document.getElementById('connection-status');
        $notifications = document.getElementById('notifications');

        Object.keys(tabs).forEach(function (name) {
            tabs[name].section = document.getElementById('tab-' + name);
            tabs[name].button = document.querySelector('.nav-tab[data-tab="' + name + '"]');
        });

        document.querySelectorAll('.nav-tab').forEach(function (btn) {
            btn.addEventListener('click', function () { switchTab(btn.dataset.tab); });
        });

        // Bind export buttons
        document.querySelectorAll('.btn-export').forEach(function (btn) {
            btn.addEventListener('click', function () {
                handleExport(btn.dataset.export, btn.dataset.format);
            });
        });

        PingTab.init();
        TraceTab.init();
        MapperTab.init();
        tabs[activeTab].module.activate();
        updateConnectionStatus();
        setInterval(updateConnectionStatus, 15000);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }

    return { showNotification: showNotification };
})();
