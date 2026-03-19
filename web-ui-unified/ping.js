// nettools — Ping tab module
// On-demand ping with full parameter control + real-time display

var PingTab = (function () {
    'use strict';

    var state = {
        targets: [],
        history: {},
        alerts: [],
    };

    var HISTORY_LIMIT = 120;
    var TARGET_COLORS = [
        '#4a9eff', '#34d399', '#fbbf24', '#f87171',
        '#a78bfa', '#fb923c', '#38bdf8', '#f472b6',
    ];

    var $grid, $alertsList, rttChart, eventSource;
    var $startBtn, $stopBtn, $jobStatus;

    // -----------------------------------------------------------------------
    // RTT Chart
    // -----------------------------------------------------------------------

    function createChart() {
        var ctx = document.getElementById('ping-rtt-chart').getContext('2d');
        rttChart = new Chart(ctx, {
            type: 'line',
            data: { datasets: [] },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 0 },
                interaction: { mode: 'index', intersect: false },
                scales: {
                    x: {
                        type: 'linear',
                        title: { display: true, text: 'Time (s ago)', color: '#8b8fa3' },
                        reverse: true,
                        ticks: { color: '#5a5e72' },
                        grid: { color: '#1e2130' },
                    },
                    y: {
                        title: { display: true, text: 'RTT (ms)', color: '#8b8fa3' },
                        beginAtZero: true,
                        ticks: { color: '#5a5e72' },
                        grid: { color: '#1e2130' },
                    },
                },
                plugins: {
                    legend: { labels: { color: '#e4e6f0', usePointStyle: true, pointStyle: 'circle' } },
                    tooltip: { backgroundColor: '#1a1d27', titleColor: '#e4e6f0', bodyColor: '#8b8fa3', borderColor: '#2a2e3f', borderWidth: 1 },
                },
            },
        });
    }

    // -----------------------------------------------------------------------
    // SSE Connection
    // -----------------------------------------------------------------------

    function connect() {
        if (eventSource) return;
        var es = new EventSource('/api/ping/events');

        es.addEventListener('ping_result', function (e) {
            var data = JSON.parse(e.data);
            var tid = data.target_id;
            var result = data.result;

            if (!state.history[tid]) state.history[tid] = [];
            state.history[tid].push({
                rtt_ms: result.rtt ? result.rtt.secs * 1000 + result.rtt.nanos / 1e6 : null,
                timestamp_ms: Date.now(),
                status: result.status,
            });
            if (state.history[tid].length > HISTORY_LIMIT) {
                state.history[tid].shift();
            }
        });

        es.addEventListener('stats_update', function (e) {
            var data = JSON.parse(e.data);
            var tid = data.target_id;
            var stats = data.stats;

            var target = state.targets.find(function (t) { return t.id === tid; });
            if (target) {
                target.stats = stats.stats;
                target.is_up = stats.is_up;
                target.last_rtt_ms = stats.last_rtt_ms;
            }

            renderTargetCard(tid);
            updateChart();
        });

        es.addEventListener('alert_fired', function (e) {
            var data = JSON.parse(e.data);
            state.alerts.unshift({ time: new Date(), message: data.alert.message, target_id: data.target_id });
            if (state.alerts.length > 50) state.alerts.pop();
            renderAlerts();
        });

        eventSource = es;
    }

    function disconnect() {
        if (eventSource) { eventSource.close(); eventSource = null; }
    }

    // -----------------------------------------------------------------------
    // Data loading
    // -----------------------------------------------------------------------

    function loadTargets() {
        return fetch('/api/ping/targets')
            .then(function (resp) { return resp.json(); })
            .then(function (targets) {
                state.targets = targets.map(function (t) {
                    return {
                        id: t.id, host: t.host, label: t.label, mode: t.mode,
                        port: t.port, interval: t.interval,
                        stats: t.stats ? t.stats.stats : null,
                        is_up: t.stats ? t.stats.is_up : null,
                        last_rtt_ms: t.stats ? t.stats.last_rtt_ms : null,
                    };
                });
                renderAllCards();
            })
            .catch(function (err) { console.error('Failed to load ping targets:', err); });
    }

    function pollJobStatus() {
        fetch('/api/ping/status')
            .then(function (resp) { return resp.json(); })
            .then(function (status) {
                if (status.running) {
                    $startBtn.disabled = true;
                    $stopBtn.disabled = false;
                    $jobStatus.textContent = status.message;
                    $jobStatus.className = 'job-status running';
                } else {
                    $startBtn.disabled = false;
                    $stopBtn.disabled = true;
                    $jobStatus.textContent = status.message;
                    $jobStatus.className = 'job-status';
                }
            })
            .catch(function () {});
    }

    // -----------------------------------------------------------------------
    // Control Panel Actions
    // -----------------------------------------------------------------------

    function startPing() {
        var target = document.getElementById('ping-target').value.trim();
        if (!target) { App.showNotification('Please enter a target', 'alert'); return; }

        var body = {
            target: target,
            mode: document.getElementById('ping-mode').value,
            interval: document.getElementById('ping-interval').value || '1s',
            timeout: document.getElementById('ping-timeout').value || '2s',
            size: parseInt(document.getElementById('ping-size').value) || 56,
        };

        var port = document.getElementById('ping-port').value;
        if (port) body.port = parseInt(port);

        var count = document.getElementById('ping-count').value;
        if (count) body.count = parseInt(count);

        var ttl = document.getElementById('ping-ttl').value;
        if (ttl) body.ttl = parseInt(ttl);

        var tos = document.getElementById('ping-tos').value;
        if (tos) body.tos = parseInt(tos);

        var pattern = document.getElementById('ping-pattern').value;
        if (pattern) body.pattern = pattern;

        // Clear previous data
        state.history = {};
        state.targets = [];
        state.alerts = [];
        $grid.innerHTML = '';

        $startBtn.disabled = true;
        $jobStatus.textContent = 'Starting...';
        $jobStatus.className = 'job-status running';

        fetch('/api/ping/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        })
        .then(function (resp) { return resp.json(); })
        .then(function (data) {
            if (data.error) {
                App.showNotification(data.error, 'alert');
                $startBtn.disabled = false;
                $jobStatus.textContent = '';
                $jobStatus.className = 'job-status';
            } else {
                $stopBtn.disabled = false;
                App.showNotification('Ping started: ' + target);
                // Reconnect SSE and load targets
                disconnect();
                connect();
                setTimeout(loadTargets, 500);
            }
        })
        .catch(function (err) {
            App.showNotification('Failed to start ping: ' + err, 'alert');
            $startBtn.disabled = false;
        });
    }

    function stopPing() {
        $stopBtn.disabled = true;
        fetch('/api/ping/stop', { method: 'POST' })
            .then(function (resp) { return resp.json(); })
            .then(function () {
                $startBtn.disabled = false;
                $jobStatus.textContent = 'Stopped';
                $jobStatus.className = 'job-status';
                App.showNotification('Ping stopped');
            })
            .catch(function (err) {
                App.showNotification('Failed to stop ping: ' + err, 'alert');
                $stopBtn.disabled = false;
            });
    }

    // -----------------------------------------------------------------------
    // Rendering — Target Cards
    // -----------------------------------------------------------------------

    function rttClass(ms) {
        if (ms == null) return 'none';
        if (ms > 150) return 'bad';
        if (ms > 50) return 'warn';
        return 'good';
    }
    function fmtRtt(ms) { return ms == null ? '--' : ms.toFixed(1) + 'ms'; }
    function fmtPct(v) { return v == null ? '--' : v.toFixed(1) + '%'; }
    function fmtMos(v) { return v == null ? '--' : v.toFixed(2); }

    function renderTargetCard(tid) {
        var target = state.targets.find(function (t) { return t.id === tid; });
        if (!target) return;
        var card = document.getElementById('ping-card-' + tid);
        if (!card) {
            card = document.createElement('div');
            card.id = 'ping-card-' + tid;
            card.className = 'target-card';
            $grid.appendChild(card);
        }
        var statusClass = target.is_up === true ? 'up' : target.is_up === false ? 'down' : 'unknown';
        var s = target.stats;
        card.innerHTML =
            '<div class="card-header">' +
                '<div class="status-dot ' + statusClass + '"></div>' +
                '<div class="host-name">' + target.host + '</div>' +
                '<span class="mode-badge">' + target.mode + (target.port ? ':' + target.port : '') + '</span>' +
                (target.label && target.label !== target.host ? '<span class="label">' + target.label + '</span>' : '') +
            '</div>' +
            '<div class="stats-grid">' +
                '<div class="stat-item"><span class="stat-label">Last RTT</span><span class="stat-value ' + rttClass(target.last_rtt_ms) + '">' + fmtRtt(target.last_rtt_ms) + '</span></div>' +
                '<div class="stat-item"><span class="stat-label">Avg RTT</span><span class="stat-value ' + rttClass(s && s.avg_rtt_ms) + '">' + fmtRtt(s && s.avg_rtt_ms) + '</span></div>' +
                '<div class="stat-item"><span class="stat-label">Loss</span><span class="stat-value ' + (s && s.loss_pct > 5 ? 'bad' : s && s.loss_pct > 1 ? 'warn' : 'good') + '">' + (s ? fmtPct(s.loss_pct) : '--') + '</span></div>' +
                '<div class="stat-item"><span class="stat-label">Jitter</span><span class="stat-value ' + rttClass(s && s.jitter_ms) + '">' + fmtRtt(s && s.jitter_ms) + '</span></div>' +
                '<div class="stat-item"><span class="stat-label">MOS</span><span class="stat-value ' + (s && s.mos ? (s.mos > 4 ? 'good' : s.mos > 3 ? 'warn' : 'bad') : 'none') + '">' + (s ? fmtMos(s.mos) : '--') + '</span></div>' +
                '<div class="stat-item"><span class="stat-label">Packets</span><span class="stat-value">' + (s ? s.transmitted : '--') + '</span></div>' +
            '</div>';
    }

    function renderAllCards() {
        $grid.innerHTML = '';
        state.targets.forEach(function (t) { renderTargetCard(t.id); });
    }

    function renderAlerts() {
        if (state.alerts.length === 0) {
            $alertsList.innerHTML = '<div class="alert-empty">No alerts yet.</div>';
            return;
        }
        $alertsList.innerHTML = state.alerts.slice(0, 20).map(function (a) {
            return '<div class="alert-item"><span class="alert-time">' + a.time.toLocaleTimeString() + '</span><span class="alert-message">' + a.message + '</span></div>';
        }).join('');
    }

    function updateChart() {
        var now = Date.now();
        var datasets = [];
        state.targets.forEach(function (target, idx) {
            var hist = state.history[target.id];
            if (!hist || hist.length === 0) return;
            var points = hist.filter(function (h) { return h.rtt_ms != null; }).map(function (h) {
                return { x: (now - h.timestamp_ms) / 1000, y: h.rtt_ms };
            });
            var color = TARGET_COLORS[idx % TARGET_COLORS.length];
            datasets.push({
                label: target.label || target.host,
                data: points, borderColor: color, backgroundColor: color + '20',
                borderWidth: 1.5, pointRadius: 0, tension: 0.3, fill: false,
            });
        });
        rttChart.data.datasets = datasets;
        rttChart.update('none');
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    var refreshInterval = null;
    var statusInterval = null;

    function init() {
        $grid = document.getElementById('ping-targets-grid');
        $alertsList = document.getElementById('ping-alerts-list');
        $startBtn = document.getElementById('ping-start-btn');
        $stopBtn = document.getElementById('ping-stop-btn');
        $jobStatus = document.getElementById('ping-job-status');

        $startBtn.addEventListener('click', startPing);
        $stopBtn.addEventListener('click', stopPing);

        createChart();
        renderAlerts();
    }

    function activate() {
        loadTargets();
        connect();
        pollJobStatus();
        refreshInterval = setInterval(loadTargets, 30000);
        statusInterval = setInterval(pollJobStatus, 3000);
    }

    function deactivate() {
        disconnect();
        if (refreshInterval) { clearInterval(refreshInterval); refreshInterval = null; }
        if (statusInterval) { clearInterval(statusInterval); statusInterval = null; }
    }

    return { init: init, activate: activate, deactivate: deactivate };
})();
