// nettools — Trace tab module
// On-demand traceroute/MTR with full parameter control

var TraceTab = (function () {
    'use strict';

    var state = {
        target: '--',
        round: 0,
        maxTtl: 0,
        hops: {},
        rttHistory: {},
    };

    var HISTORY_LIMIT = 60;
    var HOP_COLORS = [
        '#4a9eff', '#34d399', '#fbbf24', '#f87171',
        '#a78bfa', '#fb923c', '#38bdf8', '#f472b6',
        '#6ee7b7', '#fcd34d', '#c084fc', '#f97316',
        '#67e8f9', '#e879f9', '#a3e635', '#fb7185',
    ];

    var $targetHost, $roundCounter, $hopCount, $hopTbody;
    var rttChart, eventSource;
    var $startBtn, $stopBtn, $jobStatus;

    function createChart() {
        var ctx = document.getElementById('trace-rtt-chart').getContext('2d');
        rttChart = new Chart(ctx, {
            type: 'line',
            data: { datasets: [] },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 0 },
                interaction: { mode: 'index', intersect: false },
                scales: {
                    x: { type: 'linear', title: { display: true, text: 'Round', color: '#8b8fa3' }, ticks: { color: '#5a5e72' }, grid: { color: '#1e2140' } },
                    y: { title: { display: true, text: 'RTT (ms)', color: '#8b8fa3' }, beginAtZero: true, ticks: { color: '#5a5e72' }, grid: { color: '#1e2140' } },
                },
                plugins: {
                    legend: { labels: { color: '#e0e0e0', usePointStyle: true, pointStyle: 'circle', font: { size: 11 } } },
                    tooltip: { backgroundColor: '#16213e', titleColor: '#e0e0e0', bodyColor: '#8b8fa3', borderColor: '#2a2e4a', borderWidth: 1 },
                },
            },
        });
    }

    function connect() {
        if (eventSource) return;
        var es = new EventSource('/api/trace/events');
        es.addEventListener('hop_update', function (e) {
            var data = JSON.parse(e.data);
            var ttl = data.ttl;
            state.hops[ttl] = { stats: data.stats, hostname: data.hostname, asn: data.asn, asn_name: data.asn_name };
            if (data.stats.avg_rtt_ms != null) {
                if (!state.rttHistory[ttl]) state.rttHistory[ttl] = [];
                state.rttHistory[ttl].push({ round: state.round, avg_rtt_ms: data.stats.avg_rtt_ms });
                if (state.rttHistory[ttl].length > HISTORY_LIMIT) state.rttHistory[ttl].shift();
            }
            renderHopTable();
        });
        es.addEventListener('round_complete', function (e) {
            var data = JSON.parse(e.data);
            state.round = data.round;
            if (data.max_ttl_seen > state.maxTtl) state.maxTtl = data.max_ttl_seen;
            $roundCounter.textContent = state.round;
            $hopCount.textContent = state.maxTtl;
            updateChart();
        });
        es.addEventListener('path_change', function (e) {
            var data = JSON.parse(e.data);
            App.showNotification('Path change at hop ' + data.ttl + ': ' + (data.old_addr || '???') + ' -> ' + (data.new_addr || '???'));
        });
        eventSource = es;
    }

    function disconnect() {
        if (eventSource) { eventSource.close(); eventSource = null; }
    }

    function loadInfo() {
        return fetch('/api/trace/info')
            .then(function (resp) { return resp.json(); })
            .then(function (info) {
                state.target = info.target;
                state.round = info.round;
                state.maxTtl = info.max_ttl;
                $targetHost.textContent = info.target || '--';
                $roundCounter.textContent = info.round;
                $hopCount.textContent = info.max_ttl;
                info.hops.forEach(function (h) {
                    state.hops[h.ttl] = {
                        stats: { ttl: h.ttl, addr: h.addr, loss_pct: h.loss_pct, sent: h.sent, last_rtt_ms: h.last_rtt_ms, avg_rtt_ms: h.avg_rtt_ms, min_rtt_ms: h.min_rtt_ms, max_rtt_ms: h.max_rtt_ms, stddev_rtt_ms: h.stddev_rtt_ms },
                        hostname: h.hostname, asn: h.asn, asn_name: h.asn_name,
                    };
                });
                renderHopTable();
            })
            .catch(function (err) { console.error('Failed to load trace info:', err); });
    }

    function pollJobStatus() {
        fetch('/api/trace/status')
            .then(function (resp) { return resp.json(); })
            .then(function (status) {
                $startBtn.disabled = status.running;
                $stopBtn.disabled = !status.running;
                $jobStatus.textContent = status.message;
                $jobStatus.className = status.running ? 'job-status running' : 'job-status';
            })
            .catch(function () {});
    }

    function startTrace() {
        var target = document.getElementById('trace-target-input').value.trim();
        if (!target) { App.showNotification('Please enter a target', 'alert'); return; }
        var body = {
            target: target,
            method: document.getElementById('trace-method').value,
            max_ttl: parseInt(document.getElementById('trace-max-ttl').value) || 30,
            queries: parseInt(document.getElementById('trace-queries').value) || 1,
            interval: document.getElementById('trace-interval').value || '1s',
            timeout: document.getElementById('trace-timeout').value || '2s',
            send_wait: document.getElementById('trace-send-wait').value || '50ms',
            packet_size: parseInt(document.getElementById('trace-packet-size').value) || 60,
            first_ttl: parseInt(document.getElementById('trace-first-ttl').value) || 1,
            no_dns: document.getElementById('trace-no-dns').checked,
            asn: document.getElementById('trace-asn').checked,
        };
        var port = document.getElementById('trace-port').value;
        if (port) body.port = parseInt(port);
        var count = document.getElementById('trace-count').value;
        if (count) body.count = parseInt(count);

        state.hops = {};
        state.rttHistory = {};
        state.round = 0;
        state.maxTtl = 0;
        $hopTbody.innerHTML = '';
        $startBtn.disabled = true;
        $jobStatus.textContent = 'Starting...';
        $jobStatus.className = 'job-status running';

        fetch('/api/trace/start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
            .then(function (resp) { return resp.json(); })
            .then(function (data) {
                if (data.error) {
                    App.showNotification(data.error, 'alert');
                    $startBtn.disabled = false;
                    $jobStatus.textContent = '';
                    $jobStatus.className = 'job-status';
                } else {
                    $stopBtn.disabled = false;
                    App.showNotification('Trace started: ' + target);
                    disconnect();
                    connect();
                    setTimeout(loadInfo, 500);
                }
            })
            .catch(function (err) {
                App.showNotification('Failed to start trace: ' + err, 'alert');
                $startBtn.disabled = false;
            });
    }

    function stopTrace() {
        $stopBtn.disabled = true;
        fetch('/api/trace/stop', { method: 'POST' })
            .then(function (resp) { return resp.json(); })
            .then(function () {
                $startBtn.disabled = false;
                $jobStatus.textContent = 'Stopped';
                $jobStatus.className = 'job-status';
                App.showNotification('Trace stopped');
            })
            .catch(function (err) {
                App.showNotification('Failed to stop: ' + err, 'alert');
                $stopBtn.disabled = false;
            });
    }

    function rttClass(ms) { if (ms == null) return 'none'; if (ms > 150) return 'bad'; if (ms > 50) return 'warn'; return 'good'; }
    function lossClass(pct) { if (pct > 10) return 'bad'; if (pct > 0) return 'warn'; return 'good'; }
    function fmtRtt(ms) { return ms == null ? '--' : ms.toFixed(1); }
    function fmtLoss(pct) { return pct == null ? '--' : pct.toFixed(1) + '%'; }

    function renderHopTable() {
        var rows = '';
        for (var ttl = 1; ttl <= state.maxTtl; ttl++) {
            var hop = state.hops[ttl];
            if (!hop) {
                rows += '<tr><td class="col-ttl">' + ttl + '</td><td class="col-host none">???</td><td class="col-loss none">--</td><td class="col-snt none">--</td><td class="col-last none">--</td><td class="col-avg none">--</td><td class="col-best none">--</td><td class="col-wrst none">--</td><td class="col-stdev none">--</td></tr>';
                continue;
            }
            var s = hop.stats;
            var hostStr = hop.hostname ? hop.hostname + ' <span class="host-ip">(' + (s.addr || '???') + ')</span>' : (s.addr || '???');
            if (hop.asn) {
                hostStr += ' <span class="asn-tag">AS' + hop.asn + (hop.asn_name ? ' ' + hop.asn_name : '') + '</span>';
            }
            rows += '<tr><td class="col-ttl">' + ttl + '</td><td class="col-host">' + hostStr + '</td><td class="col-loss ' + lossClass(s.loss_pct) + '">' + fmtLoss(s.loss_pct) + '</td><td class="col-snt">' + s.sent + '</td><td class="col-last ' + rttClass(s.last_rtt_ms) + '">' + fmtRtt(s.last_rtt_ms) + '</td><td class="col-avg ' + rttClass(s.avg_rtt_ms) + '">' + fmtRtt(s.avg_rtt_ms) + '</td><td class="col-best ' + rttClass(s.min_rtt_ms) + '">' + fmtRtt(s.min_rtt_ms) + '</td><td class="col-wrst ' + rttClass(s.max_rtt_ms) + '">' + fmtRtt(s.max_rtt_ms) + '</td><td class="col-stdev">' + fmtRtt(s.stddev_rtt_ms) + '</td></tr>';
        }
        $hopTbody.innerHTML = rows;
    }

    function updateChart() {
        var datasets = [];
        var ttls = Object.keys(state.rttHistory).map(Number).sort(function (a, b) { return a - b; });
        ttls.forEach(function (ttl, idx) {
            var hist = state.rttHistory[ttl];
            if (!hist || hist.length === 0) return;
            var hop = state.hops[ttl];
            var label = 'Hop ' + ttl;
            if (hop && hop.hostname) label = ttl + ': ' + hop.hostname;
            else if (hop && hop.stats && hop.stats.addr) label = ttl + ': ' + hop.stats.addr;
            var color = HOP_COLORS[idx % HOP_COLORS.length];
            datasets.push({ label: label, data: hist.map(function (h) { return { x: h.round, y: h.avg_rtt_ms }; }), borderColor: color, backgroundColor: color + '20', borderWidth: 1.5, pointRadius: 0, tension: 0.3, fill: false });
        });
        rttChart.data.datasets = datasets;
        rttChart.update('none');
    }

    var refreshInterval = null;
    var statusInterval = null;

    function init() {
        $targetHost = document.getElementById('trace-target');
        $roundCounter = document.getElementById('trace-round');
        $hopCount = document.getElementById('trace-hop-count');
        $hopTbody = document.getElementById('trace-hop-tbody');
        $startBtn = document.getElementById('trace-start-btn');
        $stopBtn = document.getElementById('trace-stop-btn');
        $jobStatus = document.getElementById('trace-job-status');
        $startBtn.addEventListener('click', startTrace);
        $stopBtn.addEventListener('click', stopTrace);
        createChart();
    }

    function activate() {
        loadInfo();
        connect();
        pollJobStatus();
        refreshInterval = setInterval(loadInfo, 30000);
        statusInterval = setInterval(pollJobStatus, 3000);
    }

    function deactivate() {
        disconnect();
        if (refreshInterval) { clearInterval(refreshInterval); refreshInterval = null; }
        if (statusInterval) { clearInterval(statusInterval); statusInterval = null; }
    }

    return { init: init, activate: activate, deactivate: deactivate };
})();
