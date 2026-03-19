// nettools — Mapper tab module
// On-demand network scanning with full parameter control

var MapperTab = (function () {
    'use strict';

    var state = {
        devices: [],
        topology: { nodes: [], edges: [] },
        scanInfo: null,
        sortCol: 'ip',
        sortAsc: true,
        filter: '',
    };

    var $progressBar, $progressPhase, $scanId, $scanStarted, $scanCompleted;
    var $scanSubnets, $scanDevices, $deviceTbody, $deviceFilter;
    var $mapperProgress;
    var eventSource, simulation;
    var $startBtn, $stopBtn, $jobStatus;

    function connect() {
        if (eventSource) return;
        var es = new EventSource('/api/mapper/events');
        es.addEventListener('phase_started', function (e) {
            var data = JSON.parse(e.data);
            $mapperProgress.classList.remove('hidden');
            $progressPhase.textContent = data.PhaseStarted.phase;
            App.showNotification('Phase started: ' + data.PhaseStarted.phase, 'phase');
        });
        es.addEventListener('phase_completed', function (e) {
            var data = JSON.parse(e.data);
            App.showNotification('Phase completed: ' + data.PhaseCompleted.phase, 'phase');
        });
        es.addEventListener('host_discovered', function (e) {
            var data = JSON.parse(e.data);
            App.showNotification('Host discovered: ' + data.HostDiscovered.ip);
        });
        es.addEventListener('host_scanned', function () { loadDevices(); });
        es.addEventListener('progress', function (e) {
            var data = JSON.parse(e.data);
            $mapperProgress.classList.remove('hidden');
            var pct = data.Progress.total > 0 ? (data.Progress.done / data.Progress.total * 100) : 0;
            $progressBar.style.width = pct.toFixed(1) + '%';
        });
        es.addEventListener('scan_completed', function () {
            $mapperProgress.classList.add('hidden');
            App.showNotification('Scan completed!', 'phase');
            loadAll();
        });
        eventSource = es;
    }

    function disconnect() {
        if (eventSource) { eventSource.close(); eventSource = null; }
    }

    function loadAll() { loadDevices(); loadTopology(); loadScanInfo(); }

    function loadDevices() {
        return fetch('/api/mapper/devices')
            .then(function (r) { return r.ok ? r.json() : []; })
            .then(function (devices) { state.devices = devices; renderDeviceTable(); })
            .catch(function (err) { console.error('Failed to load mapper devices:', err); });
    }

    function loadTopology() {
        return fetch('/api/mapper/topology')
            .then(function (r) { return r.ok ? r.json() : { nodes: [], edges: [] }; })
            .then(function (topo) { state.topology = topo; renderTopology(); })
            .catch(function (err) { console.error('Failed to load mapper topology:', err); });
    }

    function loadScanInfo() {
        return fetch('/api/mapper/scan-info')
            .then(function (r) { if (r.status === 204) return null; return r.ok ? r.json() : null; })
            .then(function (info) { if (info) { state.scanInfo = info; renderScanInfo(); } })
            .catch(function (err) { console.error('Failed to load mapper scan info:', err); });
    }

    function pollJobStatus() {
        fetch('/api/mapper/status')
            .then(function (r) { return r.json(); })
            .then(function (status) {
                $startBtn.disabled = status.running;
                $stopBtn.disabled = !status.running;
                $jobStatus.textContent = status.message;
                $jobStatus.className = status.running ? 'job-status running' : 'job-status';
                if (status.running) $mapperProgress.classList.remove('hidden');
            })
            .catch(function () {});
    }

    // -----------------------------------------------------------------------
    // Control Panel Actions
    // -----------------------------------------------------------------------

    function startScan() {
        var targetsStr = document.getElementById('mapper-targets').value.trim();
        if (!targetsStr) { App.showNotification('Please enter target(s)', 'alert'); return; }

        var targets = targetsStr.split(',').map(function (s) { return s.trim(); }).filter(function (s) { return s; });

        var body = {
            targets: targets,
            ping_timeout: parseInt(document.getElementById('mapper-ping-timeout').value) || 1000,
            concurrency: parseInt(document.getElementById('mapper-concurrency').value) || 64,
            no_arp: document.getElementById('mapper-no-arp').checked,
            no_rdns: document.getElementById('mapper-no-rdns').checked,
        };

        var portsStr = document.getElementById('mapper-ports').value.trim();
        if (portsStr) {
            body.ports = portsStr.split(',').map(function (s) { return parseInt(s.trim()); }).filter(function (n) { return !isNaN(n); });
        }

        var community = document.getElementById('mapper-snmp-community').value.trim();
        if (community) body.snmp_community = community;

        var v3user = document.getElementById('mapper-snmp-v3-user').value.trim();
        if (v3user) {
            body.snmp_v3_user = v3user;
            body.snmp_v3_auth_proto = document.getElementById('mapper-snmp-v3-auth-proto').value;
            body.snmp_v3_auth_pass = document.getElementById('mapper-snmp-v3-auth-pass').value || undefined;
            body.snmp_v3_priv_proto = document.getElementById('mapper-snmp-v3-priv-proto').value;
            body.snmp_v3_priv_pass = document.getElementById('mapper-snmp-v3-priv-pass').value || undefined;
        }

        $startBtn.disabled = true;
        $jobStatus.textContent = 'Starting scan...';
        $jobStatus.className = 'job-status running';
        $progressBar.style.width = '0%';
        $mapperProgress.classList.remove('hidden');
        $progressPhase.textContent = 'Initializing...';

        fetch('/api/mapper/start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data.error) {
                    App.showNotification(data.error, 'alert');
                    $startBtn.disabled = false;
                    $jobStatus.textContent = '';
                    $jobStatus.className = 'job-status';
                    $mapperProgress.classList.add('hidden');
                } else {
                    $stopBtn.disabled = false;
                    App.showNotification('Scan started');
                    disconnect();
                    connect();
                }
            })
            .catch(function (err) {
                App.showNotification('Failed to start scan: ' + err, 'alert');
                $startBtn.disabled = false;
            });
    }

    function stopScan() {
        $stopBtn.disabled = true;
        fetch('/api/mapper/stop', { method: 'POST' })
            .then(function (r) { return r.json(); })
            .then(function () {
                $startBtn.disabled = false;
                $jobStatus.textContent = 'Stopped';
                $jobStatus.className = 'job-status';
                App.showNotification('Scan stopped');
            })
            .catch(function (err) {
                App.showNotification('Failed to stop: ' + err, 'alert');
                $stopBtn.disabled = false;
            });
    }

    // -----------------------------------------------------------------------
    // Rendering
    // -----------------------------------------------------------------------

    function fmtTime(iso) {
        if (!iso) return '--';
        return new Date(iso).toLocaleTimeString();
    }

    function renderScanInfo() {
        var info = state.scanInfo;
        if (!info) return;
        $scanId.textContent = info.scan_id.substring(0, 8);
        $scanStarted.textContent = fmtTime(info.started_at);
        $scanCompleted.textContent = fmtTime(info.completed_at);
        $scanSubnets.textContent = info.subnet_count;
        $scanDevices.textContent = info.device_count;
    }

    function typeClass(t) { return 'type-' + t.toLowerCase().replace(/\s+/g, ''); }

    function ipToNum(ip) {
        var parts = ip.split('.');
        if (parts.length !== 4) return 0;
        return ((+parts[0]) << 24) + ((+parts[1]) << 16) + ((+parts[2]) << 8) + (+parts[3]);
    }

    function sortDevices(devices) {
        var col = state.sortCol, asc = state.sortAsc ? 1 : -1;
        return devices.slice().sort(function (a, b) {
            var va, vb;
            if (col === 'open_ports') { va = (a.open_ports || []).length; vb = (b.open_ports || []).length; }
            else if (col === 'ip') { va = ipToNum(a.ip); vb = ipToNum(b.ip); }
            else { va = (a[col] || '').toString().toLowerCase(); vb = (b[col] || '').toString().toLowerCase(); }
            return va < vb ? -1 * asc : va > vb ? 1 * asc : 0;
        });
    }

    function filterDevices(devices) {
        var q = state.filter.toLowerCase();
        if (!q) return devices;
        return devices.filter(function (d) {
            return (d.ip && d.ip.toLowerCase().indexOf(q) >= 0) ||
                   (d.mac && d.mac.toLowerCase().indexOf(q) >= 0) ||
                   (d.vendor && d.vendor.toLowerCase().indexOf(q) >= 0) ||
                   (d.hostname && d.hostname.toLowerCase().indexOf(q) >= 0) ||
                   (d.device_type && d.device_type.toLowerCase().indexOf(q) >= 0) ||
                   (d.os_guess && d.os_guess.toLowerCase().indexOf(q) >= 0);
        });
    }

    function renderDeviceTable() {
        var filtered = filterDevices(state.devices);
        var sorted = sortDevices(filtered);
        document.querySelectorAll('#mapper-device-table th.sortable').forEach(function (th) {
            var arrow = th.querySelector('.sort-arrow');
            if (arrow) arrow.remove();
            if (th.dataset.col === state.sortCol) {
                var span = document.createElement('span');
                span.className = 'sort-arrow';
                span.textContent = state.sortAsc ? ' \u25B2' : ' \u25BC';
                th.appendChild(span);
            }
        });
        var rows = '';
        sorted.forEach(function (d) {
            var ports = (d.open_ports || []).map(function (p) {
                return '<span class="port-tag">' + (p.service ? p.port + '/' + p.service : String(p.port)) + '</span>';
            }).join('');
            rows += '<tr><td>' + (d.ip || '--') + '</td><td>' + (d.mac || '--') + '</td><td>' + (d.vendor || '--') + '</td><td>' + (d.hostname || '--') + '</td><td><span class="type-badge ' + typeClass(d.device_type || 'Unknown') + '">' + (d.device_type || 'Unknown') + '</span></td><td>' + (d.os_guess || '--') + '</td><td>' + (ports || '--') + '</td></tr>';
        });
        $deviceTbody.innerHTML = rows;
    }

    function renderTopology() {
        var container = document.getElementById('mapper-topology-container');
        var svg = d3.select('#mapper-topology-svg');
        svg.selectAll('*').remove();
        var width = container.clientWidth, height = container.clientHeight;
        svg.attr('viewBox', '0 0 ' + width + ' ' + height);
        var nodes = state.topology.nodes, edges = state.topology.edges;
        if (nodes.length === 0) return;
        var nodeMap = {};
        nodes.forEach(function (n) { nodeMap[n.ip] = n; });
        var links = edges.map(function (e) { return { source: e.source, target: e.target, link_type: e.link_type }; }).filter(function (l) { return nodeMap[l.source] && nodeMap[l.target]; });
        var simNodes = nodes.map(function (n) { return { id: n.ip, label: n.label, tier: n.tier, device_type: n.device_type, subnet: n.subnet }; });
        var simLinks = links.map(function (l) { return { source: l.source, target: l.target, link_type: l.link_type }; });
        var tooltip = d3.select(container).selectAll('.topo-tooltip').data([0]);
        tooltip = tooltip.enter().append('div').attr('class', 'topo-tooltip').merge(tooltip);
        if (simulation) simulation.stop();
        simulation = d3.forceSimulation(simNodes)
            .force('link', d3.forceLink(simLinks).id(function (d) { return d.id; }).distance(80))
            .force('charge', d3.forceManyBody().strength(-200))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collision', d3.forceCollide(30));
        var link = svg.append('g').selectAll('line').data(simLinks).enter().append('line').attr('class', 'topo-link');
        var node = svg.append('g').selectAll('g').data(simNodes).enter().append('g').attr('class', 'topo-node')
            .call(d3.drag().on('start', dragstarted).on('drag', dragged).on('end', dragended));
        var nodeRadius = function (d) { return d.tier === 0 ? 12 : d.tier === 1 ? 9 : 7; };
        node.append('circle').attr('r', nodeRadius).attr('class', function (d) { return 'tier-' + d.tier; })
            .on('mouseover', function (event, d) {
                tooltip.style('display', 'block').html('<div class="tt-ip">' + d.id + '</div><div class="tt-type">' + d.device_type + '</div><div>' + d.label + '</div>')
                    .style('left', (event.offsetX + 16) + 'px').style('top', (event.offsetY - 10) + 'px');
            })
            .on('mouseout', function () { tooltip.style('display', 'none'); });
        node.append('text').attr('dy', function (d) { return nodeRadius(d) + 12; })
            .text(function (d) { return d.label.length > 16 ? d.label.substring(0, 14) + '..' : d.label; });
        simulation.on('tick', function () {
            link.attr('x1', function (d) { return d.source.x; }).attr('y1', function (d) { return d.source.y; })
                .attr('x2', function (d) { return d.target.x; }).attr('y2', function (d) { return d.target.y; });
            node.attr('transform', function (d) { return 'translate(' + d.x + ',' + d.y + ')'; });
        });
        function dragstarted(event, d) { if (!event.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; }
        function dragged(event, d) { d.fx = event.x; d.fy = event.y; }
        function dragended(event, d) { if (!event.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }
    }

    function bindEvents() {
        document.querySelectorAll('#mapper-device-table th.sortable').forEach(function (th) {
            th.addEventListener('click', function () {
                var col = th.dataset.col;
                if (state.sortCol === col) state.sortAsc = !state.sortAsc;
                else { state.sortCol = col; state.sortAsc = true; }
                renderDeviceTable();
            });
        });
        $deviceFilter.addEventListener('input', function () {
            state.filter = $deviceFilter.value;
            renderDeviceTable();
        });
    }

    var refreshInterval = null;
    var resizeHandler = null;
    var statusInterval = null;

    function init() {
        $mapperProgress = document.getElementById('mapper-progress');
        $progressPhase = document.getElementById('mapper-phase');
        $progressBar = document.getElementById('mapper-progress-bar');
        $scanId = document.getElementById('mapper-scan-id');
        $scanStarted = document.getElementById('mapper-started');
        $scanCompleted = document.getElementById('mapper-completed');
        $scanSubnets = document.getElementById('mapper-subnet-count');
        $scanDevices = document.getElementById('mapper-device-count');
        $deviceTbody = document.getElementById('mapper-device-tbody');
        $deviceFilter = document.getElementById('mapper-device-filter');
        $startBtn = document.getElementById('mapper-start-btn');
        $stopBtn = document.getElementById('mapper-stop-btn');
        $jobStatus = document.getElementById('mapper-job-status');

        $startBtn.addEventListener('click', startScan);
        $stopBtn.addEventListener('click', stopScan);
        bindEvents();
    }

    function activate() {
        loadAll();
        connect();
        pollJobStatus();
        refreshInterval = setInterval(loadAll, 30000);
        statusInterval = setInterval(pollJobStatus, 3000);
        resizeHandler = function () { if (state.topology.nodes.length > 0) renderTopology(); };
        window.addEventListener('resize', resizeHandler);
    }

    function deactivate() {
        disconnect();
        if (refreshInterval) { clearInterval(refreshInterval); refreshInterval = null; }
        if (statusInterval) { clearInterval(statusInterval); statusInterval = null; }
        if (resizeHandler) { window.removeEventListener('resize', resizeHandler); resizeHandler = null; }
        if (simulation) { simulation.stop(); simulation = null; }
    }

    return { init: init, activate: activate, deactivate: deactivate };
})();
