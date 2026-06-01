document.addEventListener('DOMContentLoaded', () => {
    initDashboard();
});

let alertChart;

function initDashboard() {
    // 1. Initial Data Fetch
    fetchStats();
    fetchInitialLogs();
    
    // 2. Initialize WebSocket
    const ws = new WebSocket('ws://' + window.location.host + '/ws/alerts/');

    ws.onmessage = function(event) {
        const data = JSON.parse(event.data);
        
        // Skip connection messages
        if (data.type === 'connection_established') return;

        // Process live alert
        handleLiveAlert(data);
    };

    ws.onerror = function(err) {
        console.error('WebSocket Error:', err);
    };

    // 3. Initialize Chart
    initChart();
}

async function fetchStats() {
    try {
        const response = await fetch('/api/stats/');
        const data = await response.json();
        updateStatsUI(data);
    } catch (err) {
        console.error('Failed to fetch stats:', err);
    }
}

async function fetchInitialLogs() {
    try {
        const response = await fetch('/api/alerts/?page_size=15');
        const data = await response.json();
        const feed = document.getElementById('live-feed');
        if (!feed) return;

        data.results.forEach(alert => {
            const row = createAlertRow(alert);
            feed.appendChild(row);
        });
    } catch (err) {
        console.error('Failed to fetch initial logs:', err);
    }
}

function updateStatsUI(data) {
    const totalLogs = document.getElementById('stat-total-logs');
    const attacks = document.getElementById('stat-attacks');
    const suspicious = document.getElementById('stat-suspicious');
    const normal = document.getElementById('stat-normal');

    if (totalLogs) totalLogs.innerText = data.totals.logs.toLocaleString();
    if (attacks) attacks.innerText = data.today.attacks.toLocaleString();
    if (suspicious) suspicious.innerText = data.today.suspicious.toLocaleString();
    if (normal) normal.innerText = data.today.normal.toLocaleString();
}

function handleLiveAlert(alert) {
    // Add to feed
    const feed = document.getElementById('live-feed');
    if (feed) {
        const row = createAlertRow(alert);
        row.classList.add('new-event'); // Add highlight animation
        feed.prepend(row);
        
        // Keep only last 20 rows
        if (feed.children.length > 20) {
            feed.removeChild(feed.lastChild);
        }
    }

    // Update stats counters locally (optimistic)
    updateStatsCounter(alert.verdict);
    
    // Update Chart
    updateChartData(alert.verdict);
}

function updateStatsCounter(verdict) {
    const total = document.getElementById('stat-total-logs');
    if (total) total.innerText = (parseInt(total.innerText.replace(/,/g, '')) + 1).toLocaleString();

    let targetId = '';
    if (verdict === 'ATTACK') targetId = 'stat-attacks';
    else if (verdict === 'SUSPICIOUS') targetId = 'stat-suspicious';
    else if (verdict === 'NORMAL') targetId = 'stat-normal';

    const target = document.getElementById(targetId);
    if (target) target.innerText = (parseInt(target.innerText.replace(/,/g, '')) + 1).toLocaleString();
}

function createAlertRow(alert) {
    const tr = document.createElement('tr');
    
    const badgeClass = `verdict-${alert.verdict.toLowerCase()}`;
    const timestamp = new Date(alert.timestamp).toLocaleTimeString([], { hour12: false });

    tr.innerHTML = `
        <td>${timestamp}</td>
        <td><a href="/dashboard/ip/${alert.ip_address}/" class="ip-link">${alert.ip_address}</a></td>
        <td>${alert.event_type}</td>
        <td><span class="verdict-badge ${badgeClass}">${alert.verdict}</span></td>
        <td>${(alert.confidence * 100).toFixed(0)}%</td>
        <td style="color: var(--text-secondary); font-size: 0.8rem; font-style: italic;">${alert.reason}</td>
    `;
    return tr;
}

function initChart() {
    const ctx = document.getElementById('attackTrendChart');
    if (!ctx) return;

    alertChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: Array(12).fill(''),
            datasets: [{
                label: 'Attacks',
                data: Array(12).fill(0),
                borderColor: '#ef4444',
                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { beginAtZero: true, grid: { color: 'rgba(255, 255, 255, 0.05)' } },
                x: { grid: { display: false } }
            },
            plugins: { legend: { display: false } }
        }
    });
}

function updateChartData(verdict) {
    if (!alertChart || verdict !== 'ATTACK') return;
    
    // Simple push-style update for real-time visualization
    alertChart.data.datasets[0].data.shift();
    const lastValue = alertChart.data.datasets[0].data[alertChart.data.datasets[0].data.length - 1];
    alertChart.data.datasets[0].data.push(lastValue + 1);
    alertChart.update();
}
