/**
 * PhishDetect AI - Dashboard Controller
 * static/js/dashboard.js
 *
 * Manages dashboard analytics, counter animations, recent scans feed,
 * and Chart.js telemetry visualizations with cybersecurity dark-glass theme.
 */

// Global chart references for proper lifecycle disposal on re-render
let riskDistributionChartInstance = null;
let detectionTrendChartInstance = null;

/**
 * Animates a numeric counter smoothly from 0 to target value.
 * @param {HTMLElement} element - Target DOM element
 * @param {number} target - Final numeric value
 * @param {number} duration - Animation duration in milliseconds
 */
function animateCounter(element, target, duration = 1200) {
    if (!element) return;
    const finalVal = parseInt(target, 10) || 0;
    const startTime = performance.now();

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        // Ease-out cubic calculation
        const easeOut = 1 - Math.pow(1 - progress, 3);
        const currentCount = Math.floor(easeOut * finalVal);

        element.textContent = currentCount.toLocaleString();

        if (progress < 1) {
            requestAnimationFrame(update);
        } else {
            element.textContent = finalVal.toLocaleString();
        }
    }

    requestAnimationFrame(update);
}

/**
 * Fetches dashboard summary metrics and updates KPI cards.
 */
async function loadDashboardStats() {
    try {
        const res = await fetch('/api/stats', { cache: 'no-cache' });
        if (!res.ok) throw new Error(`HTTP error ${res.status}`);
        const data = await res.json();

        const statTotal = document.getElementById('stat-total');
        const statPhishing = document.getElementById('stat-phishing');
        const statSafe = document.getElementById('stat-safe');
        const statCritical = document.getElementById('stat-critical');

        if (statTotal) animateCounter(statTotal, data.total_scans || 0);
        if (statPhishing) animateCounter(statPhishing, data.phishing_count || 0);
        if (statSafe) animateCounter(statSafe, data.safe_count || 0);
        if (statCritical) animateCounter(statCritical, data.critical_count || 0);

        return data;
    } catch (err) {
        console.error('Failed to load dashboard stats:', err);
        return null;
    }
}

/**
 * Fetches and renders the 5 most recent scans in the dashboard table.
 */
async function loadRecentScans() {
    const tableEl = document.getElementById('recent-scans-table');
    if (!tableEl) return;

    const tbody = tableEl.querySelector('tbody') || tableEl;

    try {
        const res = await fetch('/api/history?per_page=5&sort_by=scan_timestamp&sort_dir=desc', {
            cache: 'no-cache'
        });
        if (!res.ok) throw new Error(`HTTP error ${res.status}`);
        const data = await res.json();
        const scans = data.scans || [];

        if (scans.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center py-8 text-muted">
                        <div class="empty-feed">
                            <i data-lucide="shield-check" class="w-8 h-8 mx-auto mb-2 opacity-50"></i>
                            <p>No email scans yet. Use the Analysis tool to inspect your first email.</p>
                        </div>
                    </td>
                </tr>
            `;
            if (window.lucide && typeof window.lucide.createIcons === 'function') {
                window.lucide.createIcons();
            }
            return;
        }

        tbody.innerHTML = scans.map((scan, idx) => {
            const formattedTime = formatDate(scan.scan_timestamp);
            const senderShort = truncateText(scan.sender || 'Unknown', 30);
            const subjectShort = truncateText(scan.subject || '(No Subject)', 40);
            const categoryBadge = getRiskBadge(scan.risk_category);
            const catLower = (scan.risk_category || 'low').toLowerCase();

            return `
                <tr class="recent-row animate-in" style="animation-delay: ${idx * 50}ms">
                    <td class="text-xs text-secondary whitespace-nowrap">${formattedTime}</td>
                    <td class="font-medium text-sm" title="${escapeHtml(scan.sender || '')}">
                        ${escapeHtml(senderShort)}
                    </td>
                    <td class="text-sm text-primary" title="${escapeHtml(scan.subject || '')}">
                        ${escapeHtml(subjectShort)}
                    </td>
                    <td class="text-center">
                        <span class="badge badge-${catLower} font-mono">${scan.risk_score !== undefined ? scan.risk_score : 0}/100</span>
                    </td>
                    <td class="text-center">${categoryBadge}</td>
                    <td class="text-right">
                        <a href="/results/${scan.scan_id}" class="btn btn-secondary btn-sm" title="View Full Analysis">
                            <i data-lucide="arrow-right"></i> View
                        </a>
                    </td>
                </tr>
            `;
        }).join('');

        if (window.lucide && typeof window.lucide.createIcons === 'function') {
            window.lucide.createIcons();
        }
    } catch (err) {
        console.error('Failed to load recent scans:', err);
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="text-center py-4 text-danger">
                    Unable to load recent scans: ${escapeHtml(err.message)}
                </td>
            </tr>
        `;
    }
}

/**
 * Renders the Risk Category Distribution doughnut chart.
 * @param {Object} data - Category counts { low, medium, high, critical }
 */
function renderRiskDistributionChart(data) {
    const canvas = document.getElementById('riskDistributionChart');
    if (!canvas || !window.Chart) return;

    if (riskDistributionChartInstance) {
        riskDistributionChartInstance.destroy();
    }

    const dist = data || { low: 0, medium: 0, high: 0, critical: 0 };
    const values = [
        dist.low || 0,
        dist.medium || 0,
        dist.high || 0,
        dist.critical || 0
    ];

    const hasData = values.some(v => v > 0);
    const displayValues = hasData ? values : [1, 0, 0, 0];
    const displayColors = hasData
        ? ['#10b981', '#f59e0b', '#ef4444', '#8b5cf6']
        : ['rgba(148, 163, 184, 0.2)', 'transparent', 'transparent', 'transparent'];

    const ctx = canvas.getContext('2d');
    riskDistributionChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Low Risk', 'Medium Risk', 'High Risk', 'Critical Threat'],
            datasets: [{
                data: displayValues,
                backgroundColor: displayColors,
                borderColor: '#0f172a',
                borderWidth: 2,
                hoverOffset: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '72%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#f8fafc',
                        padding: 16,
                        font: {
                            family: 'Inter, system-ui, sans-serif',
                            size: 12
                        },
                        usePointStyle: true,
                        pointStyle: 'circle'
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(15, 23, 42, 0.95)',
                    titleColor: '#00d4ff',
                    bodyColor: '#f8fafc',
                    borderColor: 'rgba(0, 212, 255, 0.3)',
                    borderWidth: 1,
                    padding: 10,
                    boxPadding: 6,
                    callbacks: {
                        label: function (context) {
                            if (!hasData) return 'No scan data recorded';
                            const label = context.label || '';
                            const val = context.raw || 0;
                            const total = values.reduce((a, b) => a + b, 0);
                            const pct = total > 0 ? ((val / total) * 100).toFixed(1) : 0;
                            return ` ${label}: ${val} (${pct}%)`;
                        }
                    }
                }
            }
        }
    });
}

/**
 * Renders the 7-Day Detection Trend line chart.
 * @param {Array<Object>} data - Daily activity items [{ date, total, phishing }]
 */
function renderDetectionTrendChart(data) {
    const canvas = document.getElementById('detectionTrendChart');
    if (!canvas || !window.Chart) return;

    if (detectionTrendChartInstance) {
        detectionTrendChartInstance.destroy();
    }

    const activity = Array.isArray(data) && data.length > 0 ? data : generateDefaultTrendData();

    const labels = activity.map(item => {
        if (!item.date) return '';
        try {
            const d = new Date(item.date);
            return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
        } catch (e) {
            return item.date;
        }
    });

    const totalScans = activity.map(item => item.total || 0);
    const phishingScans = activity.map(item => item.phishing || 0);

    const ctx = canvas.getContext('2d');

    // Create subtle cyber gradients
    const cyanGradient = ctx.createLinearGradient(0, 0, 0, 300);
    cyanGradient.addColorStop(0, 'rgba(0, 212, 255, 0.25)');
    cyanGradient.addColorStop(1, 'rgba(0, 212, 255, 0.00)');

    const redGradient = ctx.createLinearGradient(0, 0, 0, 300);
    redGradient.addColorStop(0, 'rgba(239, 68, 68, 0.25)');
    redGradient.addColorStop(1, 'rgba(239, 68, 68, 0.00)');

    detectionTrendChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Total Scans',
                    data: totalScans,
                    borderColor: '#00d4ff',
                    backgroundColor: cyanGradient,
                    fill: true,
                    tension: 0.35,
                    borderWidth: 2,
                    pointBackgroundColor: '#00d4ff',
                    pointBorderColor: '#0f172a',
                    pointBorderWidth: 2,
                    pointRadius: 4,
                    pointHoverRadius: 6
                },
                {
                    label: 'Phishing Identified',
                    data: phishingScans,
                    borderColor: '#ef4444',
                    backgroundColor: redGradient,
                    fill: true,
                    tension: 0.35,
                    borderWidth: 2,
                    pointBackgroundColor: '#ef4444',
                    pointBorderColor: '#0f172a',
                    pointBorderWidth: 2,
                    pointRadius: 4,
                    pointHoverRadius: 6
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                mode: 'index',
                intersect: false
            },
            scales: {
                x: {
                    grid: {
                        color: 'rgba(0, 212, 255, 0.06)',
                        drawBorder: false
                    },
                    ticks: {
                        color: '#94a3b8',
                        font: { family: 'Inter, system-ui, sans-serif', size: 11 }
                    }
                },
                y: {
                    beginAtZero: true,
                    suggestedMax: 5,
                    grid: {
                        color: 'rgba(0, 212, 255, 0.06)',
                        drawBorder: false
                    },
                    ticks: {
                        stepSize: 1,
                        color: '#94a3b8',
                        font: { family: 'Inter, system-ui, sans-serif', size: 11 }
                    }
                }
            },
            plugins: {
                legend: {
                    position: 'top',
                    align: 'end',
                    labels: {
                        color: '#f8fafc',
                        font: { family: 'Inter, system-ui, sans-serif', size: 12 },
                        usePointStyle: true,
                        boxWidth: 8
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(15, 23, 42, 0.95)',
                    titleColor: '#00d4ff',
                    bodyColor: '#f8fafc',
                    borderColor: 'rgba(0, 212, 255, 0.3)',
                    borderWidth: 1,
                    padding: 10
                }
            }
        }
    });
}

/**
 * Generates empty baseline trend data for last 7 days if history is empty.
 * @returns {Array<Object>}
 */
function generateDefaultTrendData() {
    const list = [];
    for (let i = 6; i >= 0; i--) {
        const d = new Date();
        d.setDate(d.getDate() - i);
        list.push({
            date: d.toISOString().split('T')[0],
            total: 0,
            phishing: 0
        });
    }
    return list;
}

/**
 * Checks and updates the dashboard-level Ollama connection indicator card.
 */
async function checkAndShowOllamaStatus() {
    const statusBox = document.getElementById('dashboard-ollama-status');
    if (!statusBox) return;

    try {
        const res = await fetch('/api/ollama/status');
        const data = await res.json();

        if (data.connected) {
            statusBox.innerHTML = `
                <div class="flex items-center space-x-3">
                    <span class="status-dot status-online"></span>
                    <div>
                        <div class="text-sm font-semibold text-white">Ollama AI Engine Connected</div>
                        <div class="text-xs text-muted">Model: <span class="text-cyan font-mono">${escapeHtml(data.current_model || 'llama3.2')}</span> &bull; Local API Active</div>
                    </div>
                </div>
            `;
        } else {
            statusBox.innerHTML = `
                <div class="flex items-center space-x-3">
                    <span class="status-dot status-offline"></span>
                    <div>
                        <div class="text-sm font-semibold text-danger">Ollama Offline</div>
                        <div class="text-xs text-muted">${escapeHtml(data.error || 'Run `ollama serve` and pull llama3.2 to enable AI')}</div>
                    </div>
                </div>
            `;
        }
    } catch (e) {
        // Fallback UI
        statusBox.innerHTML = `
            <div class="flex items-center space-x-3">
                <span class="status-dot status-offline"></span>
                <div class="text-xs text-danger">Cannot connect to Ollama service</div>
            </div>
        `;
    }
}

// ============================================================================
// DASHBOARD LIFECYCLE INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', async () => {
    // Only execute if on dashboard view
    const isDashboard = document.getElementById('stat-total') || document.getElementById('riskDistributionChart');
    if (!isDashboard) return;

    // Load metrics and recent scans
    await loadDashboardStats();
    await loadRecentScans();
    await checkAndShowOllamaStatus();

    // Fetch analytics for Chart.js telemetry
    try {
        const res = await fetch('/api/analytics', { cache: 'no-cache' });
        if (res.ok) {
            const data = await res.json();
            renderRiskDistributionChart(data.category_distribution);
            renderDetectionTrendChart(data.daily_activity);
        } else {
            renderRiskDistributionChart({ low: 0, medium: 0, high: 0, critical: 0 });
            renderDetectionTrendChart([]);
        }
    } catch (err) {
        console.error('Failed to load dashboard chart telemetry:', err);
        renderRiskDistributionChart({ low: 0, medium: 0, high: 0, critical: 0 });
        renderDetectionTrendChart([]);
    }
});
