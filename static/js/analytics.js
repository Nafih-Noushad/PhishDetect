/**
 * PhishDetect AI - Analytics & Telemetry Controller
 * static/js/analytics.js
 *
 * Orchestrates analytics telemetry, KPI performance metrics, Chart.js visualizations
 * (daily activity bars, risk distribution doughnut, weekly trend spline, horizontal indicators),
 * and the heuristic rule indicator prevalence table.
 */

// Global Chart instances to allow clean re-render / destruction
let dailyActivityChartInstance = null;
let analyticsDistChartInstance = null;
let weeklyTrendChartInstance = null;
let indicatorsChartInstance = null;

/**
 * Main analytics loader. Fetches consolidated analytics telemetry.
 */
async function loadAnalytics() {
    try {
        const res = await fetch('/api/analytics', { cache: 'no-cache' });
        if (!res.ok) throw new Error(`HTTP error ${res.status}`);
        const data = await res.json();

        // 1. Update KPI overview cards
        if (data.kpis) {
            updateKPIs(data.kpis);
        }

        // 2. Render all telemetry charts
        renderDailyActivityChart(data.daily_activity || []);
        renderRiskDistributionChart(data.category_distribution || { low: 0, medium: 0, high: 0, critical: 0 });
        renderWeeklyTrendChart(data.weekly_trend || []);
        renderIndicatorsChart(data.top_indicators || []);

        // 3. Render indicator distribution breakdown table
        renderIndicatorsTable(data.top_indicators || []);

    } catch (err) {
        console.error('Failed to load analytics dashboard:', err);
        if (typeof showToast === 'function') {
            showToast('Failed to load analytics telemetry: ' + err.message, 'error');
        }
    }
}

/**
 * Updates KPI indicator counters with smooth animated transitions.
 * @param {Object} kpis - { total_scans, phishing_rate, safe_rate, critical_count }
 */
function updateKPIs(kpis) {
    const totalEl = document.getElementById('stat-total-analyzed');
    const phishingRateEl = document.getElementById('stat-phishing-rate');
    const safeRateEl = document.getElementById('stat-safe-rate');
    const criticalEl = document.getElementById('stat-critical-count');

    if (totalEl) animateNumericCounter(totalEl, kpis.total_scans || 0, '');
    if (phishingRateEl) animateNumericCounter(phishingRateEl, kpis.phishing_rate || 0, '%');
    if (safeRateEl) animateNumericCounter(safeRateEl, kpis.safe_rate || 0, '%');
    if (criticalEl) animateNumericCounter(criticalEl, kpis.critical_count || 0, '');
}

/**
 * Helper to animate numeric counters with optional suffix (e.g. '%').
 */
function animateNumericCounter(element, target, suffix = '', duration = 1000) {
    if (!element) return;
    const finalVal = parseFloat(target) || 0;
    const isFloat = finalVal % 1 !== 0;
    const startTime = performance.now();

    function update(now) {
        const elapsed = now - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const easeOut = 1 - Math.pow(1 - progress, 3);
        const current = easeOut * finalVal;

        element.textContent = (isFloat ? current.toFixed(1) : Math.floor(current)) + suffix;

        if (progress < 1) {
            requestAnimationFrame(update);
        } else {
            element.textContent = (isFloat ? finalVal.toFixed(1) : finalVal) + suffix;
        }
    }

    requestAnimationFrame(update);
}

/**
 * Renders the daily scan volume grouped bar chart.
 * @param {Array<Object>} dailyData - [{ date, total, phishing }]
 */
function renderDailyActivityChart(dailyData) {
    const canvas = document.getElementById('dailyActivityChart');
    if (!canvas || !window.Chart) return;

    if (dailyActivityChartInstance) {
        dailyActivityChartInstance.destroy();
    }

    const items = Array.isArray(dailyData) && dailyData.length > 0
        ? dailyData
        : generateFallbackDays(7);

    const labels = items.map(d => {
        try {
            const dt = new Date(d.date);
            return dt.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
        } catch (e) {
            return d.date || 'Day';
        }
    });

    const totals = items.map(d => d.total || 0);
    const phishing = items.map(d => d.phishing || 0);

    const ctx = canvas.getContext('2d');
    dailyActivityChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Total Scans',
                    data: totals,
                    backgroundColor: 'rgba(0, 212, 255, 0.75)',
                    borderColor: '#00d4ff',
                    borderWidth: 1,
                    borderRadius: 4,
                    barPercentage: 0.6,
                    categoryPercentage: 0.7
                },
                {
                    label: 'Phishing Identified',
                    data: phishing,
                    backgroundColor: 'rgba(239, 68, 68, 0.75)',
                    borderColor: '#ef4444',
                    borderWidth: 1,
                    borderRadius: 4,
                    barPercentage: 0.6,
                    categoryPercentage: 0.7
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    grid: { color: 'rgba(0, 212, 255, 0.05)', drawBorder: false },
                    ticks: { color: '#94a3b8', font: { family: 'Inter, system-ui', size: 11 } }
                },
                y: {
                    beginAtZero: true,
                    suggestedMax: 5,
                    grid: { color: 'rgba(0, 212, 255, 0.05)', drawBorder: false },
                    ticks: { stepSize: 1, color: '#94a3b8', font: { family: 'Inter, system-ui', size: 11 } }
                }
            },
            plugins: {
                legend: {
                    position: 'top',
                    labels: { color: '#f8fafc', font: { size: 11 }, usePointStyle: true }
                },
                tooltip: {
                    backgroundColor: 'rgba(15, 23, 42, 0.95)',
                    titleColor: '#00d4ff',
                    bodyColor: '#f8fafc',
                    borderColor: 'rgba(0, 212, 255, 0.3)',
                    borderWidth: 1
                }
            }
        }
    });
}

/**
 * Renders the overall Risk Category distribution doughnut.
 * @param {Object} distData - { low, medium, high, critical }
 */
function renderRiskDistributionChart(distData) {
    const canvas = document.getElementById('riskDistributionChart');
    if (!canvas || !window.Chart) return;

    if (analyticsDistChartInstance) {
        analyticsDistChartInstance.destroy();
    }

    const dist = distData || { low: 0, medium: 0, high: 0, critical: 0 };
    const values = [dist.low || 0, dist.medium || 0, dist.high || 0, dist.critical || 0];
    const hasData = values.some(v => v > 0);

    const displayValues = hasData ? values : [1, 0, 0, 0];
    const displayColors = hasData
        ? ['#10b981', '#f59e0b', '#ef4444', '#8b5cf6']
        : ['rgba(148, 163, 184, 0.2)', 'transparent', 'transparent', 'transparent'];

    const ctx = canvas.getContext('2d');
    analyticsDistChartInstance = new Chart(ctx, {
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
            cutout: '70%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#f8fafc',
                        padding: 14,
                        font: { family: 'Inter, system-ui', size: 11 },
                        usePointStyle: true
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(15, 23, 42, 0.95)',
                    titleColor: '#00d4ff',
                    bodyColor: '#f8fafc',
                    borderColor: 'rgba(0, 212, 255, 0.3)',
                    borderWidth: 1
                }
            }
        }
    });
}

/**
 * Renders weekly trend spline area chart.
 * @param {Array<Object>} weeklyData - [{ week, total, phishing }]
 */
function renderWeeklyTrendChart(weeklyData) {
    const canvas = document.getElementById('weeklyTrendChart');
    if (!canvas || !window.Chart) return;

    if (weeklyTrendChartInstance) {
        weeklyTrendChartInstance.destroy();
    }

    const items = Array.isArray(weeklyData) && weeklyData.length > 0
        ? weeklyData
        : [
            { week: 'Week 1', total: 0, phishing: 0 },
            { week: 'Week 2', total: 0, phishing: 0 },
            { week: 'Week 3', total: 0, phishing: 0 },
            { week: 'Week 4', total: 0, phishing: 0 }
        ];

    const labels = items.map(w => w.week || 'Week');
    const totals = items.map(w => w.total || 0);
    const phishing = items.map(w => w.phishing || 0);

    const ctx = canvas.getContext('2d');

    const gradient = ctx.createLinearGradient(0, 0, 0, 280);
    gradient.addColorStop(0, 'rgba(139, 92, 246, 0.30)');
    gradient.addColorStop(1, 'rgba(139, 92, 246, 0.00)');

    weeklyTrendChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Total Scans',
                    data: totals,
                    borderColor: '#00d4ff',
                    backgroundColor: 'transparent',
                    borderWidth: 2,
                    tension: 0.4,
                    pointBackgroundColor: '#00d4ff',
                    pointRadius: 4
                },
                {
                    label: 'Phishing Identified',
                    data: phishing,
                    borderColor: '#8b5cf6',
                    backgroundColor: gradient,
                    fill: true,
                    borderWidth: 2,
                    tension: 0.4,
                    pointBackgroundColor: '#8b5cf6',
                    pointRadius: 4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    grid: { color: 'rgba(0, 212, 255, 0.05)', drawBorder: false },
                    ticks: { color: '#94a3b8', font: { family: 'Inter, system-ui', size: 11 } }
                },
                y: {
                    beginAtZero: true,
                    suggestedMax: 5,
                    grid: { color: 'rgba(0, 212, 255, 0.05)', drawBorder: false },
                    ticks: { stepSize: 1, color: '#94a3b8', font: { family: 'Inter, system-ui', size: 11 } }
                }
            },
            plugins: {
                legend: {
                    position: 'top',
                    labels: { color: '#f8fafc', font: { size: 11 }, usePointStyle: true }
                },
                tooltip: {
                    backgroundColor: 'rgba(15, 23, 42, 0.95)',
                    titleColor: '#00d4ff',
                    bodyColor: '#f8fafc',
                    borderColor: 'rgba(0, 212, 255, 0.3)',
                    borderWidth: 1
                }
            }
        }
    });
}

/**
 * Renders horizontal ranking bar chart of most common indicators.
 * @param {Array<Object>} indicators - [{ type, count, label }]
 */
function renderIndicatorsChart(indicators) {
    const canvas = document.getElementById('indicatorsChart');
    if (!canvas || !window.Chart) return;

    if (indicatorsChartInstance) {
        indicatorsChartInstance.destroy();
    }

    // Sort descending by occurrence count
    const sorted = [...(indicators || [])].sort((a, b) => (b.count || 0) - (a.count || 0)).slice(0, 8);

    const labels = sorted.map(i => i.label || i.type || 'Indicator');
    const counts = sorted.map(i => i.count || 0);

    const ctx = canvas.getContext('2d');
    indicatorsChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels.length > 0 ? labels : ['No indicators yet'],
            datasets: [{
                label: 'Occurrences',
                data: counts.length > 0 ? counts : [0],
                backgroundColor: 'rgba(0, 212, 255, 0.7)',
                borderColor: '#00d4ff',
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    beginAtZero: true,
                    grid: { color: 'rgba(0, 212, 255, 0.05)', drawBorder: false },
                    ticks: { stepSize: 1, color: '#94a3b8', font: { family: 'Inter, system-ui', size: 11 } }
                },
                y: {
                    grid: { display: false },
                    ticks: { color: '#f8fafc', font: { family: 'Inter, system-ui', size: 11 } }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(15, 23, 42, 0.95)',
                    titleColor: '#00d4ff',
                    bodyColor: '#f8fafc',
                    borderColor: 'rgba(0, 212, 255, 0.3)',
                    borderWidth: 1
                }
            }
        }
    });
}

/**
 * Renders the tabular breakdown of top heuristic indicators.
 * @param {Array<Object>} indicators - [{ type, count, label }]
 */
function renderIndicatorsTable(indicators) {
    const tableEl = document.getElementById('indicators-table');
    if (!tableEl) return;

    const tbody = tableEl.querySelector('tbody') || tableEl;
    const sorted = [...(indicators || [])].sort((a, b) => (b.count || 0) - (a.count || 0));

    if (sorted.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="4" class="text-center py-6 text-muted">
                    No indicator findings recorded yet.
                </td>
            </tr>
        `;
        return;
    }

    const totalFindings = sorted.reduce((sum, item) => sum + (item.count || 0), 0);

    tbody.innerHTML = sorted.map((ind, idx) => {
        const count = ind.count || 0;
        const pct = totalFindings > 0 ? ((count / totalFindings) * 100).toFixed(1) : '0.0';
        const label = ind.label || ind.type || 'Indicator';
        const typeCode = ind.type || 'RULE';

        return `
            <tr class="animate-in" style="animation-delay: ${idx * 40}ms">
                <td class="font-mono text-xs text-cyan">${escapeHtml(typeCode)}</td>
                <td class="text-sm font-medium text-white">${escapeHtml(label)}</td>
                <td class="text-center font-mono font-bold">${count}</td>
                <td class="text-right">
                    <div class="flex items-center justify-end space-x-2">
                        <span class="text-xs text-muted font-mono">${pct}%</span>
                        <div class="w-16 bg-slate-800 h-1.5 rounded-full overflow-hidden">
                            <div class="bg-cyan h-full rounded-full" style="width: ${pct}%"></div>
                        </div>
                    </div>
                </td>
            </tr>
        `;
    }).join('');
}

/**
 * Generates dummy dates for chart baselines when history is empty.
 */
function generateFallbackDays(daysCount) {
    const list = [];
    for (let i = daysCount - 1; i >= 0; i--) {
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

// ============================================================================
// INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    // Only initialize if analytics elements exist on the page
    if (document.getElementById('stat-total-analyzed') || document.getElementById('dailyActivityChart')) {
        loadAnalytics();
    }
});
