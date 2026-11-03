/**
 * PhishDetect AI - Global Application Utilities
 * static/js/main.js
 *
 * Core global functionality across all application views:
 * - Toast notification system
 * - Responsive sidebar navigation controller
 * - Ollama local AI connection status monitor
 * - Risk badges, colors, date and text formatters
 * - Modal confirmations and clipboard utilities
 * - History and Settings page controllers
 */

// ============================================================================
// 1. TOAST NOTIFICATIONS
// ============================================================================

/**
 * Displays a toast notification in the UI.
 * @param {string} message - Notification text
 * @param {'info'|'success'|'warning'|'error'} type - Notification style type
 * @param {number} duration - Auto-dismiss timeout in milliseconds (default: 4000ms)
 */
function showToast(message, type = 'info', duration = 4000) {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'toast-container';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast toast-${type} animate-in`;

    // Map types to descriptive icon classes / SVGs
    let iconSvg = '';
    switch (type) {
        case 'success':
            iconSvg = `<svg class="toast-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>`;
            break;
        case 'warning':
            iconSvg = `<svg class="toast-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`;
            break;
        case 'error':
            iconSvg = `<svg class="toast-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>`;
            break;
        case 'info':
        default:
            iconSvg = `<svg class="toast-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>`;
            break;
    }

    toast.innerHTML = `
        <div class="toast-content">
            <span class="toast-icon-wrap">${iconSvg}</span>
            <span class="toast-message">${escapeHtml(message)}</span>
        </div>
        <button type="button" class="toast-close" aria-label="Close notification">&times;</button>
    `;

    const closeBtn = toast.querySelector('.toast-close');
    const removeToast = () => {
        toast.classList.add('toast-fade-out');
        setTimeout(() => {
            if (toast.parentElement) {
                toast.parentElement.removeChild(toast);
            }
        }, 300);
    };

    closeBtn.addEventListener('click', removeToast);

    container.appendChild(toast);

    if (duration > 0) {
        setTimeout(removeToast, duration);
    }
}

// ============================================================================
// 2. SIDEBAR TOGGLE & NAVIGATION
// ============================================================================

/**
 * Initializes sidebar persistence, mobile overlay behavior, and toggle event handlers.
 */
function initSidebar() {
    const sidebar = document.getElementById('sidebar');
    const sidebarToggle = document.getElementById('sidebar-toggle');
    const mainContent = document.getElementById('main-content');

    if (!sidebar) return;

    // Restore desktop collapsed preference from localStorage
    const savedState = localStorage.getItem('phishdetect_sidebar_collapsed');
    if (savedState === 'true' && window.innerWidth > 768) {
        sidebar.classList.add('collapsed');
        if (mainContent) mainContent.classList.add('sidebar-expanded');
    }

    if (sidebarToggle) {
        sidebarToggle.addEventListener('click', (e) => {
            e.stopPropagation();
            if (window.innerWidth <= 768) {
                // Mobile overlay toggle
                sidebar.classList.toggle('mobile-open');
                let backdrop = document.getElementById('sidebar-backdrop');
                if (!backdrop) {
                    backdrop = document.createElement('div');
                    backdrop.id = 'sidebar-backdrop';
                    backdrop.className = 'sidebar-backdrop';
                    document.body.appendChild(backdrop);
                    backdrop.addEventListener('click', () => {
                        sidebar.classList.remove('mobile-open');
                        backdrop.classList.remove('active');
                    });
                }
                backdrop.classList.toggle('active', sidebar.classList.contains('mobile-open'));
            } else {
                // Desktop toggle
                const isCollapsed = sidebar.classList.toggle('collapsed');
                if (mainContent) {
                    mainContent.classList.toggle('sidebar-expanded', isCollapsed);
                }
                localStorage.setItem('phishdetect_sidebar_collapsed', isCollapsed ? 'true' : 'false');
            }
        });
    }

    // Close mobile sidebar on window resize beyond breakpoint
    window.addEventListener('resize', () => {
        if (window.innerWidth > 768) {
            sidebar.classList.remove('mobile-open');
            const backdrop = document.getElementById('sidebar-backdrop');
            if (backdrop) backdrop.classList.remove('active');
        }
    });
}

// ============================================================================
// 3. OLLAMA STATUS CHECK
// ============================================================================

/**
 * Polls the Ollama API status endpoint and updates the status indicator in the UI.
 * @returns {Promise<Object>} Status response object
 */
async function checkOllamaStatus() {
    const statusDot = document.getElementById('status-dot');
    const statusText = document.getElementById('status-text');
    const statusMini = document.getElementById('ollama-status-mini');

    try {
        const response = await fetch('/api/ollama/status', {
            headers: { 'Accept': 'application/json' },
            cache: 'no-cache'
        });

        if (!response.ok) {
            throw new Error(`HTTP error ${response.status}`);
        }

        const data = await response.json();

        if (data.connected) {
            if (statusDot) {
                statusDot.className = 'status-dot status-online';
            }
            if (statusText) {
                statusText.textContent = data.current_model ? `Online (${data.current_model})` : 'Connected';
            }
            if (statusMini) {
                statusMini.title = `Ollama Online - Model: ${data.current_model || 'llama3.2'}`;
                statusMini.classList.add('online');
                statusMini.classList.remove('offline');
            }
        } else {
            if (statusDot) {
                statusDot.className = 'status-dot status-offline';
            }
            if (statusText) {
                statusText.textContent = 'Offline';
            }
            if (statusMini) {
                statusMini.title = data.error || 'Ollama Offline';
                statusMini.classList.add('offline');
                statusMini.classList.remove('online');
            }
        }
        return data;
    } catch (err) {
        if (statusDot) {
            statusDot.className = 'status-dot status-offline';
        }
        if (statusText) {
            statusText.textContent = 'Offline';
        }
        if (statusMini) {
            statusMini.title = 'Cannot reach Ollama server';
            statusMini.classList.add('offline');
            statusMini.classList.remove('online');
        }
        return { connected: false, error: err.message };
    }
}

// ============================================================================
// 4. RISK BADGE HELPER
// ============================================================================

/**
 * Generates an HTML badge string with appropriate severity styling.
 * @param {string} category - Risk category ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
 * @returns {string} HTML string for the styled badge
 */
function getRiskBadge(category) {
    if (!category) return '<span class="badge badge-low">UNKNOWN</span>';
    const catUpper = String(category).toUpperCase();
    const catClass = catUpper.toLowerCase();
    return `<span class="badge badge-${catClass}">${catUpper}</span>`;
}

// ============================================================================
// 5. RISK COLOR HELPER
// ============================================================================

/**
 * Returns a hex CSS color corresponding to the given risk category.
 * @param {string} category - Risk category
 * @returns {string} Hex color code
 */
function getRiskColor(category) {
    if (!category) return '#64748b';
    switch (String(category).toUpperCase()) {
        case 'LOW':
            return '#10b981'; // Emerald Green
        case 'MEDIUM':
            return '#f59e0b'; // Amber Orange
        case 'HIGH':
            return '#ef4444'; // Bright Red
        case 'CRITICAL':
            return '#8b5cf6'; // Electric Purple
        default:
            return '#64748b'; // Slate Gray
    }
}

// ============================================================================
// 6. FORMAT DATE
// ============================================================================

/**
 * Formats an ISO date string or timestamp into 'Nov 03, 2026 10:15 AM' format.
 * @param {string|number|Date} isoString - Date representation
 * @returns {string} Human-readable formatted date string
 */
function formatDate(isoString) {
    if (!isoString) return '—';
    try {
        const date = new Date(isoString);
        if (isNaN(date.getTime())) return String(isoString);

        const options = {
            month: 'short',
            day: '2-digit',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            hour12: true
        };
        return new Intl.DateTimeFormat('en-US', options).format(date);
    } catch (e) {
        return String(isoString);
    }
}

// ============================================================================
// 7. TRUNCATE TEXT
// ============================================================================

/**
 * Truncates text to a specified maximum length, appending an ellipsis if truncated.
 * @param {string} text - Input text
 * @param {number} maxLength - Maximum allowable characters
 * @returns {string} Truncated string
 */
function truncateText(text, maxLength = 30) {
    if (!text) return '';
    const str = String(text).trim();
    if (str.length <= maxLength) return str;
    return str.substring(0, maxLength) + '...';
}

/**
 * Helper to safely escape HTML entities.
 * @param {string} str - Raw string
 * @returns {string} Escaped HTML string
 */
function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// ============================================================================
// 8. CONFIRM DIALOG
// ============================================================================

/**
 * Asynchronous confirmation dialog wrapper.
 * @param {string} message - Confirmation prompt text
 * @returns {Promise<boolean>} Resolves true if confirmed, false otherwise
 */
async function confirmAction(message) {
    return Promise.resolve(window.confirm(message));
}

// ============================================================================
// 9. COPY TO CLIPBOARD
// ============================================================================

/**
 * Copies text to the user's system clipboard and alerts with a toast.
 * @param {string} text - Text to copy
 * @returns {Promise<boolean>} True on success
 */
async function copyToClipboard(text) {
    if (!text) {
        showToast('Nothing to copy', 'warning');
        return false;
    }

    try {
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(text);
            showToast('Copied to clipboard!', 'success');
            return true;
        } else {
            // Fallback for non-secure contexts or legacy browsers
            const textArea = document.createElement('textarea');
            textArea.value = text;
            textArea.style.position = 'fixed';
            textArea.style.left = '-999999px';
            textArea.style.top = '-999999px';
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            const successful = document.execCommand('copy');
            document.body.removeChild(textArea);
            if (successful) {
                showToast('Copied to clipboard!', 'success');
                return true;
            } else {
                throw new Error('execCommand returned false');
            }
        }
    } catch (err) {
        console.error('Clipboard copy failed:', err);
        showToast('Failed to copy to clipboard', 'error');
        return false;
    }
}

// ============================================================================
// 10. ANIMATE ELEMENTS IN
// ============================================================================

/**
 * Staggers entrance animation on all `.card` elements for high polish.
 */
function animateIn() {
    const cards = document.querySelectorAll('.card');
    cards.forEach((card, index) => {
        card.classList.add('animate-in');
        card.style.animationDelay = `${index * 60}ms`;
    });
}

// ============================================================================
// 11. HISTORY PAGE CONTROLLER
// ============================================================================

let currentHistoryPage = 1;

/**
 * Loads paginated, filtered scan history records from the server.
 * @param {number} page - Page number (1-indexed)
 */
async function loadHistory(page = 1) {
    currentHistoryPage = page;
    const tableBody = document.getElementById('history-table-body');
    const emptyState = document.getElementById('empty-state');
    const paginationContainer = document.getElementById('pagination-container');

    if (!tableBody) return;

    const searchInput = document.getElementById('search-input');
    const categoryFilter = document.getElementById('category-filter');
    const sortSelect = document.getElementById('sort-select');

    const search = searchInput ? searchInput.value.trim() : '';
    const category = categoryFilter ? categoryFilter.value : '';

    let sortBy = 'scan_timestamp';
    let sortDir = 'desc';
    if (sortSelect && sortSelect.value) {
        const parts = sortSelect.value.split(':');
        if (parts.length === 2) {
            sortBy = parts[0];
            sortDir = parts[1];
        } else {
            sortBy = sortSelect.value;
        }
    }

    const queryParams = new URLSearchParams({
        page: page.toString(),
        per_page: '10',
        search: search,
        category: category,
        sort_by: sortBy,
        sort_dir: sortDir
    });

    try {
        tableBody.innerHTML = `
            <tr>
                <td colspan="8" class="text-center py-6 text-muted">
                    <div class="spinner inline-spinner mb-2"></div>
                    <div>Loading scan records...</div>
                </td>
            </tr>
        `;

        const response = await fetch(`/api/history?${queryParams.toString()}`);
        if (!response.ok) throw new Error(`HTTP error ${response.status}`);

        const data = await response.json();
        const scans = data.scans || [];
        const total = data.total || 0;
        const totalPages = data.pages || Math.ceil(total / 10) || 1;

        if (scans.length === 0) {
            tableBody.innerHTML = '';
            if (emptyState) emptyState.style.display = 'block';
            if (paginationContainer) paginationContainer.innerHTML = '';
            return;
        }

        if (emptyState) emptyState.style.display = 'none';

        tableBody.innerHTML = scans.map((scan, idx) => {
            const rowNumber = (page - 1) * 10 + idx + 1;
            const formattedDate = formatDate(scan.scan_timestamp);
            const senderShort = truncateText(scan.sender || 'Unknown', 28);
            const subjectShort = truncateText(scan.subject || '(No Subject)', 36);
            const categoryBadge = getRiskBadge(scan.risk_category);
            const scoreClass = (scan.risk_category || 'low').toLowerCase();

            return `
                <tr class="history-row animate-in" style="animation-delay: ${idx * 40}ms">
                    <td class="font-mono text-muted text-center">${rowNumber}</td>
                    <td class="whitespace-nowrap text-sm text-secondary">${formattedDate}</td>
                    <td class="font-medium" title="${escapeHtml(scan.sender || '')}">
                        <div class="truncate-cell">${escapeHtml(senderShort)}</div>
                    </td>
                    <td title="${escapeHtml(scan.subject || '')}">
                        <div class="truncate-cell text-primary">${escapeHtml(subjectShort)}</div>
                    </td>
                    <td class="text-center">
                        <span class="badge badge-${scoreClass} font-mono">${scan.risk_score !== undefined ? scan.risk_score : '—'}/100</span>
                    </td>
                    <td class="text-center">${categoryBadge}</td>
                    <td class="text-center">
                        <span class="verdict-tag verdict-${(scan.ai_verdict || 'unknown').toLowerCase()}">${escapeHtml(scan.ai_verdict || 'N/A')}</span>
                    </td>
                    <td class="text-right whitespace-nowrap actions-cell">
                        <a href="/results/${scan.scan_id}" class="btn btn-secondary btn-sm" title="View Detailed Report">
                            <i data-lucide="eye"></i> View
                        </a>
                        <button type="button" class="btn btn-danger btn-sm ml-2" onclick="deleteHistoryScan('${scan.scan_id}')" title="Delete scan">
                            <i data-lucide="trash-2"></i> Delete
                        </button>
                    </td>
                </tr>
            `;
        }).join('');

        if (paginationContainer) {
            renderPagination(page, totalPages, (targetPage) => loadHistory(targetPage));
        }

        if (window.lucide && typeof window.lucide.createIcons === 'function') {
            window.lucide.createIcons();
        }
    } catch (err) {
        console.error('Failed to load history:', err);
        tableBody.innerHTML = `
            <tr>
                <td colspan="8" class="text-center py-6 text-danger">
                    Failed to load scan records: ${escapeHtml(err.message)}
                </td>
            </tr>
        `;
        showToast('Error loading scan history', 'error');
    }
}

/**
 * Deletes a single scan by scan_id with confirmation.
 * @param {string} scanId - UUID of the scan
 */
async function deleteHistoryScan(scanId) {
    if (!scanId) return;

    const confirmed = await confirmAction('Are you sure you want to permanently delete this scan record?');
    if (!confirmed) return;

    try {
        const response = await fetch(`/api/history/${scanId}`, {
            method: 'DELETE',
            headers: { 'Accept': 'application/json' }
        });
        const data = await response.json();

        if (response.ok && data.success) {
            showToast('Scan record deleted successfully', 'success');
            loadHistory(currentHistoryPage);
        } else {
            showToast(data.message || 'Failed to delete scan record', 'error');
        }
    } catch (err) {
        console.error('Delete error:', err);
        showToast('Network error while deleting scan', 'error');
    }
}

/**
 * Clears the entire scan history with confirmation.
 */
async function clearAllHistory() {
    const confirmed = await confirmAction(
        'WARNING: This will permanently delete ALL email scan records and associated findings. This action cannot be undone. Proceed?'
    );
    if (!confirmed) return;

    try {
        const response = await fetch('/api/history', {
            method: 'DELETE',
            headers: { 'Accept': 'application/json' }
        });
        const data = await response.json();

        if (response.ok && data.success) {
            showToast(`History cleared. ${data.deleted || 0} scans deleted.`, 'success');
            loadHistory(1);
        } else {
            showToast(data.message || 'Failed to clear history', 'error');
        }
    } catch (err) {
        console.error('Clear history error:', err);
        showToast('Network error while clearing history', 'error');
    }
}

/**
 * Builds responsive pagination controls.
 * @param {number} currentPage - Currently active page
 * @param {number} totalPages - Total available pages
 * @param {Function} onPageChange - Callback when a page button is clicked
 */
function renderPagination(currentPage, totalPages, onPageChange) {
    const container = document.getElementById('pagination-container');
    if (!container) return;

    if (totalPages <= 1) {
        container.innerHTML = '';
        return;
    }

    let html = '<div class="pagination flex items-center justify-center space-x-1">';

    // Previous Button
    const prevDisabled = currentPage <= 1 ? 'disabled' : '';
    html += `
        <button type="button" class="btn btn-secondary btn-sm pagination-prev ${prevDisabled}" 
            ${currentPage <= 1 ? 'disabled' : ''} data-page="${currentPage - 1}">
            &laquo; Prev
        </button>
    `;

    // Page window calculation
    let startPage = Math.max(1, currentPage - 2);
    let endPage = Math.min(totalPages, currentPage + 2);

    if (startPage > 1) {
        html += `<button type="button" class="btn btn-secondary btn-sm pagination-num" data-page="1">1</button>`;
        if (startPage > 2) {
            html += `<span class="pagination-ellipsis px-2 text-muted">...</span>`;
        }
    }

    for (let p = startPage; p <= endPage; p++) {
        const activeClass = p === currentPage ? 'btn-primary active' : 'btn-secondary';
        html += `<button type="button" class="btn ${activeClass} btn-sm pagination-num" data-page="${p}">${p}</button>`;
    }

    if (endPage < totalPages) {
        if (endPage < totalPages - 1) {
            html += `<span class="pagination-ellipsis px-2 text-muted">...</span>`;
        }
        html += `<button type="button" class="btn btn-secondary btn-sm pagination-num" data-page="${totalPages}">${totalPages}</button>`;
    }

    // Next Button
    const nextDisabled = currentPage >= totalPages ? 'disabled' : '';
    html += `
        <button type="button" class="btn btn-secondary btn-sm pagination-next ${nextDisabled}" 
            ${currentPage >= totalPages ? 'disabled' : ''} data-page="${currentPage + 1}">
            Next &raquo;
        </button>
    `;

    html += '</div>';
    container.innerHTML = html;

    // Attach click listeners to pagination buttons
    const buttons = container.querySelectorAll('button[data-page]');
    buttons.forEach(btn => {
        btn.addEventListener('click', () => {
            const pageTarget = parseInt(btn.getAttribute('data-page'), 10);
            if (!isNaN(pageTarget) && pageTarget >= 1 && pageTarget <= totalPages && pageTarget !== currentPage) {
                onPageChange(pageTarget);
            }
        });
    });
}

// ============================================================================
// 12. SETTINGS PAGE CONTROLLER
// ============================================================================

/**
 * Loads application and Ollama configuration into settings inputs.
 */
async function loadSettings() {
    const urlInput = document.getElementById('ollama-url-input');
    const currentModelEl = document.getElementById('current-model');
    const dbPathEl = document.getElementById('db-path');
    const appVersionEl = document.getElementById('app-version');
    const totalScansEl = document.getElementById('total-scans');

    try {
        const res = await fetch('/api/settings');
        if (!res.ok) throw new Error(`HTTP error ${res.status}`);
        const data = await res.json();

        if (urlInput && data.ollama_url) {
            urlInput.value = data.ollama_url;
        }
        if (currentModelEl && data.ollama_model) {
            currentModelEl.textContent = data.ollama_model;
        }
        if (dbPathEl && data.db_path) {
            dbPathEl.textContent = data.db_path;
        }
        if (appVersionEl && data.app_version) {
            appVersionEl.textContent = data.app_version;
        }
        if (totalScansEl && data.total_scans !== undefined) {
            totalScansEl.textContent = data.total_scans;
        }
    } catch (err) {
        console.error('Failed to load settings:', err);
        showToast('Failed to load application settings', 'error');
    }
}

/**
 * Fetches available Ollama models and populates the model select dropdown.
 */
async function loadModels() {
    const modelSelect = document.getElementById('model-select');
    if (!modelSelect) return;

    try {
        const res = await fetch('/api/ollama/models');
        if (!res.ok) throw new Error(`HTTP error ${res.status}`);
        const data = await res.json();
        const models = data.models || [];

        modelSelect.innerHTML = '';

        if (models.length === 0) {
            const opt = document.createElement('option');
            opt.value = 'llama3.2';
            opt.textContent = 'llama3.2 (Default)';
            modelSelect.appendChild(opt);
        } else {
            models.forEach(modelName => {
                const opt = document.createElement('option');
                opt.value = modelName;
                opt.textContent = modelName;
                modelSelect.appendChild(opt);
            });
        }

        // Check if there's a current model from settings to select
        const currentModelEl = document.getElementById('current-model');
        if (currentModelEl && currentModelEl.textContent) {
            modelSelect.value = currentModelEl.textContent.trim();
        }
    } catch (err) {
        console.error('Failed to load Ollama models:', err);
        const opt = document.createElement('option');
        opt.value = 'llama3.2';
        opt.textContent = 'llama3.2 (Fallback)';
        modelSelect.innerHTML = '';
        modelSelect.appendChild(opt);
    }
}

/**
 * Checks Ollama server status specifically for the settings page status panel.
 */
async function checkOllamaStatusSettings() {
    const connStatusEl = document.getElementById('ollama-conn-status');
    if (!connStatusEl) return;

    try {
        connStatusEl.innerHTML = `<span class="spinner inline-spinner mr-2"></span> Checking Ollama...`;
        const res = await fetch('/api/ollama/status');
        const data = await res.json();

        if (data.connected) {
            connStatusEl.innerHTML = `
                <span class="inline-flex items-center text-success font-medium">
                    <span class="status-dot status-online mr-2"></span> Connected
                </span>
                <span class="text-muted text-sm ml-2">(${data.current_model || 'llama3.2'})</span>
            `;
        } else {
            connStatusEl.innerHTML = `
                <span class="inline-flex items-center text-danger font-medium">
                    <span class="status-dot status-offline mr-2"></span> Offline
                </span>
                <span class="text-muted text-sm ml-2">${escapeHtml(data.error || 'Server unreachable')}</span>
            `;
        }
    } catch (err) {
        connStatusEl.innerHTML = `
            <span class="inline-flex items-center text-danger font-medium">
                <span class="status-dot status-offline mr-2"></span> Offline
            </span>
            <span class="text-muted text-sm ml-2">Cannot connect</span>
        `;
    }
}

/**
 * Tests connection to the Ollama endpoint and measures latency.
 */
async function testConnection() {
    const btn = document.getElementById('test-connection-btn');
    const resultEl = document.getElementById('test-result');
    const urlInput = document.getElementById('ollama-url-input');

    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<span class="spinner inline-spinner mr-2"></span> Testing...`;
    }

    if (resultEl) {
        resultEl.className = 'test-result-box mt-3 p-3 text-sm rounded bg-glass text-muted';
        resultEl.innerHTML = 'Sending handshake test request to Ollama...';
        resultEl.style.display = 'block';
    }

    try {
        const payload = urlInput && urlInput.value ? { url: urlInput.value.trim() } : {};
        const res = await fetch('/api/ollama/test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await res.json();

        if (res.ok && data.success) {
            if (resultEl) {
                resultEl.className = 'test-result-box mt-3 p-3 text-sm rounded bg-success-dim text-success border border-success';
                resultEl.innerHTML = `
                    <div class="font-medium flex items-center">
                        <span class="mr-2">✓</span> Connection Successful!
                    </div>
                    <div class="text-xs mt-1 text-muted">
                        ${escapeHtml(data.message || 'Connected to Ollama API')} &bull; Latency: <strong>${data.response_time_ms || 0} ms</strong>
                    </div>
                `;
            }
            showToast(`Ollama connected in ${data.response_time_ms || 0}ms`, 'success');
        } else {
            if (resultEl) {
                resultEl.className = 'test-result-box mt-3 p-3 text-sm rounded bg-danger-dim text-danger border border-danger';
                resultEl.innerHTML = `
                    <div class="font-medium flex items-center">
                        <span class="mr-2">✗</span> Connection Failed
                    </div>
                    <div class="text-xs mt-1">
                        ${escapeHtml(data.message || 'Could not connect to Ollama server')}
                    </div>
                `;
            }
            showToast('Ollama connection test failed', 'error');
        }
    } catch (err) {
        if (resultEl) {
            resultEl.className = 'test-result-box mt-3 p-3 text-sm rounded bg-danger-dim text-danger border border-danger';
            resultEl.innerHTML = `
                <div class="font-medium">Connection Test Error</div>
                <div class="text-xs mt-1">${escapeHtml(err.message)}</div>
            `;
        }
        showToast('Error testing Ollama connection', 'error');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<i data-lucide="zap"></i> Test Connection`;
            if (window.lucide && typeof window.lucide.createIcons === 'function') {
                window.lucide.createIcons();
            }
        }
        checkOllamaStatus();
        checkOllamaStatusSettings();
    }
}

/**
 * Saves modified application configuration to the backend.
 */
async function saveSettings() {
    const urlInput = document.getElementById('ollama-url-input');
    const modelSelect = document.getElementById('model-select');
    const saveBtn = document.getElementById('save-settings-btn');

    if (!urlInput || !modelSelect) return;

    const payload = {
        ollama_url: urlInput.value.trim(),
        ollama_model: modelSelect.value.trim()
    };

    if (saveBtn) {
        saveBtn.disabled = true;
        saveBtn.innerHTML = `<span class="spinner inline-spinner mr-2"></span> Saving...`;
    }

    try {
        const res = await fetch('/api/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await res.json();

        if (res.ok && data.success) {
            showToast('Settings saved successfully', 'success');
            const currentModelEl = document.getElementById('current-model');
            if (currentModelEl) currentModelEl.textContent = payload.ollama_model;
            checkOllamaStatus();
            checkOllamaStatusSettings();
        } else {
            showToast(data.message || 'Failed to save settings', 'error');
        }
    } catch (err) {
        console.error('Settings save error:', err);
        showToast('Network error saving settings', 'error');
    } finally {
        if (saveBtn) {
            saveBtn.disabled = false;
            saveBtn.innerHTML = `<i data-lucide="save"></i> Save Settings`;
            if (window.lucide && typeof window.lucide.createIcons === 'function') {
                window.lucide.createIcons();
            }
        }
    }
}

// Debounce helper for instant search input
function debounce(func, delay = 300) {
    let timer;
    return function (...args) {
        clearTimeout(timer);
        timer = setTimeout(() => func.apply(this, args), delay);
    };
}

// ============================================================================
// 13. DOM READY INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    // 1. Initialize Icons
    if (window.lucide && typeof window.lucide.createIcons === 'function') {
        window.lucide.createIcons();
    }

    // 2. Global UI components
    initSidebar();
    checkOllamaStatus();
    animateIn();

    // 3. Page detection and targeted initializers
    const path = window.location.pathname;

    // History Page setup
    const historyTableBody = document.getElementById('history-table-body');
    if (path.includes('/history') || historyTableBody) {
        loadHistory(1);

        const searchInput = document.getElementById('search-input');
        if (searchInput) {
            searchInput.addEventListener('input', debounce(() => loadHistory(1), 350));
        }

        const categoryFilter = document.getElementById('category-filter');
        if (categoryFilter) {
            categoryFilter.addEventListener('change', () => loadHistory(1));
        }

        const sortSelect = document.getElementById('sort-select');
        if (sortSelect) {
            sortSelect.addEventListener('change', () => loadHistory(1));
        }

        const clearAllBtn = document.getElementById('clear-all-btn');
        if (clearAllBtn) {
            clearAllBtn.addEventListener('click', clearAllHistory);
        }
    }

    // Settings Page setup
    const settingsForm = document.getElementById('ollama-url-input');
    if (path.includes('/settings') || settingsForm) {
        loadSettings();
        loadModels();
        checkOllamaStatusSettings();

        const testBtn = document.getElementById('test-connection-btn');
        if (testBtn) {
            testBtn.addEventListener('click', testConnection);
        }

        const saveBtn = document.getElementById('save-settings-btn');
        if (saveBtn) {
            saveBtn.addEventListener('click', saveSettings);
        }

        const clearHistoryBtn = document.getElementById('clear-history-btn');
        if (clearHistoryBtn) {
            clearHistoryBtn.addEventListener('click', clearAllHistory);
        }
    }

    // Export & Action Buttons on scan reports
    const exportJsonBtn = document.getElementById('export-json');
    if (exportJsonBtn) {
        exportJsonBtn.addEventListener('click', () => {
            const scanIdEl = document.getElementById('scan-id-data');
            const scanId = scanIdEl ? scanIdEl.dataset.scanId : '';
            if (scanId) {
                window.location.href = `/api/export/${scanId}?format=json`;
            } else {
                showToast('Scan ID not found for export', 'error');
            }
        });
    }

    const exportTxtBtn = document.getElementById('export-txt');
    if (exportTxtBtn) {
        exportTxtBtn.addEventListener('click', () => {
            const scanIdEl = document.getElementById('scan-id-data');
            const scanId = scanIdEl ? scanIdEl.dataset.scanId : '';
            if (scanId) {
                window.location.href = `/api/export/${scanId}?format=txt`;
            } else {
                showToast('Scan ID not found for export', 'error');
            }
        });
    }

    const copyReportBtn = document.getElementById('copy-report');
    if (copyReportBtn) {
        copyReportBtn.addEventListener('click', async () => {
            const scanIdEl = document.getElementById('scan-id-data');
            const scanId = scanIdEl ? scanIdEl.dataset.scanId : '';
            if (!scanId) {
                showToast('No scan ID found', 'error');
                return;
            }
            try {
                const res = await fetch(`/api/scan/${scanId}`);
                const data = await res.json();
                if (data.success && data.scan) {
                    const formattedJson = JSON.stringify(data.scan, null, 2);
                    await copyToClipboard(formattedJson);
                } else {
                    showToast('Could not fetch scan report for copying', 'error');
                }
            } catch (e) {
                showToast('Failed to copy report: ' + e.message, 'error');
            }
        });
    }
});
