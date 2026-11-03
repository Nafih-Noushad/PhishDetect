/**
 * PhishDetect AI - Email Analysis & Results Controller
 * static/js/analysis.js
 *
 * Handles client-side email inspection submission, animated step-by-step
 * heuristic + AI scanning pipeline, dynamic results rendering, SVG risk gauges,
 * rule indicator cards, and report exports.
 */

// ============================================================================
// SAMPLE DATASETS FOR QUICK DEMONSTRATION
// ============================================================================

const PHISHING_EXAMPLE = {
    sender: 'security-noreply@paypa1-verify.com',
    subject: 'URGENT: Your PayPal Account Has Been Suspended - Verify Now!',
    body: `Dear Valued Customer,

We have detected unusual activity on your PayPal account and have temporarily suspended it for your security.

ACTION REQUIRED: You must verify your account within 24 hours or it will be permanently closed.

Click here to verify your account immediately: http://bit.ly/paypal-verify-now

You will need to:
- Enter your PayPal email and password
- Confirm your credit card details
- Enter the OTP sent to your phone

If you do not verify within 24 hours, your account will be permanently suspended and all pending transactions will be cancelled.

Warning: Failure to act now will result in permanent account closure.

PayPal Security Team
Do not reply to this email`
};

const LEGIT_EXAMPLE = {
    sender: 'newsletter@github.com',
    subject: 'GitHub Actions: Your workflow completed successfully',
    body: `Hi there,

Your GitHub Actions workflow "CI/CD Pipeline" completed successfully.

Repository: myproject/webapp
Branch: main
Commit: a1b2c3d
Duration: 2m 34s
Status: Success ✓

All 47 tests passed.

View the full workflow run at: https://github.com/myproject/webapp/actions/runs/12345

You are receiving this because you have notifications enabled for this repository.
To manage your notification settings, visit https://github.com/settings/notifications

GitHub, Inc.`
};

// ============================================================================
// ANALYSIS PIPELINE CONTROLLER
// ============================================================================

let stepTimers = [];

/**
 * Validates form inputs and dispatches the email analysis request.
 */
async function analyzeEmail() {
    const senderInput = document.getElementById('sender-input');
    const subjectInput = document.getElementById('subject-input');
    const bodyInput = document.getElementById('body-input');
    const analyzeBtn = document.getElementById('analyze-btn');

    if (!senderInput || !subjectInput || !bodyInput) return;

    const sender = senderInput.value.trim();
    const subject = subjectInput.value.trim();
    const body = bodyInput.value.trim();

    // 1. Client-side validation
    if (!sender || !subject || !body) {
        showToast('Please fill in sender, subject, and email body fields', 'warning');
        return;
    }

    if (!sender.includes('@')) {
        showToast('Please provide a valid sender email address (e.g. name@domain.com)', 'warning');
        senderInput.focus();
        return;
    }

    if (body.length < 10) {
        showToast('Email body is too brief for meaningful phishing analysis', 'warning');
        bodyInput.focus();
        return;
    }

    // 2. Begin progress animation
    if (analyzeBtn) {
        analyzeBtn.disabled = true;
        analyzeBtn.innerHTML = `<span class="spinner inline-spinner mr-2"></span> Analyzing...`;
    }
    showLoadingWithSteps();

    // 3. Dispatch to API
    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({ sender, subject, body })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            // Smooth transition to results page
            setTimeout(() => {
                window.location.href = `/results/${data.scan_id}`;
            }, 600);
        } else {
            hideLoading();
            if (analyzeBtn) {
                analyzeBtn.disabled = false;
                analyzeBtn.innerHTML = `<i data-lucide="scan"></i> Inspect Email`;
                if (window.lucide) window.lucide.createIcons();
            }
            showToast(data.message || 'Analysis failed. Please check inputs and Ollama service.', 'error');
        }
    } catch (err) {
        console.error('Analysis request error:', err);
        hideLoading();
        if (analyzeBtn) {
            analyzeBtn.disabled = false;
            analyzeBtn.innerHTML = `<i data-lucide="scan"></i> Inspect Email`;
            if (window.lucide) window.lucide.createIcons();
        }
        showToast('Network error during analysis: ' + err.message, 'error');
    }
}

/**
 * Displays the full-screen loading overlay and schedules sequential stepper items.
 */
function showLoadingWithSteps() {
    const overlay = document.getElementById('loading-overlay');
    const loadingText = document.getElementById('loading-text');
    const stepsContainer = document.getElementById('loading-steps');
    const stepperWrapper = document.getElementById('analysis-stepper');
    const stepperFill = document.getElementById('stepper-progress-fill');
    const stepperPct = document.getElementById('stepper-percentage');
    const stepperStatus = document.getElementById('stepper-status-text');

    if (overlay) {
        overlay.style.display = 'flex';
        overlay.classList.add('animate-in');
    }

    if (stepperWrapper) {
        stepperWrapper.style.display = 'block';
    }

    const steps = [
        { label: 'Normalizing text and parsing headers...', time: 0, pct: 20, stepId: 'step-1' },
        { label: 'Inspecting 15+ heuristic phishing rules (URLs, urgency, credentials)...', time: 1000, pct: 45, stepId: 'step-2' },
        { label: 'Dispatching to Ollama Llama 3.2 for semantic threat reasoning...', time: 2000, pct: 75, stepId: 'step-3' },
        { label: 'Synthesizing hybrid risk score & generating explainable evidence report...', time: 3500, pct: 95, stepId: 'step-4' }
    ];

    if (stepsContainer) {
        stepsContainer.innerHTML = steps.map((s, idx) => `
            <div id="step-item-${idx}" class="loading-step-item text-sm py-1 flex items-center text-muted">
                <span class="step-indicator mr-2 font-mono">[ ]</span>
                <span class="step-text">${s.label}</span>
            </div>
        `).join('');
    }

    // Schedule active state highlights
    stepTimers.forEach(t => clearTimeout(t));
    stepTimers = [];

    steps.forEach((s, idx) => {
        const timer = setTimeout(() => {
            if (loadingText) loadingText.textContent = s.label;
            if (stepperStatus) stepperStatus.textContent = s.label;
            if (stepperPct) stepperPct.textContent = `${s.pct}%`;
            if (stepperFill) stepperFill.style.width = `${s.pct}%`;

            const stepNode = document.getElementById(s.stepId);
            if (stepNode) {
                stepNode.classList.add('active');
            }

            const item = document.getElementById(`step-item-${idx}`);
            if (item) {
                item.classList.remove('text-muted');
                item.classList.add('text-cyan', 'font-medium');
                const ind = item.querySelector('.step-indicator');
                if (ind) ind.innerHTML = `<span class="spinner inline-spinner-xs"></span>`;
            }

            // Mark prior step complete
            if (idx > 0) {
                const prev = document.getElementById(`step-item-${idx - 1}`);
                if (prev) {
                    prev.classList.remove('text-cyan');
                    prev.classList.add('text-success');
                    const ind = prev.querySelector('.step-indicator');
                    if (ind) ind.textContent = '[✓]';
                }
                const prevStepNode = document.getElementById(steps[idx - 1].stepId);
                if (prevStepNode) {
                    prevStepNode.classList.add('completed');
                }
            }
        }, s.time);
        stepTimers.push(timer);
    });
}

/**
 * Hides loading overlay and cleans up timers.
 */
function hideLoading() {
    const overlay = document.getElementById('loading-overlay');
    if (overlay) {
        overlay.style.display = 'none';
        overlay.classList.remove('animate-in');
    }
    const stepperWrapper = document.getElementById('analysis-stepper');
    if (stepperWrapper) {
        stepperWrapper.style.display = 'none';
    }
    stepTimers.forEach(t => clearTimeout(t));
    stepTimers = [];
}

/**
 * Updates the live character and word counter under the body textarea.
 */
function updateBodyCounter() {
    const bodyInput = document.getElementById('body-input');
    const counterEl = document.getElementById('body-counter');
    if (!bodyInput || !counterEl) return;

    const text = bodyInput.value;
    const charCount = text.length;
    const words = text.trim() ? text.trim().split(/\s+/).length : 0;
    counterEl.textContent = `${charCount.toLocaleString()} / 50,000 characters (${words.toLocaleString()} words)`;
}

// ============================================================================
// RESULTS PAGE RENDERER
// ============================================================================

/**
 * Loads scan data from `/api/scan/<id>` if on the results view.
 */
async function loadResultsPage() {
    const scanIdEl = document.getElementById('scan-id-data');
    if (!scanIdEl) return;

    const scanId = scanIdEl.dataset.scanId;
    if (!scanId) {
        showToast('No scan ID provided in page data', 'error');
        return;
    }

    try {
        const res = await fetch(`/api/scan/${scanId}`, { cache: 'no-cache' });
        if (!res.ok) throw new Error(`HTTP error ${res.status}`);
        const data = await res.json();

        if (data.success && data.scan) {
            renderResults(data.scan);
        } else {
            showToast(data.message || 'Unable to locate scan details', 'error');
        }
    } catch (err) {
        console.error('Failed to load scan report:', err);
        showToast('Error loading scan results: ' + err.message, 'error');
    }
}

/**
 * Dynamically populates all sections of the results view.
 * @param {Object} scan - Scan model payload from backend
 */
function renderResults(scan) {
    if (!scan) return;

    // 1. Metadata Headers
    const senderEl = document.getElementById('email-sender') || document.getElementById('result-sender');
    const subjectEl = document.getElementById('email-subject') || document.getElementById('result-subject');
    const timeEl = document.getElementById('scan-timestamp') || document.getElementById('result-timestamp');
    const modelEl = document.getElementById('result-model-badge');

    if (senderEl) senderEl.textContent = scan.sender || 'Unknown Sender';
    if (subjectEl) subjectEl.textContent = scan.subject || '(No Subject)';
    if (timeEl) timeEl.textContent = formatDate(scan.scan_timestamp);
    if (modelEl) {
        modelEl.textContent = scan.model_used ? `Model: ${scan.model_used}` : 'Deterministic Rules Only';
    }

    // 2. Risk Score & Category Gauge
    renderRiskGauge(scan.risk_score || 0, scan.risk_category || 'LOW');

    const catBadgeContainer = document.getElementById('risk-category-badge') || document.getElementById('result-category-badge');
    if (catBadgeContainer) {
        catBadgeContainer.innerHTML = getRiskBadge(scan.risk_category);
    }

    const classText = document.getElementById('score-classification-text');
    if (classText) {
        classText.textContent = `${(scan.risk_category || 'LOW').toUpperCase()} THREAT LEVEL`;
        classText.style.color = getRiskColor(scan.risk_category);
    }

    // 3. Score Breakdown Meters
    const ruleScoreEl = document.getElementById('rule-score-display') || document.getElementById('score-rule-val');
    const aiScoreEl = document.getElementById('ai-score-display') || document.getElementById('score-ai-val');
    const totalScoreEl = document.getElementById('total-score-display') || document.getElementById('score-total-val');
    const ruleBar = document.getElementById('score-rule-bar');
    const aiBar = document.getElementById('score-ai-bar');

    if (ruleScoreEl) ruleScoreEl.textContent = `${scan.rule_score || 0} / 60`;
    if (aiScoreEl) aiScoreEl.textContent = `${scan.ai_score || 0} / 40`;
    if (totalScoreEl) totalScoreEl.textContent = `${scan.risk_score || 0} / 100`;

    if (ruleBar) {
        const rulePct = Math.min(((scan.rule_score || 0) / 60) * 100, 100);
        ruleBar.style.width = `${rulePct}%`;
    }
    if (aiBar) {
        const aiPct = Math.min(((scan.ai_score || 0) / 40) * 100, 100);
        aiBar.style.width = `${aiPct}%`;
    }

    // 4. AI Verdict & Reasoning Section
    const aiVerdictEl = document.getElementById('ai-verdict-badge') || document.getElementById('result-ai-verdict');
    const aiConfidenceEl = document.getElementById('ai-confidence-text') || document.getElementById('result-ai-confidence');
    const confPctEl = document.getElementById('confidence-percentage');
    const confBarFill = document.getElementById('confidence-bar-fill');
    const aiReasonsContainer = document.getElementById('ai-reasons-list') || document.getElementById('result-ai-reasons');
    const aiEvidenceContainer = document.getElementById('ai-evidence-list') || document.getElementById('result-ai-evidence');

    const verdict = (scan.ai_verdict || 'UNKNOWN').toUpperCase();
    if (aiVerdictEl) {
        aiVerdictEl.textContent = verdict;
        aiVerdictEl.className = `badge font-bold verdict-${verdict.toLowerCase()}`;
    }

    const confVal = typeof scan.ai_confidence === 'number' ? Math.round(scan.ai_confidence * 100) : 0;
    if (aiConfidenceEl) {
        aiConfidenceEl.textContent = `Confidence: ${confVal}%`;
    }
    if (confPctEl) {
        confPctEl.textContent = `${confVal}%`;
    }
    if (confBarFill) {
        confBarFill.style.width = `${confVal}%`;
    }

    if (aiReasonsContainer) {
        const reasons = Array.isArray(scan.ai_reasons) ? scan.ai_reasons : [];
        if (reasons.length === 0) {
            aiReasonsContainer.innerHTML = `<li class="text-muted">No explicit AI reasons cited.</li>`;
        } else {
            aiReasonsContainer.innerHTML = reasons.map(r => `<li class="mb-1">${escapeHtml(r)}</li>`).join('');
        }
    }

    if (aiEvidenceContainer) {
        const evidence = Array.isArray(scan.ai_evidence) ? scan.ai_evidence : [];
        if (evidence.length === 0) {
            aiEvidenceContainer.innerHTML = `<span class="text-muted text-sm">No suspicious snippet text was extracted.</span>`;
        } else {
            aiEvidenceContainer.innerHTML = evidence.map(e => `
                <div class="evidence-pill bg-glass p-2 my-1 rounded text-xs font-mono border-l-2 border-cyan">
                    "${escapeHtml(e)}"
                </div>
            `).join('');
        }
    }

    // 5. Deterministic Rule Findings List
    renderFindings(scan.rule_findings || scan.findings || []);

    // 6. Actionable Next Steps
    const actionsContainer = document.getElementById('ai-recommendations-list') || document.getElementById('result-actions-list');
    if (actionsContainer) {
        const actions = Array.isArray(scan.ai_recommended_actions) && scan.ai_recommended_actions.length > 0
            ? scan.ai_recommended_actions
            : generateDefaultActions(scan.risk_category);

        actionsContainer.innerHTML = actions.map(act => `
            <div class="action-item flex items-start space-x-2 py-2 border-b border-glass">
                <i data-lucide="check-circle" class="w-5 h-5 text-cyan shrink-0 mt-0.5"></i>
                <span class="text-sm text-secondary">${escapeHtml(act)}</span>
            </div>
        `).join('');
    }

    // Refresh icons
    if (window.lucide && typeof window.lucide.createIcons === 'function') {
        window.lucide.createIcons();
    }
}

/**
 * Creates or updates an SVG neon arc gauge representing the risk score.
 * @param {number} score - 0 to 100
 * @param {string} category - LOW, MEDIUM, HIGH, CRITICAL
 */
function renderRiskGauge(score, category) {
    const color = getRiskColor(category);
    const clampedScore = Math.max(0, Math.min(100, Math.round(score)));

    // 1. Update text displays
    const simpleDisplay = document.getElementById('risk-score-display');
    if (simpleDisplay) {
        simpleDisplay.textContent = clampedScore;
        simpleDisplay.style.color = color;
    }

    // 2. If dedicated SVG circle exists (from results.html: r=68, circumference = 2 * pi * 68 = 427.256)
    const circle = document.getElementById('gauge-progress-circle');
    if (circle) {
        const circ = 427.256;
        const offset = circ - (clampedScore / 100) * circ;
        circle.style.stroke = color;
        circle.style.strokeDasharray = `${circ}`;
        circle.style.strokeDashoffset = `${offset}`;
        circle.style.filter = `drop-shadow(0 0 10px ${color}88)`;
    }

    // 3. Fallback container replacement if present
    const container = document.getElementById('risk-gauge-container');
    if (container) {
        const circumference = 339.292;
        const strokeDashoffset = circumference - (clampedScore / 100) * circumference;

        container.innerHTML = `
            <div class="risk-gauge-wrapper relative flex items-center justify-center">
                <svg class="risk-gauge-svg" width="160" height="160" viewBox="0 0 120 120">
                    <circle cx="60" cy="60" r="54" 
                        fill="none" 
                        stroke="rgba(148, 163, 184, 0.15)" 
                        stroke-width="8" />
                    <circle cx="60" cy="60" r="54" 
                        fill="none" 
                        stroke="${color}" 
                        stroke-width="8" 
                        stroke-linecap="round"
                        stroke-dasharray="${circumference}"
                        stroke-dashoffset="${strokeDashoffset}"
                        style="transition: stroke-dashoffset 1.2s ease-out; filter: drop-shadow(0 0 8px ${color}88);"
                        transform="rotate(-90 60 60)" />
                </svg>
                <div class="risk-gauge-text absolute text-center">
                    <div class="text-3xl font-extrabold font-mono" style="color: ${color}">
                        ${clampedScore}
                    </div>
                    <div class="text-xs uppercase tracking-wider text-muted font-bold">
                        Risk Score
                    </div>
                </div>
            </div>
        `;
    }
}

/**
 * Renders rule findings cards with severity colors, icons, and matched snippets.
 * @param {Array<Object>} findings - List of rule findings
 */
function renderFindings(findings) {
    const container = document.getElementById('findings-container');
    const countBadge = document.getElementById('findings-count-badge');

    if (!container) return;

    if (countBadge) {
        countBadge.textContent = findings.length;
    }

    if (!findings || findings.length === 0) {
        container.innerHTML = `
            <div class="p-6 text-center text-muted border border-glass rounded-lg">
                <i data-lucide="shield-check" class="w-10 h-10 mx-auto text-success mb-2"></i>
                <div class="font-medium text-white">No Suspicious Heuristic Indicators Detected</div>
                <div class="text-xs text-muted mt-1">Email content passed all 15+ deterministic safety checks.</div>
            </div>
        `;
        return;
    }

    container.innerHTML = findings.map(f => {
        const points = f.points || 0;
        let severityColor = '#eab308'; // medium (yellow)
        let severityLabel = 'LOW';
        let borderColor = 'border-amber-500';

        if (points >= 20) {
            severityColor = '#ef4444'; // red
            severityLabel = 'CRITICAL';
            borderColor = 'border-red-500';
        } else if (points >= 10) {
            severityColor = '#f59e0b'; // orange
            severityLabel = 'HIGH';
            borderColor = 'border-orange-500';
        }

        const evidenceItems = Array.isArray(f.evidence) ? f.evidence : (f.evidence ? [f.evidence] : []);

        return `
            <div class="finding-card card p-4 mb-3 border-l-4 ${borderColor} bg-glass rounded shadow-sm">
                <div class="flex items-center justify-between mb-2">
                    <div class="flex items-center space-x-2">
                        <span class="font-mono text-xs px-2 py-0.5 rounded font-bold" 
                            style="background: ${severityColor}22; color: ${severityColor}">
                            ${escapeHtml(f.indicator_type || 'RULE')}
                        </span>
                        <h4 class="font-semibold text-sm text-white">${escapeHtml(f.description || f.indicator_type)}</h4>
                    </div>
                    <span class="badge badge-sm font-mono" style="background: ${severityColor}22; color: ${severityColor}">
                        +${points} pts
                    </span>
                </div>
                ${evidenceItems.length > 0 ? `
                    <div class="evidence-list mt-2 pt-2 border-t border-glass">
                        <div class="text-xs font-semibold text-muted uppercase tracking-wider mb-1">Matched Signal Evidence:</div>
                        ${evidenceItems.map(ev => `
                            <div class="evidence-quote text-xs font-mono text-cyan bg-slate-900/60 p-1.5 rounded mb-1">
                                &bull; ${escapeHtml(String(ev))}
                            </div>
                        `).join('')}
                    </div>
                ` : ''}
            </div>
        `;
    }).join('');
}

/**
 * Fallback recommended actions if AI provided none.
 * @param {string} category - Risk category
 * @returns {Array<string>}
 */
function generateDefaultActions(category) {
    switch (String(category).toUpperCase()) {
        case 'CRITICAL':
        case 'HIGH':
            return [
                'Do not click any embedded links or open attachments in this email.',
                'Do not reply or provide passwords, OTP tokens, or financial numbers.',
                'Report this email to your organization security / IT helpdesk immediately.',
                'Mark the sender as phishing/spam in your email client.'
            ];
        case 'MEDIUM':
            return [
                'Verify the sender identity through an independent, trusted channel (e.g. phone).',
                'Inspect destination URLs carefully by hovering over links before interacting.',
                'Check if the request creates artificial urgency or threatens account closure.'
            ];
        case 'LOW':
        default:
            return [
                'No immediate threat detected, but always remain vigilant.',
                'Ensure multi-factor authentication (MFA) remains enabled on your accounts.'
            ];
    }
}

/**
 * Navigates to report export download endpoint.
 * @param {'json'|'txt'} format
 */
function exportReport(format) {
    const scanIdEl = document.getElementById('scan-id-data');
    if (!scanIdEl) return;
    const scanId = scanIdEl.dataset.scanId;
    if (scanId) {
        window.location.href = `/api/export/${scanId}?format=${format}`;
    }
}

/**
 * Copies structured scan JSON report to clipboard.
 */
async function copyReport() {
    const scanIdEl = document.getElementById('scan-id-data');
    if (!scanIdEl) return;
    const scanId = scanIdEl.dataset.scanId;

    try {
        const res = await fetch(`/api/scan/${scanId}`);
        const data = await res.json();
        if (data.success && data.scan) {
            const reportText = JSON.stringify(data.scan, null, 2);
            await copyToClipboard(reportText);
        } else {
            showToast('Unable to copy scan data', 'error');
        }
    } catch (e) {
        showToast('Error copying report: ' + e.message, 'error');
    }
}

// ============================================================================
// DOM READY & EVENT ATTACHMENT
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    // 1. Setup Input Form Controls
    const analyzeBtn = document.getElementById('analyze-btn');
    if (analyzeBtn) {
        analyzeBtn.addEventListener('click', (e) => {
            e.preventDefault();
            analyzeEmail();
        });
    }

    const emailForm = document.getElementById('email-form');
    if (emailForm) {
        emailForm.addEventListener('submit', (e) => {
            e.preventDefault();
            analyzeEmail();
        });
    }

    const clearBtn = document.getElementById('clear-btn');
    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            const s = document.getElementById('sender-input');
            const sub = document.getElementById('subject-input');
            const b = document.getElementById('body-input');
            if (s) s.value = '';
            if (sub) sub.value = '';
            if (b) b.value = '';
            updateBodyCounter();
            showToast('Form fields cleared', 'info');
        });
    }

    const tryPhishingBtn = document.getElementById('try-phishing');
    if (tryPhishingBtn) {
        tryPhishingBtn.addEventListener('click', () => {
            const s = document.getElementById('sender-input');
            const sub = document.getElementById('subject-input');
            const b = document.getElementById('body-input');
            if (s) s.value = PHISHING_EXAMPLE.sender;
            if (sub) sub.value = PHISHING_EXAMPLE.subject;
            if (b) b.value = PHISHING_EXAMPLE.body;
            updateBodyCounter();
            showToast('Loaded sample phishing attack email', 'info');
        });
    }

    const tryLegitBtn = document.getElementById('try-legit');
    if (tryLegitBtn) {
        tryLegitBtn.addEventListener('click', () => {
            const s = document.getElementById('sender-input');
            const sub = document.getElementById('subject-input');
            const b = document.getElementById('body-input');
            if (s) s.value = LEGIT_EXAMPLE.sender;
            if (sub) sub.value = LEGIT_EXAMPLE.subject;
            if (b) b.value = LEGIT_EXAMPLE.body;
            updateBodyCounter();
            showToast('Loaded sample legitimate notification email', 'info');
        });
    }

    const bodyInput = document.getElementById('body-input');
    if (bodyInput) {
        bodyInput.addEventListener('input', updateBodyCounter);
        updateBodyCounter();
    }

    // 2. Setup Results Page (if on results view)
    const scanIdEl = document.getElementById('scan-id-data');
    if (scanIdEl) {
        loadResultsPage();
    }

    const exportJson = document.getElementById('export-json');
    if (exportJson) {
        exportJson.addEventListener('click', () => exportReport('json'));
    }

    const exportTxt = document.getElementById('export-txt');
    if (exportTxt) {
        exportTxt.addEventListener('click', () => exportReport('txt'));
    }

    const copyBtn = document.getElementById('copy-report');
    if (copyBtn) {
        copyBtn.addEventListener('click', copyReport);
    }
});
