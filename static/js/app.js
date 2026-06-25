/**
 * Phishing URL Detector — Frontend Logic
 * =======================================
 * Handles URL submission, result display, history management,
 * and all interactive animations.
 */

(function () {
    'use strict';

    // ─── DOM Elements ──────────────────────────────────────────────────
    const urlForm = document.getElementById('url-form');
    const urlInput = document.getElementById('url-input');
    const checkBtn = document.getElementById('check-btn');
    const btnText = checkBtn.querySelector('.btn-text');
    const btnLoader = checkBtn.querySelector('.btn-loader');
    const inputError = document.getElementById('input-error');
    const scanningOverlay = document.getElementById('scanning-overlay');

    const resultSection = document.getElementById('result-section');
    const statusIconWrapper = document.getElementById('status-icon-wrapper');
    const statusIcon = document.getElementById('status-icon');
    const resultStatusText = document.getElementById('result-status-text');
    const resultUrl = document.getElementById('result-url');
    const scoreRingFill = document.getElementById('score-ring-fill');
    const scoreNumber = document.getElementById('score-number');
    const checksList = document.getElementById('checks-list');

    const safeBrowsingBadge = document.getElementById('safe-browsing-badge');
    const safeBrowsingText = document.getElementById('safe-browsing-text');

    const historyToggle = document.getElementById('history-toggle');
    const historyPanel = document.getElementById('history-panel');
    const historyList = document.getElementById('history-list');
    const historyCount = document.getElementById('history-count');
    const clearHistoryBtn = document.getElementById('clear-history-btn');
    const toggleHistoryBtn = document.getElementById('toggle-history-btn');

    // ─── State ─────────────────────────────────────────────────────────
    let isAnalyzing = false;
    let historyOpen = false;

    // ─── Constants ─────────────────────────────────────────────────────
    const CIRCUMFERENCE = 2 * Math.PI * 50; // 314.16 (matches SVG circle r=50)

    const STATUS_CONFIG = {
        safe: {
            label: '✅ Safe',
            icon: `<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`,
            color: 'var(--accent-green)',
            class: 'status-safe',
        },
        suspicious: {
            label: '⚠️ Suspicious',
            icon: `<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
            color: 'var(--accent-amber)',
            class: 'status-suspicious',
        },
        dangerous: {
            label: '🚨 Dangerous',
            icon: `<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`,
            color: 'var(--accent-red)',
            class: 'status-dangerous',
        },
    };

    // ─── URL Validation ────────────────────────────────────────────────
    function isValidUrl(string) {
        // Basic client-side validation — server does thorough check
        const trimmed = string.trim();
        if (!trimmed) return false;
        if (trimmed.length < 4) return false;

        // Must have at least one dot (for domain.tld)
        // or be an IP-based URL
        const urlPattern = /^(https?:\/\/)?[\w\-]+(\.[\w\-]+)+/i;
        const ipPattern = /^(https?:\/\/)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;

        return urlPattern.test(trimmed) || ipPattern.test(trimmed);
    }

    function showError(message) {
        inputError.textContent = message;
        inputError.style.display = 'block';
        setTimeout(() => {
            inputError.style.display = 'none';
        }, 4000);
    }

    function clearError() {
        inputError.style.display = 'none';
    }

    // ─── Loading State ─────────────────────────────────────────────────
    function setLoading(loading) {
        isAnalyzing = loading;
        checkBtn.disabled = loading;

        if (loading) {
            btnText.style.display = 'none';
            btnLoader.style.display = 'flex';
            scanningOverlay.style.display = 'block';
            urlInput.disabled = true;
        } else {
            btnText.style.display = 'inline';
            btnLoader.style.display = 'none';
            scanningOverlay.style.display = 'none';
            urlInput.disabled = false;
        }
    }

    // ─── Animated Counter ──────────────────────────────────────────────
    function animateCounter(element, target, duration = 1000) {
        const start = 0;
        const startTime = performance.now();

        function update(currentTime) {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);

            // Ease-out quad
            const eased = 1 - (1 - progress) * (1 - progress);
            const current = Math.round(start + (target - start) * eased);

            element.textContent = current;

            if (progress < 1) {
                requestAnimationFrame(update);
            }
        }

        requestAnimationFrame(update);
    }

    // ─── Display Results ───────────────────────────────────────────────
    function displayResult(data) {
        const config = STATUS_CONFIG[data.status] || STATUS_CONFIG.suspicious;

        // Status icon
        statusIconWrapper.className = `status-icon-wrapper ${config.class}`;
        statusIcon.innerHTML = config.icon;
        statusIcon.style.color = config.color;

        // Status text
        resultStatusText.textContent = config.label;
        resultStatusText.className = `result-status-text ${config.class}`;

        // URL
        resultUrl.textContent = data.url;

        // Score ring
        const offset = CIRCUMFERENCE - (data.risk_score / 100) * CIRCUMFERENCE;
        scoreRingFill.style.stroke = config.color;
        // Reset for animation
        scoreRingFill.style.transition = 'none';
        scoreRingFill.style.strokeDashoffset = CIRCUMFERENCE;

        requestAnimationFrame(() => {
            scoreRingFill.style.transition = 'stroke-dashoffset 1.2s cubic-bezier(0.4, 0, 0.2, 1), stroke 0.5s ease';
            scoreRingFill.style.strokeDashoffset = offset;
        });

        // Score number with animation
        scoreNumber.style.color = config.color;
        animateCounter(scoreNumber, data.risk_score, 1200);

        // Safe Browsing badge
        if (data.safe_browsing) {
            safeBrowsingBadge.style.display = 'flex';
            if (data.safe_browsing.flagged) {
                safeBrowsingBadge.className = 'safe-browsing-badge sb-flagged';
                safeBrowsingText.textContent = data.safe_browsing.detail;
            } else {
                safeBrowsingBadge.className = 'safe-browsing-badge sb-safe';
                safeBrowsingText.textContent = data.safe_browsing.detail;
            }
        } else {
            safeBrowsingBadge.style.display = 'none';
        }

        // Check details
        checksList.innerHTML = '';
        data.checks.forEach((check, index) => {
            const item = document.createElement('div');
            item.className = `check-item ${check.passed ? 'check-passed' : 'check-failed'}`;
            item.style.animationDelay = `${index * 0.06}s`;

            const iconSvg = check.passed
                ? `<svg class="check-icon icon-pass" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>`
                : `<svg class="check-icon icon-fail" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`;

            item.innerHTML = `
                ${iconSvg}
                <div class="check-content">
                    <div class="check-name">${escapeHtml(check.name)}</div>
                    <div class="check-detail">${escapeHtml(check.detail)}</div>
                </div>
                ${!check.passed ? `<div class="check-weight">+${check.weight} risk</div>` : ''}
            `;

            checksList.appendChild(item);
        });

        // Show result section
        resultSection.style.display = 'block';

        // Scroll to result
        setTimeout(() => {
            resultSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }, 100);
    }

    // ─── API Calls ─────────────────────────────────────────────────────
    async function checkUrl(url) {
        setLoading(true);
        clearError();

        try {
            const response = await fetch('/api/check', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url }),
            });

            const data = await response.json();

            if (!response.ok) {
                showError(data.error || 'An error occurred while analyzing the URL.');
                return;
            }

            displayResult(data);
            loadHistory(); // Refresh history
        } catch (err) {
            showError('Network error. Please check your connection and try again.');
            console.error('Check URL error:', err);
        } finally {
            setLoading(false);
        }
    }

    async function loadHistory() {
        try {
            const response = await fetch('/api/history?limit=20');
            const data = await response.json();

            renderHistory(data.history);
            historyCount.textContent = `${data.count} scan${data.count !== 1 ? 's' : ''}`;
        } catch (err) {
            console.error('Load history error:', err);
        }
    }

    async function clearHistory() {
        try {
            const response = await fetch('/api/history/clear', { method: 'DELETE' });
            const data = await response.json();

            renderHistory([]);
            historyCount.textContent = '0 scans';
        } catch (err) {
            console.error('Clear history error:', err);
        }
    }

    // ─── Render History ────────────────────────────────────────────────
    function renderHistory(entries) {
        if (!entries || entries.length === 0) {
            historyList.innerHTML = `
                <div class="history-empty">
                    <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" opacity="0.4">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                        <polyline points="14 2 14 8 20 8"/>
                        <line x1="16" y1="13" x2="8" y2="13"/>
                        <line x1="16" y1="17" x2="8" y2="17"/>
                    </svg>
                    <p>No scans yet. Enter a URL above to get started.</p>
                </div>
            `;
            return;
        }

        historyList.innerHTML = entries.map((entry, i) => {
            const dotClass = `dot-${entry.status}`;
            const scoreClass = `score-${entry.status}`;
            const time = formatTimestamp(entry.timestamp);

            return `
                <div class="history-item" style="animation-delay: ${i * 0.04}s"
                     data-url="${escapeAttr(entry.url)}"
                     title="Click to re-scan this URL">
                    <div class="history-status-dot ${dotClass}"></div>
                    <span class="history-item-url">${escapeHtml(entry.url)}</span>
                    <span class="history-item-score ${scoreClass}">${entry.risk_score}</span>
                    <span class="history-item-time">${time}</span>
                </div>
            `;
        }).join('');

        // Add click handlers to re-scan
        historyList.querySelectorAll('.history-item').forEach(item => {
            item.addEventListener('click', () => {
                const url = item.getAttribute('data-url');
                urlInput.value = url;
                urlInput.focus();
                checkUrl(url);

                // Scroll to scanner
                document.getElementById('scanner').scrollIntoView({ behavior: 'smooth' });
            });
        });
    }

    // ─── Utility Functions ─────────────────────────────────────────────
    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function escapeAttr(str) {
        return str.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function formatTimestamp(isoString) {
        try {
            const date = new Date(isoString);
            const now = new Date();
            const diff = now - date;

            if (diff < 60000) return 'Just now';
            if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
            if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;

            return date.toLocaleDateString('en-US', {
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
            });
        } catch {
            return '';
        }
    }

    // ─── Event Listeners ───────────────────────────────────────────────
    urlForm.addEventListener('submit', (e) => {
        e.preventDefault();
        if (isAnalyzing) return;

        const url = urlInput.value.trim();

        if (!url) {
            showError('Please enter a URL to analyze.');
            urlInput.focus();
            return;
        }

        if (!isValidUrl(url)) {
            showError('Please enter a valid URL (e.g., https://example.com).');
            urlInput.focus();
            return;
        }

        clearError();
        checkUrl(url);
    });

    // Live validation — clear error on input
    urlInput.addEventListener('input', () => {
        clearError();
    });

    // History toggle
    historyToggle.addEventListener('click', (e) => {
        // Don't toggle if clicking clear button
        if (e.target.closest('#clear-history-btn')) return;

        historyOpen = !historyOpen;
        historyPanel.style.display = historyOpen ? 'block' : 'none';
        toggleHistoryBtn.classList.toggle('open', historyOpen);

        if (historyOpen) {
            loadHistory();
        }
    });

    // Clear history
    clearHistoryBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        clearHistory();
    });

    // Keyboard shortcut: Ctrl+K to focus input
    document.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            urlInput.focus();
            urlInput.select();
        }
    });

    // ─── Initialize ────────────────────────────────────────────────────
    function init() {
        urlInput.focus();
        loadHistory();
    }

    // Run when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
