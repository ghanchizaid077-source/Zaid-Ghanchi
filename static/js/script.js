document.addEventListener('DOMContentLoaded', () => {
    // ----------------------------------------------------
    // Theme Toggle Initialization
    // ----------------------------------------------------
    const themeToggleBtn = document.getElementById('theme-toggle-btn');
    const themeIcon = themeToggleBtn?.querySelector('i');
    
    // Check local storage for theme
    const currentTheme = localStorage.getItem('theme') || 'dark';
    if (currentTheme === 'light') {
        document.body.classList.add('light-theme');
        if (themeIcon) {
            themeIcon.classList.replace('fa-moon', 'fa-sun');
        }
    }

    if (themeToggleBtn) {
        themeToggleBtn.addEventListener('click', () => {
            document.body.classList.toggle('light-theme');
            let theme = 'dark';
            
            if (document.body.classList.contains('light-theme')) {
                theme = 'light';
                if (themeIcon) themeIcon.classList.replace('fa-moon', 'fa-sun');
                showToast('Theme Changed', 'Light mode enabled.', 'info');
            } else {
                if (themeIcon) themeIcon.classList.replace('fa-sun', 'fa-moon');
                showToast('Theme Changed', 'Dark mode enabled.', 'info');
            }
            localStorage.setItem('theme', theme);
            
            // Re-render chart if it exists on theme change to adjust colors
            if (window.statsChart && typeof renderChart === 'function') {
                updateChartColors();
            }
        });
    }

    // ----------------------------------------------------
    // Toast Notification System
    // ----------------------------------------------------
    window.showToast = function(title, message, type = 'info') {
        const toastContainer = document.getElementById('toast-container');
        if (!toastContainer) return;
        
        const toastId = 'toast-' + Date.now();
        let borderGlow = 'rgba(0, 240, 255, 0.4)';
        let titleColor = 'var(--accent-blue)';
        let icon = 'fa-info-circle';
        
        if (type === 'success') {
            borderGlow = 'rgba(16, 185, 129, 0.4)';
            titleColor = 'var(--color-safe)';
            icon = 'fa-check-circle';
        } else if (type === 'warning') {
            borderGlow = 'rgba(245, 158, 11, 0.4)';
            titleColor = 'var(--color-suspicious)';
            icon = 'fa-exclamation-triangle';
        } else if (type === 'error' || type === 'danger') {
            borderGlow = 'rgba(239, 68, 68, 0.4)';
            titleColor = 'var(--color-dangerous)';
            icon = 'fa-shield-alt';
        }
        
        const toastHTML = `
            <div id="${toastId}" class="cyber-toast show" style="border-color: ${borderGlow}; margin-top: 10px;">
                <div class="cyber-toast-header">
                    <strong style="color: ${titleColor}"><i class="fas ${icon} me-2"></i>${title}</strong>
                    <button type="button" class="btn-close btn-close-white" onclick="document.getElementById('${toastId}').remove()"></button>
                </div>
                <div class="cyber-toast-body">
                    ${message}
                </div>
            </div>
        `;
        
        toastContainer.insertAdjacentHTML('beforeend', toastHTML);
        
        // Auto remove after 5 seconds
        setTimeout(() => {
            const toastEl = document.getElementById(toastId);
            if (toastEl) {
                toastEl.style.transition = 'opacity 0.5s ease-out';
                toastEl.style.opacity = 0;
                setTimeout(() => toastEl.remove(), 500);
            }
        }, 5000);
    };

    // ----------------------------------------------------
    // URL Analysis Page (Home Page)
    // ----------------------------------------------------
    const scanForm = document.getElementById('scan-form');
    const urlInput = document.getElementById('url-input');
    const loadingSection = document.getElementById('loading-section');
    const resultSection = document.getElementById('result-section');
    
    if (scanForm) {
        scanForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const urlVal = urlInput.value.trim();
            
            if (!urlVal) {
                showToast('Validation Error', 'Please enter a URL to analyze.', 'warning');
                return;
            }
            
            // Clean UI
            resultSection.style.display = 'none';
            loadingSection.style.display = 'block';
            
            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ url: urlVal }),
                });
                
                const data = await response.json();
                
                // Add a small delay for premium scanner feel
                setTimeout(() => {
                    loadingSection.style.display = 'none';
                    if (!response.ok) {
                        showToast('Scan Failed', data.error || 'Unable to scan URL.', 'error');
                        return;
                    }
                    
                    renderScanResult(data);
                }, 1500);
                
            } catch (err) {
                loadingSection.style.display = 'none';
                showToast('Connection Error', 'Failed to communicate with scanning engine.', 'error');
                console.error(err);
            }
        });
    }

    function getExplanationIcon(checkName, status) {
        let colorClass = 'text-success';
        if (status === 'warning') colorClass = 'text-warning';
        if (status === 'fail') colorClass = 'text-danger';
        
        switch(checkName) {
            case 'HTTPS Availability':
                return status === 'pass' 
                    ? `<i class="fas fa-lock ${colorClass}"></i>` 
                    : `<i class="fas fa-lock-open ${colorClass}"></i>`;
            case 'URL Length':
                return `<i class="fas fa-text-width ${colorClass}"></i>`;
            case 'Suspicious Keywords':
                return `<i class="fas fa-keyboard ${colorClass}"></i>`;
            case 'IP Address in Domain':
                return status === 'pass'
                    ? `<i class="fas fa-globe ${colorClass}"></i>`
                    : `<i class="fas fa-network-wired ${colorClass}"></i>`;
            case 'Shortening Service':
                return `<i class="fas fa-link-slash ${colorClass}"></i>`;
            case 'Subdomain Count':
                return `<i class="fas fa-sitemap ${colorClass}"></i>`;
            case 'Special Characters':
                return `<i class="fas fa-asterisk ${colorClass}"></i>`;
            default:
                return `<i class="fas fa-circle-question ${colorClass}"></i>`;
        }
    }

    function renderScanResult(data) {
        // Reset classes
        resultSection.className = 'result-card p-4 p-md-5';
        const categoryClass = data.category.toLowerCase(); // 'safe', 'suspicious', 'dangerous'
        resultSection.classList.add(categoryClass);
        
        // Set values
        document.getElementById('res-url').innerText = data.url;
        document.getElementById('res-score').innerText = data.risk_score + '%';
        document.getElementById('res-category').innerText = data.category + ' Website';
        
        // Circular Risk Meter Animation
        const circularMeter = document.getElementById('circular-meter');
        if (circularMeter) {
            circularMeter.className = 'circular-risk-meter my-2 ' + categoryClass;
        }
        
        const circularRatingVal = document.getElementById('circular-rating-val');
        if (circularRatingVal) {
            circularRatingVal.innerText = data.category;
        }
        
        const circularMeterFg = document.getElementById('circular-meter-fg');
        if (circularMeterFg) {
            const circumference = 282.74; // 2 * pi * 45
            circularMeterFg.style.strokeDasharray = circumference;
            circularMeterFg.style.strokeDashoffset = circumference;
            setTimeout(() => {
                const offset = circumference - (circumference * data.risk_score) / 100;
                circularMeterFg.style.strokeDashoffset = offset;
            }, 100);
        }

        // Progress Meter Animation (Legacy horizontal bar)
        const meterBar = document.getElementById('res-meter-bar');
        if (meterBar) {
            meterBar.style.width = '0%';
            setTimeout(() => {
                meterBar.style.width = data.risk_score + '%';
            }, 100);
        }
        
        // Set category icon
        const iconEl = document.getElementById('res-icon');
        if (iconEl) {
            iconEl.className = 'fas fa-2x mb-2 ';
            if (categoryClass === 'safe') {
                iconEl.classList.add('fa-shield-alt', 'text-success');
                showToast('Scan Complete', 'The website appears SAFE.', 'success');
            } else if (categoryClass === 'suspicious') {
                iconEl.classList.add('fa-exclamation-triangle', 'text-warning');
                showToast('Warning', 'The website has SUSPICIOUS factors.', 'warning');
            } else {
                iconEl.classList.add('fa-skull-crossbones', 'text-danger');
                showToast('Alert', 'The website is DANGEROUS!', 'error');
            }
        }

        // Map explanations for the 7 requested parameters
        const explanationMap = {
            'HTTPS Availability': 'exp-https',
            'URL Length': 'exp-length',
            'Suspicious Keywords': 'exp-keywords',
            'IP Address in Domain': 'exp-ip',
            'Shortening Service': 'exp-shortener',
            'Subdomain Count': 'exp-subdomains',
            'Special Characters': 'exp-special'
        };

        // Reset cards to default pass
        Object.keys(explanationMap).forEach(key => {
            const cardId = explanationMap[key];
            const badgeEl = document.getElementById(`${cardId}-badge`);
            const iconContainer = document.getElementById(`${cardId}-icon`);
            const descEl = document.getElementById(`${cardId}-desc`);
            if (badgeEl && iconContainer && descEl) {
                badgeEl.className = 'badge badge-safe';
                badgeEl.innerText = 'Pass';
                descEl.innerText = 'No flags detected for this parameter.';
                iconContainer.innerHTML = getExplanationIcon(key, 'pass');
            }
        });

        // Loop details to update matched parameters
        data.details.forEach(detail => {
            const cardId = explanationMap[detail.check];
            if (cardId) {
                const badgeEl = document.getElementById(`${cardId}-badge`);
                const iconContainer = document.getElementById(`${cardId}-icon`);
                const descEl = document.getElementById(`${cardId}-desc`);
                
                if (badgeEl && iconContainer && descEl) {
                    descEl.innerText = detail.message;
                    
                    if (detail.status === 'pass') {
                        badgeEl.className = 'badge badge-safe';
                        badgeEl.innerText = 'Pass';
                        iconContainer.innerHTML = getExplanationIcon(detail.check, 'pass');
                    } else if (detail.status === 'warning') {
                        badgeEl.className = 'badge badge-suspicious';
                        badgeEl.innerText = `Warning (+${detail.impact}%)`;
                        iconContainer.innerHTML = getExplanationIcon(detail.check, 'warning');
                    } else {
                        badgeEl.className = 'badge badge-dangerous';
                        badgeEl.innerText = `Fail (+${detail.impact}%)`;
                        iconContainer.innerHTML = getExplanationIcon(detail.check, 'fail');
                    }
                }
            }
        });

        // Render checklist details (Legacy list logs)
        const checklistContainer = document.getElementById('res-checklist');
        if (checklistContainer) {
            checklistContainer.innerHTML = '';
            
            data.details.forEach(detail => {
                let statusBadge = '';
                let itemClass = '';
                let statusIcon = '';
                
                if (detail.status === 'pass') {
                    statusBadge = '<span class="badge badge-safe">Pass</span>';
                    itemClass = 'pass';
                    statusIcon = '<i class="fas fa-check-circle text-success me-3"></i>';
                } else if (detail.status === 'warning') {
                    statusBadge = `<span class="badge badge-suspicious">Warning (+${detail.impact}%)</span>`;
                    itemClass = 'warning';
                    statusIcon = '<i class="fas fa-exclamation-circle text-warning me-3"></i>';
                } else {
                    statusBadge = `<span class="badge badge-dangerous">Fail (+${detail.impact}%)</span>`;
                    itemClass = 'fail';
                    statusIcon = '<i class="fas fa-times-circle text-danger me-3"></i>';
                }
                
                const itemHTML = `
                    <div class="checklist-item ${itemClass}">
                        <div class="d-flex align-items-center">
                            ${statusIcon}
                            <div>
                                <strong class="d-block">${detail.check}</strong>
                                <small class="text-secondary">${detail.message}</small>
                            </div>
                        </div>
                        <div>
                            ${statusBadge}
                        </div>
                    </div>
                `;
                checklistContainer.insertAdjacentHTML('beforeend', itemHTML);
            });
        }
        
        resultSection.style.display = 'block';
        
        // Smooth scroll to result
        resultSection.scrollIntoView({ behavior: 'smooth' });
    }

    // ----------------------------------------------------
    // Dashboard Logic
    // ----------------------------------------------------
    const statsChartCanvas = document.getElementById('stats-chart');
    if (statsChartCanvas) {
        loadDashboardStats();
    }
    
    async function loadDashboardStats() {
        try {
            const response = await fetch('/api/history');
            const history = await response.json();
            
            let safeCount = 0;
            let suspiciousCount = 0;
            let dangerousCount = 0;
            const totalCount = history.length;
            
            history.forEach(scan => {
                if (scan.category === 'Safe') safeCount++;
                else if (scan.category === 'Suspicious') suspiciousCount++;
                else if (scan.category === 'Dangerous') dangerousCount++;
            });
            
            // Set stats values
            document.getElementById('stat-total').innerText = totalCount;
            document.getElementById('stat-safe').innerText = safeCount;
            document.getElementById('stat-suspicious').innerText = suspiciousCount;
            document.getElementById('stat-dangerous').innerText = dangerousCount;
            
            // Render Chart
            renderChart(safeCount, suspiciousCount, dangerousCount);
            
            // Render Recent Scans (last 5)
            const recentBody = document.getElementById('recent-scans-body');
            if (recentBody) {
                recentBody.innerHTML = '';
                if (totalCount === 0) {
                    recentBody.innerHTML = '<tr><td colspan="5" class="text-center text-secondary">No scan history available.</td></tr>';
                } else {
                    const recentScans = history.slice(0, 5);
                    recentScans.forEach(scan => {
                        let categoryBadge = '';
                        if (scan.category === 'Safe') {
                            categoryBadge = '<span class="badge badge-safe">Safe</span>';
                        } else if (scan.category === 'Suspicious') {
                            categoryBadge = '<span class="badge badge-suspicious">Suspicious</span>';
                        } else {
                            categoryBadge = '<span class="badge badge-dangerous">Dangerous</span>';
                        }
                        
                        const row = `
                            <tr>
                                <td class="text-truncate" style="max-width: 250px;" title="${scan.url}">${scan.url}</td>
                                <td><code>${scan.risk_score}%</code></td>
                                <td>${categoryBadge}</td>
                                <td class="text-secondary small">${scan.timestamp}</td>
                                <td>
                                    <a href="/" class="btn btn-sm btn-cyber-outline py-1 px-2" onclick="localStorage.setItem('scannedUrl', '${scan.url}')">
                                        <i class="fas fa-redo"></i> Scan
                                    </a>
                                </td>
                            </tr>
                        `;
                        recentBody.insertAdjacentHTML('beforeend', row);
                    });
                }
            }
            
        } catch (err) {
            console.error('Failed to load stats:', err);
            showToast('Stats Load Error', 'Could not fetch dashboard statistics.', 'error');
        }
    }

    function renderChart(safe, suspicious, dangerous) {
        if (!statsChartCanvas) return;
        
        const isLightTheme = document.body.classList.contains('light-theme');
        const textLabelColor = isLightTheme ? '#0f172a' : '#f8fafc';
        
        const ctx = statsChartCanvas.getContext('2d');
        
        window.statsChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Safe', 'Suspicious', 'Dangerous'],
                datasets: [{
                    data: [safe, suspicious, dangerous],
                    backgroundColor: [
                        '#10b981', // emerald
                        '#f59e0b', // amber
                        '#ef4444'  // rose
                    ],
                    borderColor: isLightTheme ? '#ffffff' : '#070e20',
                    borderWidth: 2,
                    hoverOffset: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: textLabelColor,
                            font: {
                                family: 'Outfit',
                                size: 14
                            },
                            padding: 20
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const val = context.raw;
                                const percentage = total > 0 ? ((val / total) * 100).toFixed(1) : 0;
                                return `${context.label}: ${val} (${percentage}%)`;
                            }
                        }
                    }
                },
                cutout: '65%'
            }
        });
    }
    
    function updateChartColors() {
        if (!window.statsChart) return;
        const isLightTheme = document.body.classList.contains('light-theme');
        const textLabelColor = isLightTheme ? '#0f172a' : '#f8fafc';
        
        window.statsChart.options.plugins.legend.labels.color = textLabelColor;
        window.statsChart.options.datasets[0].borderColor = isLightTheme ? '#ffffff' : '#070e20';
        window.statsChart.update();
    }

    // ----------------------------------------------------
    // History Page Logic
    // ----------------------------------------------------
    const historyTableBody = document.getElementById('history-table-body');
    const searchInput = document.getElementById('search-input');
    const clearHistoryBtn = document.getElementById('clear-history-btn');
    
    let fullHistoryData = []; // Store the full logs list to filter locally
    
    if (historyTableBody) {
        loadHistoryTable();
        
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                const query = e.target.value.toLowerCase().trim();
                filterHistory(query);
            });
        }
        
        if (clearHistoryBtn) {
            clearHistoryBtn.addEventListener('click', async () => {
                if (confirm('Are you sure you want to permanently clear ALL scan history? This action cannot be undone.')) {
                    try {
                        const response = await fetch('/api/history/clear', { method: 'POST' });
                        if (response.ok) {
                            showToast('Success', 'History database cleared.', 'success');
                            loadHistoryTable();
                        } else {
                            showToast('Error', 'Failed to clear history.', 'error');
                        }
                    } catch (err) {
                        console.error(err);
                        showToast('Error', 'Connection failed.', 'error');
                    }
                }
            });
        }
    }
    
    async function loadHistoryTable() {
        try {
            const response = await fetch('/api/history');
            fullHistoryData = await response.json();
            renderHistoryRows(fullHistoryData);
        } catch (err) {
            console.error('Failed to load history list:', err);
            showToast('History Error', 'Failed to fetch scan logs.', 'error');
        }
    }
    
    function renderHistoryRows(scans) {
        if (!historyTableBody) return;
        historyTableBody.innerHTML = '';
        
        if (scans.length === 0) {
            historyTableBody.innerHTML = '<tr><td colspan="6" class="text-center text-secondary py-4">No scan results matching parameters.</td></tr>';
            return;
        }
        
        scans.forEach((scan, index) => {
            let badge = '';
            if (scan.category === 'Safe') {
                badge = '<span class="badge badge-safe"><i class="fas fa-check-circle me-1"></i>Safe</span>';
            } else if (scan.category === 'Suspicious') {
                badge = '<span class="badge badge-suspicious"><i class="fas fa-exclamation-triangle me-1"></i>Suspicious</span>';
            } else {
                badge = '<span class="badge badge-dangerous"><i class="fas fa-skull-crossbones me-1"></i>Dangerous</span>';
            }
            
            const rowHTML = `
                <tr id="scan-row-${scan.id}">
                    <td>${index + 1}</td>
                    <td class="text-truncate text-start" style="max-width: 320px;" title="${scan.url}">
                        <span class="font-monospace text-break">${scan.url}</span>
                    </td>
                    <td><code>${scan.risk_score}%</code></td>
                    <td>${badge}</td>
                    <td class="text-secondary small">${scan.timestamp}</td>
                    <td>
                        <div class="btn-group">
                            <a href="/" class="btn btn-sm btn-cyber-outline px-2 py-1 me-2" onclick="localStorage.setItem('scannedUrl', '${scan.url}')">
                                <i class="fas fa-redo"></i>
                            </a>
                            <button class="btn btn-sm btn-outline-danger px-2 py-1" onclick="deleteHistoryEntry('${scan.id}')">
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                    </td>
                </tr>
            `;
            historyTableBody.insertAdjacentHTML('beforeend', rowHTML);
        });
    }
    
    function filterHistory(query) {
        if (!query) {
            renderHistoryRows(fullHistoryData);
            return;
        }
        
        const filtered = fullHistoryData.filter(scan => 
            scan.url.toLowerCase().includes(query) || 
            scan.category.toLowerCase().includes(query) ||
            scan.hostname.toLowerCase().includes(query)
        );
        renderHistoryRows(filtered);
    }
    
    window.deleteHistoryEntry = async function(scanId) {
        if (confirm('Delete this scan entry from records?')) {
            try {
                const response = await fetch(`/api/history/${scanId}`, { method: 'DELETE' });
                if (response.ok) {
                    showToast('Deleted', 'Scan record removed.', 'success');
                    
                    // Remove row from UI directly or reload
                    const row = document.getElementById(`scan-row-${scanId}`);
                    if (row) {
                        row.style.transition = 'opacity 0.3s ease-out';
                        row.style.opacity = 0;
                        setTimeout(() => {
                            loadHistoryTable();
                        }, 300);
                    } else {
                        loadHistoryTable();
                    }
                } else {
                    showToast('Error', 'Failed to delete record.', 'error');
                }
            } catch (err) {
                console.error(err);
                showToast('Error', 'Connection failed.', 'error');
            }
        }
    };

    // ----------------------------------------------------
    // Auto-fill Scan Input from Local Storage
    // ----------------------------------------------------
    const savedUrl = localStorage.getItem('scannedUrl');
    if (savedUrl && urlInput) {
        urlInput.value = savedUrl;
        localStorage.removeItem('scannedUrl'); // Clear it
        // Auto click submit if on home page
        setTimeout(() => {
            scanForm.dispatchEvent(new Event('submit'));
        }, 100);
    }
});
