/**
 * Enhanced Dashboard for Solana Wallet Monitor
 * Features interactive charts and visualizations with real-time data updates
 */

document.addEventListener('DOMContentLoaded', () => {
    // Initialize all charts
    initializeDashboard();
    
    // Set up refresh button
    document.getElementById('refreshDashboardBtn')?.addEventListener('click', refreshAllData);
    
    // Set up auto-refresh functionality
    setupAutoRefresh();
    
    // Initialize date range picker if available
    initializeDateRangePicker();
    
    // Set up time range buttons for filtering data
    setupTimeRangePickers();
});

/**
 * Initialize the main dashboard components
 */
function initializeDashboard() {
    // Load all dashboard data
    loadDashboardSummary();
    loadRecentTransactions();
    loadRiskAnalysis();
    loadHoneypotDetections();
    loadSuspiciousActivities();
    loadTokenDistribution();
    loadSwapActivity();
    
    // Initialize tooltips and popovers
    initializeTooltips();
}

/**
 * Set up auto-refresh functionality
 */
function setupAutoRefresh() {
    // Get refresh interval from localStorage or default to 60 seconds
    const refreshInterval = parseInt(localStorage.getItem('refreshInterval') || '60') * 1000;
    
    if (refreshInterval > 0) {
        // Set interval to refresh dashboard
        setInterval(() => {
            refreshAllData();
        }, refreshInterval);
        
        // Show refresh indicator
        const refreshIndicator = document.getElementById('refreshIndicator');
        if (refreshIndicator) {
            refreshIndicator.textContent = `Auto-refresh: ${refreshInterval / 1000}s`;
            refreshIndicator.classList.remove('d-none');
        }
    }
}

/**
 * Initialize date range picker if available
 */
function initializeDateRangePicker() {
    const dateRangePicker = document.getElementById('dashboardDateRange');
    
    if (dateRangePicker) {
        // Set up date range picker
        const now = new Date();
        const lastWeek = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        
        dateRangePicker.value = `${formatDate(lastWeek)} to ${formatDate(now)}`;
        
        // Handle date range changes
        dateRangePicker.addEventListener('change', (e) => {
            const dateRange = e.target.value;
            // Parse date range
            const [startStr, endStr] = dateRange.split(' to ');
            
            if (startStr && endStr) {
                const startDate = new Date(startStr);
                const endDate = new Date(endStr);
                
                // Load data with date range
                loadDataWithDateRange(startDate, endDate);
            }
        });
    }
}

/**
 * Format date for date range picker
 * @param {Date} date
 * @returns {string} Formatted date string
 */
function formatDate(date) {
    return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;
}

/**
 * Set up time range picker buttons
 */
function setupTimeRangePickers() {
    document.querySelectorAll('.time-range-btn').forEach(button => {
        button.addEventListener('click', (e) => {
            // Remove active class from all buttons
            document.querySelectorAll('.time-range-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            
            // Add active class to clicked button
            e.target.classList.add('active');
            
            // Get time range value
            const timeRange = e.target.getAttribute('data-range');
            
            // Load data with time range
            loadDataWithTimeRange(timeRange);
        });
    });
}

/**
 * Refresh all dashboard data
 */
function refreshAllData() {
    // Show refresh spinner
    const refreshBtn = document.getElementById('refreshDashboardBtn');
    const originalHtml = refreshBtn.innerHTML;
    
    refreshBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Refreshing...';
    refreshBtn.disabled = true;
    
    // Reload all data
    Promise.all([
        loadDashboardSummary(),
        loadRecentTransactions(),
        loadRiskAnalysis(),
        loadHoneypotDetections(),
        loadSuspiciousActivities(),
        loadTokenDistribution(),
        loadSwapActivity()
    ])
    .then(() => {
        // Restore button state
        refreshBtn.innerHTML = originalHtml;
        refreshBtn.disabled = false;
        
        // Show success toast
        showToast('Dashboard Refreshed', 'All dashboard data has been refreshed successfully.', 'success');
    })
    .catch(error => {
        console.error('Error refreshing dashboard:', error);
        
        // Restore button state
        refreshBtn.innerHTML = originalHtml;
        refreshBtn.disabled = false;
        
        // Show error toast
        showToast('Refresh Failed', 'There was an error refreshing the dashboard data.', 'danger');
    });
}

/**
 * Load data with specified date range
 * @param {Date} startDate
 * @param {Date} endDate
 */
function loadDataWithDateRange(startDate, endDate) {
    // Format dates for API
    const startStr = formatDate(startDate);
    const endStr = formatDate(endDate);
    
    // Load data with date range
    loadDashboardData(null, startStr, endStr);
}

/**
 * Load data with specified time range
 * @param {string} timeRange
 */
function loadDataWithTimeRange(timeRange) {
    // Load data with time range
    loadDashboardData(timeRange);
}

/**
 * Load dashboard data from API
 * @param {string} timeRange - Time range for filtering data
 * @param {string} startDate - Start date for custom range
 * @param {string} endDate - End date for custom range
 */
function loadDashboardData(timeRange = null, startDate = null, endDate = null) {
    // Build API URL with parameters
    let apiUrl = '/api/analytics';
    const params = [];
    
    if (timeRange) {
        params.push(`time_range=${timeRange}`);
    }
    
    if (startDate && endDate) {
        params.push(`start_date=${startDate}`);
        params.push(`end_date=${endDate}`);
    }
    
    if (params.length > 0) {
        apiUrl += `?${params.join('&')}`;
    }
    
    // Fetch data from API
    return fetch(apiUrl)
        .then(response => response.json())
        .then(data => {
            // Update all charts with the new data
            updateTransactionVolumeChart(data.volume_data);
            updateTransactionTypesChart(data.transaction_types);
            updateTokenDistributionChart(data.token_distribution);
            updateProgramInteractionsChart(data.program_interactions);
            updateRiskScore(data.risk_score);
            updateMetrics(data.metrics);
            
            return data;
        })
        .catch(error => {
            console.error('Error loading dashboard data:', error);
            showToast('Data Load Error', 'Failed to load dashboard data from API.', 'danger');
            throw error;
        });
}

/**
 * Load dashboard summary data
 */
function loadDashboardSummary() {
    const summaryContainer = document.getElementById('dashboardSummary');
    
    if (!summaryContainer) return Promise.resolve();
    
    summaryContainer.innerHTML = `
        <div class="d-flex justify-content-center">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
        </div>
    `;
    
    // Load data from analytics API
    return loadDashboardData('1d')
        .then(data => {
            // Update summary metrics
            const metrics = data.metrics;
            
            summaryContainer.innerHTML = `
                <div class="row">
                    <div class="col-md-3 mb-3">
                        <div class="card bg-primary text-white">
                            <div class="card-body text-center">
                                <h3>${metrics.total_transactions}</h3>
                                <div>Total Transactions</div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3 mb-3">
                        <div class="card bg-success text-white">
                            <div class="card-body text-center">
                                <h3>${metrics.incoming}</h3>
                                <div>Incoming</div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3 mb-3">
                        <div class="card bg-danger text-white">
                            <div class="card-body text-center">
                                <h3>${metrics.outgoing}</h3>
                                <div>Outgoing</div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3 mb-3">
                        <div class="card bg-warning text-white">
                            <div class="card-body text-center">
                                <h3>${metrics.swaps}</h3>
                                <div>Swaps</div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            return data;
        })
        .catch(error => {
            console.error('Error loading dashboard summary:', error);
            summaryContainer.innerHTML = `
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-circle"></i>
                    Failed to load dashboard summary data.
                </div>
            `;
        });
}

/**
 * Load recent transactions
 */
function loadRecentTransactions() {
    const container = document.getElementById('recentTransactions');
    
    if (!container) return Promise.resolve();
    
    container.innerHTML = `
        <div class="d-flex justify-content-center">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
        </div>
    `;
    
    return fetch('/api/transactions?limit=5')
        .then(response => response.json())
        .then(transactions => {
            if (transactions.length === 0) {
                container.innerHTML = `
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle"></i>
                        No recent transactions found.
                    </div>
                `;
                return;
            }
            
            let html = `
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead>
                            <tr>
                                <th>Signature</th>
                                <th>Date</th>
                                <th>Type</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody>
            `;
            
            transactions.forEach(tx => {
                const eventTypes = tx.events.map(event => event.type).join(', ');
                
                html += `
                    <tr>
                        <td>
                            <a href="https://explorer.solana.com/tx/${tx.signature}" target="_blank" class="text-truncate d-inline-block" style="max-width: 150px;">
                                ${tx.signature}
                            </a>
                        </td>
                        <td>${tx.date}</td>
                        <td>${eventTypes || 'Unknown'}</td>
                        <td>
                            <button class="btn btn-sm btn-outline-primary" onclick="showTransactionDetails('${tx.signature}')">
                                View Details
                            </button>
                        </td>
                    </tr>
                `;
            });
            
            html += `
                        </tbody>
                    </table>
                </div>
                <div class="text-end">
                    <a href="/transactions" class="btn btn-sm btn-outline-primary">View All Transactions</a>
                </div>
            `;
            
            container.innerHTML = html;
        })
        .catch(error => {
            console.error('Error loading recent transactions:', error);
            container.innerHTML = `
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-circle"></i>
                    Failed to load recent transactions.
                </div>
            `;
        });
}

/**
 * Load risk analysis data
 */
function loadRiskAnalysis() {
    const container = document.getElementById('riskAnalysis');
    
    if (!container) return Promise.resolve();
    
    container.innerHTML = `
        <div class="d-flex justify-content-center">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
        </div>
    `;
    
    return loadDashboardData('7d')
        .then(data => {
            // Get risk score
            const riskScore = data.risk_score || 0;
            
            // Determine risk level and color
            let riskLevel, progressClass;
            
            if (riskScore < 25) {
                riskLevel = 'Low Risk';
                progressClass = 'bg-success';
            } else if (riskScore < 50) {
                riskLevel = 'Moderate Risk';
                progressClass = 'bg-info';
            } else if (riskScore < 75) {
                riskLevel = 'High Risk';
                progressClass = 'bg-warning';
            } else {
                riskLevel = 'Critical Risk';
                progressClass = 'bg-danger';
            }
            
            container.innerHTML = `
                <div class="risk-score-container">
                    <h5>Risk Score: ${Math.round(riskScore)}%</h5>
                    <div class="progress" style="height: 25px;">
                        <div class="progress-bar ${progressClass}" role="progressbar" 
                            style="width: ${riskScore}%;" 
                            aria-valuenow="${riskScore}" 
                            aria-valuemin="0" 
                            aria-valuemax="100">
                            ${riskLevel}
                        </div>
                    </div>
                    <div class="small text-muted mt-2">
                        Based on transaction patterns, wallet age, interactions with known contracts, and suspicious activity.
                    </div>
                </div>
            `;
            
            return data;
        })
        .catch(error => {
            console.error('Error loading risk analysis:', error);
            container.innerHTML = `
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-circle"></i>
                    Failed to load risk analysis data.
                </div>
            `;
        });
}

/**
 * Load honeypot detections
 */
function loadHoneypotDetections() {
    const container = document.getElementById('honeypotDetections');
    
    if (!container) return Promise.resolve();
    
    container.innerHTML = `
        <div class="d-flex justify-content-center">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
        </div>
    `;
    
    return fetch('/api/honeypots')
        .then(response => response.json())
        .then(honeypots => {
            if (Object.keys(honeypots).length === 0) {
                container.innerHTML = `
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle"></i>
                        No honeypot tokens detected.
                    </div>
                `;
                return;
            }
            
            let html = `
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead>
                            <tr>
                                <th>Token</th>
                                <th>Confidence</th>
                                <th>Reason</th>
                            </tr>
                        </thead>
                        <tbody>
            `;
            
            for (const [mint, data] of Object.entries(honeypots)) {
                // Extract token name and confidence
                const tokenName = data.name || mint.substring(0, 6) + '...' + mint.substring(mint.length - 4);
                const confidence = data.confidence || 0;
                const reason = data.reason || 'Unknown';
                
                // Determine confidence class
                let confidenceClass = 'bg-success';
                if (confidence > 80) {
                    confidenceClass = 'bg-danger';
                } else if (confidence > 50) {
                    confidenceClass = 'bg-warning';
                }
                
                html += `
                    <tr>
                        <td>
                            <div class="d-flex align-items-center">
                                <span class="badge bg-danger me-2">HP</span>
                                ${tokenName}
                            </div>
                            <div class="small text-muted">${mint.substring(0, 10)}...</div>
                        </td>
                        <td>
                            <div class="progress" style="height: 15px;">
                                <div class="progress-bar ${confidenceClass}" role="progressbar" 
                                    style="width: ${confidence}%;" 
                                    aria-valuenow="${confidence}" 
                                    aria-valuemin="0" 
                                    aria-valuemax="100">
                                    ${confidence}%
                                </div>
                            </div>
                        </td>
                        <td>${reason}</td>
                    </tr>
                `;
            }
            
            html += `
                        </tbody>
                    </table>
                </div>
                <div class="text-end">
                    <a href="/honeypots" class="btn btn-sm btn-outline-primary">View All Honeypots</a>
                </div>
            `;
            
            container.innerHTML = html;
        })
        .catch(error => {
            console.error('Error loading honeypot detections:', error);
            container.innerHTML = `
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-circle"></i>
                    Failed to load honeypot detections.
                </div>
            `;
        });
}

/**
 * Load suspicious activities
 */
function loadSuspiciousActivities() {
    const container = document.getElementById('suspiciousActivities');
    
    if (!container) return Promise.resolve();
    
    container.innerHTML = `
        <div class="d-flex justify-content-center">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
        </div>
    `;
    
    return fetch('/api/suspicious?limit=5')
        .then(response => response.json())
        .then(activities => {
            if (activities.length === 0) {
                container.innerHTML = `
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle"></i>
                        No suspicious activities detected.
                    </div>
                `;
                return;
            }
            
            let html = `
                <div class="list-group">
            `;
            
            activities.forEach(activity => {
                // Determine alert level
                let alertLevel = 'warning';
                
                if (activity.reason?.includes('Unsellable token') || 
                    activity.reason?.includes('rug pull') ||
                    activity.reason?.includes('exploit')) {
                    alertLevel = 'danger';
                } else if (activity.reason?.includes('Suspicious')) {
                    alertLevel = 'warning';
                }
                
                html += `
                    <div class="list-group-item list-group-item-${alertLevel} d-flex justify-content-between align-items-start">
                        <div class="ms-2 me-auto">
                            <div class="fw-bold">${activity.address.substring(0, 8)}...</div>
                            ${activity.reason}
                        </div>
                        <span class="badge bg-${alertLevel} rounded-pill">${activity.timestamp || 'Unknown'}</span>
                    </div>
                `;
            });
            
            html += `
                </div>
                <div class="text-end mt-2">
                    <a href="/suspicious" class="btn btn-sm btn-outline-primary">View All Activities</a>
                </div>
            `;
            
            container.innerHTML = html;
        })
        .catch(error => {
            console.error('Error loading suspicious activities:', error);
            container.innerHTML = `
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-circle"></i>
                    Failed to load suspicious activities.
                </div>
            `;
        });
}

/**
 * Load token distribution
 */
function loadTokenDistribution() {
    const container = document.getElementById('tokenDistributionChart');
    
    if (!container) return Promise.resolve();
    
    const loadingOverlay = document.createElement('div');
    loadingOverlay.className = 'loading-overlay';
    loadingOverlay.innerHTML = `
        <div class="spinner-border text-primary" role="status">
            <span class="visually-hidden">Loading...</span>
        </div>
    `;
    
    // Add loading overlay
    container.parentNode.style.position = 'relative';
    container.parentNode.appendChild(loadingOverlay);
    
    return loadDashboardData('30d')
        .then(data => {
            // Remove loading overlay
            container.parentNode.removeChild(loadingOverlay);
            
            // Update token distribution chart
            updateTokenDistributionChart(data.token_distribution);
            
            return data;
        })
        .catch(error => {
            console.error('Error loading token distribution:', error);
            // Remove loading overlay
            container.parentNode.removeChild(loadingOverlay);
            
            // Show error message
            const errorMsg = document.createElement('div');
            errorMsg.className = 'alert alert-danger';
            errorMsg.innerHTML = `
                <i class="fas fa-exclamation-circle"></i>
                Failed to load token distribution data.
            `;
            
            container.parentNode.appendChild(errorMsg);
        });
}

/**
 * Load swap activity
 */
function loadSwapActivity() {
    const jupiterContainer = document.getElementById('jupiterSwaps');
    const raydiumContainer = document.getElementById('raydiumSwaps');
    
    const promises = [];
    
    if (jupiterContainer) {
        jupiterContainer.innerHTML = `
            <div class="d-flex justify-content-center">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
            </div>
        `;
        
        const jupiterPromise = fetch('/api/swaps/jupiter?limit=3')
            .then(response => response.json())
            .then(swaps => {
                if (swaps.length === 0) {
                    jupiterContainer.innerHTML = `
                        <div class="alert alert-info">
                            <i class="fas fa-info-circle"></i>
                            No recent Jupiter swaps found.
                        </div>
                    `;
                    return;
                }
                
                let html = `
                    <div class="list-group">
                `;
                
                swaps.forEach(swap => {
                    // Extract swap details
                    const fromToken = swap.from_token || 'Unknown';
                    const toToken = swap.to_token || 'Unknown';
                    const fromAmount = swap.from_amount || 0;
                    const toAmount = swap.to_amount || 0;
                    
                    html += `
                        <div class="list-group-item">
                            <div class="d-flex w-100 justify-content-between">
                                <h6 class="mb-1">${fromToken} → ${toToken}</h6>
                                <small>${swap.timestamp || 'Unknown'}</small>
                            </div>
                            <p class="mb-1">
                                <span class="text-danger">-${fromAmount} ${fromToken}</span>
                                <i class="fas fa-arrow-right mx-2"></i>
                                <span class="text-success">+${toAmount} ${toToken}</span>
                            </p>
                            <small class="text-muted">
                                Price Impact: ${swap.price_impact || 'Unknown'} | 
                                Slippage: ${swap.slippage || 'Unknown'}
                            </small>
                        </div>
                    `;
                });
                
                html += `
                    </div>
                    <div class="text-end mt-2">
                        <a href="/swaps" class="btn btn-sm btn-outline-primary">View All Swaps</a>
                    </div>
                `;
                
                jupiterContainer.innerHTML = html;
            })
            .catch(error => {
                console.error('Error loading Jupiter swaps:', error);
                jupiterContainer.innerHTML = `
                    <div class="alert alert-danger">
                        <i class="fas fa-exclamation-circle"></i>
                        Failed to load Jupiter swaps.
                    </div>
                `;
            });
            
        promises.push(jupiterPromise);
    }
    
    if (raydiumContainer) {
        raydiumContainer.innerHTML = `
            <div class="d-flex justify-content-center">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
            </div>
        `;
        
        const raydiumPromise = fetch('/api/swaps/raydium?limit=3')
            .then(response => response.json())
            .then(swaps => {
                if (swaps.length === 0) {
                    raydiumContainer.innerHTML = `
                        <div class="alert alert-info">
                            <i class="fas fa-info-circle"></i>
                            No recent Raydium swaps found.
                        </div>
                    `;
                    return;
                }
                
                let html = `
                    <div class="list-group">
                `;
                
                swaps.forEach(swap => {
                    // Extract swap details
                    const fromToken = swap.from_token || 'Unknown';
                    const toToken = swap.to_token || 'Unknown';
                    const fromAmount = swap.from_amount || 0;
                    const toAmount = swap.to_amount || 0;
                    
                    html += `
                        <div class="list-group-item">
                            <div class="d-flex w-100 justify-content-between">
                                <h6 class="mb-1">${fromToken} → ${toToken}</h6>
                                <small>${swap.timestamp || 'Unknown'}</small>
                            </div>
                            <p class="mb-1">
                                <span class="text-danger">-${fromAmount} ${fromToken}</span>
                                <i class="fas fa-arrow-right mx-2"></i>
                                <span class="text-success">+${toAmount} ${toToken}</span>
                            </p>
                            <small class="text-muted">
                                Price Impact: ${swap.price_impact || 'Unknown'} | 
                                Pool: ${swap.pool_id?.substring(0, 8) || 'Unknown'}...
                            </small>
                        </div>
                    `;
                });
                
                html += `
                    </div>
                    <div class="text-end mt-2">
                        <a href="/swaps" class="btn btn-sm btn-outline-primary">View All Swaps</a>
                    </div>
                `;
                
                raydiumContainer.innerHTML = html;
            })
            .catch(error => {
                console.error('Error loading Raydium swaps:', error);
                raydiumContainer.innerHTML = `
                    <div class="alert alert-danger">
                        <i class="fas fa-exclamation-circle"></i>
                        Failed to load Raydium swaps.
                    </div>
                `;
            });
            
        promises.push(raydiumPromise);
    }
    
    return Promise.all(promises);
}

// Chart update functions

/**
 * Update transaction volume chart
 * @param {Object} data 
 */
function updateTransactionVolumeChart(data) {
    const ctx = document.getElementById('transactionVolumeChart');
    
    if (!ctx) return;
    
    // Destroy existing chart if it exists
    if (window.transactionVolumeChart) {
        window.transactionVolumeChart.destroy();
    }
    
    // Create new chart
    window.transactionVolumeChart = new Chart(ctx, {
        type: 'bar',
        data: data,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top',
                },
                title: {
                    display: true,
                    text: 'Transaction Volume'
                }
            }
        }
    });
}

/**
 * Update transaction types chart
 * @param {Object} data 
 */
function updateTransactionTypesChart(data) {
    const ctx = document.getElementById('transactionTypesChart');
    
    if (!ctx) return;
    
    // Destroy existing chart if it exists
    if (window.transactionTypesChart) {
        window.transactionTypesChart.destroy();
    }
    
    // Create new chart
    window.transactionTypesChart = new Chart(ctx, {
        type: 'doughnut',
        data: data,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top',
                },
                title: {
                    display: true,
                    text: 'Transaction Types'
                }
            }
        }
    });
}

/**
 * Update token distribution chart
 * @param {Object} data 
 */
function updateTokenDistributionChart(data) {
    const ctx = document.getElementById('tokenDistributionChart');
    
    if (!ctx) return;
    
    // Destroy existing chart if it exists
    if (window.tokenDistributionChart) {
        window.tokenDistributionChart.destroy();
    }
    
    // Create new chart
    window.tokenDistributionChart = new Chart(ctx, {
        type: 'pie',
        data: data,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top',
                },
                title: {
                    display: true,
                    text: 'Token Distribution'
                }
            }
        }
    });
}

/**
 * Update program interactions chart
 * @param {Object} data 
 */
function updateProgramInteractionsChart(data) {
    const ctx = document.getElementById('programsChart');
    
    if (!ctx) return;
    
    // Destroy existing chart if it exists
    if (window.programsChart) {
        window.programsChart.destroy();
    }
    
    // Create new chart
    window.programsChart = new Chart(ctx, {
        type: 'bar',
        data: data,
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top',
                },
                title: {
                    display: true,
                    text: 'Program Interactions'
                }
            }
        }
    });
}

/**
 * Update risk score display
 * @param {number} score 
 */
function updateRiskScore(score) {
    const riskScoreElement = document.getElementById('riskScoreBar');
    
    if (!riskScoreElement) return;
    
    // Determine risk level and color
    let riskLevel, progressClass;
    
    if (score < 25) {
        riskLevel = 'Low Risk';
        progressClass = 'bg-success';
    } else if (score < 50) {
        riskLevel = 'Moderate Risk';
        progressClass = 'bg-info';
    } else if (score < 75) {
        riskLevel = 'High Risk';
        progressClass = 'bg-warning';
    } else {
        riskLevel = 'Critical Risk';
        progressClass = 'bg-danger';
    }
    
    // Update risk score display
    riskScoreElement.style.width = `${score}%`;
    riskScoreElement.setAttribute('aria-valuenow', score);
    riskScoreElement.className = `progress-bar ${progressClass}`;
    riskScoreElement.textContent = `${Math.round(score)}% - ${riskLevel}`;
}

/**
 * Update metrics display
 * @param {Object} metrics 
 */
function updateMetrics(metrics) {
    document.getElementById('totalTransactions')?.textContent = metrics.total_transactions;
    document.getElementById('incomingTx')?.textContent = metrics.incoming;
    document.getElementById('outgoingTx')?.textContent = metrics.outgoing;
    document.getElementById('swapTx')?.textContent = metrics.swaps;
}

/**
 * Show transaction details modal
 * @param {string} signature 
 */
function showTransactionDetails(signature) {
    const modal = document.getElementById('transactionDetailsModal');
    const modalBody = modal.querySelector('.modal-body');
    const modalTitle = modal.querySelector('.modal-title');
    
    // Set modal title
    modalTitle.textContent = `Transaction Details: ${signature.substring(0, 8)}...`;
    
    // Show loading indicator
    modalBody.innerHTML = `
        <div class="d-flex justify-content-center">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
        </div>
    `;
    
    // Initialize modal
    const bsModal = new bootstrap.Modal(modal);
    bsModal.show();
    
    // Fetch transaction details
    fetch(`/api/transaction/${signature}`)
        .then(response => response.json())
        .then(tx => {
            let html = `
                <div class="mb-3">
                    <h6>Transaction Information</h6>
                    <dl class="row">
                        <dt class="col-sm-3">Signature</dt>
                        <dd class="col-sm-9">
                            <a href="https://explorer.solana.com/tx/${signature}" target="_blank">
                                ${signature}
                            </a>
                        </dd>
                        
                        <dt class="col-sm-3">Block Time</dt>
                        <dd class="col-sm-9">${tx.date || 'Unknown'}</dd>
                        
                        <dt class="col-sm-3">Slot</dt>
                        <dd class="col-sm-9">${tx.slot || 'Unknown'}</dd>
                        
                        <dt class="col-sm-3">Status</dt>
                        <dd class="col-sm-9">
                            <span class="badge bg-success">Success</span>
                        </dd>
                    </dl>
                </div>
                
                <div class="mb-3">
                    <h6>Events</h6>
                    <div class="table-responsive">
                        <table class="table table-sm">
                            <thead>
                                <tr>
                                    <th>Type</th>
                                    <th>Details</th>
                                </tr>
                            </thead>
                            <tbody>
            `;
            
            // Add events
            tx.events?.forEach(event => {
                let details = '';
                
                if (event.type === 'sol_transfer') {
                    details = `${event.direction === 'Received' ? 'From' : 'To'}: ${event.other_address}
                              <br/>Amount: ${event.amount} SOL`;
                } else if (event.type === 'token_transfer') {
                    details = `Token: ${event.token_name || 'Unknown'}
                              <br/>${event.direction === 'Received' ? 'From' : 'To'}: ${event.other_address}
                              <br/>Amount: ${event.amount}`;
                } else if (event.type === 'swap') {
                    details = `From: ${event.from_token || 'Unknown'} (${event.from_amount})
                              <br/>To: ${event.to_token || 'Unknown'} (${event.to_amount})
                              <br/>Exchange: ${event.exchange || 'Unknown'}`;
                }
                
                html += `
                    <tr>
                        <td>${event.type}</td>
                        <td>${details}</td>
                    </tr>
                `;
            });
            
            html += `
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <div class="mb-3">
                    <h6>Programs</h6>
                    <ul class="list-group">
            `;
            
            // Add programs
            tx.programs?.forEach(program => {
                html += `
                    <li class="list-group-item d-flex justify-content-between align-items-center">
                        ${program.name || 'Unknown'}
                        <span class="badge bg-primary rounded-pill">${program.program_id?.substring(0, 8)}...</span>
                    </li>
                `;
            });
            
            html += `
                    </ul>
                </div>
            `;
            
            modalBody.innerHTML = html;
        })
        .catch(error => {
            console.error('Error fetching transaction details:', error);
            modalBody.innerHTML = `
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-circle"></i>
                    Failed to load transaction details.
                </div>
            `;
        });
}

/**
 * Initialize tooltips and popovers
 */
function initializeTooltips() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Initialize popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
}

/**
 * Show toast notification
 * @param {string} title 
 * @param {string} message 
 * @param {string} type 
 */
function showToast(title, message, type = 'info') {
    // Create toast container if it doesn't exist
    let toastContainer = document.querySelector('.toast-container');
    
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.className = 'toast-container position-fixed bottom-0 end-0 p-3';
        document.body.appendChild(toastContainer);
    }
    
    // Create toast
    const toastId = 'toast-' + Date.now();
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-white bg-${type} border-0`;
    toast.id = toastId;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');
    
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                <strong>${title}</strong>
                <br/>
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
    `;
    
    // Add toast to container
    toastContainer.appendChild(toast);
    
    // Initialize toast
    const bsToast = new bootstrap.Toast(toast, {
        autohide: true,
        delay: 5000
    });
    
    // Show toast
    bsToast.show();
    
    // Remove toast from DOM after it's hidden
    toast.addEventListener('hidden.bs.toast', () => {
        toast.remove();
    });
}