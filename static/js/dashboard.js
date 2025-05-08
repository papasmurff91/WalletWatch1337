/**

document.addEventListener('DOMContentLoaded', () => {
    loadDonationInfo();
});

function loadDonationInfo() {
    fetch('/api/donations')
        .then(response => response.json())
        .then(data => {
            document.getElementById('donationBalance').textContent = data.balance.toFixed(4); // assuming balance is in ETH
            const donorList = document.getElementById('donorList');
            donorList.innerHTML = ''; // Clear existing donors
            data.recent_donors.forEach(donor => {
                const listItem = document.createElement('li');
                listItem.textContent = `${donor.name}: ${donor.amount.toFixed(4)} ETH`;
                donorList.appendChild(listItem);
            });
        })
        .catch(error => {
            console.error('Error loading donations:', error);
            document.getElementById('donationBalance').textContent = 'Error fetching data';
        });
}

 * Dashboard functionality for Solana Wallet Monitor
 */

document.addEventListener('DOMContentLoaded', () => {
    refreshData();
    
    // Refresh data every 30 seconds
    setInterval(refreshData, 30000);
});

/**
 * Refresh all dashboard data
 */
function refreshData() {
    loadTransactions();
    loadHoneypots();
    loadWhitelist();
    loadFlaggedActivities();
    loadJupiterSwaps();
    loadRaydiumSwaps();
}

/**
 * Load transaction data
 */
function loadTransactions() {
    const transactionsContainer = document.getElementById('recentTransactions');
    
    fetch('/api/transactions?limit=5')
        .then(response => response.json())
        .then(data => {
            if (data.length === 0) {
                transactionsContainer.innerHTML = '<p class="text-center">No transactions found.</p>';
                return;
            }
            
            let html = '<div class="list-group">';
            
            data.forEach(tx => {
                const hasHoneypot = tx.honeypot_flags.length > 0;
                const hasSuspicious = tx.suspicious_flags && tx.suspicious_flags.length > 0;
                
                let badgeHtml = '';
                let itemClass = 'list-group-item-action';
                
                if (hasHoneypot) {
                    badgeHtml += '<span class="badge bg-danger ms-2">Honeypot</span>';
                    itemClass = 'list-group-item-danger';
                }
                
                if (hasSuspicious) {
                    badgeHtml += '<span class="badge bg-warning text-dark ms-2">Suspicious</span>';
                    if (!hasHoneypot) {
                        itemClass = 'list-group-item-warning';
                    }
                }
                
                // Get event summary
                let eventSummary = '';
                
                tx.events.forEach(event => {
                    if (event.type === 'sol_transfer') {
                        eventSummary += `
                            <span class="badge bg-warning text-dark me-1">
                                ${event.direction} ${event.amount.toFixed(4)} SOL
                            </span>
                        `;
                    } else if (event.type === 'token_transfer') {
                        let badgeClass = 'bg-info';
                        if (hasHoneypot) {
                            tx.honeypot_flags.forEach(flag => {
                                if (flag.mint === event.mint) {
                                    badgeClass = 'bg-danger';
                                }
                            });
                        }
                        
                        eventSummary += `
                            <span class="badge ${badgeClass} me-1">
                                ${event.direction} ${event.amount.toFixed(4)} ${event.token_name}
                            </span>
                        `;
                    } else if (event.type === 'swap') {
                        eventSummary += '<span class="badge bg-primary me-1">Swap</span>';
                    }
                });
                
                html += `
                    <a href="/transactions" class="list-group-item ${itemClass}">
                        <div class="d-flex justify-content-between align-items-center">
                            <small class="text-muted">${tx.timestamp}</small>
                            <div>${badgeHtml}</div>
                        </div>
                        <div class="mt-1">
                            ${eventSummary}
                        </div>
                        <div class="mt-1">
                            <small class="text-truncate d-inline-block" style="max-width: 100%;">
                                ${tx.signature}
                            </small>
                        </div>
                    </a>
                `;
            });
            
            html += '</div>';
            
            transactionsContainer.innerHTML = html;
        })
        .catch(error => {
            console.error('Error loading transactions:', error);
            transactionsContainer.innerHTML = '<p class="text-center text-danger">Error loading transactions.</p>';
        });
}

/**
 * Load honeypot token data
 */
function loadHoneypots() {
    const honeypotContainer = document.getElementById('honeypotTokens');
    
    fetch('/api/honeypots')
        .then(response => response.json())
        .then(data => {
            if (data.length === 0) {
                honeypotContainer.innerHTML = '<p class="text-center">No honeypot tokens detected yet.</p>';
                return;
            }
            
            let html = '<div class="list-group">';
            
            data.slice(0, 3).forEach(token => {
                html += `
                    <a href="/honeypots" class="list-group-item list-group-item-danger list-group-item-action">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <span class="badge bg-danger">Honeypot</span>
                            </div>
                            <div>
                                <small>$${token.price.toFixed(6)}</small>
                            </div>
                        </div>
                        <div class="mt-1">
                            <small class="text-truncate d-inline-block" style="max-width: 100%;">
                                ${token.mint}
                            </small>
                        </div>
                    </a>
                `;
            });
            
            if (data.length > 3) {
                html += `
                    <a href="/honeypots" class="list-group-item list-group-item-action text-center">
                        <small>View all ${data.length} honeypot tokens</small>
                    </a>
                `;
            }
            
            html += '</div>';
            
            honeypotContainer.innerHTML = html;
        })
        .catch(error => {
            console.error('Error loading honeypots:', error);
            honeypotContainer.innerHTML = '<p class="text-center text-danger">Error loading honeypot data.</p>';
        });
}

/**
 * Load whitelisted token data
 */
function loadWhitelist() {
    const whitelistContainer = document.getElementById('whitelistedTokens');
    
    fetch('/api/whitelist')
        .then(response => response.json())
        .then(data => {
            if (data.length === 0) {
                whitelistContainer.innerHTML = '<p class="text-center">No whitelisted tokens yet.</p>';
                return;
            }
            
            let html = '<div class="list-group">';
            
            data.slice(0, 3).forEach(token => {
                html += `
                    <a href="/honeypots" class="list-group-item list-group-item-action">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <span class="badge bg-success">Whitelisted</span>
                            </div>
                            <div>
                                <small>$${token.price.toFixed(6)}</small>
                            </div>
                        </div>
                        <div>
                            <small>${token.name}</small>
                        </div>
                        <div class="mt-1">
                            <small class="text-truncate d-inline-block" style="max-width: 100%;">
                                ${token.mint}
                            </small>
                        </div>
                    </a>
                `;
            });
            
            if (data.length > 3) {
                html += `
                    <a href="/honeypots" class="list-group-item list-group-item-action text-center">
                        <small>View all ${data.length} whitelisted tokens</small>
                    </a>
                `;
            }
            
            html += '</div>';
            
            whitelistContainer.innerHTML = html;
        })
        .catch(error => {
            console.error('Error loading whitelist:', error);
            whitelistContainer.innerHTML = '<p class="text-center text-danger">Error loading whitelist data.</p>';
        });
}

/**
 * Load flagged suspicious activities
 */
function loadFlaggedActivities() {
    const flaggedActivitiesContainer = document.getElementById('flaggedActivities');
    
    fetch('/api/suspicious?limit=5')
        .then(response => response.json())
        .then(data => {
            if (data.length === 0) {
                flaggedActivitiesContainer.innerHTML = '<p class="text-center">No suspicious activities detected yet.</p>';
                return;
            }
            
            let html = '<div class="list-group">';
            
            data.forEach(activity => {
                // Determine the severity level based on the type of suspicious activity
                let severityClass = '';
                let severityLabel = '';
                
                if (activity.reason.includes('Unsellable token') || activity.reason.includes('rug pull')) {
                    severityClass = 'danger';
                    severityLabel = 'CRITICAL';
                } else if (activity.reason.includes('Flash launch') || activity.reason.includes('Cross-chain transfer')) {
                    severityClass = 'warning';
                    severityLabel = 'HIGH';
                } else {
                    severityClass = 'info';
                    severityLabel = 'MEDIUM';
                }
                
                html += `
                    <a href="/suspicious" class="list-group-item list-group-item-${severityClass} list-group-item-action">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <span class="badge bg-${severityClass}">${severityLabel}</span>
                                <span class="ms-2">${activity.timestamp || 'Unknown time'}</span>
                            </div>
                            <div>
                                <small class="text-truncate" style="max-width: 200px; display: inline-block;">
                                    ${activity.address || 'Unknown address'}
                                </small>
                            </div>
                        </div>
                        <div class="mt-2">
                            <strong style="color: #dc3545; font-weight: bold;">${activity.reason}</strong>
                        </div>
                        <div class="mt-1">
                            <small>${activity.details || ''}</small>
                        </div>
                    </a>
                `;
            });
            
            html += '</div>';
            
            flaggedActivitiesContainer.innerHTML = html;
        })
        .catch(error => {
            console.error('Error loading suspicious activities:', error);
            flaggedActivitiesContainer.innerHTML = '<p class="text-center text-danger">Error loading suspicious activities data.</p>';
        });
}

/**
 * Load Jupiter swap alerts
 */
function loadJupiterSwaps() {
    const jupiterAlertsContainer = document.getElementById('jupiterSwapAlerts');
    
    fetch('/api/swaps/jupiter?limit=3')
        .then(response => response.json())
        .then(data => {
            if (data.length === 0) {
                jupiterAlertsContainer.innerHTML = '<p class="text-center">No Jupiter swap alerts yet.</p>';
                return;
            }
            
            let html = '<div class="list-group">';
            
            data.forEach(swap => {
                const swapDetails = swap.swap_details || {};
                const riskLevel = swapDetails.risk_level || 'low';
                const riskFactors = swapDetails.risk_factors || [];
                let riskClass = 'primary';
                
                if (riskLevel === 'high') {
                    riskClass = 'danger';
                } else if (riskLevel === 'medium') {
                    riskClass = 'warning';
                }
                
                // Check for associated accounts
                const associatedAccounts = swap.associated_accounts || [];
                let accountsHtml = '';
                
                if (associatedAccounts.length > 0) {
                    accountsHtml = '<div class="mt-2"><strong>Associated Accounts:</strong>';
                    associatedAccounts.forEach(account => {
                        accountsHtml += `
                            <div class="mt-1">
                                <span class="badge bg-info me-1">${account.tag || 'unknown'}</span>
                                <small>${account.platform || ''} ${account.username ? '@' + account.username : ''}</small>
                            </div>
                        `;
                    });
                    accountsHtml += '</div>';
                }
                
                html += `
                    <div class="list-group-item list-group-item-${riskClass}">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <span class="badge bg-${riskClass}">${riskLevel.toUpperCase()} RISK</span>
                                <span class="ms-2">${swap.timestamp || 'Unknown time'}</span>
                            </div>
                            <div>
                                <small>Jupiter ${swapDetails.jupiter_version || ''}</small>
                            </div>
                        </div>
                        <div class="mt-2">
                            <span class="badge bg-light text-dark me-1">
                                ${swapDetails.input_amount?.toFixed(4) || '?'} ${swapDetails.input_token || 'Unknown'}
                            </span>
                            <i class="fas fa-arrow-right"></i>
                            <span class="badge ${riskClass === 'danger' ? 'bg-danger' : 'bg-primary'} me-1">
                                ${swapDetails.output_amount?.toFixed(4) || '?'} ${swapDetails.output_token || 'Unknown'}
                            </span>
                        </div>
                        ${riskFactors.length > 0 ? 
                            `<div class="mt-2">
                                <strong>Risk Factors:</strong>
                                <ul class="mb-0 mt-1">
                                    ${riskFactors.map(factor => `<li><small>${factor}</small></li>`).join('')}
                                </ul>
                            </div>` : ''
                        }
                        ${accountsHtml}
                        <div class="mt-2">
                            <small class="text-truncate d-inline-block" style="max-width: 100%;">
                                ${swap.signature || ''}
                            </small>
                        </div>
                    </div>
                `;
            });
            
            html += '</div>';
            
            jupiterAlertsContainer.innerHTML = html;
        })
        .catch(error => {
            console.error('Error loading Jupiter swaps:', error);
            jupiterAlertsContainer.innerHTML = '<p class="text-center text-danger">Error loading Jupiter swap data.</p>';
        });
}

/**
 * Load Raydium swap alerts
 */
function loadRaydiumSwaps() {
    const raydiumAlertsContainer = document.getElementById('raydiumSwapAlerts');
    
    fetch('/api/swaps/raydium?limit=3')
        .then(response => response.json())
        .then(data => {
            if (data.length === 0) {
                raydiumAlertsContainer.innerHTML = '<p class="text-center">No Raydium swap alerts yet.</p>';
                return;
            }
            
            let html = '<div class="list-group">';
            
            data.forEach(swap => {
                const swapDetails = swap.swap_details || {};
                const riskLevel = swapDetails.risk_level || 'low';
                const riskFactors = swapDetails.risk_factors || [];
                let riskClass = 'primary';
                
                if (riskLevel === 'high') {
                    riskClass = 'danger';
                } else if (riskLevel === 'medium') {
                    riskClass = 'warning';
                }
                
                html += `
                    <div class="list-group-item list-group-item-${riskClass}">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <span class="badge bg-${riskClass}">${riskLevel.toUpperCase()} RISK</span>
                                <span class="ms-2">${swap.timestamp || 'Unknown time'}</span>
                            </div>
                            <div>
                                <small>Raydium</small>
                            </div>
                        </div>
                        <div class="mt-2">
                            <span class="badge bg-light text-dark me-1">
                                ${swapDetails.input_amount?.toFixed(4) || '?'} ${swapDetails.input_token || 'Unknown'}
                            </span>
                            <i class="fas fa-arrow-right"></i>
                            <span class="badge ${riskClass === 'danger' ? 'bg-danger' : 'bg-primary'} me-1">
                                ${swapDetails.output_amount?.toFixed(4) || '?'} ${swapDetails.output_token || 'Unknown'}
                            </span>
                        </div>
                        ${riskFactors.length > 0 ? 
                            `<div class="mt-2">
                                <strong>Risk Factors:</strong>
                                <ul class="mb-0 mt-1">
                                    ${riskFactors.map(factor => `<li><small>${factor}</small></li>`).join('')}
                                </ul>
                            </div>` : ''
                        }
                        <div class="mt-2">
                            <small class="text-truncate d-inline-block" style="max-width: 100%;">
                                ${swap.signature || ''}
                            </small>
                        </div>
                    </div>
                `;
            });
            
            html += '</div>';
            
            raydiumAlertsContainer.innerHTML = html;
        })
        .catch(error => {
            console.error('Error loading Raydium swaps:', error);
            raydiumAlertsContainer.innerHTML = '<p class="text-center text-danger">Error loading Raydium swap data.</p>';
        });
}

/**
 * Simulate Jupiter swap alert
 */
function simulateJupiterAlert(sendNotification) {
    const jupiterAlertsContainer = document.getElementById('jupiterSwapAlerts');
    jupiterAlertsContainer.innerHTML = '<div class="d-flex justify-content-center"><div class="spinner-border text-primary" role="status"><span class="visually-hidden">Loading...</span></div></div>';
    
    // If sendNotification is true, add the query parameter to trigger notifications
    const endpoint = sendNotification 
        ? '/webhooks/jupiter/alerts?send_notification=true' 
        : '/webhooks/jupiter/alerts';
    
    fetch(endpoint)
        .then(response => response.json())
        .then(data => {
            let html = '';
            
            // If notifications were sent, show a success message
            if (data.notification_sent) {
                html = `<div class="alert alert-success">
                    <i class="fas fa-bell me-2"></i>
                    Jupiter Swap Alert sent to notification channels
                    <div class="mt-2">
                        ${data.channels.telegram ? '<span class="badge bg-primary me-1">Telegram</span>' : ''}
                        ${data.channels.discord ? '<span class="badge bg-primary me-1">Discord</span>' : ''}
                        ${data.channels.twitter ? '<span class="badge bg-primary me-1">Twitter</span>' : ''}
                    </div>
                </div>`;
            } else {
                html = '<div class="alert alert-info">Simulated Jupiter Swap Alert (no notifications sent)</div>';
            }
            
            html += '<div class="list-group">';
            
            const swap = data;
            const swapDetails = swap.swap_details || {};
            const riskAnalysis = swap.risk_analysis || {};
            const riskLevel = riskAnalysis.overall_risk || 'low';
            const riskFactors = riskAnalysis.reasons || [];
            let riskClass = 'primary';
            
            if (riskLevel === 'critical' || riskLevel === 'high') {
                riskClass = 'danger';
            } else if (riskLevel === 'medium') {
                riskClass = 'warning';
            }
            
            // Check for associated accounts
            const associatedAccounts = swap.associated_accounts || [];
            let accountsHtml = '';
            
            if (associatedAccounts.length > 0) {
                accountsHtml = '<div class="mt-2"><strong>Associated Accounts:</strong>';
                associatedAccounts.forEach(account => {
                    accountsHtml += `
                        <div class="mt-1">
                            <span class="badge bg-info me-1">${account.tag || 'unknown'}</span>
                            <small>${account.platform || ''} ${account.username ? '@' + account.username : ''}</small>
                        </div>
                    `;
                });
                accountsHtml += '</div>';
            }
            
            html += `
                <div class="list-group-item list-group-item-${riskClass}">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <span class="badge bg-${riskClass}">${riskLevel.toUpperCase()} RISK</span>
                            <span class="ms-2">${swap.timestamp || 'Unknown time'}</span>
                        </div>
                        <div>
                            <small>Jupiter ${swapDetails.jupiter_version || ''}</small>
                        </div>
                    </div>
                    <div class="mt-2">
                        <span class="badge bg-light text-dark me-1">
                            ${swapDetails.input_amount?.toFixed(4) || '?'} ${swapDetails.input_token || 'Unknown'}
                        </span>
                        <i class="fas fa-arrow-right"></i>
                        <span class="badge ${riskClass === 'danger' ? 'bg-danger' : 'bg-primary'} me-1">
                            ${swapDetails.output_amount?.toFixed(4) || '?'} ${swapDetails.output_token || 'Unknown'}
                        </span>
                    </div>
                    ${riskFactors.length > 0 ? 
                        `<div class="mt-2">
                            <strong>Risk Factors:</strong>
                            <ul class="mb-0 mt-1">
                                ${riskFactors.map(factor => `<li><small>${factor}</small></li>`).join('')}
                            </ul>
                        </div>` : ''
                    }
                    ${accountsHtml}
                    <div class="mt-2">
                        <small class="text-truncate d-inline-block" style="max-width: 100%;">
                            ${swap.signature || ''}
                        </small>
                    </div>
                </div>
            `;
            
            html += '</div>';
            
            jupiterAlertsContainer.innerHTML = html;
        })
        .catch(error => {
            console.error('Error loading Jupiter alert:', error);
            jupiterAlertsContainer.innerHTML = '<p class="text-center text-danger">Error loading Jupiter alert data.</p>';
        });
}

/**
 * Simulate Raydium swap alert
 */
function simulateRaydiumAlert() {
    const raydiumAlertsContainer = document.getElementById('raydiumSwapAlerts');
    raydiumAlertsContainer.innerHTML = '<div class="d-flex justify-content-center"><div class="spinner-border text-warning" role="status"><span class="visually-hidden">Loading...</span></div></div>';
    
    fetch('/webhooks/raydium/alerts')
        .then(response => response.json())
        .then(data => {
            let html = '<div class="alert alert-info">Simulated Raydium Swap Alert</div>';
            
            html += '<div class="list-group">';
            
            const swap = data;
            const swapDetails = swap.swap_details || {};
            const riskAnalysis = swap.risk_analysis || {};
            const riskLevel = riskAnalysis.overall_risk || 'low';
            const riskFactors = riskAnalysis.reasons || [];
            let riskClass = 'primary';
            
            if (riskLevel === 'critical' || riskLevel === 'high') {
                riskClass = 'danger';
            } else if (riskLevel === 'medium') {
                riskClass = 'warning';
            }
            
            html += `
                <div class="list-group-item list-group-item-${riskClass}">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <span class="badge bg-${riskClass}">${riskLevel.toUpperCase()} RISK</span>
                            <span class="ms-2">${swap.timestamp || 'Unknown time'}</span>
                        </div>
                        <div>
                            <small>Raydium</small>
                        </div>
                    </div>
                    <div class="mt-2">
                        <span class="badge bg-light text-dark me-1">
                            ${swapDetails.input_amount?.toFixed(4) || '?'} ${swapDetails.input_token || 'Unknown'}
                        </span>
                        <i class="fas fa-arrow-right"></i>
                        <span class="badge ${riskClass === 'danger' ? 'bg-danger' : 'bg-primary'} me-1">
                            ${swapDetails.output_amount?.toFixed(4) || '?'} ${swapDetails.output_token || 'Unknown'}
                        </span>
                    </div>
                    ${riskFactors.length > 0 ? 
                        `<div class="mt-2">
                            <strong>Risk Factors:</strong>
                            <ul class="mb-0 mt-1">
                                ${riskFactors.map(factor => `<li><small>${factor}</small></li>`).join('')}
                            </ul>
                        </div>` : ''
                    }
                    <div class="mt-2">
                        <small class="text-truncate d-inline-block" style="max-width: 100%;">
                            ${swap.signature || ''}
                        </small>
                    </div>
                </div>
            `;
            
            html += '</div>';
            
            raydiumAlertsContainer.innerHTML = html;
        })
        .catch(error => {
            console.error('Error loading Raydium alert:', error);
            raydiumAlertsContainer.innerHTML = '<p class="text-center text-danger">Error loading Raydium alert data.</p>';
        });
}