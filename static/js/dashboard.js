/**
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