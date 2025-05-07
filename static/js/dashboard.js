/**
 * Dashboard functionality for Solana Wallet Monitor
 */

// Initialize data refresh
let refreshInterval = null;

// Start data refresh when document is ready
document.addEventListener('DOMContentLoaded', () => {
    // Initialize Feather icons if present on page
    if (typeof feather !== 'undefined') {
        feather.replace();
    }
    
    // Set up data refresh
    refreshData();
    
    // Refresh data every 30 seconds
    refreshInterval = setInterval(refreshData, 30000);
});

/**
 * Refresh all dashboard data
 */
function refreshData() {
    // Check if these elements exist on the current page
    if (document.getElementById('transactionList')) {
        loadTransactions();
    }
    
    if (document.getElementById('honeypotList')) {
        loadHoneypots();
    }
    
    if (document.getElementById('whitelistList')) {
        loadWhitelist();
    }
}

/**
 * Load transaction data
 */
function loadTransactions() {
    fetch('/api/transactions?limit=5')
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            const container = document.getElementById('transactionList');
            
            if (!data || data.length === 0) {
                container.innerHTML = '<p class="text-center">No transactions detected yet.</p>';
                return;
            }
            
            let html = '<div class="list-group">';
            data.forEach(tx => {
                let eventSummary = '';
                tx.events.forEach(event => {
                    if (event.type === 'sol_transfer') {
                        eventSummary += `<span class="badge bg-warning text-dark me-1">
                            ${event.direction} ${event.amount.toFixed(4)} SOL
                        </span>`;
                    } else if (event.type === 'token_transfer') {
                        let badgeClass = 'bg-info';
                        // Check if this is a honeypot token
                        tx.honeypot_flags.forEach(flag => {
                            if (flag.mint === event.mint) {
                                badgeClass = 'bg-danger';
                            }
                        });
                        
                        eventSummary += `<span class="badge ${badgeClass} me-1">
                            ${event.direction} ${event.amount.toFixed(4)} ${event.token_name}
                        </span>`;
                    } else if (event.type === 'swap') {
                        eventSummary += `<span class="badge bg-primary me-1">Swap</span>`;
                    }
                });
                
                html += `
                    <a href="https://solscan.io/tx/${tx.signature}" target="_blank" class="list-group-item list-group-item-action">
                        <div class="d-flex w-100 justify-content-between">
                            <h6 class="mb-1 text-truncate" style="max-width: 60%;">${tx.signature}</h6>
                            <small>${tx.timestamp}</small>
                        </div>
                        <div class="mt-2">
                            ${eventSummary}
                        </div>
                    </a>
                `;
            });
            html += '</div>';
            container.innerHTML = html;
        })
        .catch(error => {
            console.error('Error loading transactions:', error);
            const container = document.getElementById('transactionList');
            container.innerHTML = '<p class="text-center text-danger">Error loading transaction data.</p>';
        });
}

/**
 * Load honeypot token data
 */
function loadHoneypots() {
    fetch('/api/honeypots')
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            const container = document.getElementById('honeypotList');
            
            if (!data || data.length === 0) {
                container.innerHTML = '<p class="text-center">No honeypot tokens detected yet.</p>';
                return;
            }
            
            let html = '<ul class="list-group">';
            data.forEach(token => {
                html += `
                    <li class="list-group-item d-flex justify-content-between align-items-center">
                        <div>
                            <span class="badge bg-danger me-2">Honeypot</span>
                            ${token.mint.slice(0, 8)}...${token.mint.slice(-8)}
                        </div>
                        <div>
                            <span class="badge bg-secondary">${token.holders} holders</span>
                            <button class="btn btn-sm btn-outline-success ms-2" onclick="whitelistToken('${token.mint}')">
                                Whitelist
                            </button>
                        </div>
                    </li>
                `;
            });
            html += '</ul>';
            container.innerHTML = html;
        })
        .catch(error => {
            console.error('Error loading honeypots:', error);
            const container = document.getElementById('honeypotList');
            container.innerHTML = '<p class="text-center text-danger">Error loading honeypot data.</p>';
        });
}

/**
 * Load whitelisted token data
 */
function loadWhitelist() {
    fetch('/api/whitelist')
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            const container = document.getElementById('whitelistList');
            
            if (!data || data.length === 0) {
                container.innerHTML = '<p class="text-center">No whitelisted tokens yet.</p>';
                return;
            }
            
            let html = '<ul class="list-group">';
            data.forEach(token => {
                html += `
                    <li class="list-group-item d-flex justify-content-between align-items-center">
                        <div>
                            <span class="badge bg-success me-2">Safe</span>
                            ${token.name}
                        </div>
                        <div>
                            <span class="badge bg-primary">$${token.price.toFixed(4)}</span>
                        </div>
                    </li>
                `;
            });
            html += '</ul>';
            container.innerHTML = html;
        })
        .catch(error => {
            console.error('Error loading whitelist:', error);
            const container = document.getElementById('whitelistList');
            container.innerHTML = '<p class="text-center text-danger">Error loading whitelist data.</p>';
        });
}

/**
 * Whitelist a token
 */
function whitelistToken(mint) {
    fetch(`/api/whitelist/${mint}`, {
        method: 'POST'
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        if (data.success) {
            // Refresh data
            loadHoneypots();
            loadWhitelist();
        }
    })
    .catch(error => {
        console.error('Error whitelisting token:', error);
        alert('Error whitelisting token. Please try again.');
    });
}

// Clean up on page unload
window.addEventListener('beforeunload', () => {
    if (refreshInterval) {
        clearInterval(refreshInterval);
    }
});
