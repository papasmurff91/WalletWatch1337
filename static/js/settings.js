/**
 * Settings functionality for Solana Wallet Monitor
 */

document.addEventListener('DOMContentLoaded', () => {
    // Initialize form values from localStorage if available
    initializeFormValues();
    
    // Show the current webhook URL for Twitter
    updateWebhookUrl();
    
    // Add event listeners for form submissions
    document.getElementById('generalSettingsForm')?.addEventListener('submit', saveGeneralSettings);
    document.getElementById('notificationSettingsForm')?.addEventListener('submit', saveNotificationSettings);
    document.getElementById('apiKeysSettingsForm')?.addEventListener('submit', saveApiKeys);
    document.getElementById('securitySettingsForm')?.addEventListener('submit', saveSecuritySettings);
    
    // Add event listeners for Telegram test buttons
    document.getElementById('testTelegramBtn')?.addEventListener('click', testTelegramNotification);
    document.getElementById('testTelegramJupiterBtn')?.addEventListener('click', testTelegramJupiterAlert);
    
    // Add event listeners for Twitter webhook buttons
    document.getElementById('registerWebhookBtn')?.addEventListener('click', registerTwitterWebhook);
    document.getElementById('testWebhookBtn')?.addEventListener('click', testTwitterWebhook);
    document.getElementById('deleteWebhooksBtn')?.addEventListener('click', deleteTwitterWebhooks);
    document.getElementById('copyWebhookUrl')?.addEventListener('click', copyWebhookUrl);
    
    // Initialize confidence value display
    const confidenceSlider = document.getElementById('honeypotConfidenceThreshold');
    const confidenceValue = document.getElementById('confidenceValue');
    
    if (confidenceSlider && confidenceValue) {
        confidenceValue.textContent = `${confidenceSlider.value}%`;
        confidenceSlider.addEventListener('input', (e) => {
            confidenceValue.textContent = `${e.target.value}%`;
        });
    }
});

/**
 * Initialize form values from localStorage
 */
function initializeFormValues() {
    // General settings
    const walletAddress = localStorage.getItem('walletAddress');
    if (walletAddress) {
        document.getElementById('walletAddress').value = walletAddress;
    }
    
    const refreshInterval = localStorage.getItem('refreshInterval');
    if (refreshInterval) {
        document.getElementById('refreshInterval').value = refreshInterval;
    }
    
    const enableDarkMode = localStorage.getItem('darkMode');
    if (enableDarkMode) {
        document.getElementById('enableDarkMode').checked = enableDarkMode === 'true';
    }
    
    // Notification settings
    const enableDiscord = localStorage.getItem('enableDiscord');
    if (enableDiscord) {
        document.getElementById('enableDiscord').checked = enableDiscord === 'true';
    }
    
    const discordWebhook = localStorage.getItem('discordWebhook');
    if (discordWebhook) {
        document.getElementById('discordWebhook').value = discordWebhook;
    }
    
    const enableTelegram = localStorage.getItem('enableTelegram');
    if (enableTelegram) {
        document.getElementById('enableTelegram').checked = enableTelegram === 'true';
    }
    
    const telegramBotToken = localStorage.getItem('telegramBotToken');
    if (telegramBotToken) {
        document.getElementById('telegramBotToken').value = telegramBotToken;
    }
    
    const telegramChatId = localStorage.getItem('telegramChatId');
    if (telegramChatId) {
        document.getElementById('telegramChatId').value = telegramChatId;
    }
    
    // Other notification settings
    const largeTransferThreshold = localStorage.getItem('largeTransferThreshold');
    if (largeTransferThreshold) {
        document.getElementById('largeTransferThreshold').value = largeTransferThreshold;
    }
    
    // Security settings
    const enableAutoWhitelist = localStorage.getItem('enableAutoWhitelist');
    if (enableAutoWhitelist) {
        document.getElementById('enableAutoWhitelist').checked = enableAutoWhitelist === 'true';
    }
    
    const enableAdvancedSecurity = localStorage.getItem('enableAdvancedSecurity');
    if (enableAdvancedSecurity) {
        document.getElementById('enableAdvancedSecurity').checked = enableAdvancedSecurity === 'true';
    }
    
    const honeypotConfidenceThreshold = localStorage.getItem('honeypotConfidenceThreshold');
    if (honeypotConfidenceThreshold) {
        document.getElementById('honeypotConfidenceThreshold').value = honeypotConfidenceThreshold;
    }
}

/**
 * Update webhook URL display
 */
function updateWebhookUrl() {
    const webhookUrlInput = document.getElementById('webhookUrl');
    if (webhookUrlInput) {
        const protocol = window.location.protocol;
        const hostname = window.location.host;
        webhookUrlInput.value = `${protocol}//${hostname}/webhooks/twitter/activity`;
    }
}

/**
 * Copy webhook URL to clipboard
 */
function copyWebhookUrl() {
    const webhookUrlInput = document.getElementById('webhookUrl');
    if (webhookUrlInput) {
        webhookUrlInput.select();
        document.execCommand('copy');
        
        // Show a temporary success message
        const button = document.getElementById('copyWebhookUrl');
        const originalText = button.innerHTML;
        button.innerHTML = '<i data-feather="check"></i> Copied!';
        feather.replace();
        
        setTimeout(() => {
            button.innerHTML = originalText;
            feather.replace();
        }, 2000);
    }
}

/**
 * Save general settings
 */
function saveGeneralSettings(event) {
    event.preventDefault();
    
    const walletAddress = document.getElementById('walletAddress').value;
    const refreshInterval = document.getElementById('refreshInterval').value;
    const enableDarkMode = document.getElementById('enableDarkMode').checked;
    
    // Save to localStorage
    localStorage.setItem('walletAddress', walletAddress);
    localStorage.setItem('refreshInterval', refreshInterval);
    localStorage.setItem('darkMode', enableDarkMode);
    
    // Send to server
    fetch('/api/save_general_settings', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            wallet_address: walletAddress,
            refresh_interval: refreshInterval,
            enable_dark_mode: enableDarkMode
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showSuccessMessage('generalSettingsForm', 'General settings saved successfully!');
        } else {
            showErrorMessage('generalSettingsForm', data.error || 'Error saving settings.');
        }
    })
    .catch(error => {
        console.error('Error saving general settings:', error);
        showErrorMessage('generalSettingsForm', 'Error saving settings. Please try again.');
    });
}

/**
 * Save notification settings
 */
function saveNotificationSettings(event) {
    event.preventDefault();
    
    const enableDiscord = document.getElementById('enableDiscord').checked;
    const discordWebhook = document.getElementById('discordWebhook').value;
    const enableTelegram = document.getElementById('enableTelegram').checked;
    const telegramBotToken = document.getElementById('telegramBotToken').value;
    const telegramChatId = document.getElementById('telegramChatId').value;
    const enableTwitter = document.getElementById('enableTwitter').checked;
    const notifyHoneypots = document.getElementById('notifyHoneypots').checked;
    const notifyLargeTransfers = document.getElementById('notifyLargeTransfers').checked;
    const largeTransferThreshold = document.getElementById('largeTransferThreshold').value;
    const notifySuspiciousActivity = document.getElementById('notifySuspiciousActivity').checked;
    const notifyTokenWorthless = document.getElementById('notifyTokenWorthless').checked;
    
    // Save to localStorage
    localStorage.setItem('enableDiscord', enableDiscord);
    localStorage.setItem('discordWebhook', discordWebhook);
    localStorage.setItem('enableTelegram', enableTelegram);
    localStorage.setItem('telegramBotToken', telegramBotToken);
    localStorage.setItem('telegramChatId', telegramChatId);
    localStorage.setItem('enableTwitter', enableTwitter);
    localStorage.setItem('notifyHoneypots', notifyHoneypots);
    localStorage.setItem('notifyLargeTransfers', notifyLargeTransfers);
    localStorage.setItem('largeTransferThreshold', largeTransferThreshold);
    localStorage.setItem('notifySuspiciousActivity', notifySuspiciousActivity);
    localStorage.setItem('notifyTokenWorthless', notifyTokenWorthless);
    
    // Send to server
    fetch('/api/save_notification_settings', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            enable_discord: enableDiscord,
            discord_webhook: discordWebhook,
            enable_telegram: enableTelegram,
            telegram_bot_token: telegramBotToken,
            telegram_chat_id: telegramChatId,
            enable_twitter: enableTwitter,
            notify_honeypots: notifyHoneypots,
            notify_large_transfers: notifyLargeTransfers,
            large_transfer_threshold: largeTransferThreshold,
            notify_suspicious_activity: notifySuspiciousActivity,
            notify_token_worthless: notifyTokenWorthless
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showSuccessMessage('notificationSettingsForm', 'Notification settings saved successfully!');
        } else {
            showErrorMessage('notificationSettingsForm', data.error || 'Error saving settings.');
        }
    })
    .catch(error => {
        console.error('Error saving notification settings:', error);
        showErrorMessage('notificationSettingsForm', 'Error saving settings. Please try again.');
    });
}

/**
 * Save API keys
 */
function saveApiKeys(event) {
    event.preventDefault();
    
    const twitterApiKey = document.getElementById('twitterApiKey').value;
    const twitterApiSecret = document.getElementById('twitterApiSecret').value;
    const twitterAccessToken = document.getElementById('twitterAccessToken').value;
    const twitterAccessSecret = document.getElementById('twitterAccessSecret').value;
    const twitterBearerToken = document.getElementById('twitterBearerToken').value;
    const moralisApiKey = document.getElementById('moralisApiKey').value;
    
    // DO NOT save API keys to localStorage for security reasons
    
    // Send to server
    fetch('/api/save_api_keys', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            twitter_api_key: twitterApiKey,
            twitter_api_secret: twitterApiSecret,
            twitter_access_token: twitterAccessToken,
            twitter_access_secret: twitterAccessSecret,
            twitter_bearer_token: twitterBearerToken,
            moralis_api_key: moralisApiKey
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showSuccessMessage('apiKeysSettingsForm', 'API keys saved successfully!');
        } else {
            showErrorMessage('apiKeysSettingsForm', data.error || 'Error saving API keys.');
        }
    })
    .catch(error => {
        console.error('Error saving API keys:', error);
        showErrorMessage('apiKeysSettingsForm', 'Error saving API keys. Please try again.');
    });
}

/**
 * Save security settings
 */
function saveSecuritySettings(event) {
    event.preventDefault();
    
    const enableAutoWhitelist = document.getElementById('enableAutoWhitelist').checked;
    const enableAdvancedSecurity = document.getElementById('enableAdvancedSecurity').checked;
    const honeypotConfidenceThreshold = document.getElementById('honeypotConfidenceThreshold').value;
    
    // Save to localStorage
    localStorage.setItem('enableAutoWhitelist', enableAutoWhitelist);
    localStorage.setItem('enableAdvancedSecurity', enableAdvancedSecurity);
    localStorage.setItem('honeypotConfidenceThreshold', honeypotConfidenceThreshold);
    
    // Send to server
    fetch('/api/save_security_settings', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            enable_auto_whitelist: enableAutoWhitelist,
            enable_advanced_security: enableAdvancedSecurity,
            honeypot_confidence_threshold: honeypotConfidenceThreshold
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showSuccessMessage('securitySettingsForm', 'Security settings saved successfully!');
        } else {
            showErrorMessage('securitySettingsForm', data.error || 'Error saving settings.');
        }
    })
    .catch(error => {
        console.error('Error saving security settings:', error);
        showErrorMessage('securitySettingsForm', 'Error saving settings. Please try again.');
    });
}

/**
 * Test Telegram notification
 */
function testTelegramNotification() {
    const resultContainer = document.getElementById('telegramTestResult');
    resultContainer.innerHTML = '<div class="spinner-border spinner-border-sm text-primary" role="status"><span class="visually-hidden">Loading...</span></div> Testing Telegram notification...';
    
    fetch('/api/telegram/test')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                resultContainer.innerHTML = `
                    <div class="alert alert-success mt-2">
                        <i class="fas fa-check-circle"></i> 
                        Test message sent successfully to Telegram!
                    </div>
                `;
            } else {
                resultContainer.innerHTML = `
                    <div class="alert alert-danger mt-2">
                        <i class="fas fa-exclamation-circle"></i> 
                        Error: ${data.error}
                    </div>
                `;
            }
        })
        .catch(error => {
            console.error('Error testing Telegram:', error);
            resultContainer.innerHTML = `
                <div class="alert alert-danger mt-2">
                    <i class="fas fa-exclamation-circle"></i> 
                    Error: Could not connect to the server. Please try again.
                </div>
            `;
        });
}

/**
 * Test Telegram Jupiter alert
 */
function testTelegramJupiterAlert() {
    const resultContainer = document.getElementById('telegramTestResult');
    resultContainer.innerHTML = '<div class="spinner-border spinner-border-sm text-primary" role="status"><span class="visually-hidden">Loading...</span></div> Testing Jupiter alert notification...';
    
    fetch('/api/telegram/test_jupiter')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                resultContainer.innerHTML = `
                    <div class="alert alert-success mt-2">
                        <i class="fas fa-check-circle"></i> 
                        Jupiter swap alert sent successfully to Telegram!
                    </div>
                `;
            } else {
                resultContainer.innerHTML = `
                    <div class="alert alert-danger mt-2">
                        <i class="fas fa-exclamation-circle"></i> 
                        Error: ${data.error}
                    </div>
                `;
            }
        })
        .catch(error => {
            console.error('Error testing Jupiter alert:', error);
            resultContainer.innerHTML = `
                <div class="alert alert-danger mt-2">
                    <i class="fas fa-exclamation-circle"></i> 
                    Error: Could not connect to the server. Please try again.
                </div>
            `;
        });
}

/**
 * Register Twitter webhook
 */
function registerTwitterWebhook() {
    const webhooksContainer = document.querySelector('.twitter-webhooks-container');
    
    fetch('/api/webhook/twitter/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            environment_name: 'dev'
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert('Webhook registered successfully with Twitter!');
        } else {
            alert(`Error: ${data.error}`);
        }
    })
    .catch(error => {
        console.error('Error registering webhook:', error);
        alert('Error connecting to the server. Please try again.');
    });
}

/**
 * Test Twitter webhook
 */
function testTwitterWebhook() {
    fetch('/api/webhook/twitter/test')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert(`Twitter webhook test successful! Connected as: @${data.credentials.username}`);
            } else {
                alert(`Error: ${data.error}`);
            }
        })
        .catch(error => {
            console.error('Error testing webhook:', error);
            alert('Error connecting to the server. Please try again.');
        });
}

/**
 * Delete Twitter webhooks
 */
function deleteTwitterWebhooks() {
    if (!confirm('Are you sure you want to delete all registered webhooks?')) {
        return;
    }
    
    fetch('/api/webhook/twitter/delete', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            environment_name: 'dev'
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert('Webhooks deleted successfully!');
        } else {
            alert(`Error: ${data.error}`);
        }
    })
    .catch(error => {
        console.error('Error deleting webhooks:', error);
        alert('Error connecting to the server. Please try again.');
    });
}

/**
 * Show success message
 */
function showSuccessMessage(formId, message) {
    const form = document.getElementById(formId);
    
    // Check if there's already a message
    let alertElement = form.querySelector('.alert');
    if (alertElement) {
        alertElement.remove();
    }
    
    // Create new alert
    alertElement = document.createElement('div');
    alertElement.className = 'alert alert-success mt-3';
    alertElement.innerHTML = `<i class="fas fa-check-circle"></i> ${message}`;
    
    // Append after the last button
    const submitButton = form.querySelector('button[type="submit"]');
    submitButton.parentNode.insertBefore(alertElement, submitButton.nextSibling);
    
    // Remove after 3 seconds
    setTimeout(() => {
        alertElement.remove();
    }, 3000);
}

/**
 * Show error message
 */
function showErrorMessage(formId, message) {
    const form = document.getElementById(formId);
    
    // Check if there's already a message
    let alertElement = form.querySelector('.alert');
    if (alertElement) {
        alertElement.remove();
    }
    
    // Create new alert
    alertElement = document.createElement('div');
    alertElement.className = 'alert alert-danger mt-3';
    alertElement.innerHTML = `<i class="fas fa-exclamation-circle"></i> ${message}`;
    
    // Append after the last button
    const submitButton = form.querySelector('button[type="submit"]');
    submitButton.parentNode.insertBefore(alertElement, submitButton.nextSibling);
    
    // Remove after 5 seconds
    setTimeout(() => {
        alertElement.remove();
    }, 5000);
}