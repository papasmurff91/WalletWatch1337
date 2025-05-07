"""
Solana Wallet Monitor - CLI and Web Dashboard for tracking transactions
and detecting honeypot tokens
"""
import argparse
import os
import sys
import json
import threading
from flask import Flask, render_template, jsonify, request, redirect
from solana_rpc import SolanaRPC
from honeypot_detector import HoneypotDetector
from notification_service import NotificationService
from wallet_monitor import WalletMonitor
from suspicious_activity import SuspiciousActivityDetector
from phishing_detector import PhishingDetector
from config import WEB_PORT, WEB_HOST, HONEYPOT_FILE, WHITELIST_FILE, TOKEN_MAP, SUSPICIOUS_ADDRESSES_FILE

# Initialize Flask app
app = Flask(__name__)

# Global variables
monitor = None
wallet_address = None
suspicious_detector = None
phishing_detector = None

@app.route('/')
def index():
    """Render the main dashboard"""
    return render_template('dashboard.html', wallet_address=wallet_address)

@app.route('/transactions')
def transactions():
    """Render the transactions page"""
    return render_template('transactions.html', wallet_address=wallet_address)

@app.route('/honeypots')
def honeypots():
    """Render the honeypots page"""
    return render_template('honeypots.html')

@app.route('/settings')
def settings():
    """Render the settings page"""
    return render_template('settings.html', wallet_address=wallet_address)

@app.route('/suspicious')
def suspicious():
    """Render the suspicious activity page"""
    return render_template('suspicious.html', wallet_address=wallet_address)

@app.route('/analytics')
def analytics():
    """Render the transaction analytics page"""
    return render_template('analytics.html', wallet_address=wallet_address)
    
@app.route('/risk-score')
def risk_score():
    """Render the honeypot risk score page"""
    return render_template('risk_score.html', wallet_address=wallet_address)

@app.route('/api/transactions')
def api_transactions():
    """Get transaction history"""
    if not monitor:
        return jsonify({'error': 'Wallet monitor not initialized'}), 400
    
    # Get query parameters
    limit = int(request.args.get('limit', 10))
    
    # Get transactions and sort by block time descending
    transactions = sorted(
        monitor.transaction_history,
        key=lambda x: x.get('block_time', 0),
        reverse=True
    )[:limit]
    
    return jsonify(transactions)

@app.route('/api/honeypots')
def api_honeypots():
    """Get honeypot tokens"""
    if not monitor:
        return jsonify({'error': 'Wallet monitor not initialized'}), 400
    
    honeypots = []
    
    for mint in monitor.honeypot_detector.honeypots:
        price = monitor.solana_rpc.get_token_price_usd(mint)
        honeypots.append({
            'mint': mint,
            'price': price,
            'holders': monitor.solana_rpc.get_token_holders(mint)
        })
    
    return jsonify(honeypots)

@app.route('/api/whitelist')
def api_whitelist():
    """Get whitelisted tokens"""
    if not monitor:
        return jsonify({'error': 'Wallet monitor not initialized'}), 400
    
    whitelist = []
    
    for mint in monitor.honeypot_detector.whitelist:
        token_name = TOKEN_MAP.get(mint, (f"Token ({mint[:4]}...{mint[-4:]})", 6))[0]
        price = monitor.solana_rpc.get_token_price_usd(mint)
        whitelist.append({
            'mint': mint,
            'name': token_name,
            'price': price
        })
    
    return jsonify(whitelist)

@app.route('/api/whitelist/<mint>', methods=['POST'])
def api_add_to_whitelist(mint):
    """Add a token to the whitelist"""
    if not monitor:
        return jsonify({'error': 'Wallet monitor not initialized'}), 400
    
    monitor.honeypot_detector.add_to_whitelist(mint)
    return jsonify({'success': True})

@app.route('/api/token/<mint>')
def api_token_info(mint):
    """Get information about a token"""
    if not monitor:
        return jsonify({'error': 'Wallet monitor not initialized'}), 400
    
    is_honeypot = monitor.honeypot_detector.is_honeypot(mint)
    is_whitelisted = mint in monitor.honeypot_detector.whitelist
    price = monitor.solana_rpc.get_token_price_usd(mint)
    holders = monitor.solana_rpc.get_token_holders(mint)
    
    return jsonify({
        'mint': mint,
        'is_honeypot': is_honeypot,
        'is_whitelisted': is_whitelisted,
        'price': price,
        'holders': holders
    })
    
@app.route('/api/settings/notification', methods=['POST'])
def api_save_notification_settings():
    """Save notification settings"""
    if not request.is_json:
        return jsonify({'error': 'Invalid JSON'}), 400
        
    data = request.json
    
    # Update environment variables
    if 'discord_webhook' in data:
        os.environ['DISCORD_WEBHOOK_URL'] = data['discord_webhook']
        
    if 'telegram_bot_token' in data:
        os.environ['TELEGRAM_BOT_TOKEN'] = data['telegram_bot_token']
        
    if 'telegram_chat_id' in data:
        os.environ['TELEGRAM_CHAT_ID'] = data['telegram_chat_id']
        
    return jsonify({'success': True})
    
@app.route('/api/settings/api-keys', methods=['POST'])
def api_save_api_keys():
    """Save API keys settings"""
    if not request.is_json:
        return jsonify({'error': 'Invalid JSON'}), 400
        
    data = request.json
    
    # Update environment variables for Twitter
    if 'twitter_api_key' in data and data['twitter_api_key']:
        os.environ['TWITTER_API_KEY'] = data['twitter_api_key']
        
    if 'twitter_api_secret' in data and data['twitter_api_secret']:
        os.environ['TWITTER_API_SECRET'] = data['twitter_api_secret']
        
    if 'twitter_access_token' in data and data['twitter_access_token']:
        os.environ['TWITTER_ACCESS_TOKEN'] = data['twitter_access_token']
        
    if 'twitter_access_secret' in data and data['twitter_access_secret']:
        os.environ['TWITTER_ACCESS_SECRET'] = data['twitter_access_secret']
        
    if 'twitter_bearer_token' in data and data['twitter_bearer_token']:
        os.environ['TWITTER_BEARER_TOKEN'] = data['twitter_bearer_token']
        
    # Update other API keys
    if 'moralis_api_key' in data and data['moralis_api_key']:
        os.environ['MORALIS_API_KEY'] = data['moralis_api_key']
        
    return jsonify({'success': True})
    
@app.route('/api/settings/security', methods=['POST'])
def api_save_security_settings():
    """Save security settings"""
    if not request.is_json:
        return jsonify({'error': 'Invalid JSON'}), 400
        
    data = request.json
    
    if monitor and monitor.honeypot_detector:
        # Update honeypot detector settings if available
        if 'confidence_threshold' in data:
            monitor.honeypot_detector.confidence_threshold = float(data['confidence_threshold']) / 100.0
            
        if 'auto_whitelist' in data and data['auto_whitelist']:
            # Auto-whitelist common tokens
            common_tokens = [
                "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",  # USDC
                "Es9vMFrzaCERz1aZHBKz9ZwrZcpt1mMT8ffvAJhY7kF",   # USDT
                "mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So",   # mSOL
                "So11111111111111111111111111111111111111112"    # wSOL
            ]
            
            for token in common_tokens:
                monitor.honeypot_detector.add_to_whitelist(token)
                
    return jsonify({'success': True})

@app.route('/api/suspicious')
def api_suspicious_activity():
    """Get list of suspicious activity alerts"""
    if not suspicious_detector:
        return jsonify({'error': 'Suspicious activity detector not initialized'}), 400
    
    # Get query parameters
    limit = int(request.args.get('limit', 5))
    
    alerts = suspicious_detector.get_recent_alerts(limit)
    return jsonify(alerts)

@app.route('/api/suspicious/addresses')
def api_suspicious_addresses():
    """Get list of suspicious addresses"""
    if not suspicious_detector:
        return jsonify({'error': 'Suspicious activity detector not initialized'}), 400
    
    addresses = list(suspicious_detector.suspicious_addresses)
    return jsonify(addresses)

def start_monitor(wallet):
    """Start the wallet monitor in a separate thread"""
    global monitor, wallet_address, suspicious_detector, phishing_detector
    
    wallet_address = wallet
    
    # Initialize services
    solana_rpc = SolanaRPC()
    honeypot_detector = HoneypotDetector(solana_rpc)
    notification_service = NotificationService()
    suspicious_detector = SuspiciousActivityDetector(solana_rpc)
    phishing_detector = PhishingDetector(solana_rpc)
    
    # Create and start the monitor
    monitor = WalletMonitor(
        wallet, 
        solana_rpc, 
        honeypot_detector, 
        notification_service,
        suspicious_detector
    )
    
    # Start monitoring in a separate thread
    monitor_thread = threading.Thread(target=monitor.poll_wallet)
    monitor_thread.daemon = True
    monitor_thread.start()

def main():
    """Main entry point for the application"""
    parser = argparse.ArgumentParser(description='Solana Wallet Monitor')
    parser.add_argument('wallet', nargs='?', help='Solana wallet address to monitor')
    parser.add_argument('--web', action='store_true', help='Start the web dashboard')
    
    args = parser.parse_args()
    
    # Use argument or environment variable for wallet address
    wallet = args.wallet or os.getenv('WALLET_ADDRESS')
    
    if not wallet:
        print("Error: No wallet address provided.")
        print("Please specify a wallet address as an argument or set the WALLET_ADDRESS environment variable.")
        sys.exit(1)
    
    # Start the monitor
    start_monitor(wallet)
    
    # Start the web dashboard if requested
    if args.web:
        print(f"Starting web dashboard at http://{WEB_HOST}:{WEB_PORT}")
        app.run(host=WEB_HOST, port=WEB_PORT)
    else:
        # If not running the web dashboard, just keep the script running
        try:
            while True:
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            print("Stopping wallet monitor...")
            sys.exit(0)

if __name__ == "__main__":
    main()
