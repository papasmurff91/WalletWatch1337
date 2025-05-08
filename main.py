"""
Solana Wallet Monitor - CLI and Web Dashboard for tracking transactions
and detecting honeypot tokens
"""
import argparse
import os
import sys
import json
import threading
import hmac
import hashlib
import base64
from datetime import datetime
from flask import Flask, render_template, jsonify, request, redirect
from solana_rpc import SolanaRPC
from honeypot_detector import HoneypotDetector
from notification_service import NotificationService
from wallet_monitor import WalletMonitor
from suspicious_activity import SuspiciousActivityDetector
from phishing_detector import PhishingDetector
from twitter_service import TwitterService
from config import WEB_PORT, WEB_HOST, HONEYPOT_FILE, WHITELIST_FILE, TOKEN_MAP, SUSPICIOUS_ADDRESSES_FILE, SWAP_PROGRAM_IDS

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
    
@app.route('/enhanced-dashboard')
def enhanced_dashboard():
    """Render the enhanced dashboard with interactive visualizations"""
    return render_template('enhanced-dashboard.html', wallet_address=wallet_address)

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
    
@app.route('/phishing')
def phishing():
    """Render the phishing protection page"""
    return render_template('phishing.html', wallet_address=wallet_address)
    
@app.route('/threat-timeline')
def threat_timeline():
    """Render the threat timeline visualization page"""
    return render_template('threat_timeline.html', wallet_address=wallet_address)
    
@app.route('/network-graph')
def network_graph():
    """Render the network relationship graph visualization page"""
    return render_template('network_graph.html', wallet_address=wallet_address)
    
@app.route('/social-alerts')
def social_alerts():
    """Render the social media alerts page"""
    return render_template('social_alerts.html', wallet_address=wallet_address)

@app.route('/api/transactions')
def api_transactions():
    """Get transaction history"""
    if not monitor:
        return jsonify({'error': 'Wallet monitor not initialized'}), 400
    
    # Get query parameters
    try:
        # Get query parameters
        limit = int(request.args.get('limit', 10))
    
        # Get transactions and sort by block time descending
        transactions = sorted(
            monitor.transaction_history,
            key=lambda x: x.get('block_time', 0),
            reverse=True
        )[:limit]
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    return jsonify(transactions)

@app.route('/api/honeypots')
def api_honeypots():
    """Get honeypot tokens"""
    if not monitor:
        return jsonify({'error': 'Wallet monitor not initialized'}), 400
    
    try:
        honeypots = []
        for mint in monitor.honeypot_detector.honeypots:
            price = monitor.solana_rpc.get_token_price_usd(mint)
            honeypots.append({
                'mint': mint,
                'price': price,
                'holders': monitor.solana_rpc.get_token_holders(mint)
            })
        return jsonify(honeypots)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/whitelist')
def api_whitelist():
    """Get whitelisted tokens"""
    if not monitor:
        return jsonify({'error': 'Wallet monitor not initialized'}), 400
    
    try:
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
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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
    

@app.route('/api/donations', methods=['GET'])
def api_donations():
    """Return donation details"""
    # Mock data for demonstration
    donations_data = {
        'balance': 10.25,  # Balance in ETH
        'recent_donors': [
            {'name': 'Alice', 'amount': 1.5},
            {'name': 'Bob', 'amount': 0.75},
            {'name': 'Charlie', 'amount': 3.0}
        ]
    }
    return jsonify(donations_data)

@app.route('/api/analytics')
def api_analytics():
    """Get analytics data for dashboard visualizations"""
    if not monitor:
        return jsonify({'error': 'Wallet monitor not initialized'}), 400
    
    # Get query parameters
    time_range = request.args.get('time_range', '1d')  # Default to 1 day
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    # Get transaction data
    transactions = monitor.get_recent_transactions(limit=100)
    
    # Process the transaction data for analytics
    now = datetime.now()
    
    # Filter by time range if specified
    if time_range or (start_date and end_date):
        filtered_transactions = []
        
        if time_range:
            # Calculate start date based on time range
            if time_range == '1d':
                start_time = now.timestamp() - (24 * 60 * 60)  # 24 hours ago
            elif time_range == '7d':
                start_time = now.timestamp() - (7 * 24 * 60 * 60)  # 7 days ago
            elif time_range == '30d':
                start_time = now.timestamp() - (30 * 24 * 60 * 60)  # 30 days ago
            elif time_range == 'all':
                start_time = 0  # All time
            
            for tx in transactions:
                tx_time = tx.get('timestamp', 0)
                if isinstance(tx_time, str):
                    try:
                        tx_time = datetime.fromisoformat(tx_time).timestamp()
                    except ValueError:
                        tx_time = 0
                
                if tx_time >= start_time:
                    filtered_transactions.append(tx)
                    
        elif start_date and end_date:
            # Use custom date range
            try:
                start_time = datetime.fromisoformat(start_date).timestamp()
                end_time = datetime.fromisoformat(end_date).timestamp()
                
                for tx in transactions:
                    tx_time = tx.get('timestamp', 0)
                    if isinstance(tx_time, str):
                        try:
                            tx_time = datetime.fromisoformat(tx_time).timestamp()
                        except ValueError:
                            tx_time = 0
                    
                    if start_time <= tx_time <= end_time:
                        filtered_transactions.append(tx)
            except ValueError:
                filtered_transactions = transactions  # Fallback to all transactions
    else:
        filtered_transactions = transactions
    
    # Process data for charts
    
    # 1. Transaction volume by date
    volume_by_date = {}
    for tx in filtered_transactions:
        date_str = tx.get('date', '').split(' ')[0]  # Get just the date part
        if not date_str:
            continue
            
        if date_str not in volume_by_date:
            volume_by_date[date_str] = 0
        volume_by_date[date_str] += 1
    
    # Convert to chart-friendly format
    volume_data = {
        'labels': list(volume_by_date.keys()),
        'datasets': [{
            'label': 'Transaction Count',
            'data': list(volume_by_date.values()),
            'backgroundColor': 'rgba(75, 192, 192, 0.2)',
            'borderColor': 'rgba(75, 192, 192, 1)',
            'borderWidth': 1
        }]
    }
    
    # 2. Transaction types
    tx_types = {
        'sol_transfer': 0,
        'token_transfer': 0,
        'swap': 0,
        'other': 0
    }
    
    # 3. Token distribution
    token_distribution = {}
    
    # 4. Transaction direction counts
    incoming_count = 0
    outgoing_count = 0
    
    # Process events to collect this data
    for tx in filtered_transactions:
        # Process transaction types and token distribution
        has_type = False
        
        for event in tx.get('events', []):
            event_type = event.get('type')
            
            # Count transaction types
            if event_type in tx_types:
                tx_types[event_type] += 1
                has_type = True
            
            # Count direction
            if event_type in ['sol_transfer', 'token_transfer']:
                if event.get('direction') == 'Received':
                    incoming_count += 1
                else:
                    outgoing_count += 1
            
            # Token distribution
            if event_type == 'token_transfer':
                token_name = event.get('token_name', 'Unknown Token')
                if token_name not in token_distribution:
                    token_distribution[token_name] = 0
                token_distribution[token_name] += 1
        
        if not has_type:
            tx_types['other'] += 1
    
    # Sort and limit token distribution to top 10
    token_distribution = dict(sorted(token_distribution.items(), key=lambda x: x[1], reverse=True)[:10])
    
    # Format transaction types for chart
    tx_types_data = {
        'labels': list(tx_types.keys()),
        'datasets': [{
            'label': 'Transaction Types',
            'data': list(tx_types.values()),
            'backgroundColor': [
                'rgba(255, 99, 132, 0.2)',
                'rgba(54, 162, 235, 0.2)',
                'rgba(255, 206, 86, 0.2)',
                'rgba(75, 192, 192, 0.2)'
            ],
            'borderColor': [
                'rgba(255, 99, 132, 1)',
                'rgba(54, 162, 235, 1)',
                'rgba(255, 206, 86, 1)',
                'rgba(75, 192, 192, 1)'
            ],
            'borderWidth': 1
        }]
    }
    
    # Format token distribution for chart
    token_dist_data = {
        'labels': list(token_distribution.keys()),
        'datasets': [{
            'label': 'Token Transactions',
            'data': list(token_distribution.values()),
            'backgroundColor': [
                'rgba(255, 99, 132, 0.2)',
                'rgba(54, 162, 235, 0.2)',
                'rgba(255, 206, 86, 0.2)',
                'rgba(75, 192, 192, 0.2)',
                'rgba(153, 102, 255, 0.2)',
                'rgba(255, 159, 64, 0.2)',
                'rgba(199, 199, 199, 0.2)',
                'rgba(83, 102, 255, 0.2)',
                'rgba(40, 159, 64, 0.2)',
                'rgba(210, 199, 199, 0.2)'
            ],
            'borderColor': [
                'rgba(255, 99, 132, 1)',
                'rgba(54, 162, 235, 1)',
                'rgba(255, 206, 86, 1)',
                'rgba(75, 192, 192, 1)',
                'rgba(153, 102, 255, 1)',
                'rgba(255, 159, 64, 1)',
                'rgba(199, 199, 199, 1)',
                'rgba(83, 102, 255, 1)',
                'rgba(40, 159, 64, 1)',
                'rgba(210, 199, 199, 1)'
            ],
            'borderWidth': 1
        }]
    }
    
    # 5. Program interactions
    program_interactions = {}
    for tx in filtered_transactions:
        programs = tx.get('programs', [])
        for program in programs:
            program_id = program.get('program_id', 'Unknown')
            program_name = program.get('name', program_id)
            if program_name not in program_interactions:
                program_interactions[program_name] = 0
            program_interactions[program_name] += 1
    
    # Sort and limit program interactions to top 10
    program_interactions = dict(sorted(program_interactions.items(), key=lambda x: x[1], reverse=True)[:10])
    
    program_data = {
        'labels': list(program_interactions.keys()),
        'datasets': [{
            'label': 'Program Interactions',
            'data': list(program_interactions.values()),
            'backgroundColor': 'rgba(153, 102, 255, 0.2)',
            'borderColor': 'rgba(153, 102, 255, 1)',
            'borderWidth': 1
        }]
    }
    
    # 6. Calculate risk score
    risk_score = 0
    
    # Check for suspicious activity
    if suspicious_detector:
        suspicious_alerts = suspicious_detector.get_recent_alerts(limit=10)
        risk_score += len(suspicious_alerts) * 10  # Add 10 points for each suspicious alert
    
    # Check for honeypot interactions
    if monitor and monitor.honeypot_detector:
        honeypot_tokens = monitor.honeypot_detector.get_known_honeypots()
        for tx in filtered_transactions:
            for event in tx.get('events', []):
                if event.get('type') == 'token_transfer':
                    mint = event.get('mint')
                    if mint and mint in honeypot_tokens:
                        risk_score += 15  # Add 15 points for each honeypot interaction
    
    # Cap the risk score at 100
    risk_score = min(risk_score, 100)
    
    # Calculate SOL balance over time (simulated for now)
    # This would normally use real data from transactions
    sol_balance_data = {
        'labels': volume_data['labels'],
        'datasets': [{
            'label': 'SOL Balance',
            'data': [10 + i * 0.5 for i in range(len(volume_data['labels']))],  # Simulated balance
            'backgroundColor': 'rgba(54, 162, 235, 0.2)',
            'borderColor': 'rgba(54, 162, 235, 1)',
            'borderWidth': 1,
            'tension': 0.1
        }]
    }
    
    # Return all chart data
    return jsonify({
        'volume_data': volume_data,
        'transaction_types': tx_types_data,
        'token_distribution': token_dist_data,
        'sol_balance': sol_balance_data,
        'program_interactions': program_data,
        'metrics': {
            'total_transactions': len(filtered_transactions),
            'incoming': incoming_count,
            'outgoing': outgoing_count,
            'swaps': tx_types['swap']
        },
        'risk_score': risk_score
    })

def api_threat_timeline():
    """Get threat timeline data for visualization"""
    if not suspicious_detector:
        return jsonify({'error': 'Suspicious activity detector not initialized'}), 400
    
    # Get query parameters for filtering
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    severity = request.args.get('severity')
    threat_type = request.args.get('type')
    
    # Get all alerts
    alerts = suspicious_detector.get_recent_alerts(limit=100)  # Get a large number to work with
    
    # Apply filters
    if start_date:
        try:
            start_datetime = datetime.fromisoformat(start_date)
            alerts = [a for a in alerts if a.get('timestamp') and datetime.fromisoformat(a['timestamp']) >= start_datetime]
        except ValueError:
            pass
            
    if end_date:
        try:
            end_datetime = datetime.fromisoformat(end_date)
            alerts = [a for a in alerts if a.get('timestamp') and datetime.fromisoformat(a['timestamp']) <= end_datetime]
        except ValueError:
            pass
    
    # Apply severity filter
    if severity:
        if severity == 'critical':
            alerts = [a for a in alerts if 'Unsellable token' in a.get('reason', '') or 'rug pull' in a.get('reason', '')]
        elif severity == 'high':
            alerts = [a for a in alerts if 'Flash launch' in a.get('reason', '') or 'Cross-chain transfer' in a.get('reason', '')]
        elif severity == 'medium':
            alerts = [a for a in alerts if not ('Unsellable token' in a.get('reason', '') or 'rug pull' in a.get('reason', '') or 
                                          'Flash launch' in a.get('reason', '') or 'Cross-chain transfer' in a.get('reason', ''))]
    
    # Apply threat type filter
    if threat_type:
        alerts = [a for a in alerts if threat_type.lower() in a.get('reason', '').lower()]
    
    # Process the alerts for the timeline
    timeline_data = []
    
    for alert in alerts:
        severity_level = 'medium'
        if 'Unsellable token' in alert.get('reason', '') or 'rug pull' in alert.get('reason', ''):
            severity_level = 'critical'
        elif 'Flash launch' in alert.get('reason', '') or 'Cross-chain transfer' in alert.get('reason', ''):
            severity_level = 'high'
            
        timeline_item = {
            'id': alert.get('id', str(len(timeline_data))),
            'timestamp': alert.get('timestamp'),
            'address': alert.get('address'),
            'reason': alert.get('reason'),
            'details': alert.get('details', ''),
            'severity': severity_level,
            'related_events': alert.get('related_events', [])
        }
        
        timeline_data.append(timeline_item)
    
    # Sort by timestamp
    timeline_data.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
    return jsonify(timeline_data)

@app.route('/api/network-graph')
def api_network_graph():
    """Get network relationship graph data for visualization"""
    if not suspicious_detector:
        return jsonify({'error': 'Suspicious activity detector not initialized'}), 400
    
    # Get query parameters for filtering
    address_filter = request.args.get('address')
    activity_type = request.args.get('activityType')
    risk_level = request.args.get('riskLevel')
    time_frame = request.args.get('timeFrame', '7d')
    
    # In a real implementation, this would:
    # 1. Query transactions involving the wallet and suspicious addresses
    # 2. Build a graph of related addresses
    # 3. Apply the filters
    # 4. Return the graph data
    
    # For demonstration purposes, return a simple mock network
    suspicious_addresses = list(suspicious_detector.suspicious_addresses)[:5]
    
    # Create a simple network structure
    nodes = [
        {"id": wallet_address, "label": f"{wallet_address[:4]}...{wallet_address[-4:]}", "type": "wallet"}
    ]
    
    edges = []
    
    # Add suspicious addresses as nodes
    for i, address in enumerate(suspicious_addresses):
        nodes.append({
            "id": address,
            "label": f"{address[:4]}...{address[-4:]}",
            "type": "suspicious"
        })
        
        # Connect to wallet sometimes
        if i % 2 == 0:
            edges.append({
                "source": wallet_address,
                "target": address,
                "weight": 1 + i,
                "type": "transfer"
            })
    
    # Add some random addresses connected to suspicious ones
    for i in range(10):
        random_address = f"Addr{i+1:02d}" + "1" * 35
        nodes.append({
            "id": random_address,
            "label": f"{random_address[:4]}...{random_address[-4:]}",
            "type": "unknown"
        })
        
        # Connect to a suspicious address
        target_idx = i % len(suspicious_addresses)
        edges.append({
            "source": random_address,
            "target": suspicious_addresses[target_idx],
            "weight": 1,
            "type": "transfer"
        })
        
        # Sometimes connect to wallet
        if i % 3 == 0:
            edges.append({
                "source": wallet_address,
                "target": random_address,
                "weight": 1,
                "type": "transfer"
            })
    
    # Add some trusted addresses
    for i in range(3):
        trusted_address = f"Trust{i+1:02d}" + "1" * 34
        nodes.append({
            "id": trusted_address,
            "label": f"{trusted_address[:4]}...{trusted_address[-4:]}",
            "type": "trusted"
        })
        
        # Always connect to wallet
        edges.append({
            "source": wallet_address,
            "target": trusted_address,
            "weight": 2 + i,
            "type": "transfer"
        })
    
    return jsonify({
        "nodes": nodes,
        "edges": edges
    })
    
@app.route('/api/phishing')
def api_phishing_alerts():
    """Get list of phishing alerts"""
    if not phishing_detector:
        return jsonify({'error': 'Phishing detector not initialized'}), 400
    
    # Get query parameters
    limit = int(request.args.get('limit', 5))
    
    alerts = phishing_detector.get_recent_alerts(limit)
    return jsonify(alerts)
    
@app.route('/api/social-alerts')
def api_social_media_alerts():
    """Get list of social media alerts about suspicious addresses"""
    social_monitor = get_social_media_monitor()
    
    if not social_monitor:
        return jsonify({'error': 'Social media monitor not initialized'}), 400
    
    # Get query parameters
    limit = int(request.args.get('limit', 10))
    
    alerts = social_monitor.get_recent_alerts(limit)
    return jsonify(alerts)
    
@app.route('/api/phishing/check', methods=['POST'])
def api_check_phishing():
    """Check if a transaction has phishing indicators"""
    if not phishing_detector or not request.is_json:
        return jsonify({'error': 'Invalid request'}), 400
        
    tx_data = request.json
    is_phishing, confidence, reason = phishing_detector.analyze_transaction(tx_data)
    
    return jsonify({
        'is_phishing': is_phishing,
        'confidence': confidence,
        'reason': reason
    })

# DEX Swap Webhook Routes
@app.route('/api/swaps/raydium', methods=['GET'])
def api_raydium_swaps():
    """Get recent Raydium swap transactions"""
    if not monitor:
        return jsonify({'error': 'Wallet monitor not initialized'}), 400
    
    # Get query parameters
    limit = int(request.args.get('limit', 10))
    
    # Filter transactions that involve Raydium program ID
    raydium_program_id = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8"
    raydium_swaps = []
    
    for tx in sorted(monitor.transaction_history, key=lambda x: x.get('block_time', 0), reverse=True):
        if raydium_program_id in tx.get('program_ids', []):
            # Extract swap details
            for event in tx.get('events', []):
                if event.get('type') == 'swap' and event.get('program_id') == raydium_program_id:
                    raydium_swaps.append({
                        'signature': tx.get('signature'),
                        'timestamp': tx.get('timestamp'),
                        'swap_details': event,
                        'honeypot_flags': tx.get('honeypot_flags', []),
                        'suspicious_flags': tx.get('suspicious_flags', [])
                    })
                    break
    
    return jsonify(raydium_swaps[:limit])

@app.route('/webhooks/raydium/alerts', methods=['GET'])
def api_simulate_raydium_webhook():
    """
    Simulate a Raydium swap alert webhook for testing purposes
    This endpoint creates a sample Raydium swap transaction alert
    """
    if not monitor:
        return jsonify({'error': 'Wallet monitor not initialized'}), 400
    
    # Create a simulated Raydium swap alert
    simulated_swap = {
        'type': 'raydium_honeypot_swap',
        'timestamp': datetime.utcnow().strftime("%b %d, %Y %H:%M:%S"),
        'signature': '4kT3KzmCt3tTjzVuef5g6a9SQWMjBQZnuHzaX4dNEh4J88Qnkje7j5vk6ZyiaQk8KFEZSKdJsAwNZ4EyuSg8Qnuk',
        'wallet': wallet_address,
        'swap_details': {
            'type': 'swap',
            'program_id': '675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8',
            'dex_name': 'Raydium',
            'input_token': 'SOL',
            'input_amount': 1.5,
            'output_token': 'SCAM TOKEN',
            'output_amount': 150000,
            'input_mint': 'So11111111111111111111111111111111111111112',
            'output_mint': '8SHmGAR4UEmfDuJdyNdGhKXCQguZZmoWVXRTF4xSVFQA',
            'price_impact': 12.5,
            'exchange_rate': 100000,
            'risk_level': 'high',
            'risk_factors': [
                'Very high price impact: 12.5%',
                'Token has very few holders (<10)',
                'Token created in last 24 hours'
            ]
        },
        'honeypot_tokens': ['8SHmGAR4UEmfDuJdyNdGhKXCQguZZmoWVXRTF4xSVFQA'],
        'risk_analysis': {
            'overall_risk': 'critical',
            'confidence': 0.95,
            'reasons': [
                'Token has no liquidity in other pools',
                'Creator wallet associated with previous rug pulls',
                'Smart contract prevents selling by non-whitelisted addresses'
            ]
        }
    }
    
    return jsonify(simulated_swap)

@app.route('/webhooks/raydium/callback', methods=['POST'])
def api_raydium_webhook_callback():
    """
    Webhook callback endpoint for external services to receive Raydium swap alerts
    This would be called by the monitor when it detects interesting Raydium swaps
    """
    if not request.is_json:
        return jsonify({'error': 'Invalid JSON'}), 400
    
    # Process the incoming webhook data (in a real implementation)
    # Here we just echo it back for testing
    webhook_data = request.json
    
    # In a real implementation, we would validate the webhook data
    # and process it accordingly
    
    # Log the webhook call
    print(f"Received Raydium webhook: {json.dumps(webhook_data, indent=2)}")
    
    return jsonify({
        'status': 'success',
        'message': 'Raydium swap alert received',
        'received_data': webhook_data
    })

@app.route('/api/swaps/jupiter', methods=['GET'])
def api_jupiter_swaps():
    """Get recent Jupiter swap transactions"""
    if not monitor:
        return jsonify({'error': 'Wallet monitor not initialized'}), 400
    
    # Get query parameters
    limit = int(request.args.get('limit', 10))
    
    # Filter transactions that involve Jupiter program IDs
    jupiter_program_ids = ["JUP4Fb2cqiRUcaTHdrPC8h2gNsA2ETXiPDD33WcGuJB", "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"]
    jupiter_swaps = []
    
    for tx in sorted(monitor.transaction_history, key=lambda x: x.get('block_time', 0), reverse=True):
        # Check if any Jupiter program was involved
        if any(prog_id in tx.get('program_ids', []) for prog_id in jupiter_program_ids):
            # Extract swap details
            for event in tx.get('events', []):
                if event.get('type') == 'swap' and event.get('program_id') in jupiter_program_ids:
                    jupiter_swaps.append({
                        'signature': tx.get('signature'),
                        'timestamp': tx.get('timestamp'),
                        'swap_details': event,
                        'honeypot_flags': tx.get('honeypot_flags', []),
                        'suspicious_flags': tx.get('suspicious_flags', []),
                        'associated_accounts': event.get('associated_accounts', [])
                    })
                    break
    
    return jsonify(jupiter_swaps[:limit])

@app.route('/webhooks/jupiter/alerts', methods=['GET'])
def api_simulate_jupiter_webhook():
    """
    Simulate a Jupiter swap alert webhook for testing purposes
    This endpoint creates a sample Jupiter swap transaction alert with account tagging
    """
    if not monitor:
        return jsonify({'error': 'Wallet monitor not initialized'}), 400
    
    # Create a simulated Jupiter swap alert with account tagging
    simulated_swap = {
        'type': 'jupiter_swap_alert',
        'timestamp': datetime.utcnow().strftime("%b %d, %Y %H:%M:%S"),
        'signature': '5zLM8GaYKvqBDEWLqH9RJrJd1KT9FxyyKZnMPXKz6yG78xrUZ9WSaQ3KV9XD5U3GpuWbRpwc2Lkz64ui9VoaKbJC',
        'wallet': wallet_address,
        'swap_details': {
            'type': 'swap',
            'program_id': 'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4',
            'jupiter_version': '6',
            'dex_name': 'Jupiter v6',
            'input_token': 'SOL',
            'input_amount': 2.25,
            'output_token': 'SUSPICIOUS TOKEN',
            'output_amount': 245000,
            'input_mint': 'So11111111111111111111111111111111111111112',
            'output_mint': '9zT54JYUYv9Hy6JfenKZP5TfaJ22A6PxLg53BnBvGp9v',
            'price_impact': 8.7,
            'exchange_rate': 108889,
            'risk_level': 'high',
            'risk_factors': [
                'Very high price impact: 8.7%',
                'Token has very few holders (<5)',
                'Token created in last 12 hours',
                'Swapping for unknown token not in known token list'
            ],
            'account_tags': {
                'DvH8PrFzKeceSHdKrZgfpPXzVJbvXvwW6wNFUmCrxuCL': 'fee',
                'CZuPYHki3YxHBJV7AJD6r4YQ5UKBcFm9dfgPiAEPzyiK': 'admin',
                'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4': 'program'
            },
            'associated_accounts': [
                {
                    'address': 'DvH8PrFzKeceSHdKrZgfpPXzVJbvXvwW6wNFUmCrxuCL',
                    'tag': 'fee'
                },
                {
                    'address': 'CZuPYHBJwJ7AJD6r4YQ5UKBcFm9dfgPiAEPzyiK',
                    'tag': 'admin'
                },
                {
                    'address': 'xT45JSTvKPH3Hy6JfenKZP534bBvGp9v',
                    'tag': 'token_promoter'
                }
            ]
        },
        'honeypot_tokens': ['9zT54JYUYv9Hy6JfenKZP5TfaJ22A6PxLg53BnBvGp9v'],
        'risk_analysis': {
            'overall_risk': 'critical',
            'confidence': 0.95,
            'reasons': [
                'Very high price impact: 8.7%',
                'Token has very few holders (<5)',
                'Token created in last 12 hours',
                'Token contract contains selling restrictions',
                'Liquidity locked for only 1 day'
            ]
        },
        'associated_accounts': [
            {
                'address': 'DvH8PrFzKeceSHdKrZgfpPXzVJbvXvwW6wNFUmCrxuCL',
                'tag': 'fee',
                'platform': 'twitter',
                'username': 'token_fee_collector'
            },
            {
                'address': 'xT45JSTvKPH3Hy6JfenKZP5534bBvGp9v',
                'tag': 'token_promoter',
                'platform': 'twitter',
                'username': 'crypto_influencer_123'
            }
        ]
    }
    
    # If the URL parameter 'send_notification=true' is present, actually send the notification
    if request.args.get('send_notification') == 'true':
        notification_service = NotificationService()
        notification_service.notify_jupiter_swap(simulated_swap)
        
        return jsonify({
            'status': 'success',
            'message': 'Simulated Jupiter swap alert sent to notification channels',
            'notification_sent': True,
            'channels': {
                'telegram': notification_service.telegram_enabled,
                'discord': notification_service.discord_enabled,
                'twitter': notification_service.twitter_service.is_enabled()
            },
            'swap_data': simulated_swap
        })
    
    return jsonify(simulated_swap)

@app.route('/webhooks/jupiter/callback', methods=['POST'])
def api_jupiter_webhook_callback():
    """
    Webhook callback endpoint for external services to receive Jupiter swap alerts
    This would be called by the monitor when it detects interesting Jupiter swaps with account tagging
    """
    if not request.is_json:
        return jsonify({'error': 'Invalid JSON'}), 400
    
    # Process the incoming webhook data
    webhook_data = request.json
    
    # Log the webhook call
    print(f"Received Jupiter webhook: {json.dumps(webhook_data, indent=2)}")
    
    # Check if this is a swap alert with enough information to process
    if webhook_data.get('type') == 'jupiter_swap_alert' or 'swap_details' in webhook_data:
        # Send notification via all configured channels
        notification_service = NotificationService()
        notification_service.notify_jupiter_swap(webhook_data)
        
        return jsonify({
            'status': 'success',
            'message': 'Jupiter swap alert processed and notifications sent',
            'notification_channels': [
                'telegram' if notification_service.telegram_enabled else None,
                'discord' if notification_service.discord_enabled else None,
                'twitter' if notification_service.twitter_service.is_enabled() else None
            ]
        })
    else:
        # Just echo back the data if it's not a properly formatted swap alert
        return jsonify({
            'status': 'success',
            'message': 'Jupiter data received but not processed as a swap alert',
            'received_data': webhook_data
        })

# Telegram Integration Tests
@app.route('/api/telegram/test', methods=['GET'])
def api_test_telegram():
    """Test the Telegram notification service with a sample message"""
    # Check if Telegram is configured
    from notification_service import NotificationService
    notification_service = NotificationService()
    
    if not notification_service.telegram_enabled:
        return jsonify({
            'success': False,
            'error': 'Telegram is not configured. Please set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in environment variables.',
            'required_env_vars': ['TELEGRAM_BOT_TOKEN', 'TELEGRAM_CHAT_ID']
        }), 400
        
    # Try sending a test message
    try:
        test_message = "🔔 *Telegram Integration Test*\n\nThis is a test message from the Solana Wallet Monitor.\n\nIf you're seeing this, your Telegram notifications are working correctly!\n\nTimestamp: " + datetime.utcnow().strftime("%b %d, %Y %H:%M:%S UTC")
        success = notification_service.send_telegram(test_message)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Telegram test message sent successfully',
                'telegram_config': {
                    'bot_token_set': bool(notification_service.telegram_enabled),
                    'chat_id_set': bool(notification_service.telegram_enabled)
                }
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to send test message, but Telegram appears to be configured. Check your bot token and chat ID.'
            }), 500
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error testing Telegram: {str(e)}'
        }), 500
        
@app.route('/api/telegram/test_jupiter', methods=['GET'])
def api_test_telegram_jupiter():
    """Test the Telegram notification service with a simulated Jupiter swap alert"""
    # Check if Telegram is configured
    from notification_service import NotificationService
    notification_service = NotificationService()
    
    if not notification_service.telegram_enabled:
        return jsonify({
            'success': False,
            'error': 'Telegram is not configured. Please set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in environment variables.',
            'required_env_vars': ['TELEGRAM_BOT_TOKEN', 'TELEGRAM_CHAT_ID']
        }), 400
        
    # Try sending a test Jupiter swap alert
    try:
        # Create a simulated Jupiter swap alert
        simulated_swap = {
            'type': 'jupiter_swap_alert',
            'timestamp': datetime.utcnow().strftime("%b %d, %Y %H:%M:%S"),
            'signature': '5zLM8GaYKvqBDEWLqH9RJrJd1KT9FxyyKZnMPXKz6yG78xrUZ9WSaQ3KV9XD5U3GpuWbRpwc2Lkz64ui9VoaKbJC',
            'wallet': wallet_address,
            'swap_details': {
                'type': 'swap',
                'program_id': 'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4',
                'jupiter_version': '6',
                'dex_name': 'Jupiter v6',
                'input_token': 'SOL',
                'input_amount': 2.25,
                'output_token': 'TEST TOKEN',
                'output_amount': 245000,
                'input_mint': 'So11111111111111111111111111111111111111112',
                'output_mint': '9zT54JYUYv9Hy6JfenKZP5TfaJ22A6PxLg53BnBvGp9v',
                'price_impact': 8.7,
                'exchange_rate': 108889,
                'risk_level': 'high',
                'risk_factors': [
                    'Very high price impact: 8.7%',
                    'Token has very few holders (<5)',
                    'Token created in last 12 hours',
                    'Swapping for unknown token not in known token list'
                ]
            },
            'risk_analysis': {
                'overall_risk': 'critical',
                'confidence': 0.95,
                'reasons': [
                    'Very high price impact: 8.7%',
                    'Token has very few holders (<5)',
                    'Token created in last 12 hours',
                    'Token contract contains selling restrictions'
                ]
            }
        }
        
        # Send the notification
        success = notification_service.notify_jupiter_swap(simulated_swap)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Telegram Jupiter swap alert sent successfully',
                'telegram_enabled': notification_service.telegram_enabled,
                'simulated_swap': simulated_swap
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to send Jupiter swap alert via Telegram.'
            }), 500
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error testing Telegram Jupiter alert: {str(e)}'
        }), 500

# Twitter Webhook Routes
@app.route('/webhooks/twitter/activity', methods=['GET'])
def twitter_webhook_challenge():
    """
    Handle the Twitter Account Activity API CRC challenge
    Twitter will send a GET request with a crc_token to validate ownership
    """
    crc_token = request.args.get('crc_token')
    if not crc_token:
        return jsonify({'error': 'Missing crc_token parameter'}), 400
        
    # Generate the response using our API secret
    twitter_api_secret = os.getenv('TWITTER_API_SECRET', '')
    
    if not twitter_api_secret:
        return jsonify({'error': 'Missing Twitter API secret'}), 500
        
    # Create HMAC SHA-256 hash from the crc_token using our API secret
    hmac_digest = hmac.new(
        key=twitter_api_secret.encode('utf-8'),
        msg=crc_token.encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()
    
    # Base64 encode the hash
    response_token = 'sha256=' + base64.b64encode(hmac_digest).decode('utf-8')
    
    # Return the response token in the required format
    return jsonify({'response_token': response_token})
    
@app.route('/api/webhook/twitter/test', methods=['GET'])
def api_test_twitter_webhook():
    """Test the Twitter webhook configuration"""
    try:
        # Verify Twitter credentials
        twitter_service = TwitterService()
        
        # Verify that credentials are correct
        credentials = twitter_service.verify_credentials()
        if not credentials['success']:
            return jsonify({
                'success': False,
                'error': credentials['error'] if 'error' in credentials else 'Failed to verify Twitter credentials'
            }), 400
        
        # Get the webhook URL
        hostname = request.headers.get('Host', 'yourdomain.com')
        protocol = request.headers.get('X-Forwarded-Proto', 'https')
        webhook_url = f"{protocol}://{hostname}/webhooks/twitter/activity"
        
        # Test the webhook connection using Tweepy
        # In a real implementation, we would use Tweepy to verify the webhook registration
        # For demonstration purposes, we'll just check if the URL looks valid
        
        import re
        is_valid_url = bool(re.match(r'^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/webhooks/twitter/activity$', webhook_url))
        
        if not is_valid_url:
            return jsonify({
                'success': False,
                'error': 'Invalid webhook URL format'
            }), 400
        
        # Check existing webhook status
        webhook_status = twitter_service.get_webhook_status()
        
        # Return success with details
        return jsonify({
            'success': True,
            'webhook_url': webhook_url,
            'credentials': {
                'username': credentials.get('username', 'Unknown'),
                'v1_authenticated': credentials.get('v1_authenticated', False),
                'v2_authenticated': credentials.get('v2_authenticated', False)
            },
            'webhooks': webhook_status.get('webhooks', []) if webhook_status.get('success', False) else [],
            'message': 'Twitter webhook URL is valid and API credentials are configured correctly'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
        
@app.route('/api/webhook/twitter/register', methods=['POST'])
def api_register_twitter_webhook():
    """Register a webhook URL with Twitter"""
    try:
        # Get environment name (optional)
        data = request.json or {}
        environment_name = data.get('environment_name', 'dev')
        
        # Get the webhook URL
        hostname = request.headers.get('Host', 'yourdomain.com')
        protocol = request.headers.get('X-Forwarded-Proto', 'https')
        webhook_url = f"{protocol}://{hostname}/webhooks/twitter/activity"
        
        # Initialize Twitter service
        twitter_service = TwitterService()
        
        # Register the webhook
        result = twitter_service.register_webhook(webhook_url, environment_name)
        
        if not result['success']:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Unknown error registering webhook')
            }), 400
            
        return jsonify({
            'success': True,
            'webhook_id': result.get('webhook_id'),
            'webhook_url': result.get('webhook_url'),
            'environment': result.get('environment'),
            'message': 'Webhook registered successfully with Twitter'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
        
@app.route('/api/webhook/twitter/delete', methods=['POST'])
def api_delete_twitter_webhooks():
    """Delete all registered webhooks"""
    try:
        # Get environment name (optional)
        data = request.json or {}
        environment_name = data.get('environment_name', 'dev')
        
        # Initialize Twitter service
        twitter_service = TwitterService()
        
        # Delete webhooks
        result = twitter_service.delete_webhooks(environment_name)
        
        if not result['success']:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Unknown error deleting webhooks')
            }), 400
            
        return jsonify({
            'success': True,
            'deleted_webhooks': result.get('deleted_webhooks', []),
            'message': 'Webhooks deleted successfully'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
        
@app.route('/api/webhook/twitter/status', methods=['GET'])
def api_get_twitter_webhook_status():
    """Get status of registered webhooks"""
    try:
        # Get environment name (optional)
        environment_name = request.args.get('environment_name', 'dev')
        
        # Initialize Twitter service
        twitter_service = TwitterService()
        
        # Get webhook status
        result = twitter_service.get_webhook_status(environment_name)
        
        if not result['success']:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Unknown error getting webhook status')
            }), 400
            
        return jsonify({
            'success': True,
            'webhooks': result.get('webhooks', []),
            'subscriptions': result.get('subscriptions', []),
            'message': 'Webhook status retrieved successfully'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/webhooks/twitter/activity', methods=['POST'])
def twitter_webhook_event():
    """
    Handle Twitter webhook events sent to our application
    Includes functionality to cross-reference Solana addresses with suspicious activity
    """
    # Verify the request is from Twitter using signature validation
    # This is a simplified version - production should use more robust verification
    
    if not request.is_json:
        return jsonify({'error': 'Invalid request format'}), 400
    
    event_data = request.json
    print(f"Received Twitter webhook event: {json.dumps(event_data)[:200]}...")
    
    # Get our social media monitor instance
    social_monitor = get_social_media_monitor()
    
    if social_monitor:
        # Process the event with the social media monitor
        actions, suspicious_content = social_monitor.handle_twitter_event(event_data)
        
        # If suspicious content was found, record it and send notifications
        if suspicious_content:
            for item in suspicious_content:
                # Log the suspicious content
                print(f"Found suspicious addresses in tweet by @{item['username']}: {', '.join(item['addresses'])}")
                
                # Add to suspicious activity log
                if suspicious_detector:
                    for address in item['addresses']:
                        suspicious_detector.add_suspicious_address(
                            address, 
                            f"Mentioned on Twitter by @{item['username']}"
                        )
    
    # Process the different event types
    # Here we'll check for mention events which would be in for_user -> tweet_create_events
    if 'for_user_id' in event_data and 'tweet_create_events' in event_data:
        user_id = event_data['for_user_id']
        tweets = event_data['tweet_create_events']
        
        for tweet in tweets:
            # Skip our own tweets to avoid infinite loops
            if 'user' in tweet and 'screen_name' in tweet['user']:
                screen_name = tweet['user']['screen_name']
                # Check if this is a reply to us or a mention of us
                if 'in_reply_to_status_id' in tweet or 'entities' in tweet and 'user_mentions' in tweet['entities']:
                    # Process the mention specifically (for wallet check requests, etc.)
                    if social_monitor:
                        social_monitor.process_twitter_mention(tweet)
                    else:
                        process_twitter_mention(tweet)
    
    # Always return a 200 OK to Twitter regardless of processing outcome
    return jsonify({'status': 'ok'}), 200

def get_social_media_monitor():
    """Get or create a social media monitor instance"""
    global social_media_monitor, suspicious_detector, honeypot_detector
    
    if not hasattr(app, 'social_media_monitor'):
        # Only create if we have the necessary components
        if suspicious_detector and monitor and monitor.honeypot_detector:
            twitter_service = TwitterService()
            from social_media_monitor import SocialMediaMonitor
            app.social_media_monitor = SocialMediaMonitor(
                suspicious_detector=suspicious_detector,
                honeypot_detector=monitor.honeypot_detector,
                twitter_service=twitter_service
            )
        else:
            app.social_media_monitor = None
            
    return app.social_media_monitor

def process_twitter_mention(tweet):
    """Process a Twitter mention or reply (legacy method)"""
    if not monitor:
        return
        
    tweet_id = tweet.get('id_str')
    screen_name = tweet.get('user', {}).get('screen_name')
    text = tweet.get('text', '').lower()
    
    # Example: Respond to someone asking for a wallet check
    if 'check wallet' in text or 'scan wallet' in text:
        # Extract wallet address from tweet (simplified)
        # In production, use regex to extract Solana wallet addresses properly
        words = text.split()
        for word in words:
            if len(word) > 30 and not word.startswith('@'):
                potential_wallet = word.strip(',.!?:;')
                # Respond with a status on this wallet
                twitter_service = TwitterService()
                response = f"@{screen_name} I'm analyzing this wallet. Check the dashboard for results: https://solanascan.io/{potential_wallet}"
                twitter_service.post_tweet(response, alert_type="mention_reply")

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
        suspicious_detector,
        phishing_detector
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
