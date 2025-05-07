"""
Notification service for the Solana wallet monitor
Handles sending alerts to Discord, Telegram, and Twitter/X.com
"""
import requests
import json
import time
from datetime import datetime
from config import DISCORD_WEBHOOK_URL, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
from twitter_service import TwitterService

class NotificationService:
    """Service for sending notifications to various platforms"""
    
    def __init__(self):
        self.discord_enabled = bool(DISCORD_WEBHOOK_URL)
        self.telegram_enabled = bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)
        self.twitter_service = TwitterService()
        self.last_notification = {}  # Keep track of last notification time per type
        
    def _rate_limit(self, notification_type, seconds=60):
        """Rate limit notifications to prevent spam"""
        current_time = time.time()
        if notification_type in self.last_notification:
            time_since_last = current_time - self.last_notification[notification_type]
            if time_since_last < seconds:
                return False
                
        self.last_notification[notification_type] = current_time
        return True
        
    def send_discord(self, title, message, color=16711680):
        """Send a message to Discord webhook"""
        if not self.discord_enabled:
            return False
            
        webhook_data = {
            "embeds": [{
                "title": title,
                "description": message,
                "color": color,
                "footer": {
                    "text": f"Solana Wallet Monitor • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                }
            }]
        }
        
        try:
            response = requests.post(
                DISCORD_WEBHOOK_URL,
                json=webhook_data,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            return response.status_code == 204
        except Exception as e:
            print(f"Discord notification error: {e}")
            return False
            
    def send_telegram(self, message):
        """Send a message to Telegram"""
        if not self.telegram_enabled:
            return False
            
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            data = {
                "chat_id": TELEGRAM_CHAT_ID,
                "text": message,
                "parse_mode": "Markdown"
            }
            response = requests.post(url, json=data, timeout=10)
            return response.status_code == 200
        except Exception as e:
            print(f"Telegram notification error: {e}")
            return False
            
    def notify_honeypot_detected(self, mint, reasons, confidence):
        """Send notification when a honeypot token is detected"""
        if not self._rate_limit(f"honeypot_{mint}", 3600):  # Only once per hour per token
            return
            
        title = "🚨 Honeypot Token Detected"
        message = f"**Token:** {mint[:8]}...{mint[-8:]}\n"
        message += f"**Confidence:** {confidence:.2f}\n"
        message += "**Reasons:**\n"
        for reason in reasons:
            message += f"• {reason}\n"
            
        self.send_discord(title, message)
        
        telegram_msg = f"🚨 *Honeypot Token Detected*\n\n"
        telegram_msg += f"*Token:* `{mint[:8]}...{mint[-8:]}`\n"
        telegram_msg += f"*Confidence:* {confidence:.2f}\n"
        telegram_msg += "*Reasons:*\n"
        for reason in reasons:
            telegram_msg += f"• {reason}\n"
            
        self.send_telegram(telegram_msg)
        
        # Send to Twitter
        self.twitter_service.notify_honeypot_detected(mint, reasons, confidence)
        
    def notify_honeypot_transfer(self, mint, direction, amount, other_address):
        """Send notification when a honeypot token is transferred"""
        if not self._rate_limit(f"transfer_{mint}", 300):  # Once per 5 minutes per token
            return
            
        title = "⚠️ Honeypot Token Transfer"
        message = f"**Token:** {mint[:8]}...{mint[-8:]}\n"
        message += f"**{direction}:** {amount} tokens\n"
        message += f"**{'From' if direction == 'Received' else 'To'}:** {other_address[:8]}...{other_address[-8:]}"
        
        self.send_discord(title, message, color=16776960)  # Yellow
        
        telegram_msg = f"⚠️ *Honeypot Token Transfer*\n\n"
        telegram_msg += f"*Token:* `{mint[:8]}...{mint[-8:]}`\n"
        telegram_msg += f"*{direction}:* {amount} tokens\n"
        telegram_msg += f"*{'From' if direction == 'Received' else 'To'}:* `{other_address[:8]}...{other_address[-8:]}`"
        
        self.send_telegram(telegram_msg)
        
    def notify_honeypot_swap(self, mint, program_id):
        """Send notification when a honeypot token is swapped"""
        if not self._rate_limit(f"swap_{mint}", 300):  # Once per 5 minutes per token
            return
            
        title = "🔄 Honeypot Swap Attempted"
        message = f"**Token:** {mint[:8]}...{mint[-8:]}\n"
        message += f"**Program:** {program_id[:8]}...{program_id[-8:]}"
        
        self.send_discord(title, message, color=3447003)  # Blue
        
        telegram_msg = f"🔄 *Honeypot Swap Attempted*\n\n"
        telegram_msg += f"*Token:* `{mint[:8]}...{mint[-8:]}`\n"
        telegram_msg += f"*Program:* `{program_id[:8]}...{program_id[-8:]}`"
        
        self.send_telegram(telegram_msg)
        
    def notify_token_worthless(self, mint):
        """Send notification when a token becomes worthless"""
        if not self._rate_limit(f"worthless_{mint}", 86400):  # Once per day per token
            return
            
        title = "💸 Token Value Alert"
        message = f"**Token:** {mint[:8]}...{mint[-8:]}\n"
        message += "**Alert:** This token appears to be worthless now"
        
        self.send_discord(title, message, color=10038562)  # Dark purple
        
        telegram_msg = f"💸 *Token Value Alert*\n\n"
        telegram_msg += f"*Token:* `{mint[:8]}...{mint[-8:]}`\n"
        telegram_msg += "*Alert:* This token appears to be worthless now"
        
        self.send_telegram(telegram_msg)
        
    def notify_large_transfer(self, token_name, amount, direction, other_address):
        """Send notification for large token transfers"""
        if not self._rate_limit(f"large_transfer_{token_name}", 300):  # Once per 5 minutes per token
            return
            
        title = "💰 Large Transfer Detected"
        message = f"**Token:** {token_name}\n"
        message += f"**Amount:** {amount}\n"
        message += f"**{direction} {'from' if direction == 'Received' else 'to'}:** {other_address[:8]}...{other_address[-8:]}"
        
        self.send_discord(title, message, color=5763719)  # Green
        
        telegram_msg = f"💰 *Large Transfer Detected*\n\n"
        telegram_msg += f"*Token:* {token_name}\n"
        telegram_msg += f"*Amount:* {amount}\n"
        telegram_msg += f"*{direction} {'from' if direction == 'Received' else 'to'}:* `{other_address[:8]}...{other_address[-8:]}`"
        
        self.send_telegram(telegram_msg)
        
        # Send to Twitter
        self.twitter_service.notify_large_transfer(token_name, amount, direction, other_address)
        
    def notify_jupiter_swap(self, swap_data):
        """Send notification for Jupiter swap alerts with account tagging"""
        # Extract data from the swap alert
        signature = swap_data.get('signature', 'Unknown')
        swap_details = swap_data.get('swap_details', {})
        risk_analysis = swap_data.get('risk_analysis', {})
        associated_accounts = swap_data.get('associated_accounts', [])
        
        # Rate limit based on signature
        if not self._rate_limit(f"jupiter_swap_{signature}", 300):  # Once per 5 minutes per swap
            return
            
        # Get swap details
        input_token = swap_details.get('input_token', 'Unknown')
        input_amount = swap_details.get('input_amount', 0)
        output_token = swap_details.get('output_token', 'Unknown')
        output_amount = swap_details.get('output_amount', 0)
        risk_level = risk_analysis.get('overall_risk', 'Unknown').upper()
        reasons = risk_analysis.get('reasons', [])
        
        # Prepare Discord message
        title = f"🔄 Jupiter Swap Alert - {risk_level} RISK"
        message = f"**Swap:** {input_amount} {input_token} → {output_amount} {output_token}\n"
        message += f"**Risk Level:** {risk_level}\n"
        
        if reasons:
            message += "**Risk Factors:**\n"
            for reason in reasons:
                message += f"• {reason}\n"
                
        if associated_accounts:
            message += "\n**Associated Accounts:**\n"
            for account in associated_accounts:
                platform = account.get('platform', '')
                username = account.get('username', '')
                tag = account.get('tag', 'unknown')
                if platform and username:
                    message += f"• {platform} @{username} ({tag})\n"
                else:
                    message += f"• {account.get('address', '')} ({tag})\n"
        
        message += f"\n**Transaction:** {signature[:8]}...{signature[-8:]}"
        
        # Set color based on risk level
        color = 3447003  # Blue (default/low)
        if risk_level == "CRITICAL" or risk_level == "HIGH":
            color = 16711680  # Red
        elif risk_level == "MEDIUM":
            color = 16776960  # Yellow
            
        self.send_discord(title, message, color=color)
        
        # Prepare Telegram message
        telegram_msg = f"🔄 *Jupiter Swap Alert - {risk_level} RISK*\n\n"
        telegram_msg += f"*Swap:* {input_amount} {input_token} → {output_amount} {output_token}\n"
        telegram_msg += f"*Risk Level:* {risk_level}\n"
        
        if reasons:
            telegram_msg += "\n*Risk Factors:*\n"
            for reason in reasons:
                telegram_msg += f"• {reason}\n"
                
        if associated_accounts:
            telegram_msg += "\n*Associated Accounts:*\n"
            for account in associated_accounts:
                platform = account.get('platform', '')
                username = account.get('username', '')
                tag = account.get('tag', 'unknown')
                if platform and username:
                    telegram_msg += f"• {platform} @{username} ({tag})\n"
                else:
                    telegram_msg += f"• `{account.get('address', '')}` ({tag})\n"
        
        telegram_msg += f"\n*Transaction:* `{signature[:8]}...{signature[-8:]}`"
        
        self.send_telegram(telegram_msg)
        
        # Send to Twitter if it's high risk
        if risk_level in ["HIGH", "CRITICAL"]:
            self.twitter_service.notify_suspicious_activity(
                output_token, 
                f"High-risk Jupiter swap detected: {input_amount} {input_token} to {output_amount} {output_token}"
            )
