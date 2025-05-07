"""
Notification service for the Solana wallet monitor
Handles sending alerts to Discord and Telegram
"""
import requests
import json
import time
from datetime import datetime
from config import DISCORD_WEBHOOK_URL, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID

class NotificationService:
    """Service for sending notifications to various platforms"""
    
    def __init__(self):
        self.discord_enabled = bool(DISCORD_WEBHOOK_URL)
        self.telegram_enabled = bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)
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
