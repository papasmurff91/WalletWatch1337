"""
Social Media Monitoring for Solana Wallet Monitor
Identifies Solana addresses mentioned in social media and cross-references with suspicious activity
"""
import re
import json
import logging
from datetime import datetime

class SocialMediaMonitor:
    """Service for monitoring social media for suspicious Solana addresses"""
    
    def __init__(self, suspicious_detector=None, honeypot_detector=None, twitter_service=None):
        """Initialize the social media monitor with dependencies"""
        self.suspicious_detector = suspicious_detector
        self.honeypot_detector = honeypot_detector
        self.twitter_service = twitter_service
        self.solana_address_pattern = re.compile(r'[1-9A-HJ-NP-Za-km-z]{32,44}')
        self.social_alerts = []
        
    def extract_solana_addresses(self, text):
        """Extract potential Solana addresses from text"""
        if not text:
            return []
            
        # Find all potential Solana addresses (base58 strings of appropriate length)
        addresses = self.solana_address_pattern.findall(text)
        
        # Filter out non-Solana addresses (could add more validation here)
        # Solana addresses are typically 32-44 base58 characters
        valid_addresses = [addr for addr in addresses if len(addr) >= 32 and len(addr) <= 44]
        
        return valid_addresses
        
    def check_address_suspicion(self, address):
        """Check if an address is suspicious"""
        if not self.suspicious_detector:
            return False, "No suspicious detector available"
            
        # Check if address is in known suspicious addresses
        if address in self.suspicious_detector.suspicious_addresses:
            reason = self.suspicious_detector.suspicious_addresses.get(address, "Unknown")
            return True, reason
            
        # Check if address is associated with known honeypot tokens
        if self.honeypot_detector and address in self.honeypot_detector.honeypots:
            return True, "Associated with honeypot token"
            
        # In a production system, we would do more checks here,
        # such as checking historical transactions, connection to other
        # suspicious addresses, etc.
        
        return False, None
        
    def process_tweet(self, tweet_data, username=None):
        """
        Process a tweet for Solana addresses and check for suspicious activity
        Returns (is_suspicious, twitter_handle, addresses_found, reasons)
        """
        if not tweet_data:
            return False, None, [], []
            
        # Extract tweet text
        text = ""
        if isinstance(tweet_data, dict):
            # Extract from Twitter API v1.1 format
            text = tweet_data.get('text', '')
            username = username or tweet_data.get('user', {}).get('screen_name')
        elif isinstance(tweet_data, str):
            # Process raw text
            text = tweet_data
            
        if not text:
            return False, username, [], []
            
        # Extract potential Solana addresses
        addresses = self.extract_solana_addresses(text)
        
        if not addresses:
            return False, username, [], []
            
        # Check each address for suspicious activity
        suspicious_addresses = []
        reasons = []
        
        for address in addresses:
            is_suspicious, reason = self.check_address_suspicion(address)
            if is_suspicious:
                suspicious_addresses.append(address)
                reasons.append(f"{address}: {reason}")
                
        # Record this alert if suspicious addresses were found
        if suspicious_addresses and username:
            self.log_social_alert(username, suspicious_addresses, reasons)
            return True, username, suspicious_addresses, reasons
            
        return False, username, addresses, []
        
    def log_social_alert(self, username, addresses, reasons):
        """Log a social media alert for future reference"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'platform': 'twitter',
            'username': username,
            'addresses': addresses,
            'reasons': reasons
        }
        
        self.social_alerts.append(alert)
        
        # Keep only the most recent 100 alerts
        if len(self.social_alerts) > 100:
            self.social_alerts = self.social_alerts[-100:]
            
        return alert
        
    def get_recent_alerts(self, limit=10):
        """Get recent social media alerts"""
        # Sort alerts by timestamp in descending order (newest first)
        sorted_alerts = sorted(
            self.social_alerts,
            key=lambda x: x.get('timestamp', ''),
            reverse=True
        )
        
        return sorted_alerts[:limit]
        
    def handle_twitter_event(self, event_data):
        """
        Process a Twitter webhook event
        Returns actions to take (if any) and any detected suspicious activity
        """
        if not event_data:
            return None, None
            
        actions = []
        suspicious_content = []
        
        # Handle tweet creation events
        if 'tweet_create_events' in event_data:
            tweets = event_data['tweet_create_events']
            for tweet in tweets:
                # Skip our own tweets to avoid loops
                if 'user' in tweet and 'screen_name' in tweet['user']:
                    screen_name = tweet['user']['screen_name']
                    
                    # Process the tweet for suspicious addresses
                    is_suspicious, username, addresses, reasons = self.process_tweet(tweet, screen_name)
                    
                    if is_suspicious:
                        suspicious_content.append({
                            'username': username,
                            'addresses': addresses,
                            'reasons': reasons
                        })
                        
                        # Add action to post a reply if appropriate
                        if self.twitter_service:
                            actions.append({
                                'action': 'post_alert',
                                'platform': 'twitter',
                                'message': f"⚠️ Warning: Detected suspicious address(es) posted by @{username}. Check our dashboard for details.",
                                'in_reply_to': tweet.get('id_str')
                            })
                            
                            # Add action to record on website (no SMS)
                            actions.append({
                                'action': 'record_alert',
                                'platform': 'website',
                                'send_sms': False,
                                'details': {
                                    'username': username,
                                    'addresses': addresses,
                                    'reasons': reasons
                                }
                            })
        
        return actions, suspicious_content
        
    def process_twitter_mention(self, tweet_data):
        """
        Process a mention of our Twitter account
        This is for cases where someone asks us to check an address
        """
        if not tweet_data or not self.twitter_service:
            return None
            
        tweet_id = tweet_data.get('id_str')
        screen_name = tweet_data.get('user', {}).get('screen_name')
        text = tweet_data.get('text', '').lower()
        
        # Look for requests to check addresses
        check_keywords = ['check', 'scan', 'verify', 'analyze', 'investigate']
        is_check_request = any(keyword in text for keyword in check_keywords)
        
        if is_check_request:
            # Extract addresses from the tweet
            addresses = self.extract_solana_addresses(text)
            
            if addresses:
                # Analyze each address and prepare a response
                response_parts = [f"@{screen_name} Analysis of address(es):"]
                
                for address in addresses:
                    is_suspicious, reason = self.check_address_suspicion(address)
                    status = "⚠️ SUSPICIOUS" if is_suspicious else "✅ No issues detected"
                    
                    # Add shortened address and status to response
                    short_addr = f"{address[:6]}...{address[-4:]}"
                    response_parts.append(f"{short_addr}: {status}")
                    
                    if is_suspicious:
                        response_parts.append(f"Reason: {reason}")
                
                # Combine response parts and post as a reply
                response = "\n".join(response_parts)
                if len(response) > 280:
                    response = response[:270] + "... (see dashboard)"
                    
                self.twitter_service.post_tweet(response, alert_type="address_check_reply")
                return True
                
        return False