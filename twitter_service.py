"""
Twitter/X.com integration service for the Solana Wallet Monitor
Handles sending alerts to Twitter/X.com via Tweepy
"""
import os
import time
import json
import hmac
import hashlib
import base64
import requests
import tweepy
from datetime import datetime
from config import (
    TWITTER_API_KEY,
    TWITTER_API_SECRET,
    TWITTER_ACCESS_TOKEN,
    TWITTER_ACCESS_SECRET,
    TWITTER_BEARER_TOKEN,
    TWITTER_CLIENT_ID,
    TWITTER_CLIENT_SECRET,
    LOG_FILE
)

class TwitterService:
    """Service for sending notifications to Twitter/X.com"""

    def __init__(self):
        self.api_key = TWITTER_API_KEY
        self.api_secret = TWITTER_API_SECRET
        self.access_token = TWITTER_ACCESS_TOKEN
        self.access_secret = TWITTER_ACCESS_SECRET
        self.bearer_token = TWITTER_BEARER_TOKEN
        self.client_id = TWITTER_CLIENT_ID
        self.client_secret = TWITTER_CLIENT_SECRET
        
        # Rate limiting
        self.last_tweet_time = {}
        self.tweet_count = 0
        self.max_tweets_per_day = 100  # Twitter API has limits
        self.last_reset = datetime.now()
        
        # Initialize Tweepy clients
        self.client = None  # v2 API client
        self.api = None     # v1.1 API client
        self._initialize_tweepy()
        
        # Log initialization
        self.log_message("Twitter service initialized")
        
    def _initialize_tweepy(self):
        """Initialize Tweepy clients for both v1 and v2 APIs"""
        try:
            # First try v2 client (preferred)
            if self.bearer_token:
                self.client = tweepy.Client(
                    bearer_token=self.bearer_token,
                    consumer_key=self.api_key,
                    consumer_secret=self.api_secret,
                    access_token=self.access_token,
                    access_token_secret=self.access_secret
                )
                self.log_message("Initialized Tweepy v2 client successfully")
            
            # Also set up v1.1 API as fallback
            if all([self.api_key, self.api_secret, self.access_token, self.access_secret]):
                auth = tweepy.OAuth1UserHandler(
                    self.api_key,
                    self.api_secret,
                    self.access_token,
                    self.access_secret
                )
                self.api = tweepy.API(auth)
                self.log_message("Initialized Tweepy v1.1 API successfully")
                
        except Exception as e:
            self.log_message(f"Error initializing Tweepy: {str(e)}")
        
    def log_message(self, msg):
        """Log a message to the log file"""
        with open(LOG_FILE, "a") as f:
            f.write(f"[Twitter] [{datetime.utcnow()}] {msg}\n")
        print(f"[Twitter] {msg}")
        
    def _rate_limit(self, alert_type, seconds=300):
        """Rate limit notifications to prevent spam"""
        current_time = datetime.now()
        
        # Reset daily tweet counter if needed
        day_seconds = 24 * 60 * 60
        if (current_time - self.last_reset).total_seconds() > day_seconds:
            self.tweet_count = 0
            self.last_reset = current_time
            
        # Check if we've hit the daily limit
        if self.tweet_count >= self.max_tweets_per_day:
            self.log_message(f"Daily tweet limit reached ({self.max_tweets_per_day})")
            return False
            
        # Check type-specific rate limit
        if alert_type in self.last_tweet_time:
            if (current_time - self.last_tweet_time[alert_type]).total_seconds() < seconds:
                self.log_message(f"Rate limited tweet of type {alert_type}")
                return False
                
        # Update rate limit trackers
        self.last_tweet_time[alert_type] = current_time
        self.tweet_count += 1
        return True
        
    def _create_oauth1_header(self, method, url, params=None):
        """Create OAuth 1.0a header for Twitter API v1.1"""
        if not all([self.api_key, self.api_secret, self.access_token, self.access_secret]):
            self.log_message("Missing Twitter API credentials for OAuth 1.0a")
            return None
            
        # Create OAuth 1.0a signature
        # This implementation is simplified and for demonstration purposes only
        # In a production environment, use an established OAuth library
        try:
            import oauthlib.oauth1
            client = oauthlib.oauth1.Client(
                self.api_key,
                client_secret=self.api_secret,
                resource_owner_key=self.access_token,
                resource_owner_secret=self.access_secret
            )
            
            uri, headers, _ = client.sign(url, method)
            return headers
        except ImportError:
            self.log_message("oauthlib not installed, using simplified OAuth1 implementation")
            
            # Simplified OAuth 1.0a implementation (not for production)
            oauth_params = {
                'oauth_consumer_key': self.api_key,
                'oauth_nonce': hashlib.md5(str(time.time()).encode()).hexdigest(),
                'oauth_signature_method': 'HMAC-SHA1',
                'oauth_timestamp': str(int(time.time())),
                'oauth_token': self.access_token,
                'oauth_version': '1.0'
            }
            
            # Add query parameters to signature base
            if params:
                base_params = {**oauth_params, **params}
            else:
                base_params = oauth_params
                
            # Create signature base string
            param_string = '&'.join([f"{k}={v}" for k, v in sorted(base_params.items())])
            base_string = f"{method}&{requests.utils.quote(url, safe='')}&{requests.utils.quote(param_string, safe='')}"
            
            # Create signing key
            signing_key = f"{requests.utils.quote(self.api_secret, safe='')}&{requests.utils.quote(self.access_secret, safe='')}"
            
            # Generate signature
            signature = base64.b64encode(
                hmac.new(
                    signing_key.encode(),
                    base_string.encode(),
                    hashlib.sha1
                ).digest()
            ).decode()
            
            # Add signature to OAuth params
            oauth_params['oauth_signature'] = signature
            
            # Create header string
            auth_header = 'OAuth ' + ', '.join([f'{requests.utils.quote(k, safe="")}="{requests.utils.quote(v, safe="")}"' for k, v in oauth_params.items()])
            
            return {'Authorization': auth_header}
            
    def _get_bearer_token_header(self):
        """Get Bearer Token header for Twitter API v2"""
        if not self.bearer_token:
            self.log_message("Missing Twitter Bearer Token")
            return None
            
        return {'Authorization': f'Bearer {self.bearer_token}'}
        
    def post_tweet(self, message, alert_type="general"):
        """Post a tweet to Twitter/X.com using Tweepy"""
        # Apply rate limiting
        if not self._rate_limit(alert_type):
            return False
            
        # Truncate message if needed
        max_length = 280
        if len(message) > max_length:
            message = message[:max_length-3] + "..."
            
        # Try using Tweepy client v2 first, then fall back to v1.1
        try:
            if self.client:
                response = self.client.create_tweet(text=message)
                tweet_id = response.data['id']
                self.log_message(f"Tweet posted via Tweepy v2: {message[:30]}... (ID: {tweet_id})")
                return True
            raise ValueError("Tweepy v2 client not available")
                
        except Exception as e:
            self.log_message(f"Error posting tweet with Tweepy v2: {str(e)}")
            
            try:
                if self.api:
                    status = self.api.update_status(message)
                    self.log_message(f"Tweet posted via Tweepy v1.1: {message[:30]}... (ID: {status.id})")
                    return True
                else:
                    self.log_message("Tweepy v1.1 API not available")
                    return False
                    
            except Exception as e2:
                self.log_message(f"Error posting tweet with Tweepy v1.1: {str(e2)}")
                return False
            
    def notify_honeypot_detected(self, mint, reasons, confidence):
        """Send notification when a honeypot token is detected"""
        message = f"⚠️ ALERT: Honeypot token detected!\n\nMint: {mint[:8]}...{mint[-8:]}\nConfidence: {confidence:.0f}%\nReason: {reasons[0] if reasons else 'Suspicious pattern'}\n\n#Solana #Honeypot #CryptoSecurity"
        return self.post_tweet(message, "honeypot_detected")
        
    def notify_suspicious_activity(self, address, reason):
        """Send notification when suspicious activity is detected"""
        message = f"🔍 SUSPICIOUS ACTIVITY DETECTED!\n\nAddress: {address[:8]}...{address[-8:]}\nActivity: {reason}\n\n#Solana #CryptoSecurity #FraudAlert"
        return self.post_tweet(message, "suspicious_activity")
        
    def notify_large_transfer(self, token_name, amount, direction, other_address):
        """Send notification for large token transfers"""
        message = f"💰 Large Transfer Alert!\n\n{amount} {token_name} {direction.lower()} {other_address[:8]}...{other_address[-8:]}\n\n#Solana #WhaleAlert #Crypto"
        return self.post_tweet(message, "large_transfer")
        
    def notify_flash_launch(self, mint, creator):
        """Send notification for flash launch detection"""
        message = f"⚡ Flash Launch Detected!\n\nMint: {mint[:8]}...{mint[-8:]}\nCreator: {creator[:8]}...{creator[-8:]}\n\nThis token shows pump and dump patterns. Exercise caution!\n\n#Solana #FlashLaunch #CryptoScam"
        return self.post_tweet(message, "flash_launch")
        
    def notify_bridge_abuse(self, address, details):
        """Send notification for cross-chain bridge abuse"""
        message = f"🌉 Bridge Abuse Alert!\n\nAddress: {address[:8]}...{address[-8:]}\nDetails: {details}\n\nPossible cross-chain money laundering detected.\n\n#Solana #CrossChain #CryptoSecurity"
        return self.post_tweet(message, "bridge_abuse")
        
    def notify_phishing_detected(self, address, reason, confidence):
        """Send notification when phishing is detected"""
        message = f"🎣 Phishing attempt detected!\n\n"
        message += f"Address: {address[:8]}...{address[-8:]}\n"
        message += f"Type: {reason}\n"
        message += f"Confidence: {int(confidence * 100)}%\n\n"
        message += "#Solana #PhishingAlert #CryptoSecurity"
        
        return self.post_tweet(message, "phishing_detected")
        
    def get_user_timeline(self, username=None, user_id=None, count=10):
        """Get a user's timeline using Tweepy"""
        try:
            if self.client:
                if user_id:
                    response = self.client.get_users_tweets(id=user_id, max_results=count)
                    return response.data if response.data else []
                elif username:
                    # First get the user ID from the username
                    user_response = self.client.get_user(username=username)
                    if user_response.data:
                        user_id = user_response.data.id
                        response = self.client.get_users_tweets(id=user_id, max_results=count)
                        return response.data if response.data else []
            
            # Fallback to v1.1
            if self.api:
                if username:
                    statuses = self.api.user_timeline(screen_name=username, count=count)
                elif user_id:
                    statuses = self.api.user_timeline(user_id=user_id, count=count)
                else:
                    return []
                
                return [status._json for status in statuses]
                
        except Exception as e:
            self.log_message(f"Error getting timeline: {str(e)}")
            return []
    
    def search_tweets(self, query, count=10):
        """Search for tweets with a specific query"""
        try:
            if self.client:
                response = self.client.search_recent_tweets(query=query, max_results=min(count, 100))
                return response.data if response.data else []
            
            # Fallback to v1.1
            if self.api:
                search_results = self.api.search_tweets(q=query, count=count)
                return [tweet._json for tweet in search_results]
                
            return []
                
        except Exception as e:
            self.log_message(f"Error searching tweets: {str(e)}")
            return []
    
    def get_crypto_trends(self):
        """Get cryptocurrency trending topics on Twitter"""
        try:
            crypto_queries = ["#Solana", "#Crypto", "#Bitcoin", "#Ethereum", "#Web3"]
            results = {}
            
            for query in crypto_queries:
                if self.client:
                    # V2 API search
                    response = self.client.search_recent_tweets(
                        query=query, 
                        max_results=10
                    )
                    tweets = response.data if response.data else []
                    results[query] = len(tweets)
                elif self.api:
                    # V1.1 API search
                    tweets = self.api.search_tweets(q=query, count=10)
                    results[query] = len(tweets)
            
            return results
                
        except Exception as e:
            self.log_message(f"Error getting crypto trends: {str(e)}")
            return {}