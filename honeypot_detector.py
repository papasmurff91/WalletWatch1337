"""
Honeypot token detector for Solana
"""
import json
import os
from datetime import datetime, timedelta
from config import HONEYPOT_FILE, WHITELIST_FILE, HONEYPOT_HEURISTICS

class HoneypotDetector:
    """
    Detects potential honeypot tokens on Solana based on transaction patterns
    and other heuristics
    """
    
    def __init__(self, solana_rpc):
        self.solana_rpc = solana_rpc
        self.honeypots = self.load_honeypots()
        self.whitelist = self.load_whitelist()
        self.transaction_cache = {}  # mint -> [transaction_timestamps]
        self.confidence_threshold = 0.75  # Default confidence threshold for honeypot detection
        
    def load_honeypots(self):
        """Load known honeypot tokens from file"""
        if os.path.exists(HONEYPOT_FILE):
            with open(HONEYPOT_FILE, "r") as f:
                try:
                    return set(json.load(f))
                except json.JSONDecodeError:
                    return set()
        return set()
    
    def save_honeypots(self):
        """Save honeypot tokens to file"""
        with open(HONEYPOT_FILE, "w") as f:
            json.dump(list(self.honeypots), f, indent=2)
            
    def load_whitelist(self):
        """Load whitelisted tokens from file"""
        if os.path.exists(WHITELIST_FILE):
            with open(WHITELIST_FILE, "r") as f:
                try:
                    return set(json.load(f))
                except json.JSONDecodeError:
                    return set()
        return set()
    
    def save_whitelist(self):
        """Save whitelisted tokens to file"""
        with open(WHITELIST_FILE, "w") as f:
            json.dump(list(self.whitelist), f, indent=2)
    
    def add_to_whitelist(self, mint):
        """Add token to whitelist"""
        if mint in self.honeypots:
            self.honeypots.remove(mint)
            self.save_honeypots()
        
        self.whitelist.add(mint)
        self.save_whitelist()
    
    def is_honeypot(self, mint):
        """Check if a token is a known honeypot"""
        if mint in self.whitelist:
            return False
        return mint in self.honeypots
    
    def has_suspicious_metadata(self, mint):
        """Check if token has suspicious or missing metadata"""
        metadata = self.solana_rpc.get_token_metadata(mint)
        return not metadata  # True if no metadata found
    
    def has_few_holders(self, mint):
        """Check if token has suspiciously few holders"""
        holders = self.solana_rpc.get_token_holders(mint)
        return holders < HONEYPOT_HEURISTICS["unusual_holders_threshold"]
    
    def has_high_velocity(self, mint):
        """Check if token has high transaction velocity (many txs in short time)"""
        if mint not in self.transaction_cache:
            return False
            
        now = datetime.now()
        recent_window = now - timedelta(seconds=HONEYPOT_HEURISTICS["time_window_seconds"])
        
        # Count transactions in the recent time window
        recent_txs = [tx for tx in self.transaction_cache[mint] if tx > recent_window]
        return len(recent_txs) >= HONEYPOT_HEURISTICS["high_velocity_threshold"]
    
    def track_transaction(self, mint):
        """Track a transaction for a token to detect velocity"""
        if mint not in self.transaction_cache:
            self.transaction_cache[mint] = []
            
        self.transaction_cache[mint].append(datetime.now())
        
        # Cleanup old transactions
        now = datetime.now()
        cutoff = now - timedelta(hours=1)  # Keep only last hour of transactions
        self.transaction_cache[mint] = [tx for tx in self.transaction_cache[mint] if tx > cutoff]
    
    def analyze_token(self, mint):
        """
        Analyze a token for honeypot characteristics
        Returns: (is_suspicious, confidence, reasons)
        """
        if mint in self.whitelist:
            return False, 0, ["Token is whitelisted"]
            
        if mint in self.honeypots:
            return True, 1.0, ["Token is a known honeypot"]
            
        reasons = []
        confidence = 0
        
        # Check token price
        price = self.solana_rpc.get_token_price_usd(mint)
        if price == 0:
            reasons.append("Token has zero price")
            confidence += 0.3
        
        # Check for suspicious metadata
        if self.has_suspicious_metadata(mint):
            reasons.append("Missing on-chain metadata")
            confidence += 0.2
        
        # Check for few holders
        if self.has_few_holders(mint):
            reasons.append(f"Few token holders (<{HONEYPOT_HEURISTICS['unusual_holders_threshold']})")
            confidence += 0.25
        
        # Check for high transaction velocity
        if self.has_high_velocity(mint):
            reasons.append("High transaction velocity")
            confidence += 0.25
            
        # If confidence is high enough, mark as honeypot
        if confidence >= 0.5:
            self.honeypots.add(mint)
            self.save_honeypots()
            return True, confidence, reasons
            
        return False, confidence, reasons
