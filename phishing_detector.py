"""
Phishing detection module for Solana Wallet Monitor
Identifies common phishing attack patterns in transaction flow
"""
import json
import time
from datetime import datetime, timedelta
import re

class PhishingDetector:
    """Detects common phishing patterns in transaction flow"""
    
    def __init__(self, solana_rpc):
        """Initialize the phishing detector"""
        self.solana_rpc = solana_rpc
        self.phishing_addresses = set()
        self.recent_alerts = []
        self.tracked_addresses = {}  # Address -> {"first_seen": timestamp, "patterns": []}
        self.tracked_domains = {}    # Domain -> {"first_seen": timestamp, "count": 0}
        self.max_tracked = 1000
        self.min_pattern_confidence = 0.7
        
        # Common patterns of phishing transactions
        self.phishing_patterns = [
            {
                "name": "Approval Drainer",
                "description": "Token approval request followed by complete token drainage",
                "indicators": ["token_approval", "multiple_token_transfers_out"],
                "weight": 0.8
            },
            {
                "name": "SOL Drainage",
                "description": "Transfer of nearly all SOL leaving just enough for transaction fees",
                "indicators": ["near_total_sol_out"],
                "weight": 0.7
            },
            {
                "name": "Seed Phrase Stealer",
                "description": "Suspicious transaction creating accounts in sequence",
                "indicators": ["multiple_account_creations"],
                "weight": 0.9
            },
            {
                "name": "False NFT Mint",
                "description": "Creates fake NFTs that appear similar to popular collections",
                "indicators": ["similar_nft_mint", "unusual_metadata"],
                "weight": 0.6
            },
            {
                "name": "Multiple Wallet Drainage",
                "description": "Tokens from multiple wallets transferred to single destination",
                "indicators": ["multiple_source_wallets", "single_destination"],
                "weight": 0.8
            },
            {
                "name": "Airdrop Scam",
                "description": "Airdrop followed by phishing site interaction",
                "indicators": ["unexpected_airdrop", "approval_request"],
                "weight": 0.6
            }
        ]
        
        # Known phishing domains (partial matching)
        self.phishing_domain_patterns = [
            r"solana?-?claim",
            r"phantom-?wallet\.(?!io)",
            r"free-?sol",
            r"solana-?drop",
            r"solscan\.(?!io)",
            r"airdrop-?solana",
            r"solana-?nft-?mint",
            r"solana-?gift",
            r"wallet-?connect\.(?!org)"
        ]
        
        # Try to load phishing addresses from file
        try:
            with open("phishing_addresses.json", "r") as f:
                data = json.load(f)
                self.phishing_addresses = set(data["addresses"])
        except (FileNotFoundError, json.JSONDecodeError):
            self.phishing_addresses = set()
        
    def save_phishing_addresses(self):
        """Save phishing addresses to file"""
        with open("phishing_addresses.json", "w") as f:
            json.dump({"addresses": list(self.phishing_addresses)}, f)
    
    def add_phishing_address(self, address, reason="Manual addition"):
        """Add a phishing address to the database"""
        self.phishing_addresses.add(address)
        
        # Add to recent alerts
        alert = {
            "address": address,
            "reason": f"Phishing address identified: {reason}",
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        }
        self.recent_alerts.insert(0, alert)
        
        # Keep only most recent alerts
        if len(self.recent_alerts) > 50:
            self.recent_alerts = self.recent_alerts[:50]
            
        # Save to file
        self.save_phishing_addresses()
        
        return True
    
    def is_phishing_address(self, address):
        """Check if address is a known phishing address"""
        return address in self.phishing_addresses
    
    def check_transaction_memo(self, memo_text):
        """Check transaction memo for phishing URLs"""
        if not memo_text:
            return False, None
            
        # Simple URL extraction
        urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', memo_text)
        domains = []
        
        for url in urls:
            # Extract domain from URL
            domain_match = re.search(r'https?://([^/]+)', url)
            if domain_match:
                domain = domain_match.group(1).lower()
                domains.append(domain)
                
                # Track domain
                if domain in self.tracked_domains:
                    self.tracked_domains[domain]["count"] += 1
                else:
                    if len(self.tracked_domains) >= self.max_tracked:
                        # Remove oldest domain if we're tracking too many
                        oldest_domain = min(self.tracked_domains.items(), key=lambda x: x[1]["first_seen"])
                        del self.tracked_domains[oldest_domain[0]]
                        
                    self.tracked_domains[domain] = {
                        "first_seen": time.time(),
                        "count": 1
                    }
                
                # Check against phishing patterns
                for pattern in self.phishing_domain_patterns:
                    if re.search(pattern, domain, re.IGNORECASE):
                        return True, domain
                        
        return False, None
    
    def analyze_transaction(self, tx_data):
        """
        Analyze a transaction for phishing patterns
        Returns: (is_phishing, confidence, reason)
        """
        if not tx_data:
            return False, 0, None
            
        indicators = []
        total_weight = 0
        
        # Check memo for phishing URLs
        if "memo" in tx_data:
            is_phishing_url, domain = self.check_transaction_memo(tx_data["memo"])
            if is_phishing_url:
                indicators.append("phishing_url")
                total_weight += 0.9
                return True, 0.9, f"Transaction contains link to suspected phishing domain: {domain}"
        
        # Check for SOL drainage pattern (leaving minimal amount)
        if "sol_transfer" in tx_data and tx_data.get("sol_transfer_direction") == "out":
            amount = tx_data.get("sol_transfer_amount", 0)
            remaining = tx_data.get("sol_balance_after", 0)
            
            if amount > 0 and remaining < 0.01 and remaining > 0:
                indicators.append("near_total_sol_out")
                total_weight += 0.7
        
        # Check for token approval followed by transfer
        if tx_data.get("has_token_approval", False):
            indicators.append("token_approval")
            total_weight += 0.3
            
            # If we've seen approval then sudden outflow, this is suspicious
            if "account" in tx_data:
                account = tx_data["account"]
                if account in self.tracked_addresses:
                    if "token_approval" in self.tracked_addresses[account]["patterns"]:
                        # If there's been a recent approval and now tokens are flowing out
                        if "token_transfers" in tx_data and tx_data.get("token_transfer_direction") == "out":
                            indicators.append("approval_then_transfer")
                            total_weight += 0.6
        
        # Check for multiple token transfers out
        if "token_transfers" in tx_data and tx_data.get("token_transfer_count", 0) > 3 and tx_data.get("token_transfer_direction") == "out":
            indicators.append("multiple_token_transfers_out")
            total_weight += 0.5
            
        # Track this address for pattern detection
        self._track_address_patterns(tx_data.get("account"), indicators)
        
        # Calculate confidence
        pattern_count = len(indicators)
        confidence = total_weight if pattern_count > 0 else 0
        
        if confidence >= self.min_pattern_confidence:
            reason = f"Suspected phishing pattern: {', '.join(indicators)}"
            
            # If highly confident, add to phishing addresses
            if confidence > 0.85 and "account" in tx_data:
                self.add_phishing_address(tx_data["account"], reason)
                
            return True, confidence, reason
            
        return False, confidence, None
    
    def _track_address_patterns(self, address, new_patterns):
        """Track address patterns for temporal analysis"""
        if not address or not new_patterns:
            return
            
        current_time = time.time()
        
        if address in self.tracked_addresses:
            # Update existing entry
            entry = self.tracked_addresses[address]
            entry["patterns"].extend(new_patterns)
            entry["last_updated"] = current_time
            
            # Keep only recent patterns (last 24 hours)
            cutoff = current_time - (24 * 60 * 60)
            if entry.get("patterns_time"):
                recent_patterns = []
                recent_times = []
                
                for i, pattern_time in enumerate(entry["patterns_time"]):
                    if pattern_time >= cutoff:
                        recent_patterns.append(entry["patterns"][i])
                        recent_times.append(pattern_time)
                
                entry["patterns"] = recent_patterns
                entry["patterns_time"] = recent_times
            
            # Add timestamps for new patterns
            if "patterns_time" not in entry:
                entry["patterns_time"] = []
                
            entry["patterns_time"].extend([current_time] * len(new_patterns))
            
        else:
            # Create new entry
            if len(self.tracked_addresses) >= self.max_tracked:
                # Remove oldest entry if we're tracking too many
                oldest_address = min(self.tracked_addresses.items(), key=lambda x: x[1]["first_seen"])
                del self.tracked_addresses[oldest_address[0]]
                
            self.tracked_addresses[address] = {
                "first_seen": current_time,
                "last_updated": current_time,
                "patterns": new_patterns,
                "patterns_time": [current_time] * len(new_patterns)
            }
    
    def get_recent_alerts(self, limit=5):
        """Get recent phishing alerts"""
        return self.recent_alerts[:limit]
    
    def check_nft_metadata_similarity(self, mint, popular_collections):
        """Check if NFT metadata is suspiciously similar to popular collections"""
        metadata = self.solana_rpc.get_token_metadata(mint)
        if not metadata:
            return False, 0, None
            
        for collection in popular_collections:
            # Check name similarity
            name_similarity = self._get_string_similarity(
                metadata.get("name", "").lower(),
                collection.get("name", "").lower()
            )
            
            # Check symbol similarity
            symbol_similarity = self._get_string_similarity(
                metadata.get("symbol", "").lower(),
                collection.get("symbol", "").lower()
            )
            
            if name_similarity > 0.8 or symbol_similarity > 0.9:
                return True, max(name_similarity, symbol_similarity), collection.get("name")
                
        return False, 0, None
    
    def _get_string_similarity(self, str1, str2):
        """Get Levenshtein distance-based similarity between strings"""
        if not str1 or not str2:
            return 0
            
        # Simple length check
        if abs(len(str1) - len(str2)) / max(len(str1), len(str2)) > 0.3:
            return 0
            
        # Check if one string is contained in the other
        if str1 in str2 or str2 in str1:
            return 0.9
            
        # Simplified similarity based on character presence
        matches = sum(c in str2 for c in str1)
        return matches / max(len(str1), len(str2))