"""
Suspicious activity detection for Solana wallet transactions
"""
import json
import os
import time
from datetime import datetime, timedelta
from config import SUSPICIOUS_ADDRESSES_FILE

# Suspicious activity detection thresholds
THRESHOLDS = {
    "large_sol_transfer": 25.0,           # SOL amount that's considered large
    "rapid_transactions": 5,              # Number of transactions within time window to be suspicious
    "rapid_time_window": 60,              # Time window in seconds for rapid transactions
    "many_token_transfers": 10,           # Number of token transfers to be suspicious
    "unusual_time_window": 300,           # Time window to track unusual activity (5 min)
    "high_value_transfer": 1000.0,        # High value in USD
    "contract_interaction_count": 3,      # Number of different program interactions to be suspicious
    "unusual_program_ids": [              # Program IDs that are potentially suspicious
        "11111111111111111111111111111111",  # System Program - for large transfers only
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",  # SPL Token Program - for unusual token patterns
    ],
    "known_scam_addresses": [             # Known addresses associated with scams
        # These would normally be loaded from an external source or API
    ]
}

class SuspiciousActivityDetector:
    """Detects suspicious or unusual activity on the Solana blockchain"""
    
    def __init__(self, solana_rpc):
        self.solana_rpc = solana_rpc
        self.suspicious_addresses = self.load_suspicious_addresses()
        self.address_activity = {}  # address -> {timestamp: [tx_count, sol_volume, token_volume]}
        self.recent_alerts = []     # To store recent alerts for display
        
    def load_suspicious_addresses(self):
        """Load list of known suspicious addresses"""
        if os.path.exists(SUSPICIOUS_ADDRESSES_FILE):
            try:
                with open(SUSPICIOUS_ADDRESSES_FILE, "r") as f:
                    return set(json.load(f))
            except json.JSONDecodeError:
                return set()
        return set()
        
    def save_suspicious_addresses(self):
        """Save suspicious addresses to file"""
        with open(SUSPICIOUS_ADDRESSES_FILE, "w") as f:
            json.dump(list(self.suspicious_addresses), f, indent=2)
            
    def add_suspicious_address(self, address, reason):
        """Add an address to the suspicious list"""
        self.suspicious_addresses.add(address)
        self.save_suspicious_addresses()
        
        # Create an alert for the newly flagged address
        alert = {
            "address": address,
            "reason": reason,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        self.recent_alerts.append(alert)
        
        # Keep only recent alerts (last 20)
        if len(self.recent_alerts) > 20:
            self.recent_alerts = self.recent_alerts[-20:]
            
        return alert
    
    def is_suspicious_address(self, address):
        """Check if an address is on the suspicious list"""
        if address in THRESHOLDS["known_scam_addresses"]:
            return True
        return address in self.suspicious_addresses
        
    def track_address_activity(self, address, tx_data):
        """Track activity for an address to detect unusual patterns"""
        current_time = datetime.now()
        
        if address not in self.address_activity:
            self.address_activity[address] = []
            
        # Add the new transaction data
        activity = {
            "timestamp": current_time,
            "tx_signature": tx_data.get("signature", ""),
            "sol_amount": 0,
            "token_amount_usd": 0,
            "programs": set()
        }
        
        # Extract relevant data from the transaction
        for event in tx_data.get("events", []):
            if event["type"] == "sol_transfer":
                activity["sol_amount"] += float(event.get("amount", 0))
            elif event["type"] == "token_transfer":
                # Try to get USD price if available, otherwise estimate
                mint = event.get("mint", "")
                price = self.solana_rpc.get_token_price_usd(mint)
                activity["token_amount_usd"] += float(event.get("amount", 0)) * price
                
        # Track program IDs
        for program_id in tx_data.get("program_ids", []):
            activity["programs"].add(program_id)
            
        self.address_activity[address].append(activity)
        
        # Clean up old activity data
        cutoff_time = current_time - timedelta(minutes=10)
        self.address_activity[address] = [
            a for a in self.address_activity[address] 
            if a["timestamp"] > cutoff_time
        ]
        
    def analyze_address(self, address):
        """
        Analyze an address for suspicious activity
        Returns: (is_suspicious, reason)
        """
        if not address in self.address_activity:
            return False, ""
            
        # Get recent activity within the unusual time window
        now = datetime.now()
        recent_window = now - timedelta(seconds=THRESHOLDS["unusual_time_window"])
        recent_activity = [
            a for a in self.address_activity[address] 
            if a["timestamp"] > recent_window
        ]
        
        if not recent_activity:
            return False, ""
            
        # Check for rapid transaction count
        if len(recent_activity) >= THRESHOLDS["rapid_transactions"]:
            very_recent = now - timedelta(seconds=THRESHOLDS["rapid_time_window"])
            very_recent_activity = [
                a for a in self.address_activity[address]
                if a["timestamp"] > very_recent
            ]
            
            if len(very_recent_activity) >= THRESHOLDS["rapid_transactions"]:
                return True, f"Unusually high transaction velocity: {len(very_recent_activity)} transactions in {THRESHOLDS['rapid_time_window']} seconds"
        
        # Check for large SOL transfers
        sol_volume = sum(a["sol_amount"] for a in recent_activity)
        if sol_volume >= THRESHOLDS["large_sol_transfer"]:
            return True, f"Large SOL transfer detected: {sol_volume:.2f} SOL"
            
        # Check for high value token transfers
        token_volume_usd = sum(a["token_amount_usd"] for a in recent_activity)
        if token_volume_usd >= THRESHOLDS["high_value_transfer"]:
            return True, f"High value token transfer: ${token_volume_usd:.2f}"
            
        # Check for interaction with multiple contract programs
        all_programs = set()
        for activity in recent_activity:
            all_programs.update(activity["programs"])
            
        suspicious_programs = [p for p in all_programs if p in THRESHOLDS["unusual_program_ids"]]
        if len(suspicious_programs) >= THRESHOLDS["contract_interaction_count"]:
            return True, f"Unusual interaction with {len(suspicious_programs)} different programs"
            
        return False, ""
        
    def get_recent_alerts(self, limit=5):
        """Get the most recent alerts"""
        if limit and limit < len(self.recent_alerts):
            return self.recent_alerts[-limit:]
        return self.recent_alerts
        
    def analyze_transaction(self, tx_data):
        """
        Analyze a transaction for suspicious activity
        Returns: (is_suspicious, reason)
        """
        if not tx_data or not "events" in tx_data:
            return False, ""
            
        # Extract addresses from the transaction
        addresses = []
        for event in tx_data.get("events", []):
            if "other_address" in event:
                addresses.append(event["other_address"])
                
        # Check if any address is already known to be suspicious
        for address in addresses:
            if self.is_suspicious_address(address):
                return True, f"Interaction with known suspicious address: {address[:8]}...{address[-8:]}"
                
        # Track activity for each address
        for address in addresses:
            self.track_address_activity(address, tx_data)
            
            # Analyze the address for suspicious activity
            is_suspicious, reason = self.analyze_address(address)
            if is_suspicious:
                self.add_suspicious_address(address, reason)
                return True, f"Suspicious activity detected for address {address[:8]}...{address[-8:]}: {reason}"
                
        return False, ""