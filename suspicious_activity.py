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
    # Basic suspicious activity parameters
    "large_sol_transfer": 25.0,           # SOL amount that's considered large
    "rapid_transactions": 5,              # Number of transactions within time window to be suspicious
    "rapid_time_window": 60,              # Time window in seconds for rapid transactions
    "many_token_transfers": 10,           # Number of token transfers to be suspicious
    "unusual_time_window": 300,           # Time window to track unusual activity (5 min)
    "high_value_transfer": 1000.0,        # High value in USD
    "contract_interaction_count": 3,      # Number of different program interactions to be suspicious
    
    # Flash token launch detection
    "new_token_age_threshold": 3600,      # Token created within last hour (in seconds)
    "liquidity_drain_threshold": 0.9,     # 90% of liquidity removed
    "volume_spike_threshold": 5,          # 5x increase in volume from previous period
    
    # Sybil attack detection
    "wallet_group_threshold": 10,         # Number of similar wallets needed to flag
    "similar_action_threshold": 3,        # Number of identical actions needed
    "wallet_creation_window": 300,        # Time window for related wallet creation (5 min)
    
    # Airdrop and token restriction detection  
    "failed_sell_count": 3,               # Number of failed sell attempts to flag
    
    # Bridge abuse detection
    "cross_chain_transfer_window": 600,   # Time window for rapid cross-chain transfers (10 min)
    "min_bridge_transfers": 2,            # Minimum number of bridge transfers to be suspicious
    
    # Smart contract exploit detection
    "abnormal_instruction_count": 50,     # Unusually high number of instructions 
    "rent_exempt_sol_drain": 0.1,         # SOL drain from rent-exempt accounts
    
    # Program IDs to monitor
    "bridge_program_ids": [               # Known bridge programs
        "wormDTUJ6AWPNvk59vGQbDvGJmqbDTdgWgAqcLBCgUb", # Wormhole
        "3u8hJUVTA4jH1wYAyUur7FFZVQ8H635K3tSHHF4ssjQ5", # Allbridge
        "BRkWD3WyQsHY7dMz1UCbeBFpVToWRXvDWzH6rMJ6wFW7", # Sollet
    ],
    "dex_program_ids": [                  # DEX programs for liquidity detection
        "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin", # Serum v3
        "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8", # Raydium
        "JUP4Fb2cqiRUcaTHdrPC8h2gNsA2ETXiPDD33WcGuJB", # Jupiter Aggregator
    ],
    "unusual_program_ids": [              # Program IDs that are potentially suspicious
        "11111111111111111111111111111111",  # System Program - for large transfers only
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",  # SPL Token Program - for unusual token patterns
    ],
    "known_scam_addresses": [             # Known addresses associated with scams
        # These would normally be loaded from an external source or API
    ],
    
    # Token categories for analysis
    "token_categories": {
        "unsellable_tokens": set(),        # Tokens that can't be sold
        "flash_launched_tokens": set(),    # Tokens with flash launch patterns
        "impersonation_tokens": set(),     # Tokens impersonating legitimate projects
    }
}

class SuspiciousActivityDetector:
    """Detects suspicious or unusual activity on the Solana blockchain"""
    
    def __init__(self, solana_rpc):
        self.solana_rpc = solana_rpc
        self.suspicious_addresses = self.load_suspicious_addresses()
        self.address_activity = {}  # address -> {timestamp: [tx_count, sol_volume, token_volume]}
        self.recent_alerts = []     # To store recent alerts for display
        
        # Tracking data structures for advanced detection
        self.token_actions = {}     # mint -> {actions: [], creation_time, liquidity_events}
        self.wallet_groups = {}     # group_id -> {wallets: set(), actions: [], creation_times}  
        self.token_impersonation = {} # symbol/name -> [legitimate_mints, suspicious_mints]
        self.cross_chain_transfers = {} # address -> {bridge_txs: [], timestamps}
        self.contract_exploits = {} # program_id -> {abnormal_calls: [], exploit_patterns}
        
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
            "programs": set(),
            "token_actions": [], # Store token interactions (buy/sell/transfer)
            "bridge_interactions": [], # Store bridge interactions
            "instruction_count": 0
        }
        
        # Extract relevant data from the transaction
        for event in tx_data.get("events", []):
            if event["type"] == "sol_transfer":
                activity["sol_amount"] += float(event.get("amount", 0))
            elif event["type"] == "token_transfer":
                # Try to get USD price if available, otherwise estimate
                mint = event.get("mint", "")
                price = self.solana_rpc.get_token_price_usd(mint)
                amount = float(event.get("amount", 0))
                activity["token_amount_usd"] += amount * price
                
                # Track token action
                activity["token_actions"].append({
                    "mint": mint,
                    "action": event.get("direction", "unknown"),
                    "amount": amount,
                    "price_usd": price
                })
                
                # Track token for unsellable detection
                self._track_token_action(mint, address, event, tx_data)
                
            elif event["type"] == "swap":
                # Track swap events for flash launch detection
                program_id = event.get("program_id", "")
                if program_id in THRESHOLDS["dex_program_ids"]:
                    activity["token_actions"].append({
                        "mint": event.get("mint", ""),
                        "action": "swap",
                        "dex": program_id
                    })
                
        # Track program IDs
        for program_id in tx_data.get("program_ids", []):
            activity["programs"].add(program_id)
            
            # Check if it's a bridge program
            if program_id in THRESHOLDS["bridge_program_ids"]:
                activity["bridge_interactions"].append(program_id)
                self._track_bridge_activity(address, program_id, tx_data)
                
        # Track instruction count for exploit detection
        if "transaction" in tx_data and "message" in tx_data["transaction"]:
            instructions = tx_data["transaction"]["message"].get("instructions", [])
            activity["instruction_count"] = len(instructions)
            
            # Check for unusually high instruction count
            if len(instructions) > THRESHOLDS["abnormal_instruction_count"]:
                # Use a general program ID or extract it from the transaction
                program_id_to_check = next(iter(activity["programs"]), "unknown")
                self._check_for_exploit(address, program_id_to_check, tx_data, len(instructions))
                
        self.address_activity[address].append(activity)
        
        # Check for Sybil attack-like patterns
        self._check_for_sybil_pattern(address, tx_data)
        
        # Check for obfuscation of funds using complex routing
        self._check_for_fund_obfuscation(address, tx_data)
        
        # Clean up old activity data
        cutoff_time = current_time - timedelta(minutes=10)
        self.address_activity[address] = [
            a for a in self.address_activity[address] 
            if a["timestamp"] > cutoff_time
        ]
        
    def _track_token_action(self, mint, address, event, tx_data):
        """Track a token action for flash launch and unsellable token detection"""
        if mint not in self.token_actions:
            # This appears to be a new token we're tracking
            creation_time = self._get_token_creation_time(mint)
            self.token_actions[mint] = {
                "creation_time": creation_time,
                "actions": [],
                "liquidity_events": [],
                "buys": 0,
                "sells": 0,
                "failed_sells": 0,
                "creators": set(),
                "transactions": []
            }
            
            # Check if this is a newly created token
            if datetime.now().timestamp() - creation_time < THRESHOLDS["new_token_age_threshold"]:
                self._check_for_token_impersonation(mint)
                
        # Add the creator if this is one of the first transactions
        if len(self.token_actions[mint]["transactions"]) < 5:
            self.token_actions[mint]["creators"].add(address)
            
        # Add this action
        direction = event.get("direction", "unknown")
        action = {
            "address": address,
            "timestamp": datetime.now(),
            "signature": tx_data.get("signature", ""),
            "type": direction,
            "amount": float(event.get("amount", 0))
        }
        
        # Check for buy/sell actions
        if direction == "Received":
            self.token_actions[mint]["buys"] += 1
        elif direction == "Sent":
            # Check if this appears to be a sell attempt
            for program_id in tx_data.get("program_ids", []):
                if program_id in THRESHOLDS["dex_program_ids"]:
                    self.token_actions[mint]["sells"] += 1
                    
                    # Check if the transaction failed or was blocked
                    if tx_data.get("status", "") == "failed":
                        self.token_actions[mint]["failed_sells"] += 1
                        
                        if self.token_actions[mint]["failed_sells"] >= THRESHOLDS["failed_sell_count"]:
                            # This might be an unsellable token
                            if mint not in THRESHOLDS["token_categories"]["unsellable_tokens"]:
                                THRESHOLDS["token_categories"]["unsellable_tokens"].add(mint)
                                self.add_suspicious_address(
                                    address,
                                    f"Possible unsellable token: {mint[:8]}...{mint[-8:]} (multiple failed sell attempts)"
                                )
        
        self.token_actions[mint]["actions"].append(action)
        self.token_actions[mint]["transactions"].append(tx_data.get("signature", ""))
        
        # Check for liquidity events
        for program_id in tx_data.get("program_ids", []):
            if program_id in THRESHOLDS["dex_program_ids"]:
                # This could be adding or removing liquidity
                # Simplified logic - in a real system we'd need to analyze the exact instruction
                liquidity_event = {
                    "timestamp": datetime.now(),
                    "signature": tx_data.get("signature", ""),
                    "program_id": program_id
                }
                self.token_actions[mint]["liquidity_events"].append(liquidity_event)
                
                # Check for flash launch pattern
                recent_liquidity = [
                    e for e in self.token_actions[mint]["liquidity_events"]
                    if (datetime.now() - e["timestamp"]).total_seconds() < 3600  # Last hour
                ]
                
                if len(recent_liquidity) >= 2:
                    # Check if this is a new token with sudden liquidity changes
                    token_age = datetime.now().timestamp() - self.token_actions[mint]["creation_time"]
                    if token_age < THRESHOLDS["new_token_age_threshold"]:
                        # Check sell activity after liquidity events
                        if (self.token_actions[mint]["buys"] > 5 and
                            self.token_actions[mint]["buys"] > self.token_actions[mint]["sells"] * 3):
                            # Might be a flash launch token
                            if mint not in THRESHOLDS["token_categories"]["flash_launched_tokens"]:
                                THRESHOLDS["token_categories"]["flash_launched_tokens"].add(mint)
                                
                                # Mark all creator addresses as suspicious
                                for creator in self.token_actions[mint]["creators"]:
                                    self.add_suspicious_address(
                                        creator,
                                        f"Possible flash token launch: {mint[:8]}...{mint[-8:]} (quick pairing and pump pattern)"
                                    )
        
    def _get_token_creation_time(self, mint):
        """Get token creation timestamp (simplified)"""
        # In real implementation, we would query the blockchain for the token creation block
        # For now, we'll use the current time if we haven't seen this token before
        return datetime.now().timestamp()
        
    def _check_for_token_impersonation(self, mint):
        """Check if a token is impersonating a legitimate project"""
        # Get token metadata
        metadata = self.solana_rpc.get_token_metadata(mint)
        if not metadata:
            return
            
        # Extract name and symbol
        name = metadata.get("name", "").lower()
        symbol = metadata.get("symbol", "").lower()
        
        # Check against known legitimate tokens (would be a more extensive list in production)
        legitimate_tokens = {
            "solana": ["So11111111111111111111111111111111111111112"],
            "usdc": ["EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"],
            "usdt": ["Es9vMFrzaCERz1aZHBKz9ZwrZcpt1mMT8ffvAJhY7kF"],
            "bonk": ["DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263"]
        }
        
        for key, legitimate_mints in legitimate_tokens.items():
            if key in name or key in symbol:
                if mint not in legitimate_mints:
                    # This token is impersonating a legitimate project
                    THRESHOLDS["token_categories"]["impersonation_tokens"].add(mint)
                    
                    # Try to find the creator address by getting recent token transfers
                    tx_data = self.solana_rpc.get_recent_signatures(mint, limit=3)
                    if tx_data:
                        first_tx = tx_data[0].get("signature")
                        tx = self.solana_rpc.get_transaction(first_tx)
                        if tx and "transaction" in tx:
                            # Simplified - in real impl we'd analyze the transaction more carefully
                            signer = tx["transaction"].get("signer", "")
                            if signer:
                                self.add_suspicious_address(
                                    signer,
                                    f"Token impersonation: {name}/{symbol} impersonating {key} ({mint[:8]}...{mint[-8:]})"
                                )
        
    def _check_for_sybil_pattern(self, address, tx_data):
        """Check for Sybil attack-like patterns with many similar wallets"""
        # Track this address's behavior
        behavior_key = self._get_behavior_key(tx_data)
        if not behavior_key:
            return
            
        # Find or create a wallet group with similar behavior
        group_id = None
        for gid, group in self.wallet_groups.items():
            if behavior_key in group["behaviors"]:
                group_id = gid
                break
                
        if not group_id:
            # Create a new group
            group_id = f"group_{len(self.wallet_groups) + 1}"
            self.wallet_groups[group_id] = {
                "wallets": set(),
                "behaviors": set([behavior_key]),
                "creation_times": {},
                "transactions": set()
            }
            
        # Add this wallet to the group
        wallet_group = self.wallet_groups[group_id]
        wallet_group["wallets"].add(address)
        wallet_group["creation_times"][address] = datetime.now()
        wallet_group["transactions"].add(tx_data.get("signature", ""))
        
        # Check if this group has suspicious characteristics
        if len(wallet_group["wallets"]) >= THRESHOLDS["wallet_group_threshold"]:
            # Check if wallets were created close to each other
            creation_times = list(wallet_group["creation_times"].values())
            if len(creation_times) >= 2:
                # Sort by creation time
                creation_times.sort()
                # Check time differences between consecutive wallets
                for i in range(1, len(creation_times)):
                    time_diff = (creation_times[i] - creation_times[i-1]).total_seconds()
                    if time_diff <= THRESHOLDS["wallet_creation_window"]:
                        # These wallets were created close together
                        for wallet in wallet_group["wallets"]:
                            if wallet not in self.suspicious_addresses:
                                self.add_suspicious_address(
                                    wallet,
                                    f"Potential Sybil attack: part of a group of {len(wallet_group['wallets'])} similar wallets"
                                )
                        break
    
    def _get_behavior_key(self, tx_data):
        """Generate a key representing this transaction's behavior pattern"""
        # This is a simplified implementation
        # In a real system, we'd use more sophisticated behavior analysis
        
        program_ids = tx_data.get("program_ids", [])
        if not program_ids:
            return None
            
        # Sort to make the key stable
        program_ids.sort()
        
        # Generate a simplified behavior key
        event_types = [e.get("type", "") for e in tx_data.get("events", [])]
        event_types.sort()
        
        return f"{'-'.join(program_ids[:3])}-{'-'.join(event_types)}"
    
    def _track_bridge_activity(self, address, bridge_program_id, tx_data):
        """Track cross-chain bridge activity"""
        if address not in self.cross_chain_transfers:
            self.cross_chain_transfers[address] = {
                "bridge_txs": [],
                "timestamps": []
            }
            
        # Add this bridge transaction
        bridge_tx = {
            "timestamp": datetime.now(),
            "program_id": bridge_program_id,
            "signature": tx_data.get("signature", "")
        }
        
        self.cross_chain_transfers[address]["bridge_txs"].append(bridge_tx)
        self.cross_chain_transfers[address]["timestamps"].append(datetime.now())
        
        # Check for rapid cross-chain transfers
        timestamps = self.cross_chain_transfers[address]["timestamps"]
        if len(timestamps) >= THRESHOLDS["min_bridge_transfers"]:
            # Check time window for recent transfers
            recent_timestamps = [
                t for t in timestamps 
                if (datetime.now() - t).total_seconds() < THRESHOLDS["cross_chain_transfer_window"]
            ]
            
            if len(recent_timestamps) >= THRESHOLDS["min_bridge_transfers"]:
                self.add_suspicious_address(
                    address,
                    f"Rapid cross-chain transfers: {len(recent_timestamps)} bridge interactions within {THRESHOLDS['cross_chain_transfer_window']/60:.1f} minutes"
                )
    
    def _check_for_exploit(self, address, program_id, tx_data, instruction_count):
        """Check for potential smart contract exploits"""
        # In a real implementation, we'd have more sophisticated logic
        # Here we'll just check for abnormally high instruction counts
        if instruction_count > THRESHOLDS["abnormal_instruction_count"]:
            # This transaction has an unusually high number of instructions
            # It could be an exploit attempt
            self.add_suspicious_address(
                address,
                f"Potential exploit: abnormal instruction count ({instruction_count})"
            )
            
    def _check_for_fund_obfuscation(self, address, tx_data):
        """Detect potential fund obfuscation using complex routing"""
        # This requires tracking transaction patterns across multiple hops
        # Simplified implementation - check for transactions with multiple transfers
        
        events = tx_data.get("events", [])
        transfer_events = [e for e in events if e.get("type") in ["sol_transfer", "token_transfer"]]
        
        if len(transfer_events) >= 3:
            # Extract unique addresses involved in this transaction
            addresses = set()
            for event in transfer_events:
                if "other_address" in event:
                    addresses.add(event["other_address"])
                    
            # If one transaction touches multiple addresses, it might be routing funds
            if len(addresses) >= 3:
                self.add_suspicious_address(
                    address,
                    f"Possible fund obfuscation: complex transaction touching {len(addresses)} addresses"
                )
                
                # Also mark the destination addresses as suspicious
                for addr in addresses:
                    if addr != address and addr not in self.suspicious_addresses:
                        self.add_suspicious_address(
                            addr,
                            f"Involved in complex fund routing from {address[:8]}...{address[-8:]}"
                        )
        
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
            
        # Check for bridge abuse
        if address in self.cross_chain_transfers:
            recent_bridge_txs = [
                tx for tx in self.cross_chain_transfers[address]["bridge_txs"]
                if (now - tx["timestamp"]).total_seconds() < THRESHOLDS["cross_chain_transfer_window"]
            ]
            
            if len(recent_bridge_txs) >= THRESHOLDS["min_bridge_transfers"]:
                return True, f"Suspicious cross-chain activity: {len(recent_bridge_txs)} bridge transfers in short period"
        
        # Check if this address has created unsellable tokens
        for mint in THRESHOLDS["token_categories"]["unsellable_tokens"]:
            if mint in self.token_actions and address in self.token_actions[mint]["creators"]:
                return True, f"Created unsellable token: {mint[:8]}...{mint[-8:]}"
                
        # Check if this address has created flash launch tokens
        for mint in THRESHOLDS["token_categories"]["flash_launched_tokens"]:
            if mint in self.token_actions and address in self.token_actions[mint]["creators"]:
                return True, f"Created flash launch token: {mint[:8]}...{mint[-8:]}"
                
        # Check if this address has created impersonation tokens
        for mint in THRESHOLDS["token_categories"]["impersonation_tokens"]:
            if mint in self.token_actions and address in self.token_actions[mint]["creators"]:
                return True, f"Created token impersonation: {mint[:8]}...{mint[-8:]}"
            
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