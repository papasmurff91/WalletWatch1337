"""
Solana wallet monitor that tracks transactions and detects honeypot tokens
"""
import json
import time
import os
import re
from datetime import datetime
from config import POLL_INTERVAL, TOKEN_MAP, SWAP_PROGRAM_IDS, LOG_FILE, TRANSACTION_HISTORY_FILE

class WalletMonitor:
    """
    Monitors a Solana wallet for transactions and identifies potential
    honeypot tokens
    """
    
    def __init__(self, wallet_address, solana_rpc, honeypot_detector, notification_service, suspicious_detector=None, phishing_detector=None):
        self.wallet_address = wallet_address
        self.solana_rpc = solana_rpc
        self.honeypot_detector = honeypot_detector
        self.notification_service = notification_service
        self.suspicious_detector = suspicious_detector
        self.phishing_detector = phishing_detector
        self.seen_signatures = set()
        self.transaction_history = self.load_transaction_history()
        
    def load_transaction_history(self):
        """Load transaction history from file"""
        if os.path.exists(TRANSACTION_HISTORY_FILE):
            with open(TRANSACTION_HISTORY_FILE, "r") as f:
                try:
                    return json.load(f)
                except json.JSONDecodeError:
                    return []
        return []
        
    def save_transaction_history(self):
        """Save transaction history to file"""
        # Keep only the last 100 transactions to prevent the file from growing too large
        if len(self.transaction_history) > 100:
            self.transaction_history = self.transaction_history[-100:]
            
        with open(TRANSACTION_HISTORY_FILE, "w") as f:
            json.dump(self.transaction_history, f, indent=2)
    
    def log_message(self, msg):
        """Log a message to the log file"""
        with open(LOG_FILE, "a") as f:
            f.write(f"[{datetime.utcnow()}] {msg}\n")
        print(msg)
        
    def lamports_to_sol(self, lamports):
        """Convert lamports to SOL"""
        return lamports / 1_000_000_000
        
    def _get_dex_name(self, program_id):
        """Get the name of a DEX based on its program ID"""
        dex_names = {
            "JUP4Fb2cqiRUcaTHdrPC8h2gNsA2ETXiPDD33WcGuJB": "Jupiter",
            "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4": "Jupiter v6", 
            "RVKd61ztZW9GdKz6Y8qEJ4zQ2LkWcE6gY6z7mY3bR2U": "Meteora",
            "srmqPvymJeFKQ4zGQed1GFppgkRHL9kaELCbyksJtPX": "Openbook",
            "9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP": "Orca",
            "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8": "Raydium"
        }
        return dex_names.get(program_id, "Unknown DEX")
        
    def _parse_jupiter_swap(self, tx, sent_tokens, received_tokens):
        """
        Parse a Jupiter swap transaction to extract detailed information
        
        Returns a dictionary with detailed swap information or None if parsing fails
        """
        try:
            # Extract basic information
            result = {}
            
            # Get transaction logs if available
            logs = tx.get("meta", {}).get("logMessages", [])
            
            # Get accounts used in transaction
            accounts = []
            for key_obj in tx.get("transaction", {}).get("message", {}).get("accountKeys", []):
                accounts.append(key_obj.get("pubkey"))
            
            # Extract Jupiter-specific information from logs
            for log in logs:
                # Extract route information (Jupiter often logs the route in transactions)
                if "route" in log.lower() and "hops" in log.lower():
                    result["route_info"] = log
                    
                # Price impact detection
                if "price impact" in log.lower() or "impact" in log.lower():
                    match = re.search(r"impact: ([0-9.]+)%", log.lower())
                    if match:
                        result["price_impact"] = float(match.group(1))
                    
                # Slippage detection
                if "slippage" in log.lower():
                    match = re.search(r"slippage: ([0-9.]+)%", log.lower())
                    if match:
                        result["slippage"] = float(match.group(1))
                        
                # Extract version info if present
                if "jupiter" in log.lower() and "v" in log.lower():
                    match = re.search(r"jupiter\s+v([0-9]+)", log.lower())
                    if match:
                        result["jupiter_version"] = match.group(1)
            
            # Get account tags - Jupiter often has accounts tagged in the transaction
            # like MEV protection accounts, fee accounts, etc.
            account_tags = {}
            for log in logs:
                if "account:" in log.lower() and ":" in log:
                    parts = log.split(":")
                    if len(parts) >= 3:
                        tag = parts[1].strip()
                        account = parts[2].strip()
                        account_tags[account] = tag
            
            if account_tags:
                result["account_tags"] = account_tags
            
            # Get swap path if available from inner instructions
            swap_path = []
            inner_instructions = tx.get("meta", {}).get("innerInstructions", [])
            for inner_ix_group in inner_instructions:
                for inner_ix in inner_ix_group.get("instructions", []):
                    if inner_ix.get("programId") in ["JUP4Fb2cqiRUcaTHdrPC8h2gNsA2ETXiPDD33WcGuJB", "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"]:
                        for account in inner_ix.get("accounts", []):
                            if account not in swap_path:
                                swap_path.append(account)
            
            if swap_path:
                result["swap_path"] = swap_path[:5]  # Limit to first 5 for brevity
            
            # Calculate exchange rate and USD value for the swap
            if sent_tokens and received_tokens:
                input_amount = sent_tokens[0].get("amount", 0)
                output_amount = received_tokens[0].get("amount", 0)
                
                if input_amount and output_amount:
                    result["exchange_rate"] = output_amount / input_amount
                    
                    # Calculate USD value if either token is a stablecoin
                    if sent_tokens[0].get("token_name") in ["USDC", "USDT"]:
                        result["usd_value"] = input_amount
                    elif received_tokens[0].get("token_name") in ["USDC", "USDT"]:
                        result["usd_value"] = output_amount
            
            # Risk analysis for Jupiter swaps
            risk_level = "low"
            risk_factors = []
            
            # Check for high price impact (>1%)
            if result.get("price_impact", 0) > 1.0:
                risk_level = "medium"
                risk_factors.append(f"High price impact: {result.get('price_impact')}%")
                
            # Check for very high price impact (>5%)
            if result.get("price_impact", 0) > 5.0:
                risk_level = "high"
                risk_factors.append(f"Very high price impact: {result.get('price_impact')}%")
            
            # Check for suspicious exchange rate (for tokens that should be ~1:1)
            stablecoins = ["USDC", "USDT"]
            if (sent_tokens[0].get("token_name") in stablecoins and 
                received_tokens[0].get("token_name") in stablecoins and
                abs(1 - result.get("exchange_rate", 1)) > 0.02):
                risk_level = "high"
                risk_factors.append(f"Unusual stablecoin exchange rate: {result.get('exchange_rate', 0):.4f}")
            
            # Check for new tokens (potentially risky)
            if received_tokens and received_tokens[0].get("mint", "") not in TOKEN_MAP:
                risk_level = max(risk_level, "medium")
                risk_factors.append("Swapping for unknown token not in known token list")
            
            result["risk_level"] = risk_level
            result["risk_factors"] = risk_factors
            
            return result
            
        except Exception as e:
            self.log_message(f"Error parsing Jupiter swap: {e}")
            return None
            
    def _parse_raydium_swap(self, tx, sent_tokens, received_tokens):
        """
        Parse a Raydium swap transaction to extract detailed information
        
        Returns a dictionary with detailed swap information or None if parsing fails
        """
        try:
            # Extract basic information
            result = {}
            
            # Get transaction logs if available (contains important information about slippage, etc.)
            logs = tx.get("meta", {}).get("logMessages", [])
            
            # Look for specific log patterns in Raydium swaps
            for log in logs:
                # Price impact detection
                if "price impact" in log.lower():
                    # Parse price impact percentage if available
                    match = re.search(r"price impact: ([0-9.]+)%", log.lower())
                    if match:
                        result["price_impact"] = float(match.group(1))
                        
                # Slippage detection
                if "slippage" in log.lower():
                    match = re.search(r"slippage: ([0-9.]+)%", log.lower())
                    if match:
                        result["slippage"] = float(match.group(1))
            
            # Get liquidity pool information if available
            if sent_tokens and received_tokens:
                # Calculate approximate exchange rate
                input_amount = sent_tokens[0].get("amount", 0)
                output_amount = received_tokens[0].get("amount", 0)
                
                if input_amount and output_amount:
                    result["exchange_rate"] = output_amount / input_amount
                    
                    # Calculate USD value if either token is a stablecoin
                    if sent_tokens[0].get("token_name") in ["USDC", "USDT"]:
                        result["usd_value"] = input_amount
                    elif received_tokens[0].get("token_name") in ["USDC", "USDT"]:
                        result["usd_value"] = output_amount
            
            # Analyze inner instructions for pool data
            inner_instructions = tx.get("meta", {}).get("innerInstructions", [])
            if inner_instructions:
                # In Raydium swaps, pool address is often in the inner instructions
                # This is a simplified approach - a production system would need more robust parsing
                pool_addresses = []
                for inner_ix_group in inner_instructions:
                    for inner_ix in inner_ix_group.get("instructions", []):
                        if inner_ix.get("programId") == "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8":
                            for account in inner_ix.get("accounts", []):
                                if account not in pool_addresses:
                                    pool_addresses.append(account)
                
                if pool_addresses:
                    result["pool_addresses"] = pool_addresses[:3]  # Limit to first 3 for brevity
            
            # Risk analysis
            risk_level = "low"
            risk_factors = []
            
            # Check for high price impact (>1%)
            if result.get("price_impact", 0) > 1.0:
                risk_level = "medium"
                risk_factors.append(f"High price impact: {result.get('price_impact')}%")
                
            # Check for very high price impact (>5%)
            if result.get("price_impact", 0) > 5.0:
                risk_level = "high"
                risk_factors.append(f"Very high price impact: {result.get('price_impact')}%")
            
            # Check for suspicious exchange rate (for tokens that should be ~1:1)
            stablecoins = ["USDC", "USDT"]
            if (sent_tokens[0].get("token_name") in stablecoins and 
                received_tokens[0].get("token_name") in stablecoins and
                abs(1 - result.get("exchange_rate", 1)) > 0.02):
                risk_level = "high"
                risk_factors.append(f"Unusual stablecoin exchange rate: {result.get('exchange_rate', 0):.4f}")
            
            result["risk_level"] = risk_level
            result["risk_factors"] = risk_factors
            
            return result
            
        except Exception as e:
            self.log_message(f"Error parsing Raydium swap: {e}")
            return None
        
    def decode_transaction(self, tx):
        """
        Decode a Solana transaction and extract relevant information
        """
        if not tx:
            return None
            
        try:
            block_time = tx.get("blockTime", 0)
            timestamp = datetime.fromtimestamp(block_time).strftime("%b %d, %Y %H:%M:%S")
            signature = tx.get("transaction", {}).get("signatures", [""])[0]
            
            transaction_data = {
                "signature": signature,
                "timestamp": timestamp,
                "block_time": block_time,
                "events": [],
                "honeypot_flags": [],
                "suspicious_flags": [],
                "phishing_flags": None,
                "program_ids": [],
                "account": self.wallet_address
            }
            
            # Get account keys from the transaction
            account_keys = []
            for key_obj in tx.get("transaction", {}).get("message", {}).get("accountKeys", []):
                account_keys.append(key_obj.get("pubkey"))
            
            # Extract instructions
            message = tx.get("transaction", {}).get("message", {})
            instructions = message.get("instructions", [])
            
            # Process each instruction
            for ix in instructions:
                program_id = ix.get("programId")
                transaction_data["program_ids"].append(program_id)
                program = ix.get("program")
                parsed = ix.get("parsed", {})
                ix_type = parsed.get("type", "")
                info = parsed.get("info", {})
                
                # Handle system transfers (SOL)
                if program == "system" and ix_type == "transfer":
                    amount = self.lamports_to_sol(int(info.get("lamports", 0)))
                    destination = info.get("destination")
                    source = info.get("source")
                    
                    direction = "Received" if destination == self.wallet_address else "Sent"
                    other = source if direction == "Received" else destination
                    
                    event = {
                        "type": "sol_transfer",
                        "direction": direction,
                        "amount": amount,
                        "other_address": other,
                        "token_name": "SOL"
                    }
                    
                    transaction_data["events"].append(event)
                    
                    msg = f"{direction} {amount:.4f} SOL {'from' if direction == 'Received' else 'to'} {other} on {timestamp}"
                    self.log_message(msg)
                    
                    # Notify for large transfers (>1 SOL)
                    if amount > 1:
                        self.notification_service.notify_large_transfer("SOL", f"{amount:.4f}", direction, other)
                    
                # Handle SPL token transfers
                elif program == "spl-token" and ix_type == "transfer":
                    mint = info.get("mint", "")
                    amount = int(info.get("amount", 0))
                    destination = info.get("destination")
                    source = info.get("source")
                    
                    # Get token details
                    token_name, decimals = TOKEN_MAP.get(mint, (f"Unknown Token ({mint[:4]}...{mint[-4:]})", 6))
                    formatted_amount = amount / (10 ** decimals)
                    
                    direction = "Received" if destination == self.wallet_address else "Sent"
                    other = source if direction == "Received" else destination
                    
                    event = {
                        "type": "token_transfer",
                        "direction": direction,
                        "amount": formatted_amount,
                        "other_address": other,
                        "token_name": token_name,
                        "mint": mint,
                        "decimals": decimals
                    }
                    
                    transaction_data["events"].append(event)
                    
                    is_honeypot = self.honeypot_detector.is_honeypot(mint)
                    
                    # Track this transaction for the token
                    self.honeypot_detector.track_transaction(mint)
                    
                    # If this is a new token, analyze it
                    if not is_honeypot and mint not in TOKEN_MAP:
                        is_suspicious, confidence, reasons = self.honeypot_detector.analyze_token(mint)
                        if is_suspicious:
                            token_name = f"⚠️ Honeypot Token ({mint[:4]}...{mint[-4:]})"
                            is_honeypot = True
                            transaction_data["honeypot_flags"].append({
                                "mint": mint,
                                "confidence": confidence,
                                "reasons": reasons
                            })
                            self.notification_service.notify_honeypot_detected(mint, reasons, confidence)
                    
                    # Log the transfer
                    msg = f"{direction} {formatted_amount:.4f} {token_name} {'from' if direction == 'Received' else 'to'} {other} on {timestamp}"
                    self.log_message(msg)
                    
                    # If this is a honeypot token, send extra alerts
                    if is_honeypot:
                        if direction == "Sent":
                            self.log_message(f"⚠️ Alert: Honeypot token SENT!")
                            self.notification_service.notify_honeypot_transfer(
                                mint, direction, formatted_amount, other
                            )
                        
                        # Check if token is worthless
                        token_price = self.solana_rpc.get_token_price_usd(mint)
                        if token_price == 0:
                            self.log_message(f"⚠️ Alert: Token {mint[:4]}...{mint[-4:]} is now WORTHLESS!")
                            self.notification_service.notify_token_worthless(mint)
                    
                    # Notify for large known token transfers
                    if mint in TOKEN_MAP and formatted_amount > 100:
                        self.notification_service.notify_large_transfer(
                            token_name, f"{formatted_amount:.4f}", direction, other
                        )
                
            # Check for swap transactions
            for program_id in transaction_data["program_ids"]:
                if program_id in SWAP_PROGRAM_IDS:
                    # Default swap event
                    swap_event = {
                        "type": "swap",
                        "program_id": program_id,
                        "dex_name": self._get_dex_name(program_id)
                    }
                    
                    # Get input and output tokens based on transfer events
                    token_transfers = [e for e in transaction_data["events"] if e.get("type") == "token_transfer"]
                    
                    # Group by direction
                    sent_tokens = [t for t in token_transfers if t.get("direction") == "Sent"]
                    received_tokens = [t for t in token_transfers if t.get("direction") == "Received"]
                    
                    # If we have both sent and received tokens, this looks like a swap
                    if sent_tokens and received_tokens:
                        # Organize the swap details
                        swap_event.update({
                            "input_token": sent_tokens[0].get("token_name", "Unknown"),
                            "input_amount": sent_tokens[0].get("amount", 0),
                            "input_mint": sent_tokens[0].get("mint", ""),
                            "output_token": received_tokens[0].get("token_name", "Unknown"),
                            "output_amount": received_tokens[0].get("amount", 0),
                            "output_mint": received_tokens[0].get("mint", "")
                        })
                        
                        # Detailed Raydium swap parsing for better alerts
                        if program_id == "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8":  # Raydium
                            raydium_details = self._parse_raydium_swap(tx, sent_tokens, received_tokens)
                            if raydium_details:
                                swap_event.update(raydium_details)
                                
                        # Detailed Jupiter swap parsing for better alerts
                        elif program_id in ["JUP4Fb2cqiRUcaTHdrPC8h2gNsA2ETXiPDD33WcGuJB", "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"]:  # Jupiter
                            jupiter_details = self._parse_jupiter_swap(tx, sent_tokens, received_tokens)
                            if jupiter_details:
                                swap_event.update({
                                    "price_impact": jupiter_details.get("price_impact"),
                                    "slippage": jupiter_details.get("slippage"),
                                    "exchange_rate": jupiter_details.get("exchange_rate"),
                                    "risk_level": jupiter_details.get("risk_level", "low"),
                                    "risk_factors": jupiter_details.get("risk_factors", []),
                                    "account_tags": jupiter_details.get("account_tags", {}),
                                    "swap_path": jupiter_details.get("swap_path", []),
                                    "route_info": jupiter_details.get("route_info"),
                                    "jupiter_version": jupiter_details.get("jupiter_version", "")
                                })
                                
                                # Extract any associated accounts for tagging
                                associated_accounts = []
                                for account, tag in jupiter_details.get("account_tags", {}).items():
                                    if tag.lower() in ["fee", "referral", "admin", "authority"]:
                                        associated_accounts.append({"address": account, "tag": tag})
                                
                                if associated_accounts:
                                    swap_event["associated_accounts"] = associated_accounts
                    
                    transaction_data["events"].append(swap_event)
                    
                    # Log the swap details
                    if "input_token" in swap_event and "output_token" in swap_event:
                        self.log_message(
                            f"Swap on {swap_event['dex_name']}: {swap_event['input_amount']:.4f} "
                            f"{swap_event['input_token']} → {swap_event['output_amount']:.4f} "
                            f"{swap_event['output_token']}"
                        )
                        
                        # Additional logging for risk factors if present
                        if "risk_factors" in swap_event and swap_event["risk_factors"]:
                            self.log_message(f"⚠️ Swap risk level: {swap_event.get('risk_level', 'low')} - {', '.join(swap_event['risk_factors'])}")
                    
                    # Check if any honeypot tokens were involved
                    honeypot_tokens = []
                    for event in token_transfers:
                        mint = event.get("mint", "")
                        if mint and self.honeypot_detector.is_honeypot(mint):
                            honeypot_tokens.append(mint)
                            self.log_message(f"⚠️ Alert: Honeypot token {event['token_name']} involved in SWAP!")
                            self.notification_service.notify_honeypot_swap(mint, program_id)
                    
                    # If this was a Raydium swap with honeypot tokens, prepare webhook data
                    if program_id == "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8" and honeypot_tokens:
                        # Store the webhook data in the transaction for API consumption
                        transaction_data["webhook_data"] = {
                            "type": "raydium_honeypot_swap",
                            "signature": transaction_data["signature"],
                            "timestamp": transaction_data["timestamp"],
                            "wallet": self.wallet_address,
                            "swap_details": swap_event,
                            "honeypot_tokens": honeypot_tokens
                        }
                    
                    # If this was a Jupiter swap with risk factors or honeypot tokens, prepare webhook data
                    elif program_id in ["JUP4Fb2cqiRUcaTHdrPC8h2gNsA2ETXiPDD33WcGuJB", "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"] and \
                        (honeypot_tokens or swap_event.get("risk_level") in ["medium", "high"]):
                        
                        # Create risk analysis information
                        risk_analysis = {
                            "overall_risk": "critical" if honeypot_tokens else swap_event.get("risk_level", "low"),
                            "confidence": 0.95 if honeypot_tokens else 0.7,
                            "reasons": []
                        }
                        
                        # Add reasons based on risk factors and honeypot status
                        if swap_event.get("risk_factors"):
                            risk_analysis["reasons"].extend(swap_event.get("risk_factors"))
                            
                        if honeypot_tokens:
                            for mint in honeypot_tokens:
                                # Find the honeypot flag for this mint to get reasons
                                for flag in transaction_data.get("honeypot_flags", []):
                                    if flag.get("mint") == mint:
                                        risk_analysis["reasons"].extend(flag.get("reasons", []))
                        
                        # Get associated accounts for tagging in social media alerts
                        associated_accounts = []
                        if "associated_accounts" in swap_event:
                            associated_accounts = swap_event["associated_accounts"]
                            
                        # Find other associated accounts via the social media monitor if available
                        social_monitor = None
                        if hasattr(self.notification_service, 'twitter_service') and hasattr(self.notification_service.twitter_service, 'social_monitor'):
                            social_monitor = self.notification_service.twitter_service.social_monitor
                        
                        # Use social media monitor to find associated accounts for output token
                        if social_monitor and received_tokens:
                            output_mint = received_tokens[0].get("mint", "")
                            if output_mint:
                                found_accounts = social_monitor.find_associated_accounts(output_mint)
                                if found_accounts:
                                    for account in found_accounts:
                                        if account not in [a.get("address") for a in associated_accounts]:
                                            associated_accounts.append({
                                                "address": account,
                                                "tag": "token_promoter"
                                            })
                        
                        # Store the webhook data in the transaction for API consumption
                        transaction_data["webhook_data"] = {
                            "type": "jupiter_swap_alert",
                            "signature": transaction_data["signature"],
                            "timestamp": transaction_data["timestamp"],
                            "wallet": self.wallet_address,
                            "swap_details": swap_event,
                            "honeypot_tokens": honeypot_tokens,
                            "risk_analysis": risk_analysis,
                            "associated_accounts": associated_accounts
                        }
                    
                    break
            
            # Check for suspicious activity if the detector is available
            if self.suspicious_detector:
                is_suspicious, reason = self.suspicious_detector.analyze_transaction(transaction_data)
                if is_suspicious:
                    transaction_data["suspicious_flags"].append({
                        "reason": reason,
                        "severity": "high"
                    })
                    self.log_message(f"🔍 SUSPICIOUS ACTIVITY DETECTED: {reason}")
                    
                    # Send notification via Twitter
                    if hasattr(self.notification_service, 'twitter_service'):
                        self.notification_service.twitter_service.notify_suspicious_activity(
                            self.wallet_address, reason
                        )
            
            # Check for phishing indicators if the detector is available
            if self.phishing_detector:
                is_phishing, confidence, reason = self.phishing_detector.analyze_transaction(transaction_data)
                if is_phishing:
                    transaction_data["phishing_flags"] = {
                        "reason": reason,
                        "confidence": confidence,
                        "severity": "critical" if confidence > 0.8 else "high"
                    }
                    self.log_message(f"🚨 PHISHING ATTEMPT DETECTED: {reason} (Confidence: {confidence:.2f})")
                    
                    # Add phishing address to the database
                    for event in transaction_data["events"]:
                        if event.get("type") in ["sol_transfer", "token_transfer"]:
                            # Check if the other address is the potential phishing source
                            other_address = event.get("other_address")
                            if other_address and event.get("direction") == "Received":
                                self.phishing_detector.add_phishing_address(other_address, reason)
                    
                    # Send notification via Twitter for critical threats
                    if confidence > 0.8 and hasattr(self.notification_service, 'twitter_service'):
                        self.notification_service.twitter_service.notify_suspicious_activity(
                            self.wallet_address, f"Phishing attempt: {reason}"
                        )
                    
            # Add to history and save
            self.transaction_history.append(transaction_data)
            self.save_transaction_history()
            
            return transaction_data
                    
        except Exception as e:
            self.log_message(f"Error decoding transaction: {e}")
            return None
    
    def poll_wallet(self):
        """
        Poll the wallet for new transactions and process them
        """
        self.log_message(f"Tracking Wallet: {self.wallet_address}")
        
        while True:
            try:
                signatures = self.solana_rpc.get_recent_signatures(self.wallet_address)
                
                for sig in signatures:
                    signature = sig.get("signature")
                    if signature and signature not in self.seen_signatures:
                        self.seen_signatures.add(signature)
                        tx = self.solana_rpc.get_transaction(signature)
                        self.decode_transaction(tx)
                
                time.sleep(POLL_INTERVAL)
            except Exception as e:
                self.log_message(f"Polling error: {e}")
                time.sleep(POLL_INTERVAL)
