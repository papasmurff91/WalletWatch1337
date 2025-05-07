"""
Solana wallet monitor that tracks transactions and detects honeypot tokens
"""
import json
import time
import os
from datetime import datetime
from config import POLL_INTERVAL, TOKEN_MAP, SWAP_PROGRAM_IDS, LOG_FILE, TRANSACTION_HISTORY_FILE

class WalletMonitor:
    """
    Monitors a Solana wallet for transactions and identifies potential
    honeypot tokens
    """
    
    def __init__(self, wallet_address, solana_rpc, honeypot_detector, notification_service):
        self.wallet_address = wallet_address
        self.solana_rpc = solana_rpc
        self.honeypot_detector = honeypot_detector
        self.notification_service = notification_service
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
                "program_ids": []
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
                    swap_event = {
                        "type": "swap",
                        "program_id": program_id
                    }
                    transaction_data["events"].append(swap_event)
                    
                    # Check if any honeypot tokens were involved
                    for event in transaction_data["events"]:
                        if event.get("type") == "token_transfer" and self.honeypot_detector.is_honeypot(event.get("mint", "")):
                            self.log_message(f"⚠️ Alert: Honeypot SWAP detected!")
                            self.notification_service.notify_honeypot_swap(event["mint"], program_id)
                    
                    break
                    
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
