"""
Configuration settings for the Solana Wallet Monitor
"""
import os

# RPC Settings
RPC_URL = os.getenv("SOLANA_RPC_URL", "https://api.mainnet-beta.solana.com")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "30"))
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))

# File Paths
HONEYPOT_FILE = "honeypots.json"
WHITELIST_FILE = "whitelist.json"
LOG_FILE = "wallet_log.txt"
TRANSACTION_HISTORY_FILE = "transaction_history.json"
SUSPICIOUS_ADDRESSES_FILE = "suspicious_addresses.json"

# Web Interface
WEB_PORT = int(os.getenv("WEB_PORT", "5000"))
WEB_HOST = "0.0.0.0"

# Notification Settings
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

# API Keys
MORALIS_API_KEY = os.getenv("MORALIS_API_KEY", "")

# Common token definitions (mint, name, decimals)
TOKEN_MAP = {
    "So11111111111111111111111111111111111111112": ("Wrapped SOL", 9),
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": ("USDC", 6),
    "Es9vMFrzaCERz1aZHBKz9ZwrZcpt1mMT8ffvAJhY7kF": ("USDT", 6),
    "7dHbWXmci3dT8UFYWYZweBLXgycu7Y3iL6trKn1Y7ARj": ("Bonk", 5),
    "mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So": ("Marinade SOL", 9),
    "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263": ("Bonk", 5),
}

# Known swap program IDs
SWAP_PROGRAM_IDS = [
    "JUP4Fb2cqiRUcaTHdrPC8h2gNsA2ETXiPDD33WcGuJB",  # Jupiter
    "RVKd61ztZW9GdKz6Y8qEJ4zQ2LkWcE6gY6z7mY3bR2U",  # Meteora
    "srmqPvymJeFKQ4zGQed1GFppgkRHL9kaELCbyksJtPX",  # Openbook
    "9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP",  # Orca
    "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8",  # Raydium
]

# Honeypot detection settings
HONEYPOT_HEURISTICS = {
    "min_transactions": 5,           # Minimum transactions to analyze
    "suspicious_transfer_ratio": 0.8, # Ratio of transfers vs other transactions
    "high_velocity_threshold": 3,     # Number of transactions in short time
    "time_window_seconds": 300,       # Time window for high velocity (5 minutes)
    "unusual_holders_threshold": 10   # Suspicious if fewer holders than this
}
