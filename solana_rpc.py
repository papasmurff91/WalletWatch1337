"""
Solana RPC client for interacting with the Solana blockchain
"""
import requests
import time
import json
from datetime import datetime
from config import RPC_URL, MAX_RETRIES, MORALIS_API_KEY

class SolanaRPC:
    """Client for interacting with Solana RPC endpoints"""
    
    def __init__(self, rpc_url=RPC_URL):
        self.rpc_url = rpc_url
    
    def safe_post(self, payload):
        """Make a safe RPC post with retries"""
        for attempt in range(MAX_RETRIES):
            try:
                res = requests.post(self.rpc_url, json=payload, timeout=10)
                if res.status_code != 200:
                    raise Exception(f"RPC error: Status code {res.status_code}")
                
                data = res.json()
                if "error" in data:
                    raise Exception(f"RPC error: {data['error']['message']}")
                    
                return data.get("result")
            except Exception as e:
                wait = 2 ** attempt
                print(f"RPC error: {e} (retrying in {wait}s)")
                time.sleep(wait)
        return None
    
    def get_recent_signatures(self, wallet, limit=10):
        """Get recent transaction signatures for an address"""
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getSignaturesForAddress",
            "params": [wallet, {"limit": limit}]
        }
        return self.safe_post(payload) or []
    
    def get_transaction(self, signature):
        """Get transaction details by signature"""
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransaction",
            "params": [signature, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}]
        }
        return self.safe_post(payload)
    
    def get_token_accounts(self, wallet):
        """Get all token accounts for a wallet"""
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTokenAccountsByOwner",
            "params": [
                wallet,
                {"programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"},
                {"encoding": "jsonParsed"}
            ]
        }
        return self.safe_post(payload)
    
    def get_account_info(self, account):
        """Get account information"""
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getAccountInfo",
            "params": [account, {"encoding": "jsonParsed"}]
        }
        return self.safe_post(payload)
    
    def get_token_metadata(self, mint):
        """Get token metadata (from on-chain metadata program)"""
        payload = {
            "jsonrpc": "2.0",
            "id": "1",
            "method": "getProgramAccounts",
            "params": [
                "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s",
                {
                    "encoding": "jsonParsed",
                    "filters": [
                        {
                            "memcmp": {
                                "offset": 33,
                                "bytes": mint
                            }
                        }
                    ]
                }
            ]
        }
        return self.safe_post(payload)
    
    def get_token_holders(self, mint):
        """Get number of token holders"""
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getProgramAccounts",
            "params": [
                "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                {
                    "filters": [
                        {
                            "dataSize": 165
                        },
                        {
                            "memcmp": {
                                "offset": 0,
                                "bytes": mint
                            }
                        }
                    ]
                }
            ]
        }
        result = self.safe_post(payload)
        return len(result) if result else 0
    
    def get_token_price_usd(self, mint):
        """Get token price in USD using Moralis API"""
        if not MORALIS_API_KEY:
            return 0
            
        try:
            headers = {"accept": "application/json", "X-API-Key": MORALIS_API_KEY}
            url = f"https://solana-gateway.moralis.io/token/mainnet/{mint}/price"
            res = requests.get(url, headers=headers, timeout=10)
            
            if res.status_code == 200:
                return float(res.json().get("usdPrice", 0))
            return 0
        except Exception as e:
            print(f"Error getting token price: {e}")
            return 0
