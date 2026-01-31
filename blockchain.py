# blockchain.py
import hashlib
import json
import time
from datetime import datetime


class Block:
    def __init__(self, index, timestamp, data, prev_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.prev_hash = prev_hash
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "prev_hash": self.prev_hash
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def to_dict(self):
        # human-friendly timestamp
        ts = datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S")
        return {
            "index": self.index,
            "timestamp": ts,
            "data": self.data,
            "prev_hash": self.prev_hash,
            "hash": self.hash
        }


class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis = Block(0, time.time(), {"event": "genesis"}, "0")
        self.chain.append(genesis)

    def add_block(self, data: dict):
        prev_block = self.chain[-1]
        new_block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            data=data,
            prev_hash=prev_block.hash
        )
        self.chain.append(new_block)
        return new_block

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            prev = self.chain[i - 1]
            if current.hash != current.compute_hash():
                return False
            if current.prev_hash != prev.hash:
                return False
        return True

    def to_list(self):
        return [block.to_dict() for block in self.chain]
