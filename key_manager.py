import os, json, time, hmac, hashlib
from typing import Dict
from config import KEYSTORE_PATH, ITERATIONS, AES_KEY_BYTES, HMAC_KEY_BYTES
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

class KeyManager:
    def __init__(self, path=KEYSTORE_PATH):
        self.path = path
        self.db = {"keys": []}
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                self.db = json.load(f)

    def save(self):
        with open(self.path, 'w', encoding='utf-8') as f:
            json.dump(self.db, f, ensure_ascii=False, indent=2)

    @staticmethod
    def _derive(password: bytes, salt: bytes, length: int, iterations: int):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt, iterations=iterations)
        return kdf.derive(password)

    def new_key(self, label: str, password: str, iterations: int = ITERATIONS) -> Dict:
        salt = os.urandom(16)
        # Для CBC+HMAC нам потрібно 64 байти (enc+mac); для GCM достатньо 32
        key_material = self._derive(password.encode('utf-8'), salt, AES_KEY_BYTES + HMAC_KEY_BYTES, iterations)
        enc_key = key_material[:AES_KEY_BYTES]
        mac_key = key_material[AES_KEY_BYTES:]
        key_id = hashlib.sha256(enc_key).hexdigest()[:16]
        # Перевірка на повторне використання того ж ключа (за хешем enc_key)
        if any(k['key_id'] == key_id for k in self.db['keys']):
            raise ValueError('Key reuse prohibited: identical key material detected')
        meta = {
            "label": label,
            "key_id": key_id,
            "salt": salt.hex(),
            "iterations": iterations,
            "kdf": "PBKDF2-HMAC-SHA256",
            "created_at": int(time.time()),
            "uses": 0,
        }
        self.db['keys'].append(meta)
        self.save()
        return meta

    def list_keys(self):
        return self.db['keys']

    def derive_keypair(self, label: str, password: str):
        meta = next((k for k in self.db['keys'] if k['label'] == label), None)
        if not meta:
            raise ValueError('Key label not found')
        salt = bytes.fromhex(meta['salt'])
        key_material = self._derive(password.encode('utf-8'), salt, AES_KEY_BYTES + HMAC_KEY_BYTES, meta['iterations'])
        return meta, key_material[:AES_KEY_BYTES], key_material[AES_KEY_BYTES:]

    def inc_use(self, key_id: str):
        for k in self.db['keys']:
            if k['key_id'] == key_id:
                k['uses'] += 1
                break
        self.save()
