import os, json, struct, hmac
from typing import Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac as hmac_lib
from config import MAGIC, VERSION, NONCE_BYTES_GCM, IV_BYTES_CBC, AES_KEY_BYTES, HMAC_KEY_BYTES, CHUNK_SIZE

# Файл: MAGIC(4) | HDRLEN(2) | HEADER(JSON) | CIPHERTEXT | TAG (GCM) або HMAC (CBC)

def _pack_header(h: dict) -> bytes:
    blob = json.dumps(h, separators=(',',':')).encode('utf-8')
    return MAGIC + struct.pack('>H', len(blob)) + blob

def _unpack_header(fp) -> dict:
    magic = fp.read(4)
    if magic != MAGIC:
        raise ValueError('Bad magic')
    (hdrlen,) = struct.unpack('>H', fp.read(2))
    hdr = json.loads(fp.read(hdrlen).decode('utf-8'))
    return hdr

def encrypt_cbc_hmac(in_path: str, out_path: str, enc_key: bytes, mac_key: bytes):
    iv = os.urandom(IV_BYTES_CBC)
    padder = padding.PKCS7(128).padder()
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    enc = cipher.encryptor()
    h = {"v": VERSION, "mode": "CBC-HMAC", "iv": iv.hex(), "alg": "AES-256-CBC", "mac": "HMAC-SHA256"}
    header = _pack_header(h)
    mac = hmac_lib.HMAC(mac_key, hashes.SHA256())
    mac.update(header)
    mac.update(iv)

    with open(in_path, 'rb') as fi, open(out_path, 'wb') as fo:
        fo.write(header)
        fo.write(iv)
        while True:
            chunk = fi.read(CHUNK_SIZE)
            if not chunk:
                break
            ct = enc.update(padder.update(chunk))
            if ct:
                fo.write(ct)
                mac.update(ct)
        # finalize padding
        ct = enc.update(padder.finalize()) + enc.finalize()
        if ct:
            fo.write(ct)
            mac.update(ct)
        tag = mac.finalize()
        fo.write(tag)
    return len(tag)

def decrypt_cbc_hmac(in_path: str, out_path: str, enc_key: bytes, mac_key: bytes):
    with open(in_path, 'rb') as fi:
        hdr = _unpack_header(fi)
        if hdr.get('mode') != 'CBC-HMAC':
            raise ValueError('Wrong mode')
        iv = bytes.fromhex(hdr['iv'])
        data = fi.read()
    tag = data[-32:]
    ciphertext = data[:-32]
    # MAC verify
    mac = hmac_lib.HMAC(mac_key, hashes.SHA256())
    mac.update(_pack_header(hdr))
    mac.update(iv)
    mac.update(ciphertext)
    mac.verify(tag)
    # Decrypt
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    dec = cipher.decryptor()
    unpad = padding.PKCS7(128).unpadder()
    pt = unpad.update(dec.update(ciphertext) + dec.finalize()) + unpad.finalize()
    with open(out_path, 'wb') as fo:
        fo.write(pt)

def encrypt_gcm(in_path: str, out_path: str, enc_key: bytes, aad: Optional[bytes] = None):
    nonce = os.urandom(NONCE_BYTES_GCM)
    cipher = Cipher(algorithms.AES(enc_key), modes.GCM(nonce))
    enc = cipher.encryptor()
    if aad:
        enc.authenticate_additional_data(aad)
    h = {"v": VERSION, "mode": "GCM", "nonce": nonce.hex(), "alg": "AES-256-GCM"}
    header = _pack_header(h)
    with open(in_path, 'rb') as fi, open(out_path, 'wb') as fo:
        fo.write(header)
        while True:
            chunk = fi.read(CHUNK_SIZE)
            if not chunk:
                break
            fo.write(enc.update(chunk))
        fo.write(enc.finalize())
        fo.write(enc.tag)
    return len(enc.tag)

def decrypt_gcm(in_path: str, out_path: str, enc_key: bytes, aad: Optional[bytes] = None):
    with open(in_path, 'rb') as fi:
        hdr = _unpack_header(fi)
        if hdr.get('mode') != 'GCM':
            raise ValueError('Wrong mode')
        nonce = bytes.fromhex(hdr['nonce'])
        data = fi.read()
    tag = data[-16:]
    ciphertext = data[:-16]
    cipher = Cipher(algorithms.AES(enc_key), modes.GCM(nonce, tag))
    dec = cipher.decryptor()
    if aad:
        dec.authenticate_additional_data(aad)
    pt = dec.update(ciphertext) + dec.finalize()
    with open(out_path, 'wb') as fo:
        fo.write(pt)
