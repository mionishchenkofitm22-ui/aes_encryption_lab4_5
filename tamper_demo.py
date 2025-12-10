import os, sys, random

USAGE = 'python tamper_demo.py --file outputs/sample.enc'

def tamper(path: str):
    with open(path, 'rb') as f:
        data = bytearray(f.read())
    if len(data) < 64:
        print('file too small to tamper')
        return
    # flip a random byte near the end (likely in tag/HMAC or ciphertext)
    i = random.randrange(len(data)-1)
    data[i] ^= 0xFF
    out = path + '.tampered'
    with open(out, 'wb') as f:
        f.write(data)
    print('tampered ->', out)

if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--file', required=True)
    args = ap.parse_args()
    tamper(args.file)
