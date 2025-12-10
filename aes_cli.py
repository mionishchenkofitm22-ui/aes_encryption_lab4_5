import argparse, os, sys, time
from logger_setup import get_logger
from key_manager import KeyManager
from crypto_aes import encrypt_cbc_hmac, decrypt_cbc_hmac, encrypt_gcm, decrypt_gcm
from config import CHUNK_SIZE

logger = get_logger()

MODES = {"cbc": "CBC-HMAC", "gcm": "GCM"}

def _derive(km, label, password):
    meta, enc_key, mac_key = km.derive_keypair(label, password)
    return meta, enc_key, mac_key

def cmd_key(args):
    km = KeyManager()
    if args.action == 'new':
        meta = km.new_key(args.label, args.password)
        print('CREATED', meta)
    elif args.action == 'list':
        print(*km.list_keys(), sep='\n')


def cmd_enc(args):
    km = KeyManager()
    meta, enc_key, mac_key = _derive(km, args.label, args.password)
    t0 = time.perf_counter()
    if args.mode == 'cbc':
        taglen = encrypt_cbc_hmac(args.infile, args.outfile, enc_key, mac_key)
    else:
        aad = args.aad.encode('utf-8') if args.aad else None
        taglen = encrypt_gcm(args.infile, args.outfile, enc_key, aad)
    dt = time.perf_counter() - t0
    km.inc_use(meta['key_id'])
    logger.info('enc', extra={'extra': {'mode': MODES[args.mode], 'in': args.infile, 'out': args.outfile, 'sec': round(dt,4), 'taglen': taglen}})
    print(f'Encrypted in {dt:.3f}s')


def cmd_dec(args):
    km = KeyManager()
    meta, enc_key, mac_key = _derive(km, args.label, args.password)
    t0 = time.perf_counter()
    try:
        if args.mode == 'cbc':
            decrypt_cbc_hmac(args.infile, args.outfile, enc_key, mac_key)
        else:
            aad = args.aad.encode('utf-8') if args.aad else None
            decrypt_gcm(args.infile, args.outfile, enc_key, aad)
        ok = True
        err = ''
    except Exception as e:
        ok = False
        err = str(e)
    dt = time.perf_counter() - t0
    logger.info('dec', extra={'extra': {'mode': MODES[args.mode], 'in': args.infile, 'out': args.outfile, 'sec': round(dt,4), 'ok': ok, 'error': err}})
    if ok:
        print(f'Decrypted in {dt:.3f}s')
    else:
        print('ERROR:', err)


def cmd_bench(args):
    import pathlib, secrets
    km = KeyManager()
    meta, enc_key, mac_key = _derive(km, args.label, args.password)
    sizes = []
    for s in args.sizes:
        if s.lower().endswith('mb'):
            sizes.append(int(float(s[:-2]) * 1024 * 1024))
        elif s.lower().endswith('kb'):
            sizes.append(int(float(s[:-2]) * 1024))
        else:
            sizes.append(int(s))
    os.makedirs('outputs', exist_ok=True)
    res = []
    for size in sizes:
        path = f'outputs/bench_{size}.bin'
        if not os.path.exists(path):
            with open(path, 'wb') as f:
                f.write(secrets.token_bytes(size))
        for mode in args.modes:
            for _ in range(args.repeat):
                t0 = time.perf_counter()
                enc = path + f'.{mode}.enc'
                if mode == 'cbc':
                    encrypt_cbc_hmac(path, enc, enc_key, mac_key)
                else:
                    encrypt_gcm(path, enc, enc_key)
                enc_dt = time.perf_counter() - t0
                t1 = time.perf_counter()
                out = path + '.dec'
                try:
                    if mode == 'cbc':
                        decrypt_cbc_hmac(enc, out, enc_key, mac_key)
                    else:
                        decrypt_gcm(enc, out, enc_key)
                    ok = True
                except Exception:
                    ok = False
                dec_dt = time.perf_counter() - t1
                res.append((size, mode, enc_dt, dec_dt, ok))
    # Write CSV/MD
    os.makedirs('outputs', exist_ok=True)
    import csv
    with open('outputs/bench.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['size_bytes','mode','enc_sec','dec_sec','ok'])
        for r in res:
            w.writerow(r)
    # Markdown summary
    def fmt(size):
        return f"{size/1024/1024:.1f}MB"
    lines = ["| Size | Mode | Enc (s) | Dec (s) | Enc MB/s | Dec MB/s | OK |", "|---|---|---:|---:|---:|---:|:--:|"]
    for size, mode, enc_sec, dec_sec, ok in res:
        enc_mbps = (size/1024/1024)/enc_sec if enc_sec>0 else 0
        dec_mbps = (size/1024/1024)/dec_sec if dec_sec>0 else 0
        lines.append(f"| {fmt(size)} | {mode.upper()} | {enc_sec:.3f} | {dec_sec:.3f} | {enc_mbps:.1f} | {dec_mbps:.1f} | {'✅' if ok else '❌'} |")
    with open('outputs/bench.md', 'w', encoding='utf-8') as f:
        f.write("\n".join(lines))
    print('Results -> outputs/bench.csv, outputs/bench.md')


def repl():
    print('AES‑Lab REPL. commands: mode [cbc|gcm], enc IN OUT, dec IN OUT, quit')
    mode = 'gcm'
    km = KeyManager()
    label = input('Key label: ').strip()
    password = input('Password: ').strip()
    meta, enc_key, mac_key = km.derive_keypair(label, password)
    while True:
        try:
            cmd = input(f'[{mode}]> ').strip().split()
        except EOFError:
            break
        if not cmd:
            continue
        if cmd[0] in ('quit','exit'):
            break
        if cmd[0] == 'mode' and len(cmd)>=2 and cmd[1] in MODES:
            mode = cmd[1]
            print('mode ->', mode)
            continue
        if cmd[0] == 'enc' and len(cmd)>=3:
            if mode=='cbc':
                encrypt_cbc_hmac(cmd[1], cmd[2], enc_key, mac_key)
            else:
                encrypt_gcm(cmd[1], cmd[2], enc_key)
            print('ok')
            continue
        if cmd[0] == 'dec' and len(cmd)>=3:
            try:
                if mode=='cbc':
                    decrypt_cbc_hmac(cmd[1], cmd[2], enc_key, mac_key)
                else:
                    decrypt_gcm(cmd[1], cmd[2], enc_key)
                print('ok')
            except Exception as e:
                print('ERR', e)
            continue
        print('unknown command')


def main():
    p = argparse.ArgumentParser()
    sp = p.add_subparsers(dest='cmd', required=True)

    pk = sp.add_parser('key')
    pksp = pk.add_subparsers(dest='action', required=True)
    pk_new = pksp.add_parser('new')
    pk_new.add_argument('--label', required=True)
    pk_new.add_argument('--password', required=True)
    pksp.add_parser('list')

    pe = sp.add_parser('enc')
    pe.add_argument('--in', dest='infile', required=True)
    pe.add_argument('--out', dest='outfile', required=True)
    pe.add_argument('--mode', choices=['cbc','gcm'], required=True)
    pe.add_argument('--label', required=True)
    pe.add_argument('--password', required=True)
    pe.add_argument('--aad')

    pd = sp.add_parser('dec')
    pd.add_argument('--in', dest='infile', required=True)
    pd.add_argument('--out', dest='outfile', required=True)
    pd.add_argument('--mode', choices=['cbc','gcm'], required=True)
    pd.add_argument('--label', required=True)
    pd.add_argument('--password', required=True)
    pd.add_argument('--aad')

    pb = sp.add_parser('bench')
    pb.add_argument('--sizes', nargs='+', required=True)
    pb.add_argument('--modes', nargs='+', choices=['cbc','gcm'], default=['cbc','gcm'])
    pb.add_argument('--repeat', type=int, default=3)
    pb.add_argument('--label', required=True)
    pb.add_argument('--password', required=True)

    sp.add_parser('shell')

    args = p.parse_args()

    if args.cmd=='key':
        cmd_key(args)
    elif args.cmd=='enc':
        cmd_enc(args)
    elif args.cmd=='dec':
        cmd_dec(args)
    elif args.cmd=='bench':
        cmd_bench(args)
    elif args.cmd=='shell':
        repl()

if __name__ == '__main__':
    main()
