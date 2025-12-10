# thin wrapper that calls 'aes_cli.py bench' for convenience
if __name__ == '__main__':
    import subprocess, sys
    print('Use: python aes_cli.py bench --sizes 1MB 10MB --modes cbc gcm --repeat 3 --label default --password ...')
