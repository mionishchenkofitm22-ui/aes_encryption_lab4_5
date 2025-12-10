# ЛР №4-5. Реалізація симетричного шифрування з використанням AES

> Це **поради**, а не інструкція. Можливі неточності; перевіряйте офіційну документацію та політики.

## Вимоги
- Python 3.10+
- `pip install -r requirements.txt`

## Швидкий старт
```bash
python aes_cli.py key new --label default
python aes_cli.py enc --in data/sample.txt --out outputs/sample.enc --mode gcm --label default
python aes_cli.py dec --in outputs/sample.enc --out outputs/sample.dec --label default
python aes_cli.py bench --sizes 1MB 10MB --modes cbc gcm --repeat 3
python tamper_demo.py --file outputs/sample.enc  # навмисне псування і перевірка
```

## Структура
- `aes_cli.py` — CLI/REPL (encrypt/decrypt/bench/key management)
- `crypto_aes.py` — реалізація AES‑CBC+HMAC та AES‑GCM, формат контейнера
- `key_manager.py` — PBKDF2, salt, key‑id, запобігання повторному використанню
- `logger_setup.py` — JSON‑логер
- `benchmark.py` — заміри продуктивності, CSV/MD
- `tamper_demo.py` — імітація підміни шифртексту/тегу
- `config.py` — параметри за замовчуванням
- `data/` — вхідні дані; `logs/` — журнали; `outputs/` — результати

## Попередження безпеки
- Не використовуйте демо‑код у проді без аудиту.
- Не повторюйте nonce/IV із тим самим ключем.
- Не зберігайте «голі» ключі на диску.
